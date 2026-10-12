//! Interactive compute launcher. Scripted commands keep their JSON contract.
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, ClearType},
};
use serde_json::{json, Map, Value};
use std::{
    future::Future,
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
pub(crate) mod storage;
pub(crate) const CANCELLED: &str = ui::CANCELLED;
mod sync;
use yougori_cli::cli_ui as ui;

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
    ui::command_activity(menu::activity_label(args), work).await
}

/// Waits for engine work, showing `label` with a spinner once it takes a moment, so a slow
/// answer never looks frozen. Ctrl+C stops waiting with [`CANCELLED`] (see [`ui::busy`]).
pub(crate) async fn busy<T>(label: &str, work: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    ui::busy(label, work).await
}

/// Engine work shown as a step: `label` with a spinner while it runs, then `done` and the time
/// it took, as a finished [`ui::task`] reads. Ctrl+C stops waiting (see [`ui::busy`]); a
/// failure leaves `label` marked as failed.
pub(crate) async fn stage<T>(
    label: &str,
    done: impl FnOnce(&T) -> String,
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let started = Instant::now();
    match ui::busy(label, work).await {
        Ok(value) => {
            finished(&done(&value), started);
            Ok(value)
        }
        Err(error) => {
            if error != ui::CANCELLED {
                failed(label);
            }
            Err(error)
        }
    }
}

/// Starts the engine with a spinner and returns how long that took, for "Engine ready".
async fn start_engine() -> Result<Duration, String> {
    let started = Instant::now();
    match busy("Starting Yougori engine", client::start(None)).await {
        Ok(_) => Ok(started.elapsed()),
        Err(error) => {
            if error != ui::CANCELLED {
                failed("Starting Yougori engine");
            }
            Err(error)
        }
    }
}

/// A finished step and the time it took since `started`.
pub(crate) fn finished(text: &str, started: Instant) {
    ui::step(&timed(text, started.elapsed()));
}

/// A step marked as failed, as an unfinished [`ui::task`] is left.
pub(crate) fn failed(text: &str) {
    ui::task(text).fail(text);
}

/// A step's text with the time it took, as [`ui::Task::done`] writes it.
fn timed(text: &str, elapsed: Duration) -> String {
    if elapsed < Duration::from_millis(100) {
        return text.to_owned();
    }
    format!("{text}  {}", ui::muted(&ui::clock(elapsed)))
}

/// An answer the flow can do without: a failure gives `None`, but Ctrl+C still stops it.
fn tolerated<T>(result: Result<T, String>) -> Result<Option<T>, String> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error == ui::CANCELLED => Err(error),
        Err(_) => Ok(None),
    }
}

/// Whether an error only means the person left a question: Cancel, Esc or Back. These are
/// never shown as failures.
pub(crate) fn left(error: &str) -> bool {
    error == ui::CANCELLED || error == ui::BACK
}

fn hf(s: &str) -> bool {
    s.starts_with("hf.co/") || s.starts_with("https://huggingface.co/")
}
pub(crate) fn prompt_model(args:&[String])->Result<Option<String>,String>{
    chat::validate_run_options(args)?;
    let _raw=ui::Raw::on()?;
    match ui::input_prefilled("Model · OWNER/MODEL", "hf.co/", &yougori_cli::model_invocation::model_id) {
        Ok(value)=>Ok(Some(value)),
        Err(error) if error.to_lowercase().contains("cancel")=>Ok(None),
        Err(error)=>Err(error),
    }
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
// The prompts below are single questions. As a step of a `ui::Wizard` that can go back they
// offer Back (and Esc), which returns `ui::BACK`; a list with a Back item of its own gets no
// second one. Cancel choices and Ctrl+C still cancel with `ui::CANCELLED`.

/// One of `items`, the first preselected.
fn choose(title: &str, items: &[String]) -> Result<usize, String> {
    choose_with_note(title, "", items)
}
/// [`choose`] with explanatory lines under the question.
fn choose_with_note(title: &str, note: &str, items: &[String]) -> Result<usize, String> {
    choose_with_initial(title, note, items, 0)
}
/// [`choose_with_note`] with `initial` preselected, such as an earlier answer asked again.
fn choose_with_initial(title: &str, note: &str, items: &[String], initial: usize) -> Result<usize, String> {
    let note: Vec<String> = note
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(clean)
        .collect();
    ui::select(title, &note, &options(items), initial)
}
/// A line of text that cannot be empty; an empty entry takes `default`.
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
/// A port, `default` unless another is typed. A single question: as a [`ui::Wizard`] step,
/// Back returns [`ui::BACK`].
fn port(title: &str, default: u16) -> Result<u16, String> {
    valid_port(&ui::input(title, &default.to_string(), false, &|entry| {
        valid_port(entry).map(|p| p.to_string())
    })?)
}
/// A free port on this computer, suggesting `default` while it is free. A single question: as a
/// [`ui::Wizard`] step, Back returns [`ui::BACK`].
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
/// Arrow-key resources, starting from `initial` when settings are being changed or asked again.
/// A single question: as a [`ui::Wizard`] step, Back returns [`ui::BACK`].
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
/// Resources for a new model: the recommended ones, or sliders to customize them, asked in
/// turn so Back from the sliders returns to the first question. `customize` goes straight to
/// the sliders; `previous` is an earlier answer shown again. As a [`ui::Wizard`] step, Back
/// from the first question returns [`ui::BACK`].
fn model_resources(host: &Value, customize: bool, min_storage: u32, previous: Option<[u32; 3]>) -> Result<[u32; 3], String> {
    let (recommended, _) = limits(host, true, min_storage)?;
    let mut custom = customize || previous.is_some_and(|previous| previous != recommended);
    let mut chosen = recommended;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 if customize => Ok(false),
            0 => ui::select(
                "How much should this model reserve?",
                &[],
                &[
                    ui::Choice::new("Recommended", allocation_text(recommended)),
                    ui::Choice::new("Customize", "choose CPU, memory and storage"),
                ],
                usize::from(custom),
            )
            .map(|picked| {
                custom = picked == 1;
                true
            }),
            1 if custom => sliders(host, true, min_storage, Some(previous.unwrap_or(recommended))).map(|picked| {
                chosen = picked;
                true
            }),
            1 => {
                chosen = recommended;
                Ok(false)
            }
            _ => return Ok(chosen),
        };
        steps.next(asked)?;
    }
}
async fn offer_architecture_support(model: &str,quant: Option<&str>,preflight: &Value) -> Result<Option<Value>,String> {
    ui::warn(&clean(preflight["reason"].as_str().unwrap_or("This model needs a dedicated runner")));
    if preflight["supportAvailable"]!=true {return Err(preflight["reason"].as_str().unwrap_or("Unsupported model").into());}
    let mut choices=vec![ui::Choice::new("Cancel","leave the model unchanged")];
    choices.extend(yougori_cli::architecture_support::AGENTS.iter().map(|(_,name)|ui::Choice::new(*name,"implement support with its coding agent")));
    let picked=ui::select("Implement architecture support with AI?",&["Uses the selected agent's account and permissions. Support is enabled after testing and installing its build.".into()],&choices,0)?;
    if picked==0 {return Ok(None);}
    let agent=yougori_cli::architecture_support::AGENTS[picked-1].0;
    Ok(Some(busy("Preparing the task for the coding agent", call("model_support_task",json!({"model":model,"quant":quant,"agent":agent}))).await?))
}
struct ModelStorage { minimum: u32, supports_selection: bool }
impl ModelStorage {
    /// What a model's preflight says about storage: what it recommends, at least 12 GB, and
    /// whether the engine can place the model on another drive.
    fn from_preflight(preflight: &Value) -> Self {
        Self {
            minimum: preflight["resources"]["storageGbRecommended"].as_f64().unwrap_or(20.0).ceil().max(12.0) as u32,
            supports_selection: preflight["storageDriveSelection"] == true,
        }
    }
}
async fn model_storage(model: &str, quant: Option<&str>) -> Result<ModelStorage, String> {
    let preflight=busy("Checking the model on Hugging Face", call("model_preflight",json!({"model":model,"quant":quant}))).await?;
    if preflight["supported"]!=true {return Err(preflight["reason"].as_str().unwrap_or("This model needs a dedicated runner").into());}
    Ok(ModelStorage::from_preflight(&preflight))
}
/// What an existing model reserves: CPU, memory and storage.
fn current_resources(env: &Value) -> [u32; 3] {
    [
        env["resourcePolicy"]["cpu"]["max"].as_f64().unwrap_or(2.0).max(2.0).ceil() as u32,
        env["resourcePolicy"]["memoryGb"]["max"].as_f64().unwrap_or(4.0).max(4.0).ceil() as u32,
        env["storageLimitGb"].as_f64().unwrap_or(12.0).ceil() as u32,
    ]
}
/// The changes from `current` to `chosen`. A disk can grow but never shrink.
fn resource_changes(current: [u32; 3], chosen: [u32; 3]) -> Map<String, Value> {
    let mut map = Map::new();
    if chosen[..2] != current[..2] {
        map.insert("cpu".into(), json!(chosen[0]));
        map.insert("memoryGb".into(), json!(chosen[1]));
    }
    if chosen[2] > current[2] {
        map.insert("storageGb".into(), json!(chosen[2]));
    }
    map
}
/// `current` with earlier `changes` applied, to show them again.
fn with_changes(current: [u32; 3], changes: &Map<String, Value>) -> [u32; 3] {
    let value = |key: &str, at: usize| changes.get(key).and_then(Value::as_f64).map_or(current[at], |v| v.ceil() as u32);
    [value("cpu", 0), value("memoryGb", 1), value("storageGb", 2)]
}
/// Changes for an existing model's resources, or `None` to start it as before, asked in turn so
/// Back from the sliders returns to the first question. Its disk can grow but never shrink.
/// `change` goes straight to the sliders; `previous` is an earlier answer shown again. As a
/// [`ui::Wizard`] step, Back from the first question returns [`ui::BACK`].
fn changed_model_resources(host: &Value, env: &Value, change: bool, previous: Option<&Map<String, Value>>) -> Result<Option<Map<String, Value>>, String> {
    let current = current_resources(env);
    let mut changing = change || previous.is_some();
    let mut chosen = None;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 if change => Ok(false),
            0 => ui::select(
                "How should it start?",
                &[],
                &[
                    ui::Choice::new("As before", allocation_text(current)),
                    ui::Choice::new("Change resources", "choose CPU and memory, or add storage"),
                ],
                usize::from(changing),
            )
            .map(|picked| {
                changing = picked == 1;
                true
            }),
            1 if changing => {
                let start = previous.map_or(current, |previous| with_changes(current, previous));
                sliders(host, true, current[2].max(12), Some(start)).map(|picked| {
                    chosen = Some(resource_changes(current, picked));
                    true
                })
            }
            1 => {
                chosen = None;
                Ok(false)
            }
            _ => return Ok(chosen),
        };
        steps.next(asked)?;
    }
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
/// A new domain's name, tunnel origin port and Cloudflare tunnel token, asked in turn: Back goes
/// to the previous question, and from the first one returns [`ui::BACK`]. `saved` setups cannot
/// be added again; `previous` is an earlier name and port shown again.
fn new_domain(saved: &[Value], previous: Option<(&str, u16)>) -> Result<(String, String, u16), String> {
    let (mut hostname, mut host_port) = previous.map_or((String::new(), 45000), |(name, port)| (name.to_owned(), port));
    let mut token = String::new();
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::input("Public domain", &hostname, false, &|entry| domains::hostname(entry, saved))
                .map(|entry| hostname = entry),
            1 => port("Tunnel origin port (Cloudflare routes to http://127.0.0.1:THIS_PORT)", host_port)
                .map(|entry| host_port = entry),
            2 => {
                ui::info("Cloudflare dashboard: https://dash.cloudflare.com/");
                ui::info("Go to Networking > Tunnels, select your tunnel, then Add a replica to copy its install command.");
                ui::input("Cloudflare tunnel token (or the full install command)", "", true, &tunnel_token)
                    .map(|entry| token = entry)
            }
            _ => return Ok((hostname, token, host_port)),
        };
        steps.next(asked.map(|()| true))?;
    }
}
/// Who can reach a service, with `previous` (an earlier answer) preselected when it is asked
/// again. "Your own domain" goes on to ask the domain, tunnel port and token, where Back returns
/// to the previous question. As a [`ui::Wizard`] step, Back from the first question returns
/// [`ui::BACK`].
async fn network_with_previous(model: bool, current: Option<&str>, service_port: Option<u16>, previous: Option<&Network>) -> Result<Network, String> {
    let saved = domains::available(current, service_port).await?;
    let taken: Vec<Value> = saved.iter().map(|option| option.domain.clone()).collect();
    let mut options = vec![
        ui::Choice::new("This computer", "localhost only"),
        ui::Choice::new("Local network", "other devices on your Wi-Fi or LAN"),
        ui::Choice::new("Quick public link", "a temporary trycloudflare.com address"),
        ui::Choice::new("Your own domain", "set up and save a Cloudflare tunnel"),
    ];
    options.extend(saved.iter().map(|d| d.choice()));
    let earlier_domain = match previous {
        Some(Network::NewDomain { hostname, host_port, .. }) => Some((hostname.as_str(), *host_port)),
        _ => None,
    };
    let mut selection = network_initial(previous, &saved);
    let mut domain = None;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::select(
                if model {
                    "Who can reach the model API?"
                } else {
                    "Who can open your app?"
                },
                &[], &options, selection,
            )
            .map(|picked| {
                selection = picked;
                true
            }),
            1 if selection == 3 => new_domain(&taken, earlier_domain).map(|answer| {
                domain = Some(answer);
                true
            }),
            1 => Ok(false),
            _ => break,
        };
        steps.next(asked)?;
    }
    Ok(match selection {
        0 => Network::Computer,
        1 => Network::Lan,
        2 => Network::Quick,
        3 => {
            let (hostname, token, host_port) = domain.ok_or("Set up the domain first")?;
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
/// The answer preselected in the network question: an earlier answer when it is asked again,
/// else the saved domain already connected to this service, else This computer.
fn network_initial(previous: Option<&Network>, saved: &[domains::DomainOption]) -> usize {
    match previous {
        Some(Network::Computer) => 0,
        Some(Network::Lan) => 1,
        Some(Network::Quick) => 2,
        Some(Network::NewDomain { .. }) => 3,
        Some(Network::Domain(hostname)) => domains::preselected(saved, Some(hostname)).map_or(0, |i| i + 4),
        None => domains::preselected(saved, None).map_or(0, |i| i + 4),
    }
}
/// Who can reach a model, as the final question lists it.
fn destination(network: &Network) -> String {
    match network {
        Network::Computer => "This computer".into(),
        Network::Lan => "This computer and your local network".into(),
        Network::Quick => "This computer and a public quick link (anyone with the URL)".into(),
        Network::Domain(d) | Network::NewDomain { hostname: d, .. } => {
            format!("This computer and https://{}", clean(d))
        }
    }
}
/// The answers the final question lists before a model is created or started.
fn model_review(
    allocation: Option<[u32; 3]>,
    existing: Option<&str>,
    changes: Option<&Map<String, Value>>,
    drive: Option<&str>,
    local: u16,
    guest: u16,
    network: &Network,
) -> Vec<String> {
    vec![
        match (allocation, existing) {
            (Some(a), _) => allocation_text(a),
            (None, Some(name)) if changes.is_some_and(|c| !c.is_empty()) => {
                format!("Reuses {name} with new resources")
            }
            (None, Some(name)) => format!("Reuses {name}"),
            (None, None) => String::new(),
        },
        drive.map_or_else(|| "Keeping its existing storage location".into(), |drive| format!("Storage drive: {drive}")),
        format!("Local port {local} → model port {guest}"),
        destination(network),
    ]
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
        Err(error) if left(&error) => {
            ui::outro(&ui::muted(ui::CANCELLED));
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
    ui::step(&timed("Engine ready", start_engine().await?));
    // One environment per model: an existing one is started instead of creating another.
    let (state, existing) = busy("Looking for this model on this computer", async {
        let state = call("get_platform_state", json!({})).await?;
        let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
        let mut existing = public::existing_model(environments, &target).cloned();
        if let Some(env) = &mut existing {
            public::name_after_model(env, environments).await;
        }
        Ok((state, existing))
    })
    .await?;
    let existing_name = existing
        .as_ref()
        .map(|env| clean(env["name"].as_str().unwrap_or("")));
    let mut existing_api = None;
    if let (Some(env), Some(name)) = (&existing, &existing_name) {
        ui::step(&format!("{name} already has this model; it will be reused"));
        if env["status"] == "running" {
            existing_api = tolerated(busy("Checking its local API", call("model_api_status", json!({"environmentId":env["id"]}))).await)?
                .and_then(|access| access["apiUrl"].as_str().and_then(url_port));
        }
        if let Some(port) = existing_api {
            ui::step(&format!("Keeping its local API on port {port}"));
        }
    }
    let plan = if existing.is_none() {
        let preflight = busy("Checking the model on Hugging Face", call("model_preflight", json!({"model":target}))).await?;
        if preflight["supported"]!=true {
            let Some(task)=offer_architecture_support(&target,None,&preflight).await? else {return Ok(0);};
            ui::outro(&format!("Opening coding agent · task saved at {}",task["path"].as_str().unwrap_or("")));
            drop(session);drop(_raw);
            return yougori_cli::architecture_support::launch(&task);
        }
        Some(ModelStorage::from_preflight(&preflight))
    } else {None};
    let minimum = plan.as_ref().map_or(12, |plan|plan.minimum);
    let supports_selection = plan.as_ref().is_some_and(|plan| plan.supports_selection);
    // What the questions need from this PC: its drives for a new model, the disk of a stopped
    // one. A running model keeps its resources; a stopped one can change them before it starts.
    let host = match &existing {
        None => Some(busy("Reading this computer's drives and memory", call("refresh_host_metrics", json!({}))).await?["host"].take()),
        Some(env) if env["status"] != "running" => {
            Some(busy("Checking the model's storage", storage::for_environment(&state["host"], env)).await?)
        }
        Some(_) => None,
    };
    let guest = 8000;
    let environment = existing.as_ref().and_then(|env| env["id"].as_str());
    let finishes = options(&[
        "Chat here — replies stream into this terminal, plus the API".into(),
        "Python chat — run the generated yougori_chat.py, plus the API".into(),
        "API only — keep watching usage".into(),
    ]);
    let (question, go) = if existing.is_some() {
        ("Start this model?", "Start")
    } else {
        ("Create and run this model?", "Create and run")
    };
    // Each question after the first offers Back; answers are kept and shown again.
    let mut selected: Option<storage::Selection> = None;
    let mut allocation = None;
    let mut changes = None;
    let mut network = None;
    let mut local = 8000;
    let mut finish = 0;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => match (&existing, &host) {
                (None, Some(host)) => storage::choose_model(host, None, minimum, supports_selection, selected.as_ref().map(|s| s.label.as_str()))
                    .map(|selection| {
                        selected = Some(selection);
                        true
                    }),
                _ => Ok(false),
            },
            1 => match (&selected, &existing, &host) {
                (Some(selection), _, _) => model_resources(&selection.host, false, minimum, allocation).map(|chosen| {
                    allocation = Some(chosen);
                    true
                }),
                (None, Some(env), Some(host)) => changed_model_resources(host, env, false, changes.as_ref()).map(|chosen| {
                    changes = chosen;
                    true
                }),
                _ => Ok(false),
            },
            2 => network_with_previous(true, environment, Some(guest), network.as_ref()).await.map(|chosen| {
                network = Some(chosen);
                true
            }),
            3 if existing_api.is_some() => Ok(false),
            3 => local_port(local).map(|port| {
                local = port;
                true
            }),
            4 => ui::select("When the model is ready", &[], &finishes, finish).map(|picked| {
                finish = picked;
                true
            }),
            5 => {
                let review = model_review(
                    allocation,
                    existing_name.as_deref(),
                    changes.as_ref(),
                    selected.as_ref().map(|selection| selection.label.as_str()),
                    existing_api.unwrap_or(local),
                    guest,
                    network.as_ref().ok_or("Choose who can reach the model API")?,
                );
                match ui::select(
                    question,
                    &review,
                    &[
                        ui::Choice::new(go, ""),
                        ui::Choice::new("Cancel", "nothing is changed"),
                    ],
                    0,
                ) {
                    Ok(0) => Ok(true),
                    Ok(_) => {
                        ui::outro("Nothing was changed.");
                        return Ok(0);
                    }
                    Err(error) => Err(error),
                }
            }
            _ => break,
        };
        steps.next(asked)?;
    }
    drop(steps);
    let local = existing_api.unwrap_or(local);
    let network = network.ok_or("Choose who can reach the model API")?;
    if let Network::NewDomain {
        hostname,
        token,
        host_port,
    } = &network
    {
        let name = clean(hostname);
        stage(
            &format!("Saving {name}"),
            |_| format!("Saved {name}"),
            call(
                "add_saved_domain",
                json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":guest}),
            ),
        )
        .await?;
    }
    let id = match (&existing, allocation) {
        (Some(env), _) => {
            let name = existing_name.clone().unwrap_or_default();
            let result = stage(
                &format!("Starting {name}"),
                |_| format!("Using {name}"),
                public::reuse_model(env, &changes.clone().unwrap_or_default(), Some(local)),
            )
            .await?;
            result["id"]
                .as_str()
                .ok_or("Model environment missing")?
                .to_owned()
        }
        (None, allocation) => {
            let allocation = allocation.unwrap_or_default();
            let mut resources=json!({"cpu":allocation[0],"memoryGb":allocation[1],"storageGb":allocation[2]});
            if let Some(drive)=selected.as_ref().and_then(|selection|selection.drive.as_deref()) {resources["storageDrive"]=json!(drive);}
            ui::info("Image and model downloads can take several minutes.");
            let result = stage(
                "Creating model environment",
                |result: &Value| format!("Created {}", clean(result["name"].as_str().or(result["id"].as_str()).unwrap_or("the model environment"))),
                call("run_model",json!({"model":target,"port":local,"resources":resources})),
            )
            .await?;
            result["id"]
                .as_str()
                .ok_or("Created environment did not return an ID")?
                .to_owned()
        }
    };
    let id = id.as_str();
    if let Some(params) = publish_params(&network, id, guest) {
        stage("Publishing", |_| "Published".into(), domains::publish(params))
            .await
            .map_err(|e| if left(&e) { e } else {
                format!("Environment {id} exists and localhost access is enabled, but publishing failed: {e}. Retry publishing on this environment; do not recreate it.")
            })?;
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
                        // Ctrl+C while loading opens the stop options, as it does here.
                        match busy("Loading API access", call("model_api_status", json!({"environmentId":id}))).await {
                            Ok(access) => private_view("Model API · private credentials",&format!("  Base URL       {}\n  Public URL     {}\n  Authorization  Bearer {}\n\n  POST /chat/completions\n  Content-Type: application/json\n  {{\"model\":{},\"messages\":[{{\"role\":\"user\",\"content\":\"Hello\"}}]}}",access["apiUrl"],access["publicUrl"],clean(access["apiKey"].as_str().unwrap_or("")),access["model"]))?,
                            Err(error) if error == ui::CANCELLED => {}
                            Err(error) => return Err(error),
                        }
                        if ui::take_interrupt() { stop = true; }
                    }
                    _ => {}
                },
                Event::Resize(..) => ui::refresh(),
                _ => {}
            }
        }
        if stop && chat::stop_choice(id).await? {
            drop(_close);
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
    fn model_storage_follows_the_preflight_with_a_12_gb_floor() {
        let plan = ModelStorage::from_preflight(&json!({"resources":{"storageGbRecommended":30.2},"storageDriveSelection":true}));
        assert_eq!((plan.minimum, plan.supports_selection), (31, true));
        let small = ModelStorage::from_preflight(&json!({"resources":{"storageGbRecommended":3}}));
        assert_eq!((small.minimum, small.supports_selection), (12, false));
        assert_eq!(ModelStorage::from_preflight(&json!({})).minimum, 20);
    }
    #[test]
    fn changed_resources_keep_what_stayed_and_disks_only_grow() {
        let env = json!({"resourcePolicy":{"cpu":{"max":1},"memoryGb":{"max":6.5}},"storageLimitGb":19.2});
        let current = current_resources(&env);
        assert_eq!(current, [2, 7, 20]);
        assert!(resource_changes(current, current).is_empty());
        let more = resource_changes(current, [4, 8, 20]);
        assert_eq!(Value::Object(more.clone()), json!({"cpu":4,"memoryGb":8}));
        assert_eq!(Value::Object(resource_changes(current, [2, 7, 40])), json!({"storageGb":40}));
        assert!(resource_changes(current, [2, 7, 12]).is_empty(), "a disk never shrinks");
        // Changes are shown again when the question is asked again.
        assert_eq!(with_changes(current, &more), [4, 8, 20]);
        assert_eq!(with_changes(current, &Map::new()), current);
        assert_eq!(current_resources(&json!({})), [2, 4, 12]);
    }
    #[test]
    fn the_network_question_preselects_the_earlier_answer() {
        assert_eq!(network_initial(None, &[]), 0);
        assert_eq!(network_initial(Some(&Network::Computer), &[]), 0);
        assert_eq!(network_initial(Some(&Network::Lan), &[]), 1);
        assert_eq!(network_initial(Some(&Network::Quick), &[]), 2);
        let new = Network::NewDomain { hostname: "app.example.com".into(), token: "t".into(), host_port: 45000 };
        assert_eq!(network_initial(Some(&new), &[]), 3);
        let saved = |hostname: &str, connected: bool| domains::DomainOption {
            domain: json!({"hostname":hostname}),
            connected,
            enabled: true,
            hint: String::new(),
        };
        let list = [saved("a.example.com", true), saved("b.example.com", false)];
        assert_eq!(network_initial(None, &list), 4, "the connected domain");
        assert_eq!(network_initial(Some(&Network::Domain("B.example.com".into())), &list), 5);
        assert_eq!(network_initial(Some(&Network::Lan), &list), 1);
        assert_eq!(network_initial(Some(&Network::Domain("gone.example.com".into())), &[]), 0);
    }
    #[test]
    fn the_final_question_lists_the_answers() {
        let review = model_review(Some([2, 4, 30]), None, None, Some("D:\\"), 8001, 8000, &Network::Quick);
        assert_eq!(review, [
            "2 CPU · 4 GB memory · 30 GB storage",
            "Storage drive: D:\\",
            "Local port 8001 → model port 8000",
            "This computer and a public quick link (anyone with the URL)",
        ]);
        let changes = Map::from_iter([("cpu".to_owned(), json!(4))]);
        let reuse = model_review(None, Some("Qwen3-8B"), Some(&changes), None, 8000, 8000, &Network::Computer);
        assert_eq!(reuse[0], "Reuses Qwen3-8B with new resources");
        assert_eq!(reuse[1], "Keeping its existing storage location");
        assert_eq!(reuse[3], "This computer");
        assert_eq!(model_review(None, Some("Qwen3-8B"), Some(&Map::new()), None, 8000, 8000, &Network::Lan)[0], "Reuses Qwen3-8B");
        assert_eq!(destination(&Network::Domain("api.example.com\x1b[2J".into())), "This computer and https://api.example.com[2J");
    }
    #[test]
    fn steps_show_their_time_and_only_ctrl_c_stops_optional_answers() {
        assert_eq!(timed("Engine ready", Duration::from_millis(40)), "Engine ready");
        let slow = timed("Engine ready", Duration::from_millis(2500));
        assert!(slow.starts_with("Engine ready  ") && slow.contains("2.5s"), "{slow}");
        assert_eq!(tolerated(Ok::<_, String>(1)), Ok(Some(1)));
        assert_eq!(tolerated::<u8>(Err("engine busy".into())), Ok(None));
        assert_eq!(tolerated::<u8>(Err(ui::CANCELLED.into())), Err(ui::CANCELLED.into()));
        assert!(left(ui::CANCELLED) && left(ui::BACK));
        assert!(!left("Publishing failed"));
    }
    #[test]
    fn engine_answers_arrive_once_whether_quick_or_behind_the_spinner() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            assert_eq!(busy("Loading", async { Ok::<_, String>(7) }).await, Ok(7));
            assert_eq!(busy("Loading", async { Err::<u8, _>("No such model".to_owned()) }).await, Err("No such model".into()));
            // A slow answer keeps the same request going behind the spinner; it is never sent twice.
            let sent = std::sync::atomic::AtomicUsize::new(0);
            let slow = busy("Checking the model on Hugging Face", async {
                sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok::<_, String>("ready")
            });
            assert_eq!(slow.await, Ok("ready"));
            assert_eq!(sent.load(std::sync::atomic::Ordering::SeqCst), 1);
        });
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
