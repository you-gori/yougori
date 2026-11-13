//! Yougori-owned inference clients. No website-supplied host scripts are executed.
use base64::Engine as _;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;
pub const HELP: &str = "yougori inference connect URL [--models REPO,REPO --sandbox none|CPU,GB,VMS] [--reconnect]\n  Start Yougori if needed and choose what this computer does for the website: run 1 to 3 of\n  the models its administrator lists (Yougori installs them here; each loads on the GPU while\n  it is used and unloads after 5 minutes without requests), run Sandbox VMs within limits you\n  set, or both. It connects once each chosen model can answer, showing its download and load;\n  Ctrl+C before then stops waiting, and the download goes on. The first time, approve the code\n  it shows on the website. Next time, continue with the same choices or change them: a model\n  you drop is deleted from this computer if Yougori installed it for the website. Once\n  connected, Ctrl+C disconnects and stops the models it ran for it.\n  --models and --sandbox answer the questions (--models \"\" for none); without a terminal and\n  without them, the last choices are used.\n\nyougori inference run [HARNESS] --server URL [--harness NAME] [--model ID]\n    [--set ID=VALUE]... [--workspace PATH] [--internet inference|sites|targets|full]\n    [--sites HOST,HOST] [--targets HOST:PORT,HOST:PORT] [--cpu N] [--memory GB] [--yes]\n  Start a harness in a Yougori Sandbox VM. It asks, with Back: which harness (Yougori's own\n  agent first, then the website's coding and security harnesses; HARNESS or --harness starts\n  the list on one), which model (signing in on the website the first time), the harness's own\n  questions (a security harness asks what to test, whether you own it or have written\n  permission to test it, what is off limits, how far it may go, a test login, the source code\n  and a focus), then the folder copied in (changes come back only after your review), what\n  the VM can reach (only this inference, sites you choose, or the whole internet as well; a\n  security harness reaches only its target and this inference; prompts and replies always go\n  to the inference) and its CPU and memory.\n  Options given skip their question. --set ID=VALUE answers one of the harness's own, such as\n  --set target=practice or --set permission=yes. A secret, such as a test login's password,\n  comes only from a YOUGORI_SECRET_ID environment variable (YOUGORI_SECRET_LOGIN_PASSWORD),\n  never from the command line. --yes asks nothing: the options given and defaults.\n\nyougori inference install HARNESS --server URL\n  Prepare the images that run starts HARNESS from, without starting it: the Yougori\n  base image and HARNESS's pack (yougori, Yougori's own agent, needs only the base). Like\n  run, it needs HARNESS offered on the website and its images published.\n\nYougori manages the client and private runtime. No separate solver-* installation.\nRun the same command next time. Ctrl+C disconnects.\n";
const PACKAGES: &str =
    include_str!("../../examples/hub/inference-solver/site/harnesses/packages.json");
const INSTALLER: &str =
    include_str!("../../examples/hub/inference-solver/site/install-harness.ps1");
const SOURCES: &[(&str, &[u8])] = &[
    (
        "solver.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/solver.py"),
    ),
    (
        "device_login.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/device_login.py"),
    ),
    (
        "transport.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/transport.py"),
    ),
    (
        "vm_host.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/vm_host.py"),
    ),
    (
        "vm_relay.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/vm_relay.py"),
    ),
    (
        "vm_guest.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/vm_guest.py"),
    ),
    (
        "vm_package.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/vm_package.py"),
    ),
    (
        "vm_tunnel.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/vm_tunnel.py"),
    ),
    (
        "shannon_cli.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/shannon_cli.py"),
    ),
    (
        "pentagi_cli.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/pentagi_cli.py"),
    ),
    (
        "install_shannon.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/install_shannon.py"),
    ),
    (
        "install_pentagi.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/install_pentagi.py"),
    ),
    (
        "pentagi_vm.go",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/pentagi_vm.go"),
    ),
    (
        "pentagi_vm_test.go",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/pentagi_vm_test.go"),
    ),
    (
        "hexstrike_cli.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/hexstrike_cli.py"),
    ),
    (
        "plandex_cli.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/plandex_cli.py"),
    ),
    (
        "strix_cli.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/strix_cli.py"),
    ),
    (
        "cli_entry.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/cli_entry.py"),
    ),
    (
        "packages.json",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/packages.json"),
    ),
    (
        "installer.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/installer.py"),
    ),
    (
        "profiles.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/profiles.py"),
    ),
    (
        "runtime.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/runtime.py"),
    ),
    (
        "relay.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/relay.py"),
    ),
    (
        "blue.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/blue.py"),
    ),
    (
        "README.md",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/README.md"),
    ),
    (
        "compute_node.py",
        include_bytes!("../../examples/hub/inference-solver/site/compute_node.py"),
    ),
    (
        "compute_adapter.py",
        include_bytes!("../../examples/hub/inference-solver/site/compute_adapter.py"),
    ),
    (
        "compute_options.py",
        include_bytes!("../../examples/hub/inference-solver/site/compute_options.py"),
    ),
    (
        "grid_adapter.py",
        include_bytes!("../../examples/hub/inference-solver/site/grid_adapter.py"),
    ),
    (
        "control_panel.py",
        include_bytes!("../../examples/hub/inference-solver/site/control_panel.py"),
    ),
    (
        "harnesses/transport.py",
        include_bytes!("../../examples/hub/inference-solver/site/harnesses/transport.py"),
    ),
];
fn origin(value: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(value).map_err(|_| "Use the inference website's full URL.")?;
    let host = url.host_str().unwrap_or("");
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]")
        || host.strip_suffix(".localhost").is_some_and(|token| {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    if !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http" && !local)
        || host.is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("Use an HTTPS inference website URL without a path or credentials. Local development websites may use HTTP.".into());
    }
    Ok(url.as_str().trim_end_matches('/').into())
}
#[derive(Debug, PartialEq)]
struct Options {
    action: String,
    /// The harness named after the action: for `install` the one whose images it prepares, for
    /// `run` only where the list of harnesses starts (empty when none is named). The website's
    /// catalogue checks it.
    harness: String,
    server: String,
    extra: Vec<String>,
}

/// The harnesses this CLI's launcher can start (its packages.json).
fn launcher_harnesses() -> Vec<String> {
    serde_json::from_str::<Value>(PACKAGES)
        .ok()
        .and_then(|catalog| catalog.as_object().map(|names| names.keys().cloned().collect()))
        .unwrap_or_default()
}

fn options(args: &[String]) -> Result<Options, String> {
    let action = args.first().map(String::as_str).ok_or(HELP)?;
    if action == "connect" {
        let server = origin(args.get(1).ok_or(HELP)?)?;
        let mut rest = args[2..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--reconnect" | "--help" | "-h" => {}
                "--models" | "--sandbox" => {
                    rest.next().ok_or_else(|| format!("{arg} needs a value."))?;
                }
                _ => return Err(HELP.into()),
            }
        }
        return Ok(Options {
            action: action.into(),
            harness: "node".into(),
            server,
            extra: args[2..].to_vec(),
        });
    }
    if !matches!(action, "run" | "install") {
        return Err(HELP.into());
    }
    // `run` may name no harness: the person chooses one from the website's list.
    let harness = args.get(1).filter(|arg| !arg.starts_with('-')).cloned().unwrap_or_default();
    if action == "install" {
        let known = launcher_harnesses();
        if harness.is_empty() {
            return Err(HELP.into());
        }
        if !known.contains(&harness) {
            return Err(format!("Unknown harness {harness}. Available: {}", known.join(", ")));
        }
    }
    let mut server = None;
    let mut extra = Vec::new();
    let mut i = if harness.is_empty() { 1 } else { 2 };
    while i < args.len() {
        if args[i] == "--" {
            extra.extend_from_slice(&args[i..]);
            break;
        }
        if args[i] == "--server" {
            if server.is_some() {
                return Err("Give --server once.".into());
            }
            i += 1;
            server = Some(origin(
                args.get(i).ok_or("--server needs the website URL.")?,
            )?);
        } else {
            extra.push(args[i].clone());
        }
        i += 1;
    }
    // Anything else would reach the launcher, where its own spelling of an option (`--harness`,
    // `--server=URL`) would choose another harness or website than the one checked.
    if let Some(other) = extra.first().filter(|_| action == "install") {
        return Err(format!("yougori inference install does not take {}: it takes only HARNESS and --server URL.", plain_words(other)));
    }
    Ok(Options {
        action: action.into(),
        harness,
        server: server.ok_or("Add --server URL to select your inference website.")?,
        extra,
    })
}
/// What the harness VM may reach. Never nothing: prompts and replies always go to the inference
/// through Yougori's relay, which keeps the API key outside the VM.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Internet {
    Inference,
    /// The inference and these sites (each with its subdomains), over HTTPS through the relay;
    /// the VM still has no network card.
    Sites(Vec<String>),
    /// The inference, these targets (`host:port`, or a host for each of its ports) and these
    /// sites. The targets come from the target question's answer unless `--targets` names them.
    Targets(Vec<String>, Vec<String>),
    Full,
}

impl Internet {
    fn flag(&self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::Sites(_) => "sites",
            Self::Targets(..) => "targets",
            Self::Full => "full",
        }
    }
}

/// Site names as the launcher takes them: DNS names with a dot (never addresses), lowercased,
/// without repeats; each also covers its subdomains. Mirrors vm_tunnel.sites.
fn site_names(value: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for raw in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let name = raw.to_ascii_lowercase();
        let name = name.trim_end_matches('.');
        let labels: Vec<&str> = name.split('.').collect();
        let label_ok = |label: &&str| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        let top = labels.last().copied().unwrap_or("");
        if !(4..=253).contains(&name.len())
            || labels.len() < 2
            || !labels.iter().all(label_ok)
            || top.len() < 2
            || !top.bytes().all(|b| b.is_ascii_lowercase())
        {
            return Err(format!("{raw} is not a site name such as github.com."));
        }
        if !names.iter().any(|n: &String| n == name) {
            names.push(name.to_owned());
        }
    }
    if names.is_empty() || names.len() > 64 {
        return Err("Name 1 to 64 sites, separated by commas, such as github.com, pypi.org.".into());
    }
    Ok(names)
}

/// What a target naming this computer is told: a VM never reaches this computer's own services.
fn this_computer(raw: &str) -> String {
    format!("{raw} is this computer: run the app inside the VM (the practice app is there), or give its network address.")
}

/// One target the VM may reach, as the launcher takes it: `host:port`, or a host alone for each
/// of its ports. A DNS name (a single label only with a port) or an IPv4 address; never this
/// computer (localhost, 127.x.x.x) or a link-local (cloud metadata), multicast or broadcast
/// address. Mirrors solver.target_host.
fn target_host(entry: &str) -> Result<String, String> {
    let raw = entry.trim();
    let text = raw.to_ascii_lowercase();
    let parts: Vec<&str> = text.split(':').collect();
    let (host, port) = match parts[..] {
        [host] => (host, None),
        [host, port] => {
            let number = port.parse::<u32>().ok().filter(|n| (1..=65535).contains(n));
            if port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) || port.starts_with('0') || number.is_none() {
                return Err(format!("{raw} has no valid port (1 to 65535)."));
            }
            (host, Some(port))
        }
        _ => return Err(format!("{raw} is not a host such as staging.example.com:443 (IPv6 addresses are not taken).")),
    };
    let octets: Vec<&str> = host.split('.').collect();
    let host = if octets.len() == 4 && octets.iter().all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())) {
        let numbers: Vec<u32> = octets.iter().map(|part| part.parse::<u32>().unwrap_or(256)).collect();
        if octets.iter().zip(&numbers).any(|(part, number)| part.len() > 3 || *number > 255 || (part.len() > 1 && part.starts_with('0'))) {
            return Err(format!("{raw} is not an IPv4 address."));
        }
        if numbers[0] == 127 {
            return Err(this_computer(raw));
        }
        if numbers[0] == 0 || numbers[0] >= 224 || (numbers[0], numbers[1]) == (169, 254) {
            return Err(format!("{raw} is not an address of a computer to test."));
        }
        host.to_owned()
    } else {
        let name = host.strip_suffix('.').unwrap_or(host);
        let labels: Vec<&str> = name.split('.').collect();
        if labels.last() == Some(&"localhost") {
            return Err(this_computer(raw));
        }
        let label_ok = |label: &&str| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        let last = labels.last().copied().unwrap_or("");
        if !(1..=253).contains(&host.len())
            || !labels.iter().all(label_ok)
            || (labels.len() == 1 && port.is_none())
            || last.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("{raw} is not a host such as staging.example.com or staging.example.com:443."));
        }
        name.to_owned()
    };
    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// `--targets`: 1 to 64 hosts, separated by commas, each once. A web address is taken as its host
/// and port, as the target question and the launcher take it.
fn target_list(value: &str) -> Result<Vec<String>, String> {
    let mut targets: Vec<String> = Vec::new();
    for entry in value.split(',').filter(|entry| !entry.trim().is_empty()) {
        let host = if entry.contains("://") { url_host(entry.trim())? } else { target_host(entry)? };
        if !targets.contains(&host) {
            targets.push(host);
        }
    }
    if targets.is_empty() || targets.len() > 64 {
        return Err("Name 1 to 64 targets, separated by commas, such as staging.example.com:443.".into());
    }
    Ok(targets)
}

/// What the VM must reach for a web address to test: its host and port (by its scheme when it
/// names none).
fn url_host(value: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(value).map_err(|_| format!("{value} is not a web address such as https://staging.example.com."))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{value} is not an http or https address."));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Give the login in its own question, not in the address.".into());
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty() && !host.starts_with('['))
        .ok_or_else(|| format!("{value} needs a host name or an IPv4 address (IPv6 addresses are not taken)."))?;
    target_host(&format!("{host}:{}", url.port_or_known_default().unwrap_or(443)))
}

/// The addresses a target question takes, each as given (a URL as typed, a host lowercased) with
/// what the VM must reach for it: http(s) URLs, host[:port] or IPv4[:port], separated by commas,
/// 1 to 16, each once.
fn target_entries(value: &str) -> Result<Vec<(String, String)>, String> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for raw in value.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let (given, host) = if raw.contains("://") {
            (raw.to_owned(), url_host(raw)?)
        } else {
            let host = target_host(raw)?;
            (host.clone(), host)
        };
        if !entries.iter().any(|(entry, _)| *entry == given) {
            entries.push((given, host));
        }
    }
    if entries.is_empty() || entries.len() > 16 {
        return Err("Give 1 to 16 addresses, separated by commas, such as https://staging.example.com.".into());
    }
    Ok(entries)
}

/// What the person running a harness gave on the command line. `None` leaves the question.
#[derive(Clone, Debug, Default, PartialEq)]
struct Permissions {
    workspace: Option<PathBuf>,
    internet: Option<Internet>,
    cpu: Option<u32>,
    memory: Option<u32>,
    /// `--yes`: no questions; options given and defaults for the rest.
    yes: bool,
    /// `--harness NAME`: the harness Yougori holds.
    harness: Option<String>,
    /// `--model ID`.
    model: Option<String>,
    /// `--set ID=VALUE`: answers to the harness's own questions, in the order given. Never
    /// secrets, which come only from YOUGORI_SECRET_<ID> variables.
    sets: Vec<(String, String)>,
}

/// A folder the harness may work on: an existing directory that is not a drive root, as an
/// absolute path. The launcher stages a copy; nothing reaches the folder without a review.
fn project_folder(value: &str) -> Result<PathBuf, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Type the path of a project folder.".into());
    }
    let path = std::path::absolute(value).map_err(|_| "That folder path is not valid.".to_owned())?;
    if !path.is_dir() {
        return Err(format!("{} is not a folder on this computer.", path.display()));
    }
    if path.parent().is_none() || path.to_string_lossy().contains(',') {
        return Err("Choose a project folder, not a drive root (and without commas in its path).".into());
    }
    Ok(path)
}

fn count(value: &str, low: u32, high: u32, flag: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|n| (low..=high).contains(n))
        .ok_or_else(|| format!("{flag} takes a number from {low} to {high}."))
}

/// A harness's id as the website and the launcher spell it.
fn harness_name(value: &str) -> bool {
    (1..=32).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A question's id, which is its answer's key: `target`, `login_password`.
fn answer_id(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `--set ID=VALUE`.
fn setting(value: &str) -> Result<(String, String), String> {
    match value.split_once('=') {
        Some((id, answer)) if answer_id(id) => Ok((id.to_owned(), answer.to_owned())),
        _ => Err("--set takes ID=VALUE, such as --set target=practice.".into()),
    }
}

/// `--internet`, `--sites` and `--targets` together: what the VM may reach.
fn reach_flags(mode: Option<&str>, sites: Option<Vec<String>>, targets: Option<Vec<String>>) -> Result<Option<Internet>, String> {
    Ok(match (mode, sites, targets) {
        (None, None, None) => None,
        (Some("inference"), None, None) => Some(Internet::Inference),
        (Some("full"), None, None) => Some(Internet::Full),
        (Some("sites"), None, None) => return Err("Add --sites with the sites the harness may reach, such as github.com,pypi.org.".into()),
        (Some("sites") | None, Some(sites), None) => Some(Internet::Sites(sites)),
        // The targets then come from the target question's answer.
        (Some("targets"), sites, None) => Some(Internet::Targets(Vec::new(), sites.unwrap_or_default())),
        (Some("targets") | None, sites, Some(targets)) => Some(Internet::Targets(targets, sites.unwrap_or_default())),
        (_, _, Some(_)) => return Err("--targets goes with --internet targets.".into()),
        (_, Some(_), None) => return Err("--sites goes with --internet sites or targets.".into()),
        (Some(_), None, None) => return Err(INTERNET_CHOICES.into()),
    })
}

const INTERNET_CHOICES: &str = "--internet takes inference (only this inference), sites (also the --sites), targets (also the --targets) or full (the whole internet as well).";

/// The launcher's own options `run` passes on as they are. Every other option the launcher knows
/// (its answers file, the VM's folder, size and reach, the model, the harness), in any spelling
/// it takes (`--internet=full`, `--int full`, `--answers-file`), would override what the person
/// answered and Yougori checked, so `run` takes none.
const PASSED_ON: &[&str] = &["--no-tty", "--no-browser"];

/// Takes the options `run` answers questions with out of `extra`; the launcher options it passes
/// on stay. Anything else is refused: a harness starts behind Yougori's own screen, which takes no
/// tool arguments (none after `--`), and no other option may reach the launcher.
fn permissions(extra: &mut Vec<String>) -> Result<Permissions, String> {
    if extra.iter().any(|arg| arg == "--") {
        return Err("yougori inference run passes nothing after -- to the harness: it runs behind Yougori's own screen, which takes no tool arguments. Leave out -- and what follows.".into());
    }
    let mut chosen = Permissions::default();
    let mut kept = Vec::new();
    let (mut mode, mut sites, mut targets) = (None, None, None);
    let mut i = 0;
    while i < extra.len() {
        let flag = extra[i].as_str();
        let needs_value = matches!(
            flag,
            "--workspace" | "--cpu" | "--memory" | "--internet" | "--sites" | "--targets" | "--harness" | "--model" | "--set"
        );
        let value = if needs_value {
            i += 1;
            Some(extra.get(i).ok_or_else(|| format!("{flag} needs a value."))?.as_str())
        } else {
            None
        };
        match (flag, value) {
            ("--workspace", Some(v)) => chosen.workspace = Some(project_folder(v)?),
            ("--cpu", Some(v)) => chosen.cpu = Some(count(v, 1, 255, "--cpu")?),
            ("--memory", Some(v)) => chosen.memory = Some(count(v, 1, 1024, "--memory")?),
            ("--internet", Some(v @ ("inference" | "sites" | "targets" | "full"))) => mode = Some(v.to_owned()),
            ("--internet", Some(_)) => return Err(INTERNET_CHOICES.into()),
            ("--sites", Some(v)) => sites = Some(site_names(v)?),
            ("--targets", Some(v)) => targets = Some(target_list(v)?),
            ("--harness", Some(v)) => {
                if chosen.harness.is_some() || !harness_name(v) {
                    return Err("Give --harness once, with a harness name such as opencode or strix.".into());
                }
                chosen.harness = Some(v.to_owned());
            }
            ("--model", Some(v)) => {
                if chosen.model.is_some() || v.is_empty() || v.chars().count() > 1024 || v.chars().any(char::is_control) {
                    return Err("Give --model once, with a model ID from the website.".into());
                }
                chosen.model = Some(v.to_owned());
            }
            ("--set", Some(v)) => chosen.sets.push(setting(v)?),
            ("--yes", None) => chosen.yes = true,
            (flag, None) if PASSED_ON.contains(&flag) => kept.push(flag.to_owned()),
            (other, _) => {
                return Err(format!(
                    "yougori inference run does not take {}. Its options: yougori inference --help",
                    plain_words(other)
                ))
            }
        }
        i += 1;
    }
    chosen.internet = reach_flags(mode.as_deref(), sites, targets)?;
    *extra = kept;
    Ok(chosen)
}

fn site_name(server: &str) -> &str {
    server.split_once("://").map_or(server, |(_, host)| host)
}

fn internet_words(internet: &Internet, server: &str) -> String {
    match internet {
        Internet::Inference => format!("only {}", site_name(server)),
        Internet::Sites(sites) => format!("{} and {}", site_name(server), sites.join(", ")),
        Internet::Targets(targets, sites) => format!(
            "{} and {}",
            site_name(server),
            targets.iter().chain(sites).cloned().collect::<Vec<_>>().join(", ")
        ),
        Internet::Full => format!("{} and the whole internet", site_name(server)),
    }
}

/// The Yougori harness: Yougori's own terminal agent, which also holds every other harness.
const YOUGORI: &str = "yougori";
/// Where a folder answer's copy is inside the VM: its workspace (vm_guest.py).
const VM_WORKSPACE: &str = "/run/yougori/workspace";
/// A secret answer reaches the launcher, and the VM, only as this variable plus its id in capitals.
const SECRET_VARIABLE: &str = "YOUGORI_SECRET_";

/// What a harness asks before it starts, as the website's catalogue describes each question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Text,
    Choice,
    /// Yes or no.
    Confirm,
    /// A folder on this computer, copied into the VM as its workspace.
    Folder,
    /// Typed masked; it reaches the VM only in its environment.
    Secret,
    /// Items separated by commas.
    List,
    /// The practice app inside the VM, or addresses to test.
    Target,
}

/// A named check of a typed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    Url,
    Host,
    Target,
    Path,
    Text,
}

#[derive(Clone, Debug, PartialEq)]
struct Pick {
    value: String,
    label: String,
    note: String,
}

/// When a question is asked: an earlier answer is given (or not), or is not a value.
#[derive(Clone, Debug, PartialEq)]
enum When {
    Present(String, bool),
    Not(String, String),
}

#[derive(Clone, Debug, PartialEq)]
struct Question {
    /// The answer's key in the answers file.
    id: String,
    kind: Kind,
    /// The menu's wording.
    question: String,
    note: String,
    required: bool,
    /// An example answer, shown under the question.
    placeholder: String,
    check: Option<Check>,
    choices: Vec<Pick>,
    default: Option<String>,
    /// A confirmation that must be yes, or nothing starts: `refusal` says so.
    must: bool,
    refusal: String,
    when: Option<When>,
    /// This folder's copy becomes the VM's workspace, and the folder question is skipped.
    workspace: bool,
    /// The answer sets what the VM may reach.
    reach: bool,
}

/// A harness the website lists.
#[derive(Clone, Debug, PartialEq)]
struct Harness {
    id: String,
    name: String,
    security: bool,
    description: String,
    /// It can start: offered by the administrator, its VM image published, and this CLI's
    /// launcher knows it and its questions.
    ready: bool,
    /// Why it cannot start, when it cannot.
    reason: String,
    questions: Vec<Question>,
    /// CPU cores and memory in GB its VM gets unless the person chooses.
    size: (u32, u32),
}

impl Harness {
    /// Its name in the list of harnesses.
    fn label(&self) -> String {
        if self.security {
            format!("{} (security)", self.name)
        } else {
            self.name.clone()
        }
    }

    fn question(&self, id: &str) -> Option<&Question> {
        self.questions.iter().find(|question| question.id == id)
    }
}

/// One question from the catalogue; an error names what this CLI cannot ask.
fn question(item: &Value) -> Result<Question, String> {
    let words = |key: &str, most: usize| -> Result<String, String> {
        match &item[key] {
            Value::Null => Ok(String::new()),
            Value::String(text) if text.chars().count() <= most && !text.chars().any(char::is_control) => Ok(text.trim().to_owned()),
            _ => Err(format!("an invalid {key}")),
        }
    };
    let flag = |key: &str| -> Result<bool, String> {
        match &item[key] {
            Value::Null => Ok(false),
            Value::Bool(value) => Ok(*value),
            _ => Err(format!("an invalid {key}")),
        }
    };
    let id = item["id"].as_str().filter(|id| answer_id(id)).ok_or("a question without a valid id")?.to_owned();
    let kind = match item["type"].as_str() {
        Some("text") => Kind::Text,
        Some("choice") => Kind::Choice,
        Some("confirm") => Kind::Confirm,
        Some("folder") => Kind::Folder,
        Some("secret") => Kind::Secret,
        Some("list") => Kind::List,
        Some("target") => Kind::Target,
        _ => return Err(format!("question {id} of a type this CLI does not know")),
    };
    let check = match &item["validate"] {
        Value::Null => None,
        Value::String(check) => Some(match check.as_str() {
            "url" => Check::Url,
            "host" => Check::Host,
            "target" => Check::Target,
            "path" => Check::Path,
            "text" => Check::Text,
            _ => return Err(format!("question {id} with a check this CLI does not know")),
        }),
        _ => return Err(format!("question {id} with an invalid check")),
    };
    let mut choices = Vec::new();
    match &item["choices"] {
        Value::Null => {}
        Value::Array(list) if list.len() <= 32 => {
            for pick in list {
                let value = pick["value"]
                    .as_str()
                    .filter(|value| (1..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
                    .ok_or_else(|| format!("question {id} with an invalid choice"))?;
                let label = pick["label"].as_str().map(plain_words).filter(|label| !label.is_empty()).ok_or_else(|| format!("question {id} with an unnamed choice"))?;
                if choices.iter().any(|known: &Pick| known.value == value) {
                    return Err(format!("question {id} with a choice twice"));
                }
                choices.push(Pick { value: value.to_owned(), label, note: pick["note"].as_str().map(plain_words).unwrap_or_default() });
            }
        }
        _ => return Err(format!("question {id} with invalid choices")),
    }
    let default = match &item["default"] {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Bool(yes) => Some(if *yes { "yes" } else { "no" }.to_owned()),
        _ => return Err(format!("question {id} with an invalid default")),
    };
    let when = match &item["when"] {
        Value::Null => None,
        Value::Object(when) => {
            let other = when.get("id").and_then(Value::as_str).filter(|other| answer_id(other)).ok_or_else(|| format!("question {id} with an invalid condition"))?;
            match (when.get("present").and_then(Value::as_bool), when.get("not").and_then(Value::as_str)) {
                (Some(present), None) => Some(When::Present(other.to_owned(), present)),
                (None, Some(not)) => Some(When::Not(other.to_owned(), not.to_owned())),
                _ => return Err(format!("question {id} with a condition this CLI does not know")),
            }
        }
        _ => return Err(format!("question {id} with an invalid condition")),
    };
    let reach = match &item["reach"] {
        Value::Null => false,
        Value::String(reach) if reach == "targets" => true,
        _ => return Err(format!("question {id} with a reach this CLI does not know")),
    };
    let asked = Question {
        question: words("question", 300)?,
        note: words("note", 300)?,
        required: flag("required")?,
        placeholder: words("placeholder", 300)?,
        must: flag("must")?,
        refusal: words("refusal", 300)?,
        workspace: flag("workspace")?,
        id,
        kind,
        check,
        choices,
        default,
        when,
        reach,
    };
    if asked.question.is_empty() || (kind == Kind::Choice && asked.choices.is_empty()) {
        return Err(format!("question {} without its wording or choices", asked.id));
    }
    Ok(asked)
}

/// Whether a question takes its default when nothing is asked (`--yes`, or no terminal): a
/// choice, a list, a plain text, or a confirmation that need not be yes. Never what the VM gets
/// or reaches (a folder copied in, a target, a reach, a path on this computer), a secret or a
/// must-confirm: the person gives those each time.
fn takes_default(question: &Question) -> bool {
    !question.reach
        && match question.kind {
            Kind::Choice | Kind::List => true,
            Kind::Confirm => !question.must,
            Kind::Text => !matches!(question.check, Some(Check::Path | Check::Target)),
            Kind::Folder | Kind::Secret | Kind::Target => false,
        }
}

/// Why a harness's questions cannot be asked.
#[derive(Debug, PartialEq)]
enum Unaskable {
    /// A question this CLI does not know how to ask (a newer website).
    Unknown(String),
    /// A question that would decide what only the person may: an answer chosen in advance for
    /// what the VM gets or reaches, or a yes that must be given but may be skipped.
    Unsafe(String),
}

/// A harness's questions, in the order they are asked. A condition names an earlier question;
/// at most one folder becomes the workspace, and every folder must (it is how a folder reaches
/// the VM). Only a question that [`takes_default`] has a default (a must-confirm's is never
/// taken), and a must-confirm is required.
fn questions(value: &Value) -> Result<Vec<Question>, Unaskable> {
    let list = match value {
        // A website from before questions: the harness asks none.
        Value::Null => return Ok(Vec::new()),
        Value::Array(list) if list.len() <= 32 => list,
        _ => return Err(Unaskable::Unknown("questions in an unknown form".into())),
    };
    let mut asked: Vec<Question> = Vec::new();
    for item in list {
        let next = question(item).map_err(Unaskable::Unknown)?;
        let earlier = |id: &str| asked.iter().any(|known| known.id == id);
        if earlier(&next.id) {
            return Err(Unaskable::Unknown(format!("question {} twice", next.id)));
        }
        if let Some(When::Present(other, _) | When::Not(other, _)) = &next.when {
            if !earlier(other) {
                return Err(Unaskable::Unknown(format!("question {} asked after a later question", next.id)));
            }
        }
        if (next.kind == Kind::Folder) != next.workspace
            || (next.workspace && asked.iter().any(|known| known.workspace))
            || (next.must && next.kind != Kind::Confirm)
            || (next.reach && next.kind != Kind::Target)
        {
            return Err(Unaskable::Unknown(format!("question {} this CLI cannot deliver", next.id)));
        }
        if next.default.is_some() && !takes_default(&next) && !(next.kind == Kind::Confirm && next.must) {
            return Err(Unaskable::Unsafe(format!("its question {} comes with an answer chosen in advance", next.id)));
        }
        if next.must && !next.required {
            return Err(Unaskable::Unsafe(format!("its question {} must be answered yes but may be skipped", next.id)));
        }
        asked.push(next);
    }
    Ok(asked)
}

/// A harness's VM size: CPU cores and memory in GB, or the defaults for its kind.
fn vm_size(value: &Value, security: bool) -> (u32, u32) {
    let (cpu, memory) = if security { (4, 8) } else { (2, 4) };
    let number = |key: &str, high: u64, fallback: u32| value[key].as_u64().filter(|n| (1..=high).contains(n)).map_or(fallback, |n| n as u32);
    (number("cpu", 255, cpu), number("memory", 1024, memory))
}

/// What a website without the Yougori harness says of every harness: this CLI starts each one
/// inside it.
const WEBSITE_BEFORE_HELD: &str = "This website does not start harnesses inside Yougori yet. Its administrator needs to update it.";

/// The website's answer to `GET /api/harnesses`. Every harness starts inside the Yougori harness
/// (`run yougori --harness NAME`), so its `held` says whether it can start here; `setup` is its own
/// VM image, which only older launchers start. A harness this CLI's launcher cannot start, or
/// whose questions it cannot ask (a newer website), is not ready, and says to update Yougori;
/// one whose questions would decide what only the person may says so.
fn harnesses(body: &[u8]) -> Result<Vec<Harness>, String> {
    let unexpected = || "The website listed its harnesses in an unexpected form.".to_string();
    if body.len() > 1 << 20 {
        return Err(unexpected());
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| unexpected())?;
    let known = launcher_harnesses();
    let mut listed: Vec<Harness> = Vec::new();
    for item in value["harnesses"].as_array().ok_or_else(unexpected)?.iter().take(256) {
        let id = item["id"].as_str().filter(|id| harness_name(id)).ok_or_else(unexpected)?.to_owned();
        if listed.iter().any(|harness| harness.id == id) {
            continue;
        }
        let name = item["name"].as_str().map(plain_words).filter(|name| !name.is_empty()).unwrap_or_else(|| id.clone());
        let security = item["category"] == "security";
        let asked = questions(&item["questions"]);
        let said = |state: &Value| state["reason"].as_str().map(plain_words).filter(|reason| !reason.is_empty());
        let held = &item["held"];
        let reason = if item["offered"] == false {
            said(held).or_else(|| said(&item["setup"])).unwrap_or_else(|| "The administrator of this inference has not offered this harness.".into())
        } else if !held.is_object() {
            WEBSITE_BEFORE_HELD.into()
        } else if held["available"] != true {
            said(held).unwrap_or_else(|| "The administrator has not made it ready here yet.".into())
        } else if !known.contains(&id) {
            format!("This version of Yougori cannot start {name}. Update Yougori: yougori update")
        } else {
            match &asked {
                Err(Unaskable::Unknown(_)) => format!("This version of Yougori cannot ask {name}'s questions. Update Yougori: yougori update"),
                Err(Unaskable::Unsafe(detail)) => {
                    format!("The website's questions for {name} are not safe to ask: {detail}. Its administrator needs to correct them.")
                }
                Ok(_) => String::new(),
            }
        };
        listed.push(Harness {
            ready: reason.is_empty(),
            reason,
            questions: asked.unwrap_or_default(),
            size: vm_size(&item["size"], security),
            description: item["description"].as_str().map(plain_words).unwrap_or_default(),
            id,
            name,
            security,
        });
    }
    Ok(listed)
}

/// The harnesses that can start, as the list shows them: Yougori first, then the coding ones,
/// then the security ones, each in the website's order.
fn startable(catalogue: &[Harness]) -> Vec<Harness> {
    let mut ready: Vec<Harness> = catalogue.iter().filter(|harness| harness.ready).cloned().collect();
    ready.sort_by_key(|harness| (harness.id != YOUGORI, harness.security));
    ready
}

/// The harness the command line names: HARNESS or `--harness`; `yougori` as HARNESS holds the
/// `--harness` one, or is Yougori's own agent.
fn named_harness(positional: &str, flag: Option<&str>) -> Result<Option<String>, String> {
    match (positional, flag) {
        ("", None) => Ok(None),
        ("" | YOUGORI, Some(flag)) => Ok(Some(flag.to_owned())),
        (named, None) => Ok(Some(named.to_owned())),
        (named, Some(flag)) if named == flag => Ok(Some(flag.to_owned())),
        _ => Err("Name the harness once: as HARNESS, or with --harness NAME.".into()),
    }
}

/// The harness `name` from the website's list when it can start; otherwise the website's reason,
/// or the harnesses it offers when it lists no such harness.
fn find_harness<'a>(catalogue: &'a [Harness], name: &str, site: &str) -> Result<&'a Harness, String> {
    match catalogue.iter().find(|harness| harness.id == name) {
        Some(harness) if harness.ready => Ok(harness),
        Some(harness) => Err(format!("{} cannot start here: {}", harness.name, harness.reason)),
        None => {
            let ready: Vec<String> = startable(catalogue).into_iter().map(|harness| harness.id).collect();
            Err(if ready.is_empty() {
                format!("{site} lists no harness {name}, and none is ready to start.")
            } else {
                format!("{site} lists no harness {name}. It offers: {}.", ready.join(", "))
            })
        }
    }
}

/// An answer to one of a harness's questions. Secrets are kept apart, in [`Plan::secrets`].
#[derive(Clone, Debug, PartialEq)]
enum Answer {
    /// A text, or the chosen choice's value.
    Text(String),
    Yes(bool),
    List(Vec<String>),
    /// A folder on this computer, copied into the VM as its workspace.
    Folder(PathBuf),
    /// Addresses to test, each as given, with the `host:port` the VM must reach for it.
    Targets(Vec<(String, String)>),
    /// The practice app Yougori starts inside the VM.
    Practice,
}

impl Answer {
    /// Whether the answer is `value`, for a condition's `not`.
    fn is(&self, value: &str) -> bool {
        match self {
            Answer::Text(text) => text == value,
            Answer::Yes(yes) => value == if *yes { "yes" } else { "no" },
            Answer::Practice => value == "practice",
            _ => false,
        }
    }

    /// The answer in the answers file the VM gets.
    fn json(&self) -> Value {
        match self {
            Answer::Text(text) => json!(text),
            Answer::Yes(yes) => json!(yes),
            Answer::List(items) => json!(items),
            Answer::Folder(_) => json!(VM_WORKSPACE),
            Answer::Targets(entries) => json!(entries.iter().map(|(entry, _)| entry).collect::<Vec<_>>()),
            Answer::Practice => json!("practice"),
        }
    }

    /// The answer in words.
    fn words(&self, question: &Question) -> String {
        match self {
            Answer::Text(value) => question
                .choices
                .iter()
                .find(|pick| &pick.value == value)
                .map_or_else(|| value.clone(), |pick| pick.label.clone()),
            Answer::Yes(yes) => if *yes { "Yes" } else { "No" }.to_owned(),
            Answer::List(items) => items.join(", "),
            Answer::Folder(folder) => folder.display().to_string(),
            Answer::Targets(entries) => entries.iter().map(|(entry, _)| entry.as_str()).collect::<Vec<_>>().join(", "),
            Answer::Practice => "the practice app inside the VM".to_owned(),
        }
    }
}

/// One line of text: no control characters, at most `most` characters.
fn check_text(value: &str, most: usize) -> Result<String, String> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        return Err("Use one line of plain text.".into());
    }
    if value.chars().count() > most {
        return Err(format!("Use at most {most} characters."));
    }
    Ok(value.to_owned())
}

/// A secret answer: 1 to 4096 characters on one line.
fn check_secret(value: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > 4096 || value.chars().any(char::is_control) {
        return Err("Give 1 to 4096 characters on one line.".into());
    }
    Ok(())
}

fn secret_variable(id: &str) -> String {
    format!("{SECRET_VARIABLE}{}", id.to_ascii_uppercase())
}

fn is_secret_variable(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().to_ascii_uppercase().starts_with(SECRET_VARIABLE)
}

fn secret_hint(question: &Question) -> String {
    format!(
        "{} is a secret: put it in the {} environment variable, never on the command line.",
        question.id,
        secret_variable(&question.id)
    )
}

fn refusal(question: &Question) -> String {
    if question.refusal.is_empty() {
        "Nothing was started.".to_owned()
    } else {
        question.refusal.clone()
    }
}

/// "a, b or c".
fn either(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// An answer to `question` from text, typed or given with `--set`. Empty is no answer, which only
/// an optional question takes; a must-confirm answered no is its refusal.
fn parse_answer(question: &Question, text: &str) -> Result<Option<Answer>, String> {
    let text = text.trim();
    if text.is_empty() {
        return if question.required { Err("This question needs an answer.".into()) } else { Ok(None) };
    }
    let targets = |text: &str| -> Result<Answer, String> {
        if text.eq_ignore_ascii_case("practice") {
            return Ok(Answer::Practice);
        }
        Ok(Answer::Targets(target_entries(text)?))
    };
    let answer = match question.kind {
        Kind::Text => match question.check.unwrap_or(Check::Text) {
            Check::Text => Answer::Text(check_text(text, 8000)?),
            Check::Url => {
                url_host(text)?;
                Answer::Text(text.to_owned())
            }
            Check::Host => Answer::Text(target_host(text)?),
            Check::Target => targets(text)?,
            Check::Path => Answer::Text(project_folder(text)?.display().to_string()),
        },
        Kind::List => {
            let items = text
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| check_text(item, 500))
                .collect::<Result<Vec<_>, _>>()?;
            if items.len() > 64 {
                return Err("Give at most 64 items.".into());
            }
            if items.is_empty() {
                return parse_answer(question, "");
            }
            Answer::List(items)
        }
        Kind::Choice => {
            let pick = question
                .choices
                .iter()
                .find(|pick| pick.value.eq_ignore_ascii_case(text) || pick.label.eq_ignore_ascii_case(text))
                .ok_or_else(|| format!("Choose {}.", either(&question.choices.iter().map(|pick| pick.value.as_str()).collect::<Vec<_>>())))?;
            Answer::Text(pick.value.clone())
        }
        Kind::Confirm => match text.to_ascii_lowercase().as_str() {
            "yes" | "y" | "true" => Answer::Yes(true),
            "no" | "n" | "false" if question.must => return Err(refusal(question)),
            "no" | "n" | "false" => Answer::Yes(false),
            _ => return Err("Answer yes or no.".into()),
        },
        Kind::Folder => Answer::Folder(project_folder(text)?),
        Kind::Target => targets(text)?,
        Kind::Secret => return Err(secret_hint(question)),
    };
    Ok(Some(answer))
}

/// An answer options gave one of a harness's questions: `--set ID=VALUE` (none when given empty),
/// `--workspace` for its workspace question, or a secret from its YOUGORI_SECRET_<ID> variable.
#[derive(Clone)]
enum Given {
    Answer(Option<Answer>),
    Secret(Zeroizing<String>),
}

/// One harness run, as it is answered.
#[derive(Default)]
struct Plan {
    harness: Option<Harness>,
    model: Option<String>,
    answers: BTreeMap<String, Answer>,
    /// Secret answers by question id: only ever in memory and the launcher's environment.
    secrets: BTreeMap<String, Zeroizing<String>>,
    /// The answers options gave, by question id. Those questions are not asked, and each answer
    /// comes back whenever its question applies again after an earlier answer changed.
    given: BTreeMap<String, Given>,
    /// The folder copied into the VM when no workspace question's answer gives one: `--workspace`,
    /// or the folder step's answer. [`folder`] is the one copied in.
    workspace: Option<PathBuf>,
    internet: Option<Internet>,
    cpu: Option<u32>,
    memory: Option<u32>,
}

impl Plan {
    fn chosen(&self) -> Result<&Harness, String> {
        self.harness.as_ref().ok_or_else(|| "Choose a harness first.".to_owned())
    }
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("harness", &self.harness.as_ref().map(|harness| &harness.id))
            .field("model", &self.model)
            .field("answers", &self.answers)
            // Never a secret's value: only which questions have one, or were given one.
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .field("given", &self.given.keys().collect::<Vec<_>>())
            .field("workspace", &self.workspace)
            .field("internet", &self.internet)
            .field("cpu", &self.cpu)
            .field("memory", &self.memory)
            .finish()
    }
}

/// The folder a workspace question's answer copies in.
fn workspace_answer(plan: &Plan) -> Option<PathBuf> {
    let harness = plan.harness.as_ref()?;
    harness.questions.iter().filter(|question| question.workspace).find_map(|question| match plan.answers.get(&question.id) {
        Some(Answer::Folder(folder)) => Some(folder.clone()),
        _ => None,
    })
}

/// The folder copied into the VM as its workspace: a workspace question's answer, else
/// `--workspace` or the folder step's answer.
fn folder(plan: &Plan) -> Option<PathBuf> {
    workspace_answer(plan).or_else(|| plan.workspace.clone())
}

/// What the launcher says of a folder for SWE-agent without its .git directory.
const GIT_REPOSITORY: &str = "SWE-agent needs a Git repository with its .git directory in the selected workspace.";

/// What `harness` needs of the folder copied in: SWE-agent works in a Git repository, so its
/// folder needs its .git directory, as the launcher checks. (Without a folder, its empty workspace
/// is made one.)
fn folder_check(harness: &Harness, folder: &Path) -> Result<(), String> {
    if harness.id == "swe" && !folder.join(".git").is_dir() {
        return Err(GIT_REPOSITORY.into());
    }
    Ok(())
}

/// The targets the VM must reach for the answers that set its reach (the practice app needs none).
fn reach_targets(plan: &Plan) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for question in plan.harness.iter().flat_map(|harness| &harness.questions).filter(|question| question.reach) {
        if let Some(Answer::Targets(entries)) = plan.answers.get(&question.id) {
            for (_, host) in entries {
                if !hosts.contains(host) {
                    hosts.push(host.clone());
                }
            }
        }
    }
    hosts
}

/// "harness asks no question X" with the ones it asks.
fn asks_no(harness: &Harness, id: &str) -> String {
    if harness.questions.is_empty() {
        return format!("{} asks no questions, so it takes no --set {id}.", harness.name);
    }
    let ids: Vec<&str> = harness.questions.iter().map(|question| question.id.as_str()).collect();
    format!("{} asks no question {id}. Its questions: {}.", harness.name, ids.join(", "))
}

/// What a security harness is told when an option would let its VM reach more than its target.
fn security_reach(harness: &Harness) -> String {
    format!(
        "{} reaches only its target and this inference: it takes no --sites, no --targets and no --internet sites or full. The target question names what it tests.",
        harness.name
    )
}

/// Whether a reach given with options keeps a security harness to its target: none, only the
/// inference, or `--internet targets` alone (the target answer's hosts).
fn within_target(internet: Option<&Internet>) -> bool {
    match internet {
        None | Some(Internet::Inference) => true,
        Some(Internet::Targets(hosts, sites)) => hosts.is_empty() && sites.is_empty(),
        Some(Internet::Sites(_) | Internet::Full) => false,
    }
}

/// A run of `harness` with the answers options give: `--set ID=VALUE`, `--workspace` for its
/// workspace folder question, and YOUGORI_SECRET_<ID> variables (read with `environment`) for its
/// secrets. An option it cannot use is an error, so a script never runs with an answer it did not
/// mean: a security harness reaches only its target, and SWE-agent's folder is a Git repository.
fn plan_for(harness: &Harness, chosen: &Permissions, environment: &dyn Fn(&str) -> Option<Zeroizing<String>>) -> Result<Plan, String> {
    if harness.security && !within_target(chosen.internet.as_ref()) {
        return Err(security_reach(harness));
    }
    let mut plan = Plan {
        harness: Some(harness.clone()),
        model: chosen.model.clone(),
        workspace: chosen.workspace.clone(),
        internet: chosen.internet.clone(),
        cpu: chosen.cpu,
        memory: chosen.memory,
        ..Plan::default()
    };
    for (id, value) in &chosen.sets {
        let question = harness.question(id).ok_or_else(|| asks_no(harness, id))?;
        if question.kind == Kind::Secret {
            return Err(secret_hint(question));
        }
        if plan.given.contains_key(id) {
            return Err(format!("Give --set {id} once."));
        }
        let answer = parse_answer(question, value).map_err(|problem| format!("--set {id}: {problem}"))?;
        if let Some(answer) = &answer {
            plan.answers.insert(id.clone(), answer.clone());
        }
        plan.given.insert(id.clone(), Given::Answer(answer));
    }
    for question in &harness.questions {
        if question.workspace {
            match (plan.answers.get(&question.id), &chosen.workspace) {
                (Some(Answer::Folder(set)), Some(folder)) if set != folder => {
                    return Err(format!("--set {} and --workspace name different folders; give the folder once.", question.id));
                }
                (None, Some(_)) if plan.given.contains_key(&question.id) => {
                    return Err(format!("--set {}= gives no folder but --workspace gives one; give the folder once.", question.id));
                }
                (None, Some(folder)) => {
                    let answer = Answer::Folder(folder.clone());
                    plan.answers.insert(question.id.clone(), answer.clone());
                    plan.given.insert(question.id.clone(), Given::Answer(Some(answer)));
                }
                _ => {}
            }
        }
        if question.kind == Kind::Secret {
            let name = secret_variable(&question.id);
            if let Some(value) = environment(&name).filter(|value| !value.is_empty()) {
                check_secret(&value).map_err(|problem| format!("{name}: {problem}"))?;
                plan.secrets.insert(question.id.clone(), value.clone());
                plan.given.insert(question.id.clone(), Given::Secret(value));
            }
        }
    }
    if let Some(folder) = folder(&plan) {
        folder_check(harness, &folder)?;
    }
    Ok(plan)
}

/// Whether `question` is asked, given the answers so far.
fn applies(question: &Question, plan: &Plan) -> bool {
    match &question.when {
        None => true,
        Some(When::Present(other, present)) => (plan.answers.contains_key(other) || plan.secrets.contains_key(other)) == *present,
        Some(When::Not(other, value)) => !plan.answers.get(other).is_some_and(|answer| answer.is(value)),
    }
}

/// Drops the answer to a question that is no longer asked. An answer options gave stays in
/// [`Plan::given`], for [`restore`].
fn forget(plan: &mut Plan, question: &Question) {
    plan.answers.remove(&question.id);
    plan.secrets.remove(&question.id);
}

/// Puts back the answer options gave `question`, as it applies again after an earlier answer
/// changed; whether options answered it (then it is not asked).
fn restore(plan: &mut Plan, question: &Question) -> bool {
    match plan.given.get(&question.id) {
        Some(Given::Answer(Some(answer))) => {
            plan.answers.insert(question.id.clone(), answer.clone());
        }
        Some(Given::Answer(None)) => {
            plan.answers.remove(&question.id);
        }
        Some(Given::Secret(value)) => {
            plan.secrets.insert(question.id.clone(), value.clone());
        }
        None => return false,
    }
    true
}

/// Whether the menu skips `question` now: an earlier answer leaves it out (its answer is
/// dropped), or options answered it (their answer is put back, as it may have been dropped when
/// an earlier answer left the question out before Back changed that answer).
fn skipped(plan: &mut Plan, question: &Question) -> bool {
    if !applies(question, plan) {
        forget(plan, question);
        return true;
    }
    restore(plan, question)
}

/// Drops the answers of the questions that do not apply, in order, as the menu leaves them.
fn prune(plan: &mut Plan) {
    let Some(harness) = plan.harness.clone() else { return };
    for question in &harness.questions {
        if !applies(question, plan) {
            forget(plan, question);
        }
    }
}

/// The first question that applies without the answer it needs: a required one without any, a
/// must-confirm without its yes. Nothing starts while there is one.
fn unanswered(plan: &Plan) -> Option<&Question> {
    plan.harness.as_ref()?.questions.iter().find(|question| {
        let answered = plan.answers.contains_key(&question.id) || plan.secrets.contains_key(&question.id);
        applies(question, plan)
            && ((question.must && plan.answers.get(&question.id) != Some(&Answer::Yes(true))) || (question.required && !answered))
    })
}

/// What to add when a question has no answer and nothing can be asked.
fn missing(harness: &Harness, question: &Question) -> String {
    let (name, asked, id) = (&harness.name, &question.question, &question.id);
    match question.kind {
        Kind::Secret => format!(
            "{name} needs an answer to \"{asked}\": put it in the {} environment variable (never on the command line).",
            secret_variable(id)
        ),
        Kind::Confirm if question.must => format!("{name} starts only after a yes to \"{asked}\": add --set {id}=yes."),
        Kind::Target => format!("{name} needs an answer to \"{asked}\": add --set {id}=URL, or --set {id}=practice for the practice app inside the VM."),
        Kind::Folder => format!("{name} needs an answer to \"{asked}\": add --set {id}=PATH."),
        Kind::Choice => format!(
            "{name} needs an answer to \"{asked}\": add --set {id}={}.",
            question.choices.iter().map(|pick| pick.value.as_str()).collect::<Vec<_>>().join("|")
        ),
        Kind::Confirm => format!("{name} needs an answer to \"{asked}\": add --set {id}=yes or --set {id}=no."),
        Kind::Text | Kind::List => format!("{name} needs an answer to \"{asked}\": add --set {id}=TEXT."),
    }
}

/// Without questions (`--yes`, or no terminal): each question that applies keeps the answer
/// options gave or takes its default when it [`takes_default`]; a required one with neither is an
/// error naming the option to add. A must-confirm, a folder, a target and a secret never take one.
fn settle(plan: &mut Plan) -> Result<(), String> {
    let harness = plan.chosen()?.clone();
    for question in &harness.questions {
        if !applies(question, plan) {
            forget(plan, question);
            continue;
        }
        // An optional question given empty with --set is answered: skipped.
        if restore(plan, question) || plan.answers.contains_key(&question.id) || plan.secrets.contains_key(&question.id) {
            continue;
        }
        let default = match question.default.as_deref() {
            Some(default) if takes_default(question) => parse_answer(question, default)?,
            _ => None,
        };
        match default {
            Some(answer) => {
                plan.answers.insert(question.id.clone(), answer);
            }
            None if question.required || question.must => return Err(missing(&harness, question)),
            None => {}
        }
    }
    Ok(())
}

/// The model: the one given, or the only one; several without a choice is an error.
fn pick_model(list: &[String], given: Option<&str>, site: &str) -> Result<String, String> {
    match given {
        _ if list.is_empty() => Err(format!("{site} has no models for your key yet. Its administrator connects them in Admin.")),
        Some(model) if list.iter().any(|known| known == model) => Ok(model.to_owned()),
        Some(model) => Err(format!("{site} has no model {model} for your key. It has: {}.", list.join(", "))),
        None if list.len() == 1 => Ok(list[0].clone()),
        None => Err(format!("Choose the model with --model ID. {site} has: {}.", list.join(", "))),
    }
}

/// Whether the full-internet card reaches a target (`host` or `host:port`): Yougori's filter holds
/// it to the public internet, so never a private, shared, reserved or cloud management address,
/// nor a single-label name, which names a computer on a local network.
fn on_public_internet(target: &str) -> bool {
    let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..128).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..32).contains(&b))
                || (a, b) == (192, 168)
                || (a, b & 0xfe) == (198, 18)
                || matches!((a, b, c), (192, 0, 0) | (192, 0, 2) | (198, 51, 100) | (203, 0, 113) | (192, 88, 99))
                || address.octets() == [168, 63, 129, 16])
        }
        Err(_) => host.contains('.'),
    }
}

/// What the whole internet is told for a target it does not reach.
fn off_the_internet(target: &str) -> String {
    format!(
        "The whole internet leaves out {target}: Yougori holds a full-internet VM to the public internet, never a private network. Choose the target and this inference instead (--internet targets)."
    )
}

/// The reach the VM gets. A security harness reaches only its target and this inference: the
/// practice app inside the VM needs only the inference, addresses exactly their hosts. Another
/// harness gets the reach chosen or given, always with the target question's hosts when a target
/// is outside the VM (`--targets` and sites go beside them); without a choice, only the
/// inference, or only that target and the inference.
fn resolve_reach(plan: &Plan) -> Result<Internet, String> {
    let harness = plan.chosen()?;
    let targets = reach_targets(plan);
    if harness.security {
        if !within_target(plan.internet.as_ref()) {
            return Err(security_reach(harness));
        }
        return match (&plan.internet, targets.is_empty()) {
            (Some(Internet::Targets(..)), true) => {
                Err("--internet targets needs a target outside the VM: answer the target question with an address.".into())
            }
            (Some(Internet::Inference), false) => Err(format!(
                "--internet inference leaves {}'s target out of reach: leave it out, and {} reaches the target and this inference.",
                harness.name, harness.name
            )),
            (_, true) => Ok(Internet::Inference),
            (_, false) => Ok(Internet::Targets(targets, Vec::new())),
        };
    }
    match plan.internet.clone() {
        Some(Internet::Targets(given, sites)) => {
            let mut list = targets;
            for host in given {
                if !list.contains(&host) {
                    list.push(host);
                }
            }
            if list.is_empty() {
                return Err("--internet targets needs a target outside the VM: answer the target question with an address, or add --targets HOST:PORT.".into());
            }
            if list.len() > 64 {
                return Err("The VM reaches at most 64 targets: name fewer with --targets.".into());
            }
            Ok(Internet::Targets(list, sites))
        }
        Some(Internet::Sites(sites)) if !targets.is_empty() => Ok(Internet::Targets(targets, sites)),
        Some(Internet::Full) => match targets.iter().find(|target| !on_public_internet(target)) {
            Some(target) => Err(off_the_internet(target)),
            None => Ok(Internet::Full),
        },
        Some(other) => Ok(other),
        None if !targets.is_empty() => Ok(Internet::Targets(targets, Vec::new())),
        None => Ok(Internet::Inference),
    }
}

/// This computer's CPU cores and memory in GB (at most 255 and 1024), or the harness's defaults
/// when the engine does not say.
fn capacity(host: &Value, cpu: u32, memory: u32) -> (u32, u32) {
    let most = |key: &str, ceiling: f64, fallback: u32| {
        host[key]
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 1.0)
            .map_or(fallback, |value| value.min(ceiling).floor() as u32)
    };
    (most("totalCpu", 255.0, cpu), most("totalMemoryGb", 1024.0, memory).max(2))
}

/// The VM's size where none was chosen: the harness's default, within this computer.
fn settle_size(plan: &mut Plan, host: &Value) {
    let (cpu, memory) = plan.harness.as_ref().map_or((2, 4), |harness| harness.size);
    let (cpu_most, memory_most) = capacity(host, cpu, memory);
    plan.cpu.get_or_insert(cpu.min(cpu_most));
    plan.memory.get_or_insert(memory.min(memory_most));
}

/// What the person is told when the VM reaches a host by its name: Yougori holds the card to the
/// addresses the name resolves to, which other sites may share (a CDN, shared hosting). Mirrors
/// vm_host.SHARED_ADDRESSES.
const NAMED_HOSTS: &str = "A host named by its name is held to its addresses: other sites there are refused over HTTPS and HTTP, which name the site they ask for, but other kinds of connection, such as SSH, reach whatever answers at those addresses on the chosen ports.";

/// Whether the VM reaches a target by its name rather than an IPv4 address.
fn named_target(target: &str) -> bool {
    let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
    host.parse::<std::net::Ipv4Addr>().is_err()
}

/// What can keep a run from starting, said where Back can change it: a question that applies
/// without the answer it needs, a reach that cannot be, or a folder its harness cannot work in.
/// Otherwise the reach the VM gets.
fn start_check(plan: &Plan) -> Result<Internet, String> {
    let harness = plan.chosen()?;
    if let Some(question) = unanswered(plan) {
        return Err(format!("{} needs an answer to \"{}\" first.", harness.name, question.question));
    }
    if let Some(folder) = folder(plan) {
        folder_check(harness, &folder)?;
    }
    resolve_reach(plan)
}

/// The lines that sum up a run before it starts, with what the VM reaches when it can start.
fn summary(plan: &Plan, server: &str, reach: Option<&Internet>) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(harness) = &plan.harness else { return lines };
    if harness.security {
        for question in harness.questions.iter().filter(|question| question.kind == Kind::Target || question.id == "depth") {
            if let Some(answer) = plan.answers.get(&question.id) {
                let label = if question.kind == Kind::Target { "Target" } else { "Depth" };
                lines.push(format!("{label}: {}", answer.words(question)));
            }
        }
    }
    let folder = folder(plan);
    lines.push(format!(
        "Folder: {}",
        folder.as_ref().map_or("none (an empty workspace)".to_owned(), |folder| format!("a copy of {}", folder.display()))
    ));
    if let Some(reach) = reach {
        lines.push(format!("Reaches: {}", internet_words(reach, server)));
        if matches!(reach, Internet::Targets(targets, _) if targets.iter().any(|target| named_target(target))) {
            lines.push(NAMED_HOSTS.to_owned());
        }
    }
    let (cpu, memory) = harness.size;
    lines.push(format!("Size: {} CPU, {} GB memory", plan.cpu.unwrap_or(cpu), plan.memory.unwrap_or(memory)));
    if harness.security {
        lines.push(
            if folder.is_some() { "Report: saved to your folder after review" } else { "Report: shown here only; choose a folder to keep it" }.to_owned(),
        );
    }
    lines
}

/// The answers file the VM gets: every answer but the secrets.
fn answers_json(plan: &Plan) -> Value {
    Value::Object(plan.answers.iter().map(|(id, answer)| (id.clone(), answer.json())).collect())
}

/// The secret answers, as the launcher's environment variables.
fn secret_variables(plan: &Plan) -> Vec<(String, Zeroizing<String>)> {
    plan.secrets.iter().map(|(id, value)| (secret_variable(id), value.clone())).collect()
}

/// The launcher's command line for a run: `run yougori` holding the chosen harness, with its
/// model, the answers file, the folder, the size and the reach. Secrets are never in it.
fn launch_arguments(plan: &Plan, server: &str, answers: &Path) -> Result<Vec<String>, String> {
    let harness = plan.chosen()?;
    let model = plan.model.as_deref().ok_or("Choose a model first.")?;
    let mut arguments: Vec<String> = ["run", YOUGORI, "--server", server, "--harness", &harness.id, "--model", model, "--answers-file"]
        .map(str::to_owned)
        .to_vec();
    arguments.push(answers.display().to_string());
    if let Some(folder) = folder(plan) {
        arguments.extend(["--workspace".to_owned(), folder.display().to_string()]);
    }
    if let Some(cpu) = plan.cpu {
        arguments.extend(["--cpu".to_owned(), cpu.to_string()]);
    }
    if let Some(memory) = plan.memory {
        arguments.extend(["--memory".to_owned(), memory.to_string()]);
    }
    let reach = resolve_reach(plan)?;
    arguments.extend(["--internet".to_owned(), reach.flag().to_owned()]);
    match &reach {
        Internet::Sites(sites) => arguments.extend(["--sites".to_owned(), sites.join(",")]),
        Internet::Targets(targets, sites) => {
            arguments.extend(["--targets".to_owned(), targets.join(",")]);
            if !sites.is_empty() {
                arguments.extend(["--sites".to_owned(), sites.join(",")]);
            }
        }
        Internet::Inference | Internet::Full => {}
    }
    Ok(arguments)
}

/// The launcher's command line for `install HARNESS`: the Yougori harness's images that a run
/// starts HARNESS from (`install yougori --harness HARNESS`: the base it starts on and its pack;
/// `install yougori`: Yougori's own agent, which needs only the base), never the harness's own
/// older image. Only for a harness the website can start inside the Yougori harness, found as a
/// run finds it: by its `held`, never by its own image's `setup`.
fn install_arguments(catalogue: &[Harness], harness: &str, server: &str) -> Result<Vec<String>, String> {
    find_harness(catalogue, harness, site_name(server))?;
    let mut arguments: Vec<String> = ["install", YOUGORI, "--server", server].map(str::to_owned).to_vec();
    if harness != YOUGORI {
        arguments.extend(["--harness".to_owned(), harness.to_owned()]);
    }
    Ok(arguments)
}

/// The notes under a question: its own, an example answer, and that an optional one can be skipped.
fn notes(question: &Question) -> Vec<String> {
    let mut lines = Vec::new();
    if !question.note.is_empty() {
        lines.push(question.note.clone());
    }
    if !question.placeholder.is_empty() && matches!(question.kind, Kind::Text | Kind::List) {
        lines.push(format!("Such as {}", question.placeholder));
    }
    if !question.required && matches!(question.kind, Kind::Text | Kind::List | Kind::Secret) {
        lines.push("Optional: Enter skips it.".to_owned());
    }
    lines
}

/// The choices of a target question: the practice app, or addresses typed in.
fn target_picks(question: &Question) -> Vec<Pick> {
    if question.choices.iter().any(|pick| pick.value == "practice") && question.choices.iter().any(|pick| pick.value != "practice") {
        return question.choices.clone();
    }
    vec![
        Pick {
            value: "practice".into(),
            label: "A practice app inside the VM".into(),
            note: "a deliberately vulnerable app Yougori starts inside the VM, safe to try".into(),
        },
        Pick {
            value: "address".into(),
            label: "A website or address I give".into(),
            note: "http(s) URLs, host:port or IPv4 addresses, separated by commas".into(),
        },
    ]
}

/// Which harness: the ones that can start, Yougori first, coding then security. Choosing another
/// harness starts its answers again from the options given.
fn choose_harness(
    plan: &mut Plan,
    offered: &[Harness],
    preselect: Option<&str>,
    chosen: &Permissions,
    environment: &dyn Fn(&str) -> Option<Zeroizing<String>>,
) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let choices: Vec<Choice> = offered.iter().map(|harness| Choice::new(harness.label(), harness.description.clone())).collect();
    let current = plan.harness.as_ref().map(|harness| harness.id.as_str()).or(preselect);
    let initial = current.and_then(|id| offered.iter().position(|harness| harness.id == id)).unwrap_or(0);
    let harness = &offered[ui::select("Which harness?", &[], &choices, initial)?];
    if plan.harness.as_ref().is_none_or(|before| before.id != harness.id) {
        *plan = plan_for(harness, chosen, environment)?;
    }
    Ok(true)
}

/// Which model: from the person's models on the website (signing in first when needed), one
/// still shown to confirm; `--model` answers it.
async fn choose_model(plan: &mut Plan, given: Option<&str>, models: &mut Models<'_>) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let id = plan.chosen()?.id.clone();
    let list = models.of(&id).await?;
    if given.is_some() || list.is_empty() {
        plan.model = Some(pick_model(&list, given, site_name(models.server))?);
        return Ok(false);
    }
    let choices: Vec<Choice> = list.iter().map(|model| Choice::new(model.clone(), "")).collect();
    let initial = plan.model.as_ref().and_then(|model| list.iter().position(|known| known == model)).unwrap_or(0);
    plan.model = Some(list[ui::select("Which model?", &[], &choices, initial)?].clone());
    Ok(true)
}

/// One of the harness's own questions, unless options answered it (their answer comes back if
/// an earlier answer had left the question out) or an earlier answer leaves it out.
fn ask_question(plan: &mut Plan, index: usize) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let Some(question) = plan.harness.as_ref().and_then(|harness| harness.questions.get(index)).cloned() else {
        return Ok(false);
    };
    if skipped(plan, &question) {
        return Ok(false);
    }
    let notes = notes(&question);
    if question.kind == Kind::Secret {
        let secret = ui::masked(&question.question, &notes, &|entry| match entry {
            "" if question.required => Err("This question needs an answer.".into()),
            "" => Ok(()),
            entry => check_secret(entry),
        })?;
        if secret.is_empty() {
            plan.secrets.remove(&question.id);
        } else {
            plan.secrets.insert(question.id.clone(), secret);
        }
        return Ok(true);
    }
    let previous = plan.answers.get(&question.id).cloned();
    let answer = match question.kind {
        Kind::Choice => choose_answer(&question, &notes, previous.as_ref())?,
        Kind::Confirm => confirm_answer(&question, &notes, previous.as_ref())?,
        Kind::Target => target_answer(&question, &notes, previous.as_ref())?,
        Kind::Folder => {
            let before = match &previous {
                Some(Answer::Folder(folder)) => Some(folder),
                _ => None,
            };
            let none = (!question.required).then(|| Choice::new("None", "nothing is copied in"));
            let harness = plan.chosen()?;
            pick_folder(&question.question, &notes, none, "a copy goes into the VM as its workspace", before, &|folder| folder_check(harness, folder))?
                .map(Answer::Folder)
        }
        Kind::Text | Kind::List | Kind::Secret => typed_answer(&question, &notes, previous.as_ref())?,
    };
    match answer {
        Some(answer) => plan.answers.insert(question.id.clone(), answer),
        None => plan.answers.remove(&question.id),
    };
    Ok(true)
}

fn typed_answer(question: &Question, notes: &[String], previous: Option<&Answer>) -> Result<Option<Answer>, String> {
    let initial = match previous {
        Some(Answer::Text(text)) => text.clone(),
        Some(Answer::List(items)) => items.join(", "),
        Some(Answer::Targets(entries)) => entries.iter().map(|(entry, _)| entry.as_str()).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    };
    let parsed = std::cell::RefCell::new(None);
    let typed = crate::cli_ui::input_noted(&question.question, notes, &initial, &|value: &str| {
        let answer = parse_answer(question, value)?;
        let words = answer.as_ref().map_or_else(|| "none".to_owned(), |answer| answer.words(question));
        *parsed.borrow_mut() = Some(answer);
        Ok(words)
    });
    typed?;
    Ok(parsed.into_inner().flatten())
}

fn choose_answer(question: &Question, notes: &[String], previous: Option<&Answer>) -> Result<Option<Answer>, String> {
    use crate::cli_ui::{self as ui, Choice};
    let mut choices: Vec<Choice> = question
        .choices
        .iter()
        .map(|pick| Choice::new(pick.label.clone(), pick.note.clone()).recommended(question.default.as_deref() == Some(pick.value.as_str())))
        .collect();
    if !question.required {
        choices.push(Choice::new("None", "skip this question"));
    }
    let current = match previous {
        Some(Answer::Text(value)) => Some(value.as_str()),
        _ => question.default.as_deref(),
    };
    let initial = current.and_then(|value| question.choices.iter().position(|pick| pick.value == value)).unwrap_or(0);
    let picked = ui::select(&question.question, notes, &choices, initial)?;
    Ok(question.choices.get(picked).map(|pick| Answer::Text(pick.value.clone())))
}

/// Where a yes-or-no question's cursor starts (0 Yes, 1 No): on the earlier answer; without one,
/// on No for a must-confirm, so a stray or held Enter never gives its yes, and otherwise on its
/// default (Yes unless that is no).
fn confirm_initial(question: &Question, previous: Option<&Answer>) -> usize {
    let no = match previous {
        Some(answer) => *answer != Answer::Yes(true),
        None => question.must || question.default.as_deref() == Some("no"),
    };
    usize::from(no)
}

fn confirm_answer(question: &Question, notes: &[String], previous: Option<&Answer>) -> Result<Option<Answer>, String> {
    use crate::cli_ui::{self as ui, Choice};
    let choices = [Choice::new("Yes", ""), Choice::new("No", if question.must { "nothing is started" } else { "" })];
    match ui::select(&question.question, notes, &choices, confirm_initial(question, previous))? {
        0 => Ok(Some(Answer::Yes(true))),
        _ if question.must => Err(crate::wire::cancelled(&refusal(question))),
        _ => Ok(Some(Answer::Yes(false))),
    }
}

/// A target question: the practice app inside the VM, or addresses typed in (with Back from the
/// addresses to the choice).
fn target_answer(question: &Question, notes: &[String], previous: Option<&Answer>) -> Result<Option<Answer>, String> {
    use crate::cli_ui::{self as ui, Choice};
    let picks = target_picks(question);
    let mut choices: Vec<Choice> = picks.iter().map(|pick| Choice::new(pick.label.clone(), pick.note.clone())).collect();
    if !question.required {
        choices.push(Choice::new("None", "skip this question"));
    }
    let practice = picks.iter().position(|pick| pick.value == "practice").unwrap_or(0);
    let mut picked = match previous {
        Some(Answer::Targets(_)) => picks.iter().position(|pick| pick.value != "practice").unwrap_or(0),
        _ => practice,
    };
    let before = match previous {
        Some(Answer::Targets(entries)) => entries.iter().map(|(entry, _)| entry.as_str()).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    };
    let mut addresses = None;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::select(&question.question, notes, &choices, picked).map(|index| {
                picked = index;
                true
            }),
            1 if picked != practice && picked < picks.len() => {
                let mut lines = vec![picks[picked].note.clone()];
                if !question.placeholder.is_empty() {
                    lines.push(format!("Such as {}", question.placeholder));
                }
                let parsed = std::cell::RefCell::new(None);
                let typed = ui::input_noted("Website or address to test", &lines, &before, &|value: &str| {
                    let entries = target_entries(value)?;
                    let words = entries.iter().map(|(entry, _)| entry.as_str()).collect::<Vec<_>>().join(", ");
                    *parsed.borrow_mut() = Some(entries);
                    Ok(words)
                });
                typed.map(|_| {
                    addresses = parsed.into_inner().map(Answer::Targets);
                    true
                })
            }
            1 => Ok(false),
            _ => break,
        };
        steps.next(asked)?;
    }
    Ok(match picks.get(picked) {
        Some(pick) if pick.value == "practice" => Some(Answer::Practice),
        Some(_) => addresses,
        None => None,
    })
}

/// A folder from a list: none (when `none` is offered), this folder, or another one typed in, with
/// Back from the typed path to the list. `copied` says what happens to the copy; `check` is what
/// the harness needs of a folder: this folder cannot be chosen when it falls short, and says why,
/// and a folder typed in is refused in place.
fn pick_folder(
    question: &str,
    notes: &[String],
    none: Option<crate::cli_ui::Choice>,
    copied: &str,
    current: Option<&PathBuf>,
    check: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<Option<PathBuf>, String> {
    use crate::cli_ui::{self as ui, Choice};
    let here = std::env::current_dir()
        .ok()
        .and_then(|folder| project_folder(&folder.to_string_lossy()).ok());
    let offers_none = none.is_some();
    let mut choices: Vec<Choice> = none.into_iter().collect();
    if let Some(here) = &here {
        let label = format!("This folder: {}", here.display());
        choices.push(match check(here) {
            Ok(()) => Choice::new(label, copied),
            Err(problem) => Choice::new(label, problem).disabled(),
        });
    }
    choices.push(Choice::new("Another folder", "type the path of a folder to copy in"));
    let another = choices.len() - 1;
    let mut picked = match current {
        None => 0,
        Some(folder) if Some(folder) == here.as_ref() => usize::from(offers_none),
        Some(_) => another,
    };
    let before = current.filter(|folder| Some(*folder) != here.as_ref()).map(|folder| folder.display().to_string()).unwrap_or_default();
    let mut typed = None;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::select(question, notes, &choices, picked).map(|index| {
                picked = index;
                true
            }),
            1 if picked == another => ui::input_prefilled("Folder to copy into the VM", &before, &|value: &str| {
                let folder = project_folder(value)?;
                check(&folder)?;
                Ok(folder.display().to_string())
            })
            .map(|folder| {
                typed = Some(PathBuf::from(folder));
                true
            }),
            1 => Ok(false),
            _ => break,
        };
        steps.next(asked)?;
    }
    Ok(if picked == another {
        typed
    } else if offers_none && picked == 0 {
        None
    } else {
        here
    })
}

/// The folder copied into the VM, unless a workspace question or `--workspace` chose it. For a
/// security harness the folder is where its report comes back.
fn choose_folder(plan: &mut Plan, chosen: &Permissions) -> Result<bool, String> {
    use crate::cli_ui::Choice;
    if chosen.workspace.is_some() || workspace_answer(plan).is_some() {
        return Ok(false);
    }
    let harness = plan.chosen()?;
    let check = |folder: &Path| folder_check(harness, folder);
    let folder = if harness.security {
        pick_folder(
            "Where should the report go?",
            &[],
            Some(Choice::new("No folder", "the report shows here but is not kept")),
            "a copy goes into the VM; the report comes back after you review it",
            plan.workspace.as_ref(),
            &check,
        )?
    } else {
        pick_folder(
            "What should the harness work on?",
            &[],
            Some(Choice::new("No folder", "the harness starts in an empty workspace; nothing on this PC is copied in")),
            "a copy goes into the VM; changes come back only after you review them",
            plan.workspace.as_ref(),
            &check,
        )?
    };
    plan.workspace = folder;
    Ok(true)
}

/// What the VM may reach besides the inference, for a harness that is not a security one (a
/// security harness reaches only its target and this inference: nothing to ask). For a target
/// outside the VM: only that target (preset), sites as well, or the whole internet when it
/// reaches the target; otherwise only the inference, sites, or the whole internet.
fn choose_reach(plan: &mut Plan, chosen: &Permissions, server: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    if chosen.internet.is_some() || plan.chosen()?.security {
        return Ok(false);
    }
    let site = site_name(server);
    let mut notes = vec![format!(
        "Prompts and replies always go to {site}. Yougori relays them and keeps the API key outside the VM."
    )];
    let targets = reach_targets(plan);
    let mut choices = if targets.is_empty() {
        vec![
            Choice::new("Only this inference", format!("{site} and nothing else")).recommended(true),
            Choice::new(
                "This inference and sites I choose",
                "such as github.com or pypi.org, over HTTPS; the VM still has no network card",
            ),
            Choice::new(
                "The whole internet as well",
                "any website, such as package downloads; the harness could also send what it reads to any site",
            ),
        ]
    } else {
        if targets.iter().any(|target| named_target(target)) {
            notes.push(NAMED_HOSTS.to_owned());
        }
        vec![
            Choice::new("Only the target and this inference", format!("{} and {site}", targets.join(", "))).recommended(true),
            Choice::new("The target, this inference and sites I choose", "such as github.com or pypi.org, over HTTPS"),
        ]
    };
    // The whole internet is the public internet alone, so it is offered with a target only when
    // it reaches every target.
    if !targets.is_empty() && targets.iter().all(|target| on_public_internet(target)) {
        choices.push(Choice::new(
            "The whole internet as well",
            "any website or address; the harness could also send what it reads to any site",
        ));
    }
    let mut picked = match &plan.internet {
        Some(Internet::Sites(_)) => 1,
        Some(Internet::Targets(_, sites)) if !sites.is_empty() => 1,
        Some(Internet::Full) if choices.len() > 2 => 2,
        _ => 0,
    };
    let before = match &plan.internet {
        Some(Internet::Sites(sites) | Internet::Targets(_, sites)) => sites.join(", "),
        _ => String::new(),
    };
    let mut sites = Vec::new();
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => ui::select("What can the harness reach?", &notes, &choices, picked).map(|index| {
                picked = index;
                true
            }),
            1 if picked == 1 => ui::input_prefilled(
                "Sites the harness may reach, separated by commas (each covers its subdomains)",
                &before,
                &|value: &str| site_names(value).map(|names| names.join(", ")),
            )
            .map(|typed| {
                sites = site_names(&typed).unwrap_or_default();
                true
            }),
            1 => Ok(false),
            _ => break,
        };
        steps.next(asked)?;
    }
    plan.internet = Some(match (picked, targets.is_empty()) {
        (1, true) => Internet::Sites(sites),
        (1, false) => Internet::Targets(targets, sites),
        (2, _) => Internet::Full,
        (_, true) => Internet::Inference,
        (_, false) => Internet::Targets(targets, Vec::new()),
    });
    Ok(true)
}

/// CPU cores and memory, from the harness's defaults within this computer.
fn choose_size(plan: &mut Plan, chosen: &Permissions, host: &Value) -> Result<bool, String> {
    use crate::cli_ui as ui;
    if chosen.cpu.is_some() && chosen.memory.is_some() {
        return Ok(false);
    }
    let (cpu, memory) = plan.chosen()?.size;
    let (cpu_most, memory_most) = capacity(host, cpu, memory);
    let mut sliders = [
        ui::Slider {
            label: "CPU",
            unit: "cores",
            value: plan.cpu.unwrap_or(cpu).clamp(1, cpu_most),
            min: 1,
            max: cpu_most,
            default: cpu.min(cpu_most),
        },
        ui::Slider {
            label: "Memory",
            unit: "GB",
            value: plan.memory.unwrap_or(memory).clamp(2, memory_most),
            min: 2,
            max: memory_most,
            default: memory.clamp(2, memory_most),
        },
    ];
    ui::sliders("Size the harness VM", "Choose CPU cores and memory for the VM.", &mut sliders)?;
    plan.cpu = Some(sliders[0].value);
    plan.memory = Some(sliders[1].value);
    Ok(true)
}

/// What Start does, beside it: a security harness's report comes back to the folder copied in,
/// or shows here only when there is none.
fn start_hint(harness: &Harness, folder: bool) -> String {
    let opens = format!("prepare the VM and open {} in this terminal", harness.name);
    match (harness.security, folder) {
        (true, true) => format!("{opens}; the report is saved to your folder after review"),
        (true, false) => format!("{opens}; the report shows here and is not kept"),
        (false, _) => opens,
    }
}

/// The Start step: the run summed up, then Start or Cancel. When something keeps the run from
/// starting ([`start_check`]), it says what instead of what the VM reaches, Start cannot be
/// chosen, and Back (where the cursor starts) returns to the answers that change it.
fn confirm_start(plan: &Plan, server: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let harness = plan.chosen()?;
    let ready = start_check(plan);
    let mut lines = summary(plan, server, ready.as_ref().ok());
    let cancel = Choice::new("Cancel", "nothing is started");
    let choices = match &ready {
        Ok(_) => vec![Choice::new("Start", start_hint(harness, folder(plan).is_some())), cancel],
        Err(problem) => {
            lines.push(format!("Cannot start: {problem}"));
            vec![Choice::new("Start", "not until the answers above change").disabled(), Choice::new("Back", "change the answers"), cancel]
        }
    };
    match (ready.is_ok(), ui::select(&format!("Start {}?", harness.name), &lines, &choices, usize::from(ready.is_err()))?) {
        (true, 0) => Ok(true),
        (false, 1) => Err(ui::BACK.into()),
        _ => Err(crate::wire::cancelled("Nothing was started.")),
    }
}

/// The questions before a harness VM starts, as one wizard with Back: which harness, which model,
/// the harness's own questions, the folder, the reach and the size, then Start. Options given
/// answer their questions. Cancelling starts nothing.
#[allow(clippy::too_many_arguments)]
async fn ask_run(
    plan: &mut Plan,
    offered: &[Harness],
    preselect: Option<&str>,
    chosen: &Permissions,
    environment: &dyn Fn(&str) -> Option<Zeroizing<String>>,
    models: &mut Models<'_>,
    server: &str,
    host: &Value,
) -> Result<(), String> {
    let mut steps = crate::cli_ui::Wizard::new();
    loop {
        let questions = plan.harness.as_ref().map_or(0, |harness| harness.questions.len());
        let asked = match steps.step() {
            0 => choose_harness(plan, offered, preselect, chosen, environment),
            1 => choose_model(plan, chosen.model.as_deref(), models).await,
            step if step < 2 + questions => ask_question(plan, step - 2),
            step if step == 2 + questions => choose_folder(plan, chosen),
            step if step == 3 + questions => choose_reach(plan, chosen, server),
            step if step == 4 + questions => choose_size(plan, chosen, host),
            step if step == 5 + questions => confirm_start(plan, server),
            _ => break,
        };
        steps.next(asked)?;
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<(), String> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("The inference runtime folder is redirected or is not a directory.".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err("The inference runtime folder is redirected.".into());
            }
        }
    }
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
/// The YOUGORI_SECRET_<ID> variables, taken out of this process's environment as the command
/// starts, before anything is started: the engine `client::start` launches, PowerShell, the
/// launcher and the connector then inherit none, and a run's launcher gets only its own secret
/// answers ([`secret_variables`]). Keyed by name, in capitals on Windows, where a name is the same
/// in any case. A value that is not Unicode is removed and not kept.
fn take_secret_variables() -> BTreeMap<String, Zeroizing<String>> {
    let names: Vec<std::ffi::OsString> = std::env::vars_os().map(|(name, _)| name).filter(|name| is_secret_variable(name)).collect();
    let mut taken = BTreeMap::new();
    for name in names {
        let value = std::env::var_os(&name).map(std::ffi::OsString::into_string);
        std::env::remove_var(&name);
        if let (Some(name), Some(Ok(value))) = (name.to_str(), value) {
            let key = if cfg!(windows) { name.to_ascii_uppercase() } else { name.to_owned() };
            taken.insert(key, Zeroizing::new(value));
        }
    }
    taken
}

/// A stage folder's lease file and what it says: a run holds it locked for as long as the run
/// lasts, so a stage whose lease nobody holds was left by a run that ended without removing it.
const LEASE: &str = "stage.lease";
const LEASE_OWNER: &[u8] = b"yougori inference stage\n";
/// The answers file a run writes into its stage for the launcher, which reads it as it starts.
const ANSWERS_FILE: &str = "answers.json";
/// How long a stage nobody holds stays: the launcher of a run whose command was killed alone may
/// still be running from it.
const STALE_STAGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// A run's hold on its stage folder, released when it is dropped (before the folder is removed).
struct Lease {
    _file: std::fs::File,
}

impl Lease {
    fn hold(stage: &Path) -> Result<Self, String> {
        use std::io::Write;
        let problem = |e: std::io::Error| format!("Could not prepare the inference client: {e}");
        let mut file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(stage.join(LEASE)).map_err(problem)?;
        // Locked before it says whose it is, so a sweep never takes a lease still being made.
        file.lock().map_err(problem)?;
        file.write_all(LEASE_OWNER).and_then(|()| file.flush()).map_err(problem)?;
        Ok(Self { _file: file })
    }
}

/// A folder that is a folder itself, never a link or a junction to one elsewhere.
fn plain_folder(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    meta.is_dir() && !meta.file_type().is_symlink()
}

/// Clears what runs that ended without cleaning up (a closed terminal, a killed process) left in
/// `root`: a stage whose lease no run holds loses its answers file at once, as its launcher read
/// it when it started, and the whole stage once that lease is [`STALE_STAGE`] old. A stage without
/// a lease, from an older Yougori, may belong to a run still going and is left alone. Best
/// effort: what cannot be removed now is tried again next time.
fn sweep_stages(root: &Path, now: std::time::SystemTime) {
    use std::io::Read;
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let stage = entry.path();
        if !entry.file_name().to_string_lossy().starts_with("client-") || !std::fs::symlink_metadata(&stage).is_ok_and(|meta| plain_folder(&meta)) {
            continue;
        }
        let lease = stage.join(LEASE);
        let Ok(meta) = std::fs::symlink_metadata(&lease) else { continue };
        if !meta.is_file() || meta.len() != LEASE_OWNER.len() as u64 {
            continue;
        }
        let Ok(mut file) = std::fs::OpenOptions::new().read(true).write(true).open(&lease) else { continue };
        if file.try_lock().is_err() {
            continue;
        }
        let mut owner = Vec::new();
        if (&mut file).take(LEASE_OWNER.len() as u64 + 1).read_to_end(&mut owner).is_err() || owner != LEASE_OWNER {
            continue;
        }
        let _ = std::fs::remove_file(stage.join(ANSWERS_FILE));
        let old = meta.modified().ok().and_then(|at| now.duration_since(at).ok()).is_some_and(|age| age >= STALE_STAGE);
        drop(file);
        if old {
            let _ = std::fs::remove_dir_all(&stage);
        }
    }
}

fn stage(root: &Path, server: &str) -> Result<(), String> {
    for (name, bytes) in SOURCES {
        let target = root.join(name);
        private_directory(target.parent().ok_or("Invalid embedded client path")?)?;
        std::fs::write(&target, bytes).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        root.join("connection.json"),
        serde_json::to_vec(&json!({"server":server,"harness":"node"})).unwrap(),
    )
    .map_err(|e| e.to_string())
}
#[cfg(windows)]
fn python(root: &Path, stage: &Path) -> Result<PathBuf, String> {
    let config = json!({"harness":"node","sha256":"0".repeat(64),"runtime_only":true,"python_version":"3.14.10",
        "python":{"amd64":{"url":"https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip","sha256":"90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159"},
        "arm64":{"url":"https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-arm64.zip","sha256":"bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836"}}});
    let script = INSTALLER.replace(
        "__SOLVER_CONFIG_BASE64__",
        &base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&config).unwrap()),
    );
    let path = stage.join("runtime.ps1");
    std::fs::write(&path, script).map_err(|e| e.to_string())?;
    let ps = PathBuf::from(
        std::env::var_os("SystemRoot").ok_or("Windows system directory unavailable")?,
    )
    .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let result = Command::new(ps)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(path)
        .env("INFERENCE_SOLVER_HOME", root)
        .env("INFERENCE_SOLVER_NO_PATH", "1")
        .env("INFERENCE_SOLVER_NO_LAUNCH", "1")
        .stdin(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !result.success() {
        return Err(
            "Yougori could not prepare its private Python runtime. Retry the same command.".into(),
        );
    }
    let arch = std::env::var("PROCESSOR_ARCHITEW6432")
        .or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE"))
        .unwrap_or_default();
    let arch = if arch.eq_ignore_ascii_case("arm64") {
        "arm64"
    } else {
        "amd64"
    };
    Ok(root.join(format!("runtimes/python-3.14.10-{arch}/python.exe")))
}
#[cfg(not(windows))]
fn python(_root: &Path, _stage: &Path) -> Result<PathBuf, String> {
    let status = Command::new("python3")
        .args([
            "-I",
            "-c",
            "import sys;sys.exit(0 if sys.version_info>=(3,12) else 1)",
        ])
        .status()
        .map_err(|_| "Install Python 3.12 or newer to use this inference client on Linux.")?;
    if !status.success() {
        return Err("Python 3.12 or newer is required.".into());
    }
    Ok("python3".into())
}
fn launcher(python: &Path, stage: &Path, executable: &Path) -> Command {
    let mut child = Command::new(python);
    child
        .args(["-I", "-B"])
        .arg(stage.join("solver.py"))
        .env("SOLVER_YOUGORI", executable)
        .env("INFERENCE_SOLVER_YOUGORI", executable)
        .env("YOUGORI_NO_UPDATE_CHECK", "1");
    child
}

/// Before a harness VM starts: the engine runs, the website's harnesses are read, and the person
/// answers the run's questions (options answer theirs, `secrets` the secret ones; with --yes, or
/// without a terminal, nothing is asked). Every question that applies has the answer it needs
/// before anything starts. Returns the run the launcher starts.
async fn prepare_run(
    opts: &mut Options,
    python: &Path,
    stage: &Path,
    executable: &Path,
    secrets: &BTreeMap<String, Zeroizing<String>>,
) -> Result<Plan, String> {
    use crate::cli_ui as ui;
    let chosen = permissions(&mut opts.extra)?;
    let named = named_harness(&opts.harness, chosen.harness.as_deref())?;
    let asking = !chosen.yes && ui::can_prompt();
    ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
    let site = site_name(&opts.server).to_owned();
    let catalogue = ui::busy(&format!("Reading the harnesses on {site}"), site_harnesses(&opts.server)).await?;
    // `yougori` alone names no harness to start on: the list starts on Yougori anyway.
    let preselect = named.filter(|name| !(asking && name == YOUGORI && chosen.harness.is_none()));
    if let Some(name) = &preselect {
        find_harness(&catalogue, name, &site)?;
    }
    let host = match ui::busy("Reading this computer's capacity", crate::public::call("get_platform_state", json!({}))).await {
        Ok(state) => state["host"].clone(),
        Err(error) if asking || error == ui::CANCELLED => return Err(error),
        // Without questions the harness's default size is used as it is.
        Err(_) => Value::Null,
    };
    let environment = |name: &str| secrets.get(name).cloned();
    let mut models = Models { python, stage, executable, server: &opts.server, known: HashMap::new() };
    let mut plan = Plan::default();
    if asking {
        let offered = startable(&catalogue);
        if offered.is_empty() {
            return Err(format!(
                "{site} has no harness ready to start yet. Its administrator offers harnesses and publishes their VM images in Admin."
            ));
        }
        ask_run(&mut plan, &offered, preselect.as_deref(), &chosen, &environment, &mut models, &opts.server, &host)
            .await
            .map_err(|error| {
                if error == ui::BACK || error == ui::CANCELLED {
                    crate::wire::cancelled("Nothing was started.")
                } else {
                    error
                }
            })?;
    } else {
        let name = preselect.ok_or("Name the harness to run: yougori inference run HARNESS --server URL (or --harness NAME).")?;
        let harness = find_harness(&catalogue, &name, &site)?;
        plan = plan_for(harness, &chosen, &environment)?;
        let list = models.of(&harness.id).await?;
        plan.model = Some(pick_model(&list, chosen.model.as_deref(), &site)?);
        settle(&mut plan)?;
    }
    // Whatever way the answers came, the run starts only with each one it needs.
    prune(&mut plan);
    let harness = plan.chosen()?.clone();
    if let Some(question) = unanswered(&plan) {
        return Err(missing(&harness, question));
    }
    if let Some(folder) = folder(&plan) {
        folder_check(&harness, &folder)?;
    }
    settle_size(&mut plan, &host);
    let reach = resolve_reach(&plan)?;
    for line in summary(&plan, &opts.server, Some(&reach)) {
        ui::info(&line);
    }
    Ok(plan)
}

/// Before `install` prepares anything: the engine runs and the website's harnesses are read, so
/// the harness is checked as `run` checks it ([`install_arguments`]). Returns those harnesses.
async fn prepare_install(opts: &Options) -> Result<Vec<Harness>, String> {
    use crate::cli_ui as ui;
    ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
    let site = site_name(&opts.server).to_owned();
    ui::busy(&format!("Reading the harnesses on {site}"), site_harnesses(&opts.server)).await
}

/// The person's models on the website for each harness (each harness has its own key), read once.
struct Models<'a> {
    python: &'a Path,
    stage: &'a Path,
    executable: &'a Path,
    server: &'a str,
    known: HashMap<String, Vec<String>>,
}

impl Models<'_> {
    async fn of(&mut self, harness: &str) -> Result<Vec<String>, String> {
        if let Some(list) = self.known.get(harness) {
            return Ok(list.clone());
        }
        let label = format!("Reading your models on {}", site_name(self.server));
        let list = crate::cli_ui::busy(&label, signed_in_models(self.python, self.stage, self.executable, harness, self.server)).await?;
        self.known.insert(harness.to_owned(), list.clone());
        Ok(list)
    }
}

/// The models this person's key reaches on the website, from the launcher's `models --json`. It
/// first checks that `harness` can start on this computer and website, then signs in when there
/// is no key yet: its sign-in words show as they come. Stopping the wait stops it.
async fn signed_in_models(python: &Path, stage: &Path, executable: &Path, harness: &str, server: &str) -> Result<Vec<String>, String> {
    use tokio::io::AsyncBufReadExt;
    let mut command = tokio::process::Command::from(launcher(python, stage, executable));
    command
        .args(["models", harness, "--server", server, "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (name, _) in std::env::vars_os() {
        if is_secret_variable(&name) {
            command.env_remove(name);
        }
    }
    let mut child = command.spawn().map_err(|e| format!("Could not start Yougori inference: {e}"))?;
    let said = child.stderr.take();
    let relay = async move {
        if let Some(said) = said {
            let mut lines = tokio::io::BufReader::new(said).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = plain_words(&line);
                if !line.is_empty() {
                    crate::cli_ui::line(&format!("{}  {line}", crate::cli_ui::muted("│")));
                }
            }
        }
    };
    let (output, ()) = tokio::join!(child.wait_with_output(), relay);
    let output = output.map_err(|e| format!("Could not start Yougori inference: {e}"))?;
    models_reply(&output.stdout, output.status.code(), site_name(server))
}

/// What `models --json` printed: the model ids, or its error.
fn models_reply(stdout: &[u8], code: Option<i32>, site: &str) -> Result<Vec<String>, String> {
    if code == Some(130) {
        return Err(crate::cli_ui::CANCELLED.into());
    }
    let reply: Value = serde_json::from_slice(stdout.trim_ascii()).unwrap_or(Value::Null);
    if let Some(error) = reply["error"].as_str() {
        return Err(plain_words(error));
    }
    // The launcher's own words, shown above as they came, say why.
    let unread = || format!("Could not read your models on {site}.");
    match reply["models"].as_array() {
        Some(list) if code == Some(0) && list.len() <= 1000 => list
            .iter()
            .map(|model| {
                model
                    .as_str()
                    .filter(|model| !model.is_empty() && model.chars().count() <= 1024 && !model.chars().any(char::is_control))
                    .map(str::to_owned)
                    .ok_or_else(unread)
            })
            .collect(),
        _ => Err(unread()),
    }
}

/// The keys that interrupt a run, while this process holds them. On Windows that is Ctrl+C and
/// also Ctrl+Break: unheard, Ctrl+Break would end this process at once while the launcher, which
/// hears it too, is still cleaning up, and its last words would print after the shell's prompt.
#[cfg(windows)]
struct Interrupts(Option<tokio::signal::windows::CtrlC>, Option<tokio::signal::windows::CtrlBreak>);
#[cfg(unix)]
struct Interrupts(Option<tokio::signal::unix::Signal>);

fn interrupts() -> Interrupts {
    #[cfg(windows)]
    return Interrupts(tokio::signal::windows::ctrl_c().ok(), tokio::signal::windows::ctrl_break().ok());
    #[cfg(unix)]
    return Interrupts(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok());
}

/// The next Ctrl+C (or, on Windows, Ctrl+Break), if this process can hear it; otherwise never.
async fn interrupted(interrupts: &mut Interrupts) {
    #[cfg(windows)]
    {
        let Interrupts(ctrl_c, ctrl_break) = interrupts;
        let ctrl_c = async {
            match ctrl_c {
                Some(ctrl_c) => ctrl_c.recv().await,
                None => None,
            }
        };
        let ctrl_break = async {
            match ctrl_break {
                Some(ctrl_break) => ctrl_break.recv().await,
                None => None,
            }
        };
        tokio::select! {
            Some(()) = ctrl_c => return,
            Some(()) = ctrl_break => return,
            else => {}
        }
    }
    #[cfg(unix)]
    {
        if let Interrupts(Some(interrupts)) = interrupts {
            if interrupts.recv().await.is_some() {
                return;
            }
        }
    }
    std::future::pending::<()>().await
}

/// Runs the launcher or the connector in this terminal until it ends. Ctrl+C (or Ctrl+Break)
/// reaches it (it shares this console) and it stops what it started; this process waits for that
/// rather than ending first, so the private stage folder, with a run's answers file, is removed
/// after it.
async fn wait_for(mut command: Command) -> Result<std::process::ExitStatus, String> {
    let mut heard = interrupts();
    let mut child = command.spawn().map_err(|e| format!("Could not start Yougori inference: {e}"))?;
    let mut waiting = tokio::task::spawn_blocking(move || child.wait());
    loop {
        tokio::select! {
            status = &mut waiting => {
                return status.map_err(|e| e.to_string())?.map_err(|e| format!("Could not start Yougori inference: {e}"));
            }
            () = interrupted(&mut heard) => {}
        }
    }
}

/// Whether `run` or `install` asks for help (before any `--` tool arguments).
fn asks_help(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("run" | "install"))
        && args.iter().take_while(|arg| *arg != "--").any(|arg| arg == "--help" || arg == "-h")
}

/// A model this computer runs for a website unloads from the GPU after this long without requests;
/// the next request loads it again.
const IDLE_SECONDS: u64 = 300;

/// The models a website lets computers run (its administrator's list, `GET /api/compute/models`)
/// and how many one computer may run. A website without the list offers none.
#[derive(Debug, Default, PartialEq)]
struct Offered {
    models: Vec<String>,
    most: usize,
    /// What each listed model needs from a GPU, by its name in lower case.
    needs: std::collections::HashMap<String, Need>,
}

impl Offered {
    /// The website's own spelling of `repo`, when it lists it in any case.
    fn find(&self, repo: &str) -> Option<&String> {
        self.models.iter().find(|model| model.eq_ignore_ascii_case(repo))
    }

    fn need(&self, repo: &str) -> Option<&Need> {
        self.needs.get(&repo.to_ascii_lowercase())
    }
}

/// What a listed model needs from a GPU, as the website checked it when it was added: about this
/// much GPU memory, and a GPU of this generation (CUDA compute capability) or newer.
#[derive(Clone, Debug, PartialEq)]
struct Need {
    gpu_gb: f64,
    compute: f64,
}

/// One of this computer's NVIDIA GPUs: its memory in GB and its compute capability.
#[derive(Clone, Debug, PartialEq)]
struct Gpu {
    memory_gb: f64,
    compute: f64,
}

/// This computer's NVIDIA GPUs, as nvidia-smi lists them; none when it is not there.
fn local_gpus() -> Vec<Gpu> {
    match Command::new("nvidia-smi")
        .args(["--query-gpu=memory.total,compute_cap", "--format=csv,noheader,nounits"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => gpus(&String::from_utf8_lossy(&output.stdout)),
        _ => Vec::new(),
    }
}

/// nvidia-smi's lines: memory in MiB, then compute capability ("24564, 8.9").
fn gpus(listed: &str) -> Vec<Gpu> {
    listed
        .lines()
        .filter_map(|line| {
            let (memory, compute) = line.split_once(',')?;
            Some(Gpu { memory_gb: memory.trim().parse::<f64>().ok()? / 1024.0, compute: compute.trim().parse().ok()? })
        })
        .collect()
}

/// Whether this computer runs a model with this need: Ok, or why not; None when the need or this
/// computer's GPUs are unknown (Yougori checks again before installing).
fn fit(need: Option<&Need>, gpus: &[Gpu]) -> Option<Result<(), String>> {
    let need = need?;
    if gpus.is_empty() {
        return None;
    }
    // A "24 GB" card reports a little less than 24 GiB.
    if gpus.iter().any(|gpu| gpu.memory_gb + 0.5 >= need.gpu_gb && gpu.compute >= need.compute) {
        return Some(Ok(()));
    }
    let largest = gpus.iter().map(|gpu| gpu.memory_gb).fold(0.0, f64::max);
    Some(Err(if largest + 0.5 < need.gpu_gb {
        format!("needs about {:.0} GB of GPU memory; this computer's GPU has {:.0} GB", need.gpu_gb, largest)
    } else {
        "needs a newer GPU than this computer's".to_owned()
    }))
}

/// A Hugging Face repository as a website lists it: OWNER/NAME.
fn repository(value: &str) -> bool {
    let part = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    value.len() <= 200 && value.split_once('/').is_some_and(|(owner, name)| part(owner) && part(name))
}

/// The website's answer to `GET /api/compute/models`: at most 20 repositories, each once.
fn offered(body: &[u8]) -> Result<Offered, String> {
    let unexpected = || "The website listed its models in an unexpected form.".to_string();
    if body.len() > 65536 {
        return Err(unexpected());
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| unexpected())?;
    let mut models: Vec<String> = Vec::new();
    for item in value["models"].as_array().ok_or_else(unexpected)?.iter().take(20) {
        let name = item.as_str().filter(|name| repository(name)).ok_or_else(unexpected)?;
        if !models.iter().any(|known| known.eq_ignore_ascii_case(name)) {
            models.push(name.to_owned());
        }
    }
    let mut needs = std::collections::HashMap::new();
    for (name, need) in value["needs"].as_object().into_iter().flatten().take(20) {
        let number = |key: &str, ceiling: f64| need[key].as_f64().filter(|value| value.is_finite() && (0.0..ceiling).contains(value));
        if let (Some(gpu_gb), Some(compute)) = (number("gpu_gb", 10_000.0), number("compute", 100.0)) {
            needs.insert(name.to_ascii_lowercase(), Need { gpu_gb, compute });
        }
    }
    Ok(Offered { models, most: value["most"].as_u64().map_or(3, |most| most.clamp(1, 3) as usize), needs })
}

/// GETs `path` from the website, never through a proxy or a redirect: its status and, for 200,
/// its body.
async fn site_get(server: &str, path: &str) -> Result<(u16, Vec<u8>), String> {
    let site = site_name(server);
    let url = reqwest::Url::parse(server)
        .and_then(|base| base.join(path))
        .map_err(|e| e.to_string())?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30));
    if let Some(host) = url.host_str().filter(|host| *host == "localhost" || host.ends_with(".localhost")) {
        let port = url.port_or_known_default().unwrap_or(80);
        builder = builder.resolve(host, std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    }
    let client = builder.build().map_err(|e| e.to_string())?;
    let unreachable = |_| format!("Could not reach {site}. Check its address and this computer's internet connection, then retry.");
    let response = client.get(url).send().await.map_err(unreachable)?;
    match response.status().as_u16() {
        200 => Ok((200, response.bytes().await.map_err(unreachable)?.to_vec())),
        status => Ok((status, Vec::new())),
    }
}

/// Reads the models `server` lets computers run.
async fn site_models(server: &str) -> Result<Offered, String> {
    match site_get(server, "/api/compute/models").await? {
        // A website older than the list offers no models.
        (404, _) => Ok(Offered { most: 3, ..Offered::default() }),
        (200, body) => offered(&body),
        (status, _) => Err(format!("{} answered HTTP {status} when asked which models computers run.", site_name(server))),
    }
}

/// Reads the harnesses `server` lists, with their questions and VM sizes.
async fn site_harnesses(server: &str) -> Result<Vec<Harness>, String> {
    match site_get(server, "/api/harnesses").await? {
        (200, body) => harnesses(&body),
        (status, _) => Err(format!("{} answered HTTP {status} when asked for its harnesses.", site_name(server))),
    }
}

/// What this computer gave a website last time, for the next `connect`.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
struct Saved {
    models: Vec<SavedModel>,
    /// CPU cores, memory in GB and VMs at once, when the website may run Sandbox VMs here.
    sandbox: Option<(u32, u32, u32)>,
}

/// A chosen model: the environment that runs it here, and whether Yougori installed that
/// environment for the website. Only such a model is deleted when it is dropped; a model the
/// person already had keeps its environment.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct SavedModel {
    repo: String,
    environment: Option<String>,
    installed: bool,
}

/// Where the choices for `server` are kept, beside the inference client's runtime.
fn saved_path(root: &Path, server: &str) -> PathBuf {
    use sha2::Digest;
    let name: String = sha2::Sha256::digest(server.as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect();
    root.join("contributions").join(name + ".json")
}

fn load_saved(path: &Path) -> Option<Saved> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn store_saved(path: &Path, saved: &Saved) -> Result<(), String> {
    private_directory(path.parent().ok_or("Invalid path for this computer's choices")?)?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(saved).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&temporary, path).map_err(|e| format!("Could not keep this computer's choices: {e}"))
}

/// What a computer gives an inference website: models from the website's list, which Yougori
/// installs and runs here, and the Sandbox VM limits (CPU cores, memory in GB, VMs at once)
/// when the website may run VMs on it.
#[derive(Clone, Debug, Default, PartialEq)]
struct Contribution {
    models: Vec<String>,
    sandbox: Option<(u32, u32, u32)>,
}

impl Contribution {
    fn of(saved: &Saved) -> Self {
        Self { models: saved.models.iter().map(|model| model.repo.clone()).collect(), sandbox: saved.sandbox }
    }

    fn is_empty(&self) -> bool {
        self.models.is_empty() && self.sandbox.is_none()
    }

    /// The connector's `--sandbox`.
    fn sandbox_flag(&self) -> String {
        self.sandbox.map_or("none".to_owned(), |(cpu, memory, slots)| format!("{cpu},{memory},{slots}"))
    }

    /// The answers in words. `here` says whether a model is on this computer already; `dropped`
    /// are the models Yougori deletes from it.
    fn summary(&self, here: &dyn Fn(&str) -> bool, dropped: &[String]) -> Vec<String> {
        let models = self
            .models
            .iter()
            .map(|repo| format!("{repo} ({})", if here(repo) { "installed" } else { "installs now" }))
            .collect::<Vec<_>>();
        let mut lines = vec![format!("Models: {}", if models.is_empty() { "none".to_owned() } else { models.join(", ") })];
        if !dropped.is_empty() {
            lines.push(format!("Deletes from this computer: {}", dropped.join(", ")));
        }
        lines.push(format!(
            "Sandbox VMs: {}",
            self.sandbox.map_or("no".to_owned(), |(cpu, memory, slots)| format!(
                "up to {slots} at once, within {cpu} CPU cores and {memory} GB memory in all"
            ))
        ));
        lines
    }
}

/// What the computer does for the website.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Gives {
    Models,
    Sandbox,
    Both,
}

impl Gives {
    /// The answers that apply to this choice: no models for Sandbox VMs alone, no VMs for models alone.
    fn apply(self, chosen: &Contribution) -> Contribution {
        Contribution {
            models: if self == Gives::Sandbox { Vec::new() } else { chosen.models.clone() },
            sandbox: if self == Gives::Models { None } else { chosen.sandbox },
        }
    }
}

/// "1 to 3", or "one" when a computer may run a single model.
fn up_to(most: usize) -> String {
    if most == 1 { "one".to_owned() } else { format!("1 to {most}") }
}

/// The models of last time's choices that Yougori installed and the new answers drop: deleted.
fn dropped(saved: Option<&Saved>, chosen: &Contribution) -> Vec<String> {
    saved
        .map_or(&[][..], |saved| &saved.models[..])
        .iter()
        .filter(|model| model.installed && !chosen.models.iter().any(|repo| repo.eq_ignore_ascii_case(&model.repo)))
        .map(|model| model.repo.clone())
        .collect()
}

/// The questions before a computer connects, as one wizard with Back: continue with last time's
/// choices or change them; what the computer does for the website; which of its models (1 to
/// `most`); the Sandbox VM limits; then a review naming what is installed and deleted.
fn ask_contribution(chosen: &mut Contribution, offered: &Offered, saved: Option<&Saved>, here: &dyn Fn(&str) -> bool, gpus: &[Gpu], server: &str, host: &Value) -> Result<(), String> {
    use crate::cli_ui as ui;
    let site = site_name(server);
    // Last time's choices start ticked, in the website's spelling; a model it no longer lists is left out.
    let mut previous = None;
    if let Some(saved) = saved {
        chosen.models = saved.models.iter().filter_map(|model| offered.find(&model.repo).cloned())
            .filter(|repo| !matches!(fit(offered.need(repo), gpus), Some(Err(_)))).take(offered.most).collect();
        chosen.sandbox = saved.sandbox;
        if chosen.models.len() == saved.models.len() && !chosen.is_empty() {
            previous = Some(chosen.clone());
        }
    }
    let mut gives = match (chosen.models.is_empty() || offered.models.is_empty(), chosen.sandbox.is_some()) {
        (false, true) => Gives::Both,
        (true, true) => Gives::Sandbox,
        _ if offered.models.is_empty() => Gives::Sandbox,
        _ => Gives::Models,
    };
    let mut kept = false;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => match &previous {
                Some(previous) => keep_choices(previous, here, site).map(|keep| {
                    kept = keep;
                    true
                }),
                None => Ok(false),
            },
            1 => choose_gives(&mut gives, offered, site),
            2 if gives != Gives::Sandbox => choose_offered(chosen, offered, here, gpus, site),
            3 if gives != Gives::Models => choose_sandbox(chosen, site, host),
            2 | 3 => Ok(false),
            4 => {
                let answers = gives.apply(chosen);
                confirm_contribution(&answers, &dropped(saved, &answers), here, site)
            }
            _ => break,
        };
        steps.next(asked)?;
        if let (true, Some(previous)) = (kept, &previous) {
            // Last time's choices as they were, whatever was changed before going Back to them.
            *chosen = previous.clone();
            return Ok(());
        }
    }
    *chosen = gives.apply(chosen);
    Ok(())
}

fn keep_choices(previous: &Contribution, here: &dyn Fn(&str) -> bool, site: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let choices = [
        Choice::new("Continue with these choices", "connect again with the models and limits above"),
        Choice::new("Change what this computer gives", "choose again; a model you drop is deleted from this computer"),
    ];
    Ok(ui::select(&format!("Connect this computer to {site} as last time?"), &previous.summary(here, &[]), &choices, 0)? == 0)
}

fn choose_gives(gives: &mut Gives, offered: &Offered, site: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let question = format!("What can this computer do for {site}?");
    let sandbox = Choice::new("Run Sandbox VMs on my PC", format!("{site} may start isolated VMs here, within limits you set"));
    if offered.models.is_empty() {
        let notes = [format!("{site} has no models for computers to run yet; its administrator adds them in Admin.")];
        return match ui::select(&question, &notes, &[sandbox, Choice::new("Cancel", "nothing is shared")], 0)? {
            0 => {
                *gives = Gives::Sandbox;
                Ok(true)
            }
            _ => Err(crate::wire::cancelled("Nothing was connected.")),
        };
    }
    let choices = [
        Choice::new("Run models on my GPU", format!("choose {} of {site}'s models to install here", up_to(offered.most))),
        sandbox,
        Choice::new("Both", "models on the GPU, and Sandbox VMs within limits you set"),
    ];
    let initial = match gives {
        Gives::Models => 0,
        Gives::Sandbox => 1,
        Gives::Both => 2,
    };
    *gives = match ui::select(&question, &[], &choices, initial)? {
        0 => Gives::Models,
        1 => Gives::Sandbox,
        _ => Gives::Both,
    };
    Ok(true)
}

fn choose_offered(chosen: &mut Contribution, offered: &Offered, here: &dyn Fn(&str) -> bool, gpus: &[Gpu], site: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let choices: Vec<Choice> = offered
        .models
        .iter()
        .map(|repo| {
            let state = if here(repo) { "installed here" } else { "installs when you connect" };
            match (fit(offered.need(repo), gpus), offered.need(repo)) {
                (Some(Err(why)), _) => Choice::new(repo.clone(), why).disabled(),
                (Some(Ok(())), Some(need)) => Choice::new(repo.clone(), format!("{state}; fits this GPU (about {:.0} GB)", need.gpu_gb)),
                (_, Some(need)) => Choice::new(repo.clone(), format!("{state}; needs about {:.0} GB of GPU memory", need.gpu_gb)),
                _ => Choice::new(repo.clone(), state),
            }
        })
        .collect();
    let initial: Vec<usize> = offered
        .models
        .iter()
        .enumerate()
        .filter(|(_, repo)| chosen.models.iter().any(|model| model.eq_ignore_ascii_case(repo)))
        .map(|(index, _)| index)
        .collect();
    let notes = [format!("Yougori installs them. Each loads on the GPU while it is used and unloads after {} idle minutes.", IDLE_SECONDS / 60)];
    let question = format!("Which models should this computer run for {site}? Choose {}.", up_to(offered.most));
    let picked = ui::multiselect_between(&question, &notes, &choices, &initial, 1, offered.most)?;
    chosen.models = picked.into_iter().map(|index| offered.models[index].clone()).collect();
    Ok(true)
}

fn choose_sandbox(chosen: &mut Contribution, site: &str, host: &Value) -> Result<bool, String> {
    use crate::cli_ui as ui;
    let most = |key: &str, ceiling: u32| {
        host[key].as_f64().filter(|v| v.is_finite() && *v >= 1.0).map_or(ceiling, |v| (v.floor() as u32).min(ceiling))
    };
    let (cpu_max, memory_max) = (most("totalCpu", 64), most("totalMemoryGb", 256));
    let (cpu, memory, slots) = chosen.sandbox.unwrap_or((4, 8, 2));
    let mut sliders = [
        ui::Slider { label: "CPU", unit: "cores", value: cpu.min(cpu_max), min: 1, max: cpu_max, default: 4.min(cpu_max) },
        ui::Slider { label: "Memory", unit: "GB", value: memory.min(memory_max), min: 1, max: memory_max, default: 8.min(memory_max) },
        ui::Slider { label: "At once", unit: "VMs", value: slots.min(16), min: 1, max: 16, default: 2 },
    ];
    ui::sliders(
        &format!("Limits for {site}'s Sandbox VMs"),
        "All its VMs together stay within these. They run until stopped or this computer disconnects.",
        &mut sliders,
    )?;
    chosen.sandbox = Some((sliders[0].value, sliders[1].value, sliders[2].value));
    Ok(true)
}

fn confirm_contribution(chosen: &Contribution, dropped: &[String], here: &dyn Fn(&str) -> bool, site: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let installs = chosen.models.iter().any(|repo| !here(repo));
    let connect = if installs {
        "Yougori installs the new models and connects once each can answer; keep this terminal open".to_owned()
    } else {
        format!("keep this terminal open while {site} uses this computer")
    };
    let choices = [Choice::new("Connect", connect), Choice::new("Cancel", "nothing is changed")];
    match ui::select(&format!("Connect this computer to {site}?"), &chosen.summary(here, dropped), &choices, 0)? {
        0 => Ok(true),
        _ => Err(crate::wire::cancelled("Nothing was changed.")),
    }
}

/// `--sandbox`: none, or CPU cores, memory in GB and VMs at once, such as 4,8,2.
fn sandbox_limits(value: &str) -> Result<Option<(u32, u32, u32)>, String> {
    if value == "none" {
        return Ok(None);
    }
    let bad = || "Give --sandbox none, or CPU cores (1-64), memory in GB (1-256) and VMs at once (1-16), such as 4,8,2.".to_string();
    let parts = value.split(',').map(|part| part.trim().parse::<u32>()).collect::<Result<Vec<_>, _>>().map_err(|_| bad())?;
    match parts[..] {
        [cpu, memory, slots] if (1..=64).contains(&cpu) && (1..=256).contains(&memory) && (1..=16).contains(&slots) => Ok(Some((cpu, memory, slots))),
        _ => Err(bad()),
    }
}

/// `--models REPO,REPO` and `--sandbox none|CPU,GB,VMS`, the answers for scripts, taken out of
/// `extra` (which keeps `--reconnect` for the connector). Both or neither.
fn connect_flags(extra: &mut Vec<String>) -> Result<Option<Contribution>, String> {
    let (mut models, mut sandbox, mut kept) = (None, None, Vec::new());
    let mut i = 0;
    while i < extra.len() {
        match extra[i].as_str() {
            flag @ ("--models" | "--sandbox") => {
                let value = extra.get(i + 1).ok_or_else(|| format!("{flag} needs a value."))?.clone();
                if flag == "--models" {
                    models = Some(value);
                } else {
                    sandbox = Some(value);
                }
                i += 2;
            }
            _ => {
                kept.push(extra[i].clone());
                i += 1;
            }
        }
    }
    *extra = kept;
    match (models, sandbox) {
        (None, None) => Ok(None),
        (Some(models), Some(sandbox)) => Ok(Some(Contribution {
            models: models.split(',').map(str::trim).filter(|model| !model.is_empty()).map(str::to_owned).collect(),
            sandbox: sandbox_limits(&sandbox)?,
        })),
        _ => Err("Give --models and --sandbox together, such as --models Qwen/Qwen3-8B --sandbox none.".into()),
    }
}

/// Answers given as options or kept from last time, checked against the website's list: each
/// model in the website's spelling, at most `most`, and something to give.
fn check(given: Contribution, offered: &Offered, gpus: &[Gpu], site: &str) -> Result<Contribution, String> {
    let mut models: Vec<String> = Vec::new();
    for repo in &given.models {
        let listed = offered.find(repo).ok_or_else(|| {
            if offered.models.is_empty() {
                format!("{site} lists no models for computers to run yet.")
            } else {
                format!("{site} does not list {repo} for computers. It lists: {}.", offered.models.join(", "))
            }
        })?;
        if let Some(Err(why)) = fit(offered.need(listed), gpus) {
            return Err(format!("This computer cannot run {listed}: it {why}."));
        }
        if !models.contains(listed) {
            models.push(listed.clone());
        }
    }
    if models.len() > offered.most {
        return Err(format!("{site} lets a computer run at most {} models.", offered.most));
    }
    let checked = Contribution { models, sandbox: given.sandbox };
    if checked.is_empty() {
        return Err("Nothing to give: choose a model, or let the website run Sandbox VMs.".into());
    }
    Ok(checked)
}

/// What the connector receives: the environments it shares, and those it stops when it
/// disconnects (the models this computer runs only for the website).
#[derive(Debug, Default, PartialEq)]
struct Applied {
    share: Vec<String>,
    release: Vec<String>,
}

/// Runs `work` under a spinner, then leaves `done` as a finished step with the time it took.
async fn timed<T>(label: &str, done: impl FnOnce(&T) -> String, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    use crate::cli_ui as ui;
    let started = std::time::Instant::now();
    match ui::busy(label, work).await {
        Ok(value) => {
            ui::step(&format!("{}  {}", done(&value), ui::muted(&ui::clock(started.elapsed()))));
            Ok(value)
        }
        Err(error) => {
            if error != ui::CANCELLED {
                ui::task(label).fail(label);
            }
            Err(error)
        }
    }
}

/// Makes this computer match the answers before it connects: deletes the dropped models Yougori
/// installed for the website, installs the chosen ones the computer lacks (each loads on the GPU
/// while it is used and unloads after [`IDLE_SECONDS`] without requests), and keeps the choices
/// for next time. A model the person already had is used as it is, never deleted.
async fn apply(chosen: &Contribution, saved: Option<&Saved>, environments: &[Value], path: &Path) -> Result<Applied, String> {
    let alive = |id: &str| environments.iter().find(|env| env["id"] == id && env["status"] != "deleting");
    // The dropped ones go first, so their disk space is free before anything downloads.
    for model in saved.map_or(&[][..], |saved| &saved.models[..]) {
        if !dropped(saved, chosen).contains(&model.repo) {
            continue;
        }
        if let Some(id) = model.environment.as_deref().filter(|id| alive(id).is_some()) {
            timed(&format!("Deleting {}", model.repo), |_| format!("Deleted {}", model.repo), crate::public::call("delete_environment", json!({"environmentId": id}))).await?;
        }
    }
    let mut plan = Saved { models: Vec::new(), sandbox: chosen.sandbox };
    let mut applied = Applied::default();
    for repo in &chosen.models {
        let before = saved.and_then(|saved| saved.models.iter().find(|model| model.repo.eq_ignore_ascii_case(repo)));
        let known = before.and_then(|model| model.environment.as_deref()).and_then(alive);
        // Last time's environment for this model, or one the person already has.
        let found = known.or_else(|| crate::public::existing_model(environments, repo));
        // Installed for the website: last time's, or one whose install was interrupted.
        let installed = before.is_some_and(|model| model.installed && (known.is_some() || model.environment.is_none()));
        // One Yougori installed for the website on a runtime without tool calls, which vLLM would
        // serve, is installed again on vLLM (a model the person had is left as it is).
        let again = match found {
            Some(env) if installed && !on_vllm(env) => agent_runtime(repo).await,
            _ => false,
        };
        if let (true, Some(env)) = (again, found) {
            let id = env["id"].as_str().ok_or("A model environment has no ID.")?;
            timed(&format!("Moving {repo} to the runtime coding agents need"), |_| format!("Removed {repo}'s old runtime"),
                crate::public::call("delete_environment", json!({"environmentId": id}))).await?;
            plan.models.push(SavedModel { repo: repo.clone(), environment: None, installed: true });
            continue;
        }
        match found {
            Some(env) => {
                let id = env["id"].as_str().ok_or("A model environment has no ID.")?.to_owned();
                // The connector stops on disconnect what runs only for the website.
                if installed || env["status"] != "running" {
                    applied.release.push(id.clone());
                }
                plan.models.push(SavedModel { repo: repo.clone(), environment: Some(id), installed });
            }
            None => plan.models.push(SavedModel { repo: repo.clone(), environment: None, installed: true }),
        }
    }
    // Kept before installing, so an interrupted install is recognised as Yougori's next time.
    store_saved(path, &plan)?;
    // The environments made now: they run already, with the limits coding agents need.
    let mut made = Vec::new();
    for index in 0..plan.models.len() {
        if plan.models[index].environment.is_some() {
            continue;
        }
        let repo = plan.models[index].repo.clone();
        let params = install_request(&repo, agent_runtime(&repo).await);
        // run_model returns once the model's environment runs; its download follows (below).
        let created = timed(
            &format!("Setting up {repo} (the first time can take a while)"),
            |_| format!("Set up {repo}"),
            crate::public::call("run_model", params),
        )
        .await;
        let created = match created {
            Ok(created) => created,
            Err(error) => {
                if error != crate::cli_ui::CANCELLED {
                    // Not installed: chosen again next time, never taken for an environment of its own.
                    plan.models.remove(index);
                    store_saved(path, &plan)?;
                }
                return Err(error);
            }
        };
        let id = created["id"].as_str().ok_or("Yougori did not name the new model's environment.")?.to_owned();
        // Loaded while it is used: unloaded after IDLE_SECONDS without requests (a media model,
        // which stays loaded while it runs, keeps its own setting).
        let _ = crate::public::call("model_optimizer", json!({"environmentId": id, "enabled": true, "idleTimeoutSeconds": IDLE_SECONDS})).await;
        applied.release.push(id.clone());
        plan.models[index].environment = Some(id.clone());
        store_saved(path, &plan)?;
        made.push(id);
    }
    // Each chosen model, until it can answer: the website lists a model only then, so no request
    // waits on one still downloading. Installed first, so the downloads run side by side.
    let mut noted = Vec::new();
    for model in &plan.models {
        let Some(id) = model.environment.as_deref() else { continue };
        let running = environments.iter().any(|env| env["id"] == id && env["status"] == "running");
        make_ready(id, &model.repo, running, made.iter().any(|new| new == id), &mut noted).await?;
    }
    applied.share = plan.models.iter().filter_map(|model| model.environment.clone()).collect();
    Ok(applied)
}

/// What `run_model` is asked for a model Yougori installs for the website: the limits coding
/// agents need (`YOUGORI_MODEL_AGENT_API`: longer conversations, more messages, larger requests),
/// on vLLM when the engine serves the model natively there ([`agent_runtime`]).
fn install_request(repo: &str, vllm: bool) -> Value {
    let mut params = json!({"model": repo, "resources": {"agentApi": true}});
    if vllm {
        params["runner"] = json!("vllm");
    }
    params
}

/// Readies one chosen model before the connector shares it. A model this computer already had
/// takes the limits coding agents need from its next start, and is restarted when it runs
/// without them; one that is stopped starts (and takes them then). `new`: installed just now,
/// with them, and running. Then it is followed until it can answer. `noted`: the notes said
/// already, each said once.
async fn make_ready(id: &str, repo: &str, running: bool, new: bool, noted: &mut Vec<String>) -> Result<(), String> {
    use crate::cli_ui as ui;
    let mut running = running || new;
    if !new {
        match crate::public::call("model_agent_api", json!({"environmentId": id})).await {
            Ok(given) if restarts_for_agent_limits(&given) => {
                restart_with_agent_limits(id, repo, RESTART_RETRY).await?;
                running = true;
            }
            Ok(_) => {}
            Err(error) => {
                if let Some(note) = agent_limits_note(repo, &error).filter(|note| !noted.contains(note)) {
                    ui::warn(&note);
                    noted.push(note);
                }
            }
        }
    }
    if !running {
        ui::busy(&format!("Starting {repo}"), crate::public::call("start_model", json!({"environmentId": id}))).await?;
    }
    until_answering(id, repo, STATUS_EVERY, |method, params| crate::public::call(method, params)).await
}

/// Whether `model_agent_api`'s answer means the model runs without the limits coding agents need.
/// The engine says so (`restartRequired`) only while limits saved after the model's container was
/// configured have not reached it, also when an earlier restart for them failed: a model installed
/// with the limits, or one whose start marks only another setting (the idle unload connect sets),
/// is not restarted. No released engine has `model_agent_api`.
fn restarts_for_agent_limits(given: &Value) -> bool {
    given["restartRequired"] == true
}

/// A start that fails right after a restart stopped the model is tried once more after this
/// pause, so a refusal while another operation on the model finishes does not leave it stopped.
const RESTART_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// While alive at a terminal, the engine's job waits show no spinner of their own, which the
/// first Ctrl+C would stop, and print no notes: the step around them shows the work.
struct QuietWaits(Option<bool>);

impl QuietWaits {
    fn on() -> Self {
        use std::io::IsTerminal;
        let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        Self(terminal.then(|| crate::client::QUIET.swap(true, std::sync::atomic::Ordering::Relaxed)))
    }
}

impl Drop for QuietWaits {
    fn drop(&mut self) {
        if let Some(before) = self.0 {
            crate::client::QUIET.store(before, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Restarts a model the person already had, so it runs with the limits coding agents need (they
/// reach its model server as it starts). Ctrl+C waits until the model has started again and then
/// stops the connect: a stop alone would leave the person's model stopped. A start that fails is
/// tried once more after `retry`; when that fails too, the error says the model is stopped and
/// how to start it.
async fn restart_with_agent_limits(id: &str, repo: &str, retry: std::time::Duration) -> Result<(), String> {
    let call = |method: &'static str| crate::public::call(method, json!({"environmentId": id}));
    let restart = async {
        let _quiet = QuietWaits::on();
        call("stop_model").await?;
        if call("start_model").await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(retry).await;
        call("start_model").await.map(|_| ()).map_err(|error| {
            format!("{repo} stopped for its restart and could not start again: {}. Start it with: yougori start {id}", plain_words(&error))
        })
    };
    let (result, interrupted) = crate::tool_sharing::uninterrupted(
        &format!("Restarting {repo} with the limits coding agents need"),
        [&format!("Restarted {repo} with the limits coding agents need"), &format!("{repo} could not restart")],
        "connecting stops once it runs again",
        restart,
    )
    .await;
    result?;
    if interrupted {
        return Err(crate::cli_ui::CANCELLED.into());
    }
    Ok(())
}

/// What to say when a model this computer had could not take the limits coding agents need: an
/// engine older than this CLI (it lacks `model_agent_api`) is to be restarted; a model that takes
/// no such limits (a media model) says nothing; anything else is said as the engine said it.
fn agent_limits_note(repo: &str, error: &str) -> Option<String> {
    if error.contains("Unknown method 'model_agent_api'") || error.contains("(model_agent_api)") {
        Some("The models this computer already had keep their shorter request limits: the running Yougori engine is older than this CLI. Restart Yougori to give coding agents longer conversations with them: yougori app quit --yes, then yougori app start.".to_owned())
    } else if error.contains("Only a chat model") {
        None
    } else {
        Some(format!("{repo} keeps its shorter request limits for coding agents: {}", plain_words(error)))
    }
}

/// How often the wait for a chosen model asks the engine how far it has got, and how long one
/// answer may take (a model server's health waits while it frees GPU memory).
const STATUS_EVERY: std::time::Duration = std::time::Duration::from_secs(1);
const STATUS_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether a model answers requests now, as `model_status` says: ready, or loaded once with its
/// files checked and on automatic GPU memory, which loads it again for the next request.
pub fn answers(status: &Value) -> bool {
    let state = status["status"].as_str().unwrap_or("");
    state == "ready"
        || (status["weightsVerified"] == true
            && status["optimizer"]["enabled"] == true
            && matches!(state, "idle" | "queued" | "freeing_memory" | "loading" | "unloading"))
}

/// Engine words for one line: no control characters, at most 300 characters.
fn plain_words(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(300).collect::<String>().trim().to_owned()
}

/// A count of bytes from a status field, whole or not.
fn byte_count(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_f64().filter(|v| v.is_finite() && *v >= 0.0).map(|v| v as u64))
}

/// The step a model that cannot answer yet is at, in words, with the bytes of its download
/// (received, total) while it downloads.
fn waiting_step(status: &Value, repo: &str) -> (String, Option<(u64, u64)>) {
    match status["status"].as_str().unwrap_or("") {
        "downloading" => {
            let download = &status["download"];
            let bytes = byte_count(&download["totalBytes"])
                .filter(|total| *total > 0)
                .map(|total| (byte_count(&download["receivedBytes"]).unwrap_or(0).min(total), total));
            (format!("Downloading {repo}"), bytes)
        }
        "queued" | "freeing_memory" => {
            let reason = status["optimizer"]["waitingFor"].as_str().map(plain_words).filter(|reason| !reason.is_empty());
            (reason.map_or_else(|| "Waiting for the GPU".to_owned(), |reason| format!("Waiting for the GPU · {reason}")), None)
        }
        "verifying" => (format!("Checking {repo}'s files"), None),
        "loading" => (format!("Loading {repo} onto the GPU"), None),
        "installing" => (format!("Preparing {repo}"), None),
        _ => (format!("Starting {repo}"), None),
    }
}

/// Follows a chosen model until it can answer, asking the engine (`invoke`: model_status) every
/// `every`, in one step that says what it is doing: starting, downloading (with a bar, the bytes
/// and the time left), waiting for the GPU and why, checking its files, loading onto the GPU;
/// then "REPO is ready". A model that could not load, or whose environment is gone or stopped,
/// ends it with its own error. Ctrl+C stops waiting ([`crate::cli_ui::CANCELLED`]); the model
/// keeps going in the background.
async fn until_answering<F, Fut>(id: &str, repo: &str, every: std::time::Duration, mut invoke: F) -> Result<(), String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    use crate::cli_ui as ui;
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
    async fn pressed(stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let _keys = ui::Interrupts::watch(stop.clone());
    let mut label = format!("Starting {repo}");
    let mut task = ui::task(&label);
    let mut downloading = false;
    loop {
        let answer = tokio::select! {
            answer = tokio::time::timeout(STATUS_WAIT, invoke("model_status", json!({"environmentId": id}))) => answer,
            _ = pressed(&stop) => {
                task.done(&format!("{repo} keeps {} in the background", if downloading { "downloading" } else { "loading" }));
                return Err(ui::CANCELLED.into());
            }
        };
        match answer {
            Ok(Ok(status)) if answers(&status) => {
                task.done(&format!("{repo} is ready"));
                return Ok(());
            }
            Ok(Ok(status)) if status["status"] == "error" => {
                task.fail(&format!("{repo} could not load"));
                let said = status["error"].as_str().map(plain_words).filter(|said| !said.is_empty());
                return Err(said.map_or_else(
                    || format!("{repo} could not load. Its logs say why: yougori logs {id}"),
                    |said| format!("{repo} could not load: {said}"),
                ));
            }
            Ok(Ok(status)) => {
                let (next, bytes) = waiting_step(&status, repo);
                downloading = status["status"] == "downloading";
                // Setting the step clears its progress bar, so only when the step changes.
                if next != label {
                    task.set(&next);
                    label = next;
                }
                if let Some((done, total)) = bytes {
                    task.progress("Model files", done, total, "bytes");
                }
            }
            Ok(Err(error))
                if ["Model environment not found", "Start the model environment first", "not a Yougori model workload"]
                    .iter()
                    .any(|gone| error.contains(gone)) =>
            {
                task.fail(&format!("{repo} is no longer running on this computer"));
                return Err(format!("{repo} is no longer running on this computer ({}). Run this command again to start it.", plain_words(&error)));
            }
            // The engine answers "Model server is starting" until the model server listens, and a
            // busy engine may answer late: asked again.
            _ => {}
        }
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = pressed(&stop) => {}
        }
    }
}

/// Whether a model should run on vLLM for the website: when the engine runs its architecture there
/// natively. Coding agents send tools, which vLLM calls in the model family's format, with a long
/// context, as on a rented GPU; the Transformers runtime takes neither. Otherwise the engine's own
/// choice (GGUF calls tools too; image models take jobs).
async fn agent_runtime(repo: &str) -> bool {
    match crate::public::call("model_preflight", json!({"model": repo})).await {
        Ok(found) => found["supported"] == true && (found["runner"] == "yougori-vllm" || found["vllmNative"].is_object()),
        Err(_) => false,
    }
}

/// Whether an environment runs on the vLLM runtime image.
fn on_vllm(env: &Value) -> bool {
    env["runtime"].as_str().is_some_and(|image| image.contains("vllm"))
}

/// The connector, run with this CLI as its Yougori.
fn connector(python: &Path, stage: &Path, executable: &Path) -> Command {
    let mut child = Command::new(python);
    child
        .args(["-I", "-B"])
        .arg(stage.join("compute_node.py"))
        .env("SOLVER_YOUGORI", executable)
        .env("INFERENCE_SOLVER_YOUGORI", executable)
        .env("YOUGORI_NO_UPDATE_CHECK", "1");
    child
}

/// Before the connector starts: Yougori runs, the website's list of models is read, and the
/// person chooses what this computer gives (or continues with last time's choices; scripts give
/// `--models` and `--sandbox`). Yougori then deletes and installs models to match, and the
/// connector receives the answers as arguments.
async fn prepare_connect(opts: &mut Options, root: &Path) -> Result<(), String> {
    use crate::cli_ui as ui;
    if opts.extra.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(()); // The connector prints its own help.
    }
    let given = connect_flags(&mut opts.extra)?;
    ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
    let site = site_name(&opts.server).to_owned();
    let offered = ui::busy(&format!("Reading the models {site} runs"), site_models(&opts.server)).await?;
    let path = saved_path(root, &opts.server);
    let saved = load_saved(&path);
    let state = ui::busy("Reading this computer's models and capacity", crate::public::call("get_platform_state", json!({}))).await?;
    let environments = state["environments"].as_array().cloned().unwrap_or_default();
    let here = |repo: &str| crate::public::existing_model(&environments, repo).is_some();
    // Which listed models this computer's GPU can run, from what the website says each needs.
    let gpus = local_gpus();
    let chosen = match given {
        Some(given) => check(given, &offered, &gpus, &site)?,
        None if ui::can_prompt() => {
            let mut chosen = Contribution::default();
            match ask_contribution(&mut chosen, &offered, saved.as_ref(), &here, &gpus, &opts.server, &state["host"]) {
                Ok(()) => chosen,
                Err(error) if error == ui::BACK || error == ui::CANCELLED => return Err(crate::wire::cancelled("Nothing was changed.")),
                Err(error) => return Err(error),
            }
        }
        None => match &saved {
            Some(saved) => check(Contribution::of(saved), &offered, &gpus, &site)?,
            None => return Err(format!("Choose what this computer gives {site} in a terminal, or add --models REPO,REPO and --sandbox none|CPU,GB,VMS.")),
        },
    };
    let applied = apply(&chosen, saved.as_ref(), &environments, &path).await.map_err(|error| {
        if error == ui::CANCELLED {
            crate::wire::cancelled("Stopped waiting; Yougori finishes what it started. Run this command again to connect.")
        } else {
            error
        }
    })?;
    opts.extra.extend([
        "--models".to_owned(),
        applied.share.join(","),
        "--sandbox".to_owned(),
        chosen.sandbox_flag(),
        "--release".to_owned(),
        applied.release.join(","),
    ]);
    Ok(())
}

/// What the command has ready once its questions are answered and its checks are done.
enum Prepared {
    /// A run: its answers, and the file in the stage folder that holds them (never the secrets)
    /// for the launcher.
    Run(Box<Plan>, PathBuf),
    /// An install: the website's harnesses, which check the harness as a run checks it.
    Install(Vec<Harness>),
    /// A connection: the connector's options, with the person's choices, are in `opts.extra`.
    Connect,
}

impl Prepared {
    /// The launcher or the connector, with its whole command line after its own script: for a run,
    /// [`launch_arguments`] and then the launcher options passed on; for an install,
    /// [`install_arguments`]; for a connection, the connector's options. Nothing comes before or
    /// between them. Nothing is started.
    fn command(&self, opts: &Options, python: &Path, stage: &Path, executable: &Path) -> Result<Command, String> {
        let (mut command, arguments) = match self {
            Self::Run(plan, answers) => {
                let mut arguments = launch_arguments(plan, &opts.server, answers)?;
                arguments.extend(opts.extra.iter().cloned());
                (launcher(python, stage, executable), arguments)
            }
            Self::Install(catalogue) => (launcher(python, stage, executable), install_arguments(catalogue, &opts.harness, &opts.server)?),
            Self::Connect => (connector(python, stage, executable), opts.extra.clone()),
        };
        command.args(arguments);
        Ok(command)
    }
}

pub async fn run(args: &[String]) -> Result<i32, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") || asks_help(args) {
        print!("{HELP}");
        return Ok(0);
    }
    // Secret answers leave this process's environment before anything is started.
    let given_secrets = take_secret_variables();
    let mut opts = options(args)?;
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
    } else {
        std::env::var_os("XDG_DATA_HOME").or_else(|| {
            std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/share").into_os_string())
        })
    }
    .ok_or("The user data directory is unavailable.")?;
    let root = PathBuf::from(base).join("Yougori/inference");
    private_directory(&root)?;
    sweep_stages(&root, std::time::SystemTime::now());
    let stage_dir = tempfile::Builder::new()
        .prefix("client-")
        .tempdir_in(&root)
        .map_err(|e| e.to_string())?;
    // Held until this command ends; released before the stage folder is removed.
    let lease = Lease::hold(stage_dir.path())?;
    stage(stage_dir.path(), &opts.server)?;
    let python = python(&root, stage_dir.path())?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let prepared = match opts.action.as_str() {
        "run" => {
            let plan = prepare_run(&mut opts, &python, stage_dir.path(), &executable, &given_secrets).await?;
            // The answers (never the secrets) wait for the launcher in the private stage folder.
            let path = stage_dir.path().join(ANSWERS_FILE);
            std::fs::write(&path, serde_json::to_vec(&answers_json(&plan)).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Could not keep the harness's answers for its launch: {e}"))?;
            Prepared::Run(Box::new(plan), path)
        }
        "install" => Prepared::Install(prepare_install(&opts).await?),
        // `connect`, the only other action options() takes.
        _ => {
            prepare_connect(&mut opts, &root).await?;
            Prepared::Connect
        }
    };
    let mut child = prepared.command(&opts, &python, stage_dir.path(), &executable)?;
    child.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    // Secret answers reach the launcher only in its environment, and only this run's.
    for (name, _) in std::env::vars_os() {
        if is_secret_variable(&name) {
            child.env_remove(name);
        }
    }
    let (secrets, answers) = match &prepared {
        Prepared::Run(plan, path) => (secret_variables(plan), Some(path.as_path())),
        Prepared::Install(_) | Prepared::Connect => (Vec::new(), None),
    };
    for (name, value) in &secrets {
        child.env(name, value.as_str());
    }
    let _removed_on_quit = answers.map(crate::cli_ui::remove_on_quit);
    // Inherit the console: Ctrl+C reaches the launcher's or connector's normal VM/relay cleanup.
    let status = wait_for(child).await;
    if let Some(path) = answers {
        let _ = std::fs::remove_file(path);
    }
    drop(lease);
    Ok(status?.code().unwrap_or(130))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn validates_server_and_preserves_tool_arguments() {
        let o = options(&args(&[
            "run",
            "pi",
            "--server",
            "http://abc.localhost:1234/",
            "--workspace",
            "C:/a b",
            "--",
            "--server",
            "guest-value",
        ]))
        .unwrap();
        assert_eq!(o.server, "http://abc.localhost:1234");
        assert_eq!(
            o.extra,
            args(&["--workspace", "C:/a b", "--", "--server", "guest-value"])
        );
        for url in [
            "http://example.com",
            "https://user:key@example.com",
            "https://example.com/path",
            "https://example.com/?key=a",
            "http://x.localhost.evil",
            "http://169.254.169.254",
            "https://example.com\n",
        ] {
            assert!(origin(url).is_err(), "{url}");
        }
        assert!(options(&args(&["connect", "https://example.com", "--reconnect"])).is_ok());
        // `run` names a harness only to start the list on it: the website's catalogue checks it.
        assert_eq!(options(&args(&["run", "missing", "--server", "https://example.com"])).unwrap().harness, "missing");
        let unnamed = options(&args(&["run", "--server", "https://example.com", "--yes"])).unwrap();
        assert_eq!((unnamed.harness.as_str(), unnamed.extra), ("", args(&["--yes"])));
        assert!(options(&args(&["install", "missing", "--server", "https://example.com"])).is_err());
        assert!(options(&args(&["install", "--server", "https://example.com"])).is_err());
        assert!(asks_help(&args(&["run", "--help"])) && asks_help(&args(&["run", "strix", "-h"])));
        assert!(!asks_help(&args(&["run", "pi", "--", "--help"])) && !asks_help(&args(&["connect", "https://example.com", "--help"])));
    }

    #[test]
    fn install_takes_only_the_harness_and_the_server() {
        let o = options(&args(&["install", "pi", "--server", "https://example.com/"])).unwrap();
        assert_eq!((o.harness.as_str(), o.server.as_str()), ("pi", "https://example.com"));
        assert!(o.extra.is_empty());
        assert_eq!(options(&args(&["install", YOUGORI, "--server", "https://example.com"])).unwrap().harness, YOUGORI);
        // The launcher takes the last --harness and --server it is given: anything after them would
        // choose another harness or website than the one checked, or be dropped.
        for extra in [&["--harness", "codex"][..], &["--server=https://other.example"], &["--model", "m"], &["--yes"], &["pi"], &["--", "--print", "hi"]] {
            let words: Vec<&str> = ["install", "pi", "--server", "https://example.com"].into_iter().chain(extra.iter().copied()).collect();
            let error = options(&args(&words)).unwrap_err();
            assert!(
                error.starts_with("yougori inference install does not take ") && error.ends_with(": it takes only HARNESS and --server URL."),
                "{extra:?}: {error}"
            );
        }
    }
    #[test]
    fn permission_options_leave_only_the_launchers_own_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().to_string_lossy().to_string();
        let mut extra = args(&[
            "--model", "m", "--harness", "strix", "--set", "depth=look", "--set", "focus=Login and payments", "--workspace", &folder,
            "--cpu", "3", "--memory", "8", "--internet", "full", "--no-tty", "--yes", "--no-browser",
        ]);
        let chosen = permissions(&mut extra).unwrap();
        // The launcher keeps only the options it is passed as they are.
        assert_eq!(extra, args(&["--no-tty", "--no-browser"]));
        assert_eq!(
            (chosen.cpu, chosen.memory, chosen.internet.clone(), chosen.yes),
            (Some(3), Some(8), Some(Internet::Full), true)
        );
        assert_eq!((chosen.model.as_deref(), chosen.harness.as_deref()), (Some("m"), Some("strix")));
        assert_eq!(chosen.sets, vec![("depth".to_owned(), "look".to_owned()), ("focus".to_owned(), "Login and payments".to_owned())]);
        assert_eq!(chosen.workspace, Some(std::path::absolute(&folder).unwrap()));
    }

    #[test]
    fn run_passes_no_other_option_and_no_tool_arguments_to_the_launcher() {
        // The launcher's own spellings of what the menu answers and checks would override it:
        // argparse takes `--name=value` and any unambiguous prefix, and the last one given wins.
        for refused in [
            &["--answers-file", "my.json"][..],
            &["--answers-file=my.json"],
            &["--answers", "my.json"],
            &["--a=my.json"],
            &["--internet=full"],
            &["--int", "full"],
            &["--targets=evil.example.com:443"],
            &["--targ", "evil.example.com:443"],
            &["--work", "C:/"],
            &["--harn", "pi"],
            &["--server=https://other.example"],
            &["--mod", "other/model"],
            &["--json"],
            &["--key-stdin"],
            &["stray-word"],
        ] {
            let error = permissions(&mut args(refused)).unwrap_err();
            assert!(error.starts_with("yougori inference run does not take ") && error.ends_with("yougori inference --help"), "{refused:?}: {error}");
        }
        // Harnesses run behind Yougori's own screen, which takes no tool arguments: nothing after
        // `--` is silently dropped.
        for refused in [&["--"][..], &["--yes", "--", "--validate-model"], &["--", "--print", "fix it"]] {
            let error = permissions(&mut args(refused)).unwrap_err();
            assert!(error.contains("passes nothing after --"), "{refused:?}: {error}");
        }
        assert!(permissions(&mut args(&["--answers-file\u{1b}[2J"])).unwrap_err().contains("--answers-file[2J"));
    }
    #[test]
    fn permission_options_are_checked_before_anything_starts() {
        for bad in [
            &["--cpu", "0"][..],
            &["--cpu", "256"],
            &["--memory", "2000"],
            &["--internet", "off"],
            &["--internet"],
            &["--workspace", "Z:/no/such/folder/here"],
            &["--workspace", "/"],
            &["--set"],
            &["--set", "no-equals"],
            &["--set", "Target=practice"],
            &["--set", "=practice"],
            &["--harness", "Strix!"],
            &["--harness", "strix", "--harness", "pi"],
            &["--model", ""],
            &["--model", "a", "--model", "b"],
            &["--targets", "localhost:3000"],
            &["--internet", "sites", "--targets", "a.example.com:443"],
            &["--internet", "full", "--targets", "a.example.com:443"],
            &["--internet", "inference", "--sites", "github.com"],
        ] {
            assert!(permissions(&mut args(bad)).is_err(), "{bad:?}");
        }
        // An empty value answers an optional question with nothing.
        assert_eq!(permissions(&mut args(&["--set", "focus="])).unwrap().sets, vec![("focus".to_owned(), String::new())]);
    }
    #[test]
    fn chosen_sites_are_site_names_and_reach_the_launcher() {
        let mut extra = args(&["--internet", "sites", "--sites", "GitHub.com, pypi.org,github.com"]);
        let chosen = permissions(&mut extra).unwrap();
        assert!(extra.is_empty());
        assert_eq!(chosen.internet, Some(Internet::Sites(vec!["github.com".into(), "pypi.org".into()])));
        // --sites alone means the sites choice.
        let only = permissions(&mut args(&["--sites", "files.pythonhosted.org"])).unwrap();
        assert_eq!(only.internet, Some(Internet::Sites(vec!["files.pythonhosted.org".into()])));
        assert_eq!(internet_words(chosen.internet.as_ref().unwrap(), "https://acme.yougori.com"), "acme.yougori.com and github.com, pypi.org");
        let mut plan = plan_for(&harness("opencode"), &chosen, &no_secrets).unwrap();
        plan.model = Some("m".into());
        let arguments = launch_arguments(&plan, "https://acme.yougori.com", Path::new("answers.json")).unwrap();
        assert!(arguments.windows(4).any(|four| four == ["--internet", "sites", "--sites", "github.com,pypi.org"]), "{arguments:?}");
        for bad in [
            &["--internet", "sites"][..],
            &["--internet", "full", "--sites", "github.com"],
            &["--sites", "localhost"],
            &["--sites", "10.0.0.1"],
            &["--sites", "-bad.com"],
            &["--sites", "a..com"],
            &["--sites", ""],
        ] {
            assert!(permissions(&mut args(bad)).is_err(), "{bad:?}");
        }
    }

    /// The website's answer to GET /api/harnesses for this repository's catalogue, each harness
    /// offered and ready to start inside the Yougori harness.
    fn listed() -> Vec<u8> {
        let mut entries: Vec<Value> =
            serde_json::from_str(include_str!("../../examples/hub/inference-solver/site/harnesses.json")).unwrap();
        for entry in &mut entries {
            entry["offered"] = json!(true);
            entry["setup"] = json!({"available": true, "reason": "", "version": "1"});
            entry["held"] = json!({"available": true, "reason": "", "version": "1"});
        }
        serde_json::to_vec(&json!({"harnesses": entries, "categories": []})).unwrap()
    }

    fn harness(id: &str) -> Harness {
        let mut harness = harnesses(&listed()).unwrap().into_iter().find(|harness| harness.id == id).unwrap();
        // Whatever this launcher's packages hold, the questions are what these tests look at.
        harness.ready = true;
        harness
    }

    fn no_secrets(_: &str) -> Option<Zeroizing<String>> {
        None
    }

    /// YOUGORI_SECRET_LOGIN_PASSWORD set to `value`.
    fn password(value: &'static str) -> impl Fn(&str) -> Option<Zeroizing<String>> {
        move |name: &str| (name == "YOUGORI_SECRET_LOGIN_PASSWORD").then(|| Zeroizing::new(value.to_owned()))
    }

    fn sets(answers: &[(&str, &str)]) -> Permissions {
        Permissions { sets: answers.iter().map(|(id, value)| (id.to_string(), value.to_string())).collect(), ..Permissions::default() }
    }

    fn made(id: &str, security: bool, ready: bool) -> Harness {
        Harness {
            id: id.into(),
            name: id.into(),
            security,
            description: String::new(),
            ready,
            reason: if ready { String::new() } else { "The administrator has not published this harness's Sandbox VM image yet.".into() },
            questions: Vec::new(),
            size: (2, 4),
        }
    }

    #[test]
    fn the_catalogue_gives_every_harness_its_questions_and_size() {
        let catalogue = harnesses(&listed()).unwrap();
        assert_eq!(catalogue.len(), 22);
        assert_eq!(catalogue[0].id, YOUGORI);
        // Yougori's own agent starts once this launcher has its package.
        assert_eq!(catalogue[0].ready, launcher_harnesses().contains(&YOUGORI.to_owned()));
        for harness in &catalogue {
            assert_eq!(harness.size, if harness.security { (4, 8) } else { (2, 4) }, "{}", harness.id);
            if harness.id != YOUGORI {
                assert!(harness.ready, "{} {}", harness.id, harness.reason);
            }
        }
        let strix = harness("strix");
        assert_eq!(strix.label(), "Strix (security)");
        let ids: Vec<&str> = strix.questions.iter().map(|question| question.id.as_str()).collect();
        assert_eq!(ids, ["target", "permission", "off_limits", "depth", "login_user", "login_password", "source", "focus"]);
        let permission = strix.question("permission").unwrap();
        assert_eq!((permission.kind, permission.must), (Kind::Confirm, true));
        assert_eq!(permission.when, Some(When::Not("target".into(), "practice".into())));
        assert_eq!(strix.question("login_password").unwrap().when, Some(When::Present("login_user".into(), true)));
        assert!(strix.question("target").unwrap().reach && strix.question("source").unwrap().workspace);
        assert!(!strix.question("source").unwrap().required && harness("shannon").question("source").unwrap().required);
        assert_eq!(harness("swe").questions.iter().map(|question| question.id.as_str()).collect::<Vec<_>>(), ["issue"]);
        assert!(harness("opencode").questions.is_empty() && harness(YOUGORI).questions.is_empty());
    }

    #[test]
    fn a_harness_this_cli_cannot_start_or_ask_says_why() {
        let listed = harnesses(br#"{"harnesses":[
            {"id":"strix","name":"Strix","category":"security","offered":true,"setup":{"available":true},"held":{"available":true}},
            {"id":"aider","name":"Aider","category":"coding","offered":false,"setup":{"available":false,"reason":"The administrator of this inference has not offered this harness."},
             "held":{"available":false,"reason":"The administrator of this inference has not offered this harness."}},
            {"id":"newtool","name":"New Tool","category":"coding","offered":true,"setup":{"available":true},"held":{"available":true}},
            {"id":"shannon","name":"Shannon","category":"security","offered":true,"setup":{"available":true},"held":{"available":true},
             "questions":[{"id":"target","type":"radar","question":"What should it test?"}]},
            {"id":"pi","name":"Pi","category":"coding","offered":true,"setup":{"available":true},"held":{"available":true},
             "questions":[{"id":"later","type":"text","question":"Later?","when":{"id":"never","present":true}}]}]}"#)
        .unwrap();
        // A website from before questions: the harness asks none, sized by its kind.
        let strix = &listed[0];
        assert!(strix.ready && strix.questions.is_empty());
        assert_eq!(strix.size, (4, 8));
        let site = "argon.yougori.com";
        assert_eq!(find_harness(&listed, "aider", site).unwrap_err(), "Aider cannot start here: The administrator of this inference has not offered this harness.");
        assert!(find_harness(&listed, "newtool", site).unwrap_err().contains("Update Yougori: yougori update"));
        assert!(find_harness(&listed, "shannon", site).unwrap_err().contains("cannot ask Shannon's questions"));
        assert!(find_harness(&listed, "pi", site).unwrap_err().contains("cannot ask Pi's questions"));
        assert_eq!(find_harness(&listed, "nope", site).unwrap_err(), "argon.yougori.com lists no harness nope. It offers: strix.");
        assert!(harnesses(b"[]").is_err() && harnesses(br#"{"harnesses":[{"id":"Bad Id"}]}"#).is_err());
    }

    #[test]
    fn a_harness_is_ready_when_it_starts_inside_the_yougori_harness() {
        // This CLI starts every harness inside the Yougori harness (`run yougori --harness NAME`):
        // `held` says whether that can start here. A harness's own image (`setup`) is what older
        // launchers start, and does not make it ready.
        let listed = harnesses(br#"{"harnesses":[
            {"id":"yougori","name":"Yougori","category":"coding","offered":true,
             "setup":{"available":false,"reason":"This version of Yougori cannot start Yougori's own agent. Update Yougori: yougori update"},
             "held":{"available":true,"reason":""}},
            {"id":"strix","name":"Strix","category":"security","offered":true,"setup":{"available":true,"reason":""},
             "held":{"available":false,"reason":"The administrator has not published this harness's Sandbox VM image yet."}},
            {"id":"pi","name":"Pi","category":"coding","offered":true,"setup":{"available":true,"reason":""}},
            {"id":"aider","name":"Aider","category":"coding","offered":false,"setup":{"available":false,"reason":"The administrator of this inference has not offered this harness."}}]}"#)
        .unwrap();
        let reasons: Vec<(&str, bool, &str)> = listed.iter().map(|harness| (harness.id.as_str(), harness.ready, harness.reason.as_str())).collect();
        assert_eq!(reasons, [
            ("yougori", true, ""),
            ("strix", false, "The administrator has not published this harness's Sandbox VM image yet."),
            // A website from before the Yougori harness lists only each harness's own image.
            ("pi", false, WEBSITE_BEFORE_HELD),
            ("aider", false, "The administrator of this inference has not offered this harness."),
        ]);
        assert_eq!(startable(&listed).into_iter().map(|harness| harness.id).collect::<Vec<_>>(), ["yougori"]);
    }

    #[test]
    fn install_prepares_the_images_a_run_starts_the_harness_from() {
        let server = "https://acme.yougori.com";
        // `install HARNESS` once prepared the harness's own older image, which no run starts.
        let catalogue = harnesses(br#"{"harnesses":[
            {"id":"yougori","name":"Yougori","category":"coding","offered":true,
             "setup":{"available":false,"reason":"Yougori's own agent starts only inside the Yougori harness."},"held":{"available":true}},
            {"id":"pi","name":"Pi","category":"coding","offered":true,
             "setup":{"available":false,"reason":"The administrator has not published this harness's Sandbox VM image yet."},"held":{"available":true}},
            {"id":"strix","name":"Strix","category":"security","offered":true,"setup":{"available":true},
             "held":{"available":false,"reason":"The published VM image needs updating before this harness can start."}}]}"#)
        .unwrap();
        let mut plan = plan_for(&harness("pi"), &Permissions::default(), &no_secrets).unwrap();
        plan.model = Some("m".into());
        let run = launch_arguments(&plan, server, Path::new("answers.json")).unwrap();
        // Pi's base and pack, as a run starts Pi: inside the Yougori harness, though Pi's own image
        // is not published.
        let install = install_arguments(&catalogue, "pi", server).unwrap();
        assert_eq!(install, ["install", YOUGORI, "--server", server, "--harness", "pi"]);
        assert_eq!(install[1..], run[1..6]);
        // Yougori's own agent needs only the base.
        assert_eq!(install_arguments(&catalogue, YOUGORI, server).unwrap(), ["install", YOUGORI, "--server", server]);
        // Strix's own image is published, but Strix cannot start inside the Yougori harness, so
        // nothing is prepared, in the words a run would say.
        let refused = install_arguments(&catalogue, "strix", server).unwrap_err();
        assert_eq!(refused, "Strix cannot start here: The published VM image needs updating before this harness can start.");
        assert_eq!(refused, find_harness(&catalogue, "strix", site_name(server)).unwrap_err());
        assert_eq!(install_arguments(&catalogue, "aider", server).unwrap_err(), "acme.yougori.com lists no harness aider. It offers: yougori, pi.");
    }

    #[test]
    fn the_launcher_gets_only_the_command_line_its_action_prepared() {
        let server = "https://acme.yougori.com";
        let (python, stage, executable) = (Path::new("python.exe"), Path::new("stage"), Path::new("yougori.exe"));
        let words = |command: &Command| command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect::<Vec<_>>();
        // How the launcher and the connector start (`python -I -B SCRIPT`), before their command line.
        let (launcher_start, connector_start) = (words(&launcher(python, stage, executable)), words(&connector(python, stage, executable)));
        let started = |prepared: &Prepared, opts: &Options| -> Result<Vec<String>, String> {
            let command = prepared.command(opts, python, stage, executable)?;
            assert_eq!(command.get_program(), python.as_os_str());
            Ok(words(&command))
        };
        let catalogue = || {
            harnesses(br#"{"harnesses":[
                {"id":"yougori","name":"Yougori","category":"coding","offered":true,"held":{"available":true}},
                {"id":"pi","name":"Pi","category":"coding","offered":true,"held":{"available":true}},
                {"id":"strix","name":"Strix","category":"security","offered":true,"setup":{"available":true},
                 "held":{"available":false,"reason":"The published VM image needs updating before this harness can start."}}]}"#)
            .unwrap()
        };
        // `install pi` once handed the launcher `install pi --server URL`: Pi's own older image.
        // Those words before the Yougori harness's install make the launcher refuse the whole line.
        let install = |harness: &str| started(&Prepared::Install(catalogue()), &options(&args(&["install", harness, "--server", server])).unwrap());
        assert_eq!(install("pi").unwrap(), [launcher_start.clone(), args(&["install", YOUGORI, "--server", server, "--harness", "pi"])].concat());
        assert_eq!(install(YOUGORI).unwrap(), [launcher_start.clone(), args(&["install", YOUGORI, "--server", server])].concat());
        // A harness that cannot start inside the Yougori harness gets no launcher.
        assert_eq!(install("strix").unwrap_err(), "Strix cannot start here: The published VM image needs updating before this harness can start.");
        // A run: its own command line, then only the launcher options passed on.
        let mut opts = options(&args(&["run", "pi", "--server", server, "--model", "m", "--no-tty", "--yes"])).unwrap();
        let plan = plan_for(&harness("pi"), &permissions(&mut opts.extra).unwrap(), &no_secrets).unwrap();
        let answers = stage.join(ANSWERS_FILE);
        let run = args(&["run", YOUGORI, "--server", server, "--harness", "pi", "--model", "m", "--answers-file", &answers.display().to_string(), "--internet", "inference", "--no-tty"]);
        assert_eq!(started(&Prepared::Run(Box::new(plan), answers), &opts).unwrap(), [launcher_start, run].concat());
        // A connection: the connector, with its options.
        let opts = options(&args(&["connect", server, "--reconnect"])).unwrap();
        assert_eq!(started(&Prepared::Connect, &opts).unwrap(), [connector_start, args(&["--reconnect"])].concat());
    }

    #[test]
    fn questions_that_would_decide_for_the_person_make_a_harness_not_ready() {
        let catalogue = |questions: Value| {
            let body = json!({"harnesses": [{"id": "strix", "name": "Strix", "category": "security", "offered": true,
                                             "held": {"available": true}, "questions": questions}]});
            harnesses(&serde_json::to_vec(&body).unwrap()).unwrap().remove(0)
        };
        let target = json!({"id": "target", "type": "target", "question": "What should it test?", "required": true, "reach": "targets",
                            "choices": [{"value": "practice", "label": "Practice"}, {"value": "address", "label": "An address"}]});
        let mut aimed = target.clone();
        aimed["default"] = json!("https://victim.example");
        // A website's defaults never choose the folder copied in, the target, a path, a secret or
        // the yes: under --yes they would be taken without the person seeing them.
        for (question, id) in [
            (json!({"id": "source", "type": "folder", "question": "Source code?", "workspace": true, "default": "."}), "source"),
            (aimed, "target"),
            (json!({"id": "where", "type": "target", "question": "Where?", "default": "practice",
                    "choices": [{"value": "practice", "label": "Practice"}, {"value": "address", "label": "An address"}]}), "where"),
            (json!({"id": "log", "type": "text", "question": "Log file?", "validate": "path", "default": "C:/Users"}), "log"),
            (json!({"id": "also", "type": "text", "question": "Also test?", "validate": "target", "default": "https://victim.example"}), "also"),
            (json!({"id": "token", "type": "secret", "question": "Token?", "default": "hunter2"}), "token"),
        ] {
            let strix = catalogue(json!([question]));
            assert!(!strix.ready, "{id}");
            assert_eq!(strix.reason, format!("The website's questions for Strix are not safe to ask: its question {id} comes with an answer chosen in advance. Its administrator needs to correct them."));
        }
        // A yes that must be given but may be skipped.
        let skippable = catalogue(json!([target, {"id": "permission", "type": "confirm", "question": "Permission?", "must": true}]));
        assert_eq!(
            skippable.reason,
            "The website's questions for Strix are not safe to ask: its question permission must be answered yes but may be skipped. Its administrator needs to correct them."
        );
        // Defaults a person may take without being asked stay.
        let fine = catalogue(json!([
            target,
            {"id": "depth", "type": "choice", "question": "How far?", "default": "safe", "choices": [{"value": "safe", "label": "Safely"}]},
            {"id": "focus", "type": "text", "question": "Focus?", "default": "login"},
            {"id": "notes", "type": "list", "question": "Notes?", "default": "a, b"},
            {"id": "verbose", "type": "confirm", "question": "Verbose?", "default": false},
        ]));
        assert!(fine.ready, "{}", fine.reason);
        // And settle never takes the others' defaults, whatever made the question.
        let mut source = harness("shannon");
        source.questions.iter_mut().find(|question| question.id == "source").unwrap().default = Some(".".into());
        let mut plan = plan_for(&source, &sets(&[("target", "practice")]), &no_secrets).unwrap();
        assert_eq!(settle(&mut plan).unwrap_err(), "Shannon needs an answer to \"Source code?\": add --set source=PATH.");
        let mut aimed = harness("strix");
        aimed.questions[0].default = Some("https://victim.example".into());
        let mut plan = plan_for(&aimed, &Permissions::default(), &no_secrets).unwrap();
        assert!(settle(&mut plan).unwrap_err().contains("add --set target=URL"));
        let mut optional = harness("strix");
        let permission = optional.questions.iter_mut().find(|question| question.must).unwrap();
        permission.required = false;
        permission.default = Some("yes".into());
        let mut plan = plan_for(&optional, &sets(&[("target", "https://staging.example.com")]), &no_secrets).unwrap();
        assert!(settle(&mut plan).unwrap_err().ends_with("add --set permission=yes."));
    }

    #[test]
    fn the_list_puts_yougori_first_then_coding_then_security() {
        let catalogue = [made("strix", true, true), made("opencode", false, true), made("aider", false, false), made(YOUGORI, false, true), made("pi", false, true)];
        let order: Vec<String> = startable(&catalogue).into_iter().map(|harness| harness.id).collect();
        assert_eq!(order, ["yougori", "opencode", "pi", "strix"]);
        assert_eq!(named_harness("", None), Ok(None));
        assert_eq!(named_harness("strix", None), Ok(Some("strix".into())));
        assert_eq!(named_harness(YOUGORI, Some("strix")), Ok(Some("strix".into())));
        assert_eq!(named_harness("", Some("pi")), Ok(Some("pi".into())));
        assert_eq!(named_harness("pi", Some("pi")), Ok(Some("pi".into())));
        assert_eq!(named_harness(YOUGORI, None), Ok(Some(YOUGORI.into())));
        assert!(named_harness("strix", Some("pi")).is_err());
    }

    #[test]
    fn targets_are_hosts_and_ports_the_vm_may_reach() {
        assert_eq!(target_host("Staging.Example.com:8443").unwrap(), "staging.example.com:8443");
        assert_eq!(target_host(" 10.0.0.5 ").unwrap(), "10.0.0.5");
        assert_eq!(target_host("jenkins:8080").unwrap(), "jenkins:8080");
        assert_eq!(target_host("example.com.").unwrap(), "example.com");
        for bad in [
            "localhost:3000", "app.localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0:80", "224.0.0.1", "255.255.255.255",
            "jenkins", "a..b.com", "-x.com", "x.com:0", "x.com:65536", "x.com:080", "x.com:", "::1", "[::1]:80",
            "10.0.0.256", "10.0.0.05", "1.2.3", "x.123", "a b.com",
        ] {
            assert!(target_host(bad).is_err(), "{bad}");
        }
        assert_eq!(url_host("https://staging.example.com/app?x=1").unwrap(), "staging.example.com:443");
        assert_eq!(url_host("http://10.0.0.5:8080").unwrap(), "10.0.0.5:8080");
        assert_eq!(url_host("http://jenkins/").unwrap(), "jenkins:80");
        for bad in ["ftp://x.com", "https://user:pw@x.com", "http://localhost:3000", "http://[::1]/", "http://127.0.0.1/", "https://169.254.169.254/latest", "https://"] {
            assert!(url_host(bad).is_err(), "{bad}");
        }
        assert_eq!(url_host("https://user:pw@x.com").unwrap_err(), "Give the login in its own question, not in the address.");
        // This computer is named as such, with what to do instead.
        for (entry, said) in [
            ("localhost:3000", "localhost:3000"),
            ("LocalHost", "LocalHost"),
            ("app.localhost:8080", "app.localhost:8080"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            (" 127.1.2.3 ", "127.1.2.3"),
        ] {
            assert_eq!(
                target_host(entry).unwrap_err(),
                format!("{said} is this computer: run the app inside the VM (the practice app is there), or give its network address.")
            );
        }
        assert!(url_host("http://localhost:3000/app").unwrap_err().starts_with("localhost:3000 is this computer: run the app inside the VM"));
        assert!(target_entries("https://staging.example.com, 127.0.0.1").unwrap_err().starts_with("127.0.0.1 is this computer"));
        assert_eq!(target_host("0.0.0.0:80").unwrap_err(), "0.0.0.0:80 is not an address of a computer to test.");
        let entries = target_entries("https://staging.example.com, Payments.Example.com:8443, https://staging.example.com").unwrap();
        assert_eq!(entries, vec![
            ("https://staging.example.com".to_owned(), "staging.example.com:443".to_owned()),
            ("payments.example.com:8443".to_owned(), "payments.example.com:8443".to_owned()),
        ]);
        assert!(target_entries(" , ").is_err());
        assert!(target_entries(&(1..=17).map(|n| format!("h{n}.example.com")).collect::<Vec<_>>().join(",")).is_err());
        assert_eq!(target_list("a.example.com:443, a.example.com:443,10.0.0.5").unwrap(), args(&["a.example.com:443", "10.0.0.5"]));
        // --internet targets alone takes the targets from the target question's answer.
        assert_eq!(permissions(&mut args(&["--internet", "targets"])).unwrap().internet, Some(Internet::Targets(vec![], vec![])));
        assert_eq!(
            permissions(&mut args(&["--targets", "a.example.com:443"])).unwrap().internet,
            Some(Internet::Targets(args(&["a.example.com:443"]), vec![]))
        );
        assert_eq!(
            permissions(&mut args(&["--internet", "targets", "--sites", "github.com", "--targets", "a.example.com:443"])).unwrap().internet,
            Some(Internet::Targets(args(&["a.example.com:443"]), args(&["github.com"])))
        );
    }

    #[test]
    fn targets_on_the_command_line_take_a_web_address_as_its_host_and_port() {
        // As the target question and the launcher take one: its scheme's port unless it names one,
        // without its path or query.
        assert_eq!(
            target_list("https://staging.example.com/login?next=/a:b, HTTP://Jenkins:8080/job/x, staging.example.com:443,10.0.0.5").unwrap(),
            args(&["staging.example.com:443", "jenkins:8080", "10.0.0.5"])
        );
        assert_eq!(target_list(" http://10.0.0.5/ ").unwrap(), args(&["10.0.0.5:80"]));
        assert_eq!(
            permissions(&mut args(&["--targets", "https://staging.example.com/login"])).unwrap().internet,
            Some(Internet::Targets(args(&["staging.example.com:443"]), vec![]))
        );
        // Every refusal of the target question stays.
        assert_eq!(target_list("https://user:pw@x.com").unwrap_err(), "Give the login in its own question, not in the address.");
        assert_eq!(target_list("ftp://x.com").unwrap_err(), "ftp://x.com is not an http or https address.");
        assert_eq!(
            target_list("a.example.com:443, http://localhost:3000/app").unwrap_err(),
            "localhost:3000 is this computer: run the app inside the VM (the practice app is there), or give its network address."
        );
        assert!(target_list("http://127.0.0.1:8080").unwrap_err().starts_with("127.0.0.1:8080 is this computer"));
        assert_eq!(target_list("https://169.254.169.254/latest").unwrap_err(), "169.254.169.254:443 is not an address of a computer to test.");
        for bad in ["http://[::1]/", "https://", "http://224.0.0.1/"] {
            assert!(target_list(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn questions_follow_their_conditions_and_options_answer_them() {
        let strix = harness("strix");
        // Without questions a required answer names the option to add.
        let mut plan = plan_for(&strix, &Permissions::default(), &no_secrets).unwrap();
        let error = settle(&mut plan).unwrap_err();
        assert!(error.contains("\"What should it test?\"") && error.contains("--set target=URL") && error.contains("--set target=practice"), "{error}");
        // An address needs the permission yes.
        let mut plan = plan_for(&strix, &sets(&[("target", "https://staging.example.com")]), &no_secrets).unwrap();
        assert_eq!(
            settle(&mut plan).unwrap_err(),
            "Strix starts only after a yes to \"Do you own this target or have written permission to test it?\": add --set permission=yes."
        );
        let refused = plan_for(&strix, &sets(&[("target", "staging.example.com"), ("permission", "no")]), &no_secrets).err().unwrap();
        assert!(refused.contains("Yougori tests only targets you own or have written permission to test"), "{refused}");
        // The practice app needs no permission: one given is dropped. The depth takes its default.
        let mut plan = plan_for(&strix, &sets(&[("target", "practice"), ("permission", "yes")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        assert_eq!(plan.answers.get("target"), Some(&Answer::Practice));
        assert!(!plan.answers.contains_key("permission"));
        assert_eq!(plan.answers.get("depth"), Some(&Answer::Text("safe".into())));
        // A login asks for its password, which comes only from the environment.
        let login = sets(&[("target", "practice"), ("login_user", "test@example.com")]);
        let mut plan = plan_for(&strix, &login, &no_secrets).unwrap();
        assert!(settle(&mut plan).unwrap_err().contains("put it in the YOUGORI_SECRET_LOGIN_PASSWORD environment variable"));
        let given = plan_for(&strix, &sets(&[("login_password", "hunter2")]), &no_secrets).err().unwrap();
        assert!(given.contains("YOUGORI_SECRET_LOGIN_PASSWORD") && !given.contains("hunter2"), "{given}");
        let environment = password("correct horse");
        let mut plan = plan_for(&strix, &login, &environment).unwrap();
        settle(&mut plan).unwrap();
        assert_eq!(plan.secrets.get("login_password").map(|secret| secret.as_str()), Some("correct horse"));
        // Without a login the password is not used, even when the environment has one.
        let mut plan = plan_for(&strix, &sets(&[("target", "practice")]), &environment).unwrap();
        settle(&mut plan).unwrap();
        assert!(plan.secrets.is_empty());
        assert!(plan_for(&strix, &login, &password("two\nlines")).is_err());
        // Options a harness cannot use are errors.
        assert!(plan_for(&strix, &sets(&[("nope", "x")]), &no_secrets).unwrap_err().starts_with("Strix asks no question nope. Its questions: target, permission,"));
        assert_eq!(plan_for(&strix, &sets(&[("focus", "a"), ("focus", "b")]), &no_secrets).err().unwrap(), "Give --set focus once.");
        assert_eq!(plan_for(&strix, &sets(&[("depth", "deep")]), &no_secrets).err().unwrap(), "--set depth: Choose look, safe or full.");
        assert_eq!(plan_for(&harness("opencode"), &sets(&[("target", "practice")]), &no_secrets).err().unwrap(), "OpenCode asks no questions, so it takes no --set target.");
        // A choice takes its label too; an optional answer given empty is skipped.
        let mut plan = plan_for(&strix, &sets(&[("target", "practice"), ("depth", "Full exploitation"), ("focus", "")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        assert_eq!(plan.answers.get("depth"), Some(&Answer::Text("full".into())));
        assert!(!plan.answers.contains_key("focus"));
        // SWE-agent needs its issue; Shannon its source code.
        let mut swe = plan_for(&harness("swe"), &Permissions::default(), &no_secrets).unwrap();
        assert!(settle(&mut swe).unwrap_err().ends_with("add --set issue=TEXT."));
        let shannon = harness("shannon");
        let mut plan = plan_for(&shannon, &sets(&[("target", "practice")]), &no_secrets).unwrap();
        assert!(settle(&mut plan).unwrap_err().ends_with("add --set source=PATH."));
    }

    #[test]
    fn a_source_folder_is_the_workspace_once() {
        let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (one_path, two_path) = (std::path::absolute(one.path()).unwrap(), std::path::absolute(two.path()).unwrap());
        let one_text = one_path.display().to_string();
        let shannon = harness("shannon");
        // --workspace answers the source question.
        let chosen = Permissions { workspace: Some(one_path.clone()), ..sets(&[("target", "practice")]) };
        let mut plan = plan_for(&shannon, &chosen, &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        assert_eq!((plan.answers.get("source"), folder(&plan)), (Some(&Answer::Folder(one_path.clone())), Some(one_path.clone())));
        // --set source=PATH is the workspace too.
        let mut plan = plan_for(&shannon, &sets(&[("target", "practice"), ("source", one_text.as_str())]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        assert_eq!(folder(&plan), Some(one_path.clone()));
        // The source code's folder comes before the folder step's answer, which stays for when the
        // source question is answered with none.
        plan.workspace = Some(two_path.clone());
        assert_eq!(folder(&plan), Some(one_path.clone()));
        plan.answers.remove("source");
        assert_eq!(folder(&plan), Some(two_path.clone()));
        // Two different folders, or none and one, are refused.
        let both = Permissions { workspace: Some(two_path.clone()), ..sets(&[("source", one_text.as_str())]) };
        assert!(plan_for(&shannon, &both, &no_secrets).unwrap_err().contains("give the folder once"));
        let strix = harness("strix");
        let none = Permissions { workspace: Some(two_path), ..sets(&[("source", "")]) };
        assert!(plan_for(&strix, &none, &no_secrets).unwrap_err().contains("give the folder once"));
        assert!(plan_for(&shannon, &sets(&[("source", "Z:/no/such/folder/here")]), &no_secrets).is_err());
    }

    #[test]
    fn swe_agents_folder_is_a_git_repository() {
        let swe = harness("swe");
        let notes = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        let (notes_path, repository_path) = (std::path::absolute(notes.path()).unwrap(), std::path::absolute(repository.path()).unwrap());
        // The launcher's own words, before anything starts, where the menu can still go back.
        assert_eq!(folder_check(&swe, &notes_path), Err(GIT_REPOSITORY.to_owned()));
        assert_eq!(folder_check(&swe, &repository_path), Ok(()));
        assert_eq!(folder_check(&harness("opencode"), &notes_path), Ok(()));
        let issue = sets(&[("issue", "The sign-in page fails")]);
        assert_eq!(plan_for(&swe, &Permissions { workspace: Some(notes_path.clone()), ..issue.clone() }, &no_secrets).err(), Some(GIT_REPOSITORY.to_owned()));
        let mut plan = plan_for(&swe, &Permissions { workspace: Some(repository_path), ..issue.clone() }, &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        assert!(start_check(&plan).is_ok());
        // A folder chosen in the menu is checked again at Start.
        plan.workspace = Some(notes_path);
        assert_eq!(start_check(&plan), Err(GIT_REPOSITORY.to_owned()));
        // Without a folder, SWE-agent's empty workspace is made a repository in the VM.
        plan.workspace = None;
        assert!(start_check(&plan).is_ok());
    }

    #[test]
    fn the_launcher_gets_the_answers_and_never_the_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let source = std::path::absolute(dir.path()).unwrap();
        let source_text = source.display().to_string();
        let chosen = sets(&[
            ("target", "https://staging.example.com, 10.0.0.5:8080"),
            ("permission", "yes"),
            ("off_limits", "/billing, payments.example.com"),
            ("depth", "full"),
            ("login_user", "test@example.com"),
            ("source", source_text.as_str()),
            ("focus", "Login and payments"),
        ]);
        let mut plan = plan_for(&harness("strix"), &chosen, &password("correct horse")).unwrap();
        plan.model = Some("unsloth/gemma-4-26B-A4B-it-GGUF".into());
        settle(&mut plan).unwrap();
        settle_size(&mut plan, &json!({"totalCpu": 16, "totalMemoryGb": 64}));
        let answers = answers_json(&plan);
        assert_eq!(answers, json!({
            "target": ["https://staging.example.com", "10.0.0.5:8080"], "permission": true,
            "off_limits": ["/billing", "payments.example.com"], "depth": "full", "login_user": "test@example.com",
            "source": "/run/yougori/workspace", "focus": "Login and payments",
        }));
        let file = dir.path().join("answers.json");
        let arguments = launch_arguments(&plan, "https://argon.yougori.com", &file).unwrap();
        assert_eq!(
            arguments[..9],
            args(&["run", "yougori", "--server", "https://argon.yougori.com", "--harness", "strix", "--model", "unsloth/gemma-4-26B-A4B-it-GGUF", "--answers-file"])
        );
        assert_eq!(arguments[9], file.display().to_string());
        for pair in [["--workspace", source_text.as_str()], ["--cpu", "4"], ["--memory", "8"], ["--internet", "targets"], ["--targets", "staging.example.com:443,10.0.0.5:8080"]] {
            assert!(arguments.windows(2).any(|two| two == pair), "{pair:?} in {arguments:?}");
        }
        assert!(!format!("{arguments:?}{answers}").contains("correct horse"));
        let secrets = secret_variables(&plan);
        assert_eq!(secrets.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect::<Vec<_>>(), [("YOUGORI_SECRET_LOGIN_PASSWORD", "correct horse")]);
        assert!(is_secret_variable(std::ffi::OsStr::new("yougori_secret_login_password")) && !is_secret_variable(std::ffi::OsStr::new("YOUGORI_SECRETS")));
        // The practice app inside the VM needs nothing beyond the inference.
        let mut practice = plan_for(&harness("strix"), &sets(&[("target", "practice")]), &no_secrets).unwrap();
        practice.model = Some("m".into());
        settle(&mut practice).unwrap();
        let arguments = launch_arguments(&practice, "https://argon.yougori.com", &file).unwrap();
        assert!(arguments.windows(2).any(|two| two == ["--internet", "inference"]) && !arguments.contains(&"--targets".to_owned()));
        assert_eq!(answers_json(&practice), json!({"target": "practice", "depth": "safe"}));
        // A coding harness without questions gets an empty answers file.
        let mut coding = plan_for(&harness("opencode"), &Permissions::default(), &no_secrets).unwrap();
        coding.model = Some("m".into());
        assert_eq!(answers_json(&coding), json!({}));
        assert!(launch_arguments(&coding, "https://argon.yougori.com", &file).unwrap().windows(2).any(|two| two == ["--harness", "opencode"]));
    }

    #[test]
    fn a_security_harness_reaches_only_its_target_and_the_inference() {
        let target = |value: &str| {
            let mut plan = plan_for(&harness("strix"), &sets(&[("target", value), ("permission", "yes")]), &no_secrets).unwrap();
            settle(&mut plan).unwrap();
            plan
        };
        // Outside the VM: exactly the target's hosts, which the permission yes covers.
        let mut plan = target("https://staging.example.com, 10.0.0.5:8080");
        let locked = Internet::Targets(args(&["staging.example.com:443", "10.0.0.5:8080"]), vec![]);
        assert_eq!(resolve_reach(&plan), Ok(locked.clone()));
        // --internet targets alone says the same.
        plan.internet = Some(Internet::Targets(vec![], vec![]));
        assert_eq!(resolve_reach(&plan), Ok(locked));
        // Hosts nobody confirmed permission for are never added, nor the whole internet.
        let strix = harness("strix");
        for (reach, flags) in [
            (Internet::Targets(args(&["203.0.113.10:443"]), vec![]), &["--targets", "203.0.113.10:443"][..]),
            (Internet::Targets(vec![], args(&["github.com"])), &["--internet", "targets", "--sites", "github.com"]),
            (Internet::Sites(args(&["pypi.org"])), &["--sites", "pypi.org"]),
            (Internet::Full, &["--internet", "full"]),
        ] {
            plan.internet = Some(reach);
            assert_eq!(resolve_reach(&plan).unwrap_err(), security_reach(&strix));
            let mut given = permissions(&mut args(flags)).unwrap();
            given.sets = sets(&[("target", "practice")]).sets;
            assert_eq!(plan_for(&strix, &given, &no_secrets).err(), Some(security_reach(&strix)), "{flags:?}");
        }
        assert!(security_reach(&strix).starts_with("Strix reaches only its target and this inference: it takes no --sites, no --targets"));
        // The practice app: only the inference; --internet targets has nothing to reach, and
        // --internet inference leaves an address out of reach.
        let mut plan = target("practice");
        assert_eq!(resolve_reach(&plan), Ok(Internet::Inference));
        plan.internet = Some(Internet::Inference);
        assert_eq!(resolve_reach(&plan), Ok(Internet::Inference));
        plan.internet = Some(Internet::Targets(vec![], vec![]));
        assert!(resolve_reach(&plan).unwrap_err().starts_with("--internet targets needs a target outside the VM"));
        let mut plan = target("https://staging.example.com");
        plan.internet = Some(Internet::Inference);
        assert!(resolve_reach(&plan).unwrap_err().starts_with("--internet inference leaves Strix's target out of reach"));
        assert_eq!(
            internet_words(&Internet::Targets(args(&["staging.example.com:443"]), args(&["github.com"])), "https://argon.yougori.com"),
            "argon.yougori.com and staging.example.com:443, github.com"
        );
    }

    /// A coding harness with a question whose answer sets the VM's reach.
    fn reaching() -> Harness {
        let mut coding = harness("opencode");
        coding.questions = questions(&json!([{"id": "service", "type": "target", "question": "Which service?", "required": true, "reach": "targets",
            "choices": [{"value": "practice", "label": "Practice"}, {"value": "address", "label": "An address"}]}]))
        .unwrap();
        coding
    }

    #[test]
    fn another_harness_keeps_its_target_in_every_reach() {
        let plan_with = |value: &str, internet: Option<Internet>| {
            let mut plan = plan_for(&reaching(), &sets(&[("service", value)]), &no_secrets).unwrap();
            settle(&mut plan).unwrap();
            plan.internet = internet;
            plan
        };
        let named = "https://staging.example.com";
        // Sites alone, or targets given, go beside the target rather than in its place.
        assert_eq!(
            resolve_reach(&plan_with(named, Some(Internet::Sites(args(&["pypi.org"]))))),
            Ok(Internet::Targets(args(&["staging.example.com:443"]), args(&["pypi.org"])))
        );
        assert_eq!(
            resolve_reach(&plan_with(named, Some(Internet::Targets(args(&["api.example.com:8443", "staging.example.com:443"]), vec![])))),
            Ok(Internet::Targets(args(&["staging.example.com:443", "api.example.com:8443"]), vec![]))
        );
        // The whole internet reaches a public target, never one on a private network.
        assert_eq!(resolve_reach(&plan_with(named, Some(Internet::Full))), Ok(Internet::Full));
        for private in ["http://192.168.1.20:8080", "10.0.0.5:22", "jenkins:8080", "100.64.1.2:80", "172.20.0.1:443", "198.18.0.1:80"] {
            let error = resolve_reach(&plan_with(private, Some(Internet::Full))).unwrap_err();
            assert!(error.starts_with("The whole internet leaves out ") && error.contains("--internet targets"), "{private}: {error}");
        }
        assert!(on_public_internet("staging.example.com:443") && on_public_internet("8.8.8.8") && on_public_internet("93.184.216.34:443"));
        for private in ["jenkins:8080", "192.168.1.20:8080", "203.0.113.10", "192.0.2.1:80", "168.63.129.16:80", "100.100.100.200"] {
            assert!(!on_public_internet(private), "{private}");
        }
        // The practice app inside the VM needs nothing more: sites alone are the sites choice.
        assert_eq!(resolve_reach(&plan_with("practice", Some(Internet::Sites(args(&["pypi.org"]))))), Ok(Internet::Sites(args(&["pypi.org"]))));
        let too_many = (1..=64).map(|n| format!("h{n}.example.com:443")).collect::<Vec<_>>();
        assert!(resolve_reach(&plan_with(named, Some(Internet::Targets(too_many, vec![])))).unwrap_err().starts_with("The VM reaches at most 64 targets"));
    }

    #[test]
    fn the_start_step_says_why_a_run_cannot_start() {
        // --internet targets with the practice app: said at Start, where Back changes the target,
        // and never summed up as "only this inference".
        let mut plan = plan_for(&harness("strix"), &Permissions { internet: Some(Internet::Targets(vec![], vec![])), ..sets(&[("target", "practice")]) }, &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        let problem = start_check(&plan).unwrap_err();
        assert!(problem.starts_with("--internet targets needs a target outside the VM"), "{problem}");
        assert!(!summary(&plan, "https://argon.yougori.com", start_check(&plan).as_ref().ok()).iter().any(|line| line.starts_with("Reaches:")));
        // A question that applies again after Back, still without its answer.
        let mut plan = plan_for(&harness("strix"), &sets(&[("target", "practice")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        plan.answers.insert("target".into(), Answer::Targets(target_entries("https://staging.example.com").unwrap()));
        assert_eq!(start_check(&plan).unwrap_err(), "Strix needs an answer to \"Do you own this target or have written permission to test it?\" first.");
        plan.answers.insert("permission".into(), Answer::Yes(true));
        assert_eq!(start_check(&plan), Ok(Internet::Targets(args(&["staging.example.com:443"]), vec![])));
    }

    #[test]
    fn the_summary_names_target_depth_folder_reach_size_and_report() {
        let summed = |plan: &Plan, server: &str| summary(plan, server, Some(&resolve_reach(plan).unwrap()));
        let mut plan = plan_for(&harness("strix"), &sets(&[("target", "practice")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        settle_size(&mut plan, &Value::Null);
        assert_eq!(summed(&plan, "https://argon.yougori.com"), args(&[
            "Target: the practice app inside the VM",
            "Depth: Test safely",
            "Folder: none (an empty workspace)",
            "Reaches: only argon.yougori.com",
            "Size: 4 CPU, 8 GB memory",
            "Report: shown here only; choose a folder to keep it",
        ]));
        let dir = tempfile::tempdir().unwrap();
        let folder = std::path::absolute(dir.path()).unwrap();
        let chosen = Permissions { workspace: Some(folder.clone()), ..sets(&[("target", "https://staging.example.com"), ("permission", "yes"), ("depth", "full")]) };
        let mut plan = plan_for(&harness("strix"), &chosen, &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        // Within this computer: 2 cores and 6 GB.
        settle_size(&mut plan, &json!({"totalCpu": 2, "totalMemoryGb": 6.5}));
        // A host named by its name is held to its addresses, which other sites may share.
        assert_eq!(summed(&plan, "https://argon.yougori.com"), vec![
            "Target: https://staging.example.com".to_owned(),
            "Depth: Full exploitation".to_owned(),
            format!("Folder: a copy of {}", folder.display()),
            "Reaches: argon.yougori.com and staging.example.com:443".to_owned(),
            NAMED_HOSTS.to_owned(),
            "Size: 2 CPU, 6 GB memory".to_owned(),
            "Report: saved to your folder after review".to_owned(),
        ]);
        assert!(NAMED_HOSTS.contains("such as SSH, reach whatever answers at those addresses on the chosen ports"));
        // Addresses alone need no such word.
        let mut plan = plan_for(&harness("strix"), &sets(&[("target", "10.0.0.5:8080, http://192.168.1.20"), ("permission", "yes")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        let lines = summed(&plan, "https://argon.yougori.com");
        assert!(lines.contains(&"Reaches: argon.yougori.com and 10.0.0.5:8080, 192.168.1.20:80".to_owned()) && !lines.contains(&NAMED_HOSTS.to_owned()), "{lines:?}");
        assert!(named_target("staging.example.com:443") && named_target("jenkins:8080") && !named_target("10.0.0.5:8080") && !named_target("10.0.0.5"));
        let mut coding = plan_for(&harness("opencode"), &Permissions::default(), &no_secrets).unwrap();
        settle_size(&mut coding, &Value::Null);
        assert_eq!(summed(&coding, "https://acme.yougori.com"), args(&["Folder: none (an empty workspace)", "Reaches: only acme.yougori.com", "Size: 2 CPU, 4 GB memory"]));
    }

    #[test]
    fn the_start_hint_names_the_report_folder_only_when_there_is_one() {
        let strix = harness("strix");
        assert_eq!(start_hint(&strix, true), "prepare the VM and open Strix in this terminal; the report is saved to your folder after review");
        assert_eq!(start_hint(&strix, false), "prepare the VM and open Strix in this terminal; the report shows here and is not kept");
        assert_eq!(start_hint(&harness("opencode"), false), "prepare the VM and open OpenCode in this terminal");
        // The summary beside it says the same.
        let mut plan = plan_for(&strix, &sets(&[("target", "practice")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        assert!(summary(&plan, "https://argon.yougori.com", None).contains(&"Report: shown here only; choose a folder to keep it".to_owned()));
    }

    #[test]
    fn a_must_confirm_starts_on_no() {
        let strix = harness("strix");
        let permission = strix.question("permission").unwrap();
        // A held Enter never gives the yes; a yes given before is kept.
        assert_eq!(confirm_initial(permission, None), 1);
        assert_eq!(confirm_initial(permission, Some(&Answer::Yes(true))), 0);
        let mut plain = permission.clone();
        (plain.must, plain.required) = (false, false);
        assert_eq!(confirm_initial(&plain, None), 0);
        assert_eq!(confirm_initial(&plain, Some(&Answer::Yes(false))), 1);
        plain.default = Some("no".into());
        assert_eq!(confirm_initial(&plain, None), 1);
        assert_eq!(confirm_initial(&plain, Some(&Answer::Yes(true))), 0);
    }

    /// The menu's walk through a harness's own questions, as ask_question takes them, with the
    /// person's answers: a question it skips keeps the answer options gave; one it asks takes the
    /// answer here (none when not listed).
    fn walk(plan: &mut Plan, answers: &[(&str, Answer)], secrets: &[(&str, &str)]) -> Vec<String> {
        let mut asked = Vec::new();
        for question in plan.harness.clone().unwrap().questions {
            if skipped(plan, &question) {
                continue;
            }
            asked.push(question.id.clone());
            if let Some((_, secret)) = secrets.iter().find(|(id, _)| *id == question.id) {
                plan.secrets.insert(question.id.clone(), Zeroizing::new((*secret).to_owned()));
            } else if let Some((_, answer)) = answers.iter().find(|(id, _)| *id == question.id) {
                plan.answers.insert(question.id.clone(), answer.clone());
            } else {
                plan.answers.remove(&question.id);
            }
        }
        asked
    }

    #[test]
    fn an_answer_options_gave_comes_back_after_back_across_a_condition() {
        let strix = harness("strix");
        let address = Answer::Targets(target_entries("https://staging.example.com").unwrap());
        let login = Answer::Text("test@example.com".into());
        // YOUGORI_SECRET_LOGIN_PASSWORD and --set permission=yes are given.
        let mut plan = plan_for(&strix, &sets(&[("permission", "yes")]), &password("correct horse")).unwrap();
        // The practice app and no login: neither the permission nor the password applies.
        let asked = walk(&mut plan, &[("target", Answer::Practice), ("depth", Answer::Text("safe".into()))], &[]);
        assert_eq!(asked, ["target", "off_limits", "depth", "login_user", "source", "focus"]);
        assert!(!plan.answers.contains_key("permission") && plan.secrets.is_empty());
        // Back, then an address and a login: both apply again, with the answers options gave.
        let asked = walk(&mut plan, &[("target", address.clone()), ("depth", Answer::Text("safe".into())), ("login_user", login.clone())], &[]);
        assert_eq!(asked, ["target", "off_limits", "depth", "login_user", "source", "focus"]);
        assert_eq!(plan.answers.get("permission"), Some(&Answer::Yes(true)));
        assert_eq!(plan.secrets.get("login_password").map(|secret| secret.as_str()), Some("correct horse"));
        assert_eq!(unanswered(&plan), None);
        assert_eq!(answers_json(&plan)["permission"], json!(true));
        assert_eq!(secret_variables(&plan).len(), 1);
        // Without the variable, the password is asked once a login applies; the run cannot start
        // with the login but without its password.
        let mut plan = plan_for(&strix, &sets(&[("permission", "yes")]), &no_secrets).unwrap();
        walk(&mut plan, &[("target", Answer::Practice), ("depth", Answer::Text("safe".into()))], &[]);
        plan.answers.insert("login_user".into(), login.clone());
        assert_eq!(unanswered(&plan).map(|question| question.id.as_str()), Some("login_password"));
        assert!(start_check(&plan).unwrap_err().contains("\"Password for that login?\""));
        let asked = walk(&mut plan, &[("target", address), ("depth", Answer::Text("safe".into())), ("login_user", login)], &[("login_password", "typed")]);
        assert!(asked.contains(&"login_password".to_owned()) && !asked.contains(&"permission".to_owned()), "{asked:?}");
        assert_eq!(unanswered(&plan), None);
        // An answer left by a question that no longer applies never reaches the VM.
        let mut plan = plan_for(&strix, &sets(&[("target", "practice")]), &no_secrets).unwrap();
        settle(&mut plan).unwrap();
        plan.answers.insert("permission".into(), Answer::Yes(true));
        prune(&mut plan);
        assert!(!plan.answers.contains_key("permission"));
    }

    #[test]
    fn secret_answers_leave_the_environment_before_anything_starts() {
        // Every program this command starts (the engine, PowerShell, the launcher, the connector)
        // inherits this process's environment: once taken, none holds a secret answer.
        let name = format!("YOUGORI_SECRET_LEAK_CHECK_{}", std::process::id());
        let lower = format!("yougori_secret_lower_check_{}", std::process::id());
        std::env::set_var(&name, "correct horse");
        std::env::set_var(&lower, "battery staple");
        let taken = take_secret_variables();
        assert_eq!(taken.get(&name).map(|value| value.as_str()), Some("correct horse"));
        let lower_key = if cfg!(windows) { lower.to_ascii_uppercase() } else { lower.clone() };
        assert_eq!(taken.get(&lower_key).map(|value| value.as_str()), Some("battery staple"));
        assert!(std::env::var_os(&name).is_none() && std::env::var_os(&lower).is_none());
        let (shell, listing) = if cfg!(windows) { ("cmd", ["/C", "set"]) } else { ("sh", ["-c", "env"]) };
        let listed = Command::new(shell).args(listing).stdin(Stdio::null()).output().unwrap();
        let listed = String::from_utf8_lossy(&listed.stdout).to_ascii_uppercase();
        assert!(!listed.contains("YOUGORI_SECRET_"), "a started program inherited a secret answer");
        // The run's own answers come from what was taken.
        let environment = |variable: &str| taken.get(variable).cloned();
        let mut login = harness("strix");
        login.questions.iter_mut().find(|question| question.id == "login_password").unwrap().id = format!("leak_check_{}", std::process::id());
        let plan = plan_for(&login, &sets(&[("target", "practice")]), &environment).unwrap();
        assert_eq!(plan.secrets.values().map(|value| value.as_str()).collect::<Vec<_>>(), ["correct horse"]);
        assert!(!format!("{plan:?}").contains("correct horse"));
    }

    #[test]
    fn stages_left_by_runs_that_ended_without_cleaning_up_are_cleared() {
        let root = tempfile::tempdir().unwrap();
        let made = |name: &str| {
            let stage = root.path().join(name);
            std::fs::create_dir(&stage).unwrap();
            std::fs::write(stage.join(ANSWERS_FILE), b"{\"target\":\"https://staging.example.com\"}").unwrap();
            std::fs::write(stage.join("solver.py"), b"").unwrap();
            stage
        };
        let now = std::time::SystemTime::now();
        let aged = |stage: &Path, age: std::time::Duration| {
            let lease = std::fs::OpenOptions::new().write(true).open(stage.join(LEASE)).unwrap();
            lease.set_modified(now - age).unwrap();
        };
        // A run still going holds its lease, however old.
        let running = made("client-running");
        let held = Lease::hold(&running).unwrap();
        aged(&running, STALE_STAGE * 3);
        // A run that ended an hour ago without cleaning up, and one two days ago.
        let recent = made("client-recent");
        drop(Lease::hold(&recent).unwrap());
        aged(&recent, std::time::Duration::from_secs(3600));
        let stale = made("client-stale");
        drop(Lease::hold(&stale).unwrap());
        aged(&stale, STALE_STAGE * 2);
        // An older Yougori's stage has no lease and may belong to a run still going; a lease
        // that does not say it is one is not taken for one; other folders are not stages.
        let older = made("client-older");
        let odd = made("client-odd");
        std::fs::write(odd.join(LEASE), b"something else entirely\n").unwrap();
        let other = made("contributions");
        sweep_stages(root.path(), now);
        assert!(running.join(ANSWERS_FILE).is_file() && running.join(LEASE).is_file());
        // The launcher read its answers as it started: they go at once; its files stay a day.
        assert!(!recent.join(ANSWERS_FILE).exists() && recent.join("solver.py").is_file());
        assert!(!stale.exists());
        assert!(older.join(ANSWERS_FILE).is_file() && odd.join(ANSWERS_FILE).is_file() && other.join(ANSWERS_FILE).is_file());
        // Once the run ends, its stage is the next sweep's.
        drop(held);
        sweep_stages(root.path(), now);
        assert!(!running.exists());
        // A lease is made only once, in a new stage.
        assert!(Lease::hold(&older).is_ok() && Lease::hold(&older).is_err());
    }

    #[tokio::test]
    async fn the_launchers_exit_code_comes_back() {
        let (shell, script) = if cfg!(windows) { ("cmd", ["/C", "exit 3"]) } else { ("sh", ["-c", "exit 3"]) };
        let mut command = Command::new(shell);
        command.args(script).stdin(Stdio::null());
        assert_eq!(wait_for(command).await.unwrap().code(), Some(3));
        let missing = wait_for(Command::new("no-such-launcher-here")).await.unwrap_err();
        assert!(missing.starts_with("Could not start Yougori inference"), "{missing}");
    }

    #[cfg(windows)]
    const CTRL_BREAK_COPY: &str = "YOUGORI_TEST_CTRL_BREAK_COPY";

    /// Ctrl+Break interrupts the wait like Ctrl+C rather than ending this process while the
    /// launcher, which hears it too, is still cleaning up. A copy of these tests presses it in a
    /// console of its own with no window, so nothing else hears it.
    #[cfg(windows)]
    #[test]
    fn ctrl_break_waits_for_the_launcher_instead_of_ending_the_cli() {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["inference::tests::ctrl_break_in_a_console_of_its_own", "--exact", "--nocapture", "--test-threads=1"])
            .env(CTRL_BREAK_COPY, "1")
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success() && said.contains("Ctrl+Break heard"), "{:?}\n{said}", output.status);
    }

    /// The copy's half of the test above; it does nothing in an ordinary run.
    #[cfg(windows)]
    #[tokio::test]
    async fn ctrl_break_in_a_console_of_its_own() {
        use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
        if std::env::var_os(CTRL_BREAK_COPY).is_none() {
            return;
        }
        let mut heard = interrupts();
        // Group 0: every process on this console, which is this copy alone.
        assert_ne!(unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) }, 0, "{}", std::io::Error::last_os_error());
        tokio::time::timeout(std::time::Duration::from_secs(10), interrupted(&mut heard)).await.expect("Ctrl+Break was not heard");
        // The default handler would have ended the process by now; give it the chance.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        println!("Ctrl+Break heard");
    }

    #[test]
    fn the_models_come_from_the_launcher_once_signed_in() {
        assert_eq!(models_reply(b"{\"models\":[\"a/b\",\"c/d\"]}\n", Some(0), "s"), Ok(args(&["a/b", "c/d"])));
        assert_eq!(models_reply(br#"{"error":"The server refused sign-in. Check the server address and try again."}"#, Some(1), "s"),
            Err("The server refused sign-in. Check the server address and try again.".into()));
        assert_eq!(models_reply(b"", Some(130), "s"), Err(crate::cli_ui::CANCELLED.into()));
        assert!(models_reply(b"not json", Some(1), "s").unwrap_err().starts_with("Could not read your models on s."));
        assert!(models_reply(br#"{"models":[7]}"#, Some(0), "s").is_err());
        assert!(models_reply(br#"{"models":["a"]}"#, Some(1), "s").is_err());
        let site = "argon.yougori.com";
        assert_eq!(pick_model(&args(&["only/model"]), None, site), Ok("only/model".into()));
        assert_eq!(pick_model(&args(&["a/b", "c/d"]), Some("c/d"), site), Ok("c/d".into()));
        assert_eq!(pick_model(&args(&["a/b", "c/d"]), None, site), Err("Choose the model with --model ID. argon.yougori.com has: a/b, c/d.".into()));
        assert_eq!(pick_model(&args(&["a/b"]), Some("z/z"), site), Err("argon.yougori.com has no model z/z for your key. It has: a/b.".into()));
        assert!(pick_model(&[], None, site).unwrap_err().contains("has no models for your key yet"));
    }
    #[test]
    fn stages_only_bundled_client_and_keeps_server_as_data() {
        let dir = tempfile::tempdir().unwrap();
        stage(dir.path(), "https://example.com").unwrap();
        let value: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("connection.json")).unwrap())
                .unwrap();
        assert_eq!(value["server"], "https://example.com");
        assert!(dir.path().join("harnesses/transport.py").is_file());
        assert!(dir.path().join("vm_host.py").is_file());
        assert!(dir.path().join("compute_node.py").is_file());
    }
    #[test]
    fn reads_the_websites_list_of_models_for_computers() {
        let listed = offered(br#"{"models":["Qwen/Qwen3-8B","qwen/qwen3-8b","test/one"],"most":3}"#).unwrap();
        assert_eq!((listed.models.clone(), listed.most), (vec!["Qwen/Qwen3-8B".to_owned(), "test/one".to_owned()], 3));
        assert_eq!(listed.find("QWEN/qwen3-8B"), Some(&"Qwen/Qwen3-8B".to_owned()));
        assert_eq!(listed.find("Other/Model"), None);
        // An older website names no limit; a website never raises it past three.
        assert_eq!(offered(br#"{"models":[]}"#).unwrap(), Offered { most: 3, ..Offered::default() });
        assert_eq!(offered(br#"{"models":[],"most":9}"#).unwrap().most, 3);
        for bad in [&b"not json"[..], br#"{"models":{}}"#, br#"{"models":["no-owner"]}"#, br#"{"models":["a/b/c"]}"#, br#"{"models":["a/b c"]}"#, br#"{"models":[7]}"#] {
            assert!(offered(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(repository("hf-internal/Tiny_model.v2") && !repository("/x") && !repository("x/"));
    }
    #[test]
    fn a_model_this_computers_gpu_cannot_run_is_not_offered() {
        let listed = offered(br#"{"models":["Qwen/Qwen3-8B","big/model","fp8/model"],"most":3,"needs":{
            "Qwen/Qwen3-8B":{"gpu_gb":21,"compute":8.0,"summary":"Chat model"},"big/model":{"gpu_gb":159,"compute":8.0},
            "fp8/model":{"gpu_gb":13,"compute":8.9},"broken/model":{"gpu_gb":"a lot"}}}"#).unwrap();
        assert_eq!(listed.need("qwen/qwen3-8b"), Some(&Need { gpu_gb: 21.0, compute: 8.0 }));
        assert_eq!(listed.need("broken/model"), None);
        // nvidia-smi's lines: an RTX 3090 (24 GB, Ampere 8.6).
        let rtx_3090 = gpus("24576, 8.6\nnot a gpu line\n");
        assert_eq!(rtx_3090, vec![Gpu { memory_gb: 24.0, compute: 8.6 }]);
        assert_eq!(fit(listed.need("Qwen/Qwen3-8B"), &rtx_3090), Some(Ok(())));
        assert_eq!(fit(listed.need("big/model"), &rtx_3090), Some(Err("needs about 159 GB of GPU memory; this computer's GPU has 24 GB".into())));
        assert_eq!(fit(listed.need("fp8/model"), &rtx_3090), Some(Err("needs a newer GPU than this computer's".into())));
        // Unknown either way: Yougori checks again before installing.
        assert_eq!(fit(listed.need("other/model"), &rtx_3090), None);
        assert_eq!(fit(listed.need("big/model"), &[]), None);
        let given = Contribution { models: vec!["big/model".into()], sandbox: None };
        assert_eq!(check(given, &listed, &rtx_3090, "argon.yougori.com").unwrap_err(),
            "This computer cannot run big/model: it needs about 159 GB of GPU memory; this computer's GPU has 24 GB.");
    }
    #[test]
    fn options_answer_the_questions_for_scripts() {
        let mut extra = args(&["--reconnect", "--models", "qwen/qwen3-8b, test/one", "--sandbox", "4,8,2"]);
        let given = connect_flags(&mut extra).unwrap().unwrap();
        assert_eq!(extra, args(&["--reconnect"]));
        assert_eq!(given, Contribution { models: vec!["qwen/qwen3-8b".into(), "test/one".into()], sandbox: Some((4, 8, 2)) });
        assert_eq!(connect_flags(&mut args(&["--reconnect"])).unwrap(), None);
        for bad in [&["--models", "a/b"][..], &["--sandbox", "none"], &["--models", "a/b", "--sandbox", "0,8,2"], &["--models", "a/b", "--sandbox", "4,8"], &["--models"]] {
            assert!(connect_flags(&mut args(bad)).is_err(), "{bad:?}");
        }
        assert!(options(&args(&["connect", "https://example.com", "--models", "a/b", "--sandbox", "none", "--reconnect"])).is_ok());
        assert!(options(&args(&["connect", "https://example.com", "--models"])).is_err());
        // Checked against the website's list: its spelling, at most `most`, something to give.
        let listed = Offered { models: vec!["Qwen/Qwen3-8B".into(), "test/one".into(), "test/two".into(), "test/three".into()], most: 3, ..Offered::default() };
        assert_eq!(check(given, &listed, &[], "argon.yougori.com").unwrap().models, vec!["Qwen/Qwen3-8B".to_owned(), "test/one".to_owned()]);
        let some = |models: &[&str], sandbox| Contribution { models: models.iter().map(|m| m.to_string()).collect(), sandbox };
        assert_eq!(check(some(&["Other/Model"], None), &listed, &[], "argon.yougori.com").unwrap_err(),
            "argon.yougori.com does not list Other/Model for computers. It lists: Qwen/Qwen3-8B, test/one, test/two, test/three.");
        assert!(check(some(&["test/one", "test/two", "test/three", "Qwen/Qwen3-8B"], None), &listed, &[], "a").unwrap_err().contains("at most 3"));
        assert!(check(some(&[], None), &listed, &[], "a").unwrap_err().starts_with("Nothing to give"));
        assert_eq!(check(some(&[], Some((2, 4, 1))), &listed, &[], "a").unwrap().sandbox_flag(), "2,4,1");
        assert_eq!(check(some(&["a/b"], None), &Offered::default(), &[], "argon.yougori.com").unwrap_err(), "argon.yougori.com lists no models for computers to run yet.");
    }
    #[test]
    fn the_review_names_what_is_installed_and_deleted() {
        let chosen = Contribution { models: vec!["Qwen/Qwen3-8B".into(), "test/one".into()], sandbox: Some((4, 8, 2)) };
        let here = |repo: &str| repo == "test/one";
        assert_eq!(chosen.summary(&here, &["test/old".into()]), args(&[
            "Models: Qwen/Qwen3-8B (installs now), test/one (installed)",
            "Deletes from this computer: test/old",
            "Sandbox VMs: up to 2 at once, within 4 CPU cores and 8 GB memory in all",
        ]));
        let vms = Gives::Sandbox.apply(&chosen);
        assert_eq!(vms.summary(&here, &[]), args(&["Models: none", "Sandbox VMs: up to 2 at once, within 4 CPU cores and 8 GB memory in all"]));
        assert_eq!(Gives::Models.apply(&chosen).sandbox_flag(), "none");
        assert_eq!(Gives::Both.apply(&chosen), chosen);
        // Only a model Yougori installed for the website is deleted when it is dropped.
        let saved = Saved { models: vec![
            SavedModel { repo: "Qwen/Qwen3-8B".into(), environment: Some("env-1".into()), installed: true },
            SavedModel { repo: "test/old".into(), environment: Some("env-2".into()), installed: true },
            SavedModel { repo: "Own/Model".into(), environment: Some("env-3".into()), installed: false },
        ], sandbox: None };
        assert_eq!(dropped(Some(&saved), &Contribution { models: vec!["qwen/qwen3-8b".into()], sandbox: None }), args(&["test/old"]));
        assert_eq!(dropped(None, &chosen), Vec::<String>::new());
        assert_eq!(up_to(1), "one");
        assert_eq!(up_to(3), "1 to 3");
    }
    #[test]
    fn an_environment_on_the_vllm_image_is_known() {
        assert!(on_vllm(&json!({"runtime": "docker.io/vllm/vllm-openai@sha256:c291"})));
        assert!(!on_vllm(&json!({"runtime": "docker.io/pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime"})));
        assert!(!on_vllm(&json!({})));
    }
    #[test]
    fn keeps_the_choices_per_website() {
        let dir = tempfile::tempdir().unwrap();
        let argon = saved_path(dir.path(), "https://argon.yougori.com");
        assert_ne!(argon, saved_path(dir.path(), "https://demo.yougori.com"));
        assert_eq!(load_saved(&argon), None);
        let saved = Saved { models: vec![SavedModel { repo: "Qwen/Qwen3-8B".into(), environment: None, installed: true }], sandbox: Some((2, 4, 1)) };
        store_saved(&argon, &saved).unwrap();
        assert_eq!(load_saved(&argon), Some(saved.clone()));
        assert_eq!(Contribution::of(&saved), Contribution { models: vec!["Qwen/Qwen3-8B".into()], sandbox: Some((2, 4, 1)) });
        std::fs::write(&argon, "not json").unwrap();
        assert_eq!(load_saved(&argon), None);
    }
    #[test]
    fn website_installs_ask_for_the_agent_limits() {
        assert_eq!(install_request("Qwen/Qwen3-8B", true), json!({"model": "Qwen/Qwen3-8B", "runner": "vllm", "resources": {"agentApi": true}}));
        assert_eq!(install_request("Qwen/Qwen3-8B", false), json!({"model": "Qwen/Qwen3-8B", "resources": {"agentApi": true}}));
    }
    #[test]
    fn answers_once_ready_or_loadable_on_demand() {
        let on = json!({"enabled": true});
        for (status, expected) in [
            (json!({"status": "ready"}), true),
            (json!({"status": "ready", "weightsVerified": true}), true),
            // Unloaded after idle minutes, or on its way back: the next request loads it.
            (json!({"status": "idle", "weightsVerified": true, "optimizer": on}), true),
            (json!({"status": "queued", "weightsVerified": true, "optimizer": on}), true),
            (json!({"status": "freeing_memory", "weightsVerified": true, "optimizer": on}), true),
            (json!({"status": "loading", "weightsVerified": true, "optimizer": on}), true),
            (json!({"status": "unloading", "weightsVerified": true, "optimizer": on}), true),
            (json!({"status": "idle", "weightsVerified": true, "optimizer": {"enabled": false}}), false),
            // Before its first load: nothing to wake yet.
            (json!({"status": "queued", "optimizer": on}), false),
            (json!({"status": "loading", "optimizer": on}), false),
            (json!({"status": "downloading", "download": {"receivedBytes": 1, "totalBytes": 2}}), false),
            (json!({"status": "verifying"}), false),
            (json!({"status": "error", "error": "CUDA out of memory"}), false),
            (json!({}), false),
        ] {
            assert_eq!(answers(&status), expected, "{status}");
        }
    }
    #[test]
    fn waiting_step_names_the_phase_and_download_bytes() {
        let repo = "Qwen/Qwen3-4B";
        let download = json!({"status": "downloading", "download": {"receivedBytes": 3_400_000_000u64, "totalBytes": 8_000_000_000u64, "bytesPerSecond": 5.2e6}});
        assert_eq!(waiting_step(&download, repo), ("Downloading Qwen/Qwen3-4B".to_owned(), Some((3_400_000_000, 8_000_000_000))));
        // A size not known yet shows no bar; more than the size never shows past it.
        assert_eq!(waiting_step(&json!({"status": "downloading", "download": {"receivedBytes": 0, "totalBytes": 0}}), repo).1, None);
        assert_eq!(waiting_step(&json!({"status": "downloading", "download": {"receivedBytes": 9.0, "totalBytes": 8}}), repo).1, Some((8, 8)));
        let waiting = json!({"status": "queued", "optimizer": {"waitingFor": "Model A is using the GPU. This model loads once it is free."}});
        assert_eq!(waiting_step(&waiting, repo), ("Waiting for the GPU · Model A is using the GPU. This model loads once it is free.".to_owned(), None));
        assert_eq!(waiting_step(&json!({"status": "freeing_memory", "optimizer": {}}), repo).0, "Waiting for the GPU");
        assert_eq!(waiting_step(&json!({"status": "verifying"}), repo).0, "Checking Qwen/Qwen3-4B's files");
        assert_eq!(waiting_step(&json!({"status": "loading"}), repo).0, "Loading Qwen/Qwen3-4B onto the GPU");
        assert_eq!(waiting_step(&json!({"status": "installing"}), repo).0, "Preparing Qwen/Qwen3-4B");
        assert_eq!(waiting_step(&json!({}), repo).0, "Starting Qwen/Qwen3-4B");
    }
    #[tokio::test]
    async fn until_answering_follows_the_model_until_it_answers() {
        // It draws on the shared screen: one painter test at a time.
        let _painted = crate::cli_ui::tests::Painted::fresh();
        let total = 8_000_000_000u64;
        let replies = std::cell::RefCell::new(
            vec![
                Err("Model server is starting. Check Logs for installation/download progress and try again.".to_owned()),
                Ok(json!({"status": "downloading", "download": {"receivedBytes": total / 10, "totalBytes": total, "bytesPerSecond": 5e6}})),
                Ok(json!({"status": "downloading", "download": {"receivedBytes": total / 10 * 9, "totalBytes": total, "bytesPerSecond": 5e6}})),
                Ok(json!({"status": "loading"})),
                Ok(json!({"status": "ready", "weightsVerified": true})),
            ]
            .into_iter(),
        );
        let asked = std::cell::RefCell::new(Vec::new());
        let result = until_answering("env-1", "Qwen/Qwen3-4B", std::time::Duration::from_millis(1), |method, params| {
            asked.borrow_mut().push((method, params));
            std::future::ready(replies.borrow_mut().next().expect("asked again after the model answered"))
        })
        .await;
        assert_eq!(result, Ok(()));
        let asked = asked.into_inner();
        assert_eq!(asked.len(), 5);
        assert!(asked.iter().all(|(method, params)| *method == "model_status" && *params == json!({"environmentId": "env-1"})), "{asked:?}");
    }
    #[tokio::test]
    async fn until_answering_stops_on_a_load_error_or_a_missing_environment() {
        // It draws on the shared screen: one painter test at a time.
        let _painted = crate::cli_ui::tests::Painted::fresh();
        let every = std::time::Duration::from_millis(1);
        let failed = until_answering("env-1", "Qwen/Qwen3-4B", every, |_, _| {
            std::future::ready(Ok(json!({"status": "error", "error": "CUDA out of memory while loading the model"})))
        })
        .await;
        assert_eq!(failed, Err("Qwen/Qwen3-4B could not load: CUDA out of memory while loading the model".to_owned()));
        let unsaid = until_answering("env-1", "Qwen/Qwen3-4B", every, |_, _| std::future::ready(Ok(json!({"status": "error"})))).await.unwrap_err();
        assert!(unsaid.contains("yougori logs env-1"), "{unsaid}");
        for gone in ["Model environment not found", "Start the model environment first"] {
            let error = until_answering("env-1", "Qwen/Qwen3-4B", every, |_, _| std::future::ready(Err(gone.to_owned()))).await.unwrap_err();
            assert!(error.contains(gone) && error.contains("no longer running"), "{error}");
        }
    }
    #[tokio::test]
    async fn kept_models_take_the_agent_limits_and_restart_only_when_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = saved_path(dir.path(), "https://argon.yougori.com");
        let environments = vec![
            json!({"id": "env-run", "kind": "container", "status": "running", "description": "Hugging Face · Own/Running"}),
            json!({"id": "env-stop", "kind": "container", "status": "stopped", "description": "Hugging Face · Own/Stopped"}),
            json!({"id": "env-has", "kind": "container", "status": "running", "description": "Hugging Face · Own/Agents"}),
        ];
        let chosen = Contribution { models: vec!["Own/Running".into(), "Own/Stopped".into(), "Own/Agents".into()], sandbox: None };
        for older in [false, true] {
            let _engine = crate::client::fake_engine::install(move |method, params| match method {
                // An engine older than this CLI lacks the method.
                "model_agent_api" if older => Err("Unknown method 'model_agent_api'. Run yougori schema.".into()),
                // As the engine answers: restartRequired only while limits saved after the container
                // was configured have not reached it, so not for env-has, which runs with them, nor
                // for the stopped model, which takes them as it starts.
                "model_agent_api" => Ok(json!({"agentApi": true, "changed": params["environmentId"] != "env-has",
                                               "restartRequired": params["environmentId"] == "env-run"})),
                "stop_model" | "start_model" => Ok(json!({})),
                "model_status" => Ok(json!({"status": "ready", "weightsVerified": true})),
                other => Err(format!("This test does not expect {other}.")),
            });
            let applied = apply(&chosen, None, &environments, &path).await.unwrap();
            // The person's own running models keep running after a disconnect; the stopped one stops again.
            assert_eq!(applied, Applied { share: vec!["env-run".into(), "env-stop".into(), "env-has".into()], release: vec!["env-stop".into()] });
            let asked: Vec<String> = crate::client::fake_engine::calls()
                .into_iter()
                .map(|(method, params)| format!("{method} {}", params["environmentId"].as_str().unwrap_or("")))
                .collect();
            let expected: &[&str] = if older {
                &["model_agent_api env-run", "model_status env-run", "model_agent_api env-stop", "start_model env-stop", "model_status env-stop",
                  "model_agent_api env-has", "model_status env-has"]
            } else {
                &["model_agent_api env-run", "stop_model env-run", "start_model env-run", "model_status env-run",
                  "model_agent_api env-stop", "start_model env-stop", "model_status env-stop",
                  "model_agent_api env-has", "model_status env-has"]
            };
            assert_eq!(asked, expected, "older engine: {older}");
        }
        assert!(agent_limits_note("Own/Running", "The running Yougori engine does not support this yet (model_agent_api); it is older than this CLI.")
            .is_some_and(|note| note.contains("yougori app quit --yes")));
        assert_eq!(agent_limits_note("Own/Draw", "Only a chat model takes the agent limits."), None);
    }
    #[test]
    fn only_a_running_model_without_the_limits_restarts() {
        assert!(restarts_for_agent_limits(&json!({"agentApi": true, "changed": true, "restartRequired": true})));
        // Saved by an earlier connect whose restart failed: the engine still says the model lacks them.
        assert!(restarts_for_agent_limits(&json!({"agentApi": true, "changed": false, "restartRequired": true})));
        // Installed with them, or not running (it takes them as it starts).
        assert!(!restarts_for_agent_limits(&json!({"agentApi": true, "changed": false, "restartRequired": false})));
        assert!(!restarts_for_agent_limits(&json!({"agentApi": true, "changed": true, "restartRequired": false})));
        assert!(!restarts_for_agent_limits(&json!({})));
    }
    #[tokio::test]
    async fn a_restart_for_the_agent_limits_does_not_leave_the_model_stopped() {
        let retry = std::time::Duration::from_millis(1);
        let refusals = std::rc::Rc::new(std::cell::Cell::new(1));
        let left = refusals.clone();
        let _engine = crate::client::fake_engine::install(move |method, _| match method {
            "stop_model" => Ok(json!({"stopped": true})),
            "start_model" if left.get() > 0 => {
                left.set(left.get() - 1);
                Err("Another lifecycle or network operation is changing this environment; retry after that operation finishes.".into())
            }
            "start_model" => Ok(json!({})),
            other => Err(format!("This test does not expect {other}.")),
        });
        // A start refused right after the stop is tried once more.
        assert_eq!(restart_with_agent_limits("env-run", "Own/Running", retry).await, Ok(()));
        let asked: Vec<String> = crate::client::fake_engine::calls().into_iter().map(|(method, _)| method).collect();
        assert_eq!(asked, ["stop_model", "start_model", "start_model"]);
        // Refused twice, it is stopped: the error says so and how to start it.
        refusals.set(2);
        let error = restart_with_agent_limits("env-run", "Own/Running", retry).await.unwrap_err();
        assert!(error.starts_with("Own/Running stopped for its restart and could not start again: Another lifecycle"), "{error}");
        assert!(error.ends_with("Start it with: yougori start env-run"), "{error}");
    }
}
