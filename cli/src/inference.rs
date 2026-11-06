//! Yougori-owned inference clients. No website-supplied host scripts are executed.
use base64::Engine as _;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
pub const HELP: &str = "yougori inference connect URL [--reconnect]\n  Choose models or VM capacity to contribute, then approve on the website.\n\nyougori inference run HARNESS --server URL [--workspace PATH] [--model ID]\n    [--internet inference|sites|full] [--sites HOST,HOST] [--cpu N]\n    [--memory GB] [--yes]\n  Ask what the harness may use, then start it in a Yougori Sandbox VM: a folder copied in\n  (changes come back only after your review), what it can reach (only this inference, sites\n  you choose, or the whole internet as well; prompts and replies always go to the inference),\n  CPU and memory.\n  Options given skip their question; --yes keeps the defaults for the rest without asking.\n\nyougori inference install HARNESS --server URL\n  Prepare the VM image without starting the harness.\n\nYougori manages the client and private runtime. No separate solver-* installation.\nRun the same command next time. Ctrl+C disconnects.\n";
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
    harness: String,
    server: String,
    extra: Vec<String>,
}
fn options(args: &[String]) -> Result<Options, String> {
    let action = args.first().map(String::as_str).ok_or(HELP)?;
    if action == "connect" {
        let server = origin(args.get(1).ok_or(HELP)?)?;
        if args[2..]
            .iter()
            .any(|a| !matches!(a.as_str(), "--reconnect" | "--help" | "-h"))
        {
            return Err(HELP.into());
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
    let harness = args.get(1).ok_or(HELP)?.clone();
    let catalog: Value = serde_json::from_str(PACKAGES).map_err(|e| e.to_string())?;
    if catalog.get(&harness).is_none() {
        return Err(format!(
            "Unknown harness {harness}. Available: {}",
            catalog
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let mut server = None;
    let mut extra = Vec::new();
    let mut i = 2;
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
    Full,
}

impl Internet {
    fn flag(&self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::Sites(_) => "sites",
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

/// What the person running a harness allowed it, from options or the questions before its VM
/// starts. `None` keeps the launcher's default.
#[derive(Clone, Debug, Default, PartialEq)]
struct Permissions {
    workspace: Option<PathBuf>,
    internet: Option<Internet>,
    cpu: Option<u32>,
    memory: Option<u32>,
    /// `--yes`: no questions; options given and defaults for the rest.
    yes: bool,
}

impl Permissions {
    /// The launcher's options for these choices, placed before any `--` tool arguments.
    fn arguments(&self) -> Vec<String> {
        let mut arguments = Vec::new();
        if let Some(folder) = &self.workspace {
            arguments.extend(["--workspace".to_owned(), folder.display().to_string()]);
        }
        if let Some(cpu) = self.cpu {
            arguments.extend(["--cpu".to_owned(), cpu.to_string()]);
        }
        if let Some(memory) = self.memory {
            arguments.extend(["--memory".to_owned(), memory.to_string()]);
        }
        let internet = self.internet.clone().unwrap_or(Internet::Inference);
        arguments.extend(["--internet".to_owned(), internet.flag().to_owned()]);
        if let Internet::Sites(sites) = &internet {
            arguments.extend(["--sites".to_owned(), sites.join(",")]);
        }
        arguments
    }
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

/// Takes the permission options out of `extra` (those before `--`); the rest stays for the
/// launcher and, after `--`, for the tool.
fn permissions(extra: &mut Vec<String>) -> Result<Permissions, String> {
    let end = extra.iter().position(|a| a == "--").unwrap_or(extra.len());
    let mut chosen = Permissions::default();
    let mut kept = Vec::new();
    let (mut wants_sites, mut sites) = (false, None);
    let mut i = 0;
    while i < end {
        let flag = extra[i].as_str();
        let needs_value = matches!(flag, "--workspace" | "--cpu" | "--memory" | "--internet" | "--sites");
        let value = if needs_value {
            i += 1;
            Some(
                extra[..end]
                    .get(i)
                    .ok_or_else(|| format!("{flag} needs a value."))?
                    .as_str(),
            )
        } else {
            None
        };
        match (flag, value) {
            ("--workspace", Some(v)) => chosen.workspace = Some(project_folder(v)?),
            ("--cpu", Some(v)) => chosen.cpu = Some(count(v, 1, 255, "--cpu")?),
            ("--memory", Some(v)) => chosen.memory = Some(count(v, 1, 1024, "--memory")?),
            ("--internet", Some("inference")) => chosen.internet = Some(Internet::Inference),
            ("--internet", Some("sites")) => wants_sites = true,
            ("--internet", Some("full")) => chosen.internet = Some(Internet::Full),
            ("--internet", Some(_)) => {
                return Err("--internet takes inference (only this inference), sites (also the --sites) or full (the whole internet as well).".into())
            }
            ("--sites", Some(v)) => sites = Some(site_names(v)?),
            ("--yes", None) => chosen.yes = true,
            _ => kept.push(extra[i].clone()),
        }
        i += 1;
    }
    match (wants_sites, sites, &chosen.internet) {
        (_, Some(list), None) => chosen.internet = Some(Internet::Sites(list)),
        (_, Some(_), Some(_)) => return Err("--sites goes with --internet sites.".into()),
        (true, None, _) => return Err("Add --sites with the sites the harness may reach, such as github.com,pypi.org.".into()),
        (false, None, _) => {}
    }
    kept.extend_from_slice(&extra[end..]);
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
        Internet::Full => format!("{} and the whole internet", site_name(server)),
    }
}

fn default_memory(harness: &str) -> u32 {
    if harness == "shannon" {
        6
    } else {
        4
    }
}

/// The questions before a harness VM starts, as one wizard with Back. An option given on the
/// command line skips its question. Cancelling starts nothing.
fn ask(chosen: &mut Permissions, harness: &str, server: &str, host: &Value) -> Result<(), String> {
    use crate::cli_ui as ui;
    let preset = (
        chosen.workspace.is_some(),
        chosen.internet.is_some(),
        chosen.cpu.is_some() && chosen.memory.is_some(),
    );
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 if !preset.0 => choose_folder(chosen),
            1 if !preset.1 => choose_internet(chosen, server),
            2 if !preset.2 => choose_size(chosen, harness, host),
            3 => confirm(chosen, harness, server),
            0..=2 => Ok(false),
            _ => break,
        };
        steps.next(asked)?;
    }
    Ok(())
}

fn choose_folder(chosen: &mut Permissions) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let here = std::env::current_dir()
        .ok()
        .and_then(|folder| project_folder(&folder.to_string_lossy()).ok());
    let mut choices = vec![Choice::new(
        "No folder",
        "the harness starts in an empty workspace; nothing on this PC is copied in",
    )];
    if let Some(here) = &here {
        choices.push(Choice::new(
            format!("This folder: {}", here.display()),
            "a copy goes into the VM; changes come back only after you review them",
        ));
    }
    choices.push(Choice::new("Another folder", "type the path of a project folder to copy in"));
    let initial = match &chosen.workspace {
        None => 0,
        Some(folder) if Some(folder) == here.as_ref() => 1,
        Some(_) => choices.len() - 1,
    };
    let picked = ui::select("What should the harness work on?", &[], &choices, initial)?;
    chosen.workspace = if picked == 0 {
        None
    } else if here.is_some() && picked == 1 {
        here
    } else {
        let typed = ui::input("Folder to copy into the VM", "", false, &|value: &str| {
            project_folder(value).map(|folder| folder.display().to_string())
        })?;
        Some(PathBuf::from(typed))
    };
    Ok(true)
}

fn choose_internet(chosen: &mut Permissions, server: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let site = site_name(server);
    let notes = vec![format!(
        "Prompts and replies always go to {site}. Yougori relays them and keeps the API key outside the VM."
    )];
    let choices = [
        Choice::new("Only this inference", format!("{site} and nothing else")).recommended(true),
        Choice::new(
            "This inference and sites I choose",
            "such as github.com or pypi.org, over HTTPS; the VM still has no network card",
        ),
        Choice::new(
            "The whole internet as well",
            "any website, such as package downloads; the harness could also send what it reads to any site",
        ),
    ];
    let initial = match &chosen.internet {
        Some(Internet::Sites(_)) => 1,
        Some(Internet::Full) => 2,
        _ => 0,
    };
    chosen.internet = Some(match ui::select("What can the harness reach?", &notes, &choices, initial)? {
        1 => {
            let before = match &chosen.internet {
                Some(Internet::Sites(sites)) => sites.join(", "),
                _ => String::new(),
            };
            let typed = ui::input("Sites the harness may reach, separated by commas (each covers its subdomains)", &before, false, &|value: &str| {
                site_names(value).map(|names| names.join(", "))
            })?;
            Internet::Sites(site_names(&typed)?)
        }
        2 => Internet::Full,
        _ => Internet::Inference,
    });
    Ok(true)
}

fn choose_size(chosen: &mut Permissions, harness: &str, host: &Value) -> Result<bool, String> {
    use crate::cli_ui as ui;
    let limit = |key: &str, ceiling: f64, fallback: u32| {
        host[key]
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 1.0)
            .map_or(fallback, |value| value.min(ceiling).floor() as u32)
    };
    let memory_default = default_memory(harness);
    let (cpu_max, memory_max) = (limit("totalCpu", 255.0, 2), limit("totalMemoryGb", 1024.0, memory_default).max(2));
    let mut sliders = [
        ui::Slider {
            label: "CPU",
            unit: "cores",
            value: chosen.cpu.unwrap_or(2).min(cpu_max),
            min: 1,
            max: cpu_max,
            default: 2.min(cpu_max),
        },
        ui::Slider {
            label: "Memory",
            unit: "GB",
            value: chosen.memory.unwrap_or(memory_default).clamp(2, memory_max),
            min: 2,
            max: memory_max,
            default: memory_default.min(memory_max),
        },
    ];
    ui::sliders("Size the harness VM", "Choose CPU cores and memory for the VM.", &mut sliders)?;
    chosen.cpu = Some(sliders[0].value);
    chosen.memory = Some(sliders[1].value);
    Ok(true)
}

fn summary(chosen: &Permissions, harness: &str, server: &str) -> Vec<String> {
    vec![
        format!(
            "Folder: {}",
            chosen.workspace.as_ref().map_or("none (an empty workspace)".to_owned(), |folder| format!(
                "a copy of {}",
                folder.display()
            ))
        ),
        format!("Reaches: {}", internet_words(chosen.internet.as_ref().unwrap_or(&Internet::Inference), server)),
        format!(
            "Size: {} CPU, {} GB memory",
            chosen.cpu.unwrap_or(2),
            chosen.memory.unwrap_or(default_memory(harness))
        ),
    ]
}

fn confirm(chosen: &Permissions, harness: &str, server: &str) -> Result<bool, String> {
    use crate::cli_ui::{self as ui, Choice};
    let choices = [
        Choice::new("Start", "prepare the VM and open the harness in this terminal"),
        Choice::new("Cancel", "nothing is started"),
    ];
    let picked = ui::select(&format!("Start {harness} with these settings?"), &summary(chosen, harness, server), &choices, 0)?;
    if picked == 1 {
        return Err(crate::wire::cancelled("Nothing was started."));
    }
    Ok(true)
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

/// Before a harness VM starts: the engine runs, the harness can start on this server and this
/// computer, and the person running it chose what it may use. Returns the launcher's exit code
/// when the check refused.
async fn prepare_run(opts: &mut Options, python: &Path, stage: &Path, executable: &Path) -> Result<Option<i32>, String> {
    use crate::cli_ui as ui;
    let mut chosen = permissions(&mut opts.extra)?;
    ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
    let check = launcher(python, stage, executable)
        .arg("check")
        .arg(&opts.harness)
        .arg("--server")
        .arg(&opts.server)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("Could not start Yougori inference: {e}"))?;
    if !check.success() {
        return Ok(Some(check.code().unwrap_or(1)));
    }
    if !chosen.yes && ui::can_prompt() {
        let state = ui::busy("Reading this computer's capacity", crate::public::call("get_platform_state", json!({}))).await?;
        ask(&mut chosen, &opts.harness, &opts.server, &state["host"]).map_err(|error| {
            if error == ui::BACK || error == ui::CANCELLED {
                crate::wire::cancelled("Nothing was started.")
            } else {
                error
            }
        })?;
    }
    for line in summary(&chosen, &opts.harness, &opts.server) {
        ui::info(&line);
    }
    let mut arguments = chosen.arguments();
    arguments.append(&mut opts.extra);
    opts.extra = arguments;
    Ok(None)
}

pub async fn run(args: &[String]) -> Result<i32, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        print!("{HELP}");
        return Ok(0);
    }
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
    let stage_dir = tempfile::Builder::new()
        .prefix("client-")
        .tempdir_in(&root)
        .map_err(|e| e.to_string())?;
    stage(stage_dir.path(), &opts.server)?;
    let python = python(&root, stage_dir.path())?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    if opts.action == "run" {
        if let Some(code) = prepare_run(&mut opts, &python, stage_dir.path(), &executable).await? {
            return Ok(code);
        }
    }
    let mut child = if opts.action == "connect" {
        let mut child = Command::new(&python);
        child
            .args(["-I", "-B"])
            .arg(stage_dir.path().join("compute_node.py"))
            .env("SOLVER_YOUGORI", &executable)
            .env("INFERENCE_SOLVER_YOUGORI", &executable)
            .env("YOUGORI_NO_UPDATE_CHECK", "1");
        child
    } else {
        let mut child = launcher(&python, stage_dir.path(), &executable);
        child.arg(&opts.action).arg(&opts.harness).arg("--server").arg(&opts.server);
        child
    };
    child
        .args(&opts.extra)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Inherit the console: Ctrl+C reaches the connector's normal VM/relay cleanup.
    let status = child
        .status()
        .map_err(|e| format!("Could not start Yougori inference: {e}"))?;
    Ok(status.code().unwrap_or(130))
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
        assert!(options(&args(&[
            "run",
            "missing",
            "--server",
            "https://example.com"
        ]))
        .is_err());
    }
    #[test]
    fn permission_options_leave_the_rest_for_the_launcher_and_the_tool() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().to_string_lossy().to_string();
        let mut extra = args(&[
            "--model", "m", "--workspace", &folder, "--cpu", "3", "--memory", "8", "--internet", "full",
            "--yes", "--", "--cpu", "tool-value",
        ]);
        let chosen = permissions(&mut extra).unwrap();
        // Options after `--` belong to the tool, untouched.
        assert_eq!(extra, args(&["--model", "m", "--", "--cpu", "tool-value"]));
        assert_eq!(
            (chosen.cpu, chosen.memory, chosen.internet.clone(), chosen.yes),
            (Some(3), Some(8), Some(Internet::Full), true)
        );
        assert_eq!(chosen.workspace, Some(std::path::absolute(&folder).unwrap()));
        let launcher = chosen.arguments();
        assert_eq!(launcher[0], "--workspace");
        assert_eq!(&launcher[2..], args(&["--cpu", "3", "--memory", "8", "--internet", "full"]).as_slice());
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
        ] {
            assert!(permissions(&mut args(bad)).is_err(), "{bad:?}");
        }
        // Never "off": without a choice the VM reaches only the inference.
        assert_eq!(Permissions::default().arguments(), args(&["--internet", "inference"]));
        let words = summary(&Permissions::default(), "shannon", "https://acme.yougori.com");
        assert_eq!(words[1], "Reaches: only acme.yougori.com");
        assert_eq!(words[2], "Size: 2 CPU, 6 GB memory");
    }
    #[test]
    fn chosen_sites_are_site_names_and_reach_the_launcher() {
        let mut extra = args(&["--internet", "sites", "--sites", "GitHub.com, pypi.org,github.com"]);
        let chosen = permissions(&mut extra).unwrap();
        assert!(extra.is_empty());
        assert_eq!(chosen.internet, Some(Internet::Sites(vec!["github.com".into(), "pypi.org".into()])));
        assert_eq!(chosen.arguments(), args(&["--internet", "sites", "--sites", "github.com,pypi.org"]));
        // --sites alone means the sites choice.
        let only = permissions(&mut args(&["--sites", "files.pythonhosted.org"])).unwrap();
        assert_eq!(only.internet, Some(Internet::Sites(vec!["files.pythonhosted.org".into()])));
        let words = summary(&chosen, "pi", "https://acme.yougori.com");
        assert_eq!(words[1], "Reaches: acme.yougori.com and github.com, pypi.org");
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
}
