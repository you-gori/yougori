//! Persistent tool sandboxes, attached to the invoking terminal without desktop windows.
//! New sandboxes are microVMs unless the person explicitly chooses a container.
use crate::public::{call, parse_run};
use serde_json::{json, Value};
use std::{
    cmp::Reverse,
    io::{self, IsTerminal},
};

pub const TOOLS: &[&str] = &[
    "codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw",
];
/// Ubuntu 24.04 locked to one multi-architecture image index (the 2026-09-17 build).
/// A moving tag can change what a new sandbox runs; a digest cannot.
pub const DEFAULT_IMAGE: &str =
    "ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55";
pub const HELP: &str = r#"Yougori tool sandboxes

  yougori codex | claude | gemini | ollama | opencode | kilo | openclaw
  yougori TOOL [--new] [--name NAME] [--isolation microvm|container]
               [--image IMAGE] [--cpu CORES] [--memory GB] [--storage GB]
               [--storage-drive PATH] [--gpu nvidia]
               [--mount PC_FOLDER:/guest/path[:ro]] [--share]
               [--no-credentials] [--no-public] [--dry-run]
               [-- TOOL_ARGUMENTS...]
  yougori TOOL --environment ENV [-- TOOL_ARGUMENTS...]

The first run creates a sandbox and installs the tool. New sandboxes are microVMs:
each has its own kernel and minimal virtual hardware, and runs Ubuntu 24.04
pinned by digest. --isolation container opts out and creates a container in
Yougori's shared VM, which shares that VM's kernel with your other containers.
--gpu nvidia and --mount need --isolation container: microVMs cannot use the GPU
or mount PC folders. Later runs reuse the newest sandbox with the same isolation,
its files and sign-in; existing sandboxes keep their isolation. --new creates a
fresh sandbox. Creation options apply only to a new sandbox. --environment
explicitly uses an existing local container or microVM. No PC folder is shared
unless --mount is supplied.
Before creating any tool sandbox, choose CPU cores and memory with arrow keys or
type a number, then press Enter. Defaults are 2 CPU and 4 GB RAM, capped by this
computer's capacity. --cpu and --memory skip their respective choices. Reconnecting
keeps existing resources; use --new to create a sandbox with different settings.

Installation and the tool run right in this terminal. Ctrl+] disconnects the
session; the sandbox and installed files remain. Tool authentication and account
setup happen inside the sandbox. Every launch asks whether to use the tool's
sign-in from this computer ("Use your Claude Code sign-in from this computer?").
Nothing is copied unless you choose Yes; then the tool's supported credential
files are copied into the sandbox, microVM or container. Matching sandbox
credentials are replaced; other settings stay unchanged. OS keychains, extension
logins and environment-only keys always require sign-in inside the tool. OpenClaw
keeps its sign-in with other data, so its Yes choice is unavailable. Anyone
controlling the sandbox can read or use imported credentials. --no-credentials
skips this question and copies nothing.
The questions come in two groups: before the sandbox exists (Ollama's GPU
question, CPU and memory) and after the tool is installed (sign-in, public access,
--share). In each group every question after the first offers Back (Esc or the
Back row) and shows your last answer again; Esc on a group's first question
cancels. Starting Yougori and starting or creating the sandbox show a
spinner; Ctrl+C there stops waiting. Once the sandbox is in use, Ctrl+C opens
Cancel / Stop sandbox / Stop and delete, with Cancel selected. Cancel resumes
without interrupting the tool. Only Enter confirms a stop/delete.
Before the tool opens, the reconnect command is printed: `yougori TOOL` when that
reuses this sandbox, otherwise `yougori TOOL --environment NAME`.

Ollama starts its model server quietly, then opens a ready menu to run a model or
open a sandbox shell. OpenClaw opens `openclaw onboard`.
`yougori ollama` asks whether to use an NVIDIA GPU. GPUs need container isolation,
so that answer uses a GPU container; the CPU answer uses a microVM, or a container
with --isolation container. Matching sandboxes are reused; choosing another mode
creates/reuses that mode's sandbox. --isolation microvm, --gpu or --environment
skips the question.
Every tool asks whether to give your project public access, which app port to use,
and whether to use a quick HTTPS link or a saved domain. Copy the displayed link
before opening the tool. Your project becomes available when it listens on that
port inside the sandbox. Skipping this step leaves existing access unchanged.
--no-public skips this question and leaves existing access unchanged.
Pass arguments after -- to select another action, for example:
  yougori codex -- --help
  yougori ollama -- run MODEL
  yougori openclaw -- gateway run
  yougori claude --new --memory 8GB
  yougori codex --isolation container

--share asks how many teammates to add and collects a separate username/password
for each. It prints password-inclusive `yougori connect LINK USERNAME PASSWORD`
commands before opening the tool. Recipients get control of this sandbox, its
files and tool sign-in. Keep the owner computer, sandbox and gateway running.
"#;

/// How a sandbox is separated from the computer and from other sandboxes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Isolation {
    /// Its own kernel and minimal virtual hardware.
    MicroVm,
    /// A container in Yougori's shared VM, sharing that VM's kernel.
    Container,
}

impl Isolation {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "microvm" => Ok(Self::MicroVm),
            "container" => Ok(Self::Container),
            _ => Err("Use --isolation microvm or --isolation container".into()),
        }
    }
    /// The `--isolation` value, also reported by `--dry-run`.
    fn name(self) -> &'static str {
        match self {
            Self::MicroVm => "microvm",
            Self::Container => "container",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::MicroVm => "microVM",
            Self::Container => "container",
        }
    }
    fn of(environment: &Value) -> Option<Self> {
        match environment["kind"].as_str() {
            Some("microVm") => Some(Self::MicroVm),
            Some("container") => Some(Self::Container),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct Options {
    tool: String,
    name: Option<String>,
    environment: Option<String>,
    fresh: bool,
    creation: Vec<String>,
    image: String,
    /// Only an explicit --isolation; see `isolation()` for the effective choice.
    isolation: Option<Isolation>,
    arguments: Vec<String>,
    dry: bool,
    share: bool,
    desired_gpu: Option<bool>,
    ask_credentials: bool,
    ask_public: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let tool = args
            .first()
            .filter(|tool| TOOLS.contains(&tool.as_str()))
            .ok_or("Unknown tool")?
            .clone();
        let mut options = Self {
            tool,
            name: None,
            environment: None,
            fresh: false,
            creation: vec![],
            image: DEFAULT_IMAGE.into(),
            isolation: None,
            arguments: vec![],
            dry: false,
            share: false,
            desired_gpu: None,
            ask_credentials: true,
            ask_public: true,
        };
        let mut seen = std::collections::HashSet::new();
        let mut i = 1;
        while i < args.len() {
            let flag = &args[i];
            if flag == "--" {
                options.arguments = args[i + 1..].to_vec();
                break;
            }
            if flag != "--mount" && !seen.insert(flag.clone()) {
                return Err(format!("{flag} supplied twice"));
            }
            match flag.as_str() {
                "--new" => options.fresh = true,
                "--dry-run" => options.dry = true,
                "--share" => options.share = true,
                "--no-credentials" => options.ask_credentials = false,
                "--no-public" => options.ask_public = false,
                "--name" | "--environment" | "--image" | "--isolation" | "--cpu" | "--memory" | "--storage" | "--storage-drive" | "--gpu" | "--mount" => {
                    i += 1;
                    let value = args.get(i).filter(|value| !value.is_empty() && !value.starts_with('-') && !value.chars().any(char::is_control)).ok_or_else(|| format!("{flag} requires a value"))?.clone();
                    match flag.as_str() {
                        "--name" => options.name = Some(value),
                        "--environment" => options.environment = Some(value),
                        "--image" => options.image = value,
                        "--isolation" => options.isolation = Some(Isolation::parse(&value)?),
                        _ => options.creation.extend([flag.clone(), value]),
                    }
                }
                _ => return Err(format!("Unknown tool-container option {flag}. Put tool arguments after --. Run yougori {} --help.", options.tool)),
            }
            i += 1;
        }
        if options
            .arguments
            .iter()
            .any(|arg| arg.chars().any(char::is_control))
            || options.arguments.iter().map(String::len).sum::<usize>() > 4096
        {
            return Err(
                "Tool arguments must contain no control characters and fit within 4096 bytes"
                    .into(),
            );
        }
        if options.environment.is_some()
            && (options.fresh || options.name.is_some() || options.custom_creation())
        {
            return Err("--environment cannot be combined with creation options".into());
        }
        if options.environment.is_some() && options.isolation.is_some() {
            return Err("--environment keeps that sandbox's isolation; remove --isolation".into());
        }
        // Never weaken isolation implicitly: a container must be chosen explicitly.
        if options.isolation != Some(Isolation::Container) {
            for (flag, reason) in [
                ("--gpu", "GPUs work only in containers; microVM sandboxes cannot use the GPU"),
                ("--mount", "microVM sandboxes cannot mount PC folders yet"),
            ] {
                if options.creation.iter().any(|value| value == flag) {
                    return Err(format!("{flag} needs --isolation container: {reason}. A container shares Yougori's VM kernel with your other containers."));
                }
            }
        }
        options.request(options.name.as_deref().unwrap_or(&options.tool))?;
        Ok(options)
    }

    /// MicroVM unless a container was chosen explicitly: --isolation container,
    /// or the GPU answer to Ollama's question, which only containers can use.
    fn isolation(&self) -> Isolation {
        self.isolation.unwrap_or(if self.desired_gpu == Some(true) {
            Isolation::Container
        } else {
            Isolation::MicroVm
        })
    }
    fn custom_creation(&self) -> bool {
        !self.creation.is_empty() || self.image != DEFAULT_IMAGE
    }
    fn image_label(&self) -> &str {
        if self.image == DEFAULT_IMAGE {
            "Ubuntu 24.04"
        } else {
            &self.image
        }
    }
    fn resource_choices(&self) -> [bool; 2] {
        ["--cpu", "--memory"].map(|flag| {
            self.environment.is_none() && !self.creation.iter().any(|value| value == flag)
        })
    }
    fn apply_resources(&mut self, sliders: &[crate::cli_ui::Slider]) -> Result<(), String> {
        for slider in sliders {
            let flag = match slider.label {
                "CPU" => "--cpu",
                "Memory" => "--memory",
                _ => return Err("Unknown sandbox resource choice".into()),
            };
            if self.creation.iter().any(|value| value == flag)
                || slider.value < slider.min || slider.value > slider.max
            {
                return Err("Invalid or duplicate sandbox resource choice".into());
            }
        }
        for slider in sliders {
            let flag = if slider.label == "CPU" { "--cpu" } else { "--memory" };
            self.creation.extend([flag.into(), slider.value.to_string()]);
        }
        self.request(self.name.as_deref().unwrap_or(&self.tool))?;
        Ok(())
    }
    fn asks_gpu(&self) -> bool {
        self.tool == "ollama" && self.environment.is_none() && self.isolation != Some(Isolation::MicroVm) && !self.creation.iter().any(|flag|flag=="--gpu")
    }
    fn description(&self) -> String {
        format!("Yougori tool · {}", self.tool)
    }
    fn request(&self, name: &str) -> Result<Value, String> {
        let mut args = vec!["-it".into(), "--name".into(), name.into()];
        if self.isolation() == Isolation::MicroVm {
            args.extend(["--isolation".into(), "microvm".into()]);
        }
        if !self.creation.iter().any(|flag| flag == "--memory") {
            args.extend(["--memory".into(), "4GB".into()]);
        }
        args.extend(self.creation.iter().cloned());
        if self.desired_gpu == Some(true) && !self.creation.iter().any(|flag|flag=="--gpu") {
            args.extend(["--gpu".into(),"nvidia".into()]);
        }
        args.push(self.image.clone());
        let mut request = parse_run(&args, false)?.request;
        request["description"] = json!(self.description());
        Ok(request)
    }
    /// What would happen, without a terminal, an engine or any change.
    fn plan(&self) -> Result<Value, String> {
        // An explicit --environment keeps whatever isolation that sandbox has.
        let isolation = self.environment.is_none().then(|| self.isolation());
        let [cpu, memory] = self.resource_choices();
        Ok(json!({"dryRun":true,"tool":self.tool,"isolation":isolation.map(Isolation::name),"request":if self.environment.is_none(){self.request(self.name.as_deref().unwrap_or(&self.tool))?}else{Value::Null},"environment":self.environment,"reuse":!self.fresh,"arguments":launch_arguments(&self.tool,&self.arguments),"terminal":"current","share":self.share,"gpuChoiceRequired":self.asks_gpu(),"resourceChoicesRequired":{"cpu":cpu,"memory":memory},"publicAccessPrompt":self.ask_public,"credentialImportPrompt":self.ask_credentials}))
    }

    /// The sandbox this command would reuse, taking the answer Ollama's GPU question preselects.
    fn reused<'a>(&self, environments: &'a [Value]) -> Option<&'a Value> {
        if self.asks_gpu() {
            return self.preselected_gpu(environments).ok().flatten().map(|(env, _)| env);
        }
        self.existing(environments).ok().flatten()
    }

    /// Of the sandboxes each answer to Ollama's GPU question would reuse, the one reuse order
    /// prefers, and whether it is the GPU answer's.
    fn preselected_gpu<'a>(&self, environments: &'a [Value]) -> Result<Option<(&'a Value, bool)>, String> {
        let mut found = Vec::new();
        for gpu in [true, false] {
            let mut answer = self.clone();
            answer.desired_gpu = Some(gpu);
            if let Some(env) = answer.existing(environments)? {
                found.push((env, gpu));
            }
        }
        Ok(found.into_iter().min_by_key(|&(env, _)| reuse_order(env)))
    }

    fn existing<'a>(&self, environments: &'a [Value]) -> Result<Option<&'a Value>, String> {
        if let Some(target) = &self.environment {
            let found = environments
                .iter()
                .filter(|env| {
                    env["id"] == target.as_str()
                        || env["name"]
                            .as_str()
                            .is_some_and(|name| name.eq_ignore_ascii_case(target))
                })
                .collect::<Vec<_>>();
            if found.len() != 1 {
                return Err(format!(
                    "Expected one environment named {target}; run yougori ps"
                ));
            }
            validate_environment(found[0])?;
            return Ok(Some(found[0]));
        }
        if self.fresh {
            return Ok(None);
        }
        // Existing sandboxes keep their isolation. Reuse only the requested one.
        let isolation = self.isolation();
        let env = environments
            .iter()
            .filter(|env| {
                env["description"] == self.description()
                    && Isolation::of(env) == Some(isolation)
                    && self.desired_gpu.is_none_or(|gpu| environment_gpu(env) == gpu)
                    && self.name.as_deref().is_none_or(|name| {
                        env["name"]
                            .as_str()
                            .is_some_and(|n| n.eq_ignore_ascii_case(name))
                    })
            })
            .min_by_key(|&env| reuse_order(env));
        if env.is_some() && self.custom_creation() {
            return Err("Creation options require --new or an unused --name. Omit them to reuse this tool's sandbox.".into());
        }
        if let Some(environment) = env {
            validate_environment(environment)?;
        }
        Ok(env)
    }

    /// This tool's container sandbox, which the microVM default no longer reuses.
    fn kept_container<'a>(&self, environments: &'a [Value]) -> Option<&'a Value> {
        if self.isolation.is_some() || self.isolation() != Isolation::MicroVm || self.fresh || self.name.is_some() || self.environment.is_some() {
            return None;
        }
        environments
            .iter()
            .filter(|env| env["description"] == self.description() && Isolation::of(env) == Some(Isolation::Container))
            .min_by_key(|&env| reuse_order(env))
    }

    fn available_name(&self, environments: &[Value]) -> Result<String, String> {
        let taken = |name: &str| {
            environments.iter().any(|env| {
                env["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
        };
        if let Some(name) = &self.name {
            if taken(name) {
                return Err(format!("The name {name} is already in use. Choose another --name or explicitly use --environment {name}."));
            }
            return Ok(name.clone());
        }
        Ok((1..)
            .map(|index| {
                if index == 1 {
                    self.tool.clone()
                } else {
                    format!("{}-{index}", self.tool)
                }
            })
            .find(|name| !taken(name))
            .unwrap())
    }
}

/// Running sandboxes first, then the newest.
fn reuse_order(environment: &Value) -> (bool, Reverse<&str>) {
    (
        environment["status"] != "running",
        Reverse(environment["createdAt"].as_str().unwrap_or("")),
    )
}

fn environment_gpu(environment: &Value) -> bool {
    environment["gpuAccess"] == true || environment["provider"] == "yougoriCuda"
}

fn resource_sliders(options: &Options, host: &Value) -> Result<Vec<crate::cli_ui::Slider>, String> {
    let choices = options.resource_choices();
    let mut sliders = Vec::new();
    for (index, key, label, unit, fallback, ceiling) in [
        (0, "totalCpu", "CPU", "cores", 2.0, 255.0),
        (1, "totalMemoryGb", "Memory", "GB", 4.0, 1024.0),
    ] {
        if !choices[index] {
            continue;
        }
        let capacity = host[key].as_f64().unwrap_or(fallback);
        if !capacity.is_finite() || capacity < 1.0 {
            return Err(format!("This computer needs at least 1 {unit} to choose {label} for a sandbox"));
        }
        let max = capacity.min(ceiling).floor() as u32;
        let default = (fallback as u32).min(max);
        sliders.push(crate::cli_ui::Slider { label, unit, value: default, min: 1, max, default });
    }
    Ok(sliders)
}

/// CPU and memory for a new sandbox, unless both were given. Cancelling creates nothing.
fn choose_resources(options: &mut Options, host: &Value) -> Result<bool, String> {
    use crate::cli_ui as ui;
    let mut sliders = resource_sliders(options, host)?;
    if sliders.is_empty() {
        return Ok(false);
    }
    match ui::sliders("Size your sandbox", "Choose CPU cores and RAM before installation.", &mut sliders) {
        Ok(()) => {
            options.apply_resources(&sliders)?;
            Ok(true)
        }
        Err(error) if error == ui::CANCELLED => Err(crate::tool_sharing::ENDED.into()),
        Err(error) => Err(error),
    }
}

/// The GPU answer is always a container; the question says so before anyone chooses.
fn gpu_question(options: &Options) -> (Vec<String>, [crate::cli_ui::Choice; 2]) {
    use crate::cli_ui::Choice;
    let cpu = if options.isolation == Some(Isolation::Container) {
        Choice::new("Use a CPU container", "run models without a GPU")
    } else {
        Choice::new("Use a CPU microVM", "its own kernel; models run without a GPU")
    };
    (
        vec![
            "GPUs need container isolation: a GPU sandbox is a container that shares Yougori's VM kernel with your other containers.".into(),
            "Yougori reuses a matching sandbox, or creates one for the mode you choose.".into(),
        ],
        [Choice::new("Yes, give Ollama a GPU", "NVIDIA GPU in a container"), cpu],
    )
}

async fn choose_ollama_gpu(options: &mut Options,environments: &[Value]) -> Result<bool,String> {
    use crate::cli_ui as ui;
    if !options.asks_gpu() { return Ok(false); }
    // Each answer reuses its own sandbox. Preselect the one that would be reused, or the
    // answer given before going back.
    let current = options.preselected_gpu(environments)?;
    let initial = match options.desired_gpu.or(current.map(|(_, gpu)| gpu)) { Some(false) => 1, _ => 0 };
    let (notes, choices) = gpu_question(options);
    let prompt = || ui::select("Want a GPU container for Ollama?",&notes,&choices,initial);
    let selected = if let Some(id) = current.and_then(|(env,_)|env["id"].as_str()) {
        crate::tool_sharing::step_prompt(id,prompt).await?
    } else {
        prompt().map_err(|error| if error==ui::CANCELLED {crate::tool_sharing::ENDED.into()} else {error})?
    };
    options.desired_gpu=Some(selected==0);
    Ok(true)
}

/// Whether this command creates a sandbox, so CPU and memory are asked. A taken --name fails
/// here, before the sliders rather than after them.
fn creates(options: &Options, environments: &[Value]) -> Result<bool, String> {
    if options.existing(environments)?.is_some() {
        return Ok(false);
    }
    options.available_name(environments).map(|_| true)
}

/// Questions asked before anything is created: Ollama's GPU choice, then CPU and memory when no
/// sandbox can be reused. The second offers Back to the first.
async fn prepare(options: &mut Options, environments: &[Value], host: &Value) -> Result<(), String> {
    use crate::cli_ui as ui;
    // Asking again starts from the command line's own creation options.
    let creation = options.creation.clone();
    let mut kept_shown = false;
    let mut steps = ui::Wizard::new();
    loop {
        let asked = match steps.step() {
            0 => {
                options.creation = creation.clone();
                choose_ollama_gpu(options, environments).await
            }
            1 => {
                options.creation = creation.clone();
                match creates(options, environments) {
                    Ok(true) => {
                        if !std::mem::replace(&mut kept_shown, true) {
                            if let Some(kept) = options.kept_container(environments) {
                                let kept: String = kept["name"].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).collect();
                                ui::info(&format!("Your container sandbox {kept} is kept. Reconnect to it with: yougori {} --isolation container", options.tool));
                            }
                        }
                        choose_resources(options, host)
                    }
                    other => other,
                }
            }
            _ => break,
        };
        steps.next(asked)?;
    }
    Ok(())
}

/// The shortest command that reconnects to this sandbox: the plain shortcut when that reuses
/// it, else its name, or its ID when another sandbox answers to that name.
fn reconnect_command(tool: &str, id: &str, environments: &[Value]) -> String {
    // Reuse prefers running sandboxes, so the plain shortcut must pick this one whether or not
    // the others run: once this sandbox stops, a newer stopped one would win otherwise.
    let stopped: Vec<Value> = environments
        .iter()
        .map(|env| {
            let mut env = env.clone();
            env["status"] = "stopped".into();
            env
        })
        .collect();
    let picks = |environments: &[Value]| {
        Options::parse(&[tool.to_owned()])
            .ok()
            .and_then(|plain| plain.reused(environments).map(|env| env["id"] == id))
            .unwrap_or(false)
    };
    if picks(environments) && picks(&stopped) {
        return format!("yougori {tool}");
    }
    let name = environments
        .iter()
        .find(|env| env["id"] == id)
        .and_then(|env| env["name"].as_str())
        .filter(|name| {
            !name.is_empty()
                && !name.starts_with('-')
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && environments
                    .iter()
                    .filter(|env| env["id"] == **name || env["name"].as_str().is_some_and(|other| other.eq_ignore_ascii_case(name)))
                    .count()
                    == 1
        });
    format!("yougori {tool} --environment {}", name.unwrap_or(id))
}

fn validate_environment(environment: &Value) -> Result<(), String> {
    let remote = environment["runtime"].as_str().is_some_and(|runtime| {
        runtime.starts_with("shared://") || runtime.starts_with("cloud://")
    });
    let supported = match Isolation::of(environment) {
        Some(Isolation::Container) => !remote,
        // Yougori installs tools only in microVMs that boot its built-in guest.
        Some(Isolation::MicroVm) => {
            environment["provider"] == "qemu" && environment["runtime"] == "builtin:alpine"
        }
        None => false,
    };
    if !supported {
        return Err("Tool shortcuts require a local container or a microVM with Yougori's built-in guest".into());
    }
    if !matches!(environment["status"].as_str(), Some("running" | "stopped")) {
        return Err(
            "Wait for this sandbox's current operation to finish before launching a tool".into(),
        );
    }
    if environment["networkAccess"] == false {
        return Err("Enable this sandbox's Internet access before launching a tool".into());
    }
    Ok(())
}

pub fn launch_arguments(tool: &str, arguments: &[String]) -> Vec<String> {
    if !arguments.is_empty() {
        return arguments.to_vec();
    }
    match tool {
        "ollama" => vec!["serve".into()],
        "openclaw" => vec!["onboard".into()],
        _ => vec![],
    }
}

pub async fn run(args: &[String]) -> Result<Option<Value>, String> {
    let options = Options::parse(args)?;
    if options.dry {
        return options.plan().map(Some);
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Tool shortcuts require an interactive terminal. Use --dry-run to inspect without creating a sandbox.".into());
    }
    use crate::cli_ui as ui;
    let _raw = ui::Raw::on()?;
    let _session = ui::Session::start(&options.tool, "local sandbox · your tools and teammates");
    ui::intro("Tool sandbox", &options.tool);
    match launch(options).await {
        // A cancelled question or a stop action already shows on screen.
        Err(error) if error == crate::tool_sharing::ENDED || error == ui::BACK => Ok(None),
        // Ctrl+C while waiting: say what keeps running.
        Err(error) if error == ui::CANCELLED => {
            ui::outro(&ui::muted(&error));
            Ok(None)
        }
        result => result,
    }
}

async fn launch(mut options: Options) -> Result<Option<Value>, String> {
    use crate::cli_ui as ui;
    ui::busy("Starting Yougori engine", crate::client::start(None)).await?;
    let state = ui::busy("Loading your sandboxes", call("get_platform_state", json!({}))).await?;
    let environments = state["environments"]
        .as_array()
        .ok_or("No environment state")?;
    prepare(&mut options, environments, &state["host"]).await?;
    let (id, name, isolation) = if let Some(environment) = options.existing(environments)? {
        let id = environment["id"]
            .as_str()
            .ok_or("Missing environment ID")?
            .to_owned();
        let isolation = Isolation::of(environment).ok_or("Unsupported sandbox isolation")?;
        let name = environment["name"]
            .as_str()
            .unwrap_or(&options.tool)
            .to_owned();
        if environment["status"] != "running" {
            ui::busy(
                &format!("Starting {name} sandbox"),
                call(
                    "set_environment_status",
                    json!({"environmentId":id,"status":"running"}),
                ),
            )
            .await?;
        }
        (id, name, isolation)
    } else {
        let name = options.available_name(environments)?;
        let isolation = options.isolation();
        let started = std::time::Instant::now();
        let result = ui::busy(
            &format!("Creating {name} · {} · {}", isolation.label(), options.image_label()),
            call(
                "run_workload",
                json!({"request":options.request(&name)?,"start":true}),
            ),
        )
        .await?;
        ui::step(&format!("{name} sandbox ready  {}", ui::muted(&ui::clock(started.elapsed()))));
        (
            result["id"]
                .as_str()
                .ok_or("Missing created environment ID")?
                .to_owned(),
            name,
            isolation,
        )
    };
    ui::step(&format!("Using {name} · {}", isolation.label()));
    ui::info("Ctrl+C opens Cancel / Stop sandbox / Stop and delete. Ctrl+] disconnects and keeps the sandbox running.");
    // Finish quiet setup before either sharing prompts or the interactive tool.
    if crate::terminal::setup_tool(&id, &options.tool).await? != crate::terminal::SessionExit::Completed {
        return Ok(None);
    }
    {
        // Each question after the first offers Back. Going back asks again and never undoes
        // what an answer already did, such as a copied sign-in or a published link.
        let mut copy = false;
        let mut public = crate::tool_public_access::Answers::default();
        let mut steps = ui::Wizard::new();
        loop {
            let asked = match steps.step() {
                0 if options.ask_credentials => crate::tool_credentials::configure(&id, &options.tool, options.share, &mut copy).await,
                1 if options.ask_public => crate::tool_public_access::configure(&id, &options.tool, &mut public).await,
                2 if options.share => crate::tool_sharing::share(&id, &name).await,
                0..=2 => Ok(false),
                _ => break,
            };
            steps.next(asked)?;
        }
    }
    let state = call("get_platform_state", json!({})).await.unwrap_or_default();
    let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
    ui::info(&format!("Reconnect: {}", reconnect_command(&options.tool, &id, environments)));
    if options.tool=="ollama" && (options.arguments.is_empty() || options.arguments==["serve"]) {
        crate::terminal::open_ollama(&id,&name).await?;
        return Ok(None);
    }
    crate::terminal::attach_prepared_tool(
        &id,
        &options.tool,
        &launch_arguments(&options.tool, &options.arguments),
    )
    .await?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn words(value: &str) -> Vec<String> {
        shell_words::split(value).unwrap()
    }
    fn microvm(id: &str, name: &str, description: &str, status: &str) -> Value {
        json!({"id":id,"name":name,"kind":"microVm","provider":"qemu","runtime":"builtin:alpine","description":description,"status":status})
    }
    fn container(id: &str, name: &str, description: &str, status: &str) -> Value {
        json!({"id":id,"name":name,"kind":"container","provider":"yougoriOci","runtime":DEFAULT_IMAGE,"description":description,"status":status})
    }
    #[test]
    fn all_installer_tools_have_isolated_persistent_requests() {
        let ui = include_str!("../../src/lib/terminal-installers.ts");
        let ids = ui
            .lines()
            .filter(|line| line.contains("{ id:"))
            .map(|line| line.split('"').nth(1).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(TOOLS, ids);
        for tool in TOOLS {
            let options = Options::parse(&words(tool)).unwrap();
            let request = options.request(tool).unwrap();
            assert_eq!(request["description"], format!("Yougori tool · {tool}"));
            assert_eq!(request["kind"], "microVm");
            assert_eq!(request["resourcePolicy"]["memoryGb"]["preferred"].as_f64(), Some(4.0));
            assert_eq!(request["pcAccess"].as_array().map_or(0, Vec::len), 0);
            assert_eq!(request["microvmWorkload"]["image"], DEFAULT_IMAGE);
            assert_eq!(request["microvmWorkload"]["options"]["binds"], json!([]));
            let container = Options::parse(&words(&format!("{tool} --isolation container"))).unwrap().request(tool).unwrap();
            assert_eq!(container["kind"], "container");
            assert_eq!(container["runtime"], DEFAULT_IMAGE);
            assert_eq!(container["workload"]["binds"], json!([]));
        }
    }
    #[test]
    fn new_sandboxes_are_microvms_with_a_digest_pinned_image() {
        let (name, digest) = DEFAULT_IMAGE.split_once("@sha256:").unwrap();
        assert_eq!(name, "ubuntu:24.04");
        assert!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        for command in ["codex", "claude --new", "gemini --name writing", "codex --isolation microvm"] {
            let options = Options::parse(&words(command)).unwrap();
            assert_eq!(options.isolation(), Isolation::MicroVm, "{command}");
            let request = options.request("sandbox").unwrap();
            assert_eq!((request["kind"].as_str(), request["provider"].as_str()), (Some("microVm"), Some("qemu")), "{command}");
            assert_eq!(request["runtime"], "builtin:alpine");
            assert_eq!(request["gpuAccess"], false);
            assert_eq!(request["networkAccess"], true);
            assert!(request["workload"].is_null());
        }
        let custom = Options::parse(&words("codex --new --image debian:13")).unwrap().request("codex").unwrap();
        assert_eq!(custom["microvmWorkload"]["image"], "debian:13");
    }
    #[test]
    fn container_isolation_is_an_explicit_opt_out() {
        let options = Options::parse(&words("codex --isolation container")).unwrap();
        assert_eq!(options.isolation(), Isolation::Container);
        let request = options.request("codex").unwrap();
        assert_eq!((request["kind"].as_str(), request["provider"].as_str()), (Some("container"), Some("yougoriOci")));
        assert!(request.get("microvmWorkload").is_none());
        for input in [
            "codex --isolation vm",
            "codex --isolation MicroVM",
            "codex --isolation",
            "codex --isolation container --isolation microvm",
            "codex --environment env --isolation container",
            "codex --environment env --isolation microvm",
        ] {
            assert!(Options::parse(&words(input)).is_err(), "{input}");
        }
    }
    #[test]
    fn gpu_and_pc_folders_require_explicitly_choosing_a_container() {
        for input in [
            "codex --gpu nvidia",
            "ollama --gpu nvidia",
            "codex --isolation microvm --gpu nvidia",
            "kilo --mount ./site:/workspace/site",
            "kilo --isolation microvm --mount ./site:/workspace/site",
        ] {
            let error = Options::parse(&words(input)).unwrap_err();
            assert!(error.contains("needs --isolation container"), "{input}: {error}");
            assert!(error.contains("shares Yougori's VM kernel"), "{input}: {error}");
        }
        let gpu = Options::parse(&words("ollama --isolation container --gpu nvidia")).unwrap().request("ollama").unwrap();
        assert_eq!((gpu["kind"].as_str(), gpu["provider"].as_str(), gpu["gpuAccess"].as_bool()), (Some("container"), Some("yougoriCuda"), Some(true)));
        let mounted = Options::parse(&words("kilo --isolation container --mount ./site:/workspace/site")).unwrap().request("kilo").unwrap();
        assert_eq!(mounted["workload"]["binds"].as_array().map(Vec::len), Some(1));
    }
    #[test]
    fn dry_run_reports_isolation_and_offers_credential_import_for_both() {
        let plan = |command: &str| Options::parse(&words(command)).unwrap().plan().unwrap();
        let default = plan("codex --dry-run");
        assert_eq!(default["isolation"], "microvm");
        assert_eq!(default["request"]["kind"], "microVm");
        assert_eq!(default["credentialImportPrompt"], true);
        assert_eq!(default["publicAccessPrompt"], true);
        let opted_out = plan("codex --isolation container --dry-run");
        assert_eq!(opted_out["isolation"], "container");
        assert_eq!(opted_out["request"]["kind"], "container");
        assert_eq!(opted_out["credentialImportPrompt"], true);
        for command in ["codex --no-credentials --dry-run", "codex --isolation container --no-credentials --dry-run"] {
            assert_eq!(plan(command)["credentialImportPrompt"], false, "{command}");
        }
        // An explicit target keeps its own isolation, which the offline plan cannot know.
        let target = plan("codex --environment saved --dry-run");
        assert!(target["isolation"].is_null() && target["request"].is_null());
        assert_eq!(target["credentialImportPrompt"], true);
        assert_eq!(plan("ollama --dry-run")["gpuChoiceRequired"], true);
        assert_eq!(plan("ollama --isolation microvm --dry-run")["gpuChoiceRequired"], false);
        // Every tool asks, OpenClaw too; it explains why its sign-in cannot be copied.
        for tool in TOOLS {
            assert_eq!(plan(&format!("{tool} --dry-run"))["credentialImportPrompt"], true, "{tool}");
        }
    }
    #[test]
    fn reconnect_hint_is_the_plain_shortcut_when_it_reuses_the_sandbox_else_its_name() {
        let managed = Options::parse(&words("codex")).unwrap().description();
        let mut older = microvm("env-older", "codex", &managed, "stopped");
        older["createdAt"] = json!("2026-10-01T00:00:00Z");
        let mut newest = microvm("env-newest", "codex-2", &managed, "running");
        newest["createdAt"] = json!("2026-10-11T00:00:00Z");
        let opted_out = container("env-container", "codex-3", &managed, "running");
        let environments = vec![older, newest, opted_out];
        assert_eq!(reconnect_command("codex", "env-newest", &environments), "yougori codex");
        assert_eq!(reconnect_command("codex", "env-older", &environments), "yougori codex --environment codex");
        // Reuse prefers running sandboxes: once an older running one stops, the newer one wins.
        let mut running_older = environments.clone();
        running_older[0]["status"] = json!("running");
        running_older[1]["status"] = json!("stopped");
        assert_eq!(reconnect_command("codex", "env-older", &running_older), "yougori codex --environment codex");
        // `yougori codex` reuses microVMs only; the container needs its name.
        assert_eq!(reconnect_command("codex", "env-container", &environments), "yougori codex --environment codex-3");
        // A name another sandbox also answers to, or one a shell would need quoted, falls back to the ID.
        let mut shared = environments.clone();
        shared.push(json!({"id":"env-other","name":"CODEX","kind":"container","status":"running"}));
        assert_eq!(reconnect_command("codex", "env-older", &shared), "yougori codex --environment env-older");
        let mut spaced = environments.clone();
        spaced[0]["name"] = json!("my codex");
        assert_eq!(reconnect_command("codex", "env-older", &spaced), "yougori codex --environment env-older");
        assert_eq!(reconnect_command("codex", "env-gone", &[]), "yougori codex --environment env-gone");
        for command in ["yougori codex --environment codex", "yougori codex --environment codex-3"] {
            let args = shell_words::split(command).unwrap();
            let target = Options::parse(&args[1..]).unwrap();
            let resolved = target.existing(&environments).unwrap().unwrap()["id"].clone();
            assert_eq!(reconnect_command("codex", resolved.as_str().unwrap(), &environments), command, "the hint resolves to the same sandbox");
        }
    }
    #[test]
    fn only_new_sandboxes_are_sized_and_a_taken_name_fails_before_the_sliders() {
        let managed = Options::parse(&words("codex")).unwrap().description();
        let environments = vec![
            json!({"id":"env-site","name":"site","kind":"container","status":"running"}),
            microvm("env-codex", "codex", &managed, "running"),
        ];
        let creates = |command: &str| creates(&Options::parse(&words(command)).unwrap(), &environments);
        assert_eq!(creates("codex"), Ok(false), "a reused sandbox asks nothing");
        assert_eq!(creates("codex --new"), Ok(true));
        let taken = creates("codex --name SITE").unwrap_err();
        assert!(taken.contains("already in use"), "{taken}");
    }
    #[test]
    fn ollama_reconnects_with_the_plain_shortcut_when_its_preselected_answer_reuses_the_sandbox() {
        let managed = Options::parse(&words("ollama")).unwrap().description();
        let mut gpu = container("env-gpu", "ollama", &managed, "running");
        gpu["provider"] = json!("yougoriCuda");
        gpu["gpuAccess"] = json!(true);
        let cpu = microvm("env-cpu", "ollama-2", &managed, "stopped");
        let environments = vec![gpu, cpu];
        let plain = Options::parse(&words("ollama")).unwrap();
        let (preselected, uses_gpu) = plain.preselected_gpu(&environments).unwrap().unwrap();
        assert_eq!((preselected["id"].as_str(), uses_gpu), (Some("env-gpu"), true), "running sandboxes come first");
        assert_eq!(reconnect_command("ollama", "env-gpu", &environments), "yougori ollama");
        assert_eq!(reconnect_command("ollama", "env-cpu", &environments), "yougori ollama --environment ollama-2");
        assert!(Options::parse(&words("ollama")).unwrap().preselected_gpu(&[]).unwrap().is_none());
    }
    #[test]
    fn tool_arguments_are_separate_from_creation_flags() {
        let options = Options::parse(&words(
            "codex --new --memory 8GB -- --model example 'a; $(touch /tmp/no)'",
        ))
        .unwrap();
        assert!(options.fresh);
        assert_eq!(
            options.arguments,
            words("--model example 'a; $(touch /tmp/no)'")
        );
        for input in [
            "codex --new --new",
            "claude --environment env --new",
            "kilo --image",
            "codex --memory bad",
            "codex --name 'a;bad'",
            "gemini --prompt bad",
            "codex --storage 4",
        ] {
            assert!(Options::parse(&words(input)).is_err(), "{input}");
        }
        assert_eq!(Options::parse(&words("codex -- --isolation container")).unwrap().isolation(), Isolation::MicroVm);
    }
    #[test]
    fn sharing_is_available_on_every_tool_and_never_forwarded_as_a_tool_argument() {
        for tool in TOOLS {
            let options = Options::parse(&words(&format!("{tool} --share --dry-run"))).unwrap();
            assert!(options.share);
            assert!(options.dry);
            assert!(options.arguments.is_empty());
            assert!(options.request(tool).unwrap().get("share").is_none());
        }
        let options = Options::parse(&words("codex --environment env-local --share -- --model test")).unwrap();
        assert!(options.share);
        assert_eq!(options.arguments, words("--model test"));
        assert!(Options::parse(&words("codex --share --share")).is_err());
        let options = Options::parse(&words("codex -- --share")).unwrap();
        assert!(!options.share);
        assert_eq!(options.arguments, words("--share"));
    }
    #[test]
    fn launch_questions_can_be_skipped_but_tool_arguments_stay_literal() {
        let options = Options::parse(&words("claude --no-credentials --no-public --share")).unwrap();
        assert!(!options.ask_credentials && !options.ask_public && options.share);
        let defaults = Options::parse(&words("claude -- --no-credentials --no-public")).unwrap();
        assert!(defaults.ask_credentials && defaults.ask_public);
        assert_eq!(defaults.arguments, words("--no-credentials --no-public"));
        assert!(Options::parse(&words("claude --no-public --no-public")).is_err());
    }
    #[test]
    fn reuse_matches_isolation_and_existing_sandboxes_keep_theirs() {
        let options = Options::parse(&words("codex")).unwrap();
        let managed = options.description();
        let environments = vec![
            json!({"id":"foreign","kind":"container","name":"codex","status":"running"}),
            container("old-container", "codex-2", &managed, "running"),
            microvm("stopped-vm", "codex-3", &managed, "stopped"),
            microvm("running-vm", "codex-4", &managed, "running"),
        ];
        // The default reuses a microVM, never the container sandbox.
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"], "running-vm");
        assert_eq!(Options::parse(&words("codex --isolation microvm")).unwrap().existing(&environments).unwrap().unwrap()["id"], "running-vm");
        // Opting out reuses the existing container; it is never converted.
        let opted_out = Options::parse(&words("codex --isolation container")).unwrap();
        assert_eq!(opted_out.existing(&environments).unwrap().unwrap()["id"], "old-container");
        assert!(opted_out.kept_container(&environments).is_none());
        // With only a container sandbox, the default creates a microVM and names the kept one.
        let only_container = &environments[..2];
        assert!(options.existing(only_container).unwrap().is_none());
        assert_eq!(options.kept_container(only_container).unwrap()["id"], "old-container");
        assert_eq!(options.available_name(only_container).unwrap(), "codex-3");
        assert!(Options::parse(&words("codex --memory 8GB"))
            .unwrap()
            .existing(&environments)
            .is_err());
        assert!(Options::parse(&words("codex --new"))
            .unwrap()
            .existing(&environments)
            .unwrap()
            .is_none());
        let unavailable = vec![microvm("busy", "codex", &managed, "starting")];
        assert!(options.existing(&unavailable).is_err());
    }
    #[test]
    fn explicit_targets_never_install_into_cloud_vm_or_unavailable_nodes() {
        let options = Options::parse(&words("claude --environment target")).unwrap();
        for environment in [
            json!({"id":"target","kind":"vm","status":"running"}),
            json!({"id":"target","kind":"fullVm","provider":"qemu","runtime":"C:/disk.qcow2","status":"running"}),
            json!({"id":"target","kind":"microVm","provider":"qemu","runtime":"C:/custom-manifest.json","status":"running"}),
            json!({"id":"target","kind":"container","runtime":"shared://tunnel/a","status":"running"}),
            json!({"id":"target","kind":"container","status":"starting"}),
            json!({"id":"target","kind":"container","status":"running","networkAccess":false}),
            json!({"id":"target","kind":"microVm","provider":"qemu","runtime":"builtin:alpine","status":"running","networkAccess":false}),
        ] {
            assert!(options.existing(&[environment]).is_err());
        }
        for environment in [
            json!({"id":"target","kind":"container","provider":"yougoriOci","runtime":"ubuntu","status":"stopped"}),
            json!({"id":"target","kind":"microVm","provider":"qemu","runtime":"builtin:alpine","status":"running"}),
        ] {
            assert!(options.existing(std::slice::from_ref(&environment)).unwrap().is_some());
        }
        assert_eq!(launch_arguments("ollama", &[]), ["serve"]);
        assert_eq!(launch_arguments("openclaw", &[]), ["onboard"]);
        assert_eq!(
            launch_arguments("ollama", &words("run model")),
            words("run model")
        );
    }

    #[test]
    fn ollama_gpu_question_respects_explicit_configuration() {
        for command in ["ollama","ollama --new","ollama --name models","ollama --isolation container"] {
            assert!(Options::parse(&words(command)).unwrap().asks_gpu(), "{command}");
        }
        for command in ["codex","claude","ollama --isolation microvm","ollama --new --isolation container --gpu nvidia","ollama --environment existing"] {
            assert!(!Options::parse(&words(command)).unwrap().asks_gpu(), "{command}");
        }
    }
    #[test]
    fn the_gpu_question_says_gpus_need_a_container() {
        let (notes, choices) = gpu_question(&Options::parse(&words("ollama")).unwrap());
        assert!(notes[0].contains("container isolation") && notes[0].contains("kernel"));
        assert!(choices[0].hint.contains("container"));
        assert!(choices[1].label.contains("microVM"));
        let (_, choices) = gpu_question(&Options::parse(&words("ollama --isolation container")).unwrap());
        assert!(choices[1].label.contains("container"));
    }
    #[test]
    fn every_tool_offers_only_unspecified_resources_for_new_sandboxes() {
        let host = json!({"totalCpu":16,"totalMemoryGb":31.8});
        for tool in TOOLS {
            let options = Options::parse(&words(tool)).unwrap();
            let sliders = resource_sliders(&options, &host).unwrap();
            assert_eq!(sliders.len(), 2, "{tool}");
            assert_eq!((sliders[0].label, sliders[0].value, sliders[0].max), ("CPU", 2, 16));
            assert_eq!((sliders[1].label, sliders[1].value, sliders[1].max), ("Memory", 4, 31));
            for (flags, remaining) in [
                ("--new --cpu 3.5", vec!["Memory"]),
                ("--new --memory 6.5GB", vec!["CPU"]),
                ("--new --cpu 3.5 --memory 6.5GB", vec![]),
                ("--environment saved", vec![]),
            ] {
                let configured = Options::parse(&words(&format!("{tool} {flags}"))).unwrap();
                let before = configured.request(tool).unwrap();
                let sliders = resource_sliders(&configured, &host).unwrap();
                assert_eq!(sliders.iter().map(|s| s.label).collect::<Vec<_>>(), remaining);
                assert_eq!(configured.request(tool).unwrap(), before, "explicit values remain intact");
            }
        }
    }
    #[test]
    fn resource_choices_fit_small_hosts_and_runtime_limits() {
        let options = Options::parse(&words("codex --new")).unwrap();
        let small = resource_sliders(&options, &json!({"totalCpu":1,"totalMemoryGb":2.8})).unwrap();
        assert_eq!((small[0].value, small[0].max), (1, 1));
        assert_eq!((small[1].value, small[1].max), (2, 2));
        let large = resource_sliders(&options, &json!({"totalCpu":512,"totalMemoryGb":2048})).unwrap();
        assert_eq!((large[0].max, large[1].max), (255, 1024));
        for host in [json!({"totalCpu":0}), json!({"totalMemoryGb":0.5})] {
            assert!(resource_sliders(&options, &host).is_err());
        }
    }
    #[test]
    fn inspecting_resource_choices_does_not_change_reconnect_settings() {
        let options = Options::parse(&words("codex")).unwrap();
        let mut saved = microvm("saved", "codex", &options.description(), "running");
        saved["resourcePolicy"] = json!({"cpu":{"preferred":6},"memoryGb":{"preferred":12}});
        let environments = vec![saved];
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"], "saved");
        resource_sliders(&options, &json!({"totalCpu":16,"totalMemoryGb":32})).unwrap();
        assert_eq!(options.existing(&environments).unwrap().unwrap()["resourcePolicy"]["memoryGb"]["preferred"], 12);
        assert!(!options.custom_creation());
    }
    #[test]
    fn selected_resources_reach_the_creation_request_without_overriding_explicit_values() {
        let host = json!({"totalCpu":16,"totalMemoryGb":32});
        for tool in TOOLS {
            for isolation in ["microvm", "container"] {
                let mut options = Options::parse(&words(&format!("{tool} --new --isolation {isolation}"))).unwrap();
                let mut sliders = resource_sliders(&options, &host).unwrap();
                sliders[0].value = 5;
                sliders[1].value = 7;
                options.apply_resources(&sliders).unwrap();
                let request = options.request(tool).unwrap();
                assert_eq!(request["resourcePolicy"]["cpu"]["preferred"], 5.0);
                assert_eq!(request["resourcePolicy"]["memoryGb"]["preferred"], 7.0);
                assert_eq!(request["resourcePolicy"]["cpu"]["max"], 5.0);
                assert_eq!(request["resourcePolicy"]["memoryGb"]["max"], 7.0);
                assert_eq!(request["storageGb"], 20.0);
                assert!(options.apply_resources(&sliders).is_err());
            }
        }
        let mut options = Options::parse(&words("codex --new --cpu 3.5")).unwrap();
        let mut sliders = resource_sliders(&options, &host).unwrap();
        sliders[0].value = 12;
        options.apply_resources(&sliders).unwrap();
        assert_eq!(options.request("codex").unwrap()["resourcePolicy"]["cpu"]["preferred"], 3.5);
        assert_eq!(options.request("codex").unwrap()["resourcePolicy"]["memoryGb"]["preferred"], 12.0);
    }
    #[test]
    fn ollama_gpu_answer_uses_a_container_and_the_cpu_answer_a_microvm() {
        let mut options=Options::parse(&words("ollama")).unwrap();
        let managed = options.description();
        let mut cpu_container = container("cpu-container", "ollama", &managed, "running");
        cpu_container["gpuAccess"] = json!(false);
        let mut gpu = container("gpu", "ollama-2", &managed, "stopped");
        gpu["provider"] = json!("yougoriCuda");
        gpu["gpuAccess"] = json!(true);
        let cpu_vm = microvm("cpu-vm", "ollama-3", &managed, "running");
        let environments = vec![cpu_container, gpu, cpu_vm];
        options.desired_gpu=Some(true);
        assert_eq!(options.isolation(), Isolation::Container, "the GPU answer always uses a container");
        let request=options.request("ollama-4").unwrap();
        assert_eq!(request["kind"],"container");
        assert_eq!(request["gpuAccess"],true);
        assert_eq!(request["provider"],"yougoriCuda");
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"],"gpu");
        assert!(options.existing(&environments[..1]).unwrap().is_none());
        assert_eq!(options.available_name(&environments[..1]).unwrap(),"ollama-2");
        options.desired_gpu=Some(false);
        assert_eq!(options.isolation(), Isolation::MicroVm);
        assert_eq!(options.request("ollama").unwrap()["kind"],"microVm");
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"],"cpu-vm");
        assert!(options.existing(&environments[..2]).unwrap().is_none(), "a CPU container is not reused by default");
        let mut opted_out = Options::parse(&words("ollama --isolation container")).unwrap();
        opted_out.desired_gpu = Some(false);
        assert_eq!(opted_out.request("ollama").unwrap()["kind"], "container");
        assert_eq!(opted_out.existing(&environments).unwrap().unwrap()["id"], "cpu-container");
        assert_eq!(environments[0]["gpuAccess"],false,"CPU sandbox was not changed");
    }
}
