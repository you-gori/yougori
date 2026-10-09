//! Persistent tool containers, attached to the invoking terminal without desktop windows.
use crate::public::{call, parse_run};
use serde_json::{json, Value};
use std::io::{self, IsTerminal};

pub const TOOLS: &[&str] = &[
    "codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw",
];
pub const HELP: &str = r#"Yougori tool containers

  yougori codex | claude | gemini | ollama | opencode | kilo | openclaw
  yougori TOOL [--new] [--name NAME] [--image IMAGE] [--cpu CORES]
               [--memory GB] [--storage GB] [--storage-drive PATH]
               [--gpu nvidia] [--mount PC_FOLDER:/guest/path[:ro]]
               [--share] [--dry-run] [-- TOOL_ARGUMENTS...]
  yougori TOOL --environment ENV [-- TOOL_ARGUMENTS...]

The first run creates a local Ubuntu container and installs the tool. Later runs
reuse its container, files and sign-in. --new creates a fresh container. Creation
options apply only to a new container. --environment explicitly uses an existing
local container. No PC folder is shared unless --mount is supplied.
Before creating any tool sandbox, choose CPU cores and memory with arrow keys or
type a number, then press Enter. Defaults are 2 CPU and 4 GB RAM, capped by this
computer's capacity. --cpu and --memory skip their respective choices. Reconnecting
keeps existing resources; use --new to create a sandbox with different settings.

Installation and the tool run right in this terminal. Ctrl+] disconnects the
session; the container and installed files remain. Tool authentication and account
setup happen inside the container. Every launch asks whether to copy this tool's
supported credential files from this computer. Nothing is copied unless you choose
Yes. Matching sandbox credentials are replaced; other settings stay unchanged.
OS keychains, extension logins and environment-only keys require sign-in inside
the tool. Anyone controlling the sandbox can read or use imported credentials.
Ctrl+C opens Cancel / Stop sandbox / Stop and delete, with Cancel selected.
Cancel resumes without interrupting the tool. Only Enter confirms a stop/delete.

Ollama starts its model server quietly, then opens a ready menu to run a model or
open a sandbox shell. OpenClaw opens `openclaw onboard`.
`yougori ollama` asks whether to use an NVIDIA GPU or CPU container. Matching
containers are reused; choosing another mode creates/reuses that mode's sandbox.
An explicit --gpu or --environment keeps your selected configuration.
Every tool asks whether to give your project public access, which app port to use,
and whether to use a quick HTTPS link or a saved domain. Copy the displayed link
before opening the tool. Your project becomes available when it listens on that
port inside the sandbox. Skipping this step leaves existing access unchanged.
Pass arguments after -- to select another action, for example:
  yougori codex -- --help
  yougori ollama -- run MODEL
  yougori openclaw -- gateway run
  yougori claude --new --memory 8GB

--share asks how many teammates to add and collects a separate username/password
for each. It prints password-inclusive `yougori connect LINK USERNAME PASSWORD`
commands before opening the tool. Recipients get control of this sandbox, its
files and tool sign-in. Keep the owner computer, container and gateway running.
"#;

#[derive(Debug)]
struct Options {
    tool: String,
    name: Option<String>,
    environment: Option<String>,
    fresh: bool,
    creation: Vec<String>,
    image: String,
    arguments: Vec<String>,
    dry: bool,
    share: bool,
    desired_gpu: Option<bool>,
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
            image: "ubuntu:24.04".into(),
            arguments: vec![],
            dry: false,
            share: false,
            desired_gpu: None,
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
                "--name" | "--environment" | "--image" | "--cpu" | "--memory" | "--storage" | "--storage-drive" | "--gpu" | "--mount" => {
                    i += 1;
                    let value = args.get(i).filter(|value| !value.is_empty() && !value.starts_with('-') && !value.chars().any(char::is_control)).ok_or_else(|| format!("{flag} requires a value"))?.clone();
                    match flag.as_str() {
                        "--name" => options.name = Some(value),
                        "--environment" => options.environment = Some(value),
                        "--image" => options.image = value,
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
        options.request(options.name.as_deref().unwrap_or(&options.tool))?;
        Ok(options)
    }

    fn custom_creation(&self) -> bool {
        !self.creation.is_empty() || self.image != "ubuntu:24.04"
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
        self.tool == "ollama" && self.environment.is_none() && !self.creation.iter().any(|flag|flag=="--gpu")
    }
    fn description(&self) -> String {
        format!("Yougori tool · {}", self.tool)
    }
    fn request(&self, name: &str) -> Result<Value, String> {
        let mut args = vec!["-it".into(), "--name".into(), name.into()];
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
        let env = environments
            .iter()
            .filter(|env| {
                env["description"] == self.description()
                    && self.desired_gpu.is_none_or(|gpu| environment_gpu(env) == gpu)
                    && self.name.as_deref().is_none_or(|name| {
                        env["name"]
                            .as_str()
                            .is_some_and(|n| n.eq_ignore_ascii_case(name))
                    })
            })
            .min_by_key(|env| {
                (
                    env["status"] != "running",
                    std::cmp::Reverse(env["createdAt"].as_str().unwrap_or("")),
                )
            });
        if env.is_some() && self.custom_creation() {
            return Err("Creation options require --new or an unused --name. Omit them to reuse this tool's container.".into());
        }
        if let Some(environment) = env {
            validate_environment(environment)?;
        }
        Ok(env)
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

fn choose_resources(options: &mut Options, host: &Value) -> Result<bool, String> {
    use crate::cli_ui as ui;
    let mut sliders = resource_sliders(options, host)?;
    if sliders.is_empty() {
        return Ok(true);
    }
    match ui::sliders("Size your sandbox", "Choose CPU cores and RAM before installation.", &mut sliders) {
        Ok(()) => {
            options.apply_resources(&sliders)?;
            Ok(true)
        }
        Err(error) if error == ui::CANCELLED => Ok(false),
        Err(error) => Err(error),
    }
}

async fn choose_ollama_gpu(options: &mut Options,environments: &[Value]) -> Result<bool,String> {
    use crate::cli_ui::{self as ui,Choice};
    if !options.asks_gpu() { return Ok(true); }
    let existing = options.existing(environments)?;
    let initial = if existing.is_some_and(|env|!environment_gpu(env)) {1}else{0};
    let choices = [Choice::new("Yes, give Ollama a GPU", "use your NVIDIA GPU for models"),Choice::new("Use a CPU container", "run models without a GPU")];
    let prompt = || ui::select("Want a GPU container for Ollama?",&["Yougori reuses a matching sandbox, or creates one for the mode you choose.".into()],&choices,initial);
    let selected = if let Some(id) = existing.and_then(|env|env["id"].as_str()) {
        crate::tool_sharing::share_prompt(id,prompt).await?
    } else {
        match prompt() {Ok(value)=>Some(value),Err(error) if error==ui::CANCELLED=>None,Err(error)=>return Err(error)}
    };
    let Some(selected)=selected else{return Ok(false)};
    options.desired_gpu=Some(selected==0);
    Ok(true)
}

fn validate_environment(environment: &Value) -> Result<(), String> {
    if environment["kind"] != "container"
        || environment["runtime"].as_str().is_some_and(|runtime| {
            runtime.starts_with("shared://") || runtime.starts_with("cloud://")
        })
    {
        return Err("Tool shortcuts require a local container".into());
    }
    if !matches!(environment["status"].as_str(), Some("running" | "stopped")) {
        return Err(
            "Wait for this container's current operation to finish before launching a tool".into(),
        );
    }
    if environment["networkAccess"] == false {
        return Err("Enable this container's Internet access before launching a tool".into());
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
    let mut options = Options::parse(args)?;
    if options.dry {
        return Ok(Some(
            json!({"dryRun":true,"tool":options.tool,"request":if options.environment.is_none(){options.request(options.name.as_deref().unwrap_or(&options.tool))?}else{Value::Null},"environment":options.environment,"reuse":!options.fresh,"arguments":launch_arguments(&options.tool,&options.arguments),"terminal":"current","share":options.share,"gpuChoiceRequired":options.asks_gpu(),"resourceChoicesRequired":{"cpu":options.resource_choices()[0],"memory":options.resource_choices()[1]},"publicAccessPrompt":true,"credentialImportPrompt":true}),
        ));
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Tool shortcuts require an interactive terminal. Use --dry-run to inspect without creating a container.".into());
    }
    use crate::cli_ui as ui;
    let _raw = ui::Raw::on()?;
    let _session = ui::Session::start(&options.tool, "local sandbox · your tools and teammates");
    ui::intro("Tool sandbox", &options.tool);
    crate::client::start(None).await?;
    let state = call("get_platform_state", json!({})).await?;
    let environments = state["environments"]
        .as_array()
        .ok_or("No environment state")?;
    if !choose_ollama_gpu(&mut options,environments).await? {return Ok(None);}
    let (id, name) = if let Some(environment) = options.existing(environments)? {
        let id = environment["id"]
            .as_str()
            .ok_or("Missing environment ID")?
            .to_owned();
        if environment["status"] != "running" {
            call(
                "set_environment_status",
                json!({"environmentId":id,"status":"running"}),
            )
            .await?;
        }
        (
            id,
            environment["name"]
                .as_str()
                .unwrap_or(&options.tool)
                .to_owned(),
        )
    } else {
        let name = options.available_name(environments)?;
        if !choose_resources(&mut options, &state["host"])? { return Ok(None); }
        let task = ui::task(&format!("Creating {name} · {}", options.image));
        let result = call(
            "run_workload",
            json!({"request":options.request(&name)?,"start":true}),
        )
        .await?;
        task.done(&format!("{name} sandbox ready"));
        (
            result["id"]
                .as_str()
                .ok_or("Missing created environment ID")?
                .to_owned(),
            name,
        )
    };
    ui::step(&format!("Using {name}"));
    ui::info("Ctrl+C opens Cancel / Stop sandbox / Stop and delete. Ctrl+] disconnects and keeps the sandbox running.");
    // Finish quiet setup before either sharing prompts or the interactive tool.
    if crate::terminal::setup_tool(&id, &options.tool).await? != crate::terminal::SessionExit::Completed {
        return Ok(None);
    }
    if !crate::tool_credentials::configure(&id, &options.tool, options.share).await? {return Ok(None);}
    if !crate::tool_public_access::configure(&id,&options.tool).await? {return Ok(None);}
    if options.share {
        if !crate::tool_sharing::share(&id, &name).await? {
            return Ok(None);
        }
    }
    ui::info(&format!("Reconnect: yougori {} --environment {id}", options.tool));
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
            assert_eq!(request["runtime"], "ubuntu:24.04");
            assert_eq!(request["kind"], "container");
            assert_eq!(request["resourcePolicy"]["memoryGb"]["preferred"].as_f64(), Some(4.0));
            assert_eq!(request["pcAccess"].as_array().map_or(0, Vec::len), 0);
            assert_eq!(request["workload"]["binds"], json!([]));
        }
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
        ] {
            assert!(Options::parse(&words(input)).is_err(), "{input}");
        }
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
    fn only_matching_managed_containers_are_reused() {
        let options = Options::parse(&words("codex")).unwrap();
        let environments = vec![
            json!({"id":"foreign","kind":"container","name":"codex","status":"running"}),
            json!({"id":"stopped","kind":"container","description":options.description(),"status":"stopped"}),
            json!({"id":"running","kind":"container","description":options.description(),"status":"running"}),
        ];
        assert_eq!(
            options.existing(&environments).unwrap().unwrap()["id"],
            "running"
        );
        assert_eq!(options.available_name(&environments).unwrap(), "codex-2");
        assert!(Options::parse(&words("codex --memory 8GB"))
            .unwrap()
            .existing(&environments)
            .is_err());
        assert!(Options::parse(&words("codex --new"))
            .unwrap()
            .existing(&environments)
            .unwrap()
            .is_none());
        let unavailable = vec![
            json!({"kind":"container","description":options.description(),"status":"starting"}),
        ];
        assert!(options.existing(&unavailable).is_err());
    }
    #[test]
    fn explicit_targets_never_install_into_cloud_vm_or_unavailable_nodes() {
        let options = Options::parse(&words("claude --environment target")).unwrap();
        for environment in [
            json!({"id":"target","kind":"vm","status":"running"}),
            json!({"id":"target","kind":"container","runtime":"shared://tunnel/a","status":"running"}),
            json!({"id":"target","kind":"container","status":"starting"}),
            json!({"id":"target","kind":"container","status":"running","networkAccess":false}),
        ] {
            assert!(options.existing(&[environment]).is_err());
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
        for command in ["ollama","ollama --new","ollama --name models"] {
            assert!(Options::parse(&words(command)).unwrap().asks_gpu());
        }
        for command in ["codex","claude","ollama --new --gpu nvidia","ollama --environment existing"] {
            assert!(!Options::parse(&words(command)).unwrap().asks_gpu());
        }
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
        let environments = vec![json!({"id":"saved","kind":"container","description":options.description(),"status":"running","resourcePolicy":{"cpu":{"preferred":6},"memoryGb":{"preferred":12}}})];
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"], "saved");
        resource_sliders(&options, &json!({"totalCpu":16,"totalMemoryGb":32})).unwrap();
        assert_eq!(options.existing(&environments).unwrap().unwrap()["resourcePolicy"]["memoryGb"]["preferred"], 12);
        assert!(!options.custom_creation());
    }
    #[test]
    fn selected_resources_reach_the_creation_request_without_overriding_explicit_values() {
        let host = json!({"totalCpu":16,"totalMemoryGb":32});
        for tool in TOOLS {
            let mut options = Options::parse(&words(&format!("{tool} --new"))).unwrap();
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
        let mut options = Options::parse(&words("codex --new --cpu 3.5")).unwrap();
        let mut sliders = resource_sliders(&options, &host).unwrap();
        sliders[0].value = 12;
        options.apply_resources(&sliders).unwrap();
        assert_eq!(options.request("codex").unwrap()["resourcePolicy"]["cpu"]["preferred"], 3.5);
        assert_eq!(options.request("codex").unwrap()["resourcePolicy"]["memoryGb"]["preferred"], 12.0);
    }
    #[test]
    fn ollama_gpu_choice_creates_a_cuda_request_and_reuses_only_matching_containers() {
        let mut options=Options::parse(&words("ollama")).unwrap();
        let environments=vec![
            json!({"id":"cpu","name":"ollama","kind":"container","description":options.description(),"status":"running","gpuAccess":false}),
            json!({"id":"gpu","name":"ollama-2","kind":"container","description":options.description(),"status":"stopped","provider":"yougoriCuda","gpuAccess":true}),
        ];
        options.desired_gpu=Some(true);
        let request=options.request("ollama-3").unwrap();
        assert_eq!(request["gpuAccess"],true);
        assert_eq!(request["provider"],"yougoriCuda");
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"],"gpu");
        assert!(options.existing(&environments[..1]).unwrap().is_none());
        assert_eq!(options.available_name(&environments[..1]).unwrap(),"ollama-2");
        options.desired_gpu=Some(false);
        assert_eq!(options.request("ollama").unwrap()["gpuAccess"],false);
        assert_eq!(options.existing(&environments).unwrap().unwrap()["id"],"cpu");
        assert_eq!(environments[0]["gpuAccess"],false,"CPU sandbox was not changed");
    }
}
