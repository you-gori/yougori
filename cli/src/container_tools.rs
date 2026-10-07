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
               [--dry-run] [-- TOOL_ARGUMENTS...]
  yougori TOOL --environment ENV [-- TOOL_ARGUMENTS...]

The first run creates a local Ubuntu container and installs the tool. Later runs
reuse its container, files and sign-in. --new creates a fresh container. Creation
options apply only to a new container. --environment explicitly uses an existing
local container. No PC folder is shared unless --mount is supplied.

Installation and the tool run right in this terminal. Ctrl+] disconnects the
session; the container and installed files remain. Tool authentication and account
setup happen inside the container. No credentials are copied from the host.

Ollama starts `ollama serve` by default. OpenClaw opens `openclaw onboard`.
Pass arguments after -- to select another action, for example:
  yougori codex -- --help
  yougori ollama -- run MODEL
  yougori openclaw -- gateway run
  yougori claude --new --memory 8GB
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
    fn description(&self) -> String {
        format!("Yougori tool · {}", self.tool)
    }
    fn request(&self, name: &str) -> Result<Value, String> {
        let mut args = vec!["-it".into(), "--name".into(), name.into()];
        if !self.creation.iter().any(|flag| flag == "--memory") {
            args.extend(["--memory".into(), "4GB".into()]);
        }
        args.extend(self.creation.iter().cloned());
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
    let options = Options::parse(args)?;
    if options.dry {
        return Ok(Some(
            json!({"dryRun":true,"tool":options.tool,"request":if options.environment.is_none(){options.request(options.name.as_deref().unwrap_or(&options.tool))?}else{Value::Null},"environment":options.environment,"reuse":!options.fresh,"arguments":launch_arguments(&options.tool,&options.arguments),"terminal":"current"}),
        ));
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("Tool shortcuts require an interactive terminal. Use --dry-run to inspect without creating a container.".into());
    }
    crate::client::start(None).await?;
    let state = call("get_platform_state", json!({})).await?;
    let environments = state["environments"]
        .as_array()
        .ok_or("No environment state")?;
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
        eprintln!("Creating {name} · {}", options.image);
        let result = call(
            "run_workload",
            json!({"request":options.request(&name)?,"start":true}),
        )
        .await?;
        (
            result["id"]
                .as_str()
                .ok_or("Missing created environment ID")?
                .to_owned(),
            name,
        )
    };
    eprintln!("{} · {name} ({id})\nCtrl+] disconnects this session. Reconnect with: yougori {} --environment {id}", options.tool, options.tool);
    crate::terminal::attach_tool(
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
}
