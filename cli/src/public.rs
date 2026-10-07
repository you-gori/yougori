//! Friendly workload commands. The advanced, schema-driven API remains available.
use crate::{
    client,
    manifest::{self, Command, Environment, Port},
    workload::Volume,
};
use serde_json::{json, Value};
use std::{
    io::{IsTerminal, Read, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const HELP: &str = r#"
Public commands:
  yougori                         Open the main menu; quietly add this project's shortcut
  yougori cli                     Interactive menus: create, manage and open environment terminals
  yougori launch [--change]        Run this project; press y to sync when switching copies
  npm run yougori                 Run the project again; Ctrl+C stops its container
  npm run yougori-change          Change project settings, then run it
  npm run yougori-cloud           Select a connected cloud server and run this project there
  yougori launch --cloud [--change]  Cloud project launch with on-demand sync and dev logs
  python yougori [--change]       Run a Python project after its first setup
  yougori run [-d] [--name NAME] [-p HOST:GUEST] [-e KEY=VALUE] IMAGE [COMMAND...]
  yougori create [OPTIONS] IMAGE    Create without starting
  yougori status                   Everything at a glance: environments, links, sharing, jobs
  yougori ps [-a] [--type container|gpu|model|microvm|vm|cloud|shared|app]
  yougori inspect ENV | logs ENV [--cursor CURSOR] [--tail BYTES] [--follow]
  yougori exec ENV [--no-wait] [--timeout WAIT_SECONDS] [--guest-timeout SECONDS] -- COMMAND...
  yougori terminal ENV            Open an interactive shell; exit leaves the workload running
  yougori download on ENV [--domain HOST] --yes  Share a complete copy while this CLI stays open
  yougori download list | off ID   Lifetime download counts / turn off a download link
  yougori cp PC_PATH... ENV        Copy PC files into a local or connected cloud environment
  yougori cp ENV:/path PC_FOLDER   Copy out of a supported environment (never overwrites)
  yougori cp ENV:/path OTHER_ENV   Copy between environments (OTHER_ENV:/folder picks the folder)
  yougori volume ls [--scan] [--size] | inspect NAME | rm NAME... --yes | prune [--yes]
  yougori volume cp VOLUME[:/path] PC_FOLDER | cp PC_PATH... VOLUME[:/path]
  yougori ls ENV [PATH]            Browse folders inside an environment
  yougori rename ENV NEW_NAME
  yougori ports list --all         Every published port across all environments
  yougori init [--name PROJECT]    Create yougori.yaml, .yougoriignore and .yougori/PREFERENCES.md
  yougori prefs path | show | remember KEY VALUE [--project] | forget KEY [--project]
  yougori doctor                   Is this computer ready? Checks engine, runtimes, GPU, disk, PATH
  yougori app autostart on [--dashboard] | off | status
  yougori update [--check | --yes]  Signed, hash-checked updates from yougori.com
  yougori uninstall [--yes]        Removes the app; keeps environments and their data
  yougori top [--once]             Live CPU, memory, storage and network per environment
  Add --format json|table to status/ps/ports (table in a terminal, JSON when piped)
  yougori start|stop|restart ENV   Accepts an ID or exact environment name
  yougori rm ENV --yes             Permanently delete an environment and its managed data
  yougori pull IMAGE | images | image rm IMAGE
  yougori up|apply|down [-f yougori.yaml]
  yougori deployment status [-f yougori.yaml]  Application, tunnel and public HTTPS readiness
  yougori deployment secret set NAME --yes    Reads {"value":"..."} from private stdin
  yougori import compose.yaml [--dry-run]
  yougori run --gpu nvidia IMAGE
  yougori run --isolation microvm IMAGE
  yougori machine run IMAGE_OR_ISO
  yougori vm run IMAGE_OR_ISO      Alias for machine run
  yougori microvm run IMAGE        Alias for run --isolation microvm
  yougori model run [hf.co/OWNER/MODEL] [--neocloud [--environment ENV]] [--change] [--api] [--port 8000]
                                  Omit the model in a terminal to fill in hf.co/; Esc cancels
  yougori confidential --model OWNER/MODEL --provider NODE --policy LOCAL_POLICY.json
                                  Encrypt chat JSON from stdin using YOUGORI_NETWORK_API_KEY
  yougori login | logout | account  Network account shared with the desktop app
  yougori model optimize ENV [--on|--off] [--pin|--unpin] [--idle SECONDS]
  yougori model run hf.co/OWNER/MODEL --now|--nowfree [--publish (closed weights)] [--folder PATH] [--listen (free only)] [--quant Q4_K_M] [--storage-drive DRIVE]
                                   Share paid or free through Yougori
  yougori model library [--mine]    Browse published open and private models
  yougori model publish --file publication.json  Create a model publication
  yougori model connect yg/PUBLISHER/MODEL --file endpoint.json|-  Connect a publisher-hosted API
  yougori model upload yg/PUBLISHER/MODEL --folder PATH --version v1 [--quant Q4_K_M] [--resume ID]
  yougori model download yg/PUBLISHER/MODEL --output PATH  Verify and download authorized weights
  yougori model permissions yg/PUBLISHER/MODEL --wallet 0x... --role caller|downloader|host|remove
  yougori model run yg/PUBLISHER/MODEL --now|--nowfree  Run a published model on your GPU
  yougori model unshare ENV        Stop sharing; leave the model running
  yougori model auth login | status | logout  Protected Hugging Face token shared with the App
  yougori model decide ENV --file REQUEST.json|-  Typed decision probabilities
  yougori model stop ENV           Stop the model; a Neocloud pod stays billable
  yougori model preflight hf.co/OWNER/MODEL   Compatibility and requirements before weights
  yougori model support hf.co/OWNER/MODEL --agent claude|codex|kilo|opencode|gemini [--launch]
                                   Reuses this model's environment when one exists
  yougori model chat ENV | model status ENV | model api ENV [--port 8000]
  yougori model chat ENV [--new]   Continues the conversation shared with the app
  yougori model history ENV        Saved conversations
  yougori model access ENV         API key plus local and public addresses
  yougori model usage ENV [--days 7] [--reset --yes]
  yougori changes ENV [--baseline] [--offset N]
  yougori vault mcp                Connect an MCP client to Personal Vault
  yougori vault identity --output DEVICE.json
  yougori vault mcp --remote HOST:49731 --pin SHA256 --identity DEVICE.json
  yougori vault help
  yougori remote create|connect|list|update|revoke|disconnect|remove|start|stop|files|inspect|download
                                  Remote tunnel sharing; use --file - for credentials
  yougori remote start --domain app.example.com   Share on a saved domain
  yougori agent inventory         Machine-readable compute targets and current capabilities
  yougori agent discover          Current CLI/engine, protocol and canonical skill identity
  yougori neocloud providers | discover --provider P [--location REGION]
  yougori neocloud plan --file request.json | create --file request.json --yes
  yougori neocloud inspect|start|stop ENV
  yougori neocloud delete ENV --confirmation EXACT_NAME --yes
  yougori info | version
  yougori help | --help | --version

Run options: --cpu CORES, --memory 4GB, --storage 30GB, --storage-drive PATH,
  --volume NAME:/guest/path[:ro], --mount PC_FOLDER:/guest/path[:ro],
  --workdir /path, --entrypoint PROGRAM, --user USER, --restart POLICY,
  --internet true|false (default true), -it (interactive shell), --dry-run.
Ports bind to 127.0.0.1. Use `ports publish` for explicit LAN/public access.
up/apply preserve removed nodes and data; down stops without deleting volumes.
Use --dry-run to validate before starting. No Docker installation is needed.
In a terminal, new local environments ask which drive to use and show free space.
--storage-drive PATH skips that question. Scripts use the default when omitted.
Reusing an environment keeps its existing storage location.
"#;

pub async fn call(method: &str, params: Value) -> Result<Value, String> {
    let mut req = client::request(method, params);
    req.confirmed = true;
    let result = client::call(&req).await?;
    if result["accepted"] == true {
        client::wait_job(result["jobId"].as_str().ok_or("Missing job ID")?, 86400).await
    } else {
        Ok(result)
    }
}

pub async fn call_with_progress(method: &str, params: Value, progress: impl FnMut(&Value)) -> Result<Value, String> {
    let mut req = client::request(method, params);
    req.confirmed = true;
    let result = client::call(&req).await?;
    if result["accepted"] == true {
        client::wait_job_with_progress(result["jobId"].as_str().ok_or("Missing job ID")?, 86400, progress).await
    } else {
        Ok(result)
    }
}

/// Older running engines place models on their configured drive and reject the new resource field.
/// An explicitly chosen drive may be omitted only when it is exactly that configured drive.
pub fn model_storage_drive(supports_selection: bool, host: &Value, requested: Option<&str>) -> Result<Option<String>, String> {
    if supports_selection {
        return Ok(requested.map(str::to_owned));
    }
    if let Some(requested) = requested {
        if host["storageDrive"].as_str().filter(|path| !path.is_empty())
            .is_none_or(|current| !crate::storage::same_drive(current, requested)) {
            return Err("The running engine can create models only on its configured storage drive. Quit and reopen the updated Yougori app to choose another drive, then retry. No environment was created.".into());
        }
    }
    Ok(None)
}
/// `hf.co/Owner/Name` and `https://huggingface.co/Owner/Name` as the Hugging Face ID `Owner/Name`.
pub fn model_name(model: &str) -> String {
    let model = model.trim();
    model
        .strip_prefix("https://huggingface.co/")
        .or_else(|| model.strip_prefix("hf.co/"))
        .unwrap_or(model)
        .trim_end_matches('/')
        .to_owned()
}
/// The environment already serving this model, preferring a running one, then the most recent.
pub fn existing_model<'a>(environments: &'a [Value], model: &str) -> Option<&'a Value> {
    let wanted = format!("Hugging Face · {}", model_name(model)).to_lowercase();
    environments
        .iter()
        .filter(|env| {
            env["kind"] == "container"
                && env["status"] != "deleting"
                && env["description"]
                    .as_str()
                    .is_some_and(|d| d.to_lowercase() == wanted)
        })
        .min_by_key(|env| {
            let recent = env["lastOpenedAt"]
                .as_str()
                .or(env["createdAt"].as_str())
                .unwrap_or("")
                .to_owned();
            (env["status"] != "running", std::cmp::Reverse(recent))
        })
}
/// A model environment is named after its model (`Owner/Name-7B` is `Name-7B`), numbered when
/// that name is taken; environment names are unique regardless of case.
pub fn model_environment_name<'a>(model: &str, taken: impl Iterator<Item = &'a str> + Clone) -> String {
    let base = model_name(model);
    let base = base.rsplit('/').next().unwrap_or(&base);
    let base = if base.chars().count() < 2 {
        format!("model-{base}")
    } else {
        base.chars().take(76).collect()
    };
    (1..)
        .map(|n| if n == 1 { base.clone() } else { format!("{base}-{n}") })
        .find(|name| !taken.clone().any(|t| t.eq_ignore_ascii_case(name)))
        .unwrap_or(base)
}
/// Names like `model-ad450f21`, which model environments were given before they were named
/// after their model.
pub fn generated_model_name(name: &str) -> bool {
    name.strip_prefix("model-")
        .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}
/// Renames an environment from before models were named after themselves.
pub async fn name_after_model(env: &mut Value, environments: &[Value]) {
    let Some(model) = env["description"].as_str().and_then(|d| d.strip_prefix("Hugging Face · ")) else {
        return;
    };
    if !env["name"].as_str().is_some_and(generated_model_name) {
        return;
    }
    let name = model_environment_name(
        model,
        environments.iter().filter(|e| e["id"] != env["id"]).filter_map(|e| e["name"].as_str()),
    );
    if call("rename_environment", json!({"environmentId":env["id"],"name":name})).await.is_ok() {
        env["name"] = json!(name);
    }
}
pub async fn find_model(model: &str) -> Result<Option<Value>, String> {
    let state = call("get_platform_state", json!({})).await?;
    let environments = state["environments"].as_array().map_or(&[][..], Vec::as_slice);
    let Some(mut env) = existing_model(environments, model).cloned() else {
        return Ok(None);
    };
    name_after_model(&mut env, environments).await;
    Ok(Some(env))
}
pub const NO_MODEL_PODS: &str = "No RunPod GPU pods are attached to Yougori. Create or add a GPU pod in Neocloud → RunPod, start it, and wait for SSH to be ready.";
/// Display names are independent of RunPod's restricted pod names and deletion confirmation.
pub async fn name_neocloud_model(env: &mut Value, state: &Value, model: &str) -> Result<(), String> {
    let normalized = model_name(model);
    let model = normalized.trim_end_matches('/').rsplit('/').next().unwrap_or(&normalized);
    let base: String = format!("RunPod/{model}").chars().filter(|c| !c.is_control()).take(76).collect();
    let name = (1..).map(|n| if n == 1 { base.clone() } else { format!("{base}-{n}") })
        .find(|name| !state["environments"].as_array().into_iter().flatten().any(|other|
            other["id"] != env["id"] && other["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(name))))
        .unwrap_or(base);
    if env["name"] != name {
        call("rename_environment", json!({"environmentId":env["id"],"name":name})).await?;
        env["name"] = json!(name);
    }
    Ok(())
}
pub fn validate_model_neocloud(neocloud: bool, environment: Option<&str>, resources: bool) -> Result<(), String> {
    if environment.is_some() && !neocloud { return Err("--environment requires --neocloud".into()); }
    if neocloud && resources { return Err("--change, --cpu, --memory and --storage are local options. A Neocloud model uses the selected pod's existing resources.".into()); }
    Ok(())
}
pub fn neocloud_model_targets(state: &Value) -> Vec<Value> {
    state["environments"].as_array().into_iter().flatten().filter(|env| {
        let deployment = &state["neocloudDeployments"][env["id"].as_str().unwrap_or("")];
        env["kind"] == "cloud" && deployment["provider"] == "runpod"
            && matches!(deployment["product"].as_str(), Some("pod" | "gpu"))
            && env["status"] != "deleting"
            && !matches!(deployment["state"].as_str(), Some("Deleted" | "Terminated"))
            && deployment["extra"]["compute"] != "cpu"
    }).cloned().collect()
}
pub fn choose_neocloud_target<'a>(targets: &'a [Value], name: &str) -> Result<&'a Value, String> {
    let found = targets.iter().filter(|e| e["id"] == name || e["name"].as_str().is_some_and(|v| v.eq_ignore_ascii_case(name))).collect::<Vec<_>>();
    if found.len() != 1 { return Err(format!("Expected one existing RunPod GPU pod named {name}. {NO_MODEL_PODS}")); }
    Ok(found[0])
}
/// Starts an existing model environment instead of creating another GPU container, applying any
/// requested resources and, with `port`, its localhost API.
pub async fn reuse_model(env: &Value, resources: &serde_json::Map<String, Value>, port: Option<u16>) -> Result<Value, String> {
    validate_model_resources(resources)?;
    let id = env["id"].as_str().ok_or("Model environment missing")?;
    let current = |name: &str| env["resourcePolicy"][name]["max"].as_f64().unwrap_or(0.0);
    if resources.contains_key("cpu") || resources.contains_key("memoryGb")
        || env["resourcePolicy"]["cpu"]["min"].as_f64().unwrap_or(0.0) < 2.0
        || env["resourcePolicy"]["memoryGb"]["min"].as_f64().unwrap_or(0.0) < 4.0 {
        let range = |v: f64| json!({"min":v,"preferred":v,"max":v,"current":v});
        let cpu = resources.get("cpu").and_then(Value::as_f64).unwrap_or_else(|| current("cpu").max(2.0));
        let memory = resources.get("memoryGb").and_then(Value::as_f64).unwrap_or_else(|| current("memoryGb").max(4.0));
        call("update_resource_policy", json!({"environmentId":id,"resourcePolicy":{"cpu":range(cpu),"memoryGb":range(memory),"priority":"normal"}})).await?;
    }
    if let Some(storage) = resources.get("storageGb").and_then(Value::as_f64) {
        call("expand_environment_storage", json!({"environmentId":id,"capacityGb":storage.ceil() as u64})).await?;
    }
    if env["status"] != "running" {
        call("set_environment_status", json!({"environmentId":id,"status":"running"})).await?;
    }
    let model = env["description"].as_str().and_then(|d| d.strip_prefix("Hugging Face · ")).unwrap_or("");
    let mut result = json!({"id":id,"name":env["name"],"model":model,"status":"loading","reused":true});
    if let Some(port) = port {
        let api = call("model_api", json!({"environmentId":id,"port":port})).await?;
        result["apiUrl"] = api["apiUrl"].clone();
        result["apiKey"] = api["apiKey"].clone();
    }
    Ok(result)
}
pub async fn resolve(name: &str) -> Result<String, String> {
    let state = call("get_platform_state", json!({})).await?;
    let envs = state["environments"]
        .as_array()
        .ok_or("No environment state")?;
    let matches = envs
        .iter()
        .filter(|v| {
            v["id"] == name
                || v["name"]
                    .as_str()
                    .is_some_and(|v| v.eq_ignore_ascii_case(name))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "Expected one environment named {name}; run yougori ps"
        ));
    }
    Ok(matches[0]["id"].as_str().unwrap().into())
}
fn absolute(path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir().map_err(|e| e.to_string())?.join(p))
    }
}
fn value(args: &[String], i: &mut usize, name: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{name} needs a value"))
}
#[derive(Debug)]
pub struct Run {
    pub request: Value,
    pub detached: bool,
    pub interactive: bool,
    pub dry: bool,
}
fn attach_run_output(run: &Run, terminal_output: bool) -> Result<bool, String> {
    if run.interactive && !run.detached && !terminal_output {
        return Err("Interactive run requires a terminal. Use `-d` for an agent or script.".into());
    }
    Ok(!run.detached && terminal_output)
}
pub fn parse_run(args: &[String], machine: bool) -> Result<Run, String> {
    let mut spec = Environment {
        internet: true,
        ..Default::default()
    };
    if machine {
        spec.kind = "vm".into()
    }
    let mut name = None;
    let mut detached = false;
    let mut interactive = false;
    let mut dry = false;
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        match flag.as_str() {
            "-d" | "--detach" => detached = true,
            "-it" | "-ti" | "--interactive" => interactive = true,
            "--dry-run" => dry = true,
            "--name" => name = Some(value(args, &mut i, flag)?),
            "--cpu" => {
                spec.cpu = value(args, &mut i, flag)?
                    .parse()
                    .map_err(|_| "--cpu must be a number")?
            }
            "--memory" | "-m" => spec.memory = json!(value(args, &mut i, flag)?),
            "--storage" => spec.storage = json!(value(args, &mut i, flag)?),
            "--storage-drive" => spec.storage_drive = Some(value(args, &mut i, flag)?),
            "--gpu" => {
                if value(args, &mut i, flag)? != "nvidia" {
                    return Err("GPU workloads currently support NVIDIA CUDA".into());
                }
                spec.gpu = true
            }
            "--isolation" => {
                spec.kind = value(args, &mut i, flag)?;
                if !["container", "microvm"].contains(&spec.kind.as_str()) {
                    return Err("Use container or microvm isolation".into());
                }
            }
            "--internet" => {
                spec.internet = value(args, &mut i, flag)?
                    .parse::<bool>()
                    .map_err(|_| "--internet must be true or false")?
            }
            "-p" | "--publish" => {
                let p = Port::Mapping(value(args, &mut i, flag)?);
                p.values()?;
                spec.ports.push(p)
            }
            "-e" | "--env" => {
                let e = value(args, &mut i, flag)?;
                let (k, v) = e.split_once('=').ok_or("Use -e KEY=VALUE")?;
                if spec.environment.insert(k.into(), v.into()).is_some() {
                    return Err(format!("Environment variable {k} supplied twice"));
                }
            }
            "--workdir" | "-w" => spec.working_dir = Some(value(args, &mut i, flag)?),
            "--user" | "-u" => spec.user = Some(value(args, &mut i, flag)?),
            "--restart" => spec.restart = value(args, &mut i, flag)?,
            "--entrypoint" => {
                spec.entrypoint = Some(Command::Args(vec![value(args, &mut i, flag)?]))
            }
            "-v" | "--volume" | "--mount" => {
                let v = value(args, &mut i, flag)?;
                let (v, ro) = if let Some(v) = v.strip_suffix(":ro") {
                    (v, true)
                } else {
                    (v.strip_suffix(":rw").unwrap_or(&v), false)
                };
                let (source, target) = v.rsplit_once(':').ok_or("Use SOURCE:/guest/path[:ro]")?;
                let bind = flag == "--mount"
                    || source.starts_with(['.', '/'])
                    || PathBuf::from(source).is_absolute();
                spec.volumes.push(manifest::Mount {
                    source: if bind {
                        absolute(source)?.to_string_lossy().into_owned()
                    } else {
                        source.into()
                    },
                    target: target.into(),
                    read_only: ro,
                    bind,
                });
                if bind {
                    spec.permissions.pc = true;
                    spec.permissions.edit |= !ro
                }
            }
            "--" => {
                i += 1;
                break;
            }
            v if v.starts_with('-') => return Err(format!("Unknown run option {v}")),
            _ => break,
        }
        i += 1;
    }
    let image = args
        .get(i)
        .ok_or("Usage: yougori run [OPTIONS] IMAGE [COMMAND...]")?
        .clone();
    spec.image = image.clone();
    i += 1;
    if i < args.len() {
        spec.command = Some(Command::Args(args[i..].to_vec()))
    } else if interactive && !machine {
        spec.command = Some(Command::Args(vec![
            "/bin/sh".into(),
            "-c".into(),
            "while :; do sleep 3600; done".into(),
        ]));
        spec.entrypoint = Some(Command::Args(vec![]));
    }
    if machine {
        spec.source = Some(absolute(&image)?.to_string_lossy().into_owned())
    }
    if spec.gpu && spec.kind != "container" {
        return Err("--gpu requires container isolation".into());
    }
    // Bare numbers are GiB too.
    for v in [&mut spec.memory, &mut spec.storage] {
        if let Some(n) = v.as_str().and_then(|s| s.parse::<f64>().ok()) {
            *v = json!(n)
        }
    }
    let fallback = format!(
        "workload-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis()
    );
    let name = name.unwrap_or(fallback);
    if !crate::workload::identifier(&name) || name.len() < 2 {
        return Err("Use a name of 2–80 letters, digits, dots, dashes or underscores".into());
    }
    let project = manifest::Project {
        project: "run".into(),
        environments: [("workload".into(), spec.clone())].into_iter().collect(),
        connections: vec![],
        publish: Default::default(),
    };
    project.validate()?;
    let mut request = spec.create_request("run", "workload")?;
    request["name"] = name.into();
    request["description"] = json!("Created with yougori run");
    request["ports"] = serde_json::to_value(&spec.ports).unwrap();
    // Standalone named volumes use the user's name without a synthetic project prefix.
    if spec.kind == "container" {
        let mut options = spec.options("run")?;
        options.volumes = spec
            .volumes
            .iter()
            .filter(|v| !v.bind)
            .map(|v| Volume {
                source: v.source.clone(),
                target: v.target.clone(),
                read_only: v.read_only,
            })
            .collect();
        request["workload"] = json!(options)
    }
    if spec.kind == "microvm" {
        request["microvmWorkload"] = json!({"image":image,"options":spec.options("microvm")?})
    }
    Ok(Run {
        request,
        detached,
        interactive,
        dry,
    })
}

pub async fn handle(args: &[String]) -> Result<Option<Value>, String> {
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(None);
    };
    let command = if matches!(first, "vm" | "machine" | "microvm")
        && args.get(1).is_some_and(|a| a == "run")
    {
        "run"
    } else {
        first
    };
    if ![
        "run", "create", "ps", "start", "stop", "restart", "rm", "exec", "logs", "inspect", "pull",
        "images", "image", "info", "version", "up", "down", "apply", "import", "changes", "model",
        "cp", "ls", "rename", "volume", "init", "prefs", "deployment",
    ]
    .contains(&command)
    {
        return Ok(None);
    }
    if command == "version" {
        return Ok(Some(
            json!({"version":env!("CARGO_PKG_VERSION"),"command":"yougori"}),
        ));
    }
    if command == "deployment" {
        match args.get(1).map(String::as_str) {
            Some("status") => {
                let path = match &args[2..] {
                    [] => manifest::locate(&std::env::current_dir().map_err(|e| e.to_string())?)?,
                    [flag, path] if matches!(flag.as_str(), "-f" | "--file") => absolute(path)?,
                    _ => return Err("Usage: yougori deployment status [-f yougori.yaml]".into()),
                };
                client::start(None).await?;
                return call("deployment_status", json!({"path":path})).await.map(Some);
            },
            Some("secret") => {
                // Read a bounded private JSON request from stdin, never accept
                // an application credential as a shell argument.
                let (method, name) = match &args[2..] {
                    [action, name, yes] if action == "set" && yes == "--yes" => ("set_deployment_secret", name),
                    [action, name, yes] if action == "delete" && yes == "--yes" => ("delete_deployment_secret", name),
                    _ => return Err("Usage: deployment secret set NAME --yes < private-secret.json | delete NAME --yes. Set reads {\"value\":\"...\"} from stdin.".into()),
                };
                let mut params = json!({"name":name});
                if method == "set_deployment_secret" {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    std::io::stdin().take(crate::wire::MAX_REQUEST as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                    if bytes.len() > crate::wire::MAX_REQUEST { return Err("Secret request exceeds 1 MB".into()); }
                    let input: Value = serde_json::from_slice(&bytes).map_err(|_| "Secret stdin must be a JSON object containing only value")?;
                    if input.as_object().is_none_or(|o| o.len() != 1) || !input["value"].is_string() { return Err("Secret stdin must contain only a string value".into()); }
                    params["value"] = input["value"].clone();
                }
                client::start(None).await?;
                return call(method, params).await.map(Some);
            },
            _ => return Err("Usage: yougori deployment status [-f PATH] | secret set|delete NAME --yes".into()),
        }
    }
    if command == "run" || command == "create" {
        if command == "run" && first == "run" && args.get(1).is_some_and(|s| s.starts_with("hf.co/") || s.starts_with("https://huggingface.co/")) {
            let mut model_args = vec!["model".into(), "run".into()];
            model_args.extend_from_slice(&args[1..]);
            return model(&model_args).await.map(Some);
        }
        let nested = first != command;
        let mut rest = args[if nested { 2 } else { 1 }..].to_vec();
        if first == "microvm" {
            rest.splice(0..0, ["--isolation".into(), "microvm".into()]);
        }
        let run = parse_run(&rest, matches!(first, "machine" | "vm"))?;
        if run.dry {
            let mut safe = run.request.clone();
            if let Some(vars) = safe["workload"]["environment"].as_object_mut() {
                for v in vars.values_mut() {
                    *v = json!("[redacted]")
                }
            }
            return Ok(Some(
                json!({"dryRun":true,"request":safe,"start":command=="run"}),
            ));
        }
        // A pipe is a machine client: finish with one JSON result instead of
        // attaching to an endless log/terminal stream.
        let terminal_output = std::io::stdout().is_terminal();
        let attach_output = attach_run_output(&run, terminal_output)?;
        client::start(None).await?;
        let result = call(
            "run_workload",
            json!({"request":run.request,"start":command=="run"}),
        )
        .await?;
        if command == "run" && attach_output {
            let id = result["id"].as_str().ok_or("Missing created ID")?;
            eprintln!("Environment: {id}");
            if run.interactive {
                terminal(id).await?
            } else {
                follow_logs(id).await?
            }
        }
        return Ok(Some(result));
    }
    if ["up", "apply", "down"].contains(&command) {
        let mut path = None;
        let mut dry = false;
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-f" | "--file" => path = Some(absolute(&value(args, &mut i, "--file")?)?),
                "--dry-run" => dry = true,
                _ => {
                    return Err("Usage: yougori up|apply|down [-f yougori.yaml] [--dry-run]".into())
                }
            }
            i += 1;
        }
        let path = match path {
            Some(path) => path,
            None => manifest::locate(&std::env::current_dir().map_err(|e| e.to_string())?)?,
        };
        let p = manifest::parse(&manifest::read(&path)?)?;
        if dry {
            return Ok(Some(
                json!({"dryRun":true,"project":p.project,"environments":p.environments.keys().collect::<Vec<_>>(),"order":p.order()?,"action":command}),
            ));
        }
        client::start(None).await?;
        return call("project_action", json!({"path":path,"action":command}))
            .await
            .map(Some);
    }
    if command == "import" {
        if args.len() < 2 || args.len() > 3 || args.get(2).is_some_and(|s| s != "--dry-run") {
            return Err("Usage: yougori import compose.yaml [--dry-run]".into());
        }
        let path = absolute(&args[1])?;
        let p = manifest::compose::convert(&path)?;
        if args.len() == 3 {
            return Ok(Some(
                json!({"dryRun":true,"project":p.project,"environments":p.environments.keys().collect::<Vec<_>>(),"connections":p.connections.len()}),
            ));
        }
        client::start(None).await?;
        return call(
            "import_compose",
            json!({"path":path,"write":true,"project":p}),
        )
        .await
        .map(Some);
    }
    if command == "init" {
        let name = match &args[1..] {
            [] => None,
            [flag, name] if flag == "--name" => Some(name.as_str()),
            _ => return Err("Usage: yougori init [--name PROJECT]".into()),
        };
        return crate::project_files::init(&std::env::current_dir().map_err(|e| e.to_string())?, name).map(Some);
    }
    if command == "prefs" {
        return prefs(&args[1..]).map(Some);
    }
    if command == "model" {
        return model(args).await.map(Some);
    }
    if command == "rm" && !matches!(args, [_, _, yes] if yes == "--yes") {
        return Err("Usage: yougori rm ENV --yes. This permanently deletes the environment and its managed data.".into());
    }
    if command == "volume" && args.get(1).is_some_and(|action| action == "rm")
        && !args[2..].iter().any(|arg| arg == "--yes")
    {
        return Err("Usage: yougori volume rm NAME... --yes. This permanently deletes the volume and its data.".into());
    }
    let execution = if command == "exec" {
        if args.len() < 3 { return Err("Usage: exec ENV [--no-wait] [--timeout SECONDS] -- COMMAND [ARG...]".into()); }
        Some(crate::execution::parse(&args[2..])?)
    } else { None };
    let logs = if command == "logs" {
        if args.len()<2{return Err("Usage: logs ENV [--cursor CURSOR] [--limit BYTES] [--tail BYTES] [--last-error] [--follow]".into());}
        Some(crate::logs::parse(&args[2..])?)
    }else{None};
    client::start(None).await?;
    let require_one = || {
        if args.len() == 2 {
            Ok(args[1].as_str())
        } else {
            Err(format!("Usage: yougori {command} ENV"))
        }
    };
    let result = match command {
        "info" => {
            if args.len() != 1 {
                return Err("Usage: yougori info".into());
            }
            call("get_platform_state", json!({})).await?
        }
        "ps" => {
            let usage = || format!("Usage: yougori ps [-a] [--type {}]", crate::overview::TYPES.join("|"));
            let mut wanted = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-a" | "--all" => {}
                    "--type" => wanted = Some(value(args, &mut i, "--type")?),
                    _ => return Err(usage()),
                }
                i += 1;
            }
            if wanted.as_deref().is_some_and(|t| !crate::overview::TYPES.contains(&t)) {
                return Err(usage());
            }
            let envs = call("get_platform_state", json!({})).await?["environments"].clone();
            Value::Array(envs.as_array().into_iter().flatten()
                .filter(|e| wanted.as_deref().is_none_or(|t| crate::overview::matches_type(e, t)))
                .map(crate::overview::listing)
                .collect())
        }
        "start" | "stop" => {
            let id = resolve(require_one()?).await?;
            call(
                "set_environment_status",
                json!({"environmentId":id,"status":if command=="start"{"running"}else{"stopped"}}),
            )
            .await?
        }
        "restart" | "rm" => {
            let target = if command == "rm" { &args[1] } else { require_one()? };
            let id = resolve(target).await?;
            call(
                if command == "restart" {
                    "restart_environment"
                } else {
                    "delete_environment"
                },
                json!({"environmentId":id}),
            )
            .await?
        }
        "inspect" => {
            let id = resolve(require_one()?).await?;
            call("get_platform_state", json!({})).await?["environments"]
                .as_array()
                .and_then(|a| a.iter().find(|v| v["id"] == id))
                .cloned()
                .ok_or("Environment not found")?
        }
        "cp" => copy(&args[1..]).await?,
        "volume" => volume(&args[1..]).await?,
        "ls" => {
            if !(2..=3).contains(&args.len()) {
                return Err("Usage: yougori ls ENV [PATH]".into());
            }
            let id = resolve(&args[1]).await?;
            call("list_environment_folders", json!({"environmentId":id,"path":args.get(2).map_or("", String::as_str)})).await?
        }
        "rename" => {
            if args.len() != 3 {
                return Err("Usage: yougori rename ENV NEW_NAME".into());
            }
            let id = resolve(&args[1]).await?;
            call("rename_environment", json!({"environmentId":id,"name":args[2]})).await?
        }
        "logs" => {
            let id=resolve(&args[1]).await?;
            crate::logs::read(&id,logs.unwrap()).await?
        }
        "exec" => {
            let id = resolve(&args[1]).await?;
            let options = execution.unwrap();
            let state=call("get_platform_state",json!({})).await?;
            let target=state["environments"].as_array().and_then(|items|items.iter().find(|e|e["id"]==id)).ok_or("Environment not found")?;
            let request = crate::execution::prepare_request(target,&id,&options)?;
            let accepted = client::call(&request).await?;
            if !options.no_wait && accepted["accepted"] == true {
                client::wait_job(accepted["jobId"].as_str().ok_or("Missing execution job ID")?, options.timeout).await?
            } else { accepted }
        }
        "images" => {
            if args.len() != 1 {
                return Err("Usage: yougori images".into());
            }
            call("manage_oci_images", json!({"action":"list"})).await?
        }
        "pull" => {
            call(
                "manage_oci_images",
                json!({"action":"pull","image":require_one()?}),
            )
            .await?
        }
        "image" => {
            if args.len() != 3 || args[1] != "rm" {
                return Err("Usage: yougori image rm IMAGE".into());
            }
            call(
                "manage_oci_images",
                json!({"action":"remove","image":args[2]}),
            )
            .await?
        }
        "changes" => {
            if args.len() < 2 {
                return Err("Usage: yougori changes ENV [--baseline] [--offset N]".into());
            }
            let mut baseline = false;
            let mut offset = 0usize;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--baseline" => baseline = true,
                    "--offset" => {
                        offset = value(args, &mut i, "--offset")?
                            .parse()
                            .map_err(|_| "Offset must be a nonnegative number")?
                    }
                    _ => return Err("Usage: yougori changes ENV [--baseline] [--offset N]".into()),
                }
                i += 1;
            }
            let id = resolve(&args[1]).await?;
            call(
                "environment_changes",
                json!({"environmentId":id,"baseline":baseline,"offset":offset}),
            )
            .await?
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}
async fn follow_logs(id: &str) -> Result<(), String> {
    let mut cursor = None;
    let mut terminal=crate::logs::TerminalText::default();
    loop {
        let output = call("get_environment_log_window", json!({"environmentId":id,"cursor":cursor,"limit":65536,"tail":16384})).await?;
        print!("{}",terminal.feed(output["stdout"].as_str().unwrap_or("")));
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        cursor=output["nextCursor"].as_str().map(str::to_owned);
        if output["truncated"]==true {continue;}
        let state = call("refresh_host_metrics", json!({})).await?;
        let running = state["environments"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v["id"] == id && v["status"] == "running"));
        if !running {
            if let Some(failed) = state["environments"].as_array().and_then(|items| {
                items
                    .iter()
                    .find(|e| e["id"] == id && e["status"] == "error")
            }) {
                return Err(failed["lastError"]
                    .as_str()
                    .unwrap_or("Workload exited with an error")
                    .into());
            }
            return Ok(());
        }
        tokio::select! {_=tokio::signal::ctrl_c()=>{eprintln!("Detached. Workload remains running; use yougori stop {id}.");return Ok(())},_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
}
async fn terminal(id: &str) -> Result<(), String> {
    crate::terminal::attach(id, None).await
}
pub fn validate_model_resources(resources: &serde_json::Map<String, Value>) -> Result<(), String> {
    for (key, minimum) in [("cpu", 2.0), ("memoryGb", 4.0)] {
        if let Some(value) = resources.get(key) {
            if value.as_f64().is_none_or(|value| !value.is_finite() || value < minimum) {
                return Err("Models require at least 2 CPU cores and 4 GB RAM".into());
            }
        }
    }
    Ok(())
}
pub async fn model_support(args: &[String]) -> Result<Value,String> {
    let target=args.get(2).ok_or("Usage: yougori model support MODEL --agent claude|codex|kilo|opencode|gemini [--quant Q] [--launch]")?;
    let mut agent=None;let mut quant=None;let mut launch=false;let mut i=3;
    while i<args.len(){match args[i].as_str(){
        "--agent" if agent.is_none()=>agent=Some(value(args,&mut i,"--agent")?),
        "--quant" if quant.is_none()=>quant=Some(value(args,&mut i,"--quant")?),
        "--launch" if !launch=>launch=true,
        _=>return Err("Use --agent AGENT, optional --quant Q and --launch".into()),
    }i+=1;}
    let agent=agent.ok_or("Choose --agent claude, codex, kilo, opencode or gemini")?;
    if !crate::architecture_support::AGENTS.iter().any(|(id,_)|*id==agent){return Err("Unknown coding agent".into());}
    if launch&&(!std::io::stdin().is_terminal()||!std::io::stdout().is_terminal()){return Err("--launch requires an interactive terminal; omit it to prepare the task only".into());}
    client::start(None).await?;
    let mut task=call("model_support_task",json!({"model":target,"agent":agent,"quant":quant})).await?;
    if launch {let code=crate::architecture_support::launch(&task)?;task["exitCode"]=json!(code);task["agentStarted"]=json!(code!=127);}
    Ok(task)
}

async fn model(args: &[String]) -> Result<Value, String> {
    if let Some(result)=crate::model_registry::handle(args).await? { return Ok(result); }
    let action = args.get(1).map(String::as_str).unwrap_or("");
    if action == "optimize" {
        let target=args.get(2).ok_or("Usage: yougori model optimize ENV [--on|--off] [--pin|--unpin] [--idle SECONDS]")?;
        let mut params=json!({"environmentId": resolve(target).await?});
        let mut i=3;
        while i<args.len() {
            match args[i].as_str() {
                "--on"=>params["enabled"]=json!(true), "--off"=>params["enabled"]=json!(false),
                "--pin"=>params["pinned"]=json!(true), "--unpin"=>params["pinned"]=json!(false),
                "--idle"=>{params["idleTimeoutSeconds"]=json!(value(args,&mut i,"--idle")?.parse::<u64>().map_err(|_|"Idle seconds must be an integer")?);},
                _=>return Err("Use --on, --off, --pin, --unpin or --idle SECONDS".into()),
            }
            i+=1;
        }
        return call("model_optimizer",params).await;
    }
    if action=="support" {return model_support(args).await;}
    if action == "auth" { return crate::model_auth::run(&args[2..]).await; }
    if action == "decide" {
        let (target,path)=match &args[2..] {
            [target,flag,path] if flag=="--file"=>(target,path),
            _=>return Err("Usage: yougori model decide ENV --file REQUEST.json|- (JSON containing state and questions)".into()),
        };
        let reader:Box<dyn Read>=if path=="-"{Box::new(std::io::stdin())}else{Box::new(std::fs::File::open(path).map_err(|_|"Cannot open the decision request file")?)};
        let mut bytes=Vec::new();reader.take(65537).read_to_end(&mut bytes).map_err(|_|"Cannot read the decision request")?;
        if bytes.len()>65536{return Err("Decision requests must be at most 64 KiB".into())}
        let body:Value=serde_json::from_slice(bytes.strip_prefix(&[0xef,0xbb,0xbf]).unwrap_or(&bytes)).map_err(|_|"Decision request must be JSON containing state and questions")?;
        if !body.is_object()||body.get("state").is_none()||!body["questions"].is_object(){return Err("Decision request must contain state and a questions object".into())}
        client::start(None).await?;
        let id=resolve(target).await?;
        let response=call("model_chat",json!({"environmentId":id,"messages":[{"role":"user","content":body.to_string()}],"maxTokens":1,"temperature":0.0})).await?;
        return serde_json::from_str(response["choices"][0]["message"]["content"].as_str().ok_or("Invalid decision model response")?).map_err(|_|"Invalid decision model JSON response".into());
    }
    if action == "preflight" {
        let target = args.get(2).ok_or("Supply a model")?;
        let quant = match &args[3..] {
            [] => None,
            [flag, value] if flag == "--quant" && !value.starts_with('-') => Some(value),
            _ => return Err("Usage: yougori model preflight hf.co/OWNER/MODEL [--quant Q4_K_M]".into()),
        };
        client::start(None).await?;
        return call("model_preflight", json!({"model":target,"quant":quant})).await;
    }
    if !["run", "chat", "stop", "unshare", "status", "api", "usage", "access", "history"].contains(&action) {
        return Err("Usage: yougori model run hf.co/OWNER/MODEL [--now | --nowfree] [--quant Q4_K_M] [--change] [--api] [--port PORT] | chat ENV [--new] | unshare ENV | history ENV | status ENV | api ENV [--port PORT] | access ENV | usage ENV [--days N] [--reset]".into());
    }
    let target = args.get(2).ok_or("Supply a model or environment")?;
    let mut api = false;
    let mut port = 8000u16;
    let mut i = 3;
    let mut dry = false;
    let mut reset = false;
    let mut confirmed = false;
    let mut fresh = false;
    let mut days = 7u32;
    let mut resources = serde_json::Map::new();
    let mut neocloud = false;
    let mut environment = None;
    let mut share_mode = None;
    let mut listen = false;
    let mut publish = false;
    let mut quant = None;
    let mut storage_drive = None;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--now" | "--nowfree") if action == "run" => {
                if share_mode.is_some() { return Err("Use only one of --now or --nowfree".into()); }
                share_mode = crate::network::mode(flag);
            }
            "--listen" if action == "run" && !listen => listen = true,
            "--publish" if action == "run" && !publish => publish = true,
            "--folder" if action == "run" && !resources.contains_key("modelFolder") => {resources.insert("modelFolder".into(),json!(value(args,&mut i,"--folder")?));}
            "--quant" if action == "run" => quant = Some(value(args, &mut i, "--quant")?),
            "--storage-drive" if action == "run" => storage_drive = Some(value(args, &mut i, "--storage-drive")?),
            "--neocloud" if action == "run" => neocloud = true,
            "--environment" if action == "run" => environment = Some(value(args, &mut i, "--environment")?),
            "--cpu" | "--memory" | "--storage" if action == "run" => {
                let flag = args[i].clone();
                let raw = value(args, &mut i, &flag)?;
                let number = raw.trim_end_matches("GB").parse::<f64>().ok().filter(|n|n.is_finite() && *n > 0.0).ok_or("Model resources must be positive numbers (memory/storage in GB)")?;
                resources.insert(match flag.as_str() {"--cpu"=>"cpu", "--memory"=>"memoryGb", _=>"storageGb"}.into(), json!(number));
            }
            "--new" if action == "chat" => fresh = true,
            "--reset" if action == "usage" => reset = true,
            "--yes" if action == "usage" => confirmed = true,
            "--days" if action == "usage" => {
                days = value(args, &mut i, "--days")?
                    .parse()
                    .ok()
                    .filter(|d| (1..=90).contains(d))
                    .ok_or("--days must be 1–90")?
            }
            "--api" => api = true,
            "--dry-run" => dry = true,
            "--port" => {
                api = true;
                port = value(args, &mut i, "--port")?
                    .parse()
                    .map_err(|_| "Invalid model API port")?
            }
            _ => return Err("Unknown model option".into()),
        }
        i += 1;
    }
    crate::network::validate_listen(share_mode, listen)?;
    if publish && share_mode.is_none() {return Err("--publish requires --now or --nowfree".into())}
    if neocloud && resources.contains_key("modelFolder") {return Err("--folder needs a local GPU".into())}
    if port == 0 {
        return Err("Model API port must be between 1 and 65535".into());
    }
    validate_model_resources(&resources)?;
    validate_model_neocloud(neocloud, environment.as_deref(), !resources.is_empty())?;
    if neocloud && storage_drive.is_some() { return Err("--storage-drive selects local storage; it cannot be used with --neocloud".into()); }
    if storage_drive.as_deref().is_some_and(|path| path.trim().is_empty()) { return Err("--storage-drive requires a drive path".into()); }
    if neocloud && quant.is_some() { return Err("GGUF quantization is not supported on Neocloud pods".into()); }
    if reset && !confirmed {
        return Err("Resetting model usage permanently clears its history. Repeat with --yes.".into());
    }
    if dry {
        return Ok(json!({"dryRun":true,"model":target,"gpu":"nvidia","api":api,"port":port,"resources":resources,"neocloud":neocloud,"environment":environment,"shareMode":share_mode,"listen":listen,"closedWeights":publish,"quant":quant,"storageDrive":storage_drive}));
    }
    if neocloud && environment.is_none() { return Err("Choosing a Neocloud pod needs an interactive terminal. For scripts add --environment POD_NAME --api.".into()); }
    let chat_mode = model_chat_mode(action, api, std::io::stdin().is_terminal(), std::io::stdout().is_terminal());
    // Validate scripted input before starting or changing a model. Automatic
    // chat after `model run` belongs only to an interactive terminal.
    let prompts = if chat_mode == ModelChatMode::Scripted {
        Some(scripted_prompts(&mut std::io::stdin().lock())?)
    } else { None };
    client::start(None).await?;
    if share_mode.is_some() && !crate::network::signed_in().await? { return Err(crate::network::SIGN_IN_FIRST.into()); }
    let mut result = if action == "run" && neocloud {
        let state = call("get_platform_state", json!({})).await?;
        let candidates = neocloud_model_targets(&state);
        let mut env = choose_neocloud_target(&candidates, environment.as_deref().unwrap())?.clone();
        name_neocloud_model(&mut env, &state, target).await?;
        call("run_neocloud_model", json!({"model":target,"environmentId":env["id"],"port":api.then_some(port)})).await?
    } else if action == "run" {
        match find_model(target).await?.filter(|_| quant.is_none() && !resources.contains_key("modelFolder")) {
            Some(env) => {
                if storage_drive.is_some() {
                    let state=call("get_platform_state",json!({})).await?;
                    crate::storage::validate_reuse(&env,&state["host"],storage_drive.as_deref())?;
                }
                reuse_model(&env, &resources, api.then_some(port)).await?
            },
            None => {
                if let Some(drive)=storage_drive {
                    let preflight=call("model_preflight",json!({"model":target,"quant":quant,"folder":resources.get("modelFolder")})).await?;
                    let supports_selection=preflight["storageDriveSelection"]==true;
                    let host=if supports_selection {Value::Null} else {call("get_platform_state",json!({})).await?["host"].take()};
                    if let Some(drive)=model_storage_drive(supports_selection,&host,Some(&drive))? {
                        resources.insert("storageDrive".into(),json!(drive));
                    } else {
                        eprintln!("Using the running engine's configured model storage drive: {drive}. Quit and reopen the updated Yougori app to enable other drives.");
                    }
                }
                call(
                    "run_model",
                    json!({"model":target,"port":if api{Some(port)}else{None::<u16>},"resources":resources,"quant":quant}),
                )
                .await?
            }
        }
    } else {
        json!({"id":resolve(target).await?})
    };
    let id = result["id"].as_str().ok_or("Model environment missing")?.to_owned();
    let id = id.as_str();
    if let Some(mode) = share_mode { result["network"] = crate::network::share_with_publication(id, mode, listen, publish).await?; }
    if action == "unshare" { return call("market_unshare_model", json!({"environmentId":id})).await; }
    if action == "stop" { return call("stop_model", json!({"environmentId":id})).await; }
    if action == "chat" { call("start_model", json!({"environmentId":id})).await?; }
    if action == "api" {
        return call("model_api", json!({"environmentId":id,"port":port})).await;
    }
    if action == "status" {
        return call("model_status", json!({"environmentId":id})).await;
    }
    if action == "history" {
        let history = call("model_chat_history", json!({"environmentId":id})).await?;
        let conversations = history["conversations"].as_array().into_iter().flatten().map(|c| json!({
            "id": c["id"], "title": c["title"], "messages": c["messages"].as_array().map_or(0, Vec::len), "updatedAt": c["updatedAt"],
            "active": c["id"] == history["activeId"],
        })).collect::<Vec<_>>();
        return Ok(json!({"environmentId":id,"conversations":conversations,"settings":history["settings"]}));
    }
    if action == "access" {
        return call("model_api_status", json!({"environmentId":id})).await;
    }
    if action == "usage" {
        let usage = call(if reset { "reset_model_usage" } else { "model_usage" }, json!({"environmentId":id})).await?;
        return Ok(usage_summary(id, &usage, days, now_hour()));
    }
    if result["sourceOnly"]==true {return Ok(result)}
    match chat_mode {
        ModelChatMode::Interactive => chat_session(id, fresh).await?,
        ModelChatMode::Scripted => return scripted_chat(id, fresh, prompts.unwrap(), |method, params| call(method, params)).await,
        ModelChatMode::None => {},
    }
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
enum ModelChatMode { None, Interactive, Scripted }

fn model_chat_mode(action: &str, api: bool, stdin_terminal: bool, stdout_terminal: bool) -> ModelChatMode {
    if api || !matches!(action, "run" | "chat") { ModelChatMode::None }
    else if stdin_terminal && stdout_terminal { ModelChatMode::Interactive }
    else if action == "chat" { ModelChatMode::Scripted }
    else { ModelChatMode::None }
}

const SCRIPTED_CHAT_INPUT_LIMIT: usize = 64 * 1024;
const SCRIPTED_CHAT_PROMPT_LIMIT: usize = 32;
const SCRIPTED_CHAT_CONTENT_LIMIT: usize = 256 * 1024;
const SCRIPTED_CHAT_REPLY_LIMIT: usize = 64 * 1024;

fn scripted_prompts(input: &mut impl Read) -> Result<Vec<String>, String> {
    let mut bytes = Vec::new();
    input.take(SCRIPTED_CHAT_INPUT_LIMIT as u64 + 1).read_to_end(&mut bytes).map_err(|e| format!("Cannot read model chat input: {e}"))?;
    if bytes.len() > SCRIPTED_CHAT_INPUT_LIMIT { return Err("Model chat input must be at most 64 KiB".into()); }
    let text = String::from_utf8(bytes).map_err(|_| "Model chat input must be UTF-8")?;
    if text.trim_start().starts_with('{') && serde_json::from_str::<Value>(&text).is_ok() { return Ok(vec![text.trim().to_owned()]); }
    let prompts: Vec<_> = text.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect();
    if prompts.len() > SCRIPTED_CHAT_PROMPT_LIMIT { return Err("Model chat input must contain at most 32 nonempty lines".into()); }
    if prompts.iter().any(|prompt| prompt.len() > 16 * 1024) { return Err("Each model chat prompt must be at most 16 KiB".into()); }
    Ok(prompts)
}

fn transcript_message(role: &str, content: &str, limit: usize, remaining: &mut usize) -> Value {
    let mut end = content.len().min(limit).min(*remaining);
    while !content.is_char_boundary(end) { end -= 1; }
    *remaining -= end;
    json!({"role":role,"content":&content[..end],"truncated":end != content.len()})
}

fn truncate_chat_field(value: &mut String, limit: usize) -> bool {
    if value.len() <= limit { return false; }
    let mut end = limit;
    while !value.is_char_boundary(end) { end -= 1; }
    value.truncate(end);
    true
}

fn transcript_error(stage: &str, turn: usize, mut response: crate::wire::Response) -> Value {
    let mut truncated = response.error.as_mut().is_some_and(|error| truncate_chat_field(error, 8192));
    if let Some(details) = response.error_details.as_mut() {
        truncated |= truncate_chat_field(&mut details.code, 1024);
        truncated |= truncate_chat_field(&mut details.outcome, 1024);
        truncated |= details.affected_resource.as_mut().is_some_and(|resource| truncate_chat_field(resource, 1024));
    }
    json!({"stage":stage,"turn":turn,"response":response,"truncated":truncated})
}

/// Scripted chat reads literal newline-separated prompts and emits no text.
/// Capture each turn's machine error so partial success cannot look like a
/// request that never ran, and never retry a failed or unsaved turn here.
async fn scripted_chat<F, Fut>(id: &str, fresh: bool, prompts: Vec<String>, mut invoke: F) -> Result<Value, String>
where F: FnMut(&'static str, Value) -> Fut, Fut: std::future::Future<Output = Result<Value, String>> {
    let mut store = invoke("model_chat_history", json!({"environmentId":id})).await?;
    store = chat_history_or_default(store);
    let status = invoke("model_status", json!({"environmentId":id})).await?;
    let decision = status["task"] == "structured-decision";
    if decision { for prompt in &prompts { crate::decisions::parse(prompt)?; } }
    let (max_tokens, temperature, system) = chat_settings(&store, &status);
    if fresh || !store["conversations"].as_array().unwrap().iter().any(|c| c["id"] == store["activeId"]) {
        start_conversation(&mut store);
    }
    let mut transcript = Vec::new();
    let mut errors = Vec::new();
    let mut remaining = SCRIPTED_CHAT_CONTENT_LIMIT;
    let mut completed = 0;
    let mut attempted = 0;
    let mut saved = true;
    for prompt in &prompts {
        attempted += 1;
        transcript.push(transcript_message("user", prompt, SCRIPTED_CHAT_INPUT_LIMIT, &mut remaining));
        let index = store["conversations"].as_array().unwrap().iter().position(|c| c["id"] == store["activeId"]).ok_or("Saved conversation is invalid")?;
        let conversation = &mut store["conversations"][index];
        if conversation["title"] == "New chat" { conversation["title"] = chat_title(prompt).into(); }
        let messages = conversation["messages"].as_array_mut().ok_or("Saved conversation is invalid")?;
        messages.push(json!({"id":new_id(),"role":"user","content":prompt}));
        let request = if decision { vec![json!({"role":"user","content":prompt})] } else { fit_messages(&system, messages) };
        let response = client::capture_errors(invoke("model_chat", json!({"environmentId":id,"messages":request,"maxTokens":if decision {1} else {max_tokens},"temperature":if decision {0.0} else {temperature}}))).await;
        let answer = match response {
            Ok(answer) => answer,
            Err(error) => { messages.pop(); errors.push(transcript_error("reply", attempted, error)); break; }
        };
        let Some(reply) = answer["choices"][0]["message"]["content"].as_str() else {
            messages.pop(); errors.push(transcript_error("reply", attempted, crate::wire::Response::failure("Invalid model answer"))); break;
        };
        completed += 1;
        transcript.push(transcript_message("assistant", reply, SCRIPTED_CHAT_REPLY_LIMIT, &mut remaining));
        messages.push(json!({"id":new_id(),"role":"assistant","content":reply}));
        conversation["updatedAt"] = now_millis().into();
        if let Err(error) = client::capture_errors(invoke("save_model_chat_history", json!({"environmentId":id,"history":store}))).await {
            saved = false; errors.push(transcript_error("save", attempted, error)); break;
        }
    }
    let truncated = transcript.iter().any(|message| message["truncated"] == true);
    Ok(json!({"environmentId":id,"mode":"scriptedChat","messages":transcript,"truncated":truncated,
        "requested":prompts.len(),"attempted":attempted,"completed":completed,"saved":saved,
        "outcome":if errors.is_empty() {"succeeded"} else if completed == 0 {"failed"} else {"partial"},"errors":errors}))
}
/// `web:/app/data` names a path inside an environment. Windows drive paths (`C:/…`) have a one-letter prefix.
fn environment_path(arg: &str) -> Option<(&str, &str)> {
    let (name, path) = arg.split_once(':')?;
    (name.chars().count() >= 2 && !name.contains(['/', '\\']) && (path.is_empty() || path.starts_with('/'))).then_some((name, path))
}
const COPY_USAGE: &str = "Usage: yougori cp PC_PATH [PC_PATH...] ENV | cp ENV:/path PC_FOLDER | cp ENV:/path OTHER_ENV\n  Into an environment: a new folder (a drive for full VMs). Out of one: DEST/NAME, never overwriting.";
async fn copy(args: &[String]) -> Result<Value, String> {
    let (target, sources) = args.split_last().ok_or(COPY_USAGE)?;
    if sources.is_empty() || args.iter().any(|a| a.starts_with('-')) {
        return Err(COPY_USAGE.into());
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let local = |path: &str| cwd.join(path).to_string_lossy().into_owned();
    // ENV or ENV:/folder (containers and microVMs). A new yougori-import subfolder is always created.
    let into = |target: &str| match environment_path(target) {
        Some((name, path)) if !path.is_empty() && path != "/" => (name.to_owned(), Some(path.trim_end_matches('/').to_owned())),
        Some((name, _)) => (name.to_owned(), None),
        None => (target.to_owned(), None),
    };
    match (sources, environment_path(sources[0].as_str())) {
        ([_], Some((name, path))) => {
            let from = resolve(name).await?;
            let target_is_folder = std::path::Path::new(&local(target)).is_dir();
            if target_is_folder && environment_path(target).is_none() {
                return call("copy_files_from_environment", json!({"environmentId":from,"path":path,"destination":local(target)})).await;
            }
            // Between environments: out to a private temporary folder, then in, then clean up.
            let (to_name, folder) = into(target);
            let to = resolve(&to_name).await.map_err(|e| format!("{e}. To copy to this PC, give an existing folder."))?;
            let staging = tempfile::tempdir().map_err(|e| e.to_string())?;
            let out = call("copy_files_from_environment", json!({"environmentId":from,"path":path,"destination":staging.path()})).await?;
            let staged = out["folder"].as_str().or(out["file"].as_str()).ok_or("Nothing was copied")?.to_owned();
            let copied = call("copy_files_to_environment", json!({"environmentId":to,"paths":[staged],"destination":folder})).await?;
            Ok(json!({"from":from,"to":to,"entries":out["entries"],"bytes":out["bytes"],"result":copied}))
        }
        (_, Some(_)) => Err("Copy one environment path at a time".into()),
        _ if sources.iter().any(|s| environment_path(s).is_some()) => Err(COPY_USAGE.into()),
        _ => {
            let (to_name, folder) = into(target);
            let to = resolve(&to_name).await?;
            call("copy_files_to_environment", json!({"environmentId":to,"paths":sources.iter().map(|s| local(s)).collect::<Vec<_>>(),"destination":folder})).await
        }
    }
}
const VOLUME_USAGE: &str = "Usage: yougori volume ls [--scan] [--size] | inspect NAME | rm NAME... --yes | prune [--yes]\n  yougori volume cp VOLUME[:/path] PC_FOLDER | cp PC_PATH... VOLUME[:/path]\n  Volumes are created when an environment mounts one (yougori run -v NAME:/data IMAGE); copies go through a running environment that mounts it.\n  ls asks running container runtimes; --scan starts stopped ones to find volumes left by deleted environments.";
/// A volume's mount in a running environment, preferring writable ones when `write` is set.
fn volume_mount(volumes: &Value, name: &str, write: bool) -> Result<Value, String> {
    let volume = volumes.as_array().into_iter().flatten().find(|v| v["name"] == name).ok_or_else(|| format!("No volume named {name}. List them with `yougori volume ls`."))?;
    let mounts = volume["mounts"].as_array().cloned().unwrap_or_default();
    mounts.iter().find(|m| m["running"] == true && (!write || m["readOnly"] != true)).cloned().ok_or_else(|| {
        let names = mounts.iter().map(|m| format!("{} ({})", m["environment"].as_str().unwrap_or("?"), m["target"].as_str().unwrap_or("?"))).collect::<Vec<_>>().join(", ");
        format!("Start an environment that mounts {name}{}: {names}", if write { " read/write" } else { "" })
    })
}
fn volume_path(mount: &Value, sub: &str) -> String {
    let target = mount["target"].as_str().unwrap_or("/").trim_end_matches('/');
    let sub = sub.trim_matches('/');
    if sub.is_empty() { target.to_owned() } else { format!("{target}/{sub}") }
}
/// Volumes nothing mounts any more: no environment's settings and no container in any runtime.
fn unused_volumes(listing: &Value) -> Vec<String> {
    listing["volumes"].as_array().into_iter().flatten()
        .filter(|v| v["inUse"] == false && v["stored"].as_array().is_some_and(|s| !s.is_empty()))
        .filter_map(|v| v["name"].as_str().map(str::to_owned)).collect()
}
async fn volume(args: &[String]) -> Result<Value, String> {
    client::start(None).await?;
    let flag = |name: &str| args.iter().any(|a| a == name);
    match args.first().map(String::as_str) {
        Some("ls") if args[1..].iter().all(|a| a == "--scan" || a == "--size") => {
            return call("list_volumes", json!({"scan": flag("--scan"), "size": flag("--size")})).await;
        }
        Some("rm") if args.len() >= 3 && args[1..].iter().filter(|arg| arg.as_str() != "--yes").count() > 0
            && args[1..].iter().filter(|arg| arg.as_str() == "--yes").count() == 1 => {
            let mut removed = Vec::new();
            for name in args[1..].iter().filter(|arg| arg.as_str() != "--yes") {
                removed.push(call("remove_volume", json!({"name": name})).await?);
            }
            return Ok(json!({"removed": removed}));
        }
        Some("prune") if args[1..].iter().all(|a| a == "--yes" || a == "-f") => {
            let listing = call("list_volumes", json!({"scan": true})).await?;
            let unused = unused_volumes(&listing);
            if !(flag("--yes") || flag("-f")) {
                return Ok(json!({"unused": unused, "next": "Run `yougori volume prune --yes` to permanently delete these volumes and their data."}));
            }
            let mut removed = Vec::new();
            let mut failed = Vec::new();
            for name in unused {
                match call("remove_volume", json!({"name": name})).await {
                    Ok(_) => removed.push(name),
                    Err(error) => failed.push(json!({"name": name, "error": error})),
                }
            }
            return Ok(json!({"removed": removed, "failed": failed}));
        }
        _ => {}
    }
    let volumes = call("list_volumes", json!({})).await?["volumes"].clone();
    match args.first().map(String::as_str) {
        Some("inspect") if args.len() == 2 => volumes.as_array().into_iter().flatten().find(|v| v["name"] == args[1].as_str()).cloned()
            .ok_or_else(|| format!("No volume named {}. Try `yougori volume ls --scan`.", args[1])),
        Some("cp") if args.len() >= 3 => {
            let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
            let (target, sources) = args[1..].split_last().ok_or(VOLUME_USAGE)?;
            let split = |arg: &str| arg.split_once(':').filter(|(n, p)| crate::workload::identifier(n) && (p.is_empty() || p.starts_with('/'))).map(|(n, p)| (n.to_owned(), p.to_owned()));
            let local = |path: &str| cwd.join(path).to_string_lossy().into_owned();
            if let ([source], true) = (sources, std::path::Path::new(&local(target)).is_dir()) {
                let (name, sub) = split(source).unwrap_or((source.clone(), String::new()));
                if volumes.as_array().into_iter().flatten().any(|v| v["name"] == name.as_str()) {
                    let mount = volume_mount(&volumes, &name, false)?;
                    return call("copy_files_from_environment", json!({"environmentId":mount["environmentId"],"path":volume_path(&mount, &sub),"destination":local(target)})).await;
                }
            }
            let (name, sub) = split(target).unwrap_or((target.clone(), String::new()));
            let mount = volume_mount(&volumes, &name, true)?;
            call("copy_files_to_environment", json!({"environmentId":mount["environmentId"],"paths":sources.iter().map(|s| local(s)).collect::<Vec<_>>(),"destination":volume_path(&mount, &sub)})).await
        }
        Some("create") => Err("Volumes are created when an environment mounts one: yougori run -v NAME:/data IMAGE".into()),
        _ => Err(VOLUME_USAGE.into()),
    }
}
const PREFS_USAGE: &str = "Usage: yougori prefs path | show | remember KEY VALUE [--project] | forget KEY [--project]";
fn prefs(args: &[String]) -> Result<Value, String> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let (user, project) = crate::project_files::preference_files(&cwd);
    let read = |path: &Option<std::path::PathBuf>| path.as_ref().and_then(|p| std::fs::read_to_string(p).ok());
    let project_flag = args.last().is_some_and(|a| a == "--project");
    let args = if project_flag { &args[..args.len() - 1] } else { args };
    let target = if project_flag { project.clone().ok_or("No project here; run `yougori init` first")? } else { user.clone().ok_or("Cannot find your home folder")? };
    let save = |text: String| -> Result<Value, String> {
        if let Some(parent) = target.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        std::fs::write(&target, &text).map_err(|e| e.to_string())?;
        Ok(json!({"path": target, "text": text}))
    };
    match args {
        [action] if action == "path" => Ok(json!({"user": user, "project": project})),
        [action] if action == "show" => Ok(json!({
            "user": {"path": user, "text": read(&user)}, "project": {"path": project, "text": read(&project)},
            "note": "Suggestions only; project preferences take priority. Existing task authorization determines whether another question is needed; never ask again for already-authorized action and scope.",
            "projectStatus": if project.is_some() { "found" } else { "noProjectPreferences" },
        })),
        [action, key, value] if action == "remember" => {
            let current = match std::fs::read_to_string(&target) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => crate::project_files::PREFERENCES_TEMPLATE.to_owned(),
                Err(error) => return Err(format!("Cannot read preferences {}: {error}. The file was not changed.", target.display())),
            };
            save(crate::project_files::remember(&current, key, value, &civil_date((now_hour() / 24) as i64))?)
        }
        [action, key] if action == "forget" => {
            let current = std::fs::read_to_string(&target).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound { "No preferences file yet".to_owned() }
                else { format!("Cannot read preferences {}: {error}. The file was not changed.", target.display()) }
            })?;
            save(crate::project_files::forget(&current, key).ok_or_else(|| format!("Nothing remembered for {key}"))?)
        }
        _ => Err(PREFS_USAGE.into()),
    }
}
pub fn now_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
pub fn new_id() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("cli-{nanos:x}-{:x}", COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}
pub fn chat_title(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 48 { format!("{}…", line.chars().take(47).collect::<String>()) } else { line }
}
/// The newest turns that fit the model server's request limits, starting on a user turn, with repeated roles merged.
pub fn fit_messages(system: &str, messages: &[Value]) -> Vec<Value> {
    let mut turns: Vec<(String, String)> = Vec::new();
    for m in messages.iter().filter(|m| m["content"].as_str().is_some_and(|c| !c.is_empty())) {
        let (role, content) = (m["role"].as_str().unwrap_or("user").to_owned(), m["content"].as_str().unwrap_or("").to_owned());
        match turns.last_mut() {
            Some(last) if last.0 == role => { last.1.push_str("\n\n"); last.1.push_str(&content) }
            _ => turns.push((role, content)),
        }
    }
    let mut chars = system.chars().count();
    let mut start = turns.len();
    while start > 0 && turns.len() - start < 126 {
        let size = turns[start - 1].1.chars().count();
        if chars + size > 30_000 { break }
        chars += size;
        start -= 1;
    }
    while start < turns.len() && turns[start].0 != "user" { start += 1 }
    let mut fitted = if system.trim().is_empty() { Vec::new() } else { vec![json!({"role":"system","content":system.trim()})] };
    fitted.extend(turns[start..].iter().map(|(role, content)| json!({"role":role,"content":content})));
    fitted
}
/// Start missing histories with the same defaults in scripted and interactive chats.
pub fn chat_history_or_default(history: Value) -> Value {
    if history["conversations"].is_array() { history }
    else { json!({"conversations":[],"activeId":null,"settings":{"system":"","temperature":0.7,"maxTokens":1024}}) }
}

/// Saved settings with the reply length bounded by the server's current context and protocol.
pub fn chat_settings(history: &Value, status: &Value) -> (u64, f64, String) {
    let limit = (if status["stream"] == true { 4096 } else { 2048 })
        .min(status["context"].as_u64().map_or(4096, |c| c / 2));
    let settings = &history["settings"];
    (
        settings["maxTokens"].as_u64().unwrap_or(1024).clamp(1, limit.max(1)),
        settings["temperature"].as_f64().unwrap_or(0.7),
        settings["system"].as_str().unwrap_or("").to_owned(),
    )
}

pub fn start_conversation(store: &mut Value) {
    let conversation = json!({"id":new_id(),"title":"New chat","messages":[],"updatedAt":now_millis()});
    store["activeId"] = conversation["id"].clone();
    if let Some(list) = store["conversations"].as_array_mut() {
        list.insert(0, conversation);
    }
}
/// Interactive chat that continues the conversation shared with the desktop app and saves after each reply.
async fn chat_session(id: &str, fresh: bool) -> Result<(), String> {
    let mut store = call("model_chat_history", json!({"environmentId":id})).await.unwrap_or(Value::Null);
    store = chat_history_or_default(store);
    let status = call("model_status", json!({"environmentId":id})).await.unwrap_or(Value::Null);
    let (max_tokens, temperature, system) = chat_settings(&store, &status);
    let active = store["conversations"].as_array().and_then(|list| list.iter().position(|c| c["id"] == store["activeId"]));
    match active {
        Some(index) if !fresh => {
            let conversation = &store["conversations"][index];
            eprintln!("Continuing \"{}\" ({} messages). Type /new for a new conversation, /exit to leave the model running.", conversation["title"].as_str().unwrap_or("chat"), conversation["messages"].as_array().map_or(0, Vec::len));
            if let Some(last) = conversation["messages"].as_array().and_then(|m| m.iter().rev().find(|m| m["role"] == "assistant")) {
                eprintln!("\nModel > {}\n", last["content"].as_str().unwrap_or(""));
            }
        }
        _ => {
            start_conversation(&mut store);
            eprintln!("Model: {id}. Downloading/loading may take several minutes. Type /new for a new conversation, /exit to leave it running.");
        }
    }
    loop {
        eprint!("You > ");
        std::io::stderr().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())? == 0 || line.trim() == "/exit" {
            break;
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        if text == "/new" {
            start_conversation(&mut store);
            eprintln!("New conversation.");
            continue;
        }
        let index = store["conversations"].as_array().and_then(|list| list.iter().position(|c| c["id"] == store["activeId"])).unwrap_or(0);
        let conversation = &mut store["conversations"][index];
        if conversation["title"] == "New chat" {
            conversation["title"] = chat_title(text).into();
        }
        let Some(messages) = conversation["messages"].as_array_mut() else { return Err("Saved conversation is invalid".into()) };
        messages.push(json!({"id":new_id(),"role":"user","content":text}));
        let request = fit_messages(&system, messages);
        let started = std::time::Instant::now();
        match call("model_chat", json!({"environmentId":id,"messages":request,"maxTokens":max_tokens,"temperature":temperature})).await {
            Ok(answer) => {
                let reply = answer["choices"][0]["message"]["content"].as_str().ok_or("Invalid model answer")?.to_owned();
                println!("\n{reply}\n");
                let finish = if answer["choices"][0]["finish_reason"] == "length" { "length" } else { "stop" };
                messages.push(json!({"id":new_id(),"role":"assistant","content":reply,
                    "stats":{"tokens":answer["usage"]["completion_tokens"],"seconds":started.elapsed().as_secs_f64(),"finish":finish}}));
                conversation["updatedAt"] = now_millis().into();
                if let Err(error) = call("save_model_chat_history", json!({"environmentId":id,"history":store})).await {
                    eprintln!("Reply not saved: {error}");
                }
            }
            Err(e) => {
                messages.pop();
                eprintln!("{e}");
            }
        }
    }
    Ok(())
}
fn now_hour() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() / 3600).unwrap_or(0)
}

#[cfg(test)]
mod scripted_chat_tests {
    use super::*;
    #[test]
    fn pretty_printed_decision_json_is_one_scripted_request() {
        let text = serde_json::to_string_pretty(&crate::decisions::parse(crate::decisions::EXAMPLE).unwrap()).unwrap();
        assert_eq!(scripted_prompts(&mut std::io::Cursor::new(text.as_bytes())).unwrap(), vec![text]);
    }

    #[tokio::test]
    async fn decision_requests_are_independent_and_share_the_saved_history() {
        let first = crate::decisions::EXAMPLE.to_owned();
        let second = first.replace("upload secrets", "delete a file");
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = requests.clone();
        let result = scripted_chat("decision-env", true, vec![first.clone(), second.clone()], move |method, params| {
            let captured = captured.clone();
            async move { Ok(match method {
                "model_chat_history" => Value::Null,
                "model_status" => json!({"status":"ready","task":"structured-decision"}),
                "model_chat" => {
                    captured.lock().unwrap().push(params);
                    json!({"choices":[{"message":{"content":"{\"answers\":{}}"}}]})
                },
                "save_model_chat_history" => { assert_eq!(params["history"]["conversations"][0]["messages"].as_array().unwrap().len(), captured.lock().unwrap().len() * 2); json!({"saved":true}) },
                _ => panic!("Unexpected operation: {method}"),
            }) }
        }).await.unwrap();
        assert_eq!(result["completed"], 2);
        let requests = requests.lock().unwrap();
        for (request, text) in requests.iter().zip([first, second]) {
            assert_eq!(request["messages"], json!([{"role":"user","content":text}]));
            assert_eq!(request["maxTokens"], 1);
            assert_eq!(request["temperature"], 0.0);
        }
    }

    #[test]
    fn automatic_chat_requires_both_terminal_streams() {
        for (input, output) in [(false, false), (true, false), (false, true)] {
            assert_eq!(model_chat_mode("run", false, input, output), ModelChatMode::None);
            assert_eq!(model_chat_mode("chat", false, input, output), ModelChatMode::Scripted);
        }
        assert_eq!(model_chat_mode("run", false, true, true), ModelChatMode::Interactive);
        assert_eq!(model_chat_mode("chat", false, true, true), ModelChatMode::Interactive);
        assert_eq!(model_chat_mode("run", true, true, true), ModelChatMode::None);
        assert_eq!(model_chat_mode("status", false, true, true), ModelChatMode::None);
    }

    #[test]
    fn scripted_input_is_bounded_utf8_and_treats_slash_commands_literally() {
        assert_eq!(scripted_prompts(&mut "hello\n\n/exit\n/new\n日本\r\n".as_bytes()).unwrap(), ["hello", "/exit", "/new", "日本"]);
        assert!(scripted_prompts(&mut vec![b'x'; SCRIPTED_CHAT_INPUT_LIMIT + 1].as_slice()).is_err());
        assert!(scripted_prompts(&mut vec![b'x'; 16 * 1024 + 1].as_slice()).is_err());
        assert!(scripted_prompts(&mut "x\n".repeat(33).as_bytes()).is_err());
        assert!(scripted_prompts(&mut &[0xff][..]).is_err());
    }

    #[tokio::test]
    async fn mocked_scripted_chat_returns_one_transcript_and_saved_conversation() {
        let requests = std::cell::RefCell::new(Vec::new());
        let result = scripted_chat("private-fixture", true, vec!["hello".into(), "/exit".into()], |method, params| {
            requests.borrow_mut().push((method, params.clone()));
            std::future::ready(Ok(match method {
                "model_chat_history" => json!({"conversations":[],"settings":{}}),
                "model_status" => json!({"context":4096}),
                "model_chat" => json!({"choices":[{"message":{"content":"reply"}}]}),
                "save_model_chat_history" => json!({"saved":true}),
                _ => panic!("Unexpected mock request: {method}"),
            }))
        }).await.unwrap();
        assert_eq!(result["outcome"], "succeeded");
        assert_eq!(result["completed"], 2);
        assert_eq!(result["saved"], true);
        assert_eq!(result["messages"].as_array().unwrap().len(), 4);
        assert_eq!(result["messages"][2]["content"], "/exit");
        assert_eq!(result["truncated"], false);
        let requests = requests.borrow();
        assert_eq!(requests.iter().filter(|(method, _)| *method == "model_chat").count(), 2);
        let saved = requests.iter().rev().find(|(method, _)| *method == "save_model_chat_history").unwrap();
        assert_eq!(saved.1["history"]["conversations"][0]["messages"].as_array().unwrap().len(), 4);
        let wire = serde_json::to_value(crate::wire::Response::success(result)).unwrap();
        assert_eq!(wire["version"], crate::wire::VERSION);
    }

    #[tokio::test]
    async fn mocked_scripted_chat_preserves_partial_success_without_retry() {
        let calls = std::cell::Cell::new(0);
        let result = scripted_chat("private-fixture", true, vec!["first".into(), "second".into(), "third".into()], |method, _| {
            std::future::ready(match method {
                "model_chat_history" => Ok(json!({"conversations":[],"settings":{}})),
                "model_status" => Ok(json!({"context":4096})),
                "save_model_chat_history" => Ok(json!({})),
                "model_chat" => {
                    calls.set(calls.get() + 1);
                    if calls.get() == 1 { Ok(json!({"choices":[{"message":{"content":"completed reply"}}]})) }
                    else { Err("Model failed to answer".into()) }
                },
                _ => panic!("Unexpected mock request"),
            })
        }).await.unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(result["requested"], 3);
        assert_eq!(result["attempted"], 2);
        assert_eq!(result["completed"], 1);
        assert_eq!(result["outcome"], "partial");
        assert_eq!(result["errors"][0]["response"]["errorDetails"]["code"], "operation_failed");
        assert_eq!(result["messages"][1]["content"], "completed reply");
    }

    #[tokio::test]
    async fn scripted_save_failure_retains_actual_reply_and_stops_further_turns() {
        let calls = std::cell::Cell::new(0);
        let result = scripted_chat("private-fixture", true, vec!["first".into(), "second".into()], |method, _| {
            std::future::ready(match method {
                "model_chat_history" => Ok(json!({"conversations":[],"settings":{}})),
                "model_status" => Ok(json!({"context":4096})),
                "model_chat" => { calls.set(calls.get() + 1); Ok(json!({"choices":[{"message":{"content":"日本".repeat(100_000)}}]})) },
                "save_model_chat_history" => Err("History save failed".into()),
                _ => panic!("Unexpected mock request"),
            })
        }).await.unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(result["completed"], 1);
        assert_eq!(result["saved"], false);
        assert_eq!(result["outcome"], "partial");
        assert_eq!(result["errors"][0]["stage"], "save");
        assert_eq!(result["truncated"], true);
        let reply = result["messages"][1]["content"].as_str().unwrap();
        assert!(reply.len() <= SCRIPTED_CHAT_REPLY_LIMIT);
        assert!(reply.ends_with('日') || reply.ends_with('本'));
    }

    #[test]
    fn transcript_content_and_errors_are_bounded_at_unicode_boundaries() {
        let mut remaining = 4;
        let message = transcript_message("assistant", "日本語", 64, &mut remaining);
        assert_eq!(message["content"], "日");
        assert_eq!(remaining, 1);
        assert_eq!(message["truncated"], true);
        let error = transcript_error("reply", 1, crate::wire::Response::failure("日本語".repeat(10_000)));
        assert!(error["response"]["error"].as_str().unwrap().len() <= 8192);
        assert_eq!(error["truncated"], true);
    }
}
/// Proleptic Gregorian date for a count of days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
/// Groups the model server's hourly usage into the last `days` UTC days and keeps the 10 newest requests.
fn usage_summary(id: &str, usage: &Value, days: u32, now_hour: u64) -> Value {
    const KEYS: [&str; 7] = ["requests", "prompt_tokens", "completion_tokens", "errors", "rejected", "yougori", "api"];
    let today = (now_hour / 24) as i64;
    let first = today - i64::from(days) + 1;
    let mut buckets = vec![serde_json::Map::new(); days as usize];
    for (i, bucket) in buckets.iter_mut().enumerate() {
        bucket.insert("date".into(), civil_date(first + i as i64).into());
        for key in KEYS {
            bucket.insert(key.into(), 0.into());
        }
    }
    for (hour, counters) in usage["hours"].as_object().into_iter().flatten() {
        let Ok(hour) = hour.parse::<i64>() else { continue };
        let index = hour.div_euclid(24) - first;
        if !(0..i64::from(days)).contains(&index) {
            continue;
        }
        for key in KEYS {
            let bucket = &mut buckets[index as usize];
            let sum = bucket[key].as_u64().unwrap_or(0) + counters[key].as_u64().unwrap_or(0);
            bucket.insert(key.into(), sum.into());
        }
    }
    let recent = usage["recent"].as_array().map(|r| r.iter().rev().take(10).cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"environmentId":id,"since":usage["since"],"totals":usage["totals"],"days":buckets,"recent":recent,"listen":usage["listen"],"note":"UTC days. Usage counters exclude content; optional free-provider recordings are stored separately."})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn neocloud_models_keep_pending_gpu_pods_but_exclude_deleted_and_other_products() {
        let state = json!({"environments":[
            {"id":"local","kind":"container","name":"local"},
            {"id":"pod","kind":"cloud","name":"My GPU","status":"running"},
            {"id":"cpu","kind":"cloud"}, {"id":"endpoint","kind":"cloud"},
            {"id":"other","kind":"cloud"}, {"id":"new","kind":"cloud","status":"provisioning"},
            {"id":"deleted","kind":"cloud","status":"stopped"}
        ],"neocloudDeployments":{
            "pod":{"provider":"runpod","product":"pod","extra":{"compute":"gpu"}},
            "cpu":{"provider":"runpod","product":"pod","extra":{"compute":"cpu"}},
            "endpoint":{"provider":"runpod","product":"serverless"},
            "other":{"provider":"vast","product":"gpu"},
            "new":{"provider":"runpod","product":"pod","state":"Creating"},
            "deleted":{"provider":"runpod","product":"pod","state":"Deleted"}
        }});
        let targets = neocloud_model_targets(&state);
        assert_eq!(targets.len(), 2);
        assert_eq!(choose_neocloud_target(&targets, "new").unwrap()["status"], "provisioning");
        assert_eq!(choose_neocloud_target(&targets, "my gpu").unwrap()["id"], "pod");
        assert_eq!(choose_neocloud_target(&targets, "pod").unwrap()["name"], "My GPU");
        assert!(choose_neocloud_target(&targets, "local").is_err());
        assert!(neocloud_model_targets(&json!({})).is_empty());
        assert!(validate_model_neocloud(true, None, true).is_err());
        assert!(validate_model_neocloud(false, Some("pod"), false).is_err());
    }
    #[test]
    fn scripted_run_finishes_with_one_result_and_rejects_interactive_without_creating() {
        let mut run = Run { request: json!({}), detached: false, interactive: false, dry: false };
        assert_eq!(attach_run_output(&run, false).unwrap(), false);
        assert_eq!(attach_run_output(&run, true).unwrap(), true);
        run.interactive = true;
        assert!(attach_run_output(&run, false).is_err());
        run.detached = true;
        assert_eq!(attach_run_output(&run, false).unwrap(), false);
    }
    #[test]
    fn volume_copies_use_a_running_mount() {
        let volumes = json!([{"name":"data","mounts":[
            {"environmentId":"a","environment":"db","target":"/var/lib/data","readOnly":true,"running":true},
            {"environmentId":"b","environment":"web","target":"/data/","readOnly":false,"running":true},
        ]},{"name":"idle","mounts":[{"environmentId":"c","environment":"x","target":"/x","readOnly":false,"running":false}]}]);
        assert_eq!(volume_mount(&volumes, "data", false).unwrap()["environmentId"], "a");
        assert_eq!(volume_mount(&volumes, "data", true).unwrap()["environmentId"], "b");
        assert!(volume_mount(&volumes, "idle", false).unwrap_err().contains("x (/x)"));
        assert!(volume_mount(&volumes, "missing", false).is_err());
        assert_eq!(volume_path(&volumes[0]["mounts"][1], "/logs/"), "/data/logs");
        assert_eq!(volume_path(&volumes[0]["mounts"][1], ""), "/data");
    }
    #[test]
    fn prune_only_takes_stored_volumes_nothing_uses() {
        let listing = json!({"volumes":[
            {"name":"kept","inUse":true,"stored":[{"usedBy":["web"]}]},
            {"name":"old","inUse":false,"stored":[{"usedBy":[]}]},
            {"name":"declared","inUse":false,"stored":[]},
        ]});
        assert_eq!(unused_volumes(&listing), vec!["old".to_string()]);
    }
    #[test]
    fn environment_paths_are_not_windows_drives() {
        assert_eq!(environment_path("web:/app/data"), Some(("web", "/app/data")));
        assert_eq!(environment_path("my-db:"), Some(("my-db", "")));
        assert_eq!(environment_path("C:/Users/me"), None);
        assert_eq!(environment_path("C:\\Users"), None);
        assert_eq!(environment_path("./a:b"), None);
        assert_eq!(environment_path("web:relative"), None);
    }
    #[test]
    fn model_environments_are_named_after_the_model() {
        let none = std::iter::empty::<&str>();
        assert_eq!(model_environment_name("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0", none.clone()), "TinyLlama-1.1B-Chat-v1.0");
        assert_eq!(model_environment_name("Qwen/Qwen2.5-0.5B", ["qwen2.5-0.5b", "Qwen2.5-0.5B-2"].into_iter()), "Qwen2.5-0.5B-3");
        assert_eq!(model_environment_name("a/b", none.clone()), "model-b");
        assert_eq!(model_environment_name(&format!("a/{}", "x".repeat(96)), none).len(), 76);
        assert!(generated_model_name("model-ad450f21"));
        assert!(!generated_model_name("model-ad450f2"));
        assert!(!generated_model_name("TinyLlama-1.1B-Chat-v1.0"));
    }
    #[test]
    fn a_model_already_running_is_reused_before_a_stopped_or_older_one() {
        let environments = vec![
            json!({"id":"old","kind":"container","status":"stopped","createdAt":"2026-01-01","description":"Hugging Face · TinyLlama/TinyLlama-1.1B-Chat-v1.0"}),
            json!({"id":"new","kind":"container","status":"stopped","createdAt":"2026-02-01","description":"Hugging Face · TinyLlama/TinyLlama-1.1B-Chat-v1.0"}),
            json!({"id":"other","kind":"container","status":"running","description":"Hugging Face · Qwen/Qwen2.5-0.5B"}),
            json!({"id":"gone","kind":"container","status":"deleting","description":"Hugging Face · TinyLlama/TinyLlama-1.1B-Chat-v1.0"}),
        ];
        let pick = |model: &str, all: &[Value]| existing_model(all, model).map(|e| e["id"].as_str().unwrap().to_owned());
        assert_eq!(pick("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0", &environments).as_deref(), Some("new"));
        assert_eq!(pick("https://huggingface.co/tinyllama/tinyllama-1.1b-chat-v1.0/", &environments).as_deref(), Some("new"));
        let mut running = environments.clone();
        running[0]["status"] = json!("running");
        assert_eq!(pick("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0", &running).as_deref(), Some("old"));
        assert_eq!(pick("hf.co/Owner/Missing", &environments), None);
        assert_eq!(model_name(" hf.co/A/B/ "), "A/B");
    }
    #[test]
    fn chat_requests_keep_the_system_prompt_and_newest_turns() {
        let long = "x".repeat(20_000);
        let messages = vec![
            json!({"role":"user","content":long}), json!({"role":"assistant","content":long}),
            json!({"role":"user","content":"a"}), json!({"role":"user","content":"b"}), json!({"role":"assistant","content":""}),
        ];
        assert_eq!(fit_messages("be brief", &messages), vec![json!({"role":"system","content":"be brief"}), json!({"role":"user","content":"a\n\nb"})]);
        assert_eq!(chat_title("  hello   there  "), "hello there");
        assert_eq!(chat_title(&"y".repeat(60)).chars().count(), 48);
    }
    #[test]
    fn usage_is_grouped_into_utc_days_and_recent_is_newest_first() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(20_722), "2026-09-26");
        let now = 20_722 * 24 + 15;
        let usage = json!({"since":1,"totals":{"requests":4},"hours":{
            (20_722 * 24 + 2).to_string(): {"requests":2,"prompt_tokens":10,"api":2},
            (20_721 * 24 + 23).to_string(): {"requests":1,"errors":1,"yougori":1},
            (20_600 * 24).to_string(): {"requests":9}
        },"recent":[{"time":1},{"time":2}]});
        let summary = usage_summary("env-1", &usage, 2, now);
        assert_eq!(summary["days"][0]["date"], "2026-09-25");
        assert_eq!(summary["days"][0]["errors"], 1);
        assert_eq!(summary["days"][1]["requests"], 2);
        assert_eq!(summary["days"][1]["api"], 2);
        assert_eq!(summary["recent"][0]["time"], 2);
    }
    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn run_uses_image_default_and_exact_fixed_resources() {
        let r = parse_run(
            &args(&["-d", "--name", "website", "-p", "8080:80", "nginx:alpine"]),
            false,
        )
        .unwrap();
        assert_eq!(r.request["containerCommand"], "");
        assert!(r.request["workload"]["args"].is_null());
        assert_eq!(
            r.request["resourcePolicy"]["cpu"]["min"],
            r.request["resourcePolicy"]["cpu"]["max"]
        );
        assert_eq!(r.request["runtime"], "nginx:alpine");
        assert!(r.detached)
    }
    #[test]
    fn argv_is_literal_and_gpu_is_explicit() {
        let r = parse_run(
            &args(&[
                "--gpu",
                "nvidia",
                "-e",
                "KEY=with spaces",
                "ubuntu",
                "printf",
                "a; touch /bad",
            ]),
            false,
        )
        .unwrap();
        assert_eq!(r.request["provider"], "yougoriCuda");
        assert_eq!(r.request["workload"]["args"][1], "a; touch /bad");
        assert_eq!(r.request["workload"]["environment"]["KEY"], "with spaces")
    }
    #[test]
    fn storage_selection_does_not_consume_guest_command_options() {
        let run=parse_run(&args(&["--storage-drive","D:/","alpine","echo","--storage-drive","guest-value"]),false).unwrap();
        assert_eq!(run.request["storageDrive"],"D:/");
        assert_eq!(run.request["workload"]["args"],json!(["echo","--storage-drive","guest-value"]));
    }
    #[test]
    fn older_model_engines_only_omit_an_explicit_drive_when_it_matches_their_default() {
        let host=json!({"storageDrive":"D:\\"});
        assert_eq!(model_storage_drive(false,&host,None).unwrap(),None);
        assert_eq!(model_storage_drive(false,&host,Some("d:/")).unwrap(),None);
        assert!(model_storage_drive(false,&host,Some("C:\\")).unwrap_err().contains("No environment was created"));
        assert!(model_storage_drive(false,&json!({}),Some("D:\\")).is_err());
        assert_eq!(model_storage_drive(true,&host,Some("C:\\")).unwrap(),Some("C:\\".into()));
    }
    #[tokio::test]
    async fn model_storage_dry_runs_keep_scripts_noninteractive() {
        let plan=model(&args(&["model","run","hf.co/test/model","--storage-drive","D:/","--nowfree","--dry-run"])).await.unwrap();
        assert_eq!(plan["storageDrive"],"D:/");
        assert_eq!(plan["shareMode"],"free");
        assert!(model(&args(&["model","run","hf.co/test/model","--neocloud","--storage-drive","D:/","--dry-run"])).await.is_err());
    }
    #[test]
    fn validates_before_engine_start() {
        for a in [
            vec!["--wat", "nginx"],
            vec!["-p", "0:80", "nginx"],
            vec!["--cpu", "NaN", "nginx"],
            vec!["--gpu", "amd", "ubuntu"],
        ] {
            assert!(parse_run(&args(&a), false).is_err())
        }
    }
}
