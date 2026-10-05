use crate::{
    catalog,
    wire::{Request, VERSION},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const HELP: &str = r#"Yougori CLI — local runtime control

  app start [--engine]|status|show|quit  Start the background engine (--engine: the one without the
                                   desktop app) / inspect / open the dashboard / stop
  env list|show|create|start|stop|restart|pause|open|delete|reset|recover
  env resources|storage|internet|gpu|exec|console|skills ENV_ID
  connection list|create|folders|exec|enable|disable|delete
  remote create|connect|list|update|revoke|remove|start|stop|files|inspect|download
                                  Tunnel sharing (credentials via --file -)
  share list|add|remove            My PC folders
  ports list|add|remove|publish|unpublish
                                  publish --domain HOST uses a saved domain
  domain list|add|edit|remember|remove  Saved Cloudflare domains (token via --file -)
  drives list|attach|detach ENV    A VM's imported-files drives (--transfer-id ID)
  lan share ENV --address IP --permission view|control | list | revoke ID | import --file invitation.json
  project list | inspect PATH       Find and validate yougori.yaml projects
  agent inventory                  JSON compute targets, capabilities and readiness without secrets
  agent setup                      Install/update the Yougori skill for local agents
  env install-skills ENV           Write the Yougori skill and live access reference inside a guest
  cloud scan HOST [--port 22] | test|add --file request.json | connect|disconnect|show ENV
  cloud configure ENV --file request.json | auth --provider aws|azure|google --account NAME
  cloud options KIND --provider aws|azure|google --account NAME [--region R]   Look up values for deploy:
                                   regions, images, machineTypes, subnets, securityGroups, keyPairs, resourceGroups, sshKeys
  cloud deploy --file request.json --risk-acknowledged true | power ENV --action inspect|start|stop
  cloud delete ENV --confirmation EXACT_NAME
  neocloud providers | list | discover --provider P [--location REGION]
  neocloud catalog --provider P --product cpu|gpu [--location REGION_OR_PROJECT]
  neocloud install --provider P --yes | account --provider P | login --file - --yes
  neocloud forget-account --provider P --yes
  neocloud prices|compare [--product gpu|cpu] [--provider P] [--hours N]
                                   [--max-hourly USD] [--min-vram-gb GB] [--limit N] [--format table|json]
  neocloud quote --provider P --offer ID [--hours N] [--product gpu|cpu]
  neocloud plan --file request.json | create --file request.json --yes | inspect|start|stop ENV
  neocloud delete ENV --confirmation EXACT_NAME --yes | recover ENV --resource-id ID
  storage location [--set PATH] | storage reclaim
  env startup ENV --command "..."  Change a stopped container's startup command
  snapshot list|create|restore|delete
  backup list|destinations|add-destination|delete-destination|run|restore|export|import
  download on ENV [--domain HOST] --yes  Temporary complete-copy link; keep this CLI open
  download list | off ENV_ID        Lifetime download counts / revoke a link
  gpu status|setup|test            NVIDIA CUDA runtime / actual kernel check
  terminal create|read|write|resize|close|install
  microvm apps|open                Built-in guest application sessions
  window list|focus|close|title|capture
  settings get|set|patch --file PATCH_WITH_REVISION.json
  jobs list|get|wait|cancel|result JOB_ID
  skills print [--topic TOPIC|--all]|status|install [--path SKILL_DIRECTORY]
  schema [METHOD|--topic TOPIC] [--all]  Compact index; exact definitions on demand
  call METHOD --file request.json  Any catalog method (use --file - for stdin)

Create an environment:
  env create --kind container --name web --image node:22-bookworm --yes
  env create --kind gpu --name ai --image ubuntu:24.04 --yes
  env create --kind microvm --name small --yes
  env create --kind vm --name ubuntu --source C:\Images\ubuntu.iso --yes

Creation options: --cpu CORES, --memory GB, --storage GB,
  --cpu-min / --cpu-max, --memory-min / --memory-max,
  --priority low|normal|high|critical, --internet true|false (default false).
Containers: --startup image uses the image's entrypoint (e.g. a database);
  --command TEXT overrides it. Otherwise a keep-alive shell is used.
Resource edits: env resources ENV_ID --memory 4 --memory-max 8 --yes
  Only supplied resource fields change. CPU is cores; memory/storage are GB.

Options: --yes (explicit confirmation), --dry-run (syntax only), --no-wait,
         --timeout SECONDS (default 3600), --json OBJECT / --file PATH.
JSON output; coloured in terminals, plain when piped or NO_COLOR is set.
Errors exit nonzero. env skills and skills print output Markdown.
Closing this client does not cancel an accepted job. Inspect jobs before retrying.
Run schema METHOD for exact parameters; skills print includes the full guide.
"#;

#[derive(Debug)]
pub struct Invocation {
    pub request: Request,
    pub no_wait: bool,
    pub timeout: u64,
    pub select: Option<(String, Option<String>)>,
    pub markdown: bool,
}

fn camel(name: &str) -> String {
    let mut result = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '-' {
            upper = true;
        } else if upper {
            result.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            result.push(c);
        }
    }
    result
}
fn take_number(
    flags: &mut BTreeMap<String, String>,
    name: &str,
    fallback: f64,
) -> Result<f64, String> {
    let value = flags
        .remove(name)
        .map(|v| {
            v.parse::<f64>()
                .map_err(|_| format!("--{name} must be a number"))
        })
        .transpose()?
        .unwrap_or(fallback);
    if !value.is_finite() || value <= 0.0 {
        return Err(format!("--{name} must be a positive finite number"));
    }
    Ok(value)
}
fn policy(
    flags: &mut BTreeMap<String, String>,
    floor: f64,
    default_memory: f64,
) -> Result<Value, String> {
    let cpu = take_number(flags, "cpu", 2.0)?;
    let memory = take_number(flags, "memory", default_memory)?;
    let range = |min: f64, preferred: f64, max: f64| -> Result<Value, String> {
        if min > preferred || preferred > max {
            return Err("Resource ranges must satisfy min <= preferred <= max".into());
        }
        Ok(json!({"min":min,"preferred":preferred,"max":max,"current":0}))
    };
    Ok(json!({
        "cpu":range(take_number(flags,"cpu-min",floor.min(cpu))?,cpu,take_number(flags,"cpu-max",cpu)?)?,
        "memoryGb":range(take_number(flags,"memory-min",floor.min(memory))?,memory,take_number(flags,"memory-max",memory)?)?,
        "priority":flags.remove("priority").unwrap_or_else(||"normal".into()),"dynamic":true
    }))
}
fn required(flags: &mut BTreeMap<String, String>, name: &str) -> Result<String, String> {
    flags
        .remove(name)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("--{name} is required"))
}
fn toggle(flags: &mut BTreeMap<String, String>, name: &str) -> Result<bool, String> {
    match flags.remove(name).as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err(format!("--{name} must be true or false")),
    }
}

fn set_explicit(params: &mut serde_json::Map<String, Value>, key: &str, value: Value) -> Result<(), String> {
    if params.get(key).is_some_and(|previous| *previous != value) {
        return Err(format!("Conflicting values for '{key}'; use one explicit target/action"));
    }
    params.insert(key.into(), value);
    Ok(())
}
fn comma(value: String) -> Value {
    Value::Array(
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.into()))
            .collect(),
    )
}

/// Commands that only map a verb and an optional positional target to an engine method.
/// Keep request construction and validation in `parse` for commands that need them.
fn route(group: &str, action: &str) -> Result<(&'static str, Option<&'static str>), String> {
    Ok(match (group, action) {
        ("app", "status") => ("app_status", None),
        ("app", "show") => ("app_show", None),
        ("app", "quit") => ("app_quit", None),
        ("env" | "environment", "open") => ("open_environment_window", Some("environmentId")),
        ("env" | "environment", "restart") => ("restart_environment", Some("environmentId")),
        ("env" | "environment", "delete") => ("delete_environment", Some("environmentId")),
        ("env" | "environment", "reset") => ("factory_reset_environment", Some("environmentId")),
        ("env" | "environment", "internet") => ("update_container_network", Some("environmentId")),
        ("env" | "environment", "gpu") => ("update_environment_gpu", Some("environmentId")),
        ("env" | "environment", "console") => ("read_environment_console", Some("environmentId")),
        ("connection", "delete") => ("delete_connection", Some("connectionId")),
        ("remote", "create") => ("create_remote_share", None),
        ("remote", "connect") => ("connect_remote_share", None),
        ("remote", "list") => ("list_remote_shares", None),
        ("remote", "start") => ("start_remote_tunnel", None),
        ("remote", "stop") => ("stop_remote_tunnel", None),
        ("remote", "remove") => ("remove_remote_share", Some("shareId")),
        ("download", "list") => ("list_environment_downloads", None),
        ("download", "off") => ("stop_environment_download", Some("environmentId")),
        ("share", "remove") => ("detach_host_folder", Some("shareId")),
        ("ports", "list") => ("list_environment_services", Some("environmentId")),
        ("ports", "publish") => ("publish_environment_service", Some("environmentId")),
        ("ports", "unpublish") => ("unpublish_environment_service", Some("publicationId")),
        ("lan", "share") => ("create_environment_share", Some("environmentId")),
        ("lan", "list") => ("list_environment_shares", None),
        ("lan", "revoke") => ("revoke_environment_share", Some("shareId")),
        ("lan", "import") => ("import_environment_share", None),
        ("project", "list") => ("discover_projects", None),
        ("project", "inspect") => ("inspect_project", Some("path")),
        ("agent", "setup") => ("set_up_agent_access", None),
        ("env" | "environment", "install-skills") => ("install_environment_skills", Some("environmentId")),
        ("cloud", "test") => ("test_cloud_connection", None),
        ("cloud", "add") => ("add_cloud_environment", None),
        ("cloud", "configure") => ("configure_cloud_environment", Some("environmentId")),
        ("cloud", "show") => ("get_cloud_connection", Some("environmentId")),
        ("cloud", "auth") => ("cloud_authenticate", None),
        ("cloud", "options") => ("cloud_options", Some("kind")),
        ("cloud", "deploy") => ("deploy_cloud_environment", None),
        ("cloud", "power") => ("cloud_deployment_action", Some("environmentId")),
        ("cloud", "delete") => ("delete_cloud_deployment", Some("environmentId")),
        ("neocloud", "providers") => ("neocloud_providers", None),
        ("neocloud", "discover") => ("neocloud_discover", None),
        ("neocloud", "catalog") => ("neocloud_catalog", None),
        ("neocloud", "install") => ("neocloud_install", None),
        ("neocloud", "account") => ("neocloud_account", None),
        ("neocloud", "login") => ("neocloud_authenticate", None),
        ("neocloud", "forget-account") => ("neocloud_forget_account", None),
        ("neocloud", "prices" | "compare") => ("neocloud_prices", None),
        ("neocloud", "plan") => ("neocloud_plan", None),
        ("neocloud", "create") => ("create_neocloud_environment", None),
        ("neocloud", "recover") => ("neocloud_recover_id", Some("environmentId")),
        ("drives", "list") => ("list_imported_drives", Some("environmentId")),
        ("storage", "reclaim") => ("reclaim_storage", None),
        ("env" | "environment", "startup") => ("update_container_startup_command", Some("environmentId")),
        ("domain", "list") => ("list_saved_domains", None),
        ("domain", "remember") => ("remember_saved_domain", Some("environmentId")),
        ("domain", "remove") => ("remove_saved_domain", Some("domain")),
        ("snapshot", "create") => ("create_snapshot", Some("environmentId")),
        ("snapshot", "restore") => ("restore_snapshot", Some("snapshotId")),
        ("snapshot", "delete") => ("delete_snapshot", Some("snapshotId")),
        ("backup", "add-destination") => ("add_backup_destination", None),
        ("backup", "delete-destination") => ("delete_backup_destination", Some("destinationId")),
        ("backup", "run") => ("run_backup", Some("environmentId")),
        ("backup", "restore") => ("restore_backup", Some("backupId")),
        ("backup", "export") => ("export_local_backup", Some("environmentId")),
        ("backup", "import") => ("import_local_backup", Some("path")),
        ("settings", "set") => ("update_settings", None),
        ("settings", "patch") => ("patch_settings", None),
        ("app", "startup-report") => ("get_startup_report", None),
        ("env" | "environment", "execution-output") => ("guest_execution_output", Some("environmentId")),
        ("env" | "environment", "cancel-execution") => ("cancel_guest_execution", Some("environmentId")),
        ("env" | "environment", "release-execution") => ("release_guest_execution", Some("environmentId")),
        ("ports", "preflight") => ("publication_preflight", Some("environmentId")),
        ("share", "credentials") => ("host_share_credentials", Some("shareId")),
        ("gpu", "status") => ("get_cuda_runtime_status", None),
        ("gpu", "setup") => ("install_cuda_runtime", None),
        ("gpu", "test") => ("verify_environment_cuda", Some("environmentId")),
        ("terminal", "install") => ("install_terminal_tool", Some("environmentId")),
        ("microvm", "apps") => ("micro_vm_apps", Some("environmentId")),
        ("microvm", "open") => ("open_micro_vm_app_window", Some("environmentId")),
        ("window", "list") => ("list_environment_windows", None),
        ("window", "focus") => ("focus_environment_window", Some("label")),
        ("window", "close") => ("close_environment_window", Some("label")),
        ("window", "title") => ("title_environment_window", Some("label")),
        ("window", "capture") => ("set_guest_keyboard_capture", Some("label")),
        ("jobs", "list") => ("jobs_list", None),
        ("jobs", "get" | "wait") => ("jobs_get", Some("jobId")),
        ("jobs", "cancel") => ("jobs_cancel", Some("jobId")),
        ("jobs", "result") => ("jobs_result", Some("jobId")),
        ("env" | "environment", "cancel-transfer") => ("cancel_file_transfer", Some("environmentId")),
        _ => return Err(format!("Unknown command '{group} {action}'. Run yougori help.")),
    })
}

pub fn parse(
    args: &[String],
    read_json: impl Fn(&str) -> Result<Value, String>,
) -> Result<Invocation, String> {
    let mut words = Vec::new();
    let mut flags = BTreeMap::new();
    let mut option_keys = std::collections::HashSet::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(name) = args[i].strip_prefix("--") {
            let (name, value) = if let Some(pair) = name.split_once('=') {
                (pair.0.to_owned(), pair.1.to_owned())
            } else if ["yes", "dry-run", "no-wait"].contains(&name) {
                (name.to_owned(), "true".into())
            } else {
                i += 1;
                (
                    name.to_owned(),
                    args.get(i)
                        .ok_or_else(|| format!("--{name} needs a value"))?
                        .to_owned(),
                )
            };
            if !option_keys.insert(camel(&name)) || flags.insert(name.clone(), value).is_some() {
                return Err(format!("--{name} was specified twice"));
            }
        } else {
            words.push(args[i].as_str());
        }
        i += 1;
    }
    let confirmed = toggle(&mut flags, "yes")?;
    let dry_run = toggle(&mut flags, "dry-run")?;
    let no_wait = toggle(&mut flags, "no-wait")?;
    let timeout = flags
        .remove("timeout")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| "--timeout must be seconds".to_string())
        })
        .transpose()?
        .unwrap_or(3600);
    if !(1..=86400).contains(&timeout) {
        return Err("--timeout must be between 1 and 86400 seconds".into());
    }
    if words.first() == Some(&"call") && words.get(1) == Some(&"set_deployment_secret")
        && (flags.contains_key("json") || flags.contains_key("value")) {
        return Err("Application secrets must be supplied through --file - or a private JSON file, never shell arguments".into());
    }
    let input = match (flags.remove("json"), flags.remove("file")) {
        (Some(_), Some(_)) => return Err("Use either --json or --file, not both".into()),
        (Some(text), None) => {
            serde_json::from_str(&text).map_err(|e| format!("Invalid JSON: {e}"))?
        }
        (None, Some(path)) => read_json(&path)?,
        (None, None) => json!({}),
    };
    let mut params = input
        .as_object()
        .cloned()
        .ok_or("Parameters must be a JSON object")?;
    let group = words.first().copied().unwrap_or("");
    let action = words.get(1).copied().unwrap_or("");
    let mut select = None;
    let mut markdown = false;
    let mut positional = None;
    let method = match (group, action) {
        ("env" | "environment" | "connection" | "neocloud" | "snapshot" | "backup", "list")
        | ("backup", "destinations") => {
            let collection = match (group, action) {
                ("env" | "environment", _) => "environments",
                ("connection", _) => "connections",
                ("neocloud", _) => "neocloudDeployments",
                ("snapshot", _) => "snapshots",
                ("backup", "destinations") => "destinations",
                _ => "backupRuns",
            };
            select = Some((collection.into(), None));
            "get_platform_state"
        }
        ("call", name) if !name.is_empty() => name,
        ("env" | "environment", "show") => {
            select = Some((
                "environments".into(),
                Some(
                    words
                        .get(2)
                        .ok_or("An environment ID is required")?
                        .to_string(),
                ),
            ));
            "get_platform_state"
        }
        ("env" | "environment", "create") => {
            if params.is_empty() {
                let kind = flags.remove("kind").unwrap_or_else(|| "container".into());
                let (backend_kind, provider, floor, memory) = match kind.as_str() {
                    "container" => ("container", "yougoriOci", 0.5, 2.0),
                    "gpu" => ("container", "yougoriCuda", 0.5, 4.0),
                    "vm" | "fullVm" => ("fullVm", "qemu", 1.0, 4.0),
                    "microvm" | "microVm" => ("microVm", "qemu", 1.0, 2.0),
                    _ => return Err("--kind must be container, gpu, vm, or microvm".into()),
                };
                let source = flags.remove("source");
                let image = flags.remove("image");
                if source.is_some() && image.is_some() {
                    return Err("Use --source or --image, not both".into());
                }
                let runtime = source
                    .or(image)
                    .or_else(|| match kind.as_str() {
                        "gpu" => Some("docker.io/library/ubuntu:24.04".into()),
                        "container" => Some("docker.io/library/alpine:3.24".into()),
                        "microvm" | "microVm" => Some("builtin:alpine".into()),
                        _ => None,
                    })
                    .ok_or("VM creation requires --source PATH_TO_ISO_OR_DISK")?;
                let mut request = json!({"name":required(&mut flags,"name")?,"kind":backend_kind,"provider":provider,"runtime":runtime,"description":flags.remove("description").unwrap_or_default(),"networkAccess":false,"gpuAccess":kind=="gpu","resourcePolicy":policy(&mut flags,floor,memory)?});
                if let Some(internet) = flags.remove("internet") {
                    request["networkAccess"] = match internet.as_str() {
                        "true" => true.into(),
                        "false" => false.into(),
                        _ => return Err("--internet must be true or false".into()),
                    };
                }
                if flags.contains_key("storage") {
                    request["storageGb"] = take_number(&mut flags, "storage", 64.0)?.into();
                }
                let startup = flags.remove("startup");
                let command = flags.remove("command");
                if backend_kind != "container" && (startup.is_some() || command.is_some()) {
                    return Err(
                        "--startup and --command configure containers; VMs boot their source media"
                            .into(),
                    );
                }
                match startup.as_deref() {
                    Some("image") if command.is_none()=>request["containerCommand"]="".into(),
                    None|Some("keep-alive")=>{if let Some(command)=command {request["containerCommand"]=command.into();}},
                    _=>return Err("Use --startup image to run the image's default service, or --command for a custom startup command".into()),
                }
                params.insert("request".into(), request);
            }
            "create_environment"
        }
        ("env" | "environment", "start" | "stop" | "pause") => {
            positional = Some("environmentId");
            set_explicit(
                &mut params, "status",
                json!(match action {
                    "start" => "running",
                    "stop" => "stopped",
                    _ => "paused",
                }),
            )?;
            "set_environment_status"
        }
        ("env" | "environment", "recover") => {
            positional = Some("environmentId");
            params.insert("confirmed".into(), json!(confirmed));
            "recover_environment_runtime"
        }
        ("env" | "environment", "resources") => {
            positional = Some("environmentId");
            if params.contains_key("resourcePolicy") {
                "update_resource_policy"
            } else {
                for (flag, key) in [("cpu", "cpu"), ("memory", "memoryGb")] {
                    let mut range = serde_json::Map::new();
                    for (suffix, field) in [("-min", "min"), ("", "preferred"), ("-max", "max")] {
                        let name = format!("{flag}{suffix}");
                        if flags.contains_key(&name) {
                            range.insert(field.into(), take_number(&mut flags, &name, 1.0)?.into());
                        }
                    }
                    if !range.is_empty() {
                        params.insert(key.into(), Value::Object(range));
                    }
                }
                "configure_resource_limits"
            }
        }
        ("env" | "environment", "storage") => {
            positional = Some("environmentId");
            if let Some(v) = flags.remove("capacity") {
                flags.insert("capacity-gb".into(), v);
                "expand_environment_storage"
            } else {
                "get_storage_allocation"
            }
        }
        ("env" | "environment", "exec") => {
            if params.is_empty() {
                params.insert("request".into(),json!({"environmentId":words.get(2).ok_or("An environment ID is required")?,"command":required(&mut flags,"command")?}));
            }
            if let Some(id) = words.get(2) {
                let request = params.get_mut("request").and_then(Value::as_object_mut)
                    .ok_or("Command request must be an object")?;
                set_explicit(request, "environmentId", json!(id))?;
            }
            "execute_environment_command"
        }
        ("env" | "environment", "skills") => {
            positional = Some("environmentId");
            markdown = true;
            "get_connection_skills"
        }
        ("connection", "create") => {
            if params.is_empty() {
                params.insert("request".into(),json!({"sourceId":required(&mut flags,"source")?,"targetId":required(&mut flags,"target")?,"direction":flags.remove("direction").unwrap_or_else(||"bidirectional".into()),"permissions":comma(flags.remove("permissions").unwrap_or_else(||"data".into())),"ports":comma(flags.remove("ports").unwrap_or_default()),"commands":toggle(&mut flags,"commands")?,"volume":flags.remove("volume")}));
            }
            if let Some(port) = flags.remove("ssh-port") {
                let port = port.parse::<u16>().ok().filter(|p| *p > 0).ok_or("--ssh-port must be between 1 and 65535")?;
                set_explicit(params.get_mut("request").and_then(Value::as_object_mut).ok_or("Missing connection request")?, "sshPort", json!(port))?;
            }
            "create_connection"
        }
        ("connection", "exec") => {
            if params.is_empty() {
                params.insert("request".into(), json!({
                    "connectionId": words.get(2).ok_or("A connection ID is required")?,
                    "sourceId": required(&mut flags, "source")?,
                    "command": required(&mut flags, "command")?,
                }));
            }
            if let Some(id) = words.get(2) {
                let request = params.get_mut("request").and_then(Value::as_object_mut)
                    .ok_or("Command request must be an object")?;
                set_explicit(request, "connectionId", json!(id))?;
            }
            "execute_connected_command"
        }
        ("connection", "folders") => {
            set_explicit(&mut params, "environmentId", json!(words.get(2).ok_or("An environment ID is required")?))?;
            params.entry("path").or_insert(json!(""));
            "list_environment_folders"
        }
        ("connection", "enable" | "disable") => {
            positional = Some("connectionId");
            set_explicit(&mut params, "active", json!(action == "enable"))?;
            "set_connection_active"
        }
        ("remote", "update" | "revoke" | "disconnect") => {
            positional = Some("shareId");
            set_explicit(&mut params,"revoke",json!(action=="revoke"))?;
            "update_remote_share"
        }
        ("remote", "download") => { positional=Some("environmentId");params.entry("path").or_insert(json!(""));"download_remote_folder" }
        ("remote", "files" | "inspect") => {
            positional = Some("environmentId");
            set_explicit(&mut params,"method",json!(action))?;
            params.entry("params").or_insert(json!({}));
            "remote_share_request"
        }
        ("share", "list") => {
            positional = Some("environmentId");
            select = Some(("shares".into(), None));
            "list_environment_services"
        }
        ("share", "add") => {
            positional = Some("environmentId");
            params.entry("readOnly").or_insert(json!(true));
            "attach_host_folder"
        }
        ("ports", "add" | "remove") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "present", json!(action == "add"))?;
            "set_manual_service_port"
        }
        // Pinned-TLS sharing of one environment on the local network or VPN.
        // Existing SSH servers and provider VMs. Requests with credentials come from --file.
        ("cloud", "scan") => {
            positional = Some("host");
            params.entry("port").or_insert(json!(22));
            "scan_cloud_host"
        }
        ("cloud", "connect" | "disconnect") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "status", json!(if action == "connect" { "running" } else { "stopped" }))?;
            "set_environment_status"
        }
        ("neocloud", "quote") => {
            if !flags.get("provider").is_some_and(|value| !value.trim().is_empty())
                || !flags.get("offer").is_some_and(|value| !value.trim().is_empty()) {
                return Err("neocloud quote requires --provider and --offer".into());
            }
            "neocloud_prices"
        }
        ("neocloud", "inspect" | "start" | "stop" | "delete") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "action", json!(action))?;
            "neocloud_action"
        }
        ("drives", "attach" | "detach") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "attached", json!(action == "attach"))?;
            "set_imported_drive_attached"
        }
        ("storage", "location") => {
            if let Some(path) = flags.remove("set") {
                flags.insert("path".into(), path);
                "set_storage_location"
            } else {
                "get_storage_location"
            }
        }
        ("domain", "add" | "edit") => {
            positional = Some(if action == "add" { "hostname" } else { "domain" });
            for (alias, key) in [("tunnel-port", "host-port"), ("app-port", "port")] {
                if let Some(value) = flags.remove(alias) {
                    if flags.insert(key.into(), value).is_some() {
                        return Err(format!("Use --{alias} or --{key}, not both"));
                    }
                }
            }
            if action == "add" { "add_saved_domain" } else { "update_saved_domain" }
        }

        ("settings", "get") => {
            "get_settings_snapshot"
        }
        ("env" | "environment", "recover-report") => { positional = Some("environmentId"); set_explicit(&mut params,"confirmed",json!(confirmed))?; "recover_environment_runtime_report" },
        ("terminal", "create" | "read" | "write" | "resize" | "close") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "action", json!(action))?;
            "terminal_action"
        }
        _ => {
            let (method, target) = route(group, action)?;
            positional = target;
            method
        }
    };
    if let Some(key) = positional {
        if let Some(word) = words.get(2) {
            set_explicit(&mut params, key, json!(word))?;
        }
    }
    let consumes_third =
        positional.is_some() || matches!((group, action), ("env" | "environment", "show" | "exec") | ("connection", "exec"));
    if words.len() > if consumes_third { 3 } else { 2 } {
        return Err("Unexpected positional arguments; quote values containing spaces".into());
    }
    let meta = catalog::find(method)?;
    for (key, value) in flags {
        let key = camel(&key);
        let kind = meta
            .parameters
            .split_whitespace()
            .find_map(|spec| {
                let (name, kind) = spec.split_once(':')?;
                (name.trim_end_matches('?') == key).then_some(kind)
            })
            .ok_or_else(|| format!("Unknown option for {method}: {key}"))?;
        let value = if kind == "string" || kind.contains('|') {
            Value::String(value)
        } else {
            serde_json::from_str(&value).map_err(|_| format!("{key} must be {kind}"))?
        };
        // An explicit verb/positional target cannot be redirected by a flag.
        // `call METHOD` remains available for raw backend parameters.
        let protected = positional == Some(key.as_str()) && words.get(2).is_some()
            || matches!((group, action, key.as_str()),
                ("env" | "environment", "start" | "stop" | "pause", "status")
                | ("connection", "enable" | "disable", "active")
                | ("ports", "add" | "remove", "present")
                | ("cloud", "connect" | "disconnect", "status")
                | ("terminal", "create" | "read" | "write" | "resize" | "close", "action"));
        if protected {
            set_explicit(&mut params, &key, value)?;
        } else {
            params.insert(key, value);
        }
    }
    let mut params = Value::Object(params);
    // Local paths are relative to the CLI caller, never to the desktop engine's
    // working directory. Raw JSON can use absolute paths for reproducible plans.
    let absolute = |value: &str| -> Result<String, String> {
        let path = std::path::Path::new(value);
        Ok(if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(path)
        }
        .to_string_lossy()
        .into_owned())
    };
    let path_key = match method {
        "attach_host_folder" | "import_local_backup" | "inspect_project" => Some("path"),
        "export_local_backup" => Some("folder"),
        _ => None,
    };
    if let Some(key) = path_key {
        if let Some(value) = params[key].as_str() {
            params[key] = absolute(value)?.into();
        }
    }
    if method == "create_environment" && params["request"]["provider"] == "qemu" {
        if let Some(value) = params["request"]["runtime"]
            .as_str()
            .filter(|v| !v.starts_with("builtin:"))
        {
            params["request"]["runtime"] = absolute(value)?.into();
        }
    }
    meta.validate(&params)?;
    if !confirmed && !dry_run {
        if let Some(reason) = meta.confirmation_for(&params) {
            return Err(format!(
                "{reason} Repeat with --yes only if this is intended."
            ));
        }
    }
    Ok(Invocation {
        request: Request {
            version: VERSION,
            method: method.into(),
            params,
            confirmed,
            dry_run,
        },
        no_wait,
        timeout,
        select,
        markdown,
    })
}

pub fn project(value: Value, select: &Option<(String, Option<String>)>) -> Result<Value, String> {
    if let Some((key, id)) = select {
        let values = value
            .get(key)
            .ok_or_else(|| format!("Missing {key} in server response"))?;
        if let Some(id) = id {
            return values
                .as_array()
                .and_then(|items| items.iter().find(|v| v["id"] == *id))
                .cloned()
                .ok_or_else(|| format!("Environment '{id}' not found"));
        }
        return Ok(values.clone());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(args: &[&str]) -> Result<Invocation, String> {
        parse(
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            |_| Err("unexpected file".into()),
        )
    }
    #[test]
    fn cloud_servers_have_friendly_verbs() {
        let scan = run(&["cloud", "scan", "server.example.com"]).unwrap().request;
        assert_eq!((scan.method.as_str(), &scan.params), ("scan_cloud_host", &json!({"host":"server.example.com","port":22})));
        let connect = run(&["cloud", "connect", "env-1", "--yes"]).unwrap().request;
        assert_eq!((connect.method.as_str(), connect.params["status"].clone()), ("set_environment_status", json!("running")));
        assert!(run(&["cloud", "disconnect", "env-1", "--status", "running", "--yes"]).is_err());
        assert_eq!(run(&["cloud", "show", "env-1"]).unwrap().request.method, "get_cloud_connection");
        let power = run(&["cloud", "power", "env-1", "--action", "stop", "--yes"]).unwrap().request;
        assert_eq!(power.params, json!({"environmentId":"env-1","action":"stop"}));
        let options = run(&["cloud", "options", "subnets", "--provider", "aws", "--account", "prod", "--region", "eu-west-1"]).unwrap().request;
        assert_eq!((options.method.as_str(), &options.params), ("cloud_options", &json!({"kind":"subnets","provider":"aws","account":"prod","region":"eu-west-1"})));
    }
    #[test]
    fn neocloud_verbs_keep_provider_actions_explicit() {
        assert_eq!(run(&["neocloud", "providers"]).unwrap().request.method, "neocloud_providers");
        assert!(run(&["neocloud", "install", "--provider", "runpod"]).is_err());
        assert_eq!(run(&["neocloud", "install", "--provider", "runpod", "--yes"]).unwrap().request.method, "neocloud_install");
        assert_eq!(run(&["neocloud", "catalog", "--provider", "prime", "--product", "gpu"]).unwrap().request.method, "neocloud_catalog");
        assert_eq!(run(&["neocloud", "account", "--provider", "nebius", "--location", "project-1"]).unwrap().request.method, "neocloud_account");
        assert!(run(&["neocloud", "forget-account", "--provider", "prime"]).is_err());
        assert_eq!(run(&["neocloud", "list"]).unwrap().request.method, "get_platform_state");
        let prices = run(&["neocloud", "prices", "--product", "gpu", "--hours", "8", "--max-hourly", "2.5", "--min-vram-gb", "24", "--limit", "10"]).unwrap().request;
        assert_eq!(prices.method, "neocloud_prices");
        assert_eq!(prices.params, json!({"product":"gpu","hours":8,"maxHourly":2.5,"minVramGb":24,"limit":10}));
        assert_eq!(run(&["neocloud", "compare", "--provider", "vast"]).unwrap().request.method, "neocloud_prices");
        assert_eq!(run(&["neocloud", "plan", "--json", r#"{"request":{"provider":"vast","product":"gpu","name":"training","image":"ubuntu:24.04","offer":"123","diskGb":20}}"#]).unwrap().request.method, "neocloud_plan");
        assert!(run(&["neocloud", "quote", "--provider", "vast"]).is_err());
        let quote = run(&["neocloud", "quote", "--provider", "vast", "--offer", "123", "--hours", "8"]).unwrap().request;
        assert_eq!(quote.params, json!({"provider":"vast","offer":"123","hours":8}));
        let discover = run(&["neocloud", "discover", "--provider", "runpod", "--location", "US"]).unwrap().request;
        assert_eq!(discover.params, json!({"provider":"runpod","location":"US"}));
        let inspect = run(&["neocloud", "inspect", "env-1"]).unwrap().request;
        assert_eq!(inspect.params, json!({"environmentId":"env-1","action":"inspect"}));
        assert!(run(&["neocloud", "start", "env-1"]).is_err());
        assert!(run(&["neocloud", "delete", "env-1", "--confirmation", "model"]).is_err());
        let delete = run(&["neocloud", "delete", "env-1", "--confirmation", "model", "--yes"]).unwrap().request;
        assert_eq!(delete.params, json!({"environmentId":"env-1","action":"delete","confirmation":"model"}));
        let recover = run(&["neocloud", "recover", "env-1", "--resource-id", "provider-1"]).unwrap().request;
        assert_eq!(recover.params, json!({"environmentId":"env-1","resourceId":"provider-1"}));
    }
    #[test]
    fn drives_storage_and_startup_have_friendly_verbs() {
        let detach = run(&["drives", "detach", "env-1", "--transfer-id", "0123456789abcdef0123456789abcdef", "--yes"]).unwrap().request;
        assert_eq!((detach.method.as_str(), detach.params["attached"].clone()), ("set_imported_drive_attached", json!(false)));
        assert_eq!(run(&["drives", "list", "env-1"]).unwrap().request.method, "list_imported_drives");
        assert_eq!(run(&["storage", "location"]).unwrap().request.method, "get_storage_location");
        let moved = run(&["storage", "location", "--set", "D:/Yougori", "--yes"]).unwrap().request;
        assert_eq!((moved.method.as_str(), moved.params["path"].clone()), ("set_storage_location", json!("D:/Yougori")));
        assert_eq!(run(&["storage", "reclaim", "--yes"]).unwrap().request.method, "reclaim_storage");
        let startup = run(&["env", "startup", "env-1", "--command", "npm start", "--yes"]).unwrap().request;
        assert_eq!(startup.params, json!({"environmentId":"env-1","command":"npm start"}));
    }
    #[test]
    fn saved_domains_are_managed_and_used_by_name() {
        let listed = run(&["domain", "list"]).unwrap().request;
        assert_eq!(listed.method, "list_saved_domains");
        let add = |extra: &[&str]| parse(
            &[&["domain", "add", "app.example.com", "--tunnel-port", "45000"], extra].concat().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            |_| Ok(json!({"token":"secret"})),
        );
        assert!(add(&["--file", "-"]).is_err(), "storing a token needs --yes");
        let added = add(&["--file", "-", "--yes"]).unwrap().request;
        assert_eq!(added.method, "add_saved_domain");
        assert_eq!(added.params, json!({"hostname":"app.example.com","hostPort":45000,"token":"secret"}));
        assert!(add(&["--host-port", "1", "--yes"]).is_err());
        assert!(run(&["domain", "remember", "env-1", "--port", "3000"]).is_err());
        let remembered = run(&["domain", "remember", "env-1", "--port", "3000", "--yes"]).unwrap().request;
        assert_eq!(remembered.method, "remember_saved_domain");
        assert_eq!(remembered.params, json!({"environmentId":"env-1","port":3000}));
        assert!(run(&["domain", "edit", "app.example.com", "--tunnel-port", "45001"]).is_err(), "editing needs --yes");
        let edited = run(&["domain", "edit", "app.example.com", "--tunnel-port", "45001", "--app-port", "3001", "--yes"]).unwrap().request;
        assert_eq!((edited.method.as_str(), &edited.params), ("update_saved_domain", &json!({"domain":"app.example.com","hostPort":45001,"port":3001})));
        let removed = run(&["domain", "remove", "app.example.com", "--yes"]).unwrap().request;
        assert_eq!((removed.method.as_str(), &removed.params), ("remove_saved_domain", &json!({"domain":"app.example.com"})));
        let published = run(&["ports", "publish", "env-1", "--port", "3000", "--domain", "app.example.com", "--yes"]).unwrap().request;
        assert_eq!(published.params, json!({"environmentId":"env-1","port":3000,"domain":"app.example.com"}));
        let shared = run(&["remote", "start", "--domain", "app.example.com", "--yes"]).unwrap().request;
        assert_eq!(shared.params["domain"], "app.example.com");
    }
    #[test]
    fn categories_map_to_existing_providers_without_external_access() {
        for (kind, provider) in [
            ("container", "yougoriOci"),
            ("gpu", "yougoriCuda"),
            ("microvm", "qemu"),
        ] {
            let p = run(&["env", "create", "--name", "test", "--kind", kind])
                .unwrap()
                .request
                .params;
            assert_eq!(p["request"]["provider"], provider);
            assert_eq!(p["request"]["networkAccess"], false);
            assert_eq!(p["request"]["gpuAccess"], kind == "gpu");
        }
        assert!(run(&["env", "create", "--name", "test", "--kind", "vm"]).is_err());
    }
    #[test]
    fn confirmations_and_resource_units_are_unambiguous() {
        assert!(run(&["env", "delete", "env-x"]).is_err());
        assert!(run(&["call", "delete_environment", "--environment-id", "env-x"]).is_err());
        assert!(run(&["env", "delete", "env-x", "--yes"]).is_ok());
        let p = run(&[
            "env",
            "resources",
            "env-x",
            "--memory",
            "8",
            "--memory-max",
            "12",
            "--cpu",
            "4",
        ])
        .unwrap()
        .request
        .params;
        assert_eq!(p["memoryGb"]["preferred"], 8.0);
        assert_eq!(p["cpu"], json!({"preferred":4.0}));
        assert!(p.get("priority").is_none());
        assert!(run(&["env", "start", "env-x", "--typo", "1"]).is_err());
    }
    #[test]
    fn all_catalog_methods_are_callable_without_custom_shortcuts() {
        for method in catalog::methods() {
            let args = vec![
                "call".into(),
                method.name.into(),
                "--file".into(),
                "request.json".into(),
                "--dry-run".into(),
            ];
            assert!(parse(&args, |_| Ok(method.example.clone())).is_ok(), "{}", method.name);
        }
    }
    #[test]
    fn protected_deployment_values_never_accept_shell_argument_input() {
        assert!(run(&["call","set_deployment_secret","--json",r#"{"name":"x","value":"private"}"#,"--yes"]).unwrap_err().contains("never shell arguments"));
        for args in [
            vec!["--no-wait", "call", "set_deployment_secret", "--json", r#"{"name":"x","value":"private"}"#, "--yes"],
            vec!["call", "--dry-run", "set_deployment_secret", "--json", r#"{"name":"x","value":"private"}"#],
            vec!["call", "--yes", "set_deployment_secret", "--name", "x", "--value", "private"],
        ] {
            assert!(run(&args).unwrap_err().contains("never shell arguments"), "{args:?}");
        }
        let request=parse(&["call","set_deployment_secret","--file","-","--yes"].map(str::to_owned),|_|Ok(json!({"name":"x","value":"private"}))).unwrap();
        assert_eq!(request.request.method,"set_deployment_secret");
    }
    #[test]
    fn no_guest_output_is_parsed_as_instructions() {
        let p = run(&[
            "env",
            "exec",
            "env-x",
            "--command",
            "echo --yes; echo hello",
            "--yes",
        ])
        .unwrap();
        assert_eq!(
            p.request.params["request"]["command"],
            "echo --yes; echo hello"
        );
        let peer = run(&["connection", "exec", "conn-a", "--source", "env-a", "--command", "ls -la", "--yes"]).unwrap();
        assert_eq!(peer.request.method, "execute_connected_command");
        assert_eq!(peer.request.params["request"]["sourceId"], "env-a");
        assert_eq!(peer.request.params["request"]["command"], "ls -la");
        assert!(run(&["connection", "exec", "conn-a", "--json", r#"{"request":{"connectionId":"conn-b","sourceId":"env-a","command":"true"}}"#, "--yes"]).unwrap_err().contains("Conflicting"));
        assert!(run(&["env", "start", "env-x", "extra"]).is_err());
    }
    #[test]
    fn service_images_can_run_their_entrypoint_and_host_paths_are_absolute() {
        let p = run(&[
            "env",
            "create",
            "--name",
            "database",
            "--image",
            "mongo:8",
            "--startup",
            "image",
        ])
        .unwrap()
        .request
        .params;
        assert_eq!(p["request"]["containerCommand"], "");
        let p = run(&["share", "add", "env-x", "--path", ".", "--yes"])
            .unwrap()
            .request
            .params;
        assert!(std::path::Path::new(p["path"].as_str().unwrap()).is_absolute());
        assert!(run(&[
            "env",
            "create",
            "--name",
            "test",
            "--kind",
            "vm",
            "--source",
            "windows.iso",
            "--command",
            "sh"
        ])
        .is_err());
    }

    #[test]
    fn remote_commands_keep_credentials_in_structured_input_and_targets_explicit() {
        assert_eq!(run(&["remote","list"]).unwrap().request.method,"list_remote_shares");
        assert_eq!(run(&["remote","revoke","share-one"]).unwrap().request.params,json!({"shareId":"share-one","revoke":true}));
        assert_eq!(run(&["remote","disconnect","share-one"]).unwrap().request.params,json!({"shareId":"share-one","revoke":false}));
        assert_eq!(run(&["remote","inspect","env-one"]).unwrap().request.params,json!({"environmentId":"env-one","method":"inspect","params":{}}));
        assert_eq!(run(&["remote","download","env-one","--destination","C:/Downloads"]).unwrap().request.method,"download_remote_folder");
        let parsed=parse(&["remote".into(),"connect".into(),"--file".into(),"-".into()], |_|Ok(json!({"link":"https://example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","username":"alice","password":"a long password"}))).unwrap();
        assert_eq!(parsed.request.method,"connect_remote_share");
        assert_eq!(parsed.request.params["password"],"a long password");
    }

    #[test]
    fn creation_internet_is_explicit_and_strictly_boolean() {
        let p = run(&["env", "create", "--name", "web", "--internet", "true"])
            .unwrap()
            .request
            .params;
        assert_eq!(p["request"]["networkAccess"], true);
        assert!(run(&["env", "create", "--name", "web", "--internet", "yes"]).is_err());
        assert!(run(&["env", "create", "--name", "web", "--internet"]).is_err());
    }

    #[test]
    fn safety_toggles_reject_typos_instead_of_disabling_dry_run() {
        for flag in ["--dry-run=treu", "--yes=1", "--no-wait=yes"] {
            let error = run(&["env", "list", flag]).unwrap_err();
            assert!(error.contains("true or false"), "{error}");
        }
        assert!(run(&["env", "delete", "env-x", "--yes", "--dry-run=treu"]).unwrap_err().contains("true or false"));
        assert!(run(&["env", "delete", "env-x", "--dry-run=true"]).unwrap().request.dry_run);
        assert!(!run(&["env", "list", "--dry-run=false"]).unwrap().request.dry_run);
        assert!(run(&["env", "delete", "env-x", "--yes=false"]).is_err());
    }

    #[test]
    fn action_and_target_cannot_be_silently_overridden() {
        for args in [
            vec!["env", "stop", "env-A", "--status", "running"],
            vec!["env", "delete", "env-A", "--environment-id", "env-B", "--yes"],
            vec!["connection", "disable", "conn-A", "--active", "true"],
            vec!["ports", "remove", "env-A", "--port", "3000", "--present", "true"],
            vec!["terminal", "read", "env-A", "--action", "write", "--session-id", "term-A", "--yes"],
            vec!["env", "stop", "env-A", "--json", r#"{"environmentId":"env-B"}"#],
            vec!["env", "stop", "env-A", "--json", r#"{"status":"running"}"#],
            vec!["env", "exec", "env-A", "--json", r#"{"request":{"environmentId":"env-B","command":"true"}}"#, "--yes"],
        ] {
            assert!(run(&args).unwrap_err().contains("Conflicting"), "{args:?}");
        }
        assert!(run(&["call", "set_environment_status", "--environment-id", "env-A", "--status", "running"]).is_ok());
        assert!(run(&["env", "stop", "env-A", "--status", "stopped"]).is_ok());
        assert!(run(&["call", "delete_environment", "--environment-id", "env-A", "--environmentId", "env-B", "--yes"]).unwrap_err().contains("twice"));
        // The read-only share default remains deliberately configurable.
        assert_eq!(run(&["share", "add", "env-A", "--path", ".", "--read-only", "false", "--yes"]).unwrap().request.params["readOnly"], false);
    }
}
