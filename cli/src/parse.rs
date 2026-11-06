use crate::{
    catalog,
    wire::{Request, VERSION},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const HELP: &str = r#"Yougori CLI — local runtime control

  app start [--engine]|status|show|quit  Start the background engine (--engine: the one without the
                                   desktop app) / inspect / open the dashboard / stop
  app start --app ABSOLUTE_EXECUTABLE_PATH  Start this desktop app executable
  app startup-report | autostart on [--dashboard]|off|status  Sign-in startup health / start at sign-in
  env list|show|create|start|stop|restart|pause|open|delete|reset|recover|recover-report
  env resources|storage|internet|gpu|exec|console|skills ENV_ID
  env execution-output|cancel-execution|release-execution ENV_ID --execution-id ID
                                   Read, cancel (--yes) or free an exec --no-wait guest job
  env cancel-transfer ENV_ID [--transfer-id ID] --yes  Cancel file copies
  connection list|create|folders|exec|enable|disable|delete
  remote create|connect|list|update|revoke|disconnect|remove|start|stop|files|inspect|download
                                  Tunnel sharing (credentials via --file -)
  share list|add|remove|credentials  My PC folders (credentials --yes reveals a bearer URL)
  ports list|add|remove|preflight|publish|unpublish
                                  publish --domain HOST uses a saved domain
  domain list|add|edit|remember|remove  Saved Cloudflare domains (token via --file -)
  drives list|attach|detach ENV    A VM's imported-files drives (--transfer-id ID)
  lan share ENV --address IP --permission view|control --yes | list | revoke ID | import --file invitation.json --yes
  grid status | leave --yes | remove MEMBER_ID --yes
  grid delete [--when later|now|forget] --yes | restore  Admin: pause for three days then delete (restore undoes it), or delete now
                                   Closed Neo Grid membership; admin: remove a computer or the grid
  grid exclude MEMBER_ID --yes | include MEMBER_ID  Admin: leave a computer out of the grid's work, or bring it back
  grid add-plan --model hf.co/OWNER/MODEL --percent 50 [--schedule TEXT] [--idle-after MINUTES] [--quant Q]
                                   Admin: run a model on a share of the company's computers
  grid change-plan PLAN_ID [--percent P] [--schedule TEXT] [--idle-after MINUTES] [--model M] [--quant Q] | remove-plan PLAN_ID --yes
  grid add-swarm --name NAME --lead MODEL --workers '["MODEL"]' --computers 5 [--strategy plan|mixture] [--tasks N] [--rounds N]
                                   Admin: apps call swarm/NAME; one call runs a team on several computers
  grid run-swarm NAME --prompt TEXT | remove-swarm NAME --yes
  grid add-key --name APP | revoke-key KEY_ID --yes  Admin: API keys for company apps
  grid ... --grid GRID_ID          With several Neo Grids on this computer, which one (yougori grid status lists them)
  desks create COMPANY --ip THIS_PC_IP [--tunnel quick|DOMAIN] [--password -] --yes  Admin: host a Sandbox Grid; company computers host desks within the share you set
  desks join --invite INVITE [--password -] [--name NAME]  Join this computer to a company's Sandbox Grid
  desks status | leave --yes | remove MEMBER_ID --yes
  desks delete [--when later|now|forget] --yes | restore  Admin: pause for three days then delete (restore undoes it), or delete now
  desks adopt --file - --yes       A computer the hub created takes up its ready-made membership (JSON with the token on stdin)
  desks share MEMBER_ID [--cpu 2] [--memory-gb 4] [--disk-gb 50] [--gpu true] [--idle-only true] | share MEMBER_ID --suggested true
                                   Admin: what the grid may take from a computer, in use or not; or back to the automatic share
  desks add-person --username USER [--name NAME] [--password -] [--cpu 2] [--memory-gb 4] [--disk-gb 20] [--gpu true] [--kind container|microvm|vm]
                                   Admin: a person who signs in to open their desk; sized, their desk is ordered with them
  desks person-password USER [--password -] --yes | remove-person USER --yes
  desks add-desk --name NAME --person USER [--kind container|microvm|vm] [--cpu 2] [--memory-gb 4] [--disk-gb 20] [--gpu true] [--image IMG]
                                   Admin: a desk (sandbox) for a person, built on a company computer with room in its share
  desks assign-desk DESK_ID [--person USER] | retry-desk DESK_ID | remove-desk DESK_ID --yes
  desks manage --file request.json --yes  Named administrators, workspace roles, images, computers and enterprise connections
  desk refresh                     Refresh desk assignments and enterprise launch connections
  desk login --invite INVITE --username USER [--password -] [--code 123456] | desk | desk logout --yes
                                   Person: open your desks on this computer, see them, or forget the sign-in
                                   With several Sandbox Grids on this computer, add --grid ID to any desks or desk
                                   command (desks status lists each grid's ID); with one, it is chosen for you
  bounty host COMPANY --title TITLE --ip THIS_PC_IP [--source DIR] [--url URL [--health PATH]] [--instructions TEXT] [--authorization TEXT] [--password -] --yes
                                   Publish a Closed Bounty (--source, --url or both): computers join with the password and choose a model
  call bounty_dispatch --file request.json  Project import, private hosting, connect and managed workers (secrets via --file -)
  bounty hosted | remove-hunter MEMBER_ID --yes | unhost --yes  The hosted bounty and its findings; admin manages it
  grids list|status|address|new|join|password|leave|delete|restore|backup|restore-backup|settings|manage  One way of asking all four grids the same questions
  grids people|computers|share|models|desks|credentials|requests|research|connectors|work|log VERB [TARGET] [--grid NAME]
                                   Twelve nouns over the four grids; yougori grids NOUN --help lists a noun's verbs
  project list | inspect PATH       Find and validate yougori.yaml projects
  agent inventory                  JSON compute targets, capabilities and readiness without secrets
  agent setup --yes                Install/update the Yougori skill for local agents
  env install-skills ENV           Write the Yougori skill and live access reference inside a guest
  sandbox remote launch|status|start|outcome|cancel|stop|reconcile|trust|archive [RUN]
                                  Existing SSH host; start --script PATH or --file -
  cloud scan HOST [--port 22] | test --file request.json | connect|disconnect|show ENV
  cloud add --file request.json --yes | configure ENV --file request.json --yes
  cloud auth --provider aws|azure|google --account NAME
  cloud options KIND --provider aws|azure|google --account NAME [--region R]   Look up values for deploy:
                                   regions, images, machineTypes, subnets, securityGroups, keyPairs, resourceGroups, sshKeys
  cloud deploy --file request.json --risk-acknowledged true --yes | power ENV --action inspect|start|stop
  cloud delete ENV --confirmation EXACT_NAME --yes
  neocloud providers | list | discover --provider P [--location REGION]
  neocloud catalog --provider P --product cpu|gpu [--location REGION_OR_PROJECT]
  neocloud install --provider P --yes | account --provider P | login --file - --yes
  neocloud forget-account --provider P --yes
  neocloud prices|compare [--product gpu|cpu] [--provider P] [--hours N]
                                   [--max-hourly USD] [--min-vram-gb GB] [--limit N] [--format json|table|text]
  neocloud quote --provider P --offer ID [--hours N] [--product gpu|cpu] [--format json|table|text]
  neocloud plan --file request.json | create --file request.json --yes | inspect|start|stop ENV
  neocloud delete ENV --confirmation EXACT_NAME --yes | recover ENV --resource-id ID
  storage location [--set PATH --yes] | storage reclaim --yes
  env startup ENV --command "..."  Change a stopped container's startup command
  snapshot list|create|restore|delete
  backup list|destinations|add-destination|delete-destination|run|restore|export|import
  download on ENV [--domain HOST] --yes  Temporary complete-copy link; keep this CLI open
  download list | off ENV_ID        Lifetime download counts / revoke a link
  gpu status|setup|test            NVIDIA CUDA runtime / actual kernel check
  model compute                   Probe native Mac Metal/CPU and CUDA model capabilities
  terminal create|read|write|resize|close|install
  microvm apps|open                Built-in guest application sessions
  window list|focus|close|title|capture
  settings get|set|patch --file PATCH_WITH_REVISION.json
  jobs list|get|wait|cancel|result JOB_ID
  skills print [--topic TOPIC|--all]|status|install [--path SKILL_DIRECTORY]
  schema [METHOD|--topic TOPIC] [--all]  Compact index; exact definitions on demand
  call METHOD --file request.json  Any catalog method (use --file - for stdin)
  sandbox status|plan|cleanup      Restricted VM sandboxes (Windows, Linux): list, read-only preflight, remove leftovers
  sandbox capabilities             What Sandbox VMs support on this computer, such as direct GPU acceleration (Windows)
  sandbox image list | import (--layout FOLDER | --reference REGISTRY/REPO@sha256:DIGEST) --owner-selected true [--root-gb GB] --yes  Import an OCI image through a disposable VM
  sandbox launch [--image sha256:DIGEST] [--cpu N] [--memory GB] [--gpu true|false] [--internet true|false] [--routes FILE] [--workspace FOLDER] [--publish NAME=PORT,...] [--connect NAME=PORT,...] [--idle-seconds N] [--lifetime-seconds N] --yes  Boot a restricted VM (memory is host RAM including hypervisor), optionally with internet access, an imported OCI image and a staged workspace
  sandbox host-access SANDBOX_ID [--operation status|policy|approve|deny|revoke|dismiss] [--file -] --yes  Manage computer-tree visibility and explicit host-file permissions
  sandbox workspace [SANDBOX_ID]   The staged workspaces, or one with what changed in it
  sandbox review SANDBOX_ID        Compare the workspace with its folder: each changed file, its diff and flags
  sandbox promote SANDBOX_ID --review DIGEST --files '["PATH"]' --yes  Write only the approved files into the folder, as reviewed
  sandbox discard-workspace SANDBOX_ID --yes  Delete the staged workspace and every change not promoted
  sandbox normalize SANDBOX_ID --path NAME --format html|archive|plain_text [--to plain_text|markdown] [--keep-raw false] [--max-output BYTES] --yes
                                   Parse a file of the sandbox's workspace in a throwaway sandbox and keep its text
  sandbox publish SANDBOX_ID --service NAME [--audience owner|public] [--minutes N] [--budget BYTES] --yes
                                   Serve a declared guest service on this computer's loopback, to its owner (a token address) or, chosen, anyone
  sandbox withdraw SANDBOX_ID --publication N --yes  Stop serving a publication; its connections close
  sandbox connect SANDBOX_ID --endpoint NAME --to SANDBOX_ID --service NAME [--minutes N] [--budget BYTES] --yes
                                   Let a sandbox's declared endpoint reach a service another sandbox declared, through the connection gate
  sandbox disconnect SANDBOX_ID --endpoint NAME --yes  Withdraw what the endpoint was granted; its connections close
  sandbox drill vm-cp-29 --yes     The doctor's connection drill: three throwaway VM sandboxes, connections under each grant state, all stopped after
  sandbox combine SANDBOX_ID --with OTHER_ID [--operation preview|start|status|finish] [--preview DIGEST] [--request-key KEY] [--id OP] [--originals keep|remove] [--file -] --yes  One VM holding both running sandboxes: preview first, then start
  sandbox credential enroll|remove|holds --name NAME [--form bearer|raw] [--file -] --yes
                                   A provider credential in the sandbox vault; the secret comes from stdin as {"secret":"..."}
  sandbox exec SANDBOX_ID --input TEXT [--max-output BYTES] [--timeout-seconds SECONDS] --yes
                                   Run text on the guest's shell; the output and exit code are the guest's word
  sandbox cancel SANDBOX_ID --command N | stop SANDBOX_ID --yes | revoke SANDBOX_ID [--reason R] --yes
  sandbox confinement SANDBOX_ID   Probe the guest's confinement and evaluate it against the strict tool profile

Create an environment:
  env create --kind container --name web --image node:22-bookworm --yes
  env create --kind gpu --name ai --image ubuntu:24.04 --yes
  env create --kind microvm --name small --yes
  env create --kind vm --name ubuntu --source C:\Images\ubuntu.iso --yes

Creation options: --cpu CORES, --memory GB, --storage GB, --storage-drive PATH,
  --cpu-min / --cpu-max, --memory-min / --memory-max,
  --priority low|normal|high|critical, --internet true|false (default true).
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

/// Parameters that carry credentials. They are read only from --file (a private
/// JSON file, or `-` for stdin), never from the command line, where process
/// listings and shell history keep them. `a.b` names a field inside `a`.
fn credential_parameters(method: &str) -> &'static [&'static str] {
    match method {
        "set_deployment_secret" => &["value"],
        // Provider credentials, ephemeral control keys and remote workload input
        // share stdin-only protection; no secret payload belongs in process argv.
        "sandbox_vm" => &["secret", "input_hex"],
        "model_registry_connect"
        | "confidential_network_chat"
        | "runpod_connect"
        | "neocloud_authenticate" => &["apiKey"],
        "update_remote_share" | "connect_remote_share" | "runpod_registry" => &["password"],
        "add_saved_domain" => &["token"],
        "publish_environment_service" | "start_remote_tunnel" | "publication_preflight" => {
            &["cloudflare.token"]
        }
        "create_remote_share" | "add_backup_destination" => &["request"],
        "import_environment_share" => &["invitation"],
        "grid_create"
        | "grid_join"
        | "grid_password"
        | "desks_create"
        | "desks_join"
        | "desks_person_add"
        | "desks_person_password"
        | "desk_login" => &["password"],
        "desks_manage" => &[
            "request.password",
            "request.key",
            "request.accessKey",
            "request.secretKey",
            "request.credential",
        ],
        "desks_adopt_membership" => &["membership.memberToken"],
        "access_create" | "access_signin" => &["password"],
        "access_manage" => &["request.password", "request.value", "request.key"],
        "access_account" => &["request.password", "request.key"],
        "access_backup" | "access_restore_backup" => &["passphrase"],
        // The one namespace carries the verb and its words inside `request`, so a secret in it
        // is refused exactly as it is on every other door.
        "grids_realm" | "grids_people" | "grids_credentials" | "grids_desks"
        | "grids_connectors" => &[
            "request.password",
            "request.value",
            "request.passphrase",
            "request.key",
        ],
        _ => &[],
    }
}

fn credentials_in_arguments(
    method: &str,
    flags: &BTreeMap<String, String>,
    argument_json: Option<&serde_json::Map<String, Value>>,
) -> Vec<&'static str> {
    credential_parameters(method)
        .iter()
        .copied()
        .filter(|parameter| {
            let (key, field) = parameter
                .split_once('.')
                .map_or((*parameter, None), |(key, field)| (key, Some(field)));
            let present = |value: &Value| field.is_none_or(|field| value.get(field).is_some());
            flags.iter().any(|(flag, value)| {
                camel(flag) == key
                    && field.is_none_or(|_| {
                        serde_json::from_str(value).is_ok_and(|value| present(&value))
                    })
            }) || argument_json
                .and_then(|json| json.get(key))
                .is_some_and(present)
        })
        .collect()
}

fn set_explicit(
    params: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Value,
) -> Result<(), String> {
    if params.get(key).is_some_and(|previous| *previous != value) {
        return Err(format!(
            "Conflicting values for '{key}'; use one explicit target/action"
        ));
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
        ("env" | "environment", "install-skills") => {
            ("install_environment_skills", Some("environmentId"))
        }
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
        ("env" | "environment", "startup") => {
            ("update_container_startup_command", Some("environmentId"))
        }
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
        ("env" | "environment", "execution-output") => {
            ("guest_execution_output", Some("environmentId"))
        }
        ("env" | "environment", "cancel-execution") => {
            ("cancel_guest_execution", Some("environmentId"))
        }
        ("env" | "environment", "release-execution") => {
            ("release_guest_execution", Some("environmentId"))
        }
        ("ports", "preflight") => ("publication_preflight", Some("environmentId")),
        ("share", "credentials") => ("host_share_credentials", Some("shareId")),
        ("gpu", "status") => ("get_cuda_runtime_status", None),
        ("model", "compute") => ("model_compute_status", None),
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
        ("env" | "environment", "cancel-transfer") => {
            ("cancel_file_transfer", Some("environmentId"))
        }
        _ => {
            return Err(format!(
                "Unknown command '{}'. Run yougori help.",
                format!("{group} {action}").trim()
            ))
        }
    })
}

/// How a usage line names a required word: `environmentId` is ENV_ID, `snapshotId` SNAPSHOT_ID.
fn placeholder(key: &str) -> String {
    if key == "environmentId" {
        return "ENV_ID".into();
    }
    key.chars().fold(String::new(), |mut out, c| {
        if c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
        out
    })
}
/// What a value of a catalog type looks like, for an error that says how to write it.
fn kind_words(kind: &str) -> String {
    match kind {
        "number" => "a number, for example 2".into(),
        "integer" => "a whole number, for example 2".into(),
        "bool" => "true or false".into(),
        "port" => "a port number from 1 to 65535".into(),
        "object" => "a JSON object, for example {}".into(),
        "array" | "string[]" => "a JSON list, for example []".into(),
        other => other.to_owned(),
    }
}

/// One command, as the engine request it stands for. A refusal here is a request that cannot
/// be sent as typed, so it carries `invalid_request`, or `permission_denied` for an effect that
/// needs --yes, attached here rather than read back from its words.
pub fn parse(
    args: &[String],
    read_json: impl Fn(&str) -> Result<Value, String>,
) -> Result<Invocation, String> {
    parse_words(args, read_json).map_err(|refused| {
        if crate::client::remembered(&refused) {
            refused
        } else {
            crate::client::remember_error(
                refused,
                crate::wire::ErrorDetails::of(crate::wire::Code::InvalidRequest),
            )
        }
    })
}

fn parse_words(
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
    let argument_json = flags.contains_key("json");
    let input = match (flags.remove("json"), flags.remove("file")) {
        (Some(_), Some(_)) => return Err("Use either --json or --file, not both".into()),
        (Some(text), None) => {
            serde_json::from_str(&text).map_err(|e| format!("--json is not valid JSON ({e}). Quote it for your shell, or pass a file with --file PATH (- reads stdin)."))?
        }
        (None, Some(path)) => read_json(&path)?,
        (None, None) => json!({}),
    };
    let mut params = input
        .as_object()
        .cloned()
        .ok_or("Parameters must be a JSON object")?;
    let supplied = argument_json.then(|| params.clone());
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
        ("sandbox", "remote") => {
            let operation = words.get(2).copied().unwrap_or("status");
            if !matches!(
                operation,
                "launch"
                    | "status"
                    | "start"
                    | "outcome"
                    | "cancel"
                    | "stop"
                    | "reconcile"
                    | "trust"
                    | "archive"
            ) {
                return Err("Usage: yougori sandbox remote launch|status|start|outcome|cancel|stop|reconcile|trust [RUN]".into());
            }
            set_explicit(&mut params, "action", json!("remote"))?;
            set_explicit(&mut params, "operation", json!(operation))?;
            if let Some(run) = words.get(3) {
                set_explicit(&mut params, "run", json!(run))?;
            }
            if words.len() > 4 {
                return Err("Unexpected extra remote sandbox arguments.".into());
            }
            for (flag, key) in [
                ("connection", "connection"),
                ("parent", "parent"),
                ("program", "program"),
                ("endpoint", "endpoint"),
                ("engine-sha256", "engine_sha256"),
                ("accept-host-key", "accept_host_key"),
                ("request-key", "request_key"),
                ("after", "after"),
            ] {
                if let Some(value) = flags.remove(flag) {
                    set_explicit(&mut params, key, json!(value))?;
                }
            }
            for (flag, key) in [
                ("memory-mib", "memory_mib"),
                ("lifetime-seconds", "lifetime_seconds"),
                ("timeout-seconds", "timeout_seconds"),
                ("output-bytes", "output_bytes"),
                ("command", "command"),
            ] {
                if let Some(value) = flags.remove(flag) {
                    let value = value
                        .parse::<u64>()
                        .map_err(|_| format!("--{flag} must be a nonnegative integer"))?;
                    set_explicit(&mut params, key, json!(value))?;
                }
            }
            if let Some(path) = flags.remove("script") {
                if operation != "start" {
                    return Err("--script is only used with sandbox remote start.".into());
                }
                use std::io::Read;
                let mut bytes = Vec::new();
                let input: Box<dyn Read> = if path == "-" {
                    Box::new(std::io::stdin())
                } else {
                    Box::new(
                        std::fs::File::open(path)
                            .map_err(|e| format!("Cannot open remote script: {e}"))?,
                    )
                };
                input
                    .take(256 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                if bytes.is_empty() || bytes.len() > 256 * 1024 {
                    return Err("The remote script must contain 1..262144 bytes.".into());
                }
                let encoded = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                bytes.fill(0);
                set_explicit(&mut params, "input_hex", json!(encoded))?;
            }
            let required: &[&str] = match operation {
                "trust" => &["connection", "accept_host_key"],
                "launch" => &[
                    "connection",
                    "parent",
                    "program",
                    "endpoint",
                    "engine_sha256",
                ],
                "start" => &["run", "input_hex"],
                "outcome" | "cancel" => &["run", "command"],
                "stop" | "reconcile" | "archive" => &["run"],
                _ => &[],
            };
            for key in required {
                if !params.contains_key(*key) {
                    return Err(format!("Remote {operation} requires {key}; use --file for workload input or --script PATH for start."));
                }
            }
            "sandbox_vm"
        }
        ("sandbox", "capabilities" | "status" | "plan" | "cleanup") => {
            set_explicit(&mut params, "action", json!(action))?;
            "sandbox_vm"
        }
        ("sandbox", "host-access") => {
            set_explicit(&mut params, "action", json!("host_access"))?;
            positional = Some("sandbox");
            if let Some(operation) = flags.remove("operation") {
                set_explicit(&mut params, "operation", json!(operation))?;
            } else if params.get("operation").is_none() {
                set_explicit(&mut params, "operation", json!("status"))?;
            }
            for key in ["request", "grant", "mode", "duration"] {
                if let Some(value) = flags.remove(key) { set_explicit(&mut params, key, json!(value))?; }
            }
            "sandbox_vm"
        }
        ("sandbox", "launch") => {
            set_explicit(&mut params, "action", json!("launch"))?;
            for name in ["internet", "incoming"] {
                if let Some(value) = flags.remove(name) {
                    let enabled = value.parse::<bool>().map_err(|_| format!("--{name} must be true or false"))?;
                    set_explicit(&mut params, name, json!(enabled))?;
                }
            }
            if let Some(resources) = flags.remove("grid-hosting") {
                let selected: Vec<_> = resources.split(',').map(str::trim).collect();
                if selected.is_empty() || selected.iter().any(|v| !matches!(*v, "gpu" | "sandbox")) || selected.iter().enumerate().any(|(i,v)| selected[..i].contains(v)) {
                    return Err("--grid-hosting accepts gpu and sandbox (CPU and memory together).".into());
                }
                set_explicit(&mut params, "gridHosting", json!(selected))?;
            }
            if let Some(image) = flags.remove("image") {
                set_explicit(&mut params, "image", json!(image))?;
            }
            if flags.contains_key("memory") {
                let memory = take_number(&mut flags, "memory", 1.0)?;
                set_explicit(&mut params, "memoryGb", json!(memory))?;
            }
            if flags.contains_key("cpu") {
                let cpu = take_number(&mut flags, "cpu", 1.0)?;
                if !cpu.is_finite() || cpu.fract() != 0.0 || !(1.0..=255.0).contains(&cpu) {
                    return Err("--cpu must be a whole number between 1 and 255".into());
                }
                set_explicit(&mut params, "cpu", json!(cpu as u64))?;
            }
            // Lease limits lowered below the defaults (12 h idle, 24 h in all).
            for (flag, key) in [
                ("idle-seconds", "idleSeconds"),
                ("lifetime-seconds", "lifetimeSeconds"),
            ] {
                if flags.contains_key(flag) {
                    let seconds = take_number(&mut flags, flag, 0.0)?;
                    if seconds < 0.0 || seconds.fract() != 0.0 {
                        return Err(format!(
                            "--{flag} must be whole seconds; 0 means until stopped"
                        ));
                    }
                    set_explicit(&mut params, key, json!(seconds as u64))?;
                }
            }
            // The folder whose staged copy the guest works on.
            if let Some(folder) = flags.remove("workspace") {
                set_explicit(&mut params, "workspace", json!(folder))?;
            }
            // The guest services it may publish later: NAME=PORT pairs.
            if let Some(publish) = flags.remove("publish") {
                set_explicit(&mut params, "publish", json!(publish))?;
            }
            // The names its programs may reach other sandboxes' services by, once granted:
            // NAME=PORT pairs.
            if let Some(connect) = flags.remove("connect") {
                set_explicit(&mut params, "connect", json!(connect))?;
            }
            // The route declarations the sandbox's relay serves: a JSON array in a file
            // (names, hosts, operations and credential names; never a credential value).
            if let Some(path) = flags.remove("routes") {
                let routes = read_json(&path)?;
                if !routes.is_array() {
                    return Err(
                        "--routes must name a JSON file holding an array of route declarations"
                            .into(),
                    );
                }
                set_explicit(&mut params, "routes", routes)?;
            }
            "sandbox_vm"
        }
        ("sandbox", "image") => {
            let operation = words.get(2).copied().unwrap_or("list");
            if !matches!(operation, "list" | "import") {
                return Err("Usage: yougori sandbox image list | import (--layout FOLDER | --reference REGISTRY/REPO@sha256:DIGEST) --owner-selected true [--root-gb GB] --yes".into());
            }
            set_explicit(&mut params, "action", json!("image"))?;
            positional = Some("operation");
            if words.get(2).is_none() {
                set_explicit(&mut params, "operation", json!(operation))?;
            }
            if operation == "import" {
                let layout = flags.remove("layout");
                let reference = flags.remove("reference");
                match (layout, reference) {
                    (Some(layout), None) => set_explicit(&mut params, "layout", json!(layout))?,
                    (None, Some(reference)) => set_explicit(&mut params, "reference", json!(reference))?,
                    _ => return Err("Choose exactly one of --layout FOLDER or --reference REGISTRY/REPO@sha256:DIGEST".into()),
                }
                if let Some(origin) = flags.remove("auth-origin") {
                    if params.get("reference").is_none() {
                        return Err("--auth-origin requires --reference".into());
                    }
                    set_explicit(&mut params, "authOrigin", json!(origin))?;
                }
                let selected = flags.remove("owner-selected").as_deref() == Some("true");
                if !selected {
                    return Err("Add --owner-selected true to choose this unsigned image for your own scope".into());
                }
                set_explicit(&mut params, "ownerSelected", json!(true))?;
                if flags.contains_key("root-gb") {
                    let root = take_number(&mut flags, "root-gb", 0.5)?;
                    set_explicit(&mut params, "rootGb", json!(root))?;
                }
            }
            "sandbox_vm"
        }
        ("sandbox", "credential") => {
            set_explicit(&mut params, "action", json!("credential"))?;
            if !matches!(words.get(2), Some(&"enroll" | &"remove" | &"holds")) {
                return Err("Usage: yougori sandbox credential enroll|remove|holds --name NAME [--form raw|bearer] [--file -]".into());
            }
            positional = Some("op");
            if let Some(name) = flags.remove("name") {
                set_explicit(&mut params, "name", json!(name))?;
            }
            if let Some(form) = flags.remove("form") {
                set_explicit(&mut params, "form", json!(form))?;
            }
            "sandbox_vm"
        }
        // The staged workspace: listed or shown, reviewed, promoted file by file, discarded.
        ("sandbox", "workspace" | "review" | "promote" | "discard-workspace") => {
            set_explicit(&mut params, "action", json!("workspace"))?;
            let op = match (action, words.get(2)) {
                ("workspace", None) => "list",
                ("workspace", Some(_)) => "show",
                ("review", Some(_)) => "review",
                ("promote", Some(_)) => "promote",
                ("discard-workspace", Some(_)) => "discard",
                _ => return Err(format!("Usage: yougori sandbox {action} SANDBOX_ID")),
            };
            set_explicit(&mut params, "op", json!(op))?;
            positional = Some("sandbox");
            if op == "promote" {
                let review = required(&mut flags, "review")?;
                set_explicit(&mut params, "review", json!(review))?;
                // A JSON array of names, or one name per comma.
                let listed = required(&mut flags, "files")?;
                let files: Vec<String> = if listed.trim_start().starts_with('[') {
                    serde_json::from_str(&listed).map_err(|_| {
                        "--files must be a JSON array of names, or names separated by commas"
                    })?
                } else {
                    listed
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                        .collect()
                };
                if files.is_empty() {
                    return Err("--files must name at least one file from the review".into());
                }
                set_explicit(&mut params, "files", json!(files))?;
            }
            "sandbox_vm"
        }
        // A file of a sandbox's staged workspace, normalized in a throwaway sandbox (VM-W58).
        ("sandbox", "normalize") => {
            set_explicit(&mut params, "action", json!("normalize"))?;
            if words.get(2).is_none() {
                return Err("Usage: yougori sandbox normalize SANDBOX_ID --path NAME --format FORMAT [--to plain_text|markdown] --yes".into());
            }
            positional = Some("sandbox");
            // The file's path in the workspace (--file names a request file everywhere).
            let path = required(&mut flags, "path")?;
            set_explicit(&mut params, "file", json!(path))?;
            let format = required(&mut flags, "format")?;
            set_explicit(&mut params, "format", json!(format))?;
            if let Some(target) = flags.remove("to") {
                set_explicit(&mut params, "target", json!(target))?;
            }
            // The raw bytes are kept beside the text unless asked not to.
            match flags.remove("keep-raw").as_deref() {
                None | Some("true") => {}
                Some("false") => set_explicit(&mut params, "keepRaw", json!(false))?,
                Some(_) => return Err("--keep-raw must be true or false".into()),
            }
            if flags.contains_key("max-output") {
                let bytes = take_number(&mut flags, "max-output", 4_194_304.0)?;
                set_explicit(&mut params, "maxOutputBytes", json!(bytes as u64))?;
            }
            "sandbox_vm"
        }
        // A declared guest service served on this computer (M14), and its withdrawal.
        ("sandbox", "publish") => {
            set_explicit(&mut params, "action", json!("publish"))?;
            if let Some(value) = flags.remove("application") {
                let enabled = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err("--application must be true or false".into()),
                };
                set_explicit(&mut params, "application", json!(enabled))?;
            }
            if words.get(2).is_none() {
                return Err("Usage: yougori sandbox publish SANDBOX_ID --service NAME [--audience owner|public] [--minutes N] [--budget BYTES] --yes".into());
            }
            positional = Some("sandbox");
            let service = required(&mut flags, "service")?;
            set_explicit(&mut params, "service", json!(service))?;
            match flags.remove("audience").as_deref() {
                None | Some("owner") => {}
                Some("public") => set_explicit(&mut params, "audience", json!("public"))?,
                Some(_) => return Err("--audience must be owner or public".into()),
            }
            if flags.contains_key("minutes") {
                let minutes = take_number(&mut flags, "minutes", 60.0)?;
                if minutes < 1.0 || minutes.fract() != 0.0 {
                    return Err("--minutes must be a whole number above zero".into());
                }
                set_explicit(&mut params, "minutes", json!(minutes as u64))?;
            }
            if flags.contains_key("budget") {
                let bytes = take_number(&mut flags, "budget", 8_388_608.0)?;
                if bytes < 1.0 || bytes.fract() != 0.0 {
                    return Err("--budget must be a whole number of bytes above zero".into());
                }
                set_explicit(&mut params, "budgetBytes", json!(bytes as u64))?;
            }
            "sandbox_vm"
        }
        // A sandbox connection (M14): one sandbox's endpoint granted another's service, and
        // the grant's withdrawal.
        ("sandbox", "connect") => {
            set_explicit(&mut params, "action", json!("connect"))?;
            if words.get(2).is_none() {
                return Err("Usage: yougori sandbox connect SANDBOX_ID --endpoint NAME --to SANDBOX_ID --service NAME [--minutes N] [--budget BYTES] --yes".into());
            }
            positional = Some("sandbox");
            for (flag, key) in [
                ("endpoint", "endpoint"),
                ("to", "to"),
                ("service", "service"),
            ] {
                let value = required(&mut flags, flag)?;
                set_explicit(&mut params, key, json!(value))?;
            }
            if flags.contains_key("minutes") {
                let minutes = take_number(&mut flags, "minutes", 60.0)?;
                if minutes < 1.0 || minutes.fract() != 0.0 {
                    return Err("--minutes must be a whole number above zero".into());
                }
                set_explicit(&mut params, "minutes", json!(minutes as u64))?;
            }
            if flags.contains_key("budget") {
                let bytes = take_number(&mut flags, "budget", 8_388_608.0)?;
                if bytes < 1.0 || bytes.fract() != 0.0 {
                    return Err("--budget must be a whole number of bytes above zero".into());
                }
                set_explicit(&mut params, "budgetBytes", json!(bytes as u64))?;
            }
            "sandbox_vm"
        }
        // A boundary check's drill on throwaway VMs of its own (M08).
        ("sandbox", "combine") => {
            set_explicit(&mut params, "action", json!("combine"))?;
            if words.get(2).is_none() {
                return Err("Usage: yougori sandbox combine SANDBOX_ID --with OTHER_ID [--operation preview|start|status|finish] [--preview DIGEST] [--request-key KEY] [--id OPERATION] [--originals keep|remove] [--file -] [--yes]".into());
            }
            positional = Some("sandbox");
            if let Some(operation) = flags.remove("operation") {
                set_explicit(&mut params, "operation", json!(operation))?;
            } else if params.get("operation").is_none() {
                set_explicit(&mut params, "operation", json!("preview"))?;
            }
            for (flag, key) in [("with", "with"), ("preview", "preview"), ("request-key", "requestKey"), ("id", "id"), ("originals", "originals")] {
                if let Some(value) = flags.remove(flag) { set_explicit(&mut params, key, json!(value))?; }
            }
            "sandbox_vm"
        }
        ("sandbox", "drill") => {
            set_explicit(&mut params, "action", json!("drill"))?;
            if words.get(2).is_none() {
                return Err("Usage: yougori sandbox drill vm-cp-29 --yes".into());
            }
            positional = Some("check");
            "sandbox_vm"
        }
        ("sandbox", "disconnect") => {
            set_explicit(&mut params, "action", json!("disconnect"))?;
            if words.get(2).is_none() {
                return Err(
                    "Usage: yougori sandbox disconnect SANDBOX_ID --endpoint NAME --yes".into(),
                );
            }
            positional = Some("sandbox");
            let endpoint = required(&mut flags, "endpoint")?;
            set_explicit(&mut params, "endpoint", json!(endpoint))?;
            "sandbox_vm"
        }
        ("sandbox", "withdraw") => {
            set_explicit(&mut params, "action", json!("withdraw"))?;
            if words.get(2).is_none() {
                return Err(
                    "Usage: yougori sandbox withdraw SANDBOX_ID --publication N --yes".into(),
                );
            }
            positional = Some("sandbox");
            let publication = take_number(&mut flags, "publication", 0.0)?;
            if publication < 1.0 || publication.fract() != 0.0 {
                return Err("--publication must be a publication's number".into());
            }
            set_explicit(&mut params, "publication", json!(publication as u64))?;
            "sandbox_vm"
        }
        ("sandbox", "exec" | "cancel" | "stop" | "revoke" | "confinement") => {
            set_explicit(&mut params, "action", json!(action))?;
            if words.get(2).is_none() {
                return Err(format!("Usage: yougori sandbox {action} SANDBOX_ID ..."));
            }
            positional = Some("sandbox");
            match action {
                "exec" => {
                    if let Some(input) = flags.remove("input") {
                        set_explicit(&mut params, "input", json!(input))?;
                    }
                    if flags.contains_key("max-output") {
                        let bytes = take_number(&mut flags, "max-output", 1_048_576.0)?;
                        set_explicit(&mut params, "maxOutputBytes", json!(bytes as u64))?;
                    }
                    if flags.contains_key("timeout-seconds") {
                        let seconds = take_number(&mut flags, "timeout-seconds", 60.0)?;
                        set_explicit(&mut params, "timeoutSeconds", json!(seconds as u64))?;
                    }
                }
                "cancel" => {
                    let command = take_number(&mut flags, "command", 0.0)?;
                    set_explicit(&mut params, "command", json!(command as u64))?;
                }
                "revoke" => {
                    if let Some(reason) = flags.remove("reason") {
                        set_explicit(&mut params, "reason", json!(reason))?;
                    }
                }
                _ => {}
            }
            "sandbox_vm"
        }
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
                let mut request = json!({"name":required(&mut flags,"name")?,"kind":backend_kind,"provider":provider,"runtime":runtime,"description":flags.remove("description").unwrap_or_default(),"networkAccess":true,"gpuAccess":kind=="gpu","resourcePolicy":policy(&mut flags,floor,memory)?});
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
                if let Some(drive) = flags.remove("storage-drive") {
                    if drive.trim().is_empty() {
                        return Err("--storage-drive requires a drive path".into());
                    }
                    request["storageDrive"] = drive.into();
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
                &mut params,
                "status",
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
                let request = params
                    .get_mut("request")
                    .and_then(Value::as_object_mut)
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
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or("--ssh-port must be between 1 and 65535")?;
                set_explicit(
                    params
                        .get_mut("request")
                        .and_then(Value::as_object_mut)
                        .ok_or("Missing connection request")?,
                    "sshPort",
                    json!(port),
                )?;
            }
            "create_connection"
        }
        ("connection", "exec") => {
            if params.is_empty() {
                params.insert(
                    "request".into(),
                    json!({
                        "connectionId": words.get(2).ok_or("A connection ID is required")?,
                        "sourceId": required(&mut flags, "source")?,
                        "command": required(&mut flags, "command")?,
                    }),
                );
            }
            if let Some(id) = words.get(2) {
                let request = params
                    .get_mut("request")
                    .and_then(Value::as_object_mut)
                    .ok_or("Command request must be an object")?;
                set_explicit(request, "connectionId", json!(id))?;
            }
            "execute_connected_command"
        }
        ("connection", "folders") => {
            words.get(2).ok_or("An environment ID is required")?;
            positional = Some("environmentId");
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
            set_explicit(&mut params, "revoke", json!(action == "revoke"))?;
            "update_remote_share"
        }
        ("remote", "download") => {
            positional = Some("environmentId");
            params.entry("path").or_insert(json!(""));
            "download_remote_folder"
        }
        ("remote", "files" | "inspect") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "method", json!(action))?;
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
            set_explicit(
                &mut params,
                "status",
                json!(if action == "connect" {
                    "running"
                } else {
                    "stopped"
                }),
            )?;
            "set_environment_status"
        }
        ("neocloud", "quote") => {
            if flags
                .get("provider")
                .is_none_or(|value| value.trim().is_empty())
                || flags
                    .get("offer")
                    .is_none_or(|value| value.trim().is_empty())
            {
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
            positional = Some(if action == "add" {
                "hostname"
            } else {
                "domain"
            });
            for (alias, key) in [("tunnel-port", "host-port"), ("app-port", "port")] {
                if let Some(value) = flags.remove(alias) {
                    if flags.insert(key.into(), value).is_some() {
                        return Err(format!("Use --{alias} or --{key}, not both"));
                    }
                }
            }
            if action == "add" {
                "add_saved_domain"
            } else {
                "update_saved_domain"
            }
        }

        ("settings", "get") => "get_settings_snapshot",
        ("env" | "environment", "recover-report") => {
            positional = Some("environmentId");
            set_explicit(&mut params, "confirmed", json!(confirmed))?;
            "recover_environment_runtime_report"
        }
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
    // `--grid ID` says which Sandbox Grid a desks or desk command is about, when this computer
    // has several; the engine reads it as gridId.
    if matches!(group, "desks" | "desk") {
        if let Some(grid) = flags.remove("grid") {
            if flags.insert("grid-id".into(), grid).is_some() {
                return Err("--grid and --grid-id name the same thing; give one of them".into());
            }
        }
    }
    // `--grid ID` says which Closed Neo Grid a grid command is about, when this computer holds
    // several (a grid ID from `yougori grid status`); the engine reads it as gridId.
    if group == "grid" {
        if let Some(grid) = flags.remove("grid") {
            if flags.insert("grid-id".into(), grid).is_some() {
                return Err("--grid and --grid-id name the same thing; give one of them".into());
            }
        }
    }
    let exposed = credentials_in_arguments(method, &flags, supplied.as_ref());
    if !exposed.is_empty() {
        return Err(format!(
            "{} must be supplied through --file - (stdin) or a private JSON file, never shell arguments or --json, which process listings and shell history keep.",
            exposed.join(", ")
        ));
    }
    if let Some(key) = positional {
        if let Some(word) = words.get(2) {
            set_explicit(&mut params, key, json!(word))?;
        }
    }
    let consumes_third = positional.is_some()
        || matches!(
            (group, action),
            ("env" | "environment", "show" | "exec") | ("connection", "exec")
        );
    if words.len()
        > if (group, action) == ("sandbox", "remote") {
            4
        } else if consumes_third {
            3
        } else {
            2
        }
    {
        return Err("Unexpected positional arguments; quote values containing spaces".into());
    }
    let meta = catalog::find(method)?;
    for (key, value) in flags {
        let flag = key.clone();
        let key = camel(&key);
        let kind = meta
            .parameters
            .split_whitespace()
            .find_map(|spec| {
                let (name, kind) = spec.split_once(':')?;
                (name.trim_end_matches('?') == key).then_some(kind)
            })
            .ok_or_else(|| format!("Unknown option --{flag} for yougori {group} {action}. See its options with yougori schema {method}."))?;
        let value = if kind == "string" || kind.contains('|') {
            Value::String(value)
        } else {
            serde_json::from_str(&value)
                .map_err(|_| format!("--{flag} must be {}", kind_words(kind)))?
        };
        // An explicit verb/positional target cannot be redirected by a flag.
        // `call METHOD` remains available for raw backend parameters.
        let protected = positional == Some(key.as_str()) && words.get(2).is_some()
            || matches!(
                (group, action, key.as_str()),
                ("env" | "environment", "start" | "stop" | "pause", "status")
                    | ("connection", "enable" | "disable", "active")
                    | ("ports", "add" | "remove", "present")
                    | ("cloud", "connect" | "disconnect", "status")
                    | (
                        "terminal",
                        "create" | "read" | "write" | "resize" | "close",
                        "action"
                    )
            );
        if protected {
            set_explicit(&mut params, &key, value)?;
        } else {
            params.insert(key, value);
        }
    }
    let mut params = Value::Object(params);
    // A command's own required word, such as the environment for `env start`, comes as usage.
    if let Some(key) = positional {
        let required = meta
            .parameters
            .split_whitespace()
            .any(|spec| spec.split_once(':').is_some_and(|(name, _)| name == key));
        if required && params.get(key).is_none_or(Value::is_null) {
            let hint = if key == "environmentId" {
                ". Find it with yougori ps."
            } else {
                "."
            };
            return Err(format!(
                "Usage: yougori {group} {action} {}{hint}",
                placeholder(key)
            ));
        }
    }
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
    if method == "sandbox_vm" && params["action"] == "launch" {
        if let Some(folder) = params["workspace"].as_str() {
            params["workspace"] = absolute(folder)?.into();
        }
    }
    if method == "sandbox_vm" && params["action"] == "image" {
        if let Some(layout) = params["layout"].as_str() {
            params["layout"] = absolute(layout)?.into();
        }
    }
    if method == "desks_manage" && params["request"]["action"] == "imageImport" {
        if let Some(path) = params["request"]["path"].as_str() {
            params["request"]["path"] = absolute(path)?.into();
        }
    }
    meta.validate(&params)?;
    if !confirmed && !dry_run {
        if let Some(reason) = meta.confirmation_for(&params) {
            return Err(crate::client::remember_error(
                format!("{reason} Repeat with --yes only if this is intended."),
                crate::wire::ErrorDetails::of(crate::wire::Code::PermissionDenied),
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
    fn remote_vm_commands_keep_parent_and_host_identity_explicit() {
        let launch = run(&[
            "sandbox",
            "remote",
            "launch",
            "--connection",
            "env-owned",
            "--parent",
            "exe-parent",
            "--program",
            "/opt/yougori/engine",
            "--endpoint",
            "/run/engine.sock",
            "--engine-sha256",
            &"a".repeat(64),
            "--accept-host-key",
            "SHA256:owner-pin",
            "--memory-mib",
            "512",
            "--lifetime-seconds",
            "120",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(launch.method, "sandbox_vm");
        assert_eq!(launch.params["action"], "remote");
        assert_eq!(launch.params["operation"], "launch");
        assert_eq!(launch.params["parent"], "exe-parent");
        assert_eq!(launch.params["memory_mib"], 512);
        assert_eq!(launch.params["lifetime_seconds"], 120);
        let status = run(&["sandbox", "remote", "status", "run-one"])
            .unwrap()
            .request;
        assert_eq!(
            status.params,
            json!({"action":"remote","operation":"status","run":"run-one"})
        );
        let stop = run(&["sandbox", "remote", "reconcile", "run-one", "--yes"])
            .unwrap()
            .request;
        assert_eq!(stop.params["operation"], "reconcile");
        assert!(run(&[
            "sandbox",
            "remote",
            "start",
            "run-one",
            "--input_hex",
            "secret"
        ])
        .is_err());
        assert!(run(&["sandbox", "remote", "launch", "--connection", "env-owned"]).is_err());
        let trust = run(&[
            "sandbox",
            "remote",
            "trust",
            "--connection",
            "env-owned",
            "--accept-host-key",
            "SHA256:verified",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(
            trust.params,
            json!({"action":"remote","operation":"trust",
            "connection":"env-owned","accept_host_key":"SHA256:verified"})
        );
        assert!(run(&["sandbox", "remote", "trust", "--connection", "env-owned"]).is_err());
        let keyed = run(&["sandbox", "remote", "status", "--request-key", &"a".repeat(64)]).unwrap().request;
        let archived = run(&["sandbox", "remote", "archive", "run-one", "--yes"]).unwrap().request;
        assert_eq!(archived.params["operation"], "archive");
        assert!(run(&["sandbox", "remote", "archive", "--yes"]).is_err());
        let history = run(&["sandbox", "remote", "status", "--archived", "true", "--after", &"b".repeat(64)]).unwrap().request;
        assert_eq!(history.params["archived"], true);
        assert_eq!(history.params["after"], "b".repeat(64));
        assert_eq!(keyed.params["request_key"], "a".repeat(64));
        assert!(run(&["sandbox", "remote", "status", "one", "extra"]).is_err());
        assert!(run(&["sandbox", "remote", "outcome", "one", "--command", "1.5"]).is_err());
    }
    #[test]
    fn cloud_servers_have_friendly_verbs() {
        let scan = run(&["cloud", "scan", "server.example.com"])
            .unwrap()
            .request;
        assert_eq!(
            (scan.method.as_str(), &scan.params),
            (
                "scan_cloud_host",
                &json!({"host":"server.example.com","port":22})
            )
        );
        let connect = run(&["cloud", "connect", "env-1", "--yes"])
            .unwrap()
            .request;
        assert_eq!(
            (connect.method.as_str(), connect.params["status"].clone()),
            ("set_environment_status", json!("running"))
        );
        assert!(run(&[
            "cloud",
            "disconnect",
            "env-1",
            "--status",
            "running",
            "--yes"
        ])
        .is_err());
        assert_eq!(
            run(&["cloud", "show", "env-1"]).unwrap().request.method,
            "get_cloud_connection"
        );
        let power = run(&["cloud", "power", "env-1", "--action", "stop", "--yes"])
            .unwrap()
            .request;
        assert_eq!(
            power.params,
            json!({"environmentId":"env-1","action":"stop"})
        );
        let options = run(&[
            "cloud",
            "options",
            "subnets",
            "--provider",
            "aws",
            "--account",
            "prod",
            "--region",
            "eu-west-1",
        ])
        .unwrap()
        .request;
        assert_eq!(
            (options.method.as_str(), &options.params),
            (
                "cloud_options",
                &json!({"kind":"subnets","provider":"aws","account":"prod","region":"eu-west-1"})
            )
        );
    }
    #[test]
    fn neocloud_verbs_keep_provider_actions_explicit() {
        assert_eq!(
            run(&["neocloud", "providers"]).unwrap().request.method,
            "neocloud_providers"
        );
        assert!(run(&["neocloud", "install", "--provider", "runpod"]).is_err());
        assert_eq!(
            run(&["neocloud", "install", "--provider", "runpod", "--yes"])
                .unwrap()
                .request
                .method,
            "neocloud_install"
        );
        assert_eq!(
            run(&[
                "neocloud",
                "catalog",
                "--provider",
                "prime",
                "--product",
                "gpu"
            ])
            .unwrap()
            .request
            .method,
            "neocloud_catalog"
        );
        assert_eq!(
            run(&[
                "neocloud",
                "account",
                "--provider",
                "nebius",
                "--location",
                "project-1"
            ])
            .unwrap()
            .request
            .method,
            "neocloud_account"
        );
        assert!(run(&["neocloud", "forget-account", "--provider", "prime"]).is_err());
        assert_eq!(
            run(&["neocloud", "list"]).unwrap().request.method,
            "get_platform_state"
        );
        let prices = run(&[
            "neocloud",
            "prices",
            "--product",
            "gpu",
            "--hours",
            "8",
            "--max-hourly",
            "2.5",
            "--min-vram-gb",
            "24",
            "--limit",
            "10",
        ])
        .unwrap()
        .request;
        assert_eq!(prices.method, "neocloud_prices");
        assert_eq!(
            prices.params,
            json!({"product":"gpu","hours":8,"maxHourly":2.5,"minVramGb":24,"limit":10})
        );
        assert_eq!(
            run(&["neocloud", "compare", "--provider", "vast"])
                .unwrap()
                .request
                .method,
            "neocloud_prices"
        );
        assert_eq!(run(&["neocloud", "plan", "--json", r#"{"request":{"provider":"vast","product":"gpu","name":"training","image":"ubuntu:24.04","offer":"123","diskGb":20}}"#]).unwrap().request.method, "neocloud_plan");
        assert!(run(&["neocloud", "quote", "--provider", "vast"]).is_err());
        let quote = run(&[
            "neocloud",
            "quote",
            "--provider",
            "vast",
            "--offer",
            "123",
            "--hours",
            "8",
        ])
        .unwrap()
        .request;
        assert_eq!(
            quote.params,
            json!({"provider":"vast","offer":"123","hours":8})
        );
        let discover = run(&[
            "neocloud",
            "discover",
            "--provider",
            "runpod",
            "--location",
            "US",
        ])
        .unwrap()
        .request;
        assert_eq!(
            discover.params,
            json!({"provider":"runpod","location":"US"})
        );
        let inspect = run(&["neocloud", "inspect", "env-1"]).unwrap().request;
        assert_eq!(
            inspect.params,
            json!({"environmentId":"env-1","action":"inspect"})
        );
        assert!(run(&["neocloud", "start", "env-1"]).is_err());
        assert!(run(&["neocloud", "delete", "env-1", "--confirmation", "model"]).is_err());
        let delete = run(&[
            "neocloud",
            "delete",
            "env-1",
            "--confirmation",
            "model",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(
            delete.params,
            json!({"environmentId":"env-1","action":"delete","confirmation":"model"})
        );
        let recover = run(&[
            "neocloud",
            "recover",
            "env-1",
            "--resource-id",
            "provider-1",
        ])
        .unwrap()
        .request;
        assert_eq!(
            recover.params,
            json!({"environmentId":"env-1","resourceId":"provider-1"})
        );
    }
    #[test]
    fn drives_storage_and_startup_have_friendly_verbs() {
        let detach = run(&[
            "drives",
            "detach",
            "env-1",
            "--transfer-id",
            "0123456789abcdef0123456789abcdef",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(
            (detach.method.as_str(), detach.params["attached"].clone()),
            ("set_imported_drive_attached", json!(false))
        );
        assert_eq!(
            run(&["drives", "list", "env-1"]).unwrap().request.method,
            "list_imported_drives"
        );
        assert_eq!(
            run(&["storage", "location"]).unwrap().request.method,
            "get_storage_location"
        );
        let moved = run(&["storage", "location", "--set", "D:/Yougori", "--yes"])
            .unwrap()
            .request;
        assert_eq!(
            (moved.method.as_str(), moved.params["path"].clone()),
            ("set_storage_location", json!("D:/Yougori"))
        );
        assert_eq!(
            run(&["storage", "reclaim", "--yes"])
                .unwrap()
                .request
                .method,
            "reclaim_storage"
        );
        let startup = run(&["env", "startup", "env-1", "--command", "npm start", "--yes"])
            .unwrap()
            .request;
        assert_eq!(
            startup.params,
            json!({"environmentId":"env-1","command":"npm start"})
        );
    }
    #[test]
    fn saved_domains_are_managed_and_used_by_name() {
        let listed = run(&["domain", "list"]).unwrap().request;
        assert_eq!(listed.method, "list_saved_domains");
        let add = |extra: &[&str]| {
            parse(
                &[
                    &["domain", "add", "app.example.com", "--tunnel-port", "45000"],
                    extra,
                ]
                .concat()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
                |_| Ok(json!({"token":"secret"})),
            )
        };
        assert!(
            add(&["--file", "-"]).is_err(),
            "storing a token needs --yes"
        );
        let added = add(&["--file", "-", "--yes"]).unwrap().request;
        assert_eq!(added.method, "add_saved_domain");
        assert_eq!(
            added.params,
            json!({"hostname":"app.example.com","hostPort":45000,"token":"secret"})
        );
        assert!(add(&["--host-port", "1", "--yes"]).is_err());
        assert!(run(&["domain", "remember", "env-1", "--port", "3000"]).is_err());
        let remembered = run(&["domain", "remember", "env-1", "--port", "3000", "--yes"])
            .unwrap()
            .request;
        assert_eq!(remembered.method, "remember_saved_domain");
        assert_eq!(
            remembered.params,
            json!({"environmentId":"env-1","port":3000})
        );
        assert!(
            run(&[
                "domain",
                "edit",
                "app.example.com",
                "--tunnel-port",
                "45001"
            ])
            .is_err(),
            "editing needs --yes"
        );
        let edited = run(&[
            "domain",
            "edit",
            "app.example.com",
            "--tunnel-port",
            "45001",
            "--app-port",
            "3001",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(
            (edited.method.as_str(), &edited.params),
            (
                "update_saved_domain",
                &json!({"domain":"app.example.com","hostPort":45001,"port":3001})
            )
        );
        let removed = run(&["domain", "remove", "app.example.com", "--yes"])
            .unwrap()
            .request;
        assert_eq!(
            (removed.method.as_str(), &removed.params),
            ("remove_saved_domain", &json!({"domain":"app.example.com"}))
        );
        let published = run(&[
            "ports",
            "publish",
            "env-1",
            "--port",
            "3000",
            "--domain",
            "app.example.com",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(
            published.params,
            json!({"environmentId":"env-1","port":3000,"domain":"app.example.com"})
        );
        let shared = run(&["remote", "start", "--domain", "app.example.com", "--yes"])
            .unwrap()
            .request;
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
            assert_eq!(p["request"]["networkAccess"], true);
            assert_eq!(p["request"]["gpuAccess"], kind == "gpu");
        }
        assert!(run(&["env", "create", "--name", "test", "--kind", "vm"]).is_err());
    }
    /// PROVES the sandbox family reaches `sandbox_vm` with the id as a positional word (the
    /// fourth acceptance run of 30 October refused every `exec`, `stop` and `revoke` with
    /// "Unexpected positional arguments" because the id was read but never consumed) and
    /// that only launch, exec, stop and revoke ask for --yes.
    #[test]
    fn the_sandbox_family_maps_to_sandbox_vm_with_its_id_consumed() {
        let status = run(&["sandbox", "status"]).unwrap().request;
        assert_eq!(status.method, "sandbox_vm");
        assert_eq!(run(&["sandbox", "host-access", "exe-1"]).unwrap().request.params,
            json!({"action":"host_access","sandbox":"exe-1","operation":"status"}));
        assert_eq!(run(&["sandbox", "combine", "exe-1", "--with", "exe-2"]).unwrap().request.params,
            json!({"action":"combine","sandbox":"exe-1","with":"exe-2","operation":"preview"}));
        assert!(run(&["sandbox", "combine", "exe-1", "--with", "exe-2", "--operation", "start", "--preview", "d"]).is_err());
        assert_eq!(run(&["sandbox", "combine", "exe-1", "--with", "exe-2", "--operation", "start", "--preview", "d", "--request-key", "k", "--yes"]).unwrap().request.params,
            json!({"action":"combine","sandbox":"exe-1","with":"exe-2","operation":"start","preview":"d","requestKey":"k"}));
        assert!(run(&["sandbox", "host-access", "exe-1", "--operation", "approve", "--request", "r", "--mode", "read", "--duration", "once"]).is_err());
        assert_eq!(run(&["sandbox", "host-access", "exe-1", "--operation", "approve", "--request", "r", "--mode", "read", "--duration", "once", "--yes"]).unwrap().request.params,
            json!({"action":"host_access","sandbox":"exe-1","operation":"approve","request":"r","mode":"read","duration":"once"}));
        let image = run(&[
            "sandbox",
            "image",
            "import",
            "--layout",
            "layout",
            "--owner-selected",
            "true",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(image.params["operation"], "import");
        assert_eq!(image.params["ownerSelected"], true);
        assert!(std::path::Path::new(image.params["layout"].as_str().unwrap()).is_absolute());
        assert!(run(&["sandbox", "image", "import", "--layout", "layout", "--yes"]).is_err());
        assert!(run(&[
            "sandbox",
            "image",
            "import",
            "--layout",
            "layout",
            "--owner-selected",
            "true"
        ])
        .is_err());
        assert!(run(&["sandbox", "image", "list"]).is_ok());
        let reference = format!(
            "https://registry.example/team/app@sha256:{}",
            "a".repeat(64)
        );
        let registry = run(&[
            "sandbox",
            "image",
            "import",
            "--reference",
            &reference,
            "--auth-origin",
            "https://auth.example",
            "--owner-selected",
            "true",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(registry.params["reference"], reference);
        assert_eq!(registry.params["authOrigin"], "https://auth.example");
        assert!(registry.params.get("layout").is_none());
        assert!(run(&[
            "sandbox",
            "image",
            "import",
            "--layout",
            "folder",
            "--reference",
            &reference,
            "--owner-selected",
            "true",
            "--yes"
        ])
        .is_err());
        assert!(run(&[
            "sandbox",
            "image",
            "import",
            "--reference",
            &reference,
            "--secret",
            "must-not-be-in-argv",
            "--owner-selected",
            "true",
            "--yes"
        ])
        .is_err());
        assert_eq!(
            run(&["sandbox", "launch", "--image", "sha256:abc", "--yes"])
                .unwrap()
                .request
                .params["image"],
            "sha256:abc"
        );
        assert_eq!(status.params, json!({"action":"status"}));
        assert_eq!(
            run(&["sandbox", "plan"]).unwrap().request.params,
            json!({"action":"plan"})
        );
        assert_eq!(
            run(&["sandbox", "cleanup"]).unwrap().request.params,
            json!({"action":"cleanup"})
        );
        assert!(run(&["sandbox", "launch"]).is_err());
        // A credential operation names its op as the third word and its secret only from
        // --file; the name is a flag.
        let holds = run(&["sandbox", "credential", "holds", "--name", "provider-key"])
            .unwrap()
            .request;
        assert_eq!(holds.method, "sandbox_vm");
        assert_eq!(holds.params["action"], json!("credential"));
        assert_eq!(holds.params["op"], json!("holds"));
        assert_eq!(holds.params["name"], json!("provider-key"));
        assert!(run(&["sandbox", "credential", "rotate", "--name", "k"]).is_err());
        assert_eq!(
            run(&["sandbox", "launch", "--memory", "2", "--yes"])
                .unwrap()
                .request
                .params,
            json!({"action":"launch","memoryGb":2.0})
        );
        assert_eq!(run(&["sandbox", "launch", "--cpu", "4", "--yes"]).unwrap().request.params,
            json!({"action":"launch","cpu":4}));
        for invalid in ["0", "-1", "1.5", "256", "NaN"] {
            assert!(run(&["sandbox", "launch", "--cpu", invalid, "--yes"]).is_err());
        }
        assert!(run(&["sandbox", "exec", "exe-1", "--input", "echo hi"]).is_err());
        let exec = run(&[
            "sandbox",
            "exec",
            "exe-1",
            "--input",
            "echo hi; exit 7",
            "--max-output",
            "4096",
            "--timeout-seconds",
            "2",
            "--yes",
        ])
        .unwrap()
        .request;
        assert_eq!(exec.method, "sandbox_vm");
        assert_eq!(
            exec.params,
            json!({"action":"exec","sandbox":"exe-1","input":"echo hi; exit 7","maxOutputBytes":4096,"timeoutSeconds":2})
        );
        assert_eq!(
            run(&["sandbox", "cancel", "exe-1", "--command", "3"])
                .unwrap()
                .request
                .params,
            json!({"action":"cancel","sandbox":"exe-1","command":3})
        );
        assert!(run(&["sandbox", "stop", "exe-1"]).is_err());
        assert_eq!(
            run(&["sandbox", "stop", "exe-1", "--yes"])
                .unwrap()
                .request
                .params,
            json!({"action":"stop","sandbox":"exe-1"})
        );
        assert_eq!(
            run(&[
                "sandbox",
                "revoke",
                "exe-1",
                "--reason",
                "policy_changed",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action":"revoke","sandbox":"exe-1","reason":"policy_changed"})
        );
        assert!(run(&["sandbox", "stop"]).is_err());
        assert!(run(&["sandbox", "exec", "exe-1", "extra", "--input", "x", "--yes"]).is_err());
    }

    /// PROVES the staged workspace's commands: the folder is sent as an absolute path, the
    /// workspace is listed, shown, reviewed and discarded by sandbox id, and a promotion names
    /// its review and files (a JSON array or a comma list) and, like a discard, needs --yes.
    #[test]
    fn the_workspace_commands_map_to_the_workspace_action() {
        let launch = run(&["sandbox", "launch", "--workspace", "project", "--yes"])
            .unwrap()
            .request;
        let folder = launch.params["workspace"].as_str().unwrap();
        assert!(
            std::path::Path::new(folder).is_absolute() && folder.ends_with("project"),
            "{folder}"
        );
        assert_eq!(
            run(&["sandbox", "workspace"]).unwrap().request.params,
            json!({"action":"workspace","op":"list"})
        );
        assert_eq!(
            run(&["sandbox", "workspace", "exe-1"])
                .unwrap()
                .request
                .params,
            json!({"action":"workspace","op":"show","sandbox":"exe-1"})
        );
        assert_eq!(
            run(&["sandbox", "review", "exe-1"]).unwrap().request.params,
            json!({"action":"workspace","op":"review","sandbox":"exe-1"})
        );
        assert!(run(&["sandbox", "review"]).is_err());
        let promote = [
            "sandbox",
            "promote",
            "exe-1",
            "--review",
            "ab12",
            "--files",
            "[\"src/a.py\",\"b,c.txt\"]",
        ];
        assert!(run(&promote).is_err(), "a promotion needs --yes");
        let mut confirmed = promote.to_vec();
        confirmed.push("--yes");
        assert_eq!(
            run(&confirmed).unwrap().request.params,
            json!({"action":"workspace","op":"promote","sandbox":"exe-1","review":"ab12","files":["src/a.py","b,c.txt"]})
        );
        assert_eq!(
            run(&[
                "sandbox",
                "promote",
                "exe-1",
                "--review",
                "ab12",
                "--files",
                "a.txt, b.txt",
                "--yes"
            ])
            .unwrap()
            .request
            .params["files"],
            json!(["a.txt", "b.txt"])
        );
        assert!(run(&["sandbox", "promote", "exe-1", "--files", "a.txt", "--yes"]).is_err());
        assert!(run(&[
            "sandbox",
            "normalize",
            "exe-1",
            "--path",
            "page.html",
            "--format",
            "html"
        ])
        .is_err());
        assert_eq!(
            run(&[
                "sandbox",
                "normalize",
                "exe-1",
                "--path",
                "page.html",
                "--format",
                "html",
                "--to",
                "markdown",
                "--keep-raw",
                "false",
                "--max-output",
                "1000",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action": "normalize", "sandbox": "exe-1", "file": "page.html", "format": "html", "target": "markdown", "keepRaw": false, "maxOutputBytes": 1000})
        );
        assert!(run(&["sandbox", "normalize", "exe-1", "--format", "html", "--yes"]).is_err());
        // Publications (M14).
        assert_eq!(
            run(&[
                "sandbox",
                "launch",
                "--publish",
                "web=8080,api=3000",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action": "launch", "publish": "web=8080,api=3000"})
        );
        assert!(
            run(&["sandbox", "publish", "exe-1", "--service", "web"]).is_err(),
            "it asks for --yes"
        );
        assert_eq!(
            run(&[
                "sandbox",
                "publish",
                "exe-1",
                "--service",
                "web",
                "--audience",
                "public",
                "--minutes",
                "30",
                "--budget",
                "1000",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action": "publish", "sandbox": "exe-1", "service": "web", "audience": "public", "minutes": 30, "budgetBytes": 1000})
        );
        assert_eq!(
            run(&["sandbox", "publish", "exe-1", "--service", "web", "--yes"])
                .unwrap()
                .request
                .params,
            json!({"action": "publish", "sandbox": "exe-1", "service": "web"})
        );
        assert!(run(&[
            "sandbox",
            "publish",
            "exe-1",
            "--service",
            "web",
            "--audience",
            "everyone",
            "--yes"
        ])
        .is_err());
        assert!(run(&["sandbox", "publish", "exe-1", "--yes"]).is_err());
        assert_eq!(
            run(&[
                "sandbox",
                "withdraw",
                "exe-1",
                "--publication",
                "2",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action": "withdraw", "sandbox": "exe-1", "publication": 2})
        );
        assert!(run(&["sandbox", "withdraw", "exe-1", "--yes"]).is_err());
        assert_eq!(
            run(&["sandbox", "launch", "--connect", "api=8080", "--yes"])
                .unwrap()
                .request
                .params,
            json!({"action": "launch", "connect": "api=8080"})
        );
        assert!(
            run(&[
                "sandbox",
                "connect",
                "exe-1",
                "--endpoint",
                "api",
                "--to",
                "exe-2",
                "--service",
                "api"
            ])
            .is_err(),
            "it asks for --yes"
        );
        assert_eq!(
            run(&[
                "sandbox",
                "connect",
                "exe-1",
                "--endpoint",
                "api",
                "--to",
                "exe-2",
                "--service",
                "api",
                "--minutes",
                "30",
                "--budget",
                "1000",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action": "connect", "sandbox": "exe-1", "endpoint": "api", "to": "exe-2", "service": "api", "minutes": 30, "budgetBytes": 1000})
        );
        assert!(
            run(&[
                "sandbox",
                "connect",
                "exe-1",
                "--endpoint",
                "api",
                "--service",
                "api",
                "--yes"
            ])
            .is_err(),
            "it names the other sandbox"
        );
        assert!(run(&[
            "sandbox",
            "connect",
            "exe-1",
            "--endpoint",
            "api",
            "--to",
            "exe-2",
            "--service",
            "api",
            "--minutes",
            "0",
            "--yes"
        ])
        .is_err());
        assert_eq!(
            run(&[
                "sandbox",
                "disconnect",
                "exe-1",
                "--endpoint",
                "api",
                "--yes"
            ])
            .unwrap()
            .request
            .params,
            json!({"action": "disconnect", "sandbox": "exe-1", "endpoint": "api"})
        );
        assert!(run(&["sandbox", "disconnect", "exe-1", "--yes"]).is_err());
        assert!(
            run(&["sandbox", "drill", "vm-cp-29"]).is_err(),
            "it asks for --yes"
        );
        assert_eq!(
            run(&["sandbox", "drill", "vm-cp-29", "--yes"])
                .unwrap()
                .request
                .params,
            json!({"action": "drill", "check": "vm-cp-29"})
        );
        assert!(run(&["sandbox", "drill", "--yes"]).is_err());
        assert!(run(&[
            "sandbox",
            "normalize",
            "exe-1",
            "--path",
            "a",
            "--format",
            "html",
            "--keep-raw",
            "maybe",
            "--yes"
        ])
        .is_err());
        assert!(run(&["sandbox", "discard-workspace", "exe-1"]).is_err());
        assert_eq!(
            run(&["sandbox", "discard-workspace", "exe-1", "--yes"])
                .unwrap()
                .request
                .params,
            json!({"action":"workspace","op":"discard","sandbox":"exe-1"})
        );
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
            assert!(
                parse(&args, |_| Ok(method.example.clone())).is_ok(),
                "{}",
                method.name
            );
        }
    }
    #[test]
    fn development_worker_model_selection_uses_the_existing_swarm_wire() {
        let request = parse(
            &["call", "swarm_dispatch", "--file", "-"].map(str::to_owned),
            |_| {
                Ok(
                    json!({"request":{"action":"developmentModel","workerId":"worker-test",
                "modelEnvironmentId":"env-relay","confirmed":true}}),
                )
            },
        )
        .unwrap();
        assert_eq!(request.request.method, "swarm_dispatch");
        assert_eq!(
            request.request.params["request"]["modelEnvironmentId"],
            "env-relay"
        );
    }

    #[test]
    fn protected_deployment_values_never_accept_shell_argument_input() {
        assert!(run(&[
            "call",
            "set_deployment_secret",
            "--json",
            r#"{"name":"x","value":"private"}"#,
            "--yes"
        ])
        .unwrap_err()
        .contains("never shell arguments"));
        for args in [
            vec![
                "--no-wait",
                "call",
                "set_deployment_secret",
                "--json",
                r#"{"name":"x","value":"private"}"#,
                "--yes",
            ],
            vec![
                "call",
                "--dry-run",
                "set_deployment_secret",
                "--json",
                r#"{"name":"x","value":"private"}"#,
            ],
            vec![
                "call",
                "--yes",
                "set_deployment_secret",
                "--name",
                "x",
                "--value",
                "private",
            ],
        ] {
            assert!(
                run(&args).unwrap_err().contains("never shell arguments"),
                "{args:?}"
            );
        }
        let request = parse(
            &["call", "set_deployment_secret", "--file", "-", "--yes"].map(str::to_owned),
            |_| Ok(json!({"name":"x","value":"private"})),
        )
        .unwrap();
        assert_eq!(request.request.method, "set_deployment_secret");
    }
    #[test]
    fn credentials_are_refused_from_the_command_line_but_accepted_from_stdin() {
        for args in [
            vec!["call", "desk_login", "--password", "synthetic-secret"],
            vec![
                "neocloud",
                "login",
                "--provider",
                "runpod",
                "--api-key",
                "rp_secret",
                "--yes",
            ],
            vec![
                "sandbox",
                "credential",
                "enroll",
                "--name",
                "k",
                "--secret",
                "sk-live",
                "--yes",
            ],
            vec![
                "sandbox",
                "credential",
                "enroll",
                "--name",
                "k",
                "--json",
                r#"{"secret":"sk-live"}"#,
                "--yes",
            ],
            vec![
                "neocloud",
                "login",
                "--json",
                r#"{"provider":"runpod","apiKey":"rp_secret"}"#,
                "--yes",
            ],
            vec![
                "domain",
                "add",
                "app.example.com",
                "--tunnel-port",
                "45000",
                "--token",
                "cf_secret",
                "--yes",
            ],
            vec!["call", "runpod_connect", "--api-key", "rp_secret", "--yes"],
            vec![
                "call",
                "model_registry_connect",
                "--json",
                r#"{"model":"yg/a/b","endpoint":"https://x","apiKey":"k"}"#,
                "--yes",
            ],
            vec![
                "remote",
                "update",
                "share-one",
                "--password",
                "a long password",
                "--yes",
            ],
            vec![
                "remote",
                "connect",
                "--json",
                r#"{"link":"https://example.com","username":"a","password":"a long password"}"#,
            ],
            vec![
                "ports",
                "publish",
                "env-1",
                "--port",
                "3000",
                "--cloudflare",
                r#"{"hostname":"a.example.com","token":"cf"}"#,
                "--yes",
            ],
            vec![
                "ports",
                "publish",
                "env-1",
                "--json",
                r#"{"port":3000,"cloudflare":{"hostname":"a.example.com","token":"cf"}}"#,
                "--yes",
            ],
            vec![
                "remote",
                "start",
                "--cloudflare",
                r#"{"hostname":"a.example.com","token":"cf"}"#,
                "--yes",
            ],
            vec![
                "ports",
                "preflight",
                "env-1",
                "--port",
                "3000",
                "--kind",
                "cloudflare",
                "--cloudflare",
                r#"{"hostname":"a.example.com","token":"cf"}"#,
            ],
        ] {
            let error = run(&args).unwrap_err();
            assert!(error.contains("never shell arguments"), "{args:?}: {error}");
        }
        let login = parse(
            &[
                "neocloud",
                "login",
                "--provider",
                "runpod",
                "--file",
                "-",
                "--yes",
            ]
            .map(str::to_owned),
            |_| Ok(json!({"apiKey":"rp_secret"})),
        )
        .unwrap();
        assert_eq!(
            login.request.params,
            json!({"provider":"runpod","apiKey":"rp_secret"})
        );
        // A public hostname without a token stays an ordinary argument.
        let published = run(&[
            "ports",
            "publish",
            "env-1",
            "--port",
            "3000",
            "--cloudflare",
            r#"{"hostname":"a.example.com","remember":true,"routesReviewed":true}"#,
            "--yes",
        ])
        .unwrap();
        assert_eq!(
            published.request.params["cloudflare"]["hostname"],
            "a.example.com"
        );
        assert!(run(&[
            "window",
            "capture",
            "environment-env-1-main",
            "--token",
            "capture-token"
        ])
        .is_ok());
    }
    #[test]
    fn connection_folders_takes_one_environment_and_an_optional_path() {
        let request = run(&["connection", "folders", "env-1"]).unwrap().request;
        assert_eq!(
            (request.method.as_str(), &request.params),
            (
                "list_environment_folders",
                &json!({"environmentId":"env-1","path":""})
            )
        );
        assert_eq!(
            run(&["connection", "folders", "env-1", "--path", "/app"])
                .unwrap()
                .request
                .params["path"],
            "/app"
        );
        assert!(run(&["connection", "folders"]).is_err());
        assert!(run(&["connection", "folders", "env-1", "extra"]).is_err());
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
        let peer = run(&[
            "connection",
            "exec",
            "conn-a",
            "--source",
            "env-a",
            "--command",
            "ls -la",
            "--yes",
        ])
        .unwrap();
        assert_eq!(peer.request.method, "execute_connected_command");
        assert_eq!(peer.request.params["request"]["sourceId"], "env-a");
        assert_eq!(peer.request.params["request"]["command"], "ls -la");
        assert!(run(&[
            "connection",
            "exec",
            "conn-a",
            "--json",
            r#"{"request":{"connectionId":"conn-b","sourceId":"env-a","command":"true"}}"#,
            "--yes"
        ])
        .unwrap_err()
        .contains("Conflicting"));
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
        assert_eq!(
            run(&["remote", "list"]).unwrap().request.method,
            "list_remote_shares"
        );
        assert_eq!(
            run(&["remote", "revoke", "share-one"])
                .unwrap()
                .request
                .params,
            json!({"shareId":"share-one","revoke":true})
        );
        assert_eq!(
            run(&["remote", "disconnect", "share-one"])
                .unwrap()
                .request
                .params,
            json!({"shareId":"share-one","revoke":false})
        );
        assert_eq!(
            run(&["remote", "inspect", "env-one"])
                .unwrap()
                .request
                .params,
            json!({"environmentId":"env-one","method":"inspect","params":{}})
        );
        assert_eq!(
            run(&[
                "remote",
                "download",
                "env-one",
                "--destination",
                "C:/Downloads"
            ])
            .unwrap()
            .request
            .method,
            "download_remote_folder"
        );
        let parsed=parse(&["remote".into(),"connect".into(),"--file".into(),"-".into()], |_|Ok(json!({"link":"https://example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","username":"alice","password":"a long password"}))).unwrap();
        assert_eq!(parsed.request.method, "connect_remote_share");
        assert_eq!(parsed.request.params["password"], "a long password");
    }

    #[test]
    fn sandbox_internet_is_explicit_and_strictly_boolean() {
        let offline = run(&["sandbox", "launch", "--dry-run"]).unwrap();
        assert!(offline.request.params.get("internet").is_none());
        assert!(offline.request.params.get("incoming").is_none());
        for (flag, name) in [("--internet", "internet"), ("--incoming", "incoming")] {
            for value in ["true", "false"] {
                let parsed = run(&["sandbox", "launch", flag, value, "--dry-run"]).unwrap();
                assert_eq!(parsed.request.params[name], value == "true");
            }
            assert!(run(&["sandbox", "launch", flag, "anything", "--dry-run"]).is_err());
        }
    }

    #[test]
    fn creation_internet_is_explicit_and_strictly_boolean() {
        let offline = run(&["env", "create", "--name", "offline", "--internet", "false"]).unwrap();
        assert_eq!(offline.request.params["request"]["networkAccess"], false);
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
        assert!(run(&["env", "delete", "env-x", "--yes", "--dry-run=treu"])
            .unwrap_err()
            .contains("true or false"));
        assert!(
            run(&["env", "delete", "env-x", "--dry-run=true"])
                .unwrap()
                .request
                .dry_run
        );
        assert!(
            !run(&["env", "list", "--dry-run=false"])
                .unwrap()
                .request
                .dry_run
        );
        assert!(run(&["env", "delete", "env-x", "--yes=false"]).is_err());
    }

    #[test]
    fn action_and_target_cannot_be_silently_overridden() {
        for args in [
            vec!["env", "stop", "env-A", "--status", "running"],
            vec![
                "env",
                "delete",
                "env-A",
                "--environment-id",
                "env-B",
                "--yes",
            ],
            vec!["connection", "disable", "conn-A", "--active", "true"],
            vec![
                "ports",
                "remove",
                "env-A",
                "--port",
                "3000",
                "--present",
                "true",
            ],
            vec![
                "terminal",
                "read",
                "env-A",
                "--action",
                "write",
                "--session-id",
                "term-A",
                "--yes",
            ],
            vec![
                "env",
                "stop",
                "env-A",
                "--json",
                r#"{"environmentId":"env-B"}"#,
            ],
            vec!["env", "stop", "env-A", "--json", r#"{"status":"running"}"#],
            vec![
                "env",
                "exec",
                "env-A",
                "--json",
                r#"{"request":{"environmentId":"env-B","command":"true"}}"#,
                "--yes",
            ],
        ] {
            assert!(run(&args).unwrap_err().contains("Conflicting"), "{args:?}");
        }
        assert!(run(&[
            "call",
            "set_environment_status",
            "--environment-id",
            "env-A",
            "--status",
            "running"
        ])
        .is_ok());
        assert!(run(&["env", "stop", "env-A", "--status", "stopped"]).is_ok());
        assert!(run(&[
            "call",
            "delete_environment",
            "--environment-id",
            "env-A",
            "--environmentId",
            "env-B",
            "--yes"
        ])
        .unwrap_err()
        .contains("twice"));
        // The read-only share default remains deliberately configurable.
        assert_eq!(
            run(&[
                "share",
                "add",
                "env-A",
                "--path",
                ".",
                "--read-only",
                "false",
                "--yes"
            ])
            .unwrap()
            .request
            .params["readOnly"],
            false
        );
    }
}

/// Model measurement syntax is validated before starting or contacting an engine.
pub fn model_measurement_args(args: &[String]) -> Result<(String, String, Option<String>), String> {
    let usage =
        "Usage: yougori model measure start|collect|seal|status|export|abandon ENV [--session ID]";
    let action = args.get(2).ok_or(usage)?;
    if !matches!(
        action.as_str(),
        "start" | "collect" | "seal" | "status" | "export" | "abandon"
    ) {
        return Err(usage.into());
    }
    let environment = args
        .get(3)
        .filter(|v| !v.is_empty() && !v.starts_with('-'))
        .ok_or(usage)?;
    let session = match &args[4..] {
        [] => None,
        [flag, id]
            if flag == "--session"
                && id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Some(id.clone())
        }
        _ => return Err(usage.into()),
    };
    Ok((action.clone(), environment.clone(), session))
}

#[cfg(test)]
mod measurement_tests {
    use super::*;
    fn words(v: &[&str]) -> Vec<String> {
        v.iter().map(|v| v.to_string()).collect()
    }
    #[test]
    fn measurement_syntax_preserves_identity_and_all_actions() {
        for action in ["start", "collect", "seal", "status", "export", "abandon"] {
            let args = words(&[
                "model",
                "measure",
                action,
                "env-1",
                "--session",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]);
            let (found, env, session) = model_measurement_args(&args).unwrap();
            assert_eq!(found, action);
            assert_eq!(env, "env-1");
            assert_eq!(session.unwrap(), "a".repeat(32));
        }
    }
    #[test]
    fn measurement_syntax_refuses_unknown_flags_actions_and_paths() {
        for args in [
            vec!["model", "measure"],
            vec!["model", "measure", "drop", "env-1"],
            vec!["model", "measure", "start", "--session"],
            vec![
                "model",
                "measure",
                "start",
                "env-1",
                "--session",
                "../escape",
            ],
            vec![
                "model",
                "measure",
                "start",
                "env-1",
                "--session",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ],
            vec!["model", "measure", "start", "env-1", "--force"],
        ] {
            assert!(model_measurement_args(&words(&args)).is_err());
        }
    }
}
