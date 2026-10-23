//! `template capture ENV... [--output FOLDER]`: running environments become a template folder.
//! Only settings are copied. Disks, files, sign-ins, variable values, credentials and data never
//! are: variables become secret inputs (their values are never read out of the sandbox), folders
//! shared from this computer are left out, and everything left out is listed in the README.
use super::{
    format,
    scan::Files,
    tools,
};
use serde_json::{json, Value};
use serde_yaml_ng::{Mapping, Value as Yaml};
use std::collections::{BTreeMap, BTreeSet};

/// What capture learned about one environment.
#[derive(Clone, Debug, Default)]
pub struct Captured {
    /// The environment's name in the template.
    pub key: String,
    /// Its name on this computer.
    pub name: String,
    pub kind: String,
    pub image: String,
    pub cpu: f64,
    pub memory_gb: f64,
    pub storage_gb: f64,
    pub internet: bool,
    pub gpu: bool,
    pub ports: Vec<u16>,
    /// Ports with a public link on this computer.
    pub public: Vec<u16>,
    /// Named volumes: name, target, read only.
    pub volumes: Vec<(String, String, bool)>,
    /// Variable names only.
    pub variables: Vec<String>,
    pub tools: Vec<String>,
    pub signed_in: Vec<String>,
    /// Folders shared from this computer, by path or name.
    pub pc_folders: Vec<String>,
    /// Whether the sandbox could be looked into (it was running).
    pub probed: bool,
}

/// Variables a sandbox has from its image or from Yougori, which are not the person's settings.
fn system_variable(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "PATH", "HOME", "HOSTNAME", "TERM", "PWD", "OLDPWD", "SHLVL", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TZ",
        "container", "_", "MAIL", "DEBIAN_FRONTEND", "HOSTTYPE", "GPG_KEY", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
        "LD_LIBRARY_PATH", "LIBRARY_PATH", "GOPATH", "GOTOOLCHAIN", "NODE_OPTIONS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    ];
    const PREFIXES: &[&str] = &["LC_", "NVIDIA_", "CUDA_", "NV_", "NCCL_", "PIP_", "CARGO_", "RUSTUP_", "NPM_CONFIG_", "YARN_", "YOUGORI_", "PYTHON_"];
    const SUFFIXES: &[&str] = &["_VERSION", "_SHA256", "_HOME", "_DOWNLOAD_SHA256", "_URL_BASE"];
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p)) || SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// The probe run inside a sandbox: built-in tools present, tools signed in, and variable names
/// (from the sandbox's settings and from `.env` files in /workspace). Values never leave it.
pub fn probe() -> String {
    let mut script = format!("{}; ", tools::SETUP);
    script.push_str(&format!("for t in {}; do command -v \"$t\" >/dev/null 2>&1 && echo \"tool $t\"; done; ", crate::container_tools::TOOLS.join(" ")));
    for (path, tool) in [(".codex/auth.json", "codex"), (".claude/.credentials.json", "claude"), (".gemini/oauth_creds.json", "gemini"), (".local/share/opencode/auth.json", "opencode"), (".local/share/kilo/auth.json", "kilo"), (".openclaw", "openclaw")] {
        script.push_str(&format!("[ -e \"$HOME/{path}\" ] && echo \"signin {tool}\"; "));
    }
    script.push_str("tr '\\0' '\\n' < /proc/1/environ 2>/dev/null | sed -n 's/^\\([A-Za-z_][A-Za-z0-9_]*\\)=.*/var \\1/p'; ");
    script.push_str("for f in /workspace/.env /workspace/*/.env /app/.env; do [ -f \"$f\" ] && sed -n 's/^[[:space:]]*\\(export[[:space:]][[:space:]]*\\)\\{0,1\\}\\([A-Za-z_][A-Za-z0-9_]*\\)=.*/var \\2/p' \"$f\"; done; true");
    script
}

/// Reads the probe's answer.
pub fn read_probe(output: &str, captured: &mut Captured) {
    for line in output.lines() {
        let Some((kind, name)) = line.trim().split_once(' ') else { continue };
        let name = name.trim();
        match kind {
            "tool" if crate::container_tools::TOOLS.contains(&name) && !captured.tools.iter().any(|t| t == name) => captured.tools.push(name.to_owned()),
            "signin" if !captured.signed_in.iter().any(|t| t == name) => captured.signed_in.push(name.to_owned()),
            "var" if !system_variable(name) && name.len() <= 256 && !captured.variables.iter().any(|v| v == name) => captured.variables.push(name.to_owned()),
            _ => {}
        }
    }
    captured.probed = true;
}

/// A name for the template's own use: lowercase letters, digits, - or _.
pub fn slug(text: &str, fallback: &str) -> String {
    let cleaned: String = text.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '-' }).collect();
    let cleaned = cleaned.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-");
    let cleaned: String = cleaned.chars().take(40).collect();
    let cleaned = cleaned.trim_matches(['-', '_']).to_owned();
    if cleaned.is_empty() { fallback.to_owned() } else { cleaned }
}

fn input_id(variable: &str, taken: &mut BTreeSet<String>) -> String {
    let mut base: String = variable.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if !base.starts_with(|c: char| c.is_ascii_lowercase()) {
        base = format!("v_{base}");
    }
    let base: String = base.chars().take(28).collect();
    let base = base.trim_end_matches('_').to_owned();
    let mut id = base.clone();
    let mut n = 2;
    while !taken.insert(id.clone()) {
        id = format!("{base}_{n}");
        n += 1;
    }
    id
}

fn yaml_string(text: &str) -> String {
    serde_yaml_ng::to_string(&Yaml::String(text.to_owned())).unwrap_or_default().trim_end().to_owned()
}

/// The template folder for these environments, and what was left out.
pub fn build(name: &str, environments: &[Captured], connections: &[(String, String)]) -> Result<(Files, Vec<String>), String> {
    let mut left_out: Vec<String> = Vec::new();
    let mut project = Mapping::new();
    project.insert("project".into(), name.into());
    let mut envs = Mapping::new();
    let mut inputs: Vec<String> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut tools_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut steps: Vec<String> = Vec::new();
    let mut public: Vec<(String, u16)> = Vec::new();
    let mut gpu = false;
    for env in environments {
        let mut spec = Mapping::new();
        spec.insert("type".into(), env.kind.clone().into());
        if !env.image.is_empty() {
            spec.insert("image".into(), env.image.clone().into());
        }
        spec.insert("cpu".into(), serde_yaml_ng::to_value(env.cpu).unwrap_or(Yaml::Null));
        spec.insert("memory".into(), format!("{}GB", super::review::number(env.memory_gb)).into());
        spec.insert("storage".into(), serde_yaml_ng::to_value(env.storage_gb.ceil().max(if env.kind == "microvm" { 6.0 } else { 1.0 }) as u64).unwrap_or(Yaml::Null));
        if env.gpu {
            spec.insert("gpu".into(), true.into());
            gpu = true;
        }
        if !env.internet {
            spec.insert("internet".into(), false.into());
        }
        if !env.ports.is_empty() {
            spec.insert("ports".into(), Yaml::Sequence(env.ports.iter().map(|p| serde_yaml_ng::to_value(p).unwrap_or(Yaml::Null)).collect()));
        }
        if !env.volumes.is_empty() {
            let volumes = env.volumes.iter().map(|(source, target, read_only)| {
                let mut volume = Mapping::new();
                volume.insert("source".into(), source.clone().into());
                volume.insert("target".into(), target.clone().into());
                if *read_only {
                    volume.insert("read_only".into(), true.into());
                }
                Yaml::Mapping(volume)
            }).collect();
            spec.insert("volumes".into(), Yaml::Sequence(volumes));
            left_out.push(format!("The data in {}'s volumes ({}): the template creates empty ones with the same names.", env.name, env.volumes.iter().map(|v| v.0.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if !env.variables.is_empty() {
            let mut secrets = Mapping::new();
            for variable in &env.variables {
                let id = input_id(variable, &mut ids);
                secrets.insert(variable.clone().into(), format!("{{{{secrets.{id}}}}}").into());
                inputs.push(format!("  - id: {id}\n    question: {}\n    type: secret\n", yaml_string(&format!("Value for {variable} in {}", env.key))));
            }
            spec.insert("secrets".into(), Yaml::Mapping(secrets));
            left_out.push(format!("The values of {}'s variables ({}): each became a secret question, asked when the template runs.", env.name, env.variables.join(", ")));
        }
        for tool in &env.tools {
            tools_map.entry(env.key.clone()).or_default().push(tool.clone());
        }
        for tool in &env.signed_in {
            left_out.push(format!("The {tool} sign-in in {}: whoever runs the template signs in to their own account.", env.name));
            steps.push(format!("  - title: {}\n    command: {}\n", yaml_string(&format!("Sign in to {tool} in {}", env.key)), yaml_string(&format!("yougori {tool} --environment {{{{env.{}}}}}", env.key))));
        }
        for folder in &env.pc_folders {
            // Only the folder's own name: a full path would put this computer's user names in a
            // file that may be published.
            let short = folder.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next().unwrap_or("a folder");
            left_out.push(format!("The folder {short} shared from this computer with {}: a template never takes folders from the computer it was made on.", env.name));
        }
        if let Some(port) = env.public.first() {
            public.push((env.key.clone(), *port));
            if env.public.len() > 1 {
                left_out.push(format!("{}'s other public links: a template has one public address per environment.", env.name));
            }
        }
        if !env.probed {
            left_out.push(format!("{} was not running, so its variables and signed-in tools could not be read. Start it and capture again to include them.", env.name));
        }
        envs.insert(env.key.clone().into(), Yaml::Mapping(spec));
    }
    project.insert("environments".into(), Yaml::Mapping(envs));
    if !connections.is_empty() {
        project.insert("connections".into(), Yaml::Sequence(connections.iter().map(|(from, to)| format!("{from} -> {to}").into()).collect()));
    }
    let project_text = serde_yaml_ng::to_string(&Yaml::Mapping(project)).map_err(|e| e.to_string())?;
    let mut template = String::new();
    template.push_str(&format!("# Captured from {} with yougori template capture.\n# README.md lists what was left out. Check it with: yougori template check .\nkind: template\nname: {name}\ntitle: {name}\nsummary: {}\nversion: 0.1.0\n# The open-source licence you publish it under; MIT is a placeholder.\nlicense: MIT\n", environments.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", "), yaml_string(&format!("Captured from {} sandboxes. Say here what it sets up.", environments.len()))));
    if gpu {
        template.push_str("\nrequires:\n  gpu: required\n");
    }
    if !public.is_empty() {
        inputs.push("  - id: access\n    question: Where should it be reachable?\n    type: choice\n    choices:\n      - {value: quick, label: Quick link, hint: Free HTTPS link from Cloudflare. It can change after a restart.}\n      - {value: domain, label: My own domain, hint: A domain you saved with yougori domain add.}\n      - {value: none, label: Only this computer}\n    default: quick\n  - id: domain\n    question: Which saved domain?\n    type: domain\n    when: {access: domain}\n".into());
    }
    if !inputs.is_empty() {
        template.push_str("\ninputs:\n");
        for input in &inputs {
            template.push_str(input);
        }
    }
    if !tools_map.is_empty() {
        template.push_str("\ntools:\n");
        for (environment, list) in &tools_map {
            template.push_str(&format!("  {environment}: [{}]\n", list.join(", ")));
        }
    }
    if !public.is_empty() {
        template.push_str("\npublic:\n");
        for (environment, port) in &public {
            template.push_str(&format!("  - environment: {environment}\n    port: {port}\n    access: \"{{{{inputs.access}}}}\"\n    domain: \"{{{{inputs.domain}}}}\"\n"));
        }
        template.push_str("\noutputs:\n");
        for (environment, _) in &public {
            template.push_str(&format!("  - label: {environment}\n    value: \"{{{{public.{environment}}}}}\"\n"));
        }
    }
    if !steps.is_empty() {
        template.push_str("\nsteps:\n");
        for step in &steps {
            template.push_str(step);
        }
    }
    left_out.push("Every sandbox's disk: files, installed programs other than the listed tools, databases, snapshots and backups.".into());
    let mut readme = format!("# {name}\n\nCaptured from {} on this computer with `yougori template capture`. Only settings were copied.\n\n## Left out\n\n", environments.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", "));
    for item in &left_out {
        readme.push_str(&format!("- {item}\n"));
    }
    readme.push_str(&format!("\n## Next\n\n```text\nyougori template check .\nyougori template run .\nyougori template publish .\n```\n\nChoose the licence in `{}` before publishing; everything on the Hub is public and open source.\n", format::TEMPLATE_FILE));
    let files: Files = [
        (format::TEMPLATE_FILE.to_owned(), template.into_bytes()),
        ("yougori.yaml".to_owned(), project_text.into_bytes()),
        ("README.md".to_owned(), readme.into_bytes()),
    ].into();
    format::template(&files).map_err(|problems| format!("The captured template did not pass its own check, so nothing was written:\n- {}", problems.join("\n- ")))?;
    Ok((files, left_out))
}

/// The key an environment gets in the template: a project's own name for it, or its name.
fn key(environment: &Value, taken: &mut BTreeSet<String>) -> String {
    let name = environment["name"].as_str().unwrap_or("sandbox");
    let description = environment["description"].as_str().unwrap_or_default();
    let own = description.strip_prefix("Yougori project ").and_then(|rest| rest.rsplit_once(" / ")).map(|(_, key)| key.to_owned());
    let base = slug(own.as_deref().unwrap_or(name), "sandbox");
    let mut key = base.clone();
    let mut n = 2;
    while !taken.insert(key.clone()) {
        key = format!("{base}-{n}");
        n += 1;
    }
    key
}

/// Reads what the engine knows about one environment.
pub fn describe(environment: &Value, state: &Value, volumes: &Value, taken: &mut BTreeSet<String>) -> Result<Captured, String> {
    let name = environment["name"].as_str().unwrap_or_default().to_owned();
    let id = environment["id"].as_str().unwrap_or_default();
    let runtime = environment["runtime"].as_str().unwrap_or_default();
    let kind = match (environment["kind"].as_str(), environment["provider"].as_str()) {
        _ if runtime.starts_with("shared://") || runtime.starts_with("cloud://") => return Err(format!("{name} is shared from another computer or a cloud server; only sandboxes on this computer can be captured.")),
        (Some("container"), Some("yougoriCuda")) => "gpu",
        (Some("container"), _) => "container",
        (Some("microVm"), _) => "microvm",
        (Some("fullVm"), _) => return Err(format!("{name} is a VM: its disk stays on this computer, so it cannot be captured. Capture containers and microVMs.")),
        _ => return Err(format!("{name} cannot be captured: only containers and microVMs can.")),
    };
    let project = environment["description"].as_str().unwrap_or_default().starts_with("Yougori project ");
    let own_key = environment["description"].as_str().and_then(|d| d.rsplit_once(" / ")).map(|(_, key)| key.to_owned());
    let prefix = own_key.as_ref().and_then(|key| name.strip_suffix(&format!("-{key}"))).map(|project| format!("{project}-"));
    let policy = &environment["resourcePolicy"];
    let mut captured = Captured {
        key: key(environment, taken),
        name: name.clone(),
        kind: kind.into(),
        image: if kind == "microvm" && runtime == "builtin:alpine" { String::new() } else { runtime.to_owned() },
        cpu: policy["cpu"]["preferred"].as_f64().or(policy["cpu"]["max"].as_f64()).unwrap_or(2.0).max(0.5),
        memory_gb: policy["memoryGb"]["preferred"].as_f64().or(policy["memoryGb"]["max"].as_f64()).unwrap_or(2.0).max(0.25),
        storage_gb: environment["storageLimitGb"].as_f64().unwrap_or(20.0),
        internet: environment["networkAccess"] != false,
        gpu: environment["gpuAccess"] == true && kind == "container",
        ..Default::default()
    };
    let mut ports: BTreeSet<u16> = state["manualServicePorts"][id].as_array().into_iter().flatten().filter_map(|p| p.as_u64()).filter_map(|p| u16::try_from(p).ok()).collect();
    for service in state["savedEnvironmentServices"].as_array().into_iter().flatten().filter(|s| s["environmentId"] == id) {
        if let Some(port) = service["port"].as_u64().and_then(|p| u16::try_from(p).ok()) {
            ports.insert(port);
            if service["kind"] == "cloudflare" && !captured.public.contains(&port) {
                captured.public.push(port);
            }
        }
    }
    captured.ports = ports.into_iter().collect();
    for volume in volumes["volumes"].as_array().into_iter().flatten() {
        for mount in volume["mounts"].as_array().into_iter().flatten().filter(|m| m["environmentId"] == id) {
            let full = volume["name"].as_str().unwrap_or_default();
            let short = match (&prefix, project) {
                (Some(prefix), true) => full.strip_prefix(prefix.as_str()).unwrap_or(full),
                _ => full,
            };
            captured.volumes.push((short.to_owned(), mount["target"].as_str().unwrap_or("/data").to_owned(), mount["readOnly"] == true));
        }
    }
    Ok(captured)
}

/// `template capture ENV... [--output FOLDER]`.
pub async fn capture(words: &[String], output: Option<&str>, interactive: bool) -> Result<Value, String> {
    if words.is_empty() {
        return Err("Usage: yougori template capture ENV... [--output FOLDER]. Name the running environments to turn into a template.".into());
    }
    let gathered = async {
        crate::client::start(None).await?;
        let state = crate::public::call("get_platform_state", json!({})).await?;
        let volumes = crate::public::call("list_volumes", json!({})).await.unwrap_or(Value::Null);
        let mut taken = BTreeSet::new();
        let mut captured = Vec::new();
        let mut ids = BTreeMap::new();
        for word in words {
            let id = crate::public::resolve(word).await?;
            let environment = state["environments"].as_array().into_iter().flatten().find(|e| e["id"] == id.as_str()).cloned().ok_or_else(|| format!("{word} was not found. See your environments with yougori ps."))?;
            let mut item = describe(&environment, &state, &volumes, &mut taken)?;
            if environment["status"] == "running" {
                if let Ok(probe) = crate::public::call("execute_environment_command", json!({"request": {"environmentId": id, "command": probe()}})).await {
                    read_probe(probe["stdout"].as_str().unwrap_or_default(), &mut item);
                }
                if let Ok(services) = crate::public::call("list_environment_services", json!({"environmentId": id})).await {
                    item.pc_folders = services["shares"].as_array().into_iter().flatten().filter_map(|s| s["path"].as_str().or(s["name"].as_str()).map(str::to_owned)).collect();
                }
            }
            ids.insert(id, item.key.clone());
            captured.push(item);
        }
        let connections: Vec<(String, String)> = state["connections"].as_array().into_iter().flatten().filter_map(|c| {
            Some((ids.get(c["sourceId"].as_str()?)?.clone(), ids.get(c["targetId"].as_str()?)?.clone()))
        }).collect();
        Ok::<_, String>((captured, connections))
    };
    let (captured, connections) = super::run::wait(interactive, "Reading the sandboxes' settings", gathered).await?;
    let name = slug(&captured[0].key, "captured");
    let folder = std::env::current_dir().map_err(|e| e.to_string())?.join(output.unwrap_or(&format!("{name}-template")));
    if folder.exists() && std::fs::read_dir(&folder).map(|mut d| d.next().is_some()).unwrap_or(true) {
        return Err(format!("{} already exists and is not empty. Choose another folder with --output.", folder.display()));
    }
    let (files, left_out) = build(&name, &captured, &connections)?;
    super::client::write_files(&folder, &files)?;
    Ok(json!({
        "captured": captured.iter().map(|c| &c.name).collect::<Vec<_>>(), "folder": folder, "files": files.keys().collect::<Vec<_>>(),
        "leftOut": left_out,
        "next": [format!("Read {}/README.md and fill in the summary and licence.", folder.display()), format!("yougori template check {}", shell_words::quote(&folder.to_string_lossy())), format!("yougori template run {}", shell_words::quote(&folder.to_string_lossy()))],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_keeps_settings_and_leaves_out_values_sign_ins_folders_and_data() {
        let state = json!({
            "manualServicePorts": {"env-web": [3000]},
            "savedEnvironmentServices": [{"environmentId": "env-web", "port": 3000, "kind": "cloudflare"}],
        });
        let volumes = json!({"volumes": [{"name": "shop-pgdata", "mounts": [{"environmentId": "env-db", "target": "/var/lib/postgresql/data", "readOnly": false}]}]});
        let web = json!({"id": "env-web", "name": "Web App", "kind": "container", "provider": "yougoriOci", "runtime": "node:24", "description": "Created with yougori run", "networkAccess": true, "storageLimitGb": 19.5, "resourcePolicy": {"cpu": {"preferred": 2}, "memoryGb": {"preferred": 4}}});
        let db = json!({"id": "env-db", "name": "shop-db", "kind": "container", "provider": "yougoriOci", "runtime": "postgres:17", "description": "Yougori project abc / db", "networkAccess": false, "storageLimitGb": 10, "resourcePolicy": {"cpu": {"preferred": 1}, "memoryGb": {"preferred": 1}}});
        let mut taken = BTreeSet::new();
        let mut first = describe(&web, &state, &volumes, &mut taken).unwrap();
        read_probe("tool codex\nsignin codex\nvar PATH\nvar NODE_VERSION\nvar OPENAI_API_KEY\nvar DATABASE_URL\nvar OPENAI_API_KEY\nnoise\n", &mut first);
        first.pc_folders.push("C:/Users/me/projects/shop".into());
        let second = describe(&db, &state, &volumes, &mut taken).unwrap();
        assert_eq!((first.key.as_str(), second.key.as_str()), ("web-app", "db"));
        assert_eq!(second.volumes, [("pgdata".to_owned(), "/var/lib/postgresql/data".to_owned(), false)]);
        assert_eq!(first.variables, ["OPENAI_API_KEY", "DATABASE_URL"]);
        let (files, left_out) = build("shop", &[first, second], &[("web-app".into(), "db".into())]).unwrap();
        let template = String::from_utf8(files[format::TEMPLATE_FILE].clone()).unwrap();
        let project = String::from_utf8(files["yougori.yaml"].clone()).unwrap();
        let readme = String::from_utf8(files["README.md"].clone()).unwrap();
        let checked = format::template(&files).unwrap();
        assert_eq!(checked.questions.iter().map(|q| (q.id.as_str(), q.kind.name())).collect::<Vec<_>>(), [("openai_api_key", "secret"), ("database_url", "secret"), ("access", "choice"), ("domain", "domain")]);
        assert_eq!(checked.project.environments["web-app"].secrets["OPENAI_API_KEY"], "{{secrets.openai_api_key}}");
        assert_eq!(checked.project.environments["web-app"].storage, json!(20));
        assert!(!checked.project.environments["db"].internet);
        assert!(template.contains("web-app: [codex]") && template.contains("Sign in to codex in web-app"));
        assert!(project.contains("web-app -> db"));
        for said in ["The values of Web App's variables (OPENAI_API_KEY, DATABASE_URL)", "The codex sign-in in Web App", "The folder shop shared from this computer", "The data in shop-db's volumes (pgdata)", "Every sandbox's disk"] {
            assert!(left_out.iter().any(|l| l.contains(said)), "{said}: {left_out:?}");
            assert!(readme.contains(said), "{said}");
        }
        assert!(!project.contains("C:/Users") && !template.contains("C:/Users") && !readme.contains("C:/Users"), "a PC folder's path never enters the template");
    }

    #[test]
    fn vms_and_shared_environments_cannot_be_captured() {
        let mut taken = BTreeSet::new();
        let vm = json!({"id": "e", "name": "ubuntu", "kind": "fullVm", "provider": "qemu", "runtime": "C:/isos/u.iso"});
        assert!(describe(&vm, &json!({}), &json!({}), &mut taken).unwrap_err().contains("cannot be captured"));
        let shared = json!({"id": "s", "name": "notes (remote)", "kind": "container", "runtime": "shared://tunnel/x"});
        assert!(describe(&shared, &json!({}), &json!({}), &mut taken).unwrap_err().contains("only sandboxes on this computer"));
        assert!(probe().contains("/proc/1/environ") && !probe().contains("cat /proc/1/environ"), "only names are printed");
        assert_eq!(slug("My Shop!", "x"), "my-shop");
    }
}
