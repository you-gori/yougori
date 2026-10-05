//! A project container on an already connected Linux server, reached over SSH.
use super::*;

fn eligible(node: &Value) -> bool {
    node["kind"] == "cloud" && node["status"] == "running"
}

fn state_key(folder: &Path, id: &str) -> Result<String, String> {
    Ok(format!("{:x}", Sha256::digest(format!("cloud:{}:{id}", directory_key(folder)?))))
}

fn bootstrap(container: &str, owner: &str, project: &package::Project, setup: &Setup) -> String {
    let name = shell(container);
    let image = shell(&project.image());
    let label = shell(owner);
    let port = live::proxy_port(setup.guest_port);
    format!(r#"set -eu
command -v docker >/dev/null 2>&1 || {{ echo 'This server needs Docker Engine to run project containers. Install Docker and allow this SSH account to use it, then retry.' >&2; exit 1; }}
docker info >/dev/null
if docker container inspect {name} >/dev/null 2>&1; then
  test "$(docker inspect -f '{{{{index .Config.Labels "com.yougori.project"}}}}' {name})" = {label} || {{ echo 'Container name belongs to another workload' >&2; exit 1; }}
  test "$(docker inspect -f '{{{{.State.Running}}}}' {name})" = false || {{ echo 'This project is already running on the server. Quit its other launcher before retrying.' >&2; exit 1; }}
  test "$(docker inspect -f '{{{{.Config.Image}}}}' {name})" = {image} || {{ echo 'Project runtime changed. Remove this stopped project container when ready, then retry; its data has been kept.' >&2; exit 1; }}
  test "$(docker inspect -f '{{{{index .Config.Labels "com.yougori.proxy-port"}}}}' {name})" = '{port}' || {{ echo 'Project proxy port changed. Remove this stopped project container when ready, then retry.' >&2; exit 1; }}
  docker update --cpus {cpu} --memory {memory}g --memory-swap {memory}g {name} >/dev/null
else
  docker pull {image}
  docker create --name {name} --label com.yougori.project={label} --label com.yougori.proxy-port={port} --cpus {cpu} --memory {memory}g --memory-swap {memory}g --log-opt max-size=10m --log-opt max-file=2 -p 127.0.0.1::{port} --entrypoint sh {image} -c {boot} >/dev/null
fi
"#, cpu=setup.allocation[0], memory=setup.allocation[1], boot=shell(BOOT))
}

fn uploaded_project(destination: &str, container: &str) -> Result<String, String> {
    let leaf = destination.rsplit('/').next().unwrap_or("");
    let transfer = leaf.strip_prefix("yougori-import-").unwrap_or("");
    if !destination.starts_with('/') || destination.split('/').any(|p| p == "..")
        || transfer.len() != 32 || !transfer.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Unexpected cloud upload destination; no files were removed".into());
    }
    let clear = live::container_command(Some(container), "find /workspace -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; rm -f /yougori/launch/installed-*", false);
    Ok(format!("test \"$(dirname -- {})\" = \"$HOME\" || exit 1; {clear} && docker cp {} {} ; code=$?; rm -rf -- {}; exit \"$code\"", shell(destination), shell(&format!("{destination}/project/workspace/.")), shell(&format!("{container}:/workspace/")), shell(destination)))
}

async fn configure_cloud(folder: &Path, id: &str, old: Option<&Setup>) -> Result<Setup, String> {
    let allocation = if choose("Choose project resources", &["Recommended — 2 CPU · 4 GB RAM".into(), "Customize — container limits on this server".into()])? == 0 {
        [2, 4, 0]
    } else {
        let number = |title: &str, default: u32| -> Result<u32, String> {
            ui::input(title, &default.to_string(), false, &|value| {
                value.parse::<u32>().ok().filter(|n| (1..=1024).contains(n)).map(|n| n.to_string()).ok_or("Enter a whole number from 1 to 1024".into())
            })?.parse::<u32>().map_err(|e| e.to_string())
        };
        [number("CPU limit", old.map_or(2, |s| s.allocation[0]))?, number("RAM limit in GB", old.map_or(4, |s| s.allocation[1]))?, 0]
    };
    let guest_port = port("Port your application listens on", old.map_or(package::Project::load(folder)?.port, |s| s.guest_port))?;
    let network = network(false, Some(id), None).await?;
    let (kind, domain) = match network {
        Network::Computer => ("computer", None), Network::Lan => ("lan", None),
        Network::Quick => ("quick", None), Network::Domain(name) => ("domain", Some(name)),
        Network::NewDomain { hostname, token, host_port } => {
            call("add_saved_domain", json!({"hostname":hostname,"token":token,"hostPort":host_port,"port":guest_port})).await?;
            ("domain", Some(hostname))
        }
    };
    Ok(Setup { version: 1, directory: folder.to_string_lossy().into(), environment: Some(id.into()), gpu: false,
        allocation, guest_port, local_port: old.map_or(guest_port, |s| s.local_port), network: kind.into(), domain,
        needs_update: false, ..old.cloned().unwrap_or_default() })
}

pub(super) async fn run_in(folder: &Path, change: bool) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() { return Err("Cloud launch needs an interactive terminal to choose a connected cloud environment.".into()); }
    let folder = folder.canonicalize().map_err(|e| e.to_string())?;
    let mut project = package::Project::load(&folder)?;
    if let Some(root) = &project.workspace_root { return Err(format!("Launch from the workspace root: {}", root.display())); }
    let _session = ui::Session::start("launch --cloud", "Run your project in a connected cloud environment");
    let name = project_name(&folder)?;
    ui::intro(&clean(&name), &project.runtime_label());
    let engine = ui::task("Starting Yougori engine");
    client::start(None).await?;
    let state = call("get_platform_state", json!({})).await?;
    engine.done("Engine ready");
    let nodes: Vec<_> = state["environments"].as_array().ok_or("Missing environment list")?.iter().filter(|node| eligible(node)).collect();
    if nodes.is_empty() { return Err("No connected cloud environments are ready. Connect your Linux server in Yougori, then run npm run yougori-cloud again.".into()); }
    let choices: Vec<_> = nodes.iter().map(|node| clean(node["name"].as_str().unwrap_or("Cloud server"))).collect();
    let node = nodes[choose_with_note("Choose a cloud environment", "Your project runs in its own Docker container. The SSH account must have access to Docker. Quitting stops only this project container.", &choices)?];
    let id = node["id"].as_str().ok_or("Missing environment ID")?;
    let key = state_key(&folder, id)?;
    let settings = yougori_cli::launcher_state::directory()?;
    fs::create_dir_all(&settings).map_err(|e| e.to_string())?;
    let path = settings.join(format!("{key}.json"));
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path.with_extension("lock")).map_err(|e| e.to_string())?;
    lock.try_lock().map_err(|_| "This cloud project is already open in another terminal")?;
    let old = load(&path, &folder)?;
    let mut setup = if change || old.is_none() { configure_cloud(&folder, id, old.as_ref()).await? } else { old.unwrap() };
    if change || !setup.command_reviewed {
        setup.custom_command = choose_command(&folder, &project, setup.custom_command.as_deref())?;
        if setup.custom_command.is_some() { setup.guest_port = port("Port your application listens on", setup.guest_port)?; }
        setup.command_reviewed = true;
    }
    if sync::has_env_files(&folder) && (change || !setup.env_reviewed) {
        setup.env_files = choose_with_note("Copy .env files to this cloud project?", "These files can contain credentials. Selected files will be sent to the cloud server over SSH.", &["Keep them on this computer".into(), "Copy them into the cloud container".into()])? == 1;
        setup.env_reviewed = true;
    }
    review_command(&folder, &project, &mut setup)?;
    project.custom_command = setup.custom_command.clone();
    choose_sync(&mut setup, change, &folder)?;
    add_project_shortcut(&folder, &project)?;
    save(&path, &setup)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let signal = tokio::spawn(async move { while tokio::signal::ctrl_c().await.is_ok() { flag.store(true, Ordering::Relaxed); } });
    let container = format!("yougori-project-{}", &key[..24]);
    let mut started = false;
    let mut publications = Vec::<String>::new();
    let mut uploads = Vec::<String>::new();
    let result = async {
        let preparing = ui::task("Preparing cloud project container");
        live::remote_task(id, &bootstrap(&container, &key, &project, &setup), &cancel).await?;
        cancelled(&cancel)?;
        started = true;
        exec(id, &format!("docker start {} >/dev/null && docker exec {} sh -c 'mkdir -p /workspace /yougori/launch'", shell(&container), shell(&container))).await?;
        preparing.done(&format!("Project container running on {}", clean(node["name"].as_str().unwrap_or(id))));
        if project.is_python() {
            let helper = ui::task("Preparing Python project helpers");
            live::remote_task(id, &live::container_command(Some(&container), "command -v node >/dev/null 2>&1 || { apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*; }", false), &cancel).await?;
            helper.done("Project helpers ready");
        }
        let ports = exec(id, &format!("docker port {} {}/tcp", shell(&container), live::proxy_port(setup.guest_port))).await?;
        let remote_port = ports.trim().strip_prefix("127.0.0.1:").and_then(|s| s.parse::<u16>().ok()).filter(|p| *p > 0).ok_or("Docker did not return a private project port")?;
        // Clear routes left by an interrupted previous run before starting the app.
        let services = call("list_environment_services", json!({"environmentId":id})).await?;
        for publication in services["publications"].as_array().into_iter().flatten().filter(|p| p["port"] == remote_port) {
            if let Some(id) = publication["id"].as_str() {
                call("unpublish_environment_service", json!({"publicationId":id})).await?;
            }
        }
        let mut syncing = ui::task("Syncing project to cloud");
        let filter = sync::Filter::load(&folder, setup.env_files)?;
        let manifest = sync::scan(&folder, &filter)?;
        let sync_path = path.with_extension("sync.json");
        let mut saved = sync::Saved::load(&sync_path);
        let remote_token = exec(id, &live::container_command(Some(&container), "cat /yougori/launch/sync-token 2>/dev/null || true", false)).await?;
        let reconcile = saved.needs_reconcile(id, &remote_token);
        let copied = exec(id, &live::container_command(Some(&container), "if [ -d /workspace ] && [ -n \"$(ls -A /workspace)\" ]; then printf existing; fi", false)).await?.trim() != "existing";
        let mut initial_databases = std::collections::BTreeSet::new();
        if copied {
            syncing.copy_status("Preparing project files");
            let staging = stage_project(&folder, &manifest, &syncing, &cancel).await?;
            syncing.detail(&format!("{} files · {}", manifest.len(), ui::bytes(manifest.values().map(|(size, _)| size).sum())));
            syncing.copy_status("Waiting for copy progress");
            let copy = public::call_with_progress("copy_files_to_environment", json!({"environmentId":id,"paths":[staging.path().join("project")]}), |progress| syncing.copy_progress(progress)).await?;
            syncing.set("Setting up project sync");
            let destination = copy["destination"].as_str().ok_or("Missing cloud copy destination")?;
            let copy_command = uploaded_project(destination, &container)?;
            uploads.push(destination.into());
            live::remote_task(id, &copy_command, &cancel).await?;
            saved.files = manifest.clone();
            saved.token.clear();
            saved.pending.clear();
            initial_databases = staging.databases.keys().cloned().collect();
            saved.databases = staging.databases;
            saved.environment = id.into();
            saved.common.clear();
            saved.directories.clear();
            saved.save(&sync_path)?;
        }
        if let Some(text) = plan::describe(&plan::installs(&folder, &project, &manifest)) {
            ui::info(&clean(&text));
        }
        cancelled(&cancel)?;
        let mut live = live::Live::prepare_target(id, &folder, &project, &manifest, setup.two_way, setup.guest_port, &sync_path, saved, Some(container.clone()), remote_port).await?;
        live.priority = setup.sync_priority.unwrap_or_default();
        live.env_files = setup.env_files;
        live.initial_databases = initial_databases;
        let running = async {
            if !setup.two_way && !copied && reconcile { live.reconcile_one_way(&manifest).await?; }
            if setup.two_way { live.sync_both(setup.env_files).await?; } else { live.sync_to(manifest).await?; }
            cancelled(&cancel)?;
            syncing.done(if setup.two_way { "Two-way sync checked" } else { "Project files up to date" });
            let publishing = ui::task("Setting up project access");
            let network = match setup.network.as_str() { "lan" => Network::Lan, "quick" => Network::Quick, "domain" => Network::Domain(setup.domain.clone().ok_or("Missing saved domain")?), _ => Network::Computer };
            if !matches!(network, Network::Computer | Network::Lan) {
                if let Some(params) = publish_params(&network, id, remote_port) {
                    let result = call("publish_environment_service", params).await?;
                    if let Some(id) = result["id"].as_str() { publications.push(id.into()); }
                    for url in result["urls"].as_array().into_iter().flatten().filter_map(Value::as_str) { ui::info(&format!("public  {}", clean(url))); }
                }
            }
            let kind = if matches!(network, Network::Lan) { "local" } else { "loopback" };
            let params = json!({"environmentId":id,"port":remote_port,"kind":kind});
            let mut requested = params.clone();
            requested["hostPort"] = json!(setup.local_port);
            let result = match call("publish_environment_service", requested).await {
                Err(error) if port_in_use(&error) => call("publish_environment_service", params).await?,
                result => result?,
            };
            if let Some(id) = result["id"].as_str() { publications.push(id.into()); }
            setup.local_port = result["hostPort"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).ok_or("Missing local port")?;
            save(&path, &setup)?;
            publishing.done(&format!("Available at http://localhost:{}", setup.local_port));
            cancelled(&cancel)?;
            live.start().await?;
            ui::outro(&format!("$ {}", clean(&project.command_label())));
            live.watch(&format!("{} · cloud", clean(&name)), setup.local_port, setup.env_files, setup.two_way, setup.continuous_sync, false, &cancel).await
        }.await;
        if running.is_ok() && setup.continuous_sync {
            if let Err(error) = live.sync_current(setup.env_files, setup.two_way).await { ui::warn(&format!("Final sync incomplete: {}. Cloud project files are kept for the next launch.", clean(&error))); }
        }
        live.close().await;
        running
    }.await;
    let stopping = ui::task("Stopping cloud project session");
    let mut cleanup_errors = Vec::new();
    for publication in publications {
        if let Err(error) = call("unpublish_environment_service", json!({"publicationId":publication})).await { cleanup_errors.push(error); }
    }
    if started {
        if let Err(error) = exec(id, &format!("test \"$(docker inspect -f '{{{{index .Config.Labels \"com.yougori.project\"}}}}' {})\" = {} && docker stop -t 5 {}", shell(&container), shell(&key), shell(&container))).await { cleanup_errors.push(error); }
    }
    for upload in uploads {
        // The receipt was validated before recording it; the receiver only writes
        // fresh yougori-import-<transfer-id> directories directly under $HOME.
        if let Err(error) = exec(id, &format!("test \"$(dirname -- {})\" = \"$HOME\" && rm -rf -- {}", shell(&upload), shell(&upload))).await { cleanup_errors.push(error); }
    }
    signal.abort();
    if cleanup_errors.is_empty() { stopping.done("Project stopped; cloud environment stays connected"); }
    else { stopping.fail("Could not confirm project cleanup"); return Err(format!("Check container {container} on the server: {}", cleanup_errors.join("; "))); }
    ui::outro("npm run yougori-cloud starts again · npm run yougori-cloud -- --change edits this server's project settings");
    match result {
        Err(_) if cancel.load(Ordering::Relaxed) => Ok(130),
        result => result.map(|_| 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_ready_cloud_nodes_are_selectable_and_settings_are_separate() {
        assert!(eligible(&json!({"kind":"cloud","status":"running"})));
        for node in [json!({"kind":"cloud","status":"stopped"}), json!({"kind":"container","status":"running"}), json!({"kind":"shared","status":"running"})] { assert!(!eligible(&node)); }
        let folder = tempfile::tempdir().unwrap();
        let a = state_key(folder.path(), "cloud-a").unwrap();
        assert_ne!(a, state_key(folder.path(), "cloud-b").unwrap());
        assert_ne!(a, directory_key(folder.path()).unwrap());
        assert_eq!(a.len(), 64);
    }
    #[test]
    fn uploaded_files_cleanup_is_limited_to_a_verified_transfer() {
        for path in ["/", "/home/me", "/home/me/yougori-import-bad", "/home/me/../yougori-import-0123456789abcdef0123456789abcdef"] { assert!(uploaded_project(path, "container").is_err()); }
        let script = uploaded_project("/home/me/yougori-import-0123456789abcdef0123456789abcdef", "container").unwrap();
        assert!(script.contains("container:/workspace/"));
        assert!(!script.contains("docker rm"));
    }

    #[test]
    fn cloud_bootstrap_creates_private_containers_and_refuses_other_or_running_workloads() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let setup: Setup = serde_json::from_value(json!({"version":1,"directory":folder.path(),"environment":"env-cloud","gpu":false,"allocation":[2,4,0],"guest_port":3000,"local_port":3000,"network":"computer","domain":null})).unwrap();
        let script = bootstrap("yougori-project-test", "owner", &project, &setup);
        let bash = if cfg!(windows) { "C:/Program Files/Git/bin/bash.exe" } else { "bash" };
        for mode in ["new", "stopped", "running", "foreign", "wrong-image"] {
            let fixture = format!(r#"
docker() {{
  printf '%s\n' "$*" >&2
  case "$1" in
    info|update|pull|create) return 0 ;;
    container) [ "$MODE" != new ]; return $? ;;
    inspect)
      case "$3" in
        *com.yougori.project*) if [ "$MODE" = foreign ]; then echo someone-else; else echo owner; fi ;;
        *State.Running*) if [ "$MODE" = running ]; then echo true; else echo false; fi ;;
        *Config.Image*) if [ "$MODE" = wrong-image ]; then echo old-image; else echo {}; fi ;;
        *com.yougori.proxy-port*) echo 43119 ;;
        *) return 1 ;;
      esac ;;
    *) echo 'Unexpected mutating Docker action' >&2; return 1 ;;
  esac
}}
{script}
"#, shell(&project.image()));
            let output = std::process::Command::new(bash).args(["--noprofile", "--norc", "-c", &fixture]).env("MODE", mode).output().expect("Bash is required for the cloud bootstrap test");
            let log = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.success(), matches!(mode, "new" | "stopped"), "{mode}: {log}");
            if mode == "new" {
                assert!(log.contains("create --name yougori-project-test"));
                assert!(log.contains("-p 127.0.0.1::43119"));
                assert!(log.contains("--cpus 2 --memory 4g"));
            } else if mode == "stopped" {
                assert!(log.contains("update --cpus 2"));
                assert!(!log.contains("create --name"));
            } else {
                assert!(!log.contains("update --cpus"));
                assert!(!log.contains("create --name"));
            }
            assert!(!log.lines().any(|line| line.starts_with("stop ") || line.starts_with("rm ") || line.starts_with("start ")));
        }
    }
}
