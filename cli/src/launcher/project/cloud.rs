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
    // Match the guest's development-tool capabilities, retaining package
    // installation without raw networking, device creation or administration.
    let capabilities = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE",
        "SETGID", "SETUID", "SETFCAP", "SYS_CHROOT", "AUDIT_WRITE"];
    let cap_arguments = capabilities.iter().map(|cap| format!("--cap-add {cap}")).collect::<Vec<_>>().join(" ");
    let cap_check = capabilities.iter().flat_map(|cap| [format!(r#"(eq . "{cap}")"#), format!(r#"(eq . "CAP_{cap}")"#)])
        .collect::<Vec<_>>().join(" ");
    // Docker uses its daemon's built-in seccomp profile when no container
    // override is specified. Verify that default instead of relying on the
    // newer seccomp=builtin CLI syntax, which older supported clients lack.
    let daemon_security = shell("{{range .SecurityOptions}}{{println .}}{{end}}");
    let daemon_pids = shell("{{.PidsLimit}}");
    let security_template = r#"{{ $safe := true }}{{ $nnp := false }}{{ $drop := false }}{{ $core := false }}
{{range .HostConfig.SecurityOpt}}{{if or (eq . "no-new-privileges") (eq . "no-new-privileges=true") (eq . "no-new-privileges:true")}}{{ $nnp = true }}{{else}}{{ $safe = false }}{{end}}{{end}}
{{range .HostConfig.CapDrop}}{{if or (eq . "ALL") (eq . "CAP_ALL")}}{{ $drop = true }}{{end}}{{end}}
{{range .HostConfig.CapAdd}}{{if not (or __CAP_CHECK__)}}{{ $safe = false }}{{end}}{{end}}
{{range .HostConfig.Ulimits}}{{if and (eq .Name "core") (eq .Soft 0) (eq .Hard 0)}}{{ $core = true }}{{end}}{{end}}
{{range .Mounts}}{{if eq .Type "bind"}}{{ $safe = false }}{{end}}{{end}}
{{if or .HostConfig.Privileged (eq .HostConfig.UsernsMode "host") (ne .HostConfig.PidMode "") (ne .HostConfig.UTSMode "")}}{{ $safe = false }}{{end}}
{{if not (or (eq .HostConfig.IpcMode "private") (eq .HostConfig.IpcMode "") (eq .HostConfig.IpcMode "shareable"))}}{{ $safe = false }}{{end}}
{{if not (or (eq .HostConfig.NetworkMode "bridge") (eq .HostConfig.NetworkMode "default") (eq .HostConfig.NetworkMode ""))}}{{ $safe = false }}{{end}}
{{if or (gt (len .HostConfig.Devices) 0) (gt (len .HostConfig.DeviceRequests) 0) (gt (len .HostConfig.DeviceCgroupRules) 0)}}{{ $safe = false }}{{end}}
{{if and $safe $nnp $drop $core}}safe{{else}}unsafe{{end}}"#.replace("__CAP_CHECK__", &cap_check);
    let security_check = shell(&security_template);
    let recovery = shell(&format!("This stopped project container does not enforce the current sandbox policy. Its files were kept. Security options cannot be added with docker update. Back up needed files using docker cp {container}:/workspace <backup-folder>, deliberately remove only this stopped container, then run npm run yougori-cloud again."));
    format!(r#"set -eu
command -v docker >/dev/null 2>&1 || {{ echo 'This server needs Docker Engine to run project containers. Install Docker and allow this SSH account to use it, then retry.' >&2; exit 1; }}
docker info >/dev/null
docker info -f {daemon_security} | grep -Eq '^name=seccomp,profile=(builtin|default)$' || {{ echo 'Enable Docker Engine built-in seccomp on this server before launching; no container was started.' >&2; exit 1; }}
test "$(docker info -f {daemon_pids})" = true || {{ echo 'Enable the Docker pids cgroup controller on this server before launching; no container was started.' >&2; exit 1; }}
if docker container inspect {name} >/dev/null 2>&1; then
  test "$(docker inspect -f '{{{{index .Config.Labels "com.yougori.project"}}}}' {name})" = {label} || {{ echo 'Container name belongs to another workload' >&2; exit 1; }}
  test "$(docker inspect -f '{{{{.State.Running}}}}' {name})" = false || {{ echo 'This project is already running on the server. Quit its other launcher before retrying.' >&2; exit 1; }}
  test "$(docker inspect -f '{{{{.Config.Image}}}}' {name})" = {image} || {{ echo 'Project runtime changed. Remove this stopped project container when ready, then retry; its data has been kept.' >&2; exit 1; }}
  test "$(docker inspect -f '{{{{index .Config.Labels "com.yougori.proxy-port"}}}}' {name})" = '{port}' || {{ echo 'Project proxy port changed. Remove this stopped project container when ready, then retry.' >&2; exit 1; }}
  test "$(docker inspect -f {security_check} {name} | tr -d '\n')" = safe || {{ echo {recovery} >&2; exit 1; }}
  docker update --cpus {cpu} --memory {memory}g --memory-swap {memory}g --pids-limit 4096 {name} >/dev/null
else
  docker pull {image}
  docker create --name {name} --label com.yougori.project={label} --label com.yougori.proxy-port={port} --security-opt no-new-privileges=true --cap-drop ALL {cap_arguments} --pids-limit 4096 --ulimit core=0:0 --sysctl net.ipv4.ping_group_range='0 2147483647' --cpus {cpu} --memory {memory}g --memory-swap {memory}g --log-opt max-size=10m --log-opt max-file=2 -p 127.0.0.1::{port} --entrypoint sh {image} -c {boot} >/dev/null
fi
test "$(docker inspect -f {security_check} {name} | tr -d '\n')" = safe || {{ echo {recovery} >&2; exit 1; }}
test "$(docker inspect -f '{{{{.HostConfig.PidsLimit}}}}' {name})" = 4096 || {{ echo 'Docker did not enforce the project process limit; no container was started.' >&2; exit 1; }}
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

/// Resource and access questions for a server, asked on the first launch there and with
/// --change. Answers stay while the person goes back.
struct CloudSettings {
    id: String,
    local_port: Option<u16>,
    recommended: bool,
    cpu: u32,
    memory: u32,
    port: u16,
    network: Option<Network>,
}

impl CloudSettings {
    const STEPS: usize = 5;

    fn new(folder: &Path, id: &str, old: Option<&Setup>) -> Result<Self, String> {
        Ok(Self {
            id: id.into(),
            local_port: old.map(|s| s.local_port),
            recommended: true,
            cpu: old.map_or(2, |s| s.allocation[0]),
            memory: old.map_or(4, |s| s.allocation[1]),
            port: old.map_or(package::Project::load(folder)?.port, |s| s.guest_port),
            network: None,
        })
    }

    /// Asks question `step`; returns whether it asked anything.
    async fn ask(&mut self, step: usize) -> Result<bool, String> {
        let number = |title: &str, default: u32| -> Result<u32, String> {
            ui::input(title, &default.to_string(), false, &|value| {
                value.parse::<u32>().ok().filter(|n| (1..=1024).contains(n)).map(|n| n.to_string()).ok_or("Enter a whole number from 1 to 1024".into())
            })?.parse::<u32>().map_err(|e| e.to_string())
        };
        let custom = !self.recommended;
        match step {
            0 => {
                self.recommended = ui::select(
                    "Choose project resources",
                    &[],
                    &options(&["Recommended — 2 CPU · 4 GB RAM".into(), "Customize — container limits on this server".into()]),
                    usize::from(custom),
                )? == 0;
            }
            1 if custom => self.cpu = number("CPU limit", self.cpu)?,
            2 if custom => self.memory = number("RAM limit in GB", self.memory)?,
            3 => self.port = port("Port your application listens on", self.port)?,
            4 => self.network = Some(network_with_previous(false, Some(&self.id), None, self.network.as_ref()).await?),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Writes the answers into `setup` before the questions that follow them.
    fn apply(&self, setup: &mut Setup) {
        setup.allocation = if self.recommended { [2, 4, 0] } else { [self.cpu, self.memory, 0] };
        setup.guest_port = self.port;
        setup.local_port = self.local_port.unwrap_or(self.port);
    }

    async fn finish(self, setup: &mut Setup) -> Result<(), String> {
        let (kind, domain) = access(self.network.ok_or("Choose who can open your app")?, self.port).await?;
        setup.network = kind.into();
        setup.domain = domain;
        Ok(())
    }
}

/// The server chosen for this project: its own saved settings and lock, and the answers so far.
struct Server {
    index: usize,
    id: String,
    key: String,
    path: PathBuf,
    _lock: fs::File,
    settings: Option<CloudSettings>,
    setup: Setup,
    questions: Questions,
}

impl Server {
    fn open(folder: &Path, project: &package::Project, node: &Value, index: usize, change: bool) -> Result<Self, String> {
        let id = node["id"].as_str().ok_or("Missing environment ID")?;
        let key = state_key(folder, id)?;
        let settings = yougori_cli::launcher_state::directory()?;
        fs::create_dir_all(&settings).map_err(|e| e.to_string())?;
        let path = settings.join(format!("{key}.json"));
        let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path.with_extension("lock")).map_err(|e| e.to_string())?;
        lock.try_lock().map_err(|_| "This cloud project is already open in another terminal")?;
        let old = load(&path, folder)?;
        let (settings, setup) = match old {
            Some(old) if !change => (None, old),
            old => {
                let settings = CloudSettings::new(folder, id, old.as_ref())?;
                let setup = Setup { version: 1, directory: folder.to_string_lossy().into(), environment: Some(id.into()), gpu: false,
                    needs_update: false, ..old.unwrap_or_default() };
                (Some(settings), setup)
            }
        };
        let questions = Questions::new(folder, project, &setup, change, true, None);
        Ok(Self { index, id: id.into(), key, path, _lock: lock, settings, setup, questions })
    }
}

pub(super) async fn run_in(folder: &Path, change: bool) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() { return Err("Cloud launch needs an interactive terminal to choose a connected cloud environment.".into()); }
    let folder = folder.canonicalize().map_err(|e| e.to_string())?;
    let mut project = package::Project::load(&folder)?;
    if let Some(root) = &project.workspace_root { return Err(format!("Launch from the workspace root: {}", root.display())); }
    let _session = ui::Session::start("launch --cloud", "Run your project in a connected cloud environment");
    let name = project_name(&folder)?;
    ui::intro(&clean(&name), &project.runtime_label());
    let mut stop = Stop::new();
    stop.watch();
    let engine = ui::task("Starting Yougori engine");
    let state = match stop.until(async { client::start(None).await?; call("get_platform_state", json!({})).await }).await {
        Err(_) if stop.requested() => {
            engine.clear();
            drop(stop);
            ui::outro("Cancelled");
            return Ok(130);
        }
        state => state?,
    };
    engine.done("Engine ready");
    let nodes: Vec<_> = state["environments"].as_array().ok_or("Missing environment list")?.iter().filter(|node| eligible(node)).collect();
    if nodes.is_empty() { return Err("No connected cloud environments are ready. Connect your Linux server in Yougori, then run npm run yougori-cloud again.".into()); }
    let choices: Vec<_> = nodes.iter().map(|node| clean(node["name"].as_str().unwrap_or("Cloud server"))).collect();
    // Questions read their own keys. Each one after the first offers Back; choosing another
    // server starts its own settings.
    stop.release();
    let mut server: Option<Server> = None;
    let mut steps = ui::Wizard::new();
    loop {
        if stop.requested() { return Err(ui::CANCELLED.into()); }
        let step = steps.step();
        let asked = if step == 0 {
            let current = server.as_ref().map(|server| server.index);
            match ui::select("Choose a cloud environment", &["Your project runs in its own Docker container. The SSH account must have access to Docker. Quitting stops only this project container.".into()], &options(&choices), current.unwrap_or(0)) {
                Ok(index) if current == Some(index) => Ok(true),
                Ok(index) => {
                    // Release the other server's lock before taking this one.
                    drop(server.take());
                    server = Some(Server::open(&folder, &project, nodes[index], index, change)?);
                    Ok(true)
                }
                Err(error) => Err(error),
            }
        } else {
            let server = server.as_mut().ok_or("Choose a cloud environment")?;
            match (&mut server.settings, step - 1) {
                (Some(settings), step) if step < CloudSettings::STEPS => settings.ask(step).await,
                (settings, CloudSettings::STEPS) => {
                    if let Some(settings) = settings { settings.apply(&mut server.setup); }
                    Ok(false)
                }
                (_, step) if step < CloudSettings::STEPS => Ok(false),
                (_, step) => match server.questions.ask(step - CloudSettings::STEPS - 1, &mut server.setup).await {
                    Some(asked) => asked,
                    None => break,
                },
            }
        };
        steps.next(asked)?;
    }
    drop(steps);
    let Server { index, id: node_id, key, path, _lock: lock, settings, mut setup, questions } = server.ok_or("Choose a cloud environment")?;
    questions.finish(&mut setup);
    if let Some(settings) = settings { settings.finish(&mut setup).await?; }
    let node = nodes[index];
    let id = node_id.as_str();
    project.custom_command = setup.custom_command.clone();
    add_project_shortcut(&folder, &project)?;
    save(&path, &setup)?;
    stop.watch();
    let container = format!("yougori-project-{}", &key[..24]);
    let mut started = false;
    let mut publications = Vec::<String>::new();
    let mut uploads = Vec::<String>::new();
    let result = async {
        let preparing = ui::task("Preparing cloud project container");
        live::remote_task(id, &bootstrap(&container, &key, &project, &setup), &stop.flag).await?;
        stop.check()?;
        started = true;
        exec(id, &format!("docker start {} >/dev/null && docker exec {} sh -c 'mkdir -p /workspace /yougori/launch'", shell(&container), shell(&container))).await?;
        preparing.done(&format!("Project container running on {}", clean(node["name"].as_str().unwrap_or(id))));
        if project.is_python() {
            let helper = ui::task("Preparing Python project helpers");
            live::remote_task(id, &live::container_command(Some(&container), "command -v node >/dev/null 2>&1 || { apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*; }", false), &stop.flag).await?;
            helper.done("Project helpers ready");
        }
        let remote_port = busy("Checking project access on the server", async {
            let ports = exec(id, &format!("docker port {} {}/tcp", shell(&container), live::proxy_port(setup.guest_port))).await?;
            let remote_port = ports.trim().strip_prefix("127.0.0.1:").and_then(|s| s.parse::<u16>().ok()).filter(|p| *p > 0).ok_or("Docker did not return a private project port")?;
            // Clear routes left by an interrupted previous run before starting the app.
            let services = call("list_environment_services", json!({"environmentId":id})).await?;
            for publication in services["publications"].as_array().into_iter().flatten().filter(|p| p["port"] == remote_port) {
                if let Some(id) = publication["id"].as_str() {
                    call("unpublish_environment_service", json!({"publicationId":id})).await?;
                }
            }
            Ok(remote_port)
        }).await?;
        let mut syncing = ui::task("Syncing project to cloud");
        let filter = sync::Filter::load(&folder, setup.env_files)?;
        let (source, flag) = (folder.clone(), stop.flag.clone());
        // A stop ends the scan at its next folder; it is waited for, as the CLI cannot exit before.
        let manifest = tokio::task::spawn_blocking(move || sync::scan_until(&source, &filter, &flag))
            .await
            .map_err(|e| e.to_string())??;
        let sync_path = path.with_extension("sync.json");
        let mut saved = sync::Saved::load(&sync_path);
        let remote_token = stop.until(exec(id, &live::container_command(Some(&container), "cat /yougori/launch/sync-token 2>/dev/null || true", false))).await?;
        let reconcile = saved.needs_reconcile(id, &remote_token);
        let copied = stop.until(exec(id, &live::container_command(Some(&container), "if [ -d /workspace ] && [ -n \"$(ls -A /workspace)\" ]; then printf existing; fi", false))).await?.trim() != "existing";
        let mut initial_databases = std::collections::BTreeSet::new();
        if copied {
            syncing.detail(&format!("{} files · {}", manifest.len(), ui::bytes(manifest.values().map(|(size, _)| size).sum())));
            syncing.copy_status("Preparing project files");
            let staging = stage_project(&folder, &manifest, &syncing, &stop.flag).await?;
            syncing.detail(&format!("{} files · {}", manifest.len(), ui::bytes(manifest.values().map(|(size, _)| size).sum())));
            syncing.copy_status("Waiting for copy progress");
            let copy = copy_into(id, json!({"environmentId":id,"paths":[staging.path().join("project")]}), &syncing, &stop).await?;
            syncing.set("Setting up project sync");
            let destination = copy["destination"].as_str().ok_or("Missing cloud copy destination")?;
            let copy_command = uploaded_project(destination, &container)?;
            uploads.push(destination.into());
            live::remote_task(id, &copy_command, &stop.flag).await?;
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
        stop.check()?;
        let mut live = stop.until(live::Live::prepare_target(id, &folder, &project, &manifest, setup.two_way, setup.guest_port, &sync_path, saved, Some(container.clone()), remote_port)).await?;
        live.priority = setup.sync_priority.unwrap_or_default();
        live.env_files = setup.env_files;
        live.initial_databases = initial_databases;
        let running = async {
            if !setup.two_way && !copied && reconcile { stop.until(live.reconcile_one_way(&manifest)).await?; }
            if setup.two_way { stop.until(live.sync_both(setup.env_files)).await?; } else { stop.until(live.sync_to(manifest)).await?; }
            stop.check()?;
            syncing.done(if setup.two_way { "Two-way sync checked" } else { "Project files up to date" });
            let publishing = ui::task("Setting up project access");
            let network = match setup.network.as_str() { "lan" => Network::Lan, "quick" => Network::Quick, "domain" => Network::Domain(setup.domain.clone().ok_or("Missing saved domain")?), _ => Network::Computer };
            if !matches!(network, Network::Computer | Network::Lan) {
                if let Some(params) = publish_params(&network, id, remote_port) {
                    let result = stop.until(call("publish_environment_service", params)).await?;
                    if let Some(id) = result["id"].as_str() { publications.push(id.into()); }
                    for url in result["urls"].as_array().into_iter().flatten().filter_map(Value::as_str) { ui::info(&format!("public  {}", clean(url))); }
                }
            }
            let kind = if matches!(network, Network::Lan) { "local" } else { "loopback" };
            let params = json!({"environmentId":id,"port":remote_port,"kind":kind});
            let mut requested = params.clone();
            requested["hostPort"] = json!(setup.local_port);
            let result = match stop.until(call("publish_environment_service", requested)).await {
                Err(error) if !stop.requested() && port_in_use(&error) => stop.until(call("publish_environment_service", params)).await?,
                result => result?,
            };
            if let Some(id) = result["id"].as_str() { publications.push(id.into()); }
            setup.local_port = result["hostPort"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).ok_or("Missing local port")?;
            save(&path, &setup)?;
            publishing.done(&format!("Available at http://localhost:{}", setup.local_port));
            stop.check()?;
            stop.until(live.start()).await?;
            ui::outro(&format!("$ {}", clean(&project.command_label())));
            // The dev server's view reads its own keys, Ctrl+C included.
            stop.release();
            let watched = live.watch(&format!("{} · cloud", clean(&name)), setup.local_port, setup.env_files, setup.two_way, setup.continuous_sync, false, &stop.flag).await;
            stop.watch();
            watched
        }.await;
        if running.is_ok() && setup.continuous_sync {
            let syncing = ui::task("Syncing your latest changes");
            let synced = live.sync_current(setup.env_files, setup.two_way).await;
            syncing.clear();
            if let Err(error) = synced { ui::warn(&format!("Final sync incomplete: {}. Cloud project files are kept for the next launch.", clean(&error))); }
        }
        live.close().await;
        running
    }.await;
    // A Ctrl+C during the cleanup never hides an error the launch already had.
    let interrupted = stop.requested();
    stop.watch();
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
    drop(stop);
    drop(lock);
    if cleanup_errors.is_empty() { stopping.done("Project stopped; cloud environment stays connected"); }
    else { stopping.fail("Could not confirm project cleanup"); return Err(format!("Check container {container} on the server: {}", cleanup_errors.join("; "))); }
    ui::outro("npm run yougori-cloud starts again · npm run yougori-cloud -- --change edits this server's project settings");
    match result {
        Err(_) if interrupted => Ok(130),
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
        for mode in ["new", "stopped", "running", "foreign", "wrong-image", "legacy-security", "seccomp-disabled", "pids-disabled", "pids-unenforced"] {
            let fixture = format!(r#"
docker() {{
  printf '%s\n' "$*" >&2
  case "$1" in
    info)
      if [ "${{2:-}}" = -f ]; then
        case "$3" in
          *SecurityOptions*) if [ "$MODE" = seccomp-disabled ]; then echo name=apparmor; else echo name=seccomp,profile=builtin; fi ;;
          *PidsLimit*) if [ "$MODE" = pids-disabled ]; then echo false; else echo true; fi ;;
          *) return 1 ;;
        esac
      fi ;;
    update|pull|create) return 0 ;;
    container) [ "$MODE" != new ]; return $? ;;
    inspect)
      case "$3" in
        *com.yougori.project*) if [ "$MODE" = foreign ]; then echo someone-else; else echo owner; fi ;;
        *State.Running*) if [ "$MODE" = running ]; then echo true; else echo false; fi ;;
        *Config.Image*) if [ "$MODE" = wrong-image ]; then echo old-image; else echo {}; fi ;;
        *com.yougori.proxy-port*) echo 43119 ;;
        *'$safe := true'*) if [ "$MODE" = legacy-security ]; then echo unsafe; else echo safe; fi ;;
        *HostConfig.PidsLimit*) if [ "$MODE" = pids-unenforced ]; then echo 0; else echo 4096; fi ;;
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
                assert!(log.contains("--security-opt no-new-privileges=true --cap-drop ALL"));
                assert!(log.contains("--pids-limit 4096 --ulimit core=0:0"));
                assert!(!log.contains("--security-opt seccomp=unconfined"));
            } else if mode == "stopped" {
                assert!(log.contains("update --cpus 2"));
                assert!(!log.contains("create --name"));
            } else if mode == "pids-unenforced" {
                assert!(log.contains("update --cpus 2"));
                assert!(log.contains("did not enforce the project process limit"));
            } else {
                assert!(!log.contains("update --cpus"));
                assert!(!log.contains("create --name"));
            }
            assert!(!log.lines().any(|line| line.starts_with("stop ") || line.starts_with("rm ") || line.starts_with("start ")));
        }
    }

    #[test]
    #[ignore = "requires Docker CLI; uses only a fake read-only loopback API, never a Docker daemon"]
    fn cloud_security_policy_evaluates_actual_docker_inspection_templates() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::{Duration, Instant};
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let setup: Setup = serde_json::from_value(json!({"version":1,"directory":folder.path(),"environment":"env-cloud","gpu":false,"allocation":[2,4,0],"guest_port":3000,"local_port":3000,"network":"computer","domain":null})).unwrap();
        let script = bootstrap("yougori-project-test", "owner", &project, &setup);
        let beginning = script.find("'{{ $safe := true }}").unwrap() + 1;
        let end = beginning + script[beginning..].find('\'').unwrap();
        let template = &script[beginning..end];
        let baseline = json!({"Id":"a".repeat(64),"Name":"/yougori-project-test","Mounts":[],"HostConfig":{
            "SecurityOpt":["no-new-privileges:true"],"CapDrop":["ALL"],"CapAdd":["CHOWN","DAC_OVERRIDE","FOWNER","FSETID","KILL","NET_BIND_SERVICE","SETGID","SETUID","SETFCAP","SYS_CHROOT","AUDIT_WRITE"],
            "Ulimits":[{"Name":"core","Soft":0,"Hard":0}],"Privileged":false,"UsernsMode":"","PidMode":"","UTSMode":"","IpcMode":"private","NetworkMode":"bridge","Devices":[],"DeviceRequests":[],"DeviceCgroupRules":[]}});
        let mut cases = vec![("enforced", baseline.clone(), true)];
        for (field, value) in [("SecurityOpt", json!([])), ("SecurityOpt", json!(["no-new-privileges:true","seccomp=unconfined"])),
            ("SecurityOpt", json!(["no-new-privileges:true","apparmor=unconfined"])), ("CapDrop", json!([])),
            ("CapAdd", json!(["SYS_ADMIN"])), ("CapAdd", json!(["NET_RAW"])), ("Privileged", json!(true)),
            ("PidMode", json!("host")), ("PidMode", json!("container:other")), ("IpcMode", json!("host")),
            ("NetworkMode", json!("host")), ("UTSMode", json!("host")), ("UsernsMode", json!("host")),
            ("DeviceCgroupRules", json!(["a *:* rwm"])), ("Ulimits", json!([{"Name":"core","Soft":-1,"Hard":-1}]))] {
            let mut unsafe_case = baseline.clone();
            unsafe_case["HostConfig"][field] = value;
            cases.push((field, unsafe_case, false));
        }
        let mut bind = baseline.clone();
        bind["Mounts"] = json!([{"Type":"bind","Source":"/","Destination":"/host"}]);
        cases.push(("host bind", bind, false));
        for (name, inspection, expected) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                            let mut header = Vec::new();
                            while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                                let mut byte = [0];
                                if socket.read(&mut byte).unwrap_or(0) != 1 { break; }
                                header.push(byte[0]);
                            }
                            let request = String::from_utf8_lossy(&header);
                            if request.contains("/containers/") && request.contains("/json") {
                                let body = serde_json::to_vec(&inspection).unwrap();
                                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                                socket.write_all(&body).unwrap();
                                return;
                            }
                            socket.write_all(b"HTTP/1.1 200 OK\r\nAPI-Version: 1.47\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").unwrap();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
                        Err(error) => panic!("{error}"),
                    }
                }
                panic!("Docker CLI did not inspect the fake endpoint");
            });
            let output = std::process::Command::new(if cfg!(windows) { "docker.exe" } else { "docker" })
                .args(["inspect", "--format", template, "yougori-project-test"])
                .env("DOCKER_HOST", format!("tcp://{address}"))
                .env("DOCKER_API_VERSION", "1.47").env("DOCKER_CONFIG", folder.path())
                .env_remove("DOCKER_CONTEXT").env_remove("DOCKER_TLS_VERIFY").env_remove("DOCKER_CERT_PATH")
                .output().expect("Docker CLI required; no Docker daemon is used");
            server.join().unwrap();
            assert!(output.status.success(), "{name}: {}", String::from_utf8_lossy(&output.stderr));
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), if expected { "safe" } else { "unsafe" }, "{name}");
        }
    }
}
