//! Live project sessions. Only acknowledged writes become the next sync baseline.
use super::{call, clean, diagnose, package, plan, project::shell, stream::Stream, sync, ui};
mod two_way;
mod databases;
mod folders;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};
use notify::Watcher;
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub fn proxy_port(app: u16) -> u16 {
    if app == 43119 {
        43120
    } else {
        43119
    }
}
fn nonce() -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(format!(
            "{}:{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ))
    )[..24]
        .into()
}

struct Session {
    environment: String,
    id: String,
    offset: u64,
    stream: Stream,
}
impl Session {
    async fn open(environment: &str, command: &str, nonce: &str) -> Result<Self, String> {
        let mut session = Self {
            environment: environment.into(),
            id: format!("term-cli-{}", self::nonce()),
            offset: 0,
            stream: Stream::new(nonce, None, true).protocol(),
        };
        let (cols, rows) = terminal::size().unwrap_or((100, 30));
        session
            .action("create", json!({"cols":cols,"rows":rows}))
            .await?;
        let opened = async {
            session.write(format!("stty -echo; PS1=''; unset PROMPT_COMMAND; printf '\\n[%s:%s]\\n' 'yougori-{nonce}' 'shell-ready'\r").as_bytes()).await?;
            session.wait("shell-ready").await?;
            session.write(format!("exec {command}\r").as_bytes()).await
        }.await;
        if let Err(error) = opened {
            let _ = session.action("close", json!({})).await;
            return Err(error);
        }
        Ok(session)
    }
    async fn action(&self, action: &str, mut params: Value) -> Result<Value, String> {
        params["environmentId"] = json!(self.environment);
        params["sessionId"] = json!(self.id);
        params["action"] = json!(action);
        call("terminal_action", params).await
    }
    async fn write(&self, bytes: &[u8]) -> Result<(), String> {
        // Bound each control request and PTY write; a file can span several frames.
        for chunk in bytes.chunks(12 * 1024) {
            self.action("write", json!({"data":B64.encode(chunk)}))
                .await?;
        }
        Ok(())
    }
    async fn read(&mut self) -> Result<(Vec<u8>, Vec<String>), String> {
        let result = self.action("read", json!({"offset":self.offset})).await?;
        self.offset = result["offset"].as_u64().unwrap_or(self.offset);
        let data = B64
            .decode(result["data"].as_str().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        let output = self.stream.feed(&data);
        if result["done"] == true {
            return Err(
                "The project terminal ended. Run yougori launch again to reconnect.".into(),
            );
        }
        Ok(output)
    }
    async fn wait(&mut self, expected: &str) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (_, events) = self.read().await?;
            for event in &events {
                if let Some(error) = event.strip_prefix("error:") {
                    return Err(format!(
                        "File sync failed: {}",
                        String::from_utf8_lossy(&B64.decode(error).unwrap_or_default())
                    ));
                }
            }
            if events.iter().any(|e| e == expected) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("The container did not acknowledge file sync. Its saved sync state was not updated.".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn barrier(&mut self) -> Result<(), String> {
        let seq = nonce();
        self.write(format!("B {seq}\n").as_bytes()).await?;
        self.wait(&format!("ack:{seq}")).await
    }
}

pub struct Live {
    receiver: Session,
    dev: Option<Session>,
    folder: PathBuf,
    saved: sync::Saved,
    state_path: PathBuf,
    nonce: String,
    app_port: u16,
    custom_command: Option<String>,
    crashed: bool,
    container: Option<String>,
    service_port: u16,
    conflicts: std::collections::BTreeSet<String>,
    local_hashes: std::collections::BTreeMap<String, ((u64, i64), String)>,
    pub priority: sync::Priority,
    database_helper: Option<databases::Helper>,
    database_files: std::collections::BTreeSet<String>,
    database_probes: std::collections::BTreeMap<String, (u64, i64)>,
    database_versions: std::collections::BTreeMap<String, databases::Revision>,
    /// Known snapshots just bulk-copied into an empty, stopped project workspace.
    pub initial_databases: std::collections::BTreeSet<String>,
    remote_directories: std::collections::BTreeSet<String>,
    folder_conflicts: std::collections::BTreeSet<String>,
    pub env_files: bool,
    /// Path identities left untouched by the current two-way pass.
    held: std::collections::BTreeSet<String>,
    /// Warnings already shown in this session.
    warned: std::collections::BTreeSet<String>,
    /// Container change stamp and checksum of each file from the previous pass.
    remote_stamps: std::collections::BTreeMap<String, (String, String)>,
    view: Option<View>,
}

/// The running dev-server view while `watch` is active. Sync passes keep its log
/// flowing and notice Ctrl+C or q instead of freezing it.
struct View {
    display: Stream,
    log: Vec<u8>,
    /// Dev-server markers and keys read during a sync pass, handled after it.
    events: Vec<String>,
    input: Vec<Event>,
    interactive: bool,
    quit: bool,
    ended: bool,
    pumped: Instant,
}

impl View {
    fn record(&mut self, output: &[u8]) {
        self.log.extend_from_slice(output);
        if self.log.len() > 96 * 1024 {
            self.log.drain(..self.log.len() - 64 * 1024);
        }
    }
}

const STOPPED: &str = "Sync stopped because the project launcher is closing";

pub(super) fn container_command(container: Option<&str>, command: &str, terminal: bool) -> String {
    match container {
        Some(name) => format!("docker exec {} {} sh -c {}", if terminal { "-it" } else { "-i" }, shell(name), shell(command)),
        None => command.into(),
    }
}

/// Visible above the footer while startup is pending, including the initial
/// terminal connection and service lookup. Clear on quit as well as readiness.
struct StartupProgress(Option<ui::Task>);

impl StartupProgress {
    fn new() -> Self {
        Self(Some(ui::task("Starting dev server · attempt 1/2")))
    }

    fn show(&mut self, text: &str) {
        match &mut self.0 {
            Some(task) => task.set(text),
            None => self.0 = Some(ui::task(text)),
        }
        ui::dash(|d| d.status(ui::Tone::Busy, text));
    }

    fn clear(&mut self) {
        if let Some(task) = self.0.take() { task.clear(); }
    }
}

impl Drop for StartupProgress {
    fn drop(&mut self) { self.clear(); }
}

fn failure_details(event: &str) -> Option<(String, Vec<String>)> {
    let parts: Vec<_> = event.split(':').collect();
    let ["failure", phase, code, reason, memory, cpu] = parts.as_slice() else { return None };
    let phase = match *phase {
        "install" => "Dependency installation",
        "run" => "Dev server",
        _ => return None,
    };
    let code = code.parse::<u8>().ok()?;
    let summary = if *reason == "oom" {
        format!("{phase}: out of memory (exit {code})")
    } else {
        format!("{phase} failed (exit {code})")
    };
    let mut details = vec![match *reason {
        "oom" => "The container's OOM counter increased during this step: Linux killed a process because memory ran out.".into(),
        "killed" => "The process was forcibly killed (SIGKILL). Running out of memory is possible, but the container did not confirm the cause.".into(),
        _ => match code {
            126 => "The command could not be executed. Check its permissions and the error output above.".into(),
            127 => "A command was not found. Check the executable name and installed dependencies in the output above.".into(),
            143 => "The process received a termination signal (SIGTERM). Check whether another process stopped it.".into(),
            _ => "The command reported a failure. Its output above contains the package or application error; no memory kill was confirmed.".into(),
        },
    }];
    let mut limits = Vec::new();
    if let Ok(cpu) = cpu.parse::<f64>() {
        if cpu.is_finite() && cpu > 0.0 { limits.push(format!("{cpu} CPU")); }
    }
    if let Ok(bytes) = memory.parse::<u64>() {
        if bytes > 0 { limits.push(format!("{} RAM", ui::size_gb(bytes as f64 / 1_073_741_824.0))); }
    }
    if !limits.is_empty() { details.push(format!("Container limit: {}.", limits.join(" · "))); }
    if matches!(*reason, "oom" | "killed") {
        details.push("Memory usage can drop immediately after a process is killed. Press q, then run yougori launch --change to increase RAM before retrying.".into());
    }
    Some((summary, details))
}

async fn execute(id: &str, command: &str) -> Result<(), String> {
    let reply = call(
        "execute_environment_command",
        json!({"request":{"environmentId":id,"command":command}}),
    )
    .await?;
    if reply["exitCode"] != 0 {
        return Err(format!(
            "Project helper setup failed: {}{}",
            reply["stdout"].as_str().unwrap_or(""),
            reply["stderr"].as_str().unwrap_or("")
        ));
    }
    Ok(())
}

/// The supervisor's settings. `files` is what the container has of the project, which decides the
/// package folders to install; with two-way sync the container's copy of scripts stays unchanged.
fn environment(folder: &Path, project: &package::Project, files: &sync::Manifest, two_way: bool, port: u16, nonce: &str) -> String {
    let python = if project.is_python() { "export PATH=/yougori/venv/bin:$PATH\nexport PYTHONUNBUFFERED=1\nexport PIP_NO_CACHE_DIR=1\n" } else { "" };
    let installs = plan::lines(&plan::installs(folder, project, files));
    format!("YOUGORI_APP_PORT={port}\nYOUGORI_PROXY_PORT={}\nYOUGORI_NONCE={}\nYOUGORI_INSTALLS={}\nYOUGORI_RUN={}\nYOUGORI_TWO_WAY={}\nexport npm_config_cache=/yougori/cache/npm\nexport YARN_CACHE_FOLDER=/yougori/cache/yarn\nexport PNPM_HOME=/yougori/cache/pnpm\nexport BUN_INSTALL_CACHE_DIR=/yougori/cache/bun\n{python}", proxy_port(port), shell(nonce), shell(&installs), shell(&project.run_command(port)), u8::from(two_way))
}

/// Run slow cloud preparation through a PTY instead of the bounded exec API.
/// Always close that terminal, including cancellation and command failure.
pub(super) async fn remote_task(id: &str, command: &str, cancel: &AtomicBool) -> Result<(), String> {
    let token = nonce();
    let script = format!("sh -c {}; code=$?; printf '\\n[yougori-{token}:complete:%s]\\n' \"$code\"; sleep 86400", shell(command));
    let mut session = Session::open(id, &format!("sh -c {}", shell(&script)), &token).await?;
    let deadline = Instant::now() + Duration::from_secs(30 * 60);
    let result = async {
        loop {
            if cancel.load(Ordering::Relaxed) { return Err("Cloud project setup cancelled".into()); }
            if Instant::now() > deadline { return Err("Cloud project setup exceeded 30 minutes".into()); }
            let (output, events) = session.read().await?;
            ui::write(&output);
            for event in events {
                if let Some(code) = event.strip_prefix("complete:") {
                    return if code == "0" { Ok(()) } else { Err(format!("Cloud project setup failed (exit {code}). See the command output above.")) };
                }
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }.await;
    let _ = session.action("close", json!({})).await;
    result
}

impl Live {
    /// Explicit handoff. Refresh checksum caches because on-demand sessions
    /// have no watcher to invalidate them while the user works elsewhere.
    pub async fn handoff(&mut self, env_files: bool, two_way: bool, direction: sync::Direction) -> Result<usize, String> {
        if !two_way && direction != sync::Direction::ToContainer {
            return Err("Enable two-way sync in project settings before bringing container changes to this computer".into());
        }
        self.local_hashes.clear();
        self.database_probes.clear();
        self.database_versions.clear();
        self.initial_databases.clear();
        if two_way { self.sync_direction(env_files, direction).await }
        else { self.sync_current(env_files, false).await }
    }

    async fn choose_handoff(&mut self, env_files: bool, two_way: bool) -> Result<(), String> {
        let priority = if !two_way { "One-way sync: this computer is the source." } else {
            match self.priority {
                sync::Priority::Local => "Conflict priority: this computer wins. Receive leaves these conflicts pending for Sync to container.",
                sync::Priority::Remote => "Conflict priority: container wins. Send leaves these conflicts pending for Sync to this computer.",
                sync::Priority::KeepBoth => "Conflict priority: keep both versions until you resolve them.",
            }
        };
        let receive = ui::Choice::new("Sync to this computer", if two_way { "bring container changes home" } else { "enable two-way sync in project settings" });
        let mut choices = vec![
            ui::Choice::new("Sync to container", "send changes from this computer"),
            if two_way { receive } else { receive.disabled() },
        ];
        if two_way { choices.push(ui::Choice::new("Sync both ways", "exchange changes using your saved conflict priority")); }
        choices.push(ui::Choice::new("Back", "keep working without syncing"));
        let selected = match ui::select(
            "Sync project",
            &["Includes code, files, folders and SQLite database records. Pause editing on the destination while switching.".into(), priority.into(), "Changes waiting to go the other way are kept for the next sync.".into()],
            &choices, 0,
        ) { Err(error) if error == ui::CANCELLED => return Ok(()), result => result? };
        let direction = match selected { 0 => sync::Direction::ToContainer, 1 => sync::Direction::ToComputer, 2 if two_way => sync::Direction::Both, _ => return Ok(()) };
        let syncing = ui::task(&choices[selected].label);
        match self.handoff(env_files, two_way, direction).await {
            Ok(count) => {
                let message = format!("{} · {count} changes", choices[selected].label);
                syncing.done(&message);
                ui::dash(|d| d.note(&message));
            }
            Err(error) => {
                syncing.fail("Sync incomplete — both copies kept; retry from the Sync menu");
                ui::warn(&clean(&error));
            }
        }
        Ok(())
    }

    pub async fn sync_current(&mut self, env_files: bool, two_way: bool) -> Result<usize, String> {
        self.env_files = env_files;
        if two_way { return self.sync_both(env_files).await; }
        let folder = self.folder.clone();
        let next = tokio::task::spawn_blocking(move || {
            sync::scan(&folder, &sync::Filter::load(&folder, env_files)?)
        }).await.map_err(|e| e.to_string())??;
        self.sync_to(next).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare(
        id: &str,
        folder: &Path,
        project: &package::Project,
        files: &sync::Manifest,
        two_way: bool,
        port: u16,
        state_path: &Path,
        saved: sync::Saved,
    ) -> Result<Self, String> {
        Self::prepare_target(id, folder, project, files, two_way, port, state_path, saved, None, proxy_port(port)).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_target(
        id: &str, folder: &Path, project: &package::Project, files: &sync::Manifest, two_way: bool, port: u16,
        state_path: &Path, mut saved: sync::Saved, container: Option<String>, service_port: u16,
    ) -> Result<Self, String> {
        if saved.environment != id { saved.databases.clear(); saved.directories.clear(); }
        let nonce = nonce();
        let env = environment(folder, project, files, two_way, port, &nonce);
        let mut command = "set -eu; mkdir -p /workspace /yougori/launch /yougori/cache; ".to_owned();
        if project.is_python() {
            command.push_str("if ! command -v node >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*; fi; ");
        }
        execute(id, &container_command(container.as_deref(), &command, false)).await?;
        let preparing = ui::task("Preparing project sync helpers");
        let helpers = [
            ("proxy.cjs", include_str!("assets/proxy.cjs")),
            ("sync.cjs", include_str!("assets/sync.cjs")),
            ("two-way.cjs", include_str!("assets/two-way.cjs")),
            ("sqlite.cjs", include_str!("assets/sqlite.cjs")),
            ("prepare.cjs", include_str!("assets/prepare.cjs")),
            ("dev.sh", include_str!("assets/dev.sh")),
            ("dev.env", env.as_str()),
        ];
        preparing.progress("Installing sync helpers", 0, helpers.len() as u64, "files");
        for (index, (name, content)) in helpers.iter().enumerate() {
            preparing.detail(name);
            let command = format!(
                "printf '%s' {} | base64 -d > /yougori/launch/{name}; ",
                shell(&B64.encode(content.replace("\r\n", "\n")))
            );
            execute(id, &container_command(container.as_deref(), &command, false)).await?;
            preparing.progress("Installing sync helpers", index as u64 + 1, helpers.len() as u64, "files");
        }
        preparing.copy_status("Opening sync connection");
        let mut receiver = Session::open(
            id,
            &container_command(container.as_deref(), &format!("node /yougori/launch/sync.cjs {nonce}"), true),
            &nonce,
        )
        .await?;
        if let Err(error) = receiver.wait("ready").await {
            let _ = receiver.action("close", json!({})).await;
            return Err(error);
        }
        preparing.clear();
        Ok(Self {
            receiver,
            dev: None,
            folder: folder.into(),
            saved,
            state_path: state_path.into(),
            nonce,
            app_port: port,
            custom_command: project.custom_command.clone(),
            crashed: false,
            container,
            service_port,
            conflicts: Default::default(),
            local_hashes: Default::default(),
            priority: Default::default(),
            database_helper: None,
            database_files: Default::default(),
            database_probes: Default::default(),
            database_versions: Default::default(),
            initial_databases: Default::default(),
            remote_directories: Default::default(),
            folder_conflicts: Default::default(),
            env_files: false,
            held: Default::default(),
            warned: Default::default(),
            remote_stamps: Default::default(),
            view: None,
        })
    }

    /// Shows dev-server output and reads keys during a long sync pass, at most every
    /// 100 ms. Ctrl+C or q stops the pass so the launcher can close.
    pub(super) async fn pump(&mut self) -> Result<(), String> {
        let Some(view) = self.view.as_mut() else { return Ok(()) };
        if view.quit {
            return Err(STOPPED.into());
        }
        if view.pumped.elapsed() < Duration::from_millis(100) {
            return Ok(());
        }
        view.pumped = Instant::now();
        if let Some(dev) = self.dev.as_mut().filter(|_| !view.ended) {
            let result = dev.action("read", json!({"offset":dev.offset})).await?;
            dev.offset = result["offset"].as_u64().unwrap_or(dev.offset);
            let data = B64.decode(result["data"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
            let (output, events) = view.display.feed(&data);
            ui::write(&output);
            view.record(&output);
            view.events.extend(events);
            view.ended = result["done"] == true;
        }
        while view.interactive && event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
            let event = event::read().map_err(|e| e.to_string())?;
            if let Event::Key(key) = &event {
                let shortcut = ui::footer_visible() && key.modifiers.difference(KeyModifiers::SHIFT).is_empty();
                let interrupt = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                if key.kind != KeyEventKind::Release && (interrupt || (shortcut && key.code == KeyCode::Char('q'))) {
                    view.quit = true;
                    return Err(STOPPED.into());
                }
            }
            view.input.push(event);
        }
        Ok(())
    }

    /// Sends the files that differ from the container's copy; returns how many changed.
    pub async fn sync_to(&mut self, manifest: sync::Manifest) -> Result<usize, String> {
        self.discover_databases(&manifest);
        self.database_files.extend(self.saved.databases.keys().cloned());
        let (mut changed, mut removed) = self.saved.changes(&manifest);
        changed.retain(|p| !sync::database_member(p, &self.database_files));
        // Links are not followed. A folder replaced by a link keeps the container's
        // earlier copy rather than deleting it there.
        removed.retain(|p| !sync::database_member(p, &self.database_files) && !sync::under_link(&self.folder, p));
        self.saved.pending.retain(|p| !sync::database_member(p, &self.database_files));
        self.keep_remote_links(&mut changed, &mut removed).await?;
        let total = (changed.len() + removed.len()) as u64;
        let progress = (total > 0).then(|| ui::task("Syncing changed project files"));
        let mut completed = 0;
        if let Some(progress) = &progress { progress.progress("Syncing files", 0, total, "files"); }
        let copied_dependencies = changed.iter().chain(&removed)
            .any(|p| p.split('/').any(|part| part == "node_modules"));
        let restart = self.crashed
            || copied_dependencies
            || (!changed.is_empty() || !removed.is_empty()) && package::Project::load(&self.folder)?.is_python()
            || changed
                .iter()
                .chain(&removed)
                .any(|p| sync::needs_install(p));
        // Journal the paths before touching the guest. Recovery compares these files,
        // including an interrupted addition subsequently deleted on the host.
        if !changed.is_empty() || !removed.is_empty() {
            self.saved.pending.extend(changed.iter().chain(&removed).cloned());
            self.saved.save(&self.state_path)?;
            self.receiver.write(b"T incomplete\n").await?;
            self.receiver.barrier().await?;
        } else if !self.saved.token.is_empty() && !self.saved.two_way
            && self.saved.environment == self.receiver.environment && !restart {
            if self.saved.files != manifest {
                self.saved.files = manifest;
                self.saved.save(&self.state_path)?;
            }
            return Ok(self.sync_databases(false).await? + self.sync_folders(false).await?);
        }
        for path in &removed {
            if let Some(progress) = &progress { progress.detail(&clean(path)); }
            self.receiver
                .write(sync::delete_op(path).as_bytes())
                .await?;
            self.receiver.barrier().await?;
            completed += 1;
            if let Some(progress) = &progress { progress.progress("Syncing files", completed, total, "files"); }
            self.pump().await?;
        }
        for path in &changed {
            if let Some(progress) = &progress { progress.detail(&clean(path)); }
            // Bound memory even when a file grows after scanning. Large files use
            // chunked uploads with a checksum and atomic rename at completion.
            let mut data = Vec::new();
            fs::File::open(self.folder.join(path))
                .and_then(|file| file.take(64 * 1024 + 1).read_to_end(&mut data))
                .map_err(|e| format!("Cannot sync {path}: {e}"))?;
            if data.len() > 64 * 1024 {
                self.sync_large_file(path).await?;
            } else {
                self.receiver.write(sync::write_op(path, &data).as_bytes()).await?;
            }
            self.receiver.barrier().await?;
            completed += 1;
            if let Some(progress) = &progress { progress.progress("Syncing files", completed, total, "files"); }
            self.pump().await?;
        }
        if let Some(progress) = progress { progress.clear(); }
        if copied_dependencies {
            execute(&self.receiver.environment, &container_command(
                self.container.as_deref(), "rm -f /yougori/launch/installed-*", false,
            )).await?;
        }
        if restart && self.dev.is_some() {
            let mut project = package::Project::load(&self.folder)?;
            project.custom_command = self.custom_command.clone();
            let env = environment(&self.folder, &project, &manifest, false, self.app_port, &self.nonce);
            execute(
                &self.receiver.environment,
                &container_command(self.container.as_deref(), &format!(
                    "printf '%s' {} | base64 -d > /yougori/launch/dev.env",
                    shell(&B64.encode(env))
                ), false),
            )
            .await?;
            self.receiver.write(b"K\n").await?;
        }
        let token = nonce();
        self.receiver
            .write(format!("T {token}\n").as_bytes())
            .await?;
        self.receiver.barrier().await?;
        self.saved = sync::Saved {
            copy_version: sync::COPY_VERSION,
            token,
            environment: self.receiver.environment.clone(),
            files: manifest,
            databases: std::mem::take(&mut self.saved.databases),
            directories: std::mem::take(&mut self.saved.directories),
            ..Default::default()
        };
        self.saved.save(&self.state_path)?;
        Ok(changed.len() + removed.len() + self.sync_databases(false).await? + self.sync_folders(false).await?)
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let starting = ui::task("Opening project terminal");
        self.dev = Some(
            Session::open(
                &self.receiver.environment,
                &container_command(self.container.as_deref(), "bash /yougori/launch/dev.sh", true),
                &self.nonce,
            )
            .await?,
        );
        starting.clear();
        Ok(())
    }

    pub async fn close(&self) {
        if let Some(dev) = &self.dev {
            let _ = dev.action("close", json!({})).await;
        }
        let _ = self.receiver.action("close", json!({})).await;
    }

    async fn links(&self) -> Result<Vec<(String, String)>, String> {
        let result = call(
            "list_environment_services",
            json!({"environmentId":self.receiver.environment}),
        )
        .await?;
        Ok(result["publications"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| {
                if p["port"] != self.service_port { return None; }
                let urls = p["urls"].as_array()?;
                match p["kind"].as_str()? {
                    "cloudflare" => urls
                        .first()
                        .and_then(Value::as_str)
                        .map(|url| ("public".to_string(), clean(url))),
                    "local" => urls
                        .get(1)
                        .and_then(Value::as_str)
                        .map(|url| ("network".to_string(), clean(url))),
                    _ => None,
                }
            })
            .collect())
    }

    async fn all_links(&self, local: &str) -> Vec<(String, String)> {
        let mut links = vec![("local".to_string(), local.to_string())];
        links.extend(self.links().await.unwrap_or_default());
        links
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn watch(
        &mut self,
        name: &str,
        local_port: u16,
        env_files: bool,
        two_way: bool,
        continuous_sync: bool,
        gpu: bool,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        // No alternate screen: normal terminal scrollback keeps the full development log.
        let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
        self.view = Some(View {
            display: Stream::new(&self.nonce, Some((self.app_port, local_port)), ui::color()),
            // This attempt's output, so a failure is explained from what it printed.
            log: Vec::new(),
            events: Vec::new(),
            input: Vec::new(),
            interactive,
            quit: false,
            ended: false,
            pumped: Instant::now(),
        });
        let result = self.watching(name, local_port, env_files, two_way, continuous_sync, gpu, cancel, interactive).await;
        self.view = None;
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn watching(
        &mut self,
        name: &str,
        local_port: u16,
        env_files: bool,
        two_way: bool,
        continuous_sync: bool,
        gpu: bool,
        cancel: &AtomicBool,
        interactive: bool,
    ) -> Result<(), String> {
        let mut startup = StartupProgress::new();
        let mut attempt = 1;
        let mut failure_summary = String::new();
        let mut served = false;
        let project = package::Project::load(&self.folder).ok();
        let command = self.custom_command.clone().or_else(|| project.as_ref().map(package::Project::command_label)).unwrap_or_default();
        let node = project.as_ref().and_then(|p| match p.runtime { package::Runtime::Node(major) => Some(major), package::Runtime::Python(_) => None });
        let (tx, rx) = std::sync::mpsc::channel();
        // On-demand sessions do no filesystem watching or periodic DB inventory.
        let _watcher = if continuous_sync {
            let mut watcher = notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
                let _ = tx.send(event);
            })
            .map_err(|e| e.to_string())?;
            watcher.watch(&self.folder, notify::RecursiveMode::Recursive).map_err(|e| e.to_string())?;
            Some(watcher)
        } else { None };
        let _raw = if interactive {
            Some(ui::Raw::on()?)
        } else {
            None
        };
        let local = format!("http://127.0.0.1:{local_port}");
        let mut links = self.all_links(&local).await;
        let change_command = if self.container.is_some() {
            "yougori launch --cloud --change"
        } else if project.as_ref().is_some_and(|project|
            project.package["scripts"]["yougori-change"] == "yougori launch --change"
        ) {
            "npm run yougori-change"
        } else {
            "yougori launch --change"
        };
        // Usage is sampled beside the loop so the log never waits for it.
        let _footer = super::Footer::open(
            name,
            vec![
                ("t", "Open terminal"),
                ("o", "open"),
                ("p", "public"),
                ("u", "links"),
                ("r", "restart"),
                ("y", "Sync"),
                ("s", "details"),
                ("c", "clear"),
                ("q", "quit"),
                (change_command, "change settings"),
            ],
            &self.receiver.environment,
            gpu,
        );
        ui::dash(|d| {
            d.status(ui::Tone::Busy, "starting dev server");
            d.links(links.clone());
            d.note(if continuous_sync { "Continuous sync on · y Sync" } else { "On-demand sync · y Sync when switching where you work" });
        });
        let mut checked = Instant::now() - Duration::from_secs(6);
        let mut dirty = false;
        let mut restarted: Option<Instant> = None;
        loop {
            if cancel.load(Ordering::Relaxed) || self.view.as_ref().is_some_and(|view| view.quit) {
                return Ok(());
            }
            let dev = self.dev.as_mut().ok_or("Missing development terminal")?;
            let result = dev.action("read", json!({"offset":dev.offset})).await?;
            dev.offset = result["offset"].as_u64().unwrap_or(dev.offset);
            let data = B64
                .decode(result["data"].as_str().unwrap_or(""))
                .map_err(|e| e.to_string())?;
            let view = self.view.as_mut().ok_or("Missing project view")?;
            let (output, fresh) = view.display.feed(&data);
            ui::write(&output);
            view.record(&output);
            // Markers read while a sync pass ran come first.
            let mut events = std::mem::take(&mut view.events);
            events.extend(fresh);
            let ended = view.ended || result["done"] == true;
            let stopped = |attempt: u8| if attempt > 1 { format!("stopped after {attempt} attempts") } else { "stopped".to_owned() };
            for event in events {
                match event.as_str() {
                    event if event.starts_with("failure:") => {
                        if let Some((summary, mut details)) = failure_details(event) {
                            ui::warn(&summary);
                            let context = diagnose::Context { root: &self.folder, env_files, node, change: change_command };
                            let log = self.view.as_ref().map(|view| String::from_utf8_lossy(&view.log).into_owned()).unwrap_or_default();
                            let causes = diagnose::explain(&log, &context);
                            // Specific causes replace the generic reason; memory findings stay.
                            if !causes.is_empty() && event.split(':').nth(3) == Some("exit") {
                                details.remove(0);
                            }
                            for detail in causes.iter().chain(&details) { ui::info(&clean(detail)); }
                            failure_summary = summary;
                        }
                    }
                    "proxy-stopped" => {
                        ui::warn("The link proxy also stopped. Local and public links will be restored on the next attempt.");
                    }
                    event if event.starts_with("attempt:") => {
                        attempt = event[8..].parse::<u8>().unwrap_or(1).clamp(1, 2);
                        if let Some(view) = self.view.as_mut() { view.log.clear(); }
                        served = false;
                    }
                    event if event == "installing" || event.starts_with("installing:") => {
                        let what = event.strip_prefix("installing:").map_or("dependencies".to_owned(), clean);
                        startup.show(&format!("Installing {what} · attempt {attempt}/2"));
                    }
                    event if event.starts_with("install-warning:") => {
                        if let Some((code, what)) = event["install-warning:".len()..].split_once(':') {
                            ui::warn(&format!("Installing {} failed (exit {}); starting anyway. See the output above.", clean(what), clean(code)));
                        }
                    }
                    "starting" => {
                        self.crashed = false;
                        startup.show(&format!("Starting dev server · attempt {attempt}/2"));
                    }
                    "restarting" => {
                        restarted = Some(Instant::now());
                        startup.show("Restarting dev server");
                    }
                    event if event.starts_with("retrying:") => {
                        let parts: Vec<_> = event.split(':').collect();
                        if let [_, phase, next, code] = parts.as_slice() {
                            attempt = next.parse::<u8>().unwrap_or(attempt).clamp(1, 2);
                            let phase = if *phase == "install" { "dependency installation" } else { "dev server" };
                            ui::warn(&format!("Failed {phase} (exit {}) · retrying, attempt {attempt}/2", clean(code)));
                            startup.show(&format!("Retrying {phase} · attempt {attempt}/2"));
                        }
                    }
                    event if event == "install-failed" || event.starts_with("install-failed:") => {
                        self.crashed = true;
                        startup.clear();
                        let cause = if failure_summary.is_empty() { "Dependency installation failed" } else { &failure_summary };
                        let text = format!("{cause} · {}; press r to retry", stopped(attempt));
                        ui::warn(&text);
                        ui::dash(|d| {
                            d.status(ui::Tone::Bad, &text)
                        });
                    }
                    event if event.starts_with("exited:") => {
                        self.crashed = true;
                        startup.clear();
                        let text = if &event[7..] == "0" {
                            if continuous_sync { "stopped (exit 0) · save a file or press r".into() }
                            else { "stopped (exit 0) · y sync changes or r restart".into() }
                        } else {
                            let cause = if failure_summary.is_empty() { "Dev server failed" } else { &failure_summary };
                            format!("{cause} · {}; press r to retry", stopped(attempt))
                        };
                        ui::warn(&text);
                        if &event[7..] == "0" && !served {
                            ui::info(&clean(&diagnose::finished(&command)));
                        }
                        ui::dash(|d| d.status(ui::Tone::Bad, &text));
                    }
                    event if event.starts_with("ready:") => {
                        served = true;
                        startup.clear();
                        let took = restarted.map_or_else(ui::since_start, |at| at.elapsed());
                        links = self.all_links(&local).await;
                        ready(&links, took);
                        ui::dash(|d| {
                            d.status(ui::Tone::Good, "ready");
                            d.links(links.clone());
                        });
                    }
                    _ => {}
                }
            }
            if ended {
                return Err("The project supervisor exited. Run yougori launch again.".into());
            }
            for event in rx.try_iter() {
                match event {
                    Ok(e) if !matches!(e.kind, notify::EventKind::Access(_)) => {
                        dirty = true;
                        // Open files can change before their timestamps update on Windows.
                        let filter = sync::Filter::load(&self.folder, env_files)?;
                        for path in e.paths {
                            if let Ok(relative) = path.strip_prefix(&self.folder) {
                                let relative = relative.to_string_lossy().replace('\\', "/");
                                if !filter.excluded(&relative, false) && path.is_file() {
                                    self.local_hashes.remove(&relative);
                                    if !two_way { self.saved.pending.insert(relative); }
                                }
                            }
                        }
                    }
                    Err(e) => return Err(format!("File watcher failed: {e}")),
                    _ => {}
                }
            }
            if continuous_sync && ((!two_way && dirty && checked.elapsed() >= Duration::from_millis(150))
                || checked.elapsed() >= Duration::from_secs(5))
            {
                if two_way {
                    match self.sync_both(env_files).await {
                        Ok(count) if count > 0 => { ui::dash(|d| d.note(&format!("Two-way sync · {count} file changes"))); }
                        Ok(_) => {},
                        Err(_) if self.view.as_ref().is_some_and(|view| view.quit) => return Ok(()),
                        Err(error) => {
                            let message = format!("Two-way sync paused: {}", clean(&error));
                            if self.conflicts.insert(message.clone()) { ui::warn(&message); }
                            ui::dash(|d| d.note(&message));
                        }
                    }
                } else {
                    match self.sync_current(env_files, false).await {
                        Ok(count) => {
                            self.conflicts.clear();
                            if count > 0 {
                            ui::dash(|d| {
                                d.note(&format!(
                                    "synced {count} file{}",
                                    if count == 1 { "" } else { "s" }
                                ))
                            });
                            }
                        }
                        Err(_) if self.view.as_ref().is_some_and(|view| view.quit) => return Ok(()),
                        Err(error) => {
                            let message = format!("File sync will retry: {}", clean(&error));
                            if self.conflicts.insert(message.clone()) { ui::warn(&message); }
                            ui::dash(|d| d.note(&message));
                        }
                    }
                }
                checked = Instant::now();
                dirty = false;
            }
            let mut input = self.view.as_mut().map(|view| std::mem::take(&mut view.input)).unwrap_or_default();
            while interactive && event::poll(Duration::ZERO).map_err(|e| e.to_string())? {
                input.push(event::read().map_err(|e| e.to_string())?);
            }
            for event in input {
                match event {
                    Event::Key(k) if k.kind != KeyEventKind::Release => {
                        if k.code == KeyCode::Char('c')
                            && k.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            return Ok(());
                        }
                        // While the dev server asks something, every key is its answer.
                        let shortcut = ui::footer_visible()
                            && k.modifiers.difference(KeyModifiers::SHIFT).is_empty();
                        match k.code {
                            KeyCode::Char('t') if shortcut => {
                                super::open_terminal(&self.receiver.environment, true, self.container.as_deref());
                            }
                            KeyCode::Char('q') if shortcut => return Ok(()),
                            KeyCode::Char('y') if shortcut => {
                                self.choose_handoff(env_files, two_way).await?;
                                checked = Instant::now();
                                dirty = false;
                            }
                            KeyCode::Char('r') if shortcut => {
                                restarted = Some(Instant::now());
                                startup.show("Restarting dev server");
                                self.receiver.write(b"K\n").await?;
                            }
                            KeyCode::Char('u') if shortcut => {
                                links = self.all_links(&local).await;
                                ui::dash(|d| d.links(links.clone()));
                                print_links(&links);
                            }
                            KeyCode::Char('o') if shortcut => {
                                let note = match open_browser(&local) {
                                    Ok(()) => "opened in your browser".to_string(),
                                    Err(e) => e,
                                };
                                ui::dash(|d| d.note(&note));
                            }
                            KeyCode::Char('p') if shortcut => {
                                let note = match links.iter().find(|(kind, _)| kind == "public") {
                                    Some((_, url)) => open_browser(url).map(|_| "opened public link".into()).unwrap_or_else(|e| e),
                                    None => "No public link is configured".into(),
                                };
                                ui::dash(|d| d.note(&note));
                            }
                            KeyCode::Char('s') if shortcut => {
                                ui::dash(|d| d.toggle_detail());
                            }
                            KeyCode::Char('c') if shortcut => ui::clear(),
                            _ => {
                                if let (Some(bytes), Some(dev)) = (key_bytes(&k), &self.dev) {
                                    dev.write(&bytes).await?;
                                }
                            }
                        }
                    }
                    Event::Resize(cols, rows) => {
                        if let Some(dev) = &self.dev {
                            dev.action("resize", json!({"cols":cols,"rows":rows}))
                                .await?;
                        }
                        ui::refresh();
                    }
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
}

fn print_links(links: &[(String, String)]) {
    let label = links.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (name, url) in links {
        ui::line(&format!(
            "  {}  {}",
            ui::muted(&format!("{name:label$}")),
            ui::paint(url, ui::SKY)
        ));
    }
}

fn ready(links: &[(String, String)], took: Duration) {
    ui::line("");
    ui::line(&format!(
        "  {}  {}",
        ui::paint("ready", ui::GREEN),
        ui::muted(&format!("in {}", ui::clock(took)))
    ));
    print_links(links);
    ui::line("");
}

/// Bytes a terminal would send for a key, for answering the dev server's own questions.
fn key_bytes(key: &event::KeyEvent) -> Option<Vec<u8>> {
    Some(match key.code {
        KeyCode::Char(c)
            if key.modifiers.contains(KeyModifiers::CONTROL) && c.is_ascii_alphabetic() =>
        {
            vec![c.to_ascii_lowercase() as u8 & 0x1f]
        }
        KeyCode::Char(c) => c.to_string().into_bytes(),
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        _ => return None,
    })
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    let result = {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x08000000)
            .spawn()
    };
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = std::process::Command::new("xdg-open").arg(url).spawn();
    result
        .map(|_| ())
        .map_err(|e| format!("Cannot open browser: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_explain_memory_evidence_limits_and_next_steps() {
        let (summary, details) = failure_details("failure:install:137:oom:1073741824:1.00").unwrap();
        assert!(summary.contains("Dependency installation: out of memory"));
        assert!(details.iter().any(|s| s.contains("OOM counter increased")));
        assert!(details.iter().any(|s| s.contains("1 CPU · 1.0 GB RAM")));
        assert!(details.iter().any(|s| s.contains("yougori launch --change")));
        let (summary, details) = failure_details("failure:install:137:killed::").unwrap();
        assert!(!summary.contains("out of memory"));
        assert!(details.iter().any(|s| s.contains("did not confirm")));
        assert!(!details.iter().any(|s| s.contains("Container limit")));
        let (_, details) = failure_details("failure:run:127:exit:max:").unwrap();
        assert!(details[0].contains("command was not found"));
        assert!(failure_details("failure:run:bad:exit::").is_none());
    }
}
