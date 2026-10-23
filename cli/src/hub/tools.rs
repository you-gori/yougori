//! Tools: programs installed into a sandbox. Built-in tools keep their own installer and
//! shortcuts (`yougori codex`); other tools are folders with `yougori-tool.yaml`, installed by
//! running their `install` lines in the sandbox and proven by their `check`. Added tools live in
//! `~/.yougori/tools/NAME`.
use super::{
    client::{self, Cache, Site},
    format::{self, Tool},
    refs,
    review,
    scan::{self, Files},
};
use crate::cli_ui as ui;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// `$HOME/.local/bin` (and Yougori's tool folder) on `PATH`, and the tool environment the
/// built-in installers write, as `crate::terminal` sets them up for its tools.
pub const SETUP: &str = "export PATH=\"$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH\"; [ ! -r \"$HOME/.local/share/yougori/tool-env.sh\" ] || . \"$HOME/.local/share/yougori/tool-env.sh\"";

/// How long an installer may run before Yougori stops waiting.
const INSTALL_LIMIT: Duration = Duration::from_secs(60 * 60);

/// Words a tool can never be called, so `yougori NAME` and `tool open NAME` stay unambiguous.
const COMMAND_WORDS: &[&str] = &[
    "cli", "launch", "status", "top", "doctor", "update", "uninstall", "login", "logout", "account", "connect",
    "confidential", "vault", "bounty", "schema", "skills", "terminal", "download", "agent", "app", "help", "monitor",
    "audit", "lockdown", "unlock", "grid", "grids", "desks", "desk", "access", "rollout", "template", "tool", "tools",
    "hub", "env", "environment", "connection", "remote", "share", "ports", "domain", "drives", "lan", "project",
    "cloud", "neocloud", "storage", "snapshot", "backup", "gpu", "microvm", "vm", "machine", "window", "settings",
    "jobs", "call", "model", "version", "info", "create", "join", "python", "npm",
];

/// Why a tool may not be added under `name`.
pub fn clash(name: &str) -> Option<String> {
    if crate::container_tools::TOOLS.contains(&name) {
        return Some(format!("{name} is a built-in tool. Use yougori {name}, or give your tool another name."));
    }
    if COMMAND_WORDS.contains(&name) || crate::public::COMMANDS.contains(&name) {
        return Some(format!("{name} is a Yougori command. Give the tool another name in its yougori-tool.yaml."));
    }
    None
}

fn nonce() -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 9];
    let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The script that runs a tool's install lines, each in its own shell, in order, stopping at the
/// first failure, and records `LINE CODE` (0 0 when every line passed) in `DIR/status`.
pub fn runner(dir: &str, tool: &Tool) -> String {
    // The runner records its own process ID: under setsid it also leads its process group, so a
    // stop reaches every line it started.
    let mut script = format!("printf %s \"$$\" > {dir}/pid\n{SETUP}\nmkdir -p \"$HOME/.local/bin\"\ncd \"$HOME\" 2>/dev/null || cd /\n");
    for (index, line) in tool.install.iter().enumerate() {
        script.push_str(&format!(
            "/bin/sh -c {} || {{ code=$?; printf '%s %s\\n' {} \"$code\" > {dir}/status; exit 0; }}\n",
            shell_words::quote(line),
            index + 1
        ));
    }
    script.push_str(&format!("printf '0 0\\n' > {dir}/status\n"));
    script
}

/// Commands that write `script` to `path` in pieces small enough for one guest command each.
pub fn staging(path: &str, script: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut piece = String::new();
    let mut first = true;
    let mut flush = |piece: &mut String, first: &mut bool| {
        let redirect = if *first { ">" } else { ">>" };
        commands.push(format!("printf %s {} {redirect} {path}", shell_words::quote(piece)));
        piece.clear();
        *first = false;
    };
    for c in script.chars() {
        piece.push(c);
        if piece.len() >= 6 * 1024 {
            flush(&mut piece, &mut first);
        }
    }
    if !piece.is_empty() || first {
        flush(&mut piece, &mut first);
    }
    commands
}

async fn exec(id: &str, command: &str) -> Result<Value, String> {
    crate::public::call("execute_environment_command", json!({"request": {"environmentId": id, "command": command}})).await
}

fn printable(text: &str) -> String {
    text.chars().map(|c| if c.is_control() && c != '\n' { ' ' } else { c }).collect()
}

/// What an install of this tool puts in a sandbox: its name, version, install lines and check. The
/// sandbox keeps it after an install, so a new version of a tool is installed again even though
/// the old one's check still passes.
pub fn fingerprint(tool: &Tool) -> String {
    scan::sha256_hex(&serde_json::to_vec(&json!([tool.name(), tool.version(), tool.install, tool.check])).unwrap_or_default())
}

/// Where a sandbox keeps the fingerprint of an installed tool (names are Hub names, safe in a path).
fn marker(name: &str) -> String {
    format!("$HOME/.local/share/yougori/tools/{name}")
}

/// Whether this exact tool was installed in the sandbox before and its check still passes.
async fn installed(id: &str, tool: &Tool) -> bool {
    let said = exec(id, &format!("cat \"{}\" 2>/dev/null", marker(tool.name()))).await.ok();
    said.as_ref().and_then(|value| value["stdout"].as_str()).map(str::trim) == Some(fingerprint(tool).as_str()) && check(id, tool).await.unwrap_or(false)
}

async fn mark_installed(id: &str, tool: &Tool) {
    let _ = exec(id, &format!("mkdir -p \"$HOME/.local/share/yougori/tools\" && printf %s {} > \"{}\"", fingerprint(tool), marker(tool.name()))).await;
}

/// Whether the tool's `check` passes in the sandbox now.
pub async fn check(id: &str, tool: &Tool) -> Result<bool, String> {
    let line = tool.check.as_deref().unwrap_or("false");
    let result = exec(id, &format!("{SETUP}; cd \"$HOME\" 2>/dev/null || cd /; {line}")).await?;
    Ok(result["exitCode"] == 0)
}

/// What to say when a tool did not install: the tool, the sandbox, where to look and how to
/// retry only this tool.
pub fn failure(tool: &str, sandbox: &str, why: &str, retry: &str) -> String {
    format!("{tool} did not install in {sandbox}: {why} Look inside with yougori terminal {sandbox}, then run {retry} to try again; only {tool} is retried.")
}

/// Installs a custom tool in a running sandbox and proves it with its check. Each install line
/// runs in the background inside the sandbox, so a long download is never cut off; Ctrl+C
/// (`cancel`) stops it there too.
pub async fn install(id: &str, sandbox: &str, tool: &Tool, retry: &str, cancel: &AtomicBool, mut progress: impl FnMut(&str)) -> Result<(), String> {
    let name = tool.name().to_owned();
    if installed(id, tool).await {
        return Ok(());
    }
    if tool.install.is_empty() {
        // Nothing to install: the tool is there when its check passes.
        if check(id, tool).await.unwrap_or(false) {
            mark_installed(id, tool).await;
            return Ok(());
        }
        return Err(failure(&name, sandbox, "it has no install lines, and its check does not pass.", retry));
    }
    let dir = format!("/tmp/yougori-hub-{}", nonce());
    let script = runner(&dir, tool);
    exec(id, &format!("rm -rf {dir} && mkdir -m 700 -p {dir}")).await?;
    for command in staging(&format!("{dir}/run.sh"), &script) {
        let staged = exec(id, &command).await?;
        if staged["exitCode"] != 0 {
            return Err(failure(&name, sandbox, "its installer could not be copied into the sandbox.", retry));
        }
    }
    let started = exec(id, &format!("cd / && if command -v setsid >/dev/null 2>&1; then setsid nohup /bin/sh {dir}/run.sh </dev/null >{dir}/log 2>&1 & else nohup /bin/sh {dir}/run.sh </dev/null >{dir}/log 2>&1 & fi")).await?;
    if started["exitCode"] != 0 {
        return Err(failure(&name, sandbox, "its installer could not start.", retry));
    }
    let began = Instant::now();
    let outcome = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = exec(id, &format!("p=$(cat {dir}/pid 2>/dev/null); [ -z \"$p\" ] || kill -TERM -- -\"$p\" 2>/dev/null || kill -TERM \"$p\" 2>/dev/null; rm -rf {dir}")).await;
            return Err(ui::CANCELLED.into());
        }
        if began.elapsed() > INSTALL_LIMIT {
            break Err(format!("its installer was still running after {} minutes and was left running.", INSTALL_LIMIT.as_secs() / 60));
        }
        let poll = exec(id, &format!("if [ -f {dir}/status ]; then cat {dir}/status; elif [ ! -s {dir}/pid ]; then echo starting; elif kill -0 \"$(cat {dir}/pid)\" 2>/dev/null; then echo running; else echo gone; fi")).await?;
        let said = poll["stdout"].as_str().unwrap_or_default().trim().to_owned();
        match said.split_once(' ') {
            Some(("0", "0")) => break Ok(()),
            Some((line, code)) if line.parse::<usize>().is_ok() => {
                let shown = tool.install.get(line.parse::<usize>().unwrap_or(1).saturating_sub(1)).cloned().unwrap_or_default();
                let tail = exec(id, &format!("tail -n 6 {dir}/log 2>/dev/null")).await.ok().and_then(|v| v["stdout"].as_str().map(printable)).unwrap_or_default();
                let tail = tail.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| l.chars().take(200).collect::<String>()).collect::<Vec<_>>().join(" | ");
                break Err(format!("install line {line} ({}) failed with exit code {code}.{}", scan::shown(&shown).chars().take(120).collect::<String>(), if tail.is_empty() { String::new() } else { format!(" Last output: {tail}.") }));
            }
            _ if said == "gone" => break Err("its installer stopped without a result (the sandbox may have restarted).".into()),
            _ if said == "starting" && began.elapsed() > Duration::from_secs(60) => break Err("its installer did not start.".into()),
            _ => {}
        }
        progress(&format!("Installing {name} in {sandbox}"));
        tokio::time::sleep(Duration::from_millis(1500)).await;
    };
    let _ = exec(id, &format!("rm -rf {dir}")).await;
    if let Err(why) = outcome {
        return Err(failure(&name, sandbox, &why, retry));
    }
    if !check(id, tool).await? {
        return Err(failure(&name, sandbox, &format!("its installer finished, but its check ({}) does not pass.", tool.check.as_deref().unwrap_or_default()), retry));
    }
    mark_installed(id, tool).await;
    Ok(())
}

/// The command that opens a custom tool in a terminal attached to the sandbox.
pub fn open_command(tool: &Tool) -> String {
    let script = format!("{SETUP}; cd /workspace 2>/dev/null || cd \"$HOME\" 2>/dev/null || cd /; {}", tool.command.as_deref().unwrap_or("sh"));
    format!("exec /bin/sh -c {}", shell_words::quote(&script))
}

/// Where added tools live.
pub struct Added {
    pub root: PathBuf,
}

impl Added {
    pub fn standard() -> Result<Added, String> {
        Ok(Added { root: client::home()?.join("tools") })
    }
    fn meta(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.json"))
    }
    pub fn folder(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    /// An added tool and where it came from.
    pub fn get(&self, name: &str) -> Result<Option<(Tool, Value)>, String> {
        if !refs::valid_name(name) {
            return Ok(None);
        }
        let Ok(meta) = std::fs::read(self.meta(name)) else { return Ok(None) };
        let meta: Value = serde_json::from_slice(&meta).map_err(|_| format!("The record of the tool {name} cannot be read. Remove it with yougori tool remove {name} --yes."))?;
        let collected = scan::collect(&self.folder(name))?;
        let tool = format::tool(&collected.files, "").map_err(|p| format!("The added tool {name} has problems: {}", p.join(" ")))?;
        Ok(Some((tool, meta)))
    }
    pub fn list(&self) -> Vec<(Tool, Value)> {
        let mut found: Vec<(Tool, Value)> = std::fs::read_dir(&self.root).into_iter().flatten().flatten()
            .filter_map(|entry| entry.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_owned))
            .filter_map(|name| self.get(&name).ok().flatten())
            .collect();
        found.sort_by(|a, b| a.0.name().cmp(b.0.name()));
        found
    }
    /// Saves a checked tool's files under its name, replacing an earlier copy from the same place.
    pub fn save(&self, tool: &Tool, files: &Files, source: Value) -> Result<(), String> {
        let name = tool.name();
        if let Some(reason) = clash(name) {
            return Err(reason);
        }
        if let Ok(Some((_, existing))) = self.get(name) {
            if existing["source"] != source["source"] || existing["from"] != source["from"] {
                return Err(format!("A tool named {name} is already added from {}. Remove it first with yougori tool remove {name} --yes.", existing["from"].as_str().unwrap_or("elsewhere")));
            }
        }
        std::fs::create_dir_all(&self.root).map_err(|e| format!("Cannot save the tool: {e}"))?;
        let staging = tempfile::Builder::new().prefix(".partial-").tempdir_in(&self.root).map_err(|e| format!("Cannot save the tool: {e}"))?;
        client::write_files(staging.path(), files)?;
        let _ = std::fs::remove_dir_all(self.folder(name));
        std::fs::rename(staging.path(), self.folder(name)).map_err(|e| format!("Cannot save the tool: {e}"))?;
        let mut meta = source;
        meta["name"] = json!(name);
        meta["version"] = json!(tool.version());
        meta["addedAt"] = json!(super::instances::now());
        std::fs::write(self.meta(name), serde_json::to_vec_pretty(&meta).unwrap_or_default()).map_err(|e| format!("Cannot save the tool: {e}"))
    }
    /// Removes an added tool by its name. Anything else (a path, `..`, a drive) is not an added
    /// tool and deletes nothing.
    pub fn remove(&self, name: &str) -> Result<bool, String> {
        if !refs::valid_name(name) || !self.meta(name).is_file() {
            return Ok(false);
        }
        let _ = std::fs::remove_dir_all(self.folder(name));
        match std::fs::remove_file(self.meta(name)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(format!("Cannot remove the tool {name}: {e}")),
        }
    }
}

/// Reads and checks a tool folder on this computer, refusing credentials as publishing would.
pub fn read_folder(folder: &Path) -> Result<(Tool, Files, scan::Findings), String> {
    let collected = scan::collect(folder)?;
    if !collected.files.contains_key(format::TOOL_FILE) {
        return Err(format!("{} has no {}. Start one with yougori tool new NAME.", folder.display(), format::TOOL_FILE));
    }
    let tool = format::tool(&collected.files, "").map_err(|problems| list("This tool", &problems))?;
    let findings = scan::scan(&collected.files);
    Ok((tool, collected.files, findings))
}

/// Problems as a message: one per line.
pub fn list(what: &str, problems: &[String]) -> String {
    let mut text = format!("{what} has {} to fix:", if problems.len() == 1 { "one thing".to_owned() } else { format!("{} things", problems.len()) });
    for problem in problems {
        text.push_str("\n- ");
        text.push_str(problem);
    }
    text
}

/// Whether `added` already holds this Hub tool, from an earlier `tool add`.
fn added_before(added: &Added, name: &str, item: &str) -> bool {
    matches!(added.get(name), Ok(Some((_, meta))) if meta["source"] == "hub" && meta["from"] == item)
}

/// `tool add`: a folder, or a tool from the Hub. A Hub tool is other people's code: it is
/// downloaded and checked, and its review is shown and agreed to (or `--yes`) before it is saved.
pub async fn add(source: &str, yes: bool, interactive: bool) -> Result<Value, String> {
    let added = Added::standard()?;
    let website = client::website();
    if refs::looks_like_ref(source, &website) || source.starts_with("hub/") {
        let reference = refs::parse(source, &website)?;
        let site = Site::configured()?;
        let cache = Cache::standard()?;
        let nothing = |error: String| if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled("Cancelled. Nothing was added.") } else { error.replace("Nothing was created.", "Nothing was added.") };
        let got = super::run::wait(interactive, "Downloading and checking the tool", client::obtain(&site, &cache, &reference)).await.map_err(nothing)?;
        if got.bundle.kind != "tool" {
            return Err(format!("{} is a template, not a tool. Run it with yougori run {}.", reference.item(), reference.command()));
        }
        let tool = format::tool(&got.bundle.files, "").map_err(|problems| list(&reference.item(), &problems))?;
        let wallet: Vec<String> = scan::scan(&got.bundle.files).wallet_notice().into_iter().collect();
        let review = review::tool(&tool, &wallet);
        let verified = got.bundle.verified;
        let first = !added_before(&added, tool.name(), &reference.item());
        if !yes {
            if !interactive {
                return Err(format!("Adding {} {} lets its install lines run in your sandboxes later. Read its review with yougori template info hub/{}, then add --yes. Nothing was added.", reference.item(), got.bundle.version, reference.item()));
            }
            let _raw = ui::Raw::on()?;
            let mut lines = Vec::new();
            if !verified {
                lines.extend(super::views::unverified().into_iter().map(|line| ui::paint(&line, ui::AMBER)));
                lines.push(String::new());
            }
            lines.push(ui::bold(&format!("{} · hub/{} {}", super::views::clean(tool.title()), reference.item(), got.bundle.version)));
            lines.push(String::new());
            lines.extend(super::views::tool_review(&review));
            if let Some(notice) = &got.notice {
                lines.push(ui::paint(&format!("▲ {}", super::views::clean(notice)), ui::AMBER));
            }
            ui::lines(lines.into_iter().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
            let choice = ui::select(&format!("Add {} {}?", tool.name(), got.bundle.version), &[], &[ui::Choice::new("Add it", "install it into a sandbox later"), ui::Choice::new("Cancel", "nothing is added")], if verified { 0 } else { 1 }).map_err(nothing)?;
            if choice != 0 {
                return Err(crate::wire::cancelled("Cancelled. Nothing was added."));
            }
        }
        added.save(&tool, &got.bundle.files, json!({"source": "hub", "from": reference.item(), "digest": got.bundle.digest, "verified": verified}))?;
        // A computer counts once per item, after the work, and only when the Hub answered.
        let counted = if first && got.detail.is_some() {
            let id = client::home().and_then(|home| client::install_id(&home)).ok();
            match id {
                Some(id) => super::run::wait(interactive, "Telling the Hub", async { Ok(site.count_clone(&reference, &got.bundle.version, &id).await) }).await.ok().flatten().is_some(),
                None => false,
            }
        } else {
            false
        };
        return Ok(json!({"added": tool.name(), "version": tool.version(), "source": "hub", "from": reference.item(), "verified": verified, "notice": got.notice, "review": review, "counted": counted, "next": format!("yougori tool install {} --environment ENV", tool.name())}));
    }
    let folder = client::plain(std::fs::canonicalize(source).map_err(|e| format!("Cannot open the folder {source}: {e}. Give a tool folder or hub/PUBLISHER/NAME."))?);
    let (tool, files, findings) = read_folder(&folder)?;
    if !findings.refused.is_empty() {
        return Err(list("This tool's folder", &findings.refused));
    }
    let from = folder.to_string_lossy().into_owned();
    added.save(&tool, &files, json!({"source": "folder", "from": from}))?;
    Ok(json!({"added": tool.name(), "version": tool.version(), "source": "folder", "from": from, "review": review::tool(&tool, &findings.wallet_notice().into_iter().collect::<Vec<_>>()), "next": format!("yougori tool install {} --environment ENV", tool.name())}))
}

/// `tool list`: built-in tools and added ones.
pub fn listing() -> Result<Value, String> {
    let added = Added::standard()?;
    let built_in: Vec<Value> = crate::container_tools::TOOLS.iter().map(|name| json!({"name": name, "source": "built-in", "open": format!("yougori {name}")})).collect();
    let custom: Vec<Value> = added.list().into_iter().map(|(tool, meta)| json!({
        "name": tool.name(), "title": tool.title(), "version": tool.version(), "summary": tool.summary,
        "source": meta["source"], "from": meta["from"], "signin": tool.signin_method(),
        "open": format!("yougori tool open {} --environment ENV", tool.name()),
    })).collect();
    Ok(json!({"builtIn": built_in, "added": custom}))
}

/// The running sandbox a tool command targets, by name or ID.
pub async fn sandbox(word: &str) -> Result<(String, String), String> {
    sandbox_with_gpu(word).await.map(|(id, name, _)| (id, name))
}

/// [`sandbox`], and whether it has an NVIDIA GPU.
async fn sandbox_with_gpu(word: &str) -> Result<(String, String, bool), String> {
    crate::client::start(None).await?;
    let id = crate::public::resolve(word).await?;
    let state = crate::public::call("get_platform_state", json!({})).await?;
    let environment = state["environments"].as_array().into_iter().flatten().find(|e| e["id"] == id.as_str()).cloned().ok_or("This environment was not found. See your environments with yougori ps.")?;
    let name = environment["name"].as_str().unwrap_or(word).to_owned();
    if environment["status"] != "running" {
        return Err(format!("{name} is not running. Start it with yougori start {}, then try again.", shell_words::quote(&name)));
    }
    if matches!(environment["kind"].as_str(), Some("fullVm" | "cloud")) || environment["runtime"].as_str().is_some_and(|r| r.starts_with("shared://")) {
        return Err(format!("Tools install into local containers and microVMs; {name} is not one."));
    }
    Ok((id, name, environment["gpuAccess"] == true))
}

/// `tool install NAME --environment ENV`: an added tool, installed and checked.
/// `key` is the tool's API key when a script gave one on stdin; at a terminal it is asked for.
pub async fn install_added(name: &str, environment: &str, interactive: bool, key: Option<zeroize::Zeroizing<String>>) -> Result<Value, String> {
    if crate::container_tools::TOOLS.contains(&name) {
        if !interactive {
            return Err(format!("Built-in tools install in an interactive terminal: run yougori {name} --environment {} there.", shell_words::quote(environment)));
        }
        let (id, sandbox) = sandbox(environment).await?;
        let _raw = ui::Raw::on()?;
        let exit = crate::terminal::setup_tool(&id, name).await?;
        return Ok(json!({"tool": name, "environment": sandbox, "installed": exit == crate::terminal::SessionExit::Completed}));
    }
    let added = Added::standard()?;
    let (tool, meta) = added.get(name)?.ok_or_else(|| format!("There is no added tool named {}. See yougori tool list, or add one with yougori tool add FOLDER.", scan::shown(name)))?;
    let (id, sandbox, gpu) = sandbox_with_gpu(environment).await?;
    if tool.gpu() == "required" && !gpu {
        return Err(format!("{name} needs an NVIDIA GPU, and {sandbox} has none. Install it in a GPU sandbox (such as one made with yougori run --gpu nvidia IMAGE)."));
    }
    // A tool from the Hub that Yougori did not check says so each time it runs its install lines.
    let warning = (meta["source"] == "hub" && meta["verified"] != true).then(|| format!("{} is not checked by Yougori: its install lines run inside {sandbox}.", meta["from"].as_str().unwrap_or(name)));
    if let (Some(warning), true) = (&warning, interactive) {
        ui::lines(vec![ui::paint(&format!("▲ {warning}"), ui::AMBER)]);
    }
    let retry = format!("yougori tool install {name} --environment {}", shell_words::quote(&sandbox));
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let result = if interactive {
        let _raw = ui::Raw::on()?;
        let _keys = ui::Interrupts::watch(cancel.clone());
        let mut task = ui::loading_task(&format!("Installing {name} in {sandbox}"));
        let result = install(&id, &sandbox, &tool, &retry, &cancel, |label| task.set(label)).await;
        match &result {
            Ok(()) => task.done(&format!("{name} ready in {sandbox}")),
            Err(error) if error == ui::CANCELLED => task.clear(),
            Err(_) => task.fail(&format!("{name} did not install")),
        }
        result
    } else {
        install(&id, &sandbox, &tool, &retry, &cancel, |_| {}).await
    };
    if let Err(error) = result {
        if error == ui::CANCELLED {
            return Err(crate::wire::cancelled(&format!("Stopped installing {name}. {sandbox} keeps running; run {retry} to try again.")));
        }
        return Err(error);
    }
    let mut steps = Vec::new();
    if let Some(variable) = tool.key_variable() {
        // The key goes to the OS credential vault as a deployment secret, never into a file.
        let secret = format!("tool-{name}");
        let key = match key {
            Some(key) => Some(key),
            None if interactive => {
                let _raw = ui::Raw::on()?;
                let check = |entry: &str| -> Result<String, String> {
                    if entry.is_empty() || (entry.len() <= 65536 && !entry.contains(['\0', '\r', '\n'])) { Ok(entry.to_owned()) } else { Err("A key is one line of at most 64 KiB.".into()) }
                };
                let entered = ui::input(&format!("API key for {name} ({variable}) · Enter skips"), "", true, &check)
                    .map_err(|error| if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled(&format!("{name} is installed in {sandbox}; no key was stored.")) } else { error })?;
                (!entered.is_empty()).then(|| zeroize::Zeroizing::new(entered))
            }
            None => None,
        };
        match key {
            Some(key) => {
                crate::public::call("set_deployment_secret", json!({"name": secret, "value": key.as_str()})).await?;
                steps.push(format!("The key is stored as the deployment secret {secret}. Give it to {name} in a project's yougori.yaml: secrets: {{{variable}: {secret}}}, then yougori apply."));
            }
            None => steps.push(format!("{name} reads its API key from {variable}. Store it with yougori tool install {name} --environment {} --secrets - (JSON {{\"key\": \"…\"}} on stdin), or set {variable} inside the sandbox.", shell_words::quote(&sandbox))),
        }
    }
    if matches!(tool.signin_method(), "browser" | "device") {
        steps.push(format!("Sign in to {name}: yougori terminal {}, then run {}", shell_words::quote(&sandbox), tool.signin.as_ref().and_then(|s| s.command.as_deref()).unwrap_or_default()));
    }
    Ok(json!({"tool": name, "environment": sandbox, "installed": true, "check": "passed", "steps": steps, "warning": warning, "open": format!("yougori tool open {name} --environment {}", shell_words::quote(&sandbox))}))
}

/// `tool open NAME --environment ENV`: installs if needed, then opens it in this terminal.
pub async fn open(name: &str, environment: &str) -> Result<Value, String> {
    if crate::container_tools::TOOLS.contains(&name) {
        let args = vec![name.to_owned(), "--environment".to_owned(), environment.to_owned()];
        return crate::container_tools::run(&args).await.map(|value| value.unwrap_or(json!({"tool": name, "opened": true})));
    }
    let added = Added::standard()?;
    let (tool, _) = added.get(name)?.ok_or_else(|| format!("There is no added tool named {}. See yougori tool list.", scan::shown(name)))?;
    let installed = install_added(name, environment, true, None).await?;
    let (id, sandbox) = sandbox(environment).await?;
    crate::terminal::attach(&id, Some(&open_command(&tool))).await?;
    Ok(json!({"tool": name, "environment": sandbox, "opened": true, "installed": installed["installed"]}))
}

/// `tool new [NAME]`: a tool folder to fill in.
pub fn new(name: Option<&str>) -> Result<Value, String> {
    let name = name.unwrap_or("my-tool");
    if !refs::valid_name(name) {
        return Err(format!("{} is not a tool name: use {}.", scan::shown(name), refs::NAME_RULE));
    }
    if let Some(reason) = clash(name) {
        return Err(reason);
    }
    let folder = std::env::current_dir().map_err(|e| e.to_string())?.join(name);
    if folder.exists() {
        return Err(format!("{} already exists. Choose another name or folder.", folder.display()));
    }
    let files = new_files(name);
    client::write_files(&folder, &files)?;
    Ok(json!({"created": folder, "files": [format::TOOL_FILE, "README.md"], "next": [
        format!("Edit {name}/{}: the install lines, check and command.", format::TOOL_FILE),
        format!("yougori tool check {name}"),
        format!("yougori tool add {name}"),
        format!("yougori tool install {name} --environment ENV"),
    ]}))
}

/// The files of a new tool folder, valid as they stand.
fn new_files(name: &str) -> Files {
    let tool = format!("kind: tool\nname: {name}\ntitle: {name}\nsummary: What {name} does, in one line.\nversion: 0.1.0\nlicense: MIT\ntopics: []\n\n# The program, opened in a terminal for the person.\ncommand: {name}\n\n# Shell lines run in the sandbox, in order, stopping at the first failure.\n# $HOME/.local/bin is on PATH. Pin versions so every install is the same.\ninstall:\n  - python3 -m pip install --user --break-system-packages {name}==1.0.0\n\n# Must succeed after installing.\ncheck: {name} --version\n\n# Optional: how a person signs in (none, browser, device or api-key).\n# signin:\n#   method: api-key\n#   variable: EXAMPLE_API_KEY\n\n# Optional: what the sandbox needs.\nneeds:\n  gpu: none\n  internet: true\n");
    let readme = format!("# {name}\n\nWhat {name} does and how to use it.\n\n```text\nyougori tool check .\nyougori tool add .\nyougori tool install {name} --environment ENV\n```\n");
    let files: Files = [(format::TOOL_FILE.to_owned(), tool.into_bytes()), ("README.md".to_owned(), readme.into_bytes())].into();
    files
}

/// `tool check [FOLDER]`.
pub fn check_folder(folder: &str) -> Result<Value, String> {
    let path = PathBuf::from(folder);
    let (tool, files, findings) = read_folder(&path)?;
    if !findings.refused.is_empty() {
        return Err(list("This tool's folder", &findings.refused));
    }
    let notices: Vec<String> = findings.wallet_notice().into_iter().collect();
    Ok(json!({"ok": true, "name": tool.name(), "version": tool.version(), "files": files.len(), "bytes": files.values().map(Vec::len).sum::<usize>(), "review": review::tool(&tool, &notices), "clash": clash(tool.name())}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(install: &[&str]) -> Tool {
        let text = format!("name: aider\nsummary: Pair programming.\nversion: 1.0.0\nlicense: MIT\ncommand: aider --yes\ncheck: aider --version\ninstall: [{}]\n", install.iter().map(|l| format!("{:?}", l)).collect::<Vec<_>>().join(", "));
        format::tool(&[(format::TOOL_FILE.to_owned(), text.into_bytes())].into(), "").unwrap()
    }

    #[test]
    fn install_lines_run_one_shell_each_and_stop_at_the_first_failure() {
        let script = runner("/tmp/yougori-hub-abc", &tool(&["pip install 'a b'; echo \"$HOME\"", "echo it's done"]));
        let lines: Vec<&str> = script.lines().collect();
        assert_eq!(lines[0], "printf %s \"$$\" > /tmp/yougori-hub-abc/pid", "the runner records its own process");
        assert_eq!(lines[1], SETUP);
        let first = shell_words::split(lines[4]).unwrap();
        assert_eq!(&first[..3], ["/bin/sh", "-c", "pip install 'a b'; echo \"$HOME\""]);
        assert!(lines[4].contains("printf '%s %s\\n' 1 \"$code\" > /tmp/yougori-hub-abc/status; exit 0;"));
        assert_eq!(shell_words::split(lines[5]).unwrap()[2], "echo it's done");
        assert_eq!(lines.last().unwrap(), &"printf '0 0\\n' > /tmp/yougori-hub-abc/status");
    }

    #[test]
    fn a_new_version_of_a_tool_is_installed_again() {
        let first = tool(&["pip install aider-chat==0.86.1"]);
        let same = tool(&["pip install aider-chat==0.86.1"]);
        let newer = tool(&["pip install aider-chat==0.87.0"]);
        assert_eq!(fingerprint(&first), fingerprint(&same));
        assert_ne!(fingerprint(&first), fingerprint(&newer), "new install lines are a new install, although the old check still passes");
        assert_eq!(fingerprint(&first).len(), 64);
        assert_eq!(marker("aider"), "$HOME/.local/share/yougori/tools/aider");
    }

    #[test]
    fn long_installers_are_staged_in_pieces_that_rebuild_the_script() {
        let script = format!("{}\n{}", "x'y\"z $(not run)\n".repeat(900), "end");
        let commands = staging("/tmp/d/run.sh", &script);
        assert!(commands.len() > 1);
        let mut rebuilt = String::new();
        for (index, command) in commands.iter().enumerate() {
            assert!(command.len() < 32 * 1024, "each piece fits one guest command");
            let words = shell_words::split(command).unwrap();
            assert_eq!(words[0], "printf");
            assert_eq!(words[3], if index == 0 { ">" } else { ">>" });
            rebuilt.push_str(&words[2]);
        }
        assert_eq!(rebuilt, script);
    }

    #[test]
    fn the_tool_environment_matches_the_built_in_tool_shell() {
        assert!(crate::terminal::shared_tool_shell().starts_with(SETUP), "keep SETUP in step with terminal.rs");
        let opened = shell_words::split(&open_command(&tool(&[]))).unwrap();
        assert_eq!(&opened[..3], ["exec", "/bin/sh", "-c"]);
        assert!(opened[3].starts_with(SETUP) && opened[3].ends_with("; aider --yes"));
    }

    #[test]
    fn a_new_tool_passes_its_own_check() {
        let files = new_files("aider");
        let checked = format::tool(&files, "").unwrap_or_else(|p| panic!("{}", p.join(" ")));
        assert_eq!((checked.name(), checked.version()), ("aider", "0.1.0"));
        assert!(scan::scan(&files).refused.is_empty());
    }

    #[test]
    fn names_of_built_in_tools_and_commands_are_refused() {
        for name in ["codex", "claude", "ollama", "template", "run", "status", "env", "model"] {
            assert!(clash(name).is_some(), "{name}");
        }
        assert!(clash("aider").is_none());
        let failed = failure("aider", "shop-web", "install line 1 failed.", "yougori template continue shop");
        assert!(failed.contains("aider did not install in shop-web") && failed.contains("yougori terminal shop-web") && failed.contains("only aider is retried"));
    }

    #[test]
    fn added_tools_are_saved_by_name_and_never_shadow_another() {
        let root = tempfile::tempdir().unwrap();
        let added = Added { root: root.path().to_path_buf() };
        let text = "name: aider\nsummary: Pair programming.\nversion: 1.0.0\nlicense: MIT\ncommand: aider\ncheck: aider --version\n";
        let files: Files = [(format::TOOL_FILE.to_owned(), text.as_bytes().to_vec())].into();
        let parsed = format::tool(&files, "").unwrap();
        added.save(&parsed, &files, json!({"source": "folder", "from": "C:/tools/aider"})).unwrap();
        assert_eq!(added.get("aider").unwrap().unwrap().0.version(), "1.0.0");
        assert!(added.save(&parsed, &files, json!({"source": "hub", "from": "acme/aider"})).unwrap_err().contains("already added from C:/tools/aider"));
        added.save(&parsed, &files, json!({"source": "folder", "from": "C:/tools/aider"})).unwrap();
        assert_eq!(added.list().len(), 1);
        let codex: Files = [(format::TOOL_FILE.to_owned(), text.replace("aider", "codex").into_bytes())].into();
        assert!(added.save(&format::tool(&codex, "").unwrap(), &codex, json!({"source": "folder", "from": "x"})).unwrap_err().contains("is a built-in tool"));
        assert!(added.remove("aider").unwrap());
        assert!(added.get("aider").unwrap().is_none());
    }

    #[test]
    fn a_hub_tool_counts_as_added_before_only_from_the_same_item() {
        let root = tempfile::tempdir().unwrap();
        let added = Added { root: root.path().to_path_buf() };
        let text = "name: aider\nsummary: Pair programming.\nversion: 1.0.0\nlicense: MIT\ncommand: aider\ncheck: aider --version\n";
        let files: Files = [(format::TOOL_FILE.to_owned(), text.as_bytes().to_vec())].into();
        assert!(!added_before(&added, "aider", "acme/aider"));
        added.save(&format::tool(&files, "").unwrap(), &files, json!({"source": "hub", "from": "acme/aider", "verified": false})).unwrap();
        assert!(added_before(&added, "aider", "acme/aider"));
        assert!(!added_before(&added, "aider", "other/aider"));
    }

    #[test]
    fn removing_a_tool_never_deletes_a_folder_named_by_a_path() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("tools");
        std::fs::create_dir_all(root.join("keep")).unwrap();
        std::fs::write(root.join("keep").join("file.txt"), "x").unwrap();
        let outside = home.path().join("my-project");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("main.py"), "print(1)").unwrap();
        let added = Added { root: root.clone() };
        for name in [outside.to_str().unwrap(), "..", "../my-project", "keep", "", "Keep"] {
            assert!(!added.remove(name).unwrap(), "{name}");
        }
        assert!(outside.join("main.py").is_file());
        assert!(root.join("keep").join("file.txt").is_file());
        assert!(home.path().is_dir());
    }
}
