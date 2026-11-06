//! Handlers for the ordinary resources of a recipe: environments (sandboxes), volumes, service
//! publications and connections.
//!
//! They are realised by the same project engine `yougori template run` ends in
//! (`projects::run_project_action`), so a setup gets everything a v1 project gets: each sandbox
//! made once under its ownership name, files and `setup`, name resolution between sandboxes,
//! ports, quick links and domains, connections, readiness probes and cancellation. Each setup has
//! one engine-owned project (`<setups>/projects/<setup-id>/yougori.yaml`). A step changes only its
//! own resource in that project and lets the project converge; the project's stable identities
//! make a repeated or interrupted step safe.
//!
//! Secret values given with `setup_apply` are stored in the OS credential vault exactly as v1
//! deployment secrets are, under setup-scoped names, and the project refers to those names.
use super::handler::{HandlerError, HandlerFuture, HealthReport, Observation, Outcome, Recovery, ResourceHandler, StepContext};
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Health, Observed};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use yougori_cli::manifest::{self, Project};
use yougori_setup::resource::Kind;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub(crate) use yougori_cli::hub::format::Tool;

/// Keeping a folder the person chose and a sandbox's copy of it in step, for a folder binding of
/// mode sync. Declared here rather than in `mod.rs`, which other handlers own.
#[path = "folder_sync.rs"]
pub(crate) mod folder_sync;
#[path = "model_connection.rs"]
mod model_connection;

/// Yougori's coding-tool installer, the same script the terminal installer stages
/// (`workspace::installers`). It runs inside the sandbox, never on this computer.
const INSTALLER: &str = include_str!("../workspace/install-tools.sh");
/// Where the installer puts the tools' environment, as the terminal and CLI read it.
const TOOL_ENV: &str = "[ ! -r \"$HOME/.local/share/yougori/tool-env.sh\" ] || . \"$HOME/.local/share/yougori/tool-env.sh\"";

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Where a sandbox keeps the fingerprint of an installed template tool, as `yougori run` does.
fn tool_marker(tool: &Tool) -> String {
    format!("$HOME/.local/share/yougori/tools/{}", tool.name())
}

/// The private folder `mktemp` made in the sandbox's home for a sign-in copy.
fn signin_stage(path: &str) -> bool {
    yougori_cli::workload::guest_path(path)
        && path
            .rsplit('/')
            .next()
            .and_then(|name| name.strip_prefix(".yougori-credentials-"))
            .is_some_and(|suffix| suffix.len() >= 6 && suffix.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Moves the transferred sign-in files to where the tool reads them, as the CLI does: private
/// modes, no following of links, never into an existing folder.
fn signin_script(stage: &str, imported: &str, files: &[(PathBuf, String)]) -> Result<String, String> {
    let inside = imported.strip_prefix(&format!("{stage}/")).is_some_and(|name| name.starts_with("yougori-import-") && !name.contains('/'));
    if !signin_stage(stage) || !yougori_cli::workload::guest_path(imported) || !inside {
        return Err("the transfer put the files somewhere unexpected".into());
    }
    let mut script = "set -eu; umask 077; cd \"$HOME\"; ".to_owned();
    for (source, target) in files {
        let parts = target.split('/').collect::<Vec<_>>();
        if target.starts_with('/') || parts.iter().any(|part| part.is_empty() || *part == "." || *part == "..") {
            return Err("a sign-in file has an unexpected place".into());
        }
        let mut folder = String::new();
        for part in &parts[..parts.len() - 1] {
            if !folder.is_empty() {
                folder.push('/');
            }
            folder.push_str(part);
            script.push_str(&format!("test ! -L {0}; mkdir -p -- {0}; ", quoted(&folder)));
        }
        let name = source.file_name().and_then(|name| name.to_str()).ok_or("a sign-in file has an unexpected name")?;
        let from = quoted(&format!("{imported}/{name}"));
        script.push_str(&format!("test -f {from}; test ! -L {from}; chmod 600 -- {from}; mv -fT -- {from} {}; ", quoted(target)));
    }
    Ok(script)
}

/// A sandbox as the engine has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sandbox {
    pub id: String,
    pub name: String,
    pub running: bool,
    /// The project ownership stamp the engine keeps on a sandbox a project made.
    pub owner: String,
}

/// What the ordinary handlers need from the engine. `EngineProjects` calls the engine's own
/// functions; tests use a fake, so no real sandbox, port or data folder is touched.
pub(crate) trait Projects: Send + Sync {
    /// Model attachment uses the existing engine calls, never a second model runner.
    fn model_call<'a>(&'a self, _method: &'a str, _params: Value) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async { Err("This backend cannot attach models to templates.".into()) })
    }
    /// Writes the project to `folder` and lets it converge. Returns the sandbox IDs by name.
    fn apply<'a>(&'a self, folder: &'a Path, project: &'a Project, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<BTreeMap<String, String>, String>>;
    /// Stops every sandbox of the project in `folder`, keeping them and their data.
    fn down<'a>(&'a self, folder: &'a Path, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>>;
    /// Writes the project to `folder` without converging it: nothing starts or stops. The next
    /// converge reads it.
    fn write(&self, folder: &Path, project: &Project) -> Result<(), String>;
    fn sandbox(&self, id: &str) -> Option<Sandbox>;
    /// The sandbox the project in `folder` made for `resource`, by the project's ownership
    /// stamp (and its ID, when given): never one that merely has the same name.
    fn owned(&self, folder: &Path, resource: &str, id: Option<&str>) -> Option<Sandbox>;
    fn set_running<'a>(&'a self, id: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>>;
    fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), String>>;
    fn store_secret(&self, name: &str, value: &str) -> Result<(), String>;
    fn forget_secret(&self, name: &str) -> Result<(), String>;
    fn volume_exists<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<bool, String>>;
    /// Deletes a named volume and everything on it, from every place this engine keeps volumes.
    /// Refused while any sandbox still uses it. `Ok` only when it is gone from all of them: one
    /// that could not be checked is an error, never a quiet "probably gone".
    fn remove_volume<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// The publication of `port` on `sandbox`, if there is one.
    /// The publication of the sandbox's port of `kind` (`cloudflare`, or `loopback` for one kept to
    /// this computer), by its ID.
    fn publication<'a>(&'a self, sandbox: &'a str, port: u16, kind: &'a str) -> BoxFuture<'a, Result<Option<String>, String>>;
    /// The address a publication of the sandbox's port has, of `kind` (`cloudflare` for a public
    /// one, `loopback` for one kept to this computer), while it is open.
    fn address<'a>(&'a self, sandbox: &'a str, port: u16, kind: &'a str) -> BoxFuture<'a, Result<Option<String>, String>>;
    fn unpublish<'a>(&'a self, publication: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// Opens the sandbox's port to the computers of this local network at `host` on this computer
    /// (a `local` publication: other addresses than private, link-local and loopback ones are
    /// dropped). Answers its ID. Opening one that is already open answers the same one.
    fn publish_local<'a>(&'a self, sandbox: &'a str, port: u16, host: u16) -> BoxFuture<'a, Result<String, String>>;
    /// Asks `path` at `address` (`http://127.0.0.1:PORT`, an address on this network, or a public
    /// `https://` one) with a GET, and answers the HTTP status. Redirects are not followed.
    fn probe<'a>(&'a self, address: &'a str, path: &'a str) -> BoxFuture<'a, Result<u16, String>>;
    /// The connection from `source` to `target`, if there is one.
    fn connection(&self, source: &str, target: &str) -> Option<String>;
    fn remove_connection<'a>(&'a self, connection: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// The project engine's readiness report for one of the project's sandboxes: its probes'
    /// results (`ready`, `applicationVerified`, `verifiedPublicly`, `retryable`, `stages`).
    fn readiness<'a>(&'a self, folder: &'a Path, resource: &'a str) -> BoxFuture<'a, Result<Value, String>>;
    /// Whether a built-in coding tool is installed in the sandbox.
    fn tool_ready<'a>(&'a self, sandbox: &'a str, tool: &'a str) -> BoxFuture<'a, Result<bool, String>>;
    /// Installs a built-in coding tool in the sandbox with Yougori's own installer, without a
    /// terminal, and waits for it to finish. Nothing is launched.
    fn install_tool<'a>(&'a self, sandbox: &'a str, tool: &'a str, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>>;
    /// Whether this exact template tool (its version, install lines and check) is in the sandbox
    /// and its check passes, as `yougori run` records it.
    fn custom_ready<'a>(&'a self, sandbox: &'a str, tool: &'a Tool) -> BoxFuture<'a, Result<bool, String>>;
    /// Runs a template tool's install lines in the sandbox, as `yougori run` does, and proves it
    /// with its check.
    fn install_custom<'a>(&'a self, sandbox: &'a str, tool: &'a Tool, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>>;
    /// Copies the tool's sign-in from this computer into the sandbox, as the CLI does when a person
    /// chooses to use it. Called only on that explicit choice. `false`: there is none here.
    fn copy_signin<'a>(&'a self, sandbox: &'a str, tool: &'a str, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<bool, String>>;

    // ---- One synced folder's side inside the sandbox (a folder binding of mode sync) ----

    /// The checksum of every file under `folder` in the sandbox, by its path relative to it.
    fn folder_files<'a>(&'a self, sandbox: &'a str, folder: &'a str) -> BoxFuture<'a, Result<folder_sync::Checksums, String>>;
    /// Copies one file of this computer into `folder` in the sandbox, under `relative`.
    fn send_file<'a>(&'a self, sandbox: &'a str, from: &'a Path, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// Copies one file of the sandbox out to `to` on this computer.
    fn receive_file<'a>(&'a self, sandbox: &'a str, folder: &'a str, relative: &'a str, to: &'a Path) -> BoxFuture<'a, Result<(), String>>;
    /// Deletes one file under `folder` in the sandbox. Never a folder, and never outside it.
    fn remove_file<'a>(&'a self, sandbox: &'a str, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// One sandbox's side of a synced folder, as the folder sync moves files through it.
struct SandboxFolder {
    projects: Arc<dyn Projects>,
    sandbox: String,
}

impl folder_sync::Transfer for SandboxFolder {
    fn files<'a>(&'a self, folder: &'a str) -> BoxFuture<'a, Result<folder_sync::Checksums, String>> {
        self.projects.folder_files(&self.sandbox, folder)
    }
    fn send<'a>(&'a self, from: &'a Path, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>> {
        self.projects.send_file(&self.sandbox, from, folder, relative)
    }
    fn receive<'a>(&'a self, folder: &'a str, relative: &'a str, to: &'a Path) -> BoxFuture<'a, Result<(), String>> {
        self.projects.receive_file(&self.sandbox, folder, relative, to)
    }
    fn remove<'a>(&'a self, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>> {
        self.projects.remove_file(&self.sandbox, folder, relative)
    }
}

/// The coding tools Yougori installs by name.
const BUILT_IN_TOOLS: [&str; 7] = ["codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw"];

/// The name people know a built-in tool by.
fn product(tool: &str) -> &str {
    match tool {
        "codex" => "Codex",
        "claude" => "Claude Code",
        "gemini" => "Gemini CLI",
        "opencode" => "OpenCode",
        "kilo" => "Kilo Code",
        "ollama" => "Ollama",
        "openclaw" => "OpenClaw",
        _ => tool,
    }
}

/// Whether the plan copies this computer's sign-in for the tool: only for a subscription sign-in
/// whose person chose "use credentials from this computer".
fn copies_signin(tool: &Value) -> bool {
    tool["signin"].as_bool() == Some(true) && tool["copy_credentials"].as_bool() == Some(true)
}

/// The four handlers and what they share: the engine, the folder of setup projects, and where
/// a Hub tool's checked files are read from when a plan installs one.
#[derive(Clone)]
pub(crate) struct Ordinary {
    projects: Arc<dyn Projects>,
    folder: PathBuf,
    tools: Arc<dyn super::hub_tools::ToolFiles>,
}

impl Ordinary {
    /// `folder` is `<setups>/projects`; Hub tools are read from the cache beside it
    /// (`<setups>/hub-cache`), the same one the planner's resolver fills.
    pub(crate) fn new(projects: Arc<dyn Projects>, folder: PathBuf) -> Self {
        let engine_cache = folder.parent().map(|setups| setups.join("hub-cache")).unwrap_or_else(|| folder.join("hub-cache"));
        Self { projects, folder, tools: Arc::new(super::hub_tools::EngineToolFiles::new(engine_cache)) }
    }

    /// The same handlers, reading Hub tools from `tools` instead of the cache: for tests.
    #[cfg(test)]
    pub(crate) fn with_tool_files(mut self, tools: Arc<dyn super::hub_tools::ToolFiles>) -> Self {
        self.tools = tools;
        self
    }

    pub(crate) fn handlers(&self) -> Vec<Arc<dyn ResourceHandler>> {
        vec![
            Arc::new(EnvironmentHandler(self.clone())),
            Arc::new(VolumeHandler(self.clone())),
            Arc::new(PublicationHandler(self.clone())),
            Arc::new(ConnectionHandler(self.clone())),
        ]
    }

    fn folder(&self, setup: &str) -> PathBuf {
        self.folder.join(setup)
    }

    /// The names of every vault entry this setup's sandboxes were given, written before each
    /// value goes in, so they can all be forgotten when the setup goes.
    fn ledger(&self, setup: &str) -> PathBuf {
        self.folder(setup).join("vault-names")
    }

    /// Whether every other sandbox of the setup is running, so converging its project starts
    /// nothing that was stopped.
    fn all_running(&self, context: &StepContext) -> bool {
        context
            .peers
            .iter()
            .filter(|(id, peer)| peer.owned && peer.kind == Kind::Environment && *id != &context.resource)
            .all(|(_, peer)| peer.runtime_id.as_deref().and_then(|id| self.projects.sandbox(id)).is_none_or(|sandbox| sandbox.running))
    }

    /// Takes a resource out of the setup's project. With every other sandbox running the project
    /// converges as usual; otherwise only its file is rewritten (`false`), and the caller undoes
    /// its own effect directly, so a stopped setup stays stopped. The next converge reads the
    /// new file.
    async fn release(&self, context: &StepContext, project: &Project) -> Result<bool, HandlerError> {
        if self.all_running(context) {
            self.converge(context, project).await?;
            return Ok(true);
        }
        self.projects.write(&self.folder(&context.setup), project).map_err(|error| interrupted_or(context, error))?;
        Ok(false)
    }

    /// Forgets vault entries and their ledger lines, away from the async runtime.
    async fn forget(&self, setup: &str, names: Vec<String>) {
        if names.is_empty() {
            return;
        }
        let (projects, ledger) = (self.projects.clone(), self.ledger(setup));
        let _ = tokio::task::spawn_blocking(move || {
            let mut kept = read_ledger(&ledger);
            for name in &names {
                if projects.forget_secret(name).is_ok() {
                    kept.remove(name);
                }
            }
            write_ledger(&ledger, &kept)
        })
        .await;
    }

    /// Forgets every vault entry the setup's ledger names, when the setup itself goes.
    pub(crate) async fn sweep(&self, setup: &str) {
        let ledger = self.ledger(setup);
        let names = tokio::task::spawn_blocking(move || read_ledger(&ledger)).await.unwrap_or_default();
        self.forget(setup, names.into_iter().collect()).await;
    }

    /// The project with the setup's recorded ordinary resources, after `change`.
    fn project(&self, context: &StepContext, change: Change<'_>) -> Result<Project, HandlerError> {
        let mut resources = context
            .peers
            .iter()
            .filter(|(_, peer)| peer.owned)
            .map(|(id, peer)| (id.clone(), (peer.kind, peer.spec.clone())))
            .collect::<BTreeMap<_, _>>();
        if let Change::Put(kind, spec) = change {
            resources.insert(context.resource.clone(), (kind, spec.clone()));
        }
        let mut project = Project {
            project: project_name(&context.setup),
            environments: BTreeMap::new(),
            connections: Vec::new(),
            publish: BTreeMap::new(),
        };
        let mut here = Vec::new();
        for (id, (kind, spec)) in &resources {
            match kind {
                Kind::Environment => {
                    project.environments.insert(id.clone(), environment(&context.setup, id, spec, &self.folder(&context.setup).join("package"))?);
                }
                Kind::ServicePublication => match publication(spec)? {
                    (target, Opening::Public(publication)) => {
                        if project.publish.insert(target.clone(), publication).is_some() {
                            return Err(refused(&format!("{target} already has a public address in this setup; one per sandbox is supported.")));
                        }
                    }
                    (target, Opening::Here(port)) => here.push((target, port, here_port(&context.setup, id))),
                    // Opened by its own handler, beside the project: the project has no way to
                    // say a port is for this network.
                    (_, Opening::Lan(_) | Opening::Nothing) => {}
                },
                Kind::Connection => project.connections.extend(connections(spec)?),
                _ => {}
            }
        }
        // A connection to a sandbox outside this project (one another setup owns, or one being
        // removed) can't be delivered here. Left in, it made every change to the project fail,
        // removing the setup included; the review refuses new ones (`ConnectionHandler::review`).
        project.connections.retain(|connection| connection.endpoints().is_ok_and(|(from, to)| project.environments.contains_key(from) && project.environments.contains_key(to)));
        // A port kept to this computer is the sandbox's own port, published at 127.0.0.1 only.
        for (target, port, host) in here {
            if let Some(environment) = project.environments.get_mut(&target) {
                environment.ports.retain(|given| given.values().map_or(true, |(guest, _)| guest != port));
                environment.ports.push(manifest::Port::Detailed { target: port, published: Some(host) });
            }
        }
        Ok(project)
    }

    async fn converge(&self, context: &StepContext, project: &Project) -> Result<BTreeMap<String, String>, HandlerError> {
        let folder = self.folder(&context.setup);
        self.projects.apply(&folder, project, &context.cancel).await.map_err(|error| interrupted_or(context, error))
    }

    /// The sandbox ID of another resource of this setup.
    fn sandbox_of(&self, context: &StepContext, resource: &str) -> Result<String, HandlerError> {
        context
            .peers
            .get(resource)
            .filter(|peer| peer.kind == Kind::Environment)
            .and_then(|peer| peer.runtime_id.clone())
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", format!("{resource} doesn't exist yet in this setup.")))
    }
}

fn read_ledger(path: &Path) -> std::collections::BTreeSet<String> {
    std::fs::read_to_string(path).map(|text| text.lines().filter(|line| !line.is_empty()).map(str::to_owned).collect()).unwrap_or_default()
}

fn write_ledger(path: &Path, names: &std::collections::BTreeSet<String>) -> Result<(), String> {
    let folder = path.parent().ok_or("The setup's folder is missing")?;
    if names.is_empty() {
        return match std::fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
            _ => Ok(()),
        };
    }
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    let text = names.iter().map(|name| format!("{name}\n")).collect::<String>();
    std::io::Write::write_all(&mut file, text.as_bytes()).map_err(|error| error.to_string())?;
    file.as_file().sync_all().map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.error.to_string())?;
    Ok(())
}

enum Change<'a> {
    Put(Kind, &'a Value),
    Leave,
}

/// One project per setup: `setup-` and the first eight characters of its ID.
fn project_name(setup: &str) -> String {
    let id = setup.trim_start_matches("setup-");
    format!("setup-{}", &id[..id.len().min(8)])
}

/// The vault name of a secret this setup's sandbox reads as `variable`.
/// The vault name of one of a sandbox's secrets: readable, within the vault's 80 characters,
/// and with a hash of the exact setup, resource and variable so two never share an entry (the
/// readable part is lower case and may be cut short).
fn secret_name(setup: &str, resource: &str, variable: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(format!("{setup}\0{resource}\0{variable}").as_bytes()));
    let readable = format!("{}-{resource}-{}", project_name(setup), variable.to_ascii_lowercase())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(80 - 13)
        .collect::<String>();
    format!("{readable}-{}", &hash[..12])
}

/// Whether a sandbox's secret binding is one a setup may use: a value given when it is applied
/// (`apply.FIELD`), or the key the planner names for one of the sandbox's own template tools
/// (`hub-INSTANCE-key-TOOL`), which is given the same way. Never a stored entry read by its
/// name, such as another product's keys.
fn usable_binding(binding: &str, spec: &Value) -> bool {
    if binding.strip_prefix("apply.").is_some_and(|field| !field.is_empty()) {
        return true;
    }
    let tool = binding.strip_prefix("hub-").and_then(|rest| rest.rsplit_once("-key-")).map(|(_, tool)| tool);
    // A tool's key is named after its own file's name: a bundled tool's name, or the name of a
    // Hub item (`PUBLISHER/NAME`), which its file must match (`hub_tools::read`).
    tool.is_some_and(|tool| {
        spec["tools"].as_array().into_iter().flatten().any(|each| match each["source"].as_str() {
            Some("bundled") => each["name"] == tool,
            Some("hub") => each["item"].as_str().or(each["name"].as_str()).and_then(|item| item.rsplit('/').next()) == Some(tool),
            _ => false,
        })
    })
}

/// The person's agreement, asked on the review, to copy a tool's sign-in from this computer.
fn consent(resource: &str, tool: &str) -> String {
    format!("copy_signin:{resource}/{tool}")
}

/// The person's agreement, asked on the review, to let a sandbox change files in a folder of
/// this computer they chose for a folder binding.
pub(crate) fn folder_consent(resource: &str, binding: &str) -> String {
    format!("write_folder:{resource}/{binding}")
}

/// The person's choice, asked on a removal's review, to delete a volume and its backups with the
/// setup. Offered only when the template says `retention.onRemove: ask`, and never ticked for them.
pub(crate) const DELETE_DATA: &str = "delete_data:";

pub(crate) fn delete_consent(volume: &str) -> String {
    format!("{DELETE_DATA}{volume}")
}

/// The folders of this computer a sandbox may change: each bound folder the plan gives it
/// writable, mounted or synced, with the folder as the plan resolved it.
pub(crate) fn writable_folders(spec: &Value) -> Vec<(String, String, bool)> {
    let entries = |list: &str, synced: bool| {
        spec[list]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| entry["read_only"] == false)
            .filter_map(|entry| {
                let binding = entry["binding"].as_str()?;
                Some((binding.to_owned(), entry["path"].as_str().unwrap_or_default().to_owned(), synced))
            })
            .collect::<Vec<_>>()
    };
    entries("pc_access", false).into_iter().chain(entries("sync", true)).collect()
}

/// What applying a step on this sandbox needs the person to agree to, for the review.
pub(crate) fn consents(setup: &str, resource: &str, spec: &Value) -> Vec<Value> {
    let sandbox = format!("{}-{resource}", project_name(setup));
    let mut asked: Vec<Value> = writable_folders(spec)
        .into_iter()
        .map(|(binding, path, synced)| {
            json!({
                "id": folder_consent(resource, &binding),
                "message": if synced {
                    format!("Let {sandbox} change files in {path}, the folder you chose for {binding}. Changes travel both ways; a file changed in both places keeps both copies.")
                } else {
                    format!("Let {sandbox} change files in {path}, the folder you chose for {binding}. Anything that controls that sandbox can change those files.")
                },
            })
        })
        .collect();
    asked.extend(tool_consents(&sandbox, resource, spec));
    asked
}

/// The sign-in copies this sandbox's tools may make, for the review.
fn tool_consents(sandbox: &str, resource: &str, spec: &Value) -> Vec<Value> {
    spec["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|tool| copies_signin(tool))
        .map(|tool| {
            let name = tool["name"].as_str().unwrap_or_default();
            json!({
                "id": consent(resource, name),
                "message": format!("Copy your {} sign-in from this computer into {sandbox}. Anyone who controls that sandbox can use the account.", product(name)),
            })
        })
        .collect()
}

fn refused(message: &str) -> HandlerError {
    HandlerError::new(Outcome::Unsupported, "unsupported_here", format!("{message} Nothing was changed."))
}

fn invalid(message: String) -> HandlerError {
    HandlerError::new(Outcome::Failed, "invalid_spec", message)
}

/// A project error after the call began may have left work half done: the outcome is unknown
/// and is settled by looking. One refused before anything ran says so.
fn interrupted_or(context: &StepContext, error: String) -> HandlerError {
    let message = crate::lifecycle::safe_diagnostic(&error);
    if context.cancel.is_cancelled() {
        return HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("Cancelled while the sandbox was being set up: {message}"));
    }
    HandlerError::new(Outcome::Unknown, "project_failed", message)
}

/// The v1 environment for a v2 sandbox specification. The two share their fields; the v2 `tools`
/// are installed by the handler once the sandbox runs, secret bindings become vault names, and `files:` sources,
/// paths inside the template, become the setup's kept copy of them (`package`).
fn environment(setup: &str, id: &str, spec: &Value, package: &Path) -> Result<manifest::Environment, HandlerError> {
    let mut value = spec.clone();
    let object = value.as_object_mut().ok_or_else(|| invalid(format!("The settings of {id} are not an object.")))?;
    object.remove("tools");
    // A synced folder is not a v1 field: the sandbox keeps its own copy, and the handler's folder
    // sync keeps the two in step. Only the mounted folders reach the project engine.
    object.remove("sync");
    if let Some(folders) = object.get_mut("pc_access").and_then(Value::as_array_mut) {
        for folder in folders.iter_mut() {
            // The planner put the person's folder in `path` and the binding's access in
            // `read_only`; v1 knows neither the binding nor an empty path.
            let bound = folder.as_object_mut().and_then(|entry| entry.remove("binding"));
            if bound.is_some() && folder["path"].as_str().unwrap_or_default().is_empty() {
                return Err(invalid(format!("{id}: a folder you chose has no path; plan the setup again.")));
            }
        }
    }
    if let Some(files) = object.get_mut("files").and_then(Value::as_array_mut) {
        for file in files.iter_mut() {
            let source = file["source"].as_str().unwrap_or_default().to_owned();
            let copied = super::package::resolve(package, &source).map_err(|problem| invalid(format!("{id}: {problem}")))?;
            file["source"] = json!(copied.to_string_lossy());
        }
    }
    if let Some(secrets) = object.get_mut("secrets").and_then(Value::as_object_mut) {
        secrets.retain(|_, binding| binding.as_str().is_some_and(|text| !text.is_empty()));
        // Each value given at apply is in the vault under this setup's own name; a sandbox never
        // reads another entry by a name the template wrote (refused at review in any case).
        for (variable, binding) in secrets.iter_mut() {
            *binding = json!(secret_name(setup, id, variable));
        }
    }
    serde_json::from_value(value).map_err(|error| invalid(format!("The settings of {id} are not valid: {error}")))
}

/// What a publication opens on its sandbox's port.
#[derive(Debug, PartialEq)]
enum Opening {
    /// An address other people reach: a quick link or a saved domain.
    Public(manifest::Publication),
    /// A port on this computer only (`access: private`), at 127.0.0.1.
    Here(u16),
    /// A port the computers of this local network reach (`access: lan`), on this computer's
    /// address there. Anything from outside private, link-local and loopback addresses is dropped.
    Lan(u16),
    /// Nothing (`access: none`): the port is reached from inside the setup's sandboxes.
    Nothing,
}

impl Opening {
    /// The kind of publication the engine lists for it: `cloudflare` for a public address,
    /// `loopback` for a port on this computer. None for one that opens nothing.
    fn listed(&self) -> Option<&'static str> {
        match self {
            Opening::Public(_) => Some("cloudflare"),
            Opening::Here(_) => Some("loopback"),
            Opening::Lan(_) => Some("local"),
            Opening::Nothing => None,
        }
    }
}

/// The port on this computer that a publication kept to it listens on. The same for every
/// change to the setup, so the address stays put, and a different one for each setup and
/// publication, so two copies of one setup never ask for the same port. 20000 to 39999, clear of
/// the ports applications listen on by default.
pub(crate) fn here_port(setup: &str, resource: &str) -> u16 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{setup}/{resource}").as_bytes());
    20000 + u16::from_be_bytes([digest[0], digest[1]]) % 20000
}

/// The sandbox a publication opens, and what it opens there.
fn publication(spec: &Value) -> Result<(String, Opening), HandlerError> {
    let target = spec["target"]["resource"]
        .as_str()
        .ok_or_else(|| invalid("A publication names the sandbox it opens with target: {resource: ID}.".into()))?
        .to_owned();
    let port = spec["port"].as_u64().filter(|port| (1..=65535).contains(port)).ok_or_else(|| invalid("A publication needs a port from 1 to 65535.".into()))? as u16;
    let detailed = |domain: Option<String>| manifest::Publication::Detailed { port, hostname: None, token_env: None, domain };
    let opened = match spec["access"].as_str().unwrap_or("quick") {
        "quick" => Opening::Public(detailed(None)),
        "domain" => Opening::Public(detailed(Some(
            spec["domain"].as_str().filter(|domain| !domain.is_empty()).ok_or_else(|| invalid("access: domain needs a saved domain.".into()))?.to_owned(),
        ))),
        "private" => Opening::Here(port),
        "none" => Opening::Nothing,
        "lan" => Opening::Lan(port),
        other => return Err(invalid(format!("access {other} is not one Yougori knows."))),
    };
    Ok((target, opened))
}

/// The v1 connections for a v2 connection: two for one that goes both ways.
fn connections(spec: &Value) -> Result<Vec<manifest::Connection>, HandlerError> {
    let end = |field: &str| {
        spec[field]["resource"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid(format!("A connection names its {field} with {field}: {{resource: ID}}.")))
    };
    let (from, to) = (end("from")?, end("to")?);
    let ports: Vec<u16> = spec["ports"].as_array().map(|ports| ports.iter().filter_map(Value::as_u64).map(|port| port as u16).collect()).unwrap_or_default();
    let permissions: Vec<String> = spec["permissions"].as_array().map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
    let one = |from: &str, to: &str| manifest::Connection::Detailed { from: from.to_owned(), to: to.to_owned(), ports: ports.clone(), permissions: permissions.clone() };
    Ok(if spec["direction"].as_str() == Some("two_way") { vec![one(&from, &to), one(&to, &from)] } else { vec![one(&from, &to)] })
}

fn health(health: Health, detail: impl Into<String>) -> HealthReport {
    HealthReport { health, detail: detail.into() }
}

/// GET `path` at `address`, with no proxy and no redirect, within ten seconds: the HTTP status.
/// The path stays on the address's own origin.
pub(crate) async fn probe_address(address: &str, path: &str) -> Result<u16, String> {
    let base = url::Url::parse(address).map_err(|_| "its address isn't a web address".to_owned())?;
    if !matches!(base.scheme(), "http" | "https") || !base.username().is_empty() || base.password().is_some() {
        return Err("its address isn't a plain web address".into());
    }
    let url = base.join(path).map_err(|_| "the health path isn't a path".to_owned())?;
    if url.origin() != base.origin() {
        return Err("the health path leaves the address".into());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| "the check couldn't be prepared".to_owned())?;
    let answered = client.get(url).send().await.map_err(|error| if error.is_timeout() { "it took longer than ten seconds".to_owned() } else { "nothing answered".to_owned() })?;
    Ok(answered.status().as_u16())
}

/// A sandbox's health from the project's own probes. Ready only when its configured health
/// check passed (and, with a public address, passed there too): a running sandbox alone proves
/// nothing about the application inside it.
fn probed(spec: &Value, report: &Value) -> HealthReport {
    let public = report["stages"]["publicHttps"]["status"].as_str().is_some_and(|status| status != "notConfigured");
    if spec["health"].is_null() {
        return health(Health::Unknown, "Running. No health check is configured, so Yougori can't tell whether the application works.");
    }
    match (report["applicationVerified"].as_bool(), report["verifiedPublicly"].as_bool()) {
        (Some(true), Some(true)) => health(Health::Ready, "Its health check passed, at its public address too."),
        (Some(true), _) if !public => health(Health::Ready, "Its health check passed."),
        (Some(true), _) => health(Health::Degraded, "Its health check passes here, but not yet at its public address."),
        _ if report["retryable"] == true => health(Health::Starting, "Its health check hasn't passed yet."),
        _ => health(Health::Failed, "Its health check is failing. Look at its logs, then restart it."),
    }
}

fn receipt(runtime_id: Option<String>, observed: Observed, retained_data: bool, cost: Cost) -> Receipt {
    Receipt { runtime_id, observed, retained_data, cost, at: now(), adopted: false }
}

fn unknown(error: String) -> Observation {
    Observation::Unknown { reason: crate::lifecycle::safe_diagnostic(&error) }
}

// ----- Environments -----

pub(crate) struct EnvironmentHandler(Ordinary);

impl EnvironmentHandler {
    /// The sandbox this setup's project made for this resource.
    fn own(&self, context: &StepContext) -> Option<Sandbox> {
        self.0.projects.owned(&self.0.folder(&context.setup), &context.resource, context.runtime_id.as_deref())
    }

    /// Stores the secret values this sandbox reads, given with this operation, and returns the
    /// vault names this attempt added, to forget again if nothing comes of it. Each name goes in
    /// the setup's ledger before its value goes in the vault. A binding without a value is fine
    /// only if an earlier step of this resource already stored it.
    async fn store_secrets(&self, context: &StepContext) -> Result<Vec<String>, HandlerError> {
        let Some(secrets) = context.spec["secrets"].as_object() else { return Ok(Vec::new()) };
        let applied_before = context.runtime_id.is_some();
        let mut given = Vec::new();
        for (variable, binding) in secrets {
            let binding = binding.as_str().unwrap_or_default();
            if binding.is_empty() {
                continue;
            }
            match context.secret(binding) {
                Some(value) => given.push((secret_name(&context.setup, &context.resource, variable), value.to_owned())),
                None if applied_before => {}
                None => {
                    let field = binding.trim_start_matches("apply.");
                    return Err(HandlerError::new(
                        Outcome::NeedsInput,
                        "secret_needed",
                        format!("{} needs the value of {field} before it can be created.", context.resource),
                    )
                    .at(field))
                }
            }
        }
        let (projects, ledger) = (self.0.projects.clone(), self.0.ledger(&context.setup));
        let stored = tokio::task::spawn_blocking(move || {
            let mut names = read_ledger(&ledger);
            let mut added = Vec::new();
            for (name, value) in given {
                let new = names.insert(name.clone());
                let result = (if new { write_ledger(&ledger, &names) } else { Ok(()) }).and_then(|()| projects.store_secret(&name, &value));
                if new {
                    added.push(name.clone());
                }
                if let Err(error) = result {
                    for name in &added {
                        let _ = projects.forget_secret(name);
                        names.remove(name);
                    }
                    let _ = write_ledger(&ledger, &names);
                    return Err(error);
                }
            }
            Ok(added)
        })
        .await
        .map_err(|_| "The vault could not be reached".to_owned())
        .and_then(|result| result);
        stored.map_err(|error| HandlerError::new(Outcome::NotStarted, "vault_unavailable", crate::lifecycle::safe_diagnostic(&error)))
    }

    /// Converges the project with this sandbox, installs its tools, and says what it made.
    async fn converge(&self, context: &StepContext) -> Result<Receipt, HandlerError> {
        let project = self.0.project(context, Change::Put(Kind::Environment, &context.spec))?;
        let created_before = self.own(context).is_some();
        let ids = match self.0.converge(context, &project).await {
            Ok(ids) => ids,
            // Nothing was made: safe to say so plainly. Otherwise the outcome is settled by looking.
            Err(error) if !created_before && self.own(context).is_none() => {
                return Err(HandlerError { outcome: Outcome::Failed, retryable: true, ..error });
            }
            Err(error) => return Err(error),
        };
        let id = ids
            .get(&context.resource)
            .cloned()
            .ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The project didn't report this sandbox."))?;
        self.install_tools(context, &id, created_before).await?;
        self.sync_folders(context, &id).await?;
        let running = self.0.projects.sandbox(&id).is_some_and(|sandbox| sandbox.running);
        Ok(receipt(Some(id), if running { Observed::Running } else { Observed::Stopped }, Self::keeps_data(&context.spec), Self::cost(&context.spec)))
    }

    /// Where this setup keeps what the two copies of a synced folder last shared.
    fn sync_record(&self, context: &StepContext, binding: &str) -> PathBuf {
        folder_sync::record_path(&self.0.folder(&context.setup), &context.resource, binding)
    }

    /// Brings each folder the person chose for a binding of mode sync in step with the sandbox's
    /// copy, once the sandbox is there. A writable folder is touched only with the person's
    /// agreement, given when the setup was applied; without it the folder is left alone and the
    /// step says so, rather than changing files they did not agree to.
    async fn sync_folders(&self, context: &StepContext, sandbox: &str) -> Result<(), HandlerError> {
        for folder in folder_sync::folders(&context.spec) {
            if !folder.read_only && !context.consents.contains(&folder_consent(&context.resource, &folder.binding)) {
                return Err(HandlerError::new(
                    Outcome::NeedsInput,
                    "folder_consent_needed",
                    format!(
                        "{} keeps a copy of the folder you chose for {} and changes files in it, so it needs your agreement when the setup is applied. Review the setup again and agree to that, or make the folder read only in the template.",
                        context.resource, folder.binding
                    ),
                ));
            }
            let transfer = SandboxFolder { projects: self.0.projects.clone(), sandbox: sandbox.to_owned() };
            let record = self.sync_record(context, &folder.binding);
            match folder_sync::run(&folder, &transfer, &record).await {
                // A pass that stopped did not sync the folder, whatever it answered. A template
                // asks for `conflicts: stop` precisely so that a file changed on both sides is
                // not quietly passed over, so letting the step complete here would report the
                // setup Ready with a folder that is not syncing — the one thing that setting
                // exists to prevent. Nothing was changed, so this is retryable: once the two
                // copies match, Try again (a retry, which converges again) finishes it. Start
                // would not: it never runs a pass.
                //
                // The message says what DID succeed first, so a failed change is not read as
                // "nothing worked": by now this sandbox exists and its tools are in
                // (`install_tools` runs just before this), and every step before it is done.
                Ok(report) if report.stopped.is_some() => {
                    let stopped = report.note(&folder.binding).unwrap_or_else(|| format!("The folder you chose for {} is not syncing.", folder.binding));
                    return Err(HandlerError {
                        retryable: true,
                        ..HandlerError::new(
                            Outcome::Failed,
                            "folder_sync_stopped",
                            format!("{} is set up and its tools are installed, and everything before it in this setup is in place. {stopped}", context.resource),
                        )
                    });
                }
                Ok(_) => {}
                Err(problem) if context.cancel.is_cancelled() => {
                    return Err(HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("Cancelled while the folder you chose for {} was syncing: {}", folder.binding, crate::lifecycle::safe_diagnostic(&problem))));
                }
                Err(problem) => {
                    // Both copies are still there; only what did not travel is unsynced, and the
                    // next pass sees it again.
                    return Err(HandlerError {
                        retryable: true,
                        ..HandlerError::new(
                            Outcome::Failed,
                            "folder_sync_failed",
                            format!(
                                "The folder you chose for {} did not finish syncing: {}. Nothing was lost: both copies are as they were, and trying this change again syncs what is left.",
                                folder.binding,
                                crate::lifecycle::safe_diagnostic(&problem)
                            ),
                        )
                    });
                }
            }
        }
        Ok(())
    }

    /// Installs the plan's built-in tools that aren't there yet, then copies a sign-in where the
    /// person chose this computer's. A retry installs only what is missing; the tools live in the
    /// sandbox and go with it. Their API keys reach the sandbox only as its own secrets, given
    /// with this operation. Nothing is launched.
    ///
    /// A sandbox this step made, and no record holds yet, is taken down again when this fails,
    /// so nothing is left half-made; retrying makes it afresh. Named volumes are kept.
    async fn install_tools(&self, context: &StepContext, sandbox: &str, created_before: bool) -> Result<(), HandlerError> {
        let Err(error) = self.tools(context, sandbox).await else { return Ok(()) };
        if context.action != Action::Create || context.runtime_id.is_some() || created_before {
            return Err(error);
        }
        match self.0.projects.delete(sandbox).await {
            Ok(()) if context.cancel.is_cancelled() => Err(HandlerError { outcome: Outcome::NotStarted, ..error }),
            Ok(()) => Err(HandlerError { outcome: Outcome::Failed, retryable: true, ..error }),
            // Still there: settled by looking, as any half-known step is.
            Err(_) => Err(HandlerError { outcome: Outcome::Unknown, ..error }),
        }
    }

    async fn tools(&self, context: &StepContext, sandbox: &str) -> Result<(), HandlerError> {
        for tool in context.spec["tools"].as_array().into_iter().flatten() {
            let name = tool["name"].as_str().unwrap_or_default();
            let failed = |error: String| {
                if context.cancel.is_cancelled() {
                    return HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("Cancelled while {} was installing.", product(name)));
                }
                let message = format!("{} did not install: {}. Retry installs only what is missing.", product(name), crate::lifecycle::safe_diagnostic(&error));
                HandlerError { retryable: true, ..HandlerError::new(Outcome::Failed, "tool_install_failed", message) }
            };
            // A tool with its own file, from the template's folder or from the Hub: one path.
            if matches!(tool["source"].as_str(), Some("bundled" | "hub")) {
                let custom = self.custom(context, tool).await?;
                if !self.0.projects.custom_ready(sandbox, &custom).await.map_err(|error| interrupted_or(context, error))? {
                    self.0.projects.install_custom(sandbox, &custom, &context.cancel).await.map_err(failed)?;
                }
                continue;
            }
            let ready = self.0.projects.tool_ready(sandbox, name).await.map_err(|error| interrupted_or(context, error))?;
            if !ready {
                self.0.projects.install_tool(sandbox, name, &context.cancel).await.map_err(failed)?;
            }
            // Once, when the tool first arrives, and only with the person's agreement given when
            // applying: a later change never replaces a sign-in made inside.
            let agreed = context.consents.contains(&consent(&context.resource, name));
            if copies_signin(tool) && agreed && (!ready || context.action == Action::Create) {
                self.0.projects.copy_signin(sandbox, name, &context.cancel).await.map_err(|_| {
                    let message = format!("Copying your {} sign-in from this computer did not finish. Retry, or plan again and choose to sign in inside the sandbox.", product(name));
                    HandlerError { retryable: true, ..HandlerError::new(Outcome::Failed, "tool_signin_failed", message) }
                })?;
            }
        }
        Ok(())
    }

    /// A tool's own checked file: a bundled tool's from the setup's kept package copy, a Hub
    /// tool's from the checked copy the plan's resolver kept, every file hashed again. A Hub
    /// tool whose files no longer match what the plan recorded is refused, never substituted.
    async fn custom(&self, context: &StepContext, tool: &Value) -> Result<Tool, HandlerError> {
        let name = tool["name"].as_str().unwrap_or_default();
        if tool["source"].as_str() == Some("hub") {
            let item = tool["item"].as_str().unwrap_or(name);
            let (publisher, tool_name) = super::hub_tools::split_item(item).ok_or_else(|| invalid(format!("{name} is not a Hub tool Yougori knows how to install.")))?;
            let version = tool["version"].as_str().map(str::trim).filter(|version| !version.is_empty()).ok_or_else(|| invalid(format!("{name} is not pinned to a version; plan the setup again.")))?;
            let fetched = self.0.tools.load(publisher, tool_name, version).await.map_err(|problem| {
                let message = format!("{}'s files could not be read: {}. Retry fetches them again.", product(name), crate::lifecycle::safe_diagnostic(&problem));
                HandlerError { retryable: true, ..HandlerError::new(Outcome::Failed, "tool_unavailable", message) }
            })?;
            // The plan may record the digest its review showed; files that hash otherwise are
            // not what was agreed to.
            if let Some(reviewed) = tool["digest"].as_str().filter(|digest| !digest.is_empty()) {
                if !fetched.digest.eq_ignore_ascii_case(reviewed) {
                    return Err(HandlerError::new(Outcome::Failed, "tool_changed", format!("{}'s files are not the ones this setup was reviewed with (sha256:{} now, sha256:{reviewed} then). Plan the setup again to review the new files.", product(name), fetched.digest)));
                }
            }
            return super::hub_tools::read(item, &fetched)
                .map(|tool| super::hub_tools::installer(&tool))
                .map_err(|problem| HandlerError::new(Outcome::Failed, "tool_unreadable", format!("{name} could not be read as a tool: {problem}")));
        }
        super::package::resolve(&self.0.folder(&context.setup).join("package"), tool["folder"].as_str().unwrap_or_default())
            .and_then(|folder| super::hub_tools::read_folder(&folder))
            .map_err(|problem| HandlerError::new(Outcome::Failed, "tool_unreadable", format!("{name}'s folder in the template could not be read: {problem}")))
    }

    /// Whether every planned tool is in the sandbox and no sign-in copy could be outstanding.
    async fn tools_settled(&self, context: &StepContext, sandbox: &str) -> bool {
        for tool in context.spec["tools"].as_array().into_iter().flatten() {
            let ready = match tool["source"].as_str() {
                Some("bundled" | "hub") => match self.custom(context, tool).await {
                    Ok(custom) => self.0.projects.custom_ready(sandbox, &custom).await,
                    Err(_) => Ok(false),
                },
                _ => self.0.projects.tool_ready(sandbox, tool["name"].as_str().unwrap_or_default()).await,
            };
            if copies_signin(tool) || !matches!(ready, Ok(true)) {
                return false;
            }
        }
        true
    }

    fn cost(spec: &Value) -> Cost {
        if spec["type"].as_str() == Some("cloud") { Cost::Unknown } else { Cost::Free }
    }

    fn keeps_data(spec: &Value) -> bool {
        spec["volumes"].as_array().is_some_and(|volumes| volumes.iter().any(|volume| volume["bind"] != true))
    }
}

impl ResourceHandler for EnvironmentHandler {
    fn kind(&self) -> Kind {
        Kind::Environment
    }

    fn forget_setup<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.0.sweep(setup))
    }

    /// A sandbox changes in place unless what it is made from changes: then the project makes a
    /// new one and keeps the old one, stopped, with what is on its own disk. Its kind never
    /// changes in place.
    fn plan(&self, current: Option<&super::model::Resource>, spec: &Value, spec_digest: &str) -> Result<super::handler::Planned, HandlerError> {
        use super::handler::Planned;
        Ok(match current {
            None => Planned::Step(Action::Create),
            Some(resource) if resource.runtime_id.is_none() => Planned::Step(Action::Create),
            Some(resource) if resource.spec_digest == spec_digest => Planned::Unchanged,
            Some(resource) => {
                let kind = |spec: &Value| spec["type"].as_str().unwrap_or("container").to_owned();
                if kind(&resource.spec) != kind(spec) {
                    return Err(refused(&format!(
                        "{} can't change from a {} to a {} in place; remove it from the template and add it again under a new name.",
                        resource.id,
                        kind(&resource.spec),
                        kind(spec)
                    )));
                }
                if resource.spec["storage_drive"] != spec["storage_drive"] {
                    return Err(refused(&format!("{} can't move to another drive in place.", resource.id)));
                }
                Planned::Step(Action::Update)
            }
        })
    }

    fn change_notes(&self, setup: &str, resource: &str, previous: &Value, spec: &Value) -> Vec<String> {
        let sandbox = format!("{}-{resource}", project_name(setup));
        let mut notes = Vec::new();
        if ["image", "source", "gpu"].iter().any(|field| previous[field] != spec[field]) {
            notes.push(format!(
                "{sandbox} is made again from its new image. Its named volumes move to the new sandbox; the old one is kept, stopped, as {sandbox}-replaced-…, with anything saved on its own disk. Delete it once you no longer need it."
            ));
            if Self::keeps_data(spec) {
                // Forward only (plan 8.5, L16): nothing here can undo what the new version does
                // to its data.
                notes.push(format!(
                    "This can't be undone for {sandbox}'s data: once the new version writes to its volumes (a database it upgrades, say), going back to the old version may not work with them. Back the volumes up first if you might need to go back."
                ));
            }
        }
        let volumes = |spec: &Value| spec["volumes"].as_array().into_iter().flatten().filter(|volume| volume["bind"] != true).filter_map(|volume| volume["source"].as_str().map(str::to_owned)).collect::<Vec<_>>();
        let kept = volumes(spec);
        for dropped in volumes(previous).into_iter().filter(|volume| !kept.contains(volume)) {
            notes.push(format!("The volume {dropped} is no longer attached to {sandbox}. Its data stays; delete it separately if you no longer need it."));
        }
        notes
    }

    fn notes(&self, setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if !matches!(action, Action::Create | Action::Update) {
            return Vec::new();
        }
        let sandbox = format!("{}-{resource}", project_name(setup));
        spec["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|tool| tool["signin"].as_bool() == Some(true))
            .map(|tool| {
                let name = tool["name"].as_str().unwrap_or_default();
                let command = format!("yougori {name} --environment {sandbox}");
                if copies_signin(tool) {
                    format!("{} is installed in {sandbox}. Your sign-in from this computer is copied into it only if you agree when applying; otherwise, or with no sign-in here, sign in there: {command}", product(name))
                } else {
                    format!("{} is installed in {sandbox}. Sign in to it there when the setup is ready: {command}", product(name))
                }
            })
            .collect()
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        for (variable, binding) in spec["secrets"].as_object().into_iter().flatten() {
            let binding = binding.as_str().unwrap_or_default();
            if !binding.is_empty() && !usable_binding(binding, spec) {
                return Err(invalid(format!(
                    "{variable} would read the stored entry {} directly. A setup's sandboxes read only values given when the setup is applied.",
                    crate::lifecycle::safe_diagnostic(binding)
                )));
            }
        }
        for tool in spec["tools"].as_array().into_iter().flatten() {
            let name = tool["name"].as_str().unwrap_or_default();
            match tool["source"].as_str() {
                Some("built-in") if BUILT_IN_TOOLS.contains(&name) => {}
                Some("bundled") if tool["folder"].as_str().is_some_and(|folder| !folder.is_empty()) => {}
                // A Hub tool is installed from its pinned version's checked files, the way a
                // bundled tool is from the template's. Unpinned, two applies could differ.
                Some("hub") if super::hub_tools::split_item(tool["item"].as_str().unwrap_or(name)).is_none() => {
                    return Err(invalid(format!("{name} is not a Hub tool Yougori knows how to install: use hub/PUBLISHER/NAME@VERSION.")));
                }
                Some("hub") if tool["version"].as_str().is_none_or(|version| version.trim().is_empty()) => {
                    return Err(refused(&format!("{name} is a tool from the Hub without a pinned version; pin it as hub/{}@VERSION so every apply installs the same files.", tool["item"].as_str().unwrap_or(name))));
                }
                Some("hub") => {}
                _ => return Err(invalid(format!("{name} is not a tool Yougori knows how to install."))),
            }
            if !matches!(spec["type"].as_str().unwrap_or("container"), "container" | "gpu") {
                return Err(refused(&format!("{name} installs into container sandboxes.")));
            }
            if spec["internet"].as_bool() == Some(false) {
                return Err(invalid(format!("{name} downloads its installer, so its sandbox needs internet access.")));
            }
        }
        let mut environment = environment("setup-00000000", "check", spec, Path::new("/package"))?;
        // Other sandboxes are checked by the plan's own graph; this checks the sandbox itself.
        environment.depends_on.clear();
        let project = Project {
            project: "setup-00000000".into(),
            environments: BTreeMap::from([("check".to_owned(), environment)]),
            connections: Vec::new(),
            publish: BTreeMap::new(),
        };
        project.validate().map_err(|error| invalid(error.replace("check: ", "")))
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            // A research worker makes its own sandbox, offline; this part is its record.
            if super::grids::research::part_of_worker(context) {
                return Ok(super::grids::research::part_observation(context));
            }
            Ok(match self.own(context) {
                None => Observation::Absent,
                Some(sandbox) => Observation::Present {
                    runtime_id: sandbox.id,
                    observed: if sandbox.running { Observed::Running } else { Observed::Stopped },
                    label: None,
                    retained_data: Self::keeps_data(&context.spec),
                    cost: Self::cost(&context.spec),
                },
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            // A research worker makes its own sandbox, offline; this part is its record.
            if super::grids::research::part_of_worker(context) {
                return Ok(super::grids::research::part_receipt(context));
            }
            if context.action == Action::Start {
                let id = context.runtime_id.as_deref().ok_or_else(|| HandlerError::new(Outcome::Failed, "resource_missing", "This sandbox doesn't exist."))?;
                self.0.projects.set_running(id, true).await.map_err(|error| interrupted_or(context, error))?;
                return Ok(receipt(Some(id.to_owned()), Observed::Running, Self::keeps_data(&context.spec), Self::cost(&context.spec)));
            }
            let added = self.store_secrets(context).await?;
            match self.converge(context).await {
                Ok(done) => {
                    // A variable this change dropped no longer needs its entry.
                    let dropped = context.recorded.as_ref().and_then(|spec| spec["secrets"].as_object()).into_iter().flatten()
                        .filter(|(variable, _)| context.spec["secrets"].get(variable.as_str()).is_none())
                        .map(|(variable, _)| secret_name(&context.setup, &context.resource, variable))
                        .collect();
                    self.0.forget(&context.setup, dropped).await;
                    Ok(done)
                }
                Err(error) => {
                    // With nothing made, what this attempt stored goes again. A sandbox that may
                    // exist keeps its entries: the project needs them, and removal forgets them.
                    if matches!(error.outcome, Outcome::Failed | Outcome::NotStarted | Outcome::NeedsInput | Outcome::Unsupported) && self.own(context).is_none() {
                        self.0.forget(&context.setup, added).await;
                    }
                    Err(error)
                }
            }
        })
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            // A research worker makes its own sandbox, offline; this part is its record.
            if super::grids::research::part_of_worker(context) {
                return Ok(super::grids::research::part_health());
            }
            let Some(sandbox) = self.own(context) else { return Ok(health(Health::Failed, "This sandbox isn't there anymore.")) };
            if !sandbox.running {
                return Ok(health(Health::Unknown, "Stopped."));
            }
            let report = self.0.projects.readiness(&self.0.folder(&context.setup), &context.resource).await.map_err(|error| HandlerError::new(Outcome::Unknown, "health_unavailable", crate::lifecycle::safe_diagnostic(&error)))?;
            Ok(probed(&context.spec, &report))
        })
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            // A research worker makes its own sandbox, offline; this part is its record.
            if super::grids::research::part_of_worker(context) {
                return Ok(super::grids::research::part_receipt(context));
            }
            let id = context.runtime_id.as_deref().ok_or_else(|| HandlerError::new(Outcome::Failed, "resource_missing", "This sandbox doesn't exist."))?;
            self.0.projects.set_running(id, false).await.map_err(|error| interrupted_or(context, error))?;
            Ok(receipt(Some(id.to_owned()), Observed::Stopped, Self::keeps_data(&context.spec), Self::cost(&context.spec)))
        })
    }

    /// Releases the sandbox from the setup's project without starting any other, then deletes
    /// it if it is the one this setup's project made. Named volumes, where its data lives, are
    /// kept; its vault entries go.
    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            // A research worker makes its own sandbox, offline; this part is its record.
            if super::grids::research::part_of_worker(context) {
                return Ok(super::grids::research::part_receipt(context));
            }
            let project = self.0.project(context, Change::Leave)?;
            if project.environments.is_empty() {
                let folder = self.0.folder(&context.setup);
                if folder.join("yougori.yaml").is_file() {
                    // The file is the project as last written, which may still name a connection
                    // this project can't deliver; it is written again from what is really there,
                    // this last sandbox, so taking it down reads a project that can be read.
                    let last = self.0.project(context, Change::Put(Kind::Environment, &context.spec))?;
                    self.0.projects.write(&folder, &last).map_err(|error| interrupted_or(context, error))?;
                    self.0.projects.down(&folder, &context.cancel).await.map_err(|error| interrupted_or(context, error))?;
                }
            } else {
                self.0.release(context, &project).await?;
            }
            if let Some(sandbox) = self.own(context) {
                self.0.projects.delete(&sandbox.id).await.map_err(|error| interrupted_or(context, error))?;
            }
            let names = context.spec["secrets"].as_object().into_iter().flatten().map(|(variable, _)| secret_name(&context.setup, &context.resource, variable)).collect();
            self.0.forget(&context.setup, names).await;
            if project.environments.is_empty() {
                self.0.sweep(&context.setup).await;
            }
            // Its data lives on the volumes it mounted; one whose deletion was agreed on this
            // removal keeps nothing, so the sandbox doesn't leave the setup reading "retained".
            let kept = context.spec["volumes"].as_array().into_iter().flatten().filter(|volume| volume["bind"] != true).any(|volume| {
                volume["source"].as_str().is_none_or(|source| !(context.peers.get(source).is_some_and(|peer| peer.kind == Kind::Volume) && context.consents.contains(&delete_consent(source))))
            });
            Ok(receipt(None, Observed::Missing, kept, Cost::Free))
        })
    }

    /// A sandbox with this setup's project stamp for this resource was made by it; nothing is
    /// made again. Whether an update took can't be seen from outside, so it runs again, which
    /// converges to the same sandbox.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            // A research worker makes its own sandbox, offline; this part is its record.
            if super::grids::research::part_of_worker(context) {
                return Ok(Recovery::NotApplied);
            }
            let observation = self.observe(context).await?;
            Ok(match (context.action, observation) {
                (Action::Update, Observation::Present { .. }) => Recovery::NotApplied,
                // Made but never started (the step was cut off between the two, or the start
                // failed): running the step again starts this same sandbox and makes nothing twice.
                // Recording it as done would leave a finished setup with a part that never ran.
                (Action::Create, Observation::Present { observed: Observed::Stopped, .. }) => Recovery::NotApplied,
                // Its tools may not all be in: run the step again, which makes nothing twice.
                (Action::Create, Observation::Present { runtime_id, .. }) if !self.tools_settled(context, &runtime_id).await => Recovery::NotApplied,
                (Action::Create, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => {
                    Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                }
                (_, observation) => super::handler::recovery_from(context, observation),
            })
        })
    }
}

// ----- Volumes -----

/// A named volume, as v1 projects name them (`<project>-<name>`). The runtime makes it when its
/// sandbox first starts; removing the volume resource keeps its data.
pub(crate) struct VolumeHandler(Ordinary);

impl VolumeHandler {
    fn name(context: &StepContext) -> String {
        format!("{}-{}", project_name(&context.setup), context.resource)
    }
}

impl ResourceHandler for VolumeHandler {
    fn kind(&self) -> Kind {
        Kind::Volume
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if spec.get("drive").is_some_and(|drive| !drive.is_null()) {
            return Err(refused("Choosing a drive for a volume isn't available for setups yet."));
        }
        if spec.get("size_gb").is_some_and(|size| !size.is_null()) {
            return Err(refused("A size limit for a volume isn't available for setups yet."));
        }
        // The backup fields are read by the setup crate, which checks the times, the zone, the
        // policies and the sandbox the volume is read through.
        if let Ok(parsed) = yougori_setup::resource::parse_json(Kind::Volume, spec) {
            if let Some(problem) = parsed.validate().first() {
                return Err(invalid(format!("This volume's settings are not valid: {problem}.")));
            }
        }
        Ok(())
    }

    /// A volume with a backup needs the sandbox it is read through to be one of this setup's
    /// own, and to mount it. Checked at review, before anything is created.
    fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        let Ok(yougori_setup::resource::Spec::Volume(volume)) = yougori_setup::resource::parse_json(Kind::Volume, spec) else { return Ok(()) };
        let Some(backup) = volume.backup() else { return Ok(()) };
        let Some((kind, through)) = others.get(&backup.through) else {
            return Err(invalid(format!("{id} is backed up through {}, which is not part of this setup.", backup.through)));
        };
        if *kind != Kind::Environment {
            return Err(invalid(format!("{id} is backed up through {}, which is not a sandbox.", backup.through)));
        }
        if !matches!(through["type"].as_str().unwrap_or("container"), "container" | "gpu") {
            return Err(refused(&format!("Yougori backs up volumes through container sandboxes, and {} is not one.", backup.through)));
        }
        let mounts = through["volumes"].as_array().into_iter().flatten().any(|mount| mount["bind"] != true && mount["source"].as_str() == Some(id));
        if !mounts {
            return Err(invalid(format!("{id} is backed up through {}, which doesn't use it.", backup.through)));
        }
        Ok(())
    }

    /// What the review says about a volume's backups: when, where they are kept, what stops
    /// while they are taken, and what they cannot carry.
    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if !matches!(action, Action::Create | Action::Update) {
            return Vec::new();
        }
        let Ok(yougori_setup::resource::Spec::Volume(volume)) = yougori_setup::resource::parse_json(Kind::Volume, spec) else { return Vec::new() };
        let Some(backup) = volume.backup() else { return Vec::new() };
        vec![
            format!(
                "{resource} is backed up {}, {}. Yougori keeps the {} most recent backups in its own data folder on this computer and deletes older ones.",
                backup.schedule.describe(),
                backup.timezone.describe(),
                backup.keep
            ),
            super::schedules::consistency_words(backup.consistency, resource, &backup.through),
            super::schedules::LIMITS.to_owned(),
        ]
    }

    fn stoppable(&self) -> bool {
        false
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            Ok(match self.0.projects.volume_exists(&Self::name(context)).await {
                Ok(true) => health(Health::Ready, "The volume is there."),
                Ok(false) => health(Health::Unknown, "The volume is made when its sandbox first starts."),
                Err(error) => health(Health::Unknown, crate::lifecycle::safe_diagnostic(&error)),
            })
        })
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            let name = Self::name(context);
            Ok(match self.0.projects.volume_exists(&name).await {
                Ok(true) => Observation::Present { runtime_id: name, observed: Observed::Present, label: None, retained_data: true, cost: Cost::Free },
                Ok(false) => Observation::Unknown { reason: "The volume is made when its sandbox first starts.".into() },
                Err(error) => unknown(error),
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let name = Self::name(context);
            let exists = self.0.projects.volume_exists(&name).await.unwrap_or(false);
            Ok(receipt(Some(name), if exists { Observed::Present } else { Observed::Unknown }, true, Cost::Free))
        })
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        // The data stays, and so do the backups taken of it. The one exception is a volume whose
        // deletion the person ticked on the reviewed removal, which the review offers only when
        // the template says `retention.onRemove: ask`. Then the volume goes here, after every
        // sandbox that used it (a removal runs in reverse order), and the engine deletes its
        // backups straight after this step (`Service::forget_backups`).
        Box::pin(async move {
            if !context.consents.contains(&delete_consent(&context.resource)) {
                return Ok(receipt(None, Observed::Present, true, Cost::Unknown));
            }
            self.0.projects.remove_volume(&Self::name(context)).await.map_err(|error| HandlerError {
                retryable: true,
                ..HandlerError::new(
                    Outcome::Failed,
                    "volume_delete_failed",
                    format!(
                        "{} was not deleted completely: {}. Its backups are kept until it is. Try again to finish deleting it.",
                        context.resource,
                        crate::lifecycle::safe_diagnostic(&error)
                    ),
                )
            })?;
            Ok(receipt(None, Observed::Missing, false, Cost::Free))
        })
    }

    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        // Recording a volume changes nothing outside the registry, so it simply happened.
        Box::pin(async move {
            Ok(match context.action {
                Action::Create | Action::Update => Recovery::Applied(receipt(Some(Self::name(context)), Observed::Unknown, true, Cost::Free)),
                _ => Recovery::NotApplied,
            })
        })
    }
}

// ----- Publications -----

pub(crate) struct PublicationHandler(Ordinary);

impl PublicationHandler {
    fn opened(context: &StepContext) -> Result<(String, u16, Opening), HandlerError> {
        let (target, opening) = publication(&context.spec)?;
        let port = context.spec["port"].as_u64().unwrap_or_default() as u16;
        Ok((target, port, opening))
    }

    /// Whether the publication was open to this network before this step: that opening is its
    /// own, beside the project, so a change to another way of reaching it closes it here.
    fn was_lan(context: &StepContext) -> bool {
        context.recorded.as_ref().is_some_and(|spec| spec["access"].as_str() == Some("lan"))
    }

    /// The path a template asked to be checked (`health:`), and the status that means healthy.
    fn wanted_health(spec: &Value) -> Option<(String, u16)> {
        let path = spec["health"]["path"].as_str().filter(|path| path.starts_with('/'))?;
        let status = spec["health"]["expected_status"].as_u64().and_then(|status| u16::try_from(status).ok()).unwrap_or(200);
        Some((path.to_owned(), status))
    }

    /// The publication's health from its own check at `address`: ready when the path answers
    /// with the status the template expects, degraded when it answers anything else or nothing.
    async fn checked(&self, address: &str, path: &str, expected: u16) -> HealthReport {
        match self.0.projects.probe(address, path).await {
            Ok(status) if status == expected => health(Health::Ready, format!("{path} answered {status} at {address}.")),
            Ok(status) => health(Health::Degraded, format!("{path} answered {status} at {address}, not the {expected} that means healthy.")),
            Err(error) => health(Health::Degraded, format!("{path} didn't answer at {address}: {}", crate::lifecycle::safe_diagnostic(&error))),
        }
    }
}

impl ResourceHandler for PublicationHandler {
    fn kind(&self) -> Kind {
        Kind::ServicePublication
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        publication(spec).map(|_| ())
    }

    /// An address is ready when its own health check (`health:`) answers as the template says
    /// at that address, or, with none, when the project's probe reached the application through
    /// a public one. A port here or on this network with no check is only said to be open.
    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            let (target, port, opened) = Self::opened(context)?;
            if opened == Opening::Nothing {
                return Ok(health(Health::Unknown, "Reachable from inside this setup's sandboxes only; there is no address to check."));
            }
            // A stopped sandbox answers nothing at any address, and that is not a fault.
            let sandbox = self.0.sandbox_of(context, &target).ok();
            if sandbox.as_deref().and_then(|id| self.0.projects.sandbox(id)).is_some_and(|sandbox| !sandbox.running) {
                return Ok(health(Health::Unknown, "Its sandbox is stopped, so nothing answers at its address until the setup starts."));
            }
            let address = match (&opened, sandbox.as_deref()) {
                (Opening::Here(_), _) => Some(format!("http://127.0.0.1:{}", here_port(&context.setup, &context.resource))),
                (Opening::Lan(_), Some(sandbox)) => self.0.projects.address(sandbox, port, "local").await.ok().flatten(),
                (Opening::Public(_), Some(sandbox)) if Self::wanted_health(&context.spec).is_some() => self.0.projects.address(sandbox, port, "cloudflare").await.ok().flatten(),
                _ => None,
            };
            if let (Some(address), Some((path, expected))) = (&address, Self::wanted_health(&context.spec)) {
                return Ok(self.checked(address, &path, expected).await);
            }
            match opened {
                Opening::Here(_) => return Ok(health(Health::Unknown, format!("Reachable on this computer only, at http://127.0.0.1:{}.", here_port(&context.setup, &context.resource)))),
                Opening::Lan(_) => {
                    return Ok(match address {
                        Some(address) => health(Health::Unknown, format!("Reachable from the computers of this network, at {address}.")),
                        None => health(Health::Degraded, "It should be open to this network, but this computer doesn't list it right now. Start the setup again to reopen it."),
                    })
                }
                _ => {}
            }
            let report = self.0.projects.readiness(&self.0.folder(&context.setup), &target).await.map_err(|error| HandlerError::new(Outcome::Unknown, "health_unavailable", crate::lifecycle::safe_diagnostic(&error)))?;
            Ok(match report["stages"]["publicHttps"]["status"].as_str() {
                Some("ready") => health(Health::Ready, "The application answered at its public address."),
                Some("failed") => health(Health::Degraded, "The public address doesn't reach the application right now."),
                _ => health(Health::Unknown, "The address is open. No health check confirms the application answers there."),
            })
        })
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            let (target, port, opened) = Self::opened(context)?;
            let Some(kind) = opened.listed() else {
                return Ok(Observation::Present { runtime_id: String::new(), observed: Observed::Present, label: None, retained_data: false, cost: Cost::Free });
            };
            let sandbox = match self.0.sandbox_of(context, &target) {
                Ok(sandbox) => sandbox,
                Err(_) => return Ok(Observation::Absent),
            };
            Ok(match self.0.projects.publication(&sandbox, port, kind).await {
                Ok(Some(id)) => Observation::Present { runtime_id: id, observed: Observed::Running, label: None, retained_data: false, cost: Cost::Free },
                Ok(None) => Observation::Absent,
                Err(error) => unknown(error),
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let (target, port, opened) = Self::opened(context)?;
            let sandbox = self.0.sandbox_of(context, &target)?;
            // Kept to this computer, it is the sandbox's port published at 127.0.0.1 with the
            // project; public, its address. Either way an address it had before of the other kind
            // is closed when the project converges.
            let Some(kind) = opened.listed() else {
                // Reached from inside the setup only: nothing to open, and an address it had
                // before is closed.
                if let Some(id) = context.runtime_id.as_deref().filter(|id| !id.is_empty()) {
                    let project = self.0.project(context, Change::Put(Kind::ServicePublication, &context.spec))?;
                    self.0.converge(context, &project).await?;
                    if Self::was_lan(context) {
                        self.0.projects.unpublish(id).await.map_err(|error| interrupted_or(context, error))?;
                    }
                }
                return Ok(receipt(None, Observed::Present, false, Cost::Free));
            };
            let project = self.0.project(context, Change::Put(Kind::ServicePublication, &context.spec))?;
            self.0.converge(context, &project).await?;
            // Open to this network before, it is closed here: the project doesn't know it.
            if Self::was_lan(context) && !matches!(opened, Opening::Lan(_)) {
                if let Some(id) = context.runtime_id.as_deref().filter(|id| !id.is_empty()) {
                    self.0.projects.unpublish(id).await.map_err(|error| interrupted_or(context, error))?;
                }
            }
            if let Opening::Lan(_) = opened {
                let id = self.0.projects.publish_local(&sandbox, port, here_port(&context.setup, &context.resource)).await.map_err(|error| interrupted_or(context, error))?;
                return Ok(receipt(Some(id), Observed::Running, false, Cost::Free));
            }
            let id = self
                .0
                .projects
                .publication(&sandbox, port, kind)
                .await
                .map_err(|error| interrupted_or(context, error))?
                .ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The address was requested, but the sandbox doesn't list it."))?;
            Ok(receipt(Some(id), Observed::Running, false, Cost::Free))
        })
    }

    /// Closes the address; starting the setup opens it again. A port kept to this computer is
    /// one of its sandbox's own and stays with it, answering nothing while the sandbox is stopped.
    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let (_, _, opened) = Self::opened(context)?;
            if let Some(id) = context.runtime_id.as_deref().filter(|id| !id.is_empty() && !matches!(opened, Opening::Here(_))) {
                self.0.projects.unpublish(id).await.map_err(|error| interrupted_or(context, error))?;
            }
            Ok(receipt(context.runtime_id.clone(), Observed::Stopped, false, Cost::Free))
        })
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let (_, _, opened) = Self::opened(context)?;
            if opened != Opening::Nothing {
                let project = self.0.project(context, Change::Leave)?;
                let converged = !project.environments.is_empty() && self.0.release(context, &project).await?;
                // Open to this network, it is its own opening: the project never closes it.
                if !converged || matches!(opened, Opening::Lan(_)) {
                    if let Some(id) = context.runtime_id.as_deref().filter(|id| !id.is_empty()) {
                        self.0.projects.unpublish(id).await.map_err(|error| interrupted_or(context, error))?;
                    }
                }
            }
            Ok(receipt(None, Observed::Missing, false, Cost::Free))
        })
    }

    /// Its address, as `url`: the public link or domain while it is up, or the port on this
    /// computer, which is fixed for the setup. Nothing for one reached from inside the setup.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let (target, port, opened) = Self::opened(context)?;
            let Some(kind) = opened.listed() else { return Ok(BTreeMap::new()) };
            let Ok(sandbox) = self.0.sandbox_of(context, &target) else { return Ok(BTreeMap::new()) };
            let address = self.0.projects.address(&sandbox, port, kind).await.map_err(|error| HandlerError::new(Outcome::Unknown, "outputs_unavailable", crate::lifecycle::safe_diagnostic(&error)))?;
            Ok(address.into_iter().map(|url| ("url".to_owned(), url)).collect())
        })
    }
}

// ----- Connections -----

pub(crate) struct ConnectionHandler(Ordinary);

impl ConnectionHandler {
    fn ends(&self, context: &StepContext) -> Result<(String, String), HandlerError> {
        if model_connection::requested(&context.spec) {
            return model_connection::ends(context);
        }
        let connection = connections(&context.spec)?.remove(0);
        let (from, to) = connection.endpoints().map_err(invalid)?;
        Ok((self.0.sandbox_of(context, from)?, self.0.sandbox_of(context, to)?))
    }
}

impl ResourceHandler for ConnectionHandler {
    fn kind(&self) -> Kind {
        Kind::Connection
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if model_connection::requested(spec) {
            return model_connection::validate(spec);
        }
        connections(spec).map(|_| ())
    }

    /// Connections join this setup's owned resources. Model attachments additionally pin the
    /// receiver command and restrict the grant to the local model API. Borrowed parts are not
    /// among `others`: those are this setup's own.
    fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if model_connection::requested(spec) {
            return model_connection::review(id, spec, others);
        }
        for connection in connections(spec)? {
            let (from, to) = connection.endpoints().map_err(invalid)?;
            for end in [from, to] {
                if !others.get(end).is_some_and(|(kind, _)| *kind == Kind::Environment) {
                    return Err(refused(&format!("{id} connects to {end}, which isn't a sandbox of this setup's own. A connection to a sandbox another setup owns isn't available for setups yet.")));
                }
            }
        }
        Ok(())
    }

    fn stoppable(&self) -> bool {
        false
    }

    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            if model_connection::requested(&context.spec) {
                return model_connection::recover(&self.0, context).await;
            }
            Ok(super::handler::recovery_from(context, self.observe(context).await?))
        })
    }

    fn notes(&self, _setup: &str, _resource: &str, spec: &Value, _action: Action) -> Vec<String> {
        if !model_connection::requested(spec) { return Vec::new() }
        vec![format!("Runs {} in the receiving sandbox with a private model attachment file. The model key is not an output. Removal detaches the model and closes this connection.",
            spec["model_command"].as_array().into_iter().flatten().filter_map(Value::as_str).map(quoted).collect::<Vec<_>>().join(" "))]
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            if model_connection::requested(&context.spec) {
                return model_connection::health(&self.0, context).await;
            }
            let (source, target) = self.ends(context)?;
            Ok(match self.0.projects.connection(&source, &target) {
                Some(_) => health(Health::Ready, "The connection is in place."),
                None => health(Health::Failed, "The connection is missing."),
            })
        })
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            if model_connection::requested(&context.spec) {
                return model_connection::observe(&self.0, context).await;
            }
            let Ok((source, target)) = self.ends(context) else { return Ok(Observation::Absent) };
            Ok(match self.0.projects.connection(&source, &target) {
                Some(id) => Observation::Present { runtime_id: id, observed: Observed::Present, label: None, retained_data: false, cost: Cost::Free },
                None => Observation::Absent,
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.recorded.as_ref().is_some_and(|old| model_connection::requested(old) != model_connection::requested(&context.spec)) {
                return Err(refused("Replace this connection using a new resource name when changing between an ordinary connection and model_request. Remove the old resource to clean up its grant and any saved model credential."));
            }
            if model_connection::requested(&context.spec) {
                return model_connection::apply(&self.0, context).await;
            }
            let (source, target) = self.ends(context)?;
            let project = self.0.project(context, Change::Put(Kind::Connection, &context.spec))?;
            self.0.converge(context, &project).await?;
            let id = self
                .0
                .projects
                .connection(&source, &target)
                .ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The connection was requested, but it isn't listed."))?;
            Ok(receipt(Some(id), Observed::Present, false, Cost::Free))
        })
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if model_connection::requested(&context.spec) {
                return model_connection::remove(&self.0, context).await;
            }
            let project = self.0.project(context, Change::Leave)?;
            let converged = !project.environments.is_empty() && self.0.release(context, &project).await?;
            if !converged {
                if let Some(id) = context.runtime_id.as_deref().filter(|id| !id.is_empty()) {
                    self.0.projects.remove_connection(id).await.map_err(|error| interrupted_or(context, error))?;
                }
            }
            Ok(receipt(None, Observed::Missing, false, Cost::Free))
        })
    }
}

// ----- The engine -----

/// The engine's own functions, through the same entry the CLI and projects use.
pub(crate) struct EngineProjects {
    app: crate::AppHandle,
}

impl EngineProjects {
    pub(crate) fn new(app: crate::AppHandle) -> Self {
        Self { app }
    }

    fn sandboxes(&self) -> Vec<Sandbox> {
        use tauri::Manager;
        self.app
            .state::<crate::store::PlatformStore>()
            .snapshot()
            .map(|state| {
                state
                    .environments
                    .into_iter()
                    .map(|environment| Sandbox {
                        running: environment.status == crate::models::EnvironmentStatus::Running,
                        id: environment.id,
                        name: environment.name,
                        owner: environment.description,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        crate::automation::dispatch::dispatch(&self.app, method, &params).await
    }

    async fn exec(&self, sandbox: &str, command: &str) -> Result<Value, String> {
        self.call("execute_environment_command", json!({"request": {"environmentId": sandbox, "command": command}})).await
    }

    /// Runs `command` on its own in the sandbox, in a session of its own where `setsid` exists so
    /// that a stop reaches everything it started, and waits until `status` holds its result. One
    /// request may last only minutes; an installer's downloads can take far longer.
    #[allow(clippy::too_many_arguments)]
    async fn detached(&self, sandbox: &str, command: &str, log: &str, pid: &str, status: &str, cancel: &CancellationToken, minutes: u64) -> Result<String, String> {
        let command = quoted(command);
        self.run(
            sandbox,
            &format!("cd / && if command -v setsid >/dev/null 2>&1; then setsid nohup /bin/sh -c {command} </dev/null >{log} 2>&1 & else nohup /bin/sh -c {command} </dev/null >{log} 2>&1 & fi; echo $! > {pid}"),
        )
        .await?;
        let began = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = self.exec(sandbox, &format!("p=$(cat {pid} 2>/dev/null); [ -z \"$p\" ] || kill -TERM -- -\"$p\" 2>/dev/null || kill -TERM \"$p\" 2>/dev/null")).await;
                    return Err("cancelled".into());
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
            let read = self
                .exec(sandbox, &format!("if [ -s {status} ]; then cat {status}; elif [ ! -s {pid} ]; then printf starting; elif kill -0 \"$(cat {pid})\" 2>/dev/null; then printf running; else printf gone; fi"))
                .await?;
            match read["stdout"].as_str().unwrap_or_default().trim() {
                "gone" => return Err("its installer stopped without a result; the sandbox may have restarted".into()),
                "starting" if began.elapsed().as_secs() > 60 => return Err("its installer did not start".into()),
                "running" | "starting" if began.elapsed().as_secs() > minutes * 60 => return Err(format!("its installer was still running after {minutes} minutes and was left running")),
                "running" | "starting" => {}
                said => return Ok(said.to_owned()),
            }
        }
    }

    async fn custom_check(&self, sandbox: &str, tool: &Tool) -> Result<bool, String> {
        let line = tool.check.as_deref().unwrap_or("false");
        let result = self.exec(sandbox, &format!("{}; cd \"$HOME\" 2>/dev/null || cd /; {line}", yougori_cli::hub::tools::SETUP)).await?;
        Ok(result["exitCode"].as_i64() == Some(0))
    }

    /// A command that must succeed. What it printed is never repeated: a sandbox can print anything.
    async fn run(&self, sandbox: &str, command: &str) -> Result<Value, String> {
        let result = self.exec(sandbox, command).await?;
        match result["exitCode"].as_i64() {
            Some(0) => Ok(result),
            _ => Err("a command in the sandbox failed".into()),
        }
    }

    /// Runs a project action with this operation's cancellation, so the project stops between
    /// its own steps when the setup operation is cancelled.
    async fn project(&self, folder: &Path, action: &str, cancel: &CancellationToken) -> Result<Value, String> {
        let context = crate::automation::context::OperationContext {
            id: format!("setup-{}", uuid::Uuid::new_v4().simple()),
            cancellation: cancel.clone(),
            progress: Arc::new(|_| {}),
        };
        crate::automation::context::scope(
            context,
            crate::projects::run_project_action(folder.to_string_lossy().into_owned(), action.to_owned(), self.app.clone()),
        )
        .await
    }
}

impl Projects for EngineProjects {
    fn model_call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move { self.call(method, params).await })
    }
    fn apply<'a>(&'a self, folder: &'a Path, project: &'a Project, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<BTreeMap<String, String>, String>> {
        Box::pin(async move {
            self.write(folder, project)?;
            let result = self.project(folder, "apply", cancel).await?;
            Ok(result["environments"]
                .as_object()
                .map(|ids| ids.iter().filter_map(|(name, id)| id.as_str().map(|id| (name.clone(), id.to_owned()))).collect())
                .unwrap_or_default())
        })
    }

    fn down<'a>(&'a self, folder: &'a Path, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.project(folder, "down", cancel).await.map(|_| ()) })
    }

    fn write(&self, folder: &Path, project: &Project) -> Result<(), String> {
        std::fs::create_dir_all(folder).map_err(|error| format!("Yougori could not prepare the setup's project folder: {error}"))?;
        let text = manifest::to_yaml(project)?;
        let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
        std::io::Write::write_all(&mut file, text.as_bytes()).map_err(|error| error.to_string())?;
        file.as_file().sync_all().map_err(|error| error.to_string())?;
        file.persist(folder.join("yougori.yaml")).map_err(|error| error.error.to_string())?;
        Ok(())
    }

    fn sandbox(&self, id: &str) -> Option<Sandbox> {
        self.sandboxes().into_iter().find(|sandbox| sandbox.id == id)
    }

    /// The stamp is the project engine's own (`projects.rs`): the project's key, the SHA-256 of
    /// its canonical manifest path, and the environment's name.
    fn owned(&self, folder: &Path, resource: &str, id: Option<&str>) -> Option<Sandbox> {
        use sha2::{Digest, Sha256};
        let manifest = folder.join("yougori.yaml").canonicalize().ok()?;
        let stamp = format!("Yougori project {:x} / {resource}", Sha256::digest(manifest.to_string_lossy().as_bytes()));
        self.sandboxes().into_iter().find(|sandbox| sandbox.owner == stamp && id.is_none_or(|id| sandbox.id == id))
    }

    fn set_running<'a>(&'a self, id: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.call("set_environment_status", json!({"environmentId": id, "status": if running { "running" } else { "stopped" }}))
                .await
                .map(|_| ())
        })
    }

    fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.call("delete_environment", json!({"environmentId": id})).await.map(|_| ()) })
    }

    fn store_secret(&self, name: &str, value: &str) -> Result<(), String> {
        crate::projects::secrets::set_secret(name, value).map(|_| ())
    }

    fn forget_secret(&self, name: &str) -> Result<(), String> {
        crate::projects::secrets::delete_secret(name).map(|_| ())
    }

    fn volume_exists<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            let volumes = self.call("list_volumes", json!({})).await?;
            let listed = volumes.as_array().or_else(|| volumes["volumes"].as_array()).cloned().unwrap_or_default();
            Ok(listed.iter().any(|volume| volume["name"].as_str() == Some(name)))
        })
    }

    fn remove_volume<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            match self.call("remove_volume", json!({"name": name})).await {
                Ok(answer) => match answer["notChecked"].as_array().filter(|places| !places.is_empty()) {
                    // Deleted where it was looked for, but somewhere it may also be was not reached.
                    Some(places) => Err(format!(
                        "it was deleted, but {} could not be checked, so a copy of it may still be there",
                        places.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")
                    )),
                    None => Ok(()),
                },
                // Never made (a volume is made when its sandbox first starts), or deleted by an
                // earlier try: gone everywhere this engine looked, which is what was asked.
                Err(error) if error == format!("No volume named {name}.") => Ok(()),
                Err(error) => Err(error),
            }
        })
    }

    fn publication<'a>(&'a self, sandbox: &'a str, port: u16, kind: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            let services = self.call("list_environment_services", json!({"environmentId": sandbox})).await?;
            Ok(services["publications"].as_array().and_then(|publications| {
                publications
                    .iter()
                    .find(|publication| publication["port"].as_u64() == Some(u64::from(port)) && publication["kind"] == kind)
                    .and_then(|publication| publication["id"].as_str().map(str::to_owned))
            }))
        })
    }

    fn address<'a>(&'a self, sandbox: &'a str, port: u16, kind: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            let services = self.call("list_environment_services", json!({"environmentId": sandbox})).await?;
            Ok(services["publications"].as_array().and_then(|publications| {
                publications
                    .iter()
                    // A public link is the address only while it is up. A port on this computer or
                    // this network is fixed for the setup, and is listed as reconnecting for a
                    // moment after a start.
                    .filter(|publication| kind == "loopback" || kind == "local" || (publication["status"] != "error" && publication["status"] != "stopped"))
                    .find(|publication| publication["port"].as_u64() == Some(u64::from(port)) && publication["kind"] == kind)
                    .and_then(|publication| publication["urls"][0].as_str().map(str::to_owned))
            }))
        })
    }

    fn unpublish<'a>(&'a self, publication: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.call("unpublish_environment_service", json!({"publicationId": publication})).await.map(|_| ()) })
    }

    fn publish_local<'a>(&'a self, sandbox: &'a str, port: u16, host: u16) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let opened = self.call("publish_environment_service", json!({"environmentId": sandbox, "port": port, "kind": "local", "hostPort": host})).await?;
            opened["id"].as_str().map(str::to_owned).ok_or_else(|| "The sandbox opened its port but didn't say which publication it is.".to_owned())
        })
    }

    fn probe<'a>(&'a self, address: &'a str, path: &'a str) -> BoxFuture<'a, Result<u16, String>> {
        Box::pin(async move { probe_address(address, path).await })
    }

    fn remove_connection<'a>(&'a self, connection: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.call("delete_connection", json!({"connectionId": connection})).await.map(|_| ()) })
    }

    fn readiness<'a>(&'a self, folder: &'a Path, resource: &'a str) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move {
            let report = crate::projects::project_deployment_status(folder.to_string_lossy().into_owned(), self.app.clone()).await?;
            Ok(report["environments"][resource].clone())
        })
    }

    fn tool_ready<'a>(&'a self, sandbox: &'a str, tool: &'a str) -> BoxFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            let probe = self.exec(sandbox, &format!("{TOOL_ENV}; if command -v {tool} >/dev/null 2>&1; then printf ready; else printf missing; fi")).await?;
            match probe["stdout"].as_str().unwrap_or_default().trim() {
                "ready" => Ok(true),
                "missing" => Ok(false),
                _ => Err("The tool check returned an unexpected result.".into()),
            }
        })
    }

    /// Stages Yougori's installer in the sandbox (as the terminal installer does), runs it in the
    /// background, and polls its exit status, so a long download outlasts any one request.
    fn install_tool<'a>(&'a self, sandbox: &'a str, tool: &'a str, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if !BUILT_IN_TOOLS.contains(&tool) {
                return Err("This isn't a tool Yougori installs.".into());
            }
            let script = format!("od_tool='{tool}'\n{}", INSTALLER.replace("\r\n", "\n"));
            let staged = self
                .exec(sandbox, &format!("umask 077; od_dir=$(mktemp -d /tmp/yougori-install.XXXXXXXXXX) || exit 1; printf %s {} > \"$od_dir/install.sh\" || exit 1; printf '\\nYOUGORI_INSTALL_PATH=%s\\n' \"$od_dir\"", quoted(&script)))
                .await?;
            let path = staged["stdout"]
                .as_str()
                .unwrap_or_default()
                .lines()
                .find_map(|line| line.strip_prefix("YOUGORI_INSTALL_PATH="))
                .filter(|path| path.strip_prefix("/tmp/yougori-install.").is_some_and(|rest| !rest.is_empty() && rest.len() <= 32 && rest.bytes().all(|b| b.is_ascii_alphanumeric())))
                .ok_or("The installer could not be staged; the image needs /bin/sh, mktemp and a writable /tmp.")?
                .to_owned();
            let (status, pid, log) = (format!("{path}.status"), format!("{path}.pid"), format!("{path}.log"));
            let said = self.detached(sandbox, &format!("sh {path}/install.sh; echo $? > {status}"), &log, &pid, &status, cancel, 30).await;
            let _ = self.exec(sandbox, &format!("rm -f {status} {pid} {log}")).await;
            match said?.as_str() {
                "0" => {}
                "137" => return Err("its installer was stopped, perhaps for lack of memory; give the sandbox more memory and retry".into()),
                code => return Err(format!("its installer stopped with exit {code}")),
            }
            match self.tool_ready(sandbox, tool).await? {
                true => Ok(()),
                false => Err("the installer finished, but the tool isn't available in the sandbox".into()),
            }
        })
    }

    fn custom_ready<'a>(&'a self, sandbox: &'a str, tool: &'a Tool) -> BoxFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            let said = self.exec(sandbox, &format!("cat \"{}\" 2>/dev/null", tool_marker(tool))).await?;
            if said["stdout"].as_str().map(str::trim) != Some(yougori_cli::hub::tools::fingerprint(tool).as_str()) {
                return Ok(false);
            }
            self.custom_check(sandbox, tool).await
        })
    }

    /// The install lines run on their own in the sandbox, each in its own shell and in order,
    /// stopping at the first that fails (`hub::tools::runner`), then the tool's check must pass.
    fn install_custom<'a>(&'a self, sandbox: &'a str, tool: &'a Tool, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if tool.install.is_empty() {
                if !self.custom_check(sandbox, tool).await? {
                    return Err("it has no install lines, and its check does not pass".into());
                }
            } else {
                let dir = format!("/tmp/yougori-hub-{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);
                self.run(sandbox, &format!("rm -rf {dir} && mkdir -m 700 -p {dir}")).await?;
                for command in yougori_cli::hub::tools::staging(&format!("{dir}/run.sh"), &yougori_cli::hub::tools::runner(&dir, tool)) {
                    self.run(sandbox, &command).await.map_err(|_| "its installer could not be copied into the sandbox".to_owned())?;
                }
                let said = self.detached(sandbox, &format!("exec /bin/sh {dir}/run.sh"), &format!("{dir}/log"), &format!("{dir}/pid"), &format!("{dir}/status"), cancel, 60).await;
                let _ = self.exec(sandbox, &format!("rm -rf {dir}")).await;
                match said?.split_once(' ') {
                    Some(("0", "0")) => {}
                    Some((line, code)) => {
                        let shown = line.parse::<usize>().ok().and_then(|line| tool.install.get(line.wrapping_sub(1))).cloned().unwrap_or_default();
                        let shown = yougori_cli::hub::scan::shown(&shown).chars().take(120).collect::<String>();
                        return Err(format!("install line {line} ({shown}) failed with exit code {code}"));
                    }
                    None => return Err("its installer stopped without a result".into()),
                }
                if !self.custom_check(sandbox, tool).await? {
                    return Err(format!("its installer finished, but its check ({}) does not pass", tool.check.as_deref().unwrap_or_default()));
                }
            }
            let marker = tool_marker(tool);
            let fingerprint = yougori_cli::hub::tools::fingerprint(tool);
            self.run(sandbox, &format!("mkdir -p \"$HOME/.local/share/yougori/tools\" && printf %s {fingerprint} > \"{marker}\"")).await.map(|_| ())
        })
    }

    /// Names the sign-in files with the CLI's own rules (`tool_credentials::host_signin`) only
    /// now, on the person's choice, and moves them through the private file transfer into a
    /// private folder, then into place. Their contents never enter a command or a message.
    fn copy_signin<'a>(&'a self, sandbox: &'a str, tool: &'a str, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            let files = yougori_cli::tool_credentials::host_signin(tool);
            if files.is_empty() {
                return Ok(false);
            }
            let made = self.run(sandbox, "umask 077; mktemp -d \"$HOME/.yougori-credentials-XXXXXXXXXXXX\"").await?;
            let stage = made["stdout"].as_str().unwrap_or_default().trim().to_owned();
            if !signin_stage(&stage) {
                return Err("could not make a private folder for the sign-in".into());
            }
            let outcome = async {
                let paths = files.iter().map(|(path, _)| path.to_string_lossy().into_owned()).collect::<Vec<_>>();
                let copied = self
                    .call("copy_files_to_environment", json!({ "environmentId": sandbox, "paths": paths, "destination": stage }))
                    .await
                    .map_err(|_| "could not transfer the sign-in files".to_owned())?;
                if cancel.is_cancelled() {
                    return Err("cancelled before the sign-in was put in place".to_owned());
                }
                let imported = copied["destination"].as_str().ok_or("the transfer didn't say where it put the files")?;
                self.run(sandbox, &signin_script(&stage, imported, &files)?).await.map(|_| ())
            }
            .await;
            let _ = self.run(sandbox, &format!("rm -rf -- {}", quoted(&stage))).await;
            outcome.map(|()| true)
        })
    }

    /// Every file under the folder in the sandbox, with its checksum, read in one command.
    /// Folders each computer keeps for itself (`.git`, `node_modules`, …) are left out, as the
    /// launcher's two-way sync leaves them out.
    fn folder_files<'a>(&'a self, sandbox: &'a str, folder: &'a str) -> BoxFuture<'a, Result<folder_sync::Checksums, String>> {
        Box::pin(async move {
            let at = quoted(folder);
            let result = self
                .exec(
                    sandbox,
                    &format!("mkdir -p -- {at} && cd {at} && find . -type f -print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null || true"),
                )
                .await?;
            let mut found = folder_sync::Checksums::new();
            for line in result["stdout"].as_str().unwrap_or_default().lines() {
                let Some((sum, path)) = line.split_once("  ") else { continue };
                let path = path.trim_start_matches("./");
                if sum.len() != 64 || path.is_empty() || path.split('/').any(folder_sync::reconcile::host_only) {
                    continue;
                }
                found.insert(path.to_owned(), sum.to_ascii_lowercase());
            }
            Ok(found)
        })
    }

    fn send_file<'a>(&'a self, sandbox: &'a str, from: &'a Path, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
            let destination = if parent.is_empty() { folder.to_owned() } else { format!("{folder}/{parent}") };
            self.run(sandbox, &format!("mkdir -p -- {}", quoted(&destination))).await?;
            let copied = self
                .call("copy_files_to_environment", json!({ "environmentId": sandbox, "paths": [from.to_string_lossy()], "destination": destination }))
                .await?;
            // The transfer puts the file in a folder of its own; move it into place under the
            // name this computer has for it, replacing only that one file.
            let landed = copied["destination"].as_str().ok_or("the transfer didn't say where it put the file")?;
            let source = from.file_name().and_then(|name| name.to_str()).ok_or("that file's name can't be used in the sandbox")?;
            self.run(
                sandbox,
                &format!(
                    "set -eu; cp -f -- {} {}; rm -rf -- {}",
                    quoted(&format!("{landed}/{source}")),
                    quoted(&format!("{destination}/{name}")),
                    quoted(landed)
                ),
            )
            .await
            .map(|_| ())
        })
    }

    fn receive_file<'a>(&'a self, sandbox: &'a str, folder: &'a str, relative: &'a str, to: &'a Path) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let parent = to.parent().ok_or("that file has no folder on this computer")?.to_path_buf();
            let staging = tokio::task::spawn_blocking(move || tempfile::tempdir_in(&parent).map_err(|error| error.to_string()))
                .await
                .map_err(|_| "the copy could not be prepared".to_owned())??;
            let outcome = async {
                self.call(
                    "copy_files_from_environment",
                    json!({ "environmentId": sandbox, "path": format!("{folder}/{relative}"), "destination": staging.path().to_string_lossy() }),
                )
                .await?;
                let name = relative.rsplit('/').next().unwrap_or(relative);
                let landed = staging.path().join(name);
                // Written beside its destination and moved into place, so a copy that stops part
                // way never leaves half a file in the person's folder.
                tokio::fs::rename(&landed, to).await.map_err(|error| error.to_string())
            }
            .await;
            let _ = tokio::task::spawn_blocking(move || drop(staging)).await;
            outcome
        })
    }

    fn remove_file<'a>(&'a self, sandbox: &'a str, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.run(sandbox, &format!("rm -f -- {}", quoted(&format!("{folder}/{relative}")))).await.map(|_| ())
        })
    }

    fn connection(&self, source: &str, target: &str) -> Option<String> {
        use tauri::Manager;
        let state = self.app.state::<crate::store::PlatformStore>().snapshot().ok()?;
        let value = serde_json::to_value(&state.connections).ok()?;
        value.as_array()?.iter().find_map(|connection| {
            (connection["sourceId"].as_str() == Some(source) && connection["targetId"].as_str() == Some(target))
                .then(|| connection["id"].as_str().map(str::to_owned))
                .flatten()
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory engine for the ordinary handlers' tests: projects converge into fake
    //! sandboxes, and every call is counted.
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct State {
        pub sandboxes: BTreeMap<String, Sandbox>,
        pub projects: BTreeMap<PathBuf, Project>,
        pub secrets: BTreeMap<String, String>,
        pub volumes: Vec<String>,
        /// Volumes deleted, by name, in order.
        pub volumes_removed: Vec<String>,
        /// The next volume deletion is refused with this, as the engine refuses one still in use.
        pub refuse_volume_removal: Option<String>,
        /// The named volumes each sandbox mounts: one still mounted is not deleted, as the real
        /// engine refuses ("… is used by …. Delete those environments first").
        pub mounts: BTreeMap<String, Vec<String>>,
        pub publications: BTreeMap<(String, u16), String>,
        /// Ports published at 127.0.0.1, by sandbox and port: the port on this computer.
        pub here: BTreeMap<(String, u16), u16>,
        /// Ports open to this network, by sandbox and port: the publication and its port here.
        pub lan: BTreeMap<(String, u16), (String, u16)>,
        /// What each address answers a health check with, by address and path. Anything not
        /// listed answers nothing.
        pub answers: BTreeMap<String, u16>,
        pub connections: BTreeMap<(String, String), String>,
        pub applies: u32,
        pub created: u32,
        pub deleted: Vec<String>,
        /// The next apply fails after creating its sandboxes, as a failed image start would.
        pub fail_after_create: bool,
        /// Tools installed, by sandbox.
        pub tools: BTreeMap<String, Vec<String>>,
        pub installs: u32,
        /// The next tool install fails.
        pub fail_install: bool,
        /// Sign-ins copied from "this computer", as (sandbox, tool).
        pub signins: Vec<(String, String)>,
        /// This computer has no sign-in for any tool.
        pub no_host_signin: bool,
        /// Project files written without converging.
        pub writes: u32,
        /// The project's readiness report for each sandbox, by resource; a running sandbox with
        /// no passing probe when absent.
        pub readiness: BTreeMap<String, Value>,
        next: u32,
    }

    #[derive(Default)]
    pub(crate) struct FakeProjects {
        pub state: Mutex<State>,
        /// Where the fake sandboxes keep their files, when a test syncs a folder into one.
        pub sandbox_files: Option<PathBuf>,
        pub model_rpc: Option<Arc<dyn Fn(&str, Value) -> Result<Value, String> + Send + Sync>>,
    }

    impl FakeProjects {
        /// One sandbox's copy of a synced folder, inside the test's own temporary folder.
        pub(crate) fn sandbox_folder(&self, sandbox: &str, folder: &str) -> PathBuf {
            self.sandbox_files
                .clone()
                .unwrap_or_else(std::env::temp_dir)
                .join(sandbox)
                .join(folder.trim_start_matches('/'))
        }
    }

    /// The fake engine's ownership stamp, the stand-in for the project engine's.
    pub(crate) fn stamp(folder: &Path, resource: &str) -> String {
        format!("fake project {} / {resource}", folder.display())
    }

    impl Projects for FakeProjects {
        fn model_call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async move { self.model_rpc.as_ref().ok_or("No model test backend")?(method, params) })
        }

        fn apply<'a>(&'a self, folder: &'a Path, project: &'a Project, _cancel: &'a CancellationToken) -> BoxFuture<'a, Result<BTreeMap<String, String>, String>> {
            Box::pin(async move {
                project.validate()?;
                let mut state = self.state.lock().unwrap();
                state.applies += 1;
                let mut ids = BTreeMap::new();
                for (name, environment) in &project.environments {
                    for reference in environment.secrets.values() {
                        if !state.secrets.contains_key(reference) {
                            return Err(format!("The deployment secret {reference} is missing"));
                        }
                    }
                    let sandbox_name = format!("{}-{name}", project.project);
                    let owner = stamp(folder, name);
                    let id = match state.sandboxes.values().find(|sandbox| sandbox.name == sandbox_name) {
                        // As the real engine: a sandbox of the same name it didn't make blocks the project.
                        Some(sandbox) if sandbox.owner != owner => return Err(format!("{sandbox_name} already exists outside this project")),
                        Some(sandbox) => sandbox.id.clone(),
                        None => {
                            state.next += 1;
                            state.created += 1;
                            let id = format!("env-{}", state.next);
                            state.sandboxes.insert(id.clone(), Sandbox { id: id.clone(), name: sandbox_name, running: false, owner });
                            id
                        }
                    };
                    let mut mounted = Vec::new();
                    for volume in environment.volumes.iter().filter(|volume| !volume.bind) {
                        let named = format!("{}-{}", project.project, volume.source);
                        if !state.volumes.contains(&named) {
                            state.volumes.push(named.clone());
                        }
                        mounted.push(named);
                    }
                    state.mounts.insert(id.clone(), mounted);
                    ids.insert(name.clone(), id);
                }
                if std::mem::take(&mut state.fail_after_create) {
                    return Err("The image could not be started".into());
                }
                for id in ids.values() {
                    state.sandboxes.get_mut(id).unwrap().running = true;
                }
                // Publications and connections follow the project, like the real one's records.
                state.publications.retain(|(sandbox, _), _| ids.values().any(|id| id == sandbox));
                let wanted = project
                    .publish
                    .iter()
                    .filter_map(|(name, publication)| match publication {
                        manifest::Publication::Detailed { port, .. } => Some((ids[name].clone(), *port)),
                        manifest::Publication::Hostname(_) => None,
                    })
                    .collect::<Vec<_>>();
                state.publications.retain(|key, _| wanted.contains(key));
                for key in wanted {
                    let id = format!("pub-{}-{}", key.0, key.1);
                    state.publications.entry(key).or_insert(id);
                }
                state.here = project
                    .environments
                    .iter()
                    .flat_map(|(name, environment)| environment.ports.iter().filter_map(|port| port.values().ok()).filter_map(|(guest, host)| host.map(|host| ((ids[name].clone(), guest), host))))
                    .collect();
                let wanted = project
                    .connections
                    .iter()
                    .filter_map(|connection| connection.endpoints().ok())
                    .map(|(from, to)| (ids[from].clone(), ids[to].clone()))
                    .collect::<Vec<_>>();
                state.connections.retain(|key, _| wanted.contains(key));
                for key in wanted {
                    let id = format!("conn-{}-{}", key.0, key.1);
                    state.connections.entry(key).or_insert(id);
                }
                state.projects.insert(folder.to_owned(), project.clone());
                Ok(ids)
            })
        }

        fn down<'a>(&'a self, folder: &'a Path, _cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                let project = state.projects.get(folder).cloned().ok_or("No project here")?;
                for sandbox in state.sandboxes.values_mut().filter(|sandbox| sandbox.name.starts_with(&project.project)) {
                    sandbox.running = false;
                }
                Ok(())
            })
        }

        fn write(&self, folder: &Path, project: &Project) -> Result<(), String> {
            let mut state = self.state.lock().unwrap();
            state.writes += 1;
            state.projects.insert(folder.to_owned(), project.clone());
            Ok(())
        }

        fn sandbox(&self, id: &str) -> Option<Sandbox> {
            self.state.lock().unwrap().sandboxes.get(id).cloned()
        }

        fn owned(&self, folder: &Path, resource: &str, id: Option<&str>) -> Option<Sandbox> {
            let owner = stamp(folder, resource);
            self.state.lock().unwrap().sandboxes.values().find(|sandbox| sandbox.owner == owner && id.is_none_or(|id| sandbox.id == id)).cloned()
        }

        fn set_running<'a>(&'a self, id: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.sandboxes.get_mut(id).ok_or("No such sandbox")?.running = running;
                Ok(())
            })
        }

        fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.sandboxes.remove(id).ok_or("No such sandbox")?;
                state.mounts.remove(id);
                state.tools.remove(id);
                state.deleted.push(id.to_owned());
                Ok(())
            })
        }

        fn store_secret(&self, name: &str, value: &str) -> Result<(), String> {
            self.state.lock().unwrap().secrets.insert(name.to_owned(), value.to_owned());
            Ok(())
        }

        fn forget_secret(&self, name: &str) -> Result<(), String> {
            self.state.lock().unwrap().secrets.remove(name);
            Ok(())
        }

        fn volume_exists<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<bool, String>> {
            Box::pin(async move { Ok(self.state.lock().unwrap().volumes.iter().any(|volume| volume == name)) })
        }

        fn remove_volume<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(refusal) = state.refuse_volume_removal.take() {
                    return Err(refusal);
                }
                let users = state.mounts.iter().filter(|(_, volumes)| volumes.iter().any(|volume| volume == name)).filter_map(|(id, _)| state.sandboxes.get(id)).map(|sandbox| sandbox.name.clone()).collect::<Vec<_>>();
                if !users.is_empty() {
                    return Err(format!("{name} is used by {}. Delete those environments first; the volume and its data stay until then.", users.join(", ")));
                }
                state.volumes.retain(|volume| volume != name);
                state.volumes_removed.push(name.to_owned());
                Ok(())
            })
        }

        fn publication<'a>(&'a self, sandbox: &'a str, port: u16, kind: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                let key = (sandbox.to_owned(), port);
                Ok(match kind {
                    "loopback" => state.here.get(&key).map(|_| format!("here-{sandbox}-{port}")),
                    "local" => state.lan.get(&key).map(|(id, _)| id.clone()),
                    _ => state.publications.get(&key).cloned(),
                })
            })
        }

        fn address<'a>(&'a self, sandbox: &'a str, port: u16, kind: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                let key = (sandbox.to_owned(), port);
                Ok(match kind {
                    "cloudflare" => state.publications.get(&key).map(|id| format!("https://{id}.trycloudflare.test")),
                    "loopback" => state.here.get(&key).map(|host| format!("http://127.0.0.1:{host}")),
                    "local" => state.lan.get(&key).map(|(_, host)| format!("http://192.168.1.20:{host}")),
                    _ => None,
                })
            })
        }

        fn unpublish<'a>(&'a self, publication: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                state.publications.retain(|_, id| id != publication);
                state.lan.retain(|_, (id, _)| id != publication);
                Ok(())
            })
        }

        fn publish_local<'a>(&'a self, sandbox: &'a str, port: u16, host: u16) -> BoxFuture<'a, Result<String, String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                let id = state.lan.entry((sandbox.to_owned(), port)).or_insert_with(|| (format!("lan-{sandbox}-{port}"), host)).0.clone();
                Ok(id)
            })
        }

        fn probe<'a>(&'a self, address: &'a str, path: &'a str) -> BoxFuture<'a, Result<u16, String>> {
            Box::pin(async move { self.state.lock().unwrap().answers.get(&format!("{address}{path}")).copied().ok_or_else(|| "nothing answered".to_owned()) })
        }

        fn connection(&self, source: &str, target: &str) -> Option<String> {
            self.state.lock().unwrap().connections.get(&(source.to_owned(), target.to_owned())).cloned()
        }

        fn remove_connection<'a>(&'a self, connection: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.state.lock().unwrap().connections.retain(|_, id| id != connection);
                Ok(())
            })
        }

        fn readiness<'a>(&'a self, _folder: &'a Path, resource: &'a str) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                Ok(state.readiness.get(resource).cloned().unwrap_or_else(|| json!({"ready": true, "applicationVerified": false, "retryable": false, "stages": {"publicHttps": {"status": "notConfigured"}}})))
            })
        }

        fn tool_ready<'a>(&'a self, sandbox: &'a str, tool: &'a str) -> BoxFuture<'a, Result<bool, String>> {
            Box::pin(async move { Ok(self.state.lock().unwrap().tools.get(sandbox).is_some_and(|tools| tools.iter().any(|name| name == tool))) })
        }

        fn install_tool<'a>(&'a self, sandbox: &'a str, tool: &'a str, _cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if std::mem::take(&mut state.fail_install) {
                    return Err("its installer stopped with exit 1".into());
                }
                state.installs += 1;
                state.tools.entry(sandbox.to_owned()).or_default().push(tool.to_owned());
                Ok(())
            })
        }

        fn custom_ready<'a>(&'a self, sandbox: &'a str, tool: &'a Tool) -> BoxFuture<'a, Result<bool, String>> {
            self.tool_ready(sandbox, tool.name())
        }

        fn install_custom<'a>(&'a self, sandbox: &'a str, tool: &'a Tool, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<(), String>> {
            self.install_tool(sandbox, tool.name(), cancel)
        }

        fn copy_signin<'a>(&'a self, sandbox: &'a str, tool: &'a str, _cancel: &'a CancellationToken) -> BoxFuture<'a, Result<bool, String>> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if state.no_host_signin {
                    return Ok(false);
                }
                state.signins.push((sandbox.to_owned(), tool.to_owned()));
                Ok(true)
            })
        }

        /// The sandbox's side of a synced folder, as a folder under `sandbox_files`: the tests
        /// move real bytes without a container.
        fn folder_files<'a>(&'a self, sandbox: &'a str, folder: &'a str) -> BoxFuture<'a, Result<folder_sync::Checksums, String>> {
            Box::pin(async move { folder_sync::scan(&self.sandbox_folder(sandbox, folder)) })
        }

        fn send_file<'a>(&'a self, sandbox: &'a str, from: &'a Path, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let to = self.sandbox_folder(sandbox, folder).join(relative);
                std::fs::create_dir_all(to.parent().ok_or("no parent")?).map_err(|error| error.to_string())?;
                std::fs::copy(from, to).map_err(|error| error.to_string()).map(|_| ())
            })
        }

        fn receive_file<'a>(&'a self, sandbox: &'a str, folder: &'a str, relative: &'a str, to: &'a Path) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                std::fs::create_dir_all(to.parent().ok_or("no parent")?).map_err(|error| error.to_string())?;
                std::fs::copy(self.sandbox_folder(sandbox, folder).join(relative), to).map_err(|error| error.to_string()).map(|_| ())
            })
        }

        fn remove_file<'a>(&'a self, sandbox: &'a str, folder: &'a str, relative: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                match std::fs::remove_file(self.sandbox_folder(sandbox, folder).join(relative)) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
                    _ => Ok(()),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A step for the folder tests: everything a sync needs and nothing it does not.
    fn syncing_step(setup: &str, resource: &str, chosen: &Path, consented: bool) -> StepContext {
        let consents = if consented {
            [folder_consent(resource, "code")].into_iter().collect::<std::collections::BTreeSet<_>>()
        } else {
            Default::default()
        };
        StepContext {
            setup: setup.to_owned(),
            operation: "op-1".into(),
            step: "step-1".into(),
            resource: resource.to_owned(),
            kind: Kind::Environment,
            action: Action::Create,
            label: "label-1".into(),
            created_label: None,
            generation: 1,
            spec: json!({
                "image": "example/dev",
                "sync": [{
                    "binding": "code", "target": "/workspace", "path": chosen.to_string_lossy(),
                    "read_only": false, "continuous": true, "conflicts": "stop",
                }],
            }),
            runtime_id: None,
            owner: None,
            peers: Default::default(),
            planned: Default::default(),
            cancel: CancellationToken::new(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Arc::new(consents),
        }
    }

    /// PROVES that `conflicts: stop` is honoured rather than passed over. `folder_sync::run`
    /// answers a stopped pass with `Ok`, and the step used to accept that and complete, so a
    /// setup reported itself Ready with a folder that was not syncing — the one thing a template
    /// asks for `stop` to prevent. Nothing was changed, so it must be retryable.
    #[tokio::test]
    async fn a_folder_that_stopped_on_a_conflict_fails_the_step_instead_of_completing_quietly() {
        let chosen = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let sandboxes = tempfile::tempdir().unwrap();
        // Its own sandbox root: `sandbox_files: None` falls back to this computer's temp folder,
        // which every test and every run would then share.
        let projects = Arc::new(fake::FakeProjects { sandbox_files: Some(sandboxes.path().to_path_buf()), ..Default::default() });
        let handler = EnvironmentHandler(Ordinary::new(projects.clone(), state.path().to_path_buf()));
        let context = syncing_step("setup-1", "dev", chosen.path(), true);

        // First pass: one file, which travels and leaves the folder in step.
        std::fs::write(chosen.path().join("app.js"), "one").unwrap();
        handler.sync_folders(&context, "sandbox-1").await.expect("a folder in step syncs");

        // Now the same file is edited on both sides, which is exactly what `stop` is about.
        std::fs::write(chosen.path().join("app.js"), "mine").unwrap();
        let theirs = projects.sandbox_folder("sandbox-1", "/workspace").join("app.js");
        std::fs::write(&theirs, "theirs").unwrap();

        let refused = handler.sync_folders(&context, "sandbox-1").await.expect_err("a folder that is not syncing is not a success");
        assert_eq!(refused.code, "folder_sync_stopped");
        assert_eq!(refused.outcome, Outcome::Failed);
        assert!(refused.retryable, "nothing was changed, so trying again is safe");
        assert!(refused.message.contains("not syncing"), "{}", refused.message);
        assert!(refused.message.contains("app.js"), "it names the file: {}", refused.message);
        // It says what did succeed first, so a failed change is not read as "nothing worked", and
        // it sends the person to Try again, which syncs, never to Start, which does not.
        assert!(refused.message.starts_with("dev is set up and its tools are installed, and everything before it in this setup is in place."), "{}", refused.message);
        assert!(refused.message.contains("press Try again to finish"), "{}", refused.message);
        assert!(!refused.message.to_lowercase().contains("start the setup"), "{}", refused.message);
        // Neither copy was touched on the way out.
        assert_eq!(std::fs::read_to_string(chosen.path().join("app.js")).unwrap(), "mine");
        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "theirs");

        // Once the person makes them match, the same step finishes.
        std::fs::write(&theirs, "mine").unwrap();
        handler.sync_folders(&context, "sandbox-1").await.expect("trying again finishes it");
    }

    /// PROVES a writable folder is never touched without the person's agreement, which the stop
    /// path above must not have weakened.
    #[tokio::test]
    async fn a_writable_folder_without_consent_asks_rather_than_syncing() {
        let chosen = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let sandboxes = tempfile::tempdir().unwrap();
        let projects = Arc::new(fake::FakeProjects { sandbox_files: Some(sandboxes.path().to_path_buf()), ..Default::default() });
        let handler = EnvironmentHandler(Ordinary::new(projects, state.path().to_path_buf()));
        std::fs::write(chosen.path().join("app.js"), "one").unwrap();
        let refused = handler
            .sync_folders(&syncing_step("setup-1", "dev", chosen.path(), false), "sandbox-1")
            .await
            .expect_err("without agreement it does not change the person's files");
        assert_eq!(refused.code, "folder_consent_needed");
        assert_eq!(refused.outcome, Outcome::NeedsInput);
    }

    #[test]
    fn a_sandbox_spec_becomes_the_v1_environment_with_vault_names_for_its_secrets() {
        let spec = json!({
            "type": "container",
            "image": "ghcr.io/example/app:1.0.0",
            "ports": [8080],
            "secrets": {"APP_SECRET": "apply.app_secret", "STORED": "hub-site-key-codex", "UNSET": ""},
            "tools": [{"name": "codex", "source": "built-in", "spec": "codex"}],
            "volumes": [{"source": "data", "target": "/data"}]
        });
        let package = Path::new("/setups/projects/setup-1/package");
        let converted = environment("setup-6f1c2a1e-1b55-4c55-9a64-2d4a0b5c3e10", "app", &spec, package).unwrap();
        assert!(converted.secrets["APP_SECRET"].starts_with("setup-6f1c2a1e-app-app_secret-"));
        assert_ne!(converted.secrets["STORED"], "hub-site-key-codex", "never a stored entry by the template's name");
        assert!(!converted.secrets.contains_key("UNSET"));
        // A literal entry name is refused at review; a bundled tool's planner key is not.
        let handler = EnvironmentHandler(Ordinary::new(Arc::new(fake::FakeProjects::default()), PathBuf::from("/setups")));
        let grab = json!({"type": "container", "image": "x", "secrets": {"SEAL": "yougori-access-hub-seal"}});
        assert_eq!(handler.validate(&grab).unwrap_err().code, "invalid_spec");
        let key = json!({"type": "container", "image": "x", "secrets": {"KEY": "hub-site-key-httpie"}, "tools": [{"name": "httpie", "source": "bundled", "folder": "tools/httpie"}]});
        handler.validate(&key).unwrap();
        // Long or differently cased names never collide and fit the vault.
        let long = secret_name("setup-6f1c2a1e", &"r".repeat(60), &"V".repeat(60));
        assert!(long.len() <= 80 && yougori_cli::workload::identifier(&long));
        assert_ne!(secret_name("setup-1", "app", "KEY"), secret_name("setup-1", "app", "key"));
        let files = json!({"type": "container", "image": "x", "files": [{"source": "./app", "target": "/app"}]});
        let copied = environment("setup-1", "app", &files, package).unwrap();
        assert_eq!(Path::new(&copied.files[0].source), package.join("app"), "a template path becomes the kept copy");
        let escaping = json!({"type": "container", "image": "x", "files": [{"source": "../../secrets", "target": "/app"}]});
        assert_eq!(environment("setup-1", "app", &escaping, package).unwrap_err().code, "invalid_spec");
    }

    #[test]
    fn publications_map_quick_domain_and_private_access() {
        let quick = publication(&json!({"target": {"resource": "app"}, "port": 8080, "access": "quick"})).unwrap();
        assert!(matches!(quick, (target, Opening::Public(manifest::Publication::Detailed { port: 8080, domain: None, .. })) if target == "app"));
        let domain = publication(&json!({"target": {"resource": "app"}, "port": 80, "access": "domain", "domain": "shop.example.com"})).unwrap();
        assert!(matches!(domain.1, Opening::Public(manifest::Publication::Detailed { domain: Some(ref d), .. }) if d == "shop.example.com"));
        assert_eq!(publication(&json!({"target": {"resource": "app"}, "port": 80, "access": "private"})).unwrap().1, Opening::Here(80));
        assert_eq!(publication(&json!({"target": {"resource": "app"}, "port": 80, "access": "none"})).unwrap().1, Opening::Nothing);
        assert_eq!(publication(&json!({"target": {"resource": "app"}, "port": 80, "access": "lan"})).unwrap().1, Opening::Lan(80));
        assert_eq!(publication(&json!({"target": {"resource": "app"}, "port": 80, "access": "everywhere"})).unwrap_err().code, "invalid_spec");
    }

    /// PROVES the port on this computer a private publication listens on stays the same for a
    /// setup's every change and differs between two copies of one setup.
    #[test]
    fn a_private_port_is_steady_for_a_setup_and_different_for_its_copy() {
        let port = here_port("setup-1", "web");
        assert_eq!(port, here_port("setup-1", "web"));
        assert!((20000..40000).contains(&port), "{port}");
        assert_ne!(port, here_port("setup-2", "web"), "two copies of one setup ask for different ports");
    }

    #[test]
    fn a_two_way_connection_becomes_two() {
        let both = connections(&json!({"from": {"resource": "web"}, "to": {"resource": "db"}, "ports": [5432], "direction": "two_way"})).unwrap();
        assert_eq!(both.len(), 2);
        assert_eq!(both[1].endpoints().unwrap(), ("db", "web"));
    }

    /// A Hub tool's files as the handler reads them when applying: an example tool folder, or
    /// a refusal.
    struct FakeToolFiles {
        folder: PathBuf,
        error: Option<String>,
    }

    impl FakeToolFiles {
        fn httpie() -> Arc<FakeToolFiles> {
            Arc::new(FakeToolFiles { folder: Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub/hello-site/tools/httpie"), error: None })
        }
    }

    impl super::super::hub_tools::ToolFiles for FakeToolFiles {
        fn load<'a>(&'a self, _: &'a str, _: &'a str, version: &'a str) -> BoxFuture<'a, Result<super::super::hub_tools::FetchedTool, String>> {
            Box::pin(async move {
                if let Some(error) = &self.error {
                    return Err(error.clone());
                }
                let files = yougori_cli::hub::scan::collect(&self.folder).unwrap().files;
                let digest = yougori_cli::hub::scan::digest_of(&files);
                Ok(super::super::hub_tools::FetchedTool { files, version: version.to_owned(), digest, verified: true })
            })
        }
    }

    fn hub_step(tool: Value) -> StepContext {
        StepContext {
            setup: "setup-1".into(),
            operation: "op-1".into(),
            step: "step-1".into(),
            resource: "web".into(),
            kind: Kind::Environment,
            action: Action::Create,
            label: "label-1".into(),
            created_label: None,
            generation: 1,
            spec: json!({"type": "container", "image": "python:3.12-slim", "tools": [tool]}),
            runtime_id: None,
            owner: None,
            peers: Default::default(),
            planned: Default::default(),
            cancel: CancellationToken::new(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Default::default(),
        }
    }

    fn hub_tool(extra: Value) -> Value {
        let mut tool = json!({"name": "acme/httpie", "source": "hub", "item": "acme/httpie", "version": "1.0.0", "spec": "hub/acme/httpie@1.0.0"});
        tool.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
        tool
    }

    /// PROVES a pinned Hub tool is installed through the one custom-tool path a bundled tool
    /// takes (`install_custom`, under the tool's own name), that its key binding is usable, and
    /// that files other than the reviewed ones, or none, stop the step rather than installing.
    #[tokio::test]
    async fn a_hub_tool_installs_through_the_custom_tool_path_and_changed_files_are_refused() {
        let state = tempfile::tempdir().unwrap();
        let projects = Arc::new(fake::FakeProjects::default());
        let handler = EnvironmentHandler(Ordinary::new(projects.clone(), state.path().to_path_buf()).with_tool_files(FakeToolFiles::httpie()));
        let context = hub_step(hub_tool(json!({})));
        handler.validate(&context.spec).unwrap();
        handler.tools(&context, "sandbox-1").await.unwrap();
        assert_eq!(projects.state.lock().unwrap().tools["sandbox-1"], ["httpie"], "installed under its own file's name, as a bundled tool is");
        assert!(handler.tools_settled(&context, "sandbox-1").await);
        // Its key is given the way a bundled tool's is.
        let keyed = json!({"type": "container", "image": "x", "secrets": {"HTTPIE_TOKEN": "hub-toolbox-key-httpie"}, "tools": [hub_tool(json!({}))]});
        handler.validate(&keyed).unwrap();
        let other = json!({"type": "container", "image": "x", "secrets": {"HTTPIE_TOKEN": "hub-toolbox-key-other"}, "tools": [hub_tool(json!({}))]});
        assert_eq!(handler.validate(&other).unwrap_err().code, "invalid_spec", "only this tool's own key");

        // Unpinned, or not a Hub item: refused at review, before anything is made.
        let unpinned = json!({"type": "container", "image": "x", "tools": [{"name": "acme/httpie", "source": "hub", "item": "acme/httpie", "spec": "hub/acme/httpie"}]});
        let refused = handler.validate(&unpinned).unwrap_err();
        assert_eq!(refused.code, "unsupported_here");
        assert!(refused.message.contains("hub/acme/httpie@VERSION"), "{}", refused.message);
        let odd = json!({"type": "container", "image": "x", "tools": [hub_tool(json!({"item": "Acme"}))]});
        assert_eq!(handler.validate(&odd).unwrap_err().code, "invalid_spec");

        // Files that hash otherwise than the review recorded are not installed.
        let projects = Arc::new(fake::FakeProjects::default());
        let handler = EnvironmentHandler(Ordinary::new(projects.clone(), state.path().to_path_buf()).with_tool_files(FakeToolFiles::httpie()));
        let changed = handler.tools(&hub_step(hub_tool(json!({"digest": "f".repeat(64)}))), "sandbox-1").await.unwrap_err();
        assert_eq!(changed.code, "tool_changed");
        assert!(changed.message.contains("Plan the setup again"), "{}", changed.message);
        assert!(projects.state.lock().unwrap().tools.is_empty(), "nothing was installed");
        let actual = yougori_cli::hub::scan::digest_of(&yougori_cli::hub::scan::collect(&FakeToolFiles::httpie().folder).unwrap().files);
        handler.tools(&hub_step(hub_tool(json!({"digest": actual}))), "sandbox-1").await.unwrap();
        assert_eq!(projects.state.lock().unwrap().tools["sandbox-1"], ["httpie"]);

        // Files that cannot be read: the step fails and may be retried; nothing is installed.
        let projects = Arc::new(fake::FakeProjects::default());
        let gone = Arc::new(FakeToolFiles { folder: PathBuf::new(), error: Some("The Hub answered 503.".into()) });
        let handler = EnvironmentHandler(Ordinary::new(projects.clone(), state.path().to_path_buf()).with_tool_files(gone));
        let failed = handler.tools(&hub_step(hub_tool(json!({}))), "sandbox-1").await.unwrap_err();
        assert_eq!(failed.code, "tool_unavailable");
        assert!(failed.retryable && failed.message.contains("The Hub answered 503."), "{}", failed.message);
        assert!(projects.state.lock().unwrap().tools.is_empty());
    }
}
