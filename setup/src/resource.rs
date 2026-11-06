//! Typed resource kinds of a v2 project graph.
//!
//! Every kind has a spec struct that refuses unknown fields, so a typo is a refusal rather than a
//! silently ignored setting. Fields take their own types; an answer placeholder standing alone
//! keeps the answer's type. References name other resources by id, and a binding names an
//! installation-time choice the person makes on their own computer (a folder, a drive): no
//! answer can ever produce a path on this computer.
use crate::{capability::GridProfile, format::Retention, limits};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

/// The kinds a v2 project resource can have. An unknown kind is refused, never executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Environment,
    Grid,
    ComputePool,
    WorkerGroup,
    ModelService,
    WorkspacePool,
    AccessBinding,
    CredentialBroker,
    ServicePublication,
    Volume,
    Connection,
    Job,
    ArtifactStore,
    /// A restricted VM on this computer (the engine's `sandbox_vm` path): a pinned minimal
    /// guest with no network but its declared routes and no files but its staged workspace.
    VmSandbox,
}

impl Kind {
    pub const ALL: [Kind; 14] = [
        Kind::Environment,
        Kind::Grid,
        Kind::ComputePool,
        Kind::WorkerGroup,
        Kind::ModelService,
        Kind::WorkspacePool,
        Kind::AccessBinding,
        Kind::CredentialBroker,
        Kind::ServicePublication,
        Kind::Volume,
        Kind::Connection,
        Kind::Job,
        Kind::ArtifactStore,
        Kind::VmSandbox,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Environment => "environment",
            Kind::Grid => "grid",
            Kind::ComputePool => "compute_pool",
            Kind::WorkerGroup => "worker_group",
            Kind::ModelService => "model_service",
            Kind::WorkspacePool => "workspace_pool",
            Kind::AccessBinding => "access_binding",
            Kind::CredentialBroker => "credential_broker",
            Kind::ServicePublication => "service_publication",
            Kind::Volume => "volume",
            Kind::Connection => "connection",
            Kind::Job => "job",
            Kind::ArtifactStore => "artifact_store",
            Kind::VmSandbox => "vm_sandbox",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// The kind as a review names it.
    pub fn title(self) -> &'static str {
        match self {
            Kind::Environment => "sandbox",
            Kind::Grid => "grid",
            Kind::ComputePool => "compute pool",
            Kind::WorkerGroup => "worker group",
            Kind::ModelService => "model service",
            Kind::WorkspacePool => "workspace pool",
            Kind::AccessBinding => "people and access",
            Kind::CredentialBroker => "credential broker",
            Kind::ServicePublication => "public address",
            Kind::Volume => "volume",
            Kind::Connection => "connection",
            Kind::Job => "job",
            Kind::ArtifactStore => "artifact store",
            Kind::VmSandbox => "VM sandbox",
        }
    }

    /// The outputs a resource of this kind has once it exists, by name. A reference or an
    /// `{{outputs.RESOURCE.NAME}}` placeholder may name these and nothing else.
    pub fn outputs(self) -> &'static [&'static str] {
        match self {
            Kind::Environment => &["name", "address"],
            Kind::Grid => &["realm_id", "join_address", "name", "page", "invitation"],
            Kind::ComputePool => &["id", "computers"],
            Kind::WorkerGroup => &["id", "count"],
            Kind::ModelService => &["id", "endpoint", "model", "first_key"],
            Kind::WorkspacePool => &["id", "access_url"],
            Kind::AccessBinding => &["id", "join_method", "page", "invitation"],
            Kind::CredentialBroker => &["id", "endpoint"],
            Kind::ServicePublication => &["url", "port"],
            Kind::Volume => &["id", "name"],
            Kind::Connection => &["id"],
            Kind::Job => &["id", "status", "event_url"],
            Kind::ArtifactStore => &["id", "path"],
            Kind::VmSandbox => &["id", "status"],
        }
    }
}

/// A text field that accepts any scalar: a number or a boolean typed by an answer reads as text.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Text(pub String);

impl Text {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Text {
    fn from(text: &str) -> Text {
        Text(text.to_owned())
    }
}

impl Serialize for Text {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Text, D::Error> {
        use serde::de::Error;
        fn scalar(value: &Json) -> Option<String> {
            match value {
                Json::String(text) => Some(text.clone()),
                Json::Number(number) => Some(number.to_string()),
                Json::Bool(value) => Some(if *value { "yes" } else { "no" }.into()),
                Json::Null => Some(String::new()),
                _ => None,
            }
        }
        let value = Json::deserialize(deserializer)?;
        if let Some(text) = scalar(&value) {
            return Ok(Text(text));
        }
        // A multiple-choice answer standing alone reads as v1 wrote it: the values joined with
        // commas, so a site that reads SELECTED_PROVIDERS=codex,kilo keeps working.
        if let Json::Array(items) = &value {
            if let Some(parts) = items.iter().map(scalar).collect::<Option<Vec<_>>>() {
                return Ok(Text(parts.join(",")));
            }
        }
        Err(D::Error::custom("expected a single value or a list of values, not a mapping"))
    }
}

/// A typed reference to another resource of this setup (`{resource: id}`), or to an existing
/// resource of another setup chosen when the setup is applied (`{binding: id}`, a binding of
/// type resource), optionally naming one of its outputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Reference {
    pub fn to(resource: &str) -> Reference {
        Reference { resource: Some(resource.to_owned()), binding: None, output: None }
    }

    /// The resource id of this setup, when the reference names one.
    pub fn local(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    /// Why the reference is malformed, if it is: exactly one of resource and binding.
    pub fn problem(&self) -> Option<String> {
        match (&self.resource, &self.binding) {
            (Some(_), None) | (None, Some(_)) => None,
            (Some(_), Some(_)) => Some("a reference names a resource or a binding, not both".into()),
            (None, None) => Some("a reference needs resource: ID or binding: ID".into()),
        }
    }
}

/// A reference to an installation-time binding declared in the template: a folder, a drive or
/// a file the person chooses on their own computer, with consent, when the setup is applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRef {
    pub binding: String,
}

/// What a binding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingKind {
    Folder,
    Drive,
    File,
    /// An existing resource of another setup on this installation, chosen from the person's own
    /// setups: a grid to add a team to, an environment to share.
    Resource,
}

impl BindingKind {
    pub fn id(self) -> &'static str {
        match self {
            BindingKind::Folder => "folder",
            BindingKind::Drive => "drive",
            BindingKind::File => "file",
            BindingKind::Resource => "resource",
        }
    }
    pub fn parse(text: &str) -> Option<BindingKind> {
        [BindingKind::Folder, BindingKind::Drive, BindingKind::File, BindingKind::Resource].into_iter().find(|k| k.id() == text)
    }
}

pub const CONNECTION_PERMISSIONS: &[&str] = &["network", "ports", "files", "volumes", "data", "secrets"];

/// Where a kind allows placeholders. `no_placeholders` are paths on this computer: a placeholder
/// there is refused. `secrets` are the fields that may hold a `{{secrets.ID}}` binding as a whole.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub no_placeholders: &'static [&'static str],
    pub secrets: &'static [&'static str],
}

pub fn policy(kind: Kind) -> Policy {
    match kind {
        // Where a folder of this computer is, and whether and how it is mounted, are the
        // template's: an answer could otherwise turn a plain volume into a writable host folder
        // that the review never showed.
        Kind::Environment => Policy {
            no_placeholders: &["files[].source", "volumes[].source", "volumes[].bind", "volumes[].read_only", "pc_access[].path", "pc_access[].read_only", "pc_access[].binding", "sync", "source", "storage_drive", "depends_on[]"],
            secrets: &["secrets.*"],
        },
        Kind::ServicePublication | Kind::Volume | Kind::Connection | Kind::ArtifactStore => Policy { no_placeholders: &[], secrets: &[] },
        // The folder a VM sandbox works on a copy of is the person's choice at setup, and its
        // credentials are named, never given: a route carries an enrolled credential by its name.
        Kind::VmSandbox => Policy { no_placeholders: &["workspace", "workspace_folder", "application.source", "application.command"], secrets: &["application.secrets.*"] },
        _ => Policy { no_placeholders: &[], secrets: &["secrets.*"] },
    }
}

fn yes() -> bool {
    true
}
fn one() -> u32 {
    1
}
fn container() -> String {
    "container".into()
}
fn cpu() -> f64 {
    2.0
}
fn memory() -> Json {
    serde_json::json!(2)
}
fn storage() -> Json {
    serde_json::json!(20)
}
fn hour() -> u64 {
    3600
}
fn ten() -> f64 {
    10.0
}
fn root() -> Text {
    Text("/".into())
}
fn ok() -> u16 {
    200
}

// ---- environment ----

/// A sandbox's command: a list of parts, or one shell line. The list is tried first, since a
/// text field also reads a list (joined with commas) and a command list must stay a list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Command {
    Args(Vec<Text>),
    Shell(Text),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSource {
    pub source: String,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub bind: bool,
}

/// A folder of this computer the sandbox reaches: a fixed folder inside the template (`path`), or
/// the folder the person chose for a folder binding of mode mount (`binding`). For a binding the
/// planner fills in `path` and `read_only` from the person's choice and the binding; a template
/// writes neither.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcAccess {
    #[serde(default)]
    pub path: String,
    #[serde(default = "yes")]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

/// How a folder binding reaches the sandbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderMode {
    /// The sandbox reaches the folder itself (`pc_access`).
    #[default]
    Mount,
    /// The sandbox keeps its own copy, and Yougori syncs the two (`sync`).
    Sync,
    /// A VM sandbox works on a staged copy (`workspace` of a `vm_sandbox`); the folder changes
    /// only when the person reviews the copy's changes and approves them, file by file.
    Staged,
}

impl FolderMode {
    pub fn id(self) -> &'static str {
        match self {
            FolderMode::Mount => "mount",
            FolderMode::Sync => "sync",
            FolderMode::Staged => "staged",
        }
    }
    pub fn parse(text: &str) -> Option<FolderMode> {
        [FolderMode::Mount, FolderMode::Sync, FolderMode::Staged].into_iter().find(|m| m.id() == text)
    }
}

/// What a sync does with a file changed on both sides since they last matched. Neither choice
/// ever replaces an edit without keeping it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncConflicts {
    /// Both versions are kept: each side keeps its own under the file's name, the sandbox's is
    /// saved beside this computer's as a conflict copy, and the file waits until the person
    /// removes the copy.
    #[default]
    KeepBoth,
    /// The whole sync stops, changing nothing, until the two copies match again.
    Stop,
}

impl SyncConflicts {
    pub fn id(self) -> &'static str {
        match self {
            SyncConflicts::KeepBoth => "keep_both",
            SyncConflicts::Stop => "stop",
        }
    }
}

/// A folder the person chose (a folder binding of mode sync) kept in step with a folder inside the
/// sandbox by Yougori's sync. Writable bindings sync both ways; read-only ones only from this
/// computer into the sandbox. The planner fills in `path` and `read_only`; a template writes
/// `binding`, `target` and optionally `continuous` and `conflicts`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderSync {
    pub binding: String,
    /// The folder inside the sandbox that holds the copy.
    pub target: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default = "yes")]
    pub read_only: bool,
    /// Keep syncing while the setup runs (true), or only when it starts and stops.
    #[serde(default = "yes")]
    pub continuous: bool,
    #[serde(default)]
    pub conflicts: SyncConflicts,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub pc: bool,
    #[serde(default)]
    pub edit: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Port {
    Number(u16),
    Mapping(String),
    Detailed { target: u16, published: Option<u16> },
}

impl Port {
    /// The container port and the host port, if one is fixed.
    pub fn values(&self) -> Result<(u16, Option<u16>), String> {
        let pair = match self {
            Port::Number(p) => (*p, None),
            Port::Detailed { target, published } => (*target, *published),
            Port::Mapping(s) => {
                let s = s.strip_suffix("/tcp").unwrap_or(s);
                let parts = s.split(':').collect::<Vec<_>>();
                let n = |s: &str| s.parse::<u16>().map_err(|_| "Ports must be between 1 and 65535".to_string());
                match parts.as_slice() {
                    [p] => (n(p)?, None),
                    [h, p] => (n(p)?, Some(n(h)?)),
                    ["127.0.0.1", h, p] => (n(p)?, Some(n(h)?)),
                    _ => return Err("Use TCP ports as guest or host:guest; published ports are loopback-only".into()),
                }
            }
        };
        if pair.0 == 0 || pair.1 == Some(0) {
            return Err("Port zero is not valid".into());
        }
        Ok(pair)
    }
}

/// A tool the plan installs into a sandbox, as the engine needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInstall {
    pub name: String,
    /// `built-in`, `bundled` or `hub`.
    pub source: String,
    /// As written in `tools:`.
    #[serde(default)]
    pub spec: String,
    /// The folder of a bundled tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// `PUBLISHER/NAME` and the version of a Hub tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SHA-256 of a Hub tool's files as they were reviewed, so apply installs exactly those files
    /// and nothing the cache may hold now: the handler refuses a tool whose digest differs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Open the tool's subscription sign-in after the install.
    #[serde(default)]
    pub signin: bool,
    /// Whether to copy this computer's credentials (`true`) or sign in anew (`false`), when the
    /// template asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signin_hint: Option<String>,
}

/// A sandbox: the v1 environment fields with their v1 meaning, plus the tools a plan installs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSpec {
    #[serde(default = "container", rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default = "cpu")]
    pub cpu: f64,
    #[serde(default = "memory")]
    pub memory: Json,
    #[serde(default)]
    pub gpu: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Command>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Command>,
    #[serde(default)]
    pub environment: BTreeMap<String, Text>,
    /// Environment variable to the name of the binding that holds the value. Values never belong
    /// in a project file.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub files: Vec<FileSource>,
    #[serde(default)]
    pub automatic_start: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Json>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<Json>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default)]
    pub volumes: Vec<Mount>,
    #[serde(default = "storage")]
    pub storage: Json,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_drive: Option<String>,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default = "yes")]
    pub internet: bool,
    #[serde(default)]
    pub pc_access: Vec<PcAccess>,
    /// Format 2: folders the person chose, kept in step with a folder inside the sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync: Vec<FolderSync>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub restart: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<Json>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolInstall>,
}

impl EnvironmentSpec {
    /// The image the review shows: a microVM's boot source, a VM's source, else the OCI image.
    pub fn image_shown(&self) -> String {
        match self.kind.as_str() {
            "microvm" if self.image.is_empty() => self.source.clone().unwrap_or_else(|| "builtin:alpine".into()),
            "vm" => self.source.clone().unwrap_or_else(|| self.image.clone()),
            _ => self.image.clone(),
        }
    }

    pub fn uses_gpu(&self) -> bool {
        self.gpu || self.kind == "gpu"
    }

    /// The container ports.
    pub fn guest_ports(&self) -> Vec<u16> {
        self.ports.iter().filter_map(|p| p.values().ok()).map(|(guest, _)| guest).collect()
    }

    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !["container", "gpu", "microvm", "vm", "cloud", "shared"].contains(&self.kind.as_str()) {
            problems.push(format!("type {} is not an environment type", self.kind));
        }
        if !self.cpu.is_finite() || self.cpu <= 0.0 || self.cpu > 255.0 {
            problems.push("cpu must be between 0 and 255".into());
        }
        match crate::format::gib(&self.memory) {
            Ok(gb) if gb > 1024.0 => problems.push("memory must be at most 1024 GB".into()),
            Ok(_) => {}
            Err(error) => problems.push(format!("memory: {error}")),
        }
        match crate::format::gib(&self.storage) {
            Ok(gb) => {
                let minimum = if self.kind == "microvm" { 6.0 } else { 1.0 };
                if !(minimum..=16380.0).contains(&gb) || gb.fract() != 0.0 {
                    problems.push(format!("storage must be whole GiB between {minimum:.0} and 16380"));
                }
            }
            Err(error) => problems.push(format!("storage: {error}")),
        }
        if matches!(self.kind.as_str(), "container" | "gpu") && (self.image.is_empty() || self.image.starts_with('-') || self.image.len() > 512 || self.image.chars().any(char::is_whitespace)) {
            problems.push("an OCI image is required".into());
        }
        if self.kind == "vm" && self.source.as_ref().unwrap_or(&self.image).is_empty() {
            problems.push("VM source is required".into());
        }
        if matches!(self.kind.as_str(), "vm" | "cloud" | "shared") && (self.command.is_some() || self.entrypoint.is_some() || !self.environment.is_empty() || !self.volumes.is_empty() || self.working_dir.is_some() || self.user.is_some() || !self.restart.is_empty()) {
            problems.push("OCI startup, environment and volume options require a container or an OCI microVM workload".into());
        }
        if self.kind == "microvm" && self.image.is_empty() && (self.command.is_some() || !self.environment.is_empty() || !self.volumes.is_empty()) {
            problems.push("set image to configure an OCI workload inside the microVM".into());
        }
        if !self.secrets.is_empty() && !matches!(self.kind.as_str(), "container" | "gpu" | "microvm") {
            problems.push("secret bindings require a local container or microVM".into());
        }
        if self.kind == "microvm" && self.image.is_empty() && !self.secrets.is_empty() {
            problems.push("secret bindings require an OCI workload image inside the microVM".into());
        }
        if !self.files.is_empty() && !matches!(self.kind.as_str(), "container" | "gpu" | "microvm") {
            problems.push("managed file copies require a container or microVM".into());
        }
        if self.kind == "microvm" && !self.image.is_empty() && !self.files.is_empty() {
            problems.push("managed code copies in a nested OCI microVM are not supported".into());
        }
        let mut targets = BTreeSet::new();
        if self.files.len() > 64 || self.files.iter().any(|f| f.source.is_empty() || f.source.contains('\0') || !guest_path(&f.target) || !targets.insert(&f.target)) {
            problems.push("files require at most 64 source paths and unique absolute guest targets".into());
        }
        for mount in &self.volumes {
            if !guest_path(&mount.target) {
                problems.push("invalid volume target".into());
            }
            if mount.bind && !self.permissions.pc {
                problems.push("bind volumes require permissions.pc: true".into());
            }
            if mount.bind && !mount.read_only && !self.permissions.edit {
                problems.push("writable PC volumes require permissions.edit: true".into());
            }
        }
        if !self.pc_access.is_empty() && !self.permissions.pc {
            problems.push("PC access requires permissions.pc: true".into());
        }
        if self.pc_access.iter().any(|p| !p.read_only) && !self.permissions.edit {
            problems.push("View & Edit requires permissions.edit: true".into());
        }
        for access in &self.pc_access {
            if access.path.is_empty() && access.binding.is_none() {
                problems.push("pc_access needs path: (a folder in the template) or binding: (a folder binding)".into());
            }
            if access.target.as_deref().is_some_and(|target| !guest_path(target)) {
                problems.push("pc_access target must be an absolute folder inside the sandbox".into());
            }
        }
        if !self.sync.is_empty() {
            if !matches!(self.kind.as_str(), "container" | "gpu") {
                problems.push("sync needs a container sandbox".into());
            }
            if !self.permissions.pc {
                problems.push("sync reaches a folder of this computer, so it requires permissions.pc: true".into());
            }
            if self.sync.iter().any(|s| !s.read_only) && !self.permissions.edit {
                problems.push("a writable synced folder requires permissions.edit: true".into());
            }
            if self.sync.len() > 8 {
                problems.push("at most 8 synced folders per sandbox".into());
            }
            let folder = |target: &str| target.trim_end_matches('/').to_owned();
            let mut synced = BTreeSet::new();
            for entry in &self.sync {
                if !guest_path(&entry.target) || folder(&entry.target).is_empty() {
                    problems.push(format!("sync target {} must be an absolute folder inside the sandbox other than /", entry.target));
                } else if !synced.insert(folder(&entry.target)) {
                    problems.push(format!("sync target {} is used twice", entry.target));
                }
            }
            for entry in &self.sync {
                if self.sync.iter().any(|other| folder(&entry.target).starts_with(&format!("{}/", folder(&other.target)))) {
                    problems.push(format!("sync target {} is inside another synced folder", entry.target));
                }
            }
        }
        let mut guest_ports: BTreeMap<u16, u16> = BTreeMap::new();
        for port in &self.ports {
            match port.values() {
                Ok((guest, Some(host))) => {
                    if let Some(first) = guest_ports.insert(guest, host) {
                        problems.push(format!("port {guest} is published twice ({first} and {host}); publish each guest port once"));
                    }
                }
                Ok(_) => {}
                Err(error) => problems.push(error),
            }
        }
        for (variable, binding) in &self.secrets {
            if !variable_name(variable) || !identifier(binding) {
                problems.push(format!("secrets: {variable} must name an environment variable and a binding name"));
            }
        }
        if self.tools.len() > 32 {
            problems.push("at most 32 tools per sandbox".into());
        }
        problems
    }
}

/// An absolute path inside a sandbox.
pub fn guest_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 4096 && !path.contains('\0') && !path.split('/').any(|part| part == "..")
}

/// A name the engine stores things under: letters, digits, dots, dashes or underscores.
pub fn identifier(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

fn variable_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && name.bytes().enumerate().all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

// ---- grid ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GridMode {
    /// Start a grid this setup coordinates.
    #[default]
    Create,
    /// Join a grid someone else coordinates, with an invitation held as a secret.
    Join,
    /// Use an existing grid of another setup, named by `borrow:` on the resource.
    Attach,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coordinator {
    #[default]
    ThisComputer,
    Remote,
}

/// Who joins a grid: a computer that contributes, or a person who signs in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Member {
    #[default]
    Computer,
    Person,
}

/// How a person signs in to a grid.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignIn {
    #[default]
    Password,
    Sso,
}

fn lan() -> PublicAccess {
    PublicAccess::Lan
}

/// A grid: one realm with its profile, created, joined or attached.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GridSpec {
    /// Which trusted profile runs the realm: neo_grid, sandbox_grid, access_grid,
    /// swarm_mining_grid or generic.
    pub profile: GridProfile,
    #[serde(default)]
    pub mode: GridMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Text>,
    #[serde(default)]
    pub coordinator: Coordinator,
    /// The coordinator's private network address (LAN or VPN), where computers reach the grid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Text>,
    /// How computers and people reach the coordinator: this network, a quick link or a domain.
    #[serde(default = "lan")]
    pub access: PublicAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Text>,
    /// What joins, for mode join: a computer that contributes, or a person who signs in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<Member>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in: Option<SignIn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<Text>,
    /// Named secret bindings the profile needs: `invitation` to join, `join_password` or
    /// `password` to sign in.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
    /// What a research grid this setup hosts reviews, and what its host authorised
    /// (swarm_mining_grid, mode create only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub research: Option<ResearchSpec>,
}

/// What a research grid reviews, in its host's own words. The authorisation is the record of what
/// was agreed to, so it is sent as written and never made up.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchSpec {
    /// What the agents should look into.
    pub instructions: Text,
    /// What they are allowed to test, and with which test accounts.
    pub authorization: Text,
    /// What is reviewed: `source` (the code only), or a `web` site or an `api` started inside the
    /// worker's own sandbox. Never a target already running somewhere.
    #[serde(default = "source_target")]
    pub target: Text,
    /// How the project is prepared, once, before the review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_command: Option<Text>,
    /// Whether that preparation may reach the internet. The review itself never does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_network: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_command: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_command: Option<Text>,
}

fn source_target() -> Text {
    Text("source".into())
}

impl ResearchSpec {
    /// What can be checked of the text alone. That a web or api target says how it starts, and
    /// that a source review starts nothing, depends on the answers, so the engine checks it.
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.instructions.as_str().trim().is_empty() {
            problems.push("research.instructions must say what to look into".into());
        }
        if self.authorization.as_str().trim().is_empty() {
            problems.push("research.authorization must say what may be tested".into());
        }
        if !matches!(self.target.as_str(), "source" | "web" | "api") && !self.target.as_str().contains("{{") {
            problems.push("research.target must be source, web or api; a live target is never reviewed here".into());
        }
        problems
    }
}

impl GridSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.mode == GridMode::Join && !self.secrets.contains_key("invitation") {
            problems.push("mode: join needs secrets: {invitation: \"{{secrets.ID}}\"}: the invitation is private".into());
        }
        if self.mode != GridMode::Join && self.secrets.contains_key("invitation") {
            problems.push("secrets.invitation belongs to mode: join".into());
        }
        if self.profile == GridProfile::Generic {
            problems.push("profile must be neo_grid, sandbox_grid, access_grid or swarm_mining_grid; generic setups do not create a grid".into());
        }
        if self.access == PublicAccess::Domain && self.domain.as_ref().is_none_or(|d| d.as_str().trim().is_empty()) {
            problems.push("access: domain needs domain: a saved domain".into());
        }
        if matches!(self.access, PublicAccess::Private | PublicAccess::NoAccess) {
            problems.push("access must be lan, quick or domain: other computers must be able to reach the coordinator".into());
        }
        if self.member == Some(Member::Person) && self.sign_in.unwrap_or_default() == SignIn::Password && !self.secrets.contains_key("password") {
            problems.push("member: person with sign_in: password needs secrets: {password: \"{{secrets.ID}}\"}".into());
        }
        if self.member == Some(Member::Person) && self.mode != GridMode::Join {
            problems.push("member: person belongs to mode: join".into());
        }
        match &self.research {
            Some(research) if self.profile == GridProfile::SwarmMiningGrid && self.mode == GridMode::Create => problems.extend(research.validate()),
            Some(_) => problems.push("research: belongs to a swarm_mining_grid this setup hosts (mode: create)".into()),
            None if self.profile == GridProfile::SwarmMiningGrid && self.mode == GridMode::Create => {
                problems.push("a swarm_mining_grid this setup hosts needs research: {instructions, authorization}".into())
            }
            None => {}
        }
        problems
    }
}

// ---- compute pool ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeSource {
    #[default]
    ThisComputer,
    SelectedComputers,
    Cloud,
    Any,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuNeed {
    #[default]
    #[serde(rename = "none")]
    NoGpu,
    Optional,
    Required,
}

impl GpuNeed {
    pub fn id(self) -> &'static str {
        match self {
            GpuNeed::NoGpu => "none",
            GpuNeed::Optional => "optional",
            GpuNeed::Required => "required",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    #[default]
    Always,
    Idle,
    Scheduled,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus: Option<u32>,
}

impl ResourceLimits {
    fn validate(&self, what: &str) -> Vec<String> {
        let mut problems = Vec::new();
        for (name, value) in [("cpu", self.cpu), ("memory_gb", self.memory_gb), ("disk_gb", self.disk_gb)] {
            if value.is_some_and(|v| !v.is_finite() || v <= 0.0) {
                problems.push(format!("{what}.{name} must be a positive number"));
            }
        }
        problems
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudCompute {
    /// `runpod` for a Neo Grid's rented GPUs; `aws`, `azure` or `google` for the computers a
    /// Sandbox Grid makes in the company's own cloud account when its computers have no room.
    pub provider: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_type: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<Text>,
    /// The most the person accepts per hour; the provider's own billing decides what is charged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hourly_cost: Option<f64>,
    /// The most the rented computers may cost in a calendar month (`run.budget`). They are
    /// stopped before it is passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,
    /// How many computers at most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_computers: Option<u32>,
    // What a company's own cloud needs to make one (a Sandbox Grid's): the CLI profile or
    // account, the machine and its image, the network it goes on, and how Yougori signs in to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_project: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_type: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_group: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_pair: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_group: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_public_key: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<Text>,
    /// The SSH private key on this computer that signs in to a new cloud computer: a file the
    /// person chooses (`{binding: ID}`), never a path a template names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<BindingRef>,
    /// That file, as the planner fills it in from the person's choice. A template never writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_path: Option<String>,
}

/// The computers a grid may run work on, with their limits and availability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputePoolSpec {
    pub grid: Reference,
    #[serde(default)]
    pub source: ComputeSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub computers: Vec<Text>,
    #[serde(default)]
    pub gpu: GpuNeed,
    #[serde(default)]
    pub limits: ResourceLimits,
    #[serde(default)]
    pub availability: Availability,
    /// Minutes without a person at the keyboard before an idle computer serves, 1 to 1440.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_after_minutes: Option<u32>,
    /// The hours a computer serves, with availability idle or scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Text>,
    #[serde(default = "yes")]
    pub local_user_first: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudCompute>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl ComputePoolSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = self.limits.validate("limits");
        if self.source == ComputeSource::SelectedComputers && self.computers.is_empty() {
            problems.push("source: selected_computers needs computers: the names of the selected computers".into());
        }
        if !limits::COMPUTERS.allows(self.computers.len()) {
            problems.push(limits::COMPUTERS.exceeded(self.computers.len()));
        }
        if self.source == ComputeSource::Cloud && self.cloud.is_none() {
            problems.push("source: cloud needs cloud: {provider: ...}".into());
        }
        if self.availability == Availability::Scheduled && self.schedule.as_ref().is_none_or(|s| s.as_str().trim().is_empty()) {
            problems.push("availability: scheduled needs schedule:".into());
        }
        if self.idle_after_minutes.is_some_and(|m| !(1..=1440).contains(&m)) {
            problems.push("idle_after_minutes must be 1 to 1440".into());
        }
        if self.cloud.as_ref().is_some_and(|c| c.max_hourly_cost.is_some_and(|v| !v.is_finite() || v < 0.0)) {
            problems.push("cloud.max_hourly_cost must be zero or more".into());
        }
        if self.cloud.as_ref().is_some_and(|c| c.budget_usd.is_some_and(|v| !v.is_finite() || v <= 0.0)) {
            problems.push("cloud.budget_usd must be more than zero".into());
        }
        if self.cloud.as_ref().is_some_and(|c| c.max_computers.is_some_and(|n| !(1..=64).contains(&n))) {
            problems.push("cloud.max_computers must be 1 to 64".into());
        }
        problems
    }
}

// ---- worker group ----

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_minutes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<Text>,
}

/// Workers of one role on a compute pool: research workers, build workers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerGroupSpec {
    pub pool: Reference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Text>,
    #[serde(default = "one")]
    pub count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<Reference>,
    /// An isolated sandbox each worker gets, as a template of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Reference>,
    /// Source the workers work on, chosen on this computer when the setup is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<BindingRef>,
    /// That folder, as the planner fills it in from the person's choice. A template never writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_folder: Option<String>,
    /// What the worker is called where its findings and chat are shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Text>,
    /// What happens to a research worker's finding: `review` (the person reads it first) or
    /// `automatic` (sent to the project it works for, only on a project this setup hosts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_policy: Option<Text>,
    #[serde(default)]
    pub limits: ResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl WorkerGroupSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = self.limits.validate("limits");
        if self.count == 0 || !limits::WORKERS.allows(self.count as usize) {
            problems.push(format!("count must be 1 to {}", limits::WORKERS.max));
        }
        if self.max.is_some_and(|max| max < self.count) {
            problems.push("max must be at least count".into());
        }
        if self.budget.as_ref().is_some_and(|b| b.cost_cap.is_some_and(|v| !v.is_finite() || v < 0.0)) {
            problems.push("budget.cost_cap must be zero or more".into());
        }
        if self.budget.as_ref().is_some_and(|b| b.time_minutes.is_some_and(|minutes| !(1..=1440).contains(&minutes))) {
            problems.push("budget.time_minutes must be 1 to 1440".into());
        }
        if self.report_policy.as_ref().is_some_and(|policy| !matches!(policy.as_str(), "review" | "automatic")) {
            problems.push("report_policy must be review or automatic".into());
        }
        problems
    }
}

// ---- model service ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiProtocol {
    #[default]
    Openai,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelApi {
    #[serde(default)]
    pub protocol: ApiProtocol,
    /// Scoped application keys to create, shown once.
    #[serde(default)]
    pub keys: u32,
    /// The application name of the first key, shown once as the `first_key` output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_key: Option<Text>,
}

/// Where a model is placed on the pool's computers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// On the computers that still have room.
    Remaining,
    /// On every computer of the pool.
    All,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamStrategy {
    #[default]
    Plan,
    Mixture,
}

/// A team: one request answered by a lead model with worker models, across computers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Team {
    #[serde(default)]
    pub strategy: TeamStrategy,
    pub lead: Reference,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<Reference>,
    /// Computers the team may use at once, 1 to 32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computers: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rounds: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Listing {
    Free,
    Paid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkListing {
    pub listing: Listing,
    #[serde(default)]
    pub enabled: bool,
}

/// A model served for a setup: on a compute pool, in a sandbox, or borrowed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelServiceSpec {
    pub model: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<Reference>,
    #[serde(default = "one")]
    pub replicas: u32,
    #[serde(default)]
    pub gpu: GpuNeed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<f64>,
    /// On which of the pool's computers the model is placed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<Placement>,
    /// The share of each computer the model may use, 1 to 100 percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_percent: Option<u8>,
    #[serde(default)]
    pub api: ModelApi,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkListing>,
    /// A team of models answering as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<Team>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl ModelServiceSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.model.as_str().trim().is_empty() {
            problems.push("model is required".into());
        }
        if self.replicas == 0 || !limits::REPLICAS.allows(self.replicas as usize) {
            problems.push(format!("replicas must be 1 to {}", limits::REPLICAS.max));
        }
        if self.memory_gb.is_some_and(|v| !v.is_finite() || v <= 0.0) {
            problems.push("memory_gb must be a positive number".into());
        }
        if self.api.keys > 64 {
            problems.push("api.keys must be at most 64".into());
        }
        if self.share_percent.is_some_and(|p| !(1..=100).contains(&p)) {
            problems.push("share_percent must be 1 to 100".into());
        }
        if let Some(team) = &self.team {
            if team.computers.is_some_and(|c| !(1..=32).contains(&c)) {
                problems.push("team.computers must be 1 to 32".into());
            }
            if team.rounds == Some(0) {
                problems.push("team.rounds must be at least 1".into());
            }
        }
        problems
    }
}

// ---- workspace pool ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Allocation {
    #[default]
    PerPerson,
    Shared,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRuntime {
    #[default]
    Container,
    Microvm,
    Vm,
}

/// Workspaces for people, allocated on a compute pool.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspacePoolSpec {
    pub compute: Reference,
    #[serde(default)]
    pub allocation: Allocation,
    #[serde(default)]
    pub runtime: WorkspaceRuntime,
    /// The image; left out or empty means the runtime's default. A VM needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Text>,
    #[serde(default = "one")]
    pub count: u32,
    /// The most workspaces one person may hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<u32>,
    #[serde(default)]
    pub resources: ResourceLimits,
    /// Workspaces get the GPU.
    #[serde(default)]
    pub gpu: bool,
    #[serde(default)]
    pub parking: bool,
    #[serde(default)]
    pub backup: bool,
    #[serde(default)]
    pub cloud_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Reference>,
    /// The drive workspaces live on, chosen on this computer when the setup is applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<BindingRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl WorkspacePoolSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = self.resources.validate("resources");
        if self.runtime == WorkspaceRuntime::Vm && self.image.as_ref().is_none_or(|i| i.as_str().trim().is_empty()) {
            problems.push("runtime: vm needs image: the VM's source".into());
        }
        if self.count == 0 || !limits::WORKSPACES.allows(self.count as usize) {
            problems.push(format!("count must be 1 to {}", limits::WORKSPACES.max));
        }
        if self.quota == Some(0) {
            problems.push("quota must be at least 1".into());
        }
        problems
    }
}

// ---- access binding ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum People {
    #[default]
    JustMe,
    Team,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Member,
    /// Approves or denies other people's requests (Access Grid).
    Approver,
    /// Reads everything and changes nothing.
    Auditor,
    /// Runs the grid's day to day: workspaces, computers and connections (Sandbox Grid).
    Operator,
}

/// The first administrator, by username; the password is the secret binding `admin_password`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub username: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Text>,
}

/// A person to add, by username; their password is the secret binding `password`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Person {
    pub username: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<Text>,
}

/// Company sign-in through an OpenID Connect issuer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sso {
    pub issuer: Text,
    pub client_id: Text,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_claim: Option<Text>,
    /// Company sign-in only: no passwords for anyone.
    #[serde(default)]
    pub passwordless: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSharing {
    #[default]
    Individual,
    Shared,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    #[default]
    View,
    Edit,
    Control,
}

/// One prepared sandbox shared with one person through the remote-access gateway: an access
/// level, a folder and an expiry. The owner's workload is untouched; revoking the share ends it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    /// The sandbox shared: an environment of this setup, or an existing one through a binding.
    pub target: Reference,
    #[serde(default)]
    pub permission: SharePermission,
    /// The folder inside the sandbox the person may see or edit; required for view and edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<Text>,
    /// Hours until the share ends, 1 to 8760; left out means no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_hours: Option<u32>,
    /// How the person reaches the gateway: a quick link or a saved domain.
    #[serde(default)]
    pub access: PublicAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Text>,
}

/// Who may use a grid and how they sign in, or one sandbox shared with one person. Membership
/// is separate from hardware and from credential authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessBindingSpec {
    /// The grid the people belong to; left out when `share` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grid: Option<Reference>,
    /// A sandbox shared with one person instead of grid membership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<Share>,
    #[serde(default)]
    pub people: People,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Role>,
    /// The first administrator; the password is the secret binding `admin_password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<Admin>,
    /// A person to add; the password is the secret binding `password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<Person>,
    /// The pool the person's workspace is ordered from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_pool: Option<Reference>,
    /// Makes this person's workspace again from scratch. Raise it to reset: everything in their
    /// workspace is deleted and it comes back empty. 0 resets nothing, and nobody else's
    /// workspace is ever touched.
    #[serde(default)]
    pub reset: u32,
    #[serde(default)]
    pub invitations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<Sso>,
    /// Require two-step sign-in for everyone.
    #[serde(default)]
    pub mfa: bool,
    /// The person is invited: their account is made with a password nobody types, and their
    /// invitation, which carries it, is a private output only the setup's owner can read. Left
    /// out when false, so a binding written before it existed plans to the same bytes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invite: bool,
    #[serde(default)]
    pub workspaces: WorkspaceSharing,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl AccessBindingSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        match (&self.grid, &self.share) {
            (Some(_), Some(_)) => problems.push("grid and share are two different things: name one of them".into()),
            (None, None) => problems.push("name the grid the people belong to (grid: {resource: ID}), or the sandbox to share (share:)".into()),
            (None, Some(share)) => {
                if self.person.is_none() {
                    problems.push("share needs person: {username: ...}, the person it is shared with".into());
                }
                if matches!(share.permission, SharePermission::View | SharePermission::Edit) && share.folder.as_ref().is_none_or(|f| f.as_str().trim().is_empty()) {
                    problems.push("share: view and edit need folder: the folder inside the sandbox".into());
                }
                if share.folder.as_ref().is_some_and(|f| !guest_path(f.as_str())) {
                    problems.push("share.folder must be an absolute path inside the sandbox".into());
                }
                if share.expires_hours.is_some_and(|h| !(1..=8760).contains(&h)) {
                    problems.push("share.expires_hours must be 1 to 8760".into());
                }
                if !matches!(share.access, PublicAccess::Quick | PublicAccess::Domain) {
                    problems.push("share.access must be quick or domain".into());
                }
                if share.access == PublicAccess::Domain && share.domain.as_ref().is_none_or(|d| d.as_str().trim().is_empty()) {
                    problems.push("share.access: domain needs share.domain: a saved domain".into());
                }
                if self.admin.is_some() || self.sso.is_some() || self.workspace_pool.is_some() || self.reset > 0 {
                    problems.push("a share takes person and secrets.password only; admin, sso, workspace_pool and reset belong to a grid".into());
                }
            }
            (Some(_), None) => {}
        }
        if self.admin.is_some() && !self.secrets.contains_key("admin_password") {
            problems.push("admin needs secrets: {admin_password: \"{{secrets.ID}}\"}".into());
        }
        if self.person.is_some() && !self.secrets.contains_key("password") && self.sso.is_none() && !self.invite {
            problems.push("person needs secrets: {password: \"{{secrets.ID}}\"}, sso, or invite: true".into());
        }
        if self.invite && self.person.is_none() {
            problems.push("invite: true invites one person: name them with person: {username: ...}".into());
        }
        if self.invitations > 10_000 {
            problems.push("invitations must be at most 10000".into());
        }
        if self.reset > 10_000 {
            problems.push("reset must be at most 10000".into());
        }
        if self.reset > 0 && self.workspace_pool.is_none() {
            problems.push("reset makes this person's own workspace again; name where it comes from with workspace_pool: {resource: ID}".into());
        }
        if self.roles.iter().collect::<BTreeSet<_>>().len() != self.roles.len() {
            problems.push("roles lists a role twice".into());
        }
        problems
    }
}

// ---- credential broker ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    #[default]
    Bearer,
    Header,
    Basic,
    Query,
    Oauth,
    GithubApp,
    Aws,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// Ask a person each time.
    #[default]
    Ask,
    /// A standing rule: allowed within the destinations, methods, paths and limits.
    Standing,
    /// Refused.
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAccess {
    Mcp,
    Api,
    Cli,
}

/// One credential the broker holds: a descriptor only. Its value is entered privately when the
/// setup is applied, or later, never in a template.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDescriptor {
    pub name: Text,
    #[serde(default)]
    pub kind: CredentialKind,
    /// The header name, query parameter or basic-auth username the credential goes into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<Text>,
    /// The name of the secret binding, under the broker's `secrets:`, that holds the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<Text>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<Text>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<Text>,
    #[serde(default)]
    pub approval: Approval,
    /// Uses per hour, with a standing rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_hour: Option<u64>,
    /// Hours until the rule lapses, up to a year.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_hours: Option<u32>,
}

/// A scoped credential service on a grid: workloads get brokered use, never the values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBrokerSpec {
    pub grid: Reference,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_days: Option<u32>,
    #[serde(default)]
    pub audit_export: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentAccess>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

impl CredentialBrokerSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !limits::CREDENTIALS.allows(self.credentials.len()) {
            problems.push(limits::CREDENTIALS.exceeded(self.credentials.len()));
        }
        let mut names = BTreeSet::new();
        for credential in &self.credentials {
            let name = credential.name.as_str();
            if name.trim().is_empty() || !names.insert(name.to_owned()) {
                problems.push(format!("credential {} needs a unique name", crate::text::shown(name)));
            }
            if credential.approval == Approval::Standing && credential.destinations.is_empty() {
                problems.push(format!("credential {name}: a standing rule needs destinations"));
            }
            if credential.per_hour == Some(0) {
                problems.push(format!("credential {name}: per_hour must be at least 1"));
            }
            if credential.per_hour.is_some() && credential.approval != Approval::Standing {
                problems.push(format!("credential {name}: per_hour works with approval: standing"));
            }
            if credential.expires_hours.is_some_and(|h| !(1..=8760).contains(&h)) {
                problems.push(format!("credential {name}: expires_hours must be 1 to 8760"));
            }
            if let Some(value) = &credential.value {
                if !self.secrets.contains_key(value) {
                    problems.push(format!("credential {name}: value names {value}, which is not under the broker's secrets:"));
                }
            }
        }
        if self.rotation_days == Some(0) {
            problems.push("rotation_days must be at least 1".into());
        }
        problems
    }
}

// ---- service publication ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAccess {
    /// A free HTTPS link that can change after a restart.
    #[default]
    Quick,
    /// A domain saved on this computer.
    Domain,
    /// The local network only.
    Lan,
    /// This computer only.
    Private,
    /// Nothing is opened.
    #[serde(rename = "none")]
    NoAccess,
}

impl PublicAccess {
    pub fn id(self) -> &'static str {
        match self {
            PublicAccess::Quick => "quick",
            PublicAccess::Domain => "domain",
            PublicAccess::Lan => "lan",
            PublicAccess::Private => "private",
            PublicAccess::NoAccess => "none",
        }
    }
    pub fn parse(text: &str) -> Option<PublicAccess> {
        [PublicAccess::Quick, PublicAccess::Domain, PublicAccess::Lan, PublicAccess::Private, PublicAccess::NoAccess].into_iter().find(|a| a.id() == text)
    }
    /// Whether the address is reachable from the internet.
    pub fn internet(self) -> bool {
        matches!(self, PublicAccess::Quick | PublicAccess::Domain)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default = "root")]
    pub path: Text,
    #[serde(default = "ok")]
    pub expected_status: u16,
}

/// A service made reachable: a sandbox port, a model endpoint or a workspace gateway.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePublicationSpec {
    pub target: Reference,
    pub port: u16,
    #[serde(default)]
    pub access: PublicAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Health>,
}

impl ServicePublicationSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.port == 0 {
            problems.push("port must be 1 to 65535".into());
        }
        if self.access == PublicAccess::Domain && self.domain.as_ref().is_none_or(|d| d.as_str().trim().is_empty()) {
            problems.push("access: domain needs domain: a saved domain".into());
        }
        if let Some(domain) = &self.domain {
            if !domain.as_str().is_empty() && !crate::format::hostname(&domain.as_str().to_ascii_lowercase()) {
                problems.push(format!("domain {} is not a domain name", crate::text::shown(domain.as_str())));
            }
        }
        if self.health.as_ref().is_some_and(|h| !h.path.as_str().starts_with('/') || !(100..=599).contains(&h.expected_status)) {
            problems.push("health needs a path starting with / and a status 100 to 599".into());
        }
        problems
    }
}

// ---- volume ----

/// Persistent data with its own retention, shared by what references it.
///
/// The `backup_*` fields give it a scheduled backup (ADR-0001 section 16). They are flat
/// scalars so the published review shows each one; all but `backup_schedule` take defaults.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_gb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<Retention>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<BindingRef>,
    /// When the volume is backed up, such as `daily 02:00` or `Mon-Fri 01:30; Sun 04:00`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_schedule: Option<Text>,
    /// The time zone the schedule is read in (`local`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_timezone: Option<Text>,
    /// How many backups are kept (7); the oldest beyond that are deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_keep: Option<u32>,
    /// `stop` (the other sandboxes that use the volume stop while it is copied) or `live`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_consistency: Option<BackupConsistency>,
    /// What happens to a backup missed while Yougori wasn't running (`run_once`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_missed: Option<BackupMissed>,
    /// What happens when a backup is due while the previous one still runs (`skip`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_overlap: Option<BackupOverlap>,
    /// How many times a failed backup is tried again (2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_retries: Option<u32>,
    /// The sandbox of this setup that mounts the volume, which Yougori reads it through and
    /// restores it through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_through: Option<Reference>,
}

pub mod schedule;

/// The most backups a volume keeps.
pub const BACKUP_KEEP: u32 = 90;
/// The most times a failed backup is tried again.
pub const BACKUP_RETRIES: u32 = 5;

/// How a backup gets a consistent copy of a volume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupConsistency {
    /// The setup's other sandboxes that mount the volume stop while it is copied, then start
    /// again: nothing writes during the copy.
    #[default]
    Stop,
    /// Copied while everything keeps running: a file being written at that moment, a database
    /// above all, can be copied half-written. The review says so.
    Live,
}

/// A backup whose time passed while Yougori wasn't running, or while the setup was busy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupMissed {
    /// Wait for the next time.
    Skip,
    /// Make one backup as soon as possible, however many were missed.
    #[default]
    RunOnce,
}

/// A backup that falls due while the previous one is still running.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupOverlap {
    #[default]
    Skip,
    /// Run once more right after the running one, never more than one waiting.
    Queue,
}

/// A volume's backup policy, every default filled in.
#[derive(Clone, Debug, PartialEq)]
pub struct Backup {
    pub schedule: schedule::Times,
    pub timezone: schedule::Zone,
    pub keep: u32,
    pub consistency: BackupConsistency,
    pub missed: BackupMissed,
    pub overlap: BackupOverlap,
    pub retries: u32,
    /// The resource id of the sandbox the volume is read and restored through.
    pub through: String,
}

impl VolumeSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.size_gb.is_some_and(|v| !v.is_finite() || v <= 0.0 || v > 16380.0) {
            problems.push("size_gb must be between 0 and 16380".into());
        }
        problems.extend(self.backup_problems());
        problems
    }

    fn backup_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let others = [
            ("backup_timezone", self.backup_timezone.is_some()),
            ("backup_keep", self.backup_keep.is_some()),
            ("backup_consistency", self.backup_consistency.is_some()),
            ("backup_missed", self.backup_missed.is_some()),
            ("backup_overlap", self.backup_overlap.is_some()),
            ("backup_retries", self.backup_retries.is_some()),
            ("backup_through", self.backup_through.is_some()),
        ];
        let Some(schedule) = &self.backup_schedule else {
            let set = others.iter().filter(|(_, set)| *set).map(|(name, _)| *name).collect::<Vec<_>>();
            if !set.is_empty() {
                problems.push(format!("{} work with backup_schedule: add backup_schedule, or leave them out", set.join(", ")));
            }
            return problems;
        };
        if let Err(error) = schedule.as_str().parse::<schedule::Times>() {
            problems.push(format!("backup_schedule: {error}"));
        }
        if let Some(zone) = &self.backup_timezone {
            if let Err(error) = zone.as_str().parse::<schedule::Zone>() {
                problems.push(format!("backup_timezone: {error}"));
            }
        }
        if self.backup_keep.is_some_and(|keep| !(1..=BACKUP_KEEP).contains(&keep)) {
            problems.push(format!("backup_keep must be 1 to {BACKUP_KEEP}"));
        }
        if self.backup_retries.is_some_and(|retries| retries > BACKUP_RETRIES) {
            problems.push(format!("backup_retries must be 0 to {BACKUP_RETRIES}"));
        }
        match &self.backup_through {
            None => problems.push("backup_schedule needs backup_through: {resource: ID}, the sandbox of this setup that mounts the volume and that Yougori reads and restores it through".into()),
            Some(through) if through.binding.is_some() => problems.push("backup_through must name a sandbox of this setup with {resource: ID}; a sandbox of another setup can't be used".into()),
            Some(through) if through.output.is_some() => problems.push("backup_through names a sandbox, not one of its outputs".into()),
            Some(_) => {}
        }
        problems
    }

    /// The backup policy with its defaults, when the volume has a schedule that reads.
    pub fn backup(&self) -> Option<Backup> {
        if !self.backup_problems().is_empty() {
            return None;
        }
        let schedule = self.backup_schedule.as_ref()?.as_str().parse().ok()?;
        let timezone = match &self.backup_timezone {
            Some(zone) => zone.as_str().parse().ok()?,
            None => schedule::Zone::Local,
        };
        Some(Backup {
            schedule,
            timezone,
            keep: self.backup_keep.unwrap_or(7),
            consistency: self.backup_consistency.unwrap_or_default(),
            missed: self.backup_missed.unwrap_or_default(),
            overlap: self.backup_overlap.unwrap_or_default(),
            retries: self.backup_retries.unwrap_or(2),
            through: self.backup_through.as_ref()?.resource.clone()?,
        })
    }
}

// ---- connection ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[default]
    OneWay,
    TwoWay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPermission {
    Network,
    Ports,
    Files,
    Volumes,
    Data,
    Secrets,
}

impl ConnectionPermission {
    pub fn parse(text: &str) -> Option<ConnectionPermission> {
        Some(match text {
            "network" => ConnectionPermission::Network,
            "ports" => ConnectionPermission::Ports,
            "files" => ConnectionPermission::Files,
            "volumes" => ConnectionPermission::Volumes,
            "data" => ConnectionPermission::Data,
            "secrets" => ConnectionPermission::Secrets,
            _ => return None,
        })
    }
}

/// Connectivity, declared on its own: needing a resource ready never grants network access to it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSpec {
    pub from: Reference,
    pub to: Reference,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<ConnectionPermission>,
    #[serde(default)]
    pub direction: Direction,
    /// The connection attaches a model to the package's models environment: when it is ready, the
    /// engine runs the `yougori-models.yaml` command in `from` with an attach request, and with a
    /// detach request when it is removed. The model's key goes only into that request file.
    #[serde(default)]
    pub model_request: bool,
    /// Filled by the planner from yougori-models.yaml, retained in the reviewed specification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_command: Vec<String>,
}

impl ConnectionSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.from == self.to {
            problems.push("a connection joins two different resources".into());
        }
        if self.ports.contains(&0) {
            problems.push("ports must be 1 to 65535".into());
        }
        if !self.model_command.is_empty() && (!self.model_request || self.model_command.len() > 16 || self.model_command.iter().any(|part| part.is_empty() || part.chars().count() > 512 || !crate::text::one_line(part))) {
            problems.push("model_command is the reviewed model receiver's program and up to 15 arguments".into());
        }
        problems
    }
}

// ---- job ----

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retry {
    #[serde(default = "one")]
    pub attempts: u32,
    #[serde(default)]
    pub backoff_seconds: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reconcile {
    #[default]
    #[serde(rename = "none")]
    NoReconcile,
    /// A person reconciles an unknown outcome before the job runs again.
    Manual,
}

/// A finite piece of work with declared inputs, outputs, timeout and retries. Execution is at
/// least once where a retry can happen; a job that repeats external actions must say it is
/// idempotent or be reconciled by hand.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// Where its attempts run: a pool of a grid's computers, or a sandbox of this setup whose
    /// image and room each attempt's own sandbox is made from. Without one, a job runs on this
    /// computer from its own `image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<Reference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Text>,
    pub command: Vec<Text>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Reference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Reference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<BindingRef>,
    /// The folder of this computer the person chose for `source`, filled in by the planner. A
    /// template never writes it: the format refuses it, so no template can name a folder here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_folder: Option<String>,
    #[serde(default = "hour")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub resources: ResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<Retry>,
    #[serde(default)]
    pub checkpoint: bool,
    #[serde(default)]
    pub idempotent: bool,
    #[serde(default)]
    pub reconcile: Reconcile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Text>,
    /// What runs it again after it was first sent: a call to its own address, or a change in the
    /// folder it reads (`run.events`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
}

/// What runs a job again. Each event is one run of the job, never two at once, and never sooner
/// than ten seconds after the last.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// A call to the job's own address (`POST`), with a secret part only the setup's owner sees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook>,
    /// A file added, changed or removed in the folder the job reads (`source`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_changes: bool,
    /// The most runs events may start in a day (`run.quotas`). Unsaid, no daily limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_day: Option<u32>,
}

/// Who can reach a job's event address: this computer (`private`), this local network (`lan`), or
/// anyone with the link (`quick`, a free HTTPS link).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    #[serde(default = "private_access")]
    pub access: PublicAccess,
}

fn private_access() -> PublicAccess {
    PublicAccess::Private
}

impl JobSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = self.resources.validate("resources");
        if self.command.is_empty() || !limits::COMMAND_PARTS.allows(self.command.len()) || self.command.iter().any(|part| part.as_str().is_empty()) {
            problems.push(format!("command is the program and its arguments: 1 to {} parts", limits::COMMAND_PARTS.max));
        }
        if self.timeout_seconds == 0 || !limits::JOB_SECONDS.allows(self.timeout_seconds as usize) {
            problems.push(format!("timeout_seconds must be 1 to {}", limits::JOB_SECONDS.max));
        }
        if let Some(trigger) = &self.trigger {
            if trigger.webhook.is_none() && !trigger.source_changes {
                problems.push("trigger needs webhook: or source_changes: true".into());
            }
            if trigger.webhook.as_ref().is_some_and(|hook| !matches!(hook.access, PublicAccess::Private | PublicAccess::Lan | PublicAccess::Quick)) {
                problems.push("trigger.webhook.access is private, lan or quick".into());
            }
            if trigger.source_changes && self.source.is_none() {
                problems.push("trigger.source_changes watches the folder the job reads; give the job a source: {binding: ID}".into());
            }
        }
        if let Some(retry) = &self.retry {
            if retry.attempts == 0 || !limits::RETRIES.allows(retry.attempts as usize) {
                problems.push(format!("retry.attempts must be 1 to {}", limits::RETRIES.max));
            }
            if retry.attempts > 1 && !self.idempotent && self.reconcile != Reconcile::Manual {
                problems.push("a job that may run again must say idempotent: true, or reconcile: manual so a person checks an unknown outcome first".into());
            }
        }
        problems
    }
}

// ---- artifact store ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreAccess {
    #[default]
    Setup,
    Grid,
}

/// Bounded, checksummed storage for what jobs produce.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStoreSpec {
    #[serde(default = "ten")]
    pub max_gb: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
    #[serde(default)]
    pub access: StoreAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<BindingRef>,
}

impl ArtifactStoreSpec {
    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.max_gb.is_finite() || self.max_gb <= 0.0 || self.max_gb > 16380.0 {
            problems.push("max_gb must be between 0 and 16380".into());
        }
        problems
    }
}

// ---- VM sandbox ----

/// The least host memory a launch reserves (`sandbox_vm`): the guest's own 256 MiB and room for
/// the hypervisor's, 320 MiB in all.
pub const VM_GUEST_MEMORY_GB: f64 = 0.3125;
/// The most host memory one VM sandbox may reserve.
pub const VM_MOST_MEMORY_GB: f64 = 64.0;
/// The most routes one VM sandbox may declare: the guest's endpoint table holds 32.
pub const VM_MOST_ROUTES: usize = 32;
/// The longest a task VM sandbox may go without a command, and live at all, in minutes: the
/// engine's task lease defaults (12 and 24 hours), which a template may only lower.
pub const VM_LONGEST_IDLE_MINUTES: u64 = 12 * 60;
pub const VM_LONGEST_LIFETIME_MINUTES: u64 = 24 * 60;
/// The most a staged workspace copy holds, the sandbox's own writes included, in GiB: the
/// engine's bound (`sandbox_vm` workspace `MAX_TOTAL_BYTES`); a larger folder is refused.
pub const VM_WORKSPACE_MOST_GB: f64 = 1.0;

fn vm_memory() -> f64 {
    1.0
}

fn https() -> u16 {
    443
}

/// What one operation of a route does: only reads, or changes something outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteEffect {
    ReadOnly,
    External,
}

impl RouteEffect {
    pub fn id(self) -> &'static str {
        match self {
            RouteEffect::ReadOnly => "read_only",
            RouteEffect::External => "external",
        }
    }
}

/// One request a route allows: a method on a path template, with the query keys it may carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOperation {
    /// The operation's name (an identifier), as the review and the relay's records say it.
    pub name: Text,
    /// `GET`, `POST`, `PUT`, `PATCH` or `DELETE`, in either case (a template's choice values
    /// are lowercase).
    pub method: Text,
    /// The path, such as `/v1/messages`.
    pub path: Text,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_keys: Vec<Text>,
    /// What it does; when left out, a GET only reads and every other method changes something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<RouteEffect>,
}

impl RouteOperation {
    /// Its method as HTTP writes it.
    pub fn method(&self) -> String {
        self.method.as_str().to_ascii_uppercase()
    }

    /// Its effect as declared, or as its method implies.
    pub fn effect(&self) -> RouteEffect {
        self.effect.unwrap_or(if self.method() == "GET" { RouteEffect::ReadOnly } else { RouteEffect::External })
    }
}

/// How a route's requests carry their credential.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialHeader {
    #[default]
    Authorization,
    ProxyAuthorization,
    Cookie,
}

/// The credential a route carries: one enrolled on this computer with `yougori sandbox
/// credential enroll`, named here, added by the relay on the way out and never seen by the
/// guest. A template names a credential; it never holds one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCredential {
    /// The name it was enrolled under.
    pub name: Text,
    /// The provider the operations belong to (an identifier); the route's name when left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Text>,
    #[serde(default)]
    pub header: CredentialHeader,
}

/// One service a VM sandbox may reach, through the engine's relay: in the guest `name` resolves
/// to a loopback address the guest agent serves; everything else stays unreachable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmRoute {
    /// The route's id and the endpoint name in the guest (an identifier starting with a letter).
    pub name: Text,
    /// The exact host name it reaches, over TLS.
    pub host: Text,
    #[serde(default = "https")]
    pub port: u16,
    pub operations: Vec<RouteOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<RouteCredential>,
}

/// A guest service a VM sandbox may serve on this computer: its name and the guest port its
/// listener is on. Declared here, it is reachable only once someone publishes it (`yougori
/// sandbox publish`), to its owner with the address the publication gives or, chosen, to anyone
/// on this computer; nothing else is ever published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmPublish {
    /// The service's name (an identifier starting with a letter).
    pub service: Text,
    /// The guest port its listener is on.
    pub port: u16,
    /// The other VM sandboxes of this setup that may connect to it, by resource id: this
    /// sandbox's end of each connection grant, whose other end is their `connect` entry. A
    /// connection needs both. None when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<Text>,
}

/// The most guest services one VM sandbox may declare.
pub const VM_MOST_PUBLISHED: usize = 8;

/// A connection this VM sandbox's programs may make to a service another VM sandbox of the setup
/// declared (M14): the name they reach it by, `NAME:PORT` (one host name label; any TCP
/// protocol), and the grant's terms. It is this sandbox's end of the grant: the other sandbox's
/// `publish` entry must `accept` it, its own end. Nothing else of the other sandbox is reachable,
/// and nothing of this one from there.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmConnect {
    /// The name its programs reach the service by: one host name label.
    pub name: Text,
    /// The other VM sandbox of this setup, by resource id. Not a dependency: the grant is made
    /// once both are up, by whichever comes up second.
    pub to: Text,
    /// The service the other sandbox's `publish` declares.
    pub service: Text,
    /// The port its programs connect to; the service's own port when left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// How long the grant lasts after each start, in whole minutes: 60 when left out, at most
    /// 1440. Starting the setup again grants it anew.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minutes: Option<f64>,
    /// What one connection may carry each way, in bytes: 8 MiB when left out, at most 1 GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_bytes: Option<u64>,
}

/// The most connections one VM sandbox may declare (its guest's endpoints).
pub const VM_MOST_CONNECTIONS: usize = 8;
/// A connection grant's lifetime when the template gives none, and the longest, in minutes.
pub const VM_CONNECTION_MINUTES: u64 = 60;
pub const VM_LONGEST_CONNECTION_MINUTES: u64 = 1440;
/// What one connection carries each way when the template gives no budget, and the most.
pub const VM_CONNECTION_BUDGET_BYTES: u64 = 8 << 20;
pub const VM_MOST_CONNECTION_BUDGET_BYTES: u64 = 1 << 30;

impl VmConnect {
    /// The grant's lifetime in whole minutes.
    pub fn grant_minutes(&self) -> u64 {
        self.minutes.map_or(VM_CONNECTION_MINUTES, |minutes| minutes as u64)
    }

    /// What one connection carries each way.
    pub fn budget(&self) -> u64 {
        self.budget_bytes.unwrap_or(VM_CONNECTION_BUDGET_BYTES)
    }

    /// The sandbox it reaches, by resource id.
    pub fn target(&self) -> Option<&str> {
        Some(self.to.as_str()).filter(|id| !id.is_empty())
    }
}

/// A connection endpoint's name: one host name label, as the guest resolves it.
fn host_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A remote restricted VM on an already connected and explicitly trusted SSH host.
/// The template names no credential, copies no key, and cannot enroll host trust.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmRemote {
    pub connection: Text,
    pub parent: Reference,
    pub program: Text,
    pub endpoint: Text,
    pub engine_sha256: Text,
}

/// A restricted VM on this computer, launched through the engine's VM sandbox: the pinned minimal
/// guest under the restricted hypervisor profile, with no network but the routes declared here
/// and no files of this computer but a staged copy of the folder chosen for `workspace`. It is a
/// task sandbox: it stops after its idle limit and its lifetime, and starting the setup again
/// launches a fresh one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSandboxSpec {
    /// Direct GPU access through a compatible native VM backend.
    #[serde(default, skip_serializing_if = "vm_no_internet")]
    pub gpu: bool,
    #[serde(default = "vm_cpu", skip_serializing_if = "vm_cpu_default")]
    pub cpu: u16,
    #[serde(default, skip_serializing_if = "vm_no_internet")]
    pub internet: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<VmApplication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<VmRemote>,
    /// An OCI manifest already imported by this computer's owner. Empty or minimal uses the
    /// pinned minimal guest. A template cannot authorize an image import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Text>,
    /// The host memory its launch reserves, in GB: at least the guest's own 256 MiB.
    #[serde(default = "vm_memory")]
    pub memory_gb: f64,
    /// How long it may go without a command, in whole minutes, below the 12-hour default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_minutes: Option<f64>,
    /// How long it may live at all, in whole minutes, below the 24-hour default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_minutes: Option<f64>,
    /// What it may reach; nothing when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<VmRoute>,
    /// A folder binding of mode staged: the sandbox works on a copy, and the folder changes
    /// only through a reviewed promotion of approved files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<BindingRef>,
    /// The folder the person chose for `workspace`, filled in by the planner. A template never
    /// writes it: the format refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_folder: Option<String>,
    /// The guest services it may serve on this computer once published, and to the VM sandboxes
    /// of this setup each accepts; none when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub publish: Vec<VmPublish>,
    /// The services of other VM sandboxes of this setup its programs may reach (M14); none when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connect: Vec<VmConnect>,
}

fn vm_cpu() -> u16 { 1 }
fn vm_cpu_default(cpu: &u16) -> bool { *cpu == 1 }
fn vm_no_internet(internet: &bool) -> bool { !internet }

/// An application declared in VM source code. Values are public answers; secrets are
/// vault binding names. Only the VM handler resolves them, after the plan is approved.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmApplication {
    pub source: Text,
    pub image: Text,
    pub command: Vec<Text>,
    #[serde(default)] pub values: BTreeMap<String, Text>,
    #[serde(default)] pub secrets: BTreeMap<String, String>,
    #[serde(default)] pub grids: BTreeMap<String, Text>,
}

/// An HTTP method a route operation may use.
pub const ROUTE_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// A route or operation name: what the relay and the guest's endpoint table accept.
fn route_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.starts_with(|c: char| c.is_ascii_alphabetic()) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A host name of labels of letters, digits and dashes: no scheme, port, path or address.
fn route_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && !host.chars().all(|c| c.is_ascii_digit() || c == '.')
}

impl VmSandboxSpec {
    pub fn image_id(&self) -> Option<&str> {
        self.image.as_ref().map(Text::as_str).filter(|s| !s.is_empty() && *s != "minimal")
    }

    fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.gpu && self.memory_gb < 4.0 { problems.push("GPU VMs require at least 4 GB RAM".into()); }
        if self.gpu && self.remote.is_some() { problems.push("Direct GPU acceleration is currently supported only for local VM resources".into()); }
        if self.cpu == 0 || self.cpu > 255 { problems.push("cpu must be between 1 and 255".into()); }
        if self.internet && !self.routes.is_empty() { problems.push("Choose full internet or declared routes, not both".into()); }
        if let Some(app) = &self.application {
            if self.workspace.is_some() || self.workspace_folder.is_some() || self.remote.is_some() || self.image_id().is_some() {
                problems.push("An application carries its own code and image; workspace, remote and image cannot be added separately".into());
            }
            if !crate::author::relative_file(app.source.as_str()) { problems.push("application.source must be a relative package directory".into()); }
            if app.image.as_str().is_empty() || app.image.as_str().len() > 512 || app.image.as_str().contains("://") || app.image.as_str().chars().any(char::is_whitespace) {
                problems.push("application.image must be a registry image without credentials".into());
            }
            if app.command.is_empty() || app.command.len() > 64 || app.command.iter().any(|arg| arg.as_str().is_empty() || arg.as_str().len() > 4096 || arg.as_str().contains('\0')) {
                problems.push("application.command must be a bounded argv to run inside the VM".into());
            }
            if app.grids.iter().any(|(kind, enabled)| !matches!(kind.as_str(), "gpu" | "sandbox") || !matches!(enabled.as_str(), "yes" | "no" | "true" | "false" | "")) {
                problems.push("application.grids accepts gpu and sandbox, enabled by a yes/no answer".into());
            }
        }
        if let Some(remote) = &self.remote {
            let bounded = |value: &str, max: usize| !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control);
            if !bounded(remote.connection.as_str(), 256) {
                problems.push("remote.connection must name an owned SSH connection on this installation".into());
            }
            if remote.parent.local().is_none() || remote.parent.binding.is_some() || remote.parent.output.is_some() {
                problems.push("remote.parent must reference a local VM sandbox of this setup".into());
            }
            if !bounded(remote.program.as_str(), 4096) || !remote.program.as_str().starts_with('/') {
                problems.push("remote.program must be the absolute path of the remote engine".into());
            }
            if !bounded(remote.endpoint.as_str(), 1024) {
                problems.push("remote.endpoint must name the remote engine endpoint".into());
            }
            let digest = remote.engine_sha256.as_str();
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                problems.push("remote.engine_sha256 must be 64 lowercase hexadecimal digits".into());
            }
            if self.image_id().is_some() || self.workspace.is_some() || self.workspace_folder.is_some()
                || !self.routes.is_empty() || !self.publish.is_empty() || !self.connect.is_empty() || self.idle_minutes.is_some() {
                problems.push("remote VM sandboxes currently use the minimal guest and a lifetime: image, workspace, routes, publish, connect and idle_minutes are not supported remotely".into());
            }
        }
        if let Some(image) = self.image_id() {
            if !image.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
                problems.push("image must be a locally imported OCI manifest digest: sha256: followed by 64 lowercase hex digits".into());
            }
        }
        if !self.memory_gb.is_finite() || !(VM_GUEST_MEMORY_GB..=VM_MOST_MEMORY_GB).contains(&self.memory_gb) {
            problems.push(format!("memory_gb must be between {VM_GUEST_MEMORY_GB} (the guest's own memory and the hypervisor's) and {VM_MOST_MEMORY_GB}"));
        }
        let whole = |minutes: f64, longest: u64| minutes.is_finite() && minutes.fract() == 0.0 && (0.0..=longest as f64).contains(&minutes);
        if self.idle_minutes.is_some_and(|minutes| !whole(minutes, VM_LONGEST_IDLE_MINUTES)) {
            problems.push(format!("idle_minutes must be a whole number of minutes from 0 (no idle expiry) to {VM_LONGEST_IDLE_MINUTES}"));
        }
        if self.lifetime_minutes.is_some_and(|minutes| !whole(minutes, VM_LONGEST_LIFETIME_MINUTES)) {
            problems.push(format!("lifetime_minutes must be a whole number of minutes from 0 (until stopped) to {VM_LONGEST_LIFETIME_MINUTES}"));
        }
        if self.routes.len() > VM_MOST_ROUTES {
            problems.push(format!("at most {VM_MOST_ROUTES} routes per VM sandbox"));
        }
        if self.publish.len() > VM_MOST_PUBLISHED {
            problems.push(format!("at most {VM_MOST_PUBLISHED} services may be published"));
        }
        let mut services = BTreeSet::new();
        let mut ports = BTreeSet::new();
        for published in &self.publish {
            let service = published.service.as_str();
            if !route_name(service) {
                problems.push(format!("publish: {} must be 1 to 128 letters, digits, '.', '_' or '-', starting with a letter", crate::text::shown(service)));
            } else if !services.insert(service.to_owned()) {
                problems.push(format!("publish: {service} is declared twice"));
            }
            if published.port == 0 {
                problems.push(format!("publish: {service}: port must be between 1 and 65535"));
            } else if !ports.insert(published.port) {
                problems.push(format!("publish: guest port {} is declared twice", published.port));
            }
            let mut accepted = BTreeSet::new();
            for caller in &published.accept {
                if !identifier(caller.as_str()) {
                    problems.push(format!("publish: {service}: accept: {} must be a resource id", crate::text::shown(caller.as_str())));
                } else if !accepted.insert(caller.as_str()) {
                    problems.push(format!("publish: {service}: accept: {} is named twice", caller.as_str()));
                }
            }
        }
        if self.connect.len() > VM_MOST_CONNECTIONS {
            problems.push(format!("at most {VM_MOST_CONNECTIONS} connections per VM sandbox"));
        }
        let mut endpoints = BTreeSet::new();
        for connection in &self.connect {
            let name = connection.name.as_str();
            if !host_label(name) {
                problems.push(format!("connect: {} must be one host name label: 1 to 63 letters, digits or '-', starting with a letter", crate::text::shown(name)));
            } else if !endpoints.insert(name.to_ascii_lowercase()) {
                problems.push(format!("connect: {name} is declared twice"));
            } else if self.routes.iter().any(|route| route.name.as_str().eq_ignore_ascii_case(name)) {
                problems.push(format!("connect: {name} is also a route's name"));
            }
            if !route_name(connection.service.as_str()) {
                problems.push(format!("connect: {name}: service {} must be a service name the other sandbox publishes", crate::text::shown(connection.service.as_str())));
            }
            if connection.port == Some(0) {
                problems.push(format!("connect: {name}: port must be between 1 and 65535"));
            } else if let Some(port) = connection.port.filter(|port| self.publish.iter().any(|published| published.port == *port)) {
                problems.push(format!("connect: {name}: port {port} is a service of this same sandbox; give the connection another port"));
            }
            if connection.minutes.is_some_and(|minutes| minutes < 1.0 || !whole(minutes, VM_LONGEST_CONNECTION_MINUTES)) {
                problems.push(format!("connect: {name}: minutes must be a whole number of minutes between 1 and {VM_LONGEST_CONNECTION_MINUTES}"));
            }
            if connection.budget_bytes.is_some_and(|bytes| bytes == 0 || bytes > VM_MOST_CONNECTION_BUDGET_BYTES) {
                problems.push(format!("connect: {name}: budget_bytes must be between 1 and {VM_MOST_CONNECTION_BUDGET_BYTES}"));
            }
            if !identifier(connection.to.as_str()) {
                problems.push(format!("connect: {name}: to {} must name a VM sandbox of this setup by its resource id", crate::text::shown(connection.to.as_str())));
            }
        }
        let mut names = BTreeSet::new();
        for route in &self.routes {
            let name = route.name.as_str();
            if !route_name(name) {
                problems.push(format!("routes: {} must be 1 to 128 letters, digits, '.', '_' or '-', starting with a letter", crate::text::shown(name)));
            } else if !names.insert(name.to_owned()) {
                problems.push(format!("routes: {name} is declared twice"));
            }
            if !route_host(route.host.as_str()) {
                problems.push(format!("routes: {name}: host {} must be a host name, such as api.example.com, without a scheme, port or path", crate::text::shown(route.host.as_str())));
            }
            if route.port == 0 {
                problems.push(format!("routes: {name}: port must be between 1 and 65535"));
            }
            if route.operations.is_empty() {
                problems.push(format!("routes: {name}: declare at least one operation: a method and a path it may use"));
            }
            let mut operations = BTreeSet::new();
            for operation in &route.operations {
                let label = operation.name.as_str();
                if !route_name(label) || !operations.insert(label.to_owned()) {
                    problems.push(format!("routes: {name}: each operation needs its own name of letters, digits, '.', '_' or '-' ({} is not one)", crate::text::shown(label)));
                }
                if !ROUTE_METHODS.contains(&operation.method().as_str()) {
                    problems.push(format!("routes: {name}: {label}: method must be one of {}", ROUTE_METHODS.join(", ")));
                }
                let path = operation.path.as_str();
                if !path.starts_with('/') || path.len() > 1024 || path.chars().any(|c| c.is_whitespace() || c.is_control() || c == '?' || c == '#') || path.split('/').any(|part| part == "..") {
                    problems.push(format!("routes: {name}: {label}: path {} must start with / and hold no spaces, query or fragment", crate::text::shown(path)));
                }
                if operation.query_keys.iter().any(|key| key.as_str().is_empty() || key.as_str().len() > 128 || key.as_str().chars().any(|c| c.is_whitespace() || c.is_control() || c == '&' || c == '=')) {
                    problems.push(format!("routes: {name}: {label}: query_keys are plain key names"));
                }
            }
            if let Some(credential) = &route.credential {
                if !identifier(credential.name.as_str()) {
                    problems.push(format!("routes: {name}: credential name {} must be the name it was enrolled under: letters, digits, dots, dashes or underscores", crate::text::shown(credential.name.as_str())));
                }
                if credential.provider.as_ref().is_some_and(|provider| !route_name(provider.as_str())) {
                    problems.push(format!("routes: {name}: credential provider must be a name of letters, digits, '.', '_' or '-'"));
                }
            }
        }
        problems
    }

    /// The memory its launch reserves, as the engine reads it.
    pub fn memory_bytes(&self) -> u64 {
        (self.memory_gb * (1u64 << 30) as f64) as u64
    }

    /// Its idle limit in whole minutes, when it lowers the default.
    pub fn idle(&self) -> Option<u64> {
        self.idle_minutes.map(|minutes| minutes as u64)
    }

    /// Its lifetime in whole minutes, when it lowers the default.
    pub fn lifetime(&self) -> Option<u64> {
        self.lifetime_minutes.map(|minutes| minutes as u64)
    }
}

// ---- every kind ----

/// A resource's spec in its kind's type.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Spec {
    Environment(Box<EnvironmentSpec>),
    Grid(GridSpec),
    ComputePool(ComputePoolSpec),
    WorkerGroup(WorkerGroupSpec),
    ModelService(ModelServiceSpec),
    WorkspacePool(WorkspacePoolSpec),
    AccessBinding(AccessBindingSpec),
    CredentialBroker(CredentialBrokerSpec),
    ServicePublication(ServicePublicationSpec),
    Volume(VolumeSpec),
    Connection(ConnectionSpec),
    Job(JobSpec),
    ArtifactStore(ArtifactStoreSpec),
    VmSandbox(VmSandboxSpec),
}

fn kind_error(kind: Kind, error: impl std::fmt::Display) -> String {
    format!("{} spec: {error}", kind.as_str())
}

/// Reads a spec in its kind's type from a YAML value.
pub fn parse_spec(kind: Kind, value: &Yaml) -> Result<Spec, String> {
    let value = if value.is_null() { Yaml::Mapping(Default::default()) } else { value.clone() };
    let read = |e: serde_yaml_ng::Error| kind_error(kind, e);
    Ok(match kind {
        Kind::Environment => Spec::Environment(Box::new(serde_yaml_ng::from_value(value).map_err(read)?)),
        Kind::Grid => Spec::Grid(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::ComputePool => Spec::ComputePool(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::WorkerGroup => Spec::WorkerGroup(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::ModelService => Spec::ModelService(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::WorkspacePool => Spec::WorkspacePool(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::AccessBinding => Spec::AccessBinding(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::CredentialBroker => Spec::CredentialBroker(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::ServicePublication => Spec::ServicePublication(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::Volume => Spec::Volume(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::Connection => Spec::Connection(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::Job => Spec::Job(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::ArtifactStore => Spec::ArtifactStore(serde_yaml_ng::from_value(value).map_err(read)?),
        Kind::VmSandbox => Spec::VmSandbox(serde_yaml_ng::from_value(value).map_err(read)?),
    })
}

/// Reads a spec in its kind's type from JSON, as a plan stores it.
pub fn parse_json(kind: Kind, value: &Json) -> Result<Spec, String> {
    let value = if value.is_null() { Json::Object(Default::default()) } else { value.clone() };
    let read = |e: serde_json::Error| kind_error(kind, e);
    Ok(match kind {
        Kind::Environment => Spec::Environment(Box::new(serde_json::from_value(value).map_err(read)?)),
        Kind::Grid => Spec::Grid(serde_json::from_value(value).map_err(read)?),
        Kind::ComputePool => Spec::ComputePool(serde_json::from_value(value).map_err(read)?),
        Kind::WorkerGroup => Spec::WorkerGroup(serde_json::from_value(value).map_err(read)?),
        Kind::ModelService => Spec::ModelService(serde_json::from_value(value).map_err(read)?),
        Kind::WorkspacePool => Spec::WorkspacePool(serde_json::from_value(value).map_err(read)?),
        Kind::AccessBinding => Spec::AccessBinding(serde_json::from_value(value).map_err(read)?),
        Kind::CredentialBroker => Spec::CredentialBroker(serde_json::from_value(value).map_err(read)?),
        Kind::ServicePublication => Spec::ServicePublication(serde_json::from_value(value).map_err(read)?),
        Kind::Volume => Spec::Volume(serde_json::from_value(value).map_err(read)?),
        Kind::Connection => Spec::Connection(serde_json::from_value(value).map_err(read)?),
        Kind::Job => Spec::Job(serde_json::from_value(value).map_err(read)?),
        Kind::ArtifactStore => Spec::ArtifactStore(serde_json::from_value(value).map_err(read)?),
        Kind::VmSandbox => Spec::VmSandbox(serde_json::from_value(value).map_err(read)?),
    })
}

impl Spec {
    pub fn kind(&self) -> Kind {
        match self {
            Spec::Environment(_) => Kind::Environment,
            Spec::Grid(_) => Kind::Grid,
            Spec::ComputePool(_) => Kind::ComputePool,
            Spec::WorkerGroup(_) => Kind::WorkerGroup,
            Spec::ModelService(_) => Kind::ModelService,
            Spec::WorkspacePool(_) => Kind::WorkspacePool,
            Spec::AccessBinding(_) => Kind::AccessBinding,
            Spec::CredentialBroker(_) => Kind::CredentialBroker,
            Spec::ServicePublication(_) => Kind::ServicePublication,
            Spec::Volume(_) => Kind::Volume,
            Spec::Connection(_) => Kind::Connection,
            Spec::Job(_) => Kind::Job,
            Spec::ArtifactStore(_) => Kind::ArtifactStore,
            Spec::VmSandbox(_) => Kind::VmSandbox,
        }
    }

    /// What is wrong with the values, beyond their types. Each problem is one plain sentence.
    pub fn validate(&self) -> Vec<String> {
        let mut problems: Vec<String> = self.references().into_iter().filter_map(|(field, reference, _)| reference.problem().map(|p| format!("{field}: {p}"))).collect();
        problems.extend(self.validate_values());
        problems
    }

    fn validate_values(&self) -> Vec<String> {
        match self {
            Spec::Environment(spec) => spec.validate(),
            Spec::Grid(spec) => spec.validate(),
            Spec::ComputePool(spec) => spec.validate(),
            Spec::WorkerGroup(spec) => spec.validate(),
            Spec::ModelService(spec) => spec.validate(),
            Spec::WorkspacePool(spec) => spec.validate(),
            Spec::AccessBinding(spec) => spec.validate(),
            Spec::CredentialBroker(spec) => spec.validate(),
            Spec::ServicePublication(spec) => spec.validate(),
            Spec::Volume(spec) => spec.validate(),
            Spec::Connection(spec) => spec.validate(),
            Spec::Job(spec) => spec.validate(),
            Spec::ArtifactStore(spec) => spec.validate(),
            Spec::VmSandbox(spec) => spec.validate(),
        }
    }

    /// Every reference the spec makes: the field, the reference and the kinds it may name.
    pub fn references(&self) -> Vec<(String, &Reference, &'static [Kind])> {
        const GRID: &[Kind] = &[Kind::Grid];
        const POOL: &[Kind] = &[Kind::ComputePool];
        const RUNS_ON: &[Kind] = &[Kind::ComputePool, Kind::Environment];
        const MODEL: &[Kind] = &[Kind::ModelService];
        const SANDBOX: &[Kind] = &[Kind::Environment];
        const DATA: &[Kind] = &[Kind::Volume];
        /// What a job may read: a store or a volume it was given, or the result of a stage before
        /// it. A job reference is how a pipeline is written down, and it is what puts the stages
        /// in order, because every reference here is also a dependency.
        const READS: &[Kind] = &[Kind::ArtifactStore, Kind::Volume, Kind::Job];
        const STORE: &[Kind] = &[Kind::ArtifactStore];
        const SERVICE: &[Kind] = &[Kind::Environment, Kind::ModelService, Kind::WorkspacePool];
        const ANY: &[Kind] = &Kind::ALL;
        let mut found: Vec<(String, &Reference, &'static [Kind])> = Vec::new();
        match self {
            Spec::Environment(_) | Spec::ArtifactStore(_) => {}
            Spec::VmSandbox(spec) => {
                if let Some(remote) = &spec.remote {
                    found.push(("remote.parent".into(), &remote.parent, &[Kind::VmSandbox]));
                }
            }
            Spec::Volume(spec) => {
                if let Some(through) = &spec.backup_through {
                    found.push(("backup_through".into(), through, SANDBOX));
                }
            }
            Spec::Grid(_) => {}
            Spec::ComputePool(spec) => found.push(("grid".into(), &spec.grid, GRID)),
            Spec::WorkerGroup(spec) => {
                found.push(("pool".into(), &spec.pool, POOL));
                if let Some(model) = &spec.model {
                    found.push(("model".into(), model, MODEL));
                }
                if let Some(environment) = &spec.environment {
                    found.push(("environment".into(), environment, SANDBOX));
                }
            }
            Spec::ModelService(spec) => {
                if let Some(compute) = &spec.compute {
                    found.push(("compute".into(), compute, RUNS_ON));
                }
                if let Some(team) = &spec.team {
                    found.push(("team.lead".into(), &team.lead, MODEL));
                    for (index, worker) in team.workers.iter().enumerate() {
                        found.push((format!("team.workers[{index}]"), worker, MODEL));
                    }
                }
            }
            Spec::WorkspacePool(spec) => {
                found.push(("compute".into(), &spec.compute, POOL));
                if let Some(data) = &spec.data {
                    found.push(("data".into(), data, DATA));
                }
            }
            Spec::AccessBinding(spec) => {
                if let Some(grid) = &spec.grid {
                    found.push(("grid".into(), grid, GRID));
                }
                if let Some(share) = &spec.share {
                    found.push(("share.target".into(), &share.target, SANDBOX));
                }
                if let Some(pool) = &spec.workspace_pool {
                    found.push(("workspace_pool".into(), pool, &[Kind::WorkspacePool]));
                }
            }
            Spec::CredentialBroker(spec) => found.push(("grid".into(), &spec.grid, GRID)),
            Spec::ServicePublication(spec) => found.push(("target".into(), &spec.target, SERVICE)),
            Spec::Connection(spec) => {
                found.push(("from".into(), &spec.from, ANY));
                found.push(("to".into(), &spec.to, ANY));
            }
            Spec::Job(spec) => {
                if let Some(compute) = &spec.compute {
                    found.push(("compute".into(), compute, RUNS_ON));
                }
                for (index, input) in spec.inputs.iter().enumerate() {
                    found.push((format!("inputs[{index}]"), input, READS));
                }
                if let Some(outputs) = &spec.outputs {
                    found.push(("outputs".into(), outputs, STORE));
                }
            }
        }
        found
    }

    /// Every installation-time binding the spec names: the field, the binding's id and what it
    /// must be.
    pub fn bindings(&self) -> Vec<(String, &str, BindingKind)> {
        let mut found: Vec<(String, &str, BindingKind)> = Vec::new();
        match self {
            Spec::Environment(spec) => {
                for (index, access) in spec.pc_access.iter().enumerate() {
                    if let Some(binding) = &access.binding {
                        found.push((format!("pc_access[{index}].binding"), binding, BindingKind::Folder));
                    }
                }
                for (index, entry) in spec.sync.iter().enumerate() {
                    found.push((format!("sync[{index}].binding"), &entry.binding, BindingKind::Folder));
                }
            }
            Spec::WorkerGroup(spec) => {
                if let Some(source) = &spec.source {
                    found.push(("source".into(), &source.binding, BindingKind::Folder));
                }
            }
            Spec::ComputePool(spec) => {
                if let Some(identity) = spec.cloud.as_ref().and_then(|cloud| cloud.identity_file.as_ref()) {
                    found.push(("cloud.identity_file".into(), &identity.binding, BindingKind::File));
                }
            }
            Spec::WorkspacePool(spec) => {
                if let Some(drive) = &spec.drive {
                    found.push(("drive".into(), &drive.binding, BindingKind::Drive));
                }
            }
            Spec::Volume(spec) => {
                if let Some(drive) = &spec.drive {
                    found.push(("drive".into(), &drive.binding, BindingKind::Drive));
                }
            }
            Spec::ArtifactStore(spec) => {
                if let Some(drive) = &spec.drive {
                    found.push(("drive".into(), &drive.binding, BindingKind::Drive));
                }
            }
            Spec::Job(spec) => {
                if let Some(source) = &spec.source {
                    found.push(("source".into(), &source.binding, BindingKind::Folder));
                }
            }
            Spec::VmSandbox(spec) => {
                if let Some(workspace) = &spec.workspace {
                    found.push(("workspace".into(), &workspace.binding, BindingKind::Folder));
                }
            }
            _ => {}
        }
        found
    }

    /// The secret bindings the spec names, by the name the handler uses.
    pub fn secrets(&self) -> &BTreeMap<String, String> {
        static NONE: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
        match self {
            Spec::Environment(spec) => &spec.secrets,
            Spec::Grid(spec) => &spec.secrets,
            Spec::ComputePool(spec) => &spec.secrets,
            Spec::WorkerGroup(spec) => &spec.secrets,
            Spec::ModelService(spec) => &spec.secrets,
            Spec::WorkspacePool(spec) => &spec.secrets,
            Spec::AccessBinding(spec) => &spec.secrets,
            Spec::CredentialBroker(spec) => &spec.secrets,
            Spec::Job(spec) => &spec.secrets,
            Spec::VmSandbox(spec) => spec.application.as_ref().map(|app| &app.secrets).unwrap_or_else(|| NONE.get_or_init(BTreeMap::new)),
            Spec::ServicePublication(_) | Spec::Volume(_) | Spec::Connection(_) | Spec::ArtifactStore(_) => NONE.get_or_init(BTreeMap::new),
        }
    }

    /// The spec as a plan stores it.
    pub fn to_json(&self) -> Json {
        serde_json::to_value(self).unwrap_or(Json::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Yaml {
        serde_yaml_ng::from_str(text).unwrap()
    }

    #[test]
    fn kinds_parse_and_name_their_outputs() {
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
            assert!(!kind.outputs().is_empty());
        }
        assert_eq!(Kind::parse("database"), None);
    }

    #[test]
    fn every_spec_refuses_unknown_fields_and_checks_its_values() {
        let grid = parse_spec(Kind::Grid, &yaml("profile: sandbox_grid\nmode: join\nsecrets: {invitation: hub-x-invite}\n")).unwrap();
        assert!(grid.validate().is_empty(), "{:?}", grid.validate());
        assert!(parse_spec(Kind::Grid, &yaml("profile: sandbox_grid\ncolour: blue\n")).unwrap_err().contains("colour"));
        let joined = parse_spec(Kind::Grid, &yaml("profile: neo_grid\nmode: join\n")).unwrap();
        assert!(joined.validate()[0].contains("secrets: {invitation"));
        let pool = parse_spec(Kind::ComputePool, &yaml("grid: {resource: company}\nsource: selected_computers\n")).unwrap();
        assert!(pool.validate()[0].contains("needs computers"));
        assert_eq!(pool.references()[0].0, "grid");
        let bound = parse_spec(Kind::ComputePool, &yaml("grid: {binding: existing_grid}\n")).unwrap();
        assert!(bound.validate().is_empty(), "{:?}", bound.validate());
        assert_eq!(bound.references()[0].1.local(), None);
        assert!(parse_spec(Kind::ComputePool, &yaml("grid: {}\n")).unwrap().validate()[0].contains("needs resource: ID or binding: ID"));
        let job = parse_spec(Kind::Job, &yaml("compute: {resource: computers}\ncommand: [make, test]\nretry: {attempts: 3}\n")).unwrap();
        assert!(job.validate()[0].contains("idempotent"));
        let fine = parse_spec(Kind::Job, &yaml("compute: {resource: computers}\ncommand: [make, test]\nretry: {attempts: 3}\nidempotent: true\nsource: {binding: repo}\n")).unwrap();
        assert!(fine.validate().is_empty());
        assert_eq!(fine.bindings()[0].2, BindingKind::Folder);
        let publication = parse_spec(Kind::ServicePublication, &yaml("target: {resource: web}\nport: 0\naccess: domain\n")).unwrap();
        assert_eq!(publication.validate().len(), 2);
        let connection = parse_spec(Kind::Connection, &yaml("from: {resource: web}\nto: {resource: web}\npermissions: [network]\n")).unwrap();
        assert!(connection.validate()[0].contains("two different"));
        assert!(parse_spec(Kind::Connection, &yaml("from: {resource: a}\nto: {resource: b}\npermissions: [sudo]\n")).is_err());
        let broker = parse_spec(Kind::CredentialBroker, &yaml("grid: {resource: company}\ncredentials:\n  - {name: github, kind: github_app, approval: standing, value: token}\n  - {name: github, per_hour: 5}\n")).unwrap();
        let said = broker.validate();
        assert!(said.iter().any(|s| s.contains("unique name")) && said.iter().any(|s| s.contains("standing rule")) && said.iter().any(|s| s.contains("not under the broker's secrets")) && said.iter().any(|s| s.contains("per_hour works with")), "{said:?}");
        let person = parse_spec(Kind::Grid, &yaml("profile: access_grid\nmode: join\ncoordinator: remote\nmember: person\nsign_in: password\nusername: sam\nsecrets: {invitation: hub-x-i, password: hub-x-p}\n")).unwrap();
        assert!(person.validate().is_empty(), "{:?}", person.validate());
        let team = parse_spec(Kind::ModelService, &yaml("model: swarm/team\ncompute: {resource: computers}\nteam: {strategy: plan, lead: {resource: first}, workers: [{resource: first}], computers: 40}\n")).unwrap();
        assert!(team.validate()[0].contains("team.computers"));
        assert_eq!(team.references().len(), 3);
    }

    #[test]
    fn a_vm_sandbox_declares_its_memory_limits_routes_and_staged_workspace() {
        let text = "memory_gb: 2\nidle_minutes: 30\nlifetime_minutes: 240\nworkspace: {binding: project}\nroutes:\n  - name: models\n    host: api.example.com\n    operations: [{name: send, method: POST, path: /v1/messages, effect: external}]\n    credential: {name: example-key}\n";
        let spec = parse_spec(Kind::VmSandbox, &yaml(text)).unwrap();
        assert!(spec.validate().is_empty(), "{:?}", spec.validate());
        assert_eq!(spec.bindings(), vec![("workspace".to_owned(), "project", BindingKind::Folder)]);
        assert!(spec.secrets().is_empty() && spec.references().is_empty());
        let Spec::VmSandbox(parsed) = &spec else { panic!() };
        assert_eq!(parsed.routes[0].port, 443);
        assert_eq!(parsed.memory_bytes(), 2 << 30);
        assert_eq!(spec.to_json()["routes"][0]["operations"][0]["effect"], "external");
        // A sandbox of nothing: the defaults.
        let Spec::VmSandbox(empty) = parse_spec(Kind::VmSandbox, &Yaml::Null).unwrap() else { panic!() };
        assert_eq!((empty.memory_gb, empty.routes.len(), empty.workspace.is_none()), (1.0, 0, true));
        // Every wrong value is named.
        let bad = parse_spec(Kind::VmSandbox, &yaml("memory_gb: 0.1\nidle_minutes: -1\nlifetime_minutes: 99999\nroutes:\n  - {name: 9x, host: \"https://x\", port: 0, operations: []}\n  - {name: b, host: 10.0.0.1, operations: [{name: a, method: TRACE, path: \"v1?x\"}], credential: {name: \"a b\"}}\n")).unwrap();
        let said = bad.validate().join(" | ");
        for expected in ["memory_gb", "idle_minutes", "lifetime_minutes", "9x", "host https://x", "port", "at least one operation", "host 10.0.0.1", "method", "path", "credential name"] {
            assert!(said.contains(expected), "{expected}: {said}");
        }
        assert!(parse_spec(Kind::VmSandbox, &yaml("network: open\n")).unwrap_err().contains("network"));
        assert!(parse_spec(Kind::VmSandbox, &yaml("idle_minutes: 1.5\n")).unwrap().validate()[0].contains("whole number"));
        assert_eq!(parsed.routes[0].operations[0].effect(), RouteEffect::External);
        let Spec::VmSandbox(read) = parse_spec(Kind::VmSandbox, &yaml("routes: [{name: docs, host: docs.example.com, operations: [{name: page, method: GET, path: /}]}]\n")).unwrap() else { panic!() };
        assert_eq!(read.routes[0].operations[0].effect(), RouteEffect::ReadOnly);
        assert_eq!(FolderMode::parse("staged"), Some(FolderMode::Staged));
        for image in ["", "minimal", &format!("sha256:{}", "a".repeat(64))] {
            let value = serde_json::json!({"image": image});
            assert!(parse_json(Kind::VmSandbox, &value).unwrap().validate().is_empty());
        }
        for image in ["ubuntu:latest", "C:/image", "sha256:aa", &format!("sha256:{}", "A".repeat(64))] {
            let value = serde_json::json!({"image": image});
            assert!(parse_json(Kind::VmSandbox, &value).unwrap().validate().join(" ").contains("image"));
        }
        // Guest services it may publish: named, on their guest ports, neither repeated.
        let Spec::VmSandbox(published) = parse_spec(Kind::VmSandbox, &yaml("publish: [{service: web, port: 8080}]\n")).unwrap() else { panic!() };
        assert_eq!((published.publish[0].service.as_str(), published.publish[0].port), ("web", 8080));
        assert!(published.validate().is_empty(), "{:?}", published.validate());
        let wrong = parse_spec(Kind::VmSandbox, &yaml("publish: [{service: 9web, port: 0}, {service: api, port: 3000}, {service: api, port: 3000}]\n")).unwrap().validate().join(" | ");
        for expected in ["9web", "port must be between", "api is declared twice", "guest port 3000 is declared twice"] {
            assert!(wrong.contains(expected), "{expected}: {wrong}");
        }
        assert!(parse_spec(Kind::VmSandbox, &yaml("publish: [{service: web, port: 8080, audience: public}]\n")).is_err(), "an audience is chosen when publishing, never in the template");
        // Connections to another VM sandbox of the setup (M14): the caller's end, and the
        // callee's acceptance on the service it publishes.
        let Spec::VmSandbox(caller) = parse_spec(Kind::VmSandbox, &yaml("connect: [{name: db, to: store, service: sql, port: 5432, minutes: 30, budget_bytes: 1000}]\n")).unwrap() else { panic!() };
        assert!(caller.validate().is_empty(), "{:?}", caller.validate());
        let connection = &caller.connect[0];
        assert_eq!((connection.target(), connection.grant_minutes(), connection.budget()), (Some("store"), 30, 1000));
        let Spec::VmSandbox(defaults) = parse_spec(Kind::VmSandbox, &yaml("connect: [{name: db, to: store, service: sql}]\n")).unwrap() else { panic!() };
        assert_eq!((defaults.connect[0].grant_minutes(), defaults.connect[0].budget(), defaults.connect[0].port), (60, 8 << 20, None));
        let Spec::VmSandbox(callee) = parse_spec(Kind::VmSandbox, &yaml("publish: [{service: sql, port: 5432, accept: [app, worker]}]\n")).unwrap() else { panic!() };
        assert!(callee.validate().is_empty(), "{:?}", callee.validate());
        let wrong = parse_spec(
            Kind::VmSandbox,
            &yaml("routes: [{name: db, host: example.com, operations: [{name: read, method: GET, path: /}]}]\nconnect: [{name: db.x, to: store, service: sql}, {name: db, to: store, service: sql, port: 0, minutes: 2000, budget_bytes: 0}, {name: DB, to: 'bad id', service: sql}]\npublish: [{service: sql, port: 1, accept: [a, a, 'b c']}]\n"),
        )
        .unwrap()
        .validate()
        .join(" | ");
        for expected in ["db.x must be one host name label", "db is also a route's name", "port must be between 1 and 65535", "minutes must be a whole number", "budget_bytes must be between", "DB is declared twice", "must name a VM sandbox of this setup", "accept: a is named twice", "must be a resource id"] {
            assert!(wrong.contains(expected), "{expected}: {wrong}");
        }
    }

    #[test]
    fn an_environment_keeps_the_v1_fields_and_rules() {
        let text = "image: python:3.12-slim\ncpu: 1\nmemory: 1GB\nstorage: 6GB\nworking_dir: /app\nfiles: [{source: ./site, target: /app}]\nenvironment: {SITE_TITLE: Hello, COUNT: 3, ON: true}\ncommand: [python, server.py]\nports: [8080, \"9090:90\"]\nrestart: always\nhealth: {port: 8080, path: /}\n";
        let Spec::Environment(spec) = parse_spec(Kind::Environment, &yaml(text)).unwrap() else { panic!() };
        assert_eq!(spec.environment["COUNT"].as_str(), "3", "a number typed by an answer reads as text");
        assert_eq!(spec.environment["ON"].as_str(), "yes");
        let Spec::Environment(listed) = parse_spec(Kind::Environment, &yaml("image: nginx\nenvironment: {PROVIDERS: [codex, kilo]}\ncommand: [run, [a, b]]\n")).unwrap() else { panic!() };
        assert_eq!(listed.environment["PROVIDERS"].as_str(), "codex,kilo", "a multiple-choice answer reads as v1 wrote it");
        assert_eq!(listed.command, Some(Command::Args(vec![Text::from("run"), Text::from("a,b")])));
        assert_eq!(spec.guest_ports(), [8080, 90]);
        assert!(spec.validate().is_empty(), "{:?}", spec.validate());
        assert_eq!(spec.image_shown(), "python:3.12-slim");
        let bad = parse_spec(Kind::Environment, &yaml("image: nginx\nvolumes: [{source: data, target: relative}]\npc_access: [{path: ./x}]\n")).unwrap();
        let said = bad.validate();
        assert!(said.iter().any(|s| s.contains("invalid volume target")) && said.iter().any(|s| s.contains("permissions.pc")), "{said:?}");
        assert!(parse_spec(Kind::Environment, &yaml("image: nginx\nstorage_drive: D:/\nunknown: 1\n")).is_err());
        let json = parse_json(Kind::Environment, &serde_json::json!({"image": "nginx", "ports": [80]})).unwrap();
        assert_eq!(json.kind(), Kind::Environment);
        assert_eq!(json.to_json()["image"], "nginx");
    }
    #[test]
    fn remote_vm_specs_reject_silently_ignored_local_options_and_author_supplied_trust() {
        let base=serde_json::json!({"memory_gb":1,"remote":{"connection":"env-owned","parent":{"resource":"parent"},"program":"/opt/engine","endpoint":"/run/engine.sock","engine_sha256":"a".repeat(64)}});
        assert!(parse_json(Kind::VmSandbox,&base).unwrap().validate().is_empty());
        for (field,value) in [("image",serde_json::json!(format!("sha256:{}","a".repeat(64)))),
            ("workspace",serde_json::json!({"binding":"folder"})),("workspace_folder",serde_json::json!("/tmp/folder")),
            ("idle_minutes",serde_json::json!(5)),("routes",serde_json::json!([{"name":"api","host":"example.com","operations":[{"name":"read","method":"GET","path":"/"}]}])),
            ("publish",serde_json::json!([{"service":"api","port":8080}])),
            ("connect",serde_json::json!([{"name":"api","to":"peer","service":"api"}]))] {
            let mut bad=base.clone();bad[field]=value;
            assert!(parse_json(Kind::VmSandbox,&bad).unwrap().validate().iter().any(|e|e.contains("not supported remotely")),"{field}");
        }
        let mut bad=base.clone();bad["remote"]["accept_host_key"]=serde_json::json!("SHA256:from-author");
        assert!(parse_json(Kind::VmSandbox,&bad).is_err());
        let mut bad=base;bad["remote"]["parent"]=serde_json::json!({"binding":"another"});
        assert!(parse_json(Kind::VmSandbox,&bad).unwrap().validate().iter().any(|e|e.contains("local VM")));
    }

}
