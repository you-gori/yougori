//! From a template package to a reviewed engine plan, through the shared planner
//! (`yougori_setup::format` and `plan`). Nothing here changes anything: a package is read,
//! checked and planned, and the result is the review a person approves before `setup_apply`.
//! The reply also carries the plan's CORE-07 product document (`setups::product::of_plan`),
//! the one the desktop's review and the CLI read: what its chosen capabilities ask for, each
//! requested. It has no migration part, since what a plan creates is not an old record and an
//! update's existing setup shows its inventory on `setup_get`.
use super::{
    model::{Diagnostic, InstanceChange, OwnerRef, Source},
    ordinary::BoxFuture,
    service::{DeclaredResource, PlanIntent, Service, SetupDraft},
    views,
};
use crate::AppHandle;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tauri::Manager;
use yougori_setup::{capability, draft, dto, format, merge, plan};

/// `setup_plan`: `dto::PlanRequest`, plus a desktop builder draft.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PlanCall {
    #[serde(default)]
    source: Option<dto::SourceRef>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    answers: Vec<dto::Answer>,
    #[serde(default)]
    bindings: Vec<dto::Binding>,
    #[serde(default)]
    existing_setup: Option<String>,
    #[serde(default)]
    draft: Option<Value>,
    /// The drive the setup's sandboxes are stored on, as this computer names it (`D:\`). Chosen
    /// when the setup is made; a sandbox can't move to another drive in place afterwards.
    #[serde(default)]
    storage_drive: Option<String>,
    /// The drives this computer could put the setup's sandboxes on, filled in by the caller that
    /// can see them. A template that lets the person choose its drive (`data.storage_drive`) is
    /// refused until one is chosen when there is more than one.
    #[serde(skip)]
    drives: Vec<String>,
}

impl PlanCall {
    /// The drive this plan asks for, if any.
    pub(crate) fn storage_drive(&self) -> Option<&str> {
        self.storage_drive.as_deref().map(str::trim).filter(|drive| !drive.is_empty())
    }

    /// The drive, as this computer spells it once checked.
    pub(crate) fn set_storage_drive(&mut self, drive: String) {
        self.storage_drive = Some(drive);
    }

    /// The drives the setup could be stored on, as `check_drive` would take them.
    pub(crate) fn set_drives(&mut self, drives: Vec<String>) {
        self.drives = drives;
    }
}

/// The drives of `drives` (the platform's `host.storageDrives`) a setup's sandboxes could be
/// stored on: the ones `check_drive` takes.
pub(crate) fn usable_drives(drives: &[Value]) -> Vec<String> {
    drives.iter().filter_map(|drive| drive["path"].as_str()).filter_map(|path| check_drive(path, drives).ok()).collect()
}

/// The least free space, in GB, a drive needs to take a setup's sandboxes: their images and
/// first files. Their storage limits are maximums they grow into, so their sum isn't required.
const DRIVE_TO_START_GB: f64 = 10.0;

/// Whether `drive` is one of this computer's drives that can take sandboxes: known, writable, not
/// removable, with room to start. `drives` are the platform's `host.storageDrives`. Each refusal
/// says why and what to choose instead.
pub(crate) fn check_drive(drive: &str, drives: &[Value]) -> Result<String, Diagnostic> {
    let wanted = normal_drive(drive);
    let found = drives.iter().find(|one| one["path"].as_str().is_some_and(|path| normal_drive(path) == wanted));
    let refused = |message: String| Diagnostic::new("invalid_value", message).at("storageDrive");
    let Some(found) = found else {
        let known = drives.iter().filter_map(|one| one["path"].as_str()).collect::<Vec<_>>();
        return Err(refused(if known.is_empty() {
            format!("Yougori can't see {drive} on this computer. Leave the drive out to use the usual one.")
        } else {
            format!("Yougori can't see {drive} on this computer. Choose one of: {}.", known.join(", "))
        }));
    };
    let path = found["path"].as_str().unwrap_or(drive).to_owned();
    if found["readOnly"] == true {
        return Err(refused(format!("{path} can only be read, so sandboxes can't be stored there. Choose another drive.")));
    }
    if found["removable"] == true {
        return Err(refused(format!("{path} is a removable drive. Sandboxes on it would stop working when it is taken out, so choose a fixed drive.")));
    }
    let free = found["freeGb"].as_f64().unwrap_or(0.0);
    if free < DRIVE_TO_START_GB {
        return Err(refused(format!("{path} has {free:.0} GB free; a setup's sandboxes need at least {DRIVE_TO_START_GB:.0} GB to start. Free some space or choose another drive.")));
    }
    Ok(path)
}

/// A drive as compared: forward slashes, no trailing slash, case folded (`D:\`, `d:/` and `D:` are
/// one drive).
fn normal_drive(drive: &str) -> String {
    drive.trim().replace('\\', "/").trim_end_matches('/').to_ascii_lowercase()
}

/// `setup_validate`: a source reference, the template's YAML text, or a builder draft.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ValidateCall {
    #[serde(default)]
    source: Option<Value>,
    #[serde(default)]
    draft: Option<Value>,
}

/// One checked version of a Hub template.
#[derive(Clone, Debug)]
pub(crate) struct Fetched {
    pub files: format::Files,
    pub version: String,
    /// The version's digest as the Hub publishes it: SHA-256 of its files, in hex.
    pub digest: String,
    /// The item's page as the Hub sent it, when it answered: what a person read before choosing,
    /// with the review this version was published with. `None` from a saved copy used offline.
    pub page: Option<Value>,
}

/// Where Hub templates come from. `EngineHub` downloads through the CLI's Hub client, which checks
/// the version's digest and every file's SHA-256; tests use a fake.
pub(crate) trait Hub: Send + Sync {
    /// The version asked for, or the latest when `version` is `None`. With `digest`, exactly the
    /// files of that digest, as an installed setup was made from, or a refusal.
    fn fetch<'a>(&'a self, publisher: &'a str, name: &'a str, version: Option<&'a str>, digest: Option<&'a str>) -> BoxFuture<'a, Result<Fetched, String>>;
    /// A package's pinned components, each at its pinned version and digest, through the one
    /// function the CLI's `template check` and `template plan` use (`hub::components::resolve`).
    fn components<'a>(&'a self, checked: &'a format::Checked) -> BoxFuture<'a, Result<BTreeMap<String, plan::Component>, Vec<dto::Diagnostic>>>;
    /// One version of a Hub tool, through the same client and cache as components
    /// (`hub_tools::resolve` asks for each pinned tool of a package). A Hub that has no tools
    /// refuses, so a fake used for templates never resolves a tool by accident.
    fn tool<'a>(&'a self, publisher: &'a str, name: &'a str, version: &'a str) -> BoxFuture<'a, Result<super::hub_tools::FetchedTool, String>> {
        Box::pin(async move { Err(format!("{publisher}/{name} {version} cannot be fetched here.")) })
    }
}

/// The Hub client the CLI uses, with checked copies kept in the engine's own cache.
pub(crate) struct EngineHub {
    cache: PathBuf,
}

impl EngineHub {
    pub(crate) fn new(cache: PathBuf) -> Self {
        Self { cache }
    }

    /// The configured Hub, and the CLI's cache when there is one, so a version it already checked
    /// is reused (and checked again) rather than downloaded twice.
    fn client(&self) -> Result<(yougori_cli::hub::client::Site, yougori_cli::hub::client::Cache), String> {
        use yougori_cli::hub::client;
        Ok((client::Site::configured()?, client::Cache::standard().unwrap_or_else(|_| client::Cache { root: self.cache.clone() })))
    }
}

impl Hub for EngineHub {
    fn fetch<'a>(&'a self, publisher: &'a str, name: &'a str, version: Option<&'a str>, digest: Option<&'a str>) -> BoxFuture<'a, Result<Fetched, String>> {
        Box::pin(async move {
            use yougori_cli::hub::{client, refs::Ref};
            let (site, cache) = self.client()?;
            let reference = Ref { publisher: publisher.to_owned(), name: name.to_owned(), version: version.map(str::to_owned) };
            let got = match digest {
                Some(digest) => client::own(&site, &cache, &reference, digest).await?,
                None => client::obtain(&site, &cache, &reference).await?,
            };
            if got.bundle.kind != "template" {
                return Err(format!("{publisher}/{name} is a {}, not a template.", got.bundle.kind));
            }
            Ok(Fetched { files: got.bundle.files, version: got.bundle.version, digest: got.bundle.digest, page: got.detail })
        })
    }

    fn components<'a>(&'a self, checked: &'a format::Checked) -> BoxFuture<'a, Result<BTreeMap<String, plan::Component>, Vec<dto::Diagnostic>>> {
        Box::pin(async move {
            let (site, cache) = self.client().map_err(|problem| vec![dto::Diagnostic::error("component_unavailable", problem).at("imports")])?;
            yougori_cli::hub::components::resolve(&site, &cache, checked).await
        })
    }

    fn tool<'a>(&'a self, publisher: &'a str, name: &'a str, version: &'a str) -> BoxFuture<'a, Result<super::hub_tools::FetchedTool, String>> {
        Box::pin(async move {
            use yougori_cli::hub::{client, refs::Ref};
            let (site, cache) = self.client()?;
            let reference = Ref { publisher: publisher.to_owned(), name: name.to_owned(), version: Some(version.to_owned()) };
            super::hub_tools::FetchedTool::of(client::obtain(&site, &cache, &reference).await?.bundle)
        })
    }
}

/// A checked package's pinned components; a package without imports never touches the Hub.
async fn components(hub: &dyn Hub, checked: &format::Checked) -> Result<BTreeMap<String, plan::Component>, Vec<dto::Diagnostic>> {
    if checked.template.imports.is_empty() {
        return Ok(BTreeMap::new());
    }
    hub.components(checked).await
}

/// A checked package with its Hub tools resolved and its components fetched: everything the
/// planner needs at hand before the review, so what the review lists is what apply installs.
async fn resolved(hub: &dyn Hub, mut checked: format::Checked) -> Result<(format::Checked, BTreeMap<String, plan::Component>), Vec<dto::Diagnostic>> {
    super::hub_tools::resolve(hub, &mut checked).await?;
    let components = components(hub, &checked).await?;
    Ok((checked, components))
}

/// A package ready to check: its files and how the setup records where they came from.
struct Package {
    files: format::Files,
    recorded: dto::SourceRef,
    /// SHA-256 of the files, in hex, as the Hub computes it.
    digest: String,
    item: Option<String>,
    /// Set when the Hub's latest version was asked for: the version it resolved to.
    latest: Option<String>,
    /// For a package asked for from the Hub: the item's page, when the Hub sent one, and the
    /// version the files are. The review on that page is checked against the files before anyone
    /// agrees to the plan (`page_check`). A kept package or a folder has no page.
    page: Option<(Option<Value>, String)>,
}

/// A builder draft as a package, through the shared generator (`draft::to_package`).
fn generated(value: &Value) -> Result<draft::Generated, Vec<dto::Diagnostic>> {
    let built: draft::Draft = serde_json::from_value(value.clone())
        .map_err(|error| vec![dto::Diagnostic::error("invalid_draft", format!("This draft is not in the shape Yougori expects ({error})."))])?;
    draft::to_package(&built)
}

/// Where a setup made from a builder draft says it came from: its own kept package. Planning it
/// again reads that copy.
fn from_draft() -> dto::SourceRef {
    dto::SourceRef::InstalledSetup { setup_id: "draft".into() }
}

/// This computer as the capability registry judges it. Best effort from what the engine already
/// knows: providers that are ready, and the GPU runtime when its payload is installed.
pub(crate) fn capability_host(app: &AppHandle) -> capability::Host {
    use capability::{Arch, Gpu, Host, Os, Runtime};
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    let providers = runtime.provider_statuses();
    let ready = |id: &str| {
        providers
            .iter()
            .any(|provider| provider.id == id && matches!(provider.status, crate::models::ProviderAvailability::Ready))
    };
    let nvidia = runtime.cuda_payload_current();
    let mut runtimes = Vec::new();
    if ready("provider-yougori-oci") {
        runtimes.extend([Runtime::Containers, Runtime::LocalModels]);
    }
    if ready("provider-yougori-qemu") {
        runtimes.extend([Runtime::Vm, Runtime::MicroVm]);
    }
    if nvidia {
        runtimes.push(Runtime::NvidiaContainers);
    }
    // The restricted VM sandbox: its pinned build and guest installed, and the hypervisor there.
    if crate::sandbox_vm::available(app) {
        runtimes.push(Runtime::VmSandbox);
    }
    let os = if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::Macos
    } else {
        Os::Linux
    };
    let arch = if cfg!(target_arch = "aarch64") { Arch::Aarch64 } else { Arch::X86_64 };
    Host::new(os, arch, if nvidia { Gpu::Nvidia } else { Gpu::None }, runtimes, Host::PRIVATE_BUILD)
}

/// This computer as the planner's requirement checks see it.
/// The version a DEVELOPMENT build has been told to answer the planner with, when it has been.
///
/// `None` in a release build, always and without reading anything: a released Yougori reports its
/// own version, so `requires.yougori: 1.2.0` keeps meaning the release that ships format 2 and no
/// shipped build can be talked out of it. A development build may be told otherwise with
/// `YOUGORI_DEV_HOST_VERSION`, so templates written for the next release can be tried against the
/// tree that is becoming it. Without the variable a development build behaves exactly like a
/// release one.
///
/// This exists instead of moving the tree's own version forward. The working tree is deliberately
/// a version behind the templates it is growing; calling it 1.2.0 would make every format 2
/// template claim it runs on a build with no runtime acceptance, and would leave the gate
/// protecting nothing.
pub(crate) fn stand_in_version() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        let asked = stand_in_from(std::env::var("YOUGORI_DEV_HOST_VERSION").ok().as_deref())?;
        // Once per process: this is read on every plan, and a line per plan would bury the rest
        // of the development log in repeats of the same sentence.
        static SAID: std::sync::Once = std::sync::Once::new();
        SAID.call_once(|| {
            eprintln!(
                "Yougori is answering the template planner as version {asked} because YOUGORI_DEV_HOST_VERSION is set. This is a development build only; a released Yougori always reports its own version ({}).",
                env!("CARGO_PKG_VERSION")
            );
        });
        Some(asked)
    }
    #[cfg(not(debug_assertions))]
    None
}

/// The decision itself, with the environment left out so it can be tested without two tests
/// racing over one process-wide variable. Anything that is not a version is ignored rather than
/// guessed at: a typo must never quietly become a version nobody meant.
#[cfg(debug_assertions)]
fn stand_in_from(raw: Option<&str>) -> Option<String> {
    let asked = raw?.trim();
    if asked.is_empty() || yougori_setup::format::parse_version(asked).is_err() {
        return None;
    }
    Some(asked.to_owned())
}

pub(crate) fn planner_host(app: &AppHandle) -> plan::Host {
    let capabilities = capability_host(app);
    let platform = format!(
        "{}-{}",
        if cfg!(target_os = "windows") { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" },
        if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" }
    );
    let memory_gb = app
        .state::<crate::store::PlatformStore>()
        .snapshot()
        .ok()
        .map(|state| state.host.total_memory_gb)
        .filter(|memory| *memory > 0.0);
    plan::Host {
        yougori: stand_in_version().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned()),
        platform,
        gpu: Some(capabilities.gpu == capability::Gpu::Nvidia),
        memory_gb,
        free_disk_gb: None,
        capabilities,
    }
}

/// The package's files and the source to record for it. An installed setup is read from the copy
/// of its package kept beside it, when that copy still has the files it was made from, and
/// otherwise from the source it was made from, pinned to that version and digest.
async fn read(service: &Service, hub: &dyn Hub, source: &dto::SourceRef) -> Result<Package, Diagnostic> {
    match source {
        dto::SourceRef::LocalFolder { path } => {
            let folder = Path::new(path);
            if !folder.is_absolute() {
                return Err(Diagnostic::new("invalid_request", "Give the template folder's full path.").at("source.path"));
            }
            let collected = yougori_cli::hub::scan::collect(folder)
                .map_err(|problem| Diagnostic::new("package_unreadable", problem).at("source.path"))?;
            let digest = yougori_cli::hub::scan::digest_of(&collected.files);
            Ok(Package { files: collected.files, recorded: source.clone(), digest, item: None, latest: None, page: None })
        }
        dto::SourceRef::Hub { publisher, name, version } => {
            let pinned = Some(version.trim()).filter(|version| !version.is_empty() && *version != "latest");
            let fetched = hub
                .fetch(publisher, name, pinned, None)
                .await
                .map_err(|problem| Diagnostic::new("hub_download_failed", problem).at("source"))?;
            let latest = pinned.is_none().then(|| fetched.version.clone());
            Ok(Package {
                recorded: dto::SourceRef::Hub { publisher: publisher.clone(), name: name.clone(), version: fetched.version.clone() },
                files: fetched.files,
                digest: fetched.digest,
                item: Some(format!("{publisher}/{name}")),
                latest,
                page: Some((fetched.page, fetched.version)),
            })
        }
        dto::SourceRef::InstalledSetup { setup_id } => {
            let recorded = service.source_record(setup_id)?;
            let digest = recorded.digest.trim_start_matches("sha256:").to_owned();
            if let Some(files) = service.package_files(setup_id).filter(|files| yougori_cli::hub::scan::digest_of(files) == digest) {
                let item = match &recorded.reference {
                    dto::SourceRef::Hub { publisher, name, .. } => Some(format!("{publisher}/{name}")),
                    _ => None,
                };
                return Ok(Package { files, recorded: recorded.reference, digest, item, latest: None, page: None });
            }
            match &recorded.reference {
                dto::SourceRef::Hub { publisher, name, version } => {
                    let fetched = hub
                        .fetch(publisher, name, Some(version), Some(&digest))
                        .await
                        .map_err(|problem| Diagnostic::new("hub_download_failed", problem).at("source"))?;
                    Ok(Package { files: fetched.files, recorded: recorded.reference.clone(), digest, item: Some(format!("{publisher}/{name}")), latest: None, page: None })
                }
                dto::SourceRef::LocalFolder { .. } => Box::pin(read(service, hub, &recorded.reference)).await,
                dto::SourceRef::InstalledSetup { .. } => Err(Diagnostic::new("package_unreadable", "This setup doesn't say which template it came from.")),
            }
        }
    }
}

/// The checked package, or every problem found in it. A format 1 template is read by the CLI's
/// own v1 parser and handed to the planner in the shared adapter's form (`hub::plan::legacy_of`,
/// the input `v1::compile_v1` plans), so it gets the same questions and resources `yougori run`
/// gives it and nothing new is asked.
fn check(files: &format::Files) -> Result<format::Checked, Vec<dto::Diagnostic>> {
    let text = files
        .get(format::TEMPLATE_FILE)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .ok_or_else(|| vec![dto::Diagnostic::error("missing_file", format!("The folder has no {}.", format::TEMPLATE_FILE)).at(format::TEMPLATE_FILE)])?;
    match format::format_version(&text) {
        Ok(format::FormatVersion::V2) => format::template(files),
        Ok(format::FormatVersion::V1) => {
            let folder = yougori_cli::hub::format::template(files).map_err(|problems| {
                problems.into_iter().map(|problem| dto::Diagnostic::error("invalid_template", problem).at(format::TEMPLATE_FILE)).collect::<Vec<_>>()
            })?;
            let mut checked = yougori_cli::hub::plan::legacy_of(&folder).checked();
            checked.project_path = folder.project_path.clone();
            checked.project_text = folder.project_text.clone();
            Ok(checked)
        }
        Err(problem) => Err(vec![problem]),
    }
}

/// The first of the planner's problems, saying how many more there are.
fn first_problem(problems: Vec<dto::Diagnostic>) -> Diagnostic {
    let more = problems.len().saturating_sub(1);
    let Some(first) = problems.into_iter().next() else {
        return Diagnostic::new("plan_refused", "This template could not be planned.");
    };
    let message = match more {
        0 => first.message,
        1 => format!("{} (and 1 more problem)", first.message),
        more => format!("{} (and {more} more problems)", first.message),
    };
    let mut diagnostic = Diagnostic::new(&first.code, message);
    diagnostic.field = first.field;
    diagnostic.retryable = first.retryable;
    diagnostic
}

/// An instance name the planner accepts: letters, digits, dots, dashes, underscores; at most 40.
fn instance_name(name: &str, fallback: &str) -> String {
    let slug = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '-' })
        .collect::<String>();
    let slug = slug.trim_matches('-').chars().take(40).collect::<String>();
    if slug.is_empty() { fallback.chars().take(40).collect() } else { slug }
}

/// The run's answers as the planner takes them. A capability switch is `capabilities.ID`; an
/// answer to one of the template's bindings is that binding; secrets arrive as binding names.
fn answers(checked: &format::Checked, call: &PlanCall, instance: &str) -> plan::Answers {
    let bindings = checked.bindings.iter().map(|binding| binding.id.clone()).collect::<BTreeSet<_>>();
    let mut chosen = plan::Answers { instance: instance.to_owned(), ..Default::default() };
    for answer in &call.answers {
        if let Some(capability) = answer.field.strip_prefix("capabilities.").filter(|id| capability::find(id).is_some()) {
            if let Some(on) = answer.value.as_bool() {
                chosen.capabilities.insert(capability.to_owned(), on);
                continue;
            }
        }
        let text = match &answer.value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        if bindings.contains(&answer.field) {
            chosen.bindings.insert(answer.field.clone(), text);
        } else {
            chosen.inputs.insert(answer.field.clone(), text);
        }
    }
    for binding in &call.bindings {
        // `apply:FIELD` (the value comes with setup_apply) is written `apply.FIELD`, the form the
        // planner accepts as a binding name; `StepContext::secret` reads it back.
        chosen.secrets.insert(binding.field.clone(), binding.secret_ref.replace(':', "."));
    }
    chosen
}

/// The other setup's resource a borrowed declaration names, directly or through the binding the
/// person chose (`SETUP_ID/RESOURCE_ID`).
fn owner_of(borrow: &format::Borrow, chosen: &BTreeMap<String, String>) -> Option<OwnerRef> {
    match (&borrow.setup, &borrow.resource, &borrow.binding) {
        (Some(setup), Some(resource), _) => Some(OwnerRef { setup: setup.clone(), resource: resource.clone() }),
        (_, _, Some(binding)) => chosen
            .get(binding)
            .and_then(|choice| choice.split_once('/'))
            .map(|(setup, resource)| OwnerRef { setup: setup.to_owned(), resource: resource.to_owned() }),
        _ => None,
    }
}

/// A binding of type resource that a resource's spec refers to (`{binding: ID}`), with the kind
/// of resource it chooses and every field of the spec that names it.
struct BorrowedBinding {
    id: String,
    kind: yougori_setup::resource::Kind,
    fields: Vec<String>,
}

/// The bindings of type resource a planned resource's spec refers to, in the order it names them.
fn borrowed_bindings(resource: &plan::PlannedResource, checked: &format::Checked) -> Result<Vec<BorrowedBinding>, Diagnostic> {
    let Ok(parsed) = yougori_setup::resource::parse_json(resource.kind, &resource.spec) else { return Ok(Vec::new()) };
    let mut found: Vec<BorrowedBinding> = Vec::new();
    for (field, reference, _) in parsed.references() {
        let Some(id) = &reference.binding else { continue };
        let declared = checked
            .bindings
            .iter()
            .find(|binding| &binding.id == id && binding.kind == yougori_setup::resource::BindingKind::Resource)
            .and_then(|binding| binding.resource)
            .ok_or_else(|| Diagnostic::new("binding_missing", format!("{} names the binding {id}, which isn't a binding to an existing resource.", resource.id)).at(id).resource(&resource.id))?;
        match found.iter_mut().find(|binding| &binding.id == id) {
            Some(binding) => binding.fields.push(field),
            None => found.push(BorrowedBinding { id: id.clone(), kind: declared, fields: vec![field] }),
        }
    }
    Ok(found)
}

/// The value at a spec field as `references()` names it (`share.target`, `team.workers[1]`).
fn at_field<'a>(spec: &'a mut Value, field: &str) -> Option<&'a mut Value> {
    let mut at = spec;
    for part in field.split('.') {
        let (name, index) = match part.split_once('[') {
            Some((name, rest)) => (name, Some(rest.trim_end_matches(']').parse::<usize>().ok()?)),
            None => (part, None),
        };
        at = at.get_mut(name)?;
        if let Some(index) = index {
            at = at.get_mut(index)?;
        }
    }
    Some(at)
}

/// The engine's draft from the planner's plan: resources in dependency order with their resolved
/// specs, and what the setup's own record becomes.
fn draft(planned: &plan::Plan, checked: &format::Checked, name: String, source: Source, lock: &yougori_setup::lock::Lock) -> Result<SetupDraft, Diagnostic> {
    let declared = planned.resources.iter().map(|resource| resource.id.as_str()).collect::<BTreeSet<_>>();
    let mut resources: Vec<DeclaredResource> = Vec::new();
    for resource in &planned.resources {
        let owner = match &resource.borrow {
            None => None,
            Some(borrow) => Some(owner_of(borrow, &planned.bindings).ok_or_else(|| {
                Diagnostic::new("binding_missing", format!("Choose which existing resource {} should use.", resource.id))
                    .at(&borrow.binding.clone().unwrap_or_else(|| resource.id.clone()))
                    .resource(&resource.id)
            })?),
        };
        let mut spec = resource.spec.clone();
        let mut requires = resource.depends_on.clone();
        // A reference to a resource of another setup, chosen through a binding of type resource,
        // becomes a borrowed resource of this setup under the binding's id: the engine attaches it
        // (never creates or changes it), gives this step a peer that isn't owned, and keeps the
        // owner's setup from being removed while it is in use.
        for binding in borrowed_bindings(resource, checked)? {
            if declared.contains(binding.id.as_str()) {
                return Err(Diagnostic::new(
                    "invalid_template",
                    format!("The binding {0} and a resource of the same name can't both exist in this setup; rename one of them.", binding.id),
                )
                .at(&binding.id)
                .resource(&resource.id));
            }
            if !resources.iter().any(|existing| existing.id == binding.id) {
                let owner = owner_of(&format::Borrow { binding: Some(binding.id.clone()), ..format::Borrow::default() }, &planned.bindings).ok_or_else(|| {
                    Diagnostic::new("binding_missing", format!("Choose which existing resource {} should use.", binding.id)).at(&binding.id).resource(&resource.id)
                })?;
                resources.push(DeclaredResource { id: binding.id.clone(), kind: binding.kind, spec: json!({}), requires: Vec::new(), owner: Some(owner) });
            }
            for field in &binding.fields {
                let Some(reference) = at_field(&mut spec, field) else { continue };
                let output = reference.get("output").cloned();
                *reference = json!({"resource": binding.id});
                if let Some(output) = output {
                    reference["output"] = output;
                }
            }
            if !requires.contains(&binding.id) {
                requires.push(binding.id.clone());
            }
        }
        resources.push(DeclaredResource { id: resource.id.clone(), kind: resource.kind, spec, requires, owner });
    }
    Ok(SetupDraft {
        change: InstanceChange {
            name,
            source,
            format_version: planned.format_version as u32,
            protocol_version: dto::CONTRACT_VERSION,
            lock_digest: Some(lock.digest()),
            lock: serde_json::to_value(lock).ok(),
            answers: planned.inputs.iter().map(|(id, value)| (id.clone(), Value::String(value.clone()))).collect(),
            secret_bindings: planned.secrets.clone(),
            capabilities: planned
                .capabilities
                .iter()
                .filter(|capability| capability.enabled && capability.applies)
                .map(|capability| capability.id.clone())
                .collect(),
        },
        resources,
    })
}

/// The builder's draft of a checked package (`draft::from_checked`), with where it came from.
fn builder_draft(checked: &format::Checked, source: Option<&dto::SourceRef>) -> Value {
    let (mut built, _notes) = draft::from_checked(checked);
    if let Some(source) = source {
        built.source = serde_json::to_value(source).ok();
    }
    serde_json::to_value(built).unwrap_or(Value::Null)
}

/// Turn a supported Docker Compose file into a format 2 package: the shared converter makes a
/// project, which becomes `yougori.yaml` (v2), beside a minimal `yougori-template.yaml`. The
/// converter refuses any Compose key it cannot translate safely, so anything that could not be
/// carried over comes back as a plain diagnostic against `source.path`, never silently dropped. On
/// success, `notes` says in plain words what the import brought across.
fn read_compose(value: &Value) -> Result<(format::Files, Vec<String>), Diagnostic> {
    let path = value.get("path").and_then(Value::as_str).unwrap_or_default();
    if path.is_empty() {
        return Err(Diagnostic::new("invalid_request", "Say which Compose file to import.").at("source.path"));
    }
    let file = Path::new(path);
    if !file.is_absolute() {
        return Err(Diagnostic::new("invalid_request", "Give the Compose file's full path.").at("source.path"));
    }
    // The shared converter does the work and the refusing: a key it cannot translate safely stops the
    // import with a message that names the key and what to do, so nothing is carried over quietly.
    let project = yougori_cli::manifest::compose::convert(file)
        .map_err(|problem| Diagnostic::new("compose_unsupported", problem).at("source.path"))?;

    // The converted project is v1-style; write it with the CLI's own serializer and mark it format 2
    // so it reads as a format 2 project (whose environments keep their v1 shape). A format 2 package
    // needs both files to say format_version: 2; the key is added at the top of the written YAML.
    let body = yougori_cli::manifest::to_yaml(&project)
        .map_err(|problem| Diagnostic::new("compose_unsupported", format!("The converted project could not be written: {problem}")).at("source.path"))?;
    let project_yaml = format!("format_version: {}\n{body}", format::FORMAT_VERSION);

    // A minimal format 2 template wrapping the project. The builder fills in the rest; capabilities
    // start empty, so the person chooses what it can do after the import.
    let name = if project.project.is_empty() { "imported".to_owned() } else { project.project.clone() };
    let template_yaml = format!(
        "format_version: {}\nkind: template\nname: {name}\ntitle: {name}\nsummary: Imported from a Compose file.\nversion: 0.1.0\nlicense: MIT\nproject: {}\nrequires:\n  yougori: 1.2.0\n",
        format::FORMAT_VERSION,
        format::PROJECT_FILE,
    );

    // What the import brought over, in plain words. The converter already refused anything it could
    // not carry, so this names what did come across rather than what was dropped.
    let services = project.environments.len();
    let mut notes = vec![format!(
        "Imported {services} {} from the Compose file.",
        if services == 1 { "service" } else { "services" }
    )];
    if !project.publish.is_empty() {
        notes.push(format!("{} published port(s) were kept; turn on a Website & API capability to reach them.", project.publish.len()));
    }
    if project.environments.values().any(|env| !env.volumes.is_empty()) {
        notes.push("Named volumes were kept; turn on a Files & data capability if you want them managed.".to_owned());
    }
    notes.push("Choose what this setup can do next; the import did not pick any capabilities for you.".to_owned());

    let files = format::Files::from([
        (format::TEMPLATE_FILE.to_owned(), template_yaml.into_bytes()),
        (format::PROJECT_FILE.to_owned(), project_yaml.into_bytes()),
    ]);
    Ok((files, notes))
}

/// Capture the chosen environments on this computer into a format 2 package, using the shared capture
/// code, so a template can be started from sandboxes already set up here. This is a pure read of the
/// engine's own settings: no sandbox is run and no value is read out of one. `state` and `volumes` are
/// the engine's `get_platform_state` and `list_volumes`, passed in so this stays testable and reads
/// nothing itself. `left_out` from the capture becomes the notes shown before Continue, plus a line
/// that names of variables and signed-in tools are not read here (use `yougori template capture` for
/// those).
fn read_environments(state: &Value, volumes: &Value, env_ids: &[String]) -> Result<(format::Files, Vec<String>), Diagnostic> {
    if env_ids.is_empty() {
        return Err(Diagnostic::new("invalid_request", "Choose at least one environment to make a template from.").at("source.environments"));
    }
    let mut taken = std::collections::BTreeSet::new();
    let mut captured = Vec::new();
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    for id in env_ids {
        let environment = state["environments"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|env| env["id"].as_str() == Some(id.as_str()))
            .cloned()
            .ok_or_else(|| Diagnostic::new("environment_missing", format!("One chosen environment ({id}) is no longer here. Choose again.")).at("source.environments"))?;
        // Settings only: no probe, so a running sandbox's variable names and sign-ins are not read.
        let item = yougori_cli::hub::capture::describe(&environment, state, volumes, &mut taken)
            .map_err(|problem| Diagnostic::new("capture_failed", problem).at("source.environments"))?;
        keys.insert(id.clone(), item.key.clone());
        captured.push(item);
    }
    // Connections between the chosen environments, by the keys they take in the template.
    let connections: Vec<(String, String)> = state["connections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((keys.get(c["sourceId"].as_str()?)?.clone(), keys.get(c["targetId"].as_str()?)?.clone())))
        .collect();

    let name = yougori_cli::hub::capture::slug(&captured[0].key, "captured");
    let (files, mut left_out) = yougori_cli::hub::capture::build(&name, &captured, &connections)
        .map_err(|problem| Diagnostic::new("capture_failed", problem).at("source.environments"))?;

    // The captured template is v1-style (kind: template, no format_version). Mark both files format 2
    // so the builder reads it as a format 2 draft; the environments keep their v1 shape.
    let files = mark_format_2(files)?;

    left_out.push("The names of variables and signed-in tools are not read here. To include them, run yougori template capture, which reads them from a running sandbox.".to_owned());
    Ok((files, left_out))
}

/// Add `format_version: 2` to the top of the template and project files of a v1 package, so it reads
/// as a format 2 package whose environments keep their v1 shape. The template also gains
/// `requires.yougori: 1.2.0` — the release that ships format 2 — which a format 2 template must
/// declare so an older Yougori refuses it before creating anything.
fn mark_format_2(files: format::Files) -> Result<format::Files, Diagnostic> {
    let mut out = format::Files::new();
    for (path, bytes) in files {
        let is_template = path == format::TEMPLATE_FILE;
        let is_project = path == format::PROJECT_FILE;
        if is_template || is_project {
            let text = String::from_utf8(bytes)
                .map_err(|_| Diagnostic::new("capture_failed", "The captured template is not text."))?;
            let text = if is_template { require_yougori(&text) } else { text };
            out.insert(path, format!("format_version: {}\n{text}", format::FORMAT_VERSION).into_bytes());
        } else {
            out.insert(path, bytes);
        }
    }
    Ok(out)
}

/// Ensure a template declares `requires.yougori: 1.2.0`. If it already has a `requires:` block, the
/// line is added inside it (unless it already names yougori); otherwise a `requires:` block is added.
fn require_yougori(template: &str) -> String {
    if template.lines().any(|line| line.trim_start().starts_with("yougori:")) {
        return template.to_owned();
    }
    if let Some(at) = template.find("\nrequires:\n") {
        let insert = at + "\nrequires:\n".len();
        return format!("{}  yougori: 1.2.0\n{}", &template[..insert], &template[insert..]);
    }
    format!("{template}\nrequires:\n  yougori: 1.2.0\n")
}

/// Capture the chosen environments into a format 2 package and check it, for the "make a template
/// from environments" source. `state`/`volumes` are the engine's read-only snapshot, gathered by the
/// caller. Returns the same answer shape as [`validate`], with the capture's omissions as its notes.
pub(crate) async fn validate_environments(hub: &dyn Hub, state: &Value, volumes: &Value, env_ids: &[String]) -> Result<Value, Diagnostic> {
    let (files, notes) = read_environments(state, volumes, env_ids)?;
    checked_answer(hub, files, None, notes).await
}

/// Checks a package and reports every problem against its field, without planning anything. The
/// answer carries the template's and project's text, for a builder that saves them, and the
/// builder's draft of a package that checks.
pub(crate) async fn validate(service: &Service, hub: &dyn Hub, call: ValidateCall) -> Result<Value, Diagnostic> {
    let source = match (call.source, call.draft) {
        (Some(source), _) => source,
        (None, Some(mut draft)) => {
            return Ok(match generated(&draft) {
                Ok(package) => {
                    let files = package.files();
                    let checked = check(&files);
                    // What running the template it makes will ask (an image, a port), so a builder
                    // that runs it here asks them first. Found driving the app: they were never
                    // asked, and planning then refused the unanswered image.
                    if let Ok(checked) = &checked {
                        draft["questions"] = serde_json::to_value(draft::from_checked(checked).0.questions).unwrap_or_default();
                    }
                    let problems = checked.err().unwrap_or_default();
                    json!({
                        "valid": problems.is_empty(),
                        "manifest": package.manifest,
                        "project": package.project,
                        "projectPath": format::PROJECT_FILE,
                        "diagnostics": problems,
                        "notes": package.notes,
                        "added": package.added,
                        // Files it carries beside these two, such as the cloud model gateway.
                        "files": package.extra,
                        "draft": draft,
                    })
                }
                Err(problems) => json!({ "valid": false, "manifest": "", "project": null, "projectPath": format::PROJECT_FILE, "diagnostics": problems, "draft": draft }),
            });
        }
        (None, None) => return Err(Diagnostic::new("invalid_request", "Say which template to check.")),
    };
    // A Compose import is converted here, before the source is read as a template reference, so its
    // notes travel with the answer. Anything the converter could not carry over is a diagnostic.
    let import_notes: Vec<String>;
    let (files, reference) = match source {
        Value::String(yaml) => {
            import_notes = Vec::new();
            (format::Files::from([(format::TEMPLATE_FILE.to_owned(), yaml.into_bytes())]), None)
        }
        Value::Object(ref object) if object.get("kind").and_then(Value::as_str) == Some("compose") => {
            let (files, notes) = read_compose(&source)?;
            import_notes = notes;
            (files, None)
        }
        reference => {
            import_notes = Vec::new();
            let reference: dto::SourceRef = serde_json::from_value(reference)
                .map_err(|_| Diagnostic::new("invalid_request", "The source must be a folder, a Hub template or an installed setup.").at("source"))?;
            let package = read(service, hub, &reference).await?;
            (package.files, Some(package.recorded))
        }
    };
    checked_answer(hub, files, reference, import_notes).await
}

/// An import's plain note as the one shape every validate answer's `notes` has: a diagnostic
/// whose message is the note, at no field, that blocks nothing.
fn note(text: String) -> dto::Diagnostic {
    dto::Diagnostic { severity: dto::Severity::Info, ..dto::Diagnostic::error("import_note", text) }
}

/// What installing these files would be refused for, worded as `yougori template check` and the
/// export word it, so the door in and the door out agree: a credential file or key in the
/// package (`scan`), and a fixed value in a sandbox or a question's default that is someone's
/// own (`personal_v2`). `None` when nothing stands in the way.
fn install_refusal(files: &format::Files, checked: Option<&format::Checked>) -> Option<String> {
    let mut said = yougori_cli::hub::scan::scan(files).refused;
    if let Some(checked) = checked.filter(|checked| checked.format == format::FormatVersion::V2) {
        said.extend(yougori_cli::hub::publish::personal_v2(checked));
    }
    (!said.is_empty()).then(|| said.join(" "))
}

/// Check a package's files and build the validate answer: its texts, diagnostics, a format 2 builder
/// draft, and any import notes. Shared by [`validate`] and [`validate_environments`].
async fn checked_answer(hub: &dyn Hub, files: format::Files, reference: Option<dto::SourceRef>, notes: Vec<String>) -> Result<Value, Diagnostic> {
    let text = |path: &str| files.get(path).map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    let manifest = text(format::TEMPLATE_FILE).unwrap_or_default();
    let checked = match check(&files) {
        Ok(checked) => resolved(hub, checked).await.map(|(checked, _)| checked),
        Err(problems) => Err(problems),
    };
    // Said here as a warning, so a builder sees it before planning; planning refuses it outright.
    let mut notes = notes.into_iter().map(note).collect::<Vec<_>>();
    if let Some(said) = install_refusal(&files, checked.as_ref().ok()) {
        notes.push(dto::Diagnostic::warning("install_refused", format!("This template would not pass yougori template check, so it can't be installed as it is: {said}")));
    }
    let project_path = match &checked {
        Ok(checked) => checked.project_path.clone(),
        // The template's own `project:` line, read plainly, since it didn't check.
        Err(_) => manifest
            .lines()
            .find_map(|line| line.strip_prefix("project:"))
            .map(|value| value.trim().trim_matches(|c| c == '"' || c == '\'').to_owned())
            .filter(|value| yougori_cli::hub::scan::check_path(value).is_ok())
            .unwrap_or_else(|| format::PROJECT_FILE.to_owned()),
    };
    let project = text(&project_path);
    let (diagnostics, draft) = match &checked {
        // The builder edits format 2; a format 1 template is checked and planned as it is.
        Ok(checked) if checked.format == format::FormatVersion::V1 => (Vec::new(), None),
        Ok(checked) => (Vec::new(), Some(builder_draft(checked, reference.as_ref()))),
        Err(problems) => (problems.clone(), None),
    };
    let format_version = format::format_version(&manifest).ok().map(|format| format.number());
    Ok(json!({
        "valid": diagnostics.is_empty(),
        "formatVersion": format_version,
        "manifest": manifest,
        "project": project,
        "projectPath": project_path,
        "diagnostics": diagnostics,
        "draft": draft,
        // What an import (a Compose file or captured environments) carried over, for the builder.
        "notes": notes,
    }))
}

/// Plans a package for a new setup, or as a change to an existing one, and keeps the reviewed
/// plan for `setup_apply`. The answer is `dto::PlanResponse`, plus the engine's step list.
pub(crate) async fn plan(host: &plan::Host, hub: &dyn Hub, service: &Service, call: PlanCall) -> Result<Value, Diagnostic> {
    let Package { files, recorded, digest: package_digest, item, latest, page } = match (&call.source, &call.draft) {
        (Some(reference), _) => read(service, hub, reference).await?,
        (None, Some(value)) => {
            let files = generated(value).map_err(first_problem)?.files();
            let digest = yougori_cli::hub::scan::digest_of(&files);
            Package { files, recorded: from_draft(), digest, item: None, latest: None, page: None }
        }
        (None, None) => return Err(Diagnostic::new("invalid_request", "Say which template to plan.")),
    };
    let checked = check(&files).map_err(first_problem)?;
    // The same refusals the export applies before passing a template on: a package that would
    // hand this computer's credentials or the author's own values to whoever runs it is not
    // installed either. A setup planned again from its own kept package is past this door.
    if !matches!(recorded, dto::SourceRef::InstalledSetup { .. }) {
        if let Some(said) = install_refusal(&files, Some(&checked)) {
            return Err(Diagnostic::new("install_refused", format!("This template would not pass yougori template check, so nothing was planned: {said}")).at(format::TEMPLATE_FILE));
        }
    }
    let (checked, components) = resolved(hub, checked).await.map_err(first_problem)?;
    let package = plan::Package { checked: checked.clone(), components, item, digest: Some(package_digest.clone()) };
    // The Hub page against the files, for a package asked for from the Hub: the page is what the
    // person read, the files are what would run, and a page that promises less is said before
    // anyone agrees. One rule for every door (`hub::review::page_check`); a page that could not be
    // compared says why, so "nothing to compare" never reads as "compared, and the same".
    let page = page.map(|(detail, version)| yougori_cli::hub::review::page_check(&package, &files, detail.as_ref(), &version));
    if let Some(setup) = &call.existing_setup {
        // The same version planned again must resolve to exactly what was locked; a new version
        // resolves a new lock, which the review shows.
        if let Some(locked) = service.lock(setup)? {
            if locked.template.version == checked.template.version() {
                let refused = locked.verify(&package).into_iter().filter(|problem| problem.severity == dto::Severity::Error).collect::<Vec<_>>();
                if !refused.is_empty() {
                    return Err(first_problem(refused));
                }
            }
        }
    }
    // A new setup is called what the person asked, or the template's title. A change keeps the
    // setup's own name unless one is asked for: the CLI's configure and update send none, and
    // planning them under the title renamed the setup (and every `{{instance}}` its parts use).
    let name = match call.name.clone().filter(|name| !name.trim().is_empty()) {
        Some(name) => name,
        None => match &call.existing_setup {
            Some(setup) => service.get(setup).map(|detail| detail.setup.summary.name.clone()).unwrap_or_else(|_| checked.template.title().to_owned()),
            None => checked.template.title().to_owned(),
        },
    };
    let mut chosen = answers(&checked, &call, &instance_name(&name, checked.template.name()));
    // The one drive a template that has the person choose theirs goes on, when there is no other.
    let mut chosen_drive_note: Option<String> = None;
    // The drive the person chose, checked against this computer's drives by the caller, which can
    // see them; the planner puts it on every sandbox. A change to a setup keeps the drive its
    // sandboxes are on: one can't move to another drive in place.
    chosen.storage_drive = call.storage_drive().map(str::to_owned);
    if let Some(setup) = &call.existing_setup {
        let current = service.sandbox_drive(setup)?;
        match (&chosen.storage_drive, &current) {
            (Some(asked), Some(on)) if normal_drive(asked) != normal_drive(on) => {
                return Err(Diagnostic::new("invalid_value", format!("Its sandboxes are on {on}. They can't move to {asked} in place; make a new setup on {asked} and move what you need into it.")).at("storageDrive"));
            }
            (None, Some(_)) => chosen.storage_drive = current,
            _ => {}
        }
    }
    if let Some(answers) = call.draft.as_ref().and_then(|draft| draft["answers"].as_object()) {
        for (id, value) in answers {
            let text = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
            chosen.inputs.entry(id.clone()).or_insert(text);
        }
    }
    let mut conflicts = Vec::new();
    // The version a setup runs and its own answers, when this moves it to another version: what
    // that version was allowed to do is compared with what this one asks for.
    let mut before = None;
    if let Some(setup) = &call.existing_setup {
        // A change to a setup starts from what it was planned with; what the request says wins.
        let (inputs, capabilities, secrets) = service.chosen(setup)?;
        let applied: BTreeMap<String, String> = inputs.into_iter().map(|(id, value)| (id, value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()))).collect();
        // The template it runs now, checked as any package is; one that no longer checks is
        // carried as it was made.
        let base = service.package_files(setup).and_then(|files| format::template(&files).ok());
        if let Some(base) = base.as_ref().filter(|base| base.template.version() != checked.template.version()) {
            before = Some((base.clone(), answered(base, &chosen.instance, &applied, &capabilities, &secrets)));
        }
        let carried = carry(base.as_ref(), &checked, &applied, &capabilities);
        for (id, value) in carried.inputs {
            chosen.inputs.entry(id).or_insert(value);
        }
        for (id, on) in carried.capabilities {
            chosen.capabilities.entry(id).or_insert(on);
        }
        conflicts = carried.conflicts;
        for (id, binding) in secrets {
            chosen.secrets.entry(id).or_insert(binding);
        }
    }
    let planned = plan::plan(&package, &chosen, host).map_err(first_problem)?;
    // A template that keeps its data on the drive the person chooses has them choose it, when
    // this computer has more than one it could go on. A change keeps the drive it is on.
    let chooses_drive = planned.capabilities.iter().any(|capability| capability.id == "data.storage_drive" && capability.enabled);
    if chooses_drive && chosen.storage_drive.is_none() && call.existing_setup.is_none() {
        match call.drives.as_slice() {
            [] => {}
            [only] => chosen_drive_note = Some(only.clone()),
            several => {
                return Err(Diagnostic::new("invalid_value", format!("This template keeps its data on the drive you choose. Choose one of: {}.", several.join(", "))).at("storageDrive"));
            }
        }
    }
    if let Some((base, answers)) = before {
        conflicts.extend(widened(hub, host, base, &answers, &planned.review).await);
    }
    let lock = yougori_setup::lock::Lock::from_plan(&planned);
    let source = Source { reference: recorded, digest: format!("sha256:{package_digest}") };
    let draft = draft(&planned, &checked, name, source, &lock)?;
    let intent = match call.existing_setup {
        Some(setup) => PlanIntent::Update { setup, draft },
        None => PlanIntent::Create(draft),
    };
    let mut reviewed = service.plan_from(intent, Some(planned.digest.clone()), Some(Arc::new(files)))?;
    if let Some(version) = latest {
        reviewed.notes.insert(0, format!("This uses version {version}, the latest today. The setup stays on {version} until you update it."));
    }
    // Said in the review, not only in a log: a person looking at a plan that a real installation
    // would refuse should be able to see why it planned here.
    if let Some(version) = stand_in_version() {
        reviewed.notes.insert(0, format!("This development build checks templates as Yougori {version}, because YOUGORI_DEV_HOST_VERSION is set. A released Yougori would check them as {}, and may refuse what this plans.", env!("CARGO_PKG_VERSION")));
    }
    if let Some(drive) = &chosen.storage_drive {
        reviewed.notes.push(format!("Its sandboxes are stored on {drive}. They stay there: moving one to another drive means making it again."));
    } else if let Some(drive) = &chosen_drive_note {
        reviewed.notes.push(format!("Its sandboxes are stored on {drive}, the one drive of this computer they can go on."));
    }
    // What moving to this version changes about the person's own choices, said before anything.
    for (at, conflict) in conflicts.iter().enumerate() {
        reviewed.notes.insert(at, conflict.message.clone());
    }
    let response = dto::PlanResponse {
        setup_id: Some(reviewed.setup_id.clone()),
        base_revision: reviewed.base_revision,
        digest: planned.digest.clone(),
        review: planned.review.clone(),
        plan: planned,
    };
    let mut value = serde_json::to_value(&response)
        .map_err(|_| Diagnostic::new("invalid_response", "Yougori could not put this plan together."))?;
    value["lock"] = serde_json::to_value(&lock).unwrap_or(Value::Null);
    if !conflicts.is_empty() {
        value["conflicts"] = serde_json::to_value(&conflicts).unwrap_or(Value::Null);
    }
    if let Some(page) = &page {
        value["page"] = yougori_cli::hub::review::page_json(page);
    }
    if let (Some(envelope), Value::Object(engine)) = (value.as_object_mut(), views::plan(&reviewed)) {
        for (key, field) in engine {
            envelope.entry(key).or_insert(field);
        }
    }
    // The plan's product document at a reading of the engine's evidence clock, or why there is
    // none; a plan without one is still reviewed and applied as before.
    let document = super::product::engine_now().await.and_then(|now| super::product::of_plan(&reviewed, now));
    Ok(super::product::attach(value, document))
}

/// A setup's own answers, as the version it runs reads them: folders as bindings, the rest as
/// inputs, and each capability it can choose on or off as it was.
fn answered(base: &format::Checked, instance: &str, applied: &BTreeMap<String, String>, on: &[String], secrets: &BTreeMap<String, String>) -> plan::Answers {
    let bindings = base.bindings.iter().map(|binding| binding.id.as_str()).collect::<BTreeSet<_>>();
    let mut answers = plan::Answers { instance: instance.to_owned(), secrets: secrets.clone(), ..Default::default() };
    for (id, value) in applied {
        if bindings.contains(id.as_str()) {
            answers.bindings.insert(id.clone(), value.clone());
        } else {
            answers.inputs.insert(id.clone(), value.clone());
        }
    }
    answers.capabilities = base
        .capabilities
        .iter()
        .filter(|capability| capability.selection != format::Selection::Required)
        .map(|capability| (capability.id.clone(), on.contains(&capability.id)))
        .collect();
    answers
}

/// What a plan may do and fetch, one line each: its permissions and its downloads.
fn grants(review: &plan::Review) -> BTreeSet<String> {
    let downloads = review.downloads.iter().map(|download| match &download.from {
        Some(from) => format!("download the {} {} from {from}", download.kind, download.name),
        None => format!("download the {} {}", download.kind, download.name),
    });
    review.permissions.iter().cloned().chain(downloads).collect()
}

/// What a new version asks for that the version a setup runs did not, planned with the setup's
/// own answers: each is a conflict the review shows first, so a new version never widens what a
/// setup may do or fetch without saying so. When the version it runs can't be planned again, that
/// is said instead of claiming it adds nothing.
async fn widened(hub: &dyn Hub, host: &plan::Host, base: format::Checked, answers: &plan::Answers, now: &plan::Review) -> Vec<merge::Conflict> {
    let before = match resolved(hub, base).await {
        Ok((base, components)) => plan::plan(&plan::Package { checked: base, components, item: None, digest: None }, answers, host).ok(),
        Err(_) => None,
    };
    match before {
        Some(before) => merge::new_grants(&grants(&before.review), &grants(now)),
        None => vec![merge::Conflict {
            code: merge::ConflictCode::NewGrantToReview,
            message: "Yougori couldn't work out what the version this setup runs was allowed to do, so it can't say what this one adds. Read its permissions and downloads below before you apply it.".into(),
            subject: "permissions".into(),
            action: merge::ConflictAction::Review,
        }],
    }
}

/// What a change to a setup carries from the setup as it is.
#[derive(Debug, Default)]
struct Carried {
    inputs: BTreeMap<String, String>,
    capabilities: BTreeMap<String, bool>,
    conflicts: Vec<merge::Conflict>,
}

/// A question's default, in the form the setup records its answer.
fn default_text(checked: &format::Checked, id: &str) -> Option<String> {
    checked.questions.iter().find(|question| question.id == id)?.default.clone()
}

/// What a change to a setup starts from. Planned again at the version it runs, that is every answer
/// and choice it was made with. Moving to another version (`base` is the template it runs), it is
/// the three-way merge of `yougori_setup::merge`: the person's own answers and choices win, the new
/// version's defaults fill in where they kept the old default, an answer the new version can't take
/// is dropped, and each of those is a conflict the review shows first.
fn carry(base: Option<&format::Checked>, checked: &format::Checked, applied: &BTreeMap<String, String>, on: &[String]) -> Carried {
    let upstream = &checked.template;
    let choosable = |id: &str| checked.capabilities.iter().any(|capability| capability.id == id && capability.selection != format::Selection::Required);
    let Some(base) = base.filter(|base| base.template.version() != upstream.version()) else {
        return Carried {
            inputs: applied.clone(),
            capabilities: checked.capabilities.iter().filter(|capability| choosable(&capability.id)).map(|capability| (capability.id.clone(), on.contains(&capability.id))).collect(),
            conflicts: Vec::new(),
        };
    };
    // The person's own: an answer other than the old default, a capability set other than its default.
    let local = merge::Customization {
        answers: applied.iter().filter(|(id, value)| default_text(base, id).as_deref() != Some(value.as_str())).map(|(id, value)| (id.clone(), value.clone())).collect(),
        capabilities: base
            .capabilities
            .iter()
            .filter(|capability| capability.selection != format::Selection::Required)
            .filter_map(|capability| {
                let now = on.contains(&capability.id);
                (now != (capability.selection == format::Selection::Default)).then(|| (capability.id.clone(), now))
            })
            .collect(),
        added: on.iter().filter(|id| !base.capabilities.iter().any(|capability| &capability.id == *id)).cloned().collect(),
    };
    let locked = |checked: &format::Checked| -> BTreeMap<String, String> {
        checked.questions.iter().filter(|question| !question.editable).filter_map(|question| Some((question.id.clone(), question.default.clone()?))).collect()
    };
    let upstream_locked = locked(checked);
    let merged = merge::merge(&merge::Base { template: base.template.clone(), answers: BTreeMap::new() }, &local, upstream, &BTreeSet::new(), &locked(base), &upstream_locked);
    Carried {
        // A value the new version fixes is its own; the conflict says so.
        inputs: merged.answers.into_iter().filter(|(id, _)| !upstream_locked.contains_key(id)).collect(),
        capabilities: merged.capabilities.into_iter().filter(|(id, _)| choosable(id)).collect(),
        conflicts: merged.conflicts,
    }
}

#[cfg(test)]
mod tests {

    /// PROVES the development stand-in only ever accepts a real version, and that a release build
    /// cannot be talked out of its own. The gate a template relies on — `requires.yougori: 1.2.0`
    /// meaning the release that ships format 2 — is only worth anything if this holds.
    #[test]
    fn a_development_build_takes_a_stand_in_version_only_when_it_is_really_a_version() {
        assert_eq!(stand_in_from(Some("1.2.0")).as_deref(), Some("1.2.0"));
        assert_eq!(stand_in_from(Some("  1.2.0  ")).as_deref(), Some("1.2.0"), "whitespace from a shell is trimmed");
        assert_eq!(stand_in_from(Some("2.0.0-rc.1")).as_deref(), Some("2.0.0-rc.1"));
        // Unset, empty, or anything that is not a version: the build keeps its own.
        assert_eq!(stand_in_from(None), None);
        assert_eq!(stand_in_from(Some("")), None);
        assert_eq!(stand_in_from(Some("   ")), None);
        assert_eq!(stand_in_from(Some("1.2")), None, "a typo is ignored, never rounded up to a version");
        assert_eq!(stand_in_from(Some("latest")), None);
        assert_eq!(stand_in_from(Some("v1.2.0")), None);
        // A release build never reads any of this: `stand_in_version` is `None` there by
        // construction, which is asserted by this function not existing outside debug builds.
        assert!(cfg!(debug_assertions), "this test only compiles in a development build");
    }
    use super::*;

    fn template(version: &str, inputs: &str, capabilities: &str) -> format::Template {
        format::read_yaml(&format!("format_version: 2\nkind: template\nname: shop\nversion: {version}\ncapabilities:\n{capabilities}inputs:\n{inputs}")).unwrap()
    }

    fn checked(template: format::Template) -> format::Checked {
        let text = format::write_yaml(&template).unwrap();
        let text = text.replacen("name: shop\n", "name: shop\ntitle: Shop\nsummary: A small shop.\nlicense: MIT\nrequires: {yougori: 1.2.0}\n", 1);
        let files: format::Files = [(format::TEMPLATE_FILE.to_owned(), text.into_bytes()), (format::PROJECT_FILE.to_owned(), b"format_version: 2\nproject: shop\nenvironments:\n  web: {image: alpine:3.20}\n".to_vec())].into();
        format::template(&files).unwrap_or_else(|problems| panic!("{problems:?}"))
    }

    const CAPS: &str = "  - {id: grid.local_only, selection: required}\n  - {id: web.service, selection: default}\n";

    #[test]
    fn the_same_version_carries_everything_it_was_made_with() {
        let now = checked(template("1.0.0", "  - {id: size, question: Size?, type: text, group: website_api, default: small}\n", CAPS));
        let applied = BTreeMap::from([("size".to_owned(), "small".to_owned())]);
        let carried = carry(Some(&now), &now, &applied, &[]);
        assert_eq!(carried.inputs, applied);
        assert_eq!(carried.capabilities, BTreeMap::from([("web.service".to_owned(), false)]), "turned off stays off");
        assert!(carried.conflicts.is_empty());
    }

    #[test]
    fn a_new_version_keeps_the_persons_choices_and_takes_its_new_defaults() {
        let inputs = |size: &str, extra: &str| format!("  - {{id: size, question: Size?, type: text, group: website_api, default: {size}}}\n  - {{id: color, question: Color?, type: text, group: website_api, default: red}}\n  - {{id: plan, question: Plan?, type: text, group: website_api, default: basic, editable: false}}\n{extra}");
        let base = checked(template("1.0.0", &inputs("small", "  - {id: old, question: Old?, type: text, group: website_api, required: false}\n"), CAPS));
        let upstream = template("2.0.0", &inputs("medium", "  - {id: region, question: Region?, type: text, group: website_api}\n").replace("default: basic", "default: pro"), CAPS);
        let now = checked(upstream);
        // size kept its old default; color and old are the person's; plan was fixed at basic.
        let applied = BTreeMap::from([("size".to_owned(), "small".to_owned()), ("color".to_owned(), "blue".to_owned()), ("old".to_owned(), "x".to_owned()), ("plan".to_owned(), "basic".to_owned())]);
        let carried = carry(Some(&base), &now, &applied, &["web.service".to_owned()]);
        assert_eq!(carried.inputs.get("color").map(String::as_str), Some("blue"), "the person's answer wins");
        assert_eq!(carried.inputs.get("size"), None, "a kept default gives way to the new default");
        assert_eq!(carried.inputs.get("plan"), None, "the new version fixes this one");
        assert_eq!(carried.inputs.get("old"), None, "an answer to a removed question is dropped");
        let codes: Vec<merge::ConflictCode> = carried.conflicts.iter().map(|conflict| conflict.code).collect();
        assert!(codes.contains(&merge::ConflictCode::QuestionRemoved) && codes.contains(&merge::ConflictCode::NewRequiredQuestion), "{codes:?}");
        assert_eq!(carried.capabilities.get("web.service"), Some(&true));
    }

    fn checked_with(template: format::Template, project: &str) -> format::Checked {
        let text = format::write_yaml(&template).unwrap();
        let text = text.replacen("name: shop\n", "name: shop\ntitle: Shop\nsummary: A small shop.\nlicense: MIT\nrequires: {yougori: 1.2.0}\n", 1);
        let files: format::Files = [(format::TEMPLATE_FILE.to_owned(), text.into_bytes()), (format::PROJECT_FILE.to_owned(), project.as_bytes().to_vec())].into();
        format::template(&files).unwrap_or_else(|problems| panic!("{problems:?}"))
    }

    fn host() -> plan::Host {
        use capability::{Arch, Gpu, Host, Os, Runtime};
        plan::Host {
            yougori: "1.2.0".into(),
            platform: "linux-x86_64".into(),
            gpu: Some(false),
            memory_gb: Some(16.0),
            free_disk_gb: Some(200.0),
            capabilities: Host::new(Os::Linux, Arch::X86_64, Gpu::None, vec![Runtime::Containers], true),
        }
    }

    /// A Hub nothing is asked of: these templates import nothing.
    struct Unasked;

    impl Hub for Unasked {
        fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> BoxFuture<'a, Result<Fetched, String>> {
            unreachable!("nothing is fetched")
        }
        fn components<'a>(&'a self, _: &'a format::Checked) -> BoxFuture<'a, Result<BTreeMap<String, plan::Component>, Vec<dto::Diagnostic>>> {
            unreachable!("nothing is imported")
        }
    }

    fn reviewed(checked: &format::Checked, answers: &plan::Answers) -> plan::Review {
        plan::plan(&plan::Package { checked: checked.clone(), components: BTreeMap::new(), item: None, digest: None }, answers, &host()).unwrap_or_else(|problems| panic!("{problems:?}")).review
    }

    /// PROVES a new version can't widen what a setup may fetch or do without the review saying
    /// so first: the image only the new version downloads is named, what both versions do is not,
    /// and a version that adds nothing raises nothing.
    #[tokio::test]
    async fn a_new_version_that_asks_for_more_says_what_before_anything_changes() {
        let project = |extra: &str| format!("format_version: 2\nproject: shop\nenvironments:\n  web: {{image: alpine:3.20}}\n{extra}");
        let base = checked_with(template("1.0.0", "", CAPS), &project(""));
        let now = checked_with(template("2.0.0", "", CAPS), &project("  worker: {image: example/worker:1.0.0}\n"));
        let answers = answered(&base, "shop", &BTreeMap::new(), &[], &BTreeMap::new());
        let raised = widened(&Unasked, &host(), base.clone(), &answers, &reviewed(&now, &answers)).await;
        assert_eq!(raised.len(), 1, "{raised:?}");
        assert_eq!(raised[0].code, merge::ConflictCode::NewGrantToReview);
        assert_eq!(raised[0].message, "The new version asks for \"download the image example/worker:1.0.0\", which the installed version did not.");
        let same = checked_with(template("2.0.0", "", CAPS), &project(""));
        assert!(widened(&Unasked, &host(), base, &answers, &reviewed(&same, &answers)).await.is_empty(), "nothing new, nothing raised");
    }

    /// PROVES that when the version a setup runs can't be planned again, the review says it can't
    /// tell what the new one adds, rather than saying it adds nothing.
    #[tokio::test]
    async fn a_version_that_cannot_be_planned_again_is_never_taken_to_add_nothing() {
        let project = "format_version: 2\nproject: shop\nenvironments:\n  web: {image: alpine:3.20}\n";
        let base = checked_with(template("1.0.0", "  - {id: size, question: Size?, type: text, group: website_api}\n", CAPS), project);
        let now = checked_with(template("2.0.0", "", CAPS), project);
        // The setup's own answers lack what its version requires, so it can't be planned again.
        let answers = answered(&base, "shop", &BTreeMap::new(), &[], &BTreeMap::new());
        let raised = widened(&Unasked, &host(), base, &answers, &reviewed(&now, &answers)).await;
        assert_eq!(raised.len(), 1);
        assert!(raised[0].message.starts_with("Yougori couldn't work out what the version this setup runs was allowed to do"), "{}", raised[0].message);
    }

    #[test]
    fn a_setups_own_answers_are_read_as_the_version_it_runs_reads_them() {
        let base = checked(template("1.0.0", "  - {id: size, question: Size?, type: text, group: website_api, default: small}\n", CAPS));
        let applied = BTreeMap::from([("size".to_owned(), "large".to_owned())]);
        let secrets = BTreeMap::from([("key".to_owned(), "apply.key".to_owned())]);
        let answers = answered(&base, "shop", &applied, &["web.service".to_owned()], &secrets);
        assert_eq!(answers.instance, "shop");
        assert_eq!(answers.inputs, applied);
        assert_eq!(answers.secrets, secrets);
        assert_eq!(answers.capabilities, BTreeMap::from([("web.service".to_owned(), true)]), "only what can be chosen, as it was");
    }

    /// PROVES a drive is taken only when this computer has it, sandboxes can be stored there and
    /// it has room to start them; and that each refusal says why and what to choose.
    #[test]
    fn a_storage_drive_must_be_a_fixed_writable_drive_with_room() {
        let drives = vec![
            json!({"path": "C:\\", "freeGb": 120.0, "readOnly": false, "removable": false}),
            json!({"path": "D:\\", "freeGb": 900.0, "readOnly": false, "removable": false}),
            json!({"path": "E:\\", "freeGb": 50.0, "readOnly": false, "removable": true}),
            json!({"path": "F:\\", "freeGb": 50.0, "readOnly": true, "removable": false}),
            json!({"path": "G:\\", "freeGb": 3.0, "readOnly": false, "removable": false}),
        ];
        // Spelled any way, a known drive is answered as this computer spells it.
        for asked in ["D:\\", "d:/", "D:", " d:\\ "] {
            assert_eq!(check_drive(asked, &drives).unwrap(), "D:\\", "{asked}");
        }
        let refused = |drive: &str| check_drive(drive, &drives).unwrap_err().message;
        assert_eq!(refused("Z:"), "Yougori can't see Z: on this computer. Choose one of: C:\\, D:\\, E:\\, F:\\, G:\\.");
        assert!(refused("E:").contains("removable drive"), "{}", refused("E:"));
        assert!(refused("F:").contains("can only be read"), "{}", refused("F:"));
        assert_eq!(refused("G:"), "G:\\ has 3 GB free; a setup's sandboxes need at least 10 GB to start. Free some space or choose another drive.");
        assert_eq!(check_drive("Z:", &[]).unwrap_err().message, "Yougori can't see Z: on this computer. Leave the drive out to use the usual one.");
        assert_eq!(check_drive("Z:", &drives).unwrap_err().field.as_deref(), Some("storageDrive"));
    }

    #[test]
    fn instance_names_are_what_the_planner_accepts() {
        assert_eq!(instance_name("My Site!", "hello"), "my-site");
        assert_eq!(instance_name("  ", "hello"), "hello");
        assert_eq!(instance_name(&"x".repeat(80), "hello").len(), 40);
    }

    #[test]
    fn a_borrow_names_its_owner_directly_or_through_the_chosen_binding() {
        let direct = format::Borrow { setup: Some("setup-1".into()), resource: Some("db".into()), binding: None };
        assert_eq!(owner_of(&direct, &BTreeMap::new()), Some(OwnerRef { setup: "setup-1".into(), resource: "db".into() }));
        let chosen = BTreeMap::from([("model".to_owned(), "setup-2/llm".to_owned())]);
        let by_binding = format::Borrow { setup: None, resource: None, binding: Some("model".into()) };
        assert_eq!(owner_of(&by_binding, &chosen), Some(OwnerRef { setup: "setup-2".into(), resource: "llm".into() }));
        assert_eq!(owner_of(&by_binding, &BTreeMap::new()), None);
    }

    /// Write a Compose file in a temp folder and return its full path, for the import tests.
    fn compose_file(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-compose.yml");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn a_supported_compose_file_imports_into_a_format_2_package_with_notes() {
        let (_dir, path) = compose_file(
            "name: shop\nservices:\n  web:\n    image: nginx:1.27\n    ports: [\"8080:80\"]\n    environment:\n      MODE: live\n    volumes:\n      - data:/var/www\nvolumes:\n  data:\n",
        );
        let (files, notes) = read_compose(&json!({ "kind": "compose", "path": path.to_string_lossy() })).unwrap();
        // Both files are present and marked format 2, so the package reads as format 2.
        let template = String::from_utf8(files[format::TEMPLATE_FILE].clone()).unwrap();
        let project = String::from_utf8(files[format::PROJECT_FILE].clone()).unwrap();
        assert!(template.contains("format_version: 2"));
        assert!(template.contains("name: shop"));
        assert!(project.starts_with("format_version: 2"));
        assert!(project.contains("nginx:1.27"));
        // The package checks as a valid format 2 package.
        let checked = check(&files).unwrap_or_else(|problems| panic!("{problems:?}"));
        assert_eq!(checked.format, format::FormatVersion::V2);
        // The notes say what came over, in plain words, and never claim a capability was chosen.
        assert!(notes.iter().any(|note| note.contains("Imported 1 service")));
        assert!(notes.iter().any(|note| note.contains("did not pick any capabilities")));
    }

    #[test]
    fn an_unsupported_compose_key_is_refused_with_a_plain_reason_and_nothing_is_imported() {
        // `privileged` is not translated safely; the converter refuses, and the import surfaces that.
        let (_dir, path) = compose_file("name: risky\nservices:\n  app:\n    image: alpine\n    privileged: true\n");
        let error = read_compose(&json!({ "kind": "compose", "path": path.to_string_lossy() })).unwrap_err();
        assert_eq!(error.code, "compose_unsupported");
        assert_eq!(error.field.as_deref(), Some("source.path"));
        assert!(error.message.contains("privileged"));
    }

    #[test]
    fn a_compose_import_needs_a_full_path() {
        assert_eq!(read_compose(&json!({ "kind": "compose" })).unwrap_err().code, "invalid_request");
        assert_eq!(read_compose(&json!({ "kind": "compose", "path": "relative/compose.yml" })).unwrap_err().code, "invalid_request");
    }

    #[test]
    fn chosen_environments_capture_into_a_format_2_package_with_the_capture_s_omissions() {
        // A minimal platform state with one stopped container sandbox, as get_platform_state shapes
        // it (describe() reads kind, runtime, resourcePolicy, storageLimitGb, networkAccess).
        let state = json!({
            "environments": [{
                "id": "env-web", "name": "web", "kind": "container", "runtime": "nginx:1.27",
                "status": "stopped", "networkAccess": true, "gpuAccess": false, "storageLimitGb": 8,
                "resourcePolicy": { "cpu": { "preferred": 1.0 }, "memoryGb": { "preferred": 2.0 } },
            }],
            "connections": [],
        });
        let (files, left_out) = read_environments(&state, &Value::Null, &["env-web".to_owned()]).unwrap();
        // Both files are format 2, and the package checks.
        let template = String::from_utf8(files[format::TEMPLATE_FILE].clone()).unwrap();
        let project = String::from_utf8(files[format::PROJECT_FILE].clone()).unwrap();
        assert!(template.starts_with("format_version: 2"));
        assert!(project.starts_with("format_version: 2"));
        assert_eq!(check(&files).unwrap_or_else(|problems| panic!("{problems:?}")).format, format::FormatVersion::V2);
        // The capture's own omissions are listed, plus the line that variable/sign-in names aren't read.
        assert!(left_out.iter().any(|line| line.contains("not read here") && line.contains("yougori template capture")), "{left_out:?}");
        // A stopped sandbox's variables/sign-ins weren't read (build()'s own line), and disks are left out.
        assert!(left_out.iter().any(|line| line.contains("was not running")), "{left_out:?}");
        assert!(left_out.iter().any(|line| line.to_lowercase().contains("disk")), "{left_out:?}");
    }

    #[test]
    fn capturing_needs_at_least_one_environment_and_a_known_one() {
        assert_eq!(read_environments(&json!({"environments": []}), &Value::Null, &[]).unwrap_err().code, "invalid_request");
        let error = read_environments(&json!({"environments": []}), &Value::Null, &["env-gone".to_owned()]).unwrap_err();
        assert_eq!(error.code, "environment_missing");
        assert_eq!(error.field.as_deref(), Some("source.environments"));
    }
}
