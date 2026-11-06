//! Deterministic, side-effect-free planning and the review a person approves.
//!
//! A plan is computed from a checked package, the answers and a description of this computer.
//! It lists every resource to create or borrow in dependency order, with its resolved spec, and
//! a review of what that means: placement, downloads, permissions, costs, retention. The same
//! package and answers always give the same plan and the same digest. Nothing here creates,
//! downloads, signs in or stores anything.
//!
//! The same module writes the review a publisher uploads to the Hub for a format 2 package:
//! every v1 review key, plus the resources and capabilities, flat enough for the website's limits.
use crate::{
    capability::{self, GridProfile, Host as PlatformHost},
    dto::Diagnostic,
    format::{self, Access, Borrow, Checked, CheckedCapability, Keep, Question, QuestionKind, Retention, Selection, Source, Tool, ToolUse},
    graph::{Graph, Node},
    limits,
    placeholder::{self, Place, Values},
    resource::{self, ComputeSource, Kind, PublicAccess, Reference, Spec},
    text,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use serde_yaml_ng::Value as Yaml;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// A resolved, pinned component: one version of one Hub template with its files checked.
#[derive(Clone, Debug)]
pub struct Component {
    /// `PUBLISHER/NAME`.
    pub item: String,
    pub version: String,
    /// The SHA-256 of the component's files, as downloaded.
    pub digest: String,
    pub checked: Checked,
    pub components: BTreeMap<String, Component>,
}

/// A checked package with its resolved components, as the planner takes it.
#[derive(Clone, Debug)]
pub struct Package {
    pub checked: Checked,
    pub components: BTreeMap<String, Component>,
    /// `PUBLISHER/NAME` when the package came from the Hub.
    pub item: Option<String>,
    /// The digest of the package's files, when known.
    pub digest: Option<String>,
}

impl Package {
    /// A package from a checked folder with no components.
    pub fn local(checked: Checked) -> Package {
        Package { checked, components: BTreeMap::new(), item: None, digest: None }
    }
}

/// What this computer has, for the requirement checks.
#[derive(Clone, Debug)]
pub struct Host {
    /// The running Yougori version.
    pub yougori: String,
    /// One of [`format::PLATFORMS`].
    pub platform: String,
    /// Whether an NVIDIA GPU is usable; `None` when that could not be read.
    pub gpu: Option<bool>,
    pub memory_gb: Option<f64>,
    pub free_disk_gb: Option<f64>,
    /// The platform shape the capability registry judges against.
    pub capabilities: PlatformHost,
}

/// The answers and choices of one run: public answers, the names of private bindings and the
/// optional capabilities the person turned on or off. Never a secret value.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Answers {
    pub instance: String,
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
    /// Secret input id to the name of the binding that holds the value.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    /// Capability id to on or off, for optional and default capabilities.
    #[serde(default)]
    pub capabilities: BTreeMap<String, bool>,
    /// Installation-time bindings by id: the folder, drive or file the person chose. Private to
    /// this installation.
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    /// Run without a GPU when the template makes it optional.
    #[serde(default)]
    pub without_gpu: bool,
    /// The drive every sandbox is stored on, chosen at the instance's first run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_drive: Option<String>,
}

// ---- The plan ----

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub format_version: u64,
    pub instance: String,
    pub template: PlanTemplate,
    pub requires: PlanRequires,
    pub capabilities: Vec<PlannedCapability>,
    /// The public answers that were used, by input id. Secrets are never here.
    pub inputs: BTreeMap<String, String>,
    /// Secret input id to the name of the binding that holds it.
    pub secrets: BTreeMap<String, String>,
    /// Installation-time bindings that were used, by id. Private to this installation.
    pub bindings: BTreeMap<String, String>,
    /// Every resource in dependency order.
    pub resources: Vec<PlannedResource>,
    pub order: Vec<String>,
    pub steps: Vec<PlannedStep>,
    pub outputs: Vec<PlannedOutput>,
    pub retention: PlanRetention,
    pub views: Vec<String>,
    pub review: Review,
    /// SHA-256 of the plan with this field empty: the same inputs give the same digest.
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanTemplate {
    pub name: String,
    pub version: String,
    pub format_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub components: BTreeMap<String, Pinned>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pinned {
    pub item: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRequires {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yougori: Option<String>,
    pub gpu: String,
    pub platforms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedCapability {
    pub id: String,
    pub selection: String,
    pub locked: bool,
    /// Whether its condition holds for these answers.
    pub applies: bool,
    pub enabled: bool,
    pub group: String,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedResource {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    pub depends_on: Vec<String>,
    /// The existing resource this one attaches instead of creating anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrow: Option<Borrow>,
    pub retention: PlanRetention,
    /// Where it runs, in words.
    pub placement: String,
    /// The resolved spec in its kind's type, as JSON.
    pub spec: Json,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedStep {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub label: String,
    /// With the answers filled in; placeholders for what exists only after the setup is applied
    /// stay as written for the engine to finish.
    pub value: String,
    pub private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanRetention {
    pub on_stop: String,
    pub on_remove: String,
}

impl Default for PlanRetention {
    fn default() -> PlanRetention {
        Retention::default().into()
    }
}

impl From<Retention> for PlanRetention {
    fn from(retention: Retention) -> PlanRetention {
        PlanRetention { on_stop: retention.on_stop.id().to_owned(), on_remove: retention.on_remove.id().to_owned() }
    }
}

// ---- The review ----

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    /// What the setup creates, in order.
    pub creates: Vec<ReviewItem>,
    /// Existing resources it attaches and never destroys.
    pub borrows: Vec<ReviewItem>,
    pub downloads: Vec<Download>,
    /// What the setup is allowed to do, in plain sentences.
    pub permissions: Vec<String>,
    pub costs: Vec<String>,
    /// Warnings, most serious first.
    pub warnings: Vec<String>,
    /// Things to know about this computer before saying yes.
    pub notes: Vec<String>,
    pub totals: Totals,
    pub questions: Vec<ReviewQuestion>,
    pub pc_access: Vec<PcFolder>,
    pub public: Vec<PublicEntry>,
    pub retention: PlanRetention,
    /// Every secret a resource receives, and where it comes from: a question of the template or
    /// a tool's key. A plan never carries a secret the person did not give it.
    #[serde(default)]
    pub secrets: Vec<SecretSource>,
    /// What each tool runs in its sandbox when it is installed, line by line, and its check: a
    /// tool bundled with the template, or one from the Hub resolved for this review. Applying runs
    /// exactly these. Built-in tools are Yougori's own and are not listed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub installs: Vec<ToolLines>,
    /// The most the setup may use, as its template caps it (`run.quotas`): one line each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolLines {
    pub resource: String,
    pub tool: String,
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretSource {
    pub resource: String,
    /// The variable or name the resource receives it as.
    pub variable: String,
    /// Where the value comes from, in words: "the question api_key", "the key of the tool aider".
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewItem {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    pub placement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Download {
    /// `image`, `model`, `tool` or `installer`.
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// A Hub tool's version and the digest of its files, as resolved before this review: what
    /// is applied is exactly this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Whether the Hub marks that version Verified; `None` when that is not known here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    pub environments: usize,
    pub cpu: f64,
    pub memory_gb: f64,
    pub storage_gb: f64,
    pub gpu: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewQuestion {
    pub id: String,
    pub question: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
    pub secret: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PcFolder {
    pub environment: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub read_only: bool,
    /// The folder binding the person chose this folder for, when it is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    /// The sandbox keeps a copy, kept in step by Yougori's sync, rather than reaching the folder.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sync: bool,
    /// A VM sandbox works on a staged copy: the folder changes only with files the person
    /// approves after a review.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub staged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicEntry {
    pub resource: String,
    pub port: u16,
    pub access: String,
}

fn problem(code: &'static str, message: impl Into<String>) -> Diagnostic {
    Diagnostic::error(code, message)
}

/// A number as JSON: whole numbers without a fraction, so `2` and not `2.0`.
pub fn number(value: f64) -> Json {
    if value.fract() == 0.0 && value.abs() < 1e15 { json!(value as i64) } else { json!(value) }
}

/// The SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical JSON: sorted keys, no spaces, as serde_json writes a BTreeMap-backed value.
pub fn canonical(value: &Json) -> String {
    fn sort(value: &Json) -> Json {
        match value {
            Json::Object(fields) => {
                let sorted: BTreeMap<&String, Json> = fields.iter().map(|(k, v)| (k, sort(v))).collect();
                Json::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
            }
            Json::Array(items) => Json::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(value)).unwrap_or_default()
}

/// The digest of a plan: SHA-256 of its canonical JSON with the digest field empty.
pub fn digest_of(plan: &Plan) -> String {
    let mut copy = plan.clone();
    copy.digest = String::new();
    sha256_hex(canonical(&serde_json::to_value(&copy).unwrap_or(Json::Null)).as_bytes())
}

// ---- Resolving answers ----

/// The answers of one scope (the template, or one imported component), resolved.
#[derive(Clone, Debug, Default)]
struct Resolved {
    inputs: BTreeMap<String, String>,
    secrets: BTreeMap<String, String>,
    asked: Vec<Question>,
}

/// Walks the questions in order: asks each whose condition holds, takes the answer or the
/// default, and checks it. Missing required answers are `awaiting_input`, one per question, so a
/// client can ask them all.
fn resolve_inputs(questions: &[Question], given: &BTreeMap<String, String>, secrets: &BTreeMap<String, String>, scope: &str, problems: &mut Vec<Diagnostic>) -> Resolved {
    let mut resolved = Resolved::default();
    for question in questions {
        if !question.asked(&resolved.inputs) {
            continue;
        }
        let field = if scope.is_empty() { format!("inputs.{}", question.id) } else { format!("imports.{scope}.inputs.{}", question.id) };
        resolved.asked.push(question.clone());
        if question.kind == QuestionKind::Secret {
            match secrets.get(&question.id) {
                Some(binding) if resource::identifier(binding) => {
                    resolved.secrets.insert(question.id.clone(), binding.clone());
                }
                Some(_) => problems.push(problem("invalid_value", format!("The secret {} must be given as the name of a stored binding, never as a value.", question.id)).at(field)),
                None if question.required => problems.push(problem("awaiting_input", format!("{} needs an answer: {}", question.id, question.question)).at(field)),
                None => {}
            }
            continue;
        }
        // An optional question answered with nothing is a question not answered, as in v1.
        let supplied = given.get(&question.id).map(String::as_str).filter(|s| question.required || question.kind == QuestionKind::MultiChoice || !s.trim().is_empty());
        if !question.editable {
            if supplied.is_some_and(|s| Some(s) != question.default.as_deref()) {
                problems.push(problem("fixed_value", format!("{} is fixed by the template to {}; it cannot be changed.", question.id, question.default.clone().unwrap_or_default())).at(field.clone()));
            }
        }
        let text = if question.editable { supplied.map(str::to_owned).or_else(|| question.default.clone()) } else { question.default.clone() };
        match text {
            Some(text) => match question.answer(&text, None) {
                Ok(normal) => {
                    resolved.inputs.insert(question.id.clone(), normal);
                }
                Err(error) => problems.push(problem("invalid_answer", format!("{}: {error}", question.id)).at(field)),
            },
            None if question.required && question.kind != QuestionKind::MultiChoice => problems.push(problem("awaiting_input", format!("{} needs an answer: {}", question.id, question.question)).at(field)),
            None if question.kind == QuestionKind::MultiChoice => {
                resolved.inputs.insert(question.id.clone(), String::new());
            }
            None => {}
        }
    }
    resolved
}

/// The capabilities of one scope, decided.
#[derive(Clone, Debug)]
struct Decided {
    id: String,
    selection: Selection,
    locked: bool,
    applies: bool,
    enabled: bool,
}

fn decide_capabilities(capabilities: &[CheckedCapability], inputs: &BTreeMap<String, String>, choices: &BTreeMap<String, bool>, turned_on: &[String], host: &Host, profile: Option<GridProfile>, scope: &str, problems: &mut Vec<Diagnostic>) -> Vec<Decided> {
    let field = |id: &str| if scope.is_empty() { format!("capabilities.{id}") } else { format!("imports.{scope}.capabilities.{id}") };
    let mut decided = Vec::new();
    for use_ in capabilities {
        let applies = use_.when.as_ref().is_none_or(|when| when.holds(inputs));
        let chosen = if scope.is_empty() { choices.get(&use_.id).copied() } else { turned_on.contains(&use_.id).then_some(true) };
        let enabled = applies
            && match use_.selection {
                Selection::Required => true,
                Selection::Default => {
                    if use_.locked && chosen == Some(false) {
                        problems.push(problem("locked_capability", format!("{} is part of this template and cannot be turned off.", use_.id)).at(field(&use_.id)));
                    }
                    !use_.locked && chosen == Some(false) || use_.locked || chosen != Some(false)
                }
                Selection::Optional => {
                    if use_.locked && chosen == Some(true) {
                        problems.push(problem("locked_capability", format!("{} is left out by this template and cannot be turned on.", use_.id)).at(field(&use_.id)));
                    }
                    !use_.locked && chosen == Some(true)
                }
            };
        let enabled = match use_.selection {
            Selection::Default => applies && (use_.locked || chosen != Some(false)),
            _ => enabled,
        };
        decided.push(Decided { id: use_.id.clone(), selection: use_.selection, locked: use_.locked, applies, enabled });
    }
    let selected: Vec<&str> = decided.iter().filter(|d| d.enabled).map(|d| d.id.as_str()).collect();
    for item in decided.iter().filter(|d| d.enabled) {
        let Some(cap) = capability::find(&item.id) else {
            problems.push(problem("unknown_capability", format!("{} is not a capability this Yougori offers, so this setup cannot be created here.", item.id)).at(field(&item.id)));
            continue;
        };
        if !cap.enableable_for(&host.capabilities, profile) {
            // This computer could run it, but this kind of grid doesn't: say that, not "this computer".
            let reason = match profile {
                Some(profile) if cap.enableable_for(&host.capabilities, None) => format!("{} setups don't offer it. Turn it off, or use a template for another kind of setup.", profile_name(profile)),
                _ => cap.reason(&host.capabilities).unwrap_or("This capability is not available on this computer.").to_owned(),
            };
            problems.push(problem("capability_not_enableable", format!("{} ({}) cannot be enabled: {reason}", cap.name, cap.id)).at(field(&item.id)));
        } else if cap.id.starts_with("research.") && profile != Some(GridProfile::SwarmMiningGrid) {
            // Research runs in a research realm of its own and is never mixed into another setup,
            // so a template without that profile can't turn it on even though the catalogue lists it.
            problems.push(problem("capability_not_enableable", format!("{} ({}) cannot be enabled: it runs on a Swarm Mining Grid only. Use a Swarm Mining Grid template.", cap.name, cap.id)).at(field(&item.id)));
        }
        for group in cap.missing_for(&selected, profile) {
            problems.push(problem("capability_requires", format!("{} needs one of {} turned on as well.", cap.id, group.join(", "))).at(field(&item.id)));
        }
        for conflict in cap.conflicts.iter().filter(|c| selected.contains(c)) {
            if cap.id < *conflict {
                problems.push(problem("capability_conflict", format!("{} and {conflict} cannot both be on.", cap.id)).at(field(&item.id)));
            }
        }
    }
    decided
}

/// One scope of the plan: the template or an imported component, with its answers decided.
struct Scope {
    namespace: String,
    checked: Checked,
    resolved: Resolved,
    decided: Vec<Decided>,
}

fn pinned_of(component: &Component) -> Pinned {
    Pinned { item: component.item.clone(), version: component.version.clone(), digest: component.digest.clone() }
}

/// Resolves every imported component against its pin and the template's answers. A component
/// with imports of its own is refused: [`limits::IMPORT_DEPTH`] is one level.
fn resolve_components(parent: &Checked, parent_resolved: &Resolved, components: &BTreeMap<String, Component>, namespace: &str, host: &Host, scopes: &mut Vec<Scope>, pins: &mut BTreeMap<String, Pinned>, problems: &mut Vec<Diagnostic>) {
    for (name, import) in &parent.template.imports {
        let path = if namespace.is_empty() { name.clone() } else { format!("{namespace}.{name}") };
        let Some(component) = components.get(name) else {
            problems.push(problem("missing_component", format!("imports: {path}: the component {}@{} was not resolved, so the plan cannot be made.", import.item, import.version.clone().unwrap_or_default())).at(format!("imports.{path}")));
            continue;
        };
        if component.item != import.item || Some(component.version.as_str()) != import.version.as_deref() {
            problems.push(problem("digest_mismatch", format!("imports: {path}: the template pins {}@{}, but {}@{} was resolved. Nothing was created.", import.item, import.version.clone().unwrap_or_default(), component.item, component.version)).at(format!("imports.{path}")));
            continue;
        }
        if component.digest != import.digest {
            problems.push(problem("digest_mismatch", format!("imports: {path}: the files of {}@{} changed since the template pinned them (digest {} now, {} pinned). Refusing to use code that was not reviewed; update the pin after reviewing the new version.", import.item, component.version, text::shown(&component.digest), text::shown(&import.digest))).at(format!("imports.{path}")));
            continue;
        }
        if !component.checked.template.imports.is_empty() {
            problems.push(problem("unsupported_here", format!("imports: {path}: {} imports components of its own; nested imports are not supported, so a component must be complete in itself.", component.item)).at(format!("imports.{path}")));
            continue;
        }
        pins.insert(path.clone(), pinned_of(component));
        // The component's answers come from the import, never from the person.
        let mut given = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        for (id, value) in &import.inputs {
            match value {
                Yaml::String(text) if text.contains("{{") => {
                    if let Some(from) = placeholder::whole_input(text) {
                        if let Some(answer) = parent_resolved.inputs.get(&from) {
                            given.insert(id.clone(), answer.clone());
                        }
                    } else if let Some(from) = placeholder::whole_secret(text) {
                        if let Some(binding) = parent_resolved.secrets.get(&from) {
                            secrets.insert(id.clone(), binding.clone());
                        }
                    }
                }
                Yaml::Sequence(items) => {
                    given.insert(id.clone(), items.iter().filter_map(format::scalar_text).collect::<Vec<_>>().join(","));
                }
                other => {
                    if let Some(text) = format::scalar_text(other) {
                        given.insert(id.clone(), text);
                    }
                }
            }
        }
        for id in given.keys().chain(secrets.keys()) {
            if !component.checked.questions.iter().any(|q| &q.id == id) {
                problems.push(problem("unknown_input", format!("imports: {path}: {} is not an input of {}.", id, component.item)).at(format!("imports.{path}.inputs.{id}")));
            }
        }
        let mut inner = Vec::new();
        let resolved = resolve_inputs(&component.checked.questions, &given, &secrets, &path, &mut inner);
        problems.extend(inner.into_iter().map(|mut p| {
            if p.code == "awaiting_input" {
                p.code = std::borrow::Cow::Borrowed("missing_import_input");
                p.message = format!("imports: {path}: {} Give it under imports.{path}.inputs.", p.message);
            }
            p
        }));
        let decided = decide_capabilities(&component.checked.capabilities, &resolved.inputs, &BTreeMap::new(), &import.capabilities, host, component.checked.profile, &path, problems);
        scopes.push(Scope { namespace: path, checked: component.checked.clone(), resolved, decided });
    }
}

fn values_of(scope: &Scope, instance: &str) -> Values {
    Values {
        instance: instance.to_owned(),
        inputs: scope.resolved.inputs.clone(),
        types: scope.checked.types(),
        secrets: scope.resolved.secrets.clone(),
        partial: true,
        ..Values::default()
    }
}

fn placement_words(spec: &Spec, pools: &BTreeMap<String, ComputeSource>, grids: &BTreeMap<String, resource::Coordinator>) -> String {
    let pool = |reference: &resource::Reference| match reference.local().and_then(|id| pools.get(id)) {
        None if reference.binding.is_some() => "an existing pool of another setup".to_owned(),
        Some(ComputeSource::ThisComputer) | None => "this computer".to_owned(),
        Some(ComputeSource::SelectedComputers) => "the selected computers".to_owned(),
        Some(ComputeSource::Cloud) => "rented cloud compute".to_owned(),
        Some(ComputeSource::Any) => "any computer of the grid".to_owned(),
    };
    match spec {
        Spec::Environment(spec) => match spec.kind.as_str() {
            "cloud" => "a cloud server".into(),
            "shared" => "a shared sandbox".into(),
            _ => "this computer".into(),
        },
        Spec::Grid(spec) => match spec.coordinator {
            resource::Coordinator::ThisComputer => "coordinated by this computer".into(),
            resource::Coordinator::Remote => "coordinated by another computer".into(),
        },
        Spec::ComputePool(spec) => match spec.source {
            ComputeSource::ThisComputer => "this computer".into(),
            ComputeSource::SelectedComputers => format!("{} selected computers", spec.computers.len()),
            ComputeSource::Cloud => "rented cloud compute".into(),
            ComputeSource::Any => "any computer of the grid".into(),
        },
        Spec::WorkerGroup(spec) => pool(&spec.pool),
        Spec::ModelService(spec) => spec.compute.as_ref().map(pool).unwrap_or_else(|| "this computer".into()),
        Spec::WorkspacePool(spec) => pool(&spec.compute),
        Spec::Job(spec) => spec.compute.as_ref().map(pool).unwrap_or_else(|| "this computer".into()),
        Spec::AccessBinding(spec) => match &spec.grid {
            Some(grid) => on_grid(grids, grid),
            None => "this computer".into(),
        },
        Spec::CredentialBroker(spec) => on_grid(grids, &spec.grid),
        Spec::ServicePublication(_) | Spec::Volume(_) | Spec::Connection(_) | Spec::ArtifactStore(_) => "this computer".into(),
        Spec::VmSandbox(vm) => vm.remote.as_ref().map_or_else(|| "a restricted VM on this computer".into(), |remote| format!("a restricted VM on SSH connection {}", remote.connection.as_str())),
    }
}

fn on_grid(grids: &BTreeMap<String, resource::Coordinator>, grid: &resource::Reference) -> String {
    match grid.local().and_then(|id| grids.get(id)) {
        Some(resource::Coordinator::Remote) => "the grid's coordinator".into(),
        None if grid.binding.is_some() => "the existing grid of another setup".into(),
        _ => "this computer".into(),
    }
}

/// A template's limits with these answers, as numbers. One whose answer isn't a number is left out:
/// the template check already made sure each names a number question.
fn limits_of(limits: &BTreeMap<String, Yaml>, values: &placeholder::Values) -> BTreeMap<String, f64> {
    limits
        .iter()
        .filter_map(|(key, value)| {
            let number = match value {
                Yaml::Number(number) => number.as_f64(),
                Yaml::String(text) => placeholder::render(text, values).ok().and_then(|text| text.trim().parse::<f64>().ok()),
                _ => None,
            }?;
            (number.is_finite() && number > 0.0).then(|| (key.clone(), number))
        })
        .collect()
}

/// What a plan creates, in the terms its limits count.
fn usage(totals: &Totals, resources: &[PlannedResource], specs: &BTreeMap<String, Spec>) -> BTreeMap<&'static str, f64> {
    let count = |kind: Kind| resources.iter().filter(|resource| resource.kind == kind && resource.borrow.is_none()).count() as f64;
    let people = specs.values().filter(|spec| matches!(spec, Spec::AccessBinding(binding) if binding.person.is_some() || binding.admin.is_some())).count() as f64;
    let workspaces: f64 = specs.values().map(|spec| match spec {
        Spec::WorkspacePool(pool) => f64::from(pool.count.max(1)),
        _ => 0.0,
    }).sum();
    BTreeMap::from([
        ("cpu", totals.cpu),
        ("memory_gb", totals.memory_gb),
        ("disk_gb", totals.storage_gb),
        ("sandboxes", count(Kind::Environment)),
        ("jobs", count(Kind::Job)),
        ("models", count(Kind::ModelService)),
        ("people", people),
        ("workspaces", workspaces),
    ])
}

/// Where the guest agent mounts a VM sandbox's staged workspace.
pub const VM_WORKSPACE_TARGET: &str = "/run/yougori/workspace";

/// A duration in minutes as a review says it.
fn minutes_words(minutes: u64) -> String {
    match minutes {
        m if m % 60 == 0 && m >= 60 => format!("{} hour{}", m / 60, if m == 60 { "" } else { "s" }),
        1 => "1 minute".to_owned(),
        m => format!("{m} minutes"),
    }
}

/// What a VM sandbox is allowed, in the review's plain sentences: where it runs, what it can
/// reach and with which credential, what it works on, and when it stops.
pub fn vm_sandbox_lines(id: &str, vm: &resource::VmSandboxSpec) -> Vec<String> {
    if let Some(remote) = &vm.remote {
        return vec![
            format!("{id} runs the minimal guest on SSH connection {}, using {} at {} with engine SHA-256 {} and up to {} GB of remote memory.", remote.connection.as_str(), remote.program.as_str(), remote.endpoint.as_str(), remote.engine_sha256.as_str(), shown_amount(vm.memory_gb)),
            format!("It depends on local VM {} and its current lease, for at most {}. The host must already have an owner-confirmed SSH key. The server operator remains trusted; this is not hardware attestation.", remote.parent.local().unwrap_or("unknown"), minutes_words(vm.lifetime().unwrap_or(60))),
            "The template copies no credential and grants no host trust. The remote guest has no host folders or declared network routes. Work is sent through the existing remote sandbox commands.".into(),
            "An interrupted step finds its original run. Stopping waits for exact native end proof; uncertainty stays visible. The server itself stays on and its externally managed charges are not declared stopped.".into(),
        ];
    }
    let mut lines = vec![format!(
        "{id} runs in a restricted virtual machine on this computer: the pinned minimal Linux guest that comes with Yougori, with up to {} GB of memory, no network and none of your files except what is listed here.",
        shown_amount(vm.memory_gb)
    )];
    if vm.internet || vm.application.is_some() {
        lines[0] = format!("{id} runs in a restricted virtual machine on this computer, with {} CPUs and up to {} GB of memory. Your host files are not accessible unless separately granted.", vm.cpu, shown_amount(vm.memory_gb));
    }
    if vm.gpu {
        lines.push(format!("{id} uses this computer's GPU inside its VM. A compatible local GPU runtime and Windows approval may be required; GPU access is shared with the host, not a dedicated hardware partition."));
    }
    if let Some(image) = vm.image_id() {
        lines.push(format!("{id} runs the entrypoint of OCI image {image}, already imported by you on this computer. Its files are copied into its own bounded writable root; another sandbox's changes are not shared. Launch fails if the image is missing or its root needs more memory than reserved."));
    }
    if let Some(app) = &vm.application {
        lines.push(format!("{id} imports OCI image {} and runs {} inside the VM using source {}. Setup answers are delivered privately; its setup hook runs before the app starts.", app.image.as_str(), app.command.iter().map(|arg| text::shown(arg.as_str())).collect::<Vec<_>>().join(" "), app.source.as_str()));
        for kind in app.grids.keys() { lines.push(format!("{id} can host {} when enabled by its setup answer.", if kind == "sandbox" { "Sandbox Grid (CPU and memory)" } else { "GPU Grid" })); }
    }
    if vm.internet {
        lines.push(format!("{id} has full outbound internet and local-network access, with no inbound forwarding or host-file access."));
    } else if vm.routes.is_empty() {
        lines.push(if vm.application.is_some() && !vm.connect.is_empty() {format!("{id} has no general internet access. Only the declared sandbox connections may be granted.")} else {format!("{id} has no network at all.")});
    }
    for route in &vm.routes {
        let operations: Vec<String> = route.operations.iter().map(|operation| format!("{} {}", operation.method(), operation.path.as_str())).collect();
        let port = if route.port == 443 { String::new() } else { format!(" (port {})", route.port) };
        let credential = match &route.credential {
            Some(credential) => format!(", carrying the credential {} you enrolled with yougori sandbox credential enroll; the sandbox never sees it", credential.name.as_str()),
            None => String::new(),
        };
        lines.push(format!("{id} can reach {}{port} for {} and nothing else there, through Yougori's relay{credential}.", route.host.as_str(), operations.join(", ")));
    }
    for published in &vm.publish {
        lines.push(format!(
            "{id} may serve {} (its port {} inside the sandbox) on this computer, and only after you publish it: to you at the address it gives, or to anyone on this computer if you choose; each publication expires, and all of them answer 8 MiB at most.",
            published.service.as_str(),
            published.port
        ));
    }
    if let Some(workspace) = &vm.workspace {
        let folder = vm.workspace_folder.clone().unwrap_or_else(|| format::described_folder(&workspace.binding));
        lines.push(format!(
            "{id} works on a copy of {folder}, the folder you chose for {}, at {VM_WORKSPACE_TARGET}. Your folder changes only when you review the copy's changes and approve them, file by file. Files with credentials in their names and links are left out of the copy, which holds at most {} GB with the sandbox's own changes; a larger folder is refused.",
            workspace.binding,
            shown_amount(resource::VM_WORKSPACE_MOST_GB)
        ));
    }
    let idle = vm.idle().unwrap_or(resource::VM_LONGEST_IDLE_MINUTES);
    let lifetime = vm.lifetime().unwrap_or(resource::VM_LONGEST_LIFETIME_MINUTES);
    if idle == 0 && lifetime == 0 {
        lines.push(format!("{id} has no automatic expiry. Stopping Yougori or this computer stops its VM; starting the setup again keeps the application's private workspace."));
    } else { lines.push(format!(
        "{id} stops after {} without a command and after {} in all; starting the setup again launches a fresh one{}.",
        minutes_words(idle),
        minutes_words(lifetime),
        if vm.workspace.is_some() { " with a fresh copy, and the earlier copy stays for you to review" } else { "" }
    )); }
    lines
}

/// The connections between this setup's VM sandboxes (M14). Each `connect` entry is its sandbox's
/// end of a grant; the other end is the named sandbox's `publish` entry for the service, which must
/// accept it. A connection without both ends, or an acceptance naming no VM sandbox of the setup,
/// is refused here, before anything is made.
pub fn vm_connection_problems(specs: &BTreeMap<String, Spec>) -> Vec<Diagnostic> {
    let mut problems = Vec::new();
    for (id, spec) in specs {
        let Spec::VmSandbox(vm) = spec else { continue };
        if let Some(remote) = &vm.remote {
            if let Some(parent) = remote.parent.local() {
                if matches!(specs.get(parent), Some(Spec::VmSandbox(vm)) if vm.remote.is_some()) {
                    problems.push(problem("invalid_value", format!("{id}: remote.parent {parent} must run locally; chained remote delegation is not supported by this template profile.")).at(id.clone()));
                }
            }
        }
        for connection in &vm.connect {
            let target = connection.target().unwrap_or_default();
            let callee = match specs.get(target) {
                Some(Spec::VmSandbox(callee)) => callee,
                Some(_) => {
                    problems.push(problem("invalid_value", format!("{id}: connect {}: {target} is not a VM sandbox.", connection.name.as_str())).at(id.clone()));
                    continue;
                }
                None => {
                    problems.push(problem("unknown_resource", format!("{id}: connect {}: {} is not a resource of this setup.", connection.name.as_str(), text::shown(target))).at(id.clone()));
                    continue;
                }
            };
            if target == id {
                problems.push(problem("invalid_value", format!("{id}: connect {}: a VM sandbox reaches its own services directly, not through a connection.", connection.name.as_str())).at(id.clone()));
                continue;
            }
            let service = connection.service.as_str();
            // The port its programs use is the service's unless it names one; it may not be a port
            // a service of its own listens on (its guest's agent listens there for the connection).
            if let Some(published) = callee.publish.iter().find(|published| published.service.as_str() == service) {
                let port = connection.port.unwrap_or(published.port);
                if vm.publish.iter().any(|own| own.port == port) {
                    problems.push(problem("invalid_value", format!("{id}: connect {}: port {port} is a service of {id} itself; give the connection another port.", connection.name.as_str())).at(id.clone()));
                }
            }
            match callee.publish.iter().find(|published| published.service.as_str() == service) {
                None => problems.push(problem("invalid_value", format!("{id}: connect {}: {target} declares no service {service}.", connection.name.as_str())).at(id.clone())),
                Some(published) if !published.accept.iter().any(|caller| caller.as_str() == id) => problems.push(problem(
                    "invalid_value",
                    format!("{id}: connect {}: {target} does not accept {id} for {service}. A connection needs both ends: add {id} to the accept list of {target}'s {service}.", connection.name.as_str()),
                ).at(id.clone())),
                Some(_) => {}
            }
        }
        for published in &vm.publish {
            for caller in &published.accept {
                match specs.get(caller.as_str()) {
                    Some(Spec::VmSandbox(_)) => {}
                    Some(_) => problems.push(problem("invalid_value", format!("{id}: publish {}: accept names {}, which is not a VM sandbox.", published.service.as_str(), caller.as_str())).at(id.clone())),
                    None => problems.push(problem("unknown_resource", format!("{id}: publish {}: accept names {}, which is not a resource of this setup.", published.service.as_str(), text::shown(caller.as_str()))).at(id.clone())),
                }
            }
        }
    }
    problems
}

/// What a review says of the connections between this setup's VM sandboxes: each grant, from both
/// its ends.
pub fn vm_connection_lines(specs: &BTreeMap<String, Spec>) -> Vec<String> {
    let mut lines = Vec::new();
    for (id, spec) in specs {
        let Spec::VmSandbox(vm) = spec else { continue };
        for connection in &vm.connect {
            let Some(target) = connection.target() else { continue };
            let Some(Spec::VmSandbox(callee)) = specs.get(target) else { continue };
            let service = connection.service.as_str();
            let Some(published) = callee.publish.iter().find(|published| published.service.as_str() == service) else { continue };
            let port = connection.port.unwrap_or(published.port);
            lines.push(format!(
                "{id} may connect to {service} of {target} (its port {}) as {}:{port}, by any TCP protocol, for {} after each start; each connection carries at most {} bytes each way, and {target}'s answers count toward its 8 MiB release bound. Nothing else of {target} is reachable from {id}.",
                published.port,
                connection.name.as_str(),
                minutes_words(connection.grant_minutes()),
                connection.budget()
            ));
            lines.push(format!("{target} accepts {id}'s connections to {service}: the grant's other end; {target} gains nothing of {id}."));
        }
    }
    lines
}

/// A number as a review says it: whole when it is whole.
fn shown_amount(value: f64) -> String {
    if (value - value.round()).abs() < 1e-9 { format!("{}", value.round() as i64) } else { format!("{value:.1}") }
}

/// The plan for a package with these answers on this computer, or every reason there is none.
pub fn plan(package: &Package, answers: &Answers, host: &Host) -> Result<Plan, Vec<Diagnostic>> {
    let checked = &package.checked;
    let mut problems: Vec<Diagnostic> = Vec::new();
    let instance = answers.instance.trim();
    if !resource::identifier(instance) || instance.len() > 40 {
        problems.push(problem("invalid_value", "The instance name must use 1 to 40 letters, digits, dots, dashes or underscores.").at("instance".to_owned()));
    }
    // This computer.
    if let Some(needed) = checked.template.requires.yougori.as_deref() {
        if format::newer(needed, &host.yougori) {
            problems.push(problem("needs_newer_yougori", format!("This template needs Yougori {needed} or newer. Update with yougori update.")).at("requires.yougori".to_owned()));
        }
    }
    let platforms = &checked.template.requires.platforms;
    if !platforms.is_empty() && !platforms.contains(&host.platform) {
        problems.push(problem("unsupported_here", format!("This template runs on {} only; this computer is {}.", platforms.join(", "), host.platform)).at("requires.platforms".to_owned()));
    }
    let gpu = checked.gpu().to_owned();
    let mut notes = Vec::new();
    let mut without_gpu = answers.without_gpu;
    if host.gpu == Some(false) {
        match gpu.as_str() {
            "required" => problems.push(problem("unsupported_here", "This template needs an NVIDIA GPU, and this computer has none that Yougori can use. Run it on a computer with an NVIDIA GPU.").at("requires.gpu".to_owned())),
            "optional" => {
                without_gpu = true;
                notes.push("This computer has no NVIDIA GPU that Yougori can use; the setup runs without one.".to_owned());
            }
            _ => {}
        }
    }
    // Answers and capabilities of the template, then of every component.
    let resolved = resolve_inputs(&checked.questions, &answers.inputs, &answers.secrets, "", &mut problems);
    let decided = decide_capabilities(&checked.capabilities, &resolved.inputs, &answers.capabilities, &[], host, checked.profile, "", &mut problems);
    let mut scopes = Vec::new();
    let mut pins = BTreeMap::new();
    resolve_components(checked, &resolved, &package.components, "", host, &mut scopes, &mut pins, &mut problems);
    scopes.push(Scope { namespace: String::new(), checked: checked.clone(), resolved, decided });
    // Bindings the person makes on this computer.
    let root = scopes.last().expect("the template's own scope");
    let mut bindings: BTreeMap<String, String> = BTreeMap::new();
    for binding in &checked.bindings {
        if !binding.when.as_ref().is_none_or(|when| when.holds(&root.resolved.inputs)) {
            continue;
        }
        match answers.bindings.get(&binding.id) {
            Some(value) if !value.trim().is_empty() => {
                if binding.kind == resource::BindingKind::Folder {
                    if let Some(why) = format::folder_choice_problem(value) {
                        problems.push(problem("invalid_answer", format!("{}: {why}.", binding.id)).at(format!("bindings.{}", binding.id)));
                        continue;
                    }
                }
                bindings.insert(binding.id.clone(), value.trim().to_owned());
            }
            _ if binding.required => problems.push(problem("awaiting_binding", format!("{} needs a {} chosen on this computer: {}", binding.id, binding.kind.id(), binding.question)).at(format!("bindings.{}", binding.id))),
            _ => {}
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    // The whole graph, then only the part these answers select.
    let mut graph = Graph::new();
    for scope in &scopes {
        match Graph::from_checked(&scope.checked) {
            Ok(part) => {
                let part = if scope.namespace.is_empty() { part } else { part.namespaced(&scope.namespace) };
                if let Err(errors) = graph.merge(part) {
                    problems.extend(errors);
                }
            }
            Err(errors) => problems.extend(errors),
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    graph.check()?;
    let scope_of = |node: &Node| scopes.iter().find(|s| s.namespace == node.component.clone().unwrap_or_default());
    let keep = |node: &Node| -> bool {
        let Some(scope) = scope_of(node) else { return false };
        let capability_on = node.capability.as_ref().is_none_or(|id| scope.decided.iter().any(|d| &d.id == id && d.enabled));
        capability_on && node.when.as_ref().is_none_or(|when| when.holds(&scope.resolved.inputs))
    };
    let kept = graph.retain(&keep)?;
    let order = kept.order().map_err(|e| vec![e])?;
    // Resolve every kept spec.
    let mut specs: BTreeMap<String, Spec> = BTreeMap::new();
    for id in &order {
        let node = &kept.nodes[id];
        let Some(scope) = scope_of(node) else { continue };
        let values = values_of(scope, instance);
        let mut rendered = match format::select_entries(&node.spec, &scope.checked.questions, &scope.resolved.inputs, id) {
            Ok(selected) => selected,
            Err(errors) => {
                problems.extend(errors);
                continue;
            }
        };
        if let Err(error) = placeholder::substitute(&mut rendered, &values, resource::policy(node.kind).secrets, !node.legacy) {
            problems.push(problem("invalid_placeholder", format!("{}: {error}", node.origin)).at(id.clone()));
            continue;
        }
        // The written spec's folders of this computer were checked; answers may not add one or
        // mount one more widely than the template said.
        if node.kind == Kind::Environment {
            let widened = format::host_access_widened(&node.spec, &rendered);
            if !widened.is_empty() {
                problems.extend(widened.into_iter().map(|text| problem("host_path", format!("{}: {text}", node.origin)).at(id.clone())));
                continue;
            }
            // A folder of this computer is the template's own choice to ask for, so an imported
            // component never reaches one: the template that imports it binds it itself.
            if node.component.is_some() && !format::folder_uses(&rendered).is_empty() {
                problems.push(problem("host_path", format!("{}: an imported component cannot reach a folder of this computer; bind the folder in the template itself.", node.origin)).at(id.clone()));
                continue;
            }
            let bound = format::bind_folders(&mut rendered, &checked.bindings, format::Folders::Chosen(&bindings));
            if !bound.is_empty() {
                problems.extend(bound.into_iter().map(|text| problem("host_path", format!("{}: {text}", node.origin)).at(id.clone())));
                continue;
            }
        }
        let mut spec = match resource::parse_spec(node.kind, &rendered) {
            Ok(spec) => spec,
            Err(error) => {
                problems.push(problem("invalid_value", format!("{}: with these answers: {error}", node.origin)).at(id.clone()));
                continue;
            }
        };
        // Every secret a resource receives is one the person gave this setup: a name that is not
        // one of their bindings would reach into a stored secret of this computer.
        for (variable, binding) in spec.secrets() {
            if !scope.resolved.secrets.values().any(|given| given == binding) {
                problems.push(problem("invalid_value", format!("{}: secrets: {variable} names {}, which is not a secret given to this setup. Use {{{{secrets.ID}}}} of a secret input.", node.origin, text::shown(binding))).at(id.clone()));
            }
        }
        if let Spec::Environment(environment) = &mut spec {
            adjust_environment(environment, node, scope, instance, &answers.storage_drive, without_gpu);
        }
        if let Spec::Connection(connection) = &mut spec {
            if connection.model_request {
                // The package owns this command. Answers cannot replace the receiver that was
                // checked, and its exact argv is part of the plan/review digest.
                connection.model_command = scope.checked.models.as_ref().map(|models| models.command.clone()).unwrap_or_default();
            }
        }
        // A job's source is the folder the person chose for its binding, read-only.
        if let Spec::Job(job) = &mut spec {
            job.source_folder = job.source.as_ref().and_then(|source| bindings.get(&source.binding)).cloned();
        }
        // A VM sandbox's workspace is the folder the person chose, of which it gets a staged copy.
        if let Spec::VmSandbox(vm) = &mut spec {
            vm.workspace_folder = vm.workspace.as_ref().and_then(|workspace| bindings.get(&workspace.binding)).cloned();
            // A connection needs both its ends (M14): one to a VM sandbox left out of this setup is
            // left out with it, and so is the acceptance of one. An unknown name stays, so the
            // connection checks below name it.
            let left_out = |id: &str| graph.nodes.contains_key(id) && !kept.nodes.contains_key(id);
            vm.connect.retain(|connection| connection.target().is_none_or(|target| !left_out(target)));
            for published in &mut vm.publish {
                published.accept.retain(|caller| !left_out(caller.as_str()));
            }
        }
        // So is a research worker's: the folder it reviews a copy of.
        if let Spec::WorkerGroup(workers) = &mut spec {
            workers.source_folder = workers.source.as_ref().and_then(|source| bindings.get(&source.binding)).cloned();
        }
        // A cloud pool signs in to its new computers with the key file the person chose.
        if let Spec::ComputePool(pool) = &mut spec {
            if let Some(cloud) = pool.cloud.as_mut() {
                cloud.identity_path = cloud.identity_file.as_ref().and_then(|file| bindings.get(&file.binding)).cloned();
            }
        }
        for error in spec.validate() {
            problems.push(problem("invalid_value", format!("{}: with these answers: {error}", node.origin)).at(id.clone()));
        }
        for (field, reference, allowed) in spec.references() {
            if let Some(binding) = &reference.binding {
                match checked.bindings.iter().find(|b| &b.id == binding) {
                    Some(declared) if declared.kind == resource::BindingKind::Resource && declared.resource.is_some_and(|k| allowed.contains(&k)) => {
                        if !bindings.contains_key(binding) {
                            problems.push(problem("awaiting_binding", format!("{}: {field} needs the existing {} {} chosen on this computer.", node.origin, declared.resource.map(|k| k.title()).unwrap_or("resource"), binding)).at(format!("bindings.{binding}")));
                        }
                    }
                    _ => problems.push(problem("unknown_binding", format!("{}: {field} names the binding {}, which the template does not declare as a resource of that kind.", node.origin, text::shown(binding))).at(id.clone())),
                }
                continue;
            }
            let Some(target_id) = reference.local() else { continue };
            match kept.nodes.get(target_id) {
                None if graph.nodes.contains_key(target_id) => problems.push(problem("dependency_left_out", format!("{}: {field} names {}, which is not part of this setup.", node.origin, target_id)).at(id.clone())),
                None => problems.push(problem("unknown_resource", format!("{}: {field} names {}, which is not a resource.", node.origin, text::shown(target_id))).at(id.clone())),
                Some(target) if !allowed.contains(&target.kind) => problems.push(problem("invalid_value", format!("{}: {field} must name a {}; {} is a {}.", node.origin, allowed.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(" or "), target_id, target.kind.as_str())).at(id.clone())),
                Some(target) => {
                    if let Some(output) = &reference.output {
                        if !target.kind.outputs().contains(&output.as_str()) {
                            problems.push(problem("unknown_output", format!("{}: {field}: {} has no output {output}.", node.origin, target_id)).at(id.clone()));
                        }
                    }
                }
            }
        }
        if let Some(borrow) = &node.borrow {
            if let Some(binding) = &borrow.binding {
                if !bindings.contains_key(binding) {
                    problems.push(problem("awaiting_binding", format!("{}: needs the existing {} {} chosen on this computer.", node.origin, node.kind.title(), binding)).at(format!("bindings.{binding}")));
                }
            }
        }
        for (field, binding, kind) in spec.bindings() {
            match checked.bindings.iter().find(|b| b.id == binding) {
                Some(declared) if declared.kind == kind => {
                    if !bindings.contains_key(binding) {
                        problems.push(problem("awaiting_binding", format!("{}: {field} needs the {} {} chosen on this computer.", node.origin, kind.id(), binding)).at(format!("bindings.{binding}")));
                    }
                }
                _ => problems.push(problem("unknown_binding", format!("{}: {field} names the binding {}, which the template does not declare as a {}.", node.origin, text::shown(binding), kind.id())).at(id.clone())),
            }
        }
        specs.insert(id.clone(), spec);
    }
    problems.extend(vm_connection_problems(&specs));
    if !problems.is_empty() {
        return Err(problems);
    }
    // Placement, review and the plan itself.
    let pools: BTreeMap<String, ComputeSource> = specs.iter().filter_map(|(id, spec)| match spec {
        Spec::ComputePool(spec) => Some((id.clone(), spec.source)),
        _ => None,
    }).collect();
    let _ = Reference::to;
    let grids: BTreeMap<String, resource::Coordinator> = specs.iter().filter_map(|(id, spec)| match spec {
        Spec::Grid(spec) => Some((id.clone(), spec.coordinator)),
        _ => None,
    }).collect();
    let root = scopes.last().expect("the template's own scope");
    let mut resources = Vec::new();
    for id in &order {
        let node = &kept.nodes[id];
        let spec = &specs[id];
        let placement = match &node.borrow {
            Some(Borrow { setup: Some(setup), .. }) => format!("borrowed from the setup {setup}"),
            Some(Borrow { binding: Some(binding), .. }) => format!("borrowed: the existing {} chosen as {binding}", node.kind.title()),
            Some(_) => "borrowed".to_owned(),
            None => placement_words(spec, &pools, &grids),
        };
        resources.push(PlannedResource {
            id: id.clone(),
            kind: node.kind,
            title: node.kind.title().to_owned(),
            capability: node.capability.clone(),
            component: node.component.clone(),
            depends_on: node.depends_on.iter().cloned().collect(),
            borrow: node.borrow.clone(),
            retention: node.retention.unwrap_or(checked.retention).into(),
            placement,
            spec: spec.to_json(),
            outputs: node.kind.outputs().iter().map(|o| o.to_string()).collect(),
        });
    }
    let capabilities: Vec<PlannedCapability> = root.decided.iter().map(|d| {
        let cap = capability::find(&d.id);
        PlannedCapability {
            id: d.id.clone(),
            selection: d.selection.id().to_owned(),
            locked: d.locked,
            applies: d.applies,
            enabled: d.enabled,
            group: cap.map(|c| c.group.id().to_owned()).unwrap_or_default(),
            name: cap.map(|c| c.name.to_owned()).unwrap_or_default(),
            permissions: cap.map(|c| c.permissions.iter().map(|p| p.describe().to_owned()).collect()).unwrap_or_default(),
        }
    }).collect();
    let values = Values { names: BTreeMap::new(), ..values_of(root, instance) };
    let steps: Vec<PlannedStep> = checked.steps.iter().filter(|s| s.when.as_ref().is_none_or(|w| w.holds(&root.resolved.inputs))).map(|s| PlannedStep {
        title: placeholder::render(&s.title, &values).unwrap_or_else(|_| s.title.clone()),
        detail: s.detail.as_ref().map(|d| placeholder::render(d, &values).unwrap_or_else(|_| d.clone())),
        command: s.command.as_ref().map(|c| placeholder::render(c, &values).unwrap_or_else(|_| c.clone())),
    }).collect();
    let outputs: Vec<PlannedOutput> = checked.outputs.iter().filter(|o| o.when.as_ref().is_none_or(|w| w.holds(&root.resolved.inputs))).map(|o| PlannedOutput {
        key: o.key.clone(),
        label: o.label.clone(),
        value: placeholder::render(&o.value, &values).unwrap_or_else(|_| o.value.clone()),
        private: o.private,
    }).collect();
    let mut review = review(checked, root, &scopes, &resources, &specs, &kept, &capabilities, &gpu, host, notes);
    // The connections between its VM sandboxes, from both ends of each grant (M14).
    review.permissions.extend(vm_connection_lines(&specs));
    // What the template caps, against what this plan creates. Over any one, nothing is planned.
    let capped = limits_of(&checked.template.limits, &values);
    if !capped.is_empty() {
        let used = usage(&review.totals, &resources, &specs);
        for (key, most) in &capped {
            let words = format::LIMITS.iter().find(|(known, _)| known == key).map(|(_, words)| *words).unwrap_or("");
            review.limits.push(format!("At most {} {words}.", shown_amount(*most)));
            if let Some(using) = used.get(key.as_str()).filter(|using| **using > *most + 1e-9) {
                problems.push(problem("limit_exceeded", format!("This setup would use {} {words}, and its limit is {}. Ask for less, or raise the limit.", shown_amount(*using), shown_amount(*most))).at(format!("limits.{key}")));
            }
        }
        if !problems.is_empty() {
            return Err(problems);
        }
    }
    let mut plan = Plan {
        format_version: format::FORMAT_VERSION,
        instance: instance.to_owned(),
        template: PlanTemplate {
            name: checked.template.name().to_owned(),
            version: checked.template.version().to_owned(),
            format_version: checked.format.number(),
            item: package.item.clone(),
            digest: package.digest.clone(),
            profile: checked.profile.map(|p| p.id().to_owned()),
            components: pins,
        },
        requires: PlanRequires { yougori: checked.template.requires.yougori.clone(), gpu, platforms: checked.template.requires.platforms.clone() },
        capabilities,
        inputs: root.resolved.inputs.clone(),
        secrets: root.resolved.secrets.clone(),
        bindings,
        resources,
        order,
        steps,
        outputs,
        retention: checked.retention.into(),
        views: checked.views.clone(),
        review,
        digest: String::new(),
    };
    plan.digest = digest_of(&plan);
    Ok(plan)
}

/// What a run changes in a v1-style environment besides its placeholders: the tools it installs,
/// a tool's key binding, container ports only, no GPU when running without one, and the drive
/// every sandbox is stored on.
fn adjust_environment(environment: &mut resource::EnvironmentSpec, node: &Node, scope: &Scope, instance: &str, storage_drive: &Option<String>, without_gpu: bool) {
    let name = node.id.strip_prefix(&format!("{}.", scope.namespace)).unwrap_or(&node.id).to_owned();
    for use_ in scope.checked.tools.iter().filter(|t| t.environment == name && t.selected(&scope.resolved.inputs)) {
        environment.tools.push(tool_install(use_, &scope.resolved.inputs));
        // A bundled tool's key, or a resolved Hub tool's: the person gives it the same way.
        if let Some(variable) = use_.tool().and_then(Tool::key_variable) {
            environment.secrets.insert(variable.to_owned(), format!("hub-{instance}-key-{}", tool_file_name(use_)));
        }
    }
    for port in &mut environment.ports {
        if let Ok((guest, Some(_))) = port.values() {
            *port = resource::Port::Number(guest);
        }
    }
    if without_gpu {
        if environment.kind == "gpu" {
            environment.kind = "container".into();
        }
        environment.gpu = false;
    }
    if let Some(drive) = storage_drive {
        environment.storage_drive = Some(drive.clone());
    }
}

/// A grid profile as a person reads it.
pub fn profile_name(profile: GridProfile) -> &'static str {
    match profile {
        GridProfile::NeoGrid => "Neo Grid",
        GridProfile::SandboxGrid => "Sandbox Grid",
        GridProfile::AccessGrid => "Access Grid",
        GridProfile::SwarmMiningGrid => "Swarm Mining Grid",
        GridProfile::Generic => "grid",
    }
}

/// The name in a tool's own file: a bundled or resolved tool's `name:`, which is what its key
/// binding and its install marker are named after. A Hub tool's item name until it is resolved.
fn tool_file_name(use_: &ToolUse) -> String {
    match use_.tool() {
        Some(tool) => tool.name().to_owned(),
        None => use_.name().rsplit('/').next().unwrap_or_default().to_owned(),
    }
}

fn tool_install(use_: &ToolUse, answers: &BTreeMap<String, String>) -> resource::ToolInstall {
    let (folder, item, version) = match &use_.source {
        Source::BuiltIn { .. } => (None, None, None),
        Source::Bundled { folder, tool } => (Some(folder.clone()), None, Some(tool.version().to_owned())),
        // A resolved Hub tool records the version its files were fetched at, which is the pin.
        Source::Hub { item, version } => (None, Some(item.clone()), use_.resolved.as_ref().map(|resolved| resolved.version.clone()).or_else(|| version.clone())),
    };
    // The digest the review showed. Only a resolved Hub tool has one; a bundled tool's files are
    // the template's own and travel with it.
    let digest = match &use_.source {
        Source::Hub { .. } => use_.resolved.as_ref().map(|resolved| resolved.digest.clone()),
        _ => None,
    };
    resource::ToolInstall {
        name: use_.name(),
        source: use_.source_name().to_owned(),
        spec: use_.spec.clone(),
        folder,
        item,
        version,
        digest,
        signin: use_.needs_signin(answers),
        copy_credentials: use_.copy_credentials(answers),
        signin_hint: use_.signin_hint.clone(),
    }
}

/// The address each line of an installer fetches from, once each, in order.
pub fn downloads(lines: &[String]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut add = |address: String| {
        if !found.contains(&address) {
            found.push(address);
        }
    };
    for line in lines {
        let lower = line.to_lowercase();
        let mut addressed = false;
        for (at, _) in line.match_indices("http") {
            let rest = &line[at..];
            if !(rest.starts_with("http://") || rest.starts_with("https://")) {
                continue;
            }
            let end = rest.find(|c: char| c.is_whitespace() || "\"'`<>|;()\\".contains(c)).unwrap_or(rest.len());
            let url = rest[..end].trim_end_matches(['.', ',', ':']);
            if url.len() > "https://".len() {
                addressed = true;
                add(url.chars().filter(|c| !c.is_control()).take(200).collect());
            }
        }
        let has = |words: &[&str]| words.iter().any(|word| lower.contains(word));
        if has(&["pip install", "pip3 install", "pipx install", "uv tool install", "uv pip install"]) && !addressed {
            add("https://pypi.org".into());
        }
        if has(&["npm install", "npm i ", "npm add", "pnpm add", "pnpm install", "yarn add", "yarn global add", "bun add", "npx "]) && !addressed {
            add("https://registry.npmjs.org".into());
        }
        if has(&["cargo install"]) && !addressed {
            add("https://crates.io".into());
        }
        if has(&["go install"]) && !addressed {
            add("https://proxy.golang.org".into());
        }
        if has(&["gem install"]) && !addressed {
            add("https://rubygems.org".into());
        }
        if has(&["apt-get", "apt install"]) {
            add("the image's package mirrors (apt)".into());
        }
        if has(&["apk add"]) {
            add("the image's package mirrors (apk)".into());
        }
        if has(&["curl ", "wget "]) && !addressed {
            add("an address chosen when the line runs".into());
        }
    }
    found
}

/// Where a secret binding comes from, for the review: the question it answers, or a tool's key.
fn secret_source(binding: &str, sources: &BTreeMap<String, String>, tools: &[resource::ToolInstall]) -> String {
    if let Some(source) = sources.get(binding) {
        return source.clone();
    }
    // A tool's key is named after its own file's name, which for a Hub tool is the item's name.
    if let Some(tool) = tools.iter().find(|t| binding.ends_with(&format!("-key-{}", t.name.rsplit('/').next().unwrap_or_default()))) {
        return format!("the key of the tool {}", tool.name);
    }
    "a binding of this setup".to_owned()
}

#[allow(clippy::too_many_arguments)]
fn review(checked: &Checked, root: &Scope, scopes: &[Scope], resources: &[PlannedResource], specs: &BTreeMap<String, Spec>, kept: &Graph, capabilities: &[PlannedCapability], gpu: &str, host: &Host, notes: Vec<String>) -> Review {
    let mut review = Review { notes, totals: Totals { gpu: gpu.to_owned(), ..Totals::default() }, retention: checked.retention.into(), ..Review::default() };
    // Binding name to the question it answers, across the template and its components.
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    for scope in scopes {
        for (input, binding) in &scope.resolved.secrets {
            let said = if scope.namespace.is_empty() { format!("the question {input}") } else { format!("the question {input} of the component {}", scope.namespace) };
            sources.entry(binding.clone()).or_insert(said);
        }
    }
    let mut seen_downloads = BTreeSet::new();
    // Whether the download was new to the review, so a caller can say more about it.
    let mut add_download = |review: &mut Review, kind: &str, name: String, from: Option<String>| -> bool {
        let new = seen_downloads.insert((kind.to_owned(), name.clone(), from.clone()));
        if new {
            review.downloads.push(Download { kind: kind.to_owned(), name, from, version: None, digest: None, verified: None });
        }
        new
    };
    for planned in resources {
        let item = ReviewItem { id: planned.id.clone(), kind: planned.kind, title: planned.kind.title().to_owned(), placement: planned.placement.clone() };
        if planned.borrow.is_some() {
            review.borrows.push(item);
            continue;
        }
        review.creates.push(item);
        let Some(spec) = specs.get(&planned.id) else { continue };
        match spec {
            Spec::Environment(environment) => {
                review.totals.environments += 1;
                review.totals.cpu += environment.cpu;
                review.totals.memory_gb += format::gib(&environment.memory).unwrap_or(0.0);
                review.totals.storage_gb += format::gib(&environment.storage).unwrap_or(0.0);
                add_download(&mut review, "image", environment.image_shown(), None);
                for folder in environment.volumes.iter().filter(|v| v.bind) {
                    review.pc_access.push(PcFolder { environment: planned.id.clone(), path: folder.source.clone(), target: Some(folder.target.clone()), read_only: folder.read_only, binding: None, sync: false, staged: false });
                }
                for access in &environment.pc_access {
                    review.pc_access.push(PcFolder { environment: planned.id.clone(), path: access.path.clone(), target: access.target.clone(), read_only: access.read_only, binding: access.binding.clone(), sync: false, staged: false });
                    if let Some(binding) = &access.binding {
                        review.permissions.push(if access.read_only {
                            format!("{} can read {}, the folder you chose for {binding}, and nothing else on this computer.", planned.id, access.path)
                        } else {
                            format!("{} can change files in {}, the folder you chose for {binding}. You agree to that again when the setup is applied.", planned.id, access.path)
                        });
                    }
                }
                for synced in &environment.sync {
                    review.pc_access.push(PcFolder { environment: planned.id.clone(), path: synced.path.clone(), target: Some(synced.target.clone()), read_only: synced.read_only, binding: Some(synced.binding.clone()), sync: true, staged: false });
                    let when = if synced.continuous { "while the setup runs" } else { "when the setup starts and stops" };
                    review.permissions.push(if synced.read_only {
                        format!("{} gets a copy of {}, the folder you chose for {}, in {}. Changes go from this computer to the sandbox only, {when}; nothing in your folder is changed.", planned.id, synced.path, synced.binding, synced.target)
                    } else {
                        let conflicts = match synced.conflicts {
                            resource::SyncConflicts::KeepBoth => "A file changed in both places keeps both versions: the sandbox's is saved beside yours as a conflict copy.",
                            resource::SyncConflicts::Stop => "If a file changes in both places, the sync stops and changes nothing until the two copies match.",
                        };
                        format!("{} keeps a copy of {}, the folder you chose for {}, in {}, and changes sync both ways {when}. {conflicts} You agree to the sandbox changing your files again when the setup is applied.", planned.id, synced.path, synced.binding, synced.target)
                    });
                }
                for tool in &environment.tools {
                    let use_ = root.checked.tools.iter().find(|t| t.name() == tool.name);
                    let file = use_.and_then(ToolUse::tool);
                    if let Some(file) = file {
                        review.installs.push(ToolLines { resource: planned.id.clone(), tool: tool.name.clone(), commands: file.install.clone(), check: file.check.clone() });
                    }
                    match tool.source.as_str() {
                        "bundled" => {
                            for address in file.map(|bundled| downloads(&bundled.install)).unwrap_or_default() {
                                add_download(&mut review, "installer", address, Some(tool.name.clone()));
                            }
                        }
                        "hub" => {
                            let item = tool.item.clone().unwrap_or_else(|| tool.name.clone());
                            match use_.and_then(|use_| use_.resolved.as_ref()) {
                                // Resolved before this review: the review says which files, and
                                // what their install lines fetch, exactly as for a bundled tool.
                                Some(resolved) => {
                                    if add_download(&mut review, "tool", item.clone(), Some("the Hub".into())) {
                                        if let Some(download) = review.downloads.last_mut() {
                                            download.version = Some(resolved.version.clone());
                                            download.digest = Some(resolved.digest.clone());
                                            download.verified = Some(resolved.verified);
                                        }
                                    }
                                    for address in downloads(&resolved.tool.install) {
                                        add_download(&mut review, "installer", address, Some(item.clone()));
                                    }
                                }
                                None => {
                                    add_download(&mut review, "tool", item, Some("the Hub".into()));
                                }
                            }
                        }
                        _ => {
                            add_download(&mut review, "tool", tool.name.clone(), Some("built in".into()));
                        }
                    }
                    // What the tool's own file declares it reaches: shown, never granted. The
                    // sandbox has what its settings and the person's answers give it.
                    if let Some(declared) = file.map(Tool::declared_access).filter(|declared| !declared.is_empty()) {
                        review.permissions.push(format!("{} installs the tool {}, which says it {}. That is the tool's own word: the sandbox has only what its settings and your answers give it.", planned.id, tool.name, declared.join(", ")));
                    }
                }
                if environment.uses_gpu() {
                    review.permissions.push(format!("{} uses the NVIDIA GPU.", planned.id));
                }
                for (variable, binding) in &environment.secrets {
                    let source = secret_source(binding, &sources, &environment.tools);
                    review.secrets.push(SecretSource { resource: planned.id.clone(), variable: variable.clone(), source: source.clone() });
                    review.permissions.push(format!("{} receives the secret {variable} from {source}.", planned.id));
                }
                for tool in environment.tools.iter().filter(|t| t.copy_credentials == Some(true)) {
                    review.permissions.push(format!("{} gets a copy of this computer's sign-in for {}, as you chose at setup.", planned.id, tool.name));
                }
            }
            Spec::Grid(grid) => {
                for (name, binding) in &grid.secrets {
                    let source = secret_source(binding, &sources, &[]);
                    review.secrets.push(SecretSource { resource: planned.id.clone(), variable: name.clone(), source });
                }
                review.permissions.push(match grid.mode {
                    resource::GridMode::Create => format!("{} starts a {} that other computers can join.", planned.id, profile_name(grid.profile)),
                    resource::GridMode::Join => format!("{} joins a grid someone else coordinates, with a private invitation.", planned.id),
                    resource::GridMode::Attach => format!("{} uses an existing grid of another setup.", planned.id),
                });
            }
            Spec::ComputePool(pool) => {
                if let Some(cloud) = &pool.cloud {
                    review.costs.push(match cloud.max_hourly_cost {
                        Some(cap) => format!("{} rents compute from {}; the provider bills it, up to {cap} per hour as you accepted.", planned.id, cloud.provider.as_str()),
                        None => format!("{} rents compute from {}; the provider bills it, with no cap set here.", planned.id, cloud.provider.as_str()),
                    });
                }
                if pool.source == ComputeSource::SelectedComputers {
                    review.permissions.push(format!("{} runs work on {} selected computers.", planned.id, pool.computers.len()));
                }
            }
            Spec::WorkerGroup(workers) => {
                if let Some(budget) = &workers.budget {
                    if let Some(cap) = budget.cost_cap {
                        review.costs.push(format!("{}: at most {cap} {} of model or provider spend, as an estimate the setup enforces where it can.", planned.id, budget.currency.as_ref().map(|c| c.as_str()).unwrap_or("")));
                    }
                }
                review.permissions.push(format!("{} runs {} worker(s).", planned.id, workers.count));
            }
            Spec::ModelService(model) => {
                add_download(&mut review, "model", model.model.as_str().to_owned(), None);
                if model.network.as_ref().is_some_and(|n| n.enabled) {
                    review.permissions.push(format!("{} lists the model on the Yougori Network.", planned.id));
                }
            }
            Spec::WorkspacePool(pool) => {
                if let Some(image) = pool.image.as_ref().filter(|i| !i.as_str().trim().is_empty()) {
                    add_download(&mut review, "image", image.as_str().to_owned(), None);
                }
                if pool.cloud_fallback {
                    review.costs.push(format!("{} may fall back to rented compute; the provider bills it.", planned.id));
                }
            }
            Spec::AccessBinding(access) => {
                if let Some(share) = &access.share {
                    let target = share.target.resource.clone().or_else(|| share.target.binding.clone()).unwrap_or_default();
                    let permission = match share.permission {
                        resource::SharePermission::View => "view",
                        resource::SharePermission::Edit => "edit",
                        resource::SharePermission::Control => "control",
                    };
                    review.permissions.push(match share.expires_hours {
                        Some(hours) => format!("{} shares {target} with one person ({permission}) for {hours} hours.", planned.id),
                        None => format!("{} shares {target} with one person ({permission}) until it is revoked.", planned.id),
                    });
                    review.public.push(PublicEntry { resource: target, port: 0, access: share.access.id().to_owned() });
                } else if access.people == resource::People::Team {
                    review.permissions.push(format!("{} lets other people in, with the roles {}.", planned.id, if access.roles.is_empty() { "member".to_owned() } else { access.roles.iter().map(|r| format!("{r:?}").to_lowercase()).collect::<Vec<_>>().join(", ") }));
                }
            }
            Spec::CredentialBroker(broker) => {
                review.permissions.push(format!("{} brokers {} credential(s); workloads use them without receiving their values.", planned.id, broker.credentials.len()));
            }
            Spec::ServicePublication(publication) => {
                let target = publication.target.resource.clone().or_else(|| publication.target.binding.clone()).unwrap_or_default();
                review.public.push(PublicEntry { resource: target, port: publication.port, access: publication.access.id().to_owned() });
            }
            Spec::Job(job) => {
                if let Some(image) = &job.image {
                    add_download(&mut review, "image", image.as_str().to_owned(), None);
                }
                review.permissions.push(format!("{} runs a command on {}.", planned.id, planned.placement));
            }
            Spec::VmSandbox(vm) => {
                review.totals.environments += 1;
                if vm.remote.is_none() {
                    review.totals.cpu += f64::from(vm.cpu);
                    review.totals.memory_gb += vm.memory_gb;
                } else {
                    review.costs.push(format!("{} uses an existing SSH server with externally managed charges. Stopping this VM does not power off the server or confirm its billing stopped.", planned.id));
                }
                review.permissions.extend(vm_sandbox_lines(&planned.id, vm));
                if let Some(app) = &vm.application {
                    add_download(&mut review, "image", app.image.as_str().to_owned(), None);
                    for variable in app.secrets.keys() {
                        review.secrets.push(SecretSource {resource:planned.id.clone(), variable:variable.clone(), source:"asked privately during setup".into()});
                    }
                }
                if let Some(workspace) = &vm.workspace {
                    // The staged copy is bounded, and kept until it is reviewed.
                    review.totals.storage_gb += resource::VM_WORKSPACE_MOST_GB;
                    review.pc_access.push(PcFolder {
                        environment: planned.id.clone(),
                        path: vm.workspace_folder.clone().unwrap_or_else(|| format::described_folder(&workspace.binding)),
                        target: Some(VM_WORKSPACE_TARGET.to_owned()),
                        read_only: true,
                        binding: Some(workspace.binding.clone()),
                        sync: false,
                        staged: true,
                    });
                }
            }
            Spec::Volume(_) | Spec::Connection(_) | Spec::ArtifactStore(_) => {}
        }
    }
    for cap in capabilities.iter().filter(|c| c.enabled) {
        for permission in &cap.permissions {
            let said = format!("{}: {permission}", cap.name);
            if !review.permissions.contains(&said) {
                review.permissions.push(said);
            }
        }
    }
    // Warnings, most serious first.
    for folder in &review.pc_access {
        review.warnings.push(if folder.read_only { format!("{} can read {} on this computer.", folder.environment, folder.path) } else { format!("{} can change files in {} on this computer.", folder.environment, folder.path) });
    }
    for entry in &review.public {
        if PublicAccess::parse(&entry.access).is_some_and(PublicAccess::internet) {
            review.warnings.push(if entry.port == 0 { format!("Makes {} reachable from the internet for the person it is shared with.", entry.resource) } else { format!("Makes {}:{} reachable from the internet.", entry.resource, entry.port) });
        }
    }
    for download in review.downloads.iter().filter(|d| d.kind == "installer") {
        let said = format!("Installs software from {}.", download.name);
        if !review.warnings.contains(&said) {
            review.warnings.push(said);
        }
    }
    for download in review.downloads.iter().filter(|d| d.kind == "tool" && d.from.as_deref() == Some("the Hub")) {
        match (&download.version, &download.digest) {
            (Some(version), Some(digest)) => review.warnings.push(format!("Installs the Hub tool {} {version}, whose files (sha256:{digest}) were fetched and checked for this review; applying installs exactly them.", download.name)),
            _ => review.warnings.push(format!("Installs the Hub tool {}; its files are checked when it runs.", download.name)),
        }
        if download.verified == Some(false) {
            review.warnings.push(format!("The Hub tool {} is not checked by Yougori: its install lines can contain harmful code. Read its files first.", download.name));
        }
    }
    match gpu {
        "required" => review.warnings.push("Needs an NVIDIA GPU.".into()),
        "optional" => review.warnings.push("Uses an NVIDIA GPU when this computer has one.".into()),
        _ => {}
    }
    if let Some(has) = host.memory_gb {
        if review.totals.memory_gb > has {
            review.notes.push(format!("Together the sandboxes may use up to {} GB of memory; this computer has {} GB. They can still run, more slowly, if they are not all busy.", number(review.totals.memory_gb), number(has.floor())));
        }
    }
    if let Some(free) = host.free_disk_gb {
        if review.totals.storage_gb > free {
            review.notes.push(format!("Together the sandboxes may use up to {} GB of disk as they grow; {} GB is free on their drive now.", number(review.totals.storage_gb), number(free.floor())));
        }
    }
    review.questions = root.resolved.asked.iter().map(|q| ReviewQuestion {
        id: q.id.clone(),
        question: q.question.clone(),
        answer: if q.kind == QuestionKind::Secret { None } else { root.resolved.inputs.get(&q.id).cloned() },
        secret: q.kind == QuestionKind::Secret,
        group: q.group.map(|g| g.id().to_owned()),
    }).collect();
    let _ = kept;
    review
}

// ---- The review a publisher uploads ----

/// The review's format on the Hub. A page whose review has another format was written by
/// another Yougori and is not compared part by part.
pub const REVIEW_FORMAT: u64 = 2;

fn plain(text: &str) -> String {
    text::plain(text, limits::REVIEW_TEXT.max)
}

fn cleaned(mut value: Json) -> Json {
    fn walk(value: &mut Json) {
        match value {
            Json::String(text) => *text = plain(text),
            Json::Array(items) => items.iter_mut().for_each(walk),
            Json::Object(fields) => fields.values_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

/// A raw spec's top-level fields as scalars only, for the published review: strings, numbers and
/// booleans as they are; a list of scalars joined; a reference as `resource:ID`; anything deeper
/// left out, so the review stays within the website's nesting limit.
fn summary_of(spec: &Yaml) -> Json {
    let mut summary = serde_json::Map::new();
    let Some(map) = spec.as_mapping() else { return Json::Object(summary) };
    for (key, value) in map {
        let Some(key) = key.as_str() else { continue };
        if key == "secrets" {
            if let Some(names) = value.as_mapping() {
                summary.insert("secrets".into(), Json::String(names.keys().filter_map(Yaml::as_str).collect::<Vec<_>>().join(", ")));
            }
            continue;
        }
        let scalar = match value {
            Yaml::String(text) => Some(Json::String(text.clone())),
            Yaml::Number(number) => number.as_f64().map(number_json),
            Yaml::Bool(flag) => Some(Json::Bool(*flag)),
            Yaml::Sequence(items) if items.iter().all(|i| matches!(i, Yaml::String(_) | Yaml::Number(_) | Yaml::Bool(_))) => Some(Json::String(items.iter().filter_map(format::scalar_text).collect::<Vec<_>>().join(", "))),
            Yaml::Mapping(inner) if inner.get("resource").and_then(Yaml::as_str).is_some() && inner.keys().all(|k| matches!(k.as_str(), Some("resource" | "output"))) => {
                let resource = inner.get("resource").and_then(Yaml::as_str).unwrap_or_default();
                Some(Json::String(match inner.get("output").and_then(Yaml::as_str) {
                    Some(output) => format!("resource:{resource}.{output}"),
                    None => format!("resource:{resource}"),
                }))
            }
            Yaml::Mapping(inner) if inner.get("binding").and_then(Yaml::as_str).is_some() => Some(Json::String(format!("binding:{}", inner.get("binding").and_then(Yaml::as_str).unwrap_or_default()))),
            _ => None,
        };
        if let Some(scalar) = scalar {
            summary.insert(key.to_owned(), scalar);
        }
    }
    Json::Object(summary)
}

fn number_json(value: f64) -> Json {
    number(value)
}

/// One environment of the published review. Every conditional list entry is kept (the review
/// shows all the template may grant, whatever the answers), and sample answers fill placeholders
/// where the written form can't be read as its type, typed as the plan would. An environment
/// that still can't be read is an error: the review never shows less than the template grants.
fn environment_entry(name: &str, raw: &Yaml, sample: &Values, tools: &[String], bindings: &[format::CheckedBinding], typed: bool) -> Result<(Json, Vec<Json>, f64, f64, f64), String> {
    let mut every = format::every_entry(raw);
    // A folder the person chooses is shown as chosen at setup, with the binding's access; the
    // review never holds a folder of the publisher's computer.
    let bound = format::bind_folders(&mut every, bindings, format::Folders::Described);
    if let Some(problem) = bound.into_iter().next() {
        return Err(format!("environment {name}: {problem}"));
    }
    let spec = match resource::parse_spec(Kind::Environment, &every) {
        Ok(Spec::Environment(spec)) => *spec,
        _ => {
            let mut rendered = every.clone();
            placeholder::substitute(&mut rendered, sample, resource::policy(Kind::Environment).secrets, typed).map_err(|error| format!("environment {name}: {error}"))?;
            match resource::parse_spec(Kind::Environment, &rendered) {
                Ok(Spec::Environment(spec)) => *spec,
                Ok(_) => return Err(format!("environment {name} is not an environment.")),
                Err(error) => return Err(format!("environment {name} can't be read with sample answers: {error}")),
            }
        }
    };
    let memory_gb = format::gib(&spec.memory).ok();
    let storage_gb = format::gib(&spec.storage).ok();
    let mut folders: Vec<Json> = spec.volumes.iter().filter(|v| v.bind).map(|v| json!({"path": v.source, "target": v.target, "readOnly": v.read_only})).collect();
    folders.extend(spec.pc_access.iter().map(|p| match &p.binding {
        Some(binding) => json!({"path": p.path, "target": p.target, "readOnly": p.read_only, "binding": binding}),
        None => json!({"path": p.path, "target": p.target, "readOnly": p.read_only}),
    }));
    folders.extend(spec.sync.iter().map(|s| json!({"path": s.path, "target": s.target, "readOnly": s.read_only, "binding": s.binding, "sync": true, "continuous": s.continuous, "conflicts": s.conflicts.id()})));
    // Where each secret comes from, as written: sample answers would hide the question's name.
    let written_secrets: BTreeMap<String, String> = every.get("secrets").and_then(Yaml::as_mapping).into_iter().flatten()
        .filter_map(|(variable, binding)| Some((variable.as_str()?.to_owned(), format::scalar_text(binding)?)))
        .collect();
    // An image chosen by an answer is shown as written, never as a sample answer.
    let image = match every.get("image").and_then(Yaml::as_str) {
        Some(written) if written.contains("{{") => written.to_owned(),
        _ => spec.image_shown(),
    };
    let entry = json!({
        "name": name,
        "type": spec.kind,
        "image": image,
        "cpu": number(spec.cpu),
        "memoryGb": memory_gb.map(number),
        "storageGb": storage_gb.map(number),
        "gpu": spec.uses_gpu(),
        "internet": spec.internet,
        "ports": spec.guest_ports(),
        "tools": tools,
        "secrets": spec.secrets.keys().collect::<Vec<_>>(),
        "secretSources": spec.secrets.keys().map(|variable| {
            let binding = written_secrets.get(variable).cloned().unwrap_or_default();
            match placeholder::whole_secret(&binding) {
                Some(input) => format!("{variable} from the question {input}"),
                None => format!("{variable} from {binding}"),
            }
        }).collect::<Vec<_>>(),
        "pcAccess": folders,
        "writablePcFolders": spec.volumes.iter().any(|v| v.bind && !v.read_only) || spec.pc_access.iter().any(|p| !p.read_only) || spec.sync.iter().any(|s| !s.read_only),
    });
    Ok((entry, folders, spec.cpu, memory_gb.unwrap_or(0.0), storage_gb.unwrap_or(0.0)))
}

fn tool_entry(use_: &ToolUse) -> Json {
    let mut entry = json!({"name": use_.name(), "source": use_.source_name(), "environment": use_.environment});
    match &use_.source {
        Source::Bundled { folder, tool } => {
            entry["version"] = json!(tool.version());
            entry["downloads"] = json!(downloads(&tool.install));
            entry["commands"] = json!(tool.install);
            entry["signin"] = json!(tool.signin_method());
            entry["path"] = json!(folder);
        }
        Source::Hub { item, version } => {
            entry["ref"] = json!(match version {
                Some(version) => format!("hub/{item}@{version}"),
                None => format!("hub/{item}"),
            });
            if let Some(resolved) = &use_.resolved {
                entry["version"] = json!(resolved.version);
                entry["digest"] = json!(resolved.digest);
                entry["verified"] = json!(resolved.verified);
                entry["downloads"] = json!(downloads(&resolved.tool.install));
                entry["commands"] = json!(resolved.tool.install);
                entry["check"] = json!(resolved.tool.check);
                entry["command"] = json!(resolved.tool.command);
            }
        }
        Source::BuiltIn { .. } => {}
    }
    if let Some(tool) = use_.tool() {
        let declared = tool.declared_access();
        if !declared.is_empty() {
            entry["access"] = json!(declared);
        }
        if !tool.inputs.is_empty() {
            entry["inputs"] = json!(tool.inputs.iter().map(|input| input.name.clone()).collect::<Vec<_>>());
        }
        if !tool.outputs.is_empty() {
            entry["outputs"] = json!(tool.outputs.iter().map(|output| output.name.clone()).collect::<Vec<_>>());
        }
    }
    if let Some(when) = &use_.when {
        entry["when"] = json!(when.describe());
    }
    if use_.signin {
        entry["signin"] = json!("Choose PC credentials or a new account; sign-in opens in a separate terminal window");
        if let Some(when) = &use_.signin_when {
            entry["signinWhen"] = json!(when.describe());
        }
        if let Some(input) = &use_.signin_source {
            entry["signinSource"] = json!(input);
        }
    }
    entry
}

/// The review a publisher uploads for a format 2 package: every v1 key still filled, so an older
/// client shows the same grants, plus the resources, capabilities, subtitle and aliases. What its
/// imported components create, open and install is listed with theirs, under their namespace.
/// Pure and deterministic; it holds no installation-specific binding, no secret and no path of the
/// publisher's computer. `notices` are the file scan's notes. An error, never a partial review,
/// when part of the package can't be shown, or a component it imports was not resolved.
pub fn published_review(package: &Package, notices: &[String]) -> Result<Json, String> {
    let checked = &package.checked;
    let mut parts: Vec<(String, &Checked)> = vec![(String::new(), checked)];
    for (namespace, import) in &checked.template.imports {
        match package.components.get(namespace) {
            Some(component) => parts.push((namespace.clone(), &component.checked)),
            None => return Err(format!("imports: {namespace}: the component {}@{} was not resolved, so its part of the review can't be written.", import.item, import.version.clone().unwrap_or_default())),
        }
    }
    let named = |namespace: &str, id: &str| if namespace.is_empty() { id.to_owned() } else { format!("{namespace}.{id}") };
    let mut environments = Vec::new();
    let (mut cpu, mut memory, mut storage) = (0.0, 0.0, 0.0);
    let mut pc = Vec::new();
    let mut public: Vec<Json> = Vec::new();
    let mut connections: Vec<Json> = Vec::new();
    let mut tools: Vec<Json> = Vec::new();
    let mut resources: Vec<Json> = Vec::new();
    let mut resource_warnings: Vec<String> = Vec::new();
    let mut costs: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for (namespace, part) in &parts {
        let sample = format::sample_values(part);
        // Project environments are read as written (untyped), like the plan reads them;
        // environment resources take typed answers.
        let entries = part.environments.iter().map(|(n, s)| (n, s, false)).chain(part.resources.values().filter(|r| r.kind == Kind::Environment).map(|r| (&r.id, &r.spec, true)));
        for (id, raw, typed) in entries {
            let name = named(namespace, id);
            let tool_names: Vec<String> = part.tools.iter().filter(|t| &t.environment == id).map(ToolUse::name).collect();
            match environment_entry(&name, raw, &sample, &tool_names, &part.bindings, typed) {
                Ok((entry, folders, c, m, s)) => {
                    cpu += c;
                    memory += m;
                    storage += s;
                    for mut folder in folders {
                        folder["environment"] = json!(name);
                        pc.push(folder);
                    }
                    environments.push(entry);
                }
                Err(error) => unreadable.push(error),
            }
        }
        for entry in &part.public {
            let mut item = json!({"environment": named(namespace, &entry.environment), "port": entry.port});
            match &entry.access {
                Access::Fixed(access) => item["access"] = json!(access),
                Access::Asked(input) => {
                    item["access"] = json!("asked");
                    item["input"] = json!(input);
                }
            }
            public.push(item);
        }
        for resource in part.resources.values().filter(|r| r.kind == Kind::ServicePublication) {
            let target = resource.spec.get("target").and_then(|t| t.get("resource")).and_then(Yaml::as_str).unwrap_or_default();
            let port = resource.spec.get("port").and_then(Yaml::as_u64).unwrap_or_default();
            let access = resource.spec.get("access").and_then(Yaml::as_str).unwrap_or("quick");
            let mut item = json!({"environment": named(namespace, target), "port": port, "resource": named(namespace, &resource.id)});
            match placeholder::whole_input(access) {
                Some(input) => {
                    item["access"] = json!("asked");
                    item["input"] = json!(input);
                }
                None => item["access"] = json!(access),
            }
            public.push(item);
        }
        connections.extend(part.connections.iter().map(|c| json!({"from": named(namespace, &c.from), "to": named(namespace, &c.to)})));
        for resource in part.resources.values().filter(|r| r.kind == Kind::Connection) {
            let from = resource.spec.get("from").and_then(|t| t.get("resource")).and_then(Yaml::as_str).unwrap_or_default();
            let to = resource.spec.get("to").and_then(|t| t.get("resource")).and_then(Yaml::as_str).unwrap_or_default();
            connections.push(json!({"from": named(namespace, from), "to": named(namespace, to), "resource": named(namespace, &resource.id)}));
        }
        for use_ in &part.tools {
            let mut entry = tool_entry(use_);
            entry["environment"] = json!(named(namespace, &use_.environment));
            tools.push(entry);
        }
        for r in part.resources.values() {
            let mut depends_on: BTreeSet<String> = r.depends_on.iter().cloned().collect();
            crate::graph::readiness_references(r.kind, &r.spec, &mut depends_on);
            if r.kind == Kind::Environment {
                let volumes = crate::graph::mounted_volumes(&r.spec).into_iter().filter(|source| source != &r.id && part.resources.get(source).is_some_and(|other| other.kind == Kind::Volume));
                depends_on.extend(volumes.collect::<Vec<_>>());
            }
            let mut summary = summary_of(&r.spec);
            if r.kind == Kind::Connection && r.spec.get("model_request").and_then(Yaml::as_bool) == Some(true) {
                if let Some(models) = &part.models {
                    // Also show the exact receiver in the published Hub review, before install.
                    summary["model_command"] = json!(serde_json::to_string(&models.command).map_err(|e| e.to_string())?);
                }
            }
            if let Some(capability) = &r.capability {
                summary["capability"] = json!(capability);
            }
            if r.borrow.is_some() {
                summary["borrowed"] = json!(true);
            }
            if let Some(fields) = summary.as_object_mut() {
                while fields.len() > 32 {
                    let last = fields.keys().next_back().cloned();
                    if let Some(last) = last {
                        fields.remove(&last);
                    }
                }
            }
            let id = named(namespace, &r.id);
            costs.extend(published_cost(&id, r.kind, &r.spec));
            resources.push(json!({
                "id": id,
                "kind": r.kind.as_str(),
                "dependsOn": depends_on.iter().map(|d| named(namespace, d)).take(limits::DEPENDS_ON.max).collect::<Vec<_>>(),
                "when": r.when.as_ref().map(|w| w.describe()).unwrap_or_default().into_iter().take(32).collect::<Vec<_>>(),
                "summary": summary,
            }));
            match r.kind {
                Kind::Grid if r.spec.get("mode").and_then(Yaml::as_str) != Some("join") => resource_warnings.push(format!("{id} starts a grid that other computers can join.")),
                Kind::ComputePool if r.spec.get("source").and_then(Yaml::as_str) == Some("cloud") => resource_warnings.push(format!("{id} rents compute from a provider, which bills it.")),
                Kind::CredentialBroker => resource_warnings.push(format!("{id} holds credentials for workloads to use without receiving their values.")),
                Kind::AccessBinding if r.spec.get("share").is_some() => resource_warnings.push(format!("{id} shares a sandbox with another person over the internet.")),
                Kind::AccessBinding if r.spec.get("people").and_then(Yaml::as_str) == Some("team") => resource_warnings.push(format!("{id} lets other people in.")),
                Kind::Job => resource_warnings.push(format!("{id} runs commands on the computers it is placed on.")),
                _ => {}
            }
        }
    }
    if !unreadable.is_empty() {
        return Err(format!("The review can't show everything this template grants, so it was not written: {}", unreadable.join("; ")));
    }
    if resources.len() > limits::RESOURCES.max {
        return Err(limits::RESOURCES.exceeded(resources.len()));
    }
    // The website shows at most 32; the rest are counted, and the review before setup lists each.
    if costs.len() > limits::REVIEW_COSTS.max {
        let more = costs.len() - (limits::REVIEW_COSTS.max - 1);
        costs.truncate(limits::REVIEW_COSTS.max - 1);
        costs.push(format!("{more} more resources may cost money; the review before setup lists each one."));
    }
    let inputs: Vec<Json> = checked.questions.iter().map(|q| {
        let mut entry = json!({"id": q.id, "question": q.question, "type": q.kind.name(), "secret": q.kind == QuestionKind::Secret, "required": q.required});
        if let Some(group) = q.group {
            entry["group"] = json!(group.id());
        }
        if !q.editable {
            entry["editable"] = json!(false);
        }
        entry
    }).collect();
    let steps: Vec<Json> = checked.steps.iter().map(|s| Json::String(s.title.clone())).collect();
    // The strongest GPU need of the template and its components.
    let gpus: Vec<&str> = parts.iter().map(|(_, part)| part.gpu()).collect();
    let gpu = if gpus.contains(&"required") { "required" } else if gpus.contains(&"optional") { "optional" } else { checked.gpu() }.to_owned();
    let capabilities: Vec<Json> = checked.capabilities.iter().map(|c| json!({"id": c.id, "selection": c.selection.id(), "locked": c.locked})).take(limits::CAPABILITIES.max).collect();
    // Warnings, most serious first.
    let mut warnings: Vec<String> = Vec::new();
    for folder in &pc {
        let path = folder["path"].as_str().unwrap_or_default();
        let environment = folder["environment"].as_str().unwrap_or_default();
        warnings.push(if folder["readOnly"] == false { format!("{environment} can change files in {path} on this computer.") } else { format!("{environment} can read {path} on this computer.") });
    }
    for entry in &public {
        let access = entry["access"].as_str().unwrap_or("quick");
        if access != "none" && access != "private" && access != "lan" {
            warnings.push(format!("Makes {}:{} reachable from the internet.", entry["environment"].as_str().unwrap_or_default(), entry["port"]));
        }
    }
    for entry in &tools {
        for address in entry["downloads"].as_array().into_iter().flatten().filter_map(Json::as_str) {
            let said = format!("Installs software from {address}.");
            if !warnings.contains(&said) {
                warnings.push(said);
            }
        }
        if entry["source"] == "hub" && entry.get("commands").is_none() {
            warnings.push(format!("Installs the Hub tool {}; its files are checked when it runs.", entry["name"].as_str().unwrap_or_default()));
        }
        if entry["verified"] == false {
            warnings.push(format!("The Hub tool {} is not checked by Yougori: its install lines can contain harmful code. Read its files first.", entry["name"].as_str().unwrap_or_default()));
        }
        if entry["signinSource"].is_string() {
            warnings.push(format!("May copy this computer's sign-in for {} into its sandbox, only if you choose so during setup.", entry["name"].as_str().unwrap_or_default()));
        }
    }
    warnings.extend(resource_warnings);
    match gpu.as_str() {
        "required" => warnings.push("Needs an NVIDIA GPU.".into()),
        "optional" => warnings.push("Uses an NVIDIA GPU when this computer has one.".into()),
        _ => {}
    }
    warnings.extend(notices.iter().cloned());
    let environment_count = environments.len();
    let aliases: Vec<String> = checked.template.aliases.iter().take(limits::ALIASES.max).map(|a| text::js_trim(a).chars().take(limits::ALIAS_CHARS.max).collect()).collect();
    Ok(cleaned(json!({
        "format": REVIEW_FORMAT,
        "environments": environments,
        "totals": {"environments": environment_count, "cpu": number(cpu), "memoryGb": number(memory), "storageGb": number(storage), "gpu": gpu},
        "public": public,
        "connections": connections,
        "tools": tools,
        "inputs": inputs,
        "steps": steps,
        "pcAccess": pc,
        "warnings": warnings,
        "requires": {
            "yougori": checked.template.requires.yougori,
            "gpu": gpu,
            "platforms": checked.template.requires.platforms,
        },
        "resources": resources,
        "capabilities": capabilities,
        "subtitle": checked.template.subtitle.clone().unwrap_or_default(),
        "aliases": aliases,
        "retention": {"onStop": checked.retention.on_stop.id(), "onRemove": checked.retention.on_remove.id()},
        "costs": costs,
    })))
}

/// What a resource may cost, for the published review, read from its raw spec as the plan reads
/// the typed one: rented compute, a spend cap, or a fallback to rented compute. A value the
/// template asks for is said to be chosen at setup; nothing is guessed.
fn published_cost(id: &str, kind: Kind, spec: &Yaml) -> Option<String> {
    // A `{{inputs.…}}` (or any other placeholder) in the text: the answer decides it.
    fn placed(text: &str) -> bool {
        !placeholder::pieces(text).is_ok_and(|pieces| pieces.iter().all(|piece| matches!(piece, placeholder::Piece::Text(_))))
    }
    let asked = |value: Option<&Yaml>| value.and_then(Yaml::as_str).is_some_and(placed);
    fn written(value: Option<&Yaml>) -> Option<&str> {
        value.and_then(Yaml::as_str).filter(|text| !placed(text) && !text.trim().is_empty())
    }
    match kind {
        Kind::VmSandbox if spec.get("remote").is_some_and(Yaml::is_mapping) => Some(format!("{id} uses an existing SSH server with externally managed charges. Stopping this VM does not power off the server or confirm its billing stopped.")),
        Kind::ComputePool => {
            let cloud = spec.get("cloud").filter(|cloud| cloud.is_mapping())?;
            let provider = written(cloud.get("provider")).unwrap_or("the provider chosen at setup");
            let cap = cloud.get("max_hourly_cost");
            Some(match cap.and_then(Yaml::as_f64) {
                Some(cap) => format!("{id} rents compute from {provider}; the provider bills it, up to {cap} per hour."),
                None if asked(cap) => format!("{id} rents compute from {provider}; the provider bills it, up to the hourly limit chosen at setup."),
                None => format!("{id} rents compute from {provider}; the provider bills it, with no hourly limit set in the template."),
            })
        }
        Kind::WorkerGroup => {
            let budget = spec.get("budget")?;
            let cap = budget.get("cost_cap");
            let currency = written(budget.get("currency")).map(|currency| format!(" {currency}")).unwrap_or_default();
            match cap.and_then(Yaml::as_f64) {
                Some(cap) => Some(format!("{id}: at most {cap}{currency} of model or provider spend, as an estimate the setup enforces where it can.")),
                None if asked(cap) => Some(format!("{id}: at most the spend limit chosen at setup, as an estimate the setup enforces where it can.")),
                None => None,
            }
        }
        Kind::WorkspacePool => {
            let fallback = spec.get("cloud_fallback");
            if fallback.and_then(Yaml::as_bool) == Some(true) {
                Some(format!("{id} may fall back to rented compute; the provider bills it."))
            } else if asked(fallback) {
                Some(format!("{id} may fall back to rented compute if that is chosen at setup; the provider bills it."))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// What the website refuses in a review: its known parts must have their types, values nest at
/// most four deep, every text is short and plain, and the whole stays under the byte limit.
pub fn review_shape_problem(review: &Json) -> Option<String> {
    fn scalar(value: &Json, at: &str) -> Option<String> {
        match value {
            Json::String(text) if text::utf16_len(text) > limits::REVIEW_TEXT.max => Some(format!("has text longer than {} characters at {at}", limits::REVIEW_TEXT.max)),
            Json::String(text) if text.chars().any(|c| text::control(c) || text::hidden(c)) => Some(format!("has characters that cannot be shown at {at}")),
            _ => None,
        }
    }
    fn nested(value: &Json, at: &str, depth: usize) -> Option<String> {
        match value {
            Json::Array(_) | Json::Object(_) if depth == 0 => Some(format!("is nested too deeply at {at}")),
            Json::Array(items) => items.iter().enumerate().find_map(|(index, item)| nested(item, &format!("{at}[{index}]"), depth - 1)),
            Json::Object(fields) => fields.iter().find_map(|(key, item)| nested(item, &format!("{at}.{key}"), depth - 1)),
            other => scalar(other, at),
        }
    }
    let object = review.as_object()?;
    let bytes = serde_json::to_vec(review).map(|v| v.len()).unwrap_or(usize::MAX);
    if !limits::REVIEW_BYTES.allows(bytes) {
        return Some(format!("The review is larger than {} bytes.", limits::REVIEW_BYTES.max));
    }
    for (key, value) in object {
        let wrong = match key.as_str() {
            "environments" | "public" | "connections" | "tools" | "inputs" | "pcAccess" => !value.as_array().is_some_and(|items| items.iter().all(Json::is_object)),
            "resources" | "capabilities" => !(value.is_null() || value.as_array().is_some_and(|items| items.iter().all(Json::is_object))),
            "steps" | "warnings" => !value.as_array().is_some_and(|items| items.iter().all(Json::is_string)),
            "aliases" => !(value.is_null() || value.as_array().is_some_and(|items| items.iter().all(Json::is_string))),
            "totals" | "requires" | "needs" | "retention" => !value.is_object(),
            "service" => !(value.is_null() || value.is_object()),
            "subtitle" => !(value.is_null() || value.is_string()),
            _ => false,
        };
        if wrong {
            return Some(format!("The review has {key} in a form the Hub does not accept."));
        }
        if let Some(problem) = nested(value, key, limits::REVIEW_DEPTH.max) {
            return Some(format!("The review {problem}."));
        }
    }
    if object.get("resources").and_then(Json::as_array).is_some_and(|r| r.len() > limits::RESOURCES.max) {
        return Some(format!("The review lists more than {} resources.", limits::RESOURCES.max));
    }
    if object.get("capabilities").and_then(Json::as_array).is_some_and(|c| c.len() > limits::CAPABILITIES.max) {
        return Some(format!("The review lists more than {} capabilities.", limits::CAPABILITIES.max));
    }
    if object.get("aliases").and_then(Json::as_array).is_some_and(|a| a.len() > limits::ALIASES.max || a.iter().any(|x| x.as_str().is_some_and(|s| text::utf16_len(s) > limits::ALIAS_CHARS.max))) {
        return Some(format!("The review lists more than {} aliases, or an alias longer than {} characters.", limits::ALIASES.max, limits::ALIAS_CHARS.max));
    }
    for entry in object.get("resources").and_then(Json::as_array).into_iter().flatten() {
        if entry["dependsOn"].as_array().is_some_and(|d| d.len() > limits::DEPENDS_ON.max) {
            return Some(format!("The review has a resource with more than {} dependencies.", limits::DEPENDS_ON.max));
        }
    }
    match object.get("format") {
        None | Some(Json::Null) => None,
        Some(format) if format.as_u64() == Some(1) => None,
        Some(format) if format.as_u64() == Some(REVIEW_FORMAT) => closed_review_problem(object).map(|problem| format!("The review {problem}.")),
        Some(_) => Some("The review is in a format the Hub does not know; the Hub reads review formats 1 and 2.".into()),
    }
}

/// The website's closed check of a format 2 review (`checkClosed` in `server/hub/review.mjs`):
/// only known parts, the grants a format 1 page shows all present, and resources, capabilities,
/// retention, aliases and costs each in their bounded form.
fn closed_review_problem(review: &serde_json::Map<String, Json>) -> Option<String> {
    const PARTS: [&str; 19] = ["format", "environments", "public", "connections", "tools", "inputs", "pcAccess", "steps", "warnings", "totals", "requires", "needs", "service", "resources", "capabilities", "subtitle", "aliases", "retention", "costs"];
    const GRANTS: [&str; 8] = ["environments", "public", "tools", "inputs", "pcAccess", "warnings", "totals", "requires"];
    let shown = |key: &str| text::shown(&key.chars().take(64).collect::<String>());
    // `^[a-z][a-z0-9_-]{0,62}(\.[a-z][a-z0-9_-]{0,62})?$`: one namespace at most, for an import.
    let resource_id = |id: &str| {
        let part = |p: &str| p.len() <= 63 && p.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        match id.split_once('.') {
            None => part(id),
            Some((namespace, rest)) => part(namespace) && part(rest),
        }
    };
    let summary_name = |name: &str| name.len() <= 64 && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    let capability_id = |id: &str| id.len() <= 64 && id.split_once('.').is_some_and(|(area, name)| !area.is_empty() && area.bytes().all(|b| b.is_ascii_lowercase()) && !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    if let Some(key) = review.keys().find(|key| !PARTS.contains(&key.as_str())) {
        return Some(format!("has {}, which format 2 does not have", shown(key)));
    }
    if let Some(key) = GRANTS.iter().find(|key| !review.contains_key(**key)) {
        return Some(format!("is missing {key}, which pages that only read format 1 show"));
    }
    if let Some(resources) = review.get("resources").filter(|value| !value.is_null()) {
        let mut ids = BTreeSet::new();
        for (index, resource) in resources.as_array().into_iter().flatten().enumerate() {
            let at = format!("resources[{index}]");
            let Some(fields) = resource.as_object() else {
                return Some(format!("must list each resource as an object, at {at}"));
            };
            if let Some(key) = fields.keys().find(|key| !["id", "kind", "dependsOn", "when", "summary"].contains(&key.as_str())) {
                return Some(format!("has {}, which a resource cannot have, at {at}", shown(key)));
            }
            let Some(id) = fields.get("id").and_then(Json::as_str).filter(|id| resource_id(id)) else {
                return Some(format!("needs a resource id of lowercase letters, digits and dashes, such as web or models.server, at {at}.id"));
            };
            if !ids.insert(id.to_owned()) {
                return Some(format!("lists the resource {id} twice"));
            }
            if !fields.get("kind").and_then(Json::as_str).is_some_and(|kind| Kind::parse(kind).is_some()) {
                return Some(format!("has a resource kind the Hub does not know at {at}.kind"));
            }
            match fields.get("dependsOn") {
                None | Some(Json::Null) => {}
                Some(Json::Array(ids)) if ids.iter().all(|id| id.as_str().is_some_and(resource_id)) => {}
                Some(_) => return Some(format!("must list dependsOn as resource ids at {at}")),
            }
            match fields.get("when") {
                None | Some(Json::Null) => {}
                Some(Json::Array(when)) if when.iter().all(Json::is_string) => {
                    if when.len() > limits::CONDITION_TERMS.max {
                        return Some(format!("lists more than {} conditions in when at {at}", limits::CONDITION_TERMS.max));
                    }
                }
                Some(_) => return Some(format!("must list when as text at {at}")),
            }
            match fields.get("summary") {
                None | Some(Json::Null) => {}
                Some(Json::Object(summary)) => {
                    if summary.len() > 32 {
                        return Some(format!("has more than 32 summary values at {at}"));
                    }
                    for (name, value) in summary {
                        if !summary_name(name) {
                            return Some(format!("has a summary name other than letters, digits, _ and - at {at}.summary"));
                        }
                        if value.is_array() || value.is_object() {
                            return Some(format!("must give each summary value as text, a number or true/false at {at}.summary.{name}"));
                        }
                    }
                }
                Some(_) => return Some(format!("must give summary as an object at {at}")),
            }
        }
    }
    if let Some(capabilities) = review.get("capabilities").filter(|value| !value.is_null()) {
        let mut ids = BTreeSet::new();
        for (index, capability) in capabilities.as_array().into_iter().flatten().enumerate() {
            let at = format!("capabilities[{index}]");
            let Some(fields) = capability.as_object() else {
                return Some(format!("must list each capability as an object, at {at}"));
            };
            if let Some(key) = fields.keys().find(|key| !["id", "selection", "locked"].contains(&key.as_str())) {
                return Some(format!("has {}, which a capability cannot have, at {at}", shown(key)));
            }
            let Some(id) = fields.get("id").and_then(Json::as_str).filter(|id| capability_id(id)) else {
                return Some(format!("needs a capability id such as models.local at {at}.id"));
            };
            if !ids.insert(id.to_owned()) {
                return Some(format!("lists the capability {id} twice"));
            }
            if !fields.get("selection").and_then(Json::as_str).is_some_and(|s| ["required", "optional", "default"].contains(&s)) {
                return Some(format!("must give selection as required, optional or default at {at}"));
            }
            if fields.get("locked").is_some_and(|locked| !locked.is_boolean()) {
                return Some(format!("must give locked as true or false at {at}"));
            }
        }
    }
    if let Some(retention) = review.get("retention").filter(|value| !value.is_null()) {
        for (key, value) in retention.as_object().into_iter().flatten() {
            if key != "onStop" && key != "onRemove" {
                return Some(format!("has {}, which retention cannot have, at retention", shown(key)));
            }
            if !value.as_str().is_some_and(|v| v == "keep" || v == "ask") {
                return Some(format!("must give retention {key} as keep or ask"));
            }
        }
    }
    // Optional: older format 2 reviews leave costs out; an empty list says there are none.
    if let Some(costs) = review.get("costs").filter(|value| !value.is_null()) {
        let Some(costs) = costs.as_array().filter(|items| items.iter().all(Json::is_string)) else {
            return Some("must list costs as text".into());
        };
        if costs.len() > limits::REVIEW_COSTS.max {
            return Some(format!("lists more than {} costs", limits::REVIEW_COSTS.max));
        }
    }
    None
}

/// The parts of a review that decide what a template does to a computer, for comparing the Hub
/// page's review with the one computed from the files.
pub fn essentials(review: &Json) -> Json {
    let tools: Vec<Json> = review["tools"].as_array().into_iter().flatten().map(|tool| json!({
        "name": tool["name"], "source": tool["source"], "environment": tool["environment"],
        "downloads": tool["downloads"], "commands": tool["commands"], "check": tool["check"], "command": tool["command"],
        "when": tool["when"], "signin": tool["signin"], "signinWhen": tool["signinWhen"], "signinSource": tool["signinSource"],
    })).collect();
    json!({
        "environments": review["environments"], "totals": review["totals"], "public": review["public"], "pcAccess": review["pcAccess"],
        "tools": tools, "inputs": review["inputs"], "warnings": review["warnings"], "needs": review["needs"], "service": review["service"],
        "resources": review["resources"], "capabilities": review["capabilities"], "retention": review["retention"],
    })
}

/// Whether the Hub page's review says something other than the files, in the parts that matter.
/// A page without one, or with a review in another format, is not compared.
pub fn review_differs(local: &Json, page: &Json) -> bool {
    let Some(fields) = page.as_object().filter(|page| !page.is_empty()) else { return false };
    if fields.get("format").and_then(Json::as_u64).unwrap_or(REVIEW_FORMAT) != REVIEW_FORMAT {
        return false;
    }
    essentials(local) != essentials(page)
}

#[allow(dead_code)]
fn unused(_: Keep, _: Place) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_review_lists_what_each_resource_may_cost() {
        let cost = |kind: Kind, spec: &str| published_cost("pool", kind, &serde_yaml_ng::from_str(spec).unwrap());
        assert_eq!(cost(Kind::ComputePool, "{source: cloud, cloud: {provider: runpod, max_hourly_cost: 2.5}}").as_deref(), Some("pool rents compute from runpod; the provider bills it, up to 2.5 per hour."));
        assert_eq!(cost(Kind::ComputePool, "{cloud: {provider: \"{{inputs.provider}}\", max_hourly_cost: \"{{inputs.cap}}\"}}").as_deref(), Some("pool rents compute from the provider chosen at setup; the provider bills it, up to the hourly limit chosen at setup."));
        assert_eq!(cost(Kind::ComputePool, "{cloud: {provider: vast}}").as_deref(), Some("pool rents compute from vast; the provider bills it, with no hourly limit set in the template."));
        assert_eq!(cost(Kind::ComputePool, "{source: this_computer}"), None, "this computer's own share costs nothing extra");
        assert_eq!(cost(Kind::WorkerGroup, "{budget: {cost_cap: 20, currency: USD}}").as_deref(), Some("pool: at most 20 USD of model or provider spend, as an estimate the setup enforces where it can."));
        assert_eq!(cost(Kind::WorkerGroup, "{budget: {cost_cap: \"{{inputs.budget}}\"}}").as_deref(), Some("pool: at most the spend limit chosen at setup, as an estimate the setup enforces where it can."));
        assert_eq!(cost(Kind::WorkerGroup, "{budget: {time_minutes: 30}}"), None, "a time budget is not a cost");
        assert_eq!(cost(Kind::WorkspacePool, "{cloud_fallback: true}").as_deref(), Some("pool may fall back to rented compute; the provider bills it."));
        assert_eq!(cost(Kind::WorkspacePool, "{cloud_fallback: \"{{inputs.fallback}}\"}").as_deref(), Some("pool may fall back to rented compute if that is chosen at setup; the provider bills it."));
        assert_eq!(cost(Kind::WorkspacePool, "{cloud_fallback: false}"), None);
        assert_eq!(cost(Kind::Environment, "{cloud_fallback: true}"), None, "only the kinds the plan prices");
    }

    #[test]
    fn a_capability_this_kind_of_grid_does_not_offer_says_so() {
        let host = Host {
            yougori: "1.2.0".into(),
            platform: "linux-x86_64".into(),
            gpu: Some(false),
            memory_gb: None,
            free_disk_gb: None,
            capabilities: serde_json::from_value(json!({"os": "linux", "arch": "x86_64", "gpu": "none", "runtimes": ["containers"], "privateBuild": false})).unwrap(),
        };
        let wanted = |id: &str| CheckedCapability { id: id.into(), selection: Selection::Required, locked: false, when: None };
        let mut problems = Vec::new();
        decide_capabilities(&[wanted("grid.create"), wanted("grid.reuse_compute")], &BTreeMap::new(), &BTreeMap::new(), &[], &host, Some(GridProfile::AccessGrid), "", &mut problems);
        let said = problems.iter().find(|p| p.code == "capability_not_enableable").unwrap_or_else(|| panic!("{problems:?}"));
        assert!(said.message.contains("Access Grid setups don't offer it") && !said.message.contains("this computer"), "{}", said.message);
        let mut problems = Vec::new();
        decide_capabilities(&[wanted("grid.create"), wanted("grid.reuse_compute")], &BTreeMap::new(), &BTreeMap::new(), &[], &host, Some(GridProfile::NeoGrid), "", &mut problems);
        assert!(!problems.iter().any(|p| p.code == "capability_not_enableable"), "{problems:?}");
    }

    /// A format 2 package whose `web` sandbox installs `tool`.
    fn toolbox(tool: &str) -> format::Files {
        let template = format!("format_version: 2\nkind: template\nname: toolbox\ntitle: Toolbox\nsummary: A sandbox with a tool.\nversion: 1.0.0\nlicense: MIT\nrequires: {{yougori: 1.2.0}}\ntools:\n  web: [{tool}]\n");
        let project = "format_version: 2\nproject: toolbox\nenvironments:\n  web:\n    image: python:3.12-slim\n    ports: [8080]\n";
        format::Files::from([(format::TEMPLATE_FILE.to_owned(), template.into_bytes()), (format::PROJECT_FILE.to_owned(), project.as_bytes().to_vec())])
    }

    fn httpie() -> Tool {
        let text = "kind: tool\nname: httpie\ntitle: HTTPie\nsummary: A command-line HTTP client.\nversion: 1.0.0\nlicense: MIT\ncommand: http\ninstall:\n  - python3 -m pip install --user httpie==3.2.4\ncheck: http --version\nsignin: {method: api-key, variable: HTTPIE_TOKEN}\nneeds: {internet: true}\naccess: {internet: true, folders: [/workspace/.httpie]}\ninputs: [{name: HTTPIE_TOKEN, secret: true}]\n";
        format::tool(&format::Files::from([(format::TOOL_FILE.to_owned(), text.as_bytes().to_vec())]), "").unwrap()
    }

    fn linux() -> Host {
        Host {
            yougori: "1.2.0".into(),
            platform: "linux-x86_64".into(),
            gpu: Some(false),
            memory_gb: Some(16.0),
            free_disk_gb: Some(100.0),
            capabilities: serde_json::from_value(json!({"os": "linux", "arch": "x86_64", "gpu": "none", "runtimes": ["containers"], "privateBuild": true})).unwrap(),
        }
    }

    /// PROVES a Hub tool resolved before the review is reviewed exactly as a bundled tool is:
    /// its install lines' download addresses, its key as a secret the person gives, the digest
    /// of the files that will be installed, the community warning, and what it declares (shown,
    /// never granted). Unresolved, the review can only promise a check at run time.
    #[test]
    fn a_resolved_hub_tool_is_reviewed_like_a_bundled_one_and_its_declaration_grants_nothing() {
        let answers = Answers { instance: "toolbox".into(), ..Answers::default() };
        let mut checked = format::template(&toolbox("hub/acme/httpie@1.0.0")).unwrap_or_else(|problems| panic!("{problems:?}"));
        let before = plan(&Package::local(checked.clone()), &answers, &linux()).unwrap_or_else(|problems| panic!("{problems:?}"));
        let tool = before.review.downloads.iter().find(|d| d.kind == "tool").unwrap();
        assert_eq!((tool.name.as_str(), tool.from.as_deref(), tool.digest.as_deref()), ("acme/httpie", Some("the Hub"), None));
        assert!(before.review.warnings.iter().any(|w| w == "Installs the Hub tool acme/httpie; its files are checked when it runs."), "{:?}", before.review.warnings);
        assert!(!before.review.downloads.iter().any(|d| d.kind == "installer"), "{:?}", before.review.downloads);
        assert!(before.review.installs.is_empty(), "nothing is known of an unresolved tool's lines: {:?}", before.review.installs);
        assert!(before.resources[0].spec["secrets"].as_object().is_none_or(|secrets| secrets.is_empty()), "{}", before.resources[0].spec);

        checked.tools[0].resolved = Some(format::ResolvedTool { tool: httpie(), version: "1.0.0".into(), digest: "ab".repeat(32), verified: false });
        let after = plan(&Package::local(checked.clone()), &answers, &linux()).unwrap_or_else(|problems| panic!("{problems:?}"));
        assert_ne!(after.digest, before.digest, "the plan's digest covers what was resolved");
        let tool = after.review.downloads.iter().find(|d| d.kind == "tool").unwrap();
        assert_eq!((tool.version.as_deref(), tool.digest.as_deref(), tool.verified), (Some("1.0.0"), Some("ab".repeat(32).as_str()), Some(false)));
        assert!(after.review.downloads.iter().any(|d| d.kind == "installer" && d.name == "https://pypi.org" && d.from.as_deref() == Some("acme/httpie")), "{:?}", after.review.downloads);
        // The lines it runs in the sandbox are in the review itself, not only where they fetch from.
        assert_eq!(after.review.installs, vec![ToolLines { resource: "web".into(), tool: "acme/httpie".into(), commands: vec!["python3 -m pip install --user httpie==3.2.4".into()], check: Some("http --version".into()) }]);
        let warnings = &after.review.warnings;
        assert!(warnings.iter().any(|w| w == &format!("Installs the Hub tool acme/httpie 1.0.0, whose files (sha256:{}) were fetched and checked for this review; applying installs exactly them.", "ab".repeat(32))), "{warnings:?}");
        assert!(warnings.iter().any(|w| w == "The Hub tool acme/httpie is not checked by Yougori: its install lines can contain harmful code. Read its files first."), "{warnings:?}");
        assert!(warnings.iter().any(|w| w == "Installs software from https://pypi.org."), "{warnings:?}");
        assert!(!warnings.iter().any(|w| w.contains("checked when it runs")), "{warnings:?}");
        // What it declares is one line of the review, in the tool's own words, and grants nothing:
        // the sandbox's spec carries only what the project and the person's answers give it.
        assert!(after.review.permissions.iter().any(|p| p == "web installs the tool acme/httpie, which says it uses the internet, writes /workspace/.httpie, reads the secret HTTPIE_TOKEN. That is the tool's own word: the sandbox has only what its settings and your answers give it."), "{:?}", after.review.permissions);
        let spec = &after.resources[0].spec;
        assert_eq!(spec["tools"][0]["source"], "hub");
        assert_eq!(spec["tools"][0]["item"], "acme/httpie");
        assert_eq!(spec["tools"][0]["version"], "1.0.0");
        assert_eq!(spec["secrets"], json!({"HTTPIE_TOKEN": "hub-toolbox-key-httpie"}), "its key comes from the person, as a bundled tool's does: {spec}");
        for field in ["internet", "volumes", "pc_access", "sync", "gpu"] {
            assert_eq!(spec[field], before.resources[0].spec[field], "the tool's declared access changes nothing in the sandbox ({field}): {spec}");
        }
        assert!(after.review.secrets.iter().any(|s| s.variable == "HTTPIE_TOKEN" && s.source == "the key of the tool acme/httpie"), "{:?}", after.review.secrets);
        let verified = {
            let mut checked = checked.clone();
            checked.tools[0].resolved.as_mut().unwrap().verified = true;
            plan(&Package::local(checked), &answers, &linux()).unwrap()
        };
        assert!(!verified.review.warnings.iter().any(|w| w.contains("not checked by Yougori")), "{:?}", verified.review.warnings);

        // The published review says the same.
        let published = published_review(&Package::local(checked), &[]).unwrap();
        let entry = &published["tools"][0];
        assert_eq!(entry["source"], "hub");
        assert_eq!(entry["ref"], "hub/acme/httpie@1.0.0");
        assert_eq!(entry["digest"], "ab".repeat(32));
        assert_eq!(entry["verified"], false);
        assert_eq!(entry["downloads"], json!(["https://pypi.org"]));
        assert_eq!(entry["commands"], json!(["python3 -m pip install --user httpie==3.2.4"]));
        assert_eq!(entry["access"], json!(["uses the internet", "writes /workspace/.httpie", "reads the secret HTTPIE_TOKEN"]));
        assert_eq!(entry["inputs"], json!(["HTTPIE_TOKEN"]));
        let warnings = published["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w == "The Hub tool acme/httpie is not checked by Yougori: its install lines can contain harmful code. Read its files first."), "{warnings:?}");
        assert!(warnings.iter().any(|w| w == "Installs software from https://pypi.org."), "{warnings:?}");
        assert!(!warnings.iter().any(|w| w.as_str().is_some_and(|w| w.contains("checked when it runs"))), "{warnings:?}");
        assert_eq!(review_shape_problem(&published), None);
    }
}
