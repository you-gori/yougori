//! Drafts: what a person chose in the desktop template builder or in `yougori template new`, and
//! the format 2 package made from it.
//!
//! [`to_package`] turns a [`Draft`] into the same template and project files a technical author
//! would write by hand (plan 5.3), built from one fragment per capability: the questions it asks,
//! the resources it adds and the steps, outputs and views that go with them. The result is meant
//! to be edited: every value it chooses is a safe default, and nothing in it is a secret.
//!
//! A capability that is Planned, only in the private build, or not supported by the chosen grid
//! is refused with a diagnostic. A capability another one needs is added and noted. A capability
//! the engine supports but no fragment can express yet is kept in the template's capability list
//! and noted, never dropped. The same draft always gives the same bytes.
//!
//! [`from_package`] reads a package back into a draft, so the builder can show a template's
//! choices before planning. What a draft cannot hold (conditions, resources, steps) stays in the
//! package and is named in the notes.
use crate::{
    capability::{self, Capability, GridProfile, Status},
    dto::{Diagnostic, Severity},
    format::{self, Binding, CapabilityUse, Checked, Choice, Files, Input, Output, Project, QuestionKind, Requires, Resource, Retention, Selection, Step, Template, ToolOptions},
    resource::FolderMode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

/// Ubuntu 24.04 locked to one multi-architecture image index, the same one the tool shortcuts use.
pub const WORKSPACE_IMAGE: &str = "ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55";
/// The database a generated app gets when it asks for one.
pub const DATABASE_IMAGE: &str = "docker.io/library/postgres:16.4-alpine";
/// The version a new draft starts at.
pub const DRAFT_VERSION: &str = "0.1.0";
/// The image the cloud model gateway runs in.
pub const GATEWAY_IMAGE: &str = "docker.io/library/python:3.12-slim";
/// The cloud model gateway (`models.cloud`), written into a package beside its project file.
pub const GATEWAY_FILE: &str = "model-gateway.py";
pub const GATEWAY_SCRIPT: &str = include_str!("model-gateway.py");
/// The files a generated package may carry beside its own four.
pub const EXTRA_FILES: &[&str] = &[GATEWAY_FILE];

const SUMMARY: &str = "One line about what this sets up.";
const ADDRESS_PATTERN: &str = "^[0-9A-Fa-f.:]{2,45}$";
const USERNAME_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$";
const NAME_PATTERN: &str = "^.{1,64}$";
const IMAGE_PATTERN: &str = "^[a-z0-9][a-z0-9._/-]{0,250}(:[A-Za-z0-9._-]{1,128})?(@sha256:[a-f0-9]{64})?$";
const MODEL_PATTERN: &str = "^(hf\\.co/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}|yg/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9_-]{0,63})$";
const PATH_PATTERN: &str = "^/[A-Za-z0-9._~/-]{0,200}$";
/// A host name a VM sandbox's route reaches: labels of letters, digits and dashes, with a dot.
const HOST_PATTERN: &str = "^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$";
/// A path a route allows: no spaces, query or fragment.
const ROUTE_PATH_PATTERN: &str = "^/[A-Za-z0-9._~/{}%:@+-]{0,500}$";
/// The name a credential was enrolled under.
/// A published guest service's name: what `yougori sandbox publish --service` names.
const SERVICE_NAME_PATTERN: &str = "^[A-Za-z][A-Za-z0-9._-]{0,63}$";
const CREDENTIAL_PATTERN: &str = "^[A-Za-z0-9._-]{1,128}$";

// ---- The draft ----

/// What the builder has so far, in the shape the desktop sends (`SetupDraft`). Secret values are
/// never part of it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    /// What the person called it. The package name is made from it.
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Where it starts from, when it starts from something that exists. Kept as the desktop sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Json>,
    /// One of the four grid recipes: `sandbox-grid`, `neo-grid`, `access-grid`,
    /// `swarm-mining-grid`. Without one the draft is an ordinary setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe: Option<String>,
    /// Environments on this computer it is made from (capture); kept, not generated from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<String>,
    /// Capability id to the choice made about it.
    #[serde(default)]
    pub capabilities: BTreeMap<String, CapabilityChoice>,
    /// The questions read from a source, with their answers in `answers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub questions: Vec<QuestionDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub answers: BTreeMap<String, Json>,
}

/// One capability as the builder holds it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityChoice {
    /// Whether it is part of the template. A deselected choice keeps its settings.
    #[serde(default = "yes")]
    pub selected: bool,
    /// Required, optional (off unless turned on) or default (on unless turned off).
    #[serde(default)]
    pub mode: Mode,
    /// Whether the person running the template may change this capability and its answers.
    #[serde(default = "yes")]
    pub runner_editable: bool,
    /// Question id to the value the author chose: it becomes the question's default.
    #[serde(default)]
    pub settings: BTreeMap<String, Json>,
    /// Question id to the creator controls for that one question (plan 5.3).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub controls: BTreeMap<String, Control>,
}

impl Default for CapabilityChoice {
    fn default() -> Self {
        CapabilityChoice { selected: true, mode: Mode::Required, runner_editable: true, settings: BTreeMap::new(), controls: BTreeMap::new() }
    }
}

fn yes() -> bool {
    true
}

/// How a capability or a question is used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Always part of the setup; a question must be answered.
    #[default]
    Required,
    /// Off unless the person turns it on; a question may be left empty.
    Optional,
    /// On unless the person turns it off; a question starts from the author's value.
    Default,
}

impl From<Mode> for Selection {
    fn from(mode: Mode) -> Selection {
        match mode {
            Mode::Required => Selection::Required,
            Mode::Optional => Selection::Optional,
            Mode::Default => Selection::Default,
        }
    }
}

impl From<Selection> for Mode {
    fn from(selection: Selection) -> Mode {
        match selection {
            Selection::Required => Mode::Required,
            Selection::Optional => Mode::Optional,
            Selection::Default => Mode::Default,
        }
    }
}

/// The creator controls for one question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Control {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "yes")]
    pub runner_editable: bool,
}

/// A question as the desktop shows it (`SettingDescriptor`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuestionDescriptor {
    pub id: String,
    pub label: String,
    /// `text`, `number`, `choice`, `toggle` or `secret`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<QuestionOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Json>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// Set when this is not an input but an installation-time binding the person chooses on their
    /// own computer: a folder, a drive, a file or an existing resource. The builder shows a
    /// picker rather than a text box, and the answer goes to the planner as that binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    /// For a folder binding: what the setup may do with the folder, in the words the review and
    /// the CLI use, so a person reads the same sentence wherever they are asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Whether the person must answer it before the setup can be planned.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
}

/// What a folder binding will be allowed to do with the folder, in one line. The CLI
/// (`hub::plan::folder_access`) and the desktop builder show exactly this sentence, and the
/// plan's review says the same thing about the folder that was chosen.
pub fn folder_access(read_only: bool, synced: bool) -> String {
    folder_access_for(if synced { FolderMode::Sync } else { FolderMode::Mount }, read_only)
}

/// [`folder_access`] for any folder mode, a staged one included.
pub fn folder_access_for(mode: FolderMode, read_only: bool) -> String {
    if mode == FolderMode::Staged {
        return "The VM sandbox works on a copy of this folder. The folder changes only when you review the copy's changes and approve them, file by file.".to_owned();
    }
    let synced = mode == FolderMode::Sync;
    match (synced, read_only) {
        (true, false) => "The sandbox keeps its own copy of this folder and the two are kept in step both ways. A file changed in both places keeps both copies; nothing is replaced silently. You agree to this again before anything is created.".to_owned(),
        (true, true) => "The sandbox keeps its own copy of this folder. Changes travel from this computer into the sandbox only; nothing here is changed.".to_owned(),
        (false, false) => "The sandbox can read this folder and change files in it. You agree to this again before anything is created.".to_owned(),
        (false, true) => "The sandbox can read this folder. It is never changed.".to_owned(),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionOption {
    pub value: String,
    pub label: String,
}

// ---- The package made from it ----

/// A generated package: the files an author edits, plus what the generator added and noted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    /// The package name, made from the draft's name.
    pub name: String,
    /// `yougori-template.yaml`.
    pub manifest: String,
    /// `yougori.yaml`.
    pub project: String,
    pub readme: String,
    pub changelog: String,
    /// Capabilities another chosen one needed, added to the draft.
    pub added: Vec<String>,
    /// What the person should know: added dependencies, capabilities kept without resources,
    /// settings no question uses.
    pub notes: Vec<Diagnostic>,
    /// Other files the package carries, by name (one of `EXTRA_FILES`), such as the cloud model
    /// gateway's script.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl Generated {
    /// The package's files by path.
    pub fn files(&self) -> Files {
        let mut files = Files::new();
        files.insert(format::TEMPLATE_FILE.to_owned(), self.manifest.clone().into_bytes());
        files.insert(format::PROJECT_FILE.to_owned(), self.project.clone().into_bytes());
        files.insert("README.md".to_owned(), self.readme.clone().into_bytes());
        files.insert("CHANGELOG.md".to_owned(), self.changelog.clone().into_bytes());
        for (name, text) in &self.extra {
            files.insert(name.clone(), text.clone().into_bytes());
        }
        files
    }
}

fn note(code: &'static str, message: impl Into<String>) -> Diagnostic {
    Diagnostic { severity: Severity::Info, ..Diagnostic::error(code, message) }
}

/// The package name made from what the person called it: lowercase letters, digits and dashes.
pub fn package_name(name: &str) -> String {
    let mut slug = String::new();
    for character in name.trim().chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug: String = slug.trim_end_matches('-').chars().take(64).collect();
    slug.trim_end_matches('-').to_owned()
}

/// The grid profile of a recipe slug.
pub fn recipe_profile(recipe: &str) -> Option<GridProfile> {
    GridProfile::GRIDS.into_iter().find(|profile| profile.recipe_slug() == Some(recipe))
}

/// Turns a draft into a format 2 package. Errors name the field to change; nothing is guessed.
pub fn to_package(draft: &Draft) -> Result<Generated, Vec<Diagnostic>> {
    let mut problems = Vec::new();
    let name = package_name(&draft.name);
    if name.is_empty() || !format::valid_name(&name) {
        problems.push(Diagnostic::error("draft_name", "Give it a name with at least one letter or digit.").at("name"));
    }
    let profile = match draft.recipe.as_deref().filter(|recipe| !recipe.is_empty()) {
        None => None,
        Some(recipe) => match recipe_profile(recipe) {
            Some(profile) => Some(profile),
            None => {
                problems.push(Diagnostic::error("unknown_recipe", format!("{recipe} is not one of the grid recipes.")).at("recipe"));
                None
            }
        },
    };

    // The chosen capabilities, each checked against the registry.
    let mut chosen: Vec<&'static Capability> = Vec::new();
    for (id, choice) in &draft.capabilities {
        if !choice.selected {
            continue;
        }
        let field = format!("capabilities.{id}");
        let Some(cap) = capability::find(id) else {
            problems.push(Diagnostic::error("unknown_capability", format!("{id} isn't known to this version of Yougori. Turn it off, or update Yougori.")).at(field));
            continue;
        };
        match cap.status {
            Status::Planned => problems.push(Diagnostic::error("capability_not_enableable", format!("{} is planned and can't be turned on yet.", cap.name)).at(field)),
            Status::PrivateBuild => problems.push(Diagnostic::error("capability_not_enableable", format!("{} is only in the private build and never goes in a template.", cap.name)).at(field)),
            Status::Shipped => {
                if let Some(problem) = unsupported_here(cap, profile) {
                    problems.push(problem.at(field));
                } else {
                    chosen.push(cap);
                }
            }
        }
    }
    for (at, cap) in chosen.iter().enumerate() {
        for other in &chosen[at + 1..] {
            if cap.conflicts.contains(&other.id) || other.conflicts.contains(&cap.id) {
                problems.push(Diagnostic::error("capability_conflict", format!("{} can't be used together with {}. Turn one of them off.", cap.name, other.name)).at(format!("capabilities.{}", other.id)));
            }
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    // What the chosen ones need, added until nothing is missing.
    let mut notes = Vec::new();
    let mut added = Vec::new();
    loop {
        let selected: Vec<&str> = chosen.iter().map(|cap| cap.id).collect();
        // The first chosen capability with a need no choice meets yet, and that need. A grid whose
        // own handler supplies a need waives it, as the package checker and the planner do.
        let first = chosen.iter().find_map(|cap| cap.missing_for(&selected, profile).into_iter().next().map(|any_of| (*cap, any_of)));
        let mut next: Option<&'static Capability> = None;
        let mut unmet: Option<(&'static Capability, &'static [&'static str])> = None;
        if let Some((cap, any_of)) = first {
            let fits = any_of.iter().filter_map(|id| capability::find(id)).find(|dep| {
                dep.status == Status::Shipped
                    && unsupported_here(dep, profile).is_none()
                    && !chosen.iter().any(|c| c.conflicts.contains(&dep.id) || dep.conflicts.contains(&c.id))
            });
            match fits {
                Some(dep) => next = Some(dep),
                None => unmet = Some((cap, any_of)),
            }
        }
        if let Some((cap, any_of)) = unmet {
            let names: Vec<&str> = any_of.iter().map(|id| capability::find(id).map_or(*id, |c| c.name)).collect();
            return Err(vec![Diagnostic::error("capability_requires", format!("{} needs {}, and none of them can be added here.", cap.name, names.join(" or "))).at(format!("capabilities.{}", cap.id))]);
        }
        match next {
            Some(dep) => {
                notes.push(note("capability_added", format!("{} was added because another choice needs it.", dep.name)).at(format!("capabilities.{}", dep.id)));
                added.push(dep.id.to_owned());
                chosen.push(dep);
            }
            None => break,
        }
    }

    if !draft.environments.is_empty() {
        return Err(vec![Diagnostic::error("draft_environments_not_generated", "A template made from sandboxes on this computer comes from yougori template capture for now; the builder makes one from capabilities. Remove the sandboxes from the draft, or capture them instead.").at("environments")]);
    }
    let mut build = Build::new(draft, profile, &chosen);
    build.notes.extend(notes);
    if draft.source.as_ref().is_some_and(|source| !source.is_null()) {
        build.notes.push(Diagnostic { severity: Severity::Warning, ..Diagnostic::error("draft_source_not_copied", "This package is made from your choices only. The resources, steps and outputs of the template you started from are not copied into it; to keep them, edit that template's own files.").at("source") });
    }
    build.fragments();
    if !build.problems.is_empty() {
        return Err(build.problems);
    }
    build.finish(name, added)
}

/// What a Swarm Mining Grid draft may hold: the review, the model it thinks with, where its
/// findings are kept, and how it is watched. Nothing that publishes, connects or runs other work.
const RESEARCH_DRAFT: &[&str] = &["grid.create", "grid.join", "grid.worker_limits", "research.source", "models.local", "data.artifacts", "people.invites", "run.health_logs", "run.notifications"];

/// Why a shipped capability can't be part of a draft for this grid, if it can't.
fn unsupported_here(cap: &Capability, profile: Option<GridProfile>) -> Option<Diagnostic> {
    if profile == Some(GridProfile::SwarmMiningGrid) && !RESEARCH_DRAFT.contains(&cap.id) {
        return Some(Diagnostic::error("capability_unsupported", format!("{} isn't available in a Swarm Mining Grid setup: it reviews source you give it and nothing else.", cap.name)));
    }
    if cap.id.starts_with("research.") && profile != Some(GridProfile::SwarmMiningGrid) {
        return Some(Diagnostic::error("capability_unsupported", format!("{} runs on a Swarm Mining Grid. Choose that recipe first.", cap.name)));
    }
    if let Some(profile) = profile {
        if !cap.profiles.is_empty() && !cap.profiles.contains(&profile) {
            return Some(Diagnostic::error("capability_unsupported", format!("{} isn't available in a {} setup.", cap.name, crate::plan::profile_name(profile))));
        }
    }
    None
}

fn yaml(value: Json) -> Yaml {
    serde_yaml_ng::to_value(value).unwrap_or(Yaml::Null)
}

fn input(id: &str, question: &str, kind: &str) -> Input {
    Input { id: Some(id.to_owned()), question: Some(question.to_owned()), kind: Some(kind.to_owned()), ..Input::default() }
}

fn hint(mut input: Input, hint: &str) -> Input {
    input.hint = Some(hint.to_owned());
    input
}

fn pattern(mut input: Input, pattern: &str) -> Input {
    input.pattern = Some(pattern.to_owned());
    input
}

fn default(mut input: Input, value: Json) -> Input {
    input.default = Some(yaml(value));
    input
}

fn range(mut input: Input, min: f64, max: f64) -> Input {
    input.min = Some(min);
    input.max = Some(max);
    input
}

fn when(mut input: Input, condition: Json) -> Input {
    input.when = Some(yaml(condition));
    input
}

fn optional(mut input: Input) -> Input {
    input.required = Some(false);
    input
}

fn choices(mut input: Input, options: &[(&str, &str, &str)]) -> Input {
    input.choices = options
        .iter()
        .map(|(value, label, hint)| Choice { value: Some((*value).to_owned()), label: Some((*label).to_owned()), hint: (!hint.is_empty()).then(|| (*hint).to_owned()) })
        .collect();
    input
}

/// A resource that belongs to `capability`: the planner leaves it out when that capability is off.
fn resource(kind: &str, capability: &str, spec: Json) -> Resource {
    Resource { kind: kind.to_owned(), capability: Some(capability.to_owned()), spec: yaml(spec), ..Resource::default() }
}

fn step(title: &str, detail: &str) -> Step {
    Step { title: Some(title.to_owned()), detail: Some(detail.to_owned()), ..Step::default() }
}

fn output(key: &str, label: &str, value: &str) -> Output {
    Output { key: Some(key.to_owned()), label: Some(label.to_owned()), value: Some(value.to_owned()), ..Output::default() }
}

/// The built-in tools whose sign-in a template can open, with the variable an API key goes in.
const SIGN_IN_TOOLS: &[(&str, &str, &str)] = &[
    ("codex", "Codex", "OPENAI_API_KEY"),
    ("claude", "Claude Code", "ANTHROPIC_API_KEY"),
    ("gemini", "Gemini CLI", "GEMINI_API_KEY"),
    ("opencode", "OpenCode", "OPENCODE_API_KEY"),
    ("kilo", "Kilo Code", "KILO_API_KEY"),
];

struct Build<'a> {
    draft: &'a Draft,
    profile: Option<GridProfile>,
    on: BTreeSet<&'static str>,
    order: Vec<&'static Capability>,
    inputs: Vec<Input>,
    /// Question id to the capability that asks it.
    owners: BTreeMap<String, &'static str>,
    resources: BTreeMap<String, Resource>,
    app: Option<Json>,
    /// The capabilities whose fragments shaped the `app` sandbox.
    app_by: BTreeSet<&'static str>,
    /// The capability whose fragment is being generated.
    current: Option<&'static str>,
    grid: Option<Json>,
    /// Which of Create a grid or Join a grid made the grid.
    grid_by: Option<&'static str>,
    pool: Option<Json>,
    owner: Option<Json>,
    tools: BTreeMap<String, Vec<String>>,
    tool_options: BTreeMap<String, ToolOptions>,
    bindings: Vec<Binding>,
    steps: Vec<Step>,
    outputs: Vec<Output>,
    views: BTreeSet<&'static str>,
    /// What the template caps (`limits:`), by what it counts.
    limits: BTreeMap<String, Yaml>,
    /// The cloud model gateway's sandbox, while fragments shape it (`models.cloud`).
    gateway: Option<Json>,
    /// The VM sandbox, while fragments shape it (`sandbox.vm`, its workspace and routes).
    vm: Option<Json>,
    /// `sandbox.connect`: a second VM sandbox, `peer`, made from the first's settings at the end.
    vm_peer: bool,
    /// Files the package carries beside its own four.
    extra: BTreeMap<String, String>,
    notes: Vec<Diagnostic>,
    problems: Vec<Diagnostic>,
}

impl<'a> Build<'a> {
    fn new(draft: &'a Draft, profile: Option<GridProfile>, chosen: &[&'static Capability]) -> Build<'a> {
        let on: BTreeSet<&'static str> = chosen.iter().map(|cap| cap.id).collect();
        // Registry order, so the same choices always come out in the same order.
        let order = capability::all().iter().filter(|cap| on.contains(cap.id)).collect();
        Build {
            draft,
            profile,
            on,
            order,
            inputs: Vec::new(),
            owners: BTreeMap::new(),
            resources: BTreeMap::new(),
            app: None,
            app_by: BTreeSet::new(),
            current: None,
            grid: None,
            grid_by: None,
            pool: None,
            owner: None,
            tools: BTreeMap::new(),
            tool_options: BTreeMap::new(),
            bindings: Vec::new(),
            steps: Vec::new(),
            outputs: Vec::new(),
            views: BTreeSet::new(),
            limits: BTreeMap::new(),
            gateway: None,
            vm: None,
            vm_peer: false,
            extra: BTreeMap::new(),
            notes: Vec::new(),
            problems: Vec::new(),
        }
    }

    fn has(&self, id: &str) -> bool {
        self.on.contains(id)
    }

    fn choice(&self, cap: &str) -> CapabilityChoice {
        self.draft.capabilities.get(cap).cloned().unwrap_or_default()
    }

    /// Adds a question for `cap`, with the author's value as its default and their controls.
    fn ask(&mut self, cap: &'static Capability, mut question: Input) {
        let id = question.id.clone().unwrap_or_default();
        let secret = question.kind.as_deref() == Some("secret");
        let choice = self.choice(cap.id);
        question.group = Some(cap.group.id().to_owned());
        if !secret {
            if let Some(value) = choice.settings.get(&id).filter(|value| !value.is_null()) {
                match setting(value, question.kind.as_deref()) {
                    Some(value) => question.default = Some(yaml(value)),
                    None => self.problems.push(Diagnostic::error("draft_setting_invalid", format!("{} takes yes or no, and {value} is neither.", question.question.as_deref().unwrap_or(&id))).at(format!("capabilities.{}.{id}", cap.id))),
                }
            }
        }
        if let Some(control) = choice.controls.get(&id) {
            match control.mode {
                Mode::Required => question.required = None,
                Mode::Optional => question.required = Some(false),
                Mode::Default => {
                    if question.default.is_none() && !secret {
                        self.problems.push(Diagnostic::error("draft_default_missing", format!("{} starts from a default, so it needs a value.", question.question.as_deref().unwrap_or(&id))).at(format!("capabilities.{}.{id}", cap.id)));
                    }
                }
            }
        }
        let locked = !choice.runner_editable || choice.controls.get(&id).is_some_and(|control| !control.runner_editable);
        if locked && !secret {
            if question.default.is_some() {
                question.editable = Some(false);
            } else {
                self.problems.push(Diagnostic::error("draft_lock_needs_value", format!("{} is fixed by the author, so it needs a value.", question.question.as_deref().unwrap_or(&id))).at(format!("capabilities.{}.{id}", cap.id)));
            }
        }
        self.owners.insert(id, cap.id);
        self.inputs.push(question);
    }

    fn cap(id: &str) -> &'static Capability {
        capability::find(id).expect("registry id")
    }

    fn keep(&mut self, cap: &Capability, message: &str) {
        self.notes.push(note("capability_kept", format!("{}: {message}", cap.name)).at(format!("capabilities.{}", cap.id)));
    }

    /// How the setup is reached: one fixed value, or a question among the chosen ways.
    fn access(&mut self, grid: bool) -> (Json, bool) {
        if grid && self.has("web.private") {
            self.problems.push(Diagnostic::error("draft_private_grid", "A grid is reached by the computers and people that join it, so it can't be kept to this computer. Turn off Keep it to this computer; the grid is reached on this network.").at("capabilities.web.private"));
        }
        let mut ways: Vec<(&str, &str, &str)> = Vec::new();
        if grid || self.has("web.lan") {
            ways.push(("lan", "This network only", "Computers on your LAN or VPN."));
        } else if self.has("web.private") {
            ways.push(("private", "Only this computer", ""));
        } else if !(self.has("web.quick_link") || self.has("web.domain")) {
            ways.push(("none", "Only this computer", ""));
        }
        if self.has("web.quick_link") {
            ways.push(("quick", "A quick public link", "A free HTTPS link. It can change after a restart."));
        }
        if self.has("web.domain") {
            ways.push(("domain", "My own domain", "A domain you saved with yougori domain add."));
        }
        let domain = ways.iter().any(|(value, ..)| *value == "domain");
        let owner = ["web.quick_link", "web.domain", "web.lan", "web.service"].into_iter().find(|id| self.has(id)).map(Build::cap);
        if ways.len() == 1 {
            if domain {
                self.ask(Build::cap("web.domain"), input("domain", "Which saved domain?", "domain"));
            }
            return (json!(ways[0].0), domain);
        }
        let owner = owner.unwrap_or_else(|| Build::cap("web.quick_link"));
        let first = ways[0].0;
        self.ask(owner, default(choices(input("access", if grid { "Where can people and computers reach it from?" } else { "Who can reach it?" }, "choice"), &ways), json!(first)));
        if domain {
            self.ask(Build::cap("web.domain"), when(input("domain", "Which saved domain?", "domain"), json!({"access": "domain"})));
        }
        (json!("{{inputs.access}}"), domain)
    }

    fn app(&mut self) -> &mut serde_json::Map<String, Json> {
        if let Some(id) = self.current {
            self.app_by.insert(id);
        }
        if self.app.is_none() {
            self.app = Some(json!({
                "type": "container",
                "image": WORKSPACE_IMAGE,
                "cpu": 2,
                "memory": 4,
                "storage": 20,
                "internet": true,
                "working_dir": "/workspace",
                "command": ["sleep", "infinity"],
            }));
        }
        self.app.as_mut().and_then(Json::as_object_mut).expect("app spec")
    }

    fn fragments(&mut self) {
        let generic = self.profile.is_none();
        let grid = self.has("grid.create") || self.has("grid.join");
        if grid && generic {
            self.problems.push(Diagnostic::error("draft_needs_recipe", "A grid needs one of the grid recipes: Sandbox Grid, Neo Grid, Access Grid or Swarm Mining Grid. Choose one first.").at("recipe"));
            return;
        }
        if self.profile == Some(GridProfile::SwarmMiningGrid) && !grid {
            self.problems.push(Diagnostic::error("draft_needs_grid", "A Swarm Mining Grid review is hosted here or joined. Choose Create a grid or Join a grid as well.").at("capabilities"));
            return;
        }
        if self.profile == Some(GridProfile::SwarmMiningGrid) && !self.has("research.source") {
            self.problems.push(Diagnostic::error("draft_needs_research", "A Swarm Mining Grid reviews source. Turn on Review source in a sandbox as well.").at("capabilities.research.source"));
            return;
        }
        if !grid && self.order.iter().any(|cap| cap.id.starts_with("people.")) {
            self.problems.push(Diagnostic::error("draft_needs_grid", "People and access settings belong to a grid. Choose Create a grid or Join a grid as well.").at("capabilities"));
            return;
        }
        let order = self.order.clone();
        for cap in order {
            self.current = Some(cap.id);
            self.fragment(cap);
        }
        self.current = None;
    }

    fn fragment(&mut self, cap: &'static Capability) {
        let profile = self.profile;
        let access_grid = profile == Some(GridProfile::AccessGrid);
        let pool_grid = matches!(profile, Some(GridProfile::NeoGrid | GridProfile::SandboxGrid));
        let research = profile == Some(GridProfile::SwarmMiningGrid);
        match cap.id {
            "grid.local_only" => self.keep(cap, "everything runs on this computer; nothing else is added."),
            "grid.create" if research => {
                // A review this computer hosts: on this computer only, or for people on its network.
                self.ask(cap, pattern(hint(input("project_title", "What is this project called?", "text"), "The name people reviewing it see. Use a short name, not a customer's name."), NAME_PATTERN));
                self.ask(cap, default(choices(input("visibility", "Who can take part?", "choice"), &[("this_computer", "Only this computer", "Nothing is reachable from your network."), ("lan", "People on my network", "They join with the invitation and password.")]), json!("this_computer")));
                self.ask(cap, when(pattern(hint(input("coordinator_address", "Which address on your network do they reach it on?", "text"), "A private address of this computer, such as 192.168.1.20."), ADDRESS_PATTERN), json!({"visibility": "lan"})));
                self.ask(cap, when({
                    let mut question = hint(input("shared_password", "Password for people joining", "secret"), "At least 12 characters. Give it to them privately.");
                    question.min_length = Some(12);
                    question
                }, json!({"visibility": "lan"})));
                self.grid = Some(json!({"profile": "swarm_mining_grid", "mode": "create", "coordinator": "this_computer", "name": "{{inputs.project_title}}", "address": "{{inputs.coordinator_address}}", "access": "lan", "secrets": {"join_password": "{{secrets.shared_password}}"}}));
                self.grid_by = Some(cap.id);
                self.pool = Some(json!({"grid": {"resource": "grid"}, "source": "this_computer", "gpu": "optional", "availability": "always", "local_user_first": true}));
                self.outputs.push(output("project", "Project", "{{inputs.project_title}}"));
                let mut invite = output("invitation", "Invitation for people joining", "{{outputs.grid.invitation}}");
                invite.private = true;
                self.outputs.push(invite);
            }
            "grid.join" if research => {
                self.ask(cap, hint(input("invitation", "The invitation you were given", "secret"), "Paste it exactly. It names the project and the computer that runs it."));
                self.ask(cap, {
                    let mut question = input("join_password", "The password for that project", "secret");
                    question.min_length = Some(10);
                    question
                });
                self.grid = Some(json!({"profile": "swarm_mining_grid", "mode": "join", "coordinator": "remote", "member": "computer", "secrets": {"invitation": "{{secrets.invitation}}", "join_password": "{{secrets.join_password}}"}}));
                self.grid_by = Some(cap.id);
                self.pool = Some(json!({"grid": {"resource": "grid"}, "source": "this_computer", "gpu": "optional", "availability": "always", "local_user_first": true}));
            }
            "research.source" => {
                let hosts = self.has("grid.create");
                if hosts {
                    self.ask(cap, default(choices(input("target_kind", "What are the agents reviewing?", "choice"), &[
                        ("source", "The source only", "Nothing is started; the agents read the code."),
                        ("web", "A website started in the sandbox", "Yougori starts your app inside the sandbox and reviews it there."),
                        ("api", "An API started in the sandbox", "As above, for a service without pages."),
                    ]), json!("source")));
                    let started = json!({"target_kind": ["web", "api"]});
                    self.ask(cap, when(optional(hint(input("setup_command", "How is the project prepared, if it needs preparing?", "text"), "A single command, such as: npm ci.")), started.clone()));
                    self.ask(cap, when(default(hint(input("install_network", "May that preparation reach the internet?", "yesno"), "Only while preparing. The review itself runs with no internet."), json!(false)), started.clone()));
                    self.ask(cap, when(hint(input("start_command", "How is it started?", "text"), "A single command, such as: npm start."), started.clone()));
                    self.ask(cap, when(default(range(input("service_port", "Which port does it listen on inside the sandbox?", "number"), 1024.0, 65535.0), json!(3000)), started.clone()));
                    self.ask(cap, when(optional(default(input("health_path", "Which path says it is ready?", "text"), json!("/health"))), started.clone()));
                    self.ask(cap, when(optional(input("test_command", "How are its own tests run, if you want them run?", "text")), started));
                    self.ask(cap, {
                        let mut question = hint(input("instructions", "What should the agents look into?", "text"), "What matters to you, in your own words.");
                        question.min_length = Some(10);
                        question
                    });
                    self.ask(cap, {
                        let mut question = hint(input("authorized_scope", "What are they allowed to test, and with which test accounts?", "text"), "Only the parts you own or have written permission to test. Never a real customer's account.");
                        question.min_length = Some(10);
                        question
                    });
                    if let Some(grid) = self.grid.as_mut() {
                        grid["research"] = json!({
                            "instructions": "{{inputs.instructions}}", "authorization": "{{inputs.authorized_scope}}", "target": "{{inputs.target_kind}}",
                            "setup_command": "{{inputs.setup_command}}", "install_network": "{{inputs.install_network}}", "start_command": "{{inputs.start_command}}",
                            "port": "{{inputs.service_port}}", "health_path": "{{inputs.health_path}}", "test_command": "{{inputs.test_command}}",
                        });
                    }
                    self.bindings.push(Binding { id: Some("source_folder".into()), kind: Some("folder".into()), question: Some("Which folder holds the project to review?".into()), ..Binding::default() });
                }
                self.ask(cap, default(input("worker_name", "What should this worker be called?", "text"), json!("Review worker")));
                self.ask(cap, default(range(input("worker_cpu", "Processor cores for the worker's sandbox", "number"), 4.0, 64.0), json!(4)));
                self.ask(cap, default(range(input("worker_memory_gb", "Memory for the worker's sandbox, in GB", "number"), 8.0, 512.0), json!(8)));
                self.ask(cap, default(range(input("sandbox_disk_gb", "Disk for the worker's sandbox, in whole GB", "number"), 4.0, 2000.0), json!(20)));
                self.ask(cap, default(range(hint(input("budget_minutes", "How long may it work before stopping?", "number"), "Counted from the moment it starts. It stops by itself when the time is up."), 1.0, 1440.0), json!(60)));
                let policy = if hosts {
                    self.ask(cap, default(choices(input("report_policy", "What happens to a finding?", "choice"), &[("review", "I read it first", "Nothing leaves this computer until you send it."), ("automatic", "Send it to the project automatically", "")]), json!("review")));
                    json!("{{inputs.report_policy}}")
                } else {
                    // A finding for someone else's project is read here first, always.
                    json!("review")
                };
                let limits = json!({"cpu": "{{inputs.worker_cpu}}", "memory_gb": "{{inputs.worker_memory_gb}}", "disk_gb": "{{inputs.sandbox_disk_gb}}"});
                if let Some(pool) = self.pool.as_mut() {
                    pool["limits"] = limits.clone();
                }
                self.resources.insert("sandbox".into(), resource("environment", cap.id, json!({
                    "type": "container", "image": WORKSPACE_IMAGE, "cpu": "{{inputs.worker_cpu}}", "memory": "{{inputs.worker_memory_gb}}", "storage": "{{inputs.sandbox_disk_gb}}",
                    "internet": false, "working_dir": "/project", "command": ["sleep", "infinity"],
                })));
                let mut workers = json!({
                    "pool": {"resource": "computers"}, "role": "research", "name": "{{inputs.worker_name}}", "report_policy": policy, "count": 1, "max": 1,
                    "model": {"resource": "model"}, "environment": {"resource": "sandbox"}, "limits": limits, "budget": {"time_minutes": "{{inputs.budget_minutes}}"},
                });
                if hosts {
                    workers["source"] = json!({"binding": "source_folder"});
                }
                self.resources.insert("workers".into(), resource("worker_group", cap.id, workers));
                self.outputs.push(output("worker", "Worker", "{{inputs.worker_name}}"));
                self.steps.push(step("Read what the agents found", "Findings appear as they are made. Each one says what was tried, what happened, and what it means."));
                self.views.insert("workers");
                self.views.insert("findings");
                self.views.insert("reports");
            }
            "grid.create" => {
                let profile = profile.expect("checked above");
                self.ask(cap, pattern(hint(input("grid_name", "What is the company or team called?", "text"), "Up to 64 characters."), NAME_PATTERN));
                self.ask(cap, pattern(hint(input("coordinator_address", "What is this computer's private network address?", "text"), "An address on your LAN or VPN, such as 192.168.1.20."), ADDRESS_PATTERN));
                let (access, domain) = self.access(true);
                let mut spec = json!({"profile": profile.id(), "mode": "create", "coordinator": "this_computer", "name": "{{inputs.grid_name}}", "address": "{{inputs.coordinator_address}}", "access": access});
                if domain {
                    spec["domain"] = json!("{{inputs.domain}}");
                }
                if !access_grid {
                    self.ask(cap, {
                        let mut question = hint(input("grid_password", "Choose the company password computers use to join", "secret"), "At least 10 characters.");
                        question.min_length = Some(10);
                        question
                    });
                    spec["secrets"] = json!({"join_password": "{{secrets.grid_password}}"});
                }
                self.grid = Some(spec);
                self.grid_by = Some(cap.id);
                if pool_grid {
                    self.pool = Some(json!({"grid": {"resource": "grid"}, "source": if profile == GridProfile::SandboxGrid { "this_computer" } else { "any" }, "local_user_first": true}));
                    self.views.insert("computers");
                }
                self.outputs.push(output("grid_name", "Grid", "{{outputs.grid.name}}"));
                self.outputs.push(output("grid_page", "Grid page", "{{outputs.grid.page}}"));
                self.outputs.push(output("join_address", "Where to join", "{{outputs.grid.join_address}}"));
                let mut invite = output("invitation", "Invitation", "{{outputs.grid.invitation}}");
                invite.private = true;
                self.outputs.push(invite);
            }
            "grid.join" => {
                let profile = profile.expect("checked above");
                self.ask(cap, input("invitation", "Paste the invitation from the grid's admin", "secret"));
                let spec = if access_grid {
                    self.ask(cap, pattern(input("username", "Your username", "text"), USERNAME_PATTERN));
                    self.ask(cap, input("password", "Your password", "secret"));
                    json!({"profile": profile.id(), "mode": "join", "coordinator": "remote", "member": "person", "sign_in": "password", "username": "{{inputs.username}}", "secrets": {"invitation": "{{secrets.invitation}}", "password": "{{secrets.password}}"}})
                } else {
                    self.ask(cap, input("join_password", "The grid's company password", "secret"));
                    json!({"profile": profile.id(), "mode": "join", "coordinator": "remote", "member": "computer", "secrets": {"invitation": "{{secrets.invitation}}", "join_password": "{{secrets.join_password}}"}})
                };
                self.grid = Some(spec);
                self.grid_by = Some(cap.id);
                self.outputs.push(output("grid_name", "Grid", "{{outputs.grid.name}}"));
            }
            "grid.reuse_compute" => match self.pool.as_mut() {
                Some(pool) => pool["source"] = json!("any"),
                None => self.keep(cap, "this computer contributes what the grid's admin sets."),
            },
            "grid.selected_machines" => {
                if self.pool.is_none() {
                    self.keep(cap, "the grid's admin picks which computers run its work.");
                    return;
                }
                self.ask(cap, pattern(hint(input("machines", "Which computers may run its work?", "text"), "Their names as they joined the grid, separated by commas. A computer by one of these names that joins later counts too."), "^[^\n]{1,1000}$"));
                if profile == Some(GridProfile::NeoGrid) {
                    // Its models run on these computers only.
                    if let Some(pool) = self.pool.as_mut() {
                        pool["source"] = json!("selected_computers");
                        pool["computers"] = json!(["{{inputs.machines}}"]);
                    }
                } else {
                    // Only these computers take workspaces; this computer's own share is apart.
                    self.resources.insert("picked".into(), resource("compute_pool", cap.id, json!({"grid": {"resource": "grid"}, "source": "selected_computers", "computers": ["{{inputs.machines}}"]})));
                }
                self.views.insert("computers");
            }
            "grid.cloud_compute" => {
                if !self.has("grid.create") {
                    self.keep(cap, "the grid's admin adds rented computers.");
                    return;
                }
                if profile == Some(GridProfile::NeoGrid) {
                    // One GPU rented through NeoCloud, at no more than the price you allow.
                    self.ask(cap, default(hint(input("rented_gpu", "Which GPU should it rent?", "text"), "As NeoCloud lists it, such as NVIDIA GeForce RTX 4090."), json!("NVIDIA GeForce RTX 4090")));
                    self.ask(cap, default(range(hint(input("rented_max_hourly", "Most it may cost an hour, in US dollars", "number"), "Nothing dearer is rented. RunPod bills your account."), 0.01, 100.0), json!(0.8)));
                    self.resources.insert("rented".into(), resource("compute_pool", cap.id, json!({"grid": {"resource": "grid"}, "source": "cloud", "cloud": {"provider": "runpod", "gpu_type": "{{inputs.rented_gpu}}", "max_hourly_cost": "{{inputs.rented_max_hourly}}"}})));
                } else {
                    // The company's own cloud makes a computer when the grid's have no room.
                    self.ask(cap, default(choices(input("cloud_provider_account", "Which cloud does the company use?", "choice"), &[("aws", "Amazon Web Services", ""), ("azure", "Microsoft Azure", ""), ("google", "Google Cloud", "")]), json!("aws")));
                    self.ask(cap, hint(input("cloud_account", "The CLI profile or account to use", "text"), "As the provider's own command line knows it on this computer."));
                    self.ask(cap, input("cloud_region", "Region", "text"));
                    self.ask(cap, hint(input("cloud_image", "Image to make computers from", "text"), "A Linux image; Yougori installs itself over SSH once it boots."));
                    self.ask(cap, input("cloud_machine_type", "Machine type", "text"));
                    self.ask(cap, input("cloud_subnet", "Subnet", "text"));
                    self.ask(cap, optional(hint(input("cloud_security_group", "Security group", "text"), "AWS and Azure need one.")));
                    self.ask(cap, when(input("cloud_key_pair", "EC2 key pair", "text"), json!({"cloud_provider_account": "aws"})));
                    self.ask(cap, when(input("cloud_resource_group", "Resource group", "text"), json!({"cloud_provider_account": "azure"})));
                    self.ask(cap, optional(hint(input("cloud_ssh_public_key", "SSH public key", "text"), "Azure and Google Cloud need one.")));
                    self.ask(cap, default(input("cloud_username", "Username on the new computers", "text"), json!("ubuntu")));
                    self.ask(cap, default(range(input("cloud_max_computers", "Most computers at once", "number"), 1.0, 64.0), json!(2)));
                    self.bindings.push(Binding { id: Some("cloud_key".into()), kind: Some("file".into()), question: Some("Which SSH private key signs in to the new computers?".into()), ..Binding::default() });
                    self.resources.insert("rented".into(), resource("compute_pool", cap.id, json!({"grid": {"resource": "grid"}, "source": "cloud", "cloud": {
                        "provider": "{{inputs.cloud_provider_account}}", "account": "{{inputs.cloud_account}}", "region": "{{inputs.cloud_region}}", "image": "{{inputs.cloud_image}}",
                        "machine_type": "{{inputs.cloud_machine_type}}", "subnet": "{{inputs.cloud_subnet}}", "security_group": "{{inputs.cloud_security_group}}", "key_pair": "{{inputs.cloud_key_pair}}",
                        "resource_group": "{{inputs.cloud_resource_group}}", "ssh_public_key": "{{inputs.cloud_ssh_public_key}}", "username": "{{inputs.cloud_username}}",
                        "max_computers": "{{inputs.cloud_max_computers}}", "identity_file": {"binding": "cloud_key"},
                    }})));
                }
                self.views.insert("computers");
                self.views.insert("costs");
            }
            "grid.worker_limits" if research => {
                self.keep(cap, "the worker's share of this computer, its cores, memory and disk, is asked with the review.");
            }
            "grid.worker_limits" => {
                if self.pool.is_none() {
                    self.keep(cap, "the grid's admin sets what this computer gives.");
                    return;
                }
                self.ask(cap, default(range(input("share_cpu", "Processor cores each computer may give", "number"), 1.0, 1024.0), json!(4)));
                self.ask(cap, default(range(input("share_memory_gb", "Memory each computer may give, in GB", "number"), 1.0, 65536.0), json!(8)));
                self.ask(cap, default(range(input("share_disk_gb", "Disk each computer may give, in GB", "number"), 1.0, 1048576.0), json!(100)));
                if let Some(pool) = self.pool.as_mut() {
                    pool["limits"] = json!({"cpu": "{{inputs.share_cpu}}", "memory_gb": "{{inputs.share_memory_gb}}", "disk_gb": "{{inputs.share_disk_gb}}"});
                }
            }
            "grid.availability" => {
                if self.pool.is_none() {
                    self.keep(cap, "each computer's person decides when it serves.");
                    return;
                }
                self.ask(cap, default(choices(input("availability", "When may a computer work?", "choice"), &[("idle", "Only while nobody is using it", "The person at the computer always comes first."), ("always", "Whenever it is on", "")]), json!("idle")));
                self.ask(cap, when(default(range(hint(input("idle_after_minutes", "After how many quiet minutes?", "number"), "Minutes without keyboard or mouse before a computer works."), 1.0, 1440.0), json!(10)), json!({"availability": "idle"})));
                self.ask(cap, optional(pattern(hint(input("schedule", "Only in these hours?", "text"), "Leave empty for any time, or write windows such as \"Mon-Fri 18:00-08:00; Sat,Sun\"."), "^[A-Za-z0-9 ,:;-]{0,200}$")));
                if let Some(pool) = self.pool.as_mut() {
                    pool["availability"] = json!("{{inputs.availability}}");
                    pool["idle_after_minutes"] = json!("{{inputs.idle_after_minutes}}");
                    pool["schedule"] = json!("{{inputs.schedule}}");
                }
            }
            "sandbox.vm" => {
                // A VM sandbox of its own, beside whatever else the setup makes: the pinned guest,
                // nothing reachable and nothing of this computer until the routes and the
                // workspace below say so.
                self.ask(cap, default(pattern(hint(input("vm_image", "Which image should the VM sandbox run?", "text"), "Keep minimal, or paste an imported sha256 ID from yougori sandbox image list. Import it yourself first; templates cannot authorize imports."), "^(minimal|sha256:[0-9a-f]{64})$"), json!("minimal")));
                self.ask(cap, default(range(hint(input("vm_memory_gb", "How much memory may the VM sandbox use, in GB?", "number"), "At least 0.3125 GB for the minimal guest. An OCI image needs its writable-root budget plus 0.5 GB. At most 64."), 0.3125, 64.0), json!(1)));
                self.ask(cap, default(range(hint(input("vm_idle_minutes", "Stop it after how many minutes without a command?", "number"), "At most 720 (12 hours). Starting the setup again launches a fresh one."), 1.0, 720.0), json!(60)));
                self.ask(cap, default(range(hint(input("vm_lifetime_minutes", "Stop it after how many minutes in all?", "number"), "At most 1440 (24 hours)."), 1.0, 1440.0), json!(480)));
                self.vm = Some(json!({"image": "{{inputs.vm_image}}", "memory_gb": "{{inputs.vm_memory_gb}}", "idle_minutes": "{{inputs.vm_idle_minutes}}", "lifetime_minutes": "{{inputs.vm_lifetime_minutes}}"}));
                self.outputs.push(output("vm_sandbox", "VM sandbox", "{{outputs.vm.id}}"));
                self.notes.push(note("vm_sandbox_use", "VM sandbox: its id is the setup's output. Run commands in it with yougori sandbox exec ID --input TEXT --yes, or from the Sandboxes page; it has no network and none of your files unless the template declares them.").at("capabilities.sandbox.vm"));
            }
            "sandbox.remote" => {
                self.ask(cap, hint(input("remote_connection", "Which owned SSH connection should run the remote VM?", "text"), "Use an owned connection ID. Confirm its key with yougori sandbox remote trust first. This template cannot enroll trust or provision a server."));
                self.ask(cap, pattern(hint(input("remote_program", "Where is the remote Yougori engine executable?", "text"), "Its absolute path on the SSH server. The server must already have the VM runtime installed."), "^/.+$"));
                self.ask(cap, hint(input("remote_endpoint", "Which remote engine endpoint should it use?", "text"), "The endpoint of that running engine, such as its Unix socket path."));
                self.ask(cap, pattern(input("remote_engine_sha256", "What is that engine executable's SHA-256?", "text"), "^[0-9a-f]{64}$"));
                self.ask(cap, default(range(input("remote_memory_gb", "How much remote memory, in GB?", "number"), 0.3125, 64.0), json!(1)));
                self.ask(cap, default(range(input("remote_lifetime_minutes", "Stop the remote VM after how many minutes?", "number"), 1.0, 1440.0), json!(60)));
                let remote = json!({"memory_gb":"{{inputs.remote_memory_gb}}", "lifetime_minutes":"{{inputs.remote_lifetime_minutes}}",
                    "remote":{"parent":{"resource":"vm"},"connection":"{{inputs.remote_connection}}",
                    "program":"{{inputs.remote_program}}","endpoint":"{{inputs.remote_endpoint}}","engine_sha256":"{{inputs.remote_engine_sha256}}"}});
                self.resources.insert("remote_vm".into(), resource("vm_sandbox", "sandbox.remote", remote));
                self.outputs.push(output("remote_vm", "Remote VM run", "{{outputs.remote_vm.id}}"));
                self.notes.push(note("remote_vm_use", "Remote VM: its run ID works with yougori sandbox remote start/outcome/stop. It depends on the local VM's current lease, and a retry finds the original run. No credential is copied, no server is provisioned or powered off, and external billing remains unknown.").at("capabilities.sandbox.remote"));
            }
            "sandbox.routes" => {
                let Some(mut vm) = self.vm.take() else {
                    self.keep(cap, "routes belong to a VM sandbox; add VM sandbox as well.");
                    return;
                };
                self.ask(cap, pattern(hint(input("route_host", "Which service may the VM sandbox reach?", "text"), "Its host name, such as api.example.com. It is reached over HTTPS through Yougori's relay, and nothing else is."), HOST_PATTERN));
                self.ask(cap, default(choices(input("route_method", "Which requests may it send there?", "choice"), &[
                    ("get", "Reads (GET)", "It only reads."),
                    ("post", "Sends (POST)", "It may change something there."),
                ]), json!("post")));
                self.ask(cap, default(pattern(hint(input("route_path", "On which path?", "text"), "Such as /v1/messages. Only this path is allowed there."), ROUTE_PATH_PATTERN), json!("/")));
                self.ask(cap, default(hint(input("route_signs_in", "Does it carry a credential you enrolled?", "yesno"), "Enroll it first with yougori sandbox credential enroll NAME --file -. The relay adds it on the way out; the sandbox never sees it."), json!(false)));
                self.ask(cap, when(pattern(hint(input("route_credential", "Which enrolled credential?", "text"), "The name you gave it when you enrolled it."), CREDENTIAL_PATTERN), json!({"route_signs_in": "yes"})));
                let route = |signs_in: bool| {
                    let mut route = json!({
                        "when": {"route_signs_in": if signs_in { "yes" } else { "no" }},
                        "name": "service",
                        "host": "{{inputs.route_host}}",
                        "operations": [{"name": "allowed", "method": "{{inputs.route_method}}", "path": "{{inputs.route_path}}"}],
                    });
                    if signs_in {
                        route["credential"] = json!({"name": "{{inputs.route_credential}}"});
                    }
                    route
                };
                vm["routes"] = json!([route(false), route(true)]);
                self.vm = Some(vm);
                self.notes.push(note("vm_sandbox_routes", "Declared routes: one service, one method and one path. In the sandbox the host resolves to a local address served over plain HTTP (http://HOST/PATH); the relay reaches it over HTTPS. Add more routes or operations in yougori.yaml.").at("capabilities.sandbox.routes"));
            }
            "sandbox.publish" => {
                let Some(mut vm) = self.vm.take() else {
                    self.keep(cap, "a published service belongs to a VM sandbox; add VM sandbox as well.");
                    return;
                };
                self.ask(cap, default(pattern(hint(input("publish_service", "What do you call the service the VM sandbox may serve?", "text"), "A short name, such as web. You publish it by this name."), SERVICE_NAME_PATTERN), json!("web")));
                self.ask(cap, default(range(hint(input("publish_port", "Which port does it listen on inside the sandbox?", "number"), "Its own port in the guest. On this computer Yougori opens a port of its own when you publish it."), 1.0, 65535.0), json!(8080)));
                vm["publish"] = json!([{"service": "{{inputs.publish_service}}", "port": "{{inputs.publish_port}}"}]);
                self.vm = Some(vm);
                self.notes.push(note("vm_sandbox_publish", "Published guest service: nothing is reachable until you publish it with yougori sandbox publish ID --service NAME --yes, or on the Sandboxes page. It answers you at the address it gives (or anyone on this computer, if you choose) until it expires, and 8 MiB at most in all.").at("capabilities.sandbox.publish"));
            }
            "sandbox.connect" => {
                let Some(mut vm) = self.vm.take() else {
                    self.keep(cap, "a connected VM sandbox belongs to a VM sandbox; add VM sandbox as well.");
                    return;
                };
                self.ask(cap, default(pattern(hint(input("connect_service", "What do you call the service the second VM sandbox serves?", "text"), "A short name, such as api. The first reaches it as peer, on its port."), SERVICE_NAME_PATTERN), json!("api")));
                self.ask(cap, default(range(hint(input("connect_port", "Which port does it listen on inside the second sandbox?", "number"), "The first sandbox's programs use the same port: http://peer:PORT/."), 1.0, 65535.0), json!(8080)));
                self.ask(cap, default(range(hint(input("connect_minutes", "For how many minutes after each start may the first reach it?", "number"), "At most 1440 (24 hours). Starting the setup again grants it anew."), 1.0, 1440.0), json!(60)));
                // The first sandbox's end of the grant; the peer's `accept` is the other end.
                vm["connect"] = json!([{"name": "peer", "to": "peer", "service": "{{inputs.connect_service}}", "minutes": "{{inputs.connect_minutes}}"}]);
                self.vm = Some(vm);
                self.vm_peer = true;
                self.notes.push(note("vm_sandbox_connect", "Connected VM sandbox: a second VM sandbox, peer, serves the service; programs in the first reach it as peer:PORT and nothing else of it, while the grant lasts. Its id is a setup output: run the service in it with yougori sandbox exec ID --input TEXT --yes.").at("capabilities.sandbox.connect"));
            }
            "tools.builtin" => {
                if !self.profile_free(cap) {
                    return;
                }
                self.ask(cap, default(choices(input("tool", "Which AI tools do you want in the sandbox?", "multichoice"), &[
                    ("codex", "Codex", "OpenAI's coding agent."),
                    ("claude", "Claude Code", "Anthropic's coding agent."),
                    ("gemini", "Gemini CLI", "Google's coding agent."),
                    ("opencode", "OpenCode", "Open source agent for many model providers."),
                    ("kilo", "Kilo Code", "Open source agent for many model providers."),
                    ("ollama", "Ollama", "Runs open models inside the sandbox."),
                    ("openclaw", "OpenClaw", "Personal assistant agent."),
                ]), json!(["codex"])));
                self.app();
                self.tools.insert("app".to_owned(), format::BUILT_IN_TOOLS.iter().map(|tool| (*tool).to_owned()).collect());
                for tool in format::BUILT_IN_TOOLS {
                    let sign_in = format::SUBSCRIPTION_TOOLS.contains(tool);
                    self.tool_options.insert(format!("app/{tool}"), ToolOptions { when: Some(yaml(json!({"tool": tool}))), signin: sign_in, ..ToolOptions::default() });
                }
                self.steps.push(Step { title: Some("Open a tool".into()), detail: Some("Open any tool you picked in this sandbox, such as Codex.".into()), command: Some("yougori codex --environment {{env.app}}".into()), when: Some(yaml(json!({"tool": "codex"}))) });
            }
            "tools.custom" => {
                if !self.profile_free(cap) {
                    return;
                }
                self.ask(cap, pattern(hint(input("image", "Which container image should it run?", "text"), "An image reference such as ghcr.io/you/app:1.4.2. Pin a version."), IMAGE_PATTERN));
                self.app().insert("image".into(), json!("{{inputs.image}}"));
            }
            "tools.provider_access" => {
                if !self.has("tools.builtin") || self.profile.is_some() {
                    self.keep(cap, "sign-in and API keys for this source are set up after setup.");
                    return;
                }
                self.ask(cap, default(choices(input("method", "How should the tools reach their models?", "choice"), &[("subscription", "My accounts", "Sign in once per tool in a separate window."), ("api", "API keys", "Billed by each provider per use."), ("both", "Both", "")]), json!("subscription")));
                for (tool, label, variable) in SIGN_IN_TOOLS {
                    let id = format!("{tool}_api_key");
                    let question = hint(input(&id, &format!("API key for {label}"), "secret"), &format!("Given to the sandbox as {variable}."));
                    self.ask(cap, when(question, json!({"tool": tool, "method": ["api", "both"]})));
                    if let Some(options) = self.tool_options.get_mut(&format!("app/{tool}")) {
                        options.signin_when = Some(yaml(json!({"method": ["subscription", "both"]})));
                    }
                    let app = self.app();
                    let secrets = app.entry("secrets").or_insert_with(|| json!({}));
                    secrets[*variable] = json!(format!("{{{{secrets.{id}}}}}"));
                }
            }
            "models.local" if research => {
                // The model the research worker thinks with, on this computer: nothing it reads leaves it.
                self.ask(cap, pattern(hint(input("model", "Which model should it use?", "text"), "A model from Hugging Face in GGUF form, such as: hf.co/OWNER/MODEL."), "^(hf\\.co/)?[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$"));
                self.ask(cap, default(range(input("model_memory_gb", "How much memory may the model use, in GB?", "number"), 4.0, 512.0), json!(16)));
                self.resources.insert("model".into(), resource("model_service", cap.id, json!({"model": "{{inputs.model}}", "replicas": 1, "memory_gb": "{{inputs.model_memory_gb}}"})));
                self.views.insert("models");
            }
            "models.local" => {
                self.ask(cap, pattern(hint(input("model", "Which model should it run?", "text"), "hf.co/OWNER/MODEL from Hugging Face, or yg/PUBLISHER/MODEL from Yougori."), MODEL_PATTERN));
                let mut spec = json!({"model": "{{inputs.model}}", "api": {"protocol": "openai"}});
                if self.pool.is_some() && profile == Some(GridProfile::NeoGrid) {
                    spec["compute"] = json!({"resource": "computers"});
                    spec["placement"] = json!("remaining");
                    spec["share_percent"] = json!(100);
                }
                self.resources.insert("model".into(), resource("model_service", cap.id, spec));
                self.outputs.push(output("model_endpoint", "Model API address", "{{outputs.model.endpoint}}"));
                self.views.insert("models");
                self.views.insert("api");
            }
            "models.cloud" => {
                if !self.profile_free(cap) {
                    return;
                }
                // The provider's key stays in a gateway sandbox of the setup's own: the setup's
                // other sandboxes call the gateway, never the provider, so they never see the key,
                // and what Free models only and Budget ask for is kept there, outside the app.
                self.ask(cap, default(choices(input("cloud_provider", "Which provider hosts the model?", "choice"), &[
                    ("openrouter", "OpenRouter", "Many models, with prices listed, and free ones."),
                    ("openai", "OpenAI", ""),
                    ("anthropic", "Anthropic", ""),
                    ("gemini", "Google Gemini", ""),
                    ("groq", "Groq", ""),
                    ("mistral", "Mistral", ""),
                    ("deepseek", "DeepSeek", ""),
                    ("together", "Together", ""),
                    ("other", "Another, by its address", "Any provider with an OpenAI-compatible API."),
                ]), json!("openrouter")));
                self.ask(cap, when(pattern(hint(input("cloud_base_url", "The provider's API address", "text"), "Such as https://api.example.com/v1."), "^https://[^?#\\s]{1,200}$"), json!({"cloud_provider": "other"})));
                self.ask(cap, pattern(hint(input("cloud_model", "Which model?", "text"), "As the provider names it, such as openai/gpt-4o-mini or meta-llama/llama-3.3-70b-instruct:free."), "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$"));
                self.ask(cap, hint(input("cloud_api_key", "The provider's API key", "secret"), "Kept in the gateway sandbox only. The provider bills you for what it is used for."));
                self.gateway = Some(json!({
                    "type": "container", "image": GATEWAY_IMAGE, "cpu": 1, "memory": 1, "storage": 5,
                    "command": ["python3", "-u", "/gateway/model-gateway.py"],
                    "files": [{"source": GATEWAY_FILE, "target": "/gateway/model-gateway.py"}],
                    "environment": {
                        "YOUGORI_MODEL_GATEWAY": "1", "PROVIDER": "{{inputs.cloud_provider}}", "BASE_URL": "{{inputs.cloud_base_url}}",
                        "MODEL": "{{inputs.cloud_model}}", "FREE_ONLY": "no", "BUDGET_USD": "0", "PORT": "8080",
                    },
                    "secrets": {"UPSTREAM_KEY": "{{secrets.cloud_api_key}}"},
                    "volumes": [{"source": "gateway-data", "target": "/data"}],
                    "ports": [8080],
                    "health": {"port": 8080, "path": "/yougori/health", "wait_seconds": 120},
                    "internet": true,
                    "restart": "always",
                }));
                self.outputs.push(output("cloud_model", "Model", "{{inputs.cloud_model}}"));
                self.views.insert("models");
                self.views.insert("usage");
            }
            "models.existing" => {
                self.bindings.push(Binding { id: Some("existing_model".into()), kind: Some("resource".into()), resource: Some("model_service".into()), question: Some("Which of your models should it use?".into()), ..Binding::default() });
                self.ask(cap, input("existing_model_name", "Which model does that service run?", "text"));
                let mut existing = resource("model_service", cap.id, json!({"model": "{{inputs.existing_model_name}}"}));
                existing.borrow = Some(format::Borrow { binding: Some("existing_model".into()), ..format::Borrow::default() });
                self.resources.insert("existing".into(), existing);
                self.views.insert("models");
            }
            "models.team" => {
                let lead = if self.has("models.local") { "model" } else if self.has("models.existing") { "existing" } else {
                    self.keep(cap, "add the team in the Teams view once a model is served.");
                    return;
                };
                self.ask(cap, default(pattern(hint(input("team_name", "Name of the team", "text"), "Apps call it as the model swarm/NAME."), "^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$"), json!("team")));
                self.ask(cap, default(choices(input("team_strategy", "How should the team work?", "choice"), &[("plan", "Split into tasks", "The lead splits a request; workers solve the parts."), ("mixture", "Combine answers", "Every worker answers; the lead writes one answer.")]), json!("plan")));
                let mut spec = json!({"model": "swarm/{{inputs.team_name}}", "team": {"strategy": "{{inputs.team_strategy}}", "lead": {"resource": lead}, "workers": [{"resource": lead}], "computers": 5, "rounds": 1}});
                if self.pool.is_some() {
                    spec["compute"] = json!({"resource": "computers"});
                }
                self.resources.insert("team".into(), resource("model_service", cap.id, spec));
                self.outputs.push(output("team_model", "Team model name", "{{outputs.team.model}}"));
                self.views.insert("teams");
            }
            "models.free_only" => match self.gateway.as_mut() {
                Some(gateway) => {
                    gateway["environment"]["FREE_ONLY"] = json!("yes");
                    self.notes.push(note("free_only", "Free models only: the gateway refuses a model the provider charges for, and looks at its price again every ten minutes, so one that starts costing money is refused from then on.").at("capabilities.models.free_only"));
                }
                None => self.notes.push(note("free_only", "Free models only: the models this setup runs on this computer or its grid have no usage charge.").at("capabilities.models.free_only")),
            },
            "web.service" => {
                if self.profile.is_some() {
                    self.keep(cap, "the grid's own service; nothing else is added.");
                    return;
                }
                if !self.has("tools.custom") {
                    // A service needs an image that serves; without a custom tool, the service asks for it.
                    self.ask(cap, pattern(hint(input("image", "Which container image runs the service?", "text"), "An image reference such as ghcr.io/you/app:1.4.2. Pin a version."), IMAGE_PATTERN));
                    self.app().insert("image".into(), json!("{{inputs.image}}"));
                }
                self.ask(cap, default(range(hint(input("port", "Which port does the service listen on inside the sandbox?", "number"), "Yougori chooses the port on this computer."), 1024.0, 65535.0), json!(8080)));
                let (access, domain) = self.access(false);
                // Reached from inside the setup only, the service opens no address, so there is
                // none to show: an Address output would only ever read as its placeholder. Kept
                // to this computer, its address is a port here (`ordinary::here_port`).
                let addressed = access.as_str() != Some("none");
                let app = self.app();
                app.remove("command");
                app.insert("ports".into(), json!(["{{inputs.port}}"]));
                let environment = app.entry("environment").or_insert_with(|| json!({}));
                environment["PORT"] = json!("{{inputs.port}}");
                let mut spec = json!({"target": {"resource": "app"}, "port": "{{inputs.port}}", "access": access});
                if domain {
                    spec["domain"] = json!("{{inputs.domain}}");
                }
                self.resources.insert("web".into(), resource("service_publication", cap.id, spec));
                if addressed {
                    self.outputs.push(output("address", "Address", "{{outputs.web.url}}"));
                }
                self.views.insert("publications");
            }
            "web.private" | "web.lan" | "web.quick_link" | "web.domain" => {
                // Asked with the service or the grid that is reached this way.
            }
            "web.health" => {
                if self.profile.is_some() || !self.has("web.service") {
                    self.keep(cap, "the grid checks its own health.");
                    return;
                }
                self.ask(cap, default(pattern(hint(input("health_path", "Which path answers 200 when it is healthy?", "text"), "Yougori waits for it before calling the service ready."), PATH_PATTERN), json!("/")));
                self.app().insert("health".into(), json!({"port": "{{inputs.port}}", "path": "{{inputs.health_path}}", "wait_seconds": 180}));
                if let Some(web) = self.resources.get_mut("web") {
                    let mut spec: Json = serde_json::to_value(&web.spec).unwrap_or(Json::Null);
                    spec["health"] = json!({"path": "{{inputs.health_path}}", "expected_status": 200});
                    web.spec = yaml(spec);
                }
            }
            "web.app_billing" => {
                if self.profile.is_some() || !self.has("web.service") {
                    self.keep(cap, "the application that charges its users is the setup's own web service.");
                    return;
                }
                // The application charges its own users with the person's own provider account:
                // the keys go to the app sandbox as secrets, nothing of the template's.
                self.ask(cap, default(choices(input("billing_provider", "Which payment provider does your app use?", "choice"), &[
                    ("stripe", "Stripe", ""),
                    ("paddle", "Paddle", ""),
                    ("lemonsqueezy", "Lemon Squeezy", ""),
                ]), json!("stripe")));
                self.ask(cap, {
                    let mut question = hint(input("billing_secret_key", "Its secret API key", "secret"), "Your app reads it as BILLING_SECRET_KEY. Use a test key until you are ready to charge.");
                    question.min_length = Some(8);
                    question
                });
                self.ask(cap, optional(hint(input("billing_webhook_secret", "Its webhook signing secret", "secret"), "Your app reads it as BILLING_WEBHOOK_SECRET to check that a payment event really came from the provider.")));
                let app = self.app();
                let environment = app.entry("environment").or_insert_with(|| json!({}));
                environment["BILLING_PROVIDER"] = json!("{{inputs.billing_provider}}");
                let secrets = app.entry("secrets").or_insert_with(|| json!({}));
                secrets["BILLING_SECRET_KEY"] = json!("{{secrets.billing_secret_key}}");
                secrets["BILLING_WEBHOOK_SECRET"] = json!("{{secrets.billing_webhook_secret}}");
                if !(self.has("web.quick_link") || self.has("web.domain")) {
                    self.notes.push(note("billing_reach", "Charge for the application: a payment provider sends its events to a public address. Add A custom domain, or A quick public link to try it out.").at("capabilities.web.app_billing"));
                } else if !self.has("web.domain") {
                    self.notes.push(note("billing_reach", "Charge for the application: a quick link can change after a restart, and the provider's webhooks would then go nowhere. A custom domain keeps them arriving.").at("capabilities.web.app_billing"));
                }
            }
            "people.team" => self.keep(cap, "people are added in the People view."),
            "people.roles" => {
                if !access_grid || !self.has("grid.create") {
                    // The people this setup adds (with Workspaces or Invites) are asked theirs.
                    if !(self.has("people.workspaces") || self.has("people.invites")) || !self.has("grid.create") {
                        self.keep(cap, "roles are given to the people this setup adds; add Workspaces or Invites to add someone.");
                    }
                    return;
                }
                self.ask(cap, pattern(hint(input("admin_username", "Your username as the first admin", "text"), "3 to 32 letters, digits, dots, dashes or underscores."), USERNAME_PATTERN));
                self.ask(cap, {
                    let mut question = input("admin_password", "Your password", "secret");
                    question.min_length = Some(10);
                    question
                });
                self.owner = Some(json!({"grid": {"resource": "grid"}, "people": "team", "roles": ["owner", "admin"], "admin": {"username": "{{inputs.admin_username}}"}, "secrets": {"admin_password": "{{secrets.admin_password}}"}}));
                self.views.insert("people");
            }
            "people.workspaces" => {
                if self.pool.is_none() {
                    self.problems.push(Diagnostic::error("draft_needs_grid", "Workspaces are built on the grid's computers. Choose Create a grid as well.").at("capabilities.people.workspaces"));
                    return;
                }
                self.ask(cap, pattern(hint(input("person_username", "Username of the first person", "text"), "3 to 32 letters, digits, dots, dashes or underscores."), USERNAME_PATTERN));
                self.ask(cap, {
                    let mut question = hint(input("person_password", "Their password", "secret"), "At least 10 characters. Give it to them privately.");
                    question.min_length = Some(10);
                    question
                });
                self.ask(cap, default(choices(input("workspace_runtime", "What should their workspace be?", "choice"), &[("container", "Container", "Fast and light."), ("microvm", "MicroVM", "Its own kernel."), ("vm", "Full VM", "Needs a prepared disk image.")]), json!("container")));
                self.ask(cap, optional(pattern(hint(input("workspace_image", "Image to build it from", "text"), "Leave empty for the default. A full VM needs a prepared disk image."), "^[^\\s]{0,1000}$")));
                self.resources.insert("workspaces".into(), resource("workspace_pool", cap.id, json!({"compute": {"resource": "computers"}, "allocation": "per_person", "runtime": "{{inputs.workspace_runtime}}", "image": "{{inputs.workspace_image}}", "count": 1})));
                let mut first = json!({"grid": {"resource": "grid"}, "people": "team", "roles": ["member"], "person": {"username": "{{inputs.person_username}}"}, "workspaces": "individual", "workspace_pool": {"resource": "workspaces"}, "secrets": {"password": "{{secrets.person_password}}"}});
                if self.has("people.roles") {
                    self.ask(Build::cap("people.roles"), default(choices(input("person_role", "What may they do in the grid?", "choice"), &[
                        ("member", "Use their workspace", ""),
                        ("operator", "Run the grid day to day", "Workspaces, computers and connections."),
                        ("auditor", "Look at everything, change nothing", ""),
                        ("admin", "Everything", "People, settings and the rest."),
                    ]), json!("member")));
                    first["roles"] = json!(["{{inputs.person_role}}"]);
                }
                self.resources.insert("first_person".into(), resource("access_binding", cap.id, first));
                self.outputs.push(output("workspace", "First workspace", "{{outputs.workspaces.access_url}}"));
                self.views.insert("workspaces");
                self.views.insert("people");
            }
            "people.invites" => {
                if research {
                    // People on the network join a review with its own invitation and password.
                    self.keep(cap, "people on your network join the review with its own invitation, a private output shown only to you, and the password you chose.");
                    return;
                }
                if !self.has("grid.create") || profile == Some(GridProfile::NeoGrid) {
                    // A Neo Grid's computers join with the grid's own invitation, a private output.
                    self.keep(cap, "computers join with the grid's own invitation, a private output shown only to you.");
                    return;
                }
                // One person, invited by name: their account is made with a password nobody
                // types, and their invitation carries it. It is a private output, read only when
                // you ask, and it is the only way in for them until they change the password.
                self.ask(cap, pattern(hint(input("invitee_username", "Username of the person to invite", "text"), "3 to 32 letters, digits, dots, dashes or underscores."), USERNAME_PATTERN));
                let mut invitee = json!({"grid": {"resource": "grid"}, "people": "team", "roles": ["member"], "person": {"username": "{{inputs.invitee_username}}"}, "invite": true});
                if self.has("people.roles") {
                    let ways: &[(&str, &str, &str)] = if access_grid {
                        &[("member", "Use what the rules allow", ""), ("approver", "Also approve other people's requests", ""), ("auditor", "Look at everything, change nothing", ""), ("admin", "Everything", "")]
                    } else {
                        &[("member", "Use their workspace", ""), ("operator", "Run the grid day to day", ""), ("auditor", "Look at everything, change nothing", ""), ("admin", "Everything", "")]
                    };
                    self.ask(Build::cap("people.roles"), default(choices(input("invitee_role", "What may they do in the grid?", "choice"), ways), json!("member")));
                    invitee["roles"] = json!(["{{inputs.invitee_role}}"]);
                }
                if self.resources.contains_key("workspaces") {
                    invitee["workspaces"] = json!("individual");
                    invitee["workspace_pool"] = json!({"resource": "workspaces"});
                }
                self.resources.insert("invitee".into(), resource("access_binding", cap.id, invitee));
                let mut invitation = output("invitation_for_person", "Their invitation", "{{outputs.invitee.invitation}}");
                invitation.private = true;
                self.outputs.push(invitation);
                self.steps.push(step("Send the invitation privately", "Reveal Their invitation on the setup's page and give it to them privately. They paste it into yougori template join, or the Join a grid screen, to sign in."));
                self.views.insert("people");
            }
            "people.sso" => {
                self.ask(cap, pattern(hint(input("sso_issuer", "Your sign-in provider's issuer address", "text"), "The https:// address its discovery document names."), "^https://[^?#\\s]{1,504}$"));
                self.ask(cap, pattern(input("sso_client_id", "Client ID of the app registered at the provider", "text"), "^[^\\s]{1,256}$"));
                self.ask(cap, default(pattern(input("sso_claim", "Which claim holds the username?", "text"), "^[A-Za-z0-9_]{1,64}$"), json!("email")));
                self.ask(cap, default(input("sso_only", "Allow only the company sign-in (no passwords)?", "yesno"), json!(false)));
                self.resources.insert("sign_in".into(), resource("access_binding", cap.id, json!({"grid": {"resource": "grid"}, "people": "team", "sso": {"issuer": "{{inputs.sso_issuer}}", "client_id": "{{inputs.sso_client_id}}", "username_claim": "{{inputs.sso_claim}}", "passwordless": "{{inputs.sso_only}}"}})));
                self.views.insert("people");
            }
            "people.mfa" => {
                if profile == Some(GridProfile::SandboxGrid) && self.has("grid.create") {
                    // Required of everyone: until it is on for them, a person signs in only to turn it on.
                    self.resources.insert("two_step".into(), resource("access_binding", cap.id, json!({"grid": {"resource": "grid"}, "people": "team", "mfa": true})));
                    return;
                }
                if !access_grid || !self.has("grid.create") {
                    self.keep(cap, "each person turns on two-step sign-in for themselves.");
                    return;
                }
                self.ask(cap, default(hint(input("require_two_step", "Require two-step sign-in for everyone?", "yesno"), "People turn it on with an authenticator app before they can use anything."), json!(true)));
                match self.owner.as_mut() {
                    Some(owner) => owner["mfa"] = json!("{{inputs.require_two_step}}"),
                    None => {
                        self.resources.insert("two_step".into(), resource("access_binding", cap.id, json!({"grid": {"resource": "grid"}, "people": "team", "mfa": "{{inputs.require_two_step}}"})));
                    }
                }
            }
            "people.scoped_credentials" => {
                if !access_grid || !self.has("grid.create") {
                    self.keep(cap, "scoped keys and credentials are added after setup.");
                    return;
                }
                self.resources.insert("broker".into(), resource("credential_broker", cap.id, json!({"grid": {"resource": "grid"}, "agents": ["mcp", "cli"]})));
                self.outputs.push(output("broker", "Broker address", "{{outputs.broker.endpoint}}"));
                self.views.insert("credentials");
                self.views.insert("policies");
                self.views.insert("approvals");
            }
            "data.storage_drive" => {
                // A template never names a drive: each computer has its own. The person running it
                // chooses one, and every sandbox goes on it with its volumes.
                self.notes.push(note("storage_drive_at_run", "Storage drive: whoever runs it chooses the drive its sandboxes and their volumes are kept on.").at("capabilities.data.storage_drive"));
                self.views.insert("storage");
            }
            "data.volumes" => {
                if !self.profile_free(cap) {
                    return;
                }
                let app = self.app();
                let volumes = app.entry("volumes").or_insert_with(|| json!([]));
                if let Some(list) = volumes.as_array_mut() {
                    list.push(json!({"source": "data", "target": "/data"}));
                }
                self.views.insert("storage");
            }
            "data.project_source" => {
                if self.has("run.job") {
                    self.bindings.push(Binding { id: Some("project_source".into()), kind: Some("folder".into()), question: Some("Which project folder should the job use?".into()), ..Binding::default() });
                } else {
                    self.keep(cap, "a project folder is chosen when a job uses it.");
                }
            }
            "data.folders" => self.keep(cap, "selected folders are shared after setup; the template never names a folder on your computer."),
            "data.sync" => self.keep(cap, "sync is set up after setup."),
            "sandbox.workspace" => {
                let Some(vm) = self.vm.as_mut() else {
                    self.keep(cap, "a staged workspace belongs to a VM sandbox; add VM sandbox as well.");
                    return;
                };
                vm["workspace"] = json!({"binding": "workspace"});
                self.bindings.push(Binding {
                    id: Some("workspace".into()),
                    kind: Some("folder".into()),
                    mode: Some(FolderMode::Staged.id().into()),
                    question: Some("Which folder should the VM sandbox work on a copy of?".into()),
                    hint: Some("Its changes come back only when you review them and approve each file.".into()),
                    ..Binding::default()
                });
                self.notes.push(note("vm_sandbox_workspace", "Staged workspace: review the sandbox's changes with yougori sandbox review ID and bring back the files you approve with yougori sandbox promote, or on the Sandboxes page. Nothing else changes your folder.").at("capabilities.sandbox.workspace"));
            }
            "data.databases" => {
                if !self.profile_free(cap) {
                    return;
                }
                self.ask(cap, {
                    let mut question = hint(input("database_password", "Choose the database password", "secret"), "At least 16 characters. Your app reads it as DATABASE_PASSWORD.");
                    question.min_length = Some(16);
                    question
                });
                self.resources.insert("db".into(), resource("environment", cap.id, json!({
                    "type": "container", "image": DATABASE_IMAGE, "cpu": 1, "memory": 1, "storage": 20,
                    "environment": {"POSTGRES_DB": "app", "POSTGRES_USER": "app", "PGDATA": "/var/lib/postgresql/data/pgdata"},
                    "secrets": {"POSTGRES_PASSWORD": "{{secrets.database_password}}"},
                    "volumes": [{"source": "pg-data", "target": "/var/lib/postgresql/data"}],
                    "ports": [5432], "restart": "always",
                })));
                self.resources.insert("app_to_db".into(), resource("connection", cap.id, json!({"from": {"resource": "app"}, "to": {"resource": "db"}, "ports": [5432], "direction": "one_way"})));
                let app = self.app();
                let environment = app.entry("environment").or_insert_with(|| json!({}));
                for (key, value) in [("DATABASE_HOST", "db"), ("DATABASE_PORT", "5432"), ("DATABASE_NAME", "app"), ("DATABASE_USER", "app")] {
                    environment[key] = json!(value);
                }
                let secrets = app.entry("secrets").or_insert_with(|| json!({}));
                secrets["DATABASE_PASSWORD"] = json!("{{secrets.database_password}}");
                self.outputs.push(output("database", "Database sandbox", "{{outputs.db.name}}"));
                self.views.insert("storage");
                self.views.insert("diagram");
            }
            "data.artifacts" => {
                self.ask(cap, default(range(hint(input("artifacts_gb", "How much of the jobs' results to keep, in GB?", "number"), "The oldest results go first once it is full."), 1.0, 1024.0), json!(10)));
                self.ask(cap, default(range(input("artifacts_days", "How many days to keep each result?", "number"), 1.0, 365.0), json!(30)));
                self.resources.insert("results".into(), resource("artifact_store", cap.id, json!({"max_gb": "{{inputs.artifacts_gb}}", "retention_days": "{{inputs.artifacts_days}}"})));
                self.views.insert("files");
            }
            "data.private_connections" => {
                if !self.has("data.databases") {
                    self.keep(cap, "connections between sandboxes are added in yougori.yaml as one-way links.");
                }
            }
            "run.service" => {
                if self.profile.is_none() {
                    self.app().insert("restart".into(), json!("always"));
                }
            }
            "run.job" => {
                if !self.profile_free(cap) {
                    return;
                }
                // The job runs once, to its end, in a sandbox made for each attempt from the app
                // sandbox's image. Its command is a program and its arguments, never a shell line.
                self.ask(cap, pattern(hint(input("job_command", "What command should the job run?", "text"), "A program and its arguments, such as python3 build.py --fast. It is not run by a shell, so no pipes or variables."), "^[^|;&<>`$\\n]{1,1000}$"));
                self.ask(cap, default(range(hint(input("job_minutes", "How long may one attempt take, in minutes?", "number"), "An attempt still running then is stopped."), 1.0, 1440.0), json!(60)));
                let mut spec = json!({"command": ["{{inputs.job_command}}"], "timeout_seconds": "{{inputs.job_minutes}}", "outputs": {"resource": "results"}});
                if self.app.is_some() {
                    // Made from the setup's own sandbox: its image, and the room it has.
                    spec["compute"] = json!({"resource": "app"});
                } else {
                    // Nothing else needs a sandbox that stays up, so the job brings its own image.
                    self.ask(cap, default(pattern(hint(input("job_image", "Which container image should the job run in?", "text"), "An image reference such as python:3.12-slim. Pin a version."), IMAGE_PATTERN), json!(WORKSPACE_IMAGE)));
                    spec["image"] = json!("{{inputs.job_image}}");
                }
                if self.has("data.project_source") {
                    spec["source"] = json!({"binding": "project_source"});
                }
                self.resources.insert("job".into(), resource("job", cap.id, spec));
                // What the job leaves in its output folder as `result` is kept, so it can be read.
                if !self.has("data.artifacts") {
                    self.resources.insert("results".into(), resource("artifact_store", cap.id, json!({"max_gb": 10})));
                }
                self.outputs.push(output("job_status", "Job", "{{outputs.job.status}}"));
                self.views.insert("jobs");
                self.views.insert("files");
            }
            "run.retries" => {
                if !self.has("run.job") {
                    self.keep(cap, "retries apply to jobs.");
                    return;
                }
                self.ask(cap, default(range(input("attempts", "How many attempts may the job make?", "number"), 1.0, 10.0), json!(3)));
                self.ask(cap, default(range(hint(input("retry_after_seconds", "How long to wait before trying again, in seconds?", "number"), "Each later wait is twice as long, up to an hour."), 0.0, 3600.0), json!(30)));
                self.ask(cap, default(hint(input("repeat_safe", "Is running it again after a failure harmless?", "yesno"), "Say no if it changes something outside, such as sending mail or charging a card: then a failure is left for you to check instead of tried again."), json!(true)));
                if let Some(job) = self.resources.get_mut("job") {
                    let mut spec: Json = serde_json::to_value(&job.spec).unwrap_or(Json::Null);
                    spec["retry"] = json!({"attempts": "{{inputs.attempts}}", "backoff_seconds": "{{inputs.retry_after_seconds}}"});
                    spec["idempotent"] = json!("{{inputs.repeat_safe}}");
                    spec["reconcile"] = json!("manual");
                    job.spec = yaml(spec);
                }
                self.notes.push(note("job_retries", "A job that is harmless to repeat is tried again after a failure. One that isn't is tried again only when an attempt never started, and a failure is left for a person to check.").at("capabilities.run.retries"));
            }
            "run.events" => {
                let Some(job) = self.resources.get("job") else {
                    self.keep(cap, "an event runs a job again; add Run as a job.");
                    return;
                };
                let mut spec: Json = serde_json::to_value(&job.spec).unwrap_or(Json::Null);
                let folder = spec["source"].is_object();
                self.ask(cap, default(choices(input("event_access", "Who can call its address to run it again?", "choice"), &[
                    ("private", "Programs on this computer", ""),
                    ("lan", "Computers on this network", "Your LAN or VPN."),
                    ("quick", "Anyone with the link", "A free HTTPS link. Keep it private: it is the only key."),
                ]), json!("private")));
                spec["trigger"] = json!({"webhook": {"access": "{{inputs.event_access}}"}});
                if folder {
                    self.ask(cap, default(hint(input("event_folder", "Also run it when files change in the project folder?", "yesno"), "A file added, changed or removed there runs it once more."), json!(false)));
                    spec["trigger"]["source_changes"] = json!("{{inputs.event_folder}}");
                }
                if let Some(job) = self.resources.get_mut("job") {
                    job.spec = yaml(spec);
                }
                let mut address = output("event_url", "Event address", "{{outputs.job.event_url}}");
                address.private = true;
                self.outputs.push(address);
                self.notes.push(note("event_runs", "Run on an event: each call or change runs the job once more, never two at once and never sooner than ten seconds after the last. The address is a private output: only you can read it, and anyone who has it can run the job.").at("capabilities.run.events"));
            }
            "run.quotas" => {
                // The totals of what the setup makes, checked at every plan: what it would make
                // past one of them is refused before anything is made.
                let cap_at = |build: &mut Build<'a>, key: &str, question: &str, value: f64, most: f64| {
                    let id = format!("limit_{key}");
                    build.ask(cap, default(range(input(&id, question, "number"), 1.0, most), json!(value)));
                    build.limits.insert(key.to_owned(), yaml(json!(format!("{{{{inputs.{id}}}}}"))));
                };
                if self.profile.is_none() {
                    cap_at(self, "cpu", "Most processor cores its sandboxes may have together", 8.0, 1024.0);
                    cap_at(self, "memory_gb", "Most memory its sandboxes may have together, in GB", 16.0, 65536.0);
                    cap_at(self, "disk_gb", "Most disk its sandboxes may have together, in GB", 200.0, 1048576.0);
                }
                if self.has("people.workspaces") {
                    cap_at(self, "workspaces", "Most workspaces it may make", 10.0, 256.0);
                }
                if self.has("people.team") || self.has("people.workspaces") || self.has("people.roles") {
                    cap_at(self, "people", "Most people it may add", 25.0, 1024.0);
                }
                if self.has("models.local") || self.has("models.cloud") || self.has("models.team") {
                    cap_at(self, "models", "Most model services it may run", 4.0, 32.0);
                }
                if self.has("run.events") {
                    cap_at(self, "runs_per_day", "Most runs a day that events may start", 50.0, 10000.0);
                    if let Some(job) = self.resources.get_mut("job") {
                        let mut spec: Json = serde_json::to_value(&job.spec).unwrap_or(Json::Null);
                        if spec["trigger"].is_object() {
                            spec["trigger"]["per_day"] = json!("{{inputs.limit_runs_per_day}}");
                            job.spec = yaml(spec);
                        }
                    }
                }
                if self.limits.is_empty() {
                    self.keep(cap, "nothing it makes here has a total to cap.");
                }
            }
            "run.budget" => {
                let rented = self.resources.get("rented").is_some_and(|pool| serde_json::to_value(&pool.spec).ok().is_some_and(|spec| spec["cloud"]["provider"] == "runpod"));
                if self.gateway.is_none() && !rented {
                    self.keep(cap, "a spending limit applies to rented GPUs and cloud models; this setup has neither here.");
                    return;
                }
                self.ask(cap, default(range(hint(input("budget_usd", "Most to spend each month, in US dollars", "number"), "Cloud model requests that could pass it are refused before they are sent; rented GPUs are stopped before they pass it."), 0.01, 100000.0), json!(20)));
                if let Some(gateway) = self.gateway.as_mut() {
                    gateway["environment"]["BUDGET_USD"] = json!("{{inputs.budget_usd}}");
                }
                if let Some(pool) = self.resources.get_mut("rented").filter(|_| rented) {
                    let mut spec: Json = serde_json::to_value(&pool.spec).unwrap_or(Json::Null);
                    spec["cloud"]["budget_usd"] = json!("{{inputs.budget_usd}}");
                    pool.spec = yaml(spec);
                }
                self.views.insert("budget");
            }
            "run.backups" => self.keep(cap, "backups are made from the setup's views."),
            "run.health_logs" => {
                // Checked once a minute while it runs; its sandboxes' logs are on its page.
                self.views.insert("logs");
            }
            "run.notifications" => {
                self.notes.push(note("notifications_here", "Notifications: this computer shows a notification when the setup stops being healthy or is healthy again, when a change to it fails, and when one of its jobs finishes or fails.").at("capabilities.run.notifications"));
            }
            other => self.notes.push(note("capability_kept", format!("{other} has no generated part yet; describe it in yougori.yaml.")).at(format!("capabilities.{other}"))),
        }
    }

    /// Whether a sandbox-level capability can be generated: only for an ordinary setup.
    fn profile_free(&mut self, cap: &Capability) -> bool {
        if self.profile.is_some() {
            self.keep(cap, "grid setups use the grid's own sandboxes; add it in yougori.yaml if you need one.");
            return false;
        }
        true
    }

    fn finish(mut self, name: String, added: Vec<String>) -> Result<Generated, Vec<Diagnostic>> {
        // Settings no generated question uses are named, never dropped silently.
        for (id, choice) in &self.draft.capabilities {
            if !choice.selected {
                continue;
            }
            for key in choice.settings.keys().chain(choice.controls.keys()) {
                if self.owners.get(key).is_none_or(|owner| owner != id) {
                    self.notes.push(note("setting_unused", format!("The setting {key} of {id} has no question in the generated package; add it by hand if you need it.")).at(format!("capabilities.{id}.{key}")));
                }
            }
        }
        if !self.draft.questions.is_empty() || !self.draft.answers.is_empty() {
            self.notes.push(note("source_questions_kept", "The questions read from the source stay in its own package; this draft generates its own."));
        }
        if let Some(vm) = self.vm.take() {
            if self.vm_peer {
                // The peer has the first's memory, limits and workspace (a staged copy of its own),
                // and serves the service to the first sandbox alone.
                let mut peer = json!({});
                for key in ["memory_gb", "idle_minutes", "lifetime_minutes", "workspace"] {
                    if let Some(value) = vm.get(key) {
                        peer[key] = value.clone();
                    }
                }
                peer["publish"] = json!([{"service": "{{inputs.connect_service}}", "port": "{{inputs.connect_port}}", "accept": ["vm"]}]);
                self.resources.insert("peer".into(), resource("vm_sandbox", "sandbox.connect", peer));
                self.outputs.push(output("vm_sandbox_peer", "Connected VM sandbox", "{{outputs.peer.id}}"));
            }
            self.resources.insert("vm".into(), resource("vm_sandbox", "sandbox.vm", vm));
        }
        if self.app.is_none() && self.profile.is_none() && self.resources.is_empty() {
            // Nothing chosen creates anything yet; a starter sandbox makes the package runnable.
            self.app();
            self.notes.push(note("starter_sandbox", "Nothing you chose creates a sandbox yet, so a starter one was added. Replace it in yougori.yaml."));
        }
        if let Some(gateway) = self.gateway.take() {
            let app = self.app.is_some();
            self.resources.insert("model_gateway".into(), resource("environment", "models.cloud", gateway));
            if app {
                // The app calls the gateway as an OpenAI-compatible API, inside the setup only.
                let app = self.app();
                let environment = app.entry("environment").or_insert_with(|| json!({}));
                environment["OPENAI_BASE_URL"] = json!("http://model_gateway:8080/v1");
                environment["OPENAI_API_KEY"] = json!("yougori-gateway");
                environment["MODEL"] = json!("{{inputs.cloud_model}}");
                self.resources.insert("app_to_model".into(), resource("connection", "models.cloud", json!({"from": {"resource": "app"}, "to": {"resource": "model_gateway"}, "ports": [8080], "direction": "one_way"})));
                self.app_by.insert("models.cloud");
            }
            self.extra.insert(GATEWAY_FILE.to_owned(), GATEWAY_SCRIPT.to_owned());
        }
        if let Some(app) = self.app.take() {
            // The sandbox belongs to the one capability that made it. When several shaped it, it
            // stays whatever the runner turns off, and the author is told so.
            let mut sandbox = Resource { kind: "environment".into(), spec: yaml(app), ..Resource::default() };
            let by: Vec<&str> = self.app_by.iter().copied().collect();
            match by.as_slice() {
                [one] => sandbox.capability = Some((*one).to_owned()),
                [] => {}
                several => {
                    let optional = several.iter().filter(|id| self.choice(id).mode != Mode::Required).count();
                    if optional > 0 {
                        self.notes.push(note("app_shared", format!("The app sandbox is shared by {}, so it is created even when some of them are turned off.", several.join(", "))).at("capabilities"));
                    }
                }
            }
            self.resources.insert("app".into(), sandbox);
            self.views.insert("logs");
        }
        if let Some(grid) = self.grid.take() {
            let by = self.grid_by.unwrap_or("grid.create");
            self.resources.insert("grid".into(), resource("grid", by, grid));
        }
        if let Some(pool) = self.pool.take() {
            let by = self.grid_by.unwrap_or("grid.create");
            self.resources.insert("computers".into(), resource("compute_pool", by, pool));
        }
        if let Some(owner) = self.owner.take() {
            self.resources.insert("owner".into(), resource("access_binding", "people.roles", owner));
        }

        let draft = self.draft;
        let title = draft.title.clone().filter(|t| !t.trim().is_empty()).unwrap_or_else(|| draft.name.trim().to_owned());
        let summary = draft.summary.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| SUMMARY.to_owned());
        let capabilities: Vec<CapabilityUse> = self
            .order
            .iter()
            .map(|cap| {
                let choice = self.draft.capabilities.get(cap.id).cloned().unwrap_or_default();
                CapabilityUse { id: cap.id.to_owned(), selection: choice.mode.into(), locked: !choice.runner_editable, when: None }
            })
            .collect();
        let gpu = self.on.contains("models.local").then(|| "optional".to_owned());
        let template = Template {
            format_version: Some(format::FORMAT_VERSION),
            kind: Some("template".into()),
            name: Some(name.clone()),
            title: Some(title.clone()),
            subtitle: draft.subtitle.clone().filter(|s| !s.trim().is_empty()),
            summary: Some(summary.clone()),
            version: Some(DRAFT_VERSION.into()),
            license: Some("MIT".into()),
            changelog: Some("First draft.".into()),
            profile: self.profile.map(|profile| profile.id().to_owned()),
            requires: Requires { yougori: Some(format::MINIMUM_YOUGORI.into()), gpu, platforms: Vec::new() },
            capabilities,
            bindings: self.bindings.clone(),
            inputs: self.inputs.clone(),
            tools: self.tools.clone(),
            tool_options: self.tool_options.clone(),
            steps: self.steps.clone(),
            outputs: self.outputs.clone(),
            retention: Some(Retention::default()),
            views: self.views.iter().map(|view| (*view).to_owned()).collect(),
            limits: self.limits.clone(),
            ..Template::default()
        };
        let project = Project { format_version: Some(format::FORMAT_VERSION), project: name.clone(), resources: self.resources.clone(), ..Project::default() };
        let header = "# Generated by Yougori from a draft. Edit it freely: `yougori template check .` tells you\n# what to fix, and `yougori template plan .` shows what it would create.\n";
        let manifest = format!("{header}{}", serde_yaml_ng::to_string(&template).map_err(|e| vec![Diagnostic::error("draft_write", e.to_string())])?);
        let project_text = format!("{header}{}", serde_yaml_ng::to_string(&project).map_err(|e| vec![Diagnostic::error("draft_write", e.to_string())])?);
        let readme = self.readme(&title, &summary);
        let changelog = format!("# Changelog\n\n## {DRAFT_VERSION}\n\nFirst draft.\n");
        let generated = Generated { name, manifest, project: project_text, readme, changelog, added, notes: self.notes, extra: self.extra };
        // Whatever the format refuses, the draft refuses too, with the format's own words.
        format::template(&generated.files())?;
        Ok(generated)
    }

    fn readme(&self, title: &str, summary: &str) -> String {
        let mut text = format!("# {title}\n\n{summary}\n\n```text\nyougori template check .\nyougori template plan .\n```\n\n## What it uses\n\n");
        for cap in &self.order {
            text.push_str(&format!("- **{}**: {}\n", cap.name, cap.summary));
        }
        if !self.inputs.is_empty() {
            text.push_str("\n## Questions it asks\n\n| Input | Question |\n| --- | --- |\n");
            for question in &self.inputs {
                text.push_str(&format!("| `{}` | {} |\n", question.id.as_deref().unwrap_or_default(), question.question.as_deref().unwrap_or_default()));
            }
        }
        if !self.resources.is_empty() {
            text.push_str("\n## What it creates\n\n| Resource | Kind |\n| --- | --- |\n");
            for (id, resource) in &self.resources {
                text.push_str(&format!("| `{id}` | {} |\n", resource.kind.replace('_', " ")));
            }
        }
        let kept: Vec<&Diagnostic> = self.notes.iter().filter(|note| note.code == "capability_kept").collect();
        if !kept.is_empty() {
            text.push_str("\n## Known limits\n\n");
            for note in kept {
                text.push_str(&format!("- {}\n", note.message));
            }
        }
        text.push_str("\nAdd a LICENSE file before you publish it.\n");
        text
    }
}

/// An author's value as the default a question of `kind` takes, or None when a yes/no question
/// is given something that is neither.
fn setting(value: &Json, kind: Option<&str>) -> Option<Json> {
    match (kind, value) {
        (Some("yesno"), value) => yes_no_setting(value).map(|on| json!(on)),
        (Some("multichoice"), Json::String(text)) => Some(json!(text.split(',').map(str::trim).filter(|t| !t.is_empty()).collect::<Vec<_>>())),
        (_, value) => Some(value.clone()),
    }
}

/// A yes/no setting read the way the format reads a yes/no answer: yes, y or true and no, n or
/// false in any case, or a JSON boolean. Anything else is None, never a silent no.
pub fn yes_no_setting(value: &Json) -> Option<bool> {
    match value {
        Json::Bool(flag) => Some(*flag),
        Json::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "yes" | "y" | "true" => Some(true),
            "no" | "n" | "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// ---- Reading a package back ----

/// Reads a package into a draft, so its choices can be shown before planning. What a draft cannot
/// hold stays in the package and is named in the notes.
pub fn from_package(files: &Files) -> Result<(Draft, Vec<Diagnostic>), Vec<Diagnostic>> {
    let checked = format::template(files)?;
    Ok(from_checked(&checked))
}

/// The draft of a checked package.
pub fn from_checked(checked: &Checked) -> (Draft, Vec<Diagnostic>) {
    let template = &checked.template;
    let mut notes = Vec::new();
    // Which capability asks each question: read from the generated fragments' ids when the
    // package came from a draft; otherwise the question stands alone.
    let mut owners: BTreeMap<String, String> = BTreeMap::new();
    for cap in &checked.capabilities {
        for question in fragment_questions(&cap.id) {
            owners.insert((*question).to_owned(), cap.id.clone());
        }
    }
    // The answers the template starts from, in the order its questions are asked.
    let mut defaults: BTreeMap<String, String> = BTreeMap::new();
    for question in &checked.questions {
        if let Some(value) = question.default.as_ref().filter(|_| question.asked(&defaults)) {
            defaults.insert(question.id.clone(), value.clone());
        }
    }
    let mut capabilities = BTreeMap::new();
    for cap in &checked.capabilities {
        let applies = cap.when.as_ref().is_none_or(|when| when.holds(&defaults));
        if cap.when.is_some() {
            let now = if applies { "it holds with the template's default answers" } else { "it doesn't hold with the template's default answers, so it starts turned off" };
            notes.push(note("draft_condition_kept", format!("{} is used only when a condition holds; {now}. The condition stays in the package.", cap.id)).at(format!("capabilities.{}", cap.id)));
        }
        let mut settings = BTreeMap::new();
        for question in &checked.questions {
            if owners.get(&question.id) == Some(&cap.id) {
                if let Some(value) = &question.default {
                    settings.insert(question.id.clone(), answer_json(question.kind, value));
                }
            }
        }
        capabilities.insert(cap.id.clone(), CapabilityChoice { selected: applies && cap.selection != Selection::Optional, mode: cap.selection.into(), runner_editable: !cap.locked, settings, controls: BTreeMap::new() });
    }
    let questions = checked
        .questions
        .iter()
        .map(|question| QuestionDescriptor {
            id: question.id.clone(),
            label: question.question.clone(),
            kind: match question.kind {
                QuestionKind::Choice | QuestionKind::MultiChoice => "choice",
                QuestionKind::YesNo => "toggle",
                QuestionKind::Secret => "secret",
                QuestionKind::Number => "number",
                QuestionKind::Text | QuestionKind::Domain => "text",
            }
            .to_owned(),
            help: (!question.hint.is_empty()).then(|| question.hint.clone()),
            options: question.choices.iter().map(|choice| QuestionOption { value: choice.value.clone(), label: choice.label.clone() }).collect(),
            default: question.default.as_ref().map(|value| answer_json(question.kind, value)),
            min: question.min,
            max: question.max,
            capability: owners.get(&question.id).cloned(),
            group: question.group.map(|group| group.id().to_owned()),
            step: None,
            binding: None,
            access: None,
            required: question.required,
        })
        .collect::<Vec<_>>();
    // The bindings are asked beside the questions, after them: a folder, a drive, a file or an
    // existing resource the person picks on their own computer when the setup is applied. They
    // share one id namespace with the inputs, so the planner reads each answer as its binding.
    let questions = questions
        .into_iter()
        .chain(checked.bindings.iter().map(|binding| QuestionDescriptor {
            id: binding.id.clone(),
            label: binding.question.clone(),
            kind: binding.kind.id().to_owned(),
            help: (!binding.hint.is_empty()).then(|| binding.hint.clone()),
            options: Vec::new(),
            default: None,
            min: None,
            max: None,
            capability: None,
            group: Some(crate::capability::Group::FilesData.id().to_owned()),
            step: None,
            binding: Some(binding.kind.id().to_owned()),
            access: (binding.kind == crate::resource::BindingKind::Folder)
                .then(|| folder_access_for(binding.mode.unwrap_or_default(), binding.read_only)),
            required: binding.required,
        }))
        .collect::<Vec<_>>();
    for question in &checked.questions {
        if question.kind == QuestionKind::MultiChoice {
            notes.push(note("draft_multichoice", format!("{} takes several answers; the builder shows it as a choice.", question.id)).at(question.id.clone()));
        }
        if question.when.is_some() || question.pattern.is_some() {
            notes.push(note("draft_question_rules_kept", format!("{} has a condition or a pattern; it stays in the package.", question.id)).at(question.id.clone()));
        }
    }
    let kept = [
        (!checked.resources.is_empty() || !checked.environments.is_empty(), "its resources"),
        (!checked.steps.is_empty(), "its steps"),
        (!checked.outputs.is_empty(), "its outputs"),
        (!checked.bindings.is_empty(), "its bindings"),
        (!checked.tools.is_empty(), "its tools"),
        (!checked.public.is_empty(), "its public addresses"),
        (!template.imports.is_empty(), "its imports"),
    ];
    let kept: Vec<&str> = kept.iter().filter(|(present, _)| *present).map(|(_, what)| *what).collect();
    if !kept.is_empty() {
        notes.push(note("draft_package_kept", format!("The package keeps {}; the draft shows its choices and questions.", kept.join(", "))));
    }
    let draft = Draft {
        name: template.name().to_owned(),
        title: template.title.clone(),
        subtitle: template.subtitle.clone(),
        summary: template.summary.clone(),
        source: None,
        recipe: checked.profile.and_then(|profile| profile.recipe_slug()).map(str::to_owned),
        environments: Vec::new(),
        capabilities,
        questions,
        answers: BTreeMap::new(),
    };
    (draft, notes)
}

/// The question ids each capability's fragment asks, so a generated package reads back with its
/// questions under the right capability.
pub fn fragment_questions(id: &str) -> &'static [&'static str] {
    match id {
        "grid.create" => &["grid_name", "coordinator_address", "grid_password", "access"],
        "grid.join" => &["invitation", "join_password", "username", "password"],
        "grid.worker_limits" => &["share_cpu", "share_memory_gb", "share_disk_gb"],
        "grid.availability" => &["availability", "idle_after_minutes", "schedule"],
        "tools.builtin" => &["tool"],
        "tools.custom" => &["image"],
        "tools.provider_access" => &["method", "codex_api_key", "claude_api_key", "gemini_api_key", "opencode_api_key", "kilo_api_key"],
        "models.local" => &["model"],
        "models.existing" => &["existing_model_name"],
        "models.team" => &["team_name", "team_strategy"],
        "web.service" => &["image", "port"],
        "web.domain" => &["domain"],
        "web.health" => &["health_path"],
        "people.roles" => &["admin_username", "admin_password"],
        "people.workspaces" => &["person_username", "person_password", "workspace_runtime", "workspace_image"],
        "people.sso" => &["sso_issuer", "sso_client_id", "sso_claim", "sso_only"],
        "people.mfa" => &["require_two_step"],
        "data.databases" => &["database_password"],
        "sandbox.vm" => &["vm_memory_gb", "vm_idle_minutes", "vm_lifetime_minutes"],
        "sandbox.remote" => &["remote_connection", "remote_program", "remote_endpoint", "remote_engine_sha256", "remote_memory_gb", "remote_lifetime_minutes"],
        "sandbox.routes" => &["route_host", "route_method", "route_path", "route_signs_in", "route_credential"],
        "sandbox.publish" => &["publish_service", "publish_port"],
        "sandbox.connect" => &["connect_service", "connect_port", "connect_minutes"],
        "run.job" => &["job_command"],
        "run.retries" => &["attempts"],
        _ => &[],
    }
}

/// A stored answer as the JSON value the builder shows.
fn answer_json(kind: QuestionKind, value: &str) -> Json {
    match kind {
        QuestionKind::YesNo => json!(value == "yes"),
        QuestionKind::Number => value.parse::<f64>().map(|n| json!(n)).unwrap_or_else(|_| json!(value)),
        _ => json!(value),
    }
}

/// A draft's choice of one capability, for a caller building a draft by hand (the CLI).
pub fn choose(draft: &mut Draft, id: &str, mode: Mode) {
    draft.capabilities.insert(id.to_owned(), CapabilityChoice { mode, ..CapabilityChoice::default() });
}

/// Whether a yes/no setting reads as on. A value that is neither yes nor no is not on; use
/// [`yes_no_setting`] to tell it apart from no.
pub fn is_on(value: &Json) -> bool {
    yes_no_setting(value) == Some(true)
}
