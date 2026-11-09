//! Format 2 packages on this computer: checking a folder, planning it without the engine (pure,
//! nothing created or downloaded), turning a parsed v1 template into the shared adapter's form,
//! and running a format 2 package through the engine's setup service. The shared crate
//! (`yougori-setup`) owns the format and the planner; this module is the CLI's way in.
use super::{
    client::{Cache, Site},
    components,
    format as v1,
    run::{self, Fetched, Options, Wanted},
    scan::{self, Files},
    setups, views,
};
use crate::cli_ui as ui;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};
use yougori_setup::{
    capability,
    condition::Condition,
    dto::Diagnostic,
    format::{self, FormatVersion, QuestionKind},
    plan, resource,
    v1 as legacy,
};
use zeroize::Zeroizing;

/// The format a package's template file declares, or the refusal for one this Yougori does not
/// read ("This template needs a newer Yougori").
pub fn format_of(files: &Files) -> Result<FormatVersion, String> {
    let bytes = files.get(v1::TEMPLATE_FILE).ok_or_else(|| format!("The folder has no {}.", v1::TEMPLATE_FILE))?;
    let text = scan::text(bytes).ok_or_else(|| format!("{} must be UTF-8 text.", v1::TEMPLATE_FILE))?;
    format::format_version(text).map_err(|refusal| refusal.message)
}

/// Whether a package is written in format 2.
pub fn is_v2(files: &Files) -> bool {
    format_of(files) == Ok(FormatVersion::V2)
}

/// Checks a format 2 package's files: every problem, each saying what to change.
pub fn check_files(files: &Files) -> Result<format::Checked, Vec<Diagnostic>> {
    format::template(files)
}

/// Checks a format 2 package folder on this computer.
pub fn check_folder(folder: &Path) -> Result<format::Checked, Vec<Diagnostic>> {
    let collected = scan::collect(folder).map_err(|problem| vec![Diagnostic::error("package_unreadable", problem).at("source.path")])?;
    check_files(&collected.files)
}

/// The problems of a package as a terminal shows them: one line each, with where it is.
pub fn problems_text(what: &str, problems: &[Diagnostic]) -> String {
    let mut lines = vec![format!("{what} has {} to fix:", if problems.len() == 1 { "one thing".to_owned() } else { format!("{} things", problems.len()) })];
    for problem in problems {
        let place = problem.field.as_deref().filter(|f| !f.is_empty()).map(|f| format!(" ({f})")).unwrap_or_default();
        lines.push(format!("  - {}{place}", views::clean(&problem.message)));
    }
    lines.join("\n")
}

/// This computer as far as a pure check can tell: the platform and the Yougori version are
/// real; the GPU and the runtimes are assumed present until the engine reports them, so a plan
/// made without the engine never refuses a capability this computer may well support. A run
/// goes through the engine, which plans again with what it knows.
pub fn host_here() -> plan::Host {
    let platform = crate::update::platform();
    let os = match std::env::consts::OS {
        "windows" => capability::Os::Windows,
        "macos" => capability::Os::Macos,
        _ => capability::Os::Linux,
    };
    let arch = if std::env::consts::ARCH == "aarch64" { capability::Arch::Aarch64 } else { capability::Arch::X86_64 };
    let runtimes = vec![capability::Runtime::Containers, capability::Runtime::NvidiaContainers, capability::Runtime::MicroVm, capability::Runtime::Vm, capability::Runtime::LocalModels, capability::Runtime::NativeSandbox];
    plan::Host {
        yougori: host_version(),
        platform: platform.into(),
        gpu: None,
        memory_gb: None,
        free_disk_gb: None,
        capabilities: capability::Host::new(os, arch, capability::Gpu::Nvidia, runtimes, capability::Host::PRIVATE_BUILD),
    }
}

/// The version a template's `requires.yougori` is checked against here: this build's own, so
/// this pre-check refuses what the engine would. A DEVELOPMENT build reads
/// `YOUGORI_DEV_HOST_VERSION` as the engine's planner does, so the two doors agree while
/// templates written for the next release are tried against the tree that is becoming it. A
/// release build never reads it.
fn host_version() -> String {
    match stand_in(std::env::var("YOUGORI_DEV_HOST_VERSION").ok().as_deref()) {
        Some(asked) => {
            eprintln!(
                "Checking templates as Yougori {asked} because YOUGORI_DEV_HOST_VERSION is set. This is a development build only; a released Yougori always checks as its own version ({}).",
                env!("CARGO_PKG_VERSION")
            );
            asked
        }
        None => env!("CARGO_PKG_VERSION").into(),
    }
}

/// The version a development build is asked to stand in for, when what was asked is a version.
#[cfg(debug_assertions)]
fn stand_in(asked: Option<&str>) -> Option<String> {
    let asked = asked?.trim();
    format::parse_version(asked).ok().map(|_| asked.to_owned())
}

#[cfg(not(debug_assertions))]
fn stand_in(_asked: Option<&str>) -> Option<String> {
    None
}

/// [`host_here`] corrected by what the engine knows: memory, free disk and whether an NVIDIA GPU
/// is usable. `state` is `get_platform_state`; `cuda` is `get_cuda_runtime_status`'s `supported`.
pub fn host_with_engine(host: &mut plan::Host, state: &Value, cuda: Option<bool>) {
    if let Some(memory) = state["host"]["totalMemoryGb"].as_f64().filter(|m| *m > 0.0) {
        host.memory_gb = Some(memory);
    }
    if let (Some(total), Some(used)) = (state["host"]["totalStorageGb"].as_f64(), state["host"]["usedStorageGb"].as_f64()) {
        host.free_disk_gb = Some((total - used).max(0.0));
    }
    if let Some(supported) = cuda {
        host.gpu = Some(supported);
        host.capabilities.gpu = if supported { capability::Gpu::Nvidia } else { capability::Gpu::None };
    }
}

/// This computer as the engine sees it, starting the engine when it is not running. Falls back
/// to [`host_here`] when the engine cannot answer.
pub async fn host_from_engine() -> plan::Host {
    let mut host = host_here();
    if crate::client::start(None).await.is_err() {
        return host;
    }
    let state = crate::public::call("get_platform_state", json!({})).await.unwrap_or(Value::Null);
    let cuda = crate::public::call("get_cuda_runtime_status", json!({})).await.ok().and_then(|status| status["supported"].as_bool());
    host_with_engine(&mut host, &state, cuda);
    host
}

/// Plans a package's files with these answers on this computer, changing nothing. `item` is
/// the Hub item (`PUBLISHER/NAME`) when the files came from the Hub; `digest` their digest.
pub fn plan_files(files: &Files, item: Option<String>, digest: Option<String>, answers: &plan::Answers, host: &plan::Host) -> Result<plan::Plan, Vec<Diagnostic>> {
    let checked = check_files(files)?;
    let package = plan::Package { checked, components: BTreeMap::new(), item, digest };
    plan::plan(&package, answers, host)
}

/// Plans a format 2 package folder with these answers on this computer. Pure: nothing is created,
/// downloaded, signed in or stored. `awaiting_input` problems (field `inputs.ID`) mean: ask that
/// question and plan again.
pub fn plan_folder(folder: &Path, answers: &plan::Answers, host: &plan::Host) -> Result<plan::Plan, Vec<Diagnostic>> {
    let collected = scan::collect(folder).map_err(|problem| vec![Diagnostic::error("package_unreadable", problem).at("source.path")])?;
    let digest = scan::digest_of(&collected.files);
    plan_files(&collected.files, None, Some(digest), answers, host)
}

/// The rules `check` and `publish` apply to a format 2 package beyond its format: a fixed host
/// port means a second copy could never start, and an unpinned Hub tool means two runs could
/// install different files.
pub fn publishing_problems(checked: &format::Checked) -> Vec<String> {
    let mut problems = Vec::new();
    let environments = checked.environments.iter().map(|(name, spec)| (name.clone(), spec.clone()))
        .chain(checked.resources.values().filter(|r| r.kind == resource::Kind::Environment).map(|r| (r.id.clone(), r.spec.clone())));
    for (name, spec) in environments {
        for port in spec.get("ports").and_then(serde_yaml_ng::Value::as_sequence).into_iter().flatten() {
            if let Ok(resource::Port::Mapping(text)) = serde_yaml_ng::from_value::<resource::Port>(port.clone()) {
                if let Ok((guest, Some(host))) = resource::Port::Mapping(text).values() {
                    problems.push(format!("{}: {name}: ports fixes host port {host} for {guest}, so a second copy of the template could never start. List the container port only (ports: [{guest}]); Yougori picks a free port on each computer, and public: gives the internet address.", checked.project_path));
                }
            }
            if let Some(mapping) = port.as_mapping() {
                if let (Some(target), Some(published)) = (mapping.get("target").and_then(serde_yaml_ng::Value::as_u64), mapping.get("published").and_then(serde_yaml_ng::Value::as_u64)) {
                    problems.push(format!("{}: {name}: ports fixes host port {published} for {target}, so a second copy of the template could never start. List the container port only (ports: [{target}]).", checked.project_path));
                }
            }
        }
    }
    for use_ in &checked.tools {
        if let format::Source::Hub { item, version: None } = &use_.source {
            problems.push(format!("tools: {}: pin hub/{item} to a version, such as hub/{item}@1.0.0, so everyone who runs this template installs the same files.", use_.environment));
        }
    }
    problems
}

// ---- The v1 adapter ----

/// A v1 condition list (AND between inputs) in the shared form.
pub fn legacy_conditions(conditions: &[v1::Condition]) -> Option<Condition> {
    Condition::terms(conditions.iter().map(|c| (c.input.clone(), c.values.clone(), c.contains)).collect())
}

/// A v1 question in the shared form: the same question, with no group (v1 has none) and
/// editable, as every v1 answer is.
pub fn legacy_question(question: &v1::Question) -> format::Question {
    let kind = match question.kind {
        v1::Kind::Choice => QuestionKind::Choice,
        v1::Kind::MultiChoice => QuestionKind::MultiChoice,
        v1::Kind::Text => QuestionKind::Text,
        v1::Kind::Number => QuestionKind::Number,
        v1::Kind::Secret => QuestionKind::Secret,
        v1::Kind::Domain => QuestionKind::Domain,
        v1::Kind::YesNo => QuestionKind::YesNo,
    };
    format::Question {
        id: question.id.clone(),
        question: question.question.clone(),
        kind,
        required: question.required,
        default: question.default.clone(),
        when: legacy_conditions(&question.when),
        hint: question.hint.clone(),
        choices: question.choices.iter().map(|c| format::ChoiceOption { value: c.value.clone(), label: c.label.clone(), hint: c.hint.clone() }).collect(),
        pattern: question.pattern.clone(),
        min: question.min,
        max: question.max,
        min_length: question.min_length,
        group: None,
        editable: true,
    }
}

fn legacy_tool_file(tool: &v1::Tool) -> format::Tool {
    format::Tool {
        kind: tool.kind.clone(),
        name: tool.name.clone(),
        title: tool.title.clone(),
        summary: tool.summary.clone(),
        version: tool.version.clone(),
        license: tool.license.clone(),
        topics: tool.topics.clone(),
        changelog: tool.changelog.clone(),
        command: tool.command.clone(),
        install: tool.install.clone(),
        check: tool.check.clone(),
        signin: tool.signin.as_ref().map(|s| format::Signin { method: s.method.clone(), command: s.command.clone(), variable: s.variable.clone() }),
        needs: tool.needs.as_ref().map(|n| format::Needs { gpu: n.gpu.clone(), memory: n.memory.clone(), internet: n.internet }),
        service: tool.service.as_ref().map(|s| format::Service { command: s.command.clone(), port: s.port }),
        ..format::Tool::default()
    }
}

/// A v1 tool use in the shared form.
pub fn legacy_tool(use_: &v1::ToolUse) -> format::ToolUse {
    let source = match &use_.source {
        v1::Source::BuiltIn(name) => format::Source::BuiltIn { name: name.clone() },
        v1::Source::Bundled { folder, tool } => format::Source::Bundled { folder: folder.clone(), tool: Box::new(legacy_tool_file(tool)) },
        v1::Source::Hub(reference) => format::Source::Hub { item: reference.item(), version: reference.version.clone() },
    };
    format::ToolUse {
        environment: use_.environment.clone(),
        spec: use_.spec.clone(),
        source,
        when: legacy_conditions(&use_.when),
        signin: use_.signin,
        signin_when: legacy_conditions(&use_.signin_when),
        signin_hint: use_.signin_hint.clone(),
        signin_source: use_.signin_source.clone(),
        resolved: None,
    }
}

/// A checked v1 template, as the CLI's own parser read it, in the form the shared planner takes:
/// the same questions, tools, public entries, steps and outputs, and the project's environments
/// exactly as written (placeholders included). Nothing is asked that v1 did not ask.
pub fn legacy_of(folder: &v1::Folder) -> legacy::LegacyTemplate {
    let tree: serde_yaml_ng::Value = yougori_setup::format::read_yaml(&folder.project_text).unwrap_or(serde_yaml_ng::Value::Null);
    let environments: BTreeMap<String, serde_yaml_ng::Value> = tree.get("environments").and_then(serde_yaml_ng::Value::as_mapping)
        .map(|map| map.iter().filter_map(|(k, v)| k.as_str().map(|k| (k.to_owned(), v.clone()))).collect())
        .unwrap_or_default();
    let connections = folder.project.connections.iter().filter_map(|c| {
        let (from, to) = c.endpoints().ok()?;
        let (ports, permissions) = match c {
            crate::manifest::Connection::Detailed { ports, permissions, .. } => (ports.clone(), permissions.clone()),
            crate::manifest::Connection::Arrow(_) => (Vec::new(), Vec::new()),
        };
        Some(format::LegacyConnection { from: from.to_owned(), to: to.to_owned(), ports, permissions })
    }).collect();
    let questions: Vec<format::Question> = folder.questions.iter().map(legacy_question).collect();
    let public = folder.template.public.iter().filter_map(|entry| {
        let environment = entry.environment.clone()?;
        let port = entry.port?;
        let access = match entry.access.as_deref().unwrap_or("quick") {
            text @ ("quick" | "domain" | "none") => format::Access::Fixed(text.to_owned()),
            text => match yougori_setup::placeholder::whole_input(text) {
                Some(id) => format::Access::Asked(id),
                None => format::Access::Fixed("quick".into()),
            },
        };
        Some(format::CheckedPublic { environment, port, access, domain: entry.domain.clone() })
    }).collect();
    let steps = folder.template.steps.iter().map(|step| format::CheckedStep {
        title: step.title.clone().unwrap_or_default(),
        detail: step.detail.clone(),
        command: step.command.clone(),
        when: v1::conditions(&step.when, &folder.questions).ok().and_then(|c| legacy_conditions(&c)),
    }).collect();
    let outputs = folder.template.outputs.iter().map(|output| format::CheckedOutput {
        key: None,
        label: output.label.clone().unwrap_or_default(),
        value: output.value.clone().unwrap_or_default(),
        private: false,
        when: None,
    }).collect();
    legacy::LegacyTemplate {
        name: folder.template.name().to_owned(),
        version: folder.template.version().to_owned(),
        title: folder.template.title.clone(),
        summary: folder.template.summary.clone(),
        requires: format::Requires { yougori: folder.template.requires.yougori.clone(), gpu: folder.template.requires.gpu.clone(), platforms: folder.template.requires.platforms.clone() },
        project: folder.project.project.clone(),
        environments,
        connections,
        questions,
        tools: folder.tools.iter().map(legacy_tool).collect(),
        public,
        steps,
        outputs,
        models: folder.models.as_ref().map(|m| format::Models { environment: m.environment.clone(), command: m.command.clone() }),
    }
}

// ---- Running a format 2 package through the engine ----

/// A fresh operation id for an apply, so replaying after an interruption is safe.
fn operation_id() -> Result<String, String> {
    use base64::Engine;
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut bytes).map_err(|_| "Cannot make an operation id (no secure randomness). Nothing was created.".to_owned())?;
    Ok(format!("op-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)))
}

/// A format 2 question as the terminal asks it: the v1 prompt, which knows every question type.
/// The condition is decided before asking, so the prompt needs none.
fn prompt_question(question: &format::Question) -> v1::Question {
    v1::Question {
        id: question.id.clone(),
        question: question.question.clone(),
        kind: match question.kind {
            QuestionKind::Choice => v1::Kind::Choice,
            QuestionKind::MultiChoice => v1::Kind::MultiChoice,
            QuestionKind::Text => v1::Kind::Text,
            QuestionKind::Number => v1::Kind::Number,
            QuestionKind::Secret => v1::Kind::Secret,
            QuestionKind::Domain => v1::Kind::Domain,
            QuestionKind::YesNo => v1::Kind::YesNo,
        },
        required: question.required,
        default: question.default.clone(),
        when: Vec::new(),
        hint: question.hint.clone(),
        choices: question.choices.iter().map(|c| v1::Option_ { value: c.value.clone(), label: c.label.clone(), hint: c.hint.clone() }).collect(),
        pattern: question.pattern.clone(),
        min: question.min,
        max: question.max,
        min_length: question.min_length,
    }
}

/// What a run collected before planning: public answers, secret values (kept only until the
/// apply), capability choices and the bindings chosen on this computer.
#[derive(Debug, Default)]
struct Collected {
    inputs: BTreeMap<String, String>,
    secrets: BTreeMap<String, Zeroizing<String>>,
    capabilities: BTreeMap<String, bool>,
    bindings: BTreeMap<String, String>,
}

fn stop_created(error: String) -> String {
    if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled("Cancelled. Nothing was created.") } else { error }
}

/// What the person agreed to on the review, for `setup_apply`. Each agreement is asked on its own
/// and defaults to no: a plan asks, it never grants. Scripted, `--allow-pc-access` stands for the
/// folder agreements it listed in the plan, and nothing stands for a sign-in copy, which `--yes`
/// never makes (the sign-in source question has no default of this computer).
fn agree_to(planned: &Value, options: &Options, interactive: bool) -> Result<Vec<String>, String> {
    agreements(planned, options.allow_pc_access, interactive, Stage::Run)
}

/// Which command a plan's agreements are asked for, for the words its refusal and its cancel use:
/// a first run creates, a change (`template configure`, `template update`) changes, a join joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    Run,
    Change,
    Join,
}

impl Stage {
    fn nothing(self) -> &'static str {
        match self {
            Stage::Run => "Nothing was created.",
            Stage::Change => "Nothing was changed.",
            Stage::Join => "Nothing was joined.",
        }
    }

    /// A question left with Ctrl+C or Back, said as what it left undone.
    fn stopped(self, error: String) -> String {
        if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled(&format!("Cancelled. {}", self.nothing())) } else { error }
    }
}

/// The agreements of a reviewed plan (its `consents`, each `{id, message}`), for `setup_apply`:
/// the one flow every door that applies a plan uses, so a change or a join gives the engine the
/// same agreements a first run does. Each is asked on its own at a terminal and defaults to no; a
/// script agrees to the folder agreements (`write_folder:`) only with `allow_pc_access`, and never
/// to a sign-in copy. A writable folder left unagreed is refused here, before anything is applied,
/// because the engine would otherwise stop part way through waiting for that agreement.
pub(super) fn agreements(planned: &Value, allow_pc_access: bool, interactive: bool, stage: Stage) -> Result<Vec<String>, String> {
    let asked = planned["consents"].as_array().cloned().unwrap_or_default();
    let mut agreed = Vec::new();
    for consent in &asked {
        let (Some(id), Some(message)) = (consent["id"].as_str(), consent["message"].as_str()) else { continue };
        let folder = id.starts_with("write_folder:");
        if !interactive {
            // A scripted run agrees only to what its flags say, and says what it left out.
            if folder && allow_pc_access {
                agreed.push(id.to_owned());
            }
            continue;
        }
        let choices = [ui::Choice::new("Allow it", "only what this line says"), ui::Choice::new("Not this", "the setup goes on without it")];
        if ui::select(&views::clean(message), &[], &choices, 1).map_err(|error| stage.stopped(error))? == 0 {
            agreed.push(id.to_owned());
        }
    }
    // A writable folder the person did not agree to would stop the setup part way through; say so
    // now, before anything is applied, rather than after the sandbox exists or has changed.
    // A mounted folder left unagreed is mounted read only (the engine says `mode: mount`), so it
    // stops nothing; only a synced one (or one from an engine that does not say) is refused.
    let missing: Vec<&str> = asked
        .iter()
        .filter(|consent| consent["mode"] != "mount")
        .filter_map(|consent| consent["id"].as_str())
        .filter(|id| id.starts_with("write_folder:") && !agreed.iter().any(|said| said == id))
        .collect();
    if !missing.is_empty() {
        let names: Vec<&str> = missing.iter().filter_map(|id| id.rsplit('/').next()).collect();
        let what = if stage == Stage::Change { "This change" } else { "This setup" };
        let next = match (stage, interactive) {
            (Stage::Run, true) => "Run it again and allow it, or use a template that only reads the folder.",
            (Stage::Change, true) => "Review the change again and allow it.",
            (Stage::Join, true) => "Join again and allow it.",
            (Stage::Run | Stage::Change, false) => "Pass --allow-pc-access as well as --yes if that is intended.",
            (Stage::Join, false) => "Join at a terminal to agree to it.",
        };
        return Err(format!(
            "{what} keeps a folder you chose in step with its sandbox, which means changing files in it, and that was not agreed to ({}). {next} {}",
            names.join(", "),
            stage.nothing()
        ));
    }
    Ok(agreed)
}

/// What a folder binding will be allowed to do with the folder, in one line, shown as the
/// question is asked: the sentence the desktop builder shows (`draft::folder_access_for`). The
/// review says it again before anything is created.
fn folder_access(binding: &format::CheckedBinding) -> Option<String> {
    if binding.kind != resource::BindingKind::Folder {
        return None;
    }
    Some(yougori_setup::draft::folder_access_for(binding.mode.unwrap_or_default(), binding.read_only))
}

/// A binding's value as typed: an existing folder or file, a drive, or an existing resource as
/// `SETUP/RESOURCE`.
fn check_binding(binding: &format::CheckedBinding, entry: &str) -> Result<String, String> {
    let text = entry.trim();
    if text.is_empty() {
        return if binding.required { Err("Give an answer.".into()) } else { Ok(String::new()) };
    }
    match binding.kind {
        resource::BindingKind::Folder => {
            // The same rule the planner applies, so a folder the CLI takes is never refused later.
            if let Some(why) = format::folder_choice_problem(text) {
                let mut said = why.chars();
                let first = said.next().map(|c| c.to_uppercase().to_string()).unwrap_or_default();
                return Err(format!("{first}{}.", said.as_str()));
            }
            if !Path::new(text).is_dir() {
                return Err(format!("There is no folder {}. Give the full path of a folder on this computer.", scan::shown(text)));
            }
        }
        resource::BindingKind::File => {
            if !Path::new(text).is_file() {
                return Err(format!("There is no file {}. Give the full path of a file on this computer.", scan::shown(text)));
            }
        }
        resource::BindingKind::Drive => {
            if text.len() > 64 || text.chars().any(char::is_control) {
                return Err("Give a drive as yougori launch shows it, such as D:\\ or /.".into());
            }
        }
        resource::BindingKind::Resource => {
            if text.split_once('/').is_none_or(|(setup, id)| setup.trim().is_empty() || id.trim().is_empty()) {
                return Err(format!("Give the existing {} as SETUP/RESOURCE, as yougori template status shows them.", binding.resource.map(resource::Kind::title).unwrap_or("resource")));
            }
        }
    }
    Ok(text.to_owned())
}

/// An existing resource of one of the person's setups, offered for a binding of type resource.
#[derive(Clone, Debug, PartialEq)]
struct Existing {
    /// `SETUP_ID/RESOURCE_ID`, the value a binding takes.
    value: String,
    label: String,
    setup: String,
    /// `None` for a resource the setup owns; the owning setup's id for a borrowed one.
    borrowed_from: Option<String>,
}

/// The existing resources of the given kind across the person's setups, from the engine's
/// setup_list and setup_get: owned ones and borrowed ones alike (a borrowed one is offered as
/// the setup that owns it). Empty when the engine cannot answer, so the person types the choice.
async fn existing_resources(kind: resource::Kind, profile: Option<capability::GridProfile>) -> Vec<Existing> {
    let Ok(list) = crate::public::call("setup_list", json!({})).await else { return Vec::new() };
    let setups = list["setups"].as_array().cloned().or_else(|| list.as_array().cloned()).unwrap_or_default();
    let mut found = Vec::new();
    for summary in &setups {
        let Some(setup_id) = summary["setupId"].as_str() else { continue };
        if let Some(wanted) = profile {
            if summary["profile"].as_str() != Some(wanted.id()) {
                continue;
            }
        }
        let name = summary["name"].as_str().unwrap_or(setup_id).to_owned();
        let Ok(detail) = crate::public::call("setup_get", json!({"setupId": setup_id})).await else { continue };
        let resources = detail["setup"]["resources"].as_array().cloned().or_else(|| detail["resources"].as_array().cloned()).unwrap_or_default();
        for entry in resources {
            if entry["kind"].as_str() != Some(kind.as_str()) {
                continue;
            }
            let Some(resource_id) = entry["resourceId"].as_str() else { continue };
            let borrowed_from = entry["borrowedFrom"].as_str().map(str::to_owned);
            let owner = borrowed_from.clone().unwrap_or_else(|| setup_id.to_owned());
            let value = format!("{owner}/{resource_id}");
            if found.iter().any(|e: &Existing| e.value == value) {
                continue;
            }
            found.push(Existing { value, label: views::clean(entry["label"].as_str().unwrap_or(resource_id)), setup: views::clean(&name), borrowed_from });
        }
    }
    found
}

/// Picks an existing resource for a binding from the person's setups, or lets them type it when
/// nothing fits.
fn pick_existing(binding: &format::CheckedBinding, candidates: &[Existing], previous: Option<&str>) -> Result<Option<String>, String> {
    let what = binding.resource.map(resource::Kind::title).unwrap_or("resource");
    let mut choices: Vec<ui::Choice> = candidates.iter().map(|e| {
        let hint = match &e.borrowed_from {
            Some(owner) => format!("{what} of {owner}, used by {}", e.setup),
            None => format!("{what} owned by {}", e.setup),
        };
        ui::Choice::new(format!("{} ({})", e.label, e.value), hint)
    }).collect();
    choices.push(ui::Choice::new("Type it", format!("SETUP/RESOURCE, as yougori template status shows the {what}")));
    if !binding.required {
        choices.push(ui::Choice::new("Leave it out", "nothing is attached"));
    }
    let initial = previous.and_then(|p| candidates.iter().position(|e| e.value == p)).unwrap_or(0);
    let index = ui::select(&binding.question, &if binding.hint.is_empty() { Vec::new() } else { vec![binding.hint.clone()] }, &choices, initial)?;
    if index < candidates.len() {
        return Ok(Some(candidates[index].value.clone()));
    }
    if index == candidates.len() {
        let check = |entry: &str| check_binding(binding, entry);
        let typed = ui::input(&binding.question, previous.unwrap_or_default(), false, &check)?;
        return Ok((!typed.is_empty()).then_some(typed));
    }
    Ok(None)
}

/// Collects the answers of an interactive run, one question at a time with Back: the optional
/// capabilities, then the questions in order, then the bindings.
async fn ask_all(checked: &format::Checked, collected: &mut Collected, domains: &[String], host: &Value) -> Result<(), String> {
    let mut existing: BTreeMap<String, Vec<Existing>> = BTreeMap::new();
    let prompts: Vec<v1::Question> = checked.questions.iter().map(prompt_question).collect();
    let optional: Vec<&format::CheckedCapability> = checked.capabilities.iter().filter(|c| c.selection != format::Selection::Required && !c.locked).collect();
    let mut steps = ui::Wizard::new();
    loop {
        let step = steps.step();
        let asked: Result<bool, String> = if step < optional.len() {
            let use_ = optional[step];
            if !use_.when.as_ref().is_none_or(|w| w.holds(&collected.inputs)) {
                collected.capabilities.remove(&use_.id);
                Ok(false)
            } else {
                let cap = capability::find(&use_.id);
                let name = cap.map(|c| c.name).unwrap_or(use_.id.as_str());
                let summary = cap.map(|c| c.summary.to_owned()).unwrap_or_default();
                let on_by_default = use_.selection == format::Selection::Default;
                let previous = collected.capabilities.get(&use_.id).copied().unwrap_or(on_by_default);
                let choices = [ui::Choice::new(format!("Add {name}"), summary.clone()), ui::Choice::new("Leave it out", "nothing of it is created")];
                match ui::select(&format!("Include {name}?"), &[], &choices, usize::from(!previous)) {
                    Ok(index) => {
                        collected.capabilities.insert(use_.id.clone(), index == 0);
                        Ok(true)
                    }
                    Err(error) => Err(error),
                }
            }
        } else if step - optional.len() < checked.questions.len() {
            let question = &checked.questions[step - optional.len()];
            if !question.asked(&collected.inputs) {
                collected.inputs.remove(&question.id);
                collected.secrets.remove(&question.id);
                Ok(false)
            } else if !question.editable {
                if let Some(default) = &question.default {
                    collected.inputs.insert(question.id.clone(), default.clone());
                }
                Ok(false)
            } else if run::absorbed(&prompts[step - optional.len()], &prompts) {
                Ok(false)
            } else {
                let prompt = &prompts[step - optional.len()];
                run::ask_question(prompt, &prompts, &mut collected.inputs, domains).await.map(|answer| {
                    match answer {
                        Some(value) if question.kind == QuestionKind::Secret => {
                            collected.secrets.insert(question.id.clone(), Zeroizing::new(value));
                            collected.inputs.remove(&question.id);
                        }
                        Some(value) => {
                            collected.inputs.insert(question.id.clone(), value);
                        }
                        None => {
                            collected.inputs.remove(&question.id);
                            collected.secrets.remove(&question.id);
                        }
                    }
                    true
                })
            }
        } else if step - optional.len() - checked.questions.len() < checked.bindings.len() {
            let binding = &checked.bindings[step - optional.len() - checked.questions.len()];
            if !binding.when.as_ref().is_none_or(|w| w.holds(&collected.inputs)) {
                collected.bindings.remove(&binding.id);
                Ok(false)
            } else if binding.kind == resource::BindingKind::Resource {
                let key = format!("{}:{}", binding.resource.map(|k| k.as_str()).unwrap_or(""), binding.profile.map(|p| p.id()).unwrap_or(""));
                if !existing.contains_key(&key) {
                    let found = run::wait(true, "Reading your setups", async { Ok(existing_resources(binding.resource.unwrap_or(resource::Kind::Environment), binding.profile).await) }).await.unwrap_or_default();
                    existing.insert(key.clone(), found);
                }
                let candidates = existing.get(&key).cloned().unwrap_or_default();
                let previous = collected.bindings.get(&binding.id).cloned();
                let picked = if candidates.is_empty() {
                    let note: Vec<String> = if binding.hint.is_empty() { Vec::new() } else { vec![binding.hint.clone()] };
                    let label = if binding.required { binding.question.clone() } else { format!("{} (optional)", binding.question) };
                    let check = |entry: &str| check_binding(binding, entry);
                    ui::input_noted(&label, &note, previous.as_deref().unwrap_or_default(), &check).map(|value| (!value.is_empty()).then_some(value))
                } else {
                    pick_existing(binding, &candidates, previous.as_deref())
                };
                picked.map(|value| {
                    match value {
                        Some(value) => {
                            collected.bindings.insert(binding.id.clone(), value);
                        }
                        None => {
                            collected.bindings.remove(&binding.id);
                        }
                    }
                    true
                })
            } else if binding.kind == resource::BindingKind::Drive {
                crate::storage::choose_drive(host, None, 1, true, collected.bindings.get(&binding.id).map(String::as_str), &binding.question, &binding.hint).map(|selection| {
                    match selection.drive {
                        Some(drive) => {
                            collected.bindings.insert(binding.id.clone(), drive);
                        }
                        None => {
                            collected.bindings.remove(&binding.id);
                        }
                    }
                    true
                })
            } else {
                let mut note: Vec<String> = if binding.hint.is_empty() { Vec::new() } else { vec![binding.hint.clone()] };
                // What the setup may do with the folder, before it is typed, not only in the review.
                if let Some(said) = folder_access(binding) {
                    note.push(said);
                }
                let label = if binding.required { binding.question.clone() } else { format!("{} (optional)", binding.question) };
                let check = |entry: &str| check_binding(binding, entry);
                let previous = collected.bindings.get(&binding.id).cloned().unwrap_or_default();
                ui::input_noted(&label, &note, &previous, &check).map(|value| {
                    if value.is_empty() {
                        collected.bindings.remove(&binding.id);
                    } else {
                        collected.bindings.insert(binding.id.clone(), value);
                    }
                    true
                })
            }
        } else {
            break;
        };
        match steps.next(asked) {
            Ok(()) => {}
            Err(error) if error == ui::BACK || error == ui::CANCELLED => return Err(stop_created(error)),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Collects a script's answers: `--input`, `--inputs FILE` (any input, binding or
/// `capabilities.ID`) and `secrets`, what `--secrets -` read on stdin: a JSON object of the
/// template's secret questions, by id, to their values. Unknown ids are refused here; the
/// planner checks the values.
async fn given_from(checked: &format::Checked, options: &Options, secrets: Option<&[u8]>) -> Result<Collected, String> {
    let mut collected = Collected::default();
    let is_secret = |id: &str| checked.questions.iter().any(|q| q.id == id && q.kind == QuestionKind::Secret);
    let known = |id: &str| checked.questions.iter().any(|q| q.id == id) || checked.bindings.iter().any(|b| b.id == id) || id.strip_prefix("capabilities.").is_some_and(|c| checked.capabilities.iter().any(|use_| use_.id == c));
    let ids = || checked.questions.iter().filter(|q| q.kind != QuestionKind::Secret).map(|q| q.id.as_str()).chain(checked.bindings.iter().map(|b| b.id.as_str())).collect::<Vec<_>>().join(", ");
    let mut pairs: Vec<(String, Value)> = Vec::new();
    if let Some(path) = &options.inputs_file {
        let bytes = run::read_file_limited(path, "the --inputs file").await?;
        let value: Value = serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes)).map_err(|e| format!("The --inputs file is not a JSON object ({e})."))?;
        let object = value.as_object().ok_or("The --inputs file must be a JSON object such as {\"access\": \"quick\"}.")?;
        pairs.extend(object.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    pairs.extend(options.inputs.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))));
    for (id, value) in &options.bindings {
        let Some(binding) = checked.bindings.iter().find(|b| &b.id == id) else {
            return Err(format!("This template has no binding {}. Its bindings: {}.", scan::shown(id), if checked.bindings.is_empty() { "none".to_owned() } else { checked.bindings.iter().map(|b| b.id.as_str()).collect::<Vec<_>>().join(", ") }));
        };
        let checked_value = check_binding(binding, value).map_err(|error| format!("--binding {id}: {error}"))?;
        if !checked_value.is_empty() {
            collected.bindings.insert(id.clone(), checked_value);
        }
    }
    for (id, value) in pairs {
        if is_secret(&id) {
            return Err(format!("{id} is a secret: never put it in --input or an --inputs file. Pass it with --secrets - and {{\"{id}\": \"…\"}} on stdin."));
        }
        if !known(&id) {
            return Err(format!("This template has no input {}. Its inputs: {}.", scan::shown(&id), ids()));
        }
        let text = match &value {
            Value::String(text) => text.clone(),
            Value::Array(items) => items.iter().map(|v| v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string())).collect::<Vec<_>>().join(","),
            Value::Number(number) => number.to_string(),
            Value::Bool(yes) => if *yes { "yes" } else { "no" }.to_owned(),
            Value::Null => continue,
            _ => return Err(format!("The value for {id} must be text, a number, true/false or a list.")),
        };
        if let Some(capability) = id.strip_prefix("capabilities.") {
            let on = matches!(text.to_ascii_lowercase().as_str(), "yes" | "true" | "on" | "1");
            collected.capabilities.insert(capability.to_owned(), on);
        } else if checked.bindings.iter().any(|b| b.id == id) {
            collected.bindings.insert(id, text);
        } else {
            collected.inputs.insert(id, text);
        }
    }
    if let Some(bytes) = secrets {
        let object: BTreeMap<String, Value> = serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)).map_err(|_| "--secrets - reads a JSON object on stdin, such as {\"openai_key\": \"…\"}.")?;
        for (id, value) in object {
            if !is_secret(&id) {
                return Err(if known(&id) { format!("{id} is not a secret: pass it with --input {id}=VALUE.") } else { format!("This template asks for no secret {}.", scan::shown(&id)) });
            }
            let Value::String(text) = value else { return Err(format!("The secret {id} must be text.")) };
            if !text.is_empty() {
                collected.secrets.insert(id, Zeroizing::new(text));
            }
        }
    }
    Ok(collected)
}

/// The plan request's answers: every public answer as text, capability choices as
/// `capabilities.ID`, and the bindings chosen on this computer by their ids.
fn answer_list(collected: &Collected) -> Vec<Value> {
    let mut answers: Vec<Value> = collected.inputs.iter().map(|(field, value)| json!({"field": field, "value": value})).collect();
    answers.extend(collected.capabilities.iter().map(|(id, on)| json!({"field": format!("capabilities.{id}"), "value": on})));
    answers.extend(collected.bindings.iter().map(|(field, value)| json!({"field": field, "value": value})));
    answers
}

/// The plan request's secret bindings: a reference `apply:FIELD` for each secret the person gave,
/// and never its value. The values travel with `setup_apply` only.
fn secret_refs(collected: &Collected) -> Vec<Value> {
    collected.secrets.keys().map(|field| json!({"field": field, "secretRef": format!("apply:{field}")})).collect()
}

/// The name a new setup takes when none was asked for: the template's own, or, when that name is
/// already taken on this computer, the first free of NAME-2, NAME-3 and so on, so a second copy of
/// the same template never answers to the first one's name. Taken means the name (or id) of one of
/// the engine's setups, or the name of a format 1 instance (`instances`: records and folders, as
/// [`super::instances::Instances::names`] lists them), compared without case: the lifecycle
/// commands look a name up among the engine's setups first, so a setup that took a format 1
/// instance's name would hide that instance from every one of them, `template rm` included. The
/// engine keeps every copy apart by its own id and stores each one's sandboxes and data under that
/// id; this only keeps the names people type apart. When the engine cannot answer, only the
/// format 1 names are known.
async fn free_name(base: &str, instances: &std::collections::BTreeSet<String>) -> String {
    let mut taken = setups::setup_names().await;
    taken.extend(instances.iter().map(|name| name.to_ascii_lowercase()));
    if !taken.contains(&base.to_ascii_lowercase()) {
        return base.to_owned();
    }
    super::instances::available(base, &[], &taken, &std::collections::BTreeSet::new())
}

/// Why a new setup can't take the name asked for with `--name`: a format 1 instance already has
/// it (`instances`, as [`free_name`] reads them), and a setup of the same name would hide it from
/// every lifecycle command, which look among the engine's setups first. `None` when it is free of
/// format 1 instances; whether another setup holds it is the engine's to say when it plans.
fn instance_name_taken(name: &str, instances: &std::collections::BTreeSet<String>) -> Option<String> {
    instances.contains(&name.to_ascii_lowercase()).then(|| {
        format!(
            "{name} is already the name of a template instance on this computer (see yougori template list). A setup of the same name would hide it from yougori template status, update and rm. Choose another name with --name. Nothing was created."
        )
    })
}

/// A run stopped by the engine's refusal: its sentence, and that nothing was created.
fn engine_refusal(error: String) -> String {
    if crate::wire::cancellation(&error).is_some() || error == ui::CANCELLED {
        return crate::wire::cancelled("Cancelled. Nothing was created.");
    }
    if error.ends_with("Nothing was created.") { error } else { format!("{error} Nothing was created.") }
}

/// Follows an operation the engine started until it ends, with a spinner. A completed operation
/// returns its progress; a failed one its error; an operation waiting for an answer or with an
/// unknown outcome stops with the next step rather than pretending the work is done. On the wire a
/// cancelled operation is a failed one whose error code is `operation_cancelled` (the engine has
/// no cancelled state), and `cancelling` is still moving, so it is waited on like `applying`.
async fn follow_operation(setup_id: &str, started: &Value, label: &str, interactive: bool) -> Result<Value, String> {
    let operation_id = started["operationId"].as_str().or_else(|| started["operation"]["operationId"].as_str()).map(str::to_owned);
    let poll = async {
        let mut cursor = 0u64;
        let mut events: Vec<Value> = Vec::new();
        loop {
            let mut request = json!({"setupId": setup_id, "cursor": cursor});
            if let Some(id) = &operation_id {
                request["operationId"] = json!(id);
            }
            let mut progress = crate::public::call("setup_operation", request).await.map_err(|error| setups::engine_lost(setup_id, error))?;
            cursor = progress["nextCursor"].as_u64().unwrap_or(cursor);
            events.extend(progress["events"].as_array().cloned().unwrap_or_default());
            match progress["state"].as_str().unwrap_or("") {
                "completed" => {
                    progress["events"] = json!(events);
                    return Ok(progress);
                }
                "failed" if progress["error"]["code"] == "operation_cancelled" => {
                    return Err(crate::wire::cancelled(&format!("Stopped. What was created is kept; carry on where it stopped with yougori template continue {setup_id}, or remove it with yougori template rm {setup_id} --yes.")));
                }
                "failed" => {
                    let message = progress["error"]["message"].as_str().unwrap_or("The setup did not finish.").to_owned();
                    let last = events.iter().rev().find_map(|e| e["message"].as_str()).map(|m| format!(" Last step: {}.", views::clean(m))).unwrap_or_default();
                    return Err(format!("{message}{last} What was created is kept; see yougori template logs {setup_id}, then yougori template continue {setup_id} to try again (only what did not finish runs again) or yougori template rm {setup_id} --yes to remove it."));
                }
                "awaiting_input" | "unknown" => return Err(setups::settled_words(setup_id, &progress)),
                _ => tokio::time::sleep(std::time::Duration::from_millis(600)).await,
            }
        }
    };
    run::wait(interactive, label, poll).await
}

/// The Hub page check the engine made for this plan: one rule for every door
/// (`hub::review::page_check`, at the planning boundary the desktop shares), read back from the
/// plan rather than made again here. A folder has no page to compare with. An engine older than
/// this one made no check, which is said as such: "nothing to compare" must never read as
/// "compared, and the same".
fn page_of(planned: &Value, fetched: &Fetched) -> Result<Vec<String>, String> {
    match &fetched.origin {
        Wanted::Folder(_) => Err(super::review::NO_HUB_PAGE.into()),
        Wanted::Hub(_) => super::review::page_from_json(&planned["page"]).unwrap_or_else(|| {
            Err("The engine running on this computer did not check the files against the Hub's page. Update Yougori to have them checked before you agree.".into())
        }),
    }
}

/// `yougori run` / `template run` of a format 2 package: the engine plans it with the answers,
/// the person reviews and confirms, the engine applies it with the secrets, and the run follows
/// the operation to its end. v1 packages never come here. `instances` are the names the format 1
/// instances on this computer hold (`Instances::names`), which a new setup never takes.
pub async fn run_v2(fetched: Fetched, options: &Options, interactive: bool, instances: &std::collections::BTreeSet<String>) -> Result<Value, String> {
    // A script's secrets come from stdin and nowhere else; read before anything is asked of the
    // engine, so a run that cannot read them creates nothing.
    let secrets = if !interactive && options.secrets_stdin && !options.dry_run { Some(run::read_stdin("the secrets on stdin").await.map_err(stop_created)?) } else { None };
    run_v2_given(fetched, options, interactive, secrets.as_deref().map(Vec::as_slice), instances).await
}

/// [`run_v2`] with a script's secrets already read (`secrets` is what `--secrets -` found on
/// stdin, when it was asked for). Interactive runs ask for theirs.
async fn run_v2_given(fetched: Fetched, options: &Options, interactive: bool, secrets: Option<&[u8]>, instances: &std::collections::BTreeSet<String>) -> Result<Value, String> {
    let checked = check_files(&fetched.files).map_err(|problems| format!("{}\nNothing was created.", problems_text("This template", &problems)))?;
    let label = match &fetched.origin {
        Wanted::Hub(reference) => format!("{} {}", reference.item(), fetched.version),
        Wanted::Folder(path) => format!("{} {} (from {})", checked.template.name(), checked.template.version(), path.display()),
    };
    let source = match &fetched.origin {
        Wanted::Hub(reference) => json!({"kind": "hub", "publisher": reference.publisher, "name": reference.name, "version": fetched.version}),
        Wanted::Folder(path) => json!({"kind": "local_folder", "path": path.to_string_lossy()}),
    };
    // This computer and the engine, before any question.
    let state = run::wait(interactive, "Checking this computer", async {
        crate::client::start(None).await?;
        crate::public::call("get_platform_state", json!({})).await
    }).await.map_err(stop_created)?;
    let domains = if checked.questions.iter().any(|q| q.kind == QuestionKind::Domain) { run::saved_domains().await } else { Vec::new() };
    // The name asked for, or a free one: a second copy of a template someone already runs here
    // is NAME-2, never a second NAME, and a format 1 instance's name is never taken.
    let name = match &options.name {
        Some(name) => match instance_name_taken(name, instances) {
            Some(refused) => return Err(refused),
            None => name.clone(),
        },
        None => free_name(checked.template.name(), instances).await,
    };
    let unverified = matches!(&fetched.origin, Wanted::Hub(_)) && !fetched.verified;
    let mut collected = if interactive {
        let mut lines: Vec<String> = Vec::new();
        if unverified {
            lines.extend(views::unverified().into_iter().map(|l| ui::paint(&l, ui::AMBER)));
            lines.push(String::new());
        }
        lines.push(ui::bold(&format!("{} · {label}", views::clean(checked.template.title()))));
        if let Some(subtitle) = &checked.template.subtitle {
            lines.push(views::clean(subtitle));
        }
        lines.push(views::clean(checked.template.summary.as_deref().unwrap_or_default()));
        for notice in &fetched.notices {
            lines.push(ui::paint(&format!("▲ {}", views::clean(notice)), ui::AMBER));
        }
        ui::lines(lines.into_iter().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
        let mut collected = Collected::default();
        ask_all(&checked, &mut collected, &domains, &state["host"]).await?;
        collected
    } else {
        if !options.yes && !options.dry_run {
            return Err(format!("Running a template needs --yes once you have read its plan: yougori template run {} --dry-run shows it. Nothing was created.", source_text(&fetched)));
        }
        given_from(&checked, options, secrets).await?
    };
    // The plan, from the engine, with secrets as references only.
    // A dry run plans only, and a plan carries secrets as references, never values: every secret
    // question gets its reference, so a dry run doesn't need the values a real run asks for.
    let mut bindings = secret_refs(&collected);
    if options.dry_run {
        for question in checked.questions.iter().filter(|question| question.kind == QuestionKind::Secret && !collected.secrets.contains_key(&question.id)) {
            bindings.push(json!({"field": question.id, "secretRef": format!("apply:{}", question.id)}));
        }
    }
    // The drive its sandboxes go on: the one asked for, or, for a template that has the person
    // choose (Storage drive), the one chosen here. The engine checks it against this computer.
    let mut drive = options.storage_drive.clone();
    let chooses_drive = checked.template.capabilities.iter().any(|capability| capability.id == "data.storage_drive");
    if drive.is_none() && interactive && chooses_drive && !options.dry_run {
        let note = "Its sandboxes and their volumes go on this drive, and stay there.";
        drive = crate::storage::choose_drive(&state["host"], None, 10, true, None, &format!("Where should {name} keep its data?"), note).map_err(stop_created)?.drive;
    }
    let mut request = json!({"source": source, "name": name, "answers": answer_list(&collected), "bindings": bindings});
    if let Some(drive) = &drive {
        request["storageDrive"] = json!(drive);
    }
    let planned = run::wait(interactive, "Working out the plan", crate::public::call("setup_plan", request)).await.map_err(engine_refusal)?;
    // The Hub's page against the files, as the engine compared them at the planning boundary the
    // desktop shares, so a page that promises less than the files grant is on screen with the
    // review rather than discovered after the setup exists.
    let page = page_of(&planned, &fetched);
    let review = &planned["review"];
    let pc = review["pcAccess"].as_array().is_some_and(|folders| !folders.is_empty());
    if options.dry_run {
        if interactive {
            let said = super::review::page_lines(&page);
            if !said.is_empty() {
                ui::lines(said.into_iter().map(|line| format!("{}  {}", ui::muted("│"), ui::paint(&line, ui::AMBER))).collect());
            }
            ui::lines(setups::plan_review_lines(&planned).into_iter().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
            ui::outro(&format!("Dry run: nothing was created. Run it with yougori template run {} --name {name}", source_text(&fetched)));
        }
        return Ok(json!({"dryRun": true, "format": 2, "template": {"ref": label, "version": fetched.version, "verified": fetched.verified, "digest": fetched.digest}, "instance": name, "plan": planned, "review": review, "page": super::review::page_json(&page)}));
    }
    if interactive {
        let said = super::review::page_lines(&page);
        if !said.is_empty() {
            ui::lines(said.into_iter().map(|line| format!("{}  {}", ui::muted("│"), ui::paint(&line, ui::AMBER))).collect());
        }
        ui::lines(setups::plan_review_lines(&planned).into_iter().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
        let choices = [ui::Choice::new("Run it", "create what the plan lists"), ui::Choice::new("Cancel", "nothing is created")];
        if ui::select(&format!("Run {label}?"), &[], &choices, 0).map_err(stop_created)? != 0 {
            return Err(crate::wire::cancelled("Cancelled. Nothing was created."));
        }
        if pc {
            let choices = [ui::Choice::new("Allow access to these folders", "only the folders listed"), ui::Choice::new("Cancel", "nothing is created")];
            if ui::select("This template uses folders on this computer", &["See PC access in the plan above: its sandboxes can read (or change) those folders.".to_owned()], &choices, 1).map_err(stop_created)? != 0 {
                return Err(crate::wire::cancelled("Cancelled. Nothing was created."));
            }
        }
    } else if pc && !options.allow_pc_access {
        return Err("This template uses folders on this computer (see pcAccess in its plan). Pass --allow-pc-access as well as --yes if that is intended. Nothing was created.".into());
    }
    // What this plan needs the person to agree to beyond the review itself: letting a sandbox
    // change files in a folder they chose, or copying a sign-in from this computer. Each is
    // asked on its own, in its own words, and only what was agreed to travels with the apply.
    let agreed = agree_to(&planned, options, interactive)?;
    // Apply exactly the plan that was shown; the secret values travel here and nowhere else.
    let setup_id = planned["setupId"].as_str().ok_or("The engine returned no setup id for the plan. Nothing was created.")?.to_owned();
    let operation = operation_id()?;
    let secrets: BTreeMap<&str, &str> = collected.secrets.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let apply = json!({"setupId": setup_id, "planDigest": planned["digest"], "operationId": operation, "expectedRevision": planned["baseRevision"], "secrets": secrets, "consents": agreed});
    let started = crate::public::call("setup_apply", apply).await.map_err(engine_refusal)?;
    collected.secrets.clear();
    let finished = follow_operation(&setup_id, &started, &format!("Setting up {name}"), interactive).await?;
    let detail = crate::public::call("setup_get", json!({"setupId": setup_id})).await.unwrap_or(Value::Null);
    let steps: Vec<String> = finished["events"].as_array().into_iter().flatten().filter_map(|e| e["message"].as_str()).map(views::clean).collect();
    // What the engine resolved; when it lists none, only the plan's outputs that already have a
    // value. One still waiting on a part (`{{outputs.web.url}}` of a publication that opens no
    // address) is not a value, and was printed as one.
    let outputs: Vec<Value> = if detail["outputs"].is_array() {
        detail["outputs"].as_array().cloned().unwrap_or_default()
    } else {
        planned["plan"]["outputs"].as_array().into_iter().flatten().filter(|output| output["value"].as_str().is_some_and(|value| !value.contains("{{"))).cloned().collect()
    };
    let value = json!({
        "instance": name,
        "setupId": setup_id,
        "format": 2,
        "status": detail["state"].as_str().unwrap_or("ready"),
        "template": {"source": if matches!(fetched.origin, Wanted::Hub(_)) { "hub" } else { "folder" }, "ref": label, "version": fetched.version, "verified": fetched.verified, "digest": fetched.digest, "name": checked.template.name(), "title": checked.template.title()},
        "operation": finished["operation"],
        // Kept on the finished run too, not only on the dry run: a script that reads the result
        // of a real run can still see that the Hub's page and the files disagreed.
        "page": super::review::page_json(&page),
        "steps": steps,
        "outputs": outputs,
        "next": planned["plan"]["steps"],
        "statusCommand": format!("yougori template status {name}"),
        "logs": format!("yougori template logs {name}"),
        "stop": format!("yougori template stop {name}"),
        "remove": format!("yougori template rm {name} --yes"),
    });
    if interactive {
        let mut lines = Vec::new();
        for output in &outputs {
            let label = output["label"].as_str().unwrap_or_default();
            let shown = output["value"].as_str().unwrap_or_default();
            if output["private"] == true {
                lines.push(format!("{}: {} (shown once; keep it safe)", views::clean(label), views::clean(shown)));
            } else if !shown.is_empty() {
                lines.push(format!("{}: {}", views::clean(label), views::clean(shown)));
            }
        }
        for step in planned["plan"]["steps"].as_array().into_iter().flatten() {
            let title = step["title"].as_str().unwrap_or_default();
            let command = step["command"].as_str().map(|c| format!("  $ {c}")).unwrap_or_default();
            lines.push(format!("Next: {}{command}", views::clean(title)));
        }
        lines.push(format!("Status: yougori template status {name} · Logs: yougori template logs {name}"));
        ui::lines(lines.into_iter().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
        ui::outro(&format!("{name} is ready."));
    }
    Ok(value)
}

/// How the template is named in a command that runs it again.
fn source_text(fetched: &Fetched) -> String {
    match &fetched.origin {
        Wanted::Hub(reference) => format!("hub/{}@{}", reference.item(), fetched.version),
        Wanted::Folder(path) => shell_words::quote(&path.to_string_lossy()).into_owned(),
    }
}

/// `template check` of a format 2 package, as text: the published review's v1 parts, then the
/// resources, capabilities and the rest only format 2 has.
pub fn check_view(value: &Value) -> String {
    let review = &value["review"];
    let mut lines = vec![format!("{} {} passed every check · format 2 · {} files · {} bytes", views::clean(value["name"].as_str().unwrap_or_default()), views::clean(value["version"].as_str().unwrap_or_default()), value["files"], value["bytes"]), String::new()];
    lines.extend(views::review(review));
    lines.extend(format_2_lines(review));
    if let Some(components) = value["components"].as_object() {
        let pins: Vec<String> = components.iter().map(|(name, pin)| format!("{name} = {}@{} ({})", views::clean(pin["item"].as_str().unwrap_or_default()), views::clean(pin["version"].as_str().unwrap_or_default()), views::clean(&pin["digest"].as_str().unwrap_or_default().chars().take(12).collect::<String>()))).collect();
        lines.push(format!("{:<11}{}", "Components", pins.join(", ")));
    }
    if let Some(next) = value["next"].as_str() {
        lines.push(String::new());
        lines.push(format!("Next: {}", views::clean(next)));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The parts of a format 2 review only format 2 has, as text, after the format 1 parts
/// [`views::review`] shows: its resources, capabilities, data retention and aliases. `template
/// check` and `template info` both show them.
pub fn format_2_lines(review: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let resources: Vec<String> = review["resources"].as_array().into_iter().flatten().map(|r| {
        let mut said = format!("{} ({})", views::clean(r["id"].as_str().unwrap_or_default()), views::clean(r["kind"].as_str().unwrap_or_default()));
        if let Some(capability) = r["summary"]["capability"].as_str() {
            said.push_str(&format!(" · with {}", views::clean(capability)));
        }
        let when: Vec<&str> = r["when"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !when.is_empty() {
            said.push_str(" · only when selected during setup");
        }
        said
    }).collect();
    if !resources.is_empty() {
        lines.push(format!("{:<11}{}", "Resources", resources.join(", ")));
    }
    let capabilities: Vec<String> = review["capabilities"].as_array().into_iter().flatten().map(|c| {
        let selection = c["selection"].as_str().unwrap_or("required");
        let locked = if c["locked"] == true { ", locked" } else { "" };
        format!("{} ({selection}{locked})", views::clean(c["id"].as_str().unwrap_or_default()))
    }).collect();
    if !capabilities.is_empty() {
        lines.push(format!("{:<11}{}", "Capabilit.", capabilities.join(", ")));
    }
    if let Some(retention) = review["retention"].as_object() {
        lines.push(format!("{:<11}on stop {}, on removal {} (data is never deleted by default)", "Data", retention.get("onStop").and_then(Value::as_str).unwrap_or("keep"), retention.get("onRemove").and_then(Value::as_str).unwrap_or("keep")));
    }
    let aliases: Vec<&str> = review["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if !aliases.is_empty() {
        lines.push(format!("{:<11}{}", "Aliases", views::clean(&aliases.join(", "))));
    }
    lines
}

/// A package folder for `template check`, in either format: what an upload would carry, as
/// `yougori template check` reports it. A format 2 package with imports has every pinned
/// component resolved from the Hub and checked, and the report lists the pins as resolved.
pub async fn check_report(folder: &str) -> Result<Value, String> {
    let (upload, format) = super::publish::template(Path::new(folder)).await?;
    let bytes: usize = upload.files.values().map(Vec::len).sum();
    let next = format!("yougori template run {}", shell_words::quote(folder));
    let mut value = json!({"ok": true, "format": format.number(), "name": upload.name, "version": upload.version, "files": upload.files.len(), "bytes": bytes, "review": upload.review, "next": next});
    if format == FormatVersion::V2 {
        let checked = check_files(&upload.files).map_err(|problems| problems_text("This template", &problems))?;
        if !checked.template.imports.is_empty() {
            let site = Site::configured()?;
            let cache = Cache::standard()?;
            let package = components::package(&site, &cache, &upload.files, None, Some(scan::digest_of(&upload.files))).await.map_err(|problems| problems_text("This template's imports", &problems))?;
            value["components"] = components::pins(&package);
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(entries: &[(&str, &str)]) -> Files {
        entries.iter().map(|(path, text)| (path.to_string(), text.as_bytes().to_vec())).collect()
    }

    const TEMPLATE: &str = "format_version: 2\nkind: template\nname: shop\nsummary: A shop.\nversion: 1.0.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\ninputs:\n  - {id: title, question: Title?, type: text, group: website_api, default: Hi}\n  - {id: key, question: Key?, type: secret, group: ai_models, required: false}\npublic:\n  - {environment: web, port: 8080}\n";
    const PROJECT: &str = "format_version: 2\nproject: shop\nenvironments:\n  web:\n    image: nginx:1.27\n    ports: [8080]\n    environment: {TITLE: \"{{inputs.title}}\"}\n";

    #[test]
    fn a_format_2_folder_is_planned_on_this_computer_without_the_engine() {
        let package = files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)]);
        assert!(is_v2(&package));
        assert_eq!(format_of(&files(&[(v1::TEMPLATE_FILE, "name: x\n")])), Ok(FormatVersion::V1));
        assert!(format_of(&files(&[(v1::TEMPLATE_FILE, "format_version: 9\n")])).unwrap_err().starts_with("This template needs a newer Yougori"));
        let answers = plan::Answers { instance: "shop".into(), inputs: [("title".to_owned(), "Hello".to_owned())].into(), ..plan::Answers::default() };
        // The dev tree is still 1.1.2; a format 2 package needs the release that ships format 2.
        let host = plan::Host { yougori: "1.2.0".into(), ..host_here() };
        let plan = plan_files(&package, None, Some("d".repeat(64)), &answers, &host).unwrap_or_else(|p| panic!("{}", problems_text("the package", &p)));
        assert_eq!(plan.order, ["web", "public_web"]);
        assert_eq!(plan.resources[0].spec["environment"]["TITLE"], "Hello");
        assert_eq!(plan.template.digest.as_deref(), Some("d".repeat(64).as_str()));
        let said = problems_text("This template", &[Diagnostic::error("x", "Add a title.").at("title")]);
        assert_eq!(said, "This template has one thing to fix:\n  - Add a title. (title)");
        let host = host_here();
        assert_eq!(host.yougori, env!("CARGO_PKG_VERSION"), "without YOUGORI_DEV_HOST_VERSION, this build's own version");
        // A development build may stand in for a newer Yougori, only for a real version; a
        // release build never does, whatever is asked.
        if cfg!(debug_assertions) {
            assert_eq!(stand_in(Some("1.2.0")).as_deref(), Some("1.2.0"));
            assert_eq!(stand_in(Some(" 1.2.0\n")).as_deref(), Some("1.2.0"));
        } else {
            assert_eq!(stand_in(Some("1.2.0")), None);
        }
        for ignored in [None, Some(""), Some("soon"), Some("1.2"), Some("1.2.0-")] {
            assert_eq!(stand_in(ignored), None, "{ignored:?}");
        }
        assert!(host.gpu.is_none());
        let mut corrected = host_here();
        host_with_engine(&mut corrected, &json!({"host": {"totalMemoryGb": 32.0, "totalStorageGb": 500.0, "usedStorageGb": 100.0}}), Some(false));
        assert_eq!((corrected.memory_gb, corrected.free_disk_gb, corrected.gpu), (Some(32.0), Some(400.0), Some(false)));
        assert_eq!(corrected.capabilities.gpu, capability::Gpu::None);
    }

    #[test]
    fn the_v1_adapter_keeps_every_question_tool_and_public_entry() {
        let template = "name: hello\nsummary: Hello.\nversion: 1.0.0\nlicense: MIT\ninputs:\n  - {id: access, question: Where?, type: choice, choices: [{value: quick, label: Quick}, {value: domain, label: Domain}, {value: none, label: None}], default: quick}\n  - {id: domain, question: Which?, type: domain, when: {access: domain}}\ntools:\n  web: [codex, hub/acme/aider@1.0.0]\ntool_options:\n  web/codex: {when: {access: quick}, signin: true}\npublic:\n  - {environment: web, port: 8080, access: \"{{inputs.access}}\", domain: \"{{inputs.domain}}\"}\nsteps:\n  - {title: Open, command: \"yougori terminal {{env.web}}\", when: {access: quick}}\noutputs:\n  - {label: Site, value: \"{{public.web}}\"}\n";
        let project = "project: hello\nenvironments:\n  web:\n    image: nginx:1.27\n    ports: [8080]\n    environment: {TITLE: \"{{inputs.access}}\"}\n  db:\n    image: postgres:17\nconnections: [web -> db]\n";
        let folder = v1::template(&files(&[(v1::TEMPLATE_FILE, template), ("yougori.yaml", project)])).unwrap_or_else(|p| panic!("{}", p.join("\n")));
        let legacy = legacy_of(&folder);
        assert_eq!(legacy.questions.len(), 2);
        assert_eq!(legacy.questions[1].when, Condition::terms(vec![("access".into(), vec!["domain".into()], false)]));
        assert_eq!(legacy.questions[0].kind, QuestionKind::Choice);
        assert_eq!(legacy.tools.len(), 2);
        assert!(matches!(&legacy.tools[1].source, format::Source::Hub { item, version: Some(v) } if item == "acme/aider" && v == "1.0.0"));
        assert!(legacy.tools[0].signin && legacy.tools[0].when.is_some());
        assert_eq!(legacy.public[0].access, format::Access::Asked("access".into()));
        assert_eq!(legacy.connections, vec![format::LegacyConnection { from: "web".into(), to: "db".into(), ports: vec![], permissions: vec![] }]);
        assert!(legacy.steps[0].when.is_some());
        assert_eq!(legacy.environments["web"]["environment"]["TITLE"].as_str(), Some("{{inputs.access}}"), "placeholders stay as written");
        let answers = plan::Answers { instance: "hello".into(), inputs: [("access".to_owned(), "quick".to_owned())].into(), ..plan::Answers::default() };
        let plan = legacy::compile_v1(&legacy, &answers, &host_here()).unwrap_or_else(|p| panic!("{}", problems_text("hello", &p)));
        assert_eq!(plan.order, ["db", "web", "connection_web_db", "public_web"]);
        assert_eq!(plan.review.questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(), ["access"], "no new question, and the domain is not asked for a quick link");
        assert_eq!(plan.resources[1].spec["tools"][0]["name"], "codex");
        assert_eq!(plan.resources[1].spec["tools"][0]["signin"], true);
    }

    #[test]
    fn publishing_rules_catch_fixed_host_ports_and_unpinned_tools() {
        let template = TEMPLATE.replace("public:\n", "tools:\n  web: [hub/acme/aider]\npublic:\n");
        let project = PROJECT.replace("ports: [8080]", "ports: [\"9090:8080\"]");
        let checked = check_files(&files(&[(v1::TEMPLATE_FILE, &template), ("yougori.yaml", &project)])).unwrap_or_else(|p| panic!("{}", problems_text("the package", &p)));
        let said = publishing_problems(&checked);
        assert!(said.iter().any(|s| s.contains("fixes host port 9090 for 8080")), "{said:?}");
        assert!(said.iter().any(|s| s.contains("pin hub/acme/aider to a version")), "{said:?}");
        assert!(publishing_problems(&check_files(&files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)])).unwrap()).is_empty());
    }

    /// A `Fetched` as if it had come from the Hub, with `page` as the review that version was
    /// published with.
    #[cfg(test)]
    fn from_the_hub(page: Value) -> Fetched {
        Fetched {
            files: files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)]),
            origin: Wanted::Hub(crate::hub::refs::Ref { publisher: "acme".into(), name: "shop".into(), version: Some("1.0.0".into()) }),
            version: "1.0.0".into(),
            digest: "d".repeat(64),
            verified: true,
            detail: Some(json!({"version": {"version": "1.0.0", "review": page}})),
            notices: Vec::new(),
        }
    }

    /// The review this package's own files produce — what the Hub page is compared against.
    #[cfg(test)]
    fn review_of_the_files() -> Value {
        crate::hub::review::template_v2(&package_of_the_files(), &[]).unwrap()
    }

    #[cfg(test)]
    fn package_of_the_files() -> yougori_setup::plan::Package {
        let checked = check_files(&files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)])).unwrap();
        yougori_setup::plan::Package { checked, components: BTreeMap::new(), item: None, digest: Some("d".repeat(64)) }
    }

    #[test]
    fn the_page_check_is_one_rule_with_one_shape_for_every_door() {
        // PROVES the files are checked against the page the person read, by the one rule the
        // engine applies at the planning boundary the desktop and the CLI share
        // (`review::page_check`), and that its answer has one shape wherever it is read: compared
        // and the same, compared and different (naming what), or not compared with the reason —
        // which must never read as a clean check, because "no differences" and "never compared"
        // look the same to anyone reading a result, and one of them means nobody checked.
        let honest = review_of_the_files();
        let mut quiet = honest.clone();
        quiet["costs"] = json!([]);
        quiet["warnings"] = json!([]);
        let package = package_of_the_files();
        let files = files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)]);
        let page = |review: Value| json!({"version": {"version": "1.0.0", "review": review}});
        use crate::hub::review::{page_check, page_from_json, page_json, page_lines};

        // A page that agrees with the files: compared, and nothing to say.
        let agreed = page_check(&package, &files, Some(&page(honest.clone())), "1.0.0");
        assert_eq!(agreed, Ok(Vec::new()), "a page that matches its files has nothing to report");
        assert!(page_lines(&agreed).is_empty(), "and nothing is put on screen");
        assert_eq!(page_json(&agreed), json!({"compared": true, "differs": false, "differences": []}));

        // A page that promises less. The difference is named, and it reaches both the screen and
        // anything reading the JSON.
        let differs = page_check(&package, &files, Some(&page(quiet)), "1.0.0");
        let named = differs.clone().unwrap();
        assert!(named.contains(&"what it is allowed to do".to_owned()), "{named:?}");
        let said = page_lines(&differs).join(" ");
        assert!(said.contains("describes it differently from the files"), "{said}");
        assert!(said.contains("what it is allowed to do"), "{said}");
        assert!(said.contains("built from the files themselves"), "it says which one it trusts: {said}");
        assert_eq!(page_json(&differs)["differs"], true);
        assert_eq!(page_json(&differs)["compared"], true);

        // Read back from a plan the engine returned, it is the same answer; a plan with no check
        // at all is told apart from one that found nothing.
        assert_eq!(page_from_json(&page_json(&differs)), Some(differs));
        assert_eq!(page_from_json(&page_json(&agreed)), Some(agreed));
        assert_eq!(page_from_json(&Value::Null), None);
        assert_eq!(page_from_json(&json!({})), None);

        // Nothing to compare: every one of these says why, and none reads as a clean check.
        for (detail, expected) in [
            (None, "did not send a page"),
            (Some(json!({"version": {"version": "9.9.9", "review": {"format": 2}}})), "different version"),
            (Some(page(json!({}))), "published without a review"),
        ] {
            let checked_against = page_check(&package, &files, detail.as_ref(), "1.0.0");
            let why = checked_against.clone().unwrap_err();
            assert!(why.contains(expected), "expected {expected:?} in {why:?}");
            assert_eq!(page_lines(&checked_against), vec![why.clone()]);
            assert_eq!(page_json(&checked_against)["compared"], false);
            assert_eq!(page_json(&checked_against)["reason"], json!(why));
            assert_eq!(page_from_json(&page_json(&checked_against)), Some(Err(why)));
        }
    }

    #[test]
    fn a_run_of_a_hub_template_carries_the_engines_page_check_into_its_result() {
        // The comparison is the engine's, made where the desktop's plan is made too, so a run
        // reads it from the plan it was given rather than making one of its own. What a script
        // reads has to say so before it decides whether to go on — and an engine that made no
        // check, or a folder with no page, is said as such rather than passed off as checked.
        let checks: std::rc::Rc<std::cell::RefCell<Option<Value>>> = Default::default();
        let answer = checks.clone();
        let _engine = crate::client::fake_engine::install(move |method, _| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_plan" => {
                let mut planned = json!({
                    "setupId": "setup-1", "digest": "plan-digest", "baseRevision": 0,
                    "review": {"pcAccess": []}, "plan": {"outputs": []},
                });
                if let Some(page) = answer.borrow().clone() {
                    planned["page"] = page;
                }
                Ok(planned)
            }
            other => panic!("a dry run asked the engine to {other}"),
        });
        let options = Options {
            source: "hub/acme/shop".into(), name: Some("shop".into()), inputs: vec![], bindings: vec![],
            inputs_file: None, secrets_stdin: false, yes: false, allow_pc_access: false, dry_run: true, storage_drive: None,
        };
        let run = |fetched: Fetched| {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
                .block_on(run_v2(fetched, &options, false, &Default::default()))
                .unwrap_or_else(|said| panic!("the dry run was refused: {said}"))
        };

        // The engine found the page quieter than the files: the run says so, as the engine did.
        *checks.borrow_mut() = Some(json!({"compared": true, "differs": true, "differences": ["what it is allowed to do"]}));
        let shown = run(from_the_hub(review_of_the_files()));
        assert_eq!(shown["page"]["compared"], true, "the page was checked: {}", shown["page"]);
        assert_eq!(shown["page"]["differs"], true, "and it does not match the files: {}", shown["page"]);
        let named: Vec<&str> = shown["page"]["differences"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(named.contains(&"what it is allowed to do"), "{named:?}");

        // An honest page says so just as plainly, so "differs: false" is a statement about this
        // page rather than the default for everything.
        *checks.borrow_mut() = Some(json!({"compared": true, "differs": false, "differences": []}));
        assert_eq!(run(from_the_hub(review_of_the_files()))["page"], json!({"compared": true, "differs": false, "differences": []}));

        // An engine that sent no check: not compared, and the reason says to update.
        *checks.borrow_mut() = None;
        let shown = run(from_the_hub(review_of_the_files()));
        assert_eq!(shown["page"]["compared"], false, "{}", shown["page"]);
        assert!(shown["page"]["reason"].as_str().unwrap().contains("did not check"), "{}", shown["page"]);

        // A folder has no page, whatever the engine says.
        *checks.borrow_mut() = Some(json!({"compared": true, "differs": false, "differences": []}));
        let folder = Fetched { origin: Wanted::Folder(std::path::PathBuf::from(".")), detail: None, ..from_the_hub(json!({})) };
        let shown = run(folder);
        assert_eq!(shown["page"]["compared"], false);
        assert_eq!(shown["page"]["reason"], json!(crate::hub::review::NO_HUB_PAGE));
    }

    #[test]
    fn a_dry_run_reads_and_plans_and_never_applies() {
        // A dry run is what every refusal points people at before they commit to anything:
        // "yougori template run X --dry-run shows it". If it ever reached setup_apply it would
        // create the very thing it promised not to create. The engine answering here is this
        // test's own, so the engine running on this computer is never asked anything at all.
        let _engine = crate::client::fake_engine::install(|method, _params| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_plan" => Ok(json!({
                "setupId": "setup-1", "digest": "plan-digest", "baseRevision": 0,
                "review": {"pcAccess": []}, "plan": {"outputs": []},
            })),
            other => panic!("a dry run asked the engine to {other}; it may only read and plan"),
        });
        let fetched = Fetched {
            files: files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)]),
            origin: Wanted::Folder(std::path::PathBuf::from(".")),
            version: "1.0.0".into(), digest: "plan-digest".into(), verified: true,
            detail: None, notices: Vec::new(),
        };
        // No --yes: a dry run is exactly the case that does not need it, because it creates nothing.
        let options = Options {
            source: ".".into(), name: Some("shop".into()), inputs: vec![], bindings: vec![],
            inputs_file: None, secrets_stdin: false, yes: false, allow_pc_access: false, dry_run: true, storage_drive: None,
        };
        let shown = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2(fetched, &options, false, &Default::default()))
            .unwrap_or_else(|said| panic!("the dry run was refused: {said}"));
        assert_eq!(shown["dryRun"], true);
        assert_eq!(shown["instance"], "shop");
        assert_eq!(shown["plan"]["setupId"], "setup-1", "the plan it shows is the engine's own");
        // No value was given for the secret, and a dry run needs none: the plan carries its
        // reference (found on a real engine, where a dry run was refused for want of a value).
        let planned = crate::client::fake_engine::calls().into_iter().find(|(method, _)| method == "setup_plan").unwrap().1;
        assert!(planned["bindings"].as_array().unwrap().contains(&json!({"field": "key", "secretRef": "apply:key"})), "{planned}");

        let asked: Vec<String> = crate::client::fake_engine::calls().into_iter().map(|(method, _)| method).collect();
        assert!(asked.contains(&"setup_plan".to_owned()), "it should have worked out a plan: {asked:?}");
        assert!(!crate::client::fake_engine::called("setup_apply"), "a dry run must never apply: {asked:?}");
        // And nothing else either: only looking at this computer and working out the plan.
        for method in &asked {
            assert!(
                matches!(method.as_str(), "app_status" | "get_platform_state" | "setup_plan"),
                "a dry run asked the engine to {method}; it may only read and plan",
            );
        }
    }

    #[test]
    fn the_same_run_without_dry_run_does_apply_so_the_check_above_means_something() {
        // The companion to the test above. "setup_apply was never called" would also be true of a
        // command that simply never applies anything, so this runs the same package for real and
        // shows setup_apply arriving. Together they say what the dry run is: the same work, stopped
        // before anything is created. Still this test's own engine; nothing is created anywhere.
        let _engine = crate::client::fake_engine::install(|method, params| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_plan" => Ok(json!({
                "setupId": "setup-1", "digest": "plan-digest", "baseRevision": 0,
                "review": {"pcAccess": []}, "plan": {"outputs": []},
            })),
            "setup_apply" => {
                assert_eq!(params["setupId"], "setup-1");
                assert_eq!(params["planDigest"], "plan-digest", "it applies the plan it showed, not another");
                Ok(json!({"operationId": "op-1"}))
            }
            "setup_operation" => Ok(json!({"state": "completed", "events": [], "nextCursor": 1})),
            "setup_get" => Ok(json!({"outputs": []})),
            other => panic!("unexpected engine call {other}"),
        });
        let fetched = Fetched {
            files: files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)]),
            origin: Wanted::Folder(std::path::PathBuf::from(".")),
            version: "1.0.0".into(), digest: "plan-digest".into(), verified: true,
            detail: None, notices: Vec::new(),
        };
        let options = Options {
            source: ".".into(), name: Some("shop".into()), inputs: vec![], bindings: vec![],
            inputs_file: None, secrets_stdin: false, yes: true, allow_pc_access: false, dry_run: false, storage_drive: None,
        };
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2(fetched, &options, false, &Default::default()))
            .unwrap_or_else(|said| panic!("the run was refused: {said}"));
        assert!(crate::client::fake_engine::called("setup_apply"), "the real run should apply");
    }

    /// The scripted run of the package above, with an engine this test answers itself.
    #[cfg(test)]
    fn scripted_run(options: Options, engine: impl Fn(&str, &Value) -> Result<Value, String> + 'static) -> Result<Value, String> {
        let _engine = crate::client::fake_engine::install(engine);
        let fetched = Fetched {
            files: files(&[(v1::TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT)]),
            origin: Wanted::Folder(std::path::PathBuf::from(".")),
            version: "1.0.0".into(), digest: "plan-digest".into(), verified: true,
            detail: None, notices: Vec::new(),
        };
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2(fetched, &options, false, &Default::default()))
    }

    #[cfg(test)]
    fn scripted_options() -> Options {
        Options {
            source: ".".into(), name: Some("shop".into()), inputs: vec![], bindings: vec![],
            inputs_file: None, secrets_stdin: false, yes: true, allow_pc_access: false, dry_run: false, storage_drive: None,
        }
    }

    #[test]
    fn a_scripted_run_that_stops_before_applying_says_nothing_was_created() {
        // Someone running this from a script reads one line and has to know whether to clean up.
        // Every way of stopping before the apply ends the same way, so the answer is never a guess.
        let reads_only = |method: &str, _: &Value| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            other => Err(format!("the engine will not {other}.")),
        };

        // 1. Without --yes there is nothing to read yet, so it points at the dry run.
        let said = scripted_run(Options { yes: false, ..scripted_options() }, reads_only).unwrap_err();
        assert!(said.contains("--dry-run"), "it should offer the dry run: {said}");
        assert!(said.ends_with("Nothing was created."), "{said}");

        // 2. The engine refuses to plan it: its own words, and then where that leaves things.
        let said = scripted_run(scripted_options(), reads_only).unwrap_err();
        assert!(said.contains("the engine will not setup_plan"), "the engine's own words: {said}");
        assert!(said.ends_with("Nothing was created."), "{said}");

        // 3. The plan needs folders on this computer and the script never said that was intended.
        let said = scripted_run(scripted_options(), |method, _| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_plan" => Ok(json!({
                "setupId": "setup-1", "digest": "plan-digest", "baseRevision": 0,
                "review": {"pcAccess": ["C:/work"]}, "plan": {"outputs": []},
            })),
            other => panic!("it should have stopped before {other}"),
        }).unwrap_err();
        assert!(said.contains("--allow-pc-access"), "it should say what to pass: {said}");
        assert!(said.ends_with("Nothing was created."), "{said}");
    }

    #[test]
    fn a_scripted_run_that_stops_after_applying_says_what_is_there_and_how_to_finish_or_remove_it() {
        // The other half, and the one that matters more: once the apply has started, telling
        // someone "nothing was created" would be a lie and would leave half a setup on their
        // computer with no way back. Each ending names the setup and both ways out.
        let engine = |state: &'static str, error: Value| {
            move |method: &str, _: &Value| match method {
                "app_status" => Ok(json!({"running": true})),
                "get_platform_state" => Ok(json!({"host": {}})),
                "setup_plan" => Ok(json!({
                    "setupId": "setup-1", "digest": "plan-digest", "baseRevision": 0,
                    "review": {"pcAccess": []}, "plan": {"outputs": []},
                })),
                "setup_apply" => Ok(json!({"operationId": "op-1"})),
                "setup_operation" => Ok(json!({
                    "state": state, "nextCursor": 1, "error": error.clone(),
                    "events": [{"message": "Pulling nginx:1.27"}],
                })),
                other => panic!("unexpected engine call {other}"),
            }
        };

        // It failed partway. What is there stays, and both ways out are named.
        let said = scripted_run(scripted_options(), engine("failed", json!({"message": "The image could not be pulled."}))).unwrap_err();
        assert!(said.starts_with("The image could not be pulled."), "the engine's own words first: {said}");
        assert!(said.contains("Last step: Pulling nginx:1.27."), "it should say how far it got: {said}");
        assert!(said.contains("What was created is kept"), "{said}");
        assert!(said.contains("yougori template logs setup-1"), "{said}");
        assert!(said.contains("yougori template continue setup-1"), "a way to finish it: {said}");
        assert!(said.contains("yougori template rm setup-1 --yes"), "a way to remove it: {said}");

        // It was stopped. On the wire a cancelled operation is a failed one whose error code says
        // so (the engine has no cancelled state): a cancellation, carrying the same two ways out.
        let said = scripted_run(scripted_options(), engine("failed", json!({"code": "operation_cancelled", "message": "This change was cancelled. Everything already created is still tracked.", "retryable": true}))).unwrap_err();
        let plain = crate::wire::cancellation(&said).unwrap_or_else(|| panic!("a stop should read as a cancellation: {said}"));
        assert!(plain.contains("What was created is kept"), "{plain}");
        assert!(plain.contains("yougori template continue setup-1"), "{plain}");
        assert!(plain.contains("yougori template rm setup-1 --yes"), "{plain}");

        // It is waiting for an answer a script cannot give: say which setup, and how to answer it.
        let said = scripted_run(scripted_options(), engine("awaiting_input", Value::Null)).unwrap_err();
        assert!(said.contains("yougori template configure setup-1"), "{said}");

        // The outcome is not known. The one thing it must not do is invite a second run that
        // creates the same setup twice.
        let said = scripted_run(scripted_options(), engine("unknown", Value::Null)).unwrap_err();
        assert!(said.contains("yougori template logs setup-1"), "{said}");
        assert!(said.contains("yougori template continue setup-1"), "the engine checks what happened before anything runs: {said}");
        assert!(said.contains("Nothing is done twice"), "{said}");
    }

    /// A recipe as `yougori template export` writes one: the author's answers stripped where
    /// they were theirs (no default for the email, the address or the secret), the secret's
    /// question kept, the folder asked again, the Hub tool still pinned.
    const EXPORTED_TEMPLATE: &str = "format_version: 2\nkind: template\nname: notes\ntitle: Notes\nsummary: A notes service.\nversion: 1.4.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\nbindings:\n  - {id: data, type: folder, question: Where are the notes?}\ninputs:\n  - {id: region, question: Which region?, type: text, group: website_api, default: eu}\n  - {id: owner_email, question: Who looks after it?, type: text, group: website_api}\n  - {id: api_key, question: API key, type: secret, group: ai_models}\ntools:\n  web: [hub/acme/aider@1.0.0]\n";
    const EXPORTED_PROJECT: &str = "format_version: 2\nproject: notes\nenvironments:\n  web:\n    image: alpine:3.20\n";

    #[cfg(test)]
    fn exported_recipe(path: &str) -> Fetched {
        let files = files(&[(v1::TEMPLATE_FILE, EXPORTED_TEMPLATE), ("yougori.yaml", EXPORTED_PROJECT)]);
        let digest = scan::digest_of(&files);
        Fetched { files, origin: Wanted::Folder(std::path::PathBuf::from(path)), version: String::new(), digest, verified: false, detail: None, notices: Vec::new() }
    }

    #[test]
    fn an_exported_recipe_asks_the_next_person_for_everything_the_export_left_out() {
        // PROVES the import side of the export contract, without any engine: planned with no
        // answers, the recipe stops on each question the export stripped — the secret, the
        // author's own email, the folder — rather than running with a blank or the author's
        // value. The answer that was safe to carry (the region) is prefilled and not asked.
        let recipe = exported_recipe("C:/recipes/notes");
        let host = plan::Host { yougori: "1.2.0".into(), ..host_here() };
        let unanswered = plan::Answers { instance: "notes".into(), ..plan::Answers::default() };
        let problems = plan_files(&recipe.files, None, Some(recipe.digest.clone()), &unanswered, &host).unwrap_err();
        let said = problems_text("This template", &problems);
        assert!(said.contains("api_key needs an answer: API key"), "{said}");
        assert!(said.contains("owner_email needs an answer: Who looks after it?"), "{said}");
        assert!(said.contains("data needs a folder chosen on this computer: Where are the notes?"), "{said}");
        assert!(!said.contains("region needs an answer"), "the carried default stands in: {said}");
        assert!(problems.iter().all(|p| matches!(&*p.code, "awaiting_input" | "awaiting_binding")), "{said}");
    }

    #[test]
    fn a_recipient_runs_an_exported_recipe_with_their_own_answers_and_secrets() {
        // The whole import, as a script runs it: `yougori template run ./notes --input ... --binding
        // data=... --secrets - --yes`. What reaches the engine's plan is the recipient's answers and
        // a reference for each secret; the secret's value travels with the apply and nowhere else;
        // and nothing in either request is the author's — no instance name of theirs, no folder,
        // no drive, no value. The engine here is this test's own.
        let own_folder = std::env::temp_dir();
        let own_folder_text = own_folder.to_string_lossy().into_owned();
        let _engine = {
            let own_folder_text = own_folder_text.clone();
            crate::client::fake_engine::install(move |method, params| match method {
                "app_status" => Ok(json!({"running": true})),
                "get_platform_state" => Ok(json!({"host": {}})),
                "setup_list" => Ok(json!({"setups": []})),
                "setup_plan" => {
                    assert_eq!(params["source"], json!({"kind": "local_folder", "path": "C:/recipes/notes"}), "run from the folder the recipient has, by its path");
                    assert_eq!(params["name"], "notes", "named after the template, not after the author's setup");
                    assert_eq!(params["answers"], json!([
                        {"field": "owner_email", "value": "ops@example.org"},
                        {"field": "region", "value": "us"},
                        {"field": "data", "value": own_folder_text},
                    ]), "only the recipient's answers, the carried default changed as they chose");
                    assert_eq!(params["bindings"], json!([{"field": "api_key", "secretRef": "apply:api_key"}]), "a reference for the secret, never its value");
                    let whole = params.to_string();
                    assert!(!whole.contains("recipient-key-0123"), "the secret value is not in the plan: {whole}");
                    Ok(json!({"setupId": "setup-9", "digest": "plan-digest", "baseRevision": 0, "review": {"pcAccess": []}, "plan": {"outputs": []}}))
                }
                "setup_apply" => {
                    assert_eq!(params["setupId"], "setup-9");
                    assert_eq!(params["planDigest"], "plan-digest");
                    assert_eq!(params["secrets"], json!({"api_key": "recipient-key-0123"}), "the value travels with the apply only");
                    assert_eq!(params["consents"], json!([]));
                    Ok(json!({"operationId": "op-1"}))
                }
                "setup_operation" => Ok(json!({"state": "completed", "events": [], "nextCursor": 1})),
                "setup_get" => Ok(json!({"state": "ready", "outputs": []})),
                other => panic!("unexpected engine call {other}"),
            })
        };
        let options = Options {
            source: "./notes".into(), name: None,
            inputs: vec![("region".into(), "us".into()), ("owner_email".into(), "ops@example.org".into())],
            bindings: vec![("data".into(), own_folder_text.clone())],
            inputs_file: None, secrets_stdin: true, yes: true, allow_pc_access: false, dry_run: false, storage_drive: None,
        };
        let secrets = br#"{"api_key": "recipient-key-0123"}"#;
        let shown = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2_given(exported_recipe("C:/recipes/notes"), &options, false, Some(secrets), &Default::default()))
            .unwrap_or_else(|said| panic!("the run was refused: {said}"));
        assert_eq!(shown["instance"], "notes");
        assert_eq!(shown["setupId"], "setup-9");
        assert_eq!(shown["template"]["source"], "folder");
        assert!(crate::client::fake_engine::called("setup_apply"));
        // Every request the engine saw: nothing of an author anywhere in them. The recipe itself
        // carries none, and the CLI adds only what this person typed.
        for (method, params) in crate::client::fake_engine::calls() {
            let whole = params.to_string();
            assert!(!whole.contains("dana") && !whole.contains("C:/Users/") && !whole.contains("apply.api_key"), "{method} carried something of the author: {whole}");
        }

        // The same secret in the open is refused before the engine hears of it.
        let plans = || crate::client::fake_engine::calls().iter().filter(|(method, _)| method == "setup_plan").count();
        let planned_before = plans();
        let leaked = Options { inputs: vec![("api_key".into(), "recipient-key-0123".into())], secrets_stdin: false, ..options.clone() };
        let said = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2_given(exported_recipe("C:/recipes/notes"), &leaked, false, None, &Default::default()))
            .unwrap_err();
        assert!(said.contains("api_key is a secret"), "{said}");
        assert_eq!(plans(), planned_before, "nothing was planned with a secret in the open");
    }

    #[test]
    fn a_second_copy_without_a_name_is_planned_as_name_2() {
        // Two people's copies, or one person's two, on one computer: the engine keeps each setup
        // apart by its own id, and stores each one's sandboxes and data under that id, so they
        // never collide there. The name people type is the one thing that could: a second copy
        // of `notes` is planned as `notes-2`, so neither answers to the other's name.
        let _engine = crate::client::fake_engine::install(|method, params| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_list" => Ok(json!({"setups": [{"setupId": "setup-1", "name": "notes"}, {"setupId": "setup-2", "name": "notes-2"}]})),
            "setup_plan" => {
                assert_eq!(params["name"], "notes-3", "the first free name after the two already here");
                Ok(json!({"setupId": "setup-3", "digest": "plan-digest", "baseRevision": 0, "review": {"pcAccess": []}, "plan": {"outputs": []}}))
            }
            other => panic!("a dry run asked the engine to {other}"),
        });
        let options = Options {
            source: "./notes".into(), name: None, inputs: vec![("owner_email".into(), "ops@example.org".into())], bindings: vec![],
            inputs_file: None, secrets_stdin: false, yes: false, allow_pc_access: false, dry_run: true, storage_drive: None,
        };
        let shown = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2_given(exported_recipe("C:/recipes/notes"), &options, false, None, &Default::default()))
            .unwrap_or_else(|said| panic!("the dry run was refused: {said}"));
        assert_eq!(shown["instance"], "notes-3");
        assert!(!crate::client::fake_engine::called("setup_apply"));
        // Asked for by name, the name is taken as given; the engine says if it is already held.
        let named = Options { name: Some("notes".into()), ..options };
        let _engine = crate::client::fake_engine::install(|method, params| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_plan" => {
                assert_eq!(params["name"], "notes");
                Ok(json!({"setupId": "setup-1", "digest": "plan-digest", "baseRevision": 0, "review": {"pcAccess": []}, "plan": {"outputs": []}}))
            }
            other => panic!("a named dry run asked the engine to {other}; it need not list setups"),
        });
        let shown = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(run_v2_given(exported_recipe("C:/recipes/notes"), &named, false, None, &Default::default()))
            .unwrap();
        assert_eq!(shown["instance"], "notes");
    }

    #[test]
    fn script_answers_sort_inputs_bindings_capabilities_and_refuse_secrets_in_the_open() {
        let template = TEMPLATE.replace("inputs:\n", "capabilities:\n  - {id: web.service, selection: required}\n  - {id: web.quick_link, selection: optional}\nbindings:\n  - {id: data, type: folder, question: Data folder?}\ninputs:\n");
        let checked = check_files(&files(&[(v1::TEMPLATE_FILE, &template), ("yougori.yaml", PROJECT)])).unwrap_or_else(|p| panic!("{}", problems_text("the package", &p)));
        // A folder that is there on every platform the tests run on (C:/ is Windows only).
        let folder = std::env::temp_dir().to_string_lossy().to_string();
        let options = Options { source: ".".into(), name: None, inputs: vec![("title".into(), "Hi".into()), ("capabilities.web.quick_link".into(), "true".into())], bindings: vec![("data".into(), folder.clone())], inputs_file: None, secrets_stdin: false, yes: true, allow_pc_access: false, dry_run: false, storage_drive: None };
        let collected = tokio::runtime::Runtime::new().unwrap().block_on(given_from(&checked, &options, None)).unwrap();
        assert_eq!(collected.inputs["title"], "Hi");
        assert_eq!(collected.capabilities["web.quick_link"], true);
        assert_eq!(collected.bindings["data"], folder);
        let wrong = Options { bindings: vec![("nothing".into(), folder.clone())], ..options.clone() };
        assert!(tokio::runtime::Runtime::new().unwrap().block_on(given_from(&checked, &wrong, None)).unwrap_err().contains("has no binding nothing"));
        let missing = Options { bindings: vec![("data".into(), "C:/no/such/folder/for/sure".into())], ..options.clone() };
        assert!(tokio::runtime::Runtime::new().unwrap().block_on(given_from(&checked, &missing, None)).unwrap_err().contains("--binding data: There is no folder"));
        let answers = answer_list(&collected);
        assert!(answers.iter().any(|a| a["field"] == "capabilities.web.quick_link" && a["value"] == true));
        let leaked = Options { inputs: vec![("key".into(), "sk".into())], ..options.clone() };
        let said = tokio::runtime::Runtime::new().unwrap().block_on(given_from(&checked, &leaked, None)).unwrap_err();
        assert!(said.contains("key is a secret"), "{said}");
        let binding = &checked.bindings[0];
        assert!(check_binding(binding, "").is_err());
        assert!(check_binding(binding, "C:/no/such/folder/for/sure").unwrap_err().contains("There is no folder"));
        let resource = format::CheckedBinding { id: "grid".into(), kind: resource::BindingKind::Resource, resource: Some(resource::Kind::Grid), profile: None, question: "Which?".into(), hint: String::new(), required: true, when: None, read_only: true, mode: None };
        assert!(check_binding(&resource, "setup-1").unwrap_err().contains("SETUP/RESOURCE"));
        assert_eq!(check_binding(&resource, "setup-1/company").unwrap(), "setup-1/company");
    }

    #[test]
    fn every_door_that_applies_a_plan_agrees_the_same_way_and_says_what_it_left_undone() {
        // The one agreement flow for a first run, a change and a join. A script agrees to the folder
        // agreements only when told to, never to a sign-in copy, and a writable folder left
        // unagreed is refused before anything is applied, in that command's own words.
        let planned = json!({"consents": [
            {"id": "write_folder:app/data", "message": "Let app change files in the folder you chose for data."},
            {"id": "copy_signin:app/codex", "message": "Copy your Codex sign-in from this computer into app."},
        ]});
        for stage in [Stage::Run, Stage::Change, Stage::Join] {
            assert_eq!(agreements(&json!({}), false, false, stage).unwrap(), Vec::<String>::new(), "a plan that asks for nothing");
        }
        assert_eq!(agreements(&planned, true, false, Stage::Run).unwrap(), ["write_folder:app/data"]);
        assert_eq!(agreements(&planned, true, false, Stage::Change).unwrap(), ["write_folder:app/data"]);
        // A first run says exactly what it said before the flow was shared.
        assert_eq!(
            agreements(&planned, false, false, Stage::Run).unwrap_err(),
            "This setup keeps a folder you chose in step with its sandbox, which means changing files in it, and that was not agreed to (data). Pass --allow-pc-access as well as --yes if that is intended. Nothing was created."
        );
        let options = Options { allow_pc_access: false, ..scripted_options() };
        assert_eq!(agree_to(&planned, &options, false).unwrap_err(), agreements(&planned, false, false, Stage::Run).unwrap_err());
        let change = agreements(&planned, false, false, Stage::Change).unwrap_err();
        assert!(change.starts_with("This change keeps a folder") && change.contains("--allow-pc-access") && change.ends_with("Nothing was changed."), "{change}");
        let join = agreements(&planned, false, false, Stage::Join).unwrap_err();
        assert!(join.contains("Join at a terminal") && join.ends_with("Nothing was joined."), "{join}");
        assert_eq!(Stage::Change.stopped(ui::CANCELLED.to_owned()), crate::wire::cancelled("Cancelled. Nothing was changed."));
        assert_eq!(Stage::Run.stopped("The engine is busy.".to_owned()), "The engine is busy.");
        // A mounted folder left unagreed is mounted read only, which stops nothing: only a synced
        // one is refused. One whose engine does not say which it is counts as synced.
        let mounted = json!({"consents": [{"id": "write_folder:app/notes", "mode": "mount", "message": "Let app change files in the folder you chose for notes."}]});
        assert_eq!(agreements(&mounted, false, false, Stage::Change).unwrap(), Vec::<String>::new());
        assert_eq!(agreements(&mounted, true, false, Stage::Change).unwrap(), ["write_folder:app/notes"]);
        let synced = json!({"consents": [{"id": "write_folder:app/code", "mode": "sync", "message": "Let app change files in the folder you chose for code."}]});
        assert!(agreements(&synced, false, false, Stage::Run).is_err());
    }

    #[test]
    fn a_new_setup_never_takes_the_name_of_a_format_1_instance() {
        // PROVES the two kinds of names are kept apart. The lifecycle commands look a name up among
        // the engine's setups first, so a setup that took a format 1 instance's name hid that
        // instance from all of them, `template rm` included. A name chosen for a run skips both
        // kinds, without regard to case; a name asked for that an instance holds is refused.
        let instances: std::collections::BTreeSet<String> = ["notes".to_owned()].into();
        let _engine = crate::client::fake_engine::install(|method, _| match method {
            "setup_list" => Ok(json!({"setups": [{"setupId": "setup-1", "name": "Notes-2"}]})),
            other => panic!("unexpected engine call {other}"),
        });
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        assert_eq!(rt.block_on(free_name("notes", &instances)), "notes-3", "notes is an instance's, notes-2 a setup's");
        assert_eq!(rt.block_on(free_name("shop", &instances)), "shop");
        assert_eq!(rt.block_on(free_name("setup-1", &Default::default())), "setup-1-2", "a setup's id is one of its names too");
        assert!(instance_name_taken("Notes", &instances).unwrap().contains("Choose another name with --name. Nothing was created."));
        assert_eq!(instance_name_taken("shop", &instances), None);

        // Through a run: unnamed, it is planned as the free name; named as an instance is, refused
        // before anything is planned.
        let _engine = crate::client::fake_engine::install(|method, params| match method {
            "app_status" => Ok(json!({"running": true})),
            "get_platform_state" => Ok(json!({"host": {}})),
            "setup_list" => Ok(json!({"setups": []})),
            "setup_plan" => {
                assert_eq!(params["name"], "notes-2", "the format 1 instance keeps its name");
                Ok(json!({"setupId": "setup-3", "digest": "plan-digest", "baseRevision": 0, "review": {"pcAccess": []}, "plan": {"outputs": []}}))
            }
            other => panic!("unexpected engine call {other}"),
        });
        let options = Options {
            source: "./notes".into(), name: None, inputs: vec![("owner_email".into(), "ops@example.org".into())], bindings: vec![],
            inputs_file: None, secrets_stdin: false, yes: false, allow_pc_access: false, dry_run: true, storage_drive: None,
        };
        let shown = rt.block_on(run_v2_given(exported_recipe("C:/recipes/notes"), &options, false, None, &instances)).unwrap_or_else(|said| panic!("{said}"));
        assert_eq!(shown["instance"], "notes-2");
        let named = Options { name: Some("notes".into()), ..options };
        let refused = rt.block_on(run_v2_given(exported_recipe("C:/recipes/notes"), &named, false, None, &instances)).unwrap_err();
        assert!(refused.contains("template instance") && refused.contains("--name") && refused.ends_with("Nothing was created."), "{refused}");
        assert_eq!(crate::client::fake_engine::calls().iter().filter(|(method, _)| method == "setup_plan").count(), 1, "the refused run planned nothing");
    }
}
