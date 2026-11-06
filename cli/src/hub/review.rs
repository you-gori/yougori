//! The review (docs/hub.md section 7): what a template creates, opens, installs and asks,
//! computed on this computer from the files themselves. The publisher's CLI sends the same
//! computation to the Hub, so a run can say when the page and the files disagree.
use super::{
    format::{self, Folder, Kind, Source, Tool, ToolFile},
    scan::Files,
    unicode,
};
use crate::manifest;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use yougori_setup::plan as planner;

/// The format of a v1 package's review. A format 2 package's review is [`template_v2`]'s, format
/// 2. A page whose review is in a format this Yougori does not know is not compared part by part.
pub const FORMAT: u64 = 1;

/// The review of a format 2 package, as the shared crate writes it: every format 1 part still
/// filled, plus the resources, capabilities, subtitle, aliases and retention, and what each
/// imported component grants. `notices` are the scan's notes. An error when the review can't show
/// everything the package grants (a component that was not resolved, a part it can't read).
pub fn template_v2(package: &planner::Package, notices: &[String]) -> Result<Value, String> {
    planner::published_review(package, notices)
}

// ---- The Hub page against the files ----
//
// The page is what a person read before choosing; the files are what would run. A page that
// promises less than the files grant (no cost, no folder access, no grid) is the case this exists
// for. It is ONE rule, applied at the one planning boundary every door goes through: the engine's
// `setup_plan` works it out for the desktop and for `template run`, and `template plan` applies it
// when it plans a Hub package locally with no engine. Neither interface has a comparison of its own.

/// Why a template from a folder on this computer has no page to compare with.
pub const NO_HUB_PAGE: &str = "This template came from a folder on this computer, so there is no Hub page to compare it with.";

/// The Hub page's published review for one version, against the review the downloaded files
/// themselves produce. `page` is the Hub's page data for the item, when the Hub sent one; `version`
/// is the version of `files`, which are the files the review is built from (the scan's wallet notice
/// is part of a published review, so it is part of the comparison, as `template publish` writes it).
///
/// `Ok(list)` is what differs, empty when the page agrees. `Err(reason)` is why no comparison could
/// be made, which is said out loud: an unchecked page passed off as a checked one is worse than no
/// check, because it is the same silence either way.
pub fn page_check(package: &planner::Package, files: &Files, page: Option<&Value>, version: &str) -> Result<Vec<String>, String> {
    let Some(detail) = page else {
        return Err("The Hub did not send a page for this version, so the files could not be checked against what it says.".into());
    };
    if detail["version"]["version"] != version {
        return Err("The Hub's page is for a different version than the files that were downloaded, so they were not compared.".into());
    }
    let published = &detail["version"]["review"];
    if !published.as_object().is_some_and(|review| !review.is_empty()) {
        return Err("This version was published without a review, so there is nothing on the Hub to compare the files with.".into());
    }
    // Built exactly as `template publish` builds it, including the notices the scan adds to the
    // warnings: otherwise every template whose files mention a wallet would look changed.
    let notices: Vec<String> = super::scan::scan(files).wallet_notice().into_iter().collect();
    // A template built from imported components needs them fetched before its review can be
    // written at all, which is why this says so rather than comparing against a partial review
    // and calling the missing parts a difference.
    let mine = template_v2(package, &notices).map_err(|error| format!("The files could not be checked against the Hub's page: {error}"))?;
    Ok(differences(&mine, published))
}

/// What the page check has to say on screen, above the review it qualifies.
pub fn page_lines(checked: &Result<Vec<String>, String>) -> Vec<String> {
    match checked {
        Ok(differences) if !differences.is_empty() => {
            let mut lines = vec!["The Hub page for this version describes it differently from the files that were downloaded:".to_owned()];
            lines.extend(differences.iter().map(|what| format!("  - {what}")));
            lines.push("What follows is built from the files themselves, which is what would run.".to_owned());
            lines
        }
        Err(why) => vec![why.clone()],
        Ok(_) => Vec::new(),
    }
}

/// The page check as a program reads it. `compared` is false when there was nothing to compare,
/// so no one can mistake "nothing to compare" for "compared, and the same".
pub fn page_json(checked: &Result<Vec<String>, String>) -> Value {
    match checked {
        Ok(differences) => json!({"compared": true, "differs": !differences.is_empty(), "differences": differences}),
        Err(why) => json!({"compared": false, "differs": false, "differences": [], "reason": why}),
    }
}

/// [`page_json`] read back, from a plan the engine returned: `None` when the plan carries no page
/// check at all (an engine older than this, or a plan that was not of a Hub package).
pub fn page_from_json(value: &Value) -> Option<Result<Vec<String>, String>> {
    let page = value.as_object()?;
    match page.get("compared").and_then(Value::as_bool)? {
        true => Some(Ok(page.get("differences").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect())),
        false => Some(Err(page.get("reason").and_then(Value::as_str).unwrap_or("The files were not checked against the Hub's page.").to_owned())),
    }
}

/// The longest text a review may hold, in UTF-16 units, as the website allows.
pub const TEXT_MAX: usize = 4000;

/// Text as the website accepts it in a review: no control characters other than tab and line
/// breaks, nothing invisible or reordering, at most 4000 characters. Template text reaches the
/// review (paths, images, questions), so every text is made plain here.
fn plain(text: &str) -> String {
    let kept: String = text.chars().filter(|c| !unicode::control(*c) && !unicode::hidden(*c)).collect();
    if unicode::utf16_len(&kept) <= TEXT_MAX {
        return kept;
    }
    let mut out = String::new();
    let mut units = 0;
    for c in kept.chars() {
        if units + c.len_utf16() > TEXT_MAX - 1 {
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out.push('…');
    out
}

fn cleaned(mut value: Value) -> Value {
    fn walk(value: &mut Value) {
        match value {
            Value::String(text) => *text = plain(text),
            Value::Array(items) => items.iter_mut().for_each(walk),
            Value::Object(fields) => fields.values_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

/// Review conditions are descriptions, not executable rules. Keep every input, operator and
/// alternative while staying inside the Hub's four-level JSON limit (tools is already a list).
fn conditions(conditions: &[format::Condition]) -> Value {
    json!(conditions.iter().map(|condition| format!("{} {} {}", condition.input,
        if condition.contains { "contains any of" } else { "is one of" },
        json!(condition.values))).collect::<Vec<_>>())
}

/// What the website refuses in a review, in either format: its known parts must have their
/// types, values nest at most four deep, every text is short and plain, and the whole stays under
/// the website's size (`server/hub/review.mjs`). The shared crate holds the one copy of the rules.
pub fn shape_problem(review: &Value) -> Option<String> {
    planner::review_shape_problem(review)
}

/// The warning every unverified item carries, word for word.
pub const UNVERIFIED: &str = "Not checked by Yougori. Community templates can contain harmful code, including viruses.\nRead the files first and run only what you trust.";

/// A number as JSON: whole numbers without a fraction, so `2` and not `2.0`.
pub fn number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 1e15 { json!(value as i64) } else { json!(value) }
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

fn image(environment: &manifest::Environment) -> String {
    match environment.kind.as_str() {
        "microvm" if environment.image.is_empty() => environment.source.clone().unwrap_or_else(|| "builtin:alpine".into()),
        "vm" => environment.source.clone().unwrap_or_else(|| environment.image.clone()),
        _ => environment.image.clone(),
    }
}

fn pc_access(environment: &manifest::Environment) -> Vec<Value> {
    let mut folders: Vec<Value> = environment.volumes.iter().filter(|v| v.bind)
        .map(|v| json!({"path": v.source, "target": v.target, "readOnly": v.read_only}))
        .collect();
    folders.extend(environment.pc_access.iter().map(|p| json!({"path": p.path, "target": p.target, "readOnly": p.read_only})));
    folders
}

/// One tool as the review lists it. `resolved` holds Hub tools already downloaded and checked.
fn tool_entry(name: String, source: &str, environment: &str, tool: Option<&Tool>) -> Value {
    let mut entry = json!({"name": name, "source": source, "environment": environment});
    if let Some(tool) = tool {
        entry["version"] = json!(tool.version());
        entry["downloads"] = json!(downloads(&tool.install));
        entry["commands"] = json!(tool.install);
        entry["signin"] = json!(tool.signin_method());
    }
    entry
}

/// The review of a template folder. `notices` are the scan's notes (wallet addresses);
/// `resolved` maps a Hub tool's `PUBLISHER/NAME` to its checked tool file, when downloaded.
pub fn template(folder: &Folder, notices: &[String], resolved: &BTreeMap<String, Tool>) -> Value {
    let project = &folder.project;
    let mut environments = Vec::new();
    let (mut cpu, mut memory, mut storage) = (0.0, 0.0, 0.0);
    let mut pc = Vec::new();
    for (name, environment) in &project.environments {
        let memory_gb = manifest::gib(&environment.memory).ok();
        let storage_gb = manifest::gib(&environment.storage).ok();
        cpu += environment.cpu;
        memory += memory_gb.unwrap_or(0.0);
        storage += storage_gb.unwrap_or(0.0);
        let folders = pc_access(environment);
        for folder in &folders {
            let mut folder = folder.clone();
            folder["environment"] = json!(name);
            pc.push(folder);
        }
        environments.push(json!({
            "name": name,
            "type": environment.kind,
            "image": image(environment),
            "cpu": number(environment.cpu),
            "memoryGb": memory_gb.map(number),
            "storageGb": storage_gb.map(number),
            "gpu": environment.gpu || environment.kind == "gpu",
            "internet": environment.internet,
            "ports": environment.ports.iter().filter_map(|p| p.values().ok()).map(|(guest, _)| guest).collect::<Vec<_>>(),
            "tools": folder.tools.iter().filter(|t| &t.environment == name).map(|t| t.name()).collect::<Vec<_>>(),
            "secrets": environment.secrets.keys().collect::<Vec<_>>(),
            "pcAccess": folders,
            "writablePcFolders": environment.volumes.iter().any(|v| v.bind && !v.read_only) || environment.pc_access.iter().any(|p| !p.read_only),
        }));
    }
    let public: Vec<Value> = folder.template.public.iter().map(|entry| {
        let access = entry.access.as_deref().unwrap_or("quick");
        let mut item = json!({"environment": entry.environment, "port": entry.port});
        match access {
            "quick" | "domain" | "none" => item["access"] = json!(access),
            asked => {
                item["access"] = json!("asked");
                item["input"] = json!(asked.trim_start_matches("{{").trim_end_matches("}}").trim().trim_start_matches("inputs."));
            }
        }
        item
    }).collect();
    let connections: Vec<Value> = project.connections.iter().filter_map(|c| c.endpoints().ok()).map(|(from, to)| json!({"from": from, "to": to})).collect();
    let tools: Vec<Value> = folder.tools.iter().map(|use_| { let mut entry = match &use_.source {
        Source::BuiltIn(name) => tool_entry(name.clone(), "built-in", &use_.environment, None),
        Source::Bundled { folder, tool } => {
            let mut entry = tool_entry(tool.name().to_owned(), "bundled", &use_.environment, Some(tool));
            entry["path"] = json!(folder);
            entry
        }
        Source::Hub(reference) => {
            let mut entry = tool_entry(reference.item(), "hub", &use_.environment, resolved.get(&reference.item()));
            entry["ref"] = json!(reference.command());
            entry
        }
    };
        if !use_.when.is_empty() { entry["when"] = conditions(&use_.when); }
        if use_.signin {
            entry["signin"] = json!("Choose PC credentials or a new account; sign-in opens in a separate terminal window");
            if !use_.signin_when.is_empty() { entry["signinWhen"] = conditions(&use_.signin_when); }
            if let Some(input) = &use_.signin_source { entry["signinSource"] = json!(input); }
        }
        entry
    }).collect();
    let inputs: Vec<Value> = folder.questions.iter().map(|q| json!({"id": q.id, "question": q.question, "type": q.kind.name(), "secret": q.kind == Kind::Secret, "required": q.required})).collect();
    let steps: Vec<Value> = folder.template.steps.iter().filter_map(|s| s.title.clone()).map(Value::String).collect();
    let gpu = folder.gpu().to_owned();
    // Warnings, most serious first.
    let mut warnings: Vec<String> = Vec::new();
    for folder in &pc {
        let path = folder["path"].as_str().unwrap_or_default();
        let environment = folder["environment"].as_str().unwrap_or_default();
        warnings.push(if folder["readOnly"] == false {
            format!("{environment} can change files in {path} on this computer.")
        } else {
            format!("{environment} can read {path} on this computer.")
        });
    }
    for entry in &public {
        if entry["access"] != "none" {
            warnings.push(format!("Makes {}:{} reachable from the internet.", entry["environment"].as_str().unwrap_or_default(), entry["port"]));
        }
    }
    for entry in &tools {
        for address in entry["downloads"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            let said = format!("Installs software from {address}.");
            if !warnings.contains(&said) {
                warnings.push(said);
            }
        }
        if entry["source"] == "hub" && entry.get("commands").is_none() {
            warnings.push(format!("Installs the Hub tool {}; its files are checked when it runs.", entry["name"].as_str().unwrap_or_default()));
        }
    }
    match gpu.as_str() {
        "required" => warnings.push("Needs an NVIDIA GPU.".into()),
        "optional" => warnings.push("Uses an NVIDIA GPU when this computer has one.".into()),
        _ => {}
    }
    warnings.extend(notices.iter().cloned());
    cleaned(json!({
        "format": FORMAT,
        "environments": environments,
        "totals": {"environments": project.environments.len(), "cpu": number(cpu), "memoryGb": number(memory), "storageGb": number(storage), "gpu": gpu},
        "public": public,
        "connections": connections,
        "tools": tools,
        "inputs": inputs,
        "steps": steps,
        "pcAccess": pc,
        "warnings": warnings,
        "requires": {
            "yougori": folder.template.requires.yougori,
            "gpu": gpu,
            "platforms": folder.template.requires.platforms,
        },
    }))
}

/// The review of a tool file on its own: [`tool`]'s, with what the file declares it reaches
/// (its access, inputs and outputs) shown as the engine's review shows it, as the tool's own
/// word. Nothing declared grants anything: a sandbox has only what its own settings and the
/// person's answers give it, and the review says so beside the declaration.
pub fn tool_file(file: &ToolFile, notices: &[String]) -> Value {
    let mut review = tool(&Tool::from(file), notices);
    let declared = file.declared_access();
    if !declared.is_empty() {
        review["tools"][0]["access"] = json!(declared);
        review["warnings"].as_array_mut().into_iter().for_each(|warnings| {
            warnings.push(json!(format!("{} says it {}. That is the tool's own word: a sandbox has only what its own settings and your answers give it.", file.name(), declared.join(", "))));
        });
    }
    if !file.inputs.is_empty() {
        review["tools"][0]["inputs"] = json!(file.inputs.iter().map(|input| input.name.clone()).collect::<Vec<_>>());
    }
    if !file.outputs.is_empty() {
        review["tools"][0]["outputs"] = json!(file.outputs.iter().map(|output| output.name.clone()).collect::<Vec<_>>());
    }
    cleaned(review)
}

/// The review of a tool in the installer's form: what it installs, from where, its check,
/// command, sign-in, needs and service. A view declares nothing; [`tool_file`] adds what the
/// file does.
pub fn tool(tool: &Tool, notices: &[String]) -> Value {
    let downloads = downloads(&tool.install);
    let mut warnings: Vec<String> = downloads.iter().map(|address| format!("Installs software from {address}.")).collect();
    if tool.gpu() == "required" {
        warnings.push("Needs an NVIDIA GPU.".into());
    }
    if tool.service.is_some() {
        warnings.push("Runs a server inside the sandbox.".into());
    }
    warnings.extend(notices.iter().cloned());
    cleaned(json!({
        "format": FORMAT,
        "tools": [{"name": tool.name(), "source": "tool", "version": tool.version(), "downloads": downloads, "commands": tool.install, "check": tool.check, "command": tool.command, "signin": tool.signin_method()}],
        "needs": {"gpu": tool.gpu(), "memoryGb": tool.memory_gb().map(number), "internet": tool.needs.as_ref().and_then(|n| n.internet).unwrap_or(true)},
        "service": tool.service.as_ref().map(|s| json!({"command": s.command, "port": s.port})),
        "warnings": warnings,
    }))
}

/// The parts of a review that decide what a template does to a computer and that every format
/// writes: its sandboxes and totals, what it opens to the internet and on this computer, what it
/// installs from where, what it asks and its warnings. Each part is taken in the form format 1
/// wrote it, so a page in either format is compared with the files on the same grants.
fn essentials(review: &Value) -> Value {
    let tools: Vec<Value> = review["tools"].as_array().into_iter().flatten().map(|tool| json!({
        "name": tool["name"], "source": tool["source"], "environment": tool["environment"],
        "downloads": tool["downloads"], "commands": tool["commands"], "check": tool["check"], "command": tool["command"],
        "when": tool["when"], "signin": tool["signin"], "signinWhen": tool["signinWhen"], "signinSource": tool["signinSource"],
    })).collect();
    let inputs: Vec<Value> = review["inputs"].as_array().into_iter().flatten().map(|input| json!({
        "id": input["id"], "question": input["question"], "type": input["type"], "secret": input["secret"], "required": input["required"],
    })).collect();
    let public: Vec<Value> = review["public"].as_array().into_iter().flatten().map(|entry| json!({
        "environment": entry["environment"], "port": entry["port"], "access": entry["access"], "input": entry["input"],
    })).collect();
    json!({
        "environments": review["environments"], "totals": review["totals"], "public": public, "pcAccess": review["pcAccess"],
        "tools": tools, "inputs": inputs, "warnings": review["warnings"], "needs": review["needs"], "service": review["service"],
    })
}

/// The parts only a format 2 review has: what it creates beyond sandboxes, which capabilities it
/// turns on, and what happens to data.
fn format_2_essentials(review: &Value) -> Value {
    json!({
        "resources": review["resources"], "capabilities": review["capabilities"],
        "retention": review["retention"],
        // Costs were left out of this comparison until plan L727. A page that said a setup was
        // free for one that rents a GPU by the hour is exactly the kind of difference someone
        // needs before they agree, not after the first bill.
        "costs": review["costs"],
    })
}

/// Every part of a review that is compared, in the order a person needs to hear about it, with
/// the words for what that part covers. `true` marks the parts only a format 2 review has.
const COMPARED: &[(&str, &str, bool)] = &[
    ("capabilities", "what it turns on", true),
    ("resources", "what it creates", true),
    ("pcAccess", "the folders on this computer it reaches", false),
    ("public", "what it opens to the internet", false),
    ("warnings", "what it is allowed to do", false),
    ("costs", "what it may cost", true),
    ("tools", "the tools it installs, and what they download", false),
    ("environments", "the sandboxes it runs", false),
    ("retention", "what happens to your data when it stops or is removed", true),
    ("needs", "what it needs in order to run", false),
    ("service", "what it runs as a service", false),
    ("inputs", "the questions it asks", false),
    ("totals", "how much of this computer it uses", false),
];

/// Which parts of the Hub page's review say something other than the files, in plain words, most
/// consequential first.
///
/// An empty list means they agree **or** that there was nothing to compare — [`differs`] draws the
/// same distinction and the caller has to say which, since reading "no differences" as "the page
/// was checked" is the mistake this exists to prevent.
pub fn differences(local: &Value, page: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let Some(fields) = page.as_object().filter(|page| !page.is_empty()) else { return found };
    let page_format = fields.get("format").and_then(Value::as_u64).unwrap_or(FORMAT);
    let local_format = local["format"].as_u64().unwrap_or(FORMAT);
    if !matches!(page_format, 1 | 2) || !matches!(local_format, 1 | 2) {
        return found;
    }
    let both_v2 = page_format == 2 && local_format == 2;
    // The same projections `differs` uses, so the two can never disagree about whether there is
    // something to show: a reworded description is not a difference, a changed grant is.
    let (mine, theirs) = (essentials(local), essentials(page));
    let (mine_2, theirs_2) = (format_2_essentials(local), format_2_essentials(page));
    for (key, what, only_v2) in COMPARED {
        let differs = if *only_v2 {
            both_v2 && mine_2[key] != theirs_2[key]
        } else {
            mine[key] != theirs[key]
        };
        if differs {
            found.push((*what).to_owned());
        }
    }
    found
}

/// Whether the Hub page's review says something other than the files, in the parts that matter.
/// A page in format 1 or 2 is compared on the parts both formats write, so an older page never
/// hides a grant; when both are format 2, on the format 2 parts too. A page without a review, or
/// with one in a format this Yougori does not know, is not compared.
pub fn differs(local: &Value, page: &Value) -> bool {
    let Some(fields) = page.as_object().filter(|page| !page.is_empty()) else { return false };
    let page_format = fields.get("format").and_then(Value::as_u64).unwrap_or(FORMAT);
    let local_format = local["format"].as_u64().unwrap_or(FORMAT);
    if !matches!(page_format, 1 | 2) || !matches!(local_format, 1 | 2) {
        return false;
    }
    if essentials(local) != essentials(page) {
        return true;
    }
    page_format == 2 && local_format == 2 && format_2_essentials(local) != format_2_essentials(page)
}

/// What this computer has, for the requirement checks.
#[derive(Clone, Debug, Default)]
pub struct Host {
    pub version: String,
    pub platform: String,
    /// Whether an NVIDIA GPU is usable; `None` when that could not be read.
    pub gpu: Option<bool>,
    pub memory_gb: Option<f64>,
    pub free_disk_gb: Option<f64>,
}

impl Host {
    pub fn here() -> Host {
        Host { version: env!("CARGO_PKG_VERSION").into(), platform: crate::update::platform().into(), ..Default::default() }
    }
}

/// The outcome of the requirement checks.
#[derive(Debug, Default, PartialEq)]
pub struct Requirements {
    /// Reasons nothing can be created on this computer.
    pub stops: Vec<String>,
    /// The GPU is missing but optional: the person may run without it.
    pub without_gpu: bool,
    /// Things to know before saying yes.
    pub notes: Vec<String>,
}

/// Checks the Yougori version, the platform, the GPU and the totals before anything is created.
/// `tools` are the checked files of the template's Hub tools.
pub fn requirements(folder: &Folder, tools: &BTreeMap<String, Tool>, review: &Value, host: &Host) -> Requirements {
    let mut found = Requirements::default();
    if let Some(needed) = folder.template.requires.yougori.as_deref() {
        if super::refs::newer(needed, &host.version) {
            found.stops.push(format!("This template needs Yougori {needed} or newer. Update with yougori update."));
        }
    }
    let platforms = &folder.template.requires.platforms;
    if !platforms.is_empty() && !platforms.contains(&host.platform) {
        found.stops.push(format!("This template runs on {} only; this computer is {}.", platforms.join(", "), host.platform));
    }
    let tool_gpu = folder.tools.iter().filter_map(|use_| match &use_.source {
        Source::Bundled { tool, .. } => Some((tool.name().to_owned(), tool.gpu().to_owned())),
        Source::Hub(reference) => tools.get(&reference.item()).map(|tool| (reference.item(), tool.gpu().to_owned())),
        Source::BuiltIn(_) => None,
    }).find(|(_, gpu)| gpu == "required");
    let gpu = folder.gpu();
    if host.gpu == Some(false) {
        match (gpu, &tool_gpu) {
            ("optional", _) => found.without_gpu = true,
            ("required", _) => found.stops.push("This template needs an NVIDIA GPU, and this computer has none that Yougori can use. Run it on a computer with an NVIDIA GPU.".into()),
            (_, Some((tool, _))) => found.stops.push(format!("The tool {tool} needs an NVIDIA GPU, and this computer has none that Yougori can use.")),
            _ => {}
        }
    }
    let totals = &review["totals"];
    if let (Some(needed), Some(has)) = (totals["memoryGb"].as_f64(), host.memory_gb) {
        if needed > has {
            found.notes.push(format!("Together the sandboxes may use up to {} GB of memory; this computer has {} GB. They can still run, more slowly, if they are not all busy.", number(needed), number(has.floor())));
        }
    }
    if let (Some(needed), Some(free)) = (totals["storageGb"].as_f64(), host.free_disk_gb) {
        if needed > free {
            found.notes.push(format!("Together the sandboxes may use up to {} GB of disk as they grow; {} GB is free on their drive now.", number(needed), number(free.floor())));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::scan::Files;

    fn files(entries: &[(&str, &str)]) -> Files {
        entries.iter().map(|(path, text)| (path.to_string(), text.as_bytes().to_vec())).collect()
    }

    const TEMPLATE: &str = "name: shop\nsummary: A shop.\nversion: 1.0.0\nlicense: MIT\nrequires: {yougori: 1.0.0}\ninputs:\n  - {id: access, question: Where?, type: choice, choices: [{value: quick, label: Quick}, {value: none, label: Nowhere}], default: quick}\n  - {id: key, question: Key?, type: secret, required: false}\ntools:\n  web: [codex, tools/gateway]\npublic:\n  - {environment: web, port: 3000, access: \"{{inputs.access}}\"}\nsteps:\n  - {title: Sign in, command: \"yougori codex --environment {{env.web}}\"}\n";
    const PROJECT: &str = "project: shop\nenvironments:\n  web:\n    image: node:24\n    cpu: 2\n    memory: 4GB\n    storage: 20\n    ports: [\"3000:3000\"]\n    secrets: {OPENAI_API_KEY: \"{{secrets.key}}\"}\n    permissions: {pc: true, edit: true}\n    volumes: [{source: ./data, target: /data, bind: true}]\n  db:\n    image: postgres:17\n    cpu: 1.5\n    memory: 512MB\n    storage: 10\n    internet: false\nconnections: [web -> db]\n";
    const GATEWAY: &str = "name: gateway\nsummary: A gateway.\nversion: 0.2.0\nlicense: MIT\ncommand: gateway\ninstall: [\"curl -fsSL https://get.example.org/install.sh | sh\", \"npm install -g gateway@1.0.0\", \"apt-get install -y jq\"]\ncheck: gateway --version\n";

    fn checked() -> Folder {
        format::template(&files(&[
            (format::TEMPLATE_FILE, TEMPLATE),
            ("yougori.yaml", PROJECT),
            ("data/.keep", ""),
            ("tools/gateway/yougori-tool.yaml", GATEWAY),
        ])).unwrap_or_else(|p| panic!("{}", p.join("\n")))
    }

    #[test]
    fn the_review_lists_sandboxes_totals_access_tools_and_questions() {
        let notices = vec!["The files contain a wallet address (app.js). Hub templates are free and never pay their creator.".to_owned()];
        let review = template(&checked(), &notices, &BTreeMap::new());
        assert_eq!(review["totals"], json!({"environments": 2, "cpu": 3.5, "memoryGb": 4.5, "storageGb": 30, "gpu": "none"}));
        let web = &review["environments"][1];
        assert_eq!(web["name"], "web");
        assert_eq!(web["cpu"], json!(2));
        assert_eq!(web["ports"], json!([3000]));
        assert_eq!(web["tools"], json!(["codex", "gateway"]));
        assert_eq!(web["secrets"], json!(["OPENAI_API_KEY"]));
        assert_eq!(web["writablePcFolders"], true);
        assert_eq!(review["environments"][0]["internet"], false);
        assert_eq!(review["public"], json!([{"environment": "web", "port": 3000, "access": "asked", "input": "access"}]));
        assert_eq!(review["connections"], json!([{"from": "web", "to": "db"}]));
        assert_eq!(review["tools"][0], json!({"name": "codex", "source": "built-in", "environment": "web"}));
        assert_eq!(review["tools"][1]["downloads"], json!(["https://get.example.org/install.sh", "https://registry.npmjs.org", "the image's package mirrors (apt)"]));
        assert_eq!(review["inputs"][1], json!({"id": "key", "question": "Key?", "type": "secret", "secret": true, "required": false}));
        assert_eq!(review["steps"], json!(["Sign in"]));
        assert_eq!(review["pcAccess"], json!([{"path": "./data", "target": "/data", "readOnly": false, "environment": "web"}]));
        let warnings: Vec<&str> = review["warnings"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(warnings, [
            "web can change files in ./data on this computer.",
            "Makes web:3000 reachable from the internet.",
            "Installs software from https://get.example.org/install.sh.",
            "Installs software from https://registry.npmjs.org.",
            "Installs software from the image's package mirrors (apt).",
            notices[0].as_str(),
        ]);
        assert_eq!(review["requires"], json!({"yougori": "1.0.0", "gpu": "none", "platforms": []}));
        assert!(!differs(&review, &review.clone()));
        assert!(!differs(&review, &json!({})), "a page without a review is not a difference");
        let mut faked = review.clone();
        faked["warnings"] = json!([]);
        assert!(differs(&review, &faked));
        let mut hidden_download = review.clone();
        hidden_download["tools"][1]["commands"] = json!(["npm install -g gateway@1.0.0"]);
        assert!(differs(&review, &hidden_download), "an install line that differs is a difference");
        let mut reworded = review.clone();
        reworded["steps"] = json!(["Sign in to the shop"]);
        reworded["requires"]["platforms"] = json!(["linux-x86_64"]);
        assert!(!differs(&review, &reworded), "parts that do not change what runs are not compared");
        let mut newer = faked.clone();
        newer["format"] = json!(FORMAT + 1);
        assert!(differs(&review, &newer), "a format 2 page is compared on the parts both formats write");
        let mut unknown = faked.clone();
        unknown["format"] = json!(FORMAT + 2);
        assert!(!differs(&review, &unknown), "a review in a format this Yougori does not know is not compared part by part");
        let mut grouped = review.clone();
        grouped["format"] = json!(2);
        grouped["inputs"][0]["group"] = json!("website_api");
        grouped["resources"] = json!([]);
        assert!(!differs(&review, &grouped), "a format 2 page with the same grants is the same review");
        assert_eq!(review["format"], FORMAT);
        assert_eq!(shape_problem(&review), None, "the website accepts the review as it is");
    }

    #[test]
    fn a_page_that_promises_something_other_than_the_files_says_which_parts_differ() {
        let review = template(&checked(), &[], &BTreeMap::new());

        // Agreement is an empty list — and so is a page there was nothing to compare with. The
        // two mean opposite things, which is why the caller has to say which happened and cannot
        // read an empty list as "checked, and fine".
        assert!(differences(&review, &review.clone()).is_empty());
        assert!(differences(&review, &json!({})).is_empty());

        // A page that leaves out what the setup may do.
        let mut quiet = review.clone();
        quiet["warnings"] = json!([]);
        assert_eq!(differences(&review, &quiet), ["what it is allowed to do"]);

        // More than one, in the order a person needs to hear them, not the order they were found.
        let mut several = review.clone();
        several["warnings"] = json!([]);
        several["pcAccess"] = json!([]);
        assert_eq!(
            differences(&review, &several),
            ["the folders on this computer it reaches", "what it is allowed to do"],
        );

        // Wording that changes nothing about what runs is not a difference, here as in `differs`.
        let mut reworded = review.clone();
        reworded["steps"] = json!(["Sign in to the shop"]);
        assert!(differences(&review, &reworded).is_empty());

        // The format 2 parts: the grants, and the money.
        let mut mine = review.clone();
        mine["format"] = json!(2);
        mine["costs"] = json!(["A rented GPU is charged by the hour while this runs."]);
        mine["capabilities"] = json!([{"id": "grid.create", "selection": "required", "locked": false}]);
        let mut free = mine.clone();
        free["costs"] = json!([]);
        assert_eq!(differences(&mine, &free), ["what it may cost"], "a page saying a paid setup is free");
        let mut ungranted = mine.clone();
        ungranted["capabilities"] = json!([]);
        assert_eq!(differences(&mine, &ungranted), ["what it turns on"]);

        // `differences` and `differs` are the same question asked two ways; they must never
        // disagree, or a run would warn with nothing to show or show nothing while warning.
        for page in [&quiet, &several, &reworded, &free, &ungranted, &review.clone(), &json!({})] {
            assert_eq!(
                differs(&mine, page),
                !differences(&mine, page).is_empty(),
                "differs and differences disagree about {page}",
            );
        }
    }

    #[test]
    fn conditional_tools_keep_all_rules_in_a_publishable_review() {
        let mut folder = checked();
        let tool = &mut folder.tools[0];
        tool.when = vec![format::Condition { input: "providers".into(), values: vec!["codex".into()], contains: true }];
        tool.signin = true;
        tool.signin_when = vec![format::Condition { input: "access".into(), values: vec!["subscription".into(), "both".into()], contains: false }];
        tool.signin_source = Some("signin_source".into());
        let review = template(&folder, &[], &BTreeMap::new());
        assert_eq!(shape_problem(&review), None);
        assert_eq!(review["tools"][0]["when"], json!(["providers contains any of [\"codex\"]"]));
        assert_eq!(review["tools"][0]["signinWhen"], json!(["access is one of [\"subscription\",\"both\"]"]));
        assert_eq!(review["tools"][0]["signinSource"], "signin_source");
        folder.tools[0].signin_when[0].values.pop();
        assert!(differs(&review, &template(&folder, &[], &BTreeMap::new())), "changed sign-in conditions must still be detected");
    }

    #[test]
    fn template_text_never_brings_hidden_or_control_characters_into_the_review() {
        assert_eq!(plain("postgres:17\u{202e}\u{7}\ttab\nline"), "postgres:17\ttab\nline");
        let review = template(&checked(), &[format!("{}\u{200b}", "w".repeat(5000))], &BTreeMap::new());
        let last = review["warnings"].as_array().unwrap().last().unwrap().as_str().unwrap();
        assert_eq!(unicode::utf16_len(last), TEXT_MAX);
        assert!(last.ends_with('…') && !last.contains('\u{200b}'));
        assert_eq!(shape_problem(&review), None);
        assert!(shape_problem(&json!({"environments": [{"x": [{"y": [1]}]}]})).unwrap().contains("nested too deeply at environments[0].x[0].y"));
        assert!(shape_problem(&json!({"steps": [{"title": "x"}]})).unwrap().contains("steps in a form the Hub does not accept"));
        assert!(shape_problem(&json!({"warnings": ["a\u{1b}[2J"]})).unwrap().contains("characters that cannot be shown at warnings[0]"));
        assert_eq!(shape_problem(&json!({"warnings": ["tab\tand\nline"], "service": null})), None);
    }

    #[test]
    fn installer_addresses_are_found_per_line() {
        let lines = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(downloads(&lines(&["python3 -m pip install --user aider-chat==0.86.1"])), ["https://pypi.org"]);
        assert_eq!(downloads(&lines(&["pip install https://files.example.com/pkg.whl"])), ["https://files.example.com/pkg.whl"]);
        assert_eq!(downloads(&lines(&["wget -qO- 'https://a.example/x.sh'; echo done"])), ["https://a.example/x.sh"]);
        assert_eq!(downloads(&lines(&["curl -fsSL \"$URL\" | sh"])), ["an address chosen when the line runs"]);
        assert!(downloads(&lines(&["mkdir -p ~/.local/bin", "echo hi"])).is_empty());
    }

    #[test]
    fn requirements_check_version_platform_gpu_and_totals() {
        let folder = checked();
        let review = template(&folder, &[], &BTreeMap::new());
        let host = Host { version: "1.1.0".into(), platform: "windows-x86_64".into(), gpu: Some(false), memory_gb: Some(4.0), free_disk_gb: Some(12.0) };
        let found = requirements(&folder, &BTreeMap::new(), &review, &host);
        assert!(found.stops.is_empty() && !found.without_gpu);
        assert_eq!(found.notes.len(), 2, "{:?}", found.notes);
        assert!(found.notes[0].contains("up to 4.5 GB of memory; this computer has 4 GB"));
        assert!(found.notes[1].contains("up to 30 GB of disk as they grow; 12 GB is free on their drive"));
        let mut old = folder.clone();
        old.template.requires.yougori = Some("1.3.0".into());
        old.template.requires.platforms = vec!["linux-x86_64".into()];
        let stops = requirements(&old, &BTreeMap::new(), &review, &host).stops;
        assert_eq!(stops[0], "This template needs Yougori 1.3.0 or newer. Update with yougori update.");
        assert_eq!(stops[1], "This template runs on linux-x86_64 only; this computer is windows-x86_64.");
        let mut gpu = folder.clone();
        gpu.template.requires.gpu = Some("optional".into());
        assert!(requirements(&gpu, &BTreeMap::new(), &review, &host).without_gpu);
        gpu.template.requires.gpu = Some("required".into());
        assert!(requirements(&gpu, &BTreeMap::new(), &review, &host).stops[0].contains("needs an NVIDIA GPU"));
        assert!(requirements(&gpu, &BTreeMap::new(), &review, &Host { gpu: Some(true), ..host.clone() }).stops.is_empty());
        assert!(requirements(&gpu, &BTreeMap::new(), &review, &Host { gpu: None, ..host.clone() }).stops.is_empty(), "an unknown GPU is not a missing one");
    }

    #[test]
    fn a_hub_tool_that_needs_a_gpu_stops_at_requirements() {
        let template = TEMPLATE.replace("[codex, tools/gateway]", "[hub/acme/trainer@1.0.0]");
        let folder = format::template(&files(&[(format::TEMPLATE_FILE, &template), ("yougori.yaml", PROJECT), ("data/.keep", "")])).unwrap();
        let review = super::template(&folder, &[], &BTreeMap::new());
        assert!(review["warnings"].as_array().unwrap().iter().any(|w| w == "Installs the Hub tool acme/trainer; its files are checked when it runs."));
        let trainer = format::tool(&files(&[(format::TOOL_FILE, "name: trainer\nsummary: Trains.\nversion: 1.0.0\nlicense: MIT\ncommand: train\ncheck: train --version\nneeds: {gpu: required}\n")]), "").unwrap();
        let tools = BTreeMap::from([("acme/trainer".to_owned(), trainer)]);
        let host = Host { version: "1.1.0".into(), platform: "linux-x86_64".into(), gpu: Some(false), ..Default::default() };
        let stops = requirements(&folder, &tools, &review, &host).stops;
        assert_eq!(stops, ["The tool acme/trainer needs an NVIDIA GPU, and this computer has none that Yougori can use."]);
        let resolved = super::template(&folder, &[], &tools);
        assert_eq!(resolved["tools"][0]["version"], "1.0.0");
    }

    /// PROVES a tool file's review shows what the tool declares it reaches, in the engine's words
    /// for a declaration (the tool's own word, never a grant), and that the installer's view of
    /// the same tool shows the same review without it.
    #[test]
    fn a_tool_files_review_shows_its_declared_access_as_the_tools_own_word() {
        let text = "name: httpie\nsummary: A command-line HTTP client.\nversion: 1.0.0\nlicense: MIT\ncommand: http\ninstall: [python3 -m pip install --user httpie==3.2.4]\ncheck: http --version\nsignin: {method: api-key, variable: HTTPIE_TOKEN}\naccess: {internet: true, folders: [/workspace/.httpie]}\ninputs: [{name: HTTPIE_TOKEN, secret: true}, {name: HTTPIE_CONFIG_DIR}]\noutputs: [{name: report, path: /workspace/report.json}]\n";
        let file = format::tool_file(&files(&[(format::TOOL_FILE, text)]), "").unwrap_or_else(|p| panic!("{}", p.join(" ")));
        let review = tool_file(&file, &["A wallet address is in the files.".into()]);
        let entry = &review["tools"][0];
        assert_eq!(entry["access"], json!(["uses the internet", "writes /workspace/.httpie", "reads the secret HTTPIE_TOKEN", "reads HTTPIE_CONFIG_DIR"]));
        assert_eq!(entry["inputs"], json!(["HTTPIE_TOKEN", "HTTPIE_CONFIG_DIR"]));
        assert_eq!(entry["outputs"], json!(["report"]));
        let warnings: Vec<&str> = review["warnings"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(warnings, [
            "Installs software from https://pypi.org.",
            "A wallet address is in the files.",
            "httpie says it uses the internet, writes /workspace/.httpie, reads the secret HTTPIE_TOKEN, reads HTTPIE_CONFIG_DIR. That is the tool's own word: a sandbox has only what its own settings and your answers give it.",
        ]);
        // The installer's view says nothing about access, and everything else is the same.
        let mut plain = tool(&Tool::from(&file), &["A wallet address is in the files.".into()]);
        assert!(plain["tools"][0].get("access").is_none() && plain["tools"][0].get("inputs").is_none());
        plain["tools"][0]["access"] = entry["access"].clone();
        plain["tools"][0]["inputs"] = entry["inputs"].clone();
        plain["tools"][0]["outputs"] = entry["outputs"].clone();
        plain["warnings"].as_array_mut().unwrap().push(json!(warnings[2]));
        assert_eq!(plain, review);
        // A file that declares nothing reviews exactly as its view does.
        let silent = format::tool_file(&files(&[(format::TOOL_FILE, text.split("access:").next().unwrap())]), "").unwrap();
        assert_eq!(tool_file(&silent, &[]), tool(&Tool::from(&silent), &[]));
    }
}
