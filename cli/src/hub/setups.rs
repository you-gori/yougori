//! The template platform commands that speak to the shared setup engine: the capability catalogue,
//! and the setup lifecycle (`plan`, `configure`, `start`, `stop`, `logs`, `join`, `export`).
//!
//! The catalogue is read straight from the shared registry (`yougori_setup::capability`), so the CLI
//! and the desktop show the same capabilities with the same words. The lifecycle commands call the
//! engine methods (`setup_plan`, `setup_apply`, `setup_list`, `setup_get`, `setup_operation`,
//! `setup_cancel`, `setup_action`); an engine older than this CLI answers "unknown method", which the
//! client turns into a calm "update Yougori" message. Nothing here fakes success, and a `--dry-run`
//! never creates anything.

use serde_json::{json, Value};
use yougori_setup::capability::{self, Availability, Group};

use crate::cli_ui as ui;
use crate::public;
use super::views;

// ---- Trusted short-name alias catalogue (plan 16.3; design only, no behaviour yet) ----
//
// A person may type a short natural name — "my api", "sandbox grid" — and have it resolve to a
// template. Plan 16.3 and architecture invariant 17 are strict about how: a short name resolves ONLY
// through this explicit first-party alias table, never by fuzzy matching an image name and never by
// picking a community publisher. An ambiguous or unknown short name produces choices or a plain "not
// found", never a guess.
//
// The publisher is the first party's own reserved name, which the Hub will not give to anyone else
// (`refs::reserved`), so an entry here cannot resolve to an account someone else claimed. A short
// name is read only after a Hub address and after a folder on this computer, and a name that is
// both a folder here and a short name is never guessed between — `run::wanted` says so and asks.
//
// This is not the search-word → recipe/group table in `capability::ALIASES` (that steers the catalogue
// UI). This table maps a short name to a concrete publishable template `PUBLISHER/NAME`, for `run`
// and `plan` to accept "my api" as a reference once first-party templates exist.

/// One trusted short name and the first-party template `NAME` it resolves to. The publisher is
/// supplied separately by [`trusted_publisher`], so no entry hard-codes an account.
struct TrustedAlias {
    /// The short name a person types, lowercase.
    term: &'static str,
    /// The first-party template name, under the trusted publisher.
    template: &'static str,
}

/// The draft table. Names are stable; the publisher is filled in at publication. Add an entry only
/// for a template the first party actually publishes.
const TRUSTED_ALIASES: &[TrustedAlias] = &[
    TrustedAlias { term: "my api", template: "my-api" },
    TrustedAlias { term: "sandbox grid", template: "sandbox-grid" },
    TrustedAlias { term: "neo grid", template: "neo-grid" },
    TrustedAlias { term: "access grid", template: "access-grid" },
    TrustedAlias { term: "swarm mining grid", template: "swarm-mining-grid" },
];

/// The first-party publisher these aliases resolve under. It is safe to name here because the Hub
/// keeps it for the owner: [`super::refs::reserved`] refuses it, and every look-alike spelling of
/// it, to anyone else — so a short name can never land on a community account that took the name.
fn trusted_publisher() -> Option<&'static str> {
    Some("yougori")
}

/// A typed short name in the one spelling the table is written in: trimmed, lowercase, and with
/// runs of spaces closed up. Only spacing and case are forgiven. Hyphens and underscores are not,
/// so a one-word name such as `my-api` — which is also how people name images and folders — is
/// never a short name; [`alias_hint`] offers it as a suggestion instead.
fn short_name(typed: &str) -> String {
    typed.split_whitespace().map(str::to_lowercase).collect::<Vec<_>>().join(" ")
}

/// Resolve a short natural name to a trusted `hub/PUBLISHER/NAME` reference, or `None` for anything
/// this table does not name exactly. Never a fuzzy match, and never a community publisher: the only
/// references it can ever produce are the first party's own, from the fixed list above.
pub(super) fn resolve_alias(name: &str) -> Option<String> {
    let publisher = trusted_publisher()?;
    let typed = short_name(name);
    TRUSTED_ALIASES
        .iter()
        .find(|alias| alias.term == typed)
        .map(|alias| format!("hub/{}/{}", publisher, alias.template))
}

/// What someone probably meant when a name resolves to nothing: `my-api` or `my_api` for the
/// template called "my api". Only ever used to add a sentence to a refusal — it never resolves
/// anything by itself, so a hyphenated name cannot quietly stand in for an image or a folder.
pub(super) fn alias_hint(name: &str) -> Option<&'static str> {
    let spaced = name.replace(['-', '_'], " ");
    let typed = short_name(&spaced);
    TRUSTED_ALIASES.iter().find(|alias| alias.term == typed).map(|alias| alias.term)
}

/// The short word a person types for a group (`--group grid`), or its id; `None` for a display
/// name, which is not a name for a group. The words are the shared registry's (`Group::key`), the
/// same table the desktop reads through its generated client table.
fn group_from_word(word: &str) -> Option<Group> {
    Group::from_word(word)
}

/// Per-capability availability from the engine's `setup_capabilities`, keyed by capability id. The
/// engine builds this from the real host it knows (runtimes, providers, GPU), so it is authoritative.
/// Returns `None` when the engine is not running — then the catalogue still lists everything, and only
/// the host-independent Planned state is shown.
async fn engine_availability() -> Option<std::collections::BTreeMap<String, Value>> {
    let result = public::call("setup_capabilities", json!({})).await.ok()?;
    let mut by_id = std::collections::BTreeMap::new();
    for entry in result["capabilities"].as_array().into_iter().flatten() {
        if let Some(id) = entry["id"].as_str() {
            by_id.insert(id.to_owned(), entry.clone());
        }
    }
    Some(by_id)
}

/// `yougori template capabilities [--group WORD]`: the capability catalogue, read from the registry so
/// it lists everything even with no engine running. Availability comes from the engine's
/// `setup_capabilities` (authoritative per this computer) when the engine is up; a Planned capability
/// always reads Planned, because that is host-independent and never enableable.
pub async fn capabilities(group_filter: Option<&str>) -> Result<Value, String> {
    let only = match group_filter {
        None => None,
        Some(word) => Some(group_from_word(word).ok_or_else(|| {
            format!(
                "--group takes one of: {}.",
                Group::ALL.iter().map(|group| group.key()).collect::<Vec<_>>().join(", ")
            )
        })?),
    };
    let from_engine = engine_availability().await;
    let engine_known = from_engine.is_some();

    let mut groups = Vec::new();
    for group in Group::ALL {
        if only.is_some_and(|wanted| wanted != group) {
            continue;
        }
        let mut caps = Vec::new();
        for cap in capability::group(group) {
            // Planned is host-independent and never enableable, so it is always shown as planned,
            // whether or not the engine is running. For anything else, the engine's report is the
            // truth about this computer; with no engine, availability is left unstated (never null
            // text, never "shipped" dressed up as available).
            let planned = matches!(cap.status, capability::Status::Planned);
            let engine_entry = from_engine.as_ref().and_then(|map| map.get(cap.id));
            let (availability, reason): (Option<String>, Option<String>) = if planned {
                (Some("planned".to_owned()), Some("This capability is planned and cannot be enabled yet.".to_owned()))
            } else if let Some(entry) = engine_entry {
                (
                    entry["availability"].as_str().map(str::to_owned),
                    entry["reason"].as_str().map(str::to_owned),
                )
            } else {
                (None, None)
            };
            caps.push(json!({
                "id": cap.id,
                "name": cap.name,
                "summary": cap.summary,
                "examples": cap.examples,
                "availability": availability,
                "availabilityText": availability_text(availability.as_deref()),
                "reason": reason,
                "profiles": cap.profiles.iter().map(|p| p.id()).collect::<Vec<_>>(),
            }));
        }
        groups.push(json!({
            "id": group.id(),
            "name": group.name(),
            "capabilities": caps,
        }));
    }

    Ok(json!({
        "groups": groups,
        "availabilityKnown": engine_known,
    }))
}

/// The words for an availability code (the registry's, the same the desktop shows), or `None` when
/// availability is unknown (no engine) or the code is not one of the four.
fn availability_text(code: Option<&str>) -> Option<&'static str> {
    match code.and_then(Availability::parse) {
        Some(availability) => Some(availability.words()),
        _ => None,
    }
}

/// The text view of the catalogue: six groups, each capability with its availability in calm words.
pub fn capabilities_view(value: &Value) -> String {
    let mut lines = Vec::new();
    if value["availabilityKnown"] != true {
        lines.push("Availability on this computer is shown once Yougori is running (yougori app start). Planned capabilities are marked.".to_owned());
        lines.push(String::new());
    }
    for group in value["groups"].as_array().into_iter().flatten() {
        lines.push(group["name"].as_str().unwrap_or_default().to_owned());
        for cap in group["capabilities"].as_array().into_iter().flatten() {
            let name = cap["name"].as_str().unwrap_or_default();
            let state = cap["availabilityText"].as_str();
            let summary = cap["summary"].as_str().unwrap_or_default();
            match state {
                Some(state) => lines.push(format!("  {name} — {state}")),
                None => lines.push(format!("  {name}")),
            }
            lines.push(format!("      {summary}"));
            if let Some(reason) = cap["reason"].as_str() {
                lines.push(format!("      {reason}"));
            }
        }
        lines.push(String::new());
    }
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines.join("\n")
}

// ---- The engine-backed lifecycle commands ----
//
// Each calls an engine method whose name equals the Tauri command name (snake_case). The client
// turns an older engine's "unknown method" into a calm "update Yougori" message, as long as the
// method is listed in catalog.rs — which it is. Nothing here fakes success.

/// A source reference (`SourceRef`) from what the person typed: a Hub ref, a local folder, or an
/// installed setup id. The engine resolves and validates it; the CLI only shapes it.
fn source_ref(text: &str) -> Result<Value, String> {
    // A Hub address or an existing folder is resolved the same way `template run` resolves one, so a
    // Hub URL, `hub/PUBLISHER/NAME[@VERSION]` and a real folder are each classified correctly and the
    // ref is validated. Only when it is neither — a bare name, not a folder that exists — is it taken
    // as an installed setup id, which the engine resolves (or rejects) by name.
    let website = crate::hub::client::website();
    if text.starts_with("hub/") || crate::hub::refs::looks_like_ref(text, &website) || text.contains("yougori.com/hub/") {
        let reference = crate::hub::refs::parse(text, &website)?;
        let mut source = json!({
            "kind": "hub",
            "publisher": reference.publisher,
            "name": reference.name,
        });
        // A pinned field carries the asked-for version only; an unpinned ref omits it rather than
        // sending a literal "latest", so the engine (not the CLI) decides the current version.
        if let Some(version) = &reference.version {
            source["version"] = json!(version);
        }
        return Ok(source);
    }
    let path = std::path::Path::new(text);
    if path.is_dir() {
        let folder = path.canonicalize().map_err(|e| format!("Cannot open the folder {text}: {e}"))?;
        return Ok(json!({ "kind": "local_folder", "path": folder.to_string_lossy() }));
    }
    // A path that was clearly meant as a folder (it has a separator or starts with ./ or ../) but does
    // not exist is an error, not a setup id — otherwise a typo'd path would be sent to the engine as a
    // name. A bare word is treated as an installed setup id.
    if text.contains('/') || text.contains('\\') || text.starts_with('.') {
        return Err(format!(
            "There is no folder {}. Use hub/PUBLISHER/NAME, a folder with a yougori-template.yaml, or an installed setup's name.",
            crate::hub::scan::shown(text)
        ));
    }
    Ok(json!({ "kind": "installed_setup", "setupId": text }))
}

/// Public answers from `--input ID=VALUE` pairs, as the engine's `PlanRequest.answers` expects.
/// Values are parsed as JSON when they look like it (a number, true/false, a list), else kept as a
/// string, so `--input port=8080` and `--input name=app` both do the right thing.
fn answers(pairs: &[(String, String)]) -> Vec<Value> {
    pairs
        .iter()
        .map(|(field, raw)| {
            let value = serde_json::from_str::<Value>(raw).unwrap_or_else(|_| Value::String(raw.clone()));
            json!({ "field": field, "value": value })
        })
        .collect()
}

/// Render a v2 plan review (`plan::Review`) as calm text lines. The v1 `views::any_review` does not
/// understand this shape, so this reads the fields the v2 planner fills: what the setup creates and
/// borrows, downloads, permissions, costs, warnings and the totals.
pub fn review_lines(review: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let list = |key: &str| review[key].as_array().cloned().unwrap_or_default();

    let items = |key: &str| {
        list(key)
            .iter()
            .map(|item| {
                let title = item["title"].as_str().unwrap_or("");
                let placement = item["placement"].as_str().unwrap_or("");
                if placement.is_empty() { format!("  - {title}") } else { format!("  - {title} — {placement}") }
            })
            .collect::<Vec<_>>()
    };

    let creates = items("creates");
    if !creates.is_empty() {
        lines.push("Creates:".to_owned());
        lines.extend(creates);
    }
    let borrows = items("borrows");
    if !borrows.is_empty() {
        lines.push("Attaches (never destroyed):".to_owned());
        lines.extend(borrows);
    }
    let downloads: Vec<String> = list("downloads")
        .iter()
        .filter_map(|d| d["name"].as_str().map(|n| format!("  - {n}")))
        .collect();
    if !downloads.is_empty() {
        lines.push("Downloads:".to_owned());
        lines.extend(downloads);
    }
    // Every line a tool runs in its sandbox, as it will run. They come from the template's or a
    // Hub tool's files, so each is shown cleaned of anything that could disguise it.
    let limits = list("limits");
    if !limits.is_empty() {
        lines.push("Limits:".to_owned());
        lines.extend(limits.iter().map(|limit| format!("  - {}", views::clean(limit.as_str().unwrap_or_default()))));
    }
    let installs = list("installs");
    if !installs.is_empty() {
        lines.push("Installs:".to_owned());
        for install in &installs {
            let said = |value: &Value| views::clean(value.as_str().unwrap_or_default());
            lines.push(format!("  - {} in {}", said(&install["tool"]), said(&install["resource"])));
            let commands = install["commands"].as_array().cloned().unwrap_or_default();
            if commands.is_empty() {
                lines.push("      nothing (its check must already pass)".to_owned());
            }
            lines.extend(commands.iter().map(|command| format!("      $ {}", said(command))));
            if install["check"].is_string() {
                lines.push(format!("      check: $ {}", said(&install["check"])));
            }
        }
    }
    for (key, heading) in [("permissions", "Allowed to:"), ("costs", "Costs:"), ("notes", "Notes:")] {
        let values: Vec<String> = list(key).iter().filter_map(|v| v.as_str().map(|s| format!("  - {s}"))).collect();
        if !values.is_empty() {
            lines.push(heading.to_owned());
            lines.extend(values);
        }
    }
    // Warnings last and clearly marked.
    let warnings: Vec<String> = list("warnings").iter().filter_map(|v| v.as_str().map(|s| format!("  ! {s}"))).collect();
    if !warnings.is_empty() {
        lines.push("Warnings:".to_owned());
        lines.extend(warnings);
    }
    let totals = &review["totals"];
    if totals.is_object() && totals["environments"].as_u64().unwrap_or(0) > 0 {
        lines.push(format!(
            "Totals: {} environment(s), {} CPU, {} GB memory, {} GB storage.",
            totals["environments"].as_u64().unwrap_or(0),
            totals["cpu"].as_f64().unwrap_or(0.0),
            totals["memoryGb"].as_f64().unwrap_or(0.0),
            totals["storageGb"].as_f64().unwrap_or(0.0),
        ));
    }
    if lines.is_empty() {
        lines.push("This plan makes no changes.".to_owned());
    }
    lines
}

/// The public answers for a plan: `--input ID=VALUE` pairs merged with an optional `--inputs FILE`
/// JSON object. The engine validates them, so the CLI does not reject unknown fields here; it only
/// refuses a secret-looking value in a plain inputs file (secrets belong on stdin).
async fn merged_answers(inputs: &[(String, String)], inputs_file: Option<&str>) -> Result<Vec<Value>, String> {
    let mut out = answers(inputs);
    if let Some(path) = inputs_file {
        let bytes = super::run::read_file_limited(path, "the --inputs file").await?;
        let trimmed = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
        let value: Value = serde_json::from_slice(trimmed)
            .map_err(|e| format!("The --inputs file is not a JSON object ({e})."))?;
        let object = value.as_object().ok_or("The --inputs file must be a JSON object such as {\"access\": \"quick\"}.")?;
        for (field, value) in object {
            // A --input ID=VALUE on the command line overrides the file for the same field.
            if !out.iter().any(|a| a["field"] == json!(field)) {
                out.push(json!({ "field": field, "value": value }));
            }
        }
    }
    Ok(out)
}

/// Build `plan::Answers` from the CLI's input pairs, an optional inputs file and `--binding` pairs.
/// Public answers go to `inputs`; `capabilities.<id>` toggles go to `capabilities`; installation-time
/// bindings (a folder, drive, file, or `SETUP/RESOURCE`) go to `bindings`. Secrets never arrive here
/// (a plan carries references only), so `secrets` stays empty for a package plan.
async fn plan_answers(
    inputs: &[(String, String)],
    inputs_file: Option<&str>,
    bindings: &[(String, String)],
) -> Result<yougori_setup::plan::Answers, String> {
    let mut answers = yougori_setup::plan::Answers::default();
    let mut put = |field: &str, value: &Value| {
        if let Some(rest) = field.strip_prefix("capabilities.") {
            if let Some(on) = value.as_bool() {
                answers.capabilities.insert(rest.to_owned(), on);
                return;
            }
        }
        // Everything else is a public input, as text (the planner coerces types).
        let text = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
        answers.inputs.insert(field.to_owned(), text);
    };
    for entry in merged_answers(inputs, inputs_file).await? {
        if let (Some(field), value) = (entry["field"].as_str(), &entry["value"]) {
            put(field, value);
        }
    }
    for (id, value) in bindings {
        answers.bindings.insert(id.clone(), value.clone());
    }
    Ok(answers)
}

/// `yougori template plan REF`: resolve a package (or an existing setup) and return the concrete plan
/// with no infrastructure changes. It never creates anything, so an agent should run it first.
///
/// Planning a package is pure, so a local folder or a Hub ref is planned LOCALLY through the shared
/// planner and works with no engine running — the CLI fetches and verifies a Hub ref first, resolves
/// its pinned components, then plans. Only a diff against an installed setup goes to the engine's
/// setup_plan.
///
/// The instance is named as `template run` would name it (`--name`, else the template's name), and
/// every secret is taken as given: its value changes nothing in the plan, and `template run` asks
/// for it. `secretsAtRun` lists the ones this plan will need.
pub async fn plan(
    source: &str,
    name: Option<&str>,
    inputs: &[(String, String)],
    inputs_file: Option<&str>,
    bindings: &[(String, String)],
) -> Result<Value, String> {
    let source_value = source_ref(source)?;
    // A plan against an installed setup is a diff the engine computes; packages are planned locally.
    if source_value["kind"] == "installed_setup" {
        // The engine knows a setup by its id; the person names it as `template list` shows it.
        // Planned as `configure` plans it: a change to that setup, from its own kept package.
        let setup_id = resolve_setup_id(source).await?;
        let request = json!({
            "source": { "kind": "installed_setup", "setupId": setup_id },
            "existingSetup": setup_id,
            "answers": merged_answers(inputs, inputs_file).await?,
        });
        return public::call("setup_plan", request).await;
    }

    let answers = plan_answers(inputs, inputs_file, bindings).await?;
    // Use the engine's view of this computer when it is running (real GPU/runtimes), else the local
    // assumption. Either way planning changes nothing.
    let host = crate::hub::plan::host_from_engine().await;

    // Get the package's files, where it came from and its digest. A Hub ref is fetched and verified; a
    // local folder is read as-is. Then resolve any pinned components through the Hub (a package with no
    // imports never touches the Hub), and plan.
    let (files, item, digest, page) = if source_value["kind"] == "hub" {
        let reference = crate::hub::refs::parse(source, &crate::hub::client::website())?;
        let wanted = crate::hub::run::Wanted::Hub(reference.clone());
        let site = crate::hub::client::Site::configured()?;
        let cache = crate::hub::client::Cache::standard()?;
        let prepared = crate::hub::run::prepare(&site, &cache, &wanted).await?;
        (prepared.files, Some(reference.item()), Some(prepared.digest.clone()), Some((prepared.detail, prepared.version)))
    } else {
        let path = source_value["path"].as_str().unwrap_or(source);
        let collected = crate::hub::scan::collect(std::path::Path::new(path)).map_err(|e| e.to_string())?;
        let digest = crate::hub::scan::digest_of(&collected.files);
        (collected.files, None, Some(digest), None)
    };
    let site = crate::hub::client::Site::configured()?;
    let cache = crate::hub::client::Cache::standard()?;
    let package = crate::hub::components::package(&site, &cache, &files, item, digest)
        .await
        .map_err(|problems| crate::hub::plan::problems_text("This template", &problems))?;
    let mut planned = package_plan(&package, answers, name, &host)?;
    // The Hub page against the files, by the one rule the engine applies when it plans (the
    // review's `page_check`), so a plan made here with no engine says the same as one the engine
    // made. A folder has no page; that is said rather than passed off as a clean check.
    let page = match page {
        Some((detail, version)) => crate::hub::review::page_check(&package, &files, detail.as_ref(), &version),
        None => Err(crate::hub::review::NO_HUB_PAGE.to_owned()),
    };
    planned["page"] = crate::hub::review::page_json(&page);
    Ok(planned)
}

/// A package's plan as `template plan` returns it, named as `template run` would name the
/// instance, with every secret taken as given.
fn package_plan(
    package: &yougori_setup::plan::Package,
    mut answers: yougori_setup::plan::Answers,
    name: Option<&str>,
    host: &yougori_setup::plan::Host,
) -> Result<Value, String> {
    answers.instance = name.unwrap_or_else(|| package.checked.template.name()).to_owned();
    for question in package.checked.questions.iter().filter(|question| question.kind == yougori_setup::format::QuestionKind::Secret) {
        answers.secrets.insert(question.id.clone(), question.id.clone());
    }
    let plan = yougori_setup::plan::plan(package, &answers, host)
        .map_err(|problems| crate::hub::plan::problems_text("This template", &problems))?;

    // Build the PlanResponse envelope the review renderer and a scripted reader expect. A local plan
    // reserves no setup id (nothing is created), so setupId is omitted and baseRevision is 0. The lock
    // and the short pins let a script see the resolved component versions.
    let review = serde_json::to_value(&plan.review).unwrap_or(Value::Null);
    let digest = plan.digest.clone();
    let lock = serde_json::to_value(crate::hub::components::lock_of(&plan)).unwrap_or(Value::Null);
    let components = crate::hub::components::pins(package);
    let plan_value = serde_json::to_value(&plan).unwrap_or(Value::Null);
    Ok(json!({
        "baseRevision": 0,
        "digest": digest,
        "lock": lock,
        "components": components,
        "review": review,
        "plan": plan_value,
        "instance": plan.instance,
        "secretsAtRun": plan.secrets.keys().collect::<Vec<_>>(),
    }))
}

/// A plan as a terminal reviews it: the planner's review, then, when the engine planned it, the
/// plan's product document (what its chosen capabilities ask for, each requested; asking grants
/// nothing) or why it has none. A package planned here without the engine has no document and
/// reads as before. `template plan`, the review of a `template run` and the review `configure`
/// asks to confirm show it this way.
pub fn plan_review_lines(planned: &Value) -> Vec<String> {
    let mut lines = review_lines(&planned["review"]);
    lines.extend(product_lines(planned, ASKS_FOR));
    lines
}

/// `template plan`'s view: what the Hub page check found (when there was a page), the review,
/// then the secrets `template run` will ask for.
pub fn plan_view(value: &Value) -> String {
    let mut lines = super::review::page_from_json(&value["page"]).map(|page| super::review::page_lines(&page)).unwrap_or_default();
    lines.extend(plan_review_lines(value));
    let secrets = value["secretsAtRun"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>();
    if !secrets.is_empty() {
        lines.push(format!("Asked for when you run it: {}. Secrets are never part of a plan.", secrets.join(", ")));
    }
    lines.join("\n")
}

/// `yougori template configure INSTANCE`: edit an existing setup's capabilities and inputs, review the
/// diff, and apply through the shared planner. In a terminal it shows the review and asks to confirm;
/// a script must pass `--yes`, otherwise only the plan is returned. `--dry-run` returns the plan and
/// applies nothing.
///
/// A saved plan carries secret *references* only, never values: for each secret entered on stdin the
/// plan gets a binding `{ field, secretRef: "apply:<field>" }`, and the value travels separately in
/// `setup_apply.secrets`, where the engine holds it only for that operation. So a secret value is
/// never written into a plan, a review, a log or an argument.
///
/// A setup whose last change is waiting for an answer is a different case: that change holds the
/// setup, so planning another would only be refused as busy. The same command answers it instead
/// ([`answer_waiting`]): the value goes to the operation that asked, by its own id and the digest of
/// the plan the person reviewed, and nothing is planned or created a second time.
#[allow(clippy::too_many_arguments)]
pub async fn configure(
    instance: &str,
    inputs: &[(String, String)],
    install_bindings: &[(String, String)],
    inputs_file: Option<&str>,
    secrets_stdin: bool,
    yes: bool,
    dry_run: bool,
    interactive: bool,
) -> Result<Value, String> {
    // The secret values, read privately from stdin before anything is asked of the engine. On a
    // dry run no values are needed, so none are read.
    let secrets = if secrets_stdin && !dry_run { Some(read_secret_values().await?) } else { None };
    configure_given(instance, inputs, install_bindings, inputs_file, secrets, yes, dry_run, interactive).await
}

/// [`configure`] with the stdin secrets already read (`None` when `--secrets -` was not given).
#[allow(clippy::too_many_arguments)]
async fn configure_given(
    instance: &str,
    inputs: &[(String, String)],
    install_bindings: &[(String, String)],
    inputs_file: Option<&str>,
    secrets: Option<Value>,
    yes: bool,
    dry_run: bool,
    interactive: bool,
) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    if let Some(waiting) = waiting_operation(&setup_id).await {
        return answer_waiting(instance, &setup_id, &waiting, inputs, install_bindings, inputs_file, secrets, dry_run, interactive).await;
    }
    let source = json!({ "kind": "installed_setup", "setupId": setup_id });
    change(instance, &setup_id, source, inputs, install_bindings, inputs_file, secrets.unwrap_or(Value::Null), yes, dry_run, interactive).await
}

/// The setup's current operation when it is waiting for an answer, as `setup_operation` reads it.
/// `None` when it has none, when its last operation finished, or when the engine can't be asked,
/// which the ordinary path then reports itself.
async fn waiting_operation(setup_id: &str) -> Option<Value> {
    let last = public::call("setup_operation", json!({ "setupId": setup_id })).await.ok()?;
    (last["state"] == "awaiting_input").then_some(last)
}

/// What an operation is waiting for: a secret value, with the question's id when the engine named
/// it, or something only a new review can give (an agreement the review asks for).
enum Waiting {
    Secret(Option<String>),
    Other,
}

impl Waiting {
    fn of(progress: &Value) -> Self {
        let error = &progress["error"];
        match error["code"].as_str() {
            Some("secret_needed" | "needs_secret") => Self::Secret(error["field"].as_str().map(str::to_owned)),
            _ => Self::Other,
        }
    }
}

/// What a person does next for a change waiting for an answer, with a command that works. A secret
/// it asks for goes through `template configure INSTANCE --secrets -`, which answers that change
/// rather than planning another; anything else it waits for needs the change given up and the setup
/// reviewed again. On the wire the engine names the setup by its id, which the raw cancel needs.
pub(super) fn waiting_words(instance: &str, progress: &Value) -> String {
    let error = &progress["error"];
    let asked = error["message"].as_str().map(views::clean).unwrap_or_else(|| "It needs an answer before it can go on.".to_owned());
    let setup_id = progress["operation"]["setupId"].as_str().unwrap_or(instance);
    let operation = progress["operation"]["operationId"].as_str().unwrap_or("OPERATION");
    let give_up = format!("yougori call setup_cancel --setup-id {setup_id} --operation-id {operation} --yes");
    match Waiting::of(progress) {
        Waiting::Secret(field) => {
            let example = match &field {
                Some(field) => format!("{{\"{field}\": \"…\"}}"),
                None => "{\"QUESTION\": \"…\"}".to_owned(),
            };
            format!(
                "{instance} is waiting for an answer: {asked} Give it with yougori template configure {instance} --secrets - (a JSON object on stdin, such as {example}); at a terminal it is asked for without being shown. That continues this change rather than starting another. To give the change up instead: {give_up}. What it already did is kept."
            )
        }
        Waiting::Other => format!(
            "{instance} is waiting: {asked} That can't be given to a change already under way. Give it up with {give_up}, then review the setup again with yougori template configure {instance}. What it already did is kept."
        ),
    }
}

/// A sentence about a change that waits for an answer, carrying the code that says so
/// (`awaiting_input`), so a program reads a change it can answer apart from one that failed.
fn awaiting(words: String) -> String {
    crate::client::remember_error(words, crate::wire::ErrorDetails::of(crate::wire::Code::AwaitingInput))
}

/// Answers the change `waiting` is. The secret value, read privately from stdin or asked for at a
/// terminal without echo, travels to the engine with the operation's own id and the digest of the
/// plan the person reviewed (`setup_apply` joins that operation; see the engine's
/// `continue_operation`), so the operation that asked continues and nothing is planned or made again.
/// Nothing else can change a change that is under way: an input or binding needs a new plan, which
/// means giving this one up first, and the refusal says how.
#[allow(clippy::too_many_arguments)]
async fn answer_waiting(
    instance: &str,
    setup_id: &str,
    waiting: &Value,
    inputs: &[(String, String)],
    install_bindings: &[(String, String)],
    inputs_file: Option<&str>,
    secrets: Option<Value>,
    dry_run: bool,
    interactive: bool,
) -> Result<Value, String> {
    use std::io::IsTerminal;
    let words = waiting_words(instance, waiting);
    let operation = waiting["operation"]["operationId"]
        .as_str()
        .ok_or_else(|| format!("{instance} is waiting for an answer, but the engine did not say for which change. Check it with yougori template logs {instance}. Nothing was changed."))?
        .to_owned();
    if !inputs.is_empty() || !install_bindings.is_empty() || inputs_file.is_some() {
        return Err(format!("An input or binding can't be changed on a change that is already under way. {words} Nothing was changed."));
    }
    let Waiting::Secret(field) = Waiting::of(waiting) else {
        return Err(awaiting(format!("{words} Nothing was changed.")));
    };
    let asked = waiting["error"]["message"].as_str().map(views::clean).unwrap_or_default();
    if dry_run {
        return Ok(json!({
            "planned": false,
            "applied": false,
            "waiting": true,
            "operation": waiting["operation"],
            "asked": asked,
            "field": field,
            "next": format!("yougori template configure {instance} --secrets -"),
        }));
    }
    // The value: privately from stdin, or at a real terminal asked for without echo (decided on
    // the actual stdin, so it is never read with the echo on because the flag and the device
    // disagreed). Never from an argument.
    let secrets = match (secrets, &field) {
        (Some(given), _) => given,
        (None, Some(field)) if interactive && std::io::stdin().is_terminal() => {
            ui::lines(vec![format!("{instance} is waiting for an answer: {asked}")]);
            let value = ui::hidden(&format!("{field} (not shown): "))?;
            if value.trim().is_empty() {
                return Err(crate::cli_ui::CANCELLED.into());
            }
            json!({ field: value })
        }
        (None, _) => return Err(format!("{words} Nothing was changed.")),
    };
    // The answer has to include what was asked for: a value for something else would only have
    // the engine ask again.
    if let Some(field) = &field {
        if secrets.get(field).and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err(format!("The secrets given don't include {field}, which is what {instance} is waiting for. {words} Nothing was changed."));
        }
    }
    // The digest of the plan the person reviewed, as the engine names it on the operation. An
    // engine that doesn't name it can't be answered from a terminal that wasn't there for the
    // review; that is said rather than guessed around.
    let digest = waiting["planDigest"]
        .as_str()
        .ok_or_else(|| format!("The engine running on this computer doesn't say which plan {instance} is waiting on, so it can't be answered from here. Update Yougori, or answer it on the setup's page in the app. Nothing was changed."))?
        .to_owned();
    let revision = get_setup(setup_id).await.ok().and_then(|detail| detail["revision"].as_u64()).unwrap_or(0);
    let started = public::call(
        "setup_apply",
        json!({ "setupId": setup_id, "planDigest": digest, "operationId": operation, "expectedRevision": revision, "secrets": secrets }),
    )
    .await?;
    // The same operation carries on; a different one would mean the engine made something twice.
    if let Some(continued) = started["operationId"].as_str().or_else(|| started["operation"]["operationId"].as_str()) {
        if continued != operation {
            return Err(format!("The engine started a different change ({continued}) instead of continuing the one waiting ({operation}). Check both with yougori template logs {instance} before doing anything else."));
        }
    }
    let finished = follow(setup_id, &started, interactive).await?;
    match finished["state"].as_str().unwrap_or("") {
        "completed" => Ok(json!({ "planned": false, "applied": true, "answered": true, "operation": finished })),
        // Given, and still asked for: the answer did not cover it, or the change wants something
        // else now. Its own words say which.
        "awaiting_input" => Err(awaiting(format!("{instance} is still waiting after that answer. {}", waiting_words(instance, &finished)))),
        _ => Err(settled_words(instance, &finished)),
    }
}

/// `yougori template update INSTANCE` for an engine setup: plans it against the latest version of
/// its Hub template (or its folder as the folder is now), carrying the person's own answers and
/// choices across, and applies it once agreed, as `configure` does. What the new version changes
/// about those choices is shown first.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    instance: &str,
    inputs: &[(String, String)],
    inputs_file: Option<&str>,
    secrets_stdin: bool,
    yes: bool,
    interactive: bool,
) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    let summary = list_setups().await.into_iter().find(|setup| setup["setupId"] == json!(setup_id)).ok_or_else(|| format!("{instance} is not a setup on this computer. Nothing was changed."))?;
    let source = update_source(instance, &summary["source"])?;
    let secrets = if secrets_stdin { read_secret_values().await? } else { Value::Null };
    change(instance, &setup_id, source, inputs, &[], inputs_file, secrets, yes, false, interactive).await
}

/// Where an update reads the new version from: the latest version of the Hub item a setup was made
/// from, or its folder as it is now.
fn update_source(instance: &str, source: &Value) -> Result<Value, String> {
    match source["kind"].as_str() {
        Some("hub") => Ok(json!({ "kind": "hub", "publisher": source["publisher"], "name": source["name"], "version": "latest" })),
        Some("local_folder") => Ok(source.clone()),
        _ => Err(format!("{instance} wasn't made from a Hub template or a folder, so there is no newer version to move to. Change its answers with yougori template configure {instance}. Nothing was changed.")),
    }
}

/// Plans a change to a setup from `source`, shows it, and applies it once agreed. `secrets` is the
/// object of secret values read privately from stdin (`Value::Null` when none were given).
#[allow(clippy::too_many_arguments)]
async fn change(
    instance: &str,
    setup_id: &str,
    source: Value,
    inputs: &[(String, String)],
    install_bindings: &[(String, String)],
    inputs_file: Option<&str>,
    secrets: Value,
    yes: bool,
    dry_run: bool,
    interactive: bool,
) -> Result<Value, String> {
    let setup_id = setup_id.to_owned();
    // The secret values (field → value) and the references that stand in for them in the plan.
    // Secret references (never values), plus the installation-time bindings (a folder, drive, file or
    // SETUP/RESOURCE) the person gave with --binding. Both are references in the plan.
    let mut bindings: Vec<Value> = secrets
        .as_object()
        .into_iter()
        .flatten()
        .map(|(field, _)| json!({ "field": field, "secretRef": format!("apply:{field}") }))
        .collect();
    for (id, value) in install_bindings {
        bindings.push(json!({ "field": id, "value": value }));
    }

    // Plan the change first, against the existing setup. The plan sees only references.
    let planned = public::call(
        "setup_plan",
        json!({
            "source": source,
            "existingSetup": setup_id,
            "answers": merged_answers(inputs, inputs_file).await?,
            "bindings": bindings,
        }),
    )
    .await?;
    // What moving to this version changes about the person's own answers (a question removed,
    // a new required one, a fixed value): named at the top of every result, so a script sees it
    // without digging into the plan, and shown first in a terminal.
    let conflicts = planned["conflicts"].as_array().cloned().unwrap_or_default();
    let with_conflicts = |mut value: Value| {
        if !conflicts.is_empty() {
            value["conflicts"] = json!(conflicts);
        }
        value
    };
    if dry_run {
        return Ok(with_conflicts(json!({ "planned": true, "applied": false, "plan": planned })));
    }
    // The person has to agree to the change. In a terminal we show the review and ask; a script must
    // have passed --yes. Without agreement, return the plan and change nothing.
    if !yes {
        if interactive {
            let mut lines: Vec<String> = planned["conflicts"].as_array().into_iter().flatten().filter_map(|conflict| conflict["message"].as_str()).map(|said| format!("▲ {}", super::views::clean(said))).collect();
            // The Hub page against the files, when the engine compared them (a move to a Hub
            // version): said before the review it qualifies.
            if let Some(page) = super::review::page_from_json(&planned["page"]) {
                lines.extend(super::review::page_lines(&page).into_iter().map(|line| format!("▲ {line}")));
            }
            lines.extend(plan_review_lines(&planned));
            if !lines.is_empty() {
                crate::cli_ui::lines(lines);
            }
            let choices = [ui::Choice::new("Apply the change", "change this setup as reviewed"), ui::Choice::new("Cancel", "nothing is changed")];
            match ui::select(&format!("Apply this change to {instance}?"), &[], &choices, 0) {
                Ok(0) => {}
                Ok(_) => return Err(crate::cli_ui::CANCELLED.into()),
                Err(error) => return Err(error),
            }
        } else {
            return Ok(with_conflicts(json!({ "planned": true, "applied": false, "plan": planned, "needsConfirmation": true })));
        }
    }

    // Apply exactly the plan that was returned, by its digest and the setup's expected revision. The
    // secret values ride along here and nowhere else.
    let applied_setup = planned["setupId"].as_str().unwrap_or(&setup_id).to_owned();
    let operation = operation_id()?;
    let mut request = json!({
        "setupId": applied_setup,
        "planDigest": planned["digest"],
        "operationId": operation,
        "expectedRevision": planned["baseRevision"],
    });
    if secrets.is_object() {
        request["secrets"] = secrets;
    }
    let started = public::call("setup_apply", request).await?;
    // The apply runs in the background; wait for it to finish (or a terminal state) before reporting.
    let finished = wait_for_operation(&applied_setup, &started, interactive).await?;
    Ok(with_conflicts(json!({ "planned": true, "applied": true, "plan": planned, "operation": finished })))
}

/// A fresh operation id for an apply, so replaying after an interruption is safe. Random, URL-safe
/// and well within the engine's `[A-Za-z0-9._:-]{1,128}` rule. A failure to seed the RNG is surfaced
/// rather than silently producing a predictable id.
fn operation_id() -> Result<String, String> {
    use base64::Engine;
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Cannot make an operation id (no secure randomness). Nothing was changed.".to_owned())?;
    Ok(format!("op-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)))
}

/// Resolve a setup name the person typed to the engine's setup id, via `setup_list`. The engine ids
/// are like `setup-<uuid>`; a person types the memorable name. An exact id passes through. When the
/// engine is not running or the name is unknown, the original text is returned and the engine reports
/// a clear error on the call that needs it.
async fn resolve_setup_id(name: &str) -> Result<String, String> {
    let Ok(list) = public::call("setup_list", json!({})).await else {
        return Ok(name.to_owned());
    };
    let setups = list["setups"].as_array().cloned().or_else(|| list.as_array().cloned()).unwrap_or_default();
    // An exact id match wins; otherwise match the memorable name. A name that matches more than one
    // setup is ambiguous, so we ask the person to use the id.
    if setups.iter().any(|s| s["setupId"] == json!(name)) {
        return Ok(name.to_owned());
    }
    let by_name: Vec<&Value> = setups.iter().filter(|s| s["name"] == json!(name)).collect();
    match by_name.as_slice() {
        [one] => Ok(one["setupId"].as_str().unwrap_or(name).to_owned()),
        [] => Ok(name.to_owned()),
        many => Err(format!(
            "{} setups are named {name}. Use the exact id instead: {}.",
            many.len(),
            many.iter().filter_map(|s| s["setupId"].as_str()).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// The engine's setups as a JSON array (`SetupSummary` shape), or empty when the engine is not
/// running. A read-only call that never starts the engine.
pub async fn list_setups() -> Vec<Value> {
    match public::call("setup_list", json!({})).await {
        Ok(list) => list["setups"].as_array().cloned().or_else(|| list.as_array().cloned()).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Whether a name the person typed is an engine setup (by id or memorable name), so a lifecycle
/// command can route to the engine rather than the v1 instance store. Returns the resolved setup id
/// when it is one. Never errors: an ambiguous or unknown name is simply "not an engine setup" here,
/// and the v1 path (or the engine on the eventual call) gives the precise message.
pub async fn setup_named(name: &str) -> Option<String> {
    let setups = list_setups().await;
    if setups.iter().any(|s| s["setupId"] == json!(name)) {
        return Some(name.to_owned());
    }
    let by_name: Vec<&Value> = setups.iter().filter(|s| s["name"] == json!(name)).collect();
    match by_name.as_slice() {
        [one] => one["setupId"].as_str().map(str::to_owned),
        _ => None,
    }
}

/// The full view of one engine setup, via `setup_get`.
pub async fn get_setup(setup_id: &str) -> Result<Value, String> {
    public::call("setup_get", json!({ "setupId": setup_id })).await
}

/// The deletions a removal review offers, as `(consent id, what it says)`: a volume whose template
/// says `retention.onRemove: ask` (`delete_data:`), or a grid this setup made, deleted now rather
/// than paused (`delete_grid:`). Usually there are none, and the data is kept.
pub fn offered_deletions(plan: &Value) -> Vec<(String, String)> {
    plan["consents"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|consent| Some((consent["id"].as_str()?.to_owned(), consent["message"].as_str()?.to_owned())))
        .filter(|(id, _)| id.starts_with("delete_"))
        .collect()
}

/// A removal review in a terminal: what it removes, step by step, and every note on what happens
/// to the data, in the engine's own words.
pub fn removal_lines(plan: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(headline) = plan["headline"].as_str().filter(|said| !said.is_empty()) {
        lines.push(views::clean(headline));
    }
    for step in plan["steps"].as_array().into_iter().flatten() {
        let Some(title) = step["title"].as_str() else { continue };
        match step["detail"].as_str() {
            Some(detail) => lines.push(format!("  - {}. {}", views::clean(title), views::clean(detail))),
            None => lines.push(format!("  - {}", views::clean(title))),
        }
    }
    lines.extend(plan["notes"].as_array().into_iter().flatten().filter_map(Value::as_str).map(views::clean));
    lines
}

/// What a set of agreed consents deletes, by name: the part after `delete_…:`.
fn deleted_volumes(agreed: &[String]) -> Vec<String> {
    agreed.iter().filter(|id| id.starts_with("delete_")).filter_map(|id| id.split_once(':')).map(|(_, part)| part.to_owned()).collect()
}

/// Remove an engine setup, reviewed first: `setup_action remove` without a digest changes nothing
/// and answers with the review. In a terminal the review is shown and confirmed; a script gets it
/// back unconfirmed unless it passes `yes`.
///
/// Data is kept. A volume whose template says `retention.onRemove: ask` is offered for deletion
/// on the review: in a terminal each is its own question, with keeping it the answer already
/// chosen; a script deletes them only with `delete_data`, which is refused before anything is
/// removed when the review offers nothing to delete. The reviewed plan is then applied with
/// exactly the deletions agreed to (`setup_apply` with `consents`), and the engine refuses one it
/// did not offer. Returns `{removed, plan?, deleted?}`; `removed: false` means the review came
/// back for confirmation and nothing changed.
pub async fn remove_setup(setup_id: &str, yes: bool, delete_data: bool, interactive: bool) -> Result<Value, String> {
    // First call: no planDigest, so the engine returns the removal plan and changes nothing.
    let plan = public::call("setup_action", json!({ "setupId": setup_id, "action": "remove" })).await?;
    let offered = offered_deletions(&plan);
    if delete_data && offered.is_empty() {
        return Err("This setup's template keeps its data when it is removed, so --delete-data does not apply to it. Nothing was removed. Remove it without --delete-data: its data and its backups are kept.".into());
    }
    let mut agreed: Vec<String> = if delete_data { offered.iter().map(|(id, _)| id.clone()).collect() } else { Vec::new() };
    if !yes {
        if !interactive {
            return Ok(json!({ "removed": false, "plan": plan, "needsConfirmation": true }));
        }
        let lines = removal_lines(&plan);
        if !lines.is_empty() {
            crate::cli_ui::lines(lines);
        }
        if !delete_data {
            for (id, message) in &offered {
                let choices = [ui::Choice::new("Keep it", "its data and backups stay"), ui::Choice::new("Delete it", "this cannot be undone")];
                if ui::select(&views::clean(message), &[], &choices, 0)? == 1 {
                    agreed.push(id.clone());
                }
            }
        }
        let going = deleted_volumes(&agreed);
        let choices = [
            if going.is_empty() {
                ui::Choice::new("Remove the setup", "take it down as reviewed; its data is kept")
            } else {
                ui::Choice::new(format!("Remove it and delete {}", going.join(", ")), "this cannot be undone")
            },
            ui::Choice::new("Cancel", "nothing is removed"),
        ];
        match ui::select(&format!("Remove the setup {setup_id}?"), &[], &choices, 1) {
            Ok(0) => {}
            Ok(_) => return Err(crate::cli_ui::CANCELLED.into()),
            Err(error) => return Err(error),
        }
    }
    // Second call applies exactly the reviewed plan, with exactly the deletions agreed to.
    let operation = operation_id()?;
    let started = public::call(
        "setup_apply",
        json!({
            "setupId": setup_id,
            "planDigest": plan["digest"],
            "operationId": operation,
            "expectedRevision": plan["baseRevision"],
            "consents": agreed,
        }),
    )
    .await?;
    let finished = wait_for_operation(setup_id, &started, interactive).await?;
    Ok(json!({ "removed": true, "operation": finished, "deleted": deleted_volumes(&agreed) }))
}

/// The text view of the engine setups part of `template list`, appended below the v1 instances so the
/// two are clearly separate. An adopted legacy grid is marked, and a setup whose state the engine
/// never observed says so instead of a state word (invariant 16). Empty when there are no setups.
pub fn setups_list_view(setups: &[Value]) -> String {
    if setups.is_empty() {
        return String::new();
    }
    let name_width = setups
        .iter()
        .map(|s| s["name"].as_str().unwrap_or_default().chars().count())
        .max()
        .unwrap_or(8)
        .max(8);
    let mut lines = vec!["Setups (template platform):".to_owned(), format!("{:<name_width$}  {:<18}  STATE", "NAME", "KIND")];
    for s in setups {
        let name = s["name"].as_str().unwrap_or_default();
        let kind = s["profile"].as_str().map(profile_label).unwrap_or("Setup");
        let adopted = if s["adoptedLegacy"] == true { " (adopted)" } else { "" };
        let state = if s["stateObserved"] == false {
            "state not checked".to_owned()
        } else {
            s["state"].as_str().unwrap_or("unknown").replace('_', " ")
        };
        lines.push(format!("{:<name_width$}  {:<18}  {}", name, format!("{kind}{adopted}"), state));
    }
    lines.join("\n")
}

/// A grid profile id as a short label for a list.
fn profile_label(profile: &str) -> &'static str {
    match profile {
        "neo_grid" => "Neo Grid",
        "sandbox_grid" => "Sandbox Grid",
        "access_grid" => "Access Grid",
        "swarm_mining_grid" => "Swarm Mining",
        _ => "Setup",
    }
}

/// The text view of one engine setup, for `template status NAME`.
pub fn setup_view(detail: &Value) -> String {
    let summary = &detail["summary"];
    let name = summary["name"].as_str().unwrap_or_default();
    let mut lines = Vec::new();
    let kind = summary["profile"].as_str().map(profile_label).unwrap_or("Setup");
    let adopted = if summary["adoptedLegacy"] == true { " (adopted from an older grid)" } else { "" };
    lines.push(format!("{name} — {kind}{adopted}"));
    if summary["stateObserved"] == false {
        lines.push("Managed from its own tab in My setups; its state is not checked here.".to_owned());
    } else {
        lines.push(format!("State: {}", summary["state"].as_str().unwrap_or("unknown").replace('_', " ")));
    }
    if let Some(health) = summary["health"].as_str() {
        lines.push(format!("Health: {}", health.replace('_', " ")));
    }
    // Capabilities and their readiness.
    let caps: Vec<&Value> = detail["capabilities"].as_array().into_iter().flatten().collect();
    if !caps.is_empty() {
        lines.push("Capabilities:".to_owned());
        for cap in caps {
            let id = cap["id"].as_str().unwrap_or_default();
            let h = cap["health"].as_str().unwrap_or("").replace('_', " ");
            match cap["detail"].as_str() {
                Some(detail) if !detail.is_empty() => lines.push(format!("  - {id}: {h} — {detail}")),
                _ => lines.push(format!("  - {id}: {h}")),
            }
        }
    }
    // Safe outputs (a URL, a port) if any.
    for output in detail["outputs"].as_array().into_iter().flatten() {
        if let (Some(label), Some(value)) = (output["label"].as_str(), output["value"].as_str()) {
            lines.push(format!("{label}: {value}"));
        }
    }
    // Plain notes the engine attached: why an adopted grid cannot be changed here, a synced folder
    // that is holding files back. The desktop has always shown these; a terminal showing the same
    // setup used to leave them out, so the two doors disagreed about what was worth telling.
    let notes: Vec<&str> = detail["notes"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|note| !note.is_empty()).collect();
    if !notes.is_empty() {
        lines.push("Notes:".to_owned());
        lines.extend(notes.into_iter().map(|note| format!("  - {note}")));
    }
    lines.extend(product_lines(detail, PERMISSIONS));
    lines.join("\n")
}

/// The heading of a setup's own permission lines (`template status`): each line says whether it
/// is requested; enabling a capability does not grant it.
const PERMISSIONS: &str = "Permissions:";

/// The heading of a product document's permission lines where a plan (its review) asks for them.
const ASKS_FOR: &str = "Asks for:";

/// Capability declarations on `template permissions` remain requests, not approvals.
const PERMITTED: &str = "Declared permissions (requests; approval and enforcement are checked separately):";

/// A product document (the engine's CORE-07 `product`, the one the desktop reads) in a terminal,
/// from any reply that carries one (`setup_get`, `setup_plan`, `setup_permissions`): its
/// permission lines under `heading` with their status words, the inventory of the setup's move to
/// VM sandboxes and what needs the person, or why the reply has no document
/// (`productUnavailable`). Every word comes from the document; nothing is decided or changed here.
pub fn product_lines(reply: &Value, heading: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(reason) = reply["productUnavailable"].as_str() {
        lines.push(format!("Product view: not available ({}).", views::clean(reason)));
    }
    let product = &reply["product"];
    if product.is_null() { return lines; }
    if product["contract_version"].as_u64() != Some(2) {
        lines.push("Product view: this document version cannot be read; update Yougori.".to_owned());
        return lines;
    }
    let setup = reply["setupId"].as_str().or_else(|| reply["summary"]["setupId"].as_str());
    if setup.is_some_and(|id| product["subject"]["kind"] != "setup" || product["subject"]["id"] != id) {
        lines.push("Product view: the document belongs to another setup; refresh this setup.".to_owned());
        return lines;
    }
    let permissions: Vec<&Value> = product["permissions"].as_array().into_iter().flatten().collect();
    if !permissions.is_empty() {
        lines.push(heading.to_owned());
        for permission in permissions {
            let text = views::clean(permission["text"].as_str().unwrap_or_default());
            lines.push(format!("  - {text} ({})", permission_words(&permission["status"])));
        }
    }
    let migration = &product["migration"];
    let items: Vec<&Value> = migration["items"].as_array().into_iter().flatten().collect();
    if !items.is_empty() {
        lines.push(match migration["status"]["status"].as_str() {
            Some("pending") => "Move to VM sandboxes (an inventory; nothing has changed):".to_owned(),
            Some("in_progress") => "Move to VM sandboxes (in progress):".to_owned(),
            Some("interrupted") => "Move to VM sandboxes (stopped part way; it resumes after the completed steps):".to_owned(),
            Some("completed") => "Move to VM sandboxes (done):".to_owned(),
            _ => "Move to VM sandboxes:".to_owned(),
        });
        for item in items {
            lines.push(format!(
                "  - {} ({}): {}",
                views::clean(item["subject"].as_str().unwrap_or_default()),
                recorded_words(&item["recorded"]),
                outcome_words(&item["outcome"])
            ));
        }
    }
    let refusals: Vec<&Value> = product["refusals"].as_array().into_iter().flatten().collect();
    if !refusals.is_empty() {
        lines.push("Needs you:".to_owned());
        for refusal in refusals {
            lines.push(format!(
                "  - {} ({}). What you can do: {}.",
                views::clean(refusal["reason"].as_str().unwrap_or_default()),
                refusal["code"]["code"].as_str().unwrap_or("refused"),
                views::clean(refusal["remedy_text"].as_str().unwrap_or_default()).trim_end_matches('.')
            ));
        }
    }
    lines.into_iter().map(|line| views::clean(&line)).collect()
}

fn permission_words(status: &Value) -> String {
    match status["status"].as_str() {
        Some("requested") => "requested; asking grants nothing".to_owned(),
        Some("permitted_by_contract") => "permitted by the contract".to_owned(),
        Some("awaiting_approval") => "needs your approval".to_owned(),
        Some("approved") => "approved".to_owned(),
        Some("not_permitted") => format!("not permitted: {}", views::clean(status["refusal"]["reason"].as_str().unwrap_or_default())),
        _ => "status unknown to this Yougori".to_owned(),
    }
}

fn recorded_words(recorded: &Value) -> String {
    match recorded["recorded"].as_str() {
        Some("sandbox_type") => {
            let kind = recorded["kind"].as_str().unwrap_or("unknown");
            if recorded["gpu"] == true && kind != "gpu" { format!("{kind} with a GPU") } else { kind.to_owned() }
        }
        Some("isolation_tier") => format!("tier {}", recorded["tier"].as_str().unwrap_or("unknown")),
        Some("category") => recorded["category"].as_str().unwrap_or("unknown").replace('_', " "),
        _ => "recorded choice unknown to this Yougori".to_owned(),
    }
}

fn option_words(option: &Value) -> String {
    match option["option"].as_str() {
        Some("vm_sandbox") => "a VM sandbox".to_owned(),
        Some("labelled") => views::clean(option["category"]["label"].as_str().unwrap_or("a labelled runtime")),
        _ => "an option unknown to this Yougori".to_owned(),
    }
}

fn outcome_words(outcome: &Value) -> String {
    match outcome["outcome"].as_str() {
        Some("unchanged") => "stays a VM sandbox".to_owned(),
        Some("strengthened") => format!("becomes a VM sandbox: {}", views::clean(outcome["reason"].as_str().unwrap_or_default())),
        Some("preserved") => format!("keeps its label: {}", views::clean(outcome["category"]["label"].as_str().unwrap_or_default())),
        Some("needs_decision") => {
            let options: Vec<String> = outcome["options"].as_array().into_iter().flatten().map(option_words).collect();
            format!("a decision is needed before it moves: {}", options.join(" or "))
        }
        Some("decided") => format!("decided: {}", option_words(&outcome["choice"])),
        Some("refused") => format!("refused: {}", views::clean(outcome["refusal"]["reason"].as_str().unwrap_or_default())),
        Some("follows_owner") => "follows the setup that owns it".to_owned(),
        _ => "an outcome unknown to this Yougori".to_owned(),
    }
}

/// Follows a started operation until it settles, showing a spinner. `started` is whatever
/// `setup_apply`/`setup_action` returned (an OperationRef or an OperationProgress). Settled is
/// `completed`, `failed`, `awaiting_input` or `unknown`: the states nothing moves on from without
/// someone acting. `cancelling` is still moving (the current step finishes first), so it waits.
/// Returns the progress; the caller says what the state means.
/// The engine went away while a change it had accepted was running (Yougori was closed, or it
/// crashed). The change was sent and is part done, so "not submitted" would be untrue: it carries
/// on once Yougori runs again, and the engine looks at what the cut-off step did first. Any other
/// error is returned as it came.
pub(super) fn engine_lost(instance: &str, error: String) -> String {
    if !error.starts_with("Cannot reach the Yougori engine") {
        return error;
    }
    crate::client::remember_error(
        format!("Yougori stopped while this change was running, so it is part done. Start Yougori again (yougori app start), then carry it on with yougori template continue {instance}: the engine first checks what the cut-off step did, so nothing is done twice."),
        crate::wire::ErrorDetails::of(crate::wire::Code::OperationInterrupted),
    )
}

async fn follow(setup_id: &str, started: &Value, interactive: bool) -> Result<Value, String> {
    let operation_id = started["operation"]["operationId"]
        .as_str()
        .or_else(|| started["operationId"].as_str())
        .map(str::to_owned);
    let poll = async {
        let mut cursor = 0u64;
        loop {
            let mut request = json!({ "setupId": setup_id, "cursor": cursor });
            if let Some(id) = &operation_id {
                request["operationId"] = json!(id);
            }
            let progress = public::call("setup_operation", request).await.map_err(|error| engine_lost(setup_id, error))?;
            cursor = progress["nextCursor"].as_u64().unwrap_or(cursor);
            match progress["state"].as_str().unwrap_or("") {
                "completed" | "failed" | "awaiting_input" | "unknown" => return Ok(progress),
                _ => tokio::time::sleep(std::time::Duration::from_millis(600)).await,
            }
        }
    };
    super::run::wait(interactive, "Working", poll).await
}

/// Waits for a started operation to finish. A `completed` state returns its final progress; every
/// other settled state is an error that says what to do next ([`settled_words`]).
async fn wait_for_operation(setup_id: &str, started: &Value, interactive: bool) -> Result<Value, String> {
    let progress = follow(setup_id, started, interactive).await?;
    match progress["state"].as_str().unwrap_or("") {
        "completed" => Ok(progress),
        _ => Err(settled_words(setup_id, &progress)),
    }
}

/// What an operation that settled short of completing means, with a next step that works: a
/// failure names how to try again when it can be; a cancellation says what it did is kept; a change
/// waiting for an answer says how to give it; an outcome the engine can't tell yet says how to have
/// it checked. On the wire a cancelled operation is a failed one whose error code says so
/// (`operation_cancelled`); the engine has no separate cancelled state, so none is looked for.
pub(super) fn settled_words(instance: &str, progress: &Value) -> String {
    let error = &progress["error"];
    match progress["state"].as_str().unwrap_or("") {
        "failed" if error["code"] == "operation_cancelled" => crate::wire::cancelled(&format!(
            "This change was cancelled. What it had already done is kept. Carry it on with yougori template continue {instance}, or leave it as it is."
        )),
        "failed" => {
            let message = error["message"].as_str().unwrap_or("The operation failed.");
            // Try again on the setup's page is `template continue` in a terminal.
            let again = if error["retryable"] == true { format!("\nTry again with: yougori template continue {instance}") } else { String::new() };
            format!("{message}{again}")
        }
        "awaiting_input" => awaiting(waiting_words(instance, progress)),
        "unknown" => {
            let reason = error["message"].as_str().map(views::clean).unwrap_or_else(|| "A step may or may not have taken effect.".to_owned());
            format!("The outcome of this change is not known yet: {reason} Nothing is done twice: yougori template continue {instance} has the engine check what really happened before anything else runs, and yougori template logs {instance} shows what it found.")
        }
        other => format!("This change is {}. Follow it with yougori template logs {instance}.", other.replace('_', " ")),
    }
}

/// `yougori template start INSTANCE` / `stop INSTANCE`: a lifecycle action on the whole setup, through
/// `setup_action`. The action runs in the background; we wait for it to finish before reporting, so a
/// success line never appears while the engine is still working. Stop keeps data.
pub async fn action(instance: &str, action: &str, interactive: bool) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    let started = public::call("setup_action", json!({ "setupId": setup_id, "action": action })).await?;
    wait_for_operation(&setup_id, &started, interactive).await
}

/// `yougori template continue INSTANCE` for an engine setup: its last change, when it did not
/// finish, is tried again, as Try again does on the setup's page. Only the steps that did not
/// finish run again; what is done stays done. Returns `{continued: true, operation}`, or
/// `{continued: false}` when its last change already finished.
///
/// A change whose outcome is not known is not rerun blindly. The engine owns what unknown means:
/// asked to reconcile, it looks at what the cut-off step left behind, records what it finds, and
/// only then says whether the change failed (and can go on), finished, or still can't be told.
/// The retry itself settles the same way again before any step runs (`settle_before_continuing`),
/// so a continue repeated twice does nothing twice. A cancelled change arrives as `failed` with
/// the code `operation_cancelled` and carries on the same way.
pub async fn retry(setup_id: &str, interactive: bool) -> Result<Value, String> {
    let last = public::call("setup_operation", json!({ "setupId": setup_id })).await?;
    let operation = last["operation"]["operationId"].as_str().ok_or("Nothing has been done to this setup yet, so there is nothing to continue.")?.to_owned();
    let (settled, reconciled) = match last["state"].as_str().unwrap_or_default() {
        "unknown" => {
            let checked = super::run::wait(interactive, "Checking what really happened", public::call("setup_action", json!({ "setupId": setup_id, "action": "reconcile", "operationId": operation }))).await?;
            (checked, true)
        }
        _ => (last, false),
    };
    match settled["state"].as_str().unwrap_or_default() {
        "failed" => {
            let started = public::call("setup_action", json!({ "setupId": setup_id, "action": "retry", "operationId": operation })).await?;
            let finished = wait_for_operation(setup_id, &started, interactive).await?;
            Ok(json!({ "continued": true, "reconciled": reconciled, "operation": finished }))
        }
        "completed" => Ok(json!({ "continued": false, "reconciled": reconciled, "operation": settled })),
        "unknown" if reconciled => {
            let reason = settled["error"]["message"].as_str().map(views::clean).unwrap_or_else(|| "A step may or may not have taken effect.".to_owned());
            Err(format!("Yougori checked, and still can't tell what the last change to {setup_id} did: {reason} Nothing was run again. See yougori template logs {setup_id}, and try yougori template continue {setup_id} again once the resource can be reached."))
        }
        "awaiting_input" | "unknown" => Err(settled_words(setup_id, &settled)),
        _ => Err(format!("A change to it is still running. Follow it with yougori template logs {setup_id}.")),
    }
}

/// `yougori template continue INSTANCE` for an engine setup: carries its last unfinished change on
/// ([`retry`]). Secrets given with `--secrets -` answer that change when it waits for one: they are
/// held only in memory, so a change cut off by Yougori closing asks again for the ones it had, and
/// before this they were read and dropped. Inputs can't change on a change under way.
pub async fn continue_setup(instance: &str, setup_id: &str, inputs_given: bool, secrets: Option<Value>, interactive: bool) -> Result<Value, String> {
    if inputs_given {
        return Err(format!("An input can't be changed on a change that is already under way. Carry it on with yougori template continue {instance}, then change the input with yougori template configure {instance} --input ID=VALUE. Nothing was changed."));
    }
    let Some(secrets) = secrets else {
        return retry(setup_id, interactive).await;
    };
    let carried = match waiting_operation(setup_id).await {
        Some(waiting) => return answer_waiting(instance, setup_id, &waiting, &[], &[], None, Some(secrets), false, interactive).await.map(continued),
        None => retry(setup_id, interactive).await,
    };
    match waiting_operation(setup_id).await {
        Some(waiting) => answer_waiting(instance, setup_id, &waiting, &[], &[], None, Some(secrets), false, interactive).await.map(continued),
        None => carried,
    }
}

/// An answered change, said as a change carried on.
fn continued(mut answered: Value) -> Value {
    answered["continued"] = json!(true);
    answered
}

/// `yougori template logs INSTANCE [--cursor N]`: a bounded read of the setup's activity, resumable by
/// cursor. The caller handles `--follow` by reading again from the returned `nextCursor`.
pub async fn logs(instance: &str, cursor: Option<u64>) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    public::call(
        "setup_operation",
        json!({ "setupId": setup_id, "cursor": cursor.unwrap_or(0) }),
    )
    .await
}

/// `yougori template logs INSTANCE --sandbox NAME`: what one of the setup's own sandboxes printed
/// lately (its last 64 KB).
pub async fn sandbox_logs(instance: &str, sandbox: &str) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    public::call("setup_sandbox_logs", json!({ "setupId": setup_id, "resource": sandbox })).await
}

pub fn sandbox_logs_view(value: &Value) -> String {
    let text = views::clean_block(value["text"].as_str().unwrap_or_default());
    let mut out = String::new();
    if value["truncated"] == true {
        out.push_str("(only the end is shown)\n");
    }
    out.push_str(if text.trim().is_empty() { "It has printed nothing yet." } else { &text });
    out
}

/// `yougori template usage INSTANCE`: what its hosted models cost this month, and what was refused.
pub async fn usage(instance: &str) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    public::call("setup_usage", json!({ "setupId": setup_id })).await
}

pub fn usage_view(value: &Value) -> String {
    let models = value["models"].as_array().cloned().unwrap_or_default();
    if models.is_empty() {
        return "This setup uses no hosted model.".into();
    }
    let mut lines = Vec::new();
    for model in models {
        let name = views::clean(model["model"].as_str().or_else(|| model["resource"].as_str()).unwrap_or("model"));
        if let Some(error) = model["error"].as_str() {
            lines.push(format!("{name}: {}", views::clean(error)));
            continue;
        }
        let spent = model["spentUsd"].as_f64().unwrap_or_default();
        let budget = model["budgetUsd"].as_f64().map(|budget| format!(" of ${budget:.2}")).unwrap_or_default();
        lines.push(format!("{name}: ${spent:.4}{budget} spent in {}, {} requests, {} refused{}", views::clean(model["month"].as_str().unwrap_or("this month")), model["requests"].as_u64().unwrap_or_default(), model["refused"].as_u64().unwrap_or_default(), if model["freeOnly"] == true { ", free models only" } else { "" }));
    }
    lines.join("\n")
}

/// `yougori template jobs INSTANCE JOB [--settle succeeded|failed|run_again]`: what the job's last
/// attempts printed, and the runs events started; with `--settle`, settles a job nobody knows the
/// outcome of, after the person looked.
pub async fn job(instance: &str, job: &str, settle: Option<&str>) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    if let Some(outcome) = settle {
        return public::call("setup_job_settle", json!({ "setupId": setup_id, "resource": job, "outcome": outcome })).await;
    }
    public::call("setup_job_logs", json!({ "setupId": setup_id, "resource": job })).await
}

pub fn job_view(value: &Value) -> String {
    if let Some(state) = value["state"].as_str() {
        return views::done(vec![format!("Settled: {} is {state} now.", views::clean(value["resource"].as_str().unwrap_or("the job")))]);
    }
    let attempts = value["attempts"].as_array().cloned().unwrap_or_default();
    if attempts.is_empty() {
        return "No attempt has printed anything yet.".into();
    }
    let mut out = String::new();
    for attempt in attempts {
        let why = attempt["why"].as_str().map(|why| format!(", started by {}", views::clean(why))).unwrap_or_default();
        out.push_str(&format!("== attempt {}{why} ==\n", views::clean(attempt["attempt"].as_str().unwrap_or_default())));
        let text = views::clean_block(attempt["text"].as_str().unwrap_or_default());
        out.push_str(if text.trim().is_empty() { "(it printed nothing)" } else { text.trim_end() });
        out.push('\n');
    }
    out
}

/// `yougori template artifacts INSTANCE [--save ID --to FOLDER]`: the results the setup's jobs
/// handed back; with `--save`, one copied into a folder, checked against its checksum.
pub async fn artifacts(instance: &str, save: Option<(&str, &str)>) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    if let Some((artifact, folder)) = save {
        let folder = std::path::absolute(folder).map_err(|error| format!("{folder} can't be used: {error}"))?;
        return public::call("setup_artifact_save", json!({ "setupId": setup_id, "artifactId": artifact, "folder": folder.to_string_lossy() })).await;
    }
    public::call("setup_artifacts", json!({ "setupId": setup_id })).await
}

pub fn artifacts_view(value: &Value) -> String {
    if let Some(path) = value["path"].as_str() {
        return views::done(vec![format!("Saved {} bytes to {}. Its checksum matched.", value["bytes"].as_u64().unwrap_or_default(), views::clean(path))]);
    }
    let listed = value["artifacts"].as_array().cloned().unwrap_or_default();
    if listed.is_empty() {
        return "No job has handed anything back yet.".into();
    }
    let mut lines = vec!["ID  NAME  FROM  BYTES  KEPT".to_owned()];
    for artifact in listed {
        let said = |field: &str| views::clean(artifact[field].as_str().unwrap_or("-"));
        let kept = if artifact["removed"] == true { "removed by retention".to_owned() } else { "kept".to_owned() };
        lines.push(format!("{}  {}  {}  {}  {kept}", said("id"), said("name"), said("resource"), artifact["bytes"].as_u64().unwrap_or_default()));
    }
    lines.join("\n")
}

/// `yougori template permissions INSTANCE`: what a running setup is actually allowed to do on this
/// computer. The engine answers, not the template's own description, so this is what was granted
/// rather than what was asked for — the one place to look before trusting a setup with more, or
/// when deciding whether to remove it.
pub async fn permissions(instance: &str) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    public::call("setup_permissions", json!({ "setupId": setup_id })).await
}

/// What `permissions` shows. Each section is left out when it is empty, so a setup that reaches
/// nothing says so in one line instead of printing five empty headings.
pub fn permissions_view(value: &Value) -> String {
    if value["known"] == json!(false) {
        // The engine has no record of it. Say why in its words, and what to do next.
        let reason = value["reason"].as_str().unwrap_or("Yougori has no record of this setup.");
        return format!("{reason}\nSee what is here with yougori template list.");
    }
    let mut lines = Vec::new();
    if let Some(version) = value["version"].as_str() {
        lines.push(format!("Version {version}."));
    }
    let list = |key: &str| value[key].as_array().cloned().unwrap_or_default();
    let section = |lines: &mut Vec<String>, heading: &str, items: Vec<String>| {
        if !items.is_empty() {
            lines.push(heading.to_owned());
            lines.extend(items.into_iter().map(|item| format!("  - {item}")));
        }
    };

    section(&mut lines, "Allowed to:", list("permissions").iter().filter_map(|v| v.as_str().map(views::clean)).collect());

    // A download says what it is and where it comes from, because "a model" and "a model from an
    // account someone else controls" are not the same thing to agree to.
    section(&mut lines, "Downloads:", list("downloads").iter().filter_map(|d| {
        let name = d["name"].as_str()?;
        let kind = d["kind"].as_str().unwrap_or("");
        let from = d["from"].as_str();
        Some(match (kind.is_empty(), from) {
            (true, Some(from)) => format!("{} from {}", views::clean(name), views::clean(from)),
            (true, None) => views::clean(name),
            (false, Some(from)) => format!("{} ({}) from {}", views::clean(name), views::clean(kind), views::clean(from)),
            (false, None) => format!("{} ({})", views::clean(name), views::clean(kind)),
        })
    }).collect());

    // Which answer became which secret, and where the value came from. Never a value: this is a
    // command people run to check a setup, and a secret on screen is a secret in the scrollback.
    section(&mut lines, "Secrets, by question:", list("secrets").iter().filter_map(|secret| {
        let variable = secret["variable"].as_str()?;
        let resource = secret["resource"].as_str().unwrap_or("");
        let source = secret["source"].as_str().unwrap_or("");
        let mut said = views::clean(variable);
        if !resource.is_empty() {
            said = format!("{said} in {}", views::clean(resource));
        }
        if !source.is_empty() {
            said = format!("{said} — {}", views::clean(source));
        }
        Some(said)
    }).collect());

    // Each folder is a record, not a sentence (`plan::PcFolder`). Reading only the plain strings
    // here would leave the section empty and read as "it reaches no folders on this computer" —
    // the one thing this command must never get wrong, since a sandbox that can change someone's
    // files is exactly what they came here to check.
    section(&mut lines, "Folders on this computer:", list("pcAccess").iter().filter_map(|folder| {
        if let Some(said) = folder.as_str() {
            return Some(views::clean(said));
        }
        let path = folder["path"].as_str()?;
        let who = folder["environment"].as_str().unwrap_or("this setup");
        let may = if folder["readOnly"] == json!(true) { "can read" } else { "can change" };
        let mut said = format!("{} — {} {may} it", views::clean(path), views::clean(who));
        if folder["sync"] == json!(true) {
            // Worth saying: the sandbox works on a copy Yougori keeps in step, not the folder.
            said.push_str(" (a copy kept in step, not the folder itself)");
        }
        Some(said)
    }).collect());

    // Costs are plain sentences from the planner (`plan::Review.costs`). An amount that could not
    // be worked out is still said, rather than left out where it would read as free.
    section(&mut lines, "May cost:", list("costs").iter().filter_map(|cost| {
        if let Some(said) = cost.as_str() {
            return Some(views::clean(said));
        }
        let label = cost["label"].as_str()?;
        Some(match cost["amount"].as_str() {
            Some(amount) => format!("{}: {}", views::clean(label), views::clean(amount)),
            None => format!("{}: not known yet", views::clean(label)),
        })
    }).collect());

    if lines.iter().all(|line| line.starts_with("Version ")) {
        lines.push("This setup reaches nothing outside itself: no permissions, downloads, secrets, folders or costs.".to_owned());
    }
    // The setup's product document, the one the desktop's permissions panel reads: what its
    // chosen capabilities ask for, each requested; a capability does not grant access its template and answers make.
    lines.extend(product_lines(value, PERMITTED));
    lines.join("\n")
}

/// `yougori template reveal INSTANCE [KEY]`: without KEY, the private outputs the setup has (a grid's
/// invite, say), by name only; with KEY, that one's value, asked of the product again now and shown
/// in this terminal only. Nothing keeps it.
pub async fn reveal(instance: &str, key: Option<&str>) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    let mut request = json!({ "setupId": setup_id });
    if let Some(key) = key {
        request["key"] = json!(key);
    }
    public::call("setup_reveal", request).await
}

/// `template reveal`'s view: the value with a word on keeping it private, or the list of what can
/// be shown and how.
pub fn reveal_view(instance: &str, value: &Value) -> String {
    if let Some(shown) = value["value"].as_str() {
        let label = views::clean(value["label"].as_str().unwrap_or("Value"));
        return format!("{label}: {shown}\nKeep it private: give it only to the people it is for.");
    }
    let listed = value["private"].as_array().into_iter().flatten().filter_map(|output| Some((output["key"].as_str()?, output["label"].as_str().unwrap_or_default()))).collect::<Vec<_>>();
    if listed.is_empty() {
        return "This setup has nothing private to show.".to_owned();
    }
    let mut lines = vec!["Private outputs, shown only when you ask:".to_owned()];
    lines.extend(listed.iter().map(|(key, label)| format!("  {} — {}", views::clean(key), views::clean(label))));
    lines.push(format!("Show one with: yougori template reveal {instance} {}", views::clean(listed[0].0)));
    lines.join("\n")
}

/// `yougori template export INSTANCE [FOLDER]`: export a reviewed recipe, excluding runtime data and
/// secrets. The engine does the exclusion; the CLI only names the destination.
pub async fn export(instance: &str, folder: Option<&str>) -> Result<Value, String> {
    let setup_id = resolve_setup_id(instance).await?;
    let folder = export_folder(instance, folder)?;
    public::call(
        "setup_export",
        json!({ "setupId": setup_id, "folder": folder }),
    )
    .await
}

/// Where an export goes, as a full path: FOLDER as given, from where the command runs, or a folder
/// named after the setup there. The engine runs elsewhere, so it is never given a relative path.
fn export_folder(instance: &str, folder: Option<&str>) -> Result<String, String> {
    let here = std::env::current_dir().map_err(|error| format!("The current folder can't be read ({error}). Give the export folder as a full path."))?;
    let name: String = instance.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    let name = name.trim_matches('-');
    let chosen = match folder {
        Some(folder) => here.join(folder),
        None => here.join(if name.is_empty() { "setup" } else { name }),
    };
    Ok(chosen.to_string_lossy().into_owned())
}

/// `yougori template join`: an interactive scoped grid invitation flow. The invitation is entered
/// privately, never on the command line. In a script with no terminal, the invitation is read from
/// stdin instead.
pub async fn join(interactive: bool) -> Result<Value, String> {
    use std::io::IsTerminal;
    // A hidden prompt only makes sense at a real terminal; decide on the actual stdin, so an
    // invitation is never read with the echo on because the flag and the device disagreed.
    let invitation = if interactive && std::io::stdin().is_terminal() {
        crate::cli_ui::hidden("Paste the invitation (it is not shown): ")?
    } else {
        let bytes = super::run::read_stdin("the invitation on stdin").await?;
        String::from_utf8(bytes.to_vec()).map_err(|_| "The invitation must be text.".to_owned())?.trim().to_owned()
    };
    if invitation.is_empty() {
        return Err("No invitation was given. Nothing was joined.".into());
    }
    public::call("setup_action", json!({ "action": "join", "invitation": invitation })).await
}

/// Read the private secrets object from stdin: a JSON object of field → value. The value never leaves
/// the private channel.
pub(super) async fn read_secret_values() -> Result<Value, String> {
    let bytes = super::run::read_stdin("the secrets on stdin").await?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "Secrets on stdin must be a JSON object such as {\"openai_key\": \"…\"}.".to_owned())?;
    let object = value
        .as_object()
        .ok_or("Secrets on stdin must be a JSON object such as {\"openai_key\": \"…\"}.")?;
    // Every value must be a string: a secret is text, and refusing other shapes keeps a stray number
    // or object from being stored or echoed as if it were one.
    for (field, v) in object {
        if !v.is_string() {
            return Err(format!("The secret {field} must be a string value."));
        }
    }
    Ok(value)
}

/// The text view of a bounded log read: each event's time, step and message, and where to read on.
pub fn logs_view(value: &Value) -> String {
    let mut lines = Vec::new();
    if value["truncated"] == true {
        lines.push("Earlier activity was dropped before this point.".to_owned());
    }
    for event in value["events"].as_array().into_iter().flatten() {
        let step = event["step"].as_str().unwrap_or("");
        let message = event["message"].as_str().unwrap_or("");
        if step.is_empty() {
            lines.push(message.to_owned());
        } else {
            lines.push(format!("{step}: {message}"));
        }
    }
    if lines.is_empty() {
        lines.push("No activity yet.".to_owned());
    } else if let Some(cursor) = value["nextCursor"].as_u64() {
        // Name the setup in the hint when the engine told us which, rather than a literal placeholder.
        let name = value["operation"]["setupId"].as_str().unwrap_or("INSTANCE");
        lines.push(format!("Read on from here: yougori template logs {name} --cursor {cursor}"));
    }
    lines.join("\n")
}

/// One line for an event, in the mode's format: a plain sentence in text mode, the event's JSON when
/// piped. One format per mode, so a text follow never ends with a stray JSON envelope.
fn follow_line(event: &Value, text: bool) -> String {
    if text {
        let step = event["step"].as_str().unwrap_or("");
        let message = event["message"].as_str().unwrap_or("");
        if step.is_empty() { message.to_owned() } else { format!("{step}: {message}") }
    } else {
        event.to_string()
    }
}

/// `yougori template logs INSTANCE --follow`: read the activity, then keep reading from the returned
/// cursor until the operation ends or the person presses Ctrl+C. A disconnect never stops the engine
/// operation; reattach with `logs` or `status`. Output stays in one format for the whole follow (text
/// lines, or JSON events), never mixing the two. Idle polling backs off up to ~10s.
pub async fn follow_logs(instance: &str, cursor: Option<u64>, text: bool) -> Result<super::Reply, String> {
    use std::io::Write;
    let setup_id = resolve_setup_id(instance).await?;
    let mut at = cursor.unwrap_or(0);
    let mut idle = std::time::Duration::from_millis(500);
    loop {
        let value = logs(&setup_id, Some(at)).await?;
        if value["truncated"] == true && text {
            println!("… earlier activity was dropped before this point.");
        }
        let events = value["events"].as_array().cloned().unwrap_or_default();
        for event in &events {
            println!("{}", follow_line(event, text));
        }
        let _ = std::io::stdout().flush();
        let next = value["nextCursor"].as_u64().unwrap_or(at);
        // Back off when nothing new arrived; reset the moment there is activity.
        idle = if next == at && events.is_empty() {
            (idle * 2).min(std::time::Duration::from_secs(10))
        } else {
            std::time::Duration::from_millis(500)
        };
        at = next;
        match value["state"].as_str().unwrap_or("") {
            "completed" => return Ok(super::Reply { value, text: None, code: 0 }),
            "failed" => {
                if text {
                    println!("{}", crate::wire::cancellation(&settled_words(&setup_id, &value)).unwrap_or_else(|| settled_words(&setup_id, &value)));
                }
                return Ok(super::Reply { value, text: None, code: 1 });
            }
            "awaiting_input" | "unknown" => {
                if text {
                    println!("{}", settled_words(&setup_id, &value));
                }
                return Ok(super::Reply { value, text: None, code: 0 });
            }
            _ => {}
        }
        super::run::wait(false, "Following", async move {
            tokio::time::sleep(idle).await;
            Ok::<(), String>(())
        })
        .await?;
    }
}

// ---- Interactive `template new`: the six capability groups ----
//
// The desktop and the CLI present the same six groups from the same registry. This is the CLI's
// version: a question flow with Back on every step, a spinner on every wait, Ctrl+C safe. It writes
// an editable v2 draft (a template file beside a project file). The capability selection and the
// draft structure are stable; the final draft is serialized through the shared format types once
// they can write v2 (yougori-92's `format`), so the exact YAML field spelling is settled there.

/// One capability the person chose, kept with the group it came from so the draft can group them.
struct Chosen {
    group: Group,
    id: &'static str,
    /// The display name, carried for clearer "added for you" messages and future summaries.
    #[allow(dead_code)]
    name: &'static str,
}

/// Run the interactive six-group builder and write a v2 draft folder. Returns the same JSON shape as
/// the non-interactive `new`, so the caller renders it the same way.
pub async fn new_setup(name: Option<&str>, interactive: bool) -> Result<Value, String> {
    // Without a terminal there is nothing to walk through: fall back to the starter folder, which is
    // a valid, editable draft a person or a script can fill in.
    if !interactive {
        return super::new_template(name);
    }

    // Availability for greying out choices comes from the engine's authoritative report when it is
    // running; otherwise only Planned (host-independent) is enforced, and the rest stay selectable.
    let availability = engine_availability().await;

    // 1. The setup's name.
    let suggested = name.unwrap_or("my-setup").to_owned();
    let name = ui::input_noted(
        "What is this setup called?",
        &["A short, memorable name. You can change it later.".to_owned()],
        &suggested,
        &|text| {
            let text = text.trim();
            if crate::hub::refs::valid_name(text) {
                Ok(text.to_owned())
            } else {
                Err(format!("Use {}.", crate::hub::refs::NAME_RULE))
            }
        },
    )?;
    let folder = std::env::current_dir().map_err(|e| e.to_string())?.join(&name);
    if folder.exists() {
        return Err(format!("{} already exists. Choose another name or folder.", folder.display()));
    }

    // 2. The six groups, each a checklist. A Planned or Unsupported capability is shown but cannot be
    //    ticked, so people can see what exists without being able to choose something that will not
    //    run. Back on a group returns to the previous one; Back on the first returns to the name.
    let mut chosen: Vec<Chosen> = Vec::new();
    let mut recipe: Option<&'static str> = None;
    let mut steps = ui::Wizard::new();
    // The groups, and then the kind of grid when one was ticked, are steps of a single wizard, so
    // Back on the grid question returns to the last checklist rather than falling through to the
    // write with nothing chosen.
    while steps.step() < STEPS {
        let outcome = match step_at(steps.step(), &chosen) {
            Step::Group(group) => {
        let caps = capability::group(group);
        let choices: Vec<ui::Choice> = caps
            .iter()
            .map(|cap| {
                // Planned is never selectable, whatever the host. Otherwise the engine's report (when
                // the engine is running) decides; with no engine, a non-planned capability stays
                // selectable and the plan step checks it for real.
                let planned = matches!(cap.status, capability::Status::Planned);
                let code = availability.as_ref().and_then(|map| map.get(cap.id)).and_then(|e| e["availability"].as_str());
                let selectable = !planned && !matches!(code, Some("unsupported"));
                let state = if planned { Some("Planned") } else { availability_text(code) };
                let hint = match state {
                    Some(word) if !selectable => format!("{} — {word}", cap.summary),
                    Some("Needs configuration") => format!("{} — needs a sign-in or provider", cap.summary),
                    _ => cap.summary.to_owned(),
                };
                let choice = ui::Choice::new(cap.name, hint);
                if selectable { choice } else { choice.disabled() }
            })
            .collect();
        // Pre-tick the ones the person already chose if they came back to this group.
        let initial: Vec<usize> = caps
            .iter()
            .enumerate()
            .filter(|(_, cap)| chosen.iter().any(|c| c.id == cap.id))
            .map(|(at, _)| at)
            .collect();
        let note = vec![format!("{} — choose what this setup should do. Space to tick, Enter to go on.", group.name())];
        ui::multiselect(group.name(), &note, &choices, &initial, false).map(|picked| {
            // Replace this group's selections with the new ticks, dropping any that conflict with one
            // already kept (in this group or an earlier one) — the first tick wins, so the wizard
            // never records a contradiction such as "run on this computer only" plus "create a grid".
            chosen.retain(|c| c.group != group);
            for at in picked {
                let cap = caps[at];
                let clashes = chosen.iter().any(|c| {
                    cap.conflicts.contains(&c.id)
                        || capability::find(c.id).is_some_and(|other| other.conflicts.contains(&cap.id))
                });
                if !clashes {
                    chosen.push(Chosen { group, id: cap.id, name: cap.name });
                }
            }
            true
        })
            }
            Step::GridKind => {
            // 3. A grid has to say which kind it is: its people, models and credentials are served
            //    by different trusted code, and the generator refuses a grid without one. The kinds,
            //    their names and their hints are the shared registry's, the same the desktop shows.
            let kinds = capability::grid_kinds();
            let choices: Vec<ui::Choice> = kinds.iter().map(|kind| ui::Choice::new(kind.name, kind.hint)).collect();
            let note = vec!["A grid serves one of these. Each is run by its own part of Yougori.".to_owned()];
            ui::select("Which kind of grid?", &note, &choices, 0).map(|picked| {
                recipe = kinds.get(picked).map(|kind| kind.slug);
                true
            })
            }
            Step::Nothing => {
                // No grid was ticked: nothing to ask here, and nothing for Back to return to.
                recipe = None;
                Ok(false)
            }
        };
        steps.next(outcome)?;
    }

    // 4. Write the draft. The generator pulls in what a choice needs and says what it added, so
    //    the wizard and the app agree on both the files and the additions. A spinner covers the write.
    let (files, added) = draft_files(&name, recipe, &chosen)?;
    super::run::wait(true, "Writing the draft", async {
        crate::hub::client::write_files(&folder, &files).map_err(|e| e.to_string())
    })
    .await?;

    let mut next = vec![
        format!("Edit {name}/{} to adjust the setup.", crate::hub::format::TEMPLATE_FILE),
        format!("yougori template plan ./{name}"),
        format!("yougori template run ./{name}"),
    ];
    if !added.is_empty() {
        next.insert(0, format!("Added for you (needed by your choices): {}.", added.join(", ")));
    }
    Ok(json!({
        "created": folder,
        "files": files.keys().collect::<Vec<_>>(),
        "capabilities": chosen.iter().map(|c| c.id).collect::<Vec<_>>(),
        "added": added,
        "next": next,
    }))
}


/// How many questions the builder walks: one per capability group, then the kind of grid. A
/// question outside this range is never asked and never returned to, so it lives here beside
/// `step_at` rather than as a number in the loop.
const STEPS: usize = Group::ALL.len() + 1;

/// What the wizard asks at step `at`: each capability group in turn, and then the kind of grid,
/// but only when a grid was actually ticked. Kept apart from the prompts so the order of the
/// questions — and so what Back returns to — can be checked without a terminal.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Group(Group),
    GridKind,
    Nothing,
}

fn step_at(at: usize, chosen: &[Chosen]) -> Step {
    match Group::ALL.get(at) {
        Some(group) => Step::Group(*group),
        None if chosen.iter().any(|c| c.id == "grid.create" || c.id == "grid.join") => Step::GridKind,
        None => Step::Nothing,
    }
}

/// The draft a set of ticks makes, in the shape the desktop builder sends. Every capability is
/// kept as the builder's own default: part of the setup, required, and editable by whoever runs it.
fn draft_of(name: &str, recipe: Option<&str>, chosen: &[Chosen]) -> yougori_setup::draft::Draft {
    use yougori_setup::draft::{CapabilityChoice, Draft};
    Draft {
        name: name.to_owned(),
        recipe: recipe.map(str::to_owned),
        capabilities: chosen.iter().map(|c| (c.id.to_owned(), CapabilityChoice::default())).collect(),
        ..Draft::default()
    }
}

/// The draft folder for a chosen set of capabilities, and the capabilities another choice needed.
///
/// This is the one generator the desktop builder uses (`yougori_setup::draft::to_package`), not a
/// second skeleton of the CLI's own: the same ticks here and in the app write the same bytes. It
/// also resolves what a choice needs, so the wizard does not carry its own copy of that rule.
fn draft_files(name: &str, recipe: Option<&str>, chosen: &[Chosen]) -> Result<(crate::hub::scan::Files, Vec<String>), String> {
    let generated = yougori_setup::draft::to_package(&draft_of(name, recipe, chosen)).map_err(|problems| {
        let said: Vec<String> = problems.iter().map(|problem| problem.message.to_string()).collect();
        format!("This draft cannot be written: {}", said.join(" "))
    })?;
    Ok((generated.files(), generated.added))
}
// ---- The migration dry run: inventory, backup, verify, rehearse (plan 19.1, 19.3 steps 1–4) ----

/// `yougori setup migration …`. Everything here works on a folder the person names — a copy of a
/// Yougori data folder, made while Yougori was closed. The engine refuses this computer's own
/// running data folder unless `--allow-live` is passed, and this CLI never passes it by itself: it
/// is only ever sent because the person typed it.
pub const MIGRATION_USAGE: &str = "Yougori setup migration: check a copy of a Yougori data folder before anything is moved

  yougori setup migration inventory PATH [--allow-live]
  yougori setup migration backup PATH --into FOLDER [--allow-live]
  yougori setup migration verify FOLDER
  yougori setup migration rehearse PATH [--allow-live]

PATH and FOLDER are full paths. Work on a copy: close Yougori, copy its data folder, and point
these at the copy. Reading the folder this copy of Yougori is using right now is refused, because
a product may be writing to it; --allow-live says you mean that folder anyway, and nothing passes
it for you.

inventory  what is in the folder: each product's records, how many entries each holds, its size
           and its SHA-256 checksum. Record contents, keys and addresses are never read out, and a
           record that exists but can't be read is listed as unreadable, not left out.
backup     copies exactly those records into a new, empty folder, with a checksum for each. It
           carries the records only: passwords, keys and sealed values are held by this computer's
           credential store, are tied to this computer, and do not come back from a backup.
verify     re-reads a backup folder and says whether every file is still what it was.
rehearse   works out what adopting each deployment into a setup would create, and compares it with
           the inventory: counts, identities, permissions, plans, assignments, data locations and
           links. Nothing is created, changed, started or stopped.

Text in a terminal, JSON when piped or with --format json.";

pub async fn migration_inventory(path: &str, allow_live: bool) -> Result<Value, String> {
    public::call("setup_migration_inventory", json!({ "path": full_path(path)?, "allowLive": allow_live })).await
}

pub async fn migration_backup(path: &str, into: &str, allow_live: bool) -> Result<Value, String> {
    public::call("setup_migration_backup", json!({ "path": full_path(path)?, "folder": full_path(into)?, "allowLive": allow_live })).await
}

pub async fn migration_verify(folder: &str) -> Result<Value, String> {
    public::call("setup_migration_verify", json!({ "folder": full_path(folder)? })).await
}

pub async fn migration_rehearse(path: &str, allow_live: bool) -> Result<Value, String> {
    public::call("setup_migration_rehearse", json!({ "path": full_path(path)?, "allowLive": allow_live })).await
}

/// A folder as a full path. The engine runs elsewhere, so a path relative to this terminal would
/// point somewhere else; it is settled here, where the person typed it.
fn full_path(given: &str) -> Result<String, String> {
    let given = given.trim();
    if given.is_empty() {
        return Err("Give the folder as a full path.".into());
    }
    let path = std::path::Path::new(given);
    if path.is_absolute() {
        return Ok(path.to_string_lossy().into_owned());
    }
    let here = std::env::current_dir().map_err(|error| format!("The current folder can't be read ({error}). Give the folder as a full path."))?;
    Ok(here.join(path).to_string_lossy().into_owned())
}

/// What an inventory looks like in a terminal: one line per product, then the totals.
pub fn inventory_view(value: &Value) -> String {
    let mut lines = Vec::new();
    for product in value["products"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let name = product["name"].as_str().unwrap_or("A product");
        if product["present"] != true {
            lines.push(format!("{name}: nothing here."));
            continue;
        }
        let records = product["records"].as_array().map(Vec::as_slice).unwrap_or_default();
        let found = records.iter().filter(|record| record["found"]["state"] == "present").count();
        let unreadable = records.iter().filter(|record| record["found"]["state"] == "unreadable").count();
        lines.push(format!(
            "{name}: {found} record(s){}.",
            if unreadable > 0 { format!(", {unreadable} that can't be read") } else { String::new() }
        ));
        for record in records.iter().filter(|record| record["found"]["state"] == "unreadable") {
            lines.push(format!("  can't be read: {} ({})", record["id"].as_str().unwrap_or(""), record["file"].as_str().unwrap_or("")));
        }
    }
    let instances = value["totals"]["instances"].as_u64().unwrap_or(0);
    lines.push(format!("Template instances (v1): {instances}."));
    lines.extend(value["notes"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned));
    views::done(lines)
}

pub fn backup_view(value: &Value) -> String {
    let backup = &value["backup"];
    let mut lines = vec![format!(
        "Backed up {} record(s) with a checksum for each.",
        backup["files"].as_array().map(Vec::len).unwrap_or(0)
    )];
    for left in backup["leftBehind"].as_array().into_iter().flatten() {
        lines.push(format!("Not copied: {} — {}", left["id"].as_str().unwrap_or(""), left["why"].as_str().unwrap_or("")));
    }
    lines.extend(backup["cannotCarry"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned));
    lines.extend(backup["notes"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned));
    lines.push("Next: yougori setup migration verify FOLDER".to_owned());
    views::done(lines)
}

pub fn verify_view(value: &Value) -> String {
    let mut lines = vec![format!("Checked {} file(s); {} match.", value["checked"], value["matched"])];
    for problem in value["problems"].as_array().into_iter().flatten() {
        lines.push(format!("Problem: {} — {}", problem["id"].as_str().unwrap_or(""), problem["what"].as_str().unwrap_or("")));
    }
    lines.extend(value["notes"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned));
    views::done(lines)
}

/// The rehearsal in a terminal: what would be created, then every difference, named.
pub fn rehearse_view(value: &Value) -> String {
    let mut lines = Vec::new();
    let intended = value["intended"].as_array().map(Vec::as_slice).unwrap_or_default();
    if intended.is_empty() {
        lines.push("Nothing here would become a setup.".to_owned());
    }
    for setup in intended {
        let name = setup["name"].as_str().unwrap_or("A deployment");
        match setup["blocked"].as_str() {
            Some(why) => lines.push(format!("{name}: would not be adopted. {why}")),
            None => lines.push(format!(
                "{name}: would become {}, carrying {} record(s). Its data stays where it is.",
                setup["setupId"].as_str().unwrap_or(""),
                setup["carries"].as_array().map(Vec::len).unwrap_or(0)
            )),
        }
    }
    let differences = value["differences"].as_array().map(Vec::as_slice).unwrap_or_default();
    if differences.is_empty() {
        lines.push("Compared counts, identities, permissions, plans, assignments, data locations and links: no differences.".to_owned());
    } else {
        lines.push(format!("{} difference(s) to look at:", differences.len()));
        lines.extend(differences.iter().filter_map(Value::as_str).map(|said| format!("  {said}")));
    }
    lines.extend(value["notes"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned));
    views::done(lines)
}

// ---- Scheduled backups: read them, check one, put one back (plan 15, `backup-workflow`) ----

/// `yougori setup backups …`. A backup that cannot be restored from a terminal is half a feature,
/// so the three doors are here: the list, the check, and the restore — which is reviewed first and
/// does nothing at all until the person confirms.
pub const BACKUPS_USAGE: &str = "Yougori setup backups: the backups a setup keeps, and putting one back

  yougori setup backups SETUP
  yougori setup backups check SETUP --volume VOLUME --backup BACKUP
  yougori setup backups now SETUP --volume VOLUME
  yougori setup backups restore SETUP --volume VOLUME --backup BACKUP [--over-original] [--yes]

SETUP is a setup's id; VOLUME is the volume's name inside the setup, as the list shows it.

backups   every volume this setup backs up: when the next backup is due, how the last one went,
          and each copy that is kept with its time, how many files it holds and whether the setup
          was stopped while it was copied.
check     re-reads one kept backup and compares every file with the record made when it was taken.
          Nothing is changed, on the backup or on the volume.
now       takes a backup of the volume now, as its schedule would. Its regular times stay as they
          are. It is refused, saying why, while the setup is stopped or a backup of it is running.
restore   puts a kept backup back. On its own it changes nothing: it tells you which backup, from
          when, and exactly what it would replace, and stops there. Add --yes to go ahead with
          what it described.

            without --over-original  the files are put in a new folder inside the backup sandbox.
                                     The volume itself is not touched. Practise with this.
            with --over-original     everything now on the volume is replaced by what the backup
                                     holds, and anything written since is gone. The backup is
                                     checked first, and a backup that does not match is refused.

A backup holds what is on the volume and nothing else. Passwords and keys stay in this computer's
credential store, so a restored setup asks for them again, and the copies are kept in Yougori's
own data folder on this computer: copy that folder elsewhere if you need to survive losing it.

Text in a terminal, JSON when piped or with --format json.";

pub async fn backups_list(setup: &str) -> Result<Value, String> {
    public::call("setup_backups", json!({ "setupId": setup })).await
}

/// A backup of one volume now. The engine answers once it has started; the copy shows in
/// `yougori setup backups SETUP` when it is done.
pub async fn backup_now(setup: &str, volume: &str) -> Result<Value, String> {
    public::call("setup_backup_now", json!({ "setupId": setup, "resource": volume })).await
}

pub async fn backup_check(setup: &str, volume: &str, backup: &str) -> Result<Value, String> {
    public::call("setup_backup_verify", json!({ "setupId": setup, "resource": volume, "backupId": backup })).await
}

/// The review. Nothing is changed by this call: it is what the person reads before deciding.
pub async fn backup_restore_review(setup: &str, volume: &str, backup: &str, over_original: bool) -> Result<Value, String> {
    public::call(
        "setup_backup_restore",
        json!({ "setupId": setup, "resource": volume, "backupId": backup, "overOriginal": over_original }),
    )
    .await
}

/// The restore itself, with the word the review handed back. A confirmation belongs to the one
/// restore it was shown for, so this is never sent without having read the review first.
pub async fn backup_restore_confirm(setup: &str, volume: &str, backup: &str, over_original: bool, confirm: &str) -> Result<Value, String> {
    public::call(
        "setup_backup_restore",
        json!({ "setupId": setup, "resource": volume, "backupId": backup, "overOriginal": over_original, "confirm": confirm }),
    )
    .await
}

/// A setup's backups in a terminal: one block per volume, newest copy first.
pub fn backups_view(value: &Value) -> String {
    let mut lines = Vec::new();
    let volumes = value["volumes"].as_array().map(Vec::as_slice).unwrap_or_default();
    if volumes.is_empty() {
        lines.push("This setup backs nothing up. A template gives a volume a schedule; this one gave none.".to_owned());
        return views::done(lines);
    }
    for volume in volumes {
        let name = volume["resource"].as_str().unwrap_or("a volume");
        lines.push(format!("{name}: {}, keeping {}.", volume["schedule"].as_str().unwrap_or("no schedule"), volume["keep"]));
        match (volume["paused"].as_bool(), volume["nextWhen"].as_str()) {
            (Some(true), _) => lines.push("  Paused while the setup is stopped. Starting the setup resumes it.".to_owned()),
            (_, Some(when)) => lines.push(format!("  Next backup: {when}.")),
            _ => lines.push("  No next backup worked out yet.".to_owned()),
        }
        match volume["lastOutcome"].as_str().unwrap_or("never_run") {
            "never_run" => lines.push("  Last run: none yet.".to_owned()),
            outcome => lines.push(format!(
                "  Last run: {outcome}{}{}",
                volume["lastWhen"].as_str().map(|when| format!(" at {when}")).unwrap_or_default(),
                volume["lastDetail"].as_str().filter(|said| !said.is_empty()).map(|said| format!(" — {said}")).unwrap_or_default()
            )),
        }
        let kept = volume["backups"].as_array().map(Vec::as_slice).unwrap_or_default();
        if kept.is_empty() {
            lines.push("  Nothing kept yet.".to_owned());
        }
        for backup in kept {
            lines.push(format!("  {} — {}", backup["id"].as_str().unwrap_or(""), backup["describe"].as_str().unwrap_or("")));
        }
    }
    if let Some(limits) = value["limits"].as_str() {
        lines.push(limits.to_owned());
    }
    lines.push("Next: yougori setup backups restore SETUP --volume VOLUME --backup BACKUP".to_owned());
    views::done(lines)
}

pub fn backup_check_view(value: &Value) -> String {
    let mut lines = vec![format!(
        "This backup is complete and unchanged: {} file(s), taken {}.",
        value["files"],
        value["when"].as_str().unwrap_or("at an unknown time")
    )];
    if value["consistency"] == "live" {
        lines.push("It was taken while everything kept running, so a file being written then may be half-written.".to_owned());
    }
    if let Some(note) = value["note"].as_str().filter(|note| !note.is_empty()) {
        lines.push(note.to_owned());
    }
    lines.push("Nothing was changed.".to_owned());
    views::done(lines)
}

/// The review: which backup, from when, and what it would replace. This is printed whether or not
/// `--yes` was given, so the person always sees what happened described before it happens.
pub fn restore_review_view(value: &Value) -> String {
    let mut lines = vec![format!(
        "Restoring {} of {} from the backup {}.",
        value["resource"].as_str().unwrap_or("a volume"),
        value["setupId"].as_str().unwrap_or("this setup"),
        value["backupId"].as_str().unwrap_or("")
    )];
    lines.extend(value["review"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned));
    lines.push("Nothing has been changed.".to_owned());
    lines.push(
        "Next: run the same command with --yes to go ahead, or leave it and nothing happens.".to_owned(),
    );
    views::done(lines)
}

pub fn restore_done_view(value: &Value) -> String {
    let mut lines = Vec::new();
    if let Some(next) = value["next"].as_str() {
        lines.push(next.to_owned());
    }
    if value["restoredTo"] == "copy" {
        lines.push("The volume itself was not changed.".to_owned());
    }
    views::done(lines)
}

// ---- The operations reading (plan 15, `operations-dashboard`) ----

/// `yougori setup telemetry …`. A read-only reading of the setups this computer can already list:
/// health, states, counts and durations. It changes nothing, keeps nothing and sends nothing
/// anywhere, and it carries no name, path, address or secret — see `--help` for the full list of
/// what it leaves out, which the reading itself also carries.
pub const TELEMETRY_USAGE: &str = "Yougori setup telemetry: a read-only reading of your setups

  yougori setup telemetry [SETUP] [--limit N] [--cursor N]

With no SETUP, a page of the setups you can already list. SETUP reads one of them.

What it shows   each setup's state and health; how many resources it owns, by kind, by state and
                by cost, and which have drifted; how its operations went in the last 30 days, with
                the last one's kind, state, how long it took and its refusal code; and its backup
                volumes, how many copies are kept and when the next one is due.

What it does    nothing. It reads, works the reading out there and then, and answers. Nothing is
                stored for it, nothing is scheduled, and nothing is sent anywhere — there is no
                destination to configure and no notification to switch on.

What it never   setup names, template names, questions or answers; secrets, credential names and
shows           tokens; addresses, links, domains and ports; filesystem paths, folder names, image
                names and account names; log lines and refusal sentences. Operations older than 30
                days are not counted.

Bounded         one page holds at most 50 setups (20 by default). When there are more, the answer
                says the cursor the next page starts at.

Text in a terminal, JSON when piped or with --format json.";

pub async fn telemetry(setup: Option<&str>, cursor: Option<u64>, limit: Option<u64>) -> Result<Value, String> {
    let mut params = serde_json::Map::new();
    if let Some(setup) = setup {
        params.insert("setupId".into(), json!(setup));
    }
    if let Some(cursor) = cursor {
        params.insert("cursor".into(), json!(cursor));
    }
    if let Some(limit) = limit {
        params.insert("limit".into(), json!(limit));
    }
    public::call("setup_telemetry", Value::Object(params)).await
}

/// The reading in a terminal: one line per setup, then what it leaves out and where the next page
/// starts. The "what it does not show" lines are printed every time, because a dashboard whose
/// gaps are invisible is worse than no dashboard.
pub fn telemetry_view(value: &Value) -> String {
    let mut lines = Vec::new();
    let setups = value["setups"].as_array().map(Vec::as_slice).unwrap_or_default();
    if setups.is_empty() {
        lines.push("There are no setups to read.".to_owned());
    }
    for setup in setups {
        lines.push(format!(
            "{}: {}, health {}.",
            setup["setupId"].as_str().unwrap_or(""),
            setup["state"].as_str().unwrap_or("unknown"),
            setup["health"].as_str().unwrap_or("not_checked")
        ));
        let resources = &setup["resources"];
        let drifting = resources["drifting"].as_array().map(Vec::as_slice).unwrap_or_default();
        lines.push(format!(
            "  Resources: {} owned, {} borrowed{}.",
            resources["owned"],
            resources["borrowed"],
            if drifting.is_empty() {
                String::new()
            } else {
                format!(
                    "; {} not as the setup wants ({})",
                    drifting.len(),
                    drifting.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")
                )
            }
        ));
        let operations = &setup["operations"];
        let last = &operations["last"];
        lines.push(format!(
            "  Operations in the last {} days: {}, {} failed{}.",
            operations["windowDays"],
            operations["counted"],
            operations["failed"],
            match last["kind"].as_str() {
                Some(kind) => format!(
                    ". Last: {kind} {}{}",
                    last["state"].as_str().unwrap_or(""),
                    last["errorCode"].as_str().map(|code| format!(" ({code})")).unwrap_or_default()
                ),
                None => String::new(),
            }
        ));
        let backups = &setup["backups"];
        if backups["volumes"].as_u64().unwrap_or(0) > 0 {
            lines.push(format!(
                "  Backups: {} volume(s), {} copies kept, {} failing.",
                backups["volumes"], backups["kept"], backups["failingNow"]
            ));
        }
    }
    if let Some(scope) = value["scope"].as_str() {
        lines.push(scope.to_owned());
    }
    lines.push("What this reading does not show:".to_owned());
    lines.extend(value["notShown"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|said| format!("  {said}")));
    if let Some(words) = value["retention"]["words"].as_str() {
        lines.push(words.to_owned());
    }
    if let Some(next) = value["next"].as_str() {
        lines.push(format!("Next: {next}"));
    }
    views::done(lines)
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_permissions_view_says_what_a_setup_reaches_and_never_shows_a_secret_value() {
        // The shapes here are the engine's own (`setups::permissions::effective`, built from
        // `plan::Review`): costs are sentences, a download is {kind, name, from?}, a secret is
        // {resource, variable, source} and a folder is a `plan::PcFolder` record — not a string.
        let value = json!({
            "setupId": "setup-1", "known": true, "version": "1.2.0",
            "permissions": ["Run containers on this computer.", "Open a public web address for this setup."],
            "downloads": [
                {"kind": "image", "name": "nginx:1.27"},
                {"kind": "model", "name": "a-model", "from": "huggingface"},
            ],
            "secrets": [{"resource": "web", "variable": "OPENAI_KEY", "source": "the question openai_key"}],
            "pcAccess": [
                {"environment": "web", "path": "D:/shop", "readOnly": false},
                {"environment": "docs", "path": "D:/papers", "readOnly": true},
                {"environment": "build", "path": "D:/src", "readOnly": false, "sync": true},
            ],
            "costs": ["A rented GPU is charged by the hour while this runs."],
        });
        let text = permissions_view(&value);
        for expected in [
            "Version 1.2.0.",
            "Allowed to:",
            "  - Run containers on this computer.",
            "Downloads:",
            "  - nginx:1.27 (image)",
            "  - a-model (model) from huggingface",
            "Secrets, by question:",
            "  - OPENAI_KEY in web — the question openai_key",
            "Folders on this computer:",
            "  - D:/shop — web can change it",
            "  - D:/papers — docs can read it",
            "  - D:/src — build can change it (a copy kept in step, not the folder itself)",
            "May cost:",
            "  - A rented GPU is charged by the hour while this runs.",
        ] {
            assert!(text.contains(expected), "missing {expected:?} from:\n{text}");
        }
        // The folders are records, not sentences. Reading only strings would leave this section
        // empty, which would say a sandbox reaches nothing while it can change someone's files.
        assert_eq!(text.matches("  - D:/").count(), 3, "every folder is shown:\n{text}");
        // Never a secret's value, whatever the engine sends.
        let leaky = permissions_view(&json!({
            "known": true, "version": "1.0.0",
            "secrets": [{"resource": "web", "variable": "OPENAI_KEY", "source": "the question openai_key", "value": "sk-live-123"}],
        }));
        assert!(!leaky.contains("sk-live-123"), "a value must never be printed:\n{leaky}");

        // A cost whose amount the engine could not work out still appears, rather than being left
        // out where its absence would read as free.
        let unknown_cost = permissions_view(&json!({
            "known": true, "version": "1.0.0", "costs": [{"label": "Rented pod", "amount": null}],
        }));
        assert!(unknown_cost.contains("Rented pod: not known yet"), "{unknown_cost}");

        // The sections a setup has nothing in are left out rather than printed empty.
        let quiet = permissions_view(&json!({"setupId": "setup-2", "known": true, "version": "1.0.0"}));
        assert!(quiet.contains("reaches nothing outside itself"), "{quiet}");
        for heading in ["Allowed to:", "Downloads:", "Secrets, by question:", "Folders on this computer:", "May cost:"] {
            assert!(!quiet.contains(heading), "{heading} should not be shown for a setup with none: {quiet}");
        }

        // A setup the engine does not know: its reason, and where to look instead.
        let unknown = permissions_view(&json!({
            "setupId": "s", "known": false,
            "reason": "Yougori keeps no copy of the template this setup was made from, so it can't read its permissions again.",
        }));
        assert!(unknown.contains("keeps no copy of the template"), "{unknown}");
        assert!(unknown.contains("yougori template list"), "{unknown}");
    }

    #[test]
    fn a_short_name_resolves_only_through_the_trusted_table() {
        let publisher = trusted_publisher().expect("the first-party publisher");
        // The namespace it resolves into is kept for the owner, so no one else can take the name
        // a short name lands on. This is what makes the table safe to resolve at all.
        assert!(crate::hub::refs::reserved(publisher), "{publisher} must be a publisher name only the owner may use");

        // Every entry resolves, and to its own template under that publisher.
        for alias in TRUSTED_ALIASES {
            assert_eq!(resolve_alias(alias.term), Some(format!("hub/{publisher}/{}", alias.template)));
        }
        // Spacing and case are forgiven, because people type names, not identifiers.
        assert_eq!(resolve_alias("  My   API "), Some(format!("hub/{publisher}/my-api")));

        // Nothing else resolves: not a near miss, not a word on its own, not another publisher.
        for typed in ["my apis", "my ap", "api", "grid", "neo", "sandbox", "acme/my-api", "hub/acme/my-api", "my-api", "my_api", ""] {
            assert_eq!(resolve_alias(typed), None, "{typed} must not resolve");
        }
    }

    #[test]
    fn no_short_name_can_stand_for_an_image_or_a_hub_address() {
        // A short name is only read after a Hub address and after a folder here, but the table
        // itself must hold nothing that could pass for either. An image name, a folder name and a
        // bare Hub reference are all single words; every short name is more than one.
        for alias in TRUSTED_ALIASES {
            assert!(alias.term.contains(' '), "{} is a single word and could be an image or folder name", alias.term);
            assert_eq!(alias.term, short_name(alias.term), "{} is not written the way names are compared", alias.term);
            assert!(!alias.term.contains('/') && !alias.term.contains(':'), "{} could be read as an address", alias.term);
            assert!(crate::hub::refs::valid_name(alias.template), "{} is not a usable template name", alias.template);
        }
        // The hyphenated spelling is a suggestion only; it resolves nothing by itself.
        assert_eq!(alias_hint("my-api"), Some("my api"));
        assert_eq!(alias_hint("Neo_Grid"), Some("neo grid"));
        assert_eq!(alias_hint("nginx"), None);
        assert_eq!(resolve_alias("my-api"), None);
    }

    #[test]
    fn the_grid_question_is_one_of_the_wizard_steps_so_back_on_it_returns_to_a_checklist() {
        // PROVES that Back on "Which kind of grid?" has somewhere to go.
        //
        // The question used to be asked after the group loop had already ended, with a
        // steps.next() of its own. Back there moved the wizard's position back to a group, but
        // nothing re-ran that group: the builder carried straight on to write the draft with no
        // kind chosen, and the generator refused it ("A grid needs one of the grid recipes").
        // Pressing a key the screen offers should never end in a refusal.
        //
        // The fix is that the question is one of the steps the wizard walks, which is what this
        // checks. The Wizard's own Back and Ctrl+C behaviour is covered in cli_ui, under the lock
        // its tests share; this one deliberately builds no Wizard, so it cannot disturb them.
        let grid = Chosen { group: Group::GridWorkers, id: "grid.create", name: "Create a grid" };
        let chosen = vec![grid];
        assert!(
            (0..STEPS).any(|at| step_at(at, &chosen) == Step::GridKind),
            "the grid question must be one of the wizard's own steps, or Back on it falls through to the write",
        );
        // Each group is asked once, in order, before it.
        for (at, group) in Group::ALL.iter().enumerate() {
            assert_eq!(step_at(at, &chosen), Step::Group(*group));
        }
        assert_eq!(step_at(Group::ALL.len(), &chosen), Step::GridKind, "and it comes after them all");

        // With no grid ticked there is nothing to ask there, so it is skipped rather than asked
        // with one answer, and it is not a step Back can return to either.
        assert_eq!(step_at(Group::ALL.len(), &[]), Step::Nothing);
        // Joining a grid someone else runs needs the kind just as much as creating one.
        let joined = vec![Chosen { group: Group::GridWorkers, id: "grid.join", name: "Join a grid" }];
        assert_eq!(step_at(Group::ALL.len(), &joined), Step::GridKind);
    }
    use super::*;

    /// `template plan` of a package names the instance as `template run` would and needs no secret:
    /// the Sandbox Grid example plans with only its public answers, and says which secret a run
    /// asks for.
    #[test]
    fn a_package_plans_without_its_secrets_and_names_the_ones_a_run_asks_for() {
        // Moved out of examples/hub on 2026-10-26: the grids are no longer published as examples,
        // only kept as test packages for the parts a template can still build on.
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../setup/tests/fixtures/packages/sandbox-grid");
        let files = crate::hub::scan::collect(&folder).unwrap().files;
        let checked = crate::hub::plan::check_files(&files).unwrap_or_else(|problems| panic!("{}", crate::hub::plan::problems_text("the example", &problems)));
        let package = yougori_setup::plan::Package { checked, components: Default::default(), item: None, digest: None };
        let host = yougori_setup::plan::Host { yougori: "1.2.0".into(), ..crate::hub::plan::host_here() };
        let answers = |pairs: &[(&str, &str)]| yougori_setup::plan::Answers { inputs: pairs.iter().map(|(id, value)| ((*id).to_owned(), (*value).to_owned())).collect(), ..Default::default() };
        let create = answers(&[("mode", "create"), ("grid_name", "Acme"), ("coordinator_address", "192.0.2.10"), ("reach", "lan"), ("share_mode", "automatic"), ("first_person", "no")]);

        let planned = package_plan(&package, create.clone(), None, &host).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(planned["instance"], package.checked.template.name());
        assert_eq!(planned["secretsAtRun"], json!(["grid_password"]), "only the secret this plan asks for");
        assert!(plan_view(&planned).ends_with("Asked for when you run it: grid_password. Secrets are never part of a plan."), "{}", plan_view(&planned));
        assert_eq!(package_plan(&package, create.clone(), Some("acme-grid"), &host).unwrap()["instance"], "acme-grid");
        let refused = package_plan(&package, create, Some("not a name"), &host).unwrap_err();
        assert!(refused.contains("The instance name must use 1 to 40 letters"), "{refused}");
    }

    #[test]
    fn reveal_lists_names_only_and_shows_a_value_with_a_word_on_keeping_it_private() {
        let listed = reveal_view("acme", &json!({"setupId": "setup-1", "private": [{"key": "invite", "label": "Grid invite"}]}));
        assert_eq!(listed, "Private outputs, shown only when you ask:\n  invite — Grid invite\nShow one with: yougori template reveal acme invite");
        assert_eq!(reveal_view("acme", &json!({"setupId": "setup-1", "private": []})), "This setup has nothing private to show.");
        let shown = reveal_view("acme", &json!({"setupId": "setup-1", "key": "invite", "label": "Grid invite", "value": "desk-invite:abc"}));
        assert_eq!(shown, "Grid invite: desk-invite:abc\nKeep it private: give it only to the people it is for.");
    }

    #[test]
    fn the_backups_usage_says_a_restore_is_reviewed_before_it_happens() {
        assert!(BACKUPS_USAGE.contains("On its own it changes nothing"));
        assert!(BACKUPS_USAGE.contains("--over-original"));
        assert!(BACKUPS_USAGE.contains("Add --yes to go ahead"));
        // The feature's own words about what a backup cannot carry, so the terminal says the same
        // thing the package README does.
        assert!(BACKUPS_USAGE.contains("credential store"));
        assert!(BACKUPS_USAGE.contains("copy that folder elsewhere"));
    }

    #[test]
    fn the_backups_list_shows_every_kept_copy_and_what_a_backup_cannot_carry() {
        let shown = backups_view(&json!({
            "volumes": [{
                "resource": "app-data", "through": "backup", "schedule": "every day at 02:00, this computer's time",
                "keep": 7, "kept": 2, "paused": false, "nextWhen": "2026-10-27 02:00",
                "lastOutcome": "done", "lastWhen": "2026-10-26 02:00", "lastDetail": "Backed up 412 files.",
                "backups": [
                    {"id": "backup-b", "describe": "2026-10-26 02:00 — 412 files, 18 MB, taken with its sandboxes stopped"},
                    {"id": "backup-a", "describe": "2026-10-25 02:00 — 400 files, 17 MB, taken with its sandboxes stopped"}
                ]
            }],
            "limits": "A backup holds what is in the volume and nothing else."
        }));
        assert!(shown.contains("app-data: every day at 02:00"));
        assert!(shown.contains("Next backup: 2026-10-27 02:00."));
        assert!(shown.contains("Last run: done at 2026-10-26 02:00 — Backed up 412 files."));
        assert!(shown.contains("backup-b — 2026-10-26 02:00 — 412 files"));
        assert!(shown.contains("A backup holds what is in the volume and nothing else."));
    }

    #[test]
    fn a_setup_that_backs_nothing_up_says_so_rather_than_showing_an_empty_list() {
        let shown = backups_view(&json!({"volumes": [], "limits": "x"}));
        assert!(shown.contains("This setup backs nothing up."));
    }

    #[test]
    fn a_paused_schedule_says_why_and_how_to_resume() {
        let shown = backups_view(&json!({"volumes": [{
            "resource": "app-data", "schedule": "every day at 02:00", "keep": 7,
            "paused": true, "nextWhen": null, "lastOutcome": "never_run", "backups": []
        }]}));
        assert!(shown.contains("Paused while the setup is stopped. Starting the setup resumes it."));
        assert!(shown.contains("Last run: none yet."));
        assert!(shown.contains("Nothing kept yet."));
    }

    /// A removal review as the engine sends it (`views::plan`): a volume whose template asks is
    /// offered for deletion, with a writable-folder consent beside it that is not a deletion.
    fn removal_review() -> Value {
        json!({
            "setupId": "setup-1", "intent": "remove", "digest": "rm-1", "baseRevision": 4,
            "headline": "Removes Notes.",
            "steps": [
                { "title": "Remove app (sandbox)", "detail": "Its data is kept unless you delete it separately." },
                { "title": "Remove data (volume)" }
            ],
            "notes": [
                "The data of data is kept, and so are its 2 backups in Yougori's data folder on this computer, unless you tick its deletion below.",
                "Data is kept by default. Only what you tick below is deleted, and that can't be undone."
            ],
            "consents": [
                { "id": "write_folder:app/code", "message": "Let app change files in the folder you chose for code." },
                { "id": "delete_data:data", "message": "Also delete data: everything on it, and all of its backups (2 now) in Yougori's data folder on this computer. This can't be undone." }
            ]
        })
    }

    #[test]
    fn a_removal_review_shows_its_steps_and_every_note_on_the_data() {
        let lines = removal_lines(&removal_review());
        assert_eq!(lines[0], "Removes Notes.");
        assert!(lines.contains(&"  - Remove app (sandbox). Its data is kept unless you delete it separately.".to_owned()), "{lines:?}");
        assert!(lines.contains(&"  - Remove data (volume)".to_owned()), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("so are its 2 backups") && line.contains("unless you tick its deletion below")), "{lines:?}");
        assert!(lines.iter().any(|line| line.starts_with("Data is kept by default.")), "{lines:?}");
        // The renderer used before read a `review` key a removal plan does not have, so it told a
        // person about to remove a setup that "This plan makes no changes."
        assert_eq!(review_lines(&removal_review()["review"]), vec!["This plan makes no changes.".to_owned()]);
        assert!(!lines.iter().any(|line| line.contains("makes no changes")), "{lines:?}");
    }

    #[test]
    fn a_review_shows_every_line_a_tool_runs_cleaned_of_what_could_disguise_it() {
        let review = json!({"installs": [
            {"resource": "web", "tool": "acme/httpie", "commands": ["pip install httpie\u{1b}[2K", "echo \u{202e}ok"], "check": "http --version"},
            {"resource": "web", "tool": "ready", "commands": []},
        ]});
        let lines = review_lines(&review);
        assert_eq!(lines, vec![
            "Installs:".to_owned(),
            "  - acme/httpie in web".to_owned(),
            "      $ pip install httpie [2K".to_owned(),
            "      $ echo ok".to_owned(),
            "      check: $ http --version".to_owned(),
            "  - ready in web".to_owned(),
            "      nothing (its check must already pass)".to_owned(),
        ]);
    }

    #[test]
    fn only_deletions_the_review_offers_count_and_they_name_their_volumes() {
        let offered = offered_deletions(&removal_review());
        assert_eq!(offered.len(), 1, "a folder consent is not a deletion: {offered:?}");
        assert_eq!(offered[0].0, "delete_data:data");
        assert!(offered[0].1.contains("This can't be undone."));
        assert!(offered_deletions(&json!({ "consents": [] })).is_empty());
        assert!(offered_deletions(&json!({})).is_empty());
        assert_eq!(deleted_volumes(&["delete_data:data".into(), "write_folder:app/code".into(), "delete_data:cache".into(), "delete_grid:company".into()]), vec!["data", "cache", "company"]);
        // A grid deleted now rather than paused is offered like a volume's deletion.
        let grid = json!({ "consents": [{ "id": "delete_grid:company", "message": "Also delete the grid now." }, { "id": "write_folder:app/code", "message": "x" }] });
        assert_eq!(offered_deletions(&grid), vec![("delete_grid:company".to_owned(), "Also delete the grid now.".to_owned())]);
    }

    #[test]
    fn the_review_names_the_backup_and_says_nothing_was_changed() {
        let shown = restore_review_view(&json!({
            "reviewed": true, "applied": false,
            "setupId": "stp-1", "resource": "app-data", "backupId": "backup-b",
            "restoreTo": "original", "overwrites": true,
            "review": [
                "The backup from 2026-10-26 02:00 holds 412 files, 18 MB.",
                "Everything now on app-data is replaced by what this backup holds."
            ],
            "confirm": "restore-0123456789abcdef"
        }));
        assert!(shown.contains("Restoring app-data of stp-1 from the backup backup-b."));
        assert!(shown.contains("The backup from 2026-10-26 02:00 holds 412 files"));
        assert!(shown.contains("Everything now on app-data is replaced"));
        assert!(shown.contains("Nothing has been changed."));
        assert!(shown.contains("run the same command with --yes"));
    }

    #[test]
    fn the_check_view_says_the_backup_is_whole_and_that_nothing_changed() {
        let shown = backup_check_view(&json!({"files": 412, "when": "2026-10-26 02:00", "consistency": "live", "note": "It does not hold anything sealed to this computer."}));
        assert!(shown.contains("complete and unchanged: 412 file(s), taken 2026-10-26 02:00."));
        assert!(shown.contains("may be half-written"));
        assert!(shown.contains("sealed to this computer"));
        assert!(shown.contains("Nothing was changed."));
    }

    #[test]
    fn the_telemetry_usage_says_what_it_never_shows_and_that_nothing_is_sent() {
        assert!(TELEMETRY_USAGE.contains("read-only"));
        assert!(TELEMETRY_USAGE.contains("nothing is sent anywhere"));
        assert!(TELEMETRY_USAGE.contains("no
                destination to configure"));
        assert!(TELEMETRY_USAGE.contains("at most 50 setups"));
        assert!(TELEMETRY_USAGE.contains("30\ndays are not counted") || TELEMETRY_USAGE.contains("30 days"));
        for never in ["secrets", "tokens", "addresses", "filesystem paths", "account names", "refusal sentences"] {
            assert!(TELEMETRY_USAGE.contains(never), "the usage does not say it hides {never}");
        }
    }

    #[test]
    fn the_reading_prints_what_it_leaves_out_every_time() {
        let shown = telemetry_view(&json!({
            "setups": [{
                "setupId": "stp-1", "state": "running", "health": "degraded",
                "resources": {"owned": 3, "borrowed": 1, "drifting": ["store"]},
                "operations": {"windowDays": 30, "counted": 2, "failed": 1, "last": {"kind": "update", "state": "failed", "errorCode": "image_not_found"}},
                "backups": {"volumes": 1, "kept": 3, "failingNow": 0}
            }],
            "scope": "This shows the setups you can already list, and nothing beyond them.",
            "notShown": ["No secrets, credential names, tokens or sign-in state."],
            "retention": {"words": "Operations finished more than 30 days ago are not counted."},
            "next": "There are more setups. Ask again with cursor 20."
        }));
        assert!(shown.contains("stp-1: running, health degraded."));
        assert!(shown.contains("3 owned, 1 borrowed; 1 not as the setup wants (store)"));
        assert!(shown.contains("Last: update failed (image_not_found)"));
        assert!(shown.contains("Backups: 1 volume(s), 3 copies kept, 0 failing."));
        assert!(shown.contains("What this reading does not show:"));
        assert!(shown.contains("No secrets, credential names, tokens"));
        assert!(shown.contains("Operations finished more than 30 days ago are not counted."));
        assert!(shown.contains("Next: There are more setups. Ask again with cursor 20."));
    }

    #[test]
    fn a_reading_with_no_setups_says_so() {
        let shown = telemetry_view(&json!({"setups": [], "notShown": [], "retention": {}}));
        assert!(shown.contains("There are no setups to read."));
    }

    #[test]
    fn a_relative_migration_path_is_settled_where_the_person_typed_it() {
        let full = full_path("a-copy").unwrap();
        assert!(std::path::Path::new(&full).is_absolute());
        assert!(full_path("  ").is_err());
        let kept = full_path(if cfg!(windows) { r"C:\copies\yougori" } else { "/copies/yougori" }).unwrap();
        assert!(std::path::Path::new(&kept).is_absolute() && kept.contains("copies"));
    }

    #[test]
    fn the_migration_usage_says_it_works_on_a_copy_and_that_live_is_refused() {
        assert!(MIGRATION_USAGE.contains("Work on a copy"));
        assert!(MIGRATION_USAGE.contains("is refused"));
        assert!(MIGRATION_USAGE.contains("--allow-live"));
        assert!(MIGRATION_USAGE.contains("nothing passes\nit for you"));
        for verb in ["inventory", "backup", "verify", "rehearse"] {
            assert!(MIGRATION_USAGE.contains(verb), "the usage does not mention {verb}");
        }
    }

    #[test]
    fn the_inventory_view_names_unreadable_records_rather_than_leaving_them_out() {
        let shown = inventory_view(&json!({
            "products": [
                {"name": "Neo Grid", "present": true, "records": [
                    {"id": "neo-grid/hub", "file": "grid/hub.json", "found": {"state": "present"}},
                    {"id": "neo-grid/tunnel", "file": "grid/tunnel.json", "found": {"state": "unreadable"}}
                ]},
                {"name": "Access Grid", "present": false, "records": []}
            ],
            "totals": {"instances": 2},
            "notes": ["This is a reading only."]
        }));
        assert!(shown.contains("Neo Grid: 1 record(s), 1 that can't be read."));
        assert!(shown.contains("can't be read: neo-grid/tunnel"));
        assert!(shown.contains("Access Grid: nothing here."));
        assert!(shown.contains("Template instances (v1): 2."));
        assert!(shown.contains("This is a reading only."));
    }

    #[test]
    fn the_backup_view_says_what_a_backup_cannot_carry_and_what_to_do_next() {
        let shown = backup_view(&json!({"backup": {
            "files": [{"id": "neo-grid/hub"}],
            "leftBehind": [{"id": "neo-grid/tunnel", "why": "It could not be read."}],
            "cannotCarry": ["Passwords and keys are held by this computer's credential store."],
            "notes": ["A backup is not a rollback."]
        }}));
        assert!(shown.contains("Backed up 1 record(s)"));
        assert!(shown.contains("Not copied: neo-grid/tunnel"));
        assert!(shown.contains("credential store"));
        assert!(shown.contains("yougori setup migration verify"));
    }

    #[test]
    fn the_rehearsal_view_names_every_difference_and_what_would_not_be_adopted() {
        let shown = rehearse_view(&json!({
            "intended": [
                {"name": "Neo Grid (hub on this computer)", "setupId": "adopted-neo-grid-hub", "carries": ["a", "b"], "blocked": null},
                {"name": "Swarm Mining (hub on this computer)", "blocked": "Swarm Mining is left as it is; it is managed on its own, not from here."}
            ],
            "differences": ["counts — Swarm Mining records: was 2 found, would be 0 carried."],
            "notes": ["Nothing was changed."]
        }));
        assert!(shown.contains("would become adopted-neo-grid-hub, carrying 2 record(s)"));
        assert!(shown.contains("would not be adopted. Swarm Mining is left as it is; it is managed on its own, not from here."));
        assert!(shown.contains("1 difference(s) to look at:"));
        assert!(shown.contains("Nothing was changed."));
    }

    #[test]
    fn a_rehearsal_with_no_differences_says_so(){
        let shown = rehearse_view(&json!({"intended": [], "differences": [], "notes": []}));
        assert!(shown.contains("Nothing here would become a setup."));
        assert!(shown.contains("no differences."));
    }

    #[test]
    fn the_verify_view_names_each_problem() {
        let shown = verify_view(&json!({"checked": 3, "matched": 2, "problems": [{"id": "neo-grid/hub", "what": "This file is not the same."}], "notes": ["Not complete."]}));
        assert!(shown.contains("Checked 3 file(s); 2 match."));
        assert!(shown.contains("Problem: neo-grid/hub — This file is not the same."));
        assert!(shown.contains("Not complete."));
    }

    #[test]
    fn planning_an_installed_setup_by_its_name_plans_a_change_to_that_setup() {
        // Found on a real engine: `template plan tiny-a` sent the name where the engine wants the
        // setup's id, and was told the setup was not on this computer.
        let _engine = crate::client::fake_engine::install(|method, params| match method {
            "setup_list" => Ok(json!({"setups": [{"setupId": "setup-7", "name": "tiny-a"}]})),
            "setup_plan" => {
                assert_eq!(params["source"], json!({"kind": "installed_setup", "setupId": "setup-7"}));
                assert_eq!(params["existingSetup"], "setup-7", "a change to that setup, as configure plans it");
                Ok(json!({"setupId": "setup-7", "digest": "d", "baseRevision": 4}))
            }
            other => panic!("unexpected engine call {other}"),
        });
        let inputs = vec![("greeting".to_owned(), "hello".to_owned())];
        let planned = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(plan("tiny-a", None, &inputs, None, &[]))
            .unwrap_or_else(|said| panic!("the plan was refused: {said}"));
        assert_eq!(planned["baseRevision"], 4);
    }

    #[test]
    fn an_engine_that_stops_mid_change_is_said_as_a_change_part_done_not_one_never_sent() {
        // Found on a real engine killed mid-step: the run said "not submitted" about a change
        // that was sent and half done.
        let said = engine_lost("tiny-c", "Cannot reach the Yougori engine because it is not running. Start it with yougori app start.".into());
        assert!(said.contains("part done") && said.contains("yougori template continue tiny-c") && said.contains("nothing is done twice"), "{said}");
        assert_eq!(engine_lost("tiny-c", "The plan changed.".into()), "The plan changed.", "any other error is passed on as it came");
    }

    /// PROVES a change waiting for an answer carries a code of its own, so a program can tell it
    /// from one that failed. Found on a real engine: `template continue` said `operation_failed`.
    #[tokio::test]
    async fn a_change_waiting_for_an_answer_is_coded_as_waiting_not_failed() {
        let failed = crate::client::capture_errors(async { Err::<(), _>(settled_words("shop", &waiting_for("secret_needed", Some("token")))) }).await.unwrap_err();
        assert!(failed.error.as_deref().is_some_and(|said| said.contains("yougori template configure shop --secrets -")), "{:?}", failed.error);
        let details = failed.error_details.unwrap();
        assert_eq!((details.code.as_str(), details.outcome.as_str(), details.retryable), ("awaiting_input", "awaiting_input", false));
    }

    #[test]
    fn group_words_cover_every_group() {
        // Each of the six groups has a short word in the shared registry, which is what --group
        // takes; the words map back to the groups, and the usage lists the same six.
        let keys: Vec<&str> = Group::ALL.iter().map(|group| group.key()).collect();
        assert_eq!(keys, ["grid", "models", "web", "people", "data", "automation"]);
        assert_eq!(group_from_word("grid"), Some(Group::GridWorkers));
        assert_eq!(group_from_word("GRID"), Some(Group::GridWorkers));
        assert_eq!(group_from_word("people_access"), Some(Group::PeopleAccess));
        assert_eq!(group_from_word("nonsense"), None);
        assert_eq!(group_from_word("Grid & workers"), None, "a display name is not a name for a group");
    }

    #[test]
    fn availability_words_and_codes_are_the_four_states() {
        // The registry's words and codes, read here and shown by the desktop from the same table.
        for (availability, word, code) in [
            (Availability::Available, "Available", "available"),
            (Availability::NeedsConfiguration, "Needs configuration", "needs_configuration"),
            (Availability::Unsupported, "Unsupported here", "unsupported"),
            (Availability::Planned, "Planned", "planned"),
        ] {
            assert_eq!(availability.words(), word);
            assert_eq!(availability.id(), code);
            assert_eq!(availability_text(Some(code)), Some(word));
        }
        assert_eq!(availability_text(None), None);
        assert_eq!(availability_text(Some("odd")), None);
    }

    #[test]
    fn source_ref_reads_each_form() {
        // A pinned hub ref carries its version.
        assert_eq!(
            source_ref("hub/you-gori/sandbox-grid@1.2.0").unwrap(),
            json!({"kind":"hub","publisher":"you-gori","name":"sandbox-grid","version":"1.2.0"})
        );
        // An unpinned hub ref omits the version — never a literal "latest" — so the engine decides it.
        assert_eq!(
            source_ref("hub/you-gori/neo-grid").unwrap(),
            json!({"kind":"hub","publisher":"you-gori","name":"neo-grid"})
        );
        // A bare word is an installed setup id.
        let setup = source_ref("my-setup").unwrap();
        assert_eq!(setup["kind"], "installed_setup");
        assert_eq!(setup["setupId"], "my-setup");
        // A path that was clearly meant as a folder but does not exist is an error, not a setup id.
        assert!(source_ref("./does-not-exist").is_err());
        assert!(source_ref("some/missing/path").is_err());
    }

    #[test]
    fn answers_parse_json_values_but_keep_plain_strings() {
        let got = answers(&[
            ("port".into(), "8080".into()),
            ("name".into(), "my app".into()),
            ("free".into(), "true".into()),
        ]);
        assert_eq!(got[0], json!({"field":"port","value":8080}));
        assert_eq!(got[1], json!({"field":"name","value":"my app"}));
        assert_eq!(got[2], json!({"field":"free","value":true}));
    }

    #[test]
    fn operation_id_is_prefixed_and_within_the_engine_rule() {
        let id = operation_id().expect("secure randomness is available in tests");
        assert!(id.starts_with("op-"));
        assert!(id.len() <= 128);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)), "{id}");
    }

    #[test]
    fn capabilities_view_lists_groups_and_states() {
        let value = json!({
            "availabilityKnown": true,
            "groups": [{
                "id": "grid_workers",
                "name": "Grid & workers",
                "capabilities": [{
                    "id": "grid.create",
                    "name": "Create a grid",
                    "summary": "Start a grid this computer coordinates.",
                    "availability": "available",
                    "availabilityText": "Available",
                    "reason": null,
                    "profiles": [],
                }],
            }],
        });
        let text = capabilities_view(&value);
        assert!(text.contains("Grid & workers"));
        assert!(text.contains("Create a grid — Available"));
        assert!(text.contains("Start a grid this computer coordinates."));
    }

    #[test]
    fn capabilities_view_says_when_the_host_is_unknown() {
        let value = json!({ "availabilityKnown": false, "groups": [] });
        assert!(capabilities_view(&value).contains("yougori app start"));
    }

    #[test]
    fn an_update_whose_new_version_changed_a_question_shows_the_conflict_and_applies_nothing_unasked() {
        // PROVES the update side of sharing a folder: a setup made from an exported recipe, whose
        // folder now holds a newer version that dropped one question and added a required one.
        // The engine's plan names each as a conflict; the CLI hands that back before anything is
        // applied, in a script (no --yes) and in its result, rather than writing the new version's
        // defaults over the person's answers. The engine here is this test's own.
        let conflicts = json!([
            {"code": "question_removed", "message": "Version 2.0.0 no longer asks \"Which region?\"; your answer eu is dropped."},
            {"code": "new_required_question", "message": "Version 2.0.0 asks a new question that needs an answer: Which currency?"},
        ]);
        let engine = {
            let conflicts = conflicts.clone();
            move |method: &str, params: &Value| match method {
                "app_status" => Ok(json!({"running": true})),
                "setup_list" => Ok(json!({"setups": [{"setupId": "setup-7", "name": "notes", "source": {"kind": "local_folder", "path": "C:/recipes/notes"}}]})),
                "setup_plan" => {
                    assert_eq!(params["existingSetup"], "setup-7", "planned as a change to the setup, not as a new one");
                    assert_eq!(params["source"], json!({"kind": "local_folder", "path": "C:/recipes/notes"}), "read again from the folder as it is now");
                    assert_eq!(params["answers"], json!([{"field": "currency", "value": "EUR"}]), "the answer given for the new question travels; nothing else is re-answered");
                    Ok(json!({"setupId": "setup-7", "digest": "plan-digest", "baseRevision": 3, "review": {}, "plan": {}, "conflicts": conflicts.clone()}))
                }
                other => panic!("unexpected engine call {other}"),
            }
        };
        let _engine = crate::client::fake_engine::install(engine.clone());
        let inputs = vec![("currency".to_owned(), "EUR".to_owned())];
        let shown = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(update("notes", &inputs, None, false, false, false))
            .unwrap_or_else(|said| panic!("the update was refused: {said}"));
        assert_eq!(shown["applied"], false);
        assert_eq!(shown["needsConfirmation"], true, "a script without --yes gets the plan and changes nothing");
        assert_eq!(shown["conflicts"], conflicts, "the conflicts are at the top of the result, not only inside the plan");
        assert!(!crate::client::fake_engine::called("setup_apply"), "nothing was applied");

        // With --yes the apply goes ahead on the plan shown, and the result still names the
        // conflicts, so a script that said yes can see what the new version changed.
        let _engine = crate::client::fake_engine::install(move |method, params| match method {
            "setup_apply" => {
                assert_eq!(params["setupId"], "setup-7");
                assert_eq!(params["planDigest"], "plan-digest");
                assert_eq!(params["expectedRevision"], 3);
                assert!(params.get("secrets").is_none(), "no secrets were given, none travel");
                Ok(json!({"operationId": "op-1"}))
            }
            "setup_operation" => Ok(json!({"state": "completed", "events": [], "nextCursor": 1})),
            other => engine(other, params),
        });
        let shown = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(update("notes", &inputs, None, false, true, false))
            .unwrap_or_else(|said| panic!("the update was refused: {said}"));
        assert_eq!(shown["applied"], true);
        assert_eq!(shown["conflicts"], conflicts);
    }

    #[test]
    fn an_update_reads_the_newest_version_of_where_a_setup_came_from() {
        let hub = update_source("shop", &json!({"kind": "hub", "publisher": "acme", "name": "shop", "version": "1.0.0"})).unwrap();
        assert_eq!(hub, json!({"kind": "hub", "publisher": "acme", "name": "shop", "version": "latest"}));
        let folder = json!({"kind": "local_folder", "path": "C:/work/shop"});
        assert_eq!(update_source("shop", &folder).unwrap(), folder);
        let joined = update_source("member", &json!({"kind": "installed_setup", "setupId": "joined"})).unwrap_err();
        assert!(joined.contains("yougori template configure member") && joined.contains("Nothing was changed"), "{joined}");
    }

    // ----- A change waiting for an answer, answered through `template configure` -----

    /// Runs a command's future on this thread, where the test's fake engine is installed.
    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
    }

    /// The progress of a change waiting for a secret, as the engine reports it: the operation,
    /// the digest of the plan it applies, and which question's value it lacks.
    fn waiting_for(code: &str, field: Option<&str>) -> Value {
        let mut error = json!({
            "code": code, "severity": "error", "retryable": false,
            "message": "app needs the value of token before it can be created.",
            "operation": "op-waiting",
            "nextActions": [{"kind": "continue", "operation": "op-waiting"}, {"kind": "cancel", "operation": "op-waiting"}],
        });
        if let Some(field) = field {
            error["field"] = json!(field);
        }
        json!({
            "operation": {"operationId": "op-waiting", "setupId": "setup-9"},
            "state": "awaiting_input", "events": [], "nextCursor": 1,
            "planDigest": "reviewed-digest",
            "error": error,
        })
    }

    /// An engine with one setup, `shop`, whose last change is `waiting`; once answered, the
    /// operation that asked finishes, and `secrets` says what the apply must carry.
    fn engine_waiting(waiting: Value, secrets: Value) -> impl Fn(&str, &Value) -> Result<Value, String> {
        move |method: &str, params: &Value| match method {
            "app_status" => Ok(json!({"running": true})),
            "setup_list" => Ok(json!({"setups": [{"setupId": "setup-9", "name": "shop", "source": {"kind": "local_folder", "path": "C:/recipes/shop"}}]})),
            "setup_get" => Ok(json!({"setupId": "setup-9", "revision": 4})),
            "setup_operation" if crate::client::fake_engine::called("setup_apply") => {
                assert_eq!(params["operationId"], "op-waiting", "the same operation is followed");
                Ok(json!({"operation": {"operationId": "op-waiting", "setupId": "setup-9"}, "state": "completed", "events": [{"cursor": 1, "message": "Finished."}], "nextCursor": 2}))
            }
            "setup_operation" => Ok(waiting.clone()),
            "setup_apply" => {
                assert_eq!(params["setupId"], "setup-9");
                assert_eq!(params["operationId"], "op-waiting", "the operation that asked, never a new one");
                assert_eq!(params["planDigest"], "reviewed-digest", "the plan the person reviewed");
                assert_eq!(params["expectedRevision"], 4);
                assert_eq!(params["secrets"], secrets);
                Ok(json!({"operationId": "op-waiting", "setupId": "setup-9"}))
            }
            other => panic!("unexpected engine call {other}"),
        }
    }

    #[test]
    fn a_setup_waiting_for_a_secret_is_answered_through_configure_and_nothing_is_planned_or_made_twice() {
        // PROVES the recovery path the plan found unfinished: a change that stopped to ask for a
        // secret holds its setup, so `configure` used to plan a second change and be refused as
        // busy. Now it answers the change that asked, with that operation's id and the digest of
        // the plan the person reviewed, so the engine joins it (`continue_operation`) rather than
        // creating anything twice. The engine here is this test's own.
        let _engine = crate::client::fake_engine::install(engine_waiting(waiting_for("secret_needed", Some("token")), json!({"token": "S3CRET-VALUE"})));
        let shown = run(configure_given("shop", &[], &[], None, Some(json!({"token": "S3CRET-VALUE"})), false, false, false))
            .unwrap_or_else(|said| panic!("the answer was refused: {said}"));
        assert_eq!((&shown["answered"], &shown["applied"], &shown["planned"]), (&json!(true), &json!(true), &json!(false)));
        assert_eq!(shown["operation"]["state"], "completed");
        assert!(!crate::client::fake_engine::called("setup_plan"), "nothing was planned again");
        assert_eq!(crate::client::fake_engine::calls().iter().filter(|(method, _)| method == "setup_apply").count(), 1);
        // The value went to the engine once, with the apply, and nowhere else: not in another call,
        // not in the result a script reads.
        for (method, params) in crate::client::fake_engine::calls() {
            assert!(method == "setup_apply" || !params.to_string().contains("S3CRET-VALUE"), "{method} carried the secret");
        }
        assert!(!shown.to_string().contains("S3CRET-VALUE"), "{shown}");
    }

    /// PROVES `template continue --secrets -` answers a change waiting for a secret the way
    /// `configure` does. Found cutting off a real run: the secret given to continue was read and
    /// dropped, and the change asked for it again.
    #[test]
    fn continue_with_secrets_answers_the_change_waiting_for_one() {
        let _engine = crate::client::fake_engine::install(engine_waiting(waiting_for("secret_needed", Some("token")), json!({"token": "S3CRET-VALUE"})));
        let shown = run(continue_setup("shop", "setup-9", false, Some(json!({"token": "S3CRET-VALUE"})), false)).unwrap_or_else(|said| panic!("{said}"));
        assert_eq!((&shown["continued"], &shown["answered"], &shown["operation"]["state"]), (&json!(true), &json!(true), &json!("completed")));
        assert_eq!(crate::client::fake_engine::calls().iter().filter(|(method, _)| method == "setup_apply").count(), 1);
        assert!(!crate::client::fake_engine::called("setup_action"), "the waiting change is answered, not retried as another");
        let refused = run(continue_setup("shop", "setup-9", true, None, false)).unwrap_err();
        assert!(refused.contains("can't be changed on a change that is already under way") && refused.contains("Nothing was changed"), "{refused}");
    }

    #[test]
    fn an_answer_that_leaves_out_what_was_asked_is_refused_before_anything_is_sent() {
        let _engine = crate::client::fake_engine::install(engine_waiting(waiting_for("secret_needed", Some("token")), json!({})));
        // A value for something else would only have the engine ask again.
        let refused = run(configure_given("shop", &[], &[], None, Some(json!({"other": "x"})), false, false, false)).unwrap_err();
        assert!(refused.contains("don't include token"), "{refused}");
        assert!(refused.contains("Nothing was changed"), "{refused}");
        // No value at all, in a script: the working command is named, with the question.
        let refused = run(configure_given("shop", &[], &[], None, None, false, false, false)).unwrap_err();
        assert!(refused.contains("yougori template configure shop --secrets -"), "{refused}");
        assert!(refused.contains("{\"token\": \"…\"}"), "it says which key the JSON object needs: {refused}");
        assert!(refused.contains("yougori call setup_cancel --setup-id setup-9 --operation-id op-waiting --yes"), "and how to give the change up, by the engine's ids: {refused}");
        // An input or binding can't change a change that is under way.
        let refused = run(configure_given("shop", &[("size".to_owned(), "large".to_owned())], &[], None, Some(json!({"token": "x"})), false, false, false)).unwrap_err();
        assert!(refused.contains("already under way"), "{refused}");
        let refused = run(configure_given("shop", &[], &[("data".to_owned(), "D:/shop".to_owned())], None, Some(json!({"token": "x"})), false, false, false)).unwrap_err();
        assert!(refused.contains("already under way"), "{refused}");
        // A dry run says what is waiting and what would answer it, and sends nothing.
        let shown = run(configure_given("shop", &[], &[], None, None, false, true, false)).unwrap();
        assert_eq!((&shown["waiting"], &shown["applied"], &shown["field"]), (&json!(true), &json!(false), &json!("token")));
        assert_eq!(shown["next"], "yougori template configure shop --secrets -");
        assert!(!crate::client::fake_engine::called("setup_apply") && !crate::client::fake_engine::called("setup_plan"), "nothing was sent or planned");
    }

    #[test]
    fn a_change_waiting_for_an_agreement_cannot_be_answered_from_here_and_says_how_to_give_it_up() {
        // A review's agreement (a sandbox changing files in a chosen folder) is not a secret: the
        // change has to be reviewed again, which means giving this one up first. The words say
        // exactly that, with the engine's own ids, rather than the busy refusal.
        let mut waiting = waiting_for("folder_consent_needed", None);
        waiting["error"]["message"] = json!("app keeps a copy of the folder you chose for data and changes files in it, so it needs your agreement when the setup is applied. Review the setup again and agree to that.");
        let _engine = crate::client::fake_engine::install(engine_waiting(waiting, json!({})));
        let refused = run(configure_given("shop", &[], &[], None, Some(json!({"token": "x"})), false, false, false)).unwrap_err();
        assert!(refused.contains("needs your agreement"), "{refused}");
        assert!(refused.contains("yougori call setup_cancel --setup-id setup-9 --operation-id op-waiting --yes"), "{refused}");
        assert!(refused.contains("review the setup again with yougori template configure shop"), "{refused}");
        assert!(!crate::client::fake_engine::called("setup_apply") && !crate::client::fake_engine::called("setup_plan"));
    }

    #[test]
    fn an_answer_to_a_change_cancelled_meanwhile_says_so_rather_than_claiming_success() {
        // Between reading the waiting change and answering it, someone cancelled it in the app.
        // The engine joins the operation as it is (cancelled arrives as failed, with its code), and
        // the CLI reports the cancellation: it never says the answer was taken.
        let _engine = crate::client::fake_engine::install(move |method: &str, params: &Value| match method {
            "setup_operation" if crate::client::fake_engine::called("setup_apply") => Ok(json!({
                "operation": {"operationId": "op-waiting", "setupId": "setup-9"}, "state": "failed", "events": [], "nextCursor": 2,
                "error": {"code": "operation_cancelled", "message": "This change was cancelled. Everything already created is still tracked.", "retryable": true, "severity": "error", "nextActions": [{"kind": "retry"}]},
            })),
            other => engine_waiting(waiting_for("secret_needed", Some("token")), json!({"token": "x"}))(other, params),
        });
        let said = run(configure_given("shop", &[], &[], None, Some(json!({"token": "x"})), false, false, false)).unwrap_err();
        let cancelled = crate::wire::cancellation(&said).expect("reported as a cancellation, not a failure");
        assert!(cancelled.contains("was cancelled") && cancelled.contains("yougori template continue shop"), "{cancelled}");
        assert!(!said.contains("answered"), "{said}");
    }

    #[test]
    fn a_setup_that_is_not_waiting_is_configured_as_before() {
        // The ordinary path is untouched: a finished last change means a new plan, reviewed and
        // applied by its digest, with the secrets travelling only in the apply.
        let _engine = crate::client::fake_engine::install(|method: &str, params: &Value| match method {
            "app_status" => Ok(json!({"running": true})),
            "setup_list" => Ok(json!({"setups": [{"setupId": "setup-9", "name": "shop", "source": {"kind": "local_folder", "path": "C:/recipes/shop"}}]})),
            "setup_operation" if !crate::client::fake_engine::called("setup_apply") => Ok(json!({"operation": {"operationId": "op-1", "setupId": "setup-9"}, "state": "completed", "events": [], "nextCursor": 1})),
            "setup_operation" => Ok(json!({"operation": {"operationId": "op-2", "setupId": "setup-9"}, "state": "completed", "events": [], "nextCursor": 1})),
            "setup_plan" => {
                assert_eq!(params["existingSetup"], "setup-9");
                assert_eq!(params["bindings"], json!([{"field": "token", "secretRef": "apply:token"}]), "the plan sees a reference, never the value");
                Ok(json!({"setupId": "setup-9", "digest": "plan-2", "baseRevision": 5, "review": {}, "plan": {}}))
            }
            "setup_apply" => {
                assert_eq!(params["planDigest"], "plan-2");
                assert_eq!(params["expectedRevision"], 5);
                assert_eq!(params["secrets"], json!({"token": "x"}));
                Ok(json!({"operationId": params["operationId"], "setupId": "setup-9"}))
            }
            other => panic!("unexpected engine call {other}"),
        });
        let shown = run(configure_given("shop", &[], &[], None, Some(json!({"token": "x"})), true, false, false)).unwrap();
        assert_eq!((&shown["planned"], &shown["applied"]), (&json!(true), &json!(true)));
        assert!(shown.get("answered").is_none());
    }

    // ----- `template continue` after an unknown outcome, and after a cancellation -----

    fn progress(operation: &str, state: &str, error: Option<Value>) -> Value {
        let mut value = json!({"operation": {"operationId": operation, "setupId": "setup-9"}, "state": state, "events": [], "nextCursor": 1});
        if let Some(error) = error {
            value["error"] = error;
        }
        value
    }

    fn unknown_outcome() -> Value {
        json!({"code": "outcome_unknown", "message": "Can't tell whether creating app took effect. Checking before anything else runs.", "retryable": true, "severity": "error", "operation": "op-3", "nextActions": [{"kind": "reconcile", "operation": "op-3"}]})
    }

    /// An engine whose last change to `setup-9` has an unknown outcome; `settled` is what its
    /// reconciliation finds.
    fn engine_unknown(settled: Value) -> impl Fn(&str, &Value) -> Result<Value, String> {
        move |method: &str, params: &Value| match method {
            "setup_operation" if params.get("operationId").is_none() => Ok(progress("op-3", "unknown", Some(unknown_outcome()))),
            "setup_operation" => Ok(progress("op-3", "completed", None)),
            "setup_action" if params["action"] == "reconcile" => {
                assert_eq!(params["operationId"], "op-3");
                Ok(settled.clone())
            }
            "setup_action" if params["action"] == "retry" => {
                assert_eq!(params["operationId"], "op-3", "the same operation carries on; nothing new is started");
                Ok(json!({"operationId": "op-3", "setupId": "setup-9"}))
            }
            other => panic!("unexpected engine call {other} {params}"),
        }
    }

    fn actions() -> Vec<String> {
        crate::client::fake_engine::calls().into_iter().filter(|(method, _)| method == "setup_action").map(|(_, params)| params["action"].as_str().unwrap_or_default().to_owned()).collect()
    }

    #[test]
    fn continue_after_an_unknown_outcome_has_the_engine_check_first_and_runs_nothing_blindly() {
        // PROVES the CLI no longer refuses an unknown outcome on its own. The engine owns what
        // unknown means: asked to reconcile, it looks at what the cut-off step left behind and says
        // whether the change failed and can go on, finished, or still can't be told. Only the
        // first of those is retried, and the retry names the same operation, so nothing is made
        // twice. The engine here is this test's own.
        let failed = progress("op-3", "failed", Some(json!({"code": "engine_interrupted", "message": "This change was interrupted.", "retryable": true, "severity": "error", "nextActions": [{"kind": "retry"}]})));
        let _engine = crate::client::fake_engine::install(engine_unknown(failed));
        let shown = run(retry("setup-9", false)).unwrap_or_else(|said| panic!("refused: {said}"));
        assert_eq!((&shown["continued"], &shown["reconciled"]), (&json!(true), &json!(true)));
        assert_eq!(actions(), ["reconcile", "retry"], "checked first, then carried on");
        assert_eq!(shown["operation"]["state"], "completed");

        // Reconciliation found the change had in fact finished: nothing runs again.
        let _engine = crate::client::fake_engine::install(engine_unknown(progress("op-3", "completed", None)));
        let shown = run(retry("setup-9", false)).unwrap();
        assert_eq!((&shown["continued"], &shown["reconciled"]), (&json!(false), &json!(true)));
        assert_eq!(actions(), ["reconcile"], "nothing was retried");

        // Still unknown after the check: honest, and nothing runs.
        let _engine = crate::client::fake_engine::install(engine_unknown(progress("op-3", "unknown", Some(unknown_outcome()))));
        let said = run(retry("setup-9", false)).unwrap_err();
        assert!(said.contains("still can't tell"), "{said}");
        assert!(said.contains("Nothing was run again"), "{said}");
        assert!(said.contains("yougori template logs setup-9"), "{said}");
        assert_eq!(actions(), ["reconcile"]);

        // A second continue, after the first carried the change to completion, runs nothing: the
        // engine says the last change finished, and that is the answer.
        let _engine = crate::client::fake_engine::install(|method: &str, _: &Value| match method {
            "setup_operation" => Ok(progress("op-3", "completed", None)),
            other => panic!("a finished change asked the engine to {other}"),
        });
        let shown = run(retry("setup-9", false)).unwrap();
        assert_eq!((&shown["continued"], &shown["reconciled"]), (&json!(false), &json!(false)));
    }

    #[test]
    fn a_cancelled_change_arrives_as_failed_with_its_code_and_is_said_as_a_cancellation() {
        // The engine's wire states have no `cancelled`: a cancelled operation is `failed` with the
        // error code `operation_cancelled` (`views::operation_state`). The CLI reads that, says it
        // was cancelled rather than that it failed, and `continue` carries it on through the same
        // retry the engine offers a cancelled change.
        let cancelled = || progress("op-4", "failed", Some(json!({"code": "operation_cancelled", "message": "This change was cancelled. Everything already created is still tracked.", "retryable": true, "severity": "error", "operation": "op-4", "nextActions": [{"kind": "retry"}]})));
        let said = settled_words("shop", &cancelled());
        let words = crate::wire::cancellation(&said).expect("a cancellation, not a failure");
        assert!(words.contains("was cancelled") && words.contains("is kept") && words.contains("yougori template continue shop"), "{words}");
        // A plain failure is not dressed up as one.
        let failed = progress("op-4", "failed", Some(json!({"code": "image_pull_failed", "message": "The image could not be downloaded.", "retryable": true, "severity": "error", "nextActions": [{"kind": "retry"}]})));
        let said = settled_words("shop", &failed);
        assert!(crate::wire::cancellation(&said).is_none());
        assert!(said.contains("could not be downloaded") && said.contains("yougori template continue shop"), "{said}");
        // Waiting and unknown each point at a working action.
        let said = settled_words("shop", &waiting_for("secret_needed", Some("token")));
        assert!(said.contains("yougori template configure shop --secrets -"), "{said}");
        let said = settled_words("shop", &progress("op-4", "unknown", Some(unknown_outcome())));
        assert!(said.contains("not known yet") && said.contains("yougori template continue shop") && said.contains("Nothing is done twice"), "{said}");

        let _engine = crate::client::fake_engine::install(move |method: &str, params: &Value| match method {
            "setup_operation" if params.get("operationId").is_none() => Ok(cancelled()),
            "setup_operation" => Ok(progress("op-4", "completed", None)),
            "setup_action" => {
                assert_eq!((params["action"].as_str(), params["operationId"].as_str()), (Some("retry"), Some("op-4")));
                Ok(json!({"operationId": "op-4", "setupId": "setup-9"}))
            }
            other => panic!("unexpected engine call {other}"),
        });
        let shown = run(retry("setup-9", false)).unwrap();
        assert_eq!((&shown["continued"], &shown["reconciled"]), (&json!(true), &json!(false)));
        assert_eq!(actions(), ["retry"]);
    }

    #[test]
    fn what_a_choice_needs_is_added_by_the_shared_generator_and_named() {
        // grid.worker_limits needs one of grid.create/grid.join. The wizard no longer resolves this
        // itself: the generator does, and tells us what it added, so the CLI and the app agree.
        let chosen = vec![Chosen { group: Group::GridWorkers, id: "grid.worker_limits", name: "Limit what workers use" }];
        // Sandbox Grid is the kind that offers worker limits; Neo refuses it, which is itself the
        // generator keeping a draft honest about what a given grid can do.
        let (files, added) = draft_files("needs-a-grid", Some("sandbox-grid"), &chosen).unwrap();
        assert!(!added.is_empty(), "a dependency should have been added and named");
        let yaml = String::from_utf8(files[crate::hub::format::TEMPLATE_FILE].clone()).unwrap();
        let parsed: yougori_setup::format::Template = serde_yaml_ng::from_str(&yaml).unwrap();
        let ids: Vec<&str> = parsed.capabilities.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"grid.create") || ids.contains(&"grid.join"), "{ids:?}");
        // Every id it reported as added is really in the package it wrote.
        for id in &added {
            assert!(ids.contains(&id.as_str()), "{id} was reported as added but is not in the package");
        }
    }

    #[test]
    fn the_cli_and_the_app_write_the_same_bytes_for_the_same_choices() {
        // The point of the shared generator: one set of ticks, one package, whichever door it came
        // through. The app sends a Draft to the engine; the CLI builds the same Draft from its own
        // wizard. If these ever diverge, the same choices stop meaning the same setup.
        let chosen = vec![
            Chosen { group: Group::GridWorkers, id: "grid.create", name: "Create a grid" },
            Chosen { group: Group::FilesData, id: "data.volumes", name: "Persistent volumes" },
        ];
        let (from_cli, _) = draft_files("same-both-ways", Some("neo-grid"), &chosen).unwrap();
        let app_draft = yougori_setup::draft::Draft {
            name: "same-both-ways".to_owned(),
            recipe: Some("neo-grid".to_owned()),
            capabilities: ["grid.create", "data.volumes"]
                .into_iter()
                .map(|id| (id.to_owned(), yougori_setup::draft::CapabilityChoice::default()))
                .collect(),
            ..yougori_setup::draft::Draft::default()
        };
        let from_app = yougori_setup::draft::to_package(&app_draft).unwrap().files();
        assert_eq!(from_cli.keys().collect::<Vec<_>>(), from_app.keys().collect::<Vec<_>>(), "the same files");
        for (path, bytes) in &from_cli {
            assert_eq!(bytes, &from_app[path], "{path} differs between the CLI and the app");
        }
    }

    #[test]
    fn draft_files_declare_the_chosen_capabilities_as_a_valid_v2_template() {
        let chosen = vec![
            Chosen { group: Group::GridWorkers, id: "grid.create", name: "Create a grid" },
            Chosen { group: Group::FilesData, id: "data.volumes", name: "Persistent volumes" },
        ];
        let (files, _) = draft_files("my-setup", Some("neo-grid"), &chosen).unwrap();
        let yaml = String::from_utf8(files[crate::hub::format::TEMPLATE_FILE].clone()).unwrap();
        // It is marked v2, so the v1 reader does not mistake it.
        assert!(yaml.contains("format_version: 2"));
        assert!(yaml.contains("name: my-setup"));
        assert!(files.contains_key("yougori.yaml"));
        // It round-trips through the format parser with the chosen capability ids — proving it is a
        // valid v2 template, not a v1 file the check/run/publish steps would reject.
        let parsed: yougori_setup::format::Template = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(parsed.format_version, Some(2));
        let ids: Vec<&str> = parsed.capabilities.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["grid.create", "data.volumes"]);
    }

    #[test]
    fn an_empty_draft_is_still_a_valid_v2_template() {
        let (files, _) = draft_files("empty", None, &[]).unwrap();
        let yaml = String::from_utf8(files[crate::hub::format::TEMPLATE_FILE].clone()).unwrap();
        let parsed: yougori_setup::format::Template = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(parsed.format_version, Some(2));
        assert!(parsed.capabilities.is_empty());
    }

    #[test]
    fn every_trusted_alias_names_one_template_and_only_one() {
        // This stood as "the table resolves nothing until the publisher is set", which was true
        // while the publisher was unknown and the table inert. The publisher is set now and
        // `a_short_name_resolves_only_through_the_trusted_table` covers the resolving, as that
        // test said it would. What is still worth holding is that the table itself stays
        // unambiguous: two entries sharing a term would make a short name mean two things, and
        // there is no choosing between them to offer.
        let mut terms = std::collections::HashSet::new();
        let mut templates = std::collections::HashSet::new();
        for alias in TRUSTED_ALIASES {
            assert_eq!(alias.term, alias.term.to_lowercase());
            assert!(terms.insert(alias.term), "two entries both answer to {}", alias.term);
            assert!(templates.insert(alias.template), "two short names both lead to {}", alias.template);
        }
    }

    #[test]
    fn logs_view_reads_events_and_points_to_the_next_cursor() {
        let value = json!({
            "events": [{"step":"reserving_storage","message":"Reserving 2 GiB."}],
            "nextCursor": 7,
            "truncated": false,
        });
        let text = logs_view(&value);
        assert!(text.contains("reserving_storage: Reserving 2 GiB."));
        assert!(text.contains("--cursor 7"));
    }

    #[test]
    fn setups_list_view_labels_kind_adoption_and_unobserved_state() {
        let setups = vec![
            json!({"name":"models","profile":"neo_grid","state":"running","stateObserved":true}),
            json!({"name":"old-desks","profile":"sandbox_grid","state":"stopped","adoptedLegacy":true,"stateObserved":false}),
        ];
        let text = setups_list_view(&setups);
        assert!(text.contains("Setups (template platform):"));
        assert!(text.contains("Neo Grid"));
        assert!(text.contains("running"));
        // An adopted grid is marked, and its unobserved state is said, not shown as a state word.
        assert!(text.contains("(adopted)"));
        assert!(text.contains("state not checked"));
    }

    #[test]
    fn setups_list_view_is_empty_when_there_are_no_setups() {
        assert!(setups_list_view(&[]).is_empty());
    }

    #[test]
    fn setup_view_shows_capabilities_outputs_and_unobserved_state() {
        let detail = json!({
            "summary": {"name":"shop","profile":"sandbox_grid","state":"running","stateObserved":true,"health":"ready"},
            "capabilities": [{"id":"people.workspaces","health":"ready"},{"id":"web.service","health":"needs_sign_in","detail":"Sign in to the provider."}],
            "outputs": [{"label":"Workspace link","value":"https://example.invalid/w"}],
        });
        let text = setup_view(&detail);
        assert!(text.contains("shop — Sandbox Grid"));
        assert!(text.contains("State: running"));
        assert!(text.contains("people.workspaces: ready"));
        assert!(text.contains("web.service: needs sign in — Sign in to the provider."));
        assert!(text.contains("Workspace link: https://example.invalid/w"));
    }

    #[test]
    fn setup_view_says_an_adopted_grid_is_managed_elsewhere() {
        let detail = json!({
            "summary": {"name":"legacy","profile":"neo_grid","state":"stopped","adoptedLegacy":true,"stateObserved":false},
        });
        let text = setup_view(&detail);
        assert!(text.contains("adopted from an older grid"));
        assert!(text.contains("Managed from its own tab in My setups"));
    }

    #[test]
    fn setup_view_shows_the_product_document_the_desktop_reads() {
        // The engine's own golden CORE-07 document of an old setup, so the terminal's words and
        // the contract cannot drift apart.
        let product: Value = serde_json::from_str(include_str!("../../../src-tauri/src/foundation/product/fixtures/v2/migration_needs_decision.json")).unwrap();
        let detail = json!({"summary": {"name":"legacy-lab","state":"running","stateObserved":true}, "product": product});
        let text = setup_view(&detail);
        assert!(text.contains("Move to VM sandboxes (an inventory; nothing has changed):"), "{text}");
        assert!(text.contains("  - web (vm): stays a VM sandbox"), "{text}");
        assert!(text.contains("  - api (container): becomes a VM sandbox: the container now runs inside a VM sandbox"), "{text}");
        assert!(text.contains("  - trainer (gpu): a decision is needed before it moves: a VM sandbox or GPU runtime (shared kernel), not a sandbox"), "{text}");
        assert!(text.contains("  - pod (cloud): a decision is needed before it moves: a VM sandbox or remote runtime (provider container), not a sandbox"), "{text}");
        assert!(text.contains("  - shared-db (shared): follows the setup that owns it"), "{text}");
        assert!(text.contains("  - analysis (tier T2): becomes a VM sandbox: isolation tier T2 becomes its explicit requirements"), "{text}");
        assert!(text.contains("  - scratch (tier T1): refused: tier T1 was a shared kernel"), "{text}");
        assert!(text.contains("  - metal-runner (host process model runtime): keeps its label: model runtime (host process, sandbox profile), not a sandbox"), "{text}");
        assert!(text.contains("Needs you:\n  - \"trainer\": the old setup ran this GPU sandbox"), "{text}");
        assert!(text.contains("(migration_decision_required). What you can do: choose one of the listed options; nothing is chosen for you."), "{text}");
        assert!(!text.contains("verified"), "a migration inventory claims no evidence: {text}");
    }

    #[test]
    fn setup_view_shows_requested_permissions_and_why_a_document_is_missing() {
        let detail = json!({
            "summary": {"name":"shop","state":"running","stateObserved":true},
            "product": {"contract_version": 2, "subject": {"kind":"setup","id":"shop"}, "permissions": [
                {"kind":"run_containers","text":"Run containers on this computer.","status":{"status":"requested"}},
                {"kind":"use_gpu","text":"Use this computer's GPU.","status":{"status":"permitted_by_contract"}},
            ]},
        });
        let text = setup_view(&detail);
        assert!(text.contains("Permissions:\n  - Run containers on this computer. (requested; asking grants nothing)\n  - Use this computer's GPU. (permitted by the contract)"), "{text}");
        assert!(!text.contains("Move to VM sandboxes") && !text.contains("Needs you"), "{text}");
        let missing = json!({"summary": {"name":"shop","state":"running","stateObserved":true}, "productUnavailable": "the engine's evidence clock is not available: starting"});
        assert!(setup_view(&missing).contains("Product view: not available (the engine's evidence clock is not available: starting)."));
        let none = setup_view(&json!({"summary": {"name":"shop","state":"running","stateObserved":true}}));
        assert!(!none.contains("Product view") && !none.contains("Permissions:"), "an engine without the document shows the setup as before: {none}");
    }

    /// A product document's permission lines, as the engine writes them, all in `status`.
    fn document(status: &str) -> Value {
        json!({"contract_version": 2, "subject": {"kind":"setup","id":"setup-1"}, "permissions": [
            {"kind":"run_containers","text":"Run containers on this computer.","status":{"status": status}},
            {"kind":"reserve_storage","text":"Reserve storage on a drive you choose.","status":{"status": status}},
        ]})
    }

    #[test]
    fn a_plans_review_shows_what_its_capabilities_ask_for_and_a_local_plan_reads_as_before() {
        let review = json!({"creates": [{"id":"app","kind":"environment","title":"app","placement":"this computer"}], "permissions": ["Run containers on this computer."]});
        let planned = json!({"setupId": "setup-1", "review": review, "product": document("requested")});
        let lines = plan_review_lines(&planned);
        let text = lines.join("\n");
        assert!(text.starts_with(&review_lines(&review).join("\n")), "the planner's review comes first: {text}");
        assert!(text.ends_with("Asks for:\n  - Run containers on this computer. (requested; asking grants nothing)\n  - Reserve storage on a drive you choose. (requested; asking grants nothing)"), "{text}");
        assert!(plan_view(&planned).contains("Asks for:\n  - Run containers on this computer. (requested; asking grants nothing)"));
        // A package planned here without the engine has no document and reads exactly as before.
        let local = json!({"review": review});
        assert_eq!(plan_review_lines(&local), review_lines(&review));
        let missing = json!({"review": review, "productUnavailable": "the engine's evidence clock is not available: starting"});
        assert_eq!(plan_review_lines(&missing).last().unwrap(), "Product view: not available (the engine's evidence clock is not available: starting).");
    }

    #[test]
    fn permissions_view_shows_requests_without_claiming_approval_or_enforcement() {
        let value = json!({"setupId": "setup-1", "known": true, "version": "1.0.0", "permissions": ["Run containers on this computer."], "product": document("requested")});
        let text = permissions_view(&value);
        assert!(text.contains("Allowed to:\n  - Run containers on this computer.\n"), "the review's own lines stay: {text}");
        assert!(text.ends_with("Declared permissions (requests; approval and enforcement are checked separately):\n  - Run containers on this computer. (requested; asking grants nothing)\n  - Reserve storage on a drive you choose. (requested; asking grants nothing)"), "{text}");
        assert!(!text.contains("Asks for:") && !text.contains("enforced by"), "{text}");
        // Without a document (an older engine) the view is what it was.
        let older = json!({"setupId": "setup-1", "known": true, "version": "1.0.0", "permissions": ["Run containers on this computer."]});
        assert!(!permissions_view(&older).contains("Declared permissions"));
        let missing = permissions_view(&json!({"setupId": "setup-1", "known": true, "version": "1.0.0", "productUnavailable": "the engine's evidence clock is not available: starting"}));
        assert!(missing.contains("reaches nothing outside itself") && missing.ends_with("Product view: not available (the engine's evidence clock is not available: starting)."), "{missing}");
    }
    #[test]
    fn product_view_refuses_other_versions_and_subjects_and_cleans_every_output_line() {
        let mut value = json!({"setupId":"setup-1", "product":document("requested")});
        value["product"]["contract_version"] = json!(3);
        let text = product_lines(&value, ASKS_FOR).join("\n");
        assert!(text.contains("cannot be read") && !text.contains("Run containers"));
        value["product"]["contract_version"] = json!(2);
        value["product"]["subject"]["id"] = json!("somebody-else");
        assert!(product_lines(&value, ASKS_FOR).join("\n").contains("another setup"));
        value["product"]["subject"]["id"] = json!("setup-1");
        value["product"]["migration"] = json!({"status":{"status":"pending"}, "items":[{
            "subject":"untrusted", "recorded":{"recorded":"sandbox_type", "kind":"\u{1b}]52;c;payload\u{7}\u{202e}vm", "gpu":false},
            "outcome":{"outcome":"follows_owner"}
        }]});
        let text = product_lines(&value, ASKS_FOR).join("\n");
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\u{202e}'), "{text:?}");
    }

}

