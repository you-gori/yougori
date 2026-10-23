//! An instance after its run: `status`, `list`, `update`, `down` and `rm` (`continue` is in
//! run.rs). Each command that changes an instance holds it, so two never change it at once.
use super::{
    client::{Cache, Site},
    format::{Kind, Question, Source},
    instances::{self, Instances, Part, State, Target},
    refs,
    review,
    run::{self, Wanted},
};
use crate::cli_ui as ui;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use zeroize::Zeroizing;

/// Leaving a question says what was left as it was, rather than that work keeps running.
fn left(error: String, said: &str) -> String {
    if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled(said) } else { error }
}

/// The engine's state, starting the engine when needed.
async fn engine_state(interactive: bool) -> Result<Value, String> {
    run::wait(interactive, "Reading Yougori's state", async {
        crate::client::start(None).await?;
        crate::public::call("get_platform_state", json!({})).await
    })
    .await
}

/// The current public address of each of the instance's ports, by the rule a run uses: a
/// Cloudflare publication, and for a saved domain exactly `https://DOMAIN`. A quick link that
/// changed after a restart is changed in the outputs and steps too.
pub(super) async fn refresh_addresses(state: &mut State) {
    refresh_addresses_with(state, crate::public::call).await;
}

async fn refresh_addresses_with<F, Fut>(state: &mut State, mut call: F)
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    if state.phase == "stopped" { return; }
    let mut moved = Vec::new();
    let retry = state.continue_command();
    for address in state.public.iter_mut().filter(|a| matches!(a.access.as_str(), "quick" | "domain") && a.part.is("done")) {
        let Some(id) = state.environments.get(&address.environment) else { continue };
        let Ok(services) = call("list_environment_services", json!({"environmentId": id})).await else { continue };
        let now = run::serving(&services, address.port, &address.access, address.domain.as_deref());
        if let Some(before) = &address.url {
            if Some(before) != now.as_ref() {
                moved.push((before.clone(), now.clone()));
            }
        }
        if now.is_none() {
            address.part = Part::failed(format!("The public route is no longer available. Run {retry} to restore it."));
        }
        address.url = now;
    }
    for (before, after) in moved {
        let replacement = after.as_deref().unwrap_or("[public URL unavailable]");
        for (_, value) in state.outputs.iter_mut() {
            *value = value.replace(&before, replacement);
        }
        for step in state.steps.iter_mut() {
            if after.is_none() && step.command.as_ref().is_some_and(|command| command.contains(&before)) {
                step.command = None;
            }
            for text in [&mut step.detail, &mut step.command].into_iter().flatten() {
                *text = text.replace(&before, replacement);
            }
        }
    }
}

/// `template status [INSTANCE]`.
pub async fn status(name: Option<&str>, interactive: bool) -> Result<Value, String> {
    let instances = Instances::standard()?;
    let name = match name {
        Some(name) => name.to_owned(),
        None => {
            let all = instances.list();
            match all.as_slice() {
                [only] => only.instance.clone(),
                _ => return Ok(list_value(&all)),
            }
        }
    };
    let recorded = instances.get(&name)?;
    let _quiet = interactive.then(run::Quiet::on);
    let live = engine_state(interactive).await.ok();
    let mut notices = Vec::new();
    // Links are refreshed only while no other command changes the instance, from the record as
    // it is now, so nothing another command saved is overwritten.
    let state = match instances.lock(&name) {
        Ok(_held) => {
            let mut state = instances.get(&name)?;
            if live.is_some() {
                refresh_addresses(&mut state).await;
                instances.save_quietly(&mut state)?;
            }
            state
        }
        Err(_) => {
            notices.push(format!("Another yougori command is changing {name} right now; this is how it was last saved."));
            recorded
        }
    };
    if live.is_none() {
        notices.push("Yougori's engine could not be read, so the sandboxes' state is not shown.".to_owned());
    }
    let mut value = run::result(&state, live.as_ref());
    if let (Some(item), Ok(site)) = (&state.item, Site::configured()) {
        if let Ok(reference) = refs::parse(&format!("hub/{item}"), "") {
            // Never holds status up: five seconds at most.
            let checked = run::wait(interactive, "Checking the Hub for a newer version", async { Ok(tokio::time::timeout(Duration::from_secs(5), site.item(&reference)).await) }).await;
            match checked {
                Ok(Ok(Ok(detail))) => {
                    if let Some(reason) = super::client::removed(&detail) {
                        value["removed"] = json!(format!("{reason} {} keeps running on this computer with the files it was made from; remove it with {}.", state.instance, state.remove_command()));
                    } else if let Some(latest) = detail["latestVersion"].as_str().filter(|latest| refs::newer(latest, &state.version)) {
                        value["newerVersion"] = json!(latest);
                    }
                }
                Ok(Ok(Err(error))) if !error.unreachable() => {}
                _ => notices.push("Could not reach the Hub to check for a newer version.".to_owned()),
            }
        }
    }
    if !notices.is_empty() {
        value["notices"] = json!(notices);
    }
    Ok(value)
}

fn list_value(states: &[State]) -> Value {
    json!({"instances": states.iter().map(|state| json!({
        "instance": state.instance,
        "template": state.item.clone().or_else(|| state.path.clone()).unwrap_or_else(|| state.template.clone()),
        "version": state.version,
        "status": state.status_word(),
        "sandboxes": state.environments.len(),
        "next": (state.status_word() != "ready").then(|| state.continue_command()),
    })).collect::<Vec<_>>()})
}

/// `template list`.
pub fn list() -> Result<Value, String> {
    Ok(list_value(&Instances::standard()?.list()))
}

/// `template down INSTANCE`: stops its sandboxes and keeps everything.
pub async fn down(name: &str, interactive: bool) -> Result<Value, String> {
    let instances = Instances::standard()?;
    let _held = instances.lock(name)?;
    let mut state = instances.get(name)?;
    let path = instances.folder(name).join(&state.project);
    if !path.exists() {
        return Err(format!("{name}'s project file is missing ({}). Make it again with {}.", path.display(), state.continue_command()));
    }
    let _quiet = interactive.then(run::Quiet::on);
    let work = async {
        crate::client::start(None).await?;
        crate::public::call("project_action", json!({"path": path, "action": "down"})).await
    };
    run::wait(interactive, &format!("Stopping {name}"), work).await?;
    state.phase = "stopped".into();
    instances.save(&mut state)?;
    Ok(json!({"instance": name, "stopped": true, "kept": "Its sandboxes, files and data are kept.", "start": state.continue_command()}))
}

/// What `rm` removes, worked out before anything is removed.
#[derive(Debug, Default)]
struct Removal {
    environments: Vec<(String, String)>,
    volumes: Vec<String>,
    secrets: Vec<String>,
}

/// Every sandbox (including ones an update replaced or a newer version dropped), named volume and
/// stored secret of the instance.
fn removal(state: &State, project: Option<&crate::manifest::Project>, live: &Value) -> Removal {
    let mut environments: Vec<(String, String)> = instances::sandboxes(state, live).into_iter().map(|sandbox| (sandbox.name, sandbox.id)).collect();
    for id in state.environments.values() {
        let found = live["environments"].as_array().into_iter().flatten().find(|e| e["id"] == id.as_str());
        if let Some(environment) = found {
            if !environments.iter().any(|(_, known)| known == id) {
                environments.push((environment["name"].as_str().unwrap_or(id).to_owned(), id.clone()));
            }
        }
    }
    let volumes = project.into_iter().flat_map(|p| p.environments.values()).flat_map(|e| e.volumes.iter()).filter(|v| !v.bind)
        .map(|v| format!("{}-{}", state.instance, v.source)).collect::<BTreeSet<_>>().into_iter().collect();
    let mut secrets: Vec<String> = state.secrets.iter().map(|id| run::stored_name(&state.instance, id)).collect();
    // The project names the secrets it uses, which finds them even without a record.
    let prefix = format!("hub-{}-", state.instance);
    for name in project.into_iter().flat_map(|p| p.environments.values()).flat_map(|e| e.secrets.values()) {
        if name.starts_with(&prefix) && !secrets.contains(name) {
            secrets.push(name.clone());
        }
    }
    Removal { environments, volumes, secrets }
}

/// `template rm INSTANCE --yes [--delete-data]`. An instance whose record is missing or cannot be
/// read is found by its folder and the engine's mark for its project (worked out from where its
/// project file is), never by sandbox names, which a project of the person's own can share.
pub async fn rm(name: &str, yes: bool, delete_data: bool, interactive: bool) -> Result<Value, String> {
    let instances = Instances::standard()?;
    if !instances::valid_name(name) {
        return Err(instances.get(name).err().unwrap_or_default());
    }
    let _held = instances.lock(name)?;
    let folder = instances.folder(name);
    let (mut state, recorded) = match instances.load(name) {
        Ok(Some(state)) => (state, true),
        _ => (State { instance: name.to_owned(), ..Default::default() }, false),
    };
    let _quiet = interactive.then(run::Quiet::on);
    let live = engine_state(interactive).await.map_err(|e| left(e, "Cancelled. Nothing was removed."))?;
    let project_file = folder.join(if state.project.is_empty() { "yougori.yaml" } else { state.project.as_str() });
    let project = std::fs::read_to_string(&project_file).ok().and_then(|text| crate::manifest::parse(&text).ok());
    if !recorded {
        state.project_keys.extend(instances.project_key(name, &state.project));
    }
    let plan = removal(&state, project.as_ref(), &live);
    if !recorded && !folder.exists() && plan.environments.is_empty() {
        return Err(instances.get(name).err().unwrap_or_default());
    }
    let mut said = Vec::new();
    if !recorded {
        said.push(format!("{name}'s record is missing or cannot be read, so its sandboxes were found by the engine's mark for its project"));
    }
    for (environment, _) in &plan.environments {
        said.push(format!("Sandbox {environment} and its managed data"));
    }
    if delete_data {
        for volume in &plan.volumes {
            said.push(format!("Volume {volume} and everything in it"));
        }
    }
    if !plan.secrets.is_empty() {
        said.push(format!("{} stored {} of this instance", plan.secrets.len(), if plan.secrets.len() == 1 { "secret" } else { "secrets" }));
    }
    said.push(format!("The instance folder {}", folder.display()));
    let kept: Vec<String> = if delete_data { Vec::new() } else { plan.volumes.clone() };
    if !yes {
        if !interactive {
            return Err(format!("This removes: {}. Repeat with --yes only if this is intended{}.", said.join("; "), if kept.is_empty() { String::new() } else { format!("; named volumes ({}) are kept unless you add --delete-data", kept.join(", ")) }));
        }
        let _raw = ui::Raw::on()?;
        let mut note = said.iter().map(|s| format!("Removes: {s}")).collect::<Vec<_>>();
        if !kept.is_empty() {
            note.push(format!("Keeps: {} (add --delete-data to remove them too)", kept.join(", ")));
        }
        let choice = ui::select(&format!("Remove {name}?"), &note, &[ui::Choice::new("Cancel", "keep everything"), ui::Choice::new(format!("Remove {name}"), "this cannot be undone")], 0).map_err(|e| left(e, "Cancelled. Nothing was removed."))?;
        if choice != 1 {
            return Err(crate::wire::cancelled("Cancelled. Nothing was removed."));
        }
    }
    remove_plan(&mut state, &instances, &plan, recorded, delete_data, interactive, crate::public::call).await
}

async fn remove_plan<F, Fut>(state: &mut State, instances: &Instances, plan: &Removal, recorded: bool, delete_data: bool, interactive: bool, mut call: F) -> Result<Value, String>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let folder = instances.folder(&state.instance);
    let kept = if delete_data { Vec::new() } else { plan.volumes.clone() };
    let mut failed = Vec::new();
    let mut removed = Vec::new();
    for (environment, id) in &plan.environments {
        match run::wait(interactive, &format!("Removing {environment}"), call("delete_environment", json!({"environmentId": id}))).await {
            Ok(_) => removed.push(environment.clone()),
            Err(error) if error.contains("not found") || error.contains("No environment") => removed.push(environment.clone()),
            Err(error) => failed.push(format!("{environment}: {error}")),
        }
    }
    let mut volumes = Vec::new();
    if delete_data && failed.is_empty() {
        for volume in &plan.volumes {
            match run::wait(interactive, &format!("Removing the volume {volume}"), call("remove_volume", json!({"name": volume}))).await {
                Ok(_) => volumes.push(volume.clone()),
                Err(error) if error.contains("No volume") || error.to_lowercase().contains("not found") => {}
                Err(error) => failed.push(format!("volume {volume}: {error}")),
            }
        }
    }
    if failed.is_empty() {
        for secret in &plan.secrets {
            if let Err(error) = run::wait(interactive, "Removing this instance's stored secrets", call("delete_deployment_secret", json!({"name": secret}))).await {
                failed.push(format!("stored secret {secret}: {error}"));
            }
        }
    }
    if !failed.is_empty() {
        if recorded {
            let ids: BTreeSet<&String> = plan.environments.iter().filter(|(environment, _)| removed.contains(environment)).map(|(_, id)| id).collect();
            state.environments.retain(|_, id| !ids.contains(id));
            state.phase = "incomplete".into();
            instances.save(state)?;
        }
        return Err(format!("Not everything was removed: {}. Run {} again to finish.", failed.join("; "), state.remove_command()));
    }
    std::fs::remove_dir_all(&folder).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
        .map_err(|e| format!("The sandboxes were removed, but the folder {} could not be: {e}. Close anything using it, then run {} again.", folder.display(), state.remove_command()))?;
    instances.forget(&state.instance)?;
    let backups = instances.backups(&state.instance);
    Ok(json!({
        "instance": state.instance, "removed": {"environments": removed, "volumes": volumes, "secrets": plan.secrets.len(), "folder": folder},
        "kept": {"volumes": kept, "backups": backups.exists().then_some(backups)},
    }))
}

/// What a new version changes, as sentences: what it adds, replaces or removes, and whether that
/// needs its own yes (PC access).
pub fn changes(old: &Value, new: &Value) -> (Vec<String>, bool) {
    let mut said = Vec::new();
    let by_name = |review: &Value| -> BTreeMap<String, Value> {
        review["environments"].as_array().into_iter().flatten().filter_map(|e| e["name"].as_str().map(|n| (n.to_owned(), e.clone()))).collect()
    };
    let (before, after) = (by_name(old), by_name(new));
    for (name, environment) in &after {
        match before.get(name) {
            None => said.push(format!("New sandbox {name}: {} {}", environment["type"].as_str().unwrap_or_default(), environment["image"].as_str().unwrap_or_default())),
            Some(previous) => {
                // The engine makes a new sandbox for a new type, image or GPU and keeps the old one,
                // stopped, with its data.
                let replaced = ["image", "type", "gpu"].iter().any(|field| previous[*field] != environment[*field]);
                for field in ["image", "type", "cpu", "memoryGb", "storageGb", "gpu", "internet", "ports"] {
                    if previous[field] != environment[field] {
                        said.push(format!("{name}: {field} {} → {}", previous[field], environment[field]));
                    }
                }
                if replaced {
                    said.push(format!("{name}: this replaces the sandbox. The old one is kept, stopped, with its data; its tools are installed again in the new one."));
                }
            }
        }
    }
    for name in before.keys().filter(|name| !after.contains_key(*name)) {
        said.push(format!("{name} is no longer in the template; it is stopped and kept with its data."));
    }
    let set = |review: &Value, key: &str, fields: &[&str]| -> BTreeSet<String> {
        review[key].as_array().into_iter().flatten().map(|item| fields.iter().map(|f| item[*f].to_string()).collect::<Vec<_>>().join(" ")).collect()
    };
    for public in set(new, "public", &["environment", "port"]).difference(&set(old, "public", &["environment", "port"])) {
        said.push(format!("New public link: {}", public.replace('"', "")));
    }
    for tool in set(new, "tools", &["name", "environment"]).difference(&set(old, "tools", &["name", "environment"])) {
        said.push(format!("New tool: {}", tool.replace('"', "").replacen(' ', " in ", 1)));
    }
    for input in set(new, "inputs", &["id"]).difference(&set(old, "inputs", &["id"])) {
        said.push(format!("New question: {}", input.replace('"', "")));
    }
    let pc_new = set(new, "pcAccess", &["environment", "path", "readOnly"]);
    let pc_added: Vec<String> = pc_new.difference(&set(old, "pcAccess", &["environment", "path", "readOnly"])).cloned().collect();
    for access in &pc_added {
        said.push(format!("New access to this computer: {}", access.replace('"', "")));
    }
    let downloads = |review: &Value| -> BTreeSet<String> {
        review["tools"].as_array().into_iter().flatten().flat_map(|t| t["downloads"].as_array().cloned().unwrap_or_default()).filter_map(|d| d.as_str().map(str::to_owned)).collect()
    };
    for address in downloads(new).difference(&downloads(old)) {
        said.push(format!("Installs software from {address}"));
    }
    (said, !pc_added.is_empty())
}

/// The questions an update still has to ask: new ones, and required ones without an answer.
fn unanswered<'a>(questions: &'a [Question], state: &State) -> Vec<&'a Question> {
    questions.iter().filter(|q| if q.kind == Kind::Secret { !state.secrets.contains(&q.id) } else { !state.answers.contains_key(&q.id) }).collect()
}

/// `template update INSTANCE [--yes]`: moves an instance to the template's latest version (a
/// folder instance: to the folder as it is now). The version it moves to is recorded apart from
/// its own until the update finished, so `template continue` carries the same update on.
pub async fn update(name: &str, options: run::Options, interactive: bool) -> Result<Value, String> {
    instances::clear_current();
    let instances = Instances::standard()?;
    let mut lock = instances.lock(name)?;
    let mut state = instances.get(name)?;
    let _raw = if interactive { Some(ui::Raw::on()?) } else { None };
    let _quiet = interactive.then(run::Quiet::on);
    if interactive {
        ui::intro("Update", name);
    }
    let site = Site::configured()?;
    let cache = Cache::standard()?;
    let unchanged = |error: String| left(error.replace("Nothing was created.", &format!("Nothing was changed; {name} keeps running version {}.", state.version)), "Cancelled. Nothing was changed.");
    let prepared = match (&state.updating, &state.item, &state.path) {
        // An update that stopped carries on with the version it was moving to.
        (Some(target), Some(_), _) => {
            let moving = State { version: target.version.clone(), digest: target.digest.clone(), ..state.clone() };
            run::wait(interactive, "Checking the files of the update", run::prepare_own(&site, &cache, &moving)).await.map_err(unchanged)?
        }
        (_, Some(item), _) => {
            let wanted = Wanted::Hub(refs::parse(&format!("hub/{item}"), "")?);
            run::wait(interactive, "Downloading and checking the newest version", run::prepare(&site, &cache, &wanted)).await.map_err(unchanged)?
        }
        (_, None, Some(path)) => run::wait(interactive, "Reading the template folder", run::prepare(&site, &cache, &Wanted::Folder(path.into()))).await.map_err(unchanged)?,
        _ => return Err(format!("{name} does not say where its template came from; remove it with {} and run the template again.", state.remove_command())),
    };
    let newer = match (&state.updating, &state.item) {
        (Some(_), _) => true,
        (None, Some(_)) => refs::newer(&prepared.version, &state.version),
        (None, None) => prepared.digest != state.digest,
    };
    if !newer {
        return Ok(json!({"instance": name, "updated": false, "version": state.version, "said": format!("{name} already runs the latest version ({}).", state.version)}));
    }
    let (host, engine) = run::wait(interactive, "Checking this computer", run::host(&prepared.folder, &prepared.hub_tools)).await.map_err(unchanged)?;
    let requirements = review::requirements(&prepared.folder, &prepared.hub_tools, &prepared.review, &host);
    if !requirements.stops.is_empty() {
        return Err(format!("{}\nNothing was changed.", requirements.stops.join("\n")));
    }
    let (changed, pc_added) = changes(&state.review, &prepared.review);
    let folder = instances.folder(name);
    let (edited, _) = instances::changed(&folder, &state.files);
    let questions = run::questions(&prepared);
    let fresh = unanswered(&questions, &state);
    let needs_gpu_choice = requirements.without_gpu && !state.without_gpu;
    let mut answers = state.answers.clone();
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    let was_stopped = state.phase == "stopped";
    let mut summary = vec![format!("{name}: {} {} → {}", state.item.clone().unwrap_or_else(|| state.template.clone()), state.version, prepared.version)];
    summary.extend(changed.iter().map(|c| format!("  {c}")));
    if changed.is_empty() {
        summary.push("  No new sandboxes, links, tools or access; only files change.".into());
    }
    if !edited.is_empty() {
        summary.push(format!("  Files you changed are backed up first: {}", edited.join(", ")));
    }
    if was_stopped {
        summary.push(format!("  {name} is stopped: it starts for the update, then stops again."));
    }
    let community = !prepared.verified || !prepared.unverified_tools.is_empty();
    if interactive {
        let mut lines = Vec::new();
        if community {
            lines.extend(super::views::unverified());
            if prepared.verified {
                lines.push(format!("This applies to its tools from the Hub: {}.", prepared.unverified_tools.join(", ")));
            }
            lines.push(String::new());
        }
        lines.extend(summary.iter().cloned());
        lines.extend(requirements.notes.iter().chain(&prepared.notices).map(|n| format!("▲ {n}")));
        ui::lines(lines.into_iter().map(|line| format!("{}  {}", ui::muted("│"), super::views::clean(&line))).collect());
        let cancel = || crate::wire::cancelled("Cancelled. Nothing was changed.");
        let mut steps = ui::Wizard::new();
        loop {
            let asked: Result<bool, String> = match steps.step() {
                0 if options.yes => Ok(false),
                0 => match ui::select(&format!("Update {name} to {}?", prepared.version), &[], &[ui::Choice::new("Update it", "apply the changes listed"), ui::Choice::new("Cancel", "nothing changes")], 0) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Err(cancel()),
                    Err(error) => Err(error),
                },
                1 if pc_added && !options.allow_pc_access => match ui::select("The new version uses folders on this computer", &["See the changes above: its sandboxes can read (or change) those folders.".to_owned()], &[ui::Choice::new("Allow access to these folders", "only the folders listed"), ui::Choice::new("Cancel", "nothing changes")], 1) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Err(cancel()),
                    Err(error) => Err(error),
                },
                1 => Ok(false),
                2 if needs_gpu_choice => match ui::select("This computer has no NVIDIA GPU that Yougori can use", &["The new version says it also runs without one, more slowly.".to_owned()], &[ui::Choice::new("Run without the GPU", "its GPU sandboxes become ordinary containers"), ui::Choice::new("Cancel", "nothing changes")], 0) {
                    Ok(0) => Ok(true),
                    Ok(_) => return Err(cancel()),
                    Err(error) => Err(error),
                },
                2 => Ok(false),
                n => {
                    let Some(question) = fresh.get(n - 3) else { break };
                    if !question.asked(&answers) {
                        answers.remove(&question.id);
                        secrets.remove(&question.id);
                        Ok(false)
                    } else {
                        let domains = if question.kind == Kind::Domain { run::saved_domains().await } else { Vec::new() };
                        run::ask_question(question, answers.get(&question.id), &domains).map(|answer| {
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
            return Err(format!("{}\nRepeat with --yes to update. Nothing was changed.", summary.join("\n")));
        }
        if pc_added && !options.allow_pc_access {
            return Err("The new version uses folders on this computer. Add --allow-pc-access as well as --yes if that is intended. Nothing was changed.".into());
        }
        if community {
            eprintln!("Note: {} is not checked by Yougori. Community templates and tools can contain harmful code.", prepared.label());
        }
        let stdin = if options.secrets_stdin { Some(run::read_stdin("the secrets on stdin").await?) } else { None };
        let given = run::given(&options, &questions, stdin.as_deref().map(|b| b.as_slice()))?;
        let stored: BTreeSet<String> = state.secrets.iter().cloned().collect();
        let domains = if questions.iter().any(|q| q.kind == Kind::Domain) { run::saved_domains().await } else { Vec::new() };
        let (scripted, given_secrets) = run::script_answers(&questions, &given, &answers, &stored, Some(&domains))?;
        answers = scripted;
        secrets = given_secrets;
    }
    // Check the answered project before marking an update or removing any old files. A text
    // input can be valid as an answer yet invalid as a memory size, image or project path.
    let planned = State {
        answers: answers.clone(), project: prepared.folder.project_path.clone(),
        allow_pc_access: state.allow_pc_access || pc_added,
        without_gpu: state.without_gpu || needs_gpu_choice,
        ..state.clone()
    };
    run::validate_project(&planned, &prepared, &secrets)?;
    // From here the instance says it is being updated, and to which version, until it finished.
    state.updating = Some(Target { version: prepared.version.clone(), digest: prepared.digest.clone() });
    instances.save(&mut state)?;
    lock.heartbeat(folder.clone());
    // Back up what the person changed, then replace the old version's files with the new ones.
    let stamp = instances::now().to_string();
    let backup = instances.backups(name).join(&stamp);
    if !edited.is_empty() {
        instances::back_up(&folder, &edited, &backup)?;
    }
    for path in state.files.keys().filter(|path| !prepared.files.contains_key(*path) && **path != state.project) {
        if !edited.contains(path) {
            let _ = std::fs::remove_file(folder.join(path));
        }
    }
    run::check_live(&mut state, &engine);
    state.answers = answers;
    state.allow_pc_access |= pc_added;
    state.without_gpu |= needs_gpu_choice;
    state.title = prepared.folder.template.title().into();
    state.review = prepared.review.clone();
    state.files = BTreeMap::new();
    state.create = Part::pending();
    // Built-in tools are the same in every version; a tool of the template's own is installed
    // again, since its install lines may have changed.
    let built_in: BTreeSet<String> = prepared.folder.tools.iter().filter(|t| matches!(t.source, Source::BuiltIn(_))).map(|t| format!("{}/{}", t.environment, t.name())).collect();
    for (key, part) in state.tools.iter_mut() {
        if !built_in.contains(key) || !part.is("done") {
            *part = Part::pending();
        }
    }
    state.project = prepared.folder.project_path.clone();
    let ending = run::Ending { update: true, stay_stopped: was_stopped };
    let mut value = run::build(&mut state, &instances, &prepared, secrets, interactive, &site, ending).await?;
    value["updated"] = json!(true);
    value["changes"] = json!(changed);
    if !edited.is_empty() {
        value["backup"] = json!({"folder": backup, "files": edited});
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_failed_secret_removal_keeps_the_record_and_folder_until_retry_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let instances = Instances { root: root.path().join("instances") };
        let mut state = State { instance: "shop".into(), secrets: vec!["key".into()], environments: [("web".into(), "env-1".into())].into(), ..Default::default() };
        instances.save(&mut state).unwrap();
        let plan = Removal { environments: vec![("shop-web".into(), "env-1".into())], volumes: vec!["shop-data".into()], secrets: vec!["hub-shop-key".into()] };
        let mut calls = Vec::new();
        let error = remove_plan(&mut state, &instances, &plan, true, false, false, |method, _| {
            calls.push(method);
            std::future::ready(match method {
                "delete_environment" => Ok(json!({})),
                "delete_deployment_secret" => Err("vault locked".into()),
                _ => panic!("unexpected {method}"),
            })
        }).await.unwrap_err();
        assert!(error.contains("vault locked") && error.contains("Run yougori template rm shop --yes again"), "{error}");
        assert_eq!(calls, ["delete_environment", "delete_deployment_secret"]);
        let saved = instances.get("shop").unwrap();
        assert_eq!(saved.phase, "incomplete");
        assert!(saved.environments.is_empty());
        assert_eq!(saved.secrets, ["key"]);
        assert!(instances.folder("shop").exists());
        let retry = Removal { environments: vec![], ..plan };
        let done = remove_plan(&mut state, &instances, &retry, true, false, false, |method, _| {
            assert_eq!(method, "delete_deployment_secret");
            std::future::ready(Ok(json!({})))
        }).await.unwrap();
        assert_eq!(done["removed"]["secrets"], 1);
        assert_eq!(done["kept"]["volumes"], json!(["shop-data"]));
        assert!(instances.load("shop").unwrap().is_none());
        assert!(!instances.folder("shop").exists());
    }

    #[tokio::test]
    async fn vanished_public_routes_make_the_instance_incomplete_and_remove_stale_outputs() {
        let mut state = State {
            instance: "shop".into(), phase: "ready".into(), create: Part::done(),
            environments: [("web".into(), "env-1".into())].into(),
            public: vec![instances::Address { environment: "web".into(), port: 8080, access: "quick".into(), url: Some("https://old.trycloudflare.com".into()), part: Part::done(), domain: None }],
            outputs: vec![("Website".into(), "https://old.trycloudflare.com".into())],
            steps: vec![instances::Step { title: "Test".into(), detail: Some("Open https://old.trycloudflare.com".into()), command: Some("curl https://old.trycloudflare.com".into()) }],
            ..Default::default()
        };
        // A tunnel restart updates both links and commands without marking a healthy run failed.
        refresh_addresses_with(&mut state, |_, _| std::future::ready(Ok(json!({"publications": [
            {"port": 8080, "kind": "cloudflare", "status": "active", "urls": ["https://new.trycloudflare.com"]}
        ]})))).await;
        assert_eq!(state.status_word(), "ready");
        assert_eq!(state.outputs[0].1, "https://new.trycloudflare.com");
        assert_eq!(state.steps[0].command.as_deref(), Some("curl https://new.trycloudflare.com"));
        // An unreadable engine does not prove that a route vanished.
        refresh_addresses_with(&mut state, |_, _| std::future::ready(Err("offline".into()))).await;
        assert_eq!(state.status_word(), "ready");
        refresh_addresses_with(&mut state, |_, _| std::future::ready(Ok(json!({"publications": []})))).await;
        assert_eq!(state.status_word(), "incomplete");
        assert!(state.public[0].url.is_none() && state.public[0].part.is("failed"));
        assert_eq!(state.outputs[0].1, "[public URL unavailable]");
        assert!(state.steps[0].command.is_none());
        assert!(!state.steps[0].detail.as_ref().unwrap().contains("trycloudflare"));
    }

    #[test]
    fn an_update_lists_what_it_adds_replaces_and_asks_again_for_pc_access() {
        let old = json!({
            "environments": [{"name": "web", "type": "container", "image": "node:22", "cpu": 2}, {"name": "api", "type": "container", "image": "python:3.12", "cpu": 1}],
            "public": [], "tools": [{"name": "codex", "environment": "web"}], "inputs": [{"id": "access"}], "pcAccess": [],
        });
        let new = json!({
            "environments": [{"name": "web", "type": "container", "image": "node:24", "cpu": 2}, {"name": "api", "type": "container", "image": "python:3.12", "cpu": 2}, {"name": "db", "type": "container", "image": "postgres:17"}],
            "public": [{"environment": "web", "port": 3000, "access": "quick"}],
            "tools": [{"name": "codex", "environment": "web"}, {"name": "gateway", "environment": "web", "downloads": ["https://registry.npmjs.org"]}],
            "inputs": [{"id": "access"}, {"id": "domain"}],
            "pcAccess": [{"environment": "web", "path": "./data", "readOnly": true}],
        });
        let (said, pc) = changes(&old, &new);
        assert!(pc, "new PC access needs its own yes");
        for part in ["New sandbox db: container postgres:17", "web: image \"node:22\" → \"node:24\"", "web: this replaces the sandbox. The old one is kept, stopped, with its data; its tools are installed again in the new one.", "api: cpu 1 → 2", "New public link: web 3000", "New tool: gateway in web", "New question: domain", "New access to this computer: web ./data true", "Installs software from https://registry.npmjs.org"] {
            assert!(said.iter().any(|s| s == part), "{part}: {said:?}");
        }
        assert!(!said.iter().any(|s| s.starts_with("api: this replaces")), "more CPU changes the sandbox in place");
        let (gone, pc) = changes(&new, &old);
        assert!(!pc);
        assert!(gone.iter().any(|s| s == "db is no longer in the template; it is stopped and kept with its data."));
    }

    #[test]
    fn removal_names_every_sandbox_volume_and_secret_of_the_instance() {
        let mut state = State { instance: "shop".into(), secrets: vec!["openai_key".into(), "tool.aider".into()], ..Default::default() };
        state.project_keys.insert("abc".into());
        state.environments.insert("web".into(), "env-1".into());
        state.review = json!({"environments": [{"name": "web"}, {"name": "db"}]});
        let project = crate::manifest::parse("project: shop\nenvironments:\n  web:\n    image: nginx\n    volumes: [{source: data, target: /data}]\n    secrets: {TOKEN: hub-shop-token, OTHER: someone-else}\n  db:\n    image: postgres:17\n    volumes: [{source: pg, target: /var/lib/postgresql/data}]\n").unwrap();
        let live = json!({"environments": [
            {"id": "env-1", "name": "shop-web", "description": "Yougori project abc / web"},
            {"id": "env-2", "name": "shop-db", "description": "Yougori project abc / db"},
            {"id": "env-3", "name": "shop-db", "description": "Made by hand"},
            {"id": "env-4", "name": "shop-web-replaced-1a2b3c", "description": "Yougori project abc / web (replaced)"},
        ]});
        let plan = removal(&state, Some(&project), &live);
        assert_eq!(plan.environments, [("shop-web".to_owned(), "env-1".to_owned()), ("shop-db".to_owned(), "env-2".to_owned()), ("shop-web-replaced-1a2b3c".to_owned(), "env-4".to_owned())]);
        assert_eq!(plan.volumes, ["shop-data", "shop-pg"]);
        assert_eq!(plan.secrets, ["hub-shop-openai_key", "hub-shop-key-aider", "hub-shop-token"]);
        let gone = removal(&state, None, &json!({"environments": []}));
        assert!(gone.environments.is_empty(), "a sandbox already deleted is not listed");
    }

    #[test]
    fn an_instance_without_a_readable_record_is_found_by_its_project_mark_only() {
        let live = json!({"environments": [
            {"id": "env-1", "name": "shop-web", "description": "Yougori project abc / web"},
            {"id": "env-2", "name": "shop-db-1a2b3c", "description": "Yougori project abc / db"},
            {"id": "env-3", "name": "shop-db-replaced-9f8e7d", "description": "Yougori project abc / db (replaced)"},
            {"id": "env-4", "name": "shopping-web", "description": "Yougori project def / web"},
            {"id": "env-5", "name": "shop-cache", "description": "Made by hand"},
            // The person's own project called shop: same sandbox name, another project.
            {"id": "env-6", "name": "shop-web", "description": "Yougori project def / web"},
        ]});
        let mut state = State { instance: "shop".into(), ..Default::default() };
        state.project_keys.insert("abc".into());
        let plan = removal(&state, None, &live);
        let ids: Vec<&str> = plan.environments.iter().map(|(_, id)| id.as_str()).collect();
        assert_eq!(ids, ["env-1", "env-2", "env-3"]);
        state.project_keys.clear();
        assert!(removal(&state, None, &live).environments.is_empty(), "without the project's mark nothing is removed");
    }

    fn question(id: &str, kind: Kind) -> Question {
        Question { id: id.into(), question: id.into(), kind, required: true, default: None, when: None, hint: String::new(), choices: Vec::new(), pattern: None, min: None, max: None }
    }

    #[test]
    fn an_update_asks_only_what_the_instance_has_no_answer_for() {
        let questions = vec![question("email", Kind::Text), question("site", Kind::Text), question("key", Kind::Secret), question("token", Kind::Secret)];
        let mut state = State { secrets: vec!["key".into()], ..Default::default() };
        state.answers.insert("email".into(), "a@b.c".into());
        let ids: Vec<&str> = unanswered(&questions, &state).iter().map(|q| q.id.as_str()).collect();
        assert_eq!(ids, ["site", "token"]);
    }
}
