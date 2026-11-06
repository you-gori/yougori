//! The setup calls, one implementation behind two doors: the desktop's Tauri commands and the
//! CLI's engine methods (`automation::dispatch`), both named `setup_*`. The desktop gets typed
//! `dto::Diagnostic` errors; the wire gets the sentence with its code beside it (`FAULT`), so a
//! terminal prints only the sentence and a script reads the code.
use super::{
    model::{new_id, Diagnostic},
    planning,
    service::{PlanIntent, Service},
    views,
};
use crate::AppHandle;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use tauri::Manager;
// The crate's alias is generic over the runtime, so the headless engine (no webview) compiles these too.
use crate::WebviewWindow;
use yougori_setup::{capability, dto};

type Reply<T> = Result<T, dto::Diagnostic>;

// ----- Errors on the two doors -----

/// How a setup refusal travels over the wire, whose handlers hand back a string:
/// `YOUGORI_SETUP code retry|final[ resource]: sentence`. The queue takes the head off again
/// (`wire_fault`), so only the sentence is ever shown to a person.
pub(crate) const FAULT: &str = "YOUGORI_SETUP";

fn wire_error(diagnostic: &Diagnostic) -> String {
    let resource = diagnostic
        .resource
        .as_deref()
        .filter(|resource| !resource.is_empty() && !resource.contains(char::is_whitespace) && !resource.contains(": "))
        .map(|resource| format!(" {resource}"))
        .unwrap_or_default();
    format!(
        "{FAULT} {} {}{resource}: {}",
        diagnostic.code,
        if diagnostic.retryable { "retry" } else { "final" },
        diagnostic.message
    )
}

/// Reads back what `wire_error` wrote: the sentence, and the details a script reads beside it.
/// Anything else is left alone.
pub(crate) fn wire_fault(message: &str) -> Option<(String, yougori_cli::wire::ErrorDetails)> {
    let rest = message.strip_prefix(FAULT)?.strip_prefix(' ')?;
    let (head, said) = rest.split_once(": ")?;
    let mut words = head.split(' ');
    let code = words.next().filter(|code| !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))?;
    let retryable = match words.next()? {
        "retry" => true,
        "final" => false,
        _ => return None,
    };
    let resource = words.next().map(str::to_owned);
    if words.next().is_some() {
        return None;
    }
    Some((
        said.to_owned(),
        yougori_cli::wire::ErrorDetails {
            code: code.to_owned(),
            affected_resource: resource,
            retryable,
            // Every refusal here comes before anything was changed. An operation that fails
            // after it started reports that in its own progress, not as an error of the call.
            outcome: "not_started".into(),
        },
    ))
}

fn fail(diagnostic: Diagnostic) -> dto::Diagnostic {
    views::api_error(&diagnostic)
}

fn main_window(window: &WebviewWindow) -> Reply<()> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err(fail(Diagnostic::new("wrong_window", "Setups are managed from the main Yougori window.")))
    }
}

fn service(app: &AppHandle) -> Result<Arc<Service>, Diagnostic> {
    app.try_state::<Arc<Service>>()
        .map(|service| service.inner().clone())
        .ok_or_else(|| Diagnostic::new("setups_starting", "Setups are still starting. Try again in a moment.").retryable())
}

fn json_of(value: impl serde::Serialize) -> Result<Value, Diagnostic> {
    serde_json::to_value(value).map_err(|_| Diagnostic::new("invalid_response", "Yougori could not put this answer together."))
}

fn parsed<T: DeserializeOwned>(params: &Value) -> Result<T, Diagnostic> {
    serde_json::from_value(params.clone()).map_err(|error| {
        Diagnostic::new("invalid_request", format!("This request is not in the shape Yougori expects ({error})."))
    })
}

/// Runs an operation in the background; its progress is read with `setup_operation`.
fn spawn_run(service: Arc<Service>, operation: String) {
    tauri::async_runtime::spawn(async move {
        if let Err(error) = service.run(&operation).await {
            eprintln!("Setup operation stopped: {}", error.message);
        }
    });
}

// ----- The shared implementation -----

/// Every capability with whether it can be chosen here, and whether this engine can already set
/// up the resources it needs.
fn capabilities(app: &AppHandle, service: &Service) -> Value {
    let host = planning::capability_host(app);
    let handlers = service.handler_kinds();
    json!({
        "contractVersion": dto::CONTRACT_VERSION,
        "capabilities": capability::registry().iter().map(|entry| {
            let missing = entry.kinds.iter().any(|kind| !handlers.contains(kind));
            json!({
                "id": entry.id,
                "availability": entry.availability(&host),
                "reason": entry.reason(&host),
                "engineReady": !missing,
                "engineReason": missing.then_some("Yougori can't set this up on this computer yet."),
            })
        }).collect::<Vec<_>>(),
        "handlers": handlers,
        "registry": service.availability().map(|problem| views::api_error(&problem)),
    })
}

fn hub(app: &AppHandle) -> Result<Arc<dyn planning::Hub>, Diagnostic> {
    app.try_state::<super::Sources>()
        .map(|sources| sources.hub.clone())
        .ok_or_else(|| Diagnostic::new("setups_starting", "Setups are still starting. Try again in a moment.").retryable())
}

async fn validate(app: &AppHandle, service: &Service, request: Value) -> Result<Value, Diagnostic> {
    // "Make a template from environments" captures this computer's state, read only. Every other
    // source goes through the ordinary validate, which reads no live state.
    if request["source"]["kind"].as_str() == Some("environments") {
        let (state, volumes) = platform_snapshot(app).await?;
        let ids: Vec<String> = request["source"]["environments"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
        return planning::validate_environments(hub(app)?.as_ref(), &state, &volumes, &ids).await;
    }
    planning::validate(service, hub(app)?.as_ref(), parsed(&request)?).await
}

/// This computer's platform state and its volumes, as `get_platform_state` and `list_volumes` return
/// them, for capturing environments into a template. A read-only snapshot; nothing is started.
async fn platform_snapshot(app: &AppHandle) -> Result<(Value, Value), Diagnostic> {
    use tauri::Manager;
    let store = app.state::<crate::store::PlatformStore>();
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    let state = crate::commands::get_platform_state(store.clone(), runtime.clone())
        .await
        .map_err(|error| Diagnostic::new("state_unreadable", error))?;
    let state = serde_json::to_value(state).map_err(|error| Diagnostic::new("state_unreadable", error.to_string()))?;
    let volumes = crate::file_export::list_volumes(None, None, store, runtime).await.unwrap_or(Value::Null);
    Ok((state, volumes))
}

async fn plan(app: &AppHandle, service: &Service, request: Value) -> Result<Value, Diagnostic> {
    let mut call: planning::PlanCall = parsed(&request)?;
    // A drive is one this computer has, that sandboxes can live on, with room for them.
    let drives = app
        .state::<crate::store::PlatformStore>()
        .snapshot()
        .ok()
        .and_then(|state| serde_json::to_value(&state.host.storage_drives).ok())
        .and_then(|drives| drives.as_array().cloned())
        .unwrap_or_default();
    if let Some(drive) = call.storage_drive().map(str::to_owned) {
        call.set_storage_drive(planning::check_drive(&drive, &drives)?);
    }
    call.set_drives(planning::usable_drives(&drives));
    planning::plan(&planning::planner_host(app), hub(app)?.as_ref(), service, call).await
}

/// `dto::ApplyRequest`, plus secret values for this operation only. They stay in memory and are
/// never saved.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyCall {
    #[serde(flatten)]
    apply: dto::ApplyRequest,
    #[serde(default)]
    secrets: BTreeMap<String, String>,
    /// What the person agreed to on the review (`copy_signin:RESOURCE/TOOL`), each asked for
    /// by the plan's `consents`.
    #[serde(default)]
    consents: std::collections::BTreeSet<String>,
}

/// Applies a reviewed plan, or joins the operation this request already started: a repeat (or a
/// continue with the answers an operation was waiting for) needs only the operation ID and
/// digest, not the plan, which may have expired since.
fn apply(service: &Arc<Service>, call: ApplyCall) -> Result<dto::OperationRef, Diagnostic> {
    let ApplyCall { apply, secrets, consents } = call;
    let submitted = match service.continue_operation(&apply.setup_id, &apply.operation_id, &apply.plan_digest, secrets.clone())? {
        Some(joined) => joined,
        None => {
            let plan = service.reviewed(&apply.setup_id, &apply.plan_digest)?;
            service.submit_agreed(&plan, &apply.operation_id, apply.expected_revision, secrets, consents)?
        }
    };
    spawn_run(service.clone(), submitted.operation_id.clone());
    Ok(submitted.reference())
}

fn list(service: &Service) -> Result<Value, Diagnostic> {
    Ok(json!({ "setups": service.list()? }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GetCall {
    setup_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevealCall {
    setup_id: String,
    #[serde(default)]
    key: Option<String>,
}

/// A setup's private outputs: without `key`, which ones it can show now, never a value; with
/// `key`, that one's value, asked of the product now and kept nowhere.
async fn reveal(service: &Service, call: RevealCall) -> Result<Value, Diagnostic> {
    match call.key {
        None => {
            let private = service.private_outputs(&call.setup_id).await?.into_iter().map(|(key, label)| json!({ "key": key, "label": label })).collect::<Vec<_>>();
            Ok(json!({ "setupId": call.setup_id, "private": private }))
        }
        Some(key) => {
            let (label, value) = service.reveal(&call.setup_id, &key).await?;
            Ok(json!({ "setupId": call.setup_id, "key": key, "label": label, "value": value }))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportCall {
    setup_id: String,
    #[serde(default)]
    folder: Option<String>,
}

/// The migration dry run (plan 19.1, 19.3 steps 1–4). `path` is the folder to read — a copy of a
/// data folder — and is always given in full. `allowLive` is the caller saying, in so many words,
/// that it means this computer's running data folder; the CLI never sends it by itself.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationCall {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    allow_live: bool,
}

/// Inventory, back up, verify or rehearse a folder the caller named. Every one of these is
/// read-only on that folder; only a backup writes, and only into the empty folder it was given.
fn migration_call(service: &Service, method: &str, call: MigrationCall) -> Result<Value, Diagnostic> {
    use super::migration;
    let into = || {
        call.folder
            .as_deref()
            .filter(|folder| !folder.trim().is_empty())
            .map(std::path::PathBuf::from)
            .ok_or_else(|| Diagnostic::new("folder_missing", "Give the backup folder as a full path.").at("folder"))
    };
    if method == "setup_migration_verify" {
        return json_of(migration::verify(&into()?)?);
    }
    let path = call
        .path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| Diagnostic::new("path_missing", "Give the folder to read as a full path.").at("path"))?;
    migration::readable_folder(&path)?;
    migration::refuse_live(&path, service.data_root(), call.allow_live)?;
    match method {
        "setup_migration_inventory" => json_of(migration::inventory(&path)),
        "setup_migration_rehearse" => json_of(migration::rehearse(&path)),
        _ => {
            let destination = into()?;
            let taken = migration::inventory(&path);
            let manifest = migration::backup(&path, &destination, &taken)?;
            json_of(json!({ "inventory": taken, "backup": manifest }))
        }
    }
}

// ----- Scheduled backups: reading them, checking one, putting one back -----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupsCall {
    setup_id: String,
}

/// A setup's backup times and the copies kept for each volume, in the words the setup page and
/// the CLI both use. Nothing here is a path of this computer: a backup's folder is worked out
/// from its ids, and only the volume's place inside its own sandbox is shown.
fn backups_of(service: &Service, call: BackupsCall) -> Result<Value, Diagnostic> {
    use super::schedules;
    // Reading the setup first, so a setup that is not there is said so rather than answered with
    // an empty list.
    service.get(&call.setup_id)?;
    let mut volumes = service.schedules_of(&call.setup_id)?;
    volumes.sort_by(|a, b| a.resource.cmp(&b.resource));
    let volumes = volumes
        .iter()
        .map(|schedule| {
            json!({
                "resource": schedule.resource,
                "through": schedule.through,
                "mountedAt": schedule.path,
                "schedule": schedule.describe(),
                "keep": schedule.keep,
                "kept": schedule.backups.len(),
                "consistency": schedule.consistency,
                "consistencyWords": schedules::consistency_words(schedule.consistency, &schedule.resource, &schedule.through),
                "paused": schedule.paused,
                "nextAt": schedule.next_at,
                "nextWhen": (!schedule.paused && schedule.next_at > 0).then(|| schedules::stamp(schedule.next_at)),
                "lastOutcome": schedule.last_outcome.as_str(),
                "lastDetail": schedule.last_detail,
                "lastFinishedAt": schedule.last_finished_at,
                "lastWhen": schedule.last_finished_at.map(schedules::stamp),
                "backups": schedule.backups.iter().rev().map(|backup| json!({
                    "id": backup.id,
                    "at": backup.at,
                    "when": schedules::stamp(backup.at),
                    "files": backup.files,
                    "bytes": backup.bytes,
                    "consistency": backup.consistency,
                    "describe": backup.describe(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "setupId": call.setup_id,
        "volumes": volumes,
        // Said here as well as on the review, because a person reading the list is deciding
        // whether these copies are the protection they think they are.
        "limits": schedules::LIMITS,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupNowCall {
    setup_id: String,
    resource: String,
}

/// A backup of one volume now, as its schedule would take it; its regular times stay as they
/// are. The answer says it has started, or why it can't: the setup is stopped, a backup of the
/// volume is already running, or the volume isn't backed up at all.
fn back_up_now(service: &Service, call: BackupNowCall) -> Result<Value, Diagnostic> {
    // Reading the setup first, so a setup that is not there is said so.
    service.get(&call.setup_id)?;
    let scheduler = service
        .scheduler()
        .ok_or_else(|| Diagnostic::new("setups_starting", "Backups are still starting. Try again in a moment.").retryable())?;
    let id = super::schedules::Schedule::key(&call.setup_id, &call.resource);
    let said = scheduler.back_up_now(&id).map_err(|why| Diagnostic::new("backup_not_now", why).resource(&call.resource))?;
    Ok(json!({ "setupId": call.setup_id, "resource": call.resource, "said": said }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupCall {
    setup_id: String,
    resource: String,
    backup_id: String,
}

/// Restoring replaces data, so it is reviewed first, exactly as removing a setup is: the call
/// without `confirm` changes nothing and answers with what would happen; the same call with the
/// `confirm` the review handed back does it. `overOriginal` is the difference between a
/// disposable copy and the volume itself, and no caller is given it by default.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreCall {
    setup_id: String,
    resource: String,
    backup_id: String,
    #[serde(default)]
    over_original: bool,
    #[serde(default)]
    confirm: Option<String>,
}

/// What a check answers with: the worker's own report, and the moment in the words a person
/// reads, worked out here because the engine knows this computer's clock and a caller does not.
fn checked(call: &BackupCall, mut report: Value) -> Value {
    if let Some(object) = report.as_object_mut() {
        if let Some(at) = object.get("at").and_then(Value::as_i64) {
            object.insert("when".into(), json!(super::schedules::stamp(at)));
        }
        object.insert("backupId".into(), json!(call.backup_id));
        object.insert("resource".into(), json!(call.resource));
        object.insert("changed".into(), json!(false));
    }
    report
}

/// Ties a confirmation to the one restore that was reviewed: another backup, another volume or
/// the other target all make a different word, so a confirmation cannot drift onto something the
/// person never saw.
fn restore_confirmation(call: &RestoreCall) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for part in [call.setup_id.as_str(), call.resource.as_str(), call.backup_id.as_str(), if call.over_original { "original" } else { "copy" }] {
        hash.update(part.as_bytes());
        hash.update([0u8]);
    }
    format!("restore-{}", &hex::encode(hash.finalize())[..16])
}

/// What a restore request leads to. The only way to reach [`Decided::Apply`] — the only branch
/// of [`restore`] that calls the worker — is a confirmation that matches the one this exact
/// restore was reviewed with. A request with no confirmation cannot produce it.
#[derive(Debug, PartialEq)]
enum Decided {
    /// Say what would happen, and change nothing.
    Review,
    /// The person has read the review and asked for this one.
    Apply,
    /// A confirmation for some other restore. Refused rather than applied to this one.
    Stale,
}

fn decide(call: &RestoreCall) -> Decided {
    match call.confirm.as_deref() {
        None => Decided::Review,
        Some(given) if given == restore_confirmation(call) => Decided::Apply,
        Some(_) => Decided::Stale,
    }
}

async fn restore(service: &Service, call: RestoreCall) -> Result<Value, Diagnostic> {
    // The review is worked out either way, so a confirmation is never applied to a backup that
    // has since gone or a volume that no longer has times. It reads; it changes nothing.
    let review = service.restore_review(&call.setup_id, &call.resource, &call.backup_id, call.over_original)?;
    let target = if call.over_original { "original" } else { "copy" };
    match decide(&call) {
        Decided::Apply => service.restore_backup(&call.setup_id, &call.resource, &call.backup_id, call.over_original).await,
        Decided::Stale => Err(Diagnostic::new(
            "confirmation_stale",
            "That confirmation was for a different restore. Read the review again, then confirm with the word it gives. Nothing was changed.",
        )
        .resource(&call.resource)),
        Decided::Review => Ok(json!({
            "reviewed": true,
            "applied": false,
            "setupId": call.setup_id,
            "resource": call.resource,
            "backupId": call.backup_id,
            "restoreTo": target,
            "overwrites": call.over_original,
            "review": review,
            "confirm": restore_confirmation(&call),
            "next": if call.over_original {
                format!("Nothing has been changed. To go ahead and replace what is on {}, send this call again with confirm set to the word above.", call.resource)
            } else {
                "Nothing has been changed. To put these files into a new folder, send this call again with confirm set to the word above.".to_owned()
            },
        })),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationCall {
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    setup_id: Option<String>,
    #[serde(default)]
    cursor: Option<u64>,
}

/// An operation's progress, by its ID or, for `template logs SETUP`, the setup's current or
/// latest operation.
fn operation(service: &Service, call: OperationCall) -> Result<dto::OperationProgress, Diagnostic> {
    let operation = match (call.operation_id, call.setup_id) {
        (Some(operation), setup) => {
            let progress = service.operation(&operation, call.cursor.unwrap_or(0))?;
            if setup.is_some_and(|setup| setup != progress.operation.setup_id) {
                return Err(Diagnostic::new("operation_not_found", "This operation does not belong to that setup.").operation(&operation));
            }
            return Ok(progress);
        }
        (None, Some(setup)) => service.latest_operation(&setup)?,
        (None, None) => return Err(Diagnostic::new("invalid_request", "Say which setup or operation to read.")),
    };
    service.operation(&operation, call.cursor.unwrap_or(0))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelCall {
    operation_id: String,
    #[serde(default)]
    setup_id: Option<String>,
}

fn cancel(service: &Service, call: CancelCall) -> Result<dto::OperationProgress, Diagnostic> {
    if let Some(setup) = &call.setup_id {
        let progress = service.operation(&call.operation_id, 0)?;
        if &progress.operation.setup_id != setup {
            return Err(Diagnostic::new("operation_not_found", "This operation does not belong to that setup.").operation(&call.operation_id));
        }
    }
    service.cancel(&call.operation_id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionCall {
    #[serde(default)]
    setup_id: Option<String>,
    action: String,
    #[serde(default)]
    expected_revision: Option<u64>,
    #[serde(default)]
    plan_digest: Option<String>,
    #[serde(default)]
    operation_id: Option<String>,
    /// A grid invitation for `join`. Not kept anywhere.
    #[serde(default)]
    invitation: Option<String>,
    /// One part of the setup, for start, stop, remove, detach or release_compute on that part
    /// alone.
    #[serde(default)]
    resource: Option<String>,
    /// For pause_admission: whether work already running finishes (the default) or is asked to
    /// stop, as a cancel asks.
    #[serde(default)]
    drain: Option<bool>,
}

/// Lifecycle actions on a whole setup. Start and stop apply at once (borrowed resources and data
/// are left alone). Remove and repair first return a plan to review; called again with its
/// digest, they apply it.
pub(super) async fn action(service: &Arc<Service>, call: ActionCall) -> Result<Value, Diagnostic> {
    let ActionCall { setup_id, action, expected_revision, plan_digest, operation_id, invitation, resource, drain } = call;
    if action == "join" {
        // The plan to review; it is applied with setup_apply, which brings the invitation and
        // the company password as secrets.
        let invitation = invitation.filter(|text| !text.trim().is_empty()).ok_or_else(|| Diagnostic::new("invalid_request", "Give the invitation the grid's admin shared.").at("invitation"))?;
        let mut plan = service.plan(service.joining(&invitation)?)?;
        plan.notes.push(if invitation.trim().starts_with(super::grids::scoped::PREFIX) {
            "When you apply, give the invitation again: it carries your username and password, and is not kept with the setup.".into()
        } else {
            "When you apply, give the invitation again and the grid's company password. Neither is kept with the setup.".into()
        });
        return Ok(views::plan(&plan));
    }
    let not_yet = || {
        Err(Diagnostic::new(
            "unsupported_here",
            "This action is not available for setups yet. Nothing was changed.",
        ))
    };
    // Detaching is done one borrowed part at a time (with `resource`, below).
    if resource.is_none() && matches!(action.as_str(), "detach" | "delete_data") {
        return not_yet();
    }
    let setup = setup_id.ok_or_else(|| Diagnostic::new("invalid_request", "Say which setup this is for."))?;
    // New work and rented compute (plan 8.4): each is reviewed first, then applied with that
    // review's digest. Neither is an operation: nothing is made or removed, and each says what it
    // did, and for a release, whether its provider confirmed it.
    if matches!(action.as_str(), "pause_admission" | "resume_admission") {
        if let Some(resource) = &resource {
            return Err(Diagnostic::new("unsupported_here", "New work is paused and resumed for the whole setup: its jobs share one queue. Leave out the part. Nothing was changed.").resource(resource));
        }
        let change = if action == "resume_admission" { super::handler::Admission::Resume } else { super::handler::Admission::Pause { drain: drain.unwrap_or(true) } };
        return match &plan_digest {
            None => service.admission_review(&setup, change),
            Some(digest) => service.admission(&setup, change, digest).await,
        };
    }
    if action == "release_compute" {
        return match &plan_digest {
            None => service.release_review(&setup, resource.as_deref()).await,
            Some(digest) => service.release(&setup, resource.as_deref(), digest).await,
        };
    }
    // Start and stop act on what is there now, not on what was last seen: after Yougori closed
    // and opened again, or a sandbox was stopped by hand, a setup recorded running has nothing
    // running, and a start planned from the record would do nothing. Looking changes nothing,
    // and a setup that is busy is simply planned from its record, as before.
    if matches!(action.as_str(), "start" | "stop") && operation_id.as_ref().is_none_or(|operation| service.operation_kind(operation).is_none()) {
        let _ = service.refresh(&setup).await;
    }
    let needs_operation = || {
        operation_id
            .clone()
            .ok_or_else(|| Diagnostic::new("invalid_request", "Say which operation this is for."))
    };
    let start = |intent: PlanIntent| -> Result<Value, Diagnostic> {
        // The same request again, after it finished, answers with the operation it made.
        if let Some(operation) = &operation_id {
            if let Some((owner, _)) = service.operation_kind(operation) {
                if owner == setup {
                    return json_of(dto::OperationRef { operation_id: operation.clone(), setup_id: setup.clone() });
                }
                return Err(Diagnostic::new(
                    "operation_id_reused",
                    "This operation ID was already used for a different change. Send the new change with a new ID.",
                )
                .operation(operation));
            }
        }
        let plan = service.plan(intent)?;
        let operation = operation_id.clone().unwrap_or_else(|| new_id("op-"));
        let submitted = service.submit(&plan, &operation, expected_revision.unwrap_or(plan.base_revision), BTreeMap::new())?;
        spawn_run(service.clone(), submitted.operation_id.clone());
        json_of(submitted.reference())
    };
    let apply_reviewed = |digest: &str| -> Result<Value, Diagnostic> {
        let plan = service.reviewed(&setup, digest)?;
        let submitted = service.submit(&plan, &needs_operation()?, expected_revision.unwrap_or(plan.base_revision), BTreeMap::new())?;
        spawn_run(service.clone(), submitted.operation_id.clone());
        json_of(submitted.reference())
    };
    let review_then_apply = |intent: PlanIntent| -> Result<Value, Diagnostic> {
        match &plan_digest {
            None => Ok(views::plan(&service.plan(intent)?)),
            Some(digest) => apply_reviewed(digest),
        }
    };
    // One part on its own. Start and stop apply at once, as for the whole setup; removing or
    // detaching a part is reviewed first, exactly as removing the whole setup is.
    if let Some(resource) = resource {
        use super::journal::Action;
        let part = |action: Action| PlanIntent::Part { setup: setup.clone(), resource: resource.clone(), action };
        return match action.as_str() {
            "start" => start(part(Action::Start)),
            "stop" => start(part(Action::Stop)),
            "remove" => review_then_apply(part(Action::Remove)),
            "detach" => review_then_apply(part(Action::Detach)),
            _ => Err(Diagnostic::new("invalid_request", "One part of a setup can be started, stopped, removed or detached. Nothing was changed.").resource(&resource)),
        };
    }
    match action.as_str() {
        "start" => start(PlanIntent::Start { setup: setup.clone() }),
        "stop" => start(PlanIntent::Stop { setup: setup.clone() }),
        "remove" => review_then_apply(PlanIntent::Remove { setup: setup.clone() }),
        // On an adopted record: a plan for a new setup that holds it; then, with that plan's
        // setup ID and digest, its application.
        "adopt" => match &plan_digest {
            None => Ok(views::plan(&service.plan(service.adoption(&setup)?)?)),
            Some(digest) => apply_reviewed(digest),
        },
        "repair" => review_then_apply(PlanIntent::Repair { setup: setup.clone() }),
        "refresh" => json_of(service.refresh(&setup).await?),
        "reconcile" => json_of(service.reconcile(&needs_operation()?).await?),
        "retry" => {
            let operation = needs_operation()?;
            service.prepare_retry(&operation)?;
            spawn_run(service.clone(), operation.clone());
            json_of(dto::OperationRef { operation_id: operation, setup_id: setup })
        }
        _ => Err(Diagnostic::new("invalid_request", "This setup action is not one Yougori knows.")),
    }
}

/// `setup_get` on both doors: the setup's detail with its CORE-07 product document, shown at a
/// reading of the engine's evidence clock (S07, U01). A document that can't be made leaves the
/// detail as it was and says why.
async fn get(service: &Service, setup_id: &str) -> Result<views::Detail, Diagnostic> {
    let now = super::product::engine_now().await;
    service.get_with_product(setup_id, now)
}

// ----- The CLI's door -----

/// The engine methods behind `yougori template …`, reached through `automation::dispatch`. The
/// catalog has already checked the parameter names and types.
pub(crate) async fn wire(app: &AppHandle, method: &str, params: &Value) -> Result<Value, String> {
    answer(app, method, params).await.map_err(|diagnostic| wire_error(&diagnostic))
}

async fn answer(app: &AppHandle, method: &str, params: &Value) -> Result<Value, Diagnostic> {
    let service = service(app)?;
    match method {
        "setup_capabilities" => Ok(capabilities(app, &service)),
        "setup_validate" => validate(app, &service, params.clone()).await,
        "setup_plan" => plan(app, &service, params.clone()).await,
        "setup_apply" => json_of(apply(&service, parsed(params)?)?),
        "setup_list" => list(&service),
        "setup_get" => json_of(get(&service, &parsed::<GetCall>(params)?.setup_id).await?),
        "setup_permissions" => super::permissions::of(&service, &parsed::<GetCall>(params)?.setup_id, &super::planning::planner_host(app)).await,
        "setup_reveal" => reveal(&service, parsed(params)?).await,
        "setup_operation" => json_of(operation(&service, parsed(params)?)?),
        "setup_cancel" => json_of(cancel(&service, parsed(params)?)?),
        "setup_action" => action(&service, parsed(params)?).await,
        "setup_export" => {
            let call = parsed::<ExportCall>(params)?;
            super::export::export(&service, &call.setup_id, call.folder.map(std::path::PathBuf::from))
        }
        "setup_migration_inventory" | "setup_migration_backup" | "setup_migration_verify" | "setup_migration_rehearse" => {
            migration_call(&service, method, parsed(params)?)
        }
        "setup_backups" => backups_of(&service, parsed(params)?),
        "setup_backup_verify" => {
            let call = parsed::<BackupCall>(params)?;
            Ok(checked(&call, service.verify_backup(&call.setup_id, &call.resource, &call.backup_id).await?))
        }
        "setup_backup_restore" => restore(&service, parsed(params)?).await,
        "setup_backup_now" => back_up_now(&service, parsed(params)?),
        "setup_telemetry" => super::telemetry::read(&service, parsed(params)?),
        "setup_artifacts" => artifacts(app, &service, parsed(params)?).await,
        "setup_artifact_save" => save_artifact(app, &service, parsed(params)?).await,
        "setup_job_logs" => job_logs(app, &service, parsed(params)?).await,
        "setup_job_settle" => settle_job(app, &service, parsed(params)?).await,
        "setup_sandbox_logs" => sandbox_logs(app, &service, parsed(params)?).await,
        "setup_usage" => usage(app, &service, parsed(params)?).await,
        _ => Err(Diagnostic::new("invalid_request", "This setup method is not one Yougori knows.")),
    }
}

// ----- The desktop's door -----

// ----- What a setup's jobs made and printed -----

fn jobs(app: &AppHandle) -> Result<super::jobs::Jobs, Diagnostic> {
    app.try_state::<super::jobs::Jobs>()
        .map(|jobs| jobs.inner().clone())
        .ok_or_else(|| Diagnostic::new("setups_starting", "Setups are still starting. Try again in a moment.").retryable())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactsCall {
    setup_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactSaveCall {
    setup_id: String,
    artifact_id: String,
    /// A folder of this computer the person chose. The copy goes in it under the result's name.
    folder: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobCall {
    setup_id: String,
    /// The job's id in the setup.
    resource: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettleCall {
    setup_id: String,
    resource: String,
    /// `succeeded`, `failed` or `run_again`.
    outcome: String,
}

/// The job a setup recorded for `resource`, by its ID in the setup's realm.
fn job_of(service: &Service, setup: &str, resource: &str) -> Result<String, Diagnostic> {
    let part = service.resource_of(setup, resource)?;
    if part.kind != yougori_setup::resource::Kind::Job {
        return Err(Diagnostic::new("invalid_request", format!("{resource} isn't one of this setup's jobs.")).resource(resource));
    }
    part.runtime_id.ok_or_else(|| Diagnostic::new("job_not_sent", format!("{resource} hasn't been sent yet, so it has nothing to show.")).resource(resource))
}

/// Every result the setup's jobs handed back, each with the job it came from by its name in the
/// setup. Reads only.
async fn artifacts(app: &AppHandle, service: &Service, call: ArtifactsCall) -> Result<Value, Diagnostic> {
    let jobs_of: BTreeMap<String, String> = service
        .resources_of(&call.setup_id, yougori_setup::resource::Kind::Job)?
        .into_iter()
        .filter_map(|resource| resource.runtime_id.map(|id| (id, resource.id)))
        .collect();
    let found = jobs(app)?.artifacts(&call.setup_id).await.map_err(|error| Diagnostic::new("jobs_unavailable", error).retryable())?;
    let listed: Vec<Value> = found
        .into_iter()
        .map(|mut artifact| {
            let resource = artifact["job"].as_str().and_then(|job| jobs_of.get(job)).cloned();
            artifact["resource"] = json!(resource);
            artifact
        })
        .collect();
    Ok(json!({"setupId": call.setup_id, "artifacts": listed}))
}

/// The name a result is saved under: its own, made safe for a file name, and never one that is
/// already in the folder.
fn copy_name(folder: &std::path::Path, name: &str, artifact: &str) -> std::path::PathBuf {
    let safe: String = name.chars().map(|letter| if letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_' | '.') { letter } else { '_' }).collect();
    let safe = if safe.trim_matches('.').is_empty() { "result".to_owned() } else { safe };
    let first = folder.join(&safe);
    if !first.exists() {
        return first;
    }
    let short: String = artifact.chars().filter(char::is_ascii_alphanumeric).take(8).collect();
    folder.join(format!("{safe}-{short}"))
}

/// Copies one result into a folder the person chose, checked against its checksum.
async fn save_artifact(app: &AppHandle, service: &Service, call: ArtifactSaveCall) -> Result<Value, Diagnostic> {
    service.get(&call.setup_id)?;
    let folder = std::path::PathBuf::from(call.folder.trim());
    if !folder.is_absolute() || !folder.is_dir() {
        return Err(Diagnostic::new("invalid_value", "Choose a folder of this computer that exists for the copy.").at("folder"));
    }
    let jobs = jobs(app)?;
    let listed = jobs.artifacts(&call.setup_id).await.map_err(|error| Diagnostic::new("jobs_unavailable", error).retryable())?;
    let artifact = listed
        .iter()
        .find(|artifact| artifact["id"].as_str() == Some(call.artifact_id.as_str()))
        .ok_or_else(|| Diagnostic::new("artifact_unknown", "This setup has no result with that ID."))?;
    if artifact["removed"] == true {
        return Err(Diagnostic::new("artifact_removed", "That result is gone: the store's retention removed it. Its record says what it was."));
    }
    let to = copy_name(&folder, artifact["name"].as_str().unwrap_or("result"), &call.artifact_id);
    let bytes = jobs.save_artifact(&call.setup_id, &call.artifact_id, &to).await.map_err(|error| Diagnostic::new("artifact_unreadable", error))?;
    Ok(json!({"setupId": call.setup_id, "artifactId": call.artifact_id, "path": to.to_string_lossy(), "bytes": bytes, "sha256": artifact["sha256"]}))
}

/// What a job's last attempts printed. Reads only.
async fn job_logs(app: &AppHandle, service: &Service, call: JobCall) -> Result<Value, Diagnostic> {
    let job = job_of(service, &call.setup_id, &call.resource)?;
    let jobs = jobs(app)?;
    let mut attempts = jobs.logs(&call.setup_id, &job).await.map_err(|error| Diagnostic::new("jobs_unavailable", error).retryable())?;
    // And the runs events started, each said with why it ran.
    let runs = jobs.runs(&call.setup_id, &call.resource).await;
    for run in &runs {
        let Some(id) = run["job"].as_str() else { continue };
        for mut log in jobs.logs(&call.setup_id, id).await.unwrap_or_default() {
            log["run"] = json!(id);
            log["why"] = run["why"].clone();
            attempts.push(log);
        }
    }
    attempts.sort_by_key(|log| log["at"].as_i64().unwrap_or_default());
    Ok(json!({"setupId": call.setup_id, "resource": call.resource, "attempts": attempts, "runs": runs}))
}

/// Settles a job nobody knows the outcome of, after a person looked at what it did.
async fn settle_job(app: &AppHandle, service: &Service, call: SettleCall) -> Result<Value, Diagnostic> {
    let job = job_of(service, &call.setup_id, &call.resource)?;
    let state = jobs(app)?.settle(&call.setup_id, &job, &call.outcome).await.map_err(|error| Diagnostic::new("settle_refused", error))?;
    // What the job is now is read again, so the setup's own record follows.
    let _ = service.refresh(&call.setup_id).await;
    Ok(json!({"setupId": call.setup_id, "resource": call.resource, "state": state}))
}

/// What the setup's hosted models were used for this month: each cloud model gateway's own count
/// of what it spent, its budget, and what it refused (`models.cloud`, `models.free_only`,
/// `run.budget`). Read from the gateway sandbox; nothing a request carried is in it.
async fn usage(app: &AppHandle, service: &Service, call: ArtifactsCall) -> Result<Value, Diagnostic> {
    let gateways = service
        .resources_of(&call.setup_id, yougori_setup::resource::Kind::Environment)?
        .into_iter()
        .filter(|resource| resource.spec["environment"]["YOUGORI_MODEL_GATEWAY"].as_str() == Some("1"))
        .collect::<Vec<_>>();
    let mut models = Vec::new();
    for gateway in gateways {
        let Some(id) = gateway.runtime_id.clone() else { continue };
        let read = crate::automation::dispatch::dispatch(app, "execute_environment_command", &json!({"request": {"environmentId": id, "command": "cat /data/usage.json"}})).await;
        let entry = match read {
            Ok(answer) if answer["exitCode"].as_i64().unwrap_or(0) == 0 => match serde_json::from_str::<Value>(answer["stdout"].as_str().unwrap_or_default().trim()) {
                Ok(found) => json!({
                    "resource": gateway.id,
                    "month": found["month"],
                    "spentUsd": found["spentUsd"],
                    "requests": found["requests"],
                    "refused": found["refused"],
                    "unpriced": found["unpriced"],
                    "budgetUsd": gateway.spec["environment"]["BUDGET_USD"].as_str().and_then(|text| text.parse::<f64>().ok()).filter(|budget| *budget > 0.0),
                    "freeOnly": gateway.spec["environment"]["FREE_ONLY"].as_str() == Some("yes"),
                    "model": gateway.spec["environment"]["MODEL"],
                }),
                Err(_) => json!({"resource": gateway.id, "error": "Its gateway hasn't counted anything yet."}),
            },
            Ok(_) => json!({"resource": gateway.id, "error": "Its gateway hasn't counted anything yet."}),
            Err(error) => json!({"resource": gateway.id, "error": crate::lifecycle::safe_diagnostic(&error)}),
        };
        models.push(entry);
    }
    Ok(json!({"setupId": call.setup_id, "models": models}))
}

#[tauri::command]
pub async fn setup_usage(app: AppHandle, window: WebviewWindow, setup_id: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    usage(&app, &service, ArtifactsCall { setup_id }).await.map_err(fail)
}

/// How much of a sandbox's log a setup page shows: its end.
const SANDBOX_LOG_BYTES: usize = 64 * 1024;

/// What one of a setup's own sandboxes printed lately, by its id in the setup. A sandbox another
/// setup owns, or one that isn't there, has nothing of this setup's to show.
async fn sandbox_logs(app: &AppHandle, service: &Service, call: JobCall) -> Result<Value, Diagnostic> {
    let part = service.resource_of(&call.setup_id, &call.resource)?;
    if part.kind != yougori_setup::resource::Kind::Environment || part.borrowed() {
        return Err(Diagnostic::new("invalid_request", format!("{} isn't one of this setup's own sandboxes.", call.resource)).resource(&call.resource));
    }
    let id = part.runtime_id.ok_or_else(|| Diagnostic::new("sandbox_missing", format!("{} hasn't been made yet, so it has printed nothing.", call.resource)).resource(&call.resource))?;
    let printed = crate::automation::dispatch::dispatch(app, "get_environment_logs", &json!({"environmentId": id}))
        .await
        .map_err(|error| Diagnostic::new("logs_unavailable", crate::lifecycle::safe_diagnostic(&error)).retryable().resource(&call.resource))?;
    let text = printed.as_str().unwrap_or_default();
    let start = text.len().saturating_sub(SANDBOX_LOG_BYTES);
    let start = (start..=text.len()).find(|at| text.is_char_boundary(*at)).unwrap_or(text.len());
    Ok(json!({"setupId": call.setup_id, "resource": call.resource, "text": &text[start..], "truncated": start > 0}))
}

#[tauri::command]
pub async fn setup_sandbox_logs(app: AppHandle, window: WebviewWindow, setup_id: String, resource: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    sandbox_logs(&app, &service, JobCall { setup_id, resource }).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_artifacts(app: AppHandle, window: WebviewWindow, setup_id: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    artifacts(&app, &service, ArtifactsCall { setup_id }).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_artifact_save(app: AppHandle, window: WebviewWindow, setup_id: String, artifact_id: String, folder: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    save_artifact(&app, &service, ArtifactSaveCall { setup_id, artifact_id, folder }).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_job_logs(app: AppHandle, window: WebviewWindow, setup_id: String, resource: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    job_logs(&app, &service, JobCall { setup_id, resource }).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_job_settle(app: AppHandle, window: WebviewWindow, setup_id: String, resource: String, outcome: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    settle_job(&app, &service, SettleCall { setup_id, resource, outcome }).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_capabilities(app: AppHandle, window: WebviewWindow) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    Ok(capabilities(&app, &service))
}

#[tauri::command]
pub async fn setup_validate(app: AppHandle, window: WebviewWindow, request: Value) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    validate(&app, &service, request).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_plan(app: AppHandle, window: WebviewWindow, request: Value) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    plan(&app, &service, request).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_apply(app: AppHandle, window: WebviewWindow, request: ApplyCall) -> Reply<dto::OperationRef> {
    main_window(&window)?;
    apply(&service(&app).map_err(fail)?, request).map_err(fail)
}

#[tauri::command]
pub async fn setup_list(app: AppHandle, window: WebviewWindow) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    list(&service).map_err(fail)
}

#[tauri::command]
pub async fn setup_get(app: AppHandle, window: WebviewWindow, setup_id: String) -> Reply<views::Detail> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    get(&service, &setup_id).await.map_err(fail)
}

/// What a setup is allowed to do now: its template planned again with its own answers. Reads
/// only.
#[tauri::command]
pub async fn setup_permissions(app: AppHandle, window: WebviewWindow, setup_id: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    super::permissions::of(&service, &setup_id, &super::planning::planner_host(&app)).await.map_err(fail)
}

/// A setup's private outputs: without `key`, which ones it can show now; with `key`, that one's
/// value, asked of the product now. Nothing of it is kept or logged.
#[tauri::command]
pub async fn setup_reveal(app: AppHandle, window: WebviewWindow, setup_id: String, key: Option<String>) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    reveal(&service, RevealCall { setup_id, key }).await.map_err(fail)
}

#[tauri::command]
pub async fn setup_operation(
    app: AppHandle,
    window: WebviewWindow,
    operation_id: Option<String>,
    setup_id: Option<String>,
    cursor: Option<u64>,
) -> Reply<dto::OperationProgress> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    operation(&service, OperationCall { operation_id, setup_id, cursor }).map_err(fail)
}

#[tauri::command]
pub async fn setup_cancel(
    app: AppHandle,
    window: WebviewWindow,
    operation_id: String,
    setup_id: Option<String>,
) -> Reply<dto::OperationProgress> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    cancel(&service, CancelCall { operation_id, setup_id }).map_err(fail)
}

#[tauri::command]
pub async fn setup_action(app: AppHandle, window: WebviewWindow, request: ActionCall) -> Reply<Value> {
    main_window(&window)?;
    action(&service(&app).map_err(fail)?, request).await.map_err(fail)
}

/// A setup's backup times and the copies kept for each of its volumes. Reads only.
#[tauri::command]
pub async fn setup_backups(app: AppHandle, window: WebviewWindow, setup_id: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    backups_of(&service, BackupsCall { setup_id }).map_err(fail)
}

/// Checks one kept backup against its own record. Changes nothing, on the backup or the volume.
///
/// The answer goes through `checked` here for the same reason the wire path does: both doors lead
/// to the same check, so both say the same thing. Without it the desktop got a bare report and
/// every caller had to fill in which copy it was about from its own request.
#[tauri::command]
pub async fn setup_backup_verify(
    app: AppHandle,
    window: WebviewWindow,
    setup_id: String,
    resource: String,
    backup_id: String,
) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    let call = BackupCall { setup_id, resource, backup_id };
    let report = service.verify_backup(&call.setup_id, &call.resource, &call.backup_id).await.map_err(fail)?;
    Ok(checked(&call, report))
}

/// The review, then — called again with the `confirm` the review gave — the restore itself.
/// Without `confirm` nothing at all is changed.
#[tauri::command]
pub async fn setup_backup_restore(
    app: AppHandle,
    window: WebviewWindow,
    setup_id: String,
    resource: String,
    backup_id: String,
    over_original: Option<bool>,
    confirm: Option<String>,
) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    restore(
        &service,
        RestoreCall { setup_id, resource, backup_id, over_original: over_original.unwrap_or(false), confirm },
    )
    .await
    .map_err(fail)
}

/// A backup of one volume now. Its regular times stay as they are.
#[tauri::command]
pub async fn setup_backup_now(app: AppHandle, window: WebviewWindow, setup_id: String, resource: String) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    back_up_now(&service, BackupNowCall { setup_id, resource }).map_err(fail)
}

/// The read-only operations reading across this computer's setups (plan 15, `operations-dashboard`).
#[tauri::command]
pub async fn setup_telemetry(
    app: AppHandle,
    window: WebviewWindow,
    setup_id: Option<String>,
    cursor: Option<usize>,
    limit: Option<usize>,
) -> Reply<Value> {
    main_window(&window)?;
    let service = service(&app).map_err(fail)?;
    super::telemetry::read(&service, super::telemetry::Call { setup_id, cursor, limit }).map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_confirmation_belongs_to_the_one_restore_it_was_shown_for() {
        let call = |backup: &str, over: bool| RestoreCall {
            setup_id: "stp-1".into(),
            resource: "data".into(),
            backup_id: backup.into(),
            over_original: over,
            confirm: None,
        };
        let copy = restore_confirmation(&call("backup-a", false));
        assert!(copy.starts_with("restore-") && copy.len() == 24);
        // The same restore always reads the same; a different backup, or the other target, does
        // not, so a confirmation can never carry over to something that was never reviewed.
        assert_eq!(copy, restore_confirmation(&call("backup-a", false)));
        assert_ne!(copy, restore_confirmation(&call("backup-b", false)));
        assert_ne!(copy, restore_confirmation(&call("backup-a", true)));
    }

    fn restore_call(confirm: Option<&str>, over_original: bool) -> RestoreCall {
        RestoreCall {
            setup_id: "stp-1".into(),
            resource: "app-data".into(),
            backup_id: "backup-a".into(),
            over_original,
            confirm: confirm.map(str::to_owned),
        }
    }

    #[test]
    fn a_restore_does_nothing_at_all_without_a_confirmation() {
        // `Decided::Apply` is the only branch of `restore` that calls the worker, and no request
        // without a confirmation can reach it — whichever target was asked for.
        assert_eq!(decide(&restore_call(None, false)), Decided::Review);
        assert_eq!(decide(&restore_call(None, true)), Decided::Review);
        for wrong in ["", "yes", "restore-0000000000000000", &restore_confirmation(&restore_call(None, true))] {
            assert_eq!(decide(&restore_call(Some(wrong), false)), Decided::Stale, "{wrong} was taken as a confirmation");
        }
        // Only the word this exact restore was reviewed with goes ahead.
        let asked = restore_call(None, false);
        assert_eq!(decide(&restore_call(Some(&restore_confirmation(&asked)), false)), Decided::Apply);
    }

    #[test]
    fn the_review_says_it_changed_nothing_and_how_to_go_ahead() {
        let call = restore_call(None, true);
        let said = json!({
            "reviewed": true, "applied": false, "overwrites": call.over_original,
            "confirm": restore_confirmation(&call),
        });
        assert_eq!(said["applied"], false);
        assert_eq!(said["overwrites"], true);
        assert!(said["confirm"].as_str().unwrap().starts_with("restore-"));
    }

    #[test]
    fn a_check_says_what_it_looked_at_and_that_nothing_changed() {
        let call = BackupCall { setup_id: "stp-1".into(), resource: "app-data".into(), backup_id: "backup-a".into() };
        let report = checked(&call, json!({"files": 412, "at": 1_800_000_000i64, "checksum": "sha256:aa"}));
        assert_eq!(report["changed"], false);
        assert_eq!(report["backupId"], "backup-a");
        assert_eq!(report["resource"], "app-data");
        assert!(report["when"].as_str().is_some_and(|when| when.len() == 16), "{report}");
    }

    #[test]
    fn a_refusal_keeps_its_code_and_flag_and_only_the_sentence_is_shown() {
        let refusal = Diagnostic::new("setup_busy", "Another change to this setup is in progress right now.")
            .resource("setup-6f1c2a1e-1b55-4c55-9a64-2d4a0b5c3e10")
            .retryable();
        let (said, details) = wire_fault(&wire_error(&refusal)).unwrap();
        assert_eq!(said, refusal.message);
        assert!(!said.contains(FAULT) && !said.contains("setup_busy"));
        assert_eq!(details.code, "setup_busy");
        assert!(details.retryable);
        assert_eq!(details.affected_resource.as_deref(), Some("setup-6f1c2a1e-1b55-4c55-9a64-2d4a0b5c3e10"));
        assert_eq!(details.outcome, "not_started");

        let final_one = Diagnostic::new("setup_removed", "This setup was removed: start a new one.");
        let (said, details) = wire_fault(&wire_error(&final_one)).unwrap();
        assert_eq!(said, "This setup was removed: start a new one.");
        assert!(!details.retryable && details.affected_resource.is_none());
    }

    #[test]
    fn other_failures_are_left_alone() {
        assert!(wire_fault("YOUGORI_GRIDS no_such_grid: There is no such grid.").is_none());
        assert!(wire_fault("YOUGORI_SETUP Bad Code retry: x").is_none());
        assert!(wire_fault("YOUGORI_SETUP setup_busy maybe: x").is_none());
        assert!(wire_fault("Something else went wrong").is_none());
    }
}
