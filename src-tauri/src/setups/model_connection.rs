//! Reviewed, private model attachments for any format-2 template with yougori-models.yaml.
//! The durable intent contains identities and argv only, never model credentials. Receiver
//! commands must make attach/detach idempotent by model environment ID.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn invalid(message: impl Into<String>) -> HandlerError {
    super::invalid(message.into())
}

#[derive(Clone, Serialize, Deserialize)]
struct Attachment {
    source: String,
    target: String,
    command: Vec<String>,
    connection: Option<String>,
    complete: bool,
    label: String,
}

pub(super) fn requested(spec: &Value) -> bool {
    spec["model_request"] == true
}

fn command(spec: &Value) -> Result<Vec<String>, HandlerError> {
    let argv: Vec<String> = serde_json::from_value(spec["model_command"].clone()).map_err(|_| refused("model_request needs a command containing only string arguments."))?;
    if argv.is_empty() || argv.len() > 16 || argv.iter().any(|arg| arg.is_empty() || arg.chars().count() > 512 || arg.chars().any(char::is_control)) {
        return Err(refused("model_request needs the reviewed command from yougori-models.yaml."));
    }
    Ok(argv)
}

pub(super) fn validate(spec: &Value) -> Result<(), HandlerError> {
    command(spec)?;
    connections(spec)?;
    if spec["ports"] != json!([8000]) || (!spec["direction"].is_null() && spec["direction"] != "one_way") || (!spec["permissions"].is_null() && spec["permissions"] != json!([])) {
        return Err(refused("model_request permits only one-way access to port 8000; additional permissions are not allowed."));
    }
    Ok(())
}

pub(super) fn review(id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
    validate(spec)?;
    let from = spec["from"]["resource"].as_str().unwrap_or_default();
    let to = spec["to"]["resource"].as_str().unwrap_or_default();
    if !others.get(from).is_some_and(|(kind, _)| *kind == Kind::Environment)
        || !others
            .get(to)
            .is_some_and(|(kind, model)| *kind == Kind::ModelService && super::super::local_models::is_local(model))
    {
        return Err(refused(
            "model_request needs this setup's own receiving environment and its own local model_service. Grid models and borrowed resources are not supported here.",
        ));
    }
    for (other, (kind, connection)) in others {
        if other != id
            && *kind == Kind::Connection
            && ((connection["from"] == spec["from"] && connection["to"] == spec["to"]) || (connection["from"] == spec["to"] && connection["to"] == spec["from"]))
        {
            return Err(refused("Declare one model_request connection per environment/model pair."));
        }
    }
    Ok(())
}

pub(super) fn ends(context: &StepContext) -> Result<(String, String), HandlerError> {
    let peer = |field: &str, kind: Kind| {
        context.spec[field]["resource"]
            .as_str()
            .and_then(|id| context.peers.get(id))
            .filter(|p| p.kind == kind && p.owned)
            .and_then(|p| p.runtime_id.clone())
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "The model attachment's owned resources are not ready."))
    };
    Ok((peer("from", Kind::Environment)?, peer("to", Kind::ModelService)?))
}

fn path(ordinary: &Ordinary, context: &StepContext) -> PathBuf {
    ordinary
        .folder(&context.setup)
        .join("model-links")
        .join(format!("{:x}.json", Sha256::digest(context.resource.as_bytes())))
}

fn load(path: &Path) -> Result<Option<Attachment>, HandlerError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| invalid("The model attachment record is unreadable; it was preserved.")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(invalid("The model attachment record could not be read.")),
    }
}

fn save(path: &Path, value: &Attachment) -> Result<(), HandlerError> {
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|_| invalid("Cannot prepare the model attachment record."))?;
    crate::foundation::events::write_atomic(path, &serde_json::to_vec(value).map_err(|_| invalid("Cannot encode the model attachment record."))?)
        .map_err(|_| invalid("Cannot save the model attachment record."))
}

async fn call(ordinary: &Ordinary, method: &str, params: Value) -> Result<Value, HandlerError> {
    // An arbitrary receiver or remote runtime may print a key in its error. Do not relay it.
    match tokio::time::timeout(std::time::Duration::from_secs(180), ordinary.projects.model_call(method, params)).await {
        Ok(Ok(value)) => Ok(value),
        _ => Err(HandlerError::new(
            Outcome::Unknown,
            "model_attachment_pending",
            format!("The model attachment step {method} did not finish. Its private intent is saved; continue the setup to retry."),
        )),
    }
}

fn link<'a>(state: &'a Value, item: &Attachment) -> Option<&'a Value> {
    state["connections"]
        .as_array()?
        .iter()
        .find(|c| (c["sourceId"] == item.source && c["targetId"] == item.target) || (c["sourceId"] == item.target && c["targetId"] == item.source))
}

fn exact(connection: &Value, item: &Attachment) -> bool {
    connection["sourceId"] == item.source
        && connection["targetId"] == item.target
        && connection["direction"] == "oneWay"
        && connection["ports"] == json!(["8000"])
        && connection["permissions"] == json!(["ports"])
        && connection["commands"] != true
        && connection["active"] == true
        && connection["selectedFolders"].as_array().is_none_or(Vec::is_empty)
        && connection["volume"].is_null()
        && connection["sshPort"].is_null()
}

async fn send(ordinary: &Ordinary, item: &Attachment, payload: Value) -> Result<(), HandlerError> {
    let detaching = payload["action"] == "detach";
    // A stable private directory lets a retry clean up even if the copy's reply was lost.
    let staging = format!("/tmp/yougori-model-{:x}", Sha256::digest(format!("{}\n{}", item.source, item.target).as_bytes()));
    let prepared = call(
        ordinary,
        "execute_environment_command",
        json!({"request": {"environmentId": item.source,
        "command": format!("umask 077; rm -rf -- {0} && mkdir -- {0}", quoted(&staging))}}),
    )
    .await?;
    if prepared["exitCode"] != 0 {
        return Err(invalid("Cannot prepare the receiver's private transfer directory."));
    }
    let temp = tempfile::tempdir().map_err(|_| invalid("Cannot prepare the private attachment transfer."))?;
    let file = temp.path().join("model-request.json");
    std::fs::write(&file, serde_json::to_vec(&payload).map_err(|_| invalid("Cannot prepare the private attachment request."))?)
        .map_err(|_| invalid("Cannot write the private attachment request."))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).map_err(|_| invalid("Cannot protect the private attachment request."))?;
    }
    let copied = call(
        ordinary,
        "copy_files_to_environment",
        json!({"environmentId": item.source, "paths": [file.to_string_lossy()], "destination": staging}),
    )
    .await?;
    drop(temp);
    let folder = copied["destination"]
        .as_str()
        .filter(|p| {
            p.strip_prefix(&format!("{staging}/yougori-import-"))
                .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
        })
        .ok_or_else(|| invalid("The attachment transfer returned an unexpected destination."))?;
    let result = call(
        ordinary,
        "execute_environment_command",
        json!({"request": {"environmentId": item.source,
        "command": yougori_cli::template_models::command_line(&item.command, folder)}}),
    )
    .await;
    // The receiver and its wrapper remove the file; cleanup also runs after an execution error.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ordinary.projects.model_call(
            "execute_environment_command",
            json!({"request": {"environmentId": item.source, "command": format!("rm -rf -- {}", quoted(&staging))}}),
        ),
    )
    .await;
    let result = result?;
    let reply = result["stdout"]
        .as_str()
        .unwrap_or_default()
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| serde_json::from_str::<Value>(line).ok());
    if result["exitCode"] != 0 || !reply.is_some_and(|r| r.is_object() && r.get("error").is_none() && if detaching { r["detached"].is_boolean() } else { r["attached"] == true }) {
        return Err(HandlerError::new(
            Outcome::Unknown,
            "model_receiver_pending",
            "The template's model receiver did not acknowledge the request. Continue the setup to retry; receiver output is withheld because it may contain credentials.",
        ));
    }
    Ok(())
}

async fn detach(ordinary: &Ordinary, item: &Attachment) -> Result<(), HandlerError> {
    let state = call(ordinary, "get_platform_state", json!({})).await?;
    // Close authority first, including if the receiver is stopped and cannot remove its row yet.
    if let Some(connection) = link(&state, item) {
        let id = connection["id"].as_str().ok_or_else(|| invalid("The model connection has no identity."))?;
        if !exact(connection, item) || item.connection.as_deref().is_some_and(|saved| saved != id) {
            return Err(refused("The model connection was changed outside this setup; its replacement was left untouched."));
        }
        call(ordinary, "delete_connection", json!({"connectionId": id})).await?;
    }
    let source = state["environments"].as_array().into_iter().flatten().find(|e| e["id"] == item.source);
    match source {
        None => Ok(()),
        Some(env) if env["status"] == "running" => send(ordinary, item, json!({"action":"detach", "environment":item.target})).await,
        Some(_) => Err(HandlerError::new(
            Outcome::NotStarted,
            "receiver_stopped",
            "The private model connection is closed. Start the receiving sandbox and continue to remove its saved catalog entry.",
        )),
    }
}

pub(super) async fn apply(ordinary: &Ordinary, context: &StepContext) -> Result<Receipt, HandlerError> {
    validate(&context.spec)?;
    if context.cancel.is_cancelled() {
        return Err(interrupted_or(context, "cancelled".into()));
    }
    let (source, target) = ends(context)?;
    let command = command(&context.spec)?;
    let file = path(ordinary, context);
    let mut saved = load(&file)?;
    if let Some(old) = &saved {
        if old.source != source || old.target != target || old.command != command {
            detach(ordinary, old).await?;
            std::fs::remove_file(&file).map_err(|_| invalid("Cannot retire the detached model record."))?;
            saved = None;
        }
    }
    let mut item = saved.unwrap_or(Attachment {
        source,
        target,
        command,
        connection: None,
        complete: false,
        label: context.label.clone(),
    });
    let state = call(ordinary, "get_platform_state", json!({})).await?;
    for id in [&item.source, &item.target] {
        if !state["environments"].as_array().into_iter().flatten().any(|e| e["id"] == *id && e["status"] == "running") {
            return Err(HandlerError::new(
                Outcome::NotStarted,
                "target_not_running",
                "Start the receiving sandbox and model before connecting them.",
            ));
        }
    }
    let existing = link(&state, &item);
    if existing.is_some() && !file.exists() {
        return Err(refused("These resources already have a connection outside this attachment. It was left untouched."));
    }
    if existing.is_some_and(|c| !exact(c, &item) || item.connection.as_deref().is_some_and(|id| c["id"] != id)) {
        return Err(refused("The model connection no longer matches the reviewed one-way grant."));
    }
    item.complete = false;
    item.label = context.label.clone();
    save(&file, &item)?; // intent precedes the engine effect and survives a lost response
    let state = if existing.is_none() {
        call(
            ordinary,
            "create_connection",
            json!({"request":{"sourceId":item.source,"targetId":item.target,
            "direction":"oneWay","permissions":["ports"],"ports":["8000"],"commands":false}}),
        )
        .await?
    } else {
        state
    };
    let connection = link(&state, &item).filter(|c| exact(c, &item)).ok_or_else(|| {
        HandlerError::new(
            Outcome::Unknown,
            "model_connection_pending",
            "The private model connection was requested but is not confirmed. Continue to check it again.",
        )
    })?;
    item.connection = Some(connection["id"].as_str().ok_or_else(|| invalid("The model connection has no identity."))?.to_owned());
    save(&file, &item)?;
    if context.cancel.is_cancelled() {
        return Err(interrupted_or(context, "cancelled".into()));
    }
    let access = call(ordinary, "model_api_status", json!({"environmentId": item.target})).await?;
    let key = access["apiKey"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "model_key_missing", "The model has no API credential yet."))?;
    let model = access["model"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("The model has not reported its identity."))?;
    let skills = call(ordinary, "get_connection_skills", json!({"environmentId":item.source})).await?;
    let address = yougori_cli::template_models::peer_address(skills.as_str().unwrap_or_default(), &item.target).map_err(invalid)?;
    send(
        ordinary,
        &item,
        yougori_cli::template_models::request(model, &item.target, &format!("http://{address}:8000/v1"), key, "local"),
    )
    .await?;
    item.complete = true;
    save(&file, &item)?;
    Ok(receipt(item.connection, Observed::Present, false, Cost::Free))
}

pub(super) async fn remove(ordinary: &Ordinary, context: &StepContext) -> Result<Receipt, HandlerError> {
    let file = path(ordinary, context);
    if let Some(item) = load(&file)? {
        detach(ordinary, &item).await?;
        std::fs::remove_file(file).map_err(|_| invalid("The model was detached but its record could not be removed. Continue to retry."))?;
    } else if context.runtime_id.is_some() {
        return Err(HandlerError::new(
            Outcome::Unknown,
            "model_attachment_record_missing",
            "The attachment record is missing. No unowned connection was removed.",
        ));
    }
    Ok(receipt(None, Observed::Missing, false, Cost::Free))
}

pub(super) async fn observe(ordinary: &Ordinary, context: &StepContext) -> Result<Observation, HandlerError> {
    let Some(item) = load(&path(ordinary, context))? else { return Ok(Observation::Absent) };
    if !item.complete {
        return Ok(Observation::Unknown {
            reason: "Model attachment is incomplete; continue to replay its idempotent receiver.".into(),
        });
    }
    if let Ok((source, target)) = ends(context) {
        if item.source != source || item.target != target || item.command != command(&context.spec)? {
            return Ok(Observation::Absent);
        }
    } else {
        return Ok(Observation::Absent);
    }
    let state = call(ordinary, "get_platform_state", json!({})).await?;
    if !link(&state, &item).is_some_and(|c| exact(c, &item) && c["id"].as_str() == item.connection.as_deref()) {
        return Ok(Observation::Absent);
    }
    Ok(Observation::Present {
        runtime_id: item.connection.unwrap(),
        observed: Observed::Present,
        label: Some(item.label),
        retained_data: false,
        cost: Cost::Free,
    })
}

pub(super) async fn recover(ordinary: &Ordinary, context: &StepContext) -> Result<Recovery, HandlerError> {
    let item = load(&path(ordinary, context))?;
    if context.action == Action::Remove {
        // A closed grant alone does not prove that the receiver removed its stored credential.
        if item.is_some() {
            return Ok(Recovery::NotApplied);
        }
        let state = call(ordinary, "get_platform_state", json!({})).await?;
        if context
            .runtime_id
            .as_ref()
            .is_some_and(|id| state["connections"].as_array().into_iter().flatten().any(|c| c["id"] == *id))
        {
            return Ok(Recovery::Unknown {
                reason: "The attachment record is missing but its connection remains; no unowned grant was changed.".into(),
            });
        }
        return Ok(Recovery::Applied(receipt(None, Observed::Missing, false, Cost::Free)));
    }
    if matches!(context.action, Action::Create | Action::Update) && item.as_ref().is_none_or(|item| !item.complete || item.label != context.label) {
        // apply checks the durable intent and exact grant before replaying the idempotent hook.
        return Ok(Recovery::NotApplied);
    }
    Ok(super::super::handler::recovery_from(context, observe(ordinary, context).await?))
}

pub(super) async fn health(ordinary: &Ordinary, context: &StepContext) -> Result<HealthReport, HandlerError> {
    Ok(match observe(ordinary, context).await? {
        Observation::Present { .. } => super::health(
            Health::Ready,
            "The receiver acknowledged the model and its private connection is active. Model inference health is reported by the model resource.",
        ),
        _ => super::health(Health::Failed, "The model attachment is missing or incomplete. Continue or repair the setup."),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Rpc {
        links: Vec<Value>,
        payloads: Vec<Value>,
        created: usize,
        fail_create_reply: bool,
        fail_receiver: bool,
        source_stopped: bool,
    }

    fn fixture() -> (tempfile::TempDir, Ordinary, StepContext, Arc<Mutex<Rpc>>) {
        let dir = tempfile::tempdir().unwrap();
        let rpc = Arc::new(Mutex::new(Rpc::default()));
        let captured = rpc.clone();
        let projects = fake::FakeProjects {
            model_rpc: Some(Arc::new(move |method, params| {
                // The credential is carried by a file, never by an engine command or a receipt.
                assert!(!params.to_string().contains("test-private-model-key"));
                let mut rpc = captured.lock().unwrap();
                let state = |rpc: &Rpc| {
                    json!({"environments":[
                {"id":"web-1","status":if rpc.source_stopped { "stopped" } else { "running" }},
                {"id":"model-1","status":"running"}],"connections":rpc.links})
                };
                match method {
                    "get_platform_state" => Ok(state(&rpc)),
                    "create_connection" => {
                        rpc.created += 1;
                        let mut link = params["request"].clone();
                        link["id"] = json!("grant-1");
                        link["active"] = json!(true);
                        rpc.links.push(link);
                        if std::mem::take(&mut rpc.fail_create_reply) {
                            Err("response lost".into())
                        } else {
                            Ok(state(&rpc))
                        }
                    }
                    "delete_connection" => {
                        rpc.links.retain(|c| c["id"] != params["connectionId"]);
                        Ok(state(&rpc))
                    }
                    "model_api_status" => Ok(json!({"model":"test/model","apiKey":"test-private-model-key"})),
                    "get_connection_skills" => Ok(json!("```json\n{\"connections\":[{\"peerId\":\"model-1\",\"peerAddress\":\"10.88.0.8\"}]}\n```")),
                    "copy_files_to_environment" => {
                        let bytes = std::fs::read(params["paths"][0].as_str().unwrap()).unwrap();
                        rpc.payloads.push(serde_json::from_slice(&bytes).unwrap());
                        Ok(json!({"destination":format!("{}/yougori-import-test", params["destination"].as_str().unwrap())}))
                    }
                    "execute_environment_command" => {
                        if params["request"]["command"].as_str().unwrap().starts_with("rm -rf") || params["request"]["command"].as_str().unwrap().starts_with("umask") {
                            return Ok(json!({"exitCode":0}));
                        }
                        if std::mem::take(&mut rpc.fail_receiver) {
                            return Err("test-private-model-key".into());
                        }
                        let reply = if rpc.payloads.last().unwrap()["action"] == "detach" {
                            json!({"detached":true})
                        } else {
                            json!({"attached":true})
                        };
                        Ok(json!({"exitCode":0,"stdout":reply.to_string()}))
                    }
                    _ => panic!("Unexpected model RPC: {method}"),
                }
            })),
            ..Default::default()
        };
        let context = StepContext {
            setup: "test".into(),
            operation: "op".into(),
            step: "link".into(),
            resource: "attached".into(),
            kind: Kind::Connection,
            action: Action::Create,
            label: "label-1".into(),
            created_label: None,
            generation: 1,
            spec: json!({"from":{"resource":"web"},"to":{"resource":"model"},"ports":[8000],"model_request":true,"model_command":["python","/app/attached.py"]}),
            runtime_id: None,
            owner: None,
            peers: [
                (
                    "web".into(),
                    super::super::super::handler::Peer {
                        kind: Kind::Environment,
                        spec: json!({}),
                        runtime_id: Some("web-1".into()),
                        owned: true,
                    },
                ),
                (
                    "model".into(),
                    super::super::super::handler::Peer {
                        kind: Kind::ModelService,
                        spec: json!({"model":"test/model"}),
                        runtime_id: Some("model-1".into()),
                        owned: true,
                    },
                ),
            ]
            .into(),
            planned: Default::default(),
            cancel: CancellationToken::new(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Default::default(),
        };
        (dir, Ordinary::new(Arc::new(projects), std::env::temp_dir()), context, rpc)
    }

    fn isolated() -> (tempfile::TempDir, Ordinary, StepContext, Arc<Mutex<Rpc>>) {
        let (dir, mut ordinary, context, rpc) = fixture();
        ordinary.folder = dir.path().to_owned();
        (dir, ordinary, context, rpc)
    }

    #[tokio::test]
    async fn attaches_once_and_removes_the_grant_and_receiver_credential() {
        let (_dir, ordinary, mut context, rpc) = isolated();
        let first = apply(&ordinary, &context).await.unwrap();
        apply(&ordinary, &context).await.unwrap();
        assert_eq!(rpc.lock().unwrap().created, 1);
        let saved = std::fs::read_to_string(path(&ordinary, &context)).unwrap();
        assert!(!saved.contains("test-private-model-key"));
        assert_eq!(rpc.lock().unwrap().payloads[0]["key"], "test-private-model-key");
        assert!(matches!(recover(&ordinary, &context).await.unwrap(), Recovery::Applied(_)));
        context.action = Action::Remove;
        context.runtime_id = first.runtime_id;
        assert_eq!(recover(&ordinary, &context).await.unwrap(), Recovery::NotApplied);
        remove(&ordinary, &context).await.unwrap();
        assert!(rpc.lock().unwrap().links.is_empty());
        assert_eq!(rpc.lock().unwrap().payloads.last().unwrap()["action"], "detach");
        assert!(matches!(recover(&ordinary, &context).await.unwrap(), Recovery::Applied(_)));
    }

    #[tokio::test]
    async fn a_lost_create_response_or_receiver_error_can_continue_without_duplicate_grants() {
        let (_dir, ordinary, context, rpc) = isolated();
        rpc.lock().unwrap().fail_create_reply = true;
        assert_eq!(apply(&ordinary, &context).await.unwrap_err().outcome, Outcome::Unknown);
        assert_eq!(recover(&ordinary, &context).await.unwrap(), Recovery::NotApplied);
        rpc.lock().unwrap().fail_receiver = true;
        let error = apply(&ordinary, &context).await.unwrap_err();
        assert!(!error.message.contains("test-private-model-key"));
        assert_eq!(recover(&ordinary, &context).await.unwrap(), Recovery::NotApplied);
        apply(&ordinary, &context).await.unwrap();
        assert_eq!(rpc.lock().unwrap().created, 1);
    }

    #[tokio::test]
    async fn remove_after_closing_a_grant_still_retries_receiver_cleanup() {
        let (_dir, ordinary, mut context, rpc) = isolated();
        context.runtime_id = apply(&ordinary, &context).await.unwrap().runtime_id;
        context.action = Action::Remove;
        rpc.lock().unwrap().source_stopped = true;
        assert_eq!(remove(&ordinary, &context).await.unwrap_err().code, "receiver_stopped");
        assert!(rpc.lock().unwrap().links.is_empty());
        assert_eq!(recover(&ordinary, &context).await.unwrap(), Recovery::NotApplied);
        rpc.lock().unwrap().source_stopped = false;
        remove(&ordinary, &context).await.unwrap();
        assert!(!path(&ordinary, &context).exists());
    }

    #[tokio::test]
    async fn existing_or_modified_grants_and_borrowed_resources_are_not_adopted() {
        let (_dir, ordinary, mut context, rpc) = isolated();
        apply(&ordinary, &context).await.unwrap();
        let file = path(&ordinary, &context);
        let saved = std::fs::read(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert!(apply(&ordinary, &context).await.is_err());
        std::fs::write(file, saved).unwrap();
        rpc.lock().unwrap().links[0]["commands"] = json!(true);
        assert!(remove(&ordinary, &context).await.is_err());
        assert_eq!(rpc.lock().unwrap().links.len(), 1);
        context.peers.get_mut("model").unwrap().owned = false;
        assert!(ends(&context).is_err());
    }

    #[tokio::test]
    async fn cancellation_and_invalid_authority_are_refused_before_effects() {
        let (_dir, ordinary, mut context, rpc) = isolated();
        context.cancel.cancel();
        assert!(apply(&ordinary, &context).await.is_err());
        assert_eq!(rpc.lock().unwrap().created, 0);
        context.spec["ports"] = json!([8000, 22]);
        assert!(validate(&context.spec).is_err());
        context.spec["ports"] = json!([8000]);
        context.spec["permissions"] = json!(["files"]);
        assert!(validate(&context.spec).is_err());
    }

    #[tokio::test]
    async fn changing_connection_modes_cannot_abandon_an_existing_grant() {
        let (_dir, ordinary, mut context, rpc) = isolated();
        context.recorded = Some(json!({"model_request":false}));
        assert!(ConnectionHandler(ordinary).apply(&context).await.is_err());
        assert_eq!(rpc.lock().unwrap().created, 0);
    }
}
