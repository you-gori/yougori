//! Research on a Swarm Mining Grid (`research.source`): a private review of source the person is
//! authorised to test, hosted on this computer or joined with an invitation, by one worker in a
//! sandbox of its own with no internet and a model on this computer.
//!
//! It drives the Swarm Mining product's own closed review, through the same calls its page and the
//! CLI make: `inspectProject` then `hostSource` to host one, `localConnect` or `connect` then
//! `startWorker` for the worker, and `swarm_dispatch` for the worker afterwards. Everything the
//! review promises stays in that product: what was authorised, the offline sandbox, the time
//! budget, the receipts that count as evidence, and whether a finding is sent. A setup chooses
//! settings; it changes none of those rules.
//!
//! * **Hosting** sends the authorisation exactly as the person wrote it in the review they agreed
//!   to, with the instructions and what is reviewed (the source only, or a site or API started in
//!   the sandbox). A live target is never reviewed here. One review is hosted per computer, as the
//!   product allows; one already here is never taken over.
//! * **Joining** records the invitation; the worker connects with it. What the joined project asks
//!   of the worker (its authorisation, scope and commands) is only known once connected, so the
//!   worker waits for the person to read and agree to those exact terms (`accept_terms`, the start
//!   of the terms' digest) before anything starts. A finding for someone else's project is always
//!   read here first.
//! * **The model and the sandbox** the template declares for the worker are made by the worker
//!   itself, inside its own sandboxes. Their handlers keep the record and make nothing
//!   (`made_by_worker`), so nothing is downloaded or started twice.
use super::*;

/// The research grid's profile, as templates write it.
pub(crate) const PROFILE: &str = "swarm_mining_grid";

pub(crate) fn is_research(spec: &Value) -> bool {
    spec["profile"].as_str() == Some(PROFILE)
}

/// Whether the part `id` of `kind` is the model or the sandbox of one of this setup's research
/// workers, given the setup's other parts. The worker makes its own, so this part is a record.
pub(crate) fn made_by_worker<'a>(kind: Kind, id: &str, mut others: impl Iterator<Item = (Kind, &'a Value)>) -> bool {
    let field = match kind {
        Kind::ModelService => "model",
        Kind::Environment => "environment",
        _ => return false,
    };
    others.any(|(other, spec)| other == Kind::WorkerGroup && spec["role"] == "research" && spec[field]["resource"].as_str() == Some(id))
}

/// `made_by_worker`, for a step: among the parts recorded and those this operation is making.
pub(crate) fn part_of_worker(context: &StepContext) -> bool {
    made_by_worker(context.kind, &context.resource, context.peers.values().chain(context.planned.values()).map(|peer| (peer.kind, &peer.spec)))
}

/// Another part of this setup: as recorded, or as this operation is about to make it.
fn part<'a>(context: &'a StepContext, id: &str) -> Option<&'a super::super::handler::Peer> {
    context.peers.get(id).or_else(|| context.planned.get(id))
}

/// The record a research worker's model or sandbox keeps: nothing of its own runs.
pub(crate) fn part_receipt(context: &StepContext) -> Receipt {
    let observed = if context.action == Action::Remove { Observed::Missing } else { Observed::Present };
    let runtime_id = (context.action != Action::Remove).then(|| format!("{}/worker", context.resource));
    Receipt { runtime_id, observed, retained_data: false, cost: Cost::Free, at: now(), adopted: false }
}

pub(crate) fn part_observation(context: &StepContext) -> Observation {
    match &context.runtime_id {
        Some(id) => Observation::Present { runtime_id: id.clone(), observed: Observed::Present, label: None, retained_data: false, cost: Cost::Free },
        None => Observation::Absent,
    }
}

pub(crate) fn part_health() -> HealthReport {
    HealthReport { health: Health::Ready, detail: "Made and run by the research worker, inside its own sandbox.".into() }
}

fn creates(spec: &Value) -> bool {
    spec["mode"].as_str().unwrap_or("create") == "create"
}

/// The research worker of this setup that works on grid `grid`, made already or being made now.
fn worker_on<'a>(context: &'a StepContext, grid: &str) -> Option<&'a super::super::handler::Peer> {
    context.peers.values().chain(context.planned.values()).find(|peer| {
        peer.kind == Kind::WorkerGroup
            && peer.spec["role"] == "research"
            && peer.spec["pool"]["resource"].as_str().and_then(|pool| part(context, pool)).is_some_and(|pool| pool.spec["grid"]["resource"].as_str() == Some(grid))
    })
}

/// The review this computer hosts, as Swarm Mining reports it, if it hosts one.
async fn hosted(grids: &Grids, context: &StepContext) -> Result<Option<Value>, HandlerError> {
    let status = grids.ask(context, "bounty_status", json!({})).await.map_err(|error| failed(context, error))?;
    Ok(Some(status["host"].clone()).filter(|host| host.is_object()))
}

/// What is reviewed, as the product's recipe says it. A source review starts nothing.
fn target(research: &Value) -> Value {
    match research["target"].as_str() {
        Some(kind @ ("web" | "api")) => json!({
            "kind": kind,
            "setupCommand": text(research, "setup_command").unwrap_or_default(),
            "startCommand": text(research, "start_command").unwrap_or_default(),
            "testCommand": text(research, "test_command").unwrap_or_default(),
            "port": research["port"].as_u64().unwrap_or(3000),
            "healthPath": text(research, "health_path").unwrap_or_else(|| "/".into()),
            "installNetwork": research["install_network"].as_bool().unwrap_or(false),
        }),
        _ => json!({"kind": "source"}),
    }
}

/// A password for a review only this computer reaches: nobody types it, and Swarm Mining keeps it.
fn local_password() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

// ----- The grid: a review hosted here, or one joined -----

pub(crate) fn validate_grid(spec: &Value) -> Result<(), HandlerError> {
    if creates(spec) {
        if text(spec, "name").is_none() {
            return Err(invalid("A review needs its project's name."));
        }
        let research = &spec["research"];
        if text(research, "instructions").is_none() || text(research, "authorization").is_none() {
            return Err(invalid("A review needs what the agents look into and what they are allowed to test: research: {instructions, authorization}."));
        }
        match research["target"].as_str().unwrap_or("source") {
            "source" => {
                if text(research, "start_command").is_some() || !research["port"].is_null() {
                    return Err(invalid("A source review starts nothing; leave out start_command and port."));
                }
            }
            "web" | "api" => {
                if text(research, "start_command").is_none() {
                    return Err(invalid("A site or API reviewed in the sandbox needs how it is started: research.start_command."));
                }
                if !research["port"].as_u64().is_some_and(|port| (1024..=65535).contains(&port)) {
                    return Err(invalid("A site or API reviewed in the sandbox needs the port it listens on, 1024 or above: research.port."));
                }
            }
            _ => return Err(refused("A review is of source, or of a site or API started inside its own sandbox. A live target is never reviewed here.")),
        }
        if text(spec, "address").is_some() && spec["secrets"]["join_password"].as_str().unwrap_or_default().is_empty() {
            return Err(invalid("A review people join on your network needs a password for them, given privately."));
        }
        return Ok(());
    }
    if spec["mode"].as_str() != Some("join") {
        return Err(refused("Using another setup's review is done by joining it."));
    }
    if spec["secrets"]["invitation"].as_str().unwrap_or_default().is_empty() || spec["secrets"]["join_password"].as_str().unwrap_or_default().is_empty() {
        return Err(invalid("Joining a review needs its invitation and password, given privately."));
    }
    Ok(())
}

/// A hosted review reviews the folder its worker is given; a joined one, the project's own source.
pub(crate) fn review_grid(id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
    let pools: Vec<&str> = others.iter().filter(|(_, (kind, other))| *kind == Kind::ComputePool && other["grid"]["resource"].as_str() == Some(id)).map(|(pool, _)| pool.as_str()).collect();
    let workers: Vec<&Value> = others.values().filter(|(kind, other)| *kind == Kind::WorkerGroup && other["pool"]["resource"].as_str().is_some_and(|pool| pools.contains(&pool))).map(|(_, other)| other).collect();
    if workers.len() != 1 {
        return Err(refused("A review on this computer has exactly one research worker."));
    }
    if creates(spec) && workers[0]["source"]["binding"].as_str().is_none() {
        return Err(refused("A review hosted here reviews a folder its worker is given: source: {binding: ID}."));
    }
    Ok(())
}

pub(crate) fn notes_grid(spec: &Value, action: Action) -> Vec<String> {
    let name = text(spec, "name").unwrap_or_else(|| "the project".into());
    match action {
        Action::Create if creates(spec) => {
            let research = &spec["research"];
            let what = match research["target"].as_str() {
                Some("web") => "its source, and the website it starts inside the worker's sandbox",
                Some("api") => "its source, and the API it starts inside the worker's sandbox",
                _ => "its source only; nothing is started",
            };
            let reach = match text(spec, "address") {
                Some(address) => format!("People on your network join it at {address} with the invitation and the password you chose."),
                None => "Only this computer takes part; nothing is reachable from your network.".into(),
            };
            vec![
                format!("This computer hosts a private review of {name}: {what}. The agents may test only what you authorised: \"{}\". Agreeing to this review is that authorisation.", text(research, "authorization").unwrap_or_default()),
                format!("{reach} This computer runs one review at a time; while it is turned off, nobody can work on it."),
            ]
        }
        Action::Create => vec!["This computer joins a review someone else hosts. Before its worker starts, you read what that project asks of it and agree to it; nothing starts until you do.".into()],
        Action::Remove if creates(spec) => vec![format!("Removing deletes the review of {name} that this computer hosts, with what its workers found. Read and send what you want to keep first.")],
        Action::Remove => vec!["This computer stops working on the review it joined. The review itself, and what was sent to it, stay with its host.".into()],
        _ => Vec::new(),
    }
}

pub(crate) async fn apply_grid(grids: &Grids, context: &StepContext) -> Result<Receipt, HandlerError> {
    if context.action != Action::Create {
        return Err(refused("A review is changed from Swarm Mining for now."));
    }
    let spec = &context.spec;
    if !creates(spec) {
        let invitation = secret(context, "invitation")?;
        let invite = yougori_grid::invite::decode_bounty(invitation.trim()).map_err(|_| invalid("That isn't a Swarm Mining invitation. Paste the one you were given, exactly."))?;
        secret(context, "join_password")?;
        // The worker connects with these; this computer is not a member until it does.
        return Ok(Receipt { runtime_id: Some(format!("joined:{}", invite.fingerprint)), observed: Observed::Present, retained_data: false, cost: Cost::Free, at: now(), adopted: false });
    }
    if let Some(host) = hosted(grids, context).await? {
        if made_by_step(context, &host["createdAt"]) {
            return Ok(receipt(host["id"].as_str().map(str::to_owned), Observed::Running, true));
        }
        return Err(taken("This computer already hosts a Swarm Mining review, and hosts one at a time. Delete that one in Swarm Mining first, or review its project from there.".into()));
    }
    let folder = worker_on(context, &context.resource)
        .and_then(|worker| worker.spec["source_folder"].as_str().map(str::to_owned))
        .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "Choose the folder to review when you set this up."))?;
    let inspected = grids
        .ask(context, "bounty_dispatch", json!({"request": {"action": "inspectProject", "path": folder}}))
        .await
        .map_err(|error| failed(context, error))?;
    let import = inspected["importId"].as_str().ok_or_else(|| HandlerError::new(Outcome::Failed, "grid_refused", "Swarm Mining didn't take the folder in."))?;
    let name = text(spec, "name").unwrap_or_default();
    let research = &spec["research"];
    let (address, password) = match text(spec, "address") {
        Some(address) => (address, secret(context, "join_password")?),
        None => ("127.0.0.1".to_owned(), local_password()),
    };
    let request = json!({
        "action": "hostSource",
        // What the person agreed to in this setup's review: the authorisation shown there, as written.
        "confirmed": true,
        "importId": import,
        "title": name,
        "instructions": text(research, "instructions").unwrap_or_default(),
        "authorization": text(research, "authorization").unwrap_or_default(),
        "target": target(research),
        "name": name,
        "address": address,
        "password": password,
    });
    let host = grids.ask(context, "bounty_dispatch", json!({"request": request})).await.map_err(|error| failed(context, error))?;
    Ok(receipt(host["id"].as_str().map(str::to_owned), Observed::Running, true))
}

pub(crate) async fn observe_grid(grids: &Grids, context: &StepContext) -> Result<Observation, HandlerError> {
    let Some(id) = context.runtime_id.clone() else { return Ok(Observation::Absent) };
    if !creates(&context.spec) {
        return Ok(Observation::Present { runtime_id: id, observed: Observed::Present, label: None, retained_data: false, cost: Cost::Free });
    }
    let host = match hosted(grids, context).await {
        Ok(host) => host,
        Err(error) => return Ok(Observation::Unknown { reason: error.message }),
    };
    Ok(match host.filter(|host| host["id"].as_str() == Some(id.as_str())) {
        Some(_) => Observation::Present { runtime_id: id, observed: Observed::Running, label: None, retained_data: true, cost: Cost::Free },
        None => Observation::Absent,
    })
}

/// Only the review this setup hosts is deleted; one hosted since by someone else is left alone.
pub(crate) async fn remove_grid(grids: &Grids, context: &StepContext) -> Result<Receipt, HandlerError> {
    if creates(&context.spec) {
        let ours = context.runtime_id.as_deref();
        if hosted(grids, context).await?.is_some_and(|host| ours.is_some() && host["id"].as_str() == ours) {
            grids.ask(context, "bounty_delete", json!({})).await.map_err(|error| failed(context, error))?;
        }
    }
    Ok(receipt(None, Observed::Missing, false))
}

pub(crate) async fn health_grid(grids: &Grids, context: &StepContext) -> Result<HealthReport, HandlerError> {
    if !creates(&context.spec) {
        return Ok(HealthReport { health: Health::Ready, detail: "Joined; its worker works on it from this computer.".into() });
    }
    let host = hosted(grids, context).await?.filter(|host| context.runtime_id.as_deref().is_some() && host["id"].as_str() == context.runtime_id.as_deref());
    Ok(match host {
        Some(host) => HealthReport {
            health: Health::Ready,
            detail: format!("Hosted on this computer: {} of {} computers working on it.", host["computers"]["working"].as_u64().unwrap_or(0), host["computers"]["total"].as_u64().unwrap_or(0)),
        },
        None => HealthReport { health: Health::Failed, detail: "This computer doesn't host the review anymore.".into() },
    })
}

pub(crate) async fn outputs_grid(grids: &Grids, context: &StepContext) -> Result<BTreeMap<String, String>, HandlerError> {
    let mut outputs = BTreeMap::new();
    if !creates(&context.spec) {
        return Ok(outputs);
    }
    let Some(host) = hosted(grids, context).await?.filter(|host| context.runtime_id.as_deref().is_some() && host["id"].as_str() == context.runtime_id.as_deref()) else { return Ok(outputs) };
    if let Some(name) = text(&host, "name") {
        outputs.insert("name".into(), name);
    }
    // Only a review people reach on the network has someone to invite.
    if host["address"].as_str().is_some_and(|address| address != "127.0.0.1") {
        if let Some(invite) = text(&host, "invite") {
            outputs.insert("invitation".into(), invite);
        }
        if let Some(reach) = reach(&host) {
            outputs.insert("join_address".into(), reach);
        }
    }
    Ok(outputs)
}

// ----- The worker -----

/// One research worker on a Swarm Mining Grid: the only worker group a setup makes today.
pub(crate) struct WorkerGroupHandler(pub(crate) Grids);

impl WorkerGroupHandler {
    fn grid<'a>(context: &'a StepContext) -> Option<&'a super::super::handler::Peer> {
        let pool = context.spec["pool"]["resource"].as_str().and_then(|id| part(context, id))?;
        pool.spec["grid"]["resource"].as_str().and_then(|id| part(context, id))
    }

    fn minutes(spec: &Value) -> u64 {
        spec["budget"]["time_minutes"].as_u64().unwrap_or(60).clamp(1, 1440)
    }

    /// What the worker is prepared with: its model and its sandbox's share of this computer.
    fn worker(context: &StepContext) -> Value {
        let spec = &context.spec;
        let model = spec["model"]["resource"].as_str().and_then(|id| part(context, id)).and_then(|peer| text(&peer.spec, "model")).unwrap_or_default();
        let model = if model.starts_with("hf.co/") { model } else { format!("hf.co/{model}") };
        let sandbox = spec["environment"]["resource"].as_str().and_then(|id| part(context, id)).map(|peer| peer.spec.clone()).unwrap_or(Value::Null);
        let number = |limit: &str, fallback: &str, least: f64| spec["limits"][limit].as_f64().or_else(|| sandbox[fallback].as_f64()).unwrap_or(least).max(least);
        let disk = number("disk_gb", "storage", 20.0);
        json!({
            "model": model,
            "name": text(spec, "name").unwrap_or_else(|| "Review worker".into()),
            "resources": {"cpu": number("cpu", "cpu", 4.0).round() as u64, "memoryGb": number("memory_gb", "memory", 8.0).round() as u64, "storageGb": disk.round() as u64},
            "workspaceQuotaGb": (disk.round() as u64).clamp(4, 1024),
        })
    }

    /// What a joined project asks of the worker, in words, and how to agree to exactly that.
    fn terms(policy: &Value) -> String {
        let digest = policy["termsDigest"].as_str().unwrap_or_default();
        let target = match policy["target"]["kind"].as_str() {
            Some("web") => "its source, and a website started inside the worker's own sandbox",
            Some("api") => "its source, and an API started inside the worker's own sandbox",
            _ => "its source only, in the worker's own offline sandbox",
        };
        let mut said = format!(
            "Read what the review you join asks before its worker starts. Project: {}. It reviews {target}. What may be tested: \"{}\". What to look into: \"{}\".",
            text(policy, "title").unwrap_or_default(),
            text(policy, "authorization").unwrap_or_default(),
            text(policy, "objective").unwrap_or_default()
        );
        if let Some(command) = text(policy, "setupCommand") {
            let network = if policy["target"]["installNetwork"] == true { "with the internet while it runs" } else { "without the internet" };
            said.push_str(&format!(" It is prepared with: {command}, {network}."));
        }
        said.push_str(&format!(" To agree to exactly these terms, choose Agree to these terms, or continue this change with accept_terms set to {}.", &digest[..digest.len().min(12)]));
        said
    }

    async fn discard(&self, context: &StepContext, ticket: &str) {
        let _ = self.0.ask(context, "bounty_dispatch", json!({"request": {"action": "discardConnection", "ticket": ticket}})).await;
    }

    async fn view(&self, context: &StepContext, worker: &str) -> Result<Option<Value>, String> {
        match self.0.ask(context, "swarm_dispatch", json!({"request": {"action": "status", "workerId": worker}})).await {
            Ok(answer) => Ok(Some(answer["worker"].clone()).filter(Value::is_object)),
            Err(error) if error.contains("No worker") || error.contains("not found") => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl ResourceHandler for WorkerGroupHandler {
    fn kind(&self) -> Kind {
        Kind::WorkerGroup
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if spec["role"].as_str() != Some("research") {
            return Err(refused("A setup makes research workers on a Swarm Mining Grid; other worker groups aren't set up from a template yet."));
        }
        if spec["count"].as_u64().unwrap_or(1) != 1 || spec["max"].as_u64().is_some_and(|max| max > 1) {
            return Err(refused("A review on this computer has one worker; another computer adds its own by joining."));
        }
        if spec["model"]["resource"].as_str().is_none() || spec["environment"]["resource"].as_str().is_none() {
            return Err(invalid("A research worker names the model it thinks with and its sandbox: model: {resource: ID}, environment: {resource: ID}."));
        }
        if spec["report_policy"].as_str().is_some_and(|policy| !matches!(policy, "review" | "automatic")) {
            return Err(invalid("report_policy is review or automatic."));
        }
        Ok(())
    }

    fn review(&self, _id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        let pool = spec["pool"]["resource"].as_str().and_then(|id| others.get(id)).filter(|(kind, _)| *kind == Kind::ComputePool);
        let Some((profile, mode)) = pool.and_then(|(_, pool)| declared_grid(&pool["grid"], others)) else {
            return Err(refused("A research worker works on a Swarm Mining Grid this setup hosts or joins."));
        };
        if profile != PROFILE {
            return Err(refused("Research runs on a Swarm Mining Grid only, never on another grid's computers."));
        }
        let model = spec["model"]["resource"].as_str().and_then(|id| others.get(id));
        match model {
            Some((Kind::ModelService, model)) if text(model, "model").is_some_and(|name| !name.starts_with("yg/") && name.trim_start_matches("hf.co/").contains('/')) && model["compute"].is_null() => {}
            Some((Kind::ModelService, _)) => return Err(refused("A research worker thinks with a model from Hugging Face in GGUF form (hf.co/OWNER/MODEL), on this computer.")),
            _ => return Err(invalid("model: names a model service of this setup.")),
        }
        match spec["environment"]["resource"].as_str().and_then(|id| others.get(id)) {
            Some((Kind::Environment, sandbox)) if sandbox["internet"] == false => {}
            Some((Kind::Environment, _)) => return Err(refused("A research worker's sandbox has no internet: say internet: false.")),
            _ => return Err(invalid("environment: names a sandbox of this setup.")),
        }
        if mode == "join" {
            if spec["source"].is_object() {
                return Err(refused("A worker on a review you join reviews that project's source, never a folder of yours."));
            }
            if spec["report_policy"].as_str() == Some("automatic") {
                return Err(refused("A finding for a project you join is read here first; only your own project's findings are sent automatically."));
            }
        }
        Ok(())
    }

    fn plan(&self, current: Option<&Resource>, _spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        fixed_once_made(current, spec_digest, "A research worker is changed by removing it and adding it again, or from Swarm Mining.")
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let name = text(spec, "name").unwrap_or_else(|| resource.to_owned());
        match action {
            Action::Create => {
                let folder = spec["source_folder"].as_str().map(|folder| format!(" a copy of {folder}")).unwrap_or_else(|| " the project's source".into());
                let findings = match spec["report_policy"].as_str() {
                    Some("automatic") => "Each finding is sent to the project as it is made.",
                    _ => "Each finding waits here for you to read it; nothing is sent until you send it.",
                };
                vec![format!(
                    "The worker {name} reviews{folder} in a sandbox of its own with no internet, thinking with its own copy of the model on this computer. It stops by itself after {} minutes. {findings}",
                    Self::minutes(spec)
                )]
            }
            Action::Remove => vec![format!("Removing deletes the worker {name} and its sandboxes from this computer.")],
            _ => Vec::new(),
        }
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            let Some(id) = context.runtime_id.clone() else { return Ok(Observation::Absent) };
            Ok(match self.view(context, &id).await {
                Ok(Some(worker)) => {
                    let stopped = matches!(worker["state"].as_str(), Some("paused" | "stopped"));
                    Observation::Present { runtime_id: id, observed: if stopped { Observed::Stopped } else { Observed::Running }, label: None, retained_data: true, cost: Cost::Free }
                }
                Ok(None) => Observation::Absent,
                Err(error) => Observation::Unknown { reason: error },
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let started = |id: String| Receipt { runtime_id: Some(id), observed: Observed::Running, retained_data: true, cost: Cost::Free, at: now(), adopted: false };
            if context.action == Action::Start {
                if let Some(id) = context.runtime_id.clone() {
                    self.0
                        .ask(context, "swarm_dispatch", json!({"request": {"action": "resume", "workerId": id, "budgetMinutes": Self::minutes(&context.spec)}}))
                        .await
                        .map_err(|error| failed(context, error))?;
                    return Ok(started(id));
                }
            }
            if context.action != Action::Create {
                return Err(refused("A research worker is changed by removing it and adding it again, or from Swarm Mining."));
            }
            let grid = Self::grid(context).ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This worker's review isn't part of the setup yet."))?;
            let joined = grid.spec["mode"].as_str() == Some("join");
            let connected = if joined {
                let binding = |name: &str| grid.spec["secrets"][name].as_str().and_then(|binding| context.secret(binding)).map(str::to_owned);
                let (Some(invite), Some(password)) = (binding("invitation"), binding("join_password")) else {
                    return Err(HandlerError::new(Outcome::NeedsInput, "secret_needed", "The worker needs the review's invitation and password again to connect."));
                };
                let name = text(&context.spec, "name").unwrap_or_else(|| "Review worker".into());
                self.0.ask(context, "bounty_dispatch", json!({"request": {"action": "connect", "invite": invite.trim(), "password": password, "name": name}})).await
            } else {
                self.0.ask(context, "bounty_dispatch", json!({"request": {"action": "localConnect"}})).await
            }
            .map_err(|error| failed(context, error))?;
            let ticket = connected["ticket"].as_str().unwrap_or_default().to_owned();
            let policy = &connected["policy"];
            // Never a live service: this capability reviews source, and what it starts itself.
            if policy["scopeMode"].as_str() == Some("external_target") || policy["target"]["kind"].as_str() == Some("url") {
                self.discard(context, &ticket).await;
                return Err(refused("That review tests a live service. A setup only takes part in reviews of source, and of what it starts inside its own sandbox."));
            }
            let digest = policy["termsDigest"].as_str().unwrap_or_default().to_owned();
            if joined {
                let agreed = context.secret("apply.accept_terms").map(str::trim).filter(|agreed| agreed.len() >= 12 && digest.starts_with(agreed));
                if agreed.is_none() {
                    self.discard(context, &ticket).await;
                    return Err(HandlerError::new(Outcome::NeedsInput, "terms_to_accept", Self::terms(policy)));
                }
            }
            let request = json!({
                "action": "startWorker",
                // Agreed in this setup's review for a review it hosts, and to these exact terms for one it joined.
                "confirmed": true,
                "ticket": ticket,
                "termsDigest": digest,
                "budgetMinutes": Self::minutes(&context.spec),
                "reportPolicy": if joined { "review" } else { context.spec["report_policy"].as_str().unwrap_or("review") },
                "worker": Self::worker(context),
            });
            let answer = self.0.ask(context, "bounty_dispatch", json!({"request": request})).await.map_err(|error| failed(context, error))?;
            let id = answer["worker"]["id"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "Swarm Mining didn't say which worker it made. Checking before anything else runs."))?;
            Ok(started(id.to_owned()))
        })
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let Some(id) = context.runtime_id.clone() else { return Ok(receipt(None, Observed::Missing, false)) };
            self.0.ask(context, "swarm_dispatch", json!({"request": {"action": "pause", "workerId": id}})).await.map_err(|error| failed(context, error))?;
            Ok(Receipt { runtime_id: Some(id), observed: Observed::Stopped, retained_data: true, cost: Cost::Free, at: now(), adopted: false })
        })
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if let Some(id) = context.runtime_id.clone() {
                match self.0.ask(context, "swarm_dispatch", json!({"request": {"action": "delete", "workerId": id}})).await {
                    Ok(_) => {}
                    Err(error) if error.contains("No worker") || error.contains("not found") => {}
                    Err(error) => return Err(failed(context, error)),
                }
            }
            Ok(receipt(None, Observed::Missing, false))
        })
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            let Some(id) = context.runtime_id.clone() else { return Ok(HealthReport { health: Health::Unknown, detail: "Not made yet.".into() }) };
            let worker = self.view(context, &id).await.map_err(|error| HandlerError::new(Outcome::Unknown, "outcome_unknown", error))?;
            Ok(match worker {
                None => HealthReport { health: Health::Failed, detail: "The worker isn't on this computer anymore.".into() },
                Some(worker) if worker["error"].as_str().is_some_and(|error| !error.is_empty()) => HealthReport { health: Health::Failed, detail: plain(worker["error"].as_str().unwrap_or_default()) },
                Some(worker) => match worker["state"].as_str().unwrap_or_default() {
                    "awaiting_review" => HealthReport { health: Health::Degraded, detail: "A finding waits for you to read it.".into() },
                    "paused" | "stopped" => HealthReport { health: Health::Unknown, detail: "Stopped. Start the setup to let it work again.".into() },
                    "preparing" | "preparing_bounty" => HealthReport { health: Health::Starting, detail: "Preparing its sandbox and model.".into() },
                    state => HealthReport { health: Health::Ready, detail: format!("Working ({}).", state.replace('_', " ")) },
                },
            })
        })
    }

    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let mut outputs = BTreeMap::new();
            if let Some(name) = text(&context.spec, "name") {
                outputs.insert("name".into(), name);
            }
            Ok(outputs)
        })
    }

    /// A start whose outcome is unknown is looked for by its worker before anything runs again.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            Ok(match context.action {
                Action::Create => Recovery::NotApplied,
                _ => super::super::handler::recovery_from(context, self.observe(context).await?),
            })
        })
    }
}
