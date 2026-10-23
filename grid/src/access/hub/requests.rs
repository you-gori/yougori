//! An agent's requests: sent at once when a rule allows it (within its hourly limit), waiting for
//! an approver when a rule says so or the limit is spent, and refused otherwise. The answer waits
//! here until the person's computer collects it, once.
use super::{admin, change_record, find_credential, lock, new_id, note, now, text, Live, Refusal, Shared, WAIT};
use crate::access::{
    activity::Entry,
    forward::{self, Outgoing},
    mint,
    policy::{self, Decision, Person, Rule, Verdict, Who},
};
use base64::Engine;
use hyper::StatusCode;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

/// A finished request's answer waits this long to be collected.
const KEEP: i64 = 10 * 60;
/// An allowed request answers at once if it finishes within this; otherwise the caller asks again.
const QUICK: Duration = Duration::from_secs(8);
const MAX_OPEN_PER_PERSON: usize = 16;
const MAX_REQUESTS: usize = 512;
/// A request carrying the largest body, base64-encoded, with room for the rest.
pub(super) const LARGE: usize = forward::MAX_BODY / 3 * 4 + 64 * 1024;

pub(super) enum Work {
    Use(Outgoing),
    Reveal { reason: String },
}

pub(super) enum State {
    Waiting,
    Running,
    Done(Value),
    Denied(String),
    Failed(String),
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::Waiting => "waiting",
            State::Running => "running",
            State::Done(_) => "done",
            State::Denied(_) => "denied",
            State::Failed(_) => "failed",
        }
    }
    fn finished(&self) -> bool {
        matches!(self, State::Done(_) | State::Denied(_) | State::Failed(_))
    }
}

/// A request an agent made, until its answer is collected.
pub(super) struct Pending {
    id: String,
    person: String,
    username: String,
    agent: String,
    computer: String,
    credential: String,
    credential_name: String,
    work: Work,
    /// The asking rule's path, which an approval for some hours widens to.
    ask_path: String,
    /// Why it waits: a rule says so, or an allow rule's hourly limit is spent.
    why: String,
    created_at: i64,
    deadline: i64,
    finished_at: Option<i64>,
    decided_by: Option<String>,
    state: State,
}

impl Pending {
    pub(super) fn waiting(&self) -> bool {
        matches!(self.state, State::Waiting)
    }
    fn entry(&self, at: i64, action: &str, outcome: String) -> Entry {
        Entry { at, person: self.username.clone(), agent: self.agent.clone(), computer: self.computer.clone(), action: action.into(), credential: self.credential_name.clone(), target: self.target(), outcome, ..Entry::default() }
    }
    fn target(&self) -> String {
        match &self.work {
            Work::Use(outgoing) => format!("{} {}", outgoing.method, outgoing.target.shown()),
            Work::Reveal { .. } => String::new(),
        }
    }
    fn summary(&self) -> Value {
        let mut summary = json!({
            "id": self.id, "person": self.username, "agent": self.agent, "computer": self.computer, "credential": self.credential_name, "credentialId": self.credential,
            "createdAt": self.created_at, "expiresAt": self.deadline, "state": self.state.name(), "decidedBy": self.decided_by, "why": self.why,
        });
        match &self.work {
            Work::Use(outgoing) => {
                summary["kind"] = json!("use");
                summary["method"] = json!(outgoing.method);
                summary["url"] = json!(outgoing.target.shown());
                summary["hasQuery"] = json!(outgoing.target.query.is_some());
                summary["bodyBytes"] = json!(outgoing.body.len());
                // An approver sees what will be sent, up to a few kilobytes of text.
                if !outgoing.body.is_empty() {
                    let shown = &outgoing.body[..outgoing.body.len().min(4096)];
                    summary["bodyPreview"] = json!(String::from_utf8_lossy(shown));
                }
            }
            Work::Reveal { reason } => {
                summary["kind"] = json!("reveal");
                summary["reason"] = json!(reason);
            }
        }
        summary
    }
}

/// Requests waiting for an approver, oldest first.
pub(super) fn waiting(shared: &Shared) -> Vec<Value> {
    let live = lock(&shared.live);
    let mut waiting: Vec<&Pending> = live.requests.values().filter(|request| request.waiting()).collect();
    waiting.sort_by_key(|request| request.created_at);
    waiting.iter().map(|request| request.summary()).collect()
}

/// One person's requests, newest first.
pub(super) fn mine(shared: &Shared, person: &str) -> Vec<Value> {
    let live = lock(&shared.live);
    let mut mine: Vec<&Pending> = live.requests.values().filter(|request| request.person == person).collect();
    mine.sort_by_key(|request| std::cmp::Reverse(request.created_at));
    mine.iter().map(|request| request.summary()).collect()
}

/// Waiting requests past their deadline fail; collected-or-not answers go after a while.
pub(super) fn expire(live: &mut Live, at: i64) -> Vec<Entry> {
    let mut expired = Vec::new();
    for request in live.requests.values_mut() {
        if request.waiting() && request.deadline <= at {
            request.state = State::Failed(format!("No approver decided within {} minutes", WAIT / 60));
            request.finished_at = Some(at);
            expired.push(request.entry(at, match request.work { Work::Use(_) => "use", Work::Reveal { .. } => "reveal" }, "expired without a decision".into()));
        }
    }
    live.requests.retain(|_, request| request.finished_at.is_none_or(|finished| finished + KEEP > at));
    expired
}

/// Requests of people who are gone end; those for credentials that went fail.
pub(super) fn forget(live: &mut Live, people: &[String], credentials: &[String], at: i64) {
    live.requests.retain(|_, request| people.contains(&request.person));
    for request in live.requests.values_mut() {
        if !credentials.contains(&request.credential) && !request.state.finished() {
            request.state = State::Failed("The credential was removed".into());
            request.finished_at = Some(at);
        }
    }
}

fn add(shared: &Shared, pending: Pending) -> Result<(), Refusal> {
    let mut live = lock(&shared.live);
    let open = live.requests.values().filter(|request| request.person == pending.person && !request.state.finished()).count();
    if open >= MAX_OPEN_PER_PERSON {
        return Err(Refusal(StatusCode::TOO_MANY_REQUESTS, "busy", format!("You already have {MAX_OPEN_PER_PERSON} requests waiting or running; collect or wait for them first")));
    }
    if live.requests.len() >= MAX_REQUESTS {
        live.requests.retain(|_, request| !request.state.finished());
        if live.requests.len() >= MAX_REQUESTS {
            return Err(Refusal(StatusCode::SERVICE_UNAVAILABLE, "busy", "The Access Grid is handling too many requests; try again shortly".into()));
        }
    }
    live.requests.insert(pending.id.clone(), pending);
    Ok(())
}

/// Counts one use against the first limited allow rule with room left this hour; `None` when
/// every one of them is spent.
fn within_limits(shared: &Shared, person: &str, limits: &[policy::Limit], at: i64) -> Option<()> {
    if limits.is_empty() {
        return Some(());
    }
    let mut live = lock(&shared.live);
    for limit in limits {
        let times = live.usage.entry((limit.rule.clone(), person.to_owned())).or_default();
        while times.front().is_some_and(|time| *time <= at - 3600) {
            times.pop_front();
        }
        if times.len() < limit.per_hour as usize {
            times.push_back(at);
            return Some(());
        }
    }
    None
}

/// An agent's request to send something with a credential, from a signed-in person.
pub(super) async fn use_credential(shared: &Arc<Shared>, person: &Person, body: Value) -> Result<Value, Refusal> {
    let method = text(&body, "method").unwrap_or("GET").trim().to_ascii_uppercase();
    if !policy::METHODS.contains(&method.as_str()) {
        return Err(Refusal::bad(format!("{method} is not an HTTP method Access Grid sends; use {}", policy::METHODS.join(", "))));
    }
    let target = forward::target(text(&body, "url").unwrap_or_default())?;
    let payload = match (text(&body, "body"), text(&body, "bodyBase64")) {
        (Some(_), Some(_)) => return Err(Refusal::bad("Send body or bodyBase64, not both")),
        (Some(text), None) => text.as_bytes().to_vec(),
        (None, Some(encoded)) => base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| Refusal::bad("bodyBase64 is not base64"))?,
        (None, None) => Vec::new(),
    };
    if payload.len() > forward::MAX_BODY {
        return Err(Refusal::bad(format!("A request body is at most {} MB", forward::MAX_BODY / (1024 * 1024))));
    }
    let agent = note(text(&body, "agent"), 120);
    let computer = note(text(&body, "computer"), 64);
    let (credential, verdict) = {
        let record = lock(&shared.record);
        let credential = find_credential(&record, text(&body, "credential").unwrap_or_default()).cloned().ok_or_else(|| Refusal::missing("No such company credential; list_company_access shows the ones you may use"))?;
        let verdict = if credential.destinations.iter().any(|place| forward::within(&target, place)) {
            policy::evaluate(&record.rules, person, &credential, &method, &target.path, now())
        } else {
            Verdict::Refused(format!("{} may only be sent to {}", credential.name, credential.destinations.join(", ")))
        };
        (credential, verdict)
    };
    let headers = match body.get("headers") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(headers)) => forward::agent_headers(headers, &forward::owned_headers(credential.kind, &credential.field))?,
        Some(_) => return Err(Refusal::bad("headers must be an object of header names and values")),
    };
    let outgoing = Outgoing { method: method.clone(), target: target.clone(), headers, body: payload };
    let entry = |outcome: String| Entry { at: now(), person: person.username.clone(), agent: agent.clone(), computer: computer.clone(), action: "use".into(), credential: credential.name.clone(), target: format!("{method} {}", target.shown()), outcome, ..Entry::default() };
    let at = now();
    let (ask_path, waiting, why) = match verdict {
        Verdict::Refused(reason) => {
            shared.log(entry(format!("refused: {reason}")));
            return Err(Refusal::forbidden(reason));
        }
        Verdict::Allow { limits } => match within_limits(shared, &person.id, &limits, at) {
            Some(()) => (String::new(), false, String::new()),
            None => (limits.first().map(|limit| limit.path.clone()).unwrap_or_default(), true, format!("past the hourly limit of {} uses", limits.iter().map(|limit| limit.per_hour).max().unwrap_or_default())),
        },
        Verdict::Ask { path } => (path, true, "a rule says an approver decides".into()),
    };
    let id = new_id("req");
    add(shared, Pending {
        id: id.clone(),
        person: person.id.clone(),
        username: person.username.clone(),
        agent: agent.clone(),
        computer: computer.clone(),
        credential: credential.id.clone(),
        credential_name: credential.name.clone(),
        work: Work::Use(outgoing),
        ask_path,
        why: why.clone(),
        created_at: at,
        deadline: at + WAIT,
        finished_at: None,
        decided_by: None,
        state: if waiting { State::Waiting } else { State::Running },
    })?;
    if waiting {
        shared.log(entry(format!("waiting for an approver: {why}")));
        (shared.events)("access.request.waiting", json!({"person": person.username, "credential": credential.name}));
        return Ok(json!({"state": "waiting", "id": id, "expiresAt": at + WAIT, "message": format!("An approver decides this use of {} ({why}). Check back with the request ID.", credential.name)}));
    }
    let (finished, done) = tokio::sync::oneshot::channel();
    tokio::spawn(run(shared.clone(), id.clone(), Some(finished)));
    if tokio::time::timeout(QUICK, done).await.is_ok() {
        return collect(shared, person, &id);
    }
    Ok(json!({"state": "running", "id": id, "message": "Still waiting for the service to answer. Check back with the request ID."}))
}

/// An agent asks to see a credential's value. An approver always decides; a minting credential
/// hands out a short-lived token, never its secret.
pub(super) fn reveal(shared: &Arc<Shared>, person: &Person, body: Value) -> Result<Value, Refusal> {
    let agent = note(text(&body, "agent"), 120);
    let computer = note(text(&body, "computer"), 64);
    let reason = note(text(&body, "reason"), 300);
    let credential = {
        let record = lock(&shared.record);
        let credential = find_credential(&record, text(&body, "credential").unwrap_or_default()).cloned().ok_or_else(|| Refusal::missing("No such company credential"))?;
        if let Err(reason) = policy::may_reveal(&record.rules, person, &credential, now()) {
            drop(record);
            shared.log(Entry { at: now(), person: person.username.clone(), agent, computer, action: "reveal".into(), credential: credential.name.clone(), outcome: format!("refused: {reason}"), ..Entry::default() });
            return Err(Refusal::forbidden(reason));
        }
        credential
    };
    let at = now();
    let id = new_id("req");
    add(shared, Pending {
        id: id.clone(),
        person: person.id.clone(),
        username: person.username.clone(),
        agent: agent.clone(),
        computer: computer.clone(),
        credential: credential.id.clone(),
        credential_name: credential.name.clone(),
        work: Work::Reveal { reason },
        ask_path: String::new(),
        why: if credential.kind.mints() { "to receive a short-lived token".into() } else { "to see the value itself".into() },
        created_at: at,
        deadline: at + WAIT,
        finished_at: None,
        decided_by: None,
        state: State::Waiting,
    })?;
    shared.log(Entry { at, person: person.username.clone(), agent, computer, action: "reveal".into(), credential: credential.name.clone(), outcome: "waiting for an approver".into(), ..Entry::default() });
    (shared.events)("access.request.waiting", json!({"person": person.username, "credential": credential.name}));
    Ok(json!({"state": "waiting", "id": id, "expiresAt": at + WAIT, "message": format!("An approver decides whether you may have {}. Check back with the request ID.", credential.name)}))
}

/// An approver's answer to a waiting request: approve once, approve for some hours (a rule for
/// that person, method and path that lapses by itself), or deny.
pub(super) fn decide(shared: &Arc<Shared>, actor: &Person, body: &Value) -> Result<Value, Refusal> {
    let id = text(body, "request").unwrap_or_default().to_owned();
    let approve = body.get("approve").and_then(Value::as_bool).ok_or_else(|| Refusal::bad("Say approve true or false"))?;
    let until = match body.get("hours") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_f64().filter(|hours| *hours > 0.0 && *hours <= 24.0).map(|hours| now() + (hours * 3600.0) as i64).ok_or_else(|| Refusal::bad("An approval lasts up to 24 hours"))?),
    };
    let reason = note(text(body, "reason"), 200);
    let at = now();
    // Checked and decided under one lock, so two approvers cannot both decide.
    let (log, extra_rule, reveal, message) = {
        let record = lock(&shared.record);
        let mut live = lock(&shared.live);
        let request = live.requests.get_mut(&id).ok_or_else(|| Refusal::missing("That request is gone: it was decided, collected or it expired"))?;
        if !request.waiting() || request.deadline <= at {
            return Err(Refusal(StatusCode::CONFLICT, "decided", "That request was already decided or it expired".into()));
        }
        if !admin::may_decide(&record, actor, &request.person) {
            return Err(Refusal::forbidden(if actor.permission.decides() { "Someone else approves your own requests" } else { "Only approvers and admins decide requests" }));
        }
        request.decided_by = Some(actor.username.clone());
        if !approve {
            let log = request.entry(at, "deny", format!("denied by {}{}", actor.username, if reason.is_empty() { String::new() } else { format!(": {reason}") }));
            request.state = State::Denied(if reason.is_empty() { format!("{} denied it", actor.username) } else { format!("{} denied it: {reason}", actor.username) });
            request.finished_at = Some(at);
            drop(live);
            drop(record);
            shared.log(log);
            return Ok(json!({"request": id, "state": "denied", "message": "Denied"}));
        }
        let mut message = "Approved once".to_owned();
        let mut extra_rule = None;
        if let (Some(until), Work::Use(outgoing)) = (until, &request.work) {
            extra_rule = Some(Rule {
                id: new_id("rule"),
                credential: request.credential.clone(),
                who: Who::Person(request.person.clone()),
                methods: vec![outgoing.method.clone()],
                path: request.ask_path.clone(),
                decision: Decision::Allow,
                reveal: false,
                expires_at: Some(until),
                limit: None,
                note: format!("Approved by {} from request {}", actor.username, request.id),
                created_at: at,
                created_by: actor.username.clone(),
            });
            message = format!("Approved; {} may {} {} without asking until the approval lapses", request.username, outgoing.method, request.credential_name);
        }
        let log = request.entry(at, "approve", format!("approved by {}{}", actor.username, if extra_rule.is_some() { " for a while" } else { " once" }));
        request.state = State::Running;
        (log, extra_rule, matches!(request.work, Work::Reveal { .. }), message)
    };
    if let Some(rule) = extra_rule {
        change_record(shared, |record| {
            record.rules.push(rule);
            Ok(())
        })?;
    }
    shared.log(log);
    if reveal {
        tokio::spawn(hand_out(shared.clone(), id.clone()));
    } else {
        tokio::spawn(run(shared.clone(), id.clone(), None));
    }
    Ok(json!({"request": id, "state": "running", "message": message}))
}

/// The credential and person a request names, if both are still there.
fn parts(shared: &Shared, person: &str, credential: &str) -> Result<(Person, policy::Credential, String, Vec<Rule>), String> {
    let record = lock(&shared.record);
    let person = record.people.iter().find(|own| own.id == person).cloned().ok_or("The person was removed")?;
    let credential = record.credentials.iter().find(|own| own.id == credential).cloned().ok_or("The credential was removed")?;
    let value = shared.sealer.open(&credential.id, &credential.sealed)?;
    Ok((person, credential, value, record.rules.clone()))
}

fn finish(shared: &Shared, id: &str, outcome: Result<Value, String>, action: &str, described: impl FnOnce(&Value) -> String) {
    let log = {
        let mut live = lock(&shared.live);
        let Some(request) = live.requests.get_mut(id) else { return };
        let text = match &outcome {
            Ok(value) => described(value),
            Err(error) => format!("failed: {error}"),
        };
        request.state = match outcome {
            Ok(value) => State::Done(value),
            Err(error) => State::Failed(error),
        };
        request.finished_at = Some(now());
        request.entry(now(), action, text)
    };
    shared.log(log);
}

/// Makes what an approved reveal hands out.
async fn hand_out(shared: Arc<Shared>, id: String) {
    let wanted = {
        let live = lock(&shared.live);
        live.requests.get(&id).map(|request| (request.person.clone(), request.credential.clone()))
    };
    let Some((person, credential)) = wanted else { return };
    let outcome = match parts(&shared, &person, &credential) {
        Ok((person, credential, value, _)) => mint::handout(&credential, &value, &person.username).await,
        Err(error) => Err(error),
    };
    finish(&shared, &id, outcome, "reveal", |value| if value["shortLived"] == true { "handed out a short-lived credential".into() } else { "handed out the value".into() });
}

/// Sends an allowed or approved request with its credential and keeps the answer for collection.
async fn run(shared: Arc<Shared>, id: String, finished: Option<tokio::sync::oneshot::Sender<()>>) {
    let wanted = {
        let live = lock(&shared.live);
        live.requests.get(&id).and_then(|request| match &request.work {
            Work::Use(outgoing) => Some((request.person.clone(), request.credential.clone(), outgoing.clone())),
            Work::Reveal { .. } => None,
        })
    };
    let Some((person, credential, outgoing)) = wanted else { return };
    let outcome = async {
        let (person, credential, value, rules) = parts(&shared, &person, &credential)?;
        // The grid may have changed since the request was made or approved.
        if !credential.destinations.iter().any(|place| forward::within(&outgoing.target, place)) {
            return Err(format!("{} may no longer be sent to {}", credential.name, outgoing.target.origin()));
        }
        if let Verdict::Refused(reason) = policy::evaluate(&rules, &person, &credential, &outgoing.method, &outgoing.target.path, now()) {
            return Err(reason);
        }
        let prepared = mint::prepare(&shared.mint, &credential, &value, &person.username).await?;
        forward::send(&outgoing, &prepared).await
    }
    .await;
    finish(&shared, &id, outcome, "use", |answer| format!("sent; answered {}", answer["status"]));
    if let Some(finished) = finished {
        let _ = finished.send(());
    }
}

/// A request's state for the person who made it. A finished answer is handed over once.
pub(super) fn collect(shared: &Shared, person: &Person, id: &str) -> Result<Value, Refusal> {
    let mut live = lock(&shared.live);
    let request = live.requests.get(id).filter(|request| request.person == person.id).ok_or_else(|| Refusal::missing("No such request of yours: it was collected, or it expired"))?;
    if !request.state.finished() {
        let mut view = request.summary();
        view["message"] = json!(if request.waiting() { "Still waiting for an approver" } else { "Still waiting for the service to answer" });
        return Ok(view);
    }
    let request = live.requests.remove(id).expect("found above");
    let mut view = json!({"id": request.id, "state": request.state.name(), "credential": request.credential_name, "decidedBy": request.decided_by});
    match request.state {
        State::Done(answer) => match request.work {
            Work::Use(_) => view["answer"] = answer,
            Work::Reveal { .. } => {
                for key in ["value", "warning", "expiresAt", "shortLived", "tokenType"] {
                    if let Some(part) = answer.get(key) {
                        view[key] = part.clone();
                    }
                }
            }
        },
        State::Denied(reason) => view["reason"] = json!(reason),
        State::Failed(error) => view["error"] = json!(error),
        State::Waiting | State::Running => {}
    }
    Ok(view)
}
