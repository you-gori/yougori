//! Private bounty coordination: authenticated membership, immutable scope, leases and receipts.
//! The hub owns attribution. Member-supplied IDs can never impersonate another member.
use super::*;
use std::collections::BTreeMap;

const MAX_EVENTS: usize = 20_000;
const MAX_RECEIPTS: usize = 20_000;
#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct Coordination {
    sessions: BTreeMap<String, Session>,
    leases: BTreeMap<String, Value>,
    events: Vec<Value>,
    evidence: BTreeMap<String, Value>,
    reports: Vec<Value>,
    receipts: BTreeMap<String, Value>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Session {
    digest: String,
    until: i64,
    state: String,
    report_policy: String,
    messages: Vec<Value>,
    #[serde(default)]
    budget_minutes: i64,
}
impl Coordination {
    pub(super) fn public_view(&self) -> Value {
        json!({"events":self.events.iter().rev().take(100).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>(),
            "reports":self.reports.iter().filter(|r|r["state"] != "draft").collect::<Vec<_>>(),"reservations":self.leases.values().filter(|l|l["expiresAt"].as_i64().unwrap_or(0)>now()).collect::<Vec<_>>()})
    }
    fn event(&mut self, kind: &str, member: &str, body: Value) -> Result<Value, String> {
        if self.events.len() >= MAX_EVENTS {
            return Err("coordination_full: Export this bounty and create a new investigation; its history is retained".into());
        }
        let event = json!({"id":format!("event-{}",crate::token()),"sequence":self.events.len()+1,"type":kind,"memberId":member,"workerId":member,"serverReceivedAt":now(),"body":body});
        self.events.push(event.clone());
        Ok(event)
    }
}
fn text<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= max)
        .ok_or_else(|| format!("invalid_request: {key} is required (at most {max} bytes)"))
}
fn allowed(c: &Coordination, member: &str, digest: &Value) -> bool {
    c.sessions.get(member).is_some_and(|s| {
        s.state == "running" && s.until > now() && digest.as_str() == Some(s.digest.as_str())
    })
}
fn lease(c: &Coordination, member: &str, body: &Value) -> Result<Value, String> {
    let id = text(body, "leaseId", 100)?;
    c.leases
        .get(id)
        .filter(|l| {
            l["memberId"] == member
                && l["generation"] == body["generation"]
                && l["expiresAt"].as_i64().unwrap_or(0) > now()
        })
        .cloned()
        .ok_or("lease_expired: Reserve this task again".into())
}
fn dispatch(
    c: &mut Coordination,
    policy: &Value,
    source: &Value,
    member: &str,
    method: &str,
    path: &str,
    after: u64,
    body: &Value,
) -> Result<Value, String> {
    if method == "GET" {
        return match path {
            "offer" => Ok(json!({"policy":policy})),
            "state" => {
                let s = c.sessions.get(member);
                Ok(json!({"executionAllowed":allowed(c,member,&policy["termsDigest"]),"policy":policy,
                    "membership":s.map(|s|json!({"networkMode":"closed","termsDigest":s.digest,"report_policy":s.report_policy,"budgetEndsAt":s.until})),
                    "worker":{"state":s.map(|s|s.state.as_str()).unwrap_or("ready_waiting")}}))
            },
            "source" if allowed(c,member,&policy["termsDigest"]) => Ok(json!({"source":source})),
            "events" if c.sessions.contains_key(member) => Ok(json!({"events":c.events.iter().filter(|e|e["sequence"].as_u64().unwrap_or(0)>after).take(100).collect::<Vec<_>>()})),
            "messages" | "conversation" => Ok(json!({"messages":c.sessions.get(member).map(|s|s.messages.iter().filter(|m|m["sequence"].as_u64().unwrap_or(0)>after).take(100).collect::<Vec<_>>()).unwrap_or_default()})),
            "reports" => Ok(json!({"reports":c.reports.iter().filter(|r|r["memberId"]==member).collect::<Vec<_>>()})),
            _ => Err("not_allowed: Accept this exact bounty before accessing its source and coordination".into()),
        };
    }
    let key = text(body, "idempotencyKey", 180)?;
    let receipt_key = format!("{member}:{path}:{key}");
    let fingerprint = crate::bounty_project::hash(body.to_string().as_bytes());
    if let Some(receipt) = c.receipts.get(&receipt_key) {
        if receipt["fingerprint"] != fingerprint {
            return Err(
                "idempotency_conflict: Request key was already used for different content".into(),
            );
        }
        return Ok(receipt["result"].clone());
    }
    // Only requests that keep a durable receipt are refused at the receipt limit; controls,
    // renewals and heartbeats go on working.
    let keeps_receipt = !matches!(path, "heartbeat" | "checkpoint" | "tasks/renew" | "tasks/release" | "control");
    if keeps_receipt && c.receipts.len() >= MAX_RECEIPTS {
        return Err("coordination_full: This bounty reached its receipt limit; existing evidence is preserved".into());
    }
    let result = if path == "accept" {
        if body["confirmed"] != true || body["termsDigest"] != policy["termsDigest"] {
            return Err("scope_changed: Review and accept the exact project and run recipe".into());
        }
        let minutes = body["budgetMinutes"]
            .as_i64()
            .filter(|n| (1..=1440).contains(n))
            .ok_or("invalid_budget: Choose 1–1440 minutes")?;
        let report_policy = text(body, "reportPolicy", 20)?;
        if !matches!(report_policy, "automatic" | "review") {
            return Err("invalid_policy: Choose automatic or review".into());
        }
        let digest: String = policy["termsDigest"].as_str().unwrap().into();
        // Accepting the same terms again keeps the conversation so far.
        let messages = c.sessions.get(member).filter(|s| s.digest == digest).map(|s| s.messages.clone()).unwrap_or_default();
        c.sessions.insert(
            member.into(),
            Session {
                digest,
                until: now() + minutes * 60,
                state: if body["deferUntilReady"] == true {
                    "preparing"
                } else {
                    "running"
                }
                .into(),
                budget_minutes: minutes,
                report_policy: report_policy.into(),
                messages,
            },
        );
        json!({"accepted":true,"policy":policy})
    } else if path == "activate" {
        let s = c
            .sessions
            .get_mut(member)
            .ok_or("not_accepted: Accept this bounty first")?;
        if !matches!(s.state.as_str(), "preparing" | "running") {
            return Err("not_preparing: Preparation was paused".into());
        }
        if s.state == "preparing" {
            s.state = "running".into();
            s.until = now() + s.budget_minutes.clamp(1, 1440) * 60;
        }
        json!({"activated":true})
    } else if path == "control" {
        let s = c
            .sessions
            .get_mut(member)
            .ok_or("not_accepted: Accept this bounty first")?;
        match body["action"].as_str() {
            Some("resume") => {
                if let Some(minutes) = body["budgetMinutes"].as_i64() {
                    if !(1..=1440).contains(&minutes) {
                        return Err("invalid_budget: Choose 1–1440 minutes".into());
                    }
                    s.until = now() + minutes * 60;
                }
                if s.until <= now() {
                    return Err("budget_expired: Extend the work budget before resuming".into());
                }
                s.state = "running".into();
            }
            Some("pause" | "stop") => s.state = "paused".into(),
            // Leaving ends the session: its acceptance, budget and leases are gone, and the
            // worker must accept the bounty again to come back.
            Some("leave") => {
                c.sessions.remove(member);
            }
            _ => return Err("invalid_control: Unsupported worker control".into()),
        }
        c.leases.retain(|_, l| l["memberId"] != member);
        json!({"ok":true})
    } else if matches!(path, "conversation" | "messages") {
        let content = text(body, "content", 8192)?;
        let s = c
            .sessions
            .get_mut(member)
            .ok_or("not_accepted: Accept this bounty first")?;
        if s.messages.len() >= 2000 {
            return Err("conversation_full: Conversation reached its limit".into());
        }
        let msg = json!({"id":format!("message-{}",crate::token()),"sequence":s.messages.len()+1,"role":if path=="conversation"{"human"}else{"agent"},"content":content,"at":now(),"replyTo":body["replyTo"]});
        s.messages.push(msg.clone());
        json!({"message":msg})
    } else if path == "submit" {
        let id = text(body, "reportId", 100)?;
        let report = c
            .reports
            .iter_mut()
            .find(|r| r["id"] == id && r["memberId"] == member)
            .ok_or("report_missing: No own draft with that ID")?;
        report["state"] = "complete_received".into();
        json!({"report":report})
    } else {
        if !allowed(c, member, &policy["termsDigest"]) {
            return Err(
                "authorization_ended: Bounty paused, removed, changed or out of budget".into(),
            );
        }
        match path {
            "heartbeat" | "checkpoint" => json!({"ok":true}),
            "tasks/reserve" => {
                c.leases
                    .retain(|_, l| l["expiresAt"].as_i64().unwrap_or(0) > now());
                if c.leases.values().any(|l| l["memberId"] == member) {
                    return Err("task_reserved: Finish or release your current task".into());
                }
                let component = text(body, "component", 400)?;
                let category = text(body, "category", 100)?;
                let conditions = text(body, "conditions", 1000)?;
                if c.leases.values().any(|l| {
                    l["component"] == component
                        && l["category"] == category
                        && l["conditions"] == conditions
                }) {
                    return Err(
                        "task_reserved: Another agent is investigating this hypothesis".into(),
                    );
                }
                if c.events.iter().any(|e| {
                    e["type"] == "attempt_result"
                        && e["body"]["component"] == component
                        && e["body"]["category"] == category
                        && e["body"]["conditions"] == conditions
                }) {
                    return Err("already_attempted: Read the existing result or use justified new conditions".into());
                }
                let id = format!("lease-{}", crate::token());
                let l = json!({"leaseId":id,"generation":1,"memberId":member,"component":component,"category":category,"conditions":conditions,"expiresAt":now()+120});
                c.leases.insert(id, l.clone());
                json!({"lease":l})
            }
            "tasks/renew" => {
                let mut l = lease(c, member, body)?;
                l["expiresAt"] = (now() + 120).into();
                c.leases
                    .insert(l["leaseId"].as_str().unwrap().into(), l.clone());
                json!({"lease":l})
            }
            "tasks/release" => {
                let id = text(body, "leaseId", 100)?;
                if c.leases.get(id).is_some_and(|l| l["memberId"] == member) {
                    c.leases.remove(id);
                }
                json!({"released":true})
            }
            "attempts" => {
                let l = lease(c, member, body)?;
                let outcome = text(body, "outcome", 30)?;
                if !matches!(
                    outcome,
                    "candidate" | "not_reproduced" | "inconclusive" | "blocked" | "interrupted"
                ) {
                    return Err("invalid_outcome: Unknown outcome".into());
                }
                let observations = text(body, "observations", 8000)?;
                let mut artifacts = Vec::new();
                if let Some(files) = body["evidence"].as_array() {
                    if files.len() > 4 {
                        return Err("evidence_limit: Attach at most four artifacts".into());
                    }
                    for file in files {
                        artifacts.push(store_evidence(c, member, file)?);
                    }
                }
                let event=c.event("attempt_result",member,json!({"component":l["component"],"category":l["category"],"conditions":l["conditions"],"sourceRevision":policy["sourceRevision"],"outcome":outcome,"observations":observations,"expected":body["expected"],"limitations":body["limitations"],"evidence":artifacts}))?;
                json!({"attempt":{"id":event["id"]}})
            }
            "observations" => {
                let l = lease(c, member, body)?;
                if !matches!(
                    body["kind"].as_str(),
                    Some("observation" | "hypothesis" | "blocked" | "verify")
                ) {
                    return Err("invalid_kind: Choose an observation type".into());
                }
                let content = text(body, "content", 4000)?;
                let event = c.event(
                    "observation",
                    member,
                    json!({"component":l["component"],"content":content,"kind":body["kind"]}),
                )?;
                json!({"event":event})
            }
            "evidence" => {
                json!({"evidence":store_evidence(c,member,body)?})
            }
            "reports" => {
                if c.reports.len() >= 2000 {
                    return Err("report_limit: Report limit reached".into());
                }
                for field in [
                    "title",
                    "component",
                    "reproduction",
                    "observed",
                    "expected",
                    "impact",
                ] {
                    text(body, field, 12000)?;
                }
                if body["sourceRevision"] != policy["sourceRevision"] {
                    return Err("scope_changed: Report source revision differs".into());
                }
                let ids = body["evidenceIds"]
                    .as_array()
                    .filter(|ids| !ids.is_empty() && ids.len() <= 8)
                    .ok_or("evidence_required: Attach actual evidence")?;
                if ids.iter().any(|id| {
                    id.as_str()
                        .and_then(|id| c.evidence.get(id))
                        .is_none_or(|e| e["memberId"] != member)
                }) {
                    return Err("evidence_owner: Evidence must belong to this worker".into());
                }
                let review = c.sessions[member].report_policy == "review";
                let attempts = body["attemptIds"]
                    .as_array()
                    .filter(|ids| !ids.is_empty() && ids.len() <= 16)
                    .ok_or("attempt_required: Link a recorded reproduction")?;
                if attempts.iter().any(|id| {
                    !c.events.iter().any(|e| {
                        e["id"] == *id && e["workerId"] == member && e["type"] == "attempt_result"
                    })
                }) {
                    return Err("attempt_owner: Link your own recorded reproduction".into());
                }
                let mut report = body.clone();
                report["id"] = format!("report-{}", crate::token()).into();
                report["memberId"] = member.into();
                report["state"] = if review { "draft" } else { "complete_received" }.into();
                report["at"] = now().into();
                report["evidence"] = json!(ids
                    .iter()
                    .filter_map(|id| c.evidence.get(id.as_str()?))
                    .collect::<Vec<_>>());
                let mut document = body.clone();
                document.as_object_mut().unwrap().remove("idempotencyKey");
                document["evidence"] = report["evidence"].clone();
                report["document"] = document;
                c.reports.push(report.clone());
                // The answer names the evidence rather than carrying it twice over: the worker's
                // tool reads answers up to 64 KiB, and the report is already stored whole.
                let mut shown = report.clone();
                shown.as_object_mut().unwrap().remove("document");
                shown["evidence"] = json!(report["evidence"].as_array().into_iter().flatten().map(|e| json!({"id":e["id"],"name":e["name"],"sha256":e["sha256"],"bytes":e["bytes"]})).collect::<Vec<_>>());
                json!({"report":shown,"awaitingHumanReview":review})
            }
            _ => return Err("unknown_operation: Unknown private coordinator operation".into()),
        }
    };
    // High-frequency heartbeats and lease renewals do not consume durable idempotency capacity.
    if !matches!(
        path,
        "heartbeat" | "checkpoint" | "tasks/renew" | "tasks/release"
    ) {
        c.receipts.insert(
            receipt_key,
            json!({"fingerprint":fingerprint,"result":result}),
        );
    }
    Ok(result)
}

fn store_evidence(c: &mut Coordination, member: &str, body: &Value) -> Result<Value, String> {
    use ::base64::Engine;
    let name = text(body, "name", 160)?;
    let content = text(body, "contentBase64", 49152)?;
    let bytes = ::base64::engine::general_purpose::STANDARD
        .decode(content)
        .map_err(|_| "invalid_evidence: Expected base64")?;
    if bytes.is_empty() || c.evidence.len() >= 2000 {
        return Err("evidence_limit: Evidence empty or limit reached".into());
    }
    let id = format!("evidence-{}", crate::token());
    let hash = crate::bounty_project::hash(&bytes);
    if !body["sha256"].is_null() && body["sha256"] != hash {
        return Err("evidence_digest: Evidence digest differs".into());
    }
    c.evidence.insert(id.clone(),json!({"id":id,"memberId":member,"name":name,"contentBase64":content,"sha256":hash,"bytes":bytes.len()}));
    Ok(json!({"id":id,"name":name,"sha256":hash,"bytes":bytes.len()}))
}

pub(super) async fn route(
    shared: &Shared,
    member: &str,
    request: Request<Incoming>,
) -> Response<Body> {
    let method = request.method().as_str().to_owned();
    let path = request
        .uri()
        .path()
        .trim_start_matches("/bounty/v1/agent/")
        .to_owned();
    let after = request
        .uri()
        .query()
        .and_then(|q| q.strip_prefix("after="))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let body = if method == "POST" {
        match net::json_body(request.into_body(), REQUEST_LIMIT).await {
            Ok(v) => v,
            Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request", e),
        }
    } else {
        Value::Null
    };
    let mut record = lock(&shared.record);
    // Membership may have been revoked while the request body was arriving.
    if !record.members.iter().any(|m| m.id == member) {
        return error(
            StatusCode::FORBIDDEN,
            "member_revoked",
            "This member was removed",
        );
    }
    // Work on a transaction copy; failed requests/persistence cannot leave half-applied evidence.
    let mut next = record.coordination.clone();
    match dispatch(
        &mut next,
        &shared.policy,
        &shared.source,
        member,
        &method,
        &path,
        after,
        &body,
    ) {
        Ok(value) => {
            if method == "POST" {
                if !matches!(path.as_str(), "heartbeat" | "checkpoint") {
                    if let Err(e) = save_coordination(&shared.path, &next) {
                        return error(StatusCode::INTERNAL_SERVER_ERROR, "storage", e);
                    }
                }
                record.coordination = next;
            }
            // What the worker says about itself goes on the roster: its name and model from a
            // heartbeat, so the host sees the configured worker, not a placeholder.
            if path == "heartbeat" {
                let mut changed = false;
                if let Some(entry) = record.members.iter_mut().find(|entry| entry.id == member) {
                    if let Some(name) = body["name"].as_str().map(|name| name.trim().chars().take(64).collect::<String>()).filter(|name| !name.is_empty() && *name != entry.name) {
                        entry.name = name;
                        changed = true;
                    }
                    if let Some(model) = body["model"].as_str().map(|model| model.trim().chars().take(200).collect::<String>()).filter(|model| !model.is_empty() && entry.model.as_deref() != Some(model.as_str())) {
                        entry.model = Some(model);
                        changed = true;
                    }
                }
                if changed {
                    shared.dirty.store(true, Ordering::Relaxed);
                }
            }
            // Presence follows the session's real state: preparing, running or paused; a worker
            // that only previewed, or left, is not shown as working.
            let state = record.coordination.sessions.get(member).map(|s| s.state.clone()).unwrap_or_else(|| "idle".into());
            let stage = body["stage"].as_str().map(|stage| stage.chars().take(200).collect::<String>()).filter(|stage| !stage.is_empty());
            drop(record);
            let mut live = lock(&shared.live);
            let presence = live.presence.entry(member.into()).or_insert(Presence { seen: Instant::now(), address: shared.bound.ip(), state: state.clone(), stage: String::new() });
            presence.seen = Instant::now();
            presence.state = state;
            if let Some(stage) = stage {
                presence.stage = stage;
            } else if presence.stage.is_empty() {
                presence.stage = "Investigating accepted project".into();
            }
            json_response(StatusCode::OK, &value)
        }
        Err(message) => {
            let (code, _) = message.split_once(':').unwrap_or(("rejected", &message));
            error(StatusCode::CONFLICT, code, &message)
        }
    }
}

pub(super) fn load(path: &Path) -> Result<Option<Coordination>, String> {
    match std::fs::read(path.with_extension("coordination.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("Cannot read private coordination: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn save_coordination(path: &Path, value: &Coordination) -> Result<(), String> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or("Missing bounty folder")?)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, value).map_err(|e| e.to_string())?;
    file.persist(path.with_extension("coordination.json"))
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dispatch(
        record: &mut Record,
        member: &str,
        method: &str,
        path: &str,
        after: u64,
        body: &Value,
    ) -> Result<Value, String> {
        let policy = record.bounty.policy(&record.id)?;
        let source = record.bounty.snapshot()?;
        super::dispatch(
            &mut record.coordination,
            &policy,
            &source,
            member,
            method,
            path,
            after,
            body,
        )
    }
    fn record() -> Record {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.json");
        let b = Bounty::checked(
            "Review",
            "Test the API",
            "Owner authorizes this snapshot",
            vec![SourceFile {
                path: "app.js".into(),
                data: "YWJj".into(),
            }],
        )
        .unwrap();
        create(
            &path,
            "Team",
            "127.0.0.1".parse().unwrap(),
            0,
            None,
            None,
            "salt",
            b,
        )
        .unwrap();
        super::super::load(&path).unwrap()
    }
    fn accept(r: &mut Record, who: &str) {
        let digest = r.bounty.policy(&r.id).unwrap()["termsDigest"].clone();
        dispatch(r,who,"POST","accept",0,&json!({"confirmed":true,"termsDigest":digest,"budgetMinutes":30,"reportPolicy":"review","idempotencyKey":"accept"})).unwrap();
    }
    #[test]
    fn two_agents_coordinate_without_impersonation_or_duplicate_work() {
        let mut r = record();
        accept(&mut r, "a");
        accept(&mut r, "b");
        let task = json!({"component":"app.js","category":"authorization","conditions":"baseline","idempotencyKey":"task"});
        let l = dispatch(&mut r, "a", "POST", "tasks/reserve", 0, &task).unwrap()["lease"].clone();
        assert!(dispatch(&mut r, "b", "POST", "tasks/reserve", 0, &task)
            .unwrap_err()
            .starts_with("task_reserved"));
        let attempt = json!({"leaseId":l["leaseId"],"generation":l["generation"],"outcome":"candidate","observations":"Observed a failing check","idempotencyKey":"attempt"});
        assert!(dispatch(&mut r, "b", "POST", "attempts", 0, &attempt).is_err());
        let first = dispatch(&mut r, "a", "POST", "attempts", 0, &attempt).unwrap();
        assert_eq!(
            dispatch(&mut r, "a", "POST", "attempts", 0, &attempt).unwrap(),
            first
        );
        assert_eq!(
            dispatch(&mut r, "b", "GET", "events", 0, &Value::Null).unwrap()["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        dispatch(
            &mut r,
            "a",
            "POST",
            "conversation",
            0,
            &json!({"content":"private guidance","idempotencyKey":"chat"}),
        )
        .unwrap();
        assert_eq!(
            dispatch(&mut r, "b", "GET", "messages", 0, &Value::Null).unwrap()["messages"],
            json!([])
        );
        r.coordination.sessions.get_mut("a").unwrap().until = 0;
        assert_eq!(
            dispatch(&mut r, "a", "GET", "state", 0, &Value::Null).unwrap()["executionAllowed"],
            false
        );
        assert!(dispatch(&mut r, "a", "GET", "source", 0, &Value::Null).is_err());
    }
}
