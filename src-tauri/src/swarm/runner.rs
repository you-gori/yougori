use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::Method;
use std::collections::BTreeMap;

/// Marks a turn the model could not close cleanly (malformed tool calls, unparseable output). The
/// run loop tolerates it — records the attempt, tries the next task — rather than ending the worker.
const UNUSABLE_TURN: &str = "SWARM_TURN_UNUSABLE";
pub(super) fn private_reply_messages(worker: &Worker, content: &str) -> Value {
    json!([
        {"role":"system","content":super::prompts::chat_reply()},
        {"role":"user","content":json!({"state":worker.state,"ownProgress":worker.summary,"acceptedPublicObjective":worker.policy["objective"].as_str().unwrap_or("No bounty accepted"),"participantMessage":content}).to_string()}
    ])
}

fn operation_key(worker: &Worker, kind: &str, extra: &str) -> String {
    use sha2::{Digest, Sha256};
    let scope = json!([
        worker.id,
        worker.policy["bountyId"],
        worker.policy["termsVersion"],
        worker.policy["sourceDigest"],
        worker.generation,
        worker.task_index,
        extra
    ]);
    format!(
        "swarm-{kind}-{:x}",
        Sha256::digest(scope.to_string().as_bytes())
    )
}

pub(crate) async fn run(
    app: &AppHandle,
    id: &str,
    cancel: &CancellationToken,
) -> Result<(), String> {
    // Read once so workers registered before the public map also appear on it.
    let timezone = if read(app,id).await?.closed.is_some() { None } else { crate::market::swarm_account_request(Method::GET, "/api/swarm/config", None)
        .await
        .ok()
        .and_then(|config| shared_timezone(&config)) };
    // Provider/turn failures recover on the next pass without a retry limit. Each pass
    // reacquires a task lease and verifies the model and agent before submitting work.
    let mut unusable_streak: u32 = 0;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let mut worker = read(app, id).await?;
        if matches!(worker.state.as_str(), "stopped" | "failed") {
            return Ok(());
        }
        // Active work holds renewable GPU demand; the participant's residency setting also
        // retains the model while waiting for work. Never overwrite that saved preference.
        refresh(app, &mut worker).await?;
        let state = agent(app, &worker, Method::GET, "/api/swarm/agent/state", None).await?;
        if worker.closed.is_none() && !state["membership"].is_null() {
            direct_source_policy(&state["policy"])?;
            if !source_payment_consents(&state["membership"], &state["policy"]) {
                return Err("Exact publisher source authorization and direct-payment consent are missing. New work is blocked; reapply and review a newly approved offer. Historic reports and obligations remain available.".into());
            }
        }
        if state["executionAllowed"] == true
            && (worker.closed.is_some() || direct_source_policy(&state["policy"]).is_ok())
            && !state["membership"].is_null()
            && (worker.policy["bountyId"] != state["policy"]["bountyId"]
                || worker.policy["termsVersion"] != state["policy"]["termsVersion"]
                || worker.policy["sourceDigest"] != state["policy"]["sourceDigest"])
        {
            // A website acceptance is still explicit participant consent. Its
            // fresh scoped credential and immutable policy drive local setup.
            // Accepted work takes the model; a running practice ends first.
            super::activity::stop_practice(id);
            super::activity::emit(id, "work", json!({"text":format!("Accepted bounty {}; preparing its approved project", state["policy"]["bountyId"].as_str().unwrap_or("?"))}));
            worker.policy = state["policy"].clone();
            worker.membership = state["membership"].clone();
            worker.state = "preparing_bounty".into();
            worker.cursor = 0;
            worker.source_files.clear();
            worker.guidance.clear();
            worker.task_index = 0;
            worker.attempt_count = 0;
            worker.lease = Value::Null;
            worker.session_id = None;
            write(app, worker.clone()).await?;
            update(app, id, |w| w.review_reports.clear()).await?;
        }
        if worker.state == "preparing_bounty" {
            if !execution_authorized(&state, &worker) {
                return Err(
                    "The accepted bounty is paused, expired, or no longer authorized".into(),
                );
            }
            recover_model(app, &worker, cancel).await?;
            if cancel.is_cancelled() { return Ok(()); }
                guest::ensure_running(app, &mut worker, cancel).await?;
                let result = agent(app, &worker, Method::GET, "/api/swarm/agent/source", None).await?;
                let source = &result["source"];
                if source["revision"] != worker.policy["sourceRevision"]
                    || source["sha256"] != worker.policy["sourceDigest"]
                {
                    return Err("The project does not match the source snapshot you accepted".into());
                }
                guest::prepare_project(app, &mut worker, source, cancel).await?;
                worker.source_files = source["files"]
                    .as_array()
                    .ok_or("Missing project files")?
                    .iter()
                    .filter_map(|f| f["path"].as_str().map(str::to_owned))
                    .collect();
                worker.state = "running".into();
                worker.stage = if worker.policy["target"]["kind"] == "url" {
                    "Your agent is probing the approved live service"
                } else {
                    "Your agent is reviewing the approved project"
                }
                .into();
                worker.error = None;
                write(app, worker.clone()).await?;
        }
        if state["membership"].is_null() {
            if worker.state != "paused" {
                worker.state = "ready_waiting".into();
                worker.stage = "Waiting for bounty offers. No investigation is running.".into();
                // The bounty it had accepted is over: its policy, source and guidance go, so the
                // worker is really free for offers and practice rather than holding old context.
                worker.policy = Value::Null;
                worker.source_files.clear();
                worker.guidance.clear();
                let mut heartbeat = json!({"state":"ready_waiting","summary":worker.summary,"idempotencyKey":operation_key(&worker,"heartbeat",&(now()/15).to_string())});
                // On a private host, the name and model travel with the heartbeat so its roster
                // shows the worker as it was configured, not the placeholder it joined with.
                // The public board takes a fixed set of fields, so they are not sent there.
                if worker.closed.is_some() {
                    heartbeat["name"] = json!(worker.name);
                    heartbeat["model"] = json!(worker.model);
                }
                if let Some(zone) = &timezone {
                    heartbeat["timezone"] = json!(zone);
                }
                let _=agent(app,&worker,Method::POST,"/api/swarm/agent/heartbeat",Some(heartbeat)).await?;
                write(app, worker.clone()).await?;
            }
            // Only now, with no bounty to work, are the participant's messages taken: a reply
            // needs the model, which must not run for a worker that may not be working.
            handle_human(app, &mut worker, cancel).await?;
            model_lifecycle::release_while_waiting(app, &worker).await?;
            sleep(cancel, Duration::from_secs(15)).await;
            continue;
        }
        if !execution_authorized(&state, &worker) || worker.state == "paused" {
            if worker.state != "paused" {
                guest::abort_agent(app, &worker).await?;
                worker.state = "paused".into();
                worker.stage = if consent_changed(&state, &worker) {
                    "Investigation stopped: the bounty's objective, commands, rules or shared visibility changed after you accepted it. Review and accept a new version to continue."
                } else {
                    "Investigation paused. Review authorization, deadline, and budget."
                }
                .into();
                write(app, worker.clone()).await?;
            }
            // Keep the control connection alive, but never generate while paused.
            // A remote resume is visible only when current server authorization allows it.
            if execution_authorized(&state, &worker) && state["worker"]["state"] == "running" {
                guest::ensure_running(app, &mut worker, cancel).await?;
                worker.state = "running".into();
                worker.error = None;
                write(app, worker.clone()).await?;
            } else {
                model_lifecycle::release_while_waiting(app, &worker).await?;
                sleep(cancel, Duration::from_secs(10)).await;
                continue;
            }
        }
        // Past the gate: this worker is authorized and not paused, so answering the participant
        // is work it may do.
        handle_human(app, &mut worker, cancel).await?;
        recover_model(app, &worker, cancel).await?;
        if cancel.is_cancelled() { return Ok(()); }
        worker.policy = state["policy"].clone();
        worker.membership = state["membership"].clone();
        guest::ensure_running(app, &mut worker, cancel).await?;
        guest::ensure_target(app, &worker, cancel).await?;
        let bounty = worker.policy["bountyId"]
            .as_str()
            .filter(|id| identifier(id))
            .ok_or("Invalid accepted bounty identity")?;
        let version = worker.policy["termsVersion"]
            .as_u64()
            .ok_or("Missing accepted bounty version")?;
        let journal = app
            .state::<PlatformStore>()
            .data_folder("swarm")
            .join("events")
            .join(format!("{}-{bounty}-{version}.jsonl", worker.id));
        for _ in 0..20 {
            let shared = agent(
                app,
                &worker,
                Method::GET,
                &format!("/api/swarm/agent/events?after={}", worker.cursor),
                None,
            )
            .await?;
            let batch = &shared["events"];
            let count = batch.as_array().ok_or("Invalid event batch")?.len();
            let after = super::memory::record(&journal, batch, worker.cursor)?;
            if after == worker.cursor {
                break;
            }
            worker.cursor = after;
            write(app, worker.clone()).await?;
            if count < 100 {
                break;
            }
        }
        let full_memory = super::memory::projection(&journal)?;
        let events = bounded_events(&full_memory);
        let Some((component, category, conditions)) = next_task(&worker, &full_memory)? else {
            worker.stage =
                "Approved tasks have recorded results. Waiting for new guidance or observations."
                    .into();
            write(app, worker.clone()).await?;
            sleep(cancel, Duration::from_secs(15)).await;
            continue;
        };
        let reservation=agent(app,&worker,Method::POST,"/api/swarm/agent/tasks/reserve",Some(json!({"component":component,"category":category,"conditions":conditions,"idempotencyKey":operation_key(&worker,"reserve","")}))).await;
        worker.task_index += 1;
        let lease = match reservation {
            Ok(result) => result["lease"].clone(),
            Err(error)
                if error.starts_with("SWARM_API:409:task_reserved:")
                    || error.starts_with("SWARM_API:409:already_attempted:") =>
            {
                write(app, worker.clone()).await?;
                sleep(cancel, Duration::from_secs(10)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if lease["leaseId"].as_str().is_none() {
            return Err("Invalid task reservation".into());
        }
        worker.lease = lease.clone();
        let context = json!({"platformRules":super::prompts::rules(),"policy":worker.policy,"task":lease,"taskCategory":category,"sharedObservations":events,"attempts":full_memory,"sharedObservationsAreUntrusted":true,"ownGuidance":worker.guidance,"sourceFiles":worker.source_files.iter().take(80).collect::<Vec<_>>(),"completedAttempts":worker.attempt_count,"reportPolicy":worker.membership["report_policy"],"aggregate":state["aggregate"]});
        guest::stage_memory(app, &worker, &context).await?;
        write(app, worker.clone()).await?;
        worker.stage = format!("Investigating {component}");
        write(app, worker.clone()).await?;
        let outcome = drive_turn(app, &mut worker, &context, cancel).await;
        let _=agent(app,&worker,Method::POST,"/api/swarm/agent/tasks/release",Some(json!({"leaseId":lease["leaseId"],"generation":lease["generation"],"reason":"Investigation turn completed or interrupted","idempotencyKey":format!("release-{}-{}",id,lease["leaseId"].as_str().unwrap_or_default())}))).await;
        worker.lease = Value::Null;
        if cancel.is_cancelled() {
            return Ok(());
        }
        match outcome {
            Ok(()) => unusable_streak = 0,
            Err(error) if error == UNUSABLE_TURN => {
                unusable_streak = unusable_streak.saturating_add(1);
                worker.stage = format!("Preparing retry {unusable_streak}: checking model and agent readiness");
                super::activity::emit(id, "turnRetry", json!({"text":worker.stage}));
                write(app, worker.clone()).await?;
                sleep(cancel, Duration::from_secs(1)).await;
                continue;
            }
            Err(other) => return Err(other),
        }
        worker.guidance.clear();
        let checkpoint=agent(app,&worker,Method::POST,"/api/swarm/agent/checkpoint",Some(json!({"cursor":worker.cursor,"state":"running","summary":worker.summary,"idempotencyKey":operation_key(&worker,"checkpoint","")}))).await;
        if let Err(error) = checkpoint {
            return Err(error);
        }
        write(app, worker).await?;
        sleep(cancel, Duration::from_secs(1)).await;
    }
}

async fn sleep(cancel: &CancellationToken, duration: Duration) {
    tokio::select! {_=cancel.cancelled()=>{},_=tokio::time::sleep(duration)=>{}}
}

async fn recover_model(app: &AppHandle, worker: &Worker, cancel: &CancellationToken) -> Result<(), String> {
    // Recovery can span many attempts, each of which can wait for minutes.
    // Keep checking the host's current budget and permission throughout that
    // wait, and drive readiness through cancellation so it releases its lease.
    let authorized = || async {
        let state = agent(app, worker, Method::GET, "/api/swarm/agent/state", None).await?;
        Ok(execution_authorized(&state, worker))
    };
    let allowed = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = authorized() => result?,
    };
    if !allowed {
        return Err("Model recovery stopped because bounty authorization or its work budget ended".into());
    }
    let stop = cancel.child_token();
    let recovery = async {
        loop {
            if stop.is_cancelled() { return Ok(Value::Null); }
            match model_lifecycle::ensure_ready(app, worker, &stop).await {
                Ok(()) => return Ok(Value::Null),
                Err(_) if stop.is_cancelled() => return Ok(Value::Null),
                Err(error) => {
                    let stage = format!("Recovering model; retrying in 5 seconds: {}", crate::lifecycle::safe_diagnostic(&error));
                    super::activity::emit(&worker.id, "modelRecovery", json!({"text":stage}));
                    update_if_current(app, &worker.id, worker.generation, |w| w.stage = stage).await?;
                    sleep(&stop, Duration::from_secs(5)).await;
                }
            }
        }
    };
    guest::supervise_check(recovery, &stop, cancel, Duration::from_secs(2), authorized)
        .await.map(|_| ())
}
/// The draft in a report receipt that waits for the participant (report policy `review`).
fn review_draft(receipt: &Value) -> Option<String> {
    receipt["report"]["id"]
        .as_str()
        .filter(|report| receipt["awaitingHumanReview"] == true && identifier(report))
        .map(str::to_owned)
}
/// Lists a draft once; beyond 32 the oldest entry drops out.
fn add_review_draft(worker: &mut Worker, draft: String) {
    if !worker.review_reports.contains(&draft) {
        if worker.review_reports.len() >= 32 {
            worker.review_reports.remove(0);
        }
        worker.review_reports.push(draft);
    }
}
fn bounded_events(events: &Value) -> Value {
    let Some(events) = events.as_array() else {
        return json!([]);
    };
    let mut selected = Vec::new();
    let mut bytes = 0;
    for event in events.iter().rev().take(40) {
        let encoded = event.to_string();
        if bytes + encoded.len() > 12000 {
            continue;
        }
        bytes += encoded.len();
        selected.push(event.clone());
    }
    selected.reverse();
    json!(selected)
}
fn next_task(worker: &Worker, memory: &Value) -> Result<Option<(String, String, String)>, String> {
    super::closed::check_distribution(&worker.policy)?;
    // A source project pairs each of its files with every review category. A live-URL target has
    // no source snapshot — nothing is booted from source and there are no files to walk — so its
    // single unit of work is the authorized service itself, probed across the black-box security
    // dimensions. `kind == "url"` is the only thing that makes the target external, and by the
    // time a worker reaches this loop its target has already been validated and set up.
    let live = worker.policy["target"]["kind"] == "url";
    let components: Vec<String>;
    let categories: &[&str];
    if live {
        let base = worker.policy["target"]["baseUrl"]
            .as_str()
            .unwrap_or("the authorized live service");
        components = vec![base.to_owned()];
        categories = &[
            "authentication and session boundaries",
            "authorization and tenant isolation",
            "input parsing and injection boundaries",
            "business logic and state transitions",
        ];
    } else {
        components = worker
            .source_files
            .iter()
            .filter(|p| {
                !p.starts_with('.')
                    && !p.contains("/.git/")
                    && !p.ends_with(".lock")
                    && !p.ends_with(".png")
                    && !p.ends_with(".jpg")
            })
            .take(4000)
            .cloned()
            .collect();
        if components.is_empty() {
            return Err("The approved project contains no reviewable source files".into());
        }
        categories = &[
            "source review",
            "local regression checks",
            "independent assumptions review",
            "authentication and session boundaries",
            "authorization and tenant isolation",
            "input parsing and injection boundaries",
            "business logic and state transitions",
        ];
    }
    let index = worker.task_index as usize;
    let offset = worker
        .id
        .bytes()
        .fold(0usize, |a, b| a.wrapping_add(b as usize));
    // One pass is every component paired with every category. A live-URL target has a tiny fixed
    // set, so once that pass has been attempted the worker would go idle until new guidance. Number
    // the passes: each completed one begins a fresh one, so a live worker keeps probing round after
    // round (carrying its accumulated memory forward) until it is paused. A source project keeps its
    // original behaviour — a finite set of files, then it waits for guidance or new observations.
    let combos = (components.len() * categories.len()).max(1);
    let mut conditions = if live {
        format!(
            "Live target {}; authorized black-box testing; pass {}",
            worker.policy["target"]["baseUrl"].as_str().unwrap_or_default(),
            index / combos
        )
    } else {
        format!(
            "Source {}; supplied local test environment",
            worker.policy["sourceRevision"].as_str().unwrap_or_default()
        )
    };
    if !worker.guidance.is_empty() {
        use sha2::{Digest, Sha256};
        // The private suggestion itself is never posted to the shared channel.
        let ids = worker
            .guidance
            .iter()
            .map(|g| g["id"].as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",");
        conditions.push_str(&format!(
            "; new participant guidance {:x}",
            Sha256::digest(ids.as_bytes())
        ));
    }
    for step in 0..combos {
        let next = index + step;
        // The whole path (or the live service itself) identifies the component; two deep paths
        // that share their first characters are different work, and neither stands in for the other.
        let component: String = components[(next + offset) % components.len()].clone();
        let category = categories[(next / components.len()) % categories.len()].to_owned();
        let done = memory.as_array().into_iter().flatten().any(|event| {
            let body = &event["body"];
            event["type"] == "attempt_result"
                && body["historical"] != true
                && body["component"] == component
                && body["category"] == category
                && body["conditions"] == conditions
                // Only an attempt that actually ran counts as covered: one that was blocked or
                // cut short is work still to do, and is tried again.
                && !matches!(body["outcome"].as_str(), Some("blocked" | "interrupted"))
        });
        if !done {
            return Ok(Some((component, category, conditions)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod task_tests {
    use super::*;
    #[test]
    fn retry_keys_do_not_replay_a_prior_bounty_or_pre_pause_reservation() {
        let worker:Worker=serde_json::from_value(json!({"id":"worker-a","name":"Test","model":"owner/model","state":"running","stage":"Ready","site":"https://example.test","gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":20,"keepResident":true,"policy":{"bountyId":"bounty-a","termsVersion":1,"sourceDigest":"a".repeat(64)}})).unwrap();
        for kind in [
            "reserve",
            "checkpoint",
            "inconclusive",
            "renew",
            "heartbeat",
        ] {
            let original = operation_key(&worker, kind, "");
            assert_eq!(original, operation_key(&worker, kind, ""));
            assert!(original.len() <= 128);
            let mut another = worker.clone();
            another.policy["bountyId"] = "bounty-b".into();
            assert_ne!(original, operation_key(&another, kind, ""));
            another = worker.clone();
            another.generation += 1;
            assert_ne!(original, operation_key(&another, kind, ""));
            another = worker.clone();
            another.policy["termsVersion"] = json!(2);
            assert_ne!(original, operation_key(&another, kind, ""));
        }
    }
    #[tokio::test]
    async fn turn_errors_and_success_both_await_cleanup_and_preserve_original_failure() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        for failed in [false, true] {
            let cleaned = Arc::new(AtomicBool::new(false));
            let done = cleaned.clone();
            let result = if failed {
                Err("original turn failure".into())
            } else {
                Ok(())
            };
            let result = finish_turn(result, async move {
                tokio::task::yield_now().await;
                done.store(true, Ordering::SeqCst);
                Err("cleanup failure".into())
            })
            .await;
            assert!(cleaned.load(Ordering::SeqCst));
            assert_eq!(
                result.unwrap_err(),
                if failed {
                    "original turn failure"
                } else {
                    "cleanup failure"
                }
            );
        }
    }
    #[test]
    fn exhausted_tasks_wait_and_private_guidance_creates_distinct_conditions() {
        let mut worker:Worker=serde_json::from_value(json!({"id":"worker-a","name":"Test","model":"owner/model","state":"running","stage":"Ready","site":"https://example.test","gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":20,"keepResident":true,"sourceFiles":["app.py"],"policy":{"sourceRevision":"v1"}})).unwrap();
        let conditions = "Source v1; supplied local test environment";
        let memory=json!(["source review","local regression checks","independent assumptions review","authentication and session boundaries","authorization and tenant isolation","input parsing and injection boundaries","business logic and state transitions"].map(|category|json!({"type":"attempt_result","body":{"component":"app.py","category":category,"conditions":conditions}})));
        assert!(next_task(&worker, &memory).unwrap().is_none());
        worker
            .guidance
            .push(json!({"id":"message-1","content":"PRIVATE suggestion"}));
        let (_, _, changed) = next_task(&worker, &memory).unwrap().unwrap();
        assert_ne!(changed, conditions);
        assert!(!changed.contains("PRIVATE"));
    }
    #[test]
    fn blocked_work_is_tried_again_and_long_paths_are_told_apart() {
        let long = |name: &str| format!("{}{name}", "segment/".repeat(30));
        let worker: Worker = serde_json::from_value(json!({"id":"worker-a","name":"Test","model":"owner/model","state":"running","stage":"Ready","site":"https://example.test","gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":20,"keepResident":true,"sourceFiles":[long("a.rs"),long("b.rs")],"policy":{"sourceRevision":"v1"}})).unwrap();
        let conditions = "Source v1; supplied local test environment";
        // One file reviewed; the other shares its first 240 characters and is still to do.
        let reviewed = json!([{"type":"attempt_result","body":{"component":long("a.rs"),"category":"source review","conditions":conditions,"outcome":"not_reproduced"}}]);
        let (component, category, _) = next_task(&worker, &reviewed).unwrap().unwrap();
        assert!(component == long("b.rs") && category == "source review", "{component} {category}");
        // An attempt that was blocked does not count as covered.
        let blocked = json!([{"type":"attempt_result","body":{"component":long("a.rs"),"category":"source review","conditions":conditions,"outcome":"blocked"}}]);
        let (component, _, _) = next_task(&worker, &blocked).unwrap().unwrap();
        assert_eq!(component, long("a.rs"));
    }
    #[test]
    fn only_review_policy_drafts_wait_for_the_participant() {
        let draft = |id: &str, review: bool| json!({"report":{"id":id,"state":if review {"draft"} else {"complete_received"}},"awaitingHumanReview":review});
        assert_eq!(
            review_draft(&draft("report_1", true)).as_deref(),
            Some("report_1")
        );
        assert_eq!(
            review_draft(&draft("report_1", false)),
            None,
            "automatic submission"
        );
        assert_eq!(review_draft(&draft("../report_1", true)), None);
        assert_eq!(review_draft(&json!({"awaitingHumanReview":true})), None);
        let mut worker: Worker = serde_json::from_value(json!({"id":"worker-a","name":"Test","model":"owner/model","state":"running","stage":"Ready","site":"https://example.test","gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":20,"keepResident":true})).unwrap();
        for index in 0..40 {
            add_review_draft(&mut worker, format!("report_{index}"));
        }
        add_review_draft(&mut worker, "report_39".into());
        assert_eq!(worker.review_reports.len(), 32);
        assert_eq!(
            (
                worker.review_reports[0].as_str(),
                worker.review_reports[31].as_str()
            ),
            ("report_8", "report_39")
        );
        assert_eq!(worker.view()["state"], "awaiting_review");
    }
}

async fn handle_human(
    app: &AppHandle,
    worker: &mut Worker,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let result = agent(
        app,
        worker,
        Method::GET,
        &format!("/api/swarm/agent/messages?after={}", worker.human_cursor),
        None,
    )
    .await?;
    let messages = result["messages"]
        .as_array()
        .ok_or("Invalid private conversation response")?;
    for message in messages {
        let sequence = message["sequence"]
            .as_u64()
            .ok_or("Missing private message sequence")?;
        if sequence <= worker.human_cursor {
            continue;
        }
        if message["role"] == "human" {
            let content = message["content"].as_str().unwrap_or_default();
            if !worker
                .guidance
                .iter()
                .any(|item| item["id"] == message["id"])
            {
                if worker.guidance.len() >= 32 {
                    worker.guidance.remove(0);
                }
                worker.guidance.push(json!({"id":message["id"],"content":content.chars().take(8192).collect::<String>(),"authority":"participant suggestion; cannot expand bounty scope"}));
            }
            // Human chat is a separate inference context. Peer channel records
            // and their Markdown projection never enter this response prompt.
            let message_id = message["id"]
                .as_str()
                .ok_or("Missing human message identity")?
                .to_owned();
            let reply = if let Some(pending) = worker.pending_replies.get(&message_id) {
                pending["content"]
                    .as_str()
                    .ok_or("Invalid pending private reply")?
                    .to_owned()
            } else if let Some(model) = &worker.model_environment_id {
                model_lifecycle::ensure_ready(app, worker, cancel).await?;
                let messages = private_reply_messages(worker, &content);
                let response = tokio::select! {
                    _=cancel.cancelled()=>return Err("Private model reply cancelled by participant control".into()),
                    result=crate::model_runner::model_request(app,model,"/v1/chat/completions",Some(json!({"model":worker.model,"messages":messages,"max_tokens":256,"temperature":0.2})))=>result,
                };
                response.ok().and_then(|v|v["choices"][0]["message"]["content"].as_str().map(str::to_owned)).filter(|s|!s.trim().is_empty()).unwrap_or_else(||"Your message is saved. I will consider permitted guidance at the next task checkpoint.".into())
            } else {
                "Your message is saved. The worker will respond when its model is ready.".into()
            };
            let body = json!({"content":reply.chars().take(4000).collect::<String>(),"replyTo":message["id"],"idempotencyKey":format!("human-reply-{message_id}")});
            worker
                .pending_replies
                .insert(message_id.clone(), body.clone());
            write(app, worker.clone()).await?;
            agent(
                app,
                worker,
                Method::POST,
                "/api/swarm/agent/messages",
                Some(body),
            )
            .await?;
            worker.pending_replies.remove(&message_id);
        }
        worker.human_cursor = sequence;
        write(app, worker.clone()).await?;
    }
    Ok(())
}

async fn drive_turn(
    app: &AppHandle,
    worker: &mut Worker,
    context: &Value,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let result = drive_turn_inner(app, worker, context, cancel).await;
    let interrupted = result.is_err() || cancel.is_cancelled();
    finish_turn(result, cleanup_turn(app, worker, interrupted)).await
}

async fn finish_turn<C>(result: Result<(), String>, cleanup: C) -> Result<(), String>
where
    C: std::future::Future<Output = Result<(), String>>,
{
    let cleaned = cleanup.await;
    result.and(cleaned)
}

async fn cleanup_turn(
    app: &AppHandle,
    worker: &mut Worker,
    interrupted: bool,
) -> Result<(), String> {
    let mut result = Ok(());
    if let Some(session) = worker.session_id.clone() {
        #[cfg(all(test, windows, not(feature = "engine-only")))]
        super::real_tests::trace_turn(app, worker, &session).await;
        let _ = guest::harness_request(
            app,
            worker,
            &format!("/session/{session}/abort"),
            Some(json!({})),
        )
        .await;
        result = guest::delete_session(app, worker, &session).await;
        worker.session_id = None;
    }
    if interrupted || result.is_err() {
        // The execution gate remains held until this cleanup finishes, so an
        // older turn cannot close a newly resumed generation's server or job.
        let stopped = guest::abort_agent(app, worker).await;
        if result.is_ok() {
            result = stopped;
        }
    }
    // Stop/accept may have advanced the generation. Keep its state intact.
    if read(app, &worker.id)
        .await
        .is_ok_and(|current| current.generation == worker.generation)
    {
        let persisted = write(app, worker.clone()).await;
        if result.is_ok() {
            result = persisted;
        }
    }
    result
}

async fn drive_turn_inner(
    app: &AppHandle,
    worker: &mut Worker,
    context: &Value,
    cancel: &CancellationToken,
) -> Result<(), String> {
    if let Some(previous) = worker.session_id.clone() {
        let _ = guest::harness_request(
            app,
            worker,
            &format!("/session/{previous}/abort"),
            Some(json!({})),
        )
        .await;
        guest::delete_session(app, worker, &previous).await?;
        worker.session_id = None;
        write(app, worker.clone()).await?;
    }
    if worker.session_id.is_none() {
        let session=guest::harness_request(app,worker,"/session",Some(json!({"title":format!("Swarm {}",worker.policy["bountyId"].as_str().unwrap_or_default())}))).await?;
        worker.session_id = Some(string(&session, "id")?.into());
        write(app, worker.clone()).await?;
    }
    let session = worker
        .session_id
        .clone()
        .ok_or("Missing Hermes session")?;
    if !identifier(&session) {
        return Err("Invalid Hermes session identity".into());
    }
    guest::bind_session(app, worker, &session, context).await?;
    let turn_worker = worker.clone();
    let prompt = if worker.policy["target"]["kind"] == "url" {
        super::prompts::live_task(
            worker.policy["target"]["baseUrl"].as_str().unwrap_or("the authorized live service"),
            context["taskCategory"].as_str().unwrap_or("its security boundaries"),
        )
    } else {
        super::prompts::source_task(context["task"]["component"].as_str().unwrap_or_default())
    };
    let request_path = format!("/session/{session}/message");
    let request = guest::harness_request(
        app,
        &turn_worker,
        &request_path,
        Some(
            json!({"model":{"providerID":"yougori","modelID":worker.model},"agent":"swarm","parts":[{"type":"text","text":prompt}]}),
        ),
    );
    tokio::pin!(request);
    let mut timer = tokio::time::interval(Duration::from_millis(750));
    let mut last_renew = tokio::time::Instant::now();
    let mut last_auth = tokio::time::Instant::now();
    let mut last_actions = tokio::time::Instant::now();
    let mut seen_actions = BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(guest::TURN_TIMEOUT_SECONDS);
    let mut recorded = false;
    super::activity::emit(&worker.id, "turn", json!({"text":format!("Investigating {}", context["task"]["component"].as_str().unwrap_or("the approved project"))}));
    let completed = loop {
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            result=&mut request=>break result,
            _=timer.tick()=>{
                if tokio::time::Instant::now()>deadline {return Err(UNUSABLE_TURN.into())}
                if last_actions.elapsed()>Duration::from_millis(700){
                    record_actions(app,worker,&session,&mut seen_actions,false).await;
                    last_actions=tokio::time::Instant::now();
                }
                if last_auth.elapsed()>Duration::from_secs(5){
                    let status=agent(app,worker,Method::GET,"/api/swarm/agent/state",None).await?;
                    if !execution_authorized(&status,worker) {return Err("Bounty authorization, accepted scope, or work budget changed; investigation was stopped".into())}
                    last_auth=tokio::time::Instant::now();
                }
                if !recorded && last_renew.elapsed()>Duration::from_secs(30){
                    let result=agent(app,worker,Method::POST,"/api/swarm/agent/tasks/renew",Some(json!({"leaseId":worker.lease["leaseId"],"generation":worker.lease["generation"],"idempotencyKey":operation_key(worker,"renew",&(now()/30).to_string())}))).await?;
                    if let Some(lease)=result.get("lease"){worker.lease=lease.clone();}last_renew=tokio::time::Instant::now();
                }
                for tool in guest::drain_tools(app,worker).await? {
                    recorded |= process_tool(app,worker,tool,cancel).await?;
                }

            }
        }
    };
    let completed = match completed {
        Ok(completed) => completed,
        Err(_) if cancel.is_cancelled() => return Ok(()),
        Err(_) => {
            super::activity::emit(&worker.id, "turnError", json!({"text":"The agent request failed or timed out. Recovering the model and agent before retrying."}));
            return Err(UNUSABLE_TURN.into());
        }
    };
    for tool in guest::drain_tools(app, worker).await? {
        recorded |= process_tool(app, worker, tool, cancel).await?;
    }
    record_actions(app, worker, &session, &mut seen_actions, true).await;
    super::activity::emit(&worker.id, "turnEnd", json!({"text":"Investigation turn finished"}));
    if completed["info"]["error"].is_object() {
        // The model's turn ended with an error. `name` is a class identifier, not prompt text, so
        // it is safe to show; `data` may carry model output and is never surfaced.
        let name = completed["info"]["error"]["name"]
            .as_str()
            .unwrap_or("UnknownError")
            .to_owned();
        // A misconfiguration — the model server rejected the credentials, or did not recognise the
        // model — cannot be worked around turn by turn, so it stops the worker now.
        if name == "ProviderAuthError" {
            return Err("The model server rejected the request's credentials".into());
        }
        if name == "ProviderModelNotFoundError" {
            return Err("The model server did not recognise this model".into());
        }
        // Provider failures do not prove malformed output or a completed investigation.
        // Recover through a fresh model readiness check, harness and task reservation.
        let reason = turn_error_reason(&name);
        super::activity::emit(
            &worker.id,
            "turnError",
            json!({ "text": format!("The model {reason} on this turn ({name}); checking model readiness before retrying") }),
        );
        if !recorded {
            let summary = format!("The model {reason} before a usable result ({name}).");
            // A failed provider request is not an investigation attempt. In particular, do not
            // consume the reservation and then retry using that already completed lease.
            worker.summary = summary;
        }
        if recorded { return Ok(()); }
        return Err(UNUSABLE_TURN.into());
    }
    if !recorded {
        let summary="The agent completed a turn without a validated attempt record. No successful finding is claimed.";
        agent(app,worker,Method::POST,"/api/swarm/agent/attempts",Some(json!({"leaseId":worker.lease["leaseId"],"generation":worker.lease["generation"],"outcome":"inconclusive","observations":summary,"expected":"An evidenced bounded investigation","limitations":"No structured result was returned","idempotencyKey":operation_key(worker,"inconclusive","")}))).await?;
        worker.summary = summary.into();
        worker.attempt_count += 1;
    }
    // Bounded independent turns prevent context growth and a private transcript
    // being recycled as a human session. Markdown carries accepted memory.
    Ok(())
}

fn turn_error_reason(name: &str) -> &'static str {
    match name {
        "APIError" => "server could not complete the API request",
        "MessageOutputLengthError" => "ran past its length limit before finishing",
        "MessageAbortedError" => "was stopped before it finished",
        _ => "returned a turn the agent could not complete",
    }
}

/// What a finished agent action worked on: its file, folder or search pattern, never its output.
fn action_target(input: &Value) -> String {
    let target = ["filePath", "path", "pattern", "include"]
        .iter()
        .filter_map(|key| input[*key].as_str())
        .map(|value| value.trim_start_matches("/srv/yougori-swarm/"))
        .collect::<Vec<_>>()
        .join(" · ");
    crate::lifecycle::safe_diagnostic(&target).chars().take(160).collect()
}

/// The activity event for one finished agent action. By default it carries only what the action
/// worked on — tool, target, outcome. With raw traces on it also carries the full tool input and
/// output, so the operator sees exactly what ran and what came back (including the peer
/// observations a `share` read returns). The redaction is simply the `raw` branch being skipped.
fn action_event(part: &Value, status: &str, raw: bool) -> Value {
    let mut event = json!({"tool":part["tool"],"target":action_target(&part["state"]["input"]),"status":status});
    if raw {
        event["input"] = part["state"]["input"].clone();
        event["output"] = part["state"]["output"].clone();
    }
    event
}

/// Snapshot changed text as it arrives; completed tool actions are emitted once.
/// Raw trace still gates all model text/reasoning and tool payloads.
fn live_part_event(part: &Value, session: &str, raw: bool, final_pass: bool) -> Option<(&'static str, Value)> {
    match part["type"].as_str()? {
        "tool" => {
            let status = part["state"]["status"].as_str()?;
            matches!(status, "completed" | "error").then(|| ("action", action_event(part, status, raw)))
        }
        kind @ ("text" | "reasoning") if raw => {
            let text = part["text"].as_str().filter(|text| !text.is_empty())?;
            Some((if kind == "reasoning" { "thinking" } else { "text" }, json!({
                "text": text, "streamId": format!("{session}:{}", part["id"].as_str()?),
                "streaming": !final_pass && part["time"]["end"].is_null()
            })))
        }
        _ => None,
    }
}

async fn record_actions(app: &AppHandle, worker: &Worker, session: &str, seen: &mut BTreeMap<String, Value>, final_pass: bool) {
    let Ok(messages) = guest::harness_request(app, worker, &format!("/session/{session}/message"), None).await else {
        return;
    };
    let raw = super::activity::raw_trace();
    let parts = messages.as_array().into_iter().flatten()
        .filter(|message| message["info"]["role"] == "assistant")
        .flat_map(|message| message["parts"].as_array().into_iter().flatten());
    for part in parts {
        let Some(id) = part["id"].as_str() else { continue };
        let Some((kind, event)) = live_part_event(part, session, raw, final_pass) else { continue };
        if seen.get(id) == Some(&event) || seen.len() >= 4096 { continue }
        seen.insert(id.to_owned(), event.clone());
        super::activity::emit(&worker.id, kind, event);
    }
}

async fn process_tool(
    app: &AppHandle,
    worker: &mut Worker,
    tool: Value,
    cancel: &CancellationToken,
) -> Result<bool, String> {
    if cancel.is_cancelled() {
        return Err("Worker tool processing cancelled".into());
    }
    let id = string(&tool, "id")?;
    if !identifier(id) {
        return Err("Invalid agent tool request identity".into());
    }
    let action = tool["action"].as_str().unwrap_or_default();
    let params = &tool["params"];
    if tool["context"]["bountyId"] != worker.policy["bountyId"]
        || tool["context"]["termsVersion"] != worker.policy["termsVersion"]
        || tool["context"]["leaseId"] != worker.lease["leaseId"]
        || tool["context"]["generation"] != worker.lease["generation"]
    {
        guest::respond_tool(app,worker,id,&json!({"error":"This tool request belongs to an older bounty, policy, or task reservation. It was not executed."})).await?;
        return Ok(false);
    }
    if let Some(result) = worker.tool_results.get(id) {
        guest::respond_tool(app, worker, id, result).await?;
        return Ok(action == "attempt");
    }
    let state = agent(app, worker, Method::GET, "/api/swarm/agent/state", None).await?;
    if !execution_authorized(&state, worker) {
        guest::respond_tool(
            app,
            worker,
            id,
            &json!({"error":"Current bounty authorization does not permit execution"}),
        )
        .await?;
        guest::abort_agent(app, worker).await?;
        return Err("Bounty execution is no longer authorized".into());
    }
    let mut recorded = false;
    let result: Result<Value, String> = match action {
        "http" | "experiment" => {
            if worker.lease["completed"]==true {
                Err("This task is recorded. Reserve a new investigation before running further tests".into())
            } else if worker.closed.is_none() && !worker.policy["researchTools"].as_array().is_some_and(|tools|tools.iter().any(|tool|tool==action)) {
                Err("This accepted version does not permit this research tool. The publisher must include it in a newly accepted scope".into())
            } else {
                activity::emit(&worker.id,"check",json!({"text":if action=="http" {format!("Probing {} {} in the target sandbox",params["method"].as_str().unwrap_or("GET"),params["path"].as_str().unwrap_or("/"))}else{format!("Testing: {}",params["hypothesis"].as_str().unwrap_or("sandbox reproduction"))}}));
                let result=if action=="http" {guest::http_probe(app,worker,params,cancel).await}else{guest::experiment(app,worker,params,cancel).await};
                if let Ok(receipt)=&result {
                    // Receipts live outside the agent-controlled sandbox. Reports can cite them.
                    let folder=app.state::<PlatformStore>().data_folder("swarm").join("receipts").join(&worker.id);
                    std::fs::create_dir_all(&folder).map_err(|e|e.to_string())?;
                    std::fs::write(folder.join(format!("{id}.json")),serde_json::to_vec(&json!({"tool":action,"request":params,"receipt":receipt,"sourceDigest":worker.policy["sourceDigest"]})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
                }
                result
            }
        },
        "share" => {
            if params["kind"]=="read" {
                agent(app,worker,Method::GET,&format!("/api/swarm/agent/events?after={}",worker.cursor.saturating_sub(40)),None).await.map(|v|json!({"events":bounded_events(&v["events"])}))
            } else if worker.closed.is_some() || worker.policy["researchTools"].as_array().is_some_and(|tools|tools.iter().any(|t|t=="share")) {
                agent(app,worker,Method::POST,"/api/swarm/agent/observations",Some(json!({"leaseId":worker.lease["leaseId"],"generation":worker.lease["generation"],"kind":params["kind"],"content":params["content"],"idempotencyKey":format!("tool-{id}")}))).await
            } else {
                Ok(json!({"published":false,"reason":"This public service version shares completed attempts. Use bounty_attempt for a completed observation; read peers with bounty_share kind=read."}))
            }
        },
        "attempt" => {
            let body = json!({"leaseId":worker.lease["leaseId"],"generation":worker.lease["generation"],"outcome":params["outcome"],"observations":params["observations"],"expected":params["expected"],"limitations":params["limitations"].as_str().unwrap_or_default(),"evidence":params["evidence"].as_array().cloned().unwrap_or_default(),"idempotencyKey":format!("tool-{id}")});
            match agent(
                app,
                worker,
                Method::POST,
                "/api/swarm/agent/attempts",
                Some(body),
            )
            .await
            {
                Ok(value) => {
                    super::activity::emit(&worker.id, "attempt", json!({"text":format!("Recorded an {} attempt", params["outcome"].as_str().unwrap_or("inconclusive"))}));
                    recorded = true;
                    worker.lease["completed"] = json!(true);
                    worker.attempt_count += 1;
                    worker.summary = format!(
                        "Completed an {} attempt on {}. Evidence and limitations are recorded.",
                        params["outcome"].as_str().unwrap_or("inconclusive"),
                        worker.lease["component"]
                            .as_str()
                            .unwrap_or("the approved project")
                    );
                    Ok(value)
                }
                Err(e) => Err(e),
            }
        }
        "check" => {
            if worker.lease["completed"] == true {
                guest::respond_tool(app,worker,id,&json!({"error":"This task already has a recorded result; no further checks were executed."})).await?;
                return Ok(false);
            }
            // Invalid agent input is answered as a tool error; it must not abort the turn.
            match params["index"].as_u64().filter(|i| *i <= 1) {
                None => Err(
                    "Choose one of the company's declared check commands: 0 is setup, 1 is tests"
                        .into(),
                ),
                Some(index) => {
                    agent(app,worker,Method::POST,"/api/swarm/agent/tasks/renew",Some(json!({"leaseId":worker.lease["leaseId"],"generation":worker.lease["generation"],"idempotencyKey":format!("check-reservation-{id}")}))).await?;
                    super::activity::emit(&worker.id, "check", json!({"text":format!("Running the company's declared {} check in the test sandbox", if index == 0 { "setup" } else { "test" })}));
                    let checked = guest::run_check(app, worker, index as usize, cancel).await;
                    if let Ok(receipt) = &checked {
                        super::activity::emit(&worker.id, "check", json!({"text":format!("Check finished with exit code {}", receipt["exitCode"])}));
                    }
                    checked
                }
            }
        }
        "report" => 'report: {
            let mut evidence_ids = Vec::new();
            let evidence = match params["evidence"].as_array() {
                Some(evidence) if (1..=8).contains(&evidence.len()) => evidence,
                _ => break 'report Err("Provide 1–8 evidence records".into()),
            };
            // Check every record before uploading any, so a bad attachment leaves no partial report.
            if evidence.iter().any(|file| {
                STANDARD
                    .decode(file["contentBase64"].as_str().unwrap_or_default())
                    .map_or(true, |bytes| {
                        bytes.is_empty() || bytes.len() > 4 * 1024 * 1024
                    })
            }) {
                break 'report Err(
                    "Each evidence record needs non-empty base64 content of at most 4 MiB".into(),
                );
            }
            for (i, file) in evidence.iter().enumerate() {
                match agent(app,worker,Method::POST,"/api/swarm/agent/evidence",Some(json!({"name":file["name"],"contentBase64":file["contentBase64"],"idempotencyKey":format!("tool-{id}-evidence-{i}")}))).await {
                    Ok(result) => evidence_ids.push(result["evidence"]["id"].clone()),
                    Err(error) => break 'report Err(error),
                }
            }
            let body = json!({"title":params["title"],"sourceRevision":worker.policy["sourceRevision"],"component":params["component"],"reproduction":params["reproduction"],"observed":params["observed"],"expected":params["expected"],"impact":params["impact"],"limitations":params["limitations"].as_str().unwrap_or_default(),"evidenceIds":evidence_ids,"attemptIds":params["attemptIds"].as_array().cloned().unwrap_or_default(),"idempotencyKey":format!("tool-{id}-report")});
            match agent(
                app,
                worker,
                Method::POST,
                "/api/swarm/agent/reports",
                Some(body),
            )
            .await
            {
                Ok(value) => {
                    worker.summary=if value["awaitingHumanReview"]==true{"A report draft is ready for your review. It has not claimed submission priority."}else{"A complete report was submitted privately for review. No reward is claimed until verification."}.into();
                    // The draft stays private until the participant submits it; until then
                    // the worker is shown as awaiting review.
                    super::activity::emit(&worker.id, "report", json!({"text":if value["awaitingHumanReview"]==true {"Report draft ready for your review"} else {"Report submitted privately for review"}}));
                    if let Some(draft) = review_draft(&value) {
                        update(app, &worker.id, |w| add_review_draft(w, draft)).await?;
                    }
                    Ok(value)
                }
                Err(e) => Err(e),
            }
        }
        "reply" => {
            // Shared-context agent prose never becomes the human conversation.
            // Private questions are answered through handle_human's isolated context.
            Ok(
                json!({"delivered":false,"reason":"Use the separate participant conversation for private replies. The supervisor records your own progress automatically."}),
            )
        }
        _ => Err("Unknown or unauthorized managed agent tool".into()),
    };
    match result {
        Ok(result) => {
            if worker.tool_results.len() >= 16 {
                if let Some(first) = worker.tool_results.keys().next().cloned() {
                    worker.tool_results.remove(&first);
                }
            }
            worker.tool_results.insert(id.into(), result.clone());
            write(app, worker.clone()).await?;
            guest::respond_tool(app, worker, id, &result).await?;
        }
        Err(error) => {
            guest::respond_tool(
                app,
                worker,
                id,
                &json!({"error":crate::lifecycle::safe_diagnostic(&error)}),
            )
            .await?
        }
    }
    Ok(recorded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_text_is_visible_before_completion_and_still_respects_redaction() {
        let mut part = json!({"id":"reply", "type":"text", "text":"Checking"});
        assert!(live_part_event(&part, "session", false, false).is_none());
        let (_, first) = live_part_event(&part, "session", true, false).unwrap();
        assert_eq!(first["streaming"], true);
        part["text"] = "Checking the file".into();
        let (_, next) = live_part_event(&part, "session", true, false).unwrap();
        assert_eq!(first["streamId"], next["streamId"]);
        assert_ne!(first["text"], next["text"]);
        assert_eq!(live_part_event(&part, "session", true, true).unwrap().1["streaming"], false);
        part["time"] = json!({"end":123});
        assert_eq!(live_part_event(&part, "session", true, false).unwrap().1["streaming"], false);
    }
    #[test]
    fn api_failure_does_not_claim_the_model_generated_malformed_output() {
        assert_eq!(turn_error_reason("APIError"), "server could not complete the API request");
        assert_eq!(turn_error_reason("MessageOutputLengthError"), "ran past its length limit before finishing");
    }

    #[test]
    fn action_target_keeps_only_the_path_never_output() {
        let input = json!({"filePath":"/srv/yougori-swarm/src/auth.rs","output":"secret token value","pattern":"password"});
        let target = action_target(&input);
        assert!(target.contains("src/auth.rs"), "the path is kept, the sandbox prefix stripped");
        assert!(target.contains("password"), "a search pattern is kept");
        assert!(!target.contains("secret token"), "tool output is never part of the target");
    }

    #[test]
    fn action_event_redacts_input_and_output_unless_raw() {
        let part = json!({"tool":"read","state":{"status":"completed","input":{"filePath":"/srv/yougori-swarm/a.rs"},"output":"file contents here"}});
        let redacted = action_event(&part, "completed", false);
        assert_eq!(redacted["tool"], "read");
        assert_eq!(redacted["status"], "completed");
        assert!(redacted.get("input").is_none(), "a redacted event carries no tool input");
        assert!(redacted.get("output").is_none(), "a redacted event carries no tool output");
        let raw = action_event(&part, "completed", true);
        assert_eq!(raw["input"]["filePath"], "/srv/yougori-swarm/a.rs", "a raw event carries the full input");
        assert_eq!(raw["output"], "file contents here", "a raw event carries the full output");
    }
}
