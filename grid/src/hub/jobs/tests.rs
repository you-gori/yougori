//! What the jobs door must hold true, with a real realm in a temporary folder behind it.
//!
//! Nothing here opens a socket, reaches another computer or runs a command: a request is the body
//! a client would send, and the "computers" are enrolled records. What is checked is the door's
//! own three jobs — who may ask, what may arrive, and that a refusal reaches the caller with the
//! library's own word and sentence, unchanged.
use super::*;
use crate::core::{
    identity::{PrincipalKind, Role},
    realm::{Capability, RealmKind},
    work::{Commitment, Resources},
};
use http_body_util::BodyExt;

const NOW: i64 = 50_000;

fn key() -> String {
    "c".repeat(64)
}

fn room() -> Resources {
    Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: false, vram_gb: 0.0 }
}

struct Door {
    service: Arc<Service>,
    _folder: tempfile::TempDir,
}

/// A realm with one person, the computer they send work from, and one computer offering room,
/// both tied to the member names a grid would know them by.
fn door(kind: RealmKind, capability: Capability) -> Door {
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", kind, &[capability], &key(), NOW).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], NOW).unwrap();
    let (laptop, _) = core.enrol_device(&person.id, "Ada's laptop", "linux", NOW).unwrap();
    let (builder, _) = core.enrol_device(&person.id, "Build PC", "linux", NOW).unwrap();
    if kind != RealmKind::Research {
        core.offer_host(&builder.id, "Build PC", room(), room(), Commitment::Share, NOW).unwrap();
    }
    let service = Arc::new(Service::new(core));
    service.enrol("member-sender", &person.id, &laptop.id);
    service.enrol("member-builder", &person.id, &builder.id);
    Door { service, _folder: folder }
}

fn ordinary() -> Door {
    door(RealmKind::Primary, Capability::Models)
}

impl Door {
    fn call(&self, member: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let Some(worker) = self.service.worker(member) else {
            return (StatusCode::FORBIDDEN, json!({"error": {"code": "not_a_worker"}}));
        };
        let response = act(&self.service, &worker, path, &body);
        read(response)
    }
}

/// The status and the JSON of a reply, as a client sees it.
fn read(response: Response<Body>) -> (StatusCode, Value) {
    let status = response.status();
    let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime to read the reply with");
    let bytes = runtime.block_on(async { response.into_body().collect().await.unwrap().to_bytes() });
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A refusal's stable word, wherever the hub puts it.
fn code(value: &Value) -> String {
    value["error"]["code"].as_str().or_else(|| value["code"].as_str()).unwrap_or_default().to_owned()
}

fn build() -> Value {
    json!({
        "entrypoint": {"kind": "argv", "argv": ["make", "release"]},
        "outputs": ["report"],
        "timeoutSeconds": 3600,
        "needs": {"cpu": 2.0, "memoryGb": 4.0, "diskGb": 10.0, "gpu": false, "vramGb": 0.0},
        "retry": {"maxAttempts": 3, "backoffSeconds": 10},
        "sideEffects": {"class": "repeatable"},
    })
}

#[test]
fn a_member_that_no_setup_tied_to_the_realm_is_not_a_worker() {
    let door = ordinary();
    let (status, body) = door.call("member-nobody", "list", json!({}));
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "not_a_worker");
}

#[test]
fn a_member_stops_being_a_worker_the_moment_it_is_untied() {
    let door = ordinary();
    assert_eq!(door.call("member-sender", "list", json!({})).0, StatusCode::OK);
    door.service.forget("member-sender");
    assert_eq!(door.call("member-sender", "list", json!({})).0, StatusCode::FORBIDDEN);
}

#[test]
fn a_job_is_sent_read_and_cancelled_through_the_door() {
    let door = ordinary();
    let (status, sent) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": build()}));
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["replayed"], false);
    let id = sent["job"]["id"].as_str().unwrap().to_owned();
    assert_eq!(sent["job"]["state"], "queued");

    let (status, read) = door.call("member-sender", "job", json!({"jobId": id}));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["job"]["id"], id.as_str());
    assert!(read["attempts"].as_array().unwrap().is_empty());

    let (status, cancelled) = door.call("member-sender", "cancel", json!({"jobId": id}));
    assert_eq!(status, StatusCode::OK);
    // Nothing had started it, so it is cancelled at once rather than asked to stop.
    assert_eq!(cancelled["state"], "cancelled");
}

#[test]
fn a_description_the_library_refuses_is_refused_here_in_the_librarys_own_words() {
    let door = ordinary();
    let mut spec = build();
    spec["entrypoint"]["argv"] = json!(["bash", "-c", "rm -rf /"]);
    let (status, body) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": spec}));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "invalid_spec");

    // A field this build does not know is named rather than dropped.
    let mut unknown = build();
    unknown["runAsRoot"] = json!(true);
    let (status, body) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": unknown}));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"]["message"].as_str().unwrap_or_default().contains("runAsRoot"), "{body}");
}

#[test]
fn a_research_realm_refuses_every_job_at_this_door_too() {
    let door = door(RealmKind::Research, Capability::Research);
    for (path, body) in [
        ("submit", json!({"queue": "builds", "spec": build()})),
        ("lease", json!({"seconds": 60})),
        ("close", json!({"queue": "builds", "inFlight": "finish", "reason": ""})),
    ] {
        let (status, answered) = door.call("member-sender", path, body);
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answered}");
        assert_eq!(code(&answered), "research_realm", "{path}");
    }
    // Reading a queue is not a refusal: there is nothing in it, and there never can be.
    assert_eq!(door.call("member-sender", "list", json!({})).1, json!([]));
}

#[test]
fn a_worker_leases_starts_heartbeats_and_finishes_a_job_through_the_door() {
    let door = ordinary();
    let (_, sent) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": build()}));
    let id = sent["job"]["id"].as_str().unwrap().to_owned();

    let (status, leased) = door.call("member-builder", "lease", json!({"seconds": 60}));
    assert_eq!(status, StatusCode::OK, "{leased}");
    let lease = leased["lease"].clone();
    assert_eq!(lease["jobId"], id.as_str());
    let attempt = lease["attemptId"].as_str().unwrap().to_owned();
    let fence = lease["fence"].as_u64().unwrap();
    assert_eq!(lease["outputs"], json!(["report"]));

    assert_eq!(door.call("member-builder", "start", json!({"attemptId": attempt, "fence": fence})).0, StatusCode::OK);
    let (status, beat) = door.call("member-builder", "heartbeat", json!({"attemptId": attempt, "fence": fence, "seconds": 60}));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(beat["stopRequested"], false);

    // Success is refused until the declared output has arrived from this same attempt.
    let (status, early) = door.call("member-builder", "complete", json!({"attemptId": attempt, "fence": fence, "ending": "succeeded"}));
    assert_eq!(status, StatusCode::CONFLICT, "{early}");
    assert_eq!(code(&early), "outputs_missing");
}

#[test]
fn a_computer_the_job_has_moved_on_from_is_refused_at_its_first_step() {
    let door = ordinary();
    door.call("member-sender", "submit", json!({"queue": "builds", "spec": build()}));
    let (_, leased) = door.call("member-builder", "lease", json!({"seconds": 60}));
    let attempt = leased["lease"]["attemptId"].as_str().unwrap().to_owned();
    let fence = leased["lease"]["fence"].as_u64().unwrap();
    let (status, body) = door.call("member-builder", "start", json!({"attemptId": attempt, "fence": fence + 1}));
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&body), "stale_fence");
}

#[test]
fn a_cancel_reaches_the_computer_on_its_next_heartbeat() {
    let door = ordinary();
    let (_, sent) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": build()}));
    let id = sent["job"]["id"].as_str().unwrap().to_owned();
    let (_, leased) = door.call("member-builder", "lease", json!({"seconds": 60}));
    let attempt = leased["lease"]["attemptId"].as_str().unwrap().to_owned();
    let fence = leased["lease"]["fence"].as_u64().unwrap();
    door.call("member-builder", "start", json!({"attemptId": attempt, "fence": fence}));

    let (_, cancelled) = door.call("member-sender", "cancel", json!({"jobId": id}));
    assert_eq!(cancelled["state"], "cancelRequested");
    let (_, beat) = door.call("member-builder", "heartbeat", json!({"attemptId": attempt, "fence": fence, "seconds": 60}));
    assert_eq!(beat["stopRequested"], true);
    let (status, stopped) = door.call("member-builder", "complete", json!({"attemptId": attempt, "fence": fence, "ending": "stopped"}));
    assert_eq!(status, StatusCode::OK, "{stopped}");
    assert_eq!(stopped["state"], "stopped");
}

#[test]
fn a_queue_that_stops_admitting_work_says_so_here() {
    let door = ordinary();
    let (status, closed) = door.call("member-sender", "close", json!({"queue": "builds", "inFlight": "finish", "reason": "the budget for today is spent"}));
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(closed["open"], false);
    assert_eq!(closed["inFlight"], "finish");

    let (status, refused) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": build()}));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code(&refused), "queue_closed");
    assert!(refused["error"]["message"].as_str().unwrap().contains("the budget for today is spent"), "{refused}");

    assert_eq!(door.call("member-sender", "open", json!({"queue": "builds"})).1["open"], true);
    assert_eq!(door.call("member-sender", "submit", json!({"queue": "builds", "spec": build()})).0, StatusCode::OK);
}

#[test]
fn closing_a_queue_must_say_what_happens_to_what_is_running() {
    let door = ordinary();
    let (status, body) = door.call("member-sender", "close", json!({"queue": "builds"}));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"]["message"].as_str().unwrap().contains("finish"), "{body}");
}

#[test]
fn an_unknown_jobs_path_is_a_plain_not_found() {
    let door = ordinary();
    let (status, body) = door.call("member-sender", "deploy", json!({}));
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
}

#[test]
fn the_same_work_sent_twice_under_one_key_comes_back_as_the_job_already_admitted() {
    let door = ordinary();
    let mut spec = build();
    spec["sideEffects"] = json!({"class": "dedupKey", "key": "nightly-2026-10-26"});
    let (_, first) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": spec.clone()}));
    let (_, again) = door.call("member-sender", "submit", json!({"queue": "builds", "spec": spec}));
    assert_eq!(first["replayed"], false);
    assert_eq!(again["replayed"], true);
    assert_eq!(first["job"]["id"], again["job"]["id"]);
}

#[test]
fn how_an_attempt_ended_is_read_from_the_closed_set_and_nothing_else() {
    assert_eq!(ending(&json!({"ending": "succeeded"})), Some(Ending::Succeeded));
    assert_eq!(ending(&json!({"ending": "stopped"})), Some(Ending::Stopped));
    assert_eq!(ending(&json!({"ending": "failed"})), Some(Ending::Failed(Failure::Exited)));
    assert_eq!(ending(&json!({"ending": "failed", "failure": "crashed"})), Some(Ending::Failed(Failure::Crashed)));
    // A computer's own words are never taken; an ending it invents is simply not one.
    assert_eq!(ending(&json!({"ending": "went fine honestly"})), None);
    assert_eq!(ending(&json!({"ending": "failed", "failure": "the reviewer approved it"})), Some(Ending::Failed(Failure::Exited)));
}

#[test]
fn what_a_person_found_is_read_from_the_closed_set_too() {
    assert_eq!(settlement("succeeded"), Some(Settled::Succeeded));
    assert_eq!(settlement("failed"), Some(Settled::Failed));
    assert_eq!(settlement("runAgain"), Some(Settled::RunAgain));
    assert_eq!(settlement("run again"), None);
}

#[test]
fn every_refusal_carries_a_status_that_matches_what_went_wrong() {
    for (error, expected) in [
        (JobError::ResearchRealm, StatusCode::FORBIDDEN),
        (JobError::NoSuchJob, StatusCode::NOT_FOUND),
        (JobError::StaleFence, StatusCode::CONFLICT),
        (JobError::LeaseLost, StatusCode::CONFLICT),
        (JobError::Draining, StatusCode::SERVICE_UNAVAILABLE),
        (JobError::ChecksumMismatch, StatusCode::CONFLICT),
        (JobError::Limit("too big".into()), StatusCode::PAYLOAD_TOO_LARGE),
        (JobError::Trouble("the disk".into()), StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let (status, body) = read(refused(&error));
        assert_eq!(status, expected, "{}", error.code());
        assert_eq!(code(&body), error.code());
        assert_eq!(body["error"]["message"], error.describe());
    }
}
