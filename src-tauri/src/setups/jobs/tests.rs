//! What the job and artifact-store handlers must hold true, with a fake grid behind them.
//!
//! Nothing here opens a realm, starts a sandbox or reaches another computer. The fake counts every
//! call, so a test can prove that a refusal happened before anything was created and that a removal
//! deleted only what the setup recorded.
use super::*;
use crate::setups::handler::Observation;
use std::sync::Mutex as Lock;
use tokio_util::sync::CancellationToken;

/// A grid that records what it was asked to do and can refuse on request.
#[derive(Default)]
struct FakeGrid {
    calls: Lock<Vec<String>>,
    jobs: Lock<BTreeMap<String, Value>>,
    /// Queues this fake has been asked to open, and whether each is admitting work.
    queues: Lock<BTreeMap<String, bool>>,
    workers: Lock<BTreeMap<String, bool>>,
    /// The next submit fails with this.
    refuse: Lock<Option<String>>,
    next: Lock<u32>,
}

impl FakeGrid {
    fn said(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, what: String) {
        self.calls.lock().unwrap().push(what);
    }

    /// Marks a job as having ended the way a grid would, for the stage after it to find.
    fn ended(&self, job: &str, state: &str) {
        let mut jobs = self.jobs.lock().unwrap();
        let found = jobs.get_mut(job).expect("a job this fake made");
        found["state"] = json!(state);
        found["finished"] = json!(matches!(state, "succeeded" | "failed" | "cancelled" | "stopped"));
        if state == "succeeded" {
            found["outputs"] = json!(["result"]);
        }
    }
}

impl JobCalls for FakeGrid {
    fn open_queue<'a>(&'a self, _setup: &'a str, queue: &'a str) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            self.note(format!("open_queue {queue}"));
            self.queues.lock().unwrap().insert(queue.to_owned(), true);
            Ok(queue.to_owned())
        })
    }

    fn submit<'a>(&'a self, _setup: &'a str, queue: &'a str, label: &'a str, _spec: &'a Value, inputs: Vec<(String, String)>) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let reading = inputs.iter().map(|(name, artifact)| format!(" <{name}={artifact}>")).collect::<String>();
            self.note(format!("submit {queue} {label}{reading}"));
            if let Some(refusal) = self.refuse.lock().unwrap().take() {
                return Err(refusal);
            }
            // The same key sent twice finds the job already admitted, as the library does.
            if let Some((id, _)) = self.jobs.lock().unwrap().iter().find(|(_, job)| job["label"].as_str() == Some(label)) {
                return Ok(id.clone());
            }
            let mut next = self.next.lock().unwrap();
            *next += 1;
            let id = format!("job-{next}");
            self.jobs.lock().unwrap().insert(id.clone(), json!({"state": "queued", "finished": false, "attempts": 0, "label": label}));
            Ok(id)
        })
    }

    fn look<'a>(&'a self, _setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Option<Value>, String>> {
        Box::pin(async move { Ok(self.jobs.lock().unwrap().get(job).cloned()) })
    }

    fn outputs<'a>(&'a self, _setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Vec<(String, String)>, String>> {
        Box::pin(async move {
            // Only a job that succeeded has outputs, exactly as the library answers.
            let jobs = self.jobs.lock().unwrap();
            let Some(found) = jobs.get(job).filter(|found| found["state"] == "succeeded") else { return Ok(Vec::new()) };
            Ok(found["outputs"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(|name| name.as_str()).map(|name| (name.to_owned(), format!("artifact-of-{job}"))).collect())
        })
    }



    fn withdraw<'a>(&'a self, _setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.note(format!("withdraw {job}"));
            // Asked to stop, not deleted: the record stays and so does everything it produced.
            if let Some(found) = self.jobs.lock().unwrap().get_mut(job) {
                found["state"] = json!("cancelRequested");
            }
            Ok(())
        })
    }

    fn admit<'a>(&'a self, _setup: &'a str, queue: &'a str, admitting: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.note(format!("admit {queue} {admitting}"));
            self.queues.lock().unwrap().insert(queue.to_owned(), admitting);
            Ok(())
        })
    }

    fn workers<'a>(&'a self, setup: &'a str, _queue: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.note(format!("workers {running}"));
            self.workers.lock().unwrap().insert(setup.to_owned(), running);
            Ok(())
        })
    }

    fn store<'a>(&'a self, _setup: &'a str) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move { Ok(json!({"present": true, "jobs": self.jobs.lock().unwrap().len()})) })
    }

    fn keep<'a>(&'a self, _setup: &'a str, max_gb: f64, days: Option<u32>) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.note(format!("keep {max_gb} {days:?}"));
            Ok(())
        })
    }

    fn pause<'a>(&'a self, _setup: &'a str, queue: &'a str, drain: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.note(format!("pause {queue} drain={drain}"));
            self.queues.lock().unwrap().insert(queue.to_owned(), false);
            Ok(())
        })
    }

    /// As the real one: the realm exists once a queue was opened or the store was kept, and
    /// asking is not a call that does anything.
    fn realm_id<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            let made = !self.queues.lock().unwrap().is_empty() || self.said().iter().any(|call| call.starts_with("keep "));
            Ok(made.then(|| format!("realm-{setup}")))
        })
    }
}

fn handlers(grid: Arc<FakeGrid>) -> (Arc<dyn ResourceHandler>, Arc<dyn ResourceHandler>) {
    let jobs = Jobs::new(grid);
    let all = jobs.handlers();
    let job = all.iter().find(|handler| handler.kind() == Kind::Job).unwrap().clone();
    let store = all.iter().find(|handler| handler.kind() == Kind::ArtifactStore).unwrap().clone();
    (job, store)
}

fn job_spec() -> Value {
    json!({
        "compute": {"resource": "computers"},
        "command": ["make", "release"],
        "outputs": {"resource": "results"},
        "timeout_seconds": 600,
        "idempotent": true,
        "retry": {"attempts": 3},
        "resources": {"cpu": 2.0, "memory_gb": 4.0},
    })
}

fn others(profile: &str) -> BTreeMap<String, (Kind, Value)> {
    BTreeMap::from([
        ("grid".to_owned(), (Kind::Grid, json!({"profile": profile, "mode": "create"}))),
        ("computers".to_owned(), (Kind::ComputePool, json!({"grid": {"resource": "grid"}}))),
        ("results".to_owned(), (Kind::ArtifactStore, json!({"max_gb": 10.0}))),
    ])
}

/// A stage of a pipeline: what it runs, and which stage it reads.
fn stage(reads: Option<&str>) -> Value {
    let mut spec = job_spec();
    spec["command"] = json!(["make", "stage"]);
    spec["inputs"] = match reads {
        Some(before) => json!([{"resource": before}]),
        None => json!([]),
    };
    spec
}

/// The stage before this one, as the registry records it once it has been sent.
fn peer(kind: Kind, runtime_id: Option<&str>, spec: Value) -> crate::setups::handler::Peer {
    crate::setups::handler::Peer { kind, spec, runtime_id: runtime_id.map(str::to_owned), owned: true }
}

fn with_peers(mut context: StepContext, peers: &[(&str, crate::setups::handler::Peer)]) -> StepContext {
    context.peers = peers.iter().map(|(id, peer)| ((*id).to_owned(), peer.clone())).collect();
    context
}

fn context(action: Action, spec: Value, runtime_id: Option<&str>) -> StepContext {
    StepContext {
        setup: "build-farm".into(),
        operation: "operation-1".into(),
        step: "step-1".into(),
        resource: "build".into(),
        kind: Kind::Job,
        action,
        label: "yougori/build-farm/build/1".into(),
        created_label: None,
        generation: 1,
        spec,
        runtime_id: runtime_id.map(str::to_owned),
        owner: None,
        peers: BTreeMap::new(),
        planned: BTreeMap::new(),
        cancel: CancellationToken::new(),
        secrets: Arc::new(BTreeMap::new()),
        started_at: None,
        recorded: None,
        consents: Arc::new(Default::default()),
    }
}

// ---- what is refused before anything exists ----

#[test]
fn a_job_whose_computers_this_setup_does_not_declare_is_refused_at_review() {
    let (job, _) = handlers(Arc::default());
    let mut spec = job_spec();
    spec["compute"] = json!({"resource": "somewhere-else"});
    let refusal = job.review("build", &spec, &others("neo_grid")).unwrap_err();
    assert_eq!(refusal.outcome, Outcome::Unsupported);
    assert!(refusal.message.contains("pool of computers this setup makes or joins"), "{}", refusal.message);
}

#[test]
fn a_job_whose_compute_names_the_wrong_kind_of_resource_is_refused_at_review() {
    let (job, _) = handlers(Arc::default());
    let mut spec = job_spec();
    spec["compute"] = json!({"resource": "results"});
    let refusal = job.review("build", &spec, &others("neo_grid")).unwrap_err();
    assert!(refusal.message.contains("pool of computers"), "{}", refusal.message);
}

#[test]
fn a_job_on_a_research_grid_is_refused_at_review_and_says_where_research_work_goes() {
    let (job, _) = handlers(Arc::default());
    let refusal = job.review("build", &job_spec(), &others("swarm_mining_grid")).unwrap_err();
    assert_eq!(refusal.outcome, Outcome::Unsupported);
    assert!(refusal.message.contains("research grid runs no generic jobs"), "{}", refusal.message);
    assert!(refusal.message.contains("own scope"), "{}", refusal.message);
}

#[test]
fn a_job_that_may_be_tried_again_has_to_say_what_repeating_it_does() {
    let (job, _) = handlers(Arc::default());
    let mut spec = job_spec();
    spec["idempotent"] = json!(false);
    let refusal = job.validate(&spec).unwrap_err();
    assert!(refusal.message.contains("idempotent: true"), "{}", refusal.message);
    assert!(refusal.message.contains("reconcile: manual"), "{}", refusal.message);

    // Either answer is enough, and one attempt needs neither.
    spec["reconcile"] = json!("manual");
    assert!(job.validate(&spec).is_ok());
    spec["reconcile"] = json!("none");
    spec["retry"] = json!({"attempts": 1});
    assert!(job.validate(&spec).is_ok());
}

#[test]
fn a_command_that_is_really_a_line_for_a_shell_is_refused() {
    let (job, _) = handlers(Arc::default());
    for program in ["sh", "bash", "/bin/bash", "powershell.exe", "cmd"] {
        let mut spec = job_spec();
        spec["command"] = json!([program, "-c", "make release && ./publish.sh"]);
        let refusal = job.validate(&spec).unwrap_err();
        assert!(refusal.message.contains("never a line for a shell"), "{program}: {}", refusal.message);
    }
}

#[test]
fn a_job_with_no_computers_named_at_all_is_refused_before_review() {
    let (job, _) = handlers(Arc::default());
    let mut spec = job_spec();
    spec["compute"] = json!({});
    assert!(job.validate(&spec).unwrap_err().message.contains("compute: {resource: ID}"));
}

#[test]
fn a_schedule_is_refused_plainly_rather_than_quietly_ignored() {
    let (job, _) = handlers(Arc::default());
    let mut spec = job_spec();
    spec["schedule"] = json!("0 2 * * *");
    let refusal = job.validate(&spec).unwrap_err();
    assert!(refusal.message.contains("isn't available yet"), "{}", refusal.message);
}

#[test]
fn nothing_was_asked_of_the_grid_by_any_refusal() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    let _ = job.review("build", &job_spec(), &others("swarm_mining_grid"));
    let _ = job.validate(&json!({"compute": {}, "command": []}));
    assert!(grid.said().is_empty(), "{:?}", grid.said());
}

// ---- what applying does ----

#[tokio::test]
async fn applying_a_job_opens_its_queue_sends_it_once_and_starts_this_computers_workers() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    let receipt = job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    assert_eq!(receipt.runtime_id.as_deref(), Some("job-1"));
    assert_eq!(receipt.observed, Observed::Running);
    assert!(receipt.retained_data, "what a job produces outlives the step that sent it");
    assert_eq!(grid.said(), ["open_queue build-farm", "submit build-farm yougori/build-farm/build/1", "workers true"]);

    // The same step applied again finds the job it already sent. Nothing is queued twice.
    let again = job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    assert_eq!(again.runtime_id.as_deref(), Some("job-1"));
    assert_eq!(grid.jobs.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn stopping_a_setup_stops_this_computer_taking_its_work_and_lets_what_runs_finish() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    let stopped = job.stop(&context(Action::Stop, job_spec(), Some("job-1"))).await.unwrap();
    // The job itself is untouched; only the queue and this computer's workers stopped.
    assert_eq!(stopped.observed, Observed::Present);
    assert_eq!(grid.queues.lock().unwrap()["build-farm"], false);
    assert_eq!(grid.workers.lock().unwrap()["build-farm"], false);
    // Nothing was withdrawn and nothing was deleted: stopping is not removing.
    assert!(!grid.said().iter().any(|said| said.starts_with("withdraw")), "{:?}", grid.said());
    assert_eq!(grid.jobs.lock().unwrap()["job-1"]["state"], "queued");

    let started = job.apply(&context(Action::Start, job_spec(), Some("job-1"))).await.unwrap();
    assert_eq!(started.observed, Observed::Running);
    assert_eq!(grid.queues.lock().unwrap()["build-farm"], true);
}

#[tokio::test]
async fn removing_a_job_asks_it_to_stop_deletes_only_what_this_setup_recorded_and_keeps_artifacts() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    let removed = job.remove(&context(Action::Remove, job_spec(), Some("job-1"))).await.unwrap();
    assert_eq!(removed.runtime_id, None);
    assert_eq!(removed.observed, Observed::Missing);
    assert!(removed.retained_data, "what the job produced is kept");
    assert_eq!(grid.said().last().unwrap(), "workers false");
    assert!(grid.said().contains(&"withdraw job-1".to_owned()));
    assert_eq!(grid.jobs.lock().unwrap()["job-1"]["state"], "cancelRequested", "asked to stop, not killed");
}

#[tokio::test]
async fn removing_a_job_this_setup_never_sent_withdraws_nothing() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.remove(&context(Action::Remove, job_spec(), None)).await.unwrap();
    assert!(!grid.said().iter().any(|said| said.starts_with("withdraw")), "{:?}", grid.said());
}

#[tokio::test]
async fn a_job_the_grid_refused_fails_the_step_and_leaves_no_workers_running() {
    let grid = Arc::new(FakeGrid::default());
    *grid.refuse.lock().unwrap() = Some("This grid is not serving work at the moment".into());
    let (job, _) = handlers(grid.clone());
    let refusal = job.apply(&context(Action::Create, job_spec(), None)).await.unwrap_err();
    assert_eq!(refusal.outcome, Outcome::Failed);
    assert!(refusal.message.contains("not serving work"), "{}", refusal.message);
    assert!(grid.workers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_job_that_is_already_there_is_found_rather_than_sent_again() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    let found = job.observe(&context(Action::Create, job_spec(), Some("job-1"))).await.unwrap();
    match found {
        Observation::Present { runtime_id, label, retained_data, .. } => {
            assert_eq!(runtime_id, "job-1");
            assert_eq!(label.as_deref(), Some("yougori/build-farm/build/1"));
            assert!(retained_data);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(job.observe(&context(Action::Create, job_spec(), Some("job-9"))).await.unwrap(), Observation::Absent));
}

#[tokio::test]
async fn a_job_waiting_for_a_computer_says_so_rather_than_looking_broken() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    grid.jobs.lock().unwrap().get_mut("job-1").unwrap()["waitingBecause"] = json!("No computer in this grid offers 64 GB of memory.");
    let report = job.health(&context(Action::Create, job_spec(), Some("job-1"))).await.unwrap();
    assert_eq!(report.health, Health::WaitingForComputer);
    assert!(report.detail.contains("64 GB"), "{}", report.detail);

    grid.jobs.lock().unwrap().get_mut("job-1").unwrap()["state"] = json!("outcomeUnknown");
    let report = job.health(&context(Action::Create, job_spec(), Some("job-1"))).await.unwrap();
    assert_eq!(report.health, Health::Failed);
    assert!(report.detail.contains("settle it"), "{}", report.detail);
}

#[test]
fn the_review_says_that_a_job_runs_at_least_once_and_what_removing_it_keeps() {
    let (job, _) = handlers(Arc::default());
    let making = job.notes("build-farm", "build", &job_spec(), Action::Create).join(" ");
    assert!(making.contains("sandbox of its own"), "{making}");
    assert!(making.contains("at least once, never exactly once"), "{making}");
    let removing = job.notes("build-farm", "build", &job_spec(), Action::Remove).join(" ");
    assert!(removing.contains("asked to stop"), "{removing}");
    assert!(removing.contains("kept"), "{removing}");
}

#[test]
fn a_changed_description_is_a_new_job_rather_than_an_edit() {
    let (job, _) = handlers(Arc::default());
    assert_eq!(job.plan(None, &job_spec(), "digest-1").unwrap(), Planned::Step(Action::Create));
    let recorded = Resource { spec: job_spec(), ..recorded(Observed::Running) };
    assert_eq!(job.plan(Some(&recorded), &job_spec(), "digest-1").unwrap(), Planned::Unchanged);
    assert_eq!(job.plan(Some(&recorded), &job_spec(), "digest-2").unwrap(), Planned::Step(Action::Create));
}

// ---- the store ----

#[tokio::test]
async fn a_store_records_how_much_is_kept_and_removing_it_deletes_nothing() {
    let grid = Arc::new(FakeGrid::default());
    let (_, store) = handlers(grid.clone());
    let spec = json!({"max_gb": 20.0, "retention_days": 14});
    let made = store.apply(&context(Action::Create, spec.clone(), None)).await.unwrap();
    assert_eq!(made.runtime_id.as_deref(), Some("build-farm/artifacts"));
    assert_eq!(grid.said(), ["keep 20 Some(14)"]);

    let removed = store.remove(&context(Action::Remove, spec.clone(), Some("build-farm/artifacts"))).await.unwrap();
    assert!(removed.retained_data, "removing the store deletes nothing it holds");
    assert_eq!(grid.said(), ["keep 20 Some(14)"], "nothing was asked of the grid by a removal");
}

/// A job and its store say which realm they are in, for the setup's own record of its realms, and
/// asking that never makes a realm: before anything is sent or kept, there is none to name.
#[tokio::test]
async fn a_job_and_its_store_say_which_realm_they_are_in_and_asking_never_makes_one() {
    let grid = Arc::new(FakeGrid::default());
    let (job, store) = handlers(grid.clone());
    let kept = || context(Action::Update, json!({"max_gb": 10.0}), Some("build-farm/artifacts"));
    assert!(!store.outputs(&kept()).await.unwrap().contains_key("realm_id"));
    assert!(grid.said().is_empty(), "asking made nothing: {:?}", grid.said());

    let sent = job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    let shown = job.outputs(&context(Action::Update, job_spec(), sent.runtime_id.as_deref())).await.unwrap();
    assert_eq!(shown.get("realm_id").map(String::as_str), Some("realm-build-farm"));
    assert_eq!(shown.get("status").map(String::as_str), Some("queued"));
    assert_eq!(shown.get("id"), sent.runtime_id.as_ref());
    assert_eq!(store.outputs(&kept()).await.unwrap().get("realm_id").map(String::as_str), Some("realm-build-farm"));
    // A job not sent yet says nothing at all.
    assert!(job.outputs(&context(Action::Create, job_spec(), None)).await.unwrap().is_empty());
}

/// Pausing new work closes the setup's queue and leaves this computer's workers on, so what runs
/// can end. Draining or not is the person's choice, and resuming opens the queue again. A job that
/// was never sent asks nothing of the grid, and nothing is ever withdrawn.
#[tokio::test]
async fn pausing_new_work_closes_the_queue_keeps_the_workers_and_resuming_opens_it() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    let never_sent = job.admission(&context(Action::Update, job_spec(), None), Admission::Pause { drain: true }).await.unwrap();
    assert!(never_sent.contains("never sent"), "{never_sent}");
    assert!(grid.said().is_empty(), "{:?}", grid.said());

    job.apply(&context(Action::Create, job_spec(), None)).await.unwrap();
    let sent = context(Action::Update, job_spec(), Some("job-1"));
    let said = job.admission(&sent, Admission::Pause { drain: true }).await.unwrap();
    assert!(said.contains("What is running finishes"), "{said}");
    assert_eq!(grid.said().last().map(String::as_str), Some("pause build-farm drain=true"));
    assert!(!grid.queues.lock().unwrap()["build-farm"]);
    assert!(grid.workers.lock().unwrap()["build-farm"], "this computer keeps running what it has");

    let said = job.admission(&sent, Admission::Pause { drain: false }).await.unwrap();
    assert!(said.contains("asked to stop, as a cancel asks") && said.contains("Nothing was killed"), "{said}");
    assert_eq!(grid.said().last().map(String::as_str), Some("pause build-farm drain=false"));

    job.admission(&sent, Admission::Resume).await.unwrap();
    assert!(grid.queues.lock().unwrap()["build-farm"]);
    assert!(!grid.said().iter().any(|said| said.starts_with("withdraw")), "nothing was withdrawn: {:?}", grid.said());
}

#[test]
fn a_store_does_not_run_so_stopping_a_setup_leaves_it_alone() {
    let (_, store) = handlers(Arc::default());
    assert!(!store.stoppable());
}

#[test]
fn what_a_person_answers_is_what_the_grid_sweeps_to() {
    use yougori_grid::core::limits::KEEP_JOB_ARTIFACTS_FOR;
    // Ten gigabytes means ten, not the grid's own twenty; seven days means seven, not thirty.
    let small = retention_of(10.0, Some(7));
    assert_eq!(small.keep_bytes, 10 * (1 << 30));
    assert_eq!(small.keep_seconds, 7 * 86_400);
    assert!(small.keep_bytes < yougori_grid::core::limits::KEEP_JOB_ARTIFACT_BYTES);
    assert!(small.keep_seconds < KEEP_JOB_ARTIFACTS_FOR);
    // A store that says nothing about days keeps the grid's own time, and says so in the review.
    assert_eq!(retention_of(10.0, None).keep_seconds, KEEP_JOB_ARTIFACTS_FOR);
}

#[test]
fn a_store_asking_for_more_or_less_than_the_grid_can_hold_to_is_refused_with_the_bound_named() {
    let (_, store) = handlers(Arc::default());
    let too_small = store.validate(&json!({"max_gb": 0.5})).unwrap_err();
    assert!(too_small.message.contains("at least 1 GB"), "{}", too_small.message);
    let too_big = store.validate(&json!({"max_gb": 4096.0})).unwrap_err();
    assert!(too_big.message.contains("at most 1024 GB"), "{}", too_big.message);
    let too_long = store.validate(&json!({"max_gb": 10.0, "retention_days": 400})).unwrap_err();
    assert!(too_long.message.contains("at most 365 days"), "{}", too_long.message);
    // What the template actually asks for is inside the bounds at both ends.
    assert!(store.validate(&json!({"max_gb": 1.0, "retention_days": 1})).is_ok());
    assert!(store.validate(&json!({"max_gb": 1024.0, "retention_days": 365})).is_ok());
}

#[tokio::test]
async fn applying_the_store_sets_the_policy_rather_than_only_recording_it() {
    let grid = Arc::new(FakeGrid::default());
    let (_, store) = handlers(grid.clone());
    store.apply(&context(Action::Create, json!({"max_gb": 10.0, "retention_days": 7}), None)).await.unwrap();
    assert_eq!(grid.said(), ["keep 10 Some(7)"], "the person's own numbers reach the grid");
}

#[test]
fn a_store_on_another_drive_or_shared_between_setups_is_refused_plainly() {
    let (_, store) = handlers(Arc::default());
    assert!(store.validate(&json!({"max_gb": 10.0, "drive": {"binding": "backups"}})).unwrap_err().message.contains("isn't available yet"));
    assert!(store.validate(&json!({"max_gb": 10.0, "access": "grid"})).unwrap_err().message.contains("isn't available yet"));
    assert!(store.validate(&json!({"max_gb": 10.0})).is_ok());
}

#[test]
fn the_stores_review_says_what_is_kept_and_what_is_removed_first() {
    let (_, store) = handlers(Arc::default());
    let making = store.notes("build-farm", "results", &json!({"max_gb": 20.0, "retention_days": 14}), Action::Create).join(" ");
    assert!(making.contains("20 GB"), "{making}");
    assert!(making.contains("not a larger default"), "{making}");
    assert!(making.contains("14 days"), "{making}");
    let forever = store.notes("build-farm", "results", &json!({"max_gb": 20.0}), Action::Create).join(" ");
    assert!(forever.contains("oldest results are removed first"), "{forever}");
    assert!(forever.contains("still in play"), "{forever}");
}

// ---- the queue a setup's jobs go into ----

#[test]
fn each_setup_has_a_queue_of_its_own_whose_name_is_never_a_place_on_a_computer() {
    assert_eq!(queue_of("build-farm"), "build-farm");
    assert_eq!(queue_of("../../etc/passwd"), "etcpasswd");
    assert_eq!(queue_of("C:\\Windows"), "CWindows");
    assert_eq!(queue_of(""), "jobs");
    assert_eq!(queue_of("/"), "jobs");
}

#[test]
fn what_a_template_declares_becomes_a_description_the_library_accepts() {
    let sent = described(&job_spec(), Vec::new()).unwrap();
    assert_eq!(sent.outputs, ["result"]);
    assert_eq!(sent.timeout_seconds, 600);
    assert_eq!(sent.retry.max_attempts, 3);
    assert_eq!(sent.side_effects, yougori_grid::core::jobs::SideEffects::Repeatable);
    assert_eq!(sent.needs.cpu, 2.0);
    match sent.entrypoint {
        yougori_grid::core::jobs::Entrypoint::Argv { argv } => assert_eq!(argv, ["make", "release"]),
        other => panic!("{other:?}"),
    }

    // A job that is not safe to repeat is never turned into one that is.
    let mut careful = job_spec();
    careful["idempotent"] = json!(false);
    careful["retry"] = json!({"attempts": 1});
    assert_eq!(described(&careful, Vec::new()).unwrap().side_effects, yougori_grid::core::jobs::SideEffects::ManualReconcile);

    // And the library's own door is the last word: a shell is refused there too.
    let mut shell = job_spec();
    shell["command"] = json!(["bash", "-c", "make"]);
    assert!(described(&shell, Vec::new()).is_err());
}

#[test]
fn a_prepared_image_runs_its_own_entrypoint_with_the_declared_arguments() {
    let mut spec = job_spec();
    spec["image"] = json!("ghcr.io/example/builder:1.2.3");
    spec["command"] = json!(["release", "--jobs", "4"]);
    match described(&spec, Vec::new()).unwrap().entrypoint {
        yougori_grid::core::jobs::Entrypoint::Image { reference, args } => {
            assert_eq!(reference, "ghcr.io/example/builder:1.2.3");
            assert_eq!(args, ["release", "--jobs", "4"]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_setups_realm_key_is_its_own_and_lives_where_grid_cores_entries_live() {
    assert_eq!(key_account("build-farm"), "grid-core.setup-jobs.build-farm");
    assert_ne!(key_account("build-farm"), key_account("other-farm"));
}

// ---- stages that read the stage before them ----

#[test]
fn a_stage_may_only_read_another_job_of_the_same_setup() {
    let (job, _) = handlers(Arc::default());
    let mut others = others("neo_grid");
    others.insert("prepare".to_owned(), (Kind::Job, stage(None)));

    // Reading the stage before it is what a pipeline is.
    assert!(job.review("evaluate", &stage(Some("prepare")), &others).is_ok());

    // Anything else is refused, in words that say what an input actually is.
    let wrong = job.review("evaluate", &stage(Some("results")), &others).unwrap_err();
    assert!(wrong.message.contains("result of another job"), "{}", wrong.message);
    let missing = job.review("evaluate", &stage(Some("nowhere")), &others).unwrap_err();
    assert!(missing.message.contains("does not declare"), "{}", missing.message);
    let itself = job.review("evaluate", &stage(Some("evaluate")), &others).unwrap_err();
    assert!(itself.message.contains("cannot read its own result"), "{}", itself.message);
}

#[tokio::test]
async fn a_stage_waits_for_the_stage_before_it_and_reads_what_it_handed_back() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());

    // The first stage is sent with nothing to read.
    let first = job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    assert_eq!(first.runtime_id.as_deref(), Some("job-1"));
    grid.ended("job-1", "succeeded");

    // The second reads it, under the name of the stage that produced it.
    let mut second = with_peers(context(Action::Create, stage(Some("prepare")), None), &[("prepare", peer(Kind::Job, Some("job-1"), stage(None)))]);
    // Its own step, so its own key: a second stage is a second job, not a replay of the first.
    second.label = "yougori/build-farm/transform/1".into();
    let made = job.apply(&second).await.unwrap();
    assert_eq!(made.runtime_id.as_deref(), Some("job-2"));
    assert!(grid.said().iter().any(|said| said.contains("<prepare=artifact-of-job-1>")), "{:?}", grid.said());
}

#[tokio::test]
async fn a_stage_whose_stage_before_it_failed_is_not_queued_and_says_which_one() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    grid.ended("job-1", "failed");

    let second = with_peers(context(Action::Create, stage(Some("prepare")), None), &[("prepare", peer(Kind::Job, Some("job-1"), stage(None)))]);
    let refusal = job.apply(&second).await.unwrap_err();
    assert_eq!(refusal.outcome, Outcome::Failed);
    assert!(refusal.message.contains("'prepare' failed"), "{}", refusal.message);
    assert!(refusal.message.contains("not run a second time"), "{}", refusal.message);
    // Nothing was queued for it.
    assert_eq!(grid.jobs.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_stage_whose_stage_before_it_has_an_unknown_outcome_waits_for_a_person() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    grid.ended("job-1", "outcomeUnknown");

    let second = with_peers(context(Action::Create, stage(Some("prepare")), None), &[("prepare", peer(Kind::Job, Some("job-1"), stage(None)))]);
    let refusal = job.apply(&second).await.unwrap_err();
    assert_eq!(refusal.outcome, Outcome::NotStarted);
    assert!(refusal.message.contains("settle it"), "{}", refusal.message);
    assert_eq!(grid.jobs.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_stage_whose_stage_before_it_handed_nothing_back_is_not_queued() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    // It succeeded, but with no outputs at all.
    {
        let mut jobs = grid.jobs.lock().unwrap();
        let found = jobs.get_mut("job-1").unwrap();
        found["state"] = json!("succeeded");
        found["outputs"] = json!([]);
    }
    let second = with_peers(context(Action::Create, stage(Some("prepare")), None), &[("prepare", peer(Kind::Job, Some("job-1"), stage(None)))]);
    let refusal = job.apply(&second).await.unwrap_err();
    assert!(refusal.message.contains("without handing anything back"), "{}", refusal.message);
}

#[tokio::test]
async fn a_stage_whose_stage_before_it_was_never_sent_is_not_queued() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    let second = with_peers(context(Action::Create, stage(Some("prepare")), None), &[("prepare", peer(Kind::Job, None, stage(None)))]);
    let refusal = job.apply(&second).await.unwrap_err();
    assert!(refusal.message.contains("has not been sent yet"), "{}", refusal.message);
    assert!(grid.said().is_empty(), "nothing was asked of the grid: {:?}", grid.said());
}

#[tokio::test]
async fn waiting_for_a_stage_gives_way_to_the_step_being_cancelled() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    // It is still running, so the stage after it waits.
    let second = with_peers(context(Action::Create, stage(Some("prepare")), None), &[("prepare", peer(Kind::Job, Some("job-1"), stage(None)))]);
    second.cancel.cancel();
    let refusal = job.apply(&second).await.unwrap_err();
    assert_eq!(refusal.outcome, Outcome::NotStarted);
    assert!(refusal.message.contains("Nothing was queued"), "{}", refusal.message);
}

// ---- a failed pipeline carries on without repeating what already happened ----

fn recorded(observed: Observed) -> Resource {
    Resource {
        id: "stage".into(),
        kind: Kind::Job,
        depends_on: Vec::new(),
        runtime_id: Some("job-1".into()),
        owner: None,
        borrowers: Vec::new(),
        generation: 1,
        desired: crate::setups::model::Desired::Running,
        observed,
        retained_data: true,
        cost: Cost::Free,
        last_observed_at: None,
        drift: None,
        spec: stage(None),
        spec_digest: "digest-1".into(),
    }
}

#[test]
fn a_stage_that_succeeded_is_never_run_again_and_one_that_failed_is() {
    let (job, _) = handlers(Arc::default());
    // Succeeded: no step at all, so its work is never done a second time.
    assert_eq!(job.plan(Some(&recorded(Observed::Present)), &stage(None), "digest-1").unwrap(), Planned::Unchanged);
    // Still going: left alone.
    assert_eq!(job.plan(Some(&recorded(Observed::Running)), &stage(None), "digest-1").unwrap(), Planned::Unchanged);
    // Ended without succeeding: sent again, and the stages after it follow.
    assert_eq!(job.plan(Some(&recorded(Observed::Stopped)), &stage(None), "digest-1").unwrap(), Planned::Step(Action::Create));
    // Nobody knows whether it ran: this refuses to decide, and says who decides instead.
    let refusal = job.plan(Some(&recorded(Observed::Unknown)), &stage(None), "digest-1").unwrap_err();
    assert_eq!(refusal.code, "awaiting_settlement");
    assert!(refusal.message.contains("settle it"), "{}", refusal.message);
}

#[tokio::test]
async fn how_a_job_ended_is_what_the_registry_records() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    for (state, expected) in [
        ("queued", Observed::Running),
        ("running", Observed::Running),
        ("succeeded", Observed::Present),
        ("failed", Observed::Stopped),
        ("stopped", Observed::Stopped),
        ("cancelled", Observed::Stopped),
        ("outcomeUnknown", Observed::Unknown),
    ] {
        grid.jobs.lock().unwrap().get_mut("job-1").unwrap()["state"] = json!(state);
        match job.observe(&context(Action::Create, stage(None), Some("job-1"))).await.unwrap() {
            Observation::Present { observed, .. } => assert_eq!(observed, expected, "{state}"),
            other => panic!("{state}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn stopping_a_setup_does_not_make_its_jobs_look_as_if_they_failed() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    job.apply(&context(Action::Create, stage(None), None)).await.unwrap();
    let stopped = job.stop(&context(Action::Stop, stage(None), Some("job-1"))).await.unwrap();
    // `Stopped` on a job means it ended without succeeding. Stopping the setup does neither, so
    // applying the setup again must not queue the work a second time.
    assert_eq!(stopped.observed, Observed::Present);
}

// ---- a job on this computer, from a sandbox or its own image ----

#[test]
fn a_one_line_command_is_split_into_words_and_never_given_to_a_shell() {
    let split = |line: &str| super::argv(&json!({"command": [line]}));
    assert_eq!(split("python3 build.py --name 'two words' --flag=\"x y\"").unwrap(), ["python3", "build.py", "--name", "two words", "--flag=x y"]);
    assert_eq!(split("make").unwrap(), ["make"]);
    assert_eq!(super::argv(&json!({"command": ["make", "a b"]})).unwrap(), ["make", "a b"], "a list is the program and its arguments as written");
    for line in ["make | tee out", "echo $HOME", "make > out", "make; rm -rf /", "a && b", "`id`"] {
        let refusal = split(line).unwrap_err();
        assert!(refusal.contains("never through a shell"), "{line}: {refusal}");
    }
    assert!(split("echo 'unclosed").unwrap_err().contains("never closed"));
    // Split, a shell as the program is still refused.
    let (job, _) = handlers(Arc::default());
    let mut spec = job_spec();
    spec["command"] = json!(["bash -c 'make release'"]);
    assert!(job.validate(&spec).unwrap_err().message.contains("never a line for a shell"));
}

#[test]
fn a_job_runs_from_a_sandbox_of_its_setup_or_from_its_own_image() {
    let (job, _) = handlers(Arc::default());
    let mut setup = others("neo_grid");
    setup.insert("app".into(), (Kind::Environment, json!({"type": "container", "image": "python:3.12-slim"})));
    let mut spec = job_spec();
    spec["compute"] = json!({"resource": "app"});
    assert!(job.review("build", &spec, &setup).is_ok(), "a sandbox of the setup is somewhere a job can run from");

    let mut own = job_spec();
    own.as_object_mut().unwrap().remove("compute");
    assert!(job.validate(&own).is_ok());
    assert!(job.review("build", &own, &setup).unwrap_err().message.contains("its own image"));
    own["image"] = json!("python:3.12-slim");
    assert!(job.review("build", &own, &setup).is_ok());
}

#[tokio::test]
async fn a_job_made_from_a_sandbox_is_sent_with_that_sandboxs_image_and_room() {
    let grid = Arc::new(FakeGrid::default());
    let (job, _) = handlers(grid.clone());
    let mut spec = job_spec();
    spec["compute"] = json!({"resource": "app"});
    spec.as_object_mut().unwrap().remove("resources");
    let app = peer(Kind::Environment, Some("sandbox-1"), json!({"type": "container", "image": "python:3.12-slim", "cpu": 2.0, "memory": 3.0}));
    let ctx = with_peers(context(Action::Create, spec.clone(), None), &[("app", app)]);
    let sent = super::sent(&ctx);
    assert_eq!(sent["image"], "python:3.12-slim");
    assert_eq!((sent["resources"]["cpu"].as_f64(), sent["resources"]["memory_gb"].as_f64()), (Some(2.0), Some(3.0)));
    // Its own image and room win over the sandbox's.
    let mut own = spec.clone();
    own["image"] = json!("node:24");
    own["resources"] = json!({"cpu": 1.0});
    let app = peer(Kind::Environment, Some("sandbox-1"), json!({"type": "container", "image": "python:3.12-slim", "cpu": 2.0, "memory": 3.0}));
    let ctx = with_peers(context(Action::Create, own, None), &[("app", app)]);
    let sent = super::sent(&ctx);
    assert_eq!((sent["image"].as_str(), sent["resources"]["cpu"].as_f64()), (Some("node:24"), Some(1.0)));
    job.apply(&ctx).await.unwrap();
}

#[tokio::test]
async fn a_job_that_reads_a_folder_waits_for_one_that_is_there() {
    let (job, _) = handlers(Arc::new(FakeGrid::default()));
    let mut spec = job_spec();
    spec["source"] = json!({"binding": "project_source"});
    let refusal = job.apply(&context(Action::Create, spec.clone(), None)).await.unwrap_err();
    assert_eq!(refusal.outcome, Outcome::NeedsInput);
    spec["source_folder"] = json!("C:/no/such/folder/for/this/test");
    let refusal = job.apply(&context(Action::Create, spec.clone(), None)).await.unwrap_err();
    assert!(refusal.message.contains("isn't there"), "{}", refusal.message);
    let folder = tempfile::tempdir().unwrap();
    spec["source_folder"] = json!(folder.path().to_string_lossy());
    job.apply(&context(Action::Create, spec, None)).await.unwrap();
}

#[test]
fn the_wait_between_attempts_is_the_one_the_template_asked_for() {
    let mut spec = job_spec();
    spec["retry"] = json!({"attempts": 3, "backoff_seconds": 120});
    assert_eq!(super::described(&spec, Vec::new()).unwrap().retry.backoff_seconds, 120);
    spec["retry"] = json!({"attempts": 3});
    assert_eq!(super::described(&spec, Vec::new()).unwrap().retry.backoff_seconds, 30, "unsaid, half a minute");
}

#[test]
fn what_an_attempt_printed_is_kept_for_its_last_ten_attempts() {
    let meta = tempfile::tempdir().unwrap();
    for at in 0..12 {
        crate::setups::job_worker::keep_log(meta.path(), "job-1", &format!("att-{at:02}"), &format!("attempt {at}"));
    }
    let mut kept: Vec<String> = std::fs::read_dir(crate::setups::job_worker::logs_folder(meta.path(), "job-1")).unwrap().flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()).collect();
    kept.sort();
    assert_eq!(kept.len(), 10, "{kept:?}");
    assert!(kept.iter().all(|name| !name.contains("att-00") && !name.contains("att-01")), "the oldest two went: {kept:?}");
    let folder = tempfile::tempdir().unwrap();
    crate::setups::job_worker::remember_source(meta.path(), "job-1", folder.path()).unwrap();
    assert_eq!(crate::setups::job_worker::source_of(meta.path(), "job-1").as_deref(), Some(folder.path()));
    assert_eq!(crate::setups::job_worker::source_of(meta.path(), "job-2"), None);
}
