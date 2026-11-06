//! Scenario tests for the setup engine (plan 21.4). Every test runs against temporary folders and
//! the in-memory fake provider; nothing touches the real data folder or a real resource.
use super::{
    handler::{
        fake::FakeHandler, Admission, HandlerError, HandlerFuture, Handlers, Observation, ResourceHandler, StepContext,
    },
    journal::{Action, OperationState, Receipt, StepState},
    model::{new_id, Cost, Desired, Diagnostic, InstanceChange, Lifecycle, Observed, OwnerRef, Source},
    service::{plan_digest, DeclaredResource, PlanIntent, ReviewedPlan, Service, SetupDraft},
    store::{Registry, Store},
    views,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use yougori_setup::{dto, resource::Kind};

struct Bench {
    _root: tempfile::TempDir,
    setups: PathBuf,
    data: PathBuf,
    fake: Arc<FakeHandler>,
    extra: Vec<Arc<dyn ResourceHandler>>,
}

impl Bench {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        Self {
            setups: data.join("setups"),
            data,
            _root: root,
            fake: Arc::new(FakeHandler::new(Kind::Environment)),
            extra: Vec::new(),
        }
    }

    /// A fresh engine over the same folders and provider, as after a restart.
    fn service(&self) -> Arc<Service> {
        let mut handlers = Handlers::default();
        handlers.register(self.fake.clone());
        for handler in &self.extra {
            handlers.register(handler.clone());
        }
        Arc::new(Service::open(&self.setups, &self.data, handlers))
    }

    fn creates(&self) -> u32 {
        self.fake.provider.lock().unwrap().creates
    }

    fn calls(&self) -> Vec<String> {
        self.fake.provider.lock().unwrap().calls.clone()
    }

    fn on_disk(&self) -> Registry {
        Store::new(&self.setups).load().unwrap()
    }
}

fn change(name: &str) -> InstanceChange {
    InstanceChange {
        name: name.into(),
        source: Source {
            reference: dto::SourceRef::Hub { publisher: "example".into(), name: "hello".into(), version: "1.0.0".into() },
            digest: "sha256:0000".into(),
        },
        format_version: 2,
        protocol_version: 1,
        lock_digest: None,
        lock: None,
        answers: BTreeMap::new(),
        capabilities: vec!["run.health_logs".into()],
        secret_bindings: BTreeMap::new(),
    }
}

fn resource(id: &str, requires: &[&str]) -> DeclaredResource {
    DeclaredResource {
        id: id.into(),
        kind: Kind::Environment,
        spec: json!({ "image": format!("example/{id}") }),
        requires: requires.iter().map(|id| (*id).to_owned()).collect(),
        owner: None,
    }
}

fn create(name: &str, resources: Vec<DeclaredResource>) -> PlanIntent {
    PlanIntent::Create(SetupDraft { change: change(name), resources })
}

fn op() -> String {
    new_id("op-")
}

fn no_secrets() -> BTreeMap<String, String> {
    BTreeMap::new()
}

async fn created(service: &Service, name: &str, resources: Vec<DeclaredResource>) -> (ReviewedPlan, String) {
    let plan = service.plan(create(name, resources)).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(service.snapshot().operations[&operation].state, OperationState::Completed);
    (plan, operation)
}

fn state_of(service: &Service, operation: &str) -> OperationState {
    service.snapshot().operations[operation].state
}

/// PROVES that a synced folder which held files back is not silent. A sync that FAILS is reported
/// through the operation and a pass that STOPPED fails its step, but a pass that succeeded while
/// holding a conflicted or unstorable file back is not a failure, and used to say nothing at all.
/// The line comes off the folder's own record, so nothing here touches `registry.json`.
#[tokio::test]
async fn a_synced_folder_holding_files_back_says_so_in_the_setup_and_a_healthy_one_says_nothing() {
    let bench = Bench::new();
    let service = bench.service();
    let synced = DeclaredResource {
        id: "dev".into(),
        kind: Kind::Environment,
        spec: json!({
            "image": "example/dev",
            "sync": [{ "binding": "code", "target": "/workspace", "path": "/chosen/code", "read_only": false, "continuous": true, "conflicts": "keep_both" }],
        }),
        requires: Vec::new(),
        owner: None,
    };
    let (plan, _) = created(&service, "Dev", vec![synced]).await;

    // A setup whose folders are fine says nothing: notes are for what needs saying.
    assert!(service.get(&plan.setup_id).unwrap().notes.is_empty());

    // The last pass kept both copies of one file and could not store two names at all.
    let record = bench.setups.join("projects").join(&plan.setup_id).join("sync").join("dev-code.json");
    fs::create_dir_all(record.parent().unwrap()).unwrap();
    fs::write(
        &record,
        json!({
            "common": {},
            "unknown": [],
            "last": {
                "at": 1_760_000_000,
                "held": [{ "path": "notes.txt", "reason": "notes.txt changed in both places, so both copies are kept." }],
                "heldTotal": 3,
            },
        })
        .to_string(),
    )
    .unwrap();

    let notes = service.get(&plan.setup_id).unwrap().notes;
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("notes.txt changed in both places"), "{}", notes[0]);
    assert!(notes[0].contains("2 more are waiting the same way"), "the capped list says how many it leaves out: {}", notes[0]);
    // Starting a setup does not sync — `EnvironmentHandler::apply` returns for `Action::Start`
    // before it converges — so the line must not send anyone to Start.
    assert!(notes[0].contains("the next time this setup changes"), "{}", notes[0]);
    assert!(!notes[0].to_lowercase().contains("starting the setup"), "{}", notes[0]);
    // Never a real path of this computer, and never the folder the person chose.
    assert!(!notes[0].contains("/chosen/code"), "{}", notes[0]);

    // A pass with nothing held clears the line rather than leaving a stale warning.
    fs::write(&record, json!({ "common": {}, "unknown": [], "last": { "at": 1_760_000_100, "held": [], "heldTotal": 0 } }).to_string()).unwrap();
    assert!(service.get(&plan.setup_id).unwrap().notes.is_empty());

    // A record nobody can read is not a line either: it is not evidence of anything.
    fs::write(&record, "{ broken").unwrap();
    assert!(service.get(&plan.setup_id).unwrap().notes.is_empty());
}

/// PROVES the owner's second sync decision: a folder that held files back is not only a note.
/// The sync capability reads degraded with the folder's own line, and a setup that read ready
/// reads degraded, in its own view and in the list alike, so neither shows "ready" for a setup
/// that is not doing all it was asked. Other capabilities are not dragged down with it.
#[tokio::test]
async fn a_synced_folder_holding_files_back_makes_the_sync_capability_and_the_setup_read_degraded() {
    let bench = Bench::new();
    let service = bench.service();
    let mut chosen = change("Dev");
    chosen.capabilities = vec!["data.sync".into(), "run.health_logs".into()];
    let synced = DeclaredResource {
        id: "dev".into(),
        kind: Kind::Environment,
        spec: json!({
            "image": "example/dev",
            "sync": [{ "binding": "code", "target": "/workspace", "path": "/chosen/code", "read_only": false, "continuous": true, "conflicts": "keep_both" }],
        }),
        requires: Vec::new(),
        owner: None,
    };
    let plan = service.plan(PlanIntent::Create(SetupDraft { change: chosen, resources: vec![synced] })).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    // Ready, as a refresh that checked it leaves it, read back by a fresh engine.
    let store = Store::new(&bench.setups);
    let mut registry = store.load().unwrap();
    registry.instances.get_mut(&plan.setup_id).unwrap().health = super::model::Health::Ready;
    store.save(&registry).unwrap();
    let service = bench.service();
    let health_of = |detail: &views::Detail, id: &str| detail.setup.capabilities.iter().find(|capability| capability.id == id).map(|capability| capability.health);
    let listed = |service: &Service| service.list().unwrap().into_iter().find(|summary| summary.setup_id == plan.setup_id).and_then(|summary| summary.health);
    let ready = service.get(&plan.setup_id).unwrap();
    assert_eq!(ready.setup.summary.health, Some(dto::CapabilityHealth::Ready));
    assert_eq!(health_of(&ready, "data.sync"), Some(dto::CapabilityHealth::Ready));
    assert_eq!(listed(&service), Some(dto::CapabilityHealth::Ready));

    let record = bench.setups.join("projects").join(&plan.setup_id).join("sync").join("dev-code.json");
    fs::create_dir_all(record.parent().unwrap()).unwrap();
    let held = json!({ "at": 1_760_000_000, "held": [{ "path": "notes.txt", "reason": "notes.txt changed in both places, so both copies are kept." }], "heldTotal": 1 });
    fs::write(&record, json!({ "common": {}, "unknown": [], "last": held }).to_string()).unwrap();
    let detail = service.get(&plan.setup_id).unwrap();
    let sync = detail.setup.capabilities.iter().find(|capability| capability.id == "data.sync").unwrap();
    assert_eq!(sync.health, dto::CapabilityHealth::Degraded);
    assert!(sync.detail.as_deref().unwrap_or_default().contains("notes.txt changed in both places"), "{:?}", sync.detail);
    assert_eq!(health_of(&detail, "run.health_logs"), Some(dto::CapabilityHealth::Ready), "only the sync is degraded");
    assert_eq!(detail.setup.summary.health, Some(dto::CapabilityHealth::Degraded));
    assert_eq!(detail.notes.len(), 1, "and the note is still there: {:?}", detail.notes);
    assert_eq!(listed(&service), Some(dto::CapabilityHealth::Degraded), "the list says what the setup's own view says");

    // A clean pass puts both back.
    fs::write(&record, json!({ "common": {}, "unknown": [], "last": { "at": 1_760_000_100, "held": [], "heldTotal": 0 } }).to_string()).unwrap();
    let clean = service.get(&plan.setup_id).unwrap();
    assert_eq!(health_of(&clean, "data.sync"), Some(dto::CapabilityHealth::Ready));
    assert_eq!(clean.setup.summary.health, Some(dto::CapabilityHealth::Ready));
    assert_eq!(listed(&service), Some(dto::CapabilityHealth::Ready));
}

#[tokio::test]
async fn l01_running_one_template_twice_keeps_two_separate_setups() {
    let bench = Bench::new();
    let service = bench.service();
    let (first, _) = created(&service, "Site", vec![resource("web", &[]), resource("db", &["web"])]).await;
    let (second, _) = created(&service, "Site", vec![resource("web", &[]), resource("db", &["web"])]).await;
    assert_ne!(first.setup_id, second.setup_id);
    let registry = service.snapshot();
    let ids = registry
        .instances
        .values()
        .flat_map(|instance| instance.resources.values().map(|resource| resource.runtime_id.clone().unwrap()))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 4, "every resource of both setups is its own");
    assert_eq!(bench.creates(), 4);
    let listed = service.list().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|summary| summary.state == dto::InstanceState::Running && !summary.adopted_legacy));
}

#[tokio::test]
async fn l02_concurrent_requests_join_the_same_operation_or_get_a_precise_conflict() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![resource("web", &[])]).await;
    let setup = plan.setup_id.clone();
    let update = |image: &str| PlanIntent::Update {
        setup: setup.clone(),
        draft: SetupDraft {
            change: change("Site"),
            resources: vec![DeclaredResource { spec: json!({ "image": image }), ..resource("web", &[]) }],
        },
    };
    let from_ui = service.plan(update("example/web:2")).unwrap();
    let from_cli = service.plan(update("example/web:3")).unwrap();
    assert_eq!(from_ui.base_revision, from_cli.base_revision);
    bench.fake.provider.lock().unwrap().gated.insert("web".into());

    let first = op();
    let submitted = service.submit(&from_ui, &first, from_ui.base_revision, no_secrets()).unwrap();
    assert!(!submitted.joined);
    let runner = {
        let service = service.clone();
        let first = first.clone();
        tokio::spawn(async move { service.run(&first).await })
    };
    bench.fake.entered.notified().await;

    // The same request again, from either window: the same operation.
    let again = service.submit(&from_ui, &first, from_ui.base_revision, no_secrets()).unwrap();
    assert!(again.joined && again.operation_id == first);
    let same_plan_new_id = service.submit(&from_ui, &op(), from_ui.base_revision, no_secrets()).unwrap();
    assert!(same_plan_new_id.joined && same_plan_new_id.operation_id == first);
    // A different change while it runs: a precise conflict naming the running operation.
    let busy = service.submit(&from_cli, &op(), from_cli.base_revision, no_secrets()).unwrap_err();
    assert_eq!(busy.code, "setup_busy");
    assert_eq!(busy.operation.as_deref(), Some(first.as_str()));
    // Planning against a busy setup is refused the same way.
    assert_eq!(service.plan(update("example/web:4")).unwrap_err().code, "setup_busy");

    bench.fake.gate.add_permits(1);
    runner.await.unwrap().unwrap();
    assert_eq!(state_of(&service, &first), OperationState::Completed);
    // The other change was reviewed against the old revision: refused for review, not applied.
    let stale = service.submit(&from_cli, &op(), from_cli.base_revision, no_secrets()).unwrap_err();
    assert_eq!(stale.code, "revision_conflict");
    assert_eq!(service.snapshot().operations.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l02_simultaneous_submits_from_many_threads_make_one_operation() {
    let bench = Bench::new();
    let service = bench.service();
    let plan = service.plan(create("Site", vec![resource("web", &[])])).unwrap();
    let shared = op();
    let start = Arc::new(tokio::sync::Barrier::new(8));
    // Half send the same operation ID, half their own: all of them get one operation.
    let tasks = (0..8)
        .map(|index| {
            let service = service.clone();
            let plan = plan.clone();
            let operation = if index % 2 == 0 { shared.clone() } else { op() };
            let start = start.clone();
            tokio::spawn(async move {
                start.wait().await;
                service.submit(&plan, &operation, 0, BTreeMap::new())
            })
        })
        .collect::<Vec<_>>();
    let mut ids = std::collections::BTreeSet::new();
    let mut joined = 0;
    for task in tasks {
        let submitted = task.await.unwrap().unwrap();
        ids.insert(submitted.operation_id);
        joined += submitted.joined as usize;
    }
    assert_eq!(ids.len(), 1, "every request joined the first operation");
    assert_eq!(joined, 7);
    assert_eq!(service.snapshot().operations.len(), 1);
    assert_eq!(service.snapshot().instances.len(), 1);
}

#[tokio::test]
async fn l03_a_crash_after_the_effect_before_the_receipt_is_reconciled_without_a_duplicate() {
    let bench = Bench::new();
    let service = bench.service();
    let plan = service.plan(create("Site", vec![resource("web", &[]), resource("db", &["web"])])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    // Saves: start, the intent for `web`, then the receipt for `web`, which fails.
    service.store().faults.fail_after(2);
    let error = service.run(&operation).await.unwrap_err();
    assert_eq!(error.code, "durable_storage_unavailable");
    assert_eq!(bench.creates(), 1, "web was created before the receipt could be saved");
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    let disk = bench.on_disk();
    assert_eq!(disk.operations[&operation].state, OperationState::Applying, "no false completion on disk");
    assert_eq!(disk.operations[&operation].steps[0].state, StepState::Applying, "the intent was kept");
    drop(service);

    // Restart: the interrupted step is unknown until it is looked at.
    let service = bench.service();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    service.reconcile_all().await;
    let registry = service.snapshot();
    let found = &registry.operations[&operation];
    assert_eq!(found.state, OperationState::Failed, "db still has to run");
    assert_eq!(found.steps[0].state, StepState::Done);
    assert!(found.steps[0].receipt.as_ref().unwrap().adopted);
    assert_eq!(found.steps[1].state, StepState::Pending);
    let web = &registry.instances[&plan.setup_id].resources["web"];
    assert_eq!(web.runtime_id.as_deref(), Some("fake-1"));

    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.creates(), 2, "web once, db once: nothing was created twice");
    assert_eq!(service.snapshot().instances[&plan.setup_id].lifecycle, Lifecycle::Running);
}

/// PROVES the route `template continue` takes after an unknown outcome does nothing twice. The
/// CLI asks the engine to reconcile first (`setup_action reconcile`), so it can say what the
/// cut-off step left behind before anything runs; a change that then reads failed is retried,
/// and only its unfinished steps run. A second continue finds the change finished: the engine
/// refuses to retry it and checking it again changes nothing.
#[tokio::test]
async fn l03b_continuing_after_an_unknown_outcome_reconciles_first_and_a_second_continue_does_nothing_twice() {
    let bench = Bench::new();
    let service = bench.service();
    let plan = service.plan(create("Site", vec![resource("web", &[]), resource("db", &["web"])])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    service.store().faults.fail_after(2);
    assert!(service.run(&operation).await.is_err());
    assert_eq!(bench.creates(), 1, "web was created before the receipt could be saved");
    drop(service);

    let service = bench.service();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    let checked = service.reconcile(&operation).await.unwrap();
    assert_eq!(checked.state, dto::OperationState::Failed, "web was found made and recorded; db still has to run");
    assert_eq!(bench.creates(), 1, "looking made nothing");
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.creates(), 2, "web once, db once: nothing was created twice");

    // A second continue: the change finished, so there is nothing to carry on. The engine says
    // so rather than running anything, and checking it again changes nothing either.
    assert_eq!(service.prepare_retry(&operation).unwrap_err().code, "not_retryable");
    assert_eq!(service.reconcile(&operation).await.unwrap().state, dto::OperationState::Completed);
    assert_eq!(bench.creates(), 2);
}

#[tokio::test]
async fn l04_a_failed_write_keeps_the_intent_and_never_claims_completion() {
    let bench = Bench::new();
    let service = bench.service();
    let plan = service.plan(create("Site", vec![resource("web", &[])])).unwrap();

    // The operation itself can't be saved: nothing is claimed and nothing runs.
    service.store().faults.fail_after(0);
    let operation = op();
    assert_eq!(service.submit(&plan, &operation, 0, no_secrets()).unwrap_err().code, "durable_storage_unavailable");
    assert!(service.snapshot().operations.is_empty() && service.snapshot().instances.is_empty());
    assert!(!service.store().path().exists());

    // The step's intent can't be saved: the handler is never called.
    service.store().faults.heal();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    service.store().faults.fail_after(1);
    assert_eq!(service.run(&operation).await.unwrap_err().code, "durable_storage_unavailable");
    assert!(bench.calls().is_empty());
    let shown = service.operation(&operation, 0).unwrap();
    assert_eq!(shown.state, dto::OperationState::Failed);
    assert!(shown.error.as_ref().unwrap().retryable);
    assert_ne!(bench.on_disk().operations[&operation].state, OperationState::Completed);

    // After the disk recovers, a restart and a retry finish it once.
    service.store().faults.heal();
    drop(service);
    let service = bench.service();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.creates(), 1);
}

#[tokio::test]
async fn l05_progress_stays_readable_with_a_resumable_cursor_and_an_explicit_gap() {
    let bench = Bench::new();
    let service = bench.service();
    let many = (0..110).map(|index| resource(&format!("r{index}"), &[])).collect();
    let (_, operation) = created(&service, "Big", many).await;
    let all = service.operation(&operation, 0).unwrap();
    assert!(all.truncated, "older events were dropped and the reader is told so");
    assert!(all.events.len() <= super::journal::EVENT_LIMIT);
    assert_eq!(all.events.last().unwrap().cursor + 1, all.next_cursor);
    let rest = service.operation(&operation, all.next_cursor).unwrap();
    assert!(rest.events.is_empty() && !rest.truncated && rest.next_cursor == all.next_cursor);
    let recent = service.operation(&operation, all.next_cursor - 3).unwrap();
    assert_eq!(recent.events.len(), 3);
    assert!(!recent.truncated);
    assert_eq!(service.operation(&operation, all.next_cursor + 5).unwrap_err().code, "invalid_cursor");
    // Closing the window or the CLI loses nothing: a new engine reads the same progress.
    drop(service);
    let again = bench.service().operation(&operation, all.next_cursor - 3).unwrap();
    assert_eq!(again.events, recent.events);
}

#[tokio::test]
async fn l06_cancelling_a_running_provider_call_is_looked_at_at_once_and_keeps_ownership() {
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().hang.insert("db".into());
    let plan = service.plan(create("Site", vec![resource("web", &[]), resource("db", &["web"])])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    let runner = {
        let service = service.clone();
        let operation = operation.clone();
        tokio::spawn(async move { service.run(&operation).await })
    };
    // Wait for db's call: web's call came first.
    bench.fake.entered.notified().await;
    while !bench.calls().contains(&"create:db".to_owned()) {
        bench.fake.entered.notified().await;
    }
    let cancelling = service.cancel(&operation).unwrap();
    assert_eq!(cancelling.state, dto::OperationState::Cancelling);
    runner.await.unwrap().unwrap();
    // A cancelled call may have taken effect, so the engine looks before it says anything, and
    // it looks at once, while it is running: db was never created, so the cancellation completes
    // as a cancellation rather than reading "outcome unknown" until someone asks. (Found on a real
    // engine, where a cancel from the app left the CLI saying the outcome was not known.)
    let done = service.operation(&operation, 0).unwrap();
    assert_eq!(done.state, dto::OperationState::Failed);
    assert_eq!(done.error.as_ref().unwrap().code, "operation_cancelled");
    let registry = service.snapshot();
    assert!(registry.instances[&plan.setup_id].resources.contains_key("web"), "web stays tracked");
    assert!(registry.instances[&plan.setup_id].current_operation.is_none());
    assert_eq!(bench.creates(), 1);
    // Looking again changes nothing.
    assert_eq!(service.reconcile(&operation).await.unwrap().state, dto::OperationState::Failed);
    assert_eq!(bench.creates(), 1);
}

#[tokio::test]
async fn l06_cancelling_before_or_between_steps_changes_nothing_more() {
    let bench = Bench::new();
    let service = bench.service();
    let plan = service.plan(create("Site", vec![resource("web", &[])])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    service.cancel(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Cancelled);
    assert!(bench.calls().is_empty());

    // A gated call is cancelled before it acts: nothing exists, nothing is unknown.
    let plan = service.plan(create("Other", vec![resource("web", &[])])).unwrap();
    bench.fake.provider.lock().unwrap().gated.insert("web".into());
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    let runner = {
        let service = service.clone();
        let operation = operation.clone();
        tokio::spawn(async move { service.run(&operation).await })
    };
    bench.fake.entered.notified().await;
    service.cancel(&operation).unwrap();
    runner.await.unwrap().unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Cancelled);
    assert_eq!(bench.creates(), 0);
}

#[tokio::test]
async fn l08_a_partial_failure_retries_only_the_missing_steps() {
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().fail.insert("db".into(), 1);
    let plan = service
        .plan(create("Site", vec![resource("web", &[]), resource("db", &["web"]), resource("api", &["db"])]))
        .unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    let registry = service.snapshot();
    let found = &registry.operations[&operation];
    assert_eq!(found.state, OperationState::Failed);
    assert_eq!(found.steps.iter().map(|step| step.state).collect::<Vec<_>>(), [StepState::Done, StepState::Failed, StepState::Pending]);
    assert!(registry.instances[&plan.setup_id].resources.contains_key("web"), "the healthy resource is kept");
    let shown = service.operation(&operation, 0).unwrap();
    assert!(shown.error.as_ref().unwrap().next_actions.contains(&dto::NextAction::Retry));

    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.calls().iter().filter(|call| *call == "create:web").count(), 1);
    assert_eq!(bench.creates(), 3);
}

#[tokio::test]
async fn l18_a_resource_deleted_outside_is_drift_and_is_only_recreated_by_a_reviewed_repair() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![resource("web", &[])]).await;
    bench.fake.provider.lock().unwrap().resources.clear();
    let detail = service.refresh(&plan.setup_id).await.unwrap();
    let web = &detail.setup.resources[0];
    assert_eq!(web.observed, dto::ResourceObserved::Missing);
    assert!(web.drift.as_deref().unwrap().contains("outside Yougori"));
    assert_eq!(detail.setup.summary.health, Some(dto::CapabilityHealth::Degraded));
    assert_eq!(bench.creates(), 1, "refreshing never recreates anything");

    let repair = service.plan(PlanIntent::Repair { setup: plan.setup_id.clone() }).unwrap();
    assert_eq!(repair.steps.len(), 1);
    assert_eq!((repair.steps[0].action, repair.steps[0].generation), (Action::Create, 2));
    service.apply(&repair, &op(), no_secrets()).await.unwrap();
    assert_eq!(bench.creates(), 2);
    let registry = service.snapshot();
    let web = &registry.instances[&plan.setup_id].resources["web"];
    assert_eq!((web.generation, web.drift.clone(), web.observed), (2, None, Observed::Running));
}

#[tokio::test]
async fn l19_remove_then_replay_cannot_bring_a_setup_back() {
    let bench = Bench::new();
    let service = bench.service();
    let (create_plan, create_operation) = created(&service, "Site", vec![resource("web", &[])]).await;
    let setup = create_plan.setup_id.clone();
    let stale_update = service
        .plan(PlanIntent::Update {
            setup: setup.clone(),
            draft: SetupDraft { change: change("Site"), resources: vec![DeclaredResource { spec: json!({"image": "v2"}), ..resource("web", &[]) }] },
        })
        .unwrap();
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(!service.snapshot().instances.contains_key(&setup), "only the tombstone is left");
    assert!(service.snapshot().tombstones.contains_key(&setup));
    assert!(service.list().unwrap().is_empty());
    assert_eq!(service.get(&setup).unwrap_err().code, "setup_removed");

    // Replaying the original request joins its finished operation; nothing runs again.
    let replay = service.submit(&create_plan, &create_operation, 0, no_secrets()).unwrap();
    assert!(replay.joined);
    service.run(&create_operation).await.unwrap();
    assert_eq!(bench.creates(), 1);
    // The same plan under a new ID, or an older reviewed change, is refused.
    assert_eq!(service.submit(&create_plan, &op(), 0, no_secrets()).unwrap_err().code, "setup_removed");
    assert_eq!(service.submit(&stale_update, &op(), stale_update.base_revision, no_secrets()).unwrap_err().code, "setup_removed");
    assert_eq!(service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap_err().code, "setup_removed");
    // A restart keeps the tombstone.
    drop(service);
    let service = bench.service();
    assert_eq!(service.submit(&create_plan, &op(), 0, no_secrets()).unwrap_err().code, "setup_removed");
}

#[tokio::test]
async fn l19_a_removed_resource_keeps_a_tombstone_against_old_generations() {
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().retain.insert("data".into());
    let (create_plan, _) = created(&service, "Site", vec![resource("data", &[]), resource("web", &[])]).await;
    let setup = create_plan.setup_id.clone();
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    assert!(remove.notes.iter().any(|note| note.contains("Data is kept")));
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let registry = service.snapshot();
    let instance = &registry.instances[&setup];
    assert_eq!(instance.lifecycle, Lifecycle::Retained, "kept data keeps the setup visible");
    assert_eq!(instance.resources["data"].desired, Desired::Absent);
    assert!(instance.resources["data"].retained_data);
    assert!(!instance.resources.contains_key("web"));
    assert!(registry.tombstones.contains_key(&format!("{setup}/web")));

    // An old step for web's first generation, dressed as a current update, is still refused.
    let mut replay = create_plan.clone();
    replay.intent = super::journal::OperationKind::Update;
    replay.base_revision = instance.revision;
    replay.change = Some(change("Site"));
    replay.digest = plan_digest(&replay);
    let refused = service.submit(&replay, &op(), replay.base_revision, no_secrets()).unwrap_err();
    assert_eq!(refused.code, "resource_removed");
    assert_eq!(bench.creates(), 2);
}

#[tokio::test]
async fn stop_and_remove_never_touch_a_borrowed_resource() {
    let bench = Bench::new();
    let service = bench.service();
    let (owner_plan, _) = created(&service, "Model", vec![resource("shared", &[])]).await;
    let owner = owner_plan.setup_id.clone();
    let borrowing = DeclaredResource {
        owner: Some(OwnerRef { setup: owner.clone(), resource: "shared".into() }),
        ..resource("model", &[])
    };
    let (user_plan, _) = created(&service, "App", vec![borrowing, resource("app", &["model"])]).await;
    let user = user_plan.setup_id.clone();
    assert_eq!(user_plan.steps.iter().find(|step| step.resource == "model").unwrap().action, Action::Attach);
    assert_eq!(bench.creates(), 2, "shared and app; borrowing created nothing");
    assert!(!bench.calls().contains(&"create:model".to_owned()));
    assert_eq!(service.snapshot().instances[&owner].resources["shared"].borrowers.len(), 1);
    let shared_id = service.snapshot().instances[&owner].resources["shared"].runtime_id.clone().unwrap();
    assert_eq!(service.snapshot().instances[&user].resources["model"].runtime_id.as_deref(), Some(shared_id.as_str()), "the binding points at the owner's resource");

    let stop = service.plan(PlanIntent::Stop { setup: user.clone() }).unwrap();
    assert_eq!(stop.steps.iter().map(|step| step.resource.as_str()).collect::<Vec<_>>(), ["app"]);
    assert!(stop.notes.iter().any(|note| note.contains("borrowed")));
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    assert!(bench.fake.provider.lock().unwrap().resources[&shared_id].running, "the owner's resource keeps running");
    assert_eq!(service.snapshot().instances[&user].lifecycle, Lifecycle::Stopped);

    // The owner can't be removed while another setup uses it.
    assert_eq!(service.plan(PlanIntent::Remove { setup: owner.clone() }).unwrap_err().code, "resource_in_use");

    let remove = service.plan(PlanIntent::Remove { setup: user.clone() }).unwrap();
    let actions = remove.steps.iter().map(|step| (step.resource.as_str(), step.action)).collect::<Vec<_>>();
    assert_eq!(actions, [("app", Action::Remove), ("model", Action::Detach)]);
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(bench.fake.provider.lock().unwrap().resources.contains_key(&shared_id), "detach leaves the resource alone");
    assert!(!bench.calls().contains(&"remove:shared".to_owned()));
    assert!(!bench.calls().iter().any(|call| call.ends_with(":model")), "no handler acted on the binding");
    assert!(service.snapshot().instances[&owner].resources["shared"].borrowers.is_empty());
    let remove_owner = service.plan(PlanIntent::Remove { setup: owner.clone() }).unwrap();
    service.apply(&remove_owner, &op(), no_secrets()).await.unwrap();
    assert!(!bench.fake.provider.lock().unwrap().resources.contains_key(&shared_id));
}

/// Supports only what every handler must: validate, observe, apply.
struct Minimal;

impl ResourceHandler for Minimal {
    fn kind(&self) -> Kind {
        Kind::Volume
    }
    fn validate(&self, _: &Value) -> Result<(), HandlerError> {
        Ok(())
    }
    fn observe<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async { Ok(Observation::Unknown { reason: "Not checked.".into() }) })
    }
    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            Ok(Receipt {
                runtime_id: Some(format!("volume-{}", context.resource)),
                observed: Observed::Present,
                retained_data: true,
                cost: Cost::Unknown,
                at: super::model::now(),
                adopted: false,
            })
        })
    }
}

/// Takes work in, as a setup's jobs do, and keeps each change to its new work it was asked for.
#[derive(Default)]
struct TakesWork {
    changes: std::sync::Mutex<Vec<String>>,
}

impl ResourceHandler for TakesWork {
    fn kind(&self) -> Kind {
        Kind::Job
    }
    fn validate(&self, _: &Value) -> Result<(), HandlerError> {
        Ok(())
    }
    fn stoppable(&self) -> bool {
        false
    }
    fn takes_work(&self) -> bool {
        true
    }
    fn observe<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async { Ok(Observation::Unknown { reason: "Not checked.".into() }) })
    }
    fn apply<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async { Ok(Receipt { runtime_id: Some("job-1".into()), observed: Observed::Running, retained_data: true, cost: Cost::Free, at: super::model::now(), adopted: false }) })
    }
    fn admission<'a>(&'a self, context: &'a StepContext, change: Admission) -> HandlerFuture<'a, String> {
        Box::pin(async move {
            self.changes.lock().unwrap().push(format!("{}: {change:?}", context.resource));
            Ok(match change {
                Admission::Pause { .. } => "New work is paused.".to_owned(),
                Admission::Resume => "New work is taken again.".to_owned(),
            })
        })
    }
}

/// PROVES pausing new work is reviewed before anything changes and applied only with that very
/// review: running work finishes unless the person chose otherwise, nothing is deleted, and
/// resuming brings it back. A review of something else applies nothing, and a setup where nothing
/// takes work in is refused plainly.
#[tokio::test]
async fn new_work_is_paused_and_resumed_only_as_reviewed() {
    let mut bench = Bench::new();
    let worker = Arc::new(TakesWork::default());
    bench.extra.push(worker.clone());
    let service = bench.service();
    let job = DeclaredResource { id: "build".into(), kind: Kind::Job, spec: json!({}), requires: Vec::new(), owner: None };
    let (plan, _) = created(&service, "Farm", vec![job, resource("app", &[])]).await;
    let setup = plan.setup_id.clone();
    let pause = Admission::Pause { drain: true };
    let review = service.admission_review(&setup, pause).unwrap();
    assert_eq!(review["parts"], json!(["build"]), "only what takes work in is paused");
    let notes = review["notes"].to_string();
    assert!(notes.contains("Jobs already running finish") && notes.contains("Nothing is deleted"), "{notes}");
    assert!(worker.changes.lock().unwrap().is_empty(), "a review changes nothing");

    let stopping = service.admission_review(&setup, Admission::Pause { drain: false }).unwrap();
    assert!(stopping["notes"].to_string().contains("asked to stop, as a cancel asks"), "{stopping}");
    let wrong = service.admission(&setup, pause, stopping["planDigest"].as_str().unwrap()).await.unwrap_err();
    assert_eq!(wrong.code, "plan_changed", "draining or not is part of what was reviewed");
    assert!(worker.changes.lock().unwrap().is_empty());

    let done = service.admission(&setup, pause, review["planDigest"].as_str().unwrap()).await.unwrap();
    assert_eq!(done["applied"], true);
    assert_eq!(*worker.changes.lock().unwrap(), ["build: Pause { drain: true }"]);
    let resume = service.admission_review(&setup, Admission::Resume).unwrap();
    service.admission(&setup, Admission::Resume, resume["planDigest"].as_str().unwrap()).await.unwrap();
    assert_eq!(worker.changes.lock().unwrap().last().map(String::as_str), Some("build: Resume"));
    assert!(service.snapshot().instances[&setup].resources.contains_key("build"), "nothing was removed");

    let (site, _) = created(&service, "Site", vec![resource("web", &[])]).await;
    assert_eq!(service.admission_review(&site.setup_id, pause).unwrap_err().code, "unsupported_here");
}

/// A store that says it lives in a realm of its own, as a setup's jobs and store do.
struct InRealm;

impl ResourceHandler for InRealm {
    fn kind(&self) -> Kind {
        Kind::ArtifactStore
    }
    fn validate(&self, _: &Value) -> Result<(), HandlerError> {
        Ok(())
    }
    fn stoppable(&self) -> bool {
        false
    }
    fn observe<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async { Ok(Observation::Unknown { reason: "Not checked.".into() }) })
    }
    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            Ok(Receipt { runtime_id: Some(format!("{}/artifacts", context.setup)), observed: Observed::Present, retained_data: true, cost: Cost::Free, at: super::model::now(), adopted: false })
        })
    }
    fn remove<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async { Ok(Receipt { runtime_id: None, observed: Observed::Missing, retained_data: true, cost: Cost::Free, at: super::model::now(), adopted: false }) })
    }
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move { Ok(BTreeMap::from([("realm_id".to_owned(), format!("realm-{}", context.setup))])) })
    }
}

/// PROVES a setup records the Grid Core realm its parts live in, and keeps that reference once the
/// part is removed: the realm still holds what the part made, until the setup itself goes.
#[tokio::test]
async fn a_setup_records_the_realm_its_parts_live_in_and_keeps_it_until_the_setup_goes() {
    let mut bench = Bench::new();
    bench.extra.push(Arc::new(InRealm));
    let service = bench.service();
    let store = DeclaredResource { id: "results".into(), kind: Kind::ArtifactStore, spec: json!({}), requires: Vec::new(), owner: None };
    let (plan, _) = created(&service, "Farm", vec![store, resource("app", &[])]).await;
    let realm = format!("realm-{}", plan.setup_id);
    assert_eq!(service.snapshot().instances[&plan.setup_id].realms, [realm.clone()]);

    let part = service.plan(PlanIntent::Part { setup: plan.setup_id.clone(), resource: "results".into(), action: Action::Remove }).unwrap();
    service.apply(&part, &op(), no_secrets()).await.unwrap();
    assert_eq!(service.snapshot().instances[&plan.setup_id].realms, [realm], "the realm outlives the part that used it");
    assert!(bench.on_disk().instances[&plan.setup_id].outputs.is_empty(), "a setup made without a template declares no outputs");
}

#[tokio::test]
async fn unsupported_kinds_and_operations_are_refused_with_a_reason_never_a_pretend_success() {
    let mut bench = Bench::new();
    let service = bench.service();
    let volume = DeclaredResource { kind: Kind::Volume, ..resource("data", &[]) };
    let refused = service.plan(create("Site", vec![volume.clone()])).unwrap_err();
    assert_eq!(refused.code, "unsupported_resource");
    assert!(service.snapshot().instances.is_empty());

    bench.extra.push(Arc::new(Minimal));
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![volume]).await;
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    assert!(stop.notes.iter().any(|note| note.contains("may still cost money")));
    let operation = op();
    service.apply(&stop, &operation, no_secrets()).await.unwrap();
    let registry = service.snapshot();
    let found = &registry.operations[&operation];
    assert_eq!(found.state, OperationState::Failed);
    let error = found.steps[0].error.as_ref().unwrap();
    assert_eq!(error.code, "unsupported_operation");
    assert!(!error.retryable);
    assert_ne!(registry.instances[&plan.setup_id].lifecycle, Lifecycle::Stopped);
}

#[tokio::test]
async fn secrets_never_reach_the_registry() {
    let bench = Bench::new();
    let service = bench.service();
    let leaking = DeclaredResource { spec: json!({ "db": { "password": "S3CRET-VALUE" } }), ..resource("db", &[]) };
    let refused = service.plan(create("Site", vec![leaking])).unwrap_err();
    assert_eq!(refused.code, "secret_in_plan");
    let mut answers = change("Site");
    answers.answers.insert("admin".into(), json!({ "token": "S3CRET-VALUE" }));
    let refused = service
        .plan(PlanIntent::Create(SetupDraft { change: answers, resources: vec![resource("web", &[])] }))
        .unwrap_err();
    assert_eq!(refused.code, "secret_in_plan");

    let referenced = DeclaredResource { spec: json!({ "db": { "password": { "secretRef": "db-password" } } }), ..resource("db", &[]) };
    let plan = service.plan(create("Site", vec![referenced])).unwrap();
    let secrets = BTreeMap::from([("db-password".to_owned(), "S3CRET-VALUE".to_owned())]);
    service.apply(&plan, &op(), secrets).await.unwrap();
    let saved = fs::read_to_string(service.store().path()).unwrap();
    assert!(!saved.contains("S3CRET-VALUE"));
    assert!(saved.contains("db-password"));
}

#[tokio::test]
async fn a_restart_settles_operations_a_previous_engine_left_running() {
    let bench = Bench::new();
    let service = bench.service();
    let planned = service.plan(create("Planned", vec![resource("web", &[])])).unwrap();
    let never_started = op();
    service.submit(&planned, &never_started, 0, no_secrets()).unwrap();
    drop(service);
    let service = bench.service();
    let progress = service.operation(&never_started, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::Failed);
    assert!(progress.error.as_ref().unwrap().message.contains("Nothing was changed"));
    assert!(bench.calls().is_empty(), "nothing restarts by itself");

    // A provider that can't be reached leaves the outcome unknown, not failed.
    let plan = service.plan(create("Lost", vec![resource("web", &[])])).unwrap();
    let operation = op();
    bench.fake.provider.lock().unwrap().lose_answer.insert("web".into());
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    bench.fake.provider.lock().unwrap().unreachable = true;
    service.reconcile(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    assert_eq!(service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap_err().code, "setup_busy");
    bench.fake.provider.lock().unwrap().unreachable = false;
    service.reconcile(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "the lost answer was found by its label");
    assert_eq!(bench.creates(), 1);
}

#[tokio::test]
async fn a_damaged_registry_is_reported_and_left_untouched() {
    let bench = Bench::new();
    fs::create_dir_all(&bench.setups).unwrap();
    let path = bench.setups.join("registry.json");
    fs::write(&path, b"{\"schema\":1,\"revision\":").unwrap();
    let service = bench.service();
    assert_eq!(service.availability().unwrap().code, "registry_unreadable");
    assert_eq!(service.list().unwrap_err().code, "registry_unreadable");
    assert_eq!(service.plan(create("Site", vec![resource("web", &[])])).unwrap_err().code, "registry_unreadable");
    assert_eq!(fs::read(&path).unwrap(), b"{\"schema\":1,\"revision\":");
}

#[tokio::test]
async fn adopted_grids_are_listed_read_only_and_a_second_grid_of_a_kind_goes_beside_them() {
    let mut bench = Bench::new();
    fs::create_dir_all(bench.data.join("grid")).unwrap();
    fs::write(bench.data.join("grid/hub.json"), br#"{"password":"SECRET"}"#).unwrap();
    fs::create_dir_all(bench.data.join("swarm")).unwrap();
    fs::write(bench.data.join("swarm/workers.json"), br#"{"w1":{"state":"running"}}"#).unwrap();
    let grids = Arc::new(FakeHandler::new(Kind::Grid));
    bench.extra.push(grids.clone());
    let service = bench.service();

    let listed = service.list().unwrap();
    assert_eq!(listed.len(), 2);
    let swarm = listed.iter().find(|summary| summary.profile == Some(dto::GridProfile::SwarmMiningGrid)).unwrap();
    assert_eq!(swarm.state, dto::InstanceState::Stopped);
    assert!(listed.iter().all(|summary| summary.adopted_legacy));
    let hub = listed.iter().find(|summary| summary.profile == Some(dto::GridProfile::NeoGrid)).unwrap();
    let detail = service.get(&hub.setup_id).unwrap();
    assert!(detail.setup.actions.is_empty() && detail.readable);
    for intent in [PlanIntent::Start { setup: swarm.setup_id.clone() }, PlanIntent::Remove { setup: hub.setup_id.clone() }] {
        assert_eq!(service.plan(intent).unwrap_err().code, "legacy_managed");
    }

    // A second Neo Grid goes beside the one found here: its product gives it an instance of its
    // own, so the grid found here is never touched. Planning it writes nothing.
    let before = fs::read_dir(&bench.data).unwrap().count();
    let grid = DeclaredResource { kind: Kind::Grid, spec: json!({ "profile": "neo_grid" }), ..resource("grid", &[]) };
    service.plan(create("Office grid", vec![grid.clone()])).unwrap();
    assert!(service.snapshot().instances.is_empty());
    assert!(!bench.setups.join("registry.json").exists());
    assert_eq!(fs::read_dir(&bench.data).unwrap().count(), before);
    assert!(grids.provider.lock().unwrap().calls.is_empty());

    // So do two Access Grids, each in a setup of its own.
    let access = DeclaredResource { spec: json!({ "profile": "access_grid" }), ..grid };
    created(&service, "Access", vec![access.clone()]).await;
    created(&service, "Access again", vec![access]).await;
    let swarm_files = fs::read(bench.data.join("swarm/workers.json")).unwrap();
    assert_eq!(swarm_files, br#"{"w1":{"state":"running"}}"#);
}

#[tokio::test]
async fn a_grid_adopted_in_two_plans_before_either_applied_is_refused_at_apply() {
    let mut bench = Bench::new();
    bench.extra.push(Arc::new(FakeHandler::new(Kind::Grid)));
    let service = bench.service();
    let adopting = DeclaredResource { kind: Kind::Grid, spec: json!({ "profile": "sandbox_grid", "mode": "create", "adopted": true, "instance": "i-0000abcd" }), ..resource("grid", &[]) };
    let first = service.plan(create("Desks", vec![adopting.clone()])).unwrap();
    let second = service.plan(create("Desks too", vec![adopting])).unwrap();
    service.apply(&first, &op(), no_secrets()).await.unwrap();
    let refused = service.submit(&second, &op(), 0, no_secrets()).unwrap_err();
    assert_eq!(refused.code, "unsupported_here");
    assert!(refused.message.contains("already belongs to a setup"), "{refused:?}");
    assert_eq!(service.snapshot().instances.len(), 1);
}

#[test]
fn views_follow_the_shared_contract() {
    let diagnostic = Diagnostic::new("outcome_unknown", "Check it.").operation("op-1").next(&["reconcile", "cancel", "retry", "plan", "wait"]);
    let shown = views::api_error(&diagnostic);
    assert_eq!(
        shown.next_actions,
        [
            dto::NextAction::Reconcile { operation: "op-1".into() },
            dto::NextAction::Cancel { operation: "op-1".into() },
            dto::NextAction::Retry,
            dto::NextAction::Review,
        ]
    );
    assert_eq!(views::operation_state(OperationState::Cancelled), dto::OperationState::Failed);
    let text = serde_json::to_string(&shown).unwrap();
    assert!(text.contains("\"nextActions\""));
}

#[tokio::test]
async fn l10_a_removal_planned_before_a_new_borrower_is_refused() {
    let bench = Bench::new();
    let service = bench.service();
    let (owner_plan, _) = created(&service, "Model", vec![resource("shared", &[])]).await;
    let owner = owner_plan.setup_id.clone();
    let stale_remove = service.plan(PlanIntent::Remove { setup: owner.clone() }).unwrap();
    let borrowing = DeclaredResource { owner: Some(OwnerRef { setup: owner.clone(), resource: "shared".into() }), ..resource("model", &[]) };
    created(&service, "App", vec![borrowing.clone()]).await;
    let refused = service.submit(&stale_remove, &op(), stale_remove.base_revision, no_secrets()).unwrap_err();
    assert_eq!(refused.code, "revision_conflict", "a new borrower moves the owner's revision on");
    assert_eq!(service.plan(PlanIntent::Remove { setup: owner.clone() }).unwrap_err().code, "resource_in_use");
    assert!(bench.fake.provider.lock().unwrap().resources.values().count() == 1, "the shared resource is still there");

    // Borrowing from a setup in the middle of a change is refused, at review and at apply.
    bench.fake.provider.lock().unwrap().gated.insert("shared".into());
    let stop_first = service.plan(PlanIntent::Stop { setup: owner.clone() }).unwrap();
    let later = service.plan(create("Later", vec![DeclaredResource { id: "other".into(), ..borrowing.clone() }])).unwrap();
    let busy_owner = service.submit(&stop_first, &op(), stop_first.base_revision, no_secrets()).unwrap();
    assert_eq!(service.plan(create("Later too", vec![borrowing.clone()])).unwrap_err().code, "owner_busy");
    assert_eq!(service.submit(&later, &op(), 0, no_secrets()).unwrap_err().code, "owner_busy");
    let _ = busy_owner;
}

#[tokio::test]
async fn grids_of_a_kind_sit_side_by_side_and_one_instance_is_held_by_one_setup() {
    let mut bench = Bench::new();
    let grids = Arc::new(FakeHandler::new(Kind::Grid));
    bench.extra.push(grids.clone());
    let service = bench.service();
    let grid = |id: &str, spec: Value| DeclaredResource { kind: Kind::Grid, spec, ..resource(id, &[]) };
    let running = |operation: String| {
        let service = service.clone();
        tokio::spawn(async move { service.run(&operation).await })
    };
    // Two new grids of a kind, even in one plan, and a join and a sign-in beside one being made:
    // each gets an instance of its own from its product.
    service.plan(create("Two", vec![grid("first", json!({ "profile": "neo_grid", "mode": "create" })), grid("second", json!({ "profile": "neo_grid", "mode": "create" }))])).unwrap();
    grids.provider.lock().unwrap().gated.insert("office".into());
    let first = service.plan(create("Office", vec![grid("office", json!({ "profile": "sandbox_grid", "mode": "create" }))])).unwrap();
    let operation = op();
    service.submit(&first, &operation, 0, no_secrets()).unwrap();
    let runner = running(operation);
    grids.entered.notified().await;
    service.plan(create("Second", vec![grid("office", json!({ "profile": "sandbox_grid", "mode": "create" }))])).unwrap();
    service.plan(create("Member", vec![grid("member", json!({ "profile": "sandbox_grid", "mode": "join" }))])).unwrap();
    service.plan(create("Person", vec![grid("person", json!({ "profile": "sandbox_grid", "mode": "join", "member": "person" }))])).unwrap();
    grids.gate.add_permits(1);
    runner.await.unwrap().unwrap();

    // One instance named twice: in one plan, while another setup is adopting it, and once held.
    let adopting = |id: &str| grid(id, json!({ "profile": "sandbox_grid", "mode": "create", "adopted": true, "instance": "i-0000abcd" }));
    assert_eq!(service.plan(create("Twice", vec![adopting("one"), adopting("two")])).unwrap_err().code, "unsupported_here");
    grids.provider.lock().unwrap().gated.insert("held".into());
    let held = service.plan(create("Held", vec![adopting("held")])).unwrap();
    let operation = op();
    service.submit(&held, &operation, 0, no_secrets()).unwrap();
    let runner = running(operation);
    grids.entered.notified().await;
    assert_eq!(service.plan(create("Also", vec![adopting("also")])).unwrap_err().code, "unsupported_here", "an operation adopting it counts");
    grids.gate.add_permits(1);
    runner.await.unwrap().unwrap();
    let refused = service.plan(create("Again", vec![adopting("again")])).unwrap_err();
    assert!(refused.message.contains("already belongs to a setup"), "and so does the setup holding it: {refused:?}");
    // Another instance of the kind is free, and a setup's own grid is never compared with itself.
    service.plan(create("Other", vec![grid("other", json!({ "profile": "sandbox_grid", "mode": "create", "adopted": true, "instance": "i-0000beef" }))])).unwrap();
    let update = PlanIntent::Update { setup: held.setup_id.clone(), draft: SetupDraft { change: change("Held"), resources: vec![adopting("held")] } };
    service.plan(update).unwrap();
}

#[tokio::test]
async fn a_swarm_hub_found_on_this_computer_blocks_a_second_one() {
    let mut bench = Bench::new();
    fs::create_dir_all(bench.data.join("bounty")).unwrap();
    fs::write(bench.data.join("bounty/host.json"), b"{}").unwrap();
    bench.extra.push(Arc::new(FakeHandler::new(Kind::Grid)));
    let service = bench.service();
    let grid = DeclaredResource { kind: Kind::Grid, spec: json!({ "profile": "swarm_mining_grid" }), ..resource("research", &[]) };
    assert_eq!(service.plan(create("Research", vec![grid])).unwrap_err().code, "unsupported_here");
    let listed = service.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].adopted_legacy && !listed[0].state_observed);
}

#[tokio::test]
async fn an_operation_waiting_for_a_secret_continues_by_its_id_without_the_plan_in_memory() {
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().needs_secret.insert("db".into());
    let database = DeclaredResource { spec: json!({ "secretRef": "db-password" }), ..resource("db", &[]) };
    let plan = service.plan(create("Site", vec![database])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    let waiting = service.operation(&operation, 0).unwrap();
    assert_eq!(waiting.state, dto::OperationState::AwaitingInput);
    assert!(waiting.error.unwrap().next_actions.contains(&dto::NextAction::Continue { operation: operation.clone() }));
    // The progress names the digest of the plan it applies, so a client that was not there for
    // the review (a terminal opened later) can answer the operation that asked, not plan another.
    assert_eq!(waiting.plan_digest.as_deref(), Some(plan.digest.as_str()));
    let digest = waiting.plan_digest.unwrap();

    // After a restart the reviewed plan is gone; the operation ID and digest are enough.
    drop(service);
    let service = bench.service();
    assert_eq!(service.reviewed(&plan.setup_id, &plan.digest).unwrap_err().code, "plan_expired");
    let secrets = BTreeMap::from([("db-password".to_owned(), "S3CRET-VALUE".to_owned())]);
    let joined = service.continue_operation(&plan.setup_id, &operation, &digest, secrets).unwrap().unwrap();
    assert!(joined.joined);
    service.run(&operation).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().state, dto::OperationState::Completed);
    assert!(!service.holds_secrets(&operation), "secrets go as soon as the operation finishes");
    assert!(!fs::read_to_string(service.store().path()).unwrap().contains("S3CRET-VALUE"));
    // Another change can't borrow this operation's ID.
    let other = service.plan(create("Other", vec![resource("web", &[])])).unwrap();
    assert_eq!(service.continue_operation(&other.setup_id, &operation, &other.digest, no_secrets()).unwrap_err().code, "operation_id_reused");
}

#[tokio::test]
async fn retry_continues_a_waiting_operation_and_cancel_drops_its_secrets() {
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().needs_secret.insert("db".into());
    let database = DeclaredResource { spec: json!({ "secretRef": "db-password" }), ..resource("db", &[]) };
    let plan = service.plan(create("Site", vec![database])).unwrap();
    let operation = op();
    let partial = BTreeMap::from([("other".to_owned(), "x".to_owned())]);
    service.apply(&plan, &operation, partial).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().state, dto::OperationState::AwaitingInput);
    assert!(service.holds_secrets(&operation));
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().state, dto::OperationState::AwaitingInput, "still missing, so it asks again");
    service.cancel(&operation).unwrap();
    assert!(!service.holds_secrets(&operation));
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "operation_cancelled");
}

#[tokio::test]
async fn a_full_registry_makes_room_from_old_history_so_changes_still_land() {
    let bench = Bench::new();
    let service = bench.service();
    for index in 0..6 {
        created(&service, &format!("Site {index}"), (0..12).map(|r| resource(&format!("r{r}"), &[])).collect()).await;
    }
    let size = fs::metadata(service.store().path()).unwrap().len();
    *service.store().faults.size_limit.lock().unwrap() = Some(size - 1);
    let plan = service.plan(create("One more", vec![resource("web", &[])])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert!(fs::metadata(service.store().path()).unwrap().len() < size);
    let registry = service.snapshot();
    assert!(registry.operations.values().filter(|found| found.state.is_terminal()).all(|found| found.events.len() <= 10 || found.id == operation));
}

/// No Hub at all: these tests plan local folders.
struct NoHub;

impl super::planning::Hub for NoHub {
    fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> super::ordinary::BoxFuture<'a, Result<super::planning::Fetched, String>> {
        Box::pin(async { Err("The Hub can't be reached in this test.".to_owned()) })
    }

    fn components<'a>(&'a self, _: &'a yougori_setup::format::Checked) -> super::ordinary::BoxFuture<'a, Result<BTreeMap<String, yougori_setup::plan::Component>, Vec<yougori_setup::dto::Diagnostic>>> {
        Box::pin(async { Err(vec![yougori_setup::dto::Diagnostic::error("component_unavailable", "The Hub can't be reached in this test.")]) })
    }
}

fn planner_host() -> yougori_setup::plan::Host {
    use yougori_setup::capability::{Arch, Gpu, Host, Os, Runtime};
    yougori_setup::plan::Host {
        yougori: "1.2.0".into(),
        platform: "linux-x86_64".into(),
        gpu: Some(false),
        memory_gb: Some(16.0),
        free_disk_gb: Some(200.0),
        capabilities: Host::new(Os::Linux, Arch::X86_64, Gpu::None, vec![Runtime::Containers, Runtime::LocalModels], true),
    }
}

fn example(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("examples").join("hub").join(name).to_string_lossy().into_owned()
}

/// One of the grid packages, which the setup crate keeps as test fixtures rather than examples.
fn grid_package(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("setup").join("tests").join("fixtures").join("packages").join(name).to_string_lossy().into_owned()
}

#[tokio::test]
async fn a_format_2_template_is_planned_reviewed_and_applied_through_the_engine() {
    let mut bench = Bench::new();
    for kind in [Kind::ServicePublication, Kind::Volume, Kind::Connection] {
        bench.extra.push(Arc::new(FakeHandler::new(kind)));
    }
    let service = bench.service();
    let call = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": example("host-my-app") },
        "name": "My app",
        "answers": [
            { "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" },
            { "field": "access", "value": "none" }
        ],
        "bindings": [{ "field": "app_secret", "secretRef": "apply:app_secret" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let digest = planned["digest"].as_str().unwrap().to_owned();
    assert_eq!(planned["baseRevision"], 0);
    assert_eq!(digest, planned["plan"]["digest"].as_str().unwrap(), "the envelope's digest is the planner's");
    assert!(planned["review"]["creates"].as_array().is_some_and(|creates| !creates.is_empty()));
    assert!(planned["steps"].as_array().is_some_and(|steps| !steps.is_empty()), "the engine's steps are there too");
    assert!(!planned.to_string().contains("S3CRET"));

    // Apply by the planner's digest, as the desktop and CLI do.
    let reviewed = service.reviewed(&setup, &digest).unwrap();
    let operation = op();
    let secrets = BTreeMap::from([("app_secret".to_owned(), "S3CRET-VALUE".to_owned())]);
    service.submit(&reviewed, &operation, 0, secrets).unwrap();
    let app_step = reviewed.steps.iter().find(|step| step.resource == "app").unwrap();
    assert_eq!(app_step.spec["secrets"]["APP_SECRET"], "apply.app_secret", "the plan keeps the binding name");
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    let registry = service.snapshot();
    let instance = &registry.instances[&setup];
    assert_eq!(instance.name, "My app");
    assert!(instance.source.digest.starts_with("sha256:"));
    assert!(matches!(instance.source.reference, dto::SourceRef::LocalFolder { .. }));
    assert!(instance.resources.contains_key("app"));
    assert!(bench.creates() >= 1);
    assert!(!fs::read_to_string(service.store().path()).unwrap().contains("S3CRET-VALUE"));
    // The operation can be continued by the planner's digest too.
    assert!(service.continue_operation(&setup, &operation, &digest, no_secrets()).unwrap().is_some());
}

#[tokio::test]
async fn validation_reports_problems_against_their_fields_and_never_plans() {
    let bench = Bench::new();
    let service = bench.service();
    let folder: super::planning::ValidateCall = serde_json::from_value(json!({ "source": { "kind": "local_folder", "path": example("host-my-app") } })).unwrap();
    let checked = super::planning::validate(&service, &NoHub, folder).await.unwrap();
    assert_eq!(checked["valid"], true, "{checked}");
    assert!(checked["manifest"].as_str().unwrap().contains("format_version: 2"));

    let text: super::planning::ValidateCall = serde_json::from_value(json!({ "source": "format_version: 2\nkind: template\nname: lonely\n" })).unwrap();
    let checked = super::planning::validate(&service, &NoHub, text).await.unwrap();
    assert_eq!(checked["valid"], false);
    assert!(!checked["diagnostics"].as_array().unwrap().is_empty());

    let draft: super::planning::ValidateCall = serde_json::from_value(json!({ "draft": { "name": "x" } })).unwrap();
    assert!(super::planning::validate(&service, &NoHub, draft).await.unwrap()["manifest"].is_string());
    let relative: super::planning::ValidateCall = serde_json::from_value(json!({ "source": { "kind": "local_folder", "path": "relative/folder" } })).unwrap();
    assert_eq!(super::planning::validate(&service, &NoHub, relative).await.unwrap_err().field.as_deref(), Some("source.path"));
    assert!(service.snapshot().instances.is_empty() && !service.store().path().exists());
}

#[tokio::test]
async fn start_and_stop_sent_again_after_they_finish_answer_with_the_same_operation() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![resource("web", &[])]).await;
    let stop = || serde_json::from_value(json!({ "setupId": plan.setup_id, "action": "stop", "operationId": "op-stop-1" })).unwrap();
    let first = super::commands::action(&service, stop()).await.unwrap();
    assert_eq!(first["operationId"], "op-stop-1");
    for _ in 0..200 {
        if service.snapshot().operations["op-stop-1"].state.is_terminal() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(state_of(&service, "op-stop-1"), OperationState::Completed);
    let again = super::commands::action(&service, stop()).await.unwrap();
    assert_eq!(again, first, "a replay joins, it is not refused as a reused ID");
    assert_eq!(bench.calls().iter().filter(|call| *call == "stop:web").count(), 1);
}

// ----- One part of a setup on its own (plan 6.4 and 5.5) -----

/// Waits for an operation the action door started in the background.
async fn settled(service: &Service, operation: &str) -> OperationState {
    for _ in 0..300 {
        if service.snapshot().operations.get(operation).is_some_and(|found| found.state.is_terminal()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    state_of(service, operation)
}

/// What the setup page is told it may do to one part.
fn offered_on(service: &Service, setup: &str, part: &str) -> Vec<String> {
    service.get(setup).unwrap().resource_details[part]["actions"].as_array().unwrap().iter().map(|action| action.as_str().unwrap().to_owned()).collect()
}

/// PROVES that one part is stopped, started and removed on its own, through the door the setup
/// page and the CLI use, while the rest of the setup is left as it is and the setup itself stays
/// running; that what the page is offered is exactly what the engine accepts; and that removing
/// a part another part needs is refused, saying which.
#[tokio::test]
async fn one_part_is_stopped_started_and_removed_on_its_own_and_the_setup_stays_up() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Shop", vec![resource("app", &[]), resource("worker", &[]), resource("web", &["app"])]).await;
    let setup = plan.setup_id.clone();
    assert_eq!(offered_on(&service, &setup, "worker"), ["stop", "remove"]);
    assert_eq!(offered_on(&service, &setup, "app"), ["stop"], "web needs app, so app is not offered for removal");
    let call = |fields: Value| -> super::commands::ActionCall { serde_json::from_value(fields).unwrap() };
    let running = |part: &str| {
        let id = service.snapshot().instances[&setup].resources[part].runtime_id.clone().unwrap();
        bench.fake.provider.lock().unwrap().resources[&id].running
    };

    super::commands::action(&service, call(json!({ "setupId": setup, "action": "stop", "resource": "worker", "operationId": "op-part-stop" }))).await.unwrap();
    assert_eq!(settled(&service, "op-part-stop").await, OperationState::Completed);
    let registry = service.snapshot();
    assert_eq!(registry.instances[&setup].lifecycle, Lifecycle::Running, "the setup itself is still running");
    assert_eq!(registry.instances[&setup].resources["worker"].desired, Desired::Stopped);
    assert!(!running("worker"));
    assert!(running("app") && running("web"), "the rest keeps running");
    assert_eq!(offered_on(&service, &setup, "worker"), ["start", "remove"]);

    super::commands::action(&service, call(json!({ "setupId": setup, "action": "start", "resource": "worker", "operationId": "op-part-start" }))).await.unwrap();
    assert_eq!(settled(&service, "op-part-start").await, OperationState::Completed);
    assert!(running("worker"));

    let refused = super::commands::action(&service, call(json!({ "setupId": setup, "action": "remove", "resource": "app" }))).await.unwrap_err();
    assert_eq!(refused.code, "resource_in_use");
    assert!(refused.message.starts_with("web needs app."), "{}", refused.message);

    // Removing one part is reviewed first, exactly as removing the whole setup is.
    let review = super::commands::action(&service, call(json!({ "setupId": setup, "action": "remove", "resource": "worker" }))).await.unwrap();
    assert_eq!(review["steps"].as_array().unwrap().len(), 1, "{review}");
    assert!(review["notes"].as_array().unwrap().iter().any(|note| note.as_str().unwrap().starts_with("Only worker is removed")), "{review}");
    assert!(!bench.calls().contains(&"remove:worker".to_owned()), "a review changes nothing");
    let digest = review["digest"].as_str().unwrap().to_owned();
    super::commands::action(&service, call(json!({ "setupId": setup, "action": "remove", "resource": "worker", "planDigest": digest, "operationId": "op-part-remove" }))).await.unwrap();
    assert_eq!(settled(&service, "op-part-remove").await, OperationState::Completed);
    let registry = service.snapshot();
    assert!(!registry.instances[&setup].resources.contains_key("worker"));
    assert!(registry.tombstones.contains_key(&format!("{setup}/worker")), "replaying an older change can't bring it back");
    assert_eq!(registry.instances[&setup].lifecycle, Lifecycle::Running);
    assert!(running("app") && running("web"));
    assert_eq!(bench.calls().iter().filter(|call| call.starts_with("remove:")).count(), 1, "nothing else was removed");
    let gone = service.plan(PlanIntent::Part { setup: setup.clone(), resource: "worker".into(), action: Action::Remove }).unwrap_err();
    assert_eq!(gone.code, "resource_missing");
    // One part that doesn't exist, or an action one part can't take, is refused plainly.
    let unknown = super::commands::action(&service, call(json!({ "setupId": setup, "action": "repair", "resource": "app" }))).await.unwrap_err();
    assert_eq!(unknown.code, "invalid_request");
}

/// PROVES that a borrowed part is only ever detached, never removed, stopped or started by this
/// setup; that its owner keeps it; and that a part this setup still uses can't be detached from
/// under it.
#[tokio::test]
async fn a_borrowed_part_is_detached_on_its_own_and_its_owner_keeps_it() {
    let bench = Bench::new();
    let service = bench.service();
    let (owner_plan, _) = created(&service, "Model", vec![resource("shared", &[])]).await;
    let owner = owner_plan.setup_id.clone();
    let borrowing = || DeclaredResource { owner: Some(OwnerRef { setup: owner.clone(), resource: "shared".into() }), ..resource("model", &[]) };
    let (app_plan, _) = created(&service, "App", vec![borrowing(), resource("app", &["model"])]).await;
    let (lab_plan, _) = created(&service, "Lab", vec![borrowing(), resource("tool", &[])]).await;
    let (app, lab) = (app_plan.setup_id.clone(), lab_plan.setup_id.clone());
    assert!(offered_on(&service, &app, "model").is_empty(), "app uses it, so nothing is offered");
    assert_eq!(offered_on(&service, &lab, "model"), ["detach"]);
    assert_eq!(service.plan(PlanIntent::Part { setup: app.clone(), resource: "model".into(), action: Action::Detach }).unwrap_err().code, "resource_in_use");
    for action in [Action::Remove, Action::Stop, Action::Start] {
        assert_eq!(service.plan(PlanIntent::Part { setup: lab.clone(), resource: "model".into(), action }).unwrap_err().code, "resource_borrowed", "{action:?}");
    }
    let detach = service.plan(PlanIntent::Part { setup: lab.clone(), resource: "model".into(), action: Action::Detach }).unwrap();
    assert_eq!(detach.steps.iter().map(|step| (step.resource.as_str(), step.action)).collect::<Vec<_>>(), [("model", Action::Detach)]);
    assert!(detach.notes.iter().any(|note| note.contains("belongs to another setup")), "{:?}", detach.notes);
    service.apply(&detach, &op(), no_secrets()).await.unwrap();
    let registry = service.snapshot();
    assert!(!registry.instances[&lab].resources.contains_key("model"), "this setup's use of it ended");
    assert_eq!(registry.instances[&lab].lifecycle, Lifecycle::Running);
    assert_eq!(registry.instances[&owner].resources["shared"].borrowers.len(), 1, "only App still uses it");
    let shared_id = registry.instances[&owner].resources["shared"].runtime_id.clone().unwrap();
    assert!(bench.fake.provider.lock().unwrap().resources.contains_key(&shared_id), "its owner keeps it");
    assert!(!bench.calls().iter().any(|call| call.ends_with(":model")), "no handler acted on the binding");
}

/// PROVES nothing is offered on a part while a change to its setup is running, and that the
/// engine refuses one then too.
#[tokio::test]
async fn no_part_is_offered_while_its_setup_is_changing() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Shop", vec![resource("app", &[]), resource("worker", &[])]).await;
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    service.submit(&stop, &op(), stop.base_revision, no_secrets()).unwrap();
    assert!(offered_on(&service, &plan.setup_id, "worker").is_empty());
    assert!(offered_on(&service, &plan.setup_id, "app").is_empty());
    let busy = service.plan(PlanIntent::Part { setup: plan.setup_id.clone(), resource: "worker".into(), action: Action::Stop }).unwrap_err();
    assert_eq!(busy.code, "setup_busy");
}

#[test]
fn a_secret_binding_reads_the_value_given_with_apply() {
    let context = super::handler::StepContext {
        setup: String::new(),
        operation: String::new(),
        step: String::new(),
        resource: String::new(),
        kind: Kind::Environment,
        action: Action::Create,
        label: String::new(),
        created_label: None,
        generation: 1,
        spec: Value::Null,
        runtime_id: None,
        owner: None,
        peers: Default::default(),
        planned: Default::default(),
        cancel: Default::default(),
        started_at: None,
        recorded: None,
        consents: Default::default(),
        secrets: Arc::new(BTreeMap::from([("app_secret".to_owned(), "a".to_owned()), ("stored-key".to_owned(), "b".to_owned())])),
    };
    assert_eq!(context.secret("apply.app_secret"), Some("a"));
    assert_eq!(context.secret("stored-key"), Some("b"));
    assert_eq!(context.secret("apply.missing"), None);
}

// ----- Ordinary resources through the project engine (fake) -----

struct Engine {
    _root: tempfile::TempDir,
    setups: PathBuf,
    data: PathBuf,
    projects: Arc<super::ordinary::fake::FakeProjects>,
}

impl Engine {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        Self { setups: data.join("setups"), data, _root: root, projects: Default::default() }
    }

    fn service(&self) -> Arc<Service> {
        let mut handlers = Handlers::default();
        let ordinary = super::ordinary::Ordinary::new(self.projects.clone(), self.setups.join("projects"));
        for each in ordinary.handlers() {
            handlers.register(each);
        }
        Arc::new(Service::open(&self.setups, &self.data, handlers))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, super::ordinary::fake::State> {
        self.projects.state.lock().unwrap()
    }
}

fn sandbox(id: &str, extra: Value) -> DeclaredResource {
    let mut spec = json!({ "type": "container", "image": format!("example/{id}:1.0.0"), "storage": 10 });
    spec.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    DeclaredResource { id: id.into(), kind: Kind::Environment, spec, requires: Vec::new(), owner: None }
}

#[tokio::test]
async fn a_recipe_runs_through_the_project_engine_with_its_secret_in_the_vault() {
    let engine = Engine::new();
    let service = engine.service();
    let call = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": example("host-my-app") },
        "name": "My app",
        "answers": [
            { "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" },
            { "field": "access", "value": "quick" }
        ],
        "bindings": [{ "field": "app_secret", "secretRef": "apply:app_secret" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    let secrets = BTreeMap::from([("app_secret".to_owned(), "S3CRET-VALUE".to_owned())]);
    service.submit(&reviewed, &operation, 0, secrets).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);

    let registry = service.snapshot();
    let app = &registry.instances[&setup].resources["app"];
    let web = &registry.instances[&setup].resources["web"];
    let state = engine.state();
    assert_eq!(state.created, 1);
    let sandbox = &state.sandboxes[app.runtime_id.as_deref().unwrap()];
    assert!(sandbox.running && sandbox.name.ends_with("-app"));
    assert_eq!(web.runtime_id.as_deref(), state.publications.values().next().map(String::as_str), "the quick link is recorded");
    assert!(state.secrets.values().any(|value| value == "S3CRET-VALUE"), "the value went to the vault");
    drop(state);
    assert!(!fs::read_to_string(service.store().path()).unwrap().contains("S3CRET-VALUE"));
    assert!(app.retained_data, "its /data volume outlives the sandbox");
}

#[tokio::test]
async fn stop_and_start_toggle_sandboxes_and_close_and_reopen_their_address() {
    let engine = Engine::new();
    let service = engine.service();
    let web = DeclaredResource {
        id: "web".into(),
        kind: Kind::ServicePublication,
        spec: json!({ "target": { "resource": "app" }, "port": 8080, "access": "quick" }),
        requires: vec!["app".into()],
        owner: None,
    };
    let (plan, _) = created(&service, "Site", vec![sandbox("app", json!({ "ports": [8080] })), web]).await;
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    assert_eq!(stop.steps.iter().map(|step| step.resource.as_str()).collect::<Vec<_>>(), ["web", "app"]);
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    {
        let state = engine.state();
        assert!(state.sandboxes.values().all(|sandbox| !sandbox.running));
        assert!(state.publications.is_empty(), "the address is closed while stopped");
    }
    let start = service.plan(PlanIntent::Start { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&start, &op(), no_secrets()).await.unwrap();
    let state = engine.state();
    assert!(state.sandboxes.values().all(|sandbox| sandbox.running));
    assert_eq!(state.publications.len(), 1, "starting opens it again");
    assert_eq!(state.created, 1, "nothing was made twice");
}

#[tokio::test]
async fn removing_a_setup_deletes_its_sandboxes_keeps_named_volumes_and_forgets_its_secrets() {
    let engine = Engine::new();
    let service = engine.service();
    let app = sandbox("app", json!({ "secrets": { "TOKEN": "apply.token" }, "volumes": [{ "source": "data", "target": "/data" }] }));
    let plan = service.plan(create("Site", vec![app])).unwrap();
    let secrets = BTreeMap::from([("token".to_owned(), "x".to_owned())]);
    service.apply(&plan, &op(), secrets).await.unwrap();
    assert_eq!(engine.state().secrets.len(), 1);
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = engine.state();
    assert!(state.sandboxes.is_empty() && state.deleted.len() == 1);
    assert!(state.secrets.is_empty(), "the setup's secrets left the vault");
    assert_eq!(state.volumes.len(), 1, "the data volume is kept");
    drop(state);
    let registry = service.snapshot();
    assert_eq!(registry.instances[&plan.setup_id].lifecycle, Lifecycle::Retained);
}

// ----- What a removal does with a volume's data (`retention.onRemove`) -----

/// A `data` volume mounted by the sandbox `app` and backed up through it, with this removal
/// retention in the volume's own settings (`None`: it says nothing, so the data is kept).
fn backed_up_volume(on_remove: Option<&str>) -> Vec<DeclaredResource> {
    let mut spec = json!({ "backup_schedule": "daily 02:00", "backup_keep": 7, "backup_through": { "resource": "app" }, "backup_consistency": "live" });
    if let Some(on_remove) = on_remove {
        spec["retention"] = json!({ "on_stop": "keep", "on_remove": on_remove });
    }
    vec![
        DeclaredResource { id: "data".into(), kind: Kind::Volume, spec, requires: Vec::new(), owner: None },
        DeclaredResource { requires: vec!["data".into()], ..sandbox("app", json!({ "volumes": [{ "source": "data", "target": "/data" }] })) },
    ]
}

/// The engine's backups, wired as `setups::start` wires them, over a fake sandbox.
fn with_backups(engine: &Engine, service: &Arc<Service>) {
    let worker = super::backups::Backups::new(service.clone(), Arc::new(super::backups::fake::FakeSandboxes::new()), engine.setups.join("backups"));
    let scheduler = super::schedules::Scheduler::new(service.clone(), super::backups::Work::new(service.clone(), worker.clone()));
    service.wire_backups(worker, scheduler);
}

/// Two copies of `data`, recorded on its schedule as the scheduler records them and on disk
/// where it keeps them. Returns the volume's backups folder.
fn two_backups(engine: &Engine, service: &Service, setup: &str) -> PathBuf {
    use super::schedules::Records;
    let folder = engine.setups.join("backups").join(setup).join("data");
    for (id, at) in [("backup-a", 1_760_000_000), ("backup-b", 1_760_086_400)] {
        fs::create_dir_all(folder.join(id).join("files")).unwrap();
        fs::write(folder.join(id).join("files").join("notes.txt"), "kept").unwrap();
        service.change(&format!("{setup}/data"), &mut |schedule| {
            schedule.backups.push(super::backups::Backup { id: id.into(), at, files: 1, bytes: 4, checksum: "c".repeat(64), consistency: yougori_setup::resource::BackupConsistency::Live });
        });
    }
    assert_eq!(service.schedules_of(setup).unwrap()[0].backups.len(), 2, "the volume is backed up and keeps two copies");
    folder
}

fn delete_data() -> std::collections::BTreeSet<String> {
    std::collections::BTreeSet::from(["delete_data:data".to_owned()])
}

/// PROVES the default, and that it holds against a client that asks for more: a volume is kept
/// with its backups, the review says so with the count, and a deletion the review did not offer
/// is dropped, not honoured.
#[tokio::test]
async fn removing_keeps_a_volume_and_its_backups_and_ignores_a_deletion_it_did_not_offer() {
    let engine = Engine::new();
    let service = engine.service();
    with_backups(&engine, &service);
    let plan = service.plan(create("Notes", backed_up_volume(None))).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let folder = two_backups(&engine, &service, &plan.setup_id);

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    assert!(remove.offered.is_empty(), "nothing is offered when nothing asks");
    assert!(remove.notes.iter().any(|note| note == "The data of data is kept, and so are its 2 backups in Yougori's data folder on this computer."), "{:?}", remove.notes);
    assert!(remove.notes.iter().any(|note| note == "Data is kept by default. Deleting data is a separate step that shows exactly what goes."), "{:?}", remove.notes);

    let operation = op();
    service.submit_agreed(&remove, &operation, remove.base_revision, no_secrets(), delete_data()).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert!(!service.snapshot().operations[&operation].consents.contains("delete_data:data"), "an unoffered deletion is not even kept");
    assert!(engine.state().volumes_removed.is_empty(), "the volume is kept");
    assert!(folder.join("backup-a").exists() && folder.join("backup-b").exists(), "and so are its backups");
    // And the record says so: the kept volume is there, not missing (found on a real engine,
    // where a retained setup listed the very volume it was kept for as missing).
    let kept = &service.snapshot().instances[&plan.setup_id].resources["data"];
    assert_eq!((kept.observed, kept.retained_data), (Observed::Present, true));
}

/// PROVES that `ask` asks, and never answers for the person: each volume gets a choice, unticked,
/// naming everything on it and every backup and saying it cannot be undone. Left unticked, the
/// removal deletes nothing.
#[tokio::test]
async fn a_volume_whose_template_asks_is_offered_for_deletion_unticked_and_kept_unless_ticked() {
    let engine = Engine::new();
    let service = engine.service();
    with_backups(&engine, &service);
    let plan = service.plan(create("Notes", backed_up_volume(Some("ask")))).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let folder = two_backups(&engine, &service, &plan.setup_id);

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    assert_eq!(remove.offered.len(), 1, "{:?}", remove.offered);
    assert_eq!(remove.offered[0]["id"], "delete_data:data");
    assert_eq!(
        remove.offered[0]["message"],
        "Also delete data: everything on it, and all of its backups (2 now) in Yougori's data folder on this computer. This can't be undone."
    );
    assert!(remove.notes.iter().any(|note| note == "The data of data is kept, and so are its 2 backups in Yougori's data folder on this computer, unless you tick its deletion below."), "{:?}", remove.notes);
    assert!(remove.notes.iter().any(|note| note == "Data is kept by default. Only what you tick below is deleted, and that can't be undone."), "{:?}", remove.notes);
    assert!(!remove.notes.iter().any(|note| note == "The data of data is kept. Deleting it is a separate step."), "the plainer line is replaced, not repeated");
    // What is on offer is part of what was reviewed.
    assert_ne!(remove.digest, plan_digest(&ReviewedPlan { offered: Vec::new(), ..remove.clone() }));

    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().volumes_removed.is_empty(), "not ticked: the volume is kept");
    assert!(folder.join("backup-a").exists() && folder.join("backup-b").exists(), "and so are its backups");
}

/// PROVES that a ticked deletion deletes exactly what the review named: the volume and every
/// backup of it, and its backup times, and nothing of anyone else's.
#[tokio::test]
async fn a_ticked_deletion_deletes_exactly_that_volume_and_all_its_backups() {
    let engine = Engine::new();
    let service = engine.service();
    with_backups(&engine, &service);
    let plan = service.plan(create("Notes", backed_up_volume(Some("ask")))).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let folder = two_backups(&engine, &service, &plan.setup_id);
    let elsewhere = engine.setups.join("backups").join("setup-other").join("data").join("backup-z");
    fs::create_dir_all(&elsewhere).unwrap();

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.submit_agreed(&remove, &operation, remove.base_revision, no_secrets(), delete_data()).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let removed = engine.state().volumes_removed.clone();
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert!(removed[0].ends_with("-data"), "{removed:?}");
    assert!(!folder.exists(), "every backup of it is gone");
    assert!(!service.snapshot().schedules.contains_key(&format!("{}/data", plan.setup_id)), "and so are its backup times");
    assert!(elsewhere.exists(), "another setup's backups are untouched");
    // Its sandbox kept its data only on that volume, so nothing is left to call the setup retained.
    assert_ne!(service.snapshot().instances.get(&plan.setup_id).map(|instance| instance.lifecycle), Some(Lifecycle::Retained));
}

/// PROVES a setup recorded as the planner recorded it before mounts were dependencies (the
/// sandbox needing nothing, the volume waiting for the sandbox it is backed up through) still
/// stops and removes the sandbox before the volume it holds. Found on a real engine: removing the
/// volume first was refused as in use, and the removal could never finish.
#[tokio::test]
async fn a_setup_recorded_before_mounts_were_dependencies_removes_its_sandbox_before_its_volume() {
    let engine = Engine::new();
    let service = engine.service();
    with_backups(&engine, &service);
    let mut resources = backed_up_volume(Some("ask"));
    resources[1].requires.clear();
    resources[0].requires = vec!["app".into()];
    resources.reverse();
    let plan = service.plan(create("Notes", resources)).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();

    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let volume = remove.steps.iter().find(|step| step.resource == "data").expect("the volume is removed");
    let app = remove.steps.iter().find(|step| step.resource == "app").expect("and so is its sandbox");
    assert!(volume.depends_on.contains(&app.id), "the volume waits for the sandbox that mounts it: {:?}", remove.steps);
    assert!(!app.depends_on.contains(&volume.id), "and not the other way round");
    let operation = op();
    service.submit_agreed(&remove, &operation, remove.base_revision, no_secrets(), delete_data()).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(engine.state().volumes_removed.len(), 1, "the volume went, once its sandbox had");
}

/// PROVES nothing is left half-deleted without saying so: a volume the engine will not delete
/// fails the step, its backups wait for it, and trying again finishes both.
#[tokio::test]
async fn a_volume_that_cannot_be_deleted_fails_the_step_keeps_its_backups_and_trying_again_finishes() {
    let engine = Engine::new();
    let service = engine.service();
    with_backups(&engine, &service);
    let plan = service.plan(create("Notes", backed_up_volume(Some("ask")))).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let folder = two_backups(&engine, &service, &plan.setup_id);
    engine.state().refuse_volume_removal = Some("data is used by notes-app. Delete those environments first; the volume and its data stay until then.".into());

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.submit_agreed(&remove, &operation, remove.base_revision, no_secrets(), delete_data()).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    let error = service.operation(&operation, 0).unwrap().error.expect("it says why");
    assert!(error.message.starts_with("data was not deleted completely:"), "{}", error.message);
    assert!(error.message.contains("Its backups are kept until it is. Try again to finish deleting it."), "{}", error.message);
    assert!(error.retryable);
    assert!(folder.join("backup-a").exists() && folder.join("backup-b").exists(), "the backups wait for the volume");

    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(engine.state().volumes_removed.len(), 1);
    assert!(!folder.exists());
}

/// PROVES that removing one volume on its own offers its deletion exactly as removing the whole
/// setup would: unticked it is kept, ticked it goes, and the rest of the setup stays up.
#[tokio::test]
async fn removing_one_volume_on_its_own_offers_its_deletion_the_same_way() {
    let engine = Engine::new();
    let service = engine.service();
    with_backups(&engine, &service);
    let asking = |id: &str| DeclaredResource { id: id.into(), kind: Kind::Volume, spec: json!({ "retention": { "on_stop": "keep", "on_remove": "ask" } }), requires: Vec::new(), owner: None };
    let plan = service.plan(create("Notes", vec![asking("data"), asking("cache"), sandbox("app", json!({}))])).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let setup = plan.setup_id.clone();
    let part = |resource: &str| PlanIntent::Part { setup: setup.clone(), resource: resource.into(), action: Action::Remove };

    let kept = service.plan(part("cache")).unwrap();
    assert_eq!(kept.offered, vec![json!({ "id": "delete_data:cache", "message": "Also delete cache: everything on it. This can't be undone." })]);
    assert!(kept.notes.iter().any(|note| note == "The data of cache is kept, unless you tick its deletion below."), "{:?}", kept.notes);
    assert!(kept.notes.iter().any(|note| note.starts_with("Only cache is removed")), "{:?}", kept.notes);
    service.apply(&kept, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().volumes_removed.is_empty(), "not ticked: the volume is kept");

    let remove = service.plan(part("data")).unwrap();
    let operation = op();
    service.submit_agreed(&remove, &operation, remove.base_revision, no_secrets(), delete_data()).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let removed = engine.state().volumes_removed.clone();
    assert!(removed.len() == 1 && removed[0].ends_with("-data"), "{removed:?}");
    let registry = service.snapshot();
    assert_eq!(registry.instances[&setup].lifecycle, Lifecycle::Running, "the rest of the setup stays up");
    assert!(registry.instances[&setup].resources.contains_key("app"));
}

// ----- What a removal says about charges -----

/// Records what each named part costs, as its provider last said, in the registry on disk. An
/// engine opened after it reads that back, as it would after a restart.
fn charging(setups: &std::path::Path, costs: &[(&str, &str, Cost)]) {
    let store = Store::new(setups);
    let mut registry = store.load().unwrap();
    for (setup, id, cost) in costs {
        registry.instances.get_mut(*setup).unwrap().resources.get_mut(*id).unwrap().cost = *cost;
    }
    store.save(&registry).unwrap();
}

/// The lines of a review about what `id` may still be charging.
fn charges_of(notes: &[String], id: &str) -> Vec<String> {
    notes.iter().filter(|note| note.contains(&format!("{id} ")) && (note.contains("charg") || note.contains("costing"))).cloned().collect()
}

/// PROVES a removal review says, part by part, what may still be charging: a part costing money
/// now, one Yougori can't tell about, and one whose shutdown its provider never confirmed. A free
/// part, or one whose charges its provider confirmed stopped, gets no line either way, so nothing
/// is said to cost nothing. Removing one part on its own says the same of it.
#[tokio::test]
async fn a_removal_says_plainly_what_may_still_be_charging() {
    let engine = Engine::new();
    let service = engine.service();
    let parts = ["gpu-pool", "render", "relay", "archive", "local"].map(|id| sandbox(id, json!({}))).to_vec();
    let (plan, _) = created(&service, "Studio", parts).await;
    drop(service);
    let setup = plan.setup_id.as_str();
    charging(&engine.setups, &[(setup, "gpu-pool", Cost::Accruing), (setup, "render", Cost::Unknown), (setup, "relay", Cost::ShutdownUnconfirmed), (setup, "archive", Cost::Stopped), (setup, "local", Cost::Free)]);
    let service = engine.service();

    let remove = service.plan(PlanIntent::Remove { setup: setup.to_owned() }).unwrap();
    assert_eq!(charges_of(&remove.notes, "gpu-pool"), ["gpu-pool is costing money now; the charges stop once its provider confirms it is gone."]);
    assert_eq!(charges_of(&remove.notes, "render"), ["Yougori can't tell whether render is still charging; check with its provider after removing it."]);
    assert_eq!(charges_of(&remove.notes, "relay"), ["relay was asked to stop charging, but its provider hasn't confirmed it; check with its provider after removing it."]);
    assert!(charges_of(&remove.notes, "archive").is_empty() && charges_of(&remove.notes, "local").is_empty(), "{:?}", remove.notes);

    let part = |resource: &str| service.plan(PlanIntent::Part { setup: setup.to_owned(), resource: resource.into(), action: Action::Remove }).unwrap();
    assert_eq!(charges_of(&part("gpu-pool").notes, "gpu-pool"), ["gpu-pool is costing money now; the charges stop once its provider confirms it is gone."]);
    assert!(charges_of(&part("local").notes, "local").is_empty());
}

/// A borrowed part isn't this setup's to stop: removing the setup only lets go of it, and says
/// nothing about what it costs, whatever its record says. That stays with the setup that owns it.
#[tokio::test]
async fn a_removal_says_nothing_about_the_charges_of_a_part_it_only_borrows() {
    let bench = Bench::new();
    let service = bench.service();
    let (owner_plan, _) = created(&service, "Model", vec![resource("shared", &[])]).await;
    let owner = owner_plan.setup_id.clone();
    let borrowing = DeclaredResource { owner: Some(OwnerRef { setup: owner.clone(), resource: "shared".into() }), ..resource("model", &[]) };
    let (user_plan, _) = created(&service, "App", vec![borrowing, resource("app", &["model"])]).await;
    let user = user_plan.setup_id.clone();
    drop(service);
    charging(&bench.setups, &[(owner.as_str(), "shared", Cost::Accruing), (user.as_str(), "model", Cost::Accruing)]);
    let service = bench.service();

    let remove = service.plan(PlanIntent::Remove { setup: user }).unwrap();
    assert!(remove.notes.iter().any(|note| note.starts_with("model belongs to another setup")), "{:?}", remove.notes);
    assert!(charges_of(&remove.notes, "model").is_empty() && charges_of(&remove.notes, "shared").is_empty(), "{:?}", remove.notes);
}

#[tokio::test]
async fn a_lost_receipt_is_adopted_by_name_and_a_failed_start_is_settled_by_looking() {
    let engine = Engine::new();
    let service = engine.service();
    let plan = service.plan(create("Site", vec![sandbox("app", json!({}))])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    service.store().faults.fail_after(2);
    assert!(service.run(&operation).await.is_err());
    drop(service);
    let service = engine.service();
    service.reconcile_all().await;
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(engine.state().created, 1, "found by its name, not made again");

    // The project made the sandbox, then failed to start it: the outcome is checked, and a
    // sandbox made but never started is not recorded as done (a finished setup would then have a
    // part that never ran, as found on a real engine after a crash). The step runs again, which
    // starts that same sandbox and makes no second one.
    engine.state().fail_after_create = true;
    let plan = service.plan(create("Other", vec![sandbox("api", json!({}))])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    service.reconcile(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed, "made but never started: it runs again");
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert!(service.snapshot().instances[&plan.setup_id].resources["api"].runtime_id.is_some());
    assert_eq!(engine.state().created, 2, "the sandbox it made is the one started, not a second");
    assert!(engine.state().sandboxes.values().filter(|sandbox| sandbox.name.ends_with("-api")).all(|sandbox| sandbox.running));
}

#[tokio::test]
async fn a_sandbox_waits_for_its_secret_and_continues_when_given_it() {
    let engine = Engine::new();
    let service = engine.service();
    let plan = service.plan(create("Site", vec![sandbox("app", json!({ "secrets": { "TOKEN": "apply.token" } }))])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::AwaitingInput);
    assert_eq!(engine.state().created, 0, "nothing was made without its secret");
    // It says which question's value it lacks, by the id a client sends secrets by, so a
    // terminal can ask for exactly that and refuse an answer that does not include it.
    let asked = service.operation(&operation, 0).unwrap().error.unwrap();
    assert_eq!((asked.code.as_ref(), asked.field.as_deref()), ("secret_needed", Some("token")));
    let secrets = BTreeMap::from([("token".to_owned(), "x".to_owned())]);
    service.continue_operation(&plan.setup_id, &operation, &plan.digest, secrets).unwrap().unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
}

/// PROVES a connection the engine can't deliver is refused when it is planned, before anything is
/// made: one to a sandbox another setup owns (it is in that setup's project, not this one's) and a
/// model attached with model_request. On a real engine the first was planned, created this
/// setup's sandbox, and then failed at the connection.
#[tokio::test]
async fn a_connection_to_another_setups_sandbox_or_a_model_request_is_refused_before_anything_is_made() {
    let engine = Engine::new();
    let service = engine.service();
    let (owner_plan, _) = created(&service, "Owner", vec![sandbox("app", json!({}))]).await;
    let made = engine.state().created;
    let link = |to: &str, extra: Value| {
        let mut spec = json!({ "from": { "resource": "web" }, "to": { "resource": to }, "ports": [8080] });
        spec.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
        DeclaredResource { id: "link".into(), kind: Kind::Connection, spec, requires: vec!["web".into(), to.to_owned()], owner: None }
    };
    let borrowed = DeclaredResource { owner: Some(OwnerRef { setup: owner_plan.setup_id.clone(), resource: "app".into() }), ..sandbox("shared", json!({})) };
    let refused = service.plan(create("Borrower", vec![borrowed, sandbox("web", json!({})), link("shared", json!({}))])).unwrap_err();
    assert_eq!(refused.code, "unsupported_here", "{refused:?}");
    assert!(refused.message.contains("connects to shared") && refused.message.contains("another setup owns"), "{}", refused.message);
    let refused = service.plan(create("Models", vec![sandbox("db", json!({})), sandbox("web", json!({})), link("db", json!({ "model_request": true }))])).unwrap_err();
    assert!(refused.message.contains("model_request"), "{}", refused.message);
    assert_eq!(engine.state().created, made, "nothing was made by either");
    // A connection between two sandboxes of the setup's own is planned as before.
    assert!(service.plan(create("Own", vec![sandbox("db", json!({})), sandbox("web", json!({})), link("db", json!({}))])).is_ok());
}

#[tokio::test]
async fn two_sandboxes_and_their_connection_share_one_project() {
    let engine = Engine::new();
    let service = engine.service();
    let link = DeclaredResource {
        id: "link".into(),
        kind: Kind::Connection,
        spec: json!({ "from": { "resource": "web" }, "to": { "resource": "db" }, "ports": [5432] }),
        requires: vec!["web".into(), "db".into()],
        owner: None,
    };
    let (plan, _) = created(&service, "Shop", vec![sandbox("db", json!({})), sandbox("web", json!({ "depends_on": ["db"] })), link]).await;
    let registry = service.snapshot();
    let resources = &registry.instances[&plan.setup_id].resources;
    let (web, db) = (resources["web"].runtime_id.clone().unwrap(), resources["db"].runtime_id.clone().unwrap());
    {
        let state = engine.state();
        assert_eq!(state.projects.len(), 1, "one project per setup");
        assert_eq!(state.connections.get(&(web.clone(), db.clone())), resources["link"].runtime_id.as_ref());
    }
    // Stop leaves the connection alone; it doesn't run.
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    assert!(stop.steps.iter().all(|step| step.kind == Kind::Environment));
    // A dropped declaration is kept and named in the review, never removed silently.
    let update = PlanIntent::Update {
        setup: plan.setup_id.clone(),
        draft: SetupDraft { change: change("Shop"), resources: vec![sandbox("db", json!({})), sandbox("web", json!({ "depends_on": ["db"] }))] },
    };
    let reviewed = service.plan(update).unwrap();
    assert!(reviewed.steps.is_empty() && reviewed.notes.iter().any(|note| note.contains("link")));
}

#[tokio::test]
async fn ordinary_specs_this_build_cannot_honour_are_refused_at_review() {
    let engine = Engine::new();
    let service = engine.service();
    let files = sandbox("app", json!({ "files": [{ "source": "../outside", "target": "/app" }] }));
    assert_eq!(service.plan(create("Site", vec![files])).unwrap_err().code, "invalid_spec");
    let nowhere = DeclaredResource {
        id: "web".into(),
        kind: Kind::ServicePublication,
        spec: json!({ "target": { "resource": "app" }, "port": 80, "access": "everywhere" }),
        requires: vec!["app".into()],
        owner: None,
    };
    assert_eq!(service.plan(create("Site", vec![sandbox("app", json!({})), nowhere])).unwrap_err().code, "invalid_spec");
    let sized = DeclaredResource { id: "data".into(), kind: Kind::Volume, spec: json!({ "size_gb": 10 }), requires: Vec::new(), owner: None };
    assert_eq!(service.plan(create("Site", vec![sized])).unwrap_err().code, "unsupported_here");
    let too_small = sandbox("app", json!({ "storage": 0.5 }));
    assert_eq!(service.plan(create("Site", vec![too_small])).unwrap_err().code, "invalid_spec");
    assert_eq!(engine.state().applies, 0);
}

// ----- Neo Grid through the product (fake) -----

struct NeoBench {
    engine: Engine,
    grids: Arc<super::grids::fake::FakeGrids>,
}

impl NeoBench {
    fn new() -> Self {
        Self { engine: Engine::new(), grids: Default::default() }
    }

    fn service(&self) -> Arc<Service> {
        self.service_with(Vec::new())
    }

    /// The service with other handlers beside the grids' and the ordinary ones.
    fn service_with(&self, extra: Vec<Arc<dyn super::handler::ResourceHandler>>) -> Arc<Service> {
        let mut handlers = Handlers::default();
        let ordinary = super::ordinary::Ordinary::new(self.engine.projects.clone(), self.engine.setups.join("projects"));
        let grids = super::grids::Grids::new(self.grids.clone());
        for each in ordinary.handlers().into_iter().chain(grids.handlers()).chain(extra) {
            handlers.register(each);
        }
        Arc::new(Service::open(&self.engine.setups, &self.engine.data, handlers))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, super::grids::fake::State> {
        self.grids.state.lock().unwrap()
    }
}

fn neo_grid(mode: &str) -> DeclaredResource {
    let spec = match mode {
        "join" => json!({ "profile": "neo_grid", "mode": "join", "coordinator": "remote", "member": "computer", "secrets": { "invitation": "apply.invite", "join_password": "apply.join_password" } }),
        _ => json!({ "profile": "neo_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan", "secrets": { "join_password": "apply.grid_password" } }),
    };
    DeclaredResource { id: if mode == "join" { "membership".into() } else { "company".into() }, kind: Kind::Grid, spec, requires: Vec::new(), owner: None }
}

fn neo_pool() -> DeclaredResource {
    DeclaredResource {
        id: "computers".into(),
        kind: Kind::ComputePool,
        spec: json!({ "grid": { "resource": "company" }, "source": "any", "availability": "idle", "idle_after_minutes": 15, "local_user_first": true }),
        requires: vec!["company".into()],
        owner: None,
    }
}

fn neo_model(id: &str, model: &str, extra: Value) -> DeclaredResource {
    let mut spec = json!({ "model": model, "compute": { "resource": "computers" }, "placement": "remaining", "share_percent": 50 });
    spec.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    DeclaredResource { id: id.into(), kind: Kind::ModelService, spec, requires: vec!["computers".into()], owner: None }
}

fn password() -> BTreeMap<String, String> {
    BTreeMap::from([("grid_password".to_owned(), "correct horse battery".to_owned())])
}

#[tokio::test]
async fn the_neo_grid_template_plans_and_makes_a_grid_its_computers_and_its_first_model() {
    let bench = NeoBench::new();
    let service = bench.service();
    let call = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": grid_package("neo-grid") },
        "name": "Acme models",
        "answers": [
            { "field": "mode", "value": "create" },
            { "field": "grid_name", "value": "Acme" },
            { "field": "coordinator_address", "value": "10.0.0.5" },
            { "field": "reach", "value": "lan" },
            { "field": "model", "value": "hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0" },
            { "field": "availability", "value": "idle" }
        ],
        "bindings": [{ "field": "grid_password", "secretRef": "apply:grid_password" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    service.submit(&reviewed, &operation, 0, password()).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.hub.as_ref().unwrap()["name"], "Acme");
    assert_eq!(state.plans.len(), 1);
    assert_eq!(state.plans[0]["model"], "hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0");
    drop(state);
    let registry = service.snapshot();
    let resources = &registry.instances[&setup].resources;
    assert!(resources.contains_key("company") && resources.contains_key("computers") && resources.contains_key("first_model"));
    assert!(!fs::read_to_string(service.store().path()).unwrap().contains("correct horse"));
}

#[tokio::test]
async fn a_grid_its_models_and_a_team_are_made_then_removed_in_reverse_with_the_grid_paused() {
    let bench = NeoBench::new();
    let service = bench.service();
    let team = neo_model("team", "swarm/crew", json!({ "team": { "strategy": "plan", "lead": { "resource": "first" }, "workers": [{ "resource": "first" }], "computers": 3 } }));
    let mut team = team;
    team.requires.push("first".into());
    let plan = service.plan(create("Acme", vec![neo_grid("create"), neo_pool(), neo_model("first", "hf.co/a/b", json!({})), team])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    {
        let state = bench.state();
        assert_eq!(state.plans.len(), 1);
        assert_eq!(state.plans[0]["idleAfterMinutes"], 15, "the pool's rules reach the plan");
        assert_eq!(state.harnesses[0]["lead"], "hf.co/a/b");
    }
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    assert!(stop.steps.is_empty(), "a grid keeps running for its computers: stopping the setup leaves it");

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    assert!(remove.notes.iter().any(|note| note.contains("pauses the Neo Grid Acme for three days, until")), "{:?}", remove.notes);
    assert!(!remove.notes.iter().any(|note| note.contains("Data is kept by default")));
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = bench.state();
    assert!(state.plans.is_empty() && state.harnesses.is_empty());
    assert!(!state.hub.as_ref().unwrap()["closing"].is_null(), "paused for three days, restorable");
    drop(state);
    assert_eq!(service.snapshot().instances[&plan.setup_id].lifecycle, Lifecycle::Retained);
}

#[tokio::test]
async fn joining_a_grid_uses_the_invitation_given_privately_and_leaving_undoes_it() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Member", vec![neo_grid("join")])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::AwaitingInput);
    assert!(bench.state().member.is_none(), "nothing joined without the invitation");
    let secrets = BTreeMap::from([("invite".to_owned(), "grid-invite:abc".to_owned()), ("join_password".to_owned(), "correct horse battery".to_owned())]);
    service.continue_operation(&plan.setup_id, &operation, &plan.digest, secrets).unwrap().unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert!(bench.state().member.is_some());
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(bench.state().member.is_none());
}

#[tokio::test]
async fn a_hub_made_by_a_setup_isnt_listed_twice_or_counted_against_itself() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![neo_grid("create")])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    // The product writes its own record, as the real hub does.
    fs::create_dir_all(bench.engine.data.join("grid")).unwrap();
    fs::write(bench.engine.data.join("grid/hub.json"), b"{}").unwrap();
    fs::write(bench.engine.data.join("grid/member.json"), b"{}").unwrap();
    let service = bench.service();
    let listed = service.list().unwrap();
    assert_eq!(listed.len(), 1, "only the setup, not also the adopted hub or the hub's own membership");
    assert!(!listed[0].adopted_legacy);
    // The setup's own grid is never compared with itself (a change to it is refused for what it
    // is, not as a second grid); a second setup's grid goes beside it.
    let mut renamed = neo_grid("create");
    renamed.spec["name"] = json!("Acme Ltd");
    let update = PlanIntent::Update { setup: plan.setup_id.clone(), draft: SetupDraft { change: change("Acme"), resources: vec![renamed] } };
    assert!(service.plan(update).unwrap_err().message.contains("Changing a grid after it was made"));
    let same = PlanIntent::Update { setup: plan.setup_id.clone(), draft: SetupDraft { change: change("Acme"), resources: vec![neo_grid("create")] } };
    service.plan(same).unwrap();
    service.plan(create("Second", vec![neo_grid("create")])).unwrap();
}

/// PROVES a research grid that doesn't say what it reviews and what was authorised is refused
/// before anything is made, and a kind of grid with no handler is refused plainly.
#[tokio::test]
async fn a_grid_without_what_it_needs_or_of_an_unknown_kind_is_refused_plainly() {
    let bench = NeoBench::new();
    let service = bench.service();
    let research = DeclaredResource { id: "grid".into(), kind: Kind::Grid, spec: json!({ "profile": "swarm_mining_grid", "mode": "create", "name": "x", "address": "10.0.0.5" }), requires: Vec::new(), owner: None };
    assert_eq!(service.plan(create("Grid", vec![research])).unwrap_err().code, "invalid_spec");
    let generic = DeclaredResource { id: "grid".into(), kind: Kind::Grid, spec: json!({ "profile": "generic", "mode": "create", "name": "x", "address": "10.0.0.5" }), requires: Vec::new(), owner: None };
    assert!(service.plan(create("Grid", vec![generic])).is_err());
    assert!(bench.state().calls.is_empty());
}

#[tokio::test]
async fn the_sandbox_grid_template_makes_a_grid_this_computers_share_and_a_first_person_with_a_workspace() {
    let bench = NeoBench::new();
    let service = bench.service();
    let call = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": grid_package("sandbox-grid") },
        "name": "Acme desks",
        "answers": [
            { "field": "mode", "value": "create" },
            { "field": "grid_name", "value": "Acme" },
            { "field": "coordinator_address", "value": "10.0.0.5" },
            { "field": "reach", "value": "lan" },
            { "field": "first_person", "value": "yes" },
            { "field": "first_person_username", "value": "ada" },
            { "field": "first_person_name", "value": "Ada" },
            { "field": "workspace_runtime", "value": "container" },
            { "field": "workspace_image", "value": "ubuntu:24.04" }
        ],
        "bindings": [
            { "field": "grid_password", "secretRef": "apply:grid_password" },
            { "field": "first_person_password", "secretRef": "apply:first_person_password" }
        ]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    let secrets = BTreeMap::from([
        ("grid_password".to_owned(), "correct horse battery".to_owned()),
        ("first_person_password".to_owned(), "another long secret".to_owned()),
    ]);
    service.submit(&reviewed, &operation, 0, secrets).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.desk_hub.as_ref().unwrap()["name"], "Acme");
    assert_eq!(state.people.len(), 1);
    assert_eq!(state.people[0]["username"], "ada");
    assert_eq!(state.people[0]["desk"]["kind"], "container", "the person's workspace comes from the pool");
    assert!(state.share.is_some(), "this computer's share was set");
    drop(state);
    let saved = fs::read_to_string(service.store().path()).unwrap();
    assert!(!saved.contains("correct horse") && !saved.contains("another long secret"));

    // Removing the setup removes the person (their workspace stays) and pauses the grid.
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = bench.state();
    assert!(state.people.is_empty());
    assert!(!state.desk_hub.as_ref().unwrap()["closing"].is_null());
}

#[tokio::test]
async fn a_person_signs_in_to_a_sandbox_grid_with_what_they_gave_privately() {
    let bench = NeoBench::new();
    let service = bench.service();
    let session = DeclaredResource {
        id: "person_session".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "sandbox_grid", "mode": "join", "coordinator": "remote", "member": "person", "sign_in": "password", "username": "ada", "secrets": { "invitation": "apply.person_invite", "password": "apply.person_password" } }),
        requires: Vec::new(),
        owner: None,
    };
    let plan = service.plan(create("My desk", vec![session])).unwrap();
    let secrets = BTreeMap::from([("person_invite".to_owned(), "desk-invite:abc".to_owned()), ("person_password".to_owned(), "another long secret".to_owned())]);
    let operation = op();
    service.apply(&plan, &operation, secrets).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.state().signed_in.as_deref(), Some("ada"));
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(bench.state().signed_in.is_none());
    let sso = DeclaredResource {
        id: "person_session".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "sandbox_grid", "mode": "join", "member": "person", "sign_in": "sso", "secrets": { "invitation": "apply.person_invite" } }),
        requires: Vec::new(),
        owner: None,
    };
    assert_eq!(service.plan(create("My desk", vec![sso])).unwrap_err().code, "unsupported_here");
}

#[tokio::test]
async fn the_access_grid_template_makes_a_grid_with_its_administrator_and_a_brokered_credential() {
    let bench = NeoBench::new();
    let service = bench.service();
    let call = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": grid_package("access-grid") },
        "name": "Acme access",
        "answers": [
            { "field": "mode", "value": "create" },
            { "field": "grid_name", "value": "Acme" },
            { "field": "coordinator_address", "value": "10.0.0.5" },
            { "field": "reach", "value": "lan" },
            { "field": "admin_username", "value": "ada" },
            { "field": "admin_name", "value": "Ada" },
            { "field": "require_two_step", "value": true },
            { "field": "first_credential", "value": "yes" },
            { "field": "credential_name", "value": "github" },
            { "field": "credential_kind", "value": "bearer" },
            { "field": "credential_destination", "value": "https://api.github.com" },
            { "field": "rule_path", "value": "/repos/*" }
        ],
        "bindings": [
            { "field": "admin_password", "secretRef": "apply:admin_password" },
            { "field": "credential_value", "secretRef": "apply:credential_value" }
        ]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    let secrets = BTreeMap::from([
        ("admin_password".to_owned(), "a long admin password".to_owned()),
        ("credential_value".to_owned(), "ghp_SECRET-TOKEN".to_owned()),
    ]);
    service.submit(&reviewed, &operation, 0, secrets).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    {
        let state = bench.state();
        assert_eq!(state.access_hub.as_ref().unwrap()["owner"], "ada", "made with its first administrator");
        assert_eq!(state.access_people.len(), 1, "the administrator isn't added twice");
        assert_eq!(state.credentials.len(), 1);
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0]["path"], "/repos/*");
        assert!(state.two_step);
    }
    let saved = fs::read_to_string(service.store().path()).unwrap();
    assert!(!saved.contains("ghp_SECRET-TOKEN") && !saved.contains("a long admin password"));

    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = bench.state();
    assert!(state.credentials.is_empty(), "the setup's credentials and their rules are gone");
    assert!(!state.access_hub.as_ref().unwrap()["closing"].is_null(), "the grid is paused, restorable");
}

// ----- What a grid template shows once it is applied -----

/// Plans a grid package with these answers and applies it with these secrets. The setup,
/// finished.
async fn applied_template(service: &Service, package: &str, answers: Value, bindings: Value, secrets: BTreeMap<String, String>) -> String {
    let call = serde_json::from_value(json!({ "source": { "kind": "local_folder", "path": grid_package(package) }, "name": "Acme", "answers": answers, "bindings": bindings })).unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    service.submit(&reviewed, &operation, 0, secrets).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    setup
}

/// What a person sees as the setup's outputs: key, label and value.
fn outputs_shown(service: &Service, setup: &str) -> Vec<(String, String, String)> {
    service.get(setup).unwrap().setup.outputs.into_iter().map(|output| (output.key, output.label, output.value)).collect()
}

fn seen(key: &str, label: &str, value: &str) -> (String, String, String) {
    (key.to_owned(), label.to_owned(), value.to_owned())
}

/// PROVES a person sees what the Sandbox Grid template promises once it is applied: the grid, the
/// address computers join and where it is managed, each under the template's own label, and the
/// views it asks for. The first workspace isn't built yet, so it isn't shown, rather than shown as
/// a stand-in. The invite is private: never written to the registry, given only on a reveal, asked
/// of the grid each time, and gone with the grid.
#[tokio::test]
async fn the_sandbox_grid_template_shows_its_outputs_and_gives_its_invite_only_on_a_reveal() {
    let bench = NeoBench::new();
    let service = bench.service();
    let answers = json!([
        { "field": "mode", "value": "create" },
        { "field": "grid_name", "value": "Acme" },
        { "field": "coordinator_address", "value": "10.0.0.5" },
        { "field": "reach", "value": "lan" },
        { "field": "first_person", "value": "yes" },
        { "field": "first_person_username", "value": "ada" },
        { "field": "first_person_name", "value": "Ada" },
        { "field": "workspace_runtime", "value": "container" },
        { "field": "workspace_image", "value": "ubuntu:24.04" }
    ]);
    let bindings = json!([
        { "field": "grid_password", "secretRef": "apply:grid_password" },
        { "field": "first_person_password", "secretRef": "apply:first_person_password" }
    ]);
    let secrets = BTreeMap::from([("grid_password".to_owned(), "correct horse battery".to_owned()), ("first_person_password".to_owned(), "another long secret".to_owned())]);
    let setup = applied_template(&service, "sandbox-grid", answers, bindings, secrets).await;
    let invite = bench.state().desk_hub.as_ref().unwrap()["invite"].as_str().unwrap().to_owned();

    assert_eq!(
        outputs_shown(&service, &setup),
        [seen("grid_name", "Grid", "Acme"), seen("join_address", "Coordinator address", "10.0.0.5:7470"), seen("setup_page", "Grid page", "Its Sandbox Grid tab in My setups")]
    );
    assert_eq!(service.get(&setup).unwrap().setup.views, ["computers", "people", "workspaces", "images", "storage", "logs"], "the views its template asks for");
    let saved = || fs::read_to_string(service.store().path()).unwrap();
    assert!(!saved().contains(&invite), "the invite is never kept");
    assert_eq!(service.private_outputs(&setup).await.unwrap(), [("invite".to_owned(), "Grid invite".to_owned())]);
    assert_eq!(service.reveal(&setup, "invite").await.unwrap(), ("Grid invite".to_owned(), invite.clone()));
    assert_eq!(service.reveal(&setup, "grid_name").await.unwrap_err().code, "output_unknown", "only a private output is revealed");
    assert!(!saved().contains(&invite), "nor does revealing it keep it");

    // Removed, the grid is paused: what it showed goes with it, and so does its invite.
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(outputs_shown(&service, &setup).is_empty(), "{:?}", outputs_shown(&service, &setup));
    assert!(service.private_outputs(&setup).await.unwrap().is_empty());
    assert_eq!(service.reveal(&setup, "invite").await.unwrap_err().code, "output_not_ready");
}

/// The Neo Grid template shows where apps call its model and by what name. Its API key would be
/// shown once, but no template makes one yet, so it is simply absent: not shown, and not offered
/// to reveal.
#[tokio::test]
async fn the_neo_grid_template_shows_where_apps_call_its_model_and_leaves_out_a_key_it_never_made() {
    let bench = NeoBench::new();
    let service = bench.service();
    let answers = json!([
        { "field": "mode", "value": "create" },
        { "field": "grid_name", "value": "Acme" },
        { "field": "coordinator_address", "value": "10.0.0.5" },
        { "field": "reach", "value": "lan" },
        { "field": "model", "value": "hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0" },
        { "field": "availability", "value": "idle" }
    ]);
    let setup = applied_template(&service, "neo-grid", answers, json!([{ "field": "grid_password", "secretRef": "apply:grid_password" }]), password()).await;
    assert_eq!(
        outputs_shown(&service, &setup),
        [
            seen("api_base", "API address", "https://10.0.0.5:7460/v1"),
            seen("grid_name", "Grid", "Acme"),
            seen("grid_page", "Grid page", "Its Neo Grid tab in My setups"),
            seen("join_address", "Where computers join", "10.0.0.5:7460"),
            seen("model", "Model name for apps", "hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0"),
        ]
    );
    assert_eq!(service.private_outputs(&setup).await.unwrap(), [("invite".to_owned(), "Grid invite".to_owned())]);
    assert!(service.reveal(&setup, "api_key").await.is_err());
}

/// The Access Grid template shows where people sign in and where signed-in computers send their
/// requests; its invite, too, comes only on a reveal and is never kept.
#[tokio::test]
async fn the_access_grid_template_shows_where_people_sign_in_and_where_requests_go() {
    let bench = NeoBench::new();
    let service = bench.service();
    let answers = json!([
        { "field": "mode", "value": "create" },
        { "field": "grid_name", "value": "Acme" },
        { "field": "coordinator_address", "value": "10.0.0.5" },
        { "field": "reach", "value": "lan" },
        { "field": "admin_username", "value": "ada" },
        { "field": "admin_name", "value": "Ada" },
        { "field": "require_two_step", "value": true },
        { "field": "first_credential", "value": "yes" },
        { "field": "credential_name", "value": "github" },
        { "field": "credential_kind", "value": "bearer" },
        { "field": "credential_destination", "value": "https://api.github.com" },
        { "field": "rule_path", "value": "/repos/*" }
    ]);
    let bindings = json!([
        { "field": "admin_password", "secretRef": "apply:admin_password" },
        { "field": "credential_value", "secretRef": "apply:credential_value" }
    ]);
    let secrets = BTreeMap::from([("admin_password".to_owned(), "a long admin password".to_owned()), ("credential_value".to_owned(), "ghp_SECRET-TOKEN".to_owned())]);
    let setup = applied_template(&service, "access-grid", answers, bindings, secrets).await;
    let invite = bench.state().access_hub.as_ref().unwrap()["invite"].as_str().unwrap().to_owned();
    assert_eq!(
        outputs_shown(&service, &setup),
        [
            seen("broker", "Broker address", "10.0.0.5:7465"),
            seen("grid_name", "Access Grid", "Acme"),
            seen("grid_page", "Access Grid page", "Its Access Grid tab in My setups"),
            seen("join_address", "Sign-in address", "10.0.0.5:7465"),
            seen("mcp_server", "MCP server for agents", "yougori access mcp"),
        ]
    );
    assert_eq!(service.reveal(&setup, "invite").await.unwrap(), ("Invite for people".to_owned(), invite.clone()));
    assert!(!fs::read_to_string(service.store().path()).unwrap().contains(&invite), "the invite is never kept");
}

/// PROVES releasing rented compute is reviewed first and touches only the rented GPUs in the Neo
/// Grid this setup made: each is named with what it costs, the review says GPU charges stop only
/// once NeoCloud confirms each pod, and applying that review stops them through the product's own
/// stop for that grid. A pod in another grid is neither listed nor stopped, and a review that no
/// longer matches what is rented applies nothing.
#[tokio::test]
async fn releasing_rented_compute_stops_only_this_setups_own_gpus_and_only_as_reviewed() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![neo_grid("create")])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    let setup = plan.setup_id.clone();
    let grid = bench.state().hub.as_ref().unwrap()["id"].as_str().unwrap().to_owned();
    let gpu = |id: &str, grid: &str| json!({"environmentId": id, "gridId": grid, "name": format!("{id}-gpu"), "gpu": "RTX 4090", "gpuCount": 1, "hourlyUsd": 0.69, "podState": "Running"});
    bench.state().pods = vec![gpu("ours", &grid), gpu("theirs", "grid-elsewhere")];
    let stops = || bench.state().calls.iter().filter(|call| *call == "grid_neocloud_stop_all").count();

    let review = service.release_review(&setup, None).await.unwrap();
    let shown = review.to_string();
    assert!(shown.contains("ours-gpu") && !shown.contains("theirs-gpu"), "{shown}");
    assert!(shown.contains("GPU charges stop once NeoCloud confirms each pod") && shown.contains("disks may still cost storage"), "{shown}");
    assert_eq!(stops(), 0, "a review stops nothing");

    // Another GPU joins the grid: the review no longer says what would happen, so it applies nothing.
    bench.state().pods.push(gpu("new", &grid));
    assert_eq!(service.release(&setup, None, review["planDigest"].as_str().unwrap()).await.unwrap_err().code, "plan_changed");
    assert_eq!(stops(), 0);

    let review = service.release_review(&setup, Some("company")).await.unwrap();
    let done = service.release(&setup, Some("company"), review["planDigest"].as_str().unwrap()).await.unwrap();
    assert_eq!(done["chargesStopped"], true, "{done}");
    assert_eq!(stops(), 1);
    {
        let state = bench.state();
        assert!(state.pods.iter().filter(|pod| pod["gridId"] == grid.as_str()).all(|pod| pod["podState"] == "Exited"));
        assert_eq!(state.pods.iter().find(|pod| pod["environmentId"] == "theirs").unwrap()["podState"], "Running", "a pod outside the grid is never stopped");
    }
    // Nothing rented is billing now, so there is nothing more to release, and the old review applies nothing.
    assert!(service.release_review(&setup, None).await.unwrap()["planDigest"].is_null());
    assert_eq!(service.release(&setup, None, review["planDigest"].as_str().unwrap()).await.unwrap_err().code, "plan_changed");
}

/// A stop NeoCloud hasn't confirmed is reported as such, never as charges stopped, and the pod is
/// offered again until NeoCloud says it has stopped.
#[tokio::test]
async fn a_release_neocloud_has_not_confirmed_says_the_charges_may_continue() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![neo_grid("create")])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    let grid = bench.state().hub.as_ref().unwrap()["id"].as_str().unwrap().to_owned();
    bench.state().pods = vec![json!({"environmentId": "ours", "gridId": grid, "name": "big-gpu", "gpu": "A100", "gpuCount": 1, "hourlyUsd": 1.89, "podState": "Running"})];
    bench.state().stop_pending = true;
    let review = service.release_review(&plan.setup_id, None).await.unwrap();
    let done = service.release(&plan.setup_id, None, review["planDigest"].as_str().unwrap()).await.unwrap();
    assert_eq!(done["chargesStopped"], false, "{done}");
    assert_eq!(done["released"][0]["outcome"]["unconfirmed"], json!(["big-gpu"]));
    assert!(done["next"].as_str().unwrap().contains("may still be charging"));
    assert!(service.release_review(&plan.setup_id, None).await.unwrap()["planDigest"].is_string(), "it is offered again");
}

#[tokio::test]
async fn an_access_grid_waits_for_its_administrators_password_and_a_person_can_sign_in() {
    let bench = NeoBench::new();
    let service = bench.service();
    let grid = DeclaredResource {
        id: "company".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "access_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan" }),
        requires: Vec::new(),
        owner: None,
    };
    let owner = DeclaredResource {
        id: "owner".into(),
        kind: Kind::AccessBinding,
        spec: json!({ "grid": { "resource": "company" }, "roles": ["owner", "admin"], "admin": { "username": "ada" }, "secrets": { "admin_password": "apply.admin_password" } }),
        requires: vec!["company".into()],
        owner: None,
    };
    let plan = service.plan(create("Acme", vec![grid, owner])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::AwaitingInput);
    assert!(bench.state().access_hub.is_none());
    let secrets = BTreeMap::from([("admin_password".to_owned(), "a long admin password".to_owned())]);
    service.continue_operation(&plan.setup_id, &operation, &plan.digest, secrets).unwrap().unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);

    let session = DeclaredResource {
        id: "person_session".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "access_grid", "mode": "join", "member": "person", "sign_in": "password", "username": "bob", "secrets": { "invitation": "apply.person_invite", "password": "apply.person_password" } }),
        requires: Vec::new(),
        owner: None,
    };
    // The product signs its administrator in to it here. Signing in to that very grid again would
    // replace that sign-in, so it is refused; another company's Access Grid goes beside it.
    let own = invite_to("access", "Acme", "AB");
    {
        let mut state = bench.state();
        state.access_member = Some("ada".into());
        state.access_member_grid = Some(json!({ "company": "Acme", "fingerprint": fingerprint_of(&own) }));
    }
    let signing_in = |invite: String| BTreeMap::from([("person_invite".to_owned(), invite), ("person_password".to_owned(), "bob's long password".to_owned())]);
    let again = service.plan(create("Bob", vec![session.clone()])).unwrap();
    let operation = op();
    service.apply(&again, &operation, signing_in(own)).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "already_in_use");
    assert_eq!(bench.state().access_member.as_deref(), Some("ada"), "the administrator's sign-in is untouched");
    let elsewhere = service.plan(create("Bob elsewhere", vec![session])).unwrap();
    let operation = op();
    service.apply(&elsewhere, &operation, signing_in(invite_to("access", "Globex", "CD"))).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().access_member.as_deref(), Some("ada"), "and still is: Bob's sign-in went beside it");
    let computer = DeclaredResource {
        id: "membership".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "access_grid", "mode": "join", "member": "computer", "secrets": { "invitation": "apply.invite" } }),
        requires: Vec::new(),
        owner: None,
    };
    assert_eq!(service.plan(create("Computer", vec![computer])).unwrap_err().code, "unsupported_here");
}

// ----- Hub sources and kept packages -----

/// A Hub that serves example folders as versions, counting every fetch. `page` is what it says
/// about the item, as the website's page would: `None` is a Hub that sent no page.
#[derive(Default)]
struct FakeHub {
    fetches: std::sync::Mutex<Vec<(String, Option<String>, Option<String>)>>,
    page: std::sync::Mutex<Option<Value>>,
}

impl super::planning::Hub for FakeHub {
    fn fetch<'a>(&'a self, _publisher: &'a str, name: &'a str, version: Option<&'a str>, digest: Option<&'a str>) -> super::ordinary::BoxFuture<'a, Result<super::planning::Fetched, String>> {
        Box::pin(async move {
            self.fetches.lock().unwrap().push((name.to_owned(), version.map(str::to_owned), digest.map(str::to_owned)));
            let files = yougori_cli::hub::scan::collect(std::path::Path::new(&example(name))).map_err(|error| error.to_string())?.files;
            let found = yougori_cli::hub::scan::digest_of(&files);
            if digest.is_some_and(|wanted| wanted != found) {
                return Err("The Hub's copy does not match the files this setup was made from.".into());
            }
            Ok(super::planning::Fetched { files, version: version.unwrap_or("1.0.0").to_owned(), digest: found, page: self.page.lock().unwrap().clone() })
        })
    }

    /// Each import's item names an example folder, checked against its pin as the Hub client does.
    fn components<'a>(&'a self, checked: &'a yougori_setup::format::Checked) -> super::ordinary::BoxFuture<'a, Result<BTreeMap<String, yougori_setup::plan::Component>, Vec<yougori_setup::dto::Diagnostic>>> {
        Box::pin(async move {
            let mut found = BTreeMap::new();
            for (name, import) in &checked.template.imports {
                let item = import.item.split_once('/').map(|(_, item)| item).unwrap_or_default();
                let files = yougori_cli::hub::scan::collect(std::path::Path::new(&example(item))).unwrap().files;
                let digest = yougori_cli::hub::scan::digest_of(&files);
                if digest != import.digest {
                    return Err(vec![yougori_setup::dto::Diagnostic::error("digest_mismatch", format!("imports: {name}: Refusing to use code that was not reviewed."))]);
                }
                let component = yougori_setup::format::template(&files).map_err(|problems| problems)?;
                found.insert(name.clone(), yougori_setup::plan::Component { item: import.item.clone(), version: import.version.clone().unwrap_or_default(), digest, checked: component, components: BTreeMap::new() });
            }
            Ok(found)
        })
    }
}

#[tokio::test]
async fn a_hub_template_resolves_latest_to_a_pinned_version_and_its_package_is_kept_beside_the_setup() {
    let engine = Engine::new();
    let service = engine.service();
    let hub = FakeHub::default();
    let call = serde_json::from_value(json!({
        "source": { "kind": "hub", "publisher": "example", "name": "host-my-app", "version": "latest" },
        "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" }, { "field": "access", "value": "none" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &hub, &service, call).await.unwrap();
    assert!(planned["notes"].as_array().unwrap()[0].as_str().unwrap().contains("version 1.0.0, the latest today"));
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    service.apply(&reviewed, &op(), no_secrets()).await.unwrap();
    let registry = service.snapshot();
    let source = &registry.instances[&setup].source;
    assert_eq!(source.reference, dto::SourceRef::Hub { publisher: "example".into(), name: "host-my-app".into(), version: "1.0.0".into() }, "an installed setup never follows latest");
    let kept = engine.setups.join("projects").join(&setup).join("package");
    assert!(kept.join("yougori-template.yaml").is_file(), "the package is kept beside the setup");
    assert_eq!(format!("sha256:{}", yougori_cli::hub::scan::digest_of(&yougori_cli::hub::scan::collect(&kept).unwrap().files)), source.digest);

    // Planning it again reads the kept copy: nothing is fetched.
    let again = serde_json::from_value(json!({ "source": { "kind": "installed_setup", "setupId": setup }, "existingSetup": setup })).unwrap();
    super::planning::plan(&planner_host(), &hub, &service, again).await.unwrap();
    assert_eq!(hub.fetches.lock().unwrap().len(), 1);
    // Without the copy, exactly that version and digest is fetched, never latest.
    fs::remove_dir_all(&kept).unwrap();
    let again = serde_json::from_value(json!({ "source": { "kind": "installed_setup", "setupId": setup }, "existingSetup": setup })).unwrap();
    super::planning::plan(&planner_host(), &hub, &service, again).await.unwrap();
    let fetches = hub.fetches.lock().unwrap();
    assert_eq!(fetches[1].1.as_deref(), Some("1.0.0"));
    assert_eq!(fetches[1].2.as_deref(), Some(source.digest.trim_start_matches("sha256:")));
}

/// PROVES a change planned without a name (as the CLI's configure and update plan it) keeps the
/// setup's own name. Found on a real engine, where changing one answer renamed the setup to its
/// template's title and every command by its name stopped finding it.
#[tokio::test]
async fn a_change_planned_without_a_name_keeps_the_setups_own_name() {
    let engine = Engine::new();
    let service = engine.service();
    let hub = FakeHub::default();
    let call = serde_json::from_value(json!({
        "source": { "kind": "hub", "publisher": "example", "name": "host-my-app", "version": "1.0.0" },
        "name": "shop-a",
        "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" }, { "field": "access", "value": "none" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &hub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    service.apply(&service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap(), &op(), no_secrets()).await.unwrap();
    let change = serde_json::from_value(json!({
        "source": { "kind": "installed_setup", "setupId": setup },
        "existingSetup": setup,
        "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.1" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &hub, &service, change).await.unwrap();
    service.apply(&service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap(), &op(), no_secrets()).await.unwrap();
    assert_eq!(service.snapshot().instances[&setup].name, "shop-a");
}

/// PROVES the Hub page is checked against the files at the one planning boundary every door
/// goes through, so the desktop sees a page that promises less before anyone agrees, as only the
/// CLI's own run did until now. A page that agrees says so; one the Hub did not send, or for
/// another version, says it was not compared, never that it matched; a folder has no page.
#[tokio::test]
async fn a_hub_page_that_promises_less_than_the_files_is_named_in_the_plan_before_anyone_agrees() {
    let engine = Engine::new();
    let service = engine.service();
    let hub = FakeHub::default();
    let call = || {
        serde_json::from_value::<super::planning::PlanCall>(json!({
            "source": { "kind": "hub", "publisher": "example", "name": "host-my-app", "version": "1.0.0" },
            "name": "Shop",
            "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" }, { "field": "access", "value": "none" }]
        }))
        .unwrap()
    };
    // The review the files themselves produce, which is what `template publish` puts on the page.
    let files = yougori_cli::hub::scan::collect(std::path::Path::new(&example("host-my-app"))).unwrap().files;
    let checked = yougori_setup::format::template(&files).unwrap();
    let package = yougori_setup::plan::Package { checked, components: BTreeMap::new(), item: None, digest: Some(yougori_cli::hub::scan::digest_of(&files)) };
    let honest = yougori_cli::hub::review::template_v2(&package, &[]).unwrap();
    assert!(!honest["environments"].as_array().unwrap().is_empty(), "the review names the sandboxes it runs");

    // No page from the Hub: not compared, and said so rather than passed off as checked.
    let planned = super::planning::plan(&planner_host(), &hub, &service, call()).await.unwrap();
    assert_eq!(planned["page"]["compared"], false, "{}", planned["page"]);
    assert!(planned["page"]["reason"].as_str().unwrap().contains("did not send a page"), "{}", planned["page"]);

    // An honest page: compared, and nothing to say.
    *hub.page.lock().unwrap() = Some(json!({ "version": { "version": "1.0.0", "review": honest.clone() } }));
    let planned = super::planning::plan(&planner_host(), &hub, &service, call()).await.unwrap();
    assert_eq!(planned["page"], json!({ "compared": true, "differs": false, "differences": [] }));

    // A page that leaves out what the setup runs and what it may do: named in the plan, before
    // anything is applied, in the same words the CLI shows.
    let mut quiet = honest.clone();
    quiet["environments"] = json!([]);
    quiet["warnings"] = json!([]);
    *hub.page.lock().unwrap() = Some(json!({ "version": { "version": "1.0.0", "review": quiet } }));
    let planned = super::planning::plan(&planner_host(), &hub, &service, call()).await.unwrap();
    assert_eq!((planned["page"]["compared"].as_bool(), planned["page"]["differs"].as_bool()), (Some(true), Some(true)), "{}", planned["page"]);
    let named: Vec<&str> = planned["page"]["differences"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(named.contains(&"the sandboxes it runs"), "{named:?}");
    assert!(!planned["notes"].as_array().unwrap().iter().any(|note| note.as_str().unwrap().contains("Hub page")), "the page check is its own field, not a note the review buries");

    // A page for another version is not compared with these files.
    *hub.page.lock().unwrap() = Some(json!({ "version": { "version": "9.9.9", "review": honest } }));
    let planned = super::planning::plan(&planner_host(), &hub, &service, call()).await.unwrap();
    assert_eq!(planned["page"]["compared"], false);
    assert!(planned["page"]["reason"].as_str().unwrap().contains("different version"));

    // A folder on this computer has no page: the plan carries no page check at all.
    let folder = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": example("host-my-app") },
        "name": "Shop",
        "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" }, { "field": "access", "value": "none" }]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, folder).await.unwrap();
    assert!(planned.get("page").is_none(), "{}", planned["page"]);
}

#[tokio::test]
async fn a_hub_failure_is_a_plain_refusal_and_validate_returns_the_texts_and_the_builders_draft() {
    let engine = Engine::new();
    let service = engine.service();
    let call = serde_json::from_value(json!({ "source": { "kind": "hub", "publisher": "example", "name": "host-my-app", "version": "1.0.0" } })).unwrap();
    let refused = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap_err();
    assert_eq!(refused.code, "hub_download_failed");

    let hub = FakeHub::default();
    let checked: super::planning::ValidateCall = serde_json::from_value(json!({ "source": { "kind": "hub", "publisher": "example", "name": "host-my-app", "version": "latest" } })).unwrap();
    let checked = super::planning::validate(&service, &hub, checked).await.unwrap();
    assert_eq!(checked["valid"], true);
    assert_eq!(checked["projectPath"], "yougori.yaml");
    assert!(checked["project"].as_str().unwrap().contains("kind: environment"));
    let draft = &checked["draft"];
    assert_eq!(draft["capabilities"]["web.service"]["mode"], "required");
    assert_eq!(draft["capabilities"]["web.quick_link"]["selected"], false);
    assert!(draft["questions"].as_array().unwrap().iter().any(|question| question["id"] == "image" && question["kind"] == "text"));
    assert_eq!(draft["source"]["version"], "1.0.0");
}

#[tokio::test]
async fn a_sandbox_gets_its_files_from_the_kept_package() {
    let engine = Engine::new();
    let service = engine.service();
    let files = Arc::new(yougori_setup::format::Files::from([
        ("yougori-template.yaml".to_owned(), b"format_version: 2".to_vec()),
        ("app/server.js".to_owned(), b"console.log(1)".to_vec()),
    ]));
    let app = sandbox("app", json!({ "files": [{ "source": "./app", "target": "/srv/app" }] }));
    let plan = service.plan_from(create("Site", vec![app]), None, Some(files)).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let kept = engine.setups.join("projects").join(&plan.setup_id).join("package");
    assert_eq!(fs::read(kept.join("app").join("server.js")).unwrap(), b"console.log(1)");
    let state = engine.state();
    let project = state.projects.values().next().unwrap();
    assert_eq!(std::path::Path::new(&project.environments["app"].files[0].source), kept.join("app"));
}

#[tokio::test]
async fn a_builder_draft_validates_into_texts_and_plans_and_applies_like_any_package() {
    let engine = Engine::new();
    let service = engine.service();
    let draft = json!({
        "name": "My web app",
        "capabilities": {
            "web.service": { "selected": true, "mode": "required", "settings": { "image": "ghcr.io/example/app:1.0.0" } },
            "web.private": { "selected": true, "mode": "default" }
        }
    });
    let checked: super::planning::ValidateCall = serde_json::from_value(json!({ "draft": draft })).unwrap();
    let checked = super::planning::validate(&service, &NoHub, checked).await.unwrap();
    assert!(checked["manifest"].as_str().unwrap().contains("format_version: 2"), "{checked}");
    // What running it asks comes back with the draft, so the builder asks it before planning.
    let asked: Vec<&str> = checked["draft"]["questions"].as_array().into_iter().flatten().filter_map(|question| question["id"].as_str()).collect();
    assert!(asked.contains(&"port"), "{asked:?}");
    assert!(checked["project"].as_str().is_some_and(|project| !project.is_empty()));
    assert_eq!(checked["projectPath"], "yougori.yaml");

    let call = serde_json::from_value(json!({ "draft": draft, "name": "My web app" })).unwrap();
    match super::planning::plan(&planner_host(), &NoHub, &service, call).await {
        Ok(planned) => {
            let setup = planned["setupId"].as_str().unwrap().to_owned();
            let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
            let operation = op();
            service.apply(&reviewed, &operation, no_secrets()).await.unwrap();
            assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
            assert!(engine.setups.join("projects").join(&setup).join("package").join("yougori-template.yaml").is_file(), "the generated package is kept");
        }
        // A draft whose questions still need answers is refused with the field to answer.
        Err(problem) => assert!(problem.field.is_some(), "{problem:?}"),
    }

    let broken: super::planning::ValidateCall = serde_json::from_value(json!({ "draft": { "name": "", "capabilities": { "no.such": {} } } })).unwrap();
    let broken = super::planning::validate(&service, &NoHub, broken).await.unwrap();
    assert_eq!(broken["valid"], false);
    assert!(!broken["diagnostics"].as_array().unwrap().is_empty());
}

/// PROVES a service kept to this computer is reachable here and says where: the builder's Address
/// output reads its port at 127.0.0.1, the one the project publishes. Found on a real runtime,
/// where a private service opened nothing on this computer and its address was never shown.
#[tokio::test]
async fn a_service_kept_to_this_computer_shows_its_address_here() {
    let engine = Engine::new();
    let service = engine.service();
    let draft = json!({
        "name": "Here only",
        "capabilities": {
            "web.service": { "selected": true, "mode": "required", "settings": { "image": "ghcr.io/example/app:1.0.0" } },
            "web.private": { "selected": true, "mode": "default" }
        }
    });
    let call = serde_json::from_value(json!({ "draft": draft, "name": "Here only", "answers": [{ "field": "image", "value": "ghcr.io/example/app:1.0.0" }] })).unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap_or_else(|problem| panic!("{problem:?}"));
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    service.apply(&reviewed, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let here = super::ordinary::here_port(&setup, "web");
    assert_eq!(engine.state().here.values().collect::<Vec<_>>(), [&here], "{:?}", engine.state().here);
    assert_eq!(outputs_shown(&service, &setup), [seen("address", "Address", &format!("http://127.0.0.1:{here}"))]);
}

// ----- Built-in tools in sandboxes -----

fn tool(name: &str, extra: Value) -> Value {
    let mut entry = json!({ "name": name, "source": "built-in", "spec": name });
    entry.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    entry
}

fn update(setup: &str, resources: Vec<DeclaredResource>) -> PlanIntent {
    PlanIntent::Update { setup: setup.to_owned(), draft: SetupDraft { change: change("Site"), resources } }
}

#[tokio::test]
async fn built_in_tools_install_once_after_the_sandbox_starts_and_go_with_it() {
    let engine = Engine::new();
    let service = engine.service();
    let tools = json!({ "tools": [tool("claude", json!({})), tool("codex", json!({}))] });
    let (plan, _) = created(&service, "Site", vec![sandbox("app", tools.clone())]).await;
    let id = service.snapshot().instances[&plan.setup_id].resources["app"].runtime_id.clone().unwrap();
    assert_eq!(engine.state().tools[&id], ["claude", "codex"]);
    assert_eq!(engine.state().installs, 2);

    // A change converges the sandbox; what is installed is not installed again.
    let mut changed = tools.clone();
    changed["ports"] = json!([8080]);
    let change = service.plan(update(&plan.setup_id, vec![sandbox("app", changed)])).unwrap();
    service.apply(&change, &op(), no_secrets()).await.unwrap();
    assert_eq!(engine.state().installs, 2, "nothing was reinstalled");

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = engine.state();
    assert!(!state.tools.contains_key(&id), "the tools went with the sandbox");
    assert!(state.signins.is_empty(), "no sign-in was copied without the choice");
}

#[tokio::test]
async fn a_failed_install_leaves_nothing_half_made_and_retry_installs_only_what_is_missing() {
    let engine = Engine::new();
    let service = engine.service();
    engine.state().fail_install = true;
    let plan = service.plan(create("Site", vec![sandbox("app", json!({ "tools": [tool("claude", json!({}))] }))])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    let found = service.operation(&operation, 0).unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    let error = found.error.unwrap();
    assert_eq!(error.code, "tool_install_failed");
    assert!(error.retryable && error.message.contains("Claude Code did not install"), "{error:?}");
    assert!(engine.state().sandboxes.is_empty(), "the sandbox this step made was taken down again");
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(engine.state().sandboxes.len(), 1);

    // A sandbox the setup already has is kept when a newly added tool fails; retry adds only it.
    let tools = json!({ "tools": [tool("claude", json!({})), tool("gemini", json!({}))] });
    engine.state().fail_install = true;
    let change = service.plan(update(&plan.setup_id, vec![sandbox("app", tools)])).unwrap();
    let operation = op();
    service.apply(&change, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    assert_eq!(engine.state().sandboxes.len(), 1, "an existing sandbox is never removed for a failed tool");
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    let state = engine.state();
    assert_eq!(state.installs, 2, "claude once, gemini once");
    assert_eq!(state.tools.values().next().unwrap(), &["claude", "gemini"]);
}

#[tokio::test]
async fn a_host_signin_is_copied_only_on_the_explicit_choice_agreed_when_applying_and_only_once() {
    let engine = Engine::new();
    let service = engine.service();
    let tools = json!({ "tools": [
        tool("claude", json!({ "signin": true, "copy_credentials": true })),
        tool("codex", json!({ "signin": true, "copy_credentials": false })),
        tool("gemini", json!({ "signin": true })),
        tool("opencode", json!({ "copy_credentials": true })),
    ] });
    let plan = service.plan(create("Site", vec![sandbox("app", tools.clone())])).unwrap();
    assert!(plan.notes.iter().any(|note| note.contains("Codex") && note.contains("yougori codex --environment")), "{:?}", plan.notes);
    assert!(plan.notes.iter().any(|note| note.contains("copied into it only if you agree when applying")), "{:?}", plan.notes);
    assert!(!plan.notes.iter().any(|note| note.contains("OpenCode")), "no sign-in asked, no note");
    let asked = super::views::plan(&plan)["consents"].clone();
    assert_eq!(asked.as_array().unwrap().iter().map(|consent| consent["id"].as_str().unwrap()).collect::<Vec<_>>(), ["copy_signin:app/claude"]);
    let operation = op();
    service.submit_agreed(&plan, &operation, 0, no_secrets(), std::collections::BTreeSet::from(["copy_signin:app/claude".to_owned()])).unwrap();
    service.run(&operation).await.unwrap();
    let id = service.snapshot().instances[&plan.setup_id].resources["app"].runtime_id.clone().unwrap();
    assert_eq!(engine.state().signins, [(id.clone(), "claude".to_owned())]);

    // A later change never replaces a sign-in made inside the sandbox.
    let mut changed = tools.clone();
    changed["ports"] = json!([8080]);
    let change = service.plan(update(&plan.setup_id, vec![sandbox("app", changed)])).unwrap();
    service.apply(&change, &op(), no_secrets()).await.unwrap();
    assert_eq!(engine.state().signins.len(), 1);

    // The template's choice alone is never enough: without the agreement nothing is copied.
    let other = json!({ "tools": [tool("claude", json!({ "signin": true, "copy_credentials": true }))] });
    let (_, operation) = created(&service, "Other", vec![sandbox("api", other.clone())]).await;
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(engine.state().signins.len(), 1);

    // No sign-in on this computer: the setup still completes; the person signs in inside.
    engine.state().no_host_signin = true;
    let third = service.plan(create("Third", vec![sandbox("web", other)])).unwrap();
    let operation = op();
    service.submit_agreed(&third, &operation, 0, no_secrets(), std::collections::BTreeSet::from(["copy_signin:web/claude".to_owned()])).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(engine.state().signins.len(), 1);
}

#[tokio::test]
async fn a_lost_receipt_with_a_tool_still_missing_runs_the_step_again() {
    let engine = Engine::new();
    let service = engine.service();
    let plan = service.plan(create("Site", vec![sandbox("app", json!({ "tools": [tool("claude", json!({}))] }))])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    service.store().faults.fail_after(2);
    assert!(service.run(&operation).await.is_err());
    // The installer died with the engine: the tool isn't there.
    engine.state().tools.clear();
    drop(service);
    let service = engine.service();
    service.reconcile_all().await;
    assert_eq!(state_of(&service, &operation), OperationState::Failed, "not recorded as done while its tool is missing");
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    let state = engine.state();
    assert_eq!(state.created, 1, "the sandbox was found by its name, not made again");
    assert_eq!(state.tools.values().next().unwrap(), &["claude"]);
}

#[test]
fn only_built_in_tools_in_container_sandboxes_are_installed_by_a_setup() {
    let engine = Engine::new();
    let service = engine.service();
    let hub = json!({ "tools": [{ "name": "reviewer", "source": "hub", "item": "acme/reviewer", "spec": "hub/acme/reviewer" }] });
    assert_eq!(service.plan(create("Site", vec![sandbox("app", hub)])).unwrap_err().code, "unsupported_here");
    let microvm = json!({ "type": "microvm", "tools": [tool("codex", json!({}))] });
    assert_eq!(service.plan(create("Site", vec![sandbox("app", microvm)])).unwrap_err().code, "unsupported_here");
    let offline = json!({ "internet": false, "tools": [tool("codex", json!({}))] });
    assert_eq!(service.plan(create("Site", vec![sandbox("app", offline)])).unwrap_err().code, "invalid_spec");
}

// ----- Format 1 packages -----

#[tokio::test]
async fn a_format_1_template_plans_and_applies_through_the_ordinary_handlers() {
    let engine = Engine::new();
    let service = engine.service();
    let source = json!({ "kind": "local_folder", "path": example("hello-site") });
    let checked: super::planning::ValidateCall = serde_json::from_value(json!({ "source": source })).unwrap();
    let checked = super::planning::validate(&service, &NoHub, checked).await.unwrap();
    assert_eq!(checked["valid"], true, "{checked}");
    assert_eq!(checked["formatVersion"], 1);
    assert!(checked["project"].as_str().unwrap().contains("project: hello-site"));
    assert!(checked["draft"].is_null(), "the builder edits format 2 only");

    let call = serde_json::from_value(json!({ "source": source, "name": "Hello", "answers": [{ "field": "access", "value": "quick" }] })).unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap();
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let questions = planned["review"]["questions"].as_array().unwrap().iter().map(|q| q["id"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
    assert!(!questions.contains(&"domain".to_owned()), "nothing is asked that v1 would not ask: {questions:?}");
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    service.apply(&reviewed, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);

    let registry = service.snapshot();
    let instance = &registry.instances[&setup];
    let web = instance.resources["web"].runtime_id.clone().unwrap();
    let state = engine.state();
    assert_eq!(state.tools[&web], ["httpie"], "the template's own tool is installed from the kept package");
    assert_eq!(state.publications.len(), 1, "the quick link is open");
    let project = state.projects.values().next().unwrap();
    let environment = &project.environments.values().next().unwrap();
    let copied = environment.files.first().map(|file| file.source.clone()).unwrap_or_default();
    assert!(copied.replace('\\', "/").contains("/package/site"), "files: come from the kept package copy: {copied}");
    assert_eq!(environment.environment.get("SITE_TITLE").map(String::as_str), Some("Hello from Yougori"), "the default answer is used");
}

// ----- J9 review: each test names the finding it guards -----

fn access_grid() -> DeclaredResource {
    DeclaredResource {
        id: "company".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "access_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan" }),
        requires: Vec::new(),
        owner: None,
    }
}

fn access_admin(username: &str) -> DeclaredResource {
    DeclaredResource {
        id: "owner".into(),
        kind: Kind::AccessBinding,
        spec: json!({ "grid": { "resource": "company" }, "roles": ["owner", "admin"], "admin": { "username": username }, "secrets": { "admin_password": "apply.admin_password" } }),
        requires: vec!["company".into()],
        owner: None,
    }
}

fn access_person(id: &str, username: &str) -> DeclaredResource {
    DeclaredResource {
        id: id.into(),
        kind: Kind::AccessBinding,
        spec: json!({ "grid": { "resource": "company" }, "roles": ["member"], "person": { "username": username }, "secrets": { "password": "apply.person_password" } }),
        requires: vec!["company".into(), "owner".into()],
        owner: None,
    }
}

fn broker(credentials: Value) -> DeclaredResource {
    DeclaredResource {
        id: "broker".into(),
        kind: Kind::CredentialBroker,
        spec: json!({ "grid": { "resource": "company" }, "credentials": credentials, "secrets": { "token": "apply.token" } }),
        requires: vec!["company".into(), "owner".into()],
        owner: None,
    }
}

fn access_secrets() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("admin_password".to_owned(), "a long admin password".to_owned()),
        ("person_password".to_owned(), "a long person password".to_owned()),
        ("token".to_owned(), "ghp_SECRET-TOKEN".to_owned()),
    ])
}

#[tokio::test]
async fn j9_1_removing_an_access_person_really_removes_them() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada"), access_person("bob", "bob")])).unwrap();
    service.apply(&plan, &op(), access_secrets()).await.unwrap();
    assert!(bench.state().access_people.iter().any(|person| person["username"] == "bob"));
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(!bench.state().access_people.iter().any(|person| person["username"] == "bob"), "the product reads `person`; a refusal is never taken for success");
}

#[tokio::test]
async fn j9_2_a_standing_rule_is_an_allow_rule_and_a_failed_rule_is_retried_not_skipped() {
    let bench = NeoBench::new();
    let service = bench.service();
    let credentials = json!([{ "name": "github", "kind": "bearer", "destinations": ["https://api.github.com"], "approval": "standing", "paths": ["/repos/*", "/user"], "value": "token" }]);
    bench.state().fail_rule = true;
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada"), broker(credentials)])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, access_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown, "a credential was added: never reported as nothing left behind");
    service.reconcile(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed, "not done while a rule is missing");
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.credentials.len(), 1, "the credential isn't added twice");
    assert_eq!(state.rules.len(), 2, "the missing rule was added on retry, not skipped");
    assert!(state.rules.iter().all(|rule| rule["decision"] == "allow"));
}

#[tokio::test]
async fn j9_3_a_credential_the_person_added_is_never_taken_over_or_deleted() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada")])).unwrap();
    service.apply(&plan, &op(), access_secrets()).await.unwrap();
    // The person adds a credential of their own from the grid's own tab in My setups.
    bench.state().credentials.push(json!({"id": "cred-mine", "name": "github", "kind": "bearer", "note": ""}));
    let credentials = json!([{ "name": "github", "kind": "bearer", "destinations": ["https://api.github.com"], "value": "token" }]);
    let change = service.plan(PlanIntent::Update { setup: plan.setup_id.clone(), draft: SetupDraft { change: change("Acme"), resources: vec![access_grid(), access_admin("ada"), broker(credentials)] } }).unwrap();
    let operation = op();
    service.apply(&change, &operation, access_secrets()).await.unwrap();
    let error = service.operation(&operation, 0).unwrap().error.unwrap();
    assert_eq!(error.code, "credential_exists", "{error:?}");
    assert_eq!(bench.state().credentials, [json!({"id": "cred-mine", "name": "github", "kind": "bearer", "note": ""})]);
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert_eq!(bench.state().credentials.len(), 1, "removal deletes only what this setup added");
}

#[tokio::test]
async fn j9_3_credentials_go_only_to_an_access_grid_this_setup_makes_and_never_as_someone_else() {
    let bench = NeoBench::new();
    let service = bench.service();
    let credentials = json!([{ "name": "github", "kind": "bearer", "destinations": ["https://api.github.com"], "value": "token" }]);
    // A company's grid reached through a person's sign-in is refused at review.
    let session = DeclaredResource {
        id: "company".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "access_grid", "mode": "join", "member": "person", "sign_in": "password", "username": "bob", "secrets": { "invitation": "apply.invite", "password": "apply.person_password" } }),
        requires: Vec::new(),
        owner: None,
    };
    let mut remote = broker(credentials.clone());
    remote.requires = vec!["company".into()];
    let refused = service.plan(create("Remote", vec![session, remote])).unwrap_err();
    assert!(refused.message.contains("an Access Grid this setup makes"), "{refused:?}");
    // With someone else signed in to this very grid here, access_manage would act as them:
    // nothing is sent.
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada")])).unwrap();
    service.apply(&plan, &op(), access_secrets()).await.unwrap();
    bench.state().access_member = Some("mallory".into());
    let more = service.plan(update(&plan.setup_id, vec![access_grid(), access_admin("ada"), broker(credentials)])).unwrap();
    let operation = op();
    service.apply(&more, &operation, access_secrets()).await.unwrap();
    assert_ne!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.state().remote_manage, 0, "nothing went to another grid");
    assert!(bench.state().credentials.is_empty());
}

/// A join or sign-in never takes over what this computer already has: joining a grid it is already
/// in would only move that membership, and signing in to a grid it is already signed in to would
/// replace that sign-in, whoever's they are. Another grid of the same kind is fine: it goes beside
/// them, in an instance of its own, which its setup records.
#[tokio::test]
async fn j9_4_a_join_or_sign_in_never_takes_over_what_this_computer_already_has() {
    let bench = NeoBench::new();
    let service = bench.service();
    let joining = |invite: String| BTreeMap::from([("invite".to_owned(), invite), ("join_password".to_owned(), "correct horse battery".to_owned())]);
    let acme = invite_to("grid", "Acme", "AB");
    bench.state().member = Some(json!({"memberId": "member-mine", "connected": true, "joinedAt": 1, "fingerprint": fingerprint_of(&acme)}));
    let plan = service.plan(create("Member", vec![neo_grid("join")])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, joining(acme)).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "already_in_use");
    assert!(!bench.state().calls.iter().any(|call| call == "grid_join"));

    let plan = service.plan(create("Globex member", vec![neo_grid("join")])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, joining(invite_to("grid", "Globex", "CD"))).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().member.as_ref().unwrap()["memberId"], "member-mine", "the first membership is untouched");
    let record = service.snapshot().instances[&plan.setup_id].resources["membership"].runtime_id.clone().unwrap();
    assert!(record.contains("@i-"), "recorded with the instance it went to: {record}");

    let session = DeclaredResource {
        id: "person_session".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "sandbox_grid", "mode": "join", "member": "person", "sign_in": "password", "username": "ada", "secrets": { "invitation": "apply.person_invite", "password": "apply.person_password" } }),
        requires: Vec::new(),
        owner: None,
    };
    {
        let mut state = bench.state();
        state.signed_in = Some("carol".into());
        state.signed_in_grid = Some("Acme".into());
    }
    let signing_in = |invite: String| BTreeMap::from([("person_invite".to_owned(), invite), ("person_password".to_owned(), "another long secret".to_owned())]);
    let plan = service.plan(create("My desk", vec![session.clone()])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, signing_in(invite_to("desks", "Acme", "EF"))).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "already_in_use");
    assert_eq!(bench.state().signed_in.as_deref(), Some("carol"), "carol's sign-in is untouched");

    let plan = service.plan(create("Globex desk", vec![session])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, signing_in(invite_to("desks", "Globex", "EF"))).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().signed_in.as_deref(), Some("carol"), "and still is: the new sign-in went beside it");
}

/// A real invitation of `kind` (`grid`, `desks` or `access`) to the company's grid, whose
/// certificate fingerprint ends in `last`.
fn invite_to(kind: &str, company: &str, last: &str) -> String {
    use yougori_grid::invite::{encode, encode_access, encode_desk, Invite};
    let invite = Invite { company: company.into(), address: yougori_grid::net::HubAddress::parse("10.0.0.9:7460").unwrap(), fingerprint: format!("{}{last}", "01:".repeat(31)) };
    match kind {
        "desks" => encode_desk(&invite),
        "access" => encode_access(&invite),
        "bounty" => yougori_grid::invite::encode_bounty(&invite),
        _ => encode(&invite),
    }
}

/// The fingerprint an invitation carries, as the products read it.
fn fingerprint_of(invite: &str) -> String {
    use yougori_grid::invite::{decode, decode_access, decode_desk};
    decode(invite).or_else(|_| decode_desk(invite)).or_else(|_| decode_access(invite)).unwrap().fingerprint
}

/// PROVES two Sandbox Grid setups sit side by side on one computer, each in an instance of its
/// own, and each is removed without touching the other. The first stays in the product's first
/// instance; the second gets a new one and records it, and every call about either names its own.
#[tokio::test]
async fn two_sandbox_grid_setups_sit_side_by_side_and_each_is_removed_without_touching_the_other() {
    let bench = NeoBench::new();
    let service = bench.service();
    let desks = |name: &str| DeclaredResource {
        id: "company".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "sandbox_grid", "mode": "create", "name": name, "address": "10.0.0.5", "access": "lan", "secrets": { "join_password": "apply.grid_password" } }),
        requires: Vec::new(),
        owner: None,
    };
    let acme = service.plan(create("Acme desks", vec![desks("Acme")])).unwrap();
    service.apply(&acme, &op(), password()).await.unwrap();
    let globex = service.plan(create("Globex desks", vec![desks("Globex")])).unwrap();
    let operation = op();
    service.apply(&globex, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let record = |setup: &str| service.snapshot().instances[setup].resources["company"].runtime_id.clone().unwrap();
    let first = record(&acme.setup_id);
    assert!(!first.contains('@'), "the first grid of a kind stays in the product's first instance: {first}");
    let key = record(&globex.setup_id).split_once('@').map(|(_, key)| key.to_owned()).expect("the second records its own instance");
    {
        let state = bench.state();
        assert_eq!(state.desk_hub.as_ref().unwrap()["name"], "Acme");
        assert_eq!(state.desks_later[&key].desk_hub.as_ref().unwrap()["name"], "Globex");
    }

    // Removing the second pauses its own grid, and only that.
    let remove = service.plan(PlanIntent::Remove { setup: globex.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    {
        let state = bench.state();
        assert_eq!(state.desks_later[&key].desk_hub.as_ref().unwrap()["closing"]["when"], "later", "Globex is paused");
        assert!(state.desk_hub.as_ref().unwrap()["closing"].is_null(), "Acme is untouched");
    }
    // Removing the first, deleted at once, takes only its own.
    let remove = service.plan(PlanIntent::Remove { setup: acme.setup_id.clone() }).unwrap();
    let operation = op();
    service.submit_agreed(&remove, &operation, remove.base_revision, no_secrets(), std::collections::BTreeSet::from([super::grids::delete_grid_consent("company")])).unwrap();
    service.run(&operation).await.unwrap();
    let state = bench.state();
    assert_eq!(state.desk_hub.as_ref().unwrap()["closing"]["when"], "now");
    assert_eq!(state.desks_later[&key].desk_hub.as_ref().unwrap()["closing"]["when"], "later", "Globex stays as its own removal left it");
}

/// PROVES a later grid of a kind is adopted into a setup like the first: by bookkeeping alone, in
/// the instance it is in, which the setup records. The same instance is never held twice: adopting
/// it again is refused, and so is any plan that names it while a setup holds it.
#[tokio::test]
async fn a_later_grid_of_a_kind_is_adopted_and_its_instance_is_never_held_twice() {
    let bench = NeoBench::new();
    let key = "i-0000abcd";
    let folder = bench.engine.data.join("grid/desks").join(key);
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("desks-hub.json"), b"{\"legacy\":true}").unwrap();
    {
        let mut later = super::grids::fake::State::default();
        later.desk_hub = Some(json!({"id": "desks-theirs", "name": "Initech", "closing": null, "createdAt": 1}));
        bench.state().desks_later.insert(key.to_owned(), later);
    }
    let service = bench.service();
    let adopted = format!("adopted-sandbox-grid-hub-{key}");
    assert!(service.list().unwrap().iter().any(|setup| setup.setup_id == adopted), "listed, to be adopted");
    let plan = service.plan(service.adoption(&adopted).unwrap()).unwrap();
    assert_eq!(plan.steps[0].spec["instance"], key);
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let record = service.snapshot().instances[&plan.setup_id].resources["grid"].runtime_id.clone();
    assert_eq!(record.as_deref(), Some(format!("desks-theirs@{key}").as_str()));
    let calls = bench.state().calls.clone();
    assert!(calls.iter().all(|call| call.ends_with("_status")), "only its status was read: {calls:?}");
    assert!(!service.list().unwrap().iter().any(|setup| setup.setup_id == adopted), "it is listed once, as the setup");

    // The same instance again, by adoption or by a plan that names it, is refused.
    assert_eq!(service.adoption(&adopted).err().map(|refused| refused.code).as_deref(), Some("already_adopted"));
    let again = DeclaredResource { id: "grid".into(), kind: Kind::Grid, spec: json!({ "profile": "sandbox_grid", "mode": "create", "adopted": true, "instance": key }), requires: Vec::new(), owner: None };
    let refused = service.plan(create("Again", vec![again])).unwrap_err();
    assert!(refused.message.contains("already belongs to a setup"), "{refused:?}");
    // Removing the setup pauses that grid, in its own instance, and touches nothing else.
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = bench.state();
    assert_eq!(state.desks_later[key].desk_hub.as_ref().unwrap()["closing"]["when"], "later");
    assert!(state.desk_hub.is_none(), "nothing was made or touched in the first instance");
}

#[tokio::test]
async fn j9_4_removal_leaves_a_membership_this_setup_did_not_make() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Member", vec![neo_grid("join")])).unwrap();
    let secrets = BTreeMap::from([("invite".to_owned(), "grid-invite:abc".to_owned()), ("join_password".to_owned(), "correct horse battery".to_owned())]);
    service.apply(&plan, &op(), secrets).await.unwrap();
    // The person left and joined another grid from its own tab in My setups.
    bench.state().member = Some(json!({"memberId": "member-theirs", "connected": true, "joinedAt": 1}));
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.apply(&remove, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.state().member.as_ref().unwrap()["memberId"], "member-theirs");
    assert!(!bench.state().calls.iter().any(|call| call == "grid_leave"));
}

#[tokio::test]
async fn j9_5_removal_never_pauses_a_grid_this_setup_did_not_make() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![neo_grid("create")])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    // Deleted elsewhere, and a new hub made from its own tab in My setups.
    bench.state().hub = Some(json!({"id": "grid-theirs", "name": "Theirs", "closing": null, "createdAt": 1}));
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.apply(&remove, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "a setup whose grid is gone can still be removed");
    assert!(bench.state().hub.as_ref().unwrap()["closing"].is_null(), "their hub isn't paused");
}

#[tokio::test]
async fn j9_6_removal_says_what_each_grid_deletes_and_when() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada")])).unwrap();
    service.apply(&plan, &op(), access_secrets()).await.unwrap();
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    assert!(remove.notes.iter().any(|note| note.contains("Access Grid Acme for three days, until") && note.contains("stored credentials are deleted for good")), "{:?}", remove.notes);
    assert!(!remove.notes.iter().any(|note| note.contains("Data is kept by default")));
    let view = super::views::plan(&remove);
    assert!(!view["steps"].to_string().contains("Its data is kept"), "{view}");
}

#[tokio::test]
async fn j9_7_vault_entries_leave_with_a_failed_create_and_with_a_dropped_variable() {
    let engine = Engine::new();
    let service = engine.service();
    engine.state().fail_install = true;
    let app = sandbox("app", json!({ "secrets": { "TOKEN": "apply.token" }, "tools": [tool("claude", json!({}))] }));
    let plan = service.plan(create("Site", vec![app])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, BTreeMap::from([("token".to_owned(), "x".to_owned())])).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    assert!(engine.state().secrets.is_empty(), "nothing was made, so what it stored is gone");

    let both = sandbox("web", json!({ "secrets": { "A": "apply.a", "B": "apply.b" } }));
    let (plan, _) = {
        let plan = service.plan(create("Web", vec![both])).unwrap();
        service.apply(&plan, &op(), BTreeMap::from([("a".to_owned(), "1".to_owned()), ("b".to_owned(), "2".to_owned())])).await.unwrap();
        (plan, ())
    };
    assert_eq!(engine.state().secrets.len(), 2);
    let one = sandbox("web", json!({ "secrets": { "A": "apply.a" } }));
    let change = service.plan(update(&plan.setup_id, vec![one])).unwrap();
    service.apply(&change, &op(), no_secrets()).await.unwrap();
    assert_eq!(engine.state().secrets.len(), 1, "the dropped variable's entry is forgotten");
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().secrets.is_empty());
}

#[tokio::test]
async fn j9_8_a_template_cant_point_a_sandbox_at_a_stored_entry() {
    let engine = Engine::new();
    let service = engine.service();
    let grab = sandbox("app", json!({ "secrets": { "SEAL": "yougori-access-hub-seal" } }));
    let refused = service.plan(create("Site", vec![grab])).unwrap_err();
    assert_eq!(refused.code, "invalid_spec");
    assert!(refused.message.contains("read only values given when the setup is applied"));
}

#[tokio::test]
async fn j9_9_a_neo_pools_hours_reach_its_plans_and_a_change_to_them_is_applied() {
    let bench = NeoBench::new();
    let service = bench.service();
    let mut pool = neo_pool();
    pool.spec = json!({ "grid": { "resource": "company" }, "source": "any", "availability": "scheduled", "schedule": "Mon-Fri 18:00-08:00" });
    let plan = service.plan(create("Acme", vec![neo_grid("create"), pool.clone(), neo_model("first", "hf.co/a/b", json!({}))])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    assert_eq!(bench.state().plans[0]["schedule"], "Mon-Fri 18:00-08:00");
    assert_eq!(bench.state().plans[0]["idleAfterMinutes"], 0, "a scheduled pool serves throughout its hours");
    pool.spec = json!({ "grid": { "resource": "company" }, "source": "any", "availability": "idle", "idle_after_minutes": 30 });
    let change = service.plan(update(&plan.setup_id, vec![neo_grid("create"), pool, neo_model("first", "hf.co/a/b", json!({}))])).unwrap();
    let operation = op();
    service.apply(&change, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.plans[0]["idleAfterMinutes"], 30);
    assert!(state.plans[0]["schedule"].is_null(), "the hours were cleared");
}

#[tokio::test]
async fn j9_10_an_administrator_with_capitals_is_found_by_the_policys_lower_case() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("Ada")])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, access_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
}

#[tokio::test]
async fn j9_risks_refusals_come_at_review_not_half_way_through() {
    let bench = NeoBench::new();
    let service = bench.service();
    // Limits for a Neo pool, people on a Sandbox Grid with an administrator, a share on a
    // joined Sandbox Grid: each is refused before anything runs.
    let mut limited = neo_pool();
    limited.spec["limits"] = json!({ "cpu": 2 });
    limited.spec["source"] = json!("this_computer");
    assert_eq!(service.plan(create("A", vec![neo_grid("create"), limited])).unwrap_err().code, "unsupported_here");
    let desks = DeclaredResource { id: "company".into(), kind: Kind::Grid, spec: json!({ "profile": "sandbox_grid", "mode": "join", "member": "computer", "secrets": { "invitation": "apply.invite", "join_password": "apply.p" } }), requires: Vec::new(), owner: None };
    let share = DeclaredResource { id: "computers".into(), kind: Kind::ComputePool, spec: json!({ "grid": { "resource": "company" }, "source": "this_computer", "limits": { "cpu": 2 } }), requires: vec!["company".into()], owner: None };
    assert_eq!(service.plan(create("B", vec![desks, share])).unwrap_err().code, "unsupported_here");
    // A team can't be changed in place: refused at review.
    let mut team = neo_model("team", "swarm/crew", json!({ "team": { "lead": { "resource": "first" }, "workers": [{ "resource": "first" }] } }));
    team.requires.push("first".into());
    let plan = service.plan(create("C", vec![neo_grid("create"), neo_pool(), neo_model("first", "hf.co/a/b", json!({})), team.clone()])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    team.spec["team"]["computers"] = json!(5);
    let changed = service.plan(update(&plan.setup_id, vec![neo_grid("create"), neo_pool(), neo_model("first", "hf.co/a/b", json!({})), team])).unwrap_err();
    assert!(changed.message.contains("removing it and adding it again"));
}

#[tokio::test]
async fn j9_risks_a_sandbox_of_the_same_name_that_the_project_didnt_make_is_never_adopted() {
    let engine = Engine::new();
    let service = engine.service();
    let plan = service.plan(create("Site", vec![sandbox("app", json!({}))])).unwrap();
    let name = format!("setup-{}-app", &plan.setup_id.trim_start_matches("setup-")[..8]);
    engine.state().sandboxes.insert("env-theirs".into(), super::ordinary::Sandbox { id: "env-theirs".into(), name, running: true, owner: "someone else".into() });
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_ne!(state_of(&service, &operation), OperationState::Completed);
    service.reconcile_all().await;
    assert!(service.snapshot().instances[&plan.setup_id].resources.get("app").and_then(|app| app.runtime_id.clone()).is_none(), "never recorded as this setup's");
    assert!(engine.state().sandboxes.contains_key("env-theirs"), "and never deleted");
}

#[tokio::test]
async fn j9_risks_removing_a_stopped_setup_starts_nothing() {
    let engine = Engine::new();
    let service = engine.service();
    let web = DeclaredResource {
        id: "web".into(),
        kind: Kind::ServicePublication,
        spec: json!({ "target": { "resource": "app" }, "port": 8080, "access": "quick" }),
        requires: vec!["app".into()],
        owner: None,
    };
    let (plan, _) = created(&service, "Site", vec![sandbox("db", json!({})), sandbox("app", json!({ "ports": [8080] })), web]).await;
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    let applies = engine.state().applies;
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.apply(&remove, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = engine.state();
    assert_eq!(state.applies, applies, "no converge: nothing was started on the way out");
    assert!(state.sandboxes.is_empty());
}

#[tokio::test]
async fn j9_risks_a_pools_unknown_share_is_not_set_again_while_the_engine_starts() {
    let bench = NeoBench::new();
    let service = bench.service();
    let desks = DeclaredResource { id: "company".into(), kind: Kind::Grid, spec: json!({ "profile": "sandbox_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan", "secrets": { "join_password": "apply.grid_password" } }), requires: Vec::new(), owner: None };
    let share = DeclaredResource { id: "computers".into(), kind: Kind::ComputePool, spec: json!({ "grid": { "resource": "company" }, "source": "this_computer", "limits": { "cpu": 2 } }), requires: vec!["company".into()], owner: None };
    let plan = service.plan(create("Desks", vec![desks, share])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, password()).unwrap();
    // The grid is made and recorded; the share's receipt is lost.
    service.store().faults.fail_after(4);
    let _ = service.run(&operation).await;
    let shares = bench.state().calls.iter().filter(|call| *call == "desks_member_share").count();
    assert_eq!(shares, 1, "the share was set once before the receipt was lost");
    assert!(matches!(state_of(&service, &operation), OperationState::Applying | OperationState::Unknown));
    drop(service);
    let service = bench.service();
    service.reconcile_all().await;
    assert_eq!(bench.state().calls.iter().filter(|call| *call == "desks_member_share").count(), shares, "settling never acts on its own");
    assert_eq!(state_of(&service, &operation), OperationState::Failed, "it waits for a retry instead");
}

#[tokio::test]
async fn j9_nits_a_retained_setup_can_finish_its_removal() {
    let engine = Engine::new();
    let service = engine.service();
    let app = sandbox("app", json!({ "volumes": [{ "source": "data", "target": "/data" }] }));
    let (plan, _) = created(&service, "Site", vec![app]).await;
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert_eq!(service.snapshot().instances[&plan.setup_id].lifecycle, Lifecycle::Retained);
    let again = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    assert!(again.steps.is_empty() && again.notes.iter().any(|note| note.contains("removes the setup from My setups")), "{:?}", again.notes);
    service.apply(&again, &op(), no_secrets()).await.unwrap();
    assert!(!service.snapshot().instances.contains_key(&plan.setup_id), "the setup is gone; its volume stays");
    assert_eq!(engine.state().volumes.len(), 1);
}

// ----- Health from evidence -----

#[tokio::test]
async fn a_sandbox_is_ready_only_when_its_health_check_passed() {
    let engine = Engine::new();
    let service = engine.service();
    let (plain, _) = created(&service, "Plain", vec![sandbox("app", json!({}))]).await;
    service.refresh(&plain.setup_id).await.unwrap();
    assert_eq!(service.snapshot().instances[&plain.setup_id].health, super::model::Health::Unknown, "running alone proves nothing");

    let checked = sandbox("api", json!({ "ports": [8080], "health": { "port": 8080, "path": "/health" } }));
    let (api, _) = created(&service, "Api", vec![checked]).await;
    engine.state().readiness.insert("api".into(), json!({"ready": false, "applicationVerified": false, "retryable": true, "stages": {"publicHttps": {"status": "notConfigured"}}}));
    service.refresh(&api.setup_id).await.unwrap();
    assert_eq!(service.snapshot().instances[&api.setup_id].health, super::model::Health::Starting);
    engine.state().readiness.insert("api".into(), json!({"ready": true, "applicationVerified": true, "verifiedPublicly": false, "retryable": false, "stages": {"publicHttps": {"status": "notConfigured"}}}));
    service.refresh(&api.setup_id).await.unwrap();
    assert_eq!(service.snapshot().instances[&api.setup_id].health, super::model::Health::Ready);
    engine.state().readiness.insert("api".into(), json!({"ready": false, "applicationVerified": false, "retryable": false, "stages": {"publicHttps": {"status": "notConfigured"}}}));
    service.refresh(&api.setup_id).await.unwrap();
    assert_eq!(service.snapshot().instances[&api.setup_id].health, super::model::Health::Failed);
}

// ----- Updating ordinary resources -----

#[tokio::test]
async fn a_sandbox_changes_in_place_with_a_reviewed_difference_and_keeps_its_data() {
    let engine = Engine::new();
    let service = engine.service();
    let first = sandbox("app", json!({ "environment": { "MODE": "a" }, "volumes": [{ "source": "data", "target": "/data" }, { "source": "cache", "target": "/cache" }] }));
    let (plan, _) = created(&service, "Site", vec![first]).await;
    let id = service.snapshot().instances[&plan.setup_id].resources["app"].runtime_id.clone().unwrap();

    let second = sandbox("app", json!({ "environment": { "MODE": "b" }, "volumes": [{ "source": "data", "target": "/data" }] }));
    let change = service.plan(update(&plan.setup_id, vec![second])).unwrap();
    assert!(change.notes.iter().any(|note| note == "app changes in place: environment, volumes."), "{:?}", change.notes);
    assert!(change.notes.iter().any(|note| note.contains("The volume cache is no longer attached") && note.contains("Its data stays")), "{:?}", change.notes);
    service.apply(&change, &op(), no_secrets()).await.unwrap();
    let registry = service.snapshot();
    assert_eq!(registry.instances[&plan.setup_id].resources["app"].runtime_id.as_deref(), Some(id.as_str()), "the same sandbox");
    assert_eq!(engine.state().volumes.len(), 2, "no volume was deleted");

    let image = sandbox("app", json!({ "image": "example/app:2.0.0", "environment": { "MODE": "b" }, "volumes": [{ "source": "data", "target": "/data" }] }));
    let change = service.plan(update(&plan.setup_id, vec![image])).unwrap();
    assert!(change.notes.iter().any(|note| note.contains("is made again from its new image") && note.contains("named volumes move")), "{:?}", change.notes);

    let microvm = sandbox("app", json!({ "type": "microvm" }));
    let refused = service.plan(update(&plan.setup_id, vec![microvm])).unwrap_err();
    assert_eq!(refused.code, "unsupported_here");
    assert!(refused.message.contains("can't change from a container to a microvm in place"));
}

#[tokio::test]
async fn a_publication_and_a_connection_change_in_place() {
    let engine = Engine::new();
    let service = engine.service();
    let web = |access: &str| DeclaredResource {
        id: "web".into(),
        kind: Kind::ServicePublication,
        spec: json!({ "target": { "resource": "app" }, "port": 8080, "access": access }),
        requires: vec!["app".into()],
        owner: None,
    };
    let link = |ports: Value| DeclaredResource {
        id: "link".into(),
        kind: Kind::Connection,
        spec: json!({ "from": { "resource": "app" }, "to": { "resource": "db" }, "ports": ports }),
        requires: vec!["app".into(), "db".into()],
        owner: None,
    };
    let resources = |access: &str, ports: Value| vec![sandbox("db", json!({})), sandbox("app", json!({ "ports": [8080] })), web(access), link(ports)];
    let (plan, _) = created(&service, "Shop", resources("quick", json!([5432]))).await;
    assert_eq!(engine.state().publications.len(), 1);
    // The address alone first: closing it doesn't wait for another change to converge.
    let private = service.plan(update(&plan.setup_id, resources("private", json!([5432])))).unwrap();
    service.apply(&private, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().publications.is_empty(), "the quick link closed on its own step");
    // Kept to this computer, it is the sandbox's port at 127.0.0.1, on a port of its own.
    let app = engine.state().sandboxes.values().find(|sandbox| sandbox.name.ends_with("-app")).unwrap().id.clone();
    let here = super::ordinary::here_port(&plan.setup_id, "web");
    assert_eq!(engine.state().here.get(&(app.clone(), 8080)), Some(&here), "{:?}", engine.state().here);
    let change = service.plan(update(&plan.setup_id, resources("quick", json!([5432, 6432])))).unwrap();
    assert_eq!(change.steps.iter().map(|step| (step.resource.as_str(), step.action)).collect::<Vec<_>>(), [("web", Action::Update), ("link", Action::Update)]);
    let operation = op();
    service.apply(&change, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = engine.state();
    assert_eq!(state.publications.len(), 1, "opened again");
    assert!(state.here.is_empty(), "public again, it no longer listens on this computer: {:?}", state.here);
    assert_eq!(state.connections.len(), 1);
    assert_eq!(state.created, 2, "no sandbox made again");
}

// ----- Adopting a legacy grid into a setup -----

#[tokio::test]
async fn a_legacy_hub_is_adopted_into_a_setup_by_bookkeeping_alone() {
    let bench = NeoBench::new();
    fs::create_dir_all(bench.engine.data.join("grid")).unwrap();
    fs::write(bench.engine.data.join("grid/hub.json"), b"{\"legacy\":true}").unwrap();
    fs::write(bench.engine.data.join("grid/member.json"), b"{\"legacy\":true}").unwrap();
    let before = fs::metadata(bench.engine.data.join("grid/hub.json")).unwrap().modified().unwrap();
    bench.state().hub = Some(json!({"id": "grid-legacy", "name": "Acme", "closing": null, "createdAt": 1}));
    bench.state().member = Some(json!({"memberId": "member-self", "connected": true, "joinedAt": 1}));
    let service = bench.service();
    assert!(service.list().unwrap().iter().any(|setup| setup.setup_id == "adopted-neo-grid-hub"));

    let plan = service.plan(service.adoption("adopted-neo-grid-hub").unwrap()).unwrap();
    let view = super::views::plan(&plan);
    assert!(view["steps"][0]["title"].as_str().unwrap().starts_with("Adopt grid"), "{view}");
    assert!(plan.notes.iter().any(|note| note.contains("Nothing is moved, restarted or re-keyed")), "{:?}", plan.notes);
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);

    let registry = service.snapshot();
    assert_eq!(registry.instances[&plan.setup_id].resources["grid"].runtime_id.as_deref(), Some("grid-legacy"));
    assert_eq!(bench.state().calls.iter().filter(|call| !call.ends_with("_status")).count(), 0, "only the status was read");
    assert_eq!(fs::read(bench.engine.data.join("grid/hub.json")).unwrap(), b"{\"legacy\":true}");
    assert_eq!(fs::metadata(bench.engine.data.join("grid/hub.json")).unwrap().modified().unwrap(), before, "the product's records are untouched");
    let service = bench.service();
    let listed = service.list().unwrap();
    assert_eq!(listed.len(), 1, "the hub and its membership are listed once, as the setup");
    assert!(!listed[0].adopted_legacy);
    // Adopting it again is refused: it is a setup's now. A new Neo Grid goes beside it.
    assert!(service.adoption("adopted-neo-grid-hub").is_err());
    service.plan(create("Second", vec![neo_grid("create")])).unwrap();
}

#[tokio::test]
async fn swarm_unreadable_records_and_memberships_are_not_adopted() {
    let bench = NeoBench::new();
    fs::create_dir_all(bench.engine.data.join("bounty")).unwrap();
    fs::write(bench.engine.data.join("bounty/host.json"), b"{}").unwrap();
    fs::create_dir_all(bench.engine.data.join("grid/desks-hub.json")).unwrap();
    fs::write(bench.engine.data.join("grid/member.json"), b"{}").unwrap();
    let service = bench.service();
    assert_eq!(service.adoption("adopted-swarm-mining-hub").err().unwrap().code, "unsupported_here");
    assert_eq!(service.adoption("adopted-sandbox-grid-hub").err().unwrap().code, "unreadable");
    assert_eq!(service.adoption("adopted-neo-grid-member").err().unwrap().code, "unsupported_here");
    assert!(bench.state().calls.is_empty());
}


// ----- Pinned components and the lock -----

/// host-my-app with one pinned component: another copy of host-my-app.
fn with_component(pin: &str) -> tempfile::TempDir {
    let folder = tempfile::tempdir().unwrap();
    let source = PathBuf::from(example("host-my-app"));
    for entry in fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), folder.path().join(entry.file_name())).unwrap();
        }
    }
    let template = fs::read_to_string(folder.path().join("yougori-template.yaml")).unwrap();
    let imports = format!("imports:
  extra:
    item: example/host-my-app
    version: 1.0.0
    digest: {pin}
    inputs: {{image: \"ghcr.io/example/extra:1.0.0\", access: none}}
inputs:
");
    fs::write(folder.path().join("yougori-template.yaml"), template.replacen("inputs:
", &imports, 1)).unwrap();
    folder
}

#[tokio::test]
async fn pinned_components_resolve_through_the_shared_function_and_the_lock_is_kept() {
    let engine = Engine::new();
    let service = engine.service();
    let hub = FakeHub::default();
    let digest = yougori_cli::hub::scan::digest_of(&yougori_cli::hub::scan::collect(std::path::Path::new(&example("host-my-app"))).unwrap().files);
    let folder = with_component(&digest);
    let call = |path: &std::path::Path| serde_json::from_value::<super::planning::PlanCall>(json!({
        "source": { "kind": "local_folder", "path": path },
        "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" }, { "field": "access", "value": "none" }]
    })).unwrap();
    let planned = super::planning::plan(&planner_host(), &hub, &service, call(folder.path())).await.unwrap_or_else(|problem| panic!("{problem:?}"));
    assert_eq!(planned["lock"]["components"]["extra"]["digest"], digest.as_str());
    assert!(planned["steps"].to_string().contains("extra."), "the component's resources are namespaced: {}", planned["steps"]);
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    service.apply(&reviewed, &op(), no_secrets()).await.unwrap();
    assert_eq!(service.lock(&setup).unwrap().unwrap().components["extra"].digest, digest, "the lock is kept with the setup");

    // A pin that doesn't match what the Hub serves is refused, at check and at plan.
    let tampered = with_component(&"b".repeat(64));
    assert_eq!(super::planning::plan(&planner_host(), &hub, &service, call(tampered.path())).await.unwrap_err().code, "digest_mismatch");
    let checked: super::planning::ValidateCall = serde_json::from_value(json!({ "source": { "kind": "local_folder", "path": tampered.path() } })).unwrap();
    let checked = super::planning::validate(&service, &hub, checked).await.unwrap();
    assert_eq!(checked["valid"], false);
    assert_eq!(checked["diagnostics"][0]["code"], "digest_mismatch");
}

// ----- Updating a setup to a new template version -----

fn version(name: &str, v: &str) -> InstanceChange {
    let mut change = change(name);
    change.source.reference = dto::SourceRef::Hub { publisher: "example".into(), name: "hello".into(), version: v.into() };
    change.source.digest = format!("sha256:{}", v.replace('.', ""));
    change.lock = Some(json!({ "template": { "version": v } }));
    change
}

#[tokio::test]
async fn an_update_to_a_new_version_says_what_changes_and_moves_the_base_only_when_it_finishes() {
    let engine = Engine::new();
    let service = engine.service();
    let first = PlanIntent::Create(SetupDraft { change: version("Site", "1.0.0"), resources: vec![sandbox("db", json!({})), sandbox("app", json!({ "environment": { "V": "1" } })), sandbox("old", json!({}))] });
    let plan = service.plan(first).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    let setup = plan.setup_id.clone();
    let detail = serde_json::to_value(service.get(&setup).unwrap()).unwrap();
    assert_eq!(detail["lock"]["template"]["version"], "1.0.0");
    assert!(detail["customization"]["answers"].is_object() && detail["customization"]["added"].is_array(), "{detail}");

    // Version 2 changes app, adds web, keeps db and drops old (kept, with its data).
    let resources = vec![sandbox("db", json!({})), sandbox("app", json!({ "environment": { "V": "2" } })), sandbox("web", json!({}))];
    let update = service.plan(PlanIntent::Update { setup: setup.clone(), draft: SetupDraft { change: version("Site", "2.0.0"), resources: resources.clone() } }).unwrap();
    assert!(update.notes[0].contains("moves from example/hello 1.0.0 to example/hello 2.0.0") && update.notes[0].contains("if it fails, it stays there"), "{:?}", update.notes);
    assert!(update.notes.iter().any(|note| note == "New: web. Changed: app. Unchanged: db. No longer in the template, kept: old."), "{:?}", update.notes);
    assert!(update.notes.iter().any(|note| note.contains("old is no longer in the template. It is kept")));

    // Submitted but not finished: still on 1.0.0.
    let operation = op();
    service.submit(&update, &operation, update.base_revision, no_secrets()).unwrap();
    assert_eq!(service.snapshot().instances[&setup].source.version(), "1.0.0");
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    let registry = service.snapshot();
    let instance = &registry.instances[&setup];
    assert_eq!(instance.source.version(), "2.0.0");
    assert_eq!(instance.lock.as_ref().unwrap()["template"]["version"], "2.0.0");
    assert!(instance.resources.contains_key("old"), "a dropped resource is never deleted by an update");

    // A failed update keeps the base it had.
    engine.state().fail_install = true;
    let mut broken = resources;
    broken[1] = sandbox("app", json!({ "environment": { "V": "2" }, "tools": [tool("claude", json!({}))] }));
    let update = service.plan(PlanIntent::Update { setup: setup.clone(), draft: SetupDraft { change: version("Site", "3.0.0"), resources: broken } }).unwrap();
    let operation = op();
    service.apply(&update, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    assert_eq!(service.snapshot().instances[&setup].source.version(), "2.0.0");
}

#[tokio::test]
async fn a_new_image_with_data_is_named_as_forward_only_before_apply() {
    let engine = Engine::new();
    let service = engine.service();
    let (plan, _) = created(&service, "Db", vec![sandbox("db", json!({ "volumes": [{ "source": "data", "target": "/var/lib/data" }] }))]).await;
    let newer = sandbox("db", json!({ "image": "example/db:2.0.0", "volumes": [{ "source": "data", "target": "/var/lib/data" }] }));
    let update = service.plan(update(&plan.setup_id, vec![newer])).unwrap();
    assert!(update.notes.iter().any(|note| note.contains("This can't be undone") && note.contains("Back the volumes up first")), "{:?}", update.notes);
}

// ----- Joining a grid with an invitation -----

#[tokio::test]
async fn joining_with_an_invitation_plans_a_membership_without_keeping_the_invitation() {
    use yougori_grid::{invite, net::HubAddress};
    let bench = NeoBench::new();
    let service = bench.service();
    let code = invite::encode(&invite::Invite { company: "Acme".into(), address: HubAddress::Direct("10.0.0.5:7460".parse().unwrap()), fingerprint: format!("{}AB", "01:".repeat(31)) });
    let plan = service.plan(service.joining(&code).unwrap()).unwrap();
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.steps[0].spec["profile"], "neo_grid");
    assert_eq!(plan.change.as_ref().unwrap().name, "Acme Neo Grid");
    assert!(!serde_json::to_string(&plan).unwrap().contains(&code), "the invitation is never in the plan");
    let secrets = BTreeMap::from([("invitation".to_owned(), code.clone()), ("join_password".to_owned(), "correct horse battery".to_owned())]);
    let operation = op();
    service.apply(&plan, &operation, secrets).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert!(bench.state().member.is_some());
    assert!(!fs::read_to_string(service.store().path()).unwrap().contains("grid-invite:"));

    let desk = invite::encode_desk(&invite::Invite { company: "Acme".into(), address: HubAddress::Direct("10.0.0.5:7461".parse().unwrap()), fingerprint: format!("{}AB", "01:".repeat(31)) });
    assert_eq!(service.plan(service.joining(&desk).unwrap()).unwrap().steps[0].spec["profile"], "sandbox_grid");
    let access = invite::encode_access(&invite::Invite { company: "Acme".into(), address: HubAddress::Direct("10.0.0.5:7465".parse().unwrap()), fingerprint: format!("{}AB", "01:".repeat(31)) });
    assert_eq!(service.joining(&access).err().unwrap().code, "unsupported_here");
    assert_eq!(service.joining("hello").err().unwrap().code, "invalid_request");
}

// ----- Reaching a service on this network, and its health path -----

fn publication(id: &str, target: &str, port: u16, access: &str, extra: Value) -> DeclaredResource {
    let mut spec = json!({ "target": { "resource": target }, "port": port, "access": access });
    spec.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    DeclaredResource { id: id.into(), kind: Kind::ServicePublication, spec, requires: vec![target.into()], owner: None }
}

/// PROVES a service open to this network listens at the setup's own port here for every computer
/// of the network, shows that address, closes it when the setup stops and when it is removed, and
/// opens it again on start.
#[tokio::test]
async fn a_service_on_this_network_opens_its_own_port_and_closes_it_with_the_setup() {
    let engine = Engine::new();
    let service = engine.service();
    let app = sandbox("app", json!({ "ports": [8080] }));
    let (plan, _) = created(&service, "Office", vec![app, publication("web", "app", 8080, "lan", json!({}))]).await;
    let setup = plan.setup_id.clone();
    let sandbox_id = service.snapshot().instances[&setup].resources["app"].runtime_id.clone().unwrap();
    let here = super::ordinary::here_port(&setup, "web");
    assert_eq!(engine.state().lan.get(&(sandbox_id.clone(), 8080)).map(|(_, host)| *host), Some(here), "{:?}", engine.state().lan);
    assert!(engine.state().here.is_empty(), "it is not also a port for this computer only");

    let stop = service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap();
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().lan.is_empty(), "stopped, nothing listens for the network");
    let start = service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap();
    service.apply(&start, &op(), no_secrets()).await.unwrap();
    assert_eq!(engine.state().lan.len(), 1, "started again, it listens again");

    // Kept to this computer instead, the network opening is closed and a port here opens.
    let change = service.plan(update(&setup, vec![sandbox("app", json!({ "ports": [8080] })), publication("web", "app", 8080, "private", json!({}))])).unwrap();
    service.apply(&change, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().lan.is_empty(), "{:?}", engine.state().lan);
    assert_eq!(engine.state().here.values().collect::<Vec<_>>(), [&here]);

    let back = service.plan(update(&setup, vec![sandbox("app", json!({ "ports": [8080] })), publication("web", "app", 8080, "lan", json!({}))])).unwrap();
    service.apply(&back, &op(), no_secrets()).await.unwrap();
    assert_eq!(engine.state().lan.len(), 1);
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(engine.state().lan.is_empty(), "removed, its opening goes with it");
}

/// PROVES a publication's own health path decides its health: ready when the path answers the
/// status the template expects, degraded when it answers another or nothing, and not a fault at
/// all while the sandbox is stopped.
#[tokio::test]
async fn a_health_path_answers_for_the_service_at_its_address() {
    let engine = Engine::new();
    let service = engine.service();
    // The sandbox has its own check too, as a generated template gives it, and it passes: what
    // is left to decide the setup's health is the address.
    let app = sandbox("app", json!({ "ports": [8080], "health": { "port": 8080, "path": "/healthz" } }));
    let web = publication("web", "app", 8080, "private", json!({ "health": { "path": "/healthz", "expected_status": 204 } }));
    let (plan, _) = created(&service, "Checked", vec![app, web]).await;
    let setup = plan.setup_id.clone();
    engine.state().readiness.insert("app".into(), json!({"ready": true, "applicationVerified": true, "verifiedPublicly": false, "retryable": false, "stages": {"publicHttps": {"status": "notConfigured"}}}));
    let address = format!("http://127.0.0.1:{}/healthz", super::ordinary::here_port(&setup, "web"));

    engine.state().answers.insert(address.clone(), 204);
    service.refresh(&setup).await.unwrap();
    assert_eq!(service.snapshot().instances[&setup].health, super::model::Health::Ready);

    engine.state().answers.insert(address.clone(), 503);
    service.refresh(&setup).await.unwrap();
    assert_eq!(service.snapshot().instances[&setup].health, super::model::Health::Degraded);

    engine.state().answers.remove(&address);
    service.refresh(&setup).await.unwrap();
    assert_eq!(service.snapshot().instances[&setup].health, super::model::Health::Degraded, "nothing answering is not healthy");
}

// ----- Storage drive -----

/// PROVES a template that has the person choose its drive waits for that choice when this
/// computer has more than one drive it could use, takes the only one there is without asking,
/// and is planned as usual once one is chosen.
#[tokio::test]
async fn a_template_with_storage_drive_waits_for_the_drive_on_a_computer_with_several() {
    let engine = Engine::new();
    let service = engine.service();
    let draft = json!({
        "name": "On a drive",
        "capabilities": {
            "web.service": { "selected": true, "mode": "required", "settings": { "image": "ghcr.io/example/app:1.0.0" } },
            "data.storage_drive": { "selected": true, "mode": "required" }
        }
    });
    let call = |drives: &[&str], chosen: Option<&str>| {
        let mut request = json!({ "draft": draft, "name": "On a drive", "answers": [{ "field": "image", "value": "ghcr.io/example/app:1.0.0" }] });
        if let Some(drive) = chosen {
            request["storageDrive"] = json!(drive);
        }
        let mut call: super::planning::PlanCall = serde_json::from_value(request).unwrap();
        call.set_drives(drives.iter().map(|drive| (*drive).to_owned()).collect());
        call
    };
    let refused = super::planning::plan(&planner_host(), &NoHub, &service, call(&["C:\\", "D:\\"], None)).await.unwrap_err();
    assert_eq!(refused.field.as_deref(), Some("storageDrive"), "{refused:?}");
    assert!(refused.message.contains(r"C:\, D:\"), "{}", refused.message);
    let only = super::planning::plan(&planner_host(), &NoHub, &service, call(&["C:\\"], None)).await.unwrap_or_else(|problem| panic!("{problem:?}"));
    assert!(only["notes"].to_string().contains("the one drive of this computer"), "{only}");
    super::planning::plan(&planner_host(), &NoHub, &service, call(&["C:\\", "D:\\"], Some("D:\\"))).await.unwrap_or_else(|problem| panic!("{problem:?}"));
}

// ----- Watching: health, restarts and notifications -----

#[derive(Default)]
struct Told {
    notices: std::sync::Mutex<Vec<(String, String)>>,
    restarts: std::sync::Mutex<Vec<String>>,
}

impl super::watch::Effects for Told {
    fn notify(&self, title: &str, body: &str) {
        self.notices.lock().unwrap().push((title.to_owned(), body.to_owned()));
    }
    fn restart<'a>(&'a self, sandbox: &'a str) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.restarts.lock().unwrap().push(sandbox.to_owned());
            Ok(())
        })
    }
}

/// PROVES a setup with Health check and Notifications is checked by the watcher on its own: the
/// person is told once when it stops being healthy and once when it is healthy again, and the
/// service is restarted after three failing checks in a row, once.
#[tokio::test]
async fn the_watcher_tells_when_a_service_stops_answering_and_restarts_it_after_three_checks() {
    let engine = Engine::new();
    let service = engine.service();
    let draft = json!({
        "name": "Watched",
        "capabilities": {
            "web.service": { "selected": true, "mode": "required", "settings": { "image": "ghcr.io/example/app:1.0.0" } },
            "web.private": { "selected": true, "mode": "default" },
            "web.health": { "selected": true, "mode": "required", "settings": { "health_path": "/healthz" } },
            "run.notifications": { "selected": true, "mode": "required" }
        }
    });
    let call = serde_json::from_value(json!({ "draft": draft, "name": "Watched", "answers": [{ "field": "image", "value": "ghcr.io/example/app:1.0.0" }, { "field": "health_path", "value": "/healthz" }] })).unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap_or_else(|problem| panic!("{problem:?}"));
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    service.apply(&reviewed, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    engine.state().readiness.insert("app".into(), json!({"ready": true, "applicationVerified": true, "verifiedPublicly": false, "retryable": false, "stages": {"publicHttps": {"status": "notConfigured"}}}));
    let address = format!("http://127.0.0.1:{}/healthz", super::ordinary::here_port(&setup, "web"));
    engine.state().answers.insert(address.clone(), 200);

    let told = Arc::new(Told::default());
    let watcher = super::watch::Watcher::new(service.clone(), told.clone());
    assert!(watcher.tick().await.is_empty(), "healthy at the first look: nothing to say");
    assert_eq!(service.snapshot().instances[&setup].health, super::model::Health::Ready);

    engine.state().answers.insert(address.clone(), 500);
    let did = watcher.tick().await;
    assert_eq!(did, [format!("told {setup}: unhealthy")]);
    let (title, body) = told.notices.lock().unwrap().last().cloned().unwrap();
    assert_eq!(title, "Watched needs attention");
    assert!(body.contains("/healthz answered 500"), "{body}");
    assert!(watcher.tick().await.is_empty(), "said once, not every minute");
    let third = watcher.tick().await;
    assert!(third.iter().any(|line| line == &format!("restarted app of {setup}")), "{third:?}");
    assert_eq!(told.restarts.lock().unwrap().len(), 1);
    assert!(told.notices.lock().unwrap().iter().any(|(title, _)| title == "Watched was restarted"));
    for _ in 0..3 {
        watcher.tick().await;
    }
    assert_eq!(told.restarts.lock().unwrap().len(), 1, "not again within fifteen minutes");

    engine.state().answers.insert(address, 200);
    assert_eq!(watcher.tick().await, [format!("told {setup}: healthy again")]);
}

/// PROVES a setup without any of the watched capabilities is never told about or restarted by
/// the watcher.
#[tokio::test]
async fn the_watcher_leaves_setups_that_did_not_ask_alone() {
    let engine = Engine::new();
    let service = engine.service();
    let (plan, _) = created(&service, "Plain", vec![sandbox("app", json!({}))]).await;
    let told = Arc::new(Told::default());
    let watcher = super::watch::Watcher::new(service.clone(), told.clone());
    assert!(watcher.tick().await.is_empty());
    assert!(told.notices.lock().unwrap().is_empty() && told.restarts.lock().unwrap().is_empty());
    let _ = plan;
}

// ----- Run on an event -----

/// Jobs that are sent and finish at once, counted.
#[derive(Default)]
struct SentJobs {
    sent: std::sync::Mutex<Vec<String>>,
}

impl super::jobs::JobCalls for SentJobs {
    fn open_queue<'a>(&'a self, _setup: &'a str, queue: &'a str) -> super::ordinary::BoxFuture<'a, Result<String, String>> {
        Box::pin(async move { Ok(queue.to_owned()) })
    }
    fn submit<'a>(&'a self, _setup: &'a str, _queue: &'a str, label: &'a str, _spec: &'a Value, _inputs: Vec<(String, String)>) -> super::ordinary::BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let mut sent = self.sent.lock().unwrap();
            sent.push(label.to_owned());
            Ok(format!("job-{}", sent.len()))
        })
    }
    fn look<'a>(&'a self, _setup: &'a str, _job: &'a str) -> super::ordinary::BoxFuture<'a, Result<Option<Value>, String>> {
        Box::pin(async { Ok(Some(json!({"state": "succeeded"}))) })
    }
    fn outputs<'a>(&'a self, _setup: &'a str, _job: &'a str) -> super::ordinary::BoxFuture<'a, Result<Vec<(String, String)>, String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn withdraw<'a>(&'a self, _setup: &'a str, _job: &'a str) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn admit<'a>(&'a self, _setup: &'a str, _queue: &'a str, _open: bool) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn pause<'a>(&'a self, _setup: &'a str, _queue: &'a str, _drain: bool) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn workers<'a>(&'a self, _setup: &'a str, _queue: &'a str, _running: bool) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn store<'a>(&'a self, _setup: &'a str) -> super::ordinary::BoxFuture<'a, Result<Value, String>> {
        Box::pin(async { Ok(json!({"present": true})) })
    }
    fn keep<'a>(&'a self, _setup: &'a str, _max_gb: f64, _days: Option<u32>) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

/// PROVES a job with a webhook trigger gets an address of its own on this computer whose secret
/// part is the only way in: a POST runs the job once more, a second within ten seconds is told
/// to wait, a GET or a wrong secret runs nothing, a stopped setup runs nothing, and the address
/// goes when the setup does.
#[tokio::test]
async fn a_jobs_event_address_runs_it_again_and_nothing_else_does() {
    let engine = Engine::new();
    let sent = Arc::new(SentJobs::default());
    let jobs = super::jobs::Jobs::new(sent.clone());
    let mut handlers = Handlers::default();
    for each in super::ordinary::Ordinary::new(engine.projects.clone(), engine.setups.join("projects")).handlers().into_iter().chain(jobs.handlers()) {
        handlers.register(each);
    }
    let service = Arc::new(Service::open(&engine.setups, &engine.data, handlers));
    let job = DeclaredResource {
        id: "build".into(),
        kind: Kind::Job,
        spec: json!({"image": "python:3.12-slim", "command": ["python3", "-V"], "trigger": {"webhook": {"access": "private"}}}),
        requires: Vec::new(),
        owner: None,
    };
    let (plan, _) = created(&service, "Hooked", vec![job]).await;
    let setup = plan.setup_id.clone();
    let events = super::events::Events::new(service.clone(), jobs.clone(), None, jobs.urls(), false);
    events.sync(&setup).await;
    let url = events.url(&setup, "build").expect("an address once synced");
    assert!(url.starts_with(&format!("http://127.0.0.1:{}/event/", super::events::event_port(&setup, "build"))), "{url}");
    service.refresh_outputs(&setup).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let before = sent.sent.lock().unwrap().len();
    let ran = client.post(&url).body("{}").send().await.unwrap();
    assert_eq!(ran.status().as_u16(), 202);
    assert_eq!(sent.sent.lock().unwrap().len(), before + 1, "one more run");
    assert!(sent.sent.lock().unwrap().last().unwrap().contains("/build/event/"), "sent under the event's own key");
    assert_eq!(client.post(&url).send().await.unwrap().status().as_u16(), 429, "not twice within ten seconds");
    assert_eq!(client.get(&url).send().await.unwrap().status().as_u16(), 405);
    // Another last digit: the secret is hex, so a fixed "0" was the secret itself one run in 16.
    let last = if url.ends_with('0') { '1' } else { '0' };
    let wrong = format!("{}{last}", &url[..url.len() - 1]);
    assert_eq!(client.post(&wrong).send().await.unwrap().status().as_u16(), 404);
    assert_eq!(sent.sent.lock().unwrap().len(), before + 1, "nothing else ran it");
    assert_eq!(jobs.runs(&setup, "build").await.len(), 0, "the test's job calls keep no run list");

    let stop = service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap();
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    let refused = events.fire(&setup, "build", "a test").await.unwrap_err();
    assert_eq!(refused.status, 409);

    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    events.sync(&setup).await;
    assert_eq!(events.url(&setup, "build"), None, "the address went with the setup");
    assert!(client.post(&url).send().await.is_err(), "nothing listens there any more");
}

/// PROVES a job that watches its folder runs again when a file there changes, and not when
/// nothing did.
#[tokio::test]
async fn a_change_in_a_watched_folder_runs_the_job_again() {
    let engine = Engine::new();
    let sent = Arc::new(SentJobs::default());
    let jobs = super::jobs::Jobs::new(sent.clone());
    let mut handlers = Handlers::default();
    for each in super::ordinary::Ordinary::new(engine.projects.clone(), engine.setups.join("projects")).handlers().into_iter().chain(jobs.handlers()) {
        handlers.register(each);
    }
    let service = Arc::new(Service::open(&engine.setups, &engine.data, handlers));
    let folder = tempfile::tempdir().unwrap();
    let job = DeclaredResource {
        id: "build".into(),
        kind: Kind::Job,
        spec: json!({"image": "python:3.12-slim", "command": ["python3", "-V"], "source": {"binding": "code"}, "source_folder": folder.path().to_string_lossy(), "trigger": {"source_changes": true}}),
        requires: Vec::new(),
        owner: None,
    };
    let (plan, _) = created(&service, "Watched folder", vec![job]).await;
    let setup = plan.setup_id.clone();
    let events = super::events::Events::new(service.clone(), jobs.clone(), None, jobs.urls(), false);
    events.sync(&setup).await;
    assert!(events.look_at_folders().await.is_empty(), "nothing changed");
    std::fs::write(folder.path().join("new.txt"), b"hello").unwrap();
    assert_eq!(events.look_at_folders().await, [format!("{setup}/build")]);
    assert!(events.look_at_folders().await.is_empty(), "the same change runs it once");
}

// ----- Roles, company sign-in and invitations in a grid -----

fn sandbox_desks() -> DeclaredResource {
    DeclaredResource { id: "company".into(), kind: Kind::Grid, spec: json!({ "profile": "sandbox_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan", "secrets": { "join_password": "apply.grid_password" } }), requires: Vec::new(), owner: None }
}

fn binding(id: &str, spec: Value) -> DeclaredResource {
    let mut requires = vec!["company".to_owned()];
    if id != "owner" && spec["admin"].is_null() {
        requires.push("owner".into());
    }
    DeclaredResource { id: id.into(), kind: Kind::AccessBinding, spec, requires, owner: None }
}

/// PROVES a person added to an Access Grid gets the role their binding names, a change to the
/// role is made in place on the same account, and a role an Access Grid doesn't have is refused
/// before anything is made.
#[tokio::test]
async fn an_access_grid_person_gets_their_role_and_it_changes_in_place() {
    let bench = NeoBench::new();
    let service = bench.service();
    let approver = |role: &str| binding("bob", json!({ "grid": { "resource": "company" }, "people": "team", "roles": [role], "person": { "username": "bob" }, "secrets": { "password": "apply.person_password" } }));
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada"), approver("approver")])).unwrap();
    service.apply(&plan, &op(), access_secrets()).await.unwrap();
    let permission = |bench: &NeoBench| bench.state().access_people.iter().find(|person| person["username"] == "bob").map(|person| person["permission"].clone());
    assert_eq!(permission(&bench), Some(json!("approver")));
    let id = service.snapshot().instances[&plan.setup_id].resources["bob"].runtime_id.clone();

    let change = service.plan(PlanIntent::Update { setup: plan.setup_id.clone(), draft: SetupDraft { change: change("Acme"), resources: vec![access_grid(), access_admin("ada"), approver("auditor")] } }).unwrap();
    assert!(change.steps.iter().any(|step| step.resource == "bob" && step.action == Action::Update), "{:?}", change.steps);
    let operation = op();
    service.apply(&change, &operation, access_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(permission(&bench), Some(json!("auditor")));
    assert_eq!(service.snapshot().instances[&plan.setup_id].resources["bob"].runtime_id, id, "the same account");

    let refused = service.plan(create("Other", vec![access_grid(), access_admin("ada"), approver("operator")])).unwrap_err();
    assert_eq!(refused.code, "unsupported_here", "{refused:?}");
}

/// PROVES a Sandbox Grid person is given their administrative role right after they are added,
/// and an approver, which only an Access Grid has, is refused.
#[tokio::test]
async fn a_sandbox_grid_person_is_given_their_role() {
    let bench = NeoBench::new();
    let service = bench.service();
    let person = |role: &str| DeclaredResource { id: "bob".into(), kind: Kind::AccessBinding, spec: json!({ "grid": { "resource": "company" }, "people": "team", "roles": [role], "person": { "username": "bob" }, "secrets": { "password": "apply.person_password" } }), requires: vec!["company".into()], owner: None };
    let plan = service.plan(create("Desks", vec![sandbox_desks(), person("operator")])).unwrap();
    let mut secrets = password();
    secrets.insert("person_password".into(), "a long person password".into());
    let operation = op();
    service.apply(&plan, &operation, secrets).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().people.iter().find(|person| person["username"] == "bob").map(|person| person["adminRole"].clone()), Some(json!("operator")));
    assert_eq!(service.plan(create("Other", vec![sandbox_desks(), person("approver")])).unwrap_err().code, "unsupported_here");
}

/// PROVES company sign-in is set on the grid this setup made, in each product's own words, and a
/// Sandbox Grid's is turned off when the setup goes (an Access Grid goes with its setup).
#[tokio::test]
async fn company_sign_in_is_set_on_the_grid_and_turned_off_with_the_setup() {
    let bench = NeoBench::new();
    let service = bench.service();
    let sso = json!({ "issuer": "https://login.example.com/acme", "client_id": "yougori-desktop", "username_claim": "upn", "passwordless": true });
    let sign_in = binding("sign_in", json!({ "grid": { "resource": "company" }, "people": "team", "sso": sso }));
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada"), sign_in])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, access_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let set = bench.state().access_sso.clone().expect("set");
    assert_eq!((set["issuer"].as_str(), set["clientId"].as_str(), set["claim"].as_str(), set["passwordless"].as_bool()), (Some("https://login.example.com/acme"), Some("yougori-desktop"), Some("upn"), Some(true)));
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.apply(&remove, &operation, access_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert!(bench.state().calls.iter().any(|call| call == "access_manage"), "the grid was asked");

    // A Sandbox Grid names the claim its own way.
    let bench = NeoBench::new();
    let service = bench.service();
    let sign_in = DeclaredResource { id: "sign_in".into(), kind: Kind::AccessBinding, spec: json!({ "grid": { "resource": "company" }, "people": "team", "sso": sso }), requires: vec!["company".into()], owner: None };
    let plan = service.plan(create("Desks", vec![sandbox_desks(), sign_in])).unwrap();
    service.apply(&plan, &op(), password()).await.unwrap();
    assert_eq!(bench.state().desk_sso.as_ref().and_then(|sso| sso["usernameClaim"].as_str()), Some("upn"));
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert_eq!(bench.state().desk_sso, None, "turned off with the setup");
}

/// PROVES an invited person's account is made with a password nobody typed, their invitation is
/// a private output that carries it with the grid's invite, it signs a computer in as them, and
/// removing them forgets it.
#[tokio::test]
async fn an_invited_person_signs_in_with_their_invitation_alone() {
    let bench = NeoBench::new();
    let service = bench.service();
    let invitee = binding("invitee", json!({ "grid": { "resource": "company" }, "people": "team", "roles": ["member"], "person": { "username": "cleo" }, "invite": true }));
    let plan = service.plan(create("Acme", vec![access_grid(), access_admin("ada"), invitee])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, access_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let made = bench.state().access_people.iter().find(|person| person["username"] == "cleo").cloned().expect("cleo was added");
    let password = made["password"].as_str().unwrap().to_owned();
    assert!(password.len() >= 20, "a password nobody types: {password}");
    let kept = bench.state().vault.values().cloned().collect::<Vec<_>>();
    assert_eq!(kept, [password.clone()], "kept on this computer for the invitation, and nowhere else");

    // The invitation, as its part gives it.
    let resource = service.snapshot().instances[&plan.setup_id].resources["invitee"].clone();
    let handler = super::grids::Grids::new(bench.grids.clone()).handlers().into_iter().find(|handler| handler.kind() == Kind::AccessBinding).unwrap();
    let peers = service.snapshot().instances[&plan.setup_id]
        .resources
        .iter()
        .filter(|(id, _)| *id != "invitee")
        .map(|(id, peer)| (id.clone(), super::handler::Peer { kind: peer.kind, spec: peer.spec.clone(), runtime_id: peer.runtime_id.clone(), owned: true }))
        .collect();
    let context = super::handler::StepContext {
        setup: plan.setup_id.clone(),
        operation: "op-read".into(),
        step: "read".into(),
        resource: "invitee".into(),
        kind: Kind::AccessBinding,
        action: Action::Create,
        label: "read".into(),
        created_label: None,
        generation: 1,
        spec: resource.spec.clone(),
        runtime_id: resource.runtime_id.clone(),
        owner: None,
        peers,
        planned: BTreeMap::new(),
        cancel: tokio_util::sync::CancellationToken::new(),
        secrets: Arc::new(BTreeMap::new()),
        started_at: None,
        recorded: None,
        consents: Arc::new(Default::default()),
    };
    let outputs = handler.outputs(&context).await.unwrap();
    let invitation = outputs.get("invitation").cloned().expect("an invitation");
    let decoded = super::grids::scoped::decode(&invitation).expect("it reads back");
    assert_eq!((decoded.username.as_str(), decoded.password.as_str()), ("cleo", password.as_str()));
    assert!(decoded.invite.starts_with(yougori_grid::invite::ACCESS_PREFIX), "{}", decoded.invite);

    // Another computer signs in with it: no username or password typed.
    let other = NeoBench::new();
    let joining = other.service();
    let intent = joining.joining(&invitation).unwrap();
    let joined = joining.plan(intent).unwrap();
    let operation = op();
    joining.apply(&joined, &operation, BTreeMap::from([("invitation".to_owned(), invitation.clone())])).await.unwrap();
    assert_eq!(state_of(&joining, &operation), OperationState::Completed, "{:?}", joining.operation(&operation, 0).unwrap().error);
    assert_eq!(other.state().access_member.as_deref(), Some("cleo"));

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(bench.state().vault.is_empty(), "removed, their password is forgotten");
}

// ----- Picked computers, rented GPUs and a company's own cloud -----

fn picked_pool(computers: Value) -> DeclaredResource {
    DeclaredResource {
        id: "computers".into(),
        kind: Kind::ComputePool,
        spec: json!({ "grid": { "resource": "company" }, "source": "selected_computers", "computers": computers }),
        requires: vec!["company".into()],
        owner: None,
    }
}

fn rented_pool(cloud: Value) -> DeclaredResource {
    DeclaredResource { id: "rented".into(), kind: Kind::ComputePool, spec: json!({ "grid": { "resource": "company" }, "source": "cloud", "cloud": cloud }), requires: vec!["company".into()], owner: None }
}

fn rented_gpu(budget: Option<f64>) -> DeclaredResource {
    let mut cloud = json!({ "provider": "runpod", "gpu_type": "NVIDIA GeForce RTX 4090", "max_hourly_cost": 0.8 });
    if let Some(budget) = budget {
        cloud["budget_usd"] = json!(budget);
    }
    rented_pool(cloud)
}

fn company_cloud() -> DeclaredResource {
    rented_pool(json!({
        "provider": "aws", "account": "acme-prod", "region": "eu-west-1", "image": "ami-0abc", "machine_type": "t3.large", "subnet": "subnet-1",
        "security_group": "sg-1", "key_pair": "acme", "username": "ubuntu", "max_computers": 2,
        "identity_file": { "binding": "cloud_key" }, "identity_path": "C:/Users/ada/.ssh/acme.pem"
    }))
}

/// PROVES a Neo Grid model on picked computers runs only on those of them that have joined, found
/// by the names they joined with in any case, and waits, retryable, while none has.
#[tokio::test]
async fn a_neo_model_runs_only_on_the_picked_computers_that_have_joined() {
    let bench = NeoBench::new();
    let service = bench.service();
    let model = neo_model("first", "hf.co/a/b", json!({}));
    let plan = service.plan(create("Acme", vec![neo_grid("create"), picked_pool(json!(["Desk-1, desk-2"])), model])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    let error = service.operation(&operation, 0).unwrap().error.unwrap();
    assert_eq!(error.code, "waiting_for_computer", "{error:?}");
    assert!(bench.state().plans.is_empty(), "no model was added anywhere else");

    bench.state().hub.as_mut().unwrap()["members"] = json!([
        { "id": "m-1", "name": "desk-1" },
        { "id": "m-2", "name": "DESK-2" },
        { "id": "m-3", "name": "reception" }
    ]);
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.plans.len(), 1);
    assert_eq!(state.plans[0]["computers"], json!(["m-1", "m-2"]));
}

/// PROVES a Sandbox Grid this setup makes is told to place desks only on the picked computers, the
/// rule is lifted when the setup goes, and picking computers of a grid the setup only joins is
/// refused at review.
#[tokio::test]
async fn a_sandbox_grid_takes_desks_only_on_the_picked_computers_until_the_setup_goes() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Desks", vec![sandbox_desks(), picked_pool(json!(["desk-1", "desk-2"]))])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().desk_only, Some(json!(["desk-1", "desk-2"])));

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert_eq!(bench.state().desk_only, None, "lifted with the setup");

    let mut joined = picked_pool(json!(["desk-1"]));
    joined.spec["grid"] = json!({ "resource": "membership" });
    joined.requires = vec!["membership".into()];
    assert_eq!(service.plan(create("Member", vec![neo_grid("join"), joined])).unwrap_err().code, "unsupported_here");
    assert_eq!(service.plan(create("Empty", vec![sandbox_desks(), picked_pool(json!([" , "]))])).unwrap_err().code, "invalid_spec");
}

/// PROVES a rented GPU is rented only once a RunPod account is connected, at the hourly price the
/// template allows, joins the grid once NeoCloud shows it running, stops and starts with the
/// setup as the same pod, and is deleted with the setup.
#[tokio::test]
async fn a_rented_gpu_is_rented_at_its_price_stopped_and_started_with_the_setup_and_deleted_with_it() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Acme", vec![neo_grid("create"), rented_gpu(None)])).unwrap();
    assert!(plan.notes.iter().any(|note| note.contains("rents one NVIDIA GeForce RTX 4090 GPU from RunPod, at no more than $0.80 an hour")), "{:?}", plan.notes);
    let operation = op();
    service.apply(&plan, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Failed);
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "sign_in_needed");
    assert!(bench.state().rented.is_empty(), "nothing rented without an account to bill");

    bench.state().runpod_connected = true;
    bench.state().pod_starts = 2;
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let pod = service.snapshot().instances[&plan.setup_id].resources["rented"].runtime_id.clone().unwrap();
    {
        let state = bench.state();
        assert_eq!(state.rented.len(), 1);
        assert_eq!(state.rented[&pod]["maxHourlyUsd"], 0.8);
        assert_eq!(state.rented[&pod]["gpuId"], "NVIDIA GeForce RTX 4090");
        assert_eq!(state.pods.iter().filter(|member| member["environmentId"] == pod.as_str()).count(), 1, "it joined the grid");
    }

    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    assert!(stop.steps.iter().any(|step| step.resource == "rented"), "{:?}", stop.steps);
    assert!(!stop.steps.iter().any(|step| step.resource == "company"), "the grid keeps running for its computers");
    let operation = op();
    service.apply(&stop, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().rented[&pod]["podState"], "Exited");

    let start = service.plan(PlanIntent::Start { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.apply(&start, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert_eq!(bench.state().rented[&pod]["podState"], "Running");
    assert_eq!(bench.state().rented.len(), 1, "the same pod, not another");

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    let operation = op();
    service.apply(&remove, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert!(state.rented.is_empty() && state.pods.is_empty(), "deleted, so it stops billing");
}

/// PROVES a Sandbox Grid this setup makes is set to make computers in the company's own cloud
/// with the key file the person chose, it is cleared when the setup goes, and each cloud is
/// refused on the other kind of grid.
#[tokio::test]
async fn a_sandbox_grid_makes_computers_in_the_companys_cloud_with_the_key_file_chosen() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Desks", vec![sandbox_desks(), company_cloud()])).unwrap();
    assert!(plan.notes.iter().any(|note| note.contains("makes up to 2 computer(s) in your aws account")), "{:?}", plan.notes);
    let operation = op();
    service.apply(&plan, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let set = bench.state().desk_cloud.clone().expect("set");
    assert_eq!((set["provider"].as_str(), set["account"].as_str(), set["identityFile"].as_str(), set["maxComputers"].as_u64()), (Some("aws"), Some("acme-prod"), Some("C:/Users/ada/.ssh/acme.pem"), Some(2)));

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert_eq!(bench.state().desk_cloud, None, "cleared with the setup");

    assert_eq!(service.plan(create("Neo", vec![neo_grid("create"), company_cloud()])).unwrap_err().code, "unsupported_here");
    assert_eq!(service.plan(create("Desks", vec![sandbox_desks(), rented_gpu(None)])).unwrap_err().code, "unsupported_here");
}

/// What the budget watcher sees of rented GPUs and does to them.
struct Billed {
    pods: std::sync::Mutex<Vec<(String, f64, bool)>>,
    stopped: std::sync::Mutex<Vec<String>>,
    notices: std::sync::Mutex<Vec<(String, String)>>,
    file: PathBuf,
}

impl super::watch::Effects for Billed {
    fn notify(&self, title: &str, body: &str) {
        self.notices.lock().unwrap().push((title.to_owned(), body.to_owned()));
    }
    fn restart<'a>(&'a self, _: &'a str) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn rented<'a>(&'a self, _: &'a str) -> super::ordinary::BoxFuture<'a, Result<Vec<(String, f64, bool)>, String>> {
        Box::pin(async move { Ok(self.pods.lock().unwrap().clone()) })
    }
    fn stop_rented<'a>(&'a self, pod: &'a str) -> super::ordinary::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.stopped.lock().unwrap().push(pod.to_owned());
            for each in self.pods.lock().unwrap().iter_mut().filter(|(id, _, _)| id == pod) {
                each.2 = false;
            }
            Ok(())
        })
    }
    fn spend_file(&self) -> Option<PathBuf> {
        Some(self.file.clone())
    }
}

/// PROVES the watcher adds up what a setup's rented GPUs cost this month and stops them, once,
/// before the next minutes could take the month past its budget, saying so; GPUs well inside
/// their budget, and pods of other setups, are left running.
#[tokio::test]
async fn the_watcher_stops_rented_gpus_before_the_month_passes_their_budget() {
    let bench = NeoBench::new();
    let service = bench.service();
    bench.state().runpod_connected = true;
    let mut chosen = change("Acme");
    chosen.capabilities = vec!["grid.cloud_compute".into(), "run.budget".into(), "run.notifications".into()];
    let plan = service.plan(PlanIntent::Create(SetupDraft { change: chosen, resources: vec![neo_grid("create"), rented_gpu(Some(20.0))] })).unwrap();
    assert!(plan.notes.iter().any(|note| note.contains("stopped before this month's rented hours pass $20.00")), "{:?}", plan.notes);
    let operation = op();
    service.apply(&plan, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let pod = service.snapshot().instances[&plan.setup_id].resources["rented"].runtime_id.clone().unwrap();

    let folder = tempfile::tempdir().unwrap();
    let file = folder.path().join("rented-spend.json");
    let month = chrono::Utc::now().format("%Y-%m").to_string();
    let spent = |usd: f64| {
        let entry = format!("{}/rented", plan.setup_id);
        fs::write(&file, serde_json::to_vec(&json!({ entry: { "month": month, "spentUsd": usd, "at": chrono::Utc::now().timestamp() - 60 } })).unwrap()).unwrap();
    };
    let billed = |file: &PathBuf| Arc::new(Billed { pods: std::sync::Mutex::new(vec![(pod.clone(), 0.8, true), ("someone-elses".into(), 2.0, true)]), stopped: Default::default(), notices: Default::default(), file: file.clone() });

    spent(10.0);
    let effects = billed(&file);
    let watcher = super::watch::Watcher::new(service.clone(), effects.clone());
    assert!(watcher.tick().await.iter().all(|line| !line.contains("budget")));
    assert!(effects.stopped.lock().unwrap().is_empty(), "well inside its budget");
    let kept: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert!(kept[format!("{}/rented", plan.setup_id)]["spentUsd"].as_f64().unwrap() > 10.0, "the last minute was added: {kept}");

    spent(19.95);
    let effects = billed(&file);
    let watcher = super::watch::Watcher::new(service.clone(), effects.clone());
    let did = watcher.tick().await;
    assert!(did.contains(&format!("stopped {pod} of {} for its budget", plan.setup_id)), "{did:?}");
    assert_eq!(*effects.stopped.lock().unwrap(), [pod.clone()], "only this setup's own GPU");
    let (title, body) = effects.notices.lock().unwrap().last().cloned().unwrap();
    assert_eq!(title, "Acme reached its budget");
    assert!(body.contains("$20.00"), "{body}");

    // Started again by the person this month: it is not stopped a second time.
    effects.pods.lock().unwrap()[0].2 = true;
    watcher.tick().await;
    assert_eq!(effects.stopped.lock().unwrap().len(), 1);
}

// ----- Research on a Swarm Mining Grid -----

const AUTHORISED: &str = "The example-shop source in this folder only, with the test accounts in TESTING.md.";

fn research_grid(extra: Value) -> DeclaredResource {
    let mut spec = json!({ "profile": "swarm_mining_grid", "mode": "create", "coordinator": "this_computer", "name": "Example Shop", "access": "lan",
        "research": { "instructions": "Look at how sign-in handles unexpected input.", "authorization": AUTHORISED, "target": "source" } });
    spec.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    DeclaredResource { id: "project".into(), kind: Kind::Grid, spec, requires: Vec::new(), owner: None }
}

fn joined_review() -> DeclaredResource {
    DeclaredResource {
        id: "project".into(),
        kind: Kind::Grid,
        spec: json!({ "profile": "swarm_mining_grid", "mode": "join", "coordinator": "remote", "member": "computer", "secrets": { "invitation": "apply.invitation", "join_password": "apply.join_password" } }),
        requires: Vec::new(),
        owner: None,
    }
}

/// The review's pool, model, offline sandbox and worker; `source` is the chosen folder, if any.
fn research_parts(source: Option<&str>, report_policy: &str) -> Vec<DeclaredResource> {
    let part = |id: &str, kind: Kind, spec: Value, requires: &[&str]| DeclaredResource { id: id.into(), kind, spec, requires: requires.iter().map(|id| (*id).to_owned()).collect(), owner: None };
    let limits = json!({ "cpu": 4.0, "memory_gb": 8.0, "disk_gb": 20.0 });
    let mut workers = json!({ "pool": { "resource": "computers" }, "role": "research", "name": "Review worker", "report_policy": report_policy, "count": 1, "max": 1,
        "model": { "resource": "model" }, "environment": { "resource": "sandbox" }, "limits": limits, "budget": { "time_minutes": 60 } });
    if let Some(folder) = source {
        workers["source"] = json!({ "binding": "source_folder" });
        workers["source_folder"] = json!(folder);
    }
    vec![
        part("computers", Kind::ComputePool, json!({ "grid": { "resource": "project" }, "source": "this_computer", "gpu": "optional", "availability": "always", "local_user_first": true, "limits": limits }), &["project"]),
        part("model", Kind::ModelService, json!({ "model": "hf.co/example/review-model", "replicas": 1, "memory_gb": 16.0 }), &[]),
        part("sandbox", Kind::Environment, json!({ "type": "container", "image": "ubuntu:24.04", "cpu": 4, "memory": 8, "storage": 20, "internet": false, "working_dir": "/project", "command": ["sleep", "infinity"] }), &[]),
        part("workers", Kind::WorkerGroup, workers, &["computers", "model", "sandbox"]),
    ]
}

fn review_of(grid: DeclaredResource, source: Option<&str>, report_policy: &str) -> Vec<DeclaredResource> {
    let mut resources = vec![grid];
    resources.extend(research_parts(source, report_policy));
    resources
}

/// PROVES a review hosted here sends the authorisation exactly as the person wrote it in the review
/// they agreed to, takes in the folder they chose, starts its one worker with the model, share and
/// time budget declared, makes no model or sandbox of its own beside the worker's, stops and starts
/// with the setup, and goes with it.
#[tokio::test]
async fn a_hosted_review_sends_its_authorisation_as_written_and_reviews_the_chosen_folder() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Shop review", review_of(research_grid(json!({})), Some("D:/work/shop"), "review"))).unwrap();
    let notes = plan.notes.join("\n");
    assert!(notes.contains(AUTHORISED), "the review shows what is authorised: {notes}");
    assert!(notes.contains("a copy of D:/work/shop") && notes.contains("no internet") && notes.contains("60 minutes"), "{notes}");
    assert!(!notes.contains("download"), "the model and sandbox are the worker's, so nothing else is said of them: {notes}");
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    {
        let state = bench.state();
        assert_eq!(state.inspected, ["D:/work/shop"]);
        let hosted = state.hosted_with.clone().unwrap();
        assert_eq!(hosted["authorization"], AUTHORISED);
        assert_eq!((hosted["confirmed"].as_bool(), hosted["target"]["kind"].as_str(), hosted["address"].as_str()), (Some(true), Some("source"), Some("127.0.0.1")));
        assert_eq!(hosted["password"].as_str().unwrap().len(), 64, "a review only this computer reaches gets a password nobody types");
        let started = &state.started_with[0];
        assert_eq!((started["reportPolicy"].as_str(), started["budgetMinutes"].as_u64()), (Some("review"), Some(60)));
        assert_eq!(started["worker"]["model"], "hf.co/example/review-model");
        assert_eq!(started["worker"]["resources"], json!({ "cpu": 4, "memoryGb": 8, "storageGb": 20 }));
        assert!(state.calls.iter().all(|call| call.starts_with("bounty_") || call.starts_with("swarm_")), "nothing but the review and its worker: {:?}", state.calls);
    }
    assert_eq!(bench.engine.state().created, 0, "no sandbox beside the worker's own");
    let worker = service.snapshot().instances[&plan.setup_id].resources["workers"].runtime_id.clone().unwrap();
    let state_of_worker = |bench: &NeoBench| bench.state().workers.iter().find(|each| each["id"] == worker.as_str()).map(|each| each["state"].clone());

    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    assert_eq!(state_of_worker(&bench), Some(json!("paused")));
    let start = service.plan(PlanIntent::Start { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&start, &op(), no_secrets()).await.unwrap();
    assert_eq!(state_of_worker(&bench), Some(json!("running")));

    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    assert!(remove.notes.iter().any(|note| note.contains("deletes the review of Example Shop")), "{:?}", remove.notes);
    let operation = op();
    service.apply(&remove, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert!(state.workers.is_empty() && state.bounty.is_none(), "the worker and the review went with the setup");
}

/// PROVES a review on the network is hosted at the address and with the password given, and its
/// invitation is an output; a review already hosted here is never taken over or deleted.
#[tokio::test]
async fn a_review_on_the_network_has_an_invitation_and_one_already_here_is_left_alone() {
    let bench = NeoBench::new();
    let service = bench.service();
    let grid = research_grid(json!({ "address": "192.168.1.20", "secrets": { "join_password": "apply.shared_password" } }));
    let plan = service.plan(create("Shop review", review_of(grid, Some("D:/work/shop"), "automatic"))).unwrap();
    let secrets = BTreeMap::from([("shared_password".to_owned(), "a long shared password".to_owned())]);
    service.apply(&plan, &op(), secrets).await.unwrap();
    assert_eq!(bench.state().hosted_with.as_ref().unwrap()["password"], "a long shared password");
    assert_eq!(bench.state().started_with[0]["reportPolicy"], "automatic", "findings of a project hosted here may go to it automatically");
    let resource = &service.snapshot().instances[&plan.setup_id].resources["project"];
    assert!(resource.runtime_id.is_some());

    // Someone else's review is already hosted on this computer: a second setup refuses, and leaves it.
    let other = NeoBench::new();
    let service = other.service();
    other.state().bounty = Some(json!({ "id": "bounty-theirs", "name": "Theirs", "address": "127.0.0.1", "createdAt": 1 }));
    let plan = service.plan(create("Mine", review_of(research_grid(json!({})), Some("D:/work/mine"), "review"))).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "already_in_use");
    let state = other.state();
    assert_eq!(state.bounty.as_ref().unwrap()["id"], "bounty-theirs");
    assert!(state.inspected.is_empty() && state.workers.is_empty());
}

/// PROVES a worker on a review someone else hosts waits for the person to read that project's
/// terms and starts only once they agree to exactly those, with its findings read here first;
/// a review of a live service is never joined.
#[tokio::test]
async fn joining_a_review_waits_for_its_terms_and_starts_only_on_exactly_those() {
    let bench = NeoBench::new();
    let service = bench.service();
    let digest = "abcdef0123456789".repeat(4);
    bench.state().remote_policy = Some(json!({ "networkMode": "closed", "title": "Their Shop", "objective": "Check the checkout.", "authorization": "Their shop's source only.",
        "scopeMode": "local_source_only", "target": { "kind": "source" }, "termsDigest": digest }));
    let invitation = invite_to("bounty", "Their Shop", "AA");
    let secrets = BTreeMap::from([("invitation".to_owned(), invitation.clone()), ("join_password".to_owned(), "correct horse battery".to_owned())]);
    let plan = service.plan(create("Their review", review_of(joined_review(), None, "review"))).unwrap();
    assert!(plan.notes.iter().any(|note| note.contains("nothing starts until you do")), "{:?}", plan.notes);
    let operation = op();
    service.apply(&plan, &operation, secrets).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::AwaitingInput);
    let asked = service.operation(&operation, 0).unwrap().error.unwrap();
    assert_eq!(asked.code, "terms_to_accept");
    assert!(asked.message.contains("Their shop's source only.") && asked.message.contains("accept_terms set to abcdef012345"), "{}", asked.message);
    assert!(bench.state().tickets.is_empty() && bench.state().workers.is_empty(), "the connection is given back while the person reads");

    // Agreeing to other terms starts nothing.
    service.continue_operation(&plan.setup_id, &operation, &plan.digest, BTreeMap::from([("accept_terms".to_owned(), "000000000000".to_owned())])).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::AwaitingInput);
    assert!(bench.state().workers.is_empty());

    service.continue_operation(&plan.setup_id, &operation, &plan.digest, BTreeMap::from([("accept_terms".to_owned(), "abcdef012345".to_owned())])).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.workers.len(), 1);
    assert_eq!((state.started_with[0]["termsDigest"].as_str(), state.started_with[0]["reportPolicy"].as_str()), (Some(digest.as_str()), Some("review")));
    assert!(state.inspected.is_empty() && state.bounty.is_none(), "nothing of this computer's is hosted or taken in");
    drop(state);

    // A review that tests a live service is refused, and nothing is left connected.
    let live = NeoBench::new();
    let service = live.service();
    live.state().remote_policy = Some(json!({ "networkMode": "closed", "title": "Live", "scopeMode": "external_target", "target": { "kind": "url", "baseUrl": "https://shop.example.com" }, "termsDigest": digest }));
    let plan = service.plan(create("Live review", review_of(joined_review(), None, "review"))).unwrap();
    let operation = op();
    let secrets = BTreeMap::from([("invitation".to_owned(), invitation), ("join_password".to_owned(), "correct horse battery".to_owned()), ("accept_terms".to_owned(), "abcdef012345".to_owned())]);
    service.apply(&plan, &operation, secrets).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().error.unwrap().code, "unsupported_here");
    assert!(live.state().tickets.is_empty() && live.state().workers.is_empty());
}

/// PROVES what a review may not be is refused at review, before anything is made: research on
/// another grid's computers, a sandbox with the internet, a hosted review with no folder, a
/// finding for someone else's project sent automatically, a review with no authorisation, and a
/// live target.
#[tokio::test]
async fn what_a_review_may_not_be_is_refused_before_anything_is_made() {
    let bench = NeoBench::new();
    let service = bench.service();
    let code = |resources: Vec<DeclaredResource>| service.plan(create("Refused", resources)).unwrap_err().code;

    let mut on_neo = review_of(neo_grid("create"), None, "review");
    on_neo[0].id = "project".into();
    assert_eq!(code(on_neo), "unsupported_here");

    let mut online = review_of(research_grid(json!({})), Some("D:/work"), "review");
    online.iter_mut().find(|part| part.id == "sandbox").unwrap().spec["internet"] = json!(true);
    assert_eq!(code(online), "unsupported_here");

    assert_eq!(code(review_of(research_grid(json!({})), None, "review")), "unsupported_here", "a hosted review reviews a folder");
    assert_eq!(code(review_of(joined_review(), None, "automatic")), "unsupported_here");

    let unauthorised = research_grid(json!({ "research": { "instructions": "Look at sign-in.", "authorization": "", "target": "source" } }));
    assert_eq!(code(review_of(unauthorised, Some("D:/work"), "review")), "invalid_spec");
    let live = research_grid(json!({ "research": { "instructions": "Look at sign-in.", "authorization": AUTHORISED, "target": "url" } }));
    assert_eq!(code(review_of(live, Some("D:/work"), "review")), "unsupported_here");
    let started_without_command = research_grid(json!({ "research": { "instructions": "Look at sign-in.", "authorization": AUTHORISED, "target": "web", "port": 3000 } }));
    assert_eq!(code(review_of(started_without_command, Some("D:/work"), "review")), "invalid_spec");
    assert!(bench.state().calls.is_empty(), "nothing was asked of Swarm Mining");
}

/// PROVES the Swarm Mining Grid package plans through the engine with the folder the person chose
/// and applies: the same path as running it from My setups.
#[tokio::test]
async fn the_swarm_mining_grid_package_plans_and_applies_through_the_engine() {
    let bench = NeoBench::new();
    // Its findings' evidence is kept in a store of the setup's own, as a job's results are.
    let service = bench.service_with(super::jobs::Jobs::new(Arc::new(SentJobs::default())).handlers());
    let call = serde_json::from_value(json!({
        "source": { "kind": "local_folder", "path": grid_package("swarm-mining-grid") },
        "name": "Shop review",
        "answers": [
            { "field": "mode", "value": "host" },
            { "field": "project_title", "value": "Example Shop" },
            { "field": "target_kind", "value": "source" },
            { "field": "instructions", "value": "Look at how sign-in and the checkout handle unexpected input." },
            { "field": "authorized_scope", "value": AUTHORISED },
            { "field": "visibility", "value": "this_computer" },
            { "field": "model", "value": "hf.co/example/review-model" },
            { "field": "source_folder", "value": "D:/work/shop" }
        ]
    }))
    .unwrap();
    let planned = super::planning::plan(&planner_host(), &NoHub, &service, call).await.unwrap_or_else(|problem| panic!("{problem:?}"));
    let setup = planned["setupId"].as_str().unwrap().to_owned();
    let reviewed = service.reviewed(&setup, planned["digest"].as_str().unwrap()).unwrap();
    let operation = op();
    service.apply(&reviewed, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    let state = bench.state();
    assert_eq!(state.inspected, ["D:/work/shop"]);
    assert_eq!(state.hosted_with.as_ref().unwrap()["authorization"], AUTHORISED);
    assert_eq!(state.workers.len(), 1);
}

/// PROVES a review a setup hosts is listed once, as that setup, not also as Swarm Mining's own
/// record of a hub on this computer.
#[tokio::test]
async fn a_review_a_setup_hosts_is_listed_once() {
    let bench = NeoBench::new();
    let service = bench.service();
    let plan = service.plan(create("Shop review", review_of(research_grid(json!({})), Some("D:/work/shop"), "review"))).unwrap();
    service.apply(&plan, &op(), no_secrets()).await.unwrap();
    // The product writes its own records, as the real one does.
    fs::create_dir_all(bench.engine.data.join("bounty")).unwrap();
    fs::write(bench.engine.data.join("bounty/host.json"), b"{}").unwrap();
    let worker = service.snapshot().instances[&plan.setup_id].resources["workers"].runtime_id.clone().unwrap();
    fs::create_dir_all(bench.engine.data.join("swarm")).unwrap();
    fs::write(bench.engine.data.join("swarm/workers.json"), serde_json::to_vec(&json!({ worker.clone(): { "id": worker } })).unwrap()).unwrap();
    let listed = bench.service().list().unwrap();
    assert_eq!(listed.len(), 1, "{:?}", listed.iter().map(|setup| setup.setup_id.clone()).collect::<Vec<_>>());
    assert!(!listed[0].adopted_legacy);
    // A worker the person started in Swarm Mining itself keeps Swarm Mining's record listed.
    fs::write(bench.engine.data.join("swarm/workers.json"), serde_json::to_vec(&json!({ worker.clone(): { "id": worker }, "worker-theirs": { "id": "worker-theirs" } })).unwrap()).unwrap();
    assert_eq!(bench.service().list().unwrap().len(), 2);
}

/// PROVES a Sandbox Grid this setup makes requires two-step sign-in of everyone when its rule says
/// so, the rule is lifted with the setup, and two-step on one person's binding is refused before
/// anything is made, since on a Sandbox Grid it is a rule for everyone.
#[tokio::test]
async fn a_sandbox_grid_requires_two_step_of_everyone_until_the_setup_goes() {
    let bench = NeoBench::new();
    let service = bench.service();
    let rule = DeclaredResource { id: "two_step".into(), kind: Kind::AccessBinding, spec: json!({ "grid": { "resource": "company" }, "people": "team", "mfa": true }), requires: vec!["company".into()], owner: None };
    let plan = service.plan(create("Desks", vec![sandbox_desks(), rule])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, password()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    assert!(bench.state().desk_two_step, "the grid requires it");
    let remove = service.plan(PlanIntent::Remove { setup: plan.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert!(!bench.state().desk_two_step, "lifted with the setup");

    let person = DeclaredResource { id: "bob".into(), kind: Kind::AccessBinding, spec: json!({ "grid": { "resource": "company" }, "people": "team", "person": { "username": "bob" }, "mfa": true, "secrets": { "password": "apply.person_password" } }), requires: vec!["company".into()], owner: None };
    assert_eq!(service.plan(create("Other", vec![sandbox_desks(), person])).unwrap_err().code, "unsupported_here");
}

/// PROVES a start reaches a running resource whose handler has something to renew, and only that:
/// two connected VM sandboxes are created and granted; their grant lapses; starting the setup again
/// grants it anew through each handler's start, without launching anything twice.
#[cfg(windows)]
#[tokio::test]
async fn starting_a_running_setup_renews_its_vm_connection_grants() {
    let engine = Engine::new();
    let scripted = Arc::new(super::vm_sandbox::fakes::Scripted::default());
    let mut handlers = Handlers::default();
    for each in super::vm_sandbox::VmSandboxHandler::new(scripted.clone()).handlers() {
        handlers.register(each);
    }
    let service = Arc::new(Service::open(&engine.setups, &engine.data, handlers));
    let vm = |id: &str, spec: Value| DeclaredResource { id: id.into(), kind: Kind::VmSandbox, spec, requires: Vec::new(), owner: None };
    let (plan, _) = created(&service, "Boxes", vec![
        vm("server", json!({ "memory_gb": 0.5, "publish": [{ "service": "api", "port": 8080, "accept": ["client"] }] })),
        vm("client", json!({ "memory_gb": 0.5, "connect": [{ "name": "server", "to": "server", "service": "api" }] })),
    ]).await;
    let active = |scripted: &super::vm_sandbox::fakes::Scripted| scripted.grants.lock().unwrap().values().filter(|(_, _, state)| state == "active").count();
    assert_eq!(active(&scripted), 1, "created and granted");
    let launches = scripted.actions().iter().filter(|action| *action == "launch").count();
    assert_eq!(launches, 2);
    scripted.grants.lock().unwrap().values_mut().for_each(|(_, _, state)| *state = "expired".into());
    let start = service.plan(PlanIntent::Start { setup: plan.setup_id.clone() }).unwrap();
    let mut started: Vec<&str> = start.steps.iter().map(|step| step.resource.as_str()).collect();
    started.sort_unstable();
    assert_eq!(started, ["client", "server"], "both running VMs are reached to renew");
    service.apply(&start, &op(), no_secrets()).await.unwrap();
    assert_eq!(active(&scripted), 1, "the grant is made anew");
    assert_eq!(scripted.actions().iter().filter(|action| *action == "launch").count(), launches, "nothing was launched again");
}
