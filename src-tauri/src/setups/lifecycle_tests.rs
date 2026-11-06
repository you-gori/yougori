//! Acceptance of the shared setup lifecycle (template platform plan, P04): one state machine for
//! plan, create, configure, start, stop, inspect, logs, update, cancel/continue and remove; two
//! independent copies; recovery from an interruption; stale plans and concurrent changes; stops
//! that survive a restart; borrowed against owned; retention; storage and domain failures;
//! logs scoped to one setup; backups said as what they are; and a part whose product is gone.
//!
//! Every test runs against temporary folders and in-memory fakes, as `setups::tests` does;
//! nothing here touches the real data folder, a real resource or the network.
use super::super::{
    handler::{fake::FakeHandler, HandlerError, HandlerFuture, Handlers, Observation, ResourceHandler, StepContext},
    journal::{Action, OperationState, Receipt, StepState},
    model::{new_id, Cost, Desired, InstanceChange, Lifecycle, Observed, Source},
    service::{plan_digest, DeclaredResource, PlanIntent, ReviewedPlan, Service, SetupDraft},
    store::{Registry, Store},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use yougori_setup::{dto, resource::Kind};

/// Temporary folders and the in-memory fake provider, as `setups::tests::Bench`.
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
        Self { setups: data.join("setups"), data, _root: root, fake: Arc::new(FakeHandler::new(Kind::Environment)), extra: Vec::new() }
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

    /// Waits until the provider has been asked for `call` (a step is inside the provider), so a
    /// test can act while it is there rather than racing it.
    async fn entered(&self, call: &str) {
        for _ in 0..1000 {
            if self.calls().iter().any(|made| made == call) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("the provider was never asked for {call}: {:?}", self.calls());
    }
}

/// The project engine's fake, as `setups::tests::Engine`: sandboxes, volumes, publications and
/// vault entries, every one counted and named as the real engine names them.
struct Engine {
    _root: tempfile::TempDir,
    setups: PathBuf,
    data: PathBuf,
    projects: Arc<super::super::ordinary::fake::FakeProjects>,
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
        let ordinary = super::super::ordinary::Ordinary::new(self.projects.clone(), self.setups.join("projects"));
        for each in ordinary.handlers() {
            handlers.register(each);
        }
        Arc::new(Service::open(&self.setups, &self.data, handlers))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, super::super::ordinary::fake::State> {
        self.projects.state.lock().unwrap()
    }
}

fn change(name: &str) -> InstanceChange {
    InstanceChange {
        name: name.into(),
        source: Source { reference: dto::SourceRef::Hub { publisher: "example".into(), name: "hello".into(), version: "1.0.0".into() }, digest: "sha256:0000".into() },
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
    DeclaredResource { id: id.into(), kind: Kind::Environment, spec: json!({ "image": format!("example/{id}") }), requires: requires.iter().map(|id| (*id).to_owned()).collect(), owner: None }
}

fn sandbox(id: &str, extra: Value) -> DeclaredResource {
    let mut spec = json!({ "type": "container", "image": format!("example/{id}:1.0.0"), "storage": 10 });
    spec.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    DeclaredResource { id: id.into(), kind: Kind::Environment, spec, requires: Vec::new(), owner: None }
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
    assert_eq!(state_of(service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
    (plan, operation)
}

fn state_of(service: &Service, operation: &str) -> OperationState {
    service.snapshot().operations[operation].state
}

fn lifecycle_of(service: &Service, setup: &str) -> Lifecycle {
    service.snapshot().instances[setup].lifecycle
}

/// Concurrent commits cannot pair one detail revision with another revision's permission
/// configuration. No engine, provider or real environment is used.
#[tokio::test]
async fn detail_and_product_share_one_registry_snapshot_during_changes() {
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::product::test_support::Probes;
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "snapshot", vec![sandbox("web", json!({}))]).await;
    let setup = plan.setup_id.clone();
    let initial_revision = service.get(&setup).unwrap().setup.revision;
    let probes = Probes::new(SourceClass::HostProbe);
    let writer = service.clone();
    let id = setup.clone();
    let started = Arc::new(std::sync::Barrier::new(2));
    let writer_started = started.clone();
    let worker = std::thread::spawn(move || {
        writer_started.wait();
        for _ in 0..40 {
            writer.commit(|registry| {
                let instance = registry.instances.get_mut(&id).unwrap();
                instance.revision += 1;
                instance.lock_digest = Some(format!("lock-{}", instance.revision));
                Ok(())
            }).unwrap();
            std::thread::yield_now();
        }
    });
    started.wait();
    for _ in 0..80 {
        let detail = service.get_with_product(&setup, Ok(probes.now())).unwrap();
        let document = detail.product.unwrap();
        let revision = detail.setup.revision;
        // The initial created revision uses the helper's lock; later revisions name theirs.
        let lock = if revision == initial_revision { plan.change.as_ref().unwrap().lock_digest.clone() }
            else { Some(format!("lock-{revision}")) };
        assert_eq!(document.shown_at.configuration, super::super::product::configuration(&setup, revision, lock.as_deref()).unwrap());
        assert_eq!(document.subject.id(), setup);
    }
    worker.join().unwrap();
    let unavailable = service.get_with_product(&setup, Err("clock unavailable".into())).unwrap();
    assert!(unavailable.product.is_none());
    assert_eq!(unavailable.product_unavailable.as_deref(), Some("clock unavailable"));
}

/// A handler that keeps data and answers every call, standing in for a product that was later
/// retired: a service opened without it has a setup it can no longer manage.
struct Retired;

impl ResourceHandler for Retired {
    fn kind(&self) -> Kind {
        Kind::Grid
    }
    fn validate(&self, _: &Value) -> Result<(), HandlerError> {
        Ok(())
    }
    fn observe<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async { Ok(Observation::Present { runtime_id: "grid-1".into(), observed: Observed::Running, label: None, retained_data: true, cost: Cost::Free }) })
    }
    fn apply<'a>(&'a self, _: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async { Ok(Receipt { runtime_id: Some("grid-1".into()), observed: Observed::Running, retained_data: true, cost: Cost::Free, at: super::super::model::now(), adopted: false }) })
    }
}

// ----- 1. One state machine -----

/// PROVES the lifecycle as the engine implements it, state by state: what each operation is
/// allowed from, what it leaves behind, and that every refusal is a coded answer with a next
/// step, never a silent no-op. This is the table the CLI's `follow_operation` and `retry` read.
#[tokio::test]
async fn the_lifecycle_allows_each_operation_only_from_the_states_it_is_defined_for() {
    let bench = Bench::new();
    let service = bench.service();
    // Create: no setup → Creating while it runs → Running when it completes.
    let plan = service.plan(create("Site", vec![resource("web", &[])])).unwrap();
    assert_eq!(plan.base_revision, 0, "a new setup is planned against revision 0");
    let setup = plan.setup_id.clone();
    let creating = op();
    service.submit(&plan, &creating, 0, no_secrets()).unwrap();
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Creating);
    assert_eq!(state_of(&service, &creating), OperationState::Planned);
    // While the setup is held by an operation, every plan and part action is refused as busy,
    // and the refusal names the operation and what to do.
    for intent in [PlanIntent::Stop { setup: setup.clone() }, PlanIntent::Start { setup: setup.clone() }, PlanIntent::Remove { setup: setup.clone() }, PlanIntent::Repair { setup: setup.clone() }] {
        let busy = service.plan(intent).unwrap_err();
        assert_eq!(busy.code, "setup_busy");
        assert_eq!(busy.operation.as_deref(), Some(creating.as_str()));
        assert!(busy.retryable && busy.next.contains(&"wait".to_owned()));
    }
    assert!(service.get(&setup).unwrap().setup.actions.is_empty(), "no action is offered while it is busy");
    service.run(&creating).await.unwrap();
    assert_eq!(state_of(&service, &creating), OperationState::Completed);
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Running);
    assert_eq!(service.get(&setup).unwrap().setup.actions, [dto::SetupAction::Stop, dto::SetupAction::Remove]);
    // The same create sent again joins the operation it made; a second create of the same plan
    // under a new ID is refused: the setup exists.
    assert!(service.submit(&plan, &creating, 0, no_secrets()).unwrap().joined);
    assert_eq!(service.submit(&plan, &op(), 0, no_secrets()).unwrap_err().code, "setup_exists");

    // Running: start is nothing to do (no steps), stop takes it to Stopped.
    let start = service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap();
    assert!(start.steps.is_empty(), "already running: nothing to start");
    let stop = service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap();
    let stopping = op();
    service.apply(&stop, &stopping, no_secrets()).await.unwrap();
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Stopped);
    assert_eq!(service.get(&setup).unwrap().setup.actions, [dto::SetupAction::Start, dto::SetupAction::Remove]);
    assert_eq!(service.snapshot().instances[&setup].resources["web"].desired, Desired::Stopped);
    // Stopped: start takes it back to Running; the last operation is what logs show.
    let start = service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap();
    let starting = op();
    service.apply(&start, &starting, no_secrets()).await.unwrap();
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Running);
    assert_eq!(service.latest_operation(&setup).unwrap(), starting);
    // A finished operation can't be continued; the words say which states can.
    let refused = service.prepare_retry(&starting).unwrap_err();
    assert_eq!(refused.code, "not_retryable");
    assert!(refused.message.contains("failed, cancelled, waiting or unknown"), "{}", refused.message);
    // Cancel of a finished operation changes nothing and reports it as it is.
    assert_eq!(service.cancel(&starting).unwrap().state, dto::OperationState::Completed);

    // Repair with nothing missing says so and plans no step.
    let repair = service.plan(PlanIntent::Repair { setup: setup.clone() }).unwrap();
    assert!(repair.steps.is_empty() && repair.notes.iter().any(|note| note.contains("Nothing is missing")));

    // Remove: Removing while it runs, then Removed (tombstoned) when nothing kept data.
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    assert!(remove.notes.iter().any(|note| note.starts_with("Data is kept by default")));
    let removing = op();
    service.submit(&remove, &removing, remove.base_revision, no_secrets()).unwrap();
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Removing);
    service.run(&removing).await.unwrap();
    let registry = service.snapshot();
    assert!(!registry.instances.contains_key(&setup) && registry.tombstones.contains_key(&setup));
    // After removal every door says so with one code: the old plans can't bring it back.
    assert_eq!(service.get(&setup).unwrap_err().code, "setup_removed");
    assert_eq!(service.latest_operation(&setup).unwrap_err().code, "setup_removed");
    assert_eq!(service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap_err().code, "setup_removed");
    assert_eq!(service.submit(&stop, &op(), stop.base_revision, no_secrets()).unwrap_err().code, "setup_removed");
    assert!(service.list().unwrap().iter().all(|summary| summary.setup_id != setup), "a removed setup is not listed");
    // Its operations still read, so logs of what happened stay available.
    assert_eq!(service.operation(&removing, 0).unwrap().state, dto::OperationState::Completed);
}

/// PROVES what the CLI reads of each ending: `completed`; `failed` with a retryable error whose
/// next step is `retry` (what `template continue` does); a cancel reads as `failed` with
/// `operation_cancelled`, also continued by retry; and an operation waiting for an answer reads
/// as `awaiting_input` with next steps `continue` and `cancel`.
#[tokio::test]
async fn every_ending_reads_as_the_cli_expects_it() {
    let bench = Bench::new();
    let service = bench.service();
    // Failed, retryable: the provider refused once.
    bench.fake.provider.lock().unwrap().fail.insert("web".into(), 1);
    let plan = service.plan(create("Site", vec![resource("web", &[])])).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    let progress = service.operation(&operation, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::Failed);
    let error = progress.error.unwrap();
    assert!(error.retryable, "{error:?}");
    assert!(error.next_actions.iter().any(|next| matches!(next, dto::NextAction::Retry)), "{error:?}");
    assert!(progress.events.iter().any(|event| event.message.contains("Everything already created is still tracked")));
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(service.operation(&operation, 0).unwrap().state, dto::OperationState::Completed);
    assert_eq!(bench.creates(), 1);

    // Cancelled before it started: reads as failed with the cancel code, and continues by retry.
    let stop = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap();
    let cancelled = op();
    service.submit(&stop, &cancelled, stop.base_revision, no_secrets()).unwrap();
    let progress = service.cancel(&cancelled).unwrap();
    assert_eq!(progress.state, dto::OperationState::Failed);
    assert_eq!(progress.error.as_ref().unwrap().code, "operation_cancelled");
    assert_eq!(lifecycle_of(&service, &plan.setup_id), Lifecycle::Running, "a cancelled stop left it running");
    service.prepare_retry(&cancelled).unwrap();
    service.run(&cancelled).await.unwrap();
    assert_eq!(lifecycle_of(&service, &plan.setup_id), Lifecycle::Stopped);

    // Waiting for an answer: the operation holds the setup, says what it needs, and continues
    // only with the answer given by its own ID and digest.
    bench.fake.provider.lock().unwrap().needs_secret.insert("db".into());
    let draft = SetupDraft { change: change("Shop"), resources: vec![DeclaredResource { spec: json!({ "image": "example/db", "secretRef": "db_password" }), ..resource("db", &[]) }] };
    let plan = service.plan(PlanIntent::Create(draft)).unwrap();
    let waiting = op();
    service.apply(&plan, &waiting, no_secrets()).await.unwrap();
    let progress = service.operation(&waiting, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::AwaitingInput);
    let error = progress.error.unwrap();
    assert_eq!(error.code, "needs_secret");
    assert!(error.next_actions.iter().any(|next| matches!(next, dto::NextAction::Continue { .. })), "{error:?}");
    // A new plan for the waiting setup is refused as busy, naming continue and cancel.
    let busy = service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap_err();
    assert_eq!(busy.code, "setup_busy");
    assert!(busy.message.contains("waiting for your answers") && busy.next == ["continue", "cancel"]);
    let joined = service.continue_operation(&plan.setup_id, &waiting, &plan.digest, BTreeMap::from([("db_password".to_owned(), "x".to_owned())])).unwrap().unwrap();
    assert!(joined.joined);
    service.run(&waiting).await.unwrap();
    assert_eq!(service.operation(&waiting, 0).unwrap().state, dto::OperationState::Completed);
}

// ----- 2. Two independent copies -----

/// PROVES two setups made from one and the same package share nothing on this computer: each has
/// its own project, its sandboxes, named volumes, vault entries and published addresses are
/// named after its own setup, and removing one leaves every resource of the other in place.
#[tokio::test]
async fn two_copies_of_one_package_share_no_project_sandbox_volume_address_or_secret() {
    let engine = Engine::new();
    let service = engine.service();
    let package = || {
        vec![
            sandbox("app", json!({ "ports": [8080], "secrets": { "TOKEN": "apply.token" }, "volumes": [{ "source": "data", "target": "/data" }] })),
            DeclaredResource { id: "web".into(), kind: Kind::ServicePublication, spec: json!({ "target": { "resource": "app" }, "port": 8080, "access": "quick" }), requires: vec!["app".into()], owner: None },
        ]
    };
    let secrets = || BTreeMap::from([("token".to_owned(), "t".to_owned())]);
    let first = service.plan(create("Shop", package())).unwrap();
    service.apply(&first, &op(), secrets()).await.unwrap();
    let second = service.plan(create("Shop", package())).unwrap();
    service.apply(&second, &op(), secrets()).await.unwrap();
    assert_ne!(first.setup_id, second.setup_id);
    let registry = service.snapshot();
    let app_of = |setup: &str| registry.instances[setup].resources["app"].runtime_id.clone().unwrap();
    let web_of = |setup: &str| registry.instances[setup].resources["web"].runtime_id.clone().unwrap();
    {
        let state = engine.state();
        assert_eq!(state.projects.len(), 2, "one project per setup");
        assert_eq!(state.created, 2);
        let names = state.sandboxes.values().map(|sandbox| sandbox.name.clone()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), 2, "each sandbox is named after its own setup: {names:?}");
        assert!(names.iter().all(|name| name.starts_with("setup-") && name.ends_with("-app")), "{names:?}");
        assert_eq!(state.volumes.len(), 2, "each setup has a data volume of its own: {:?}", state.volumes);
        assert_eq!(state.volumes.iter().collect::<std::collections::BTreeSet<_>>().len(), 2, "{:?}", state.volumes);
        assert_eq!(state.secrets.len(), 2, "each setup's token is its own vault entry");
        // The fake keeps only the last converged project's publications; the registry is where
        // each setup's own address is recorded, and it is keyed by the sandbox, never by a host port.
        assert!(state.publications.contains_key(&(app_of(&second.setup_id), 8080)));
    }
    assert_ne!(app_of(&first.setup_id), app_of(&second.setup_id));
    assert_ne!(web_of(&first.setup_id), web_of(&second.setup_id), "the same port 8080 is published once per sandbox, with no host port to collide on");
    assert!(web_of(&first.setup_id).contains(&app_of(&first.setup_id)) && web_of(&second.setup_id).contains(&app_of(&second.setup_id)));
    // Each setup's project lives under its own folder.
    for setup in [&first.setup_id, &second.setup_id] {
        assert!(engine.state().projects.contains_key(&engine.setups.join("projects").join(setup)), "{setup} has a project of its own");
    }
    // Removing the first leaves everything of the second exactly as it was.
    let remove = service.plan(PlanIntent::Remove { setup: first.setup_id.clone() }).unwrap();
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    let state = engine.state();
    assert_eq!(state.deleted, vec![app_of(&first.setup_id)]);
    assert!(state.sandboxes.contains_key(&app_of(&second.setup_id)) && state.sandboxes[&app_of(&second.setup_id)].running);
    assert_eq!(registry.instances[&second.setup_id].resources["web"].runtime_id, service.snapshot().instances[&second.setup_id].resources["web"].runtime_id);
    assert_eq!(state.secrets.len(), 1);
    assert_eq!(state.volumes.len(), 2, "removing keeps both data volumes");
}

// ----- 3. Interruption -----

/// PROVES that a change cut off after some steps finished continues from where it stopped: the
/// journal shows steps 1..k done and step k+1 in flight; the process dies; on continue the
/// engine looks at what step k+1 left behind before anything runs, then makes only k+1..n.
/// Nothing finished is made again, whether the cut-off step had taken effect or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_cut_off_mid_way_continues_without_making_anything_twice() {
    // Case 1: step k+1 was mid-call and had not taken effect when the process died.
    let bench = Bench::new();
    let service = bench.service();
    let three = || vec![resource("a", &[]), resource("b", &["a"]), resource("c", &["b"])];
    bench.fake.provider.lock().unwrap().gated.insert("b".into());
    let plan = service.plan(create("Chain", three())).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    let runner = {
        let service = service.clone();
        let operation = operation.clone();
        tokio::spawn(async move { service.run(&operation).await })
    };
    // a is created; b has entered the provider and waits.
    bench.entered("create:b").await;
    runner.abort();
    let _ = runner.await;
    drop(service);
    let journal = bench.on_disk().operations[&operation].clone();
    assert_eq!(journal.steps.iter().map(|step| (step.id.as_str(), step.state)).collect::<Vec<_>>(), [("a", StepState::Done), ("b", StepState::Applying), ("c", StepState::Pending)], "what the journal shows at the moment the process died");
    assert_eq!(bench.creates(), 1);

    // The next engine finds the cut-off step, marks it unknown, and looks before acting.
    bench.fake.provider.lock().unwrap().gated.clear();
    let service = bench.service();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    assert!(service.snapshot().instances[&plan.setup_id].current_operation.as_deref() == Some(operation.as_str()), "the setup stays held until the outcome is known");
    service.reconcile_all().await;
    let progress = service.operation(&operation, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::Failed, "settled: b had not happened, so the change is failed and retryable");
    assert_eq!(progress.error.as_ref().unwrap().code, "engine_interrupted");
    assert!(progress.events.iter().any(|event| event.message.contains("creating b had not happened")), "{:?}", progress.events);
    // Continue, as `template continue` does: only b and c run; a is kept as recorded.
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.creates(), 3, "a once, then b and c");
    assert_eq!(bench.calls().iter().filter(|call| *call == "create:a").count(), 1, "a was never made again");
    let instance = &service.snapshot().instances[&plan.setup_id];
    assert_eq!(instance.lifecycle, Lifecycle::Running);
    assert!(["a", "b", "c"].iter().all(|id| instance.resources[*id].runtime_id.is_some()));

    // Case 2: step k+1 had taken effect, but its receipt never reached the disk. The continue
    // finds the resource by the step's label (the handler's Observation::Present) and records
    // it rather than making a second one.
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().lose_answer.insert("b".into());
    let plan = service.plan(create("Chain", three())).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    assert_eq!(bench.creates(), 2, "a and b exist; b's answer was lost");
    drop(service);
    let service = bench.service();
    // Continued straight away, with no reconcile pressed first: the runner looks first.
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    let progress = service.operation(&operation, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::Completed, "{:?}", progress.error);
    assert!(progress.events.iter().any(|event| event.message.contains("creating b had finished. Recorded it without doing it again")), "{:?}", progress.events);
    assert_eq!(bench.creates(), 3, "b was found, not made again; only c was made");
    let instance = &service.snapshot().instances[&plan.setup_id];
    assert!(instance.resources["b"].runtime_id.is_some());
    assert_eq!(instance.lifecycle, Lifecycle::Running);
    assert!(instance.current_operation.is_none());

    // Case 3: the provider can't be asked, so the outcome stays unknown: a continue does not
    // guess, runs nothing, and says why.
    let bench = Bench::new();
    let service = bench.service();
    bench.fake.provider.lock().unwrap().lose_answer.insert("b".into());
    let plan = service.plan(create("Chain", three())).unwrap();
    let operation = op();
    service.apply(&plan, &operation, no_secrets()).await.unwrap();
    bench.fake.provider.lock().unwrap().unreachable = true;
    service.prepare_retry(&operation).unwrap();
    let refused = service.run(&operation).await.unwrap_err();
    assert_eq!(state_of(&service, &operation), OperationState::Unknown);
    assert!(refused.next.contains(&"reconcile".to_owned()), "{refused:?}");
    assert_eq!(bench.creates(), 2, "nothing ran");
    assert_eq!(service.plan(PlanIntent::Stop { setup: plan.setup_id.clone() }).unwrap_err().code, "setup_busy", "the setup stays held");
}

// ----- 4. Stale plans and concurrent changes -----

/// PROVES a plan is applied only to the setup it was reviewed against: one reviewed before another
/// change landed is refused with a review, never applied over the newer state; a plan altered
/// after review is refused; and two operations on one setup never interleave: the second is
/// refused as busy at submit, a second runner of the same operation joins it, and an operation
/// ID can't be reused for a different change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_plan_is_refused_and_two_changes_never_interleave() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![resource("web", &[])]).await;
    let setup = plan.setup_id.clone();
    let revision = service.snapshot().instances[&setup].revision;
    // Two plans reviewed against the same revision.
    let stop = service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap();
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    assert_eq!((stop.base_revision, remove.base_revision), (revision, revision));
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    assert!(service.snapshot().instances[&setup].revision > revision);
    // The other plan is now stale: refused with a review, and nothing of it ran.
    let calls = bench.calls();
    let refused = service.submit(&remove, &op(), remove.base_revision, no_secrets()).unwrap_err();
    assert_eq!(refused.code, "revision_conflict");
    assert!(refused.next.contains(&"plan".to_owned()) && refused.message.contains("Review the change again"));
    assert_eq!(bench.calls(), calls);
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Stopped);
    // A client that claims a different expected revision than the plan's is refused the same way.
    let start = service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap();
    assert_eq!(service.submit(&start, &op(), start.base_revision + 1, no_secrets()).unwrap_err().code, "revision_conflict");
    // A plan altered after review is refused, even with the right revision.
    let mut altered = start.clone();
    altered.steps.clear();
    assert_eq!(service.submit(&altered, &op(), altered.base_revision, no_secrets()).unwrap_err().code, "plan_changed");
    // The door a client comes through names a digest, and only a plan this engine reviewed is
    // behind it: an altered plan, whatever digest it carries, is not there.
    altered.digest = plan_digest(&altered);
    assert_eq!(service.reviewed(&setup, &altered.digest).unwrap_err().code, "plan_expired");
    assert_eq!(service.reviewed(&setup, &start.digest).unwrap(), start);

    // Two changes at once: the first holds the setup; a different change, reviewed before the
    // first claimed it, is refused as busy at submit, and a plan can't even be reviewed meanwhile.
    // (The same change reviewed twice has one digest and joins the operation already running.)
    bench.fake.provider.lock().unwrap().gated.insert("web".into());
    let second_start = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    let first = op();
    service.submit(&start, &first, start.base_revision, no_secrets()).unwrap();
    let runner = {
        let service = service.clone();
        let first = first.clone();
        tokio::spawn(async move { service.run(&first).await })
    };
    bench.entered("start:web").await;
    assert!(service.submit(&start, &op(), start.base_revision, no_secrets()).unwrap().joined, "the same change again joins the one running");
    let busy = service.submit(&second_start, &op(), second_start.base_revision, no_secrets()).unwrap_err();
    assert_eq!(busy.code, "setup_busy");
    assert_eq!(busy.operation.as_deref(), Some(first.as_str()));
    assert_eq!(service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap_err().code, "setup_busy");
    assert_eq!(service.refresh(&setup).await.unwrap_err().code, "setup_busy", "looking is not allowed to race a change either");
    // A second runner of the same operation returns at once rather than running it twice.
    service.run(&first).await.unwrap();
    assert_eq!(bench.calls().iter().filter(|call| *call == "start:web").count(), 1);
    // The same operation ID for a different change is refused.
    assert_eq!(service.submit(&second_start, &first, second_start.base_revision, no_secrets()).unwrap_err().code, "operation_id_reused");
    assert_eq!(service.continue_operation(&setup, &first, "sha256:other", no_secrets()).unwrap_err().code, "operation_id_reused");
    bench.fake.gate.add_permits(1);
    runner.await.unwrap().unwrap();
    assert_eq!(state_of(&service, &first), OperationState::Completed);
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Running);
    // After it finished, the plan reviewed before it is stale, as it must be.
    assert_eq!(service.submit(&second_start, &op(), second_start.base_revision, no_secrets()).unwrap_err().code, "revision_conflict");
}

// ----- 5. Explicit stops survive -----

/// PROVES a setup the person stopped stays stopped through an engine restart: the stop is on
/// disk as the setup's state and each part's wanted state, the next engine starts nothing on its
/// own, a refresh finds no drift, and only an explicit start brings it back.
#[tokio::test]
async fn a_setup_the_person_stopped_stays_stopped_through_a_restart() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![resource("db", &[]), resource("web", &["db"])]).await;
    let setup = plan.setup_id.clone();
    let stop = service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap();
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    drop(service);
    let on_disk = bench.on_disk();
    assert_eq!(on_disk.instances[&setup].lifecycle, Lifecycle::Stopped);
    assert!(on_disk.instances[&setup].resources.values().all(|part| part.desired == Desired::Stopped && part.observed == Observed::Stopped));

    let calls = bench.calls();
    let service = bench.service();
    service.reconcile_all().await;
    assert_eq!(bench.calls(), calls, "a restart starts nothing by itself");
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Stopped);
    assert!(bench.fake.provider.lock().unwrap().resources.values().all(|part| !part.running));
    let detail = service.refresh(&setup).await.unwrap();
    assert_eq!(detail.setup.summary.state, dto::InstanceState::Stopped);
    assert!(detail.setup.resources.iter().all(|part| part.drift.is_none()), "stopped as wanted is not drift: {:?}", detail.setup.resources);
    assert_eq!(detail.setup.actions, [dto::SetupAction::Start, dto::SetupAction::Remove]);
    // Something started outside Yougori is reported as drift, not quietly adopted as the intent.
    bench.fake.provider.lock().unwrap().resources.values_mut().for_each(|part| part.running = true);
    let detail = service.refresh(&setup).await.unwrap();
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Stopped);
    assert!(detail.setup.resources.iter().all(|part| part.drift.as_deref() == Some("Started since this setup stopped it, for example by hand.")), "{:?}", detail.setup.resources);
}

// ----- 8. Storage and domain failures -----

/// PROVES a disk that can't be written fails a change honestly: nothing is created when the
/// failure comes before the first step, the setup is left as it was, the error says what to do,
/// and another setup's resources are never touched. A failed change to one part (a domain that
/// won't take) keeps that part's recorded settings and the rest of the setup as they were.
#[tokio::test]
async fn storage_and_domain_failures_are_honest_and_touch_no_other_setup() {
    let bench = Bench::new();
    let service = bench.service();
    let (other, _) = created(&service, "Other", vec![resource("web", &[])]).await;
    let other_resources = bench.fake.provider.lock().unwrap().resources.clone();
    // The disk fails before the first step of a new setup: nothing is created.
    let plan = service.plan(create("Site", vec![resource("app", &[])])).unwrap();
    let operation = op();
    service.submit(&plan, &operation, 0, no_secrets()).unwrap();
    service.store().faults.fail_after(0);
    let failed = service.run(&operation).await.unwrap_err();
    assert_eq!(failed.code, "durable_storage_unavailable");
    assert!(failed.message.contains("nothing further was done"), "{}", failed.message);
    let progress = service.operation(&operation, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::Failed);
    assert!(progress.error.as_ref().unwrap().retryable);
    assert_eq!(bench.creates(), 1, "only the other setup's resource exists");
    assert_eq!(bench.fake.provider.lock().unwrap().resources, other_resources);
    // Once the disk is back, the same operation continues and finishes.
    service.store().faults.heal();
    service.prepare_retry(&operation).unwrap();
    service.run(&operation).await.unwrap();
    assert_eq!(state_of(&service, &operation), OperationState::Completed);
    assert_eq!(bench.creates(), 2);
    assert_eq!(bench.on_disk().operations[&operation].state, OperationState::Completed);

    // A change to one part fails at the provider: the part keeps its recorded settings, the
    // setup stays running and is marked degraded, the error names the part, and the other setup
    // is untouched.
    let setup = plan.setup_id.clone();
    let before = service.snapshot().instances[&setup].resources["app"].clone();
    bench.fake.provider.lock().unwrap().fail.insert("app".into(), 1);
    let update = PlanIntent::Update { setup: setup.clone(), draft: SetupDraft { change: change("Site"), resources: vec![DeclaredResource { spec: json!({ "image": "example/app", "domain": "shop.example" }), ..resource("app", &[]) }] } };
    let reviewed = service.plan(update).unwrap();
    assert_eq!(reviewed.steps.iter().map(|step| step.action).collect::<Vec<_>>(), [Action::Update]);
    assert!(reviewed.notes.iter().any(|note| note.contains("app changes in place: domain")), "{:?}", reviewed.notes);
    let changing = op();
    let calls = bench.calls();
    service.apply(&reviewed, &changing, no_secrets()).await.unwrap();
    let progress = service.operation(&changing, 0).unwrap();
    assert_eq!(progress.state, dto::OperationState::Failed);
    let error = progress.error.unwrap();
    assert_eq!((error.code.as_ref(), error.resource.as_deref(), error.retryable), ("provider_failed", Some("app"), true));
    let after = &service.snapshot().instances[&setup];
    assert_eq!(after.resources["app"], before, "the part's record is exactly as it was: no settings it never got");
    assert_eq!(after.lifecycle, Lifecycle::Running);
    assert_eq!(after.health, super::super::model::Health::Degraded);
    assert!(after.current_operation.is_none(), "the setup is released for the next change");
    assert_eq!(bench.calls()[calls.len()..], ["update:app"], "nothing else was called, least of all the other setup");
    assert!(other_resources.keys().all(|id| bench.fake.provider.lock().unwrap().resources.contains_key(id)));
    assert_eq!(service.snapshot().instances[&other.setup_id].resources["web"].runtime_id, other_resources.keys().next().cloned());
}

// ----- 9. Logs scoped to one setup -----

/// PROVES what one setup's logs and operations show is that setup's alone: its latest operation
/// is its own, its events name only its parts, its page lists only its operations, and an
/// operation read by ID carries the setup it belongs to so a caller can refuse a mismatch.
#[tokio::test]
async fn logs_and_operations_of_one_setup_never_show_anothers() {
    let bench = Bench::new();
    let service = bench.service();
    let (a, a_created) = created(&service, "A", vec![resource("alpha", &[])]).await;
    let (b, b_created) = created(&service, "B", vec![resource("beta", &[])]).await;
    let stop_b = service.plan(PlanIntent::Stop { setup: b.setup_id.clone() }).unwrap();
    let b_stopped = op();
    service.apply(&stop_b, &b_stopped, no_secrets()).await.unwrap();
    assert_eq!(service.latest_operation(&a.setup_id).unwrap(), a_created);
    assert_eq!(service.latest_operation(&b.setup_id).unwrap(), b_stopped);
    let progress = service.operation(&a_created, 0).unwrap();
    assert_eq!(progress.operation.setup_id, a.setup_id);
    assert!(progress.events.iter().all(|event| event.resource.as_deref().is_none_or(|part| part == "alpha") && !event.message.contains("beta")), "{:?}", progress.events);
    assert_eq!(service.operation(&b_created, 0).unwrap().operation.setup_id, b.setup_id);
    let page = service.get(&a.setup_id).unwrap();
    assert_eq!(page.operations.iter().map(|brief| brief.operation_id.as_str()).collect::<Vec<_>>(), [a_created.as_str()]);
    let page = service.get(&b.setup_id).unwrap();
    assert!(page.operations.iter().all(|brief| [b_created.as_str(), b_stopped.as_str()].contains(&brief.operation_id.as_str())));
    assert_eq!(page.operations.len(), 2);
    // Health is the setup's own too: B is stopped, A is not.
    assert_eq!(service.get(&a.setup_id).unwrap().setup.summary.state, dto::InstanceState::Running);
    assert_eq!(service.get(&b.setup_id).unwrap().setup.summary.state, dto::InstanceState::Stopped);
}

// ----- 10. Backups say what they are -----

/// PROVES the engine's own words call a backup what it is: a copy of files, not a database's own
/// backup, in every place the limits are shown.
#[test]
fn a_backup_is_called_a_copy_of_files_and_never_a_database_backup() {
    let limits = super::super::schedules::LIMITS;
    assert!(limits.starts_with("A backup is a copy of the volume's files"), "{limits}");
    assert!(limits.contains("A database on the volume is copied as its files, not through the database's own backup tool"), "{limits}");
    for word in ["transactional", "consistent copy of the database", "point-in-time"] {
        assert!(!limits.to_ascii_lowercase().contains(word), "{limits}");
    }
}

// ----- 11. A part whose product is gone -----

/// PROVES a setup with a part this engine can no longer manage (its handler is gone) is reported
/// plainly and still has honest ways out: its page says what is left alone and how to export or
/// let the setup go; stop and start say so and do nothing to it; nothing of it is offered on its
/// own; and removing the setup takes only what can be taken, leaving the part and its data where
/// they are, rather than failing in silence or pretending to remove it.
#[tokio::test]
async fn a_part_whose_product_is_gone_is_said_plainly_and_left_alone() {
    let mut bench = Bench::new();
    bench.extra.push(Arc::new(Retired));
    let service = bench.service();
    let grid = DeclaredResource { id: "grid".into(), kind: Kind::Grid, spec: json!({ "profile": "neo_grid", "mode": "create" }), requires: Vec::new(), owner: None };
    let (plan, _) = created(&service, "Old grid", vec![grid, resource("web", &[])]).await;
    let setup = plan.setup_id.clone();
    drop(service);

    // The next version carries no handler for grids.
    bench.extra.clear();
    let service = bench.service();
    let page = service.get(&setup).unwrap();
    assert!(page.notes.iter().any(|note| note.starts_with("grid is a grid resource, which this version of Yougori can no longer manage")), "{:?}", page.notes);
    assert!(page.notes.iter().any(|note| note.contains("yougori template export")), "{:?}", page.notes);
    assert_eq!(page.resource_details["grid"]["actions"], json!([]), "nothing is offered for it on its own");
    assert_eq!(page.resource_details["web"]["actions"], json!(["stop", "remove"]));
    let refused = service.plan(PlanIntent::Part { setup: setup.clone(), resource: "grid".into(), action: Action::Stop }).unwrap_err();
    assert_eq!(refused.code, "unsupported_resource");
    assert!(refused.message.contains("left exactly as it is"), "{}", refused.message);

    let stop = service.plan(PlanIntent::Stop { setup: setup.clone() }).unwrap();
    assert_eq!(stop.steps.iter().map(|step| step.resource.as_str()).collect::<Vec<_>>(), ["web"]);
    assert!(stop.notes.iter().any(|note| note.starts_with("grid is a grid resource")), "{:?}", stop.notes);
    service.apply(&stop, &op(), no_secrets()).await.unwrap();
    assert_eq!(lifecycle_of(&service, &setup), Lifecycle::Stopped);
    let start = service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap();
    assert_eq!(start.steps.iter().map(|step| step.resource.as_str()).collect::<Vec<_>>(), ["web"]);
    assert!(start.notes.iter().any(|note| note.starts_with("grid is a grid resource")));

    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    assert_eq!(remove.steps.iter().map(|step| step.resource.as_str()).collect::<Vec<_>>(), ["web"]);
    assert!(remove.notes.iter().any(|note| note.starts_with("grid is a grid resource")), "{:?}", remove.notes);
    assert!(remove.notes.iter().any(|note| note.contains("yougori template export")));
    let removing = op();
    service.apply(&remove, &removing, no_secrets()).await.unwrap();
    assert_eq!(state_of(&service, &removing), OperationState::Completed);
    let instance = &service.snapshot().instances[&setup];
    assert_eq!(instance.lifecycle, Lifecycle::Retained, "the setup stays listed: something of it is still here");
    assert_eq!(instance.resources["grid"].runtime_id.as_deref(), Some("grid-1"), "the grid's record is untouched");
    assert!(!bench.calls().iter().any(|call| call.ends_with(":grid")), "no handler ever acted on it");
    // Letting the setup go: the second removal says it removes the setup from the list only.
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    assert!(remove.steps.is_empty());
    assert!(remove.notes.iter().any(|note| note.contains("removes the setup from My setups only")), "{:?}", remove.notes);
    service.apply(&remove, &op(), no_secrets()).await.unwrap();
    assert_eq!(service.get(&setup).unwrap_err().code, "setup_removed");
}

// ----- Install planning agrees with export -----

struct NoHub;

impl super::super::planning::Hub for NoHub {
    fn fetch<'a>(&'a self, _: &'a str, _: &'a str, _: Option<&'a str>, _: Option<&'a str>) -> super::super::ordinary::BoxFuture<'a, Result<super::super::planning::Fetched, String>> {
        Box::pin(async { Err("The Hub can't be reached in this test.".to_owned()) })
    }

    fn components<'a>(&'a self, _: &'a yougori_setup::format::Checked) -> super::super::ordinary::BoxFuture<'a, Result<BTreeMap<String, yougori_setup::plan::Component>, Vec<dto::Diagnostic>>> {
        Box::pin(async { Err(vec![dto::Diagnostic::error("component_unavailable", "The Hub can't be reached in this test.")]) })
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

/// A copy of a published example in a folder of its own, so a test can add a file to it.
fn copied_example(name: &str) -> (tempfile::TempDir, PathBuf) {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("examples").join("hub").join(name);
    let folder = tempfile::tempdir().unwrap();
    let target = folder.path().join(name);
    fs::create_dir_all(&target).unwrap();
    for entry in fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
    (folder, target)
}

/// PROVES the door in agrees with the door out: a folder the export would refuse to pass on (a
/// `.env` with values, a key file) is not installed either, with the same words, and the same
/// folder without it plans. Validate says it as a warning first, in the one shape every validate
/// note now has.
#[tokio::test]
async fn a_template_the_export_would_refuse_is_not_installed_either() {
    let engine = Engine::new();
    let service = engine.service();
    let (_folder, path) = copied_example("host-my-app");
    let call = || {
        serde_json::from_value::<super::super::planning::PlanCall>(json!({
            "source": { "kind": "local_folder", "path": path.to_string_lossy() },
            "name": "My app",
            "answers": [{ "field": "image", "value": "ghcr.io/example/hello-app:1.0.0" }, { "field": "access", "value": "quick" }],
            "bindings": [{ "field": "app_secret", "secretRef": "apply:app_secret" }]
        }))
        .unwrap()
    };
    super::super::planning::plan(&planner_host(), &NoHub, &service, call()).await.expect("the example plans as it is");
    fs::write(path.join(".env"), "OPENAI_API_KEY=sk-live-0123456789abcdef0123456789abcdef\n").unwrap();
    let refused = super::super::planning::plan(&planner_host(), &NoHub, &service, call()).await.unwrap_err();
    assert_eq!(refused.code, "install_refused");
    assert!(refused.message.starts_with("This template would not pass yougori template check, so nothing was planned:") && refused.message.contains(".env"), "{}", refused.message);
    assert!(service.snapshot().instances.is_empty(), "nothing was planned or made");
    let checked = serde_json::from_value(json!({ "source": { "kind": "local_folder", "path": path.to_string_lossy() } })).unwrap();
    let answer = super::super::planning::validate(&service, &NoHub, checked).await.unwrap();
    let notes = answer["notes"].as_array().unwrap();
    assert!(notes.iter().all(|note| note.is_object() && note["message"].is_string()), "one shape, a diagnostic each: {notes:?}");
    assert!(notes.iter().any(|note| note["code"] == "install_refused" && note["severity"] == "warning" && note["message"].as_str().unwrap().contains(".env")), "{notes:?}");
}

// ----- Found on a real engine (runtime acceptance, 27 October 2026) -----

/// PROVES a setup that was running when Yougori closed reads what is really there once Yougori
/// opens again, and that starting it starts what closing stopped. On a real engine the record
/// still said running: status said running with nothing running, and a start planned from the
/// record did nothing.
#[tokio::test]
async fn a_setup_closed_while_running_reads_stopped_after_a_restart_and_starts_again() {
    let bench = Bench::new();
    let service = bench.service();
    let (plan, _) = created(&service, "Site", vec![resource("db", &[]), resource("web", &["db"])]).await;
    let setup = plan.setup_id.clone();
    drop(service);
    // Closing Yougori stops every sandbox it runs.
    bench.fake.provider.lock().unwrap().resources.values_mut().for_each(|part| part.running = false);
    let service = bench.service();
    service.reconcile_all().await;
    service.refresh_all().await;
    let instance = service.snapshot().instances[&setup].clone();
    assert!(instance.resources.values().all(|part| part.observed == Observed::Stopped), "{:?}", instance.resources);
    assert!(instance.resources.values().all(|part| part.drift.as_deref() == Some("Stopped since this setup started it, for example when Yougori closed or by hand.")));
    // The app offers Start for it, although the setup itself still reads running.
    assert!(service.get(&setup).unwrap().setup.actions.contains(&yougori_setup::dto::SetupAction::Start));
    let start = service.plan(PlanIntent::Start { setup: setup.clone() }).unwrap();
    assert_eq!(start.steps.len(), 2, "both parts are started: {:?}", start.steps);
    service.apply(&start, &op(), no_secrets()).await.unwrap();
    assert!(bench.fake.provider.lock().unwrap().resources.values().all(|part| part.running), "and they run again");
    assert!(!service.get(&setup).unwrap().setup.actions.contains(&yougori_setup::dto::SetupAction::Start), "running again, it is not offered");
}

/// PROVES a removal stored with the waits of an earlier rule (a volume first, then the sandbox
/// that mounts it) is put in the order the setup needs before it is retried, so it can finish:
/// the volume waits for its sandbox, and the sandbox waits for nothing.
#[tokio::test]
async fn a_removal_ordered_by_an_earlier_rule_is_reordered_before_it_is_retried() {
    let mut bench = Bench::new();
    bench.extra.push(Arc::new(FakeHandler::new(Kind::Volume)));
    let service = bench.service();
    let volume = DeclaredResource { id: "data".into(), kind: Kind::Volume, spec: json!({}), requires: vec!["app".into()], owner: None };
    let app = DeclaredResource { spec: json!({ "image": "example/app", "volumes": [{ "source": "data", "target": "/data" }] }), ..resource("app", &[]) };
    let (plan, _) = created(&service, "Notes", vec![app, volume]).await;
    let setup = plan.setup_id.clone();
    let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
    let operation = op();
    service.submit(&remove, &operation, remove.base_revision, no_secrets()).unwrap();
    let mut steps = service.snapshot().operations[&operation].steps.clone();
    let step_of = |steps: &[super::super::journal::Step], resource: &str| steps.iter().position(|step| step.resource == resource).unwrap();
    let (data, app) = (step_of(&steps, "data"), step_of(&steps, "app"));
    // As an earlier engine stored it: the sandbox waiting for its own volume to go first.
    steps[data].depends_on.clear();
    steps[app].depends_on = vec![steps[data].id.clone()];
    let waits = super::teardown_waits(&steps, &service.snapshot().instances[&setup]);
    assert_eq!(waits[&steps[data].id], vec![steps[app].id.clone()], "the volume waits for the sandbox that mounts it");
    assert!(waits[&steps[app].id].is_empty(), "and the sandbox waits for nothing");
}
