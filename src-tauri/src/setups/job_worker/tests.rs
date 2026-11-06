//! The harmless distributed build that proves generic jobs reach beyond the grid profiles the
//! engine already had (template platform plan, section 22, milestone M07's exit gate).
//!
//! One realm in a temporary folder, several workers, and one queue. Each job runs a trivial
//! deterministic command — a fake sandbox writes the bytes a real `make` would — so what is proved
//! is the queue, the isolation, the checksums and the hand-over, and not a container. Nothing here
//! starts a sandbox, reaches another computer or touches anything outside its own temporary folder.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use yougori_grid::core::{
    identity::{PrincipalKind, Role},
    jobs::{JobSpec, JobState, Retry, SideEffects},
    realm::{Capability, RealmKind},
    work::Commitment,
};

const NOW: i64 = 1_000_000;

fn key() -> String {
    "d".repeat(64)
}

fn room() -> Resources {
    Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 }
}

fn needs() -> Resources {
    Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 }
}

// ---- the farm ----

/// A realm, the person who sends work to it, and a clock the test moves.
struct Farm {
    realm: Arc<Mutex<Core>>,
    person: String,
    laptop: String,
    clock: Arc<AtomicI64>,
    folder: tempfile::TempDir,
}

fn farm() -> Farm {
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), NOW).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], NOW).unwrap();
    let (laptop, _) = core.enrol_device(&person.id, "Ada's laptop", "linux", NOW).unwrap();
    Farm { realm: Arc::new(Mutex::new(core)), person: person.id, laptop: laptop.id, clock: Arc::new(AtomicI64::new(NOW)), folder }
}

impl Farm {
    fn with<T>(&self, work: impl FnOnce(&mut Core) -> T) -> T {
        work(&mut self.realm.lock().unwrap())
    }

    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    /// Moves every clock in the farm forward.
    fn after(&self, seconds: i64) {
        self.clock.fetch_add(seconds, Ordering::SeqCst);
    }

    /// One more computer offering room to the realm, with a worker loop of its own.
    fn computer(&self, name: &str, sandbox: Arc<dyn Sandbox>) -> Builder {
        let (device, host) = self.with(|core| {
            let (device, _) = core.enrol_device(&self.person, name, "linux", NOW).unwrap();
            let host = core.offer_host(&device.id, name, room(), room(), Commitment::Share, NOW).unwrap();
            (device.id, host.id)
        });
        let _ = host;
        let queue = Arc::new(TestQueue { inner: LocalQueue::new(self.realm.clone(), &device), clock: self.clock.clone(), quiet: AtomicBool::new(false) });
        Builder {
            worker: Arc::new(JobWorker::new(queue.clone(), sandbox, self.folder.path().join(format!("work-{name}")))),
            queue,
        }
    }

    fn send(&self, queue: &str, spec: JobSpec) -> String {
        self.with(|core| core.submit_job(&self.person, &self.laptop, queue, spec, self.now()).unwrap().job.id)
    }

    fn state(&self, job: &str) -> JobState {
        self.with(|core| core.job(job).unwrap().unwrap().state)
    }

    /// Every artifact a job's winning attempt handed back: its name, its size and its checksum.
    fn outputs(&self, job: &str) -> Vec<(String, u64, String)> {
        self.with(|core| core.job_outputs(job).unwrap()).into_iter().map(|artifact| (artifact.name, artifact.bytes, artifact.sha256)).collect()
    }

    fn attempts(&self, job: &str) -> Vec<(u32, String)> {
        self.with(|core| core.job_attempts(job).unwrap()).into_iter().map(|attempt| (attempt.number, attempt.state.word().to_owned())).collect()
    }
}

struct Builder {
    worker: Arc<JobWorker>,
    queue: Arc<TestQueue>,
}

impl Builder {
    async fn turn(&self) -> Turn {
        self.worker.turn(&CancellationToken::new()).await
    }
}

/// The realm on this computer, read through the farm's clock so a test can move time without
/// waiting for it. `quiet` makes a computer stop answering, the way one that was unplugged does.
struct TestQueue {
    inner: LocalQueue,
    clock: Arc<AtomicI64>,
    quiet: AtomicBool,
}

impl TestQueue {
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn with<T>(&self, work: impl FnOnce(&mut Core) -> T) -> T {
        work(&mut self.inner.realm.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    fn unplugged(&self) -> bool {
        self.quiet.load(Ordering::SeqCst)
    }
}

impl Queue for TestQueue {
    fn device(&self) -> &str {
        self.inner.device()
    }

    fn lease<'a>(&'a self, seconds: i64) -> BoxFuture<'a, Result<Option<JobLease>, JobError>> {
        Box::pin(async move { self.with(|core| core.lease_job(self.device(), seconds, self.now())) })
    }

    fn start<'a>(&'a self, attempt: &'a str, fence: u64) -> BoxFuture<'a, Result<(), JobError>> {
        Box::pin(async move { self.with(|core| core.start_job_attempt(self.device(), attempt, fence, self.now())).map(|_| ()) })
    }

    fn heartbeat<'a>(&'a self, attempt: &'a str, fence: u64, seconds: i64) -> BoxFuture<'a, Result<bool, JobError>> {
        Box::pin(async move {
            if self.unplugged() {
                return Err(JobError::Trouble("this computer cannot be reached".into()));
            }
            self.with(|core| core.heartbeat_job(self.device(), attempt, fence, seconds, self.now())).map(|beat| beat.stop_requested)
        })
    }

    fn fetch<'a>(&'a self, attempt: &'a str, fence: u64, artifact: &'a str, into: &'a Path) -> BoxFuture<'a, Result<(), JobError>> {
        Box::pin(async move {
            let mut file = std::fs::File::create(into).map_err(|error| JobError::Trouble(error.to_string()))?;
            self.with(|core| core.read_job_input(self.device(), attempt, fence, artifact, &mut file, self.now())).map(|_| ())
        })
    }

    fn send<'a>(&'a self, attempt: &'a str, fence: u64, name: &'a str, from: &'a Path) -> BoxFuture<'a, Result<String, JobError>> {
        Box::pin(async move {
            let (bytes, sha256) = measure(from)?;
            let ticket = self.with(|core| core.prepare_job_output(self.device(), attempt, fence, name, bytes, &sha256, self.now()))?;
            let mut file = std::fs::File::open(from).map_err(|error| JobError::Trouble(error.to_string()))?;
            let staged = ticket.stage(&mut file)?;
            self.with(|core| core.record_job_artifact(staged, self.now())).map(|artifact| artifact.id)
        })
    }

    fn checkpoint<'a>(&'a self, attempt: &'a str, fence: u64, from: &'a Path) -> BoxFuture<'a, Result<String, JobError>> {
        Box::pin(async move {
            let (bytes, sha256) = measure(from)?;
            let ticket = self.with(|core| core.prepare_job_checkpoint(self.device(), attempt, fence, bytes, &sha256, self.now()))?;
            let mut file = std::fs::File::open(from).map_err(|error| JobError::Trouble(error.to_string()))?;
            let staged = ticket.stage(&mut file)?;
            self.with(|core| core.record_job_artifact(staged, self.now())).map(|artifact| artifact.id)
        })
    }

    fn complete<'a>(&'a self, attempt: &'a str, fence: u64, ending: Ending) -> BoxFuture<'a, Result<(), JobError>> {
        Box::pin(async move { self.with(|core| core.complete_job_attempt(self.device(), attempt, fence, ending, self.now())).map(|_| ()) })
    }
}

// ---- the sandbox a test stands in for ----

/// A sandbox that writes what a trivial deterministic command would, and counts what it was asked
/// to do. It never starts a container and never leaves its own folder.
#[derive(Default)]
struct FakeSandbox {
    /// What each declared output's bytes are, by the attempt's program.
    runs: AtomicUsize,
    /// Every folder it was given, so a test can prove each attempt had its own.
    folders: Mutex<Vec<PathBuf>>,
    /// What it saw in the read-only input folder each time.
    saw: Mutex<Vec<Vec<String>>>,
    /// Ends the next run this way instead of succeeding.
    ending: Mutex<Option<Ran>>,
    /// Writes nothing, so the attempt has no output to send.
    empty_handed: AtomicBool,
}

impl Sandbox for FakeSandbox {
    fn run<'a>(&'a self, run: &'a Run, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<Ran, String>> {
        Box::pin(async move {
            self.runs.fetch_add(1, Ordering::SeqCst);
            self.folders.lock().unwrap().push(run.outputs.clone());
            let mut seen: Vec<String> = std::fs::read_dir(&run.inputs)
                .map(|entries| entries.filter_map(|entry| entry.ok()).map(|entry| entry.file_name().to_string_lossy().to_string()).collect())
                .unwrap_or_default();
            seen.sort();
            self.saw.lock().unwrap().push(seen);
            if cancel.is_cancelled() {
                return Ok(Ran::Stopped);
            }
            if let Some(ending) = self.ending.lock().unwrap().take() {
                return Ok(ending);
            }
            if !self.empty_handed.load(Ordering::SeqCst) {
                // The deterministic "build": the same bytes for the same command, every time.
                let Entrypoint::Argv { argv } = &run.entrypoint else { return Err("this fake runs a program and its arguments".into()) };
                std::fs::write(run.outputs.join("report"), argv.join(" ").into_bytes()).map_err(|error| error.to_string())?;
            }
            Ok(Ran::Exited(0))
        })
    }
}

/// A sandbox that waits to be told to stop, so a test can hold an attempt open.
#[derive(Default)]
struct Waiting {
    started: AtomicUsize,
}

impl Sandbox for Waiting {
    fn run<'a>(&'a self, _run: &'a Run, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<Ran, String>> {
        Box::pin(async move {
            self.started.fetch_add(1, Ordering::SeqCst);
            cancel.cancelled().await;
            Ok(Ran::Stopped)
        })
    }
}

// ---- the specification the farm builds ----

/// A repeatable build of one target: a program and its arguments, one declared output, three
/// attempts allowed.
fn target(name: &str) -> JobSpec {
    JobSpec {
        entrypoint: Entrypoint::Argv { argv: vec!["make".into(), name.into()] },
        inputs: Vec::new(),
        outputs: vec!["report".into()],
        timeout_seconds: 600,
        needs: needs(),
        retry: Retry { max_attempts: 3, backoff_seconds: 0 },
        side_effects: SideEffects::Repeatable,
        checkpoints: false,
    }
}

fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

// ---- the fixture ----

#[tokio::test]
async fn several_workers_build_one_queue_between_them_and_every_result_is_checksummed() {
    let farm = farm();
    let targets = ["alpha", "beta", "gamma", "delta"];
    let jobs: Vec<String> = targets.iter().map(|name| farm.send("builds", target(name))).collect();

    let sandboxes: Vec<Arc<FakeSandbox>> = (0..3).map(|_| Arc::new(FakeSandbox::default())).collect();
    let builders: Vec<Builder> = sandboxes.iter().enumerate().map(|(which, sandbox)| farm.computer(&format!("builder-{which}"), sandbox.clone())).collect();

    // Every worker asks in turn until the queue is empty, exactly as the loop does.
    let mut taken = 0;
    for _ in 0..targets.len() {
        for builder in &builders {
            if let Turn::Reported { ending, .. } = builder.turn().await {
                assert_eq!(ending, "succeeded");
                taken += 1;
            }
        }
    }
    assert_eq!(taken, targets.len(), "every job in the queue was built exactly once");

    // The work was shared out: no one computer did all of it.
    let each: Vec<usize> = sandboxes.iter().map(|sandbox| sandbox.runs.load(Ordering::SeqCst)).collect();
    assert_eq!(each.iter().sum::<usize>(), targets.len(), "{each:?}");
    assert!(each.iter().filter(|count| **count > 0).count() > 1, "the queue was shared between computers: {each:?}");

    // Each job succeeded, with one attempt, and handed back exactly what its command produces.
    for (job, name) in jobs.iter().zip(targets) {
        assert_eq!(farm.state(job), JobState::Succeeded, "{name}");
        let expected = format!("make {name}").into_bytes();
        assert_eq!(farm.outputs(job), vec![("report".to_owned(), expected.len() as u64, sha(&expected))], "{name}");
        assert_eq!(farm.attempts(job), vec![(1, "succeeded".to_owned())], "{name}");
    }

    // Every attempt had a folder of its own, and none of them is left behind.
    let folders: Vec<PathBuf> = sandboxes.iter().flat_map(|sandbox| sandbox.folders.lock().unwrap().clone()).collect();
    let mut unique = folders.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), folders.len(), "each attempt ran in a folder of its own: {folders:?}");
    assert!(folders.iter().all(|folder| !folder.exists()), "nothing an attempt left behind is still there");

    // Nothing was in any attempt's read-only folder: these jobs declared no inputs.
    for sandbox in &sandboxes {
        assert!(sandbox.saw.lock().unwrap().iter().all(Vec::is_empty));
    }
}

#[tokio::test]
async fn a_worker_that_goes_silent_has_its_attempt_replaced_and_never_completes_the_job_twice() {
    let farm = farm();
    let job = farm.send("builds", target("alpha"));

    // The first computer takes the job, starts it, and is unplugged mid-build.
    let slow = Arc::new(Waiting::default());
    let first = farm.computer("builder-slow", slow.clone());
    let leased = first.queue.lease(60).await.unwrap().expect("a job for the first computer");
    first.queue.start(&leased.attempt_id, leased.fence).await.unwrap();
    first.queue.quiet.store(true, Ordering::SeqCst);
    assert_eq!(farm.state(&job), JobState::Running);

    // Its reservation runs out, well inside the job's own time limit, so what happened is that
    // the computer went quiet rather than that the work took too long. The next computer to ask
    // settles what lapsed and takes the job on.
    farm.after(120);
    let sandbox = Arc::new(FakeSandbox::default());
    let second = farm.computer("builder-fresh", sandbox.clone());
    assert_eq!(second.turn().await, Turn::Reported { job: job.clone(), ending: "succeeded" });
    assert_eq!(farm.state(&job), JobState::Succeeded);

    // The silent computer comes back and tries to finish the attempt it was holding. It is
    // refused at its first step, so the job is never completed authoritatively twice.
    first.queue.quiet.store(false, Ordering::SeqCst);
    let late = first.queue.complete(&leased.attempt_id, leased.fence, Ending::Succeeded).await;
    assert!(matches!(late, Err(JobError::StaleFence)), "{late:?}");
    assert_eq!(farm.state(&job), JobState::Succeeded);

    // Two attempts are on the record, and only the second one decided anything.
    assert_eq!(farm.attempts(&job), vec![(1, "lost".to_owned()), (2, "succeeded".to_owned())]);
    assert_eq!(farm.outputs(&job).len(), 1);
    assert_eq!(sandbox.runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_result_sent_twice_is_recorded_once_and_the_second_send_finds_the_first() {
    let farm = farm();
    let job = farm.send("builds", target("alpha"));
    let builder = farm.computer("builder", Arc::new(FakeSandbox::default()));
    let leased = builder.queue.lease(60).await.unwrap().unwrap();
    builder.queue.start(&leased.attempt_id, leased.fence).await.unwrap();

    let made = farm.folder.path().join("report");
    std::fs::write(&made, b"make alpha").unwrap();
    let first = builder.queue.send(&leased.attempt_id, leased.fence, "report", &made).await.unwrap();
    // The computer never heard the first answer, so it sends the same output again.
    let again = builder.queue.send(&leased.attempt_id, leased.fence, "report", &made).await.unwrap();
    assert_eq!(first, again, "the same output sent twice is one artifact, not two");

    // Different bytes under the same name are refused: what an attempt sent is never replaced.
    std::fs::write(&made, b"make alpha, differently").unwrap();
    let different = builder.queue.send(&leased.attempt_id, leased.fence, "report", &made).await;
    assert!(matches!(different, Err(JobError::OutputAlreadySent(_))), "{different:?}");

    builder.queue.complete(&leased.attempt_id, leased.fence, Ending::Succeeded).await.unwrap();
    assert_eq!(farm.outputs(&job).len(), 1);
    assert_eq!(farm.state(&job), JobState::Succeeded);
}

#[tokio::test]
async fn a_build_that_hands_nothing_back_fails_and_is_tried_again_by_another_computer() {
    let farm = farm();
    let job = farm.send("builds", target("alpha"));

    let forgetful = Arc::new(FakeSandbox::default());
    forgetful.empty_handed.store(true, Ordering::SeqCst);
    let first = farm.computer("builder-forgetful", forgetful);
    assert_eq!(first.turn().await, Turn::Reported { job: job.clone(), ending: "failed" });
    assert_eq!(farm.state(&job), JobState::Queued, "a repeatable job that failed waits for another computer");

    let sandbox = Arc::new(FakeSandbox::default());
    let second = farm.computer("builder-good", sandbox.clone());
    assert_eq!(second.turn().await, Turn::Reported { job: job.clone(), ending: "succeeded" });
    assert_eq!(farm.state(&job), JobState::Succeeded);
    assert_eq!(farm.attempts(&job), vec![(1, "failed".to_owned()), (2, "succeeded".to_owned())]);
}

#[tokio::test]
async fn an_attempt_that_lost_its_lease_sends_nothing_and_reports_nothing() {
    let farm = farm();
    let job = farm.send("builds", target("alpha"));

    // One computer holds the attempt; another takes the job over once the reservation lapses.
    let waiting = Arc::new(Waiting::default());
    let first = farm.computer("builder-slow", waiting);
    let leased = first.queue.lease(60).await.unwrap().unwrap();
    first.queue.start(&leased.attempt_id, leased.fence).await.unwrap();
    farm.after(120);
    let second = farm.computer("builder-fresh", Arc::new(FakeSandbox::default()));
    second.turn().await;

    // What the first computer made is refused, bytes and all, and nothing of it is recorded.
    let made = farm.folder.path().join("late-report");
    std::fs::write(&made, b"make alpha").unwrap();
    let sent = first.queue.send(&leased.attempt_id, leased.fence, "report", &made).await;
    assert!(matches!(sent, Err(JobError::StaleFence)), "{sent:?}");
    assert_eq!(farm.outputs(&job).len(), 1, "only the attempt that holds the job hands anything back");
}

#[tokio::test]
async fn an_attempt_reads_its_own_jobs_inputs_under_the_names_the_job_gave_them() {
    let farm = farm();
    // One job makes something; a second reads it under a name of its own.
    let first = farm.send("builds", target("alpha"));
    let builder = farm.computer("builder", Arc::new(FakeSandbox::default()));
    builder.turn().await;
    let made = farm.with(|core| core.job_outputs(&first).unwrap())[0].id.clone();

    let mut second = target("beta");
    second.inputs = vec![yougori_grid::core::jobs::InputRef { name: "alpha-report".into(), artifact_id: made }];
    let job = farm.send("builds", second);
    let sandbox = Arc::new(FakeSandbox::default());
    let reader = farm.computer("reader", sandbox.clone());
    assert_eq!(reader.turn().await, Turn::Reported { job, ending: "succeeded" });
    assert_eq!(sandbox.saw.lock().unwrap().clone(), vec![vec!["alpha-report".to_owned()]]);
}

#[tokio::test]
async fn asking_a_running_job_to_stop_is_heard_and_the_attempt_ends_as_stopped() {
    let farm = farm();
    let job = farm.send("builds", target("alpha"));
    let builder = farm.computer("builder", Arc::new(Waiting::default()));
    let leased = builder.queue.lease(60).await.unwrap().unwrap();
    builder.queue.start(&leased.attempt_id, leased.fence).await.unwrap();

    farm.with(|core| core.cancel_job("owner", &job, farm.now()).unwrap());
    assert_eq!(farm.state(&job), JobState::CancelRequested);
    assert!(builder.queue.heartbeat(&leased.attempt_id, leased.fence, 60).await.unwrap(), "the computer hears it on its next heartbeat");
    builder.queue.complete(&leased.attempt_id, leased.fence, Ending::Stopped).await.unwrap();
    assert_eq!(farm.state(&job), JobState::Stopped);
}

#[tokio::test]
async fn a_worker_asks_again_when_the_queue_has_nothing_for_it() {
    let farm = farm();
    let builder = farm.computer("builder", Arc::new(FakeSandbox::default()));
    assert_eq!(builder.turn().await, Turn::Nothing);
}

/// The one that matters for a person's own answer: a store that asked for less than the grid's
/// default really sweeps to what it asked for. Built out of real jobs on a real realm, with the
/// same mapping from the template's words that the store handler uses.
#[tokio::test]
async fn a_store_that_asks_for_less_than_the_grid_keeps_sweeps_to_what_it_asked_for() {
    use crate::setups::jobs::retention_of;
    use yougori_grid::core::limits::{KEEP_JOB_ARTIFACTS_FOR, KEEP_JOB_ARTIFACT_BYTES};

    let farm = farm();
    // What the template asked for: a day of keeping, where the grid's own default is thirty.
    let wanted = retention_of(1.0, Some(1));
    assert!(wanted.keep_seconds < KEEP_JOB_ARTIFACTS_FOR && wanted.keep_bytes < KEEP_JOB_ARTIFACT_BYTES);
    farm.with(|core| core.set_job_retention("owner", wanted, farm.now()).unwrap());
    assert_eq!(farm.with(|core| core.job_retention().unwrap()), wanted);

    // Two builds finish and hand back their results.
    let jobs: Vec<String> = ["alpha", "beta"].iter().map(|name| farm.send("builds", target(name))).collect();
    let builder = farm.computer("builder", Arc::new(FakeSandbox::default()));
    for _ in &jobs {
        assert!(matches!(builder.turn().await, Turn::Reported { ending: "succeeded", .. }));
    }
    for job in &jobs {
        assert_eq!(farm.outputs(job).len(), 1);
    }

    // Two days later the sweep removes them, because this store keeps one day. Under the grid's
    // own thirty days nothing would have gone, which is the whole point of asking the person.
    farm.after(2 * 86_400);
    let tidied = farm.with(|core| core.tidy_job_artifacts(farm.now()).unwrap());
    assert_eq!(tidied.artifacts_removed, 2, "{tidied:?}");
    assert!(tidied.bytes_freed > 0);
    assert!(!tidied.over_allowance);

    // The records stay, saying what was sent and why its bytes went. Only the bytes are gone.
    for job in &jobs {
        let artifacts = farm.with(|core| core.job_artifacts(job).unwrap());
        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].removed_at.is_some(), "the record is kept");
        assert!(artifacts[0].removed_reason.contains("older than"), "{}", artifacts[0].removed_reason);
        assert_eq!(artifacts[0].sha256.len(), 64, "what it hashed to is never lost");
    }
}

/// And a build still in play keeps what it needs, whatever the store's answer says.
#[tokio::test]
async fn a_store_that_keeps_little_still_never_removes_what_a_build_in_play_needs() {
    use crate::setups::jobs::retention_of;
    let farm = farm();
    farm.with(|core| core.set_job_retention("owner", retention_of(1.0, Some(1)), farm.now()).unwrap());

    let first = farm.send("builds", target("alpha"));
    let builder = farm.computer("builder", Arc::new(FakeSandbox::default()));
    builder.turn().await;
    let made = farm.with(|core| core.job_outputs(&first).unwrap())[0].id.clone();

    // A second build that has not run yet reads the first one's result.
    let mut second = target("beta");
    second.inputs = vec![yougori_grid::core::jobs::InputRef { name: "alpha-report".into(), artifact_id: made.clone() }];
    farm.send("builds", second);

    farm.after(2 * 86_400);
    let tidied = farm.with(|core| core.tidy_job_artifacts(farm.now()).unwrap());
    assert_eq!(tidied.artifacts_removed, 0, "what a build still in play needs is kept whatever its age");
    assert!(farm.with(|core| core.job_artifacts(&first).unwrap())[0].removed_at.is_none());
}

#[test]
fn workers_are_off_until_something_starts_them_and_stop_when_it_says_so() {
    let workers = Workers::default();
    assert!(!workers.running("build-farm"));
    workers.stop("build-farm");
    assert!(!workers.running("build-farm"));
}
