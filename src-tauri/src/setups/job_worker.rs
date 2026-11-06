//! The loop a computer runs to take finite jobs off a grid's queue, run each one in a sandbox of
//! its own, and hand back what it made.
//!
//! Everything that decides anything is in `yougori_grid::core::jobs`: the queue, the fencing, the
//! attempts, the retries, the cancel that is a request, the artifacts that are staged and checked
//! before they are recorded. This loop decides nothing. It asks for work, runs it, reports, and
//! stops when it is told to. Written out, what it holds to:
//!
//! **A fresh sandbox for every attempt.** Nothing an attempt leaves behind is visible to the next
//! one, on this computer or any other. The attempt's folder is made before it starts and removed
//! after it ends, whichever way it ended.
//!
//! **What the attempt can see is what the job declared.** Its inputs and the source it was given
//! are written into one folder, mounted read-only, each checked against its checksum on the way in
//! by the realm that sends it. Its outputs are collected from one folder it may write. It is given
//! no path on this computer, no shell, and no credential: a job's command is a program and its
//! arguments, and the library refuses a shell as the program before any of this runs.
//!
//! **A lost lease never writes.** Before anything an attempt made is sent, the loop asks the realm
//! whether it still holds the attempt. If it does not — the fencing token moved on, the reservation
//! ran out, the computer was emptied — nothing is sent and nothing is reported, and the realm's own
//! fencing refuses it a second time anyway if the loop were ever wrong.
//!
//! **A cancel is heard on the next heartbeat.** The loop heartbeats while the sandbox runs. When
//! the realm answers that the job was asked to stop, the sandbox is stopped and the attempt ends as
//! `Stopped`. Nothing is killed by the realm; this computer stops its own work.
//!
//! **It is off until a setup turns it on.** No grid runs generic jobs because it exists. The job
//! handler (`setups::jobs`) starts one of these when a setup that declares jobs is applied, and
//! stops it when that setup is removed or stopped.
#![allow(dead_code)]
use super::ordinary::BoxFuture;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use yougori_grid::core::{
    jobs::{Ending, Entrypoint, Failure, JobError, JobLease},
    work::Resources,
    Core,
};

/// How often the loop tells the realm the attempt is still being run, and so how soon a cancel is
/// heard. Well inside the shortest reservation the realm will grant.
const HEARTBEAT: Duration = Duration::from_secs(10);
/// How long a reservation is asked for at a time.
const LEASE_SECONDS: i64 = 60;
/// How long the loop waits before asking for work again when the queue had none for it.
const IDLE: Duration = Duration::from_secs(5);
/// How long the loop waits before asking again after the realm could not be reached.
const AFTER_TROUBLE: Duration = Duration::from_secs(30);

// ---- what the loop needs from the realm ----

/// The queue this computer takes work from. A realm on this computer, or a grid's door.
pub(crate) trait Queue: Send + Sync {
    /// This computer, as the realm knows it.
    fn device(&self) -> &str;
    fn lease<'a>(&'a self, seconds: i64) -> BoxFuture<'a, Result<Option<JobLease>, JobError>>;
    fn start<'a>(&'a self, attempt: &'a str, fence: u64) -> BoxFuture<'a, Result<(), JobError>>;
    /// Renews the reservation and answers whether the job has been asked to stop.
    fn heartbeat<'a>(&'a self, attempt: &'a str, fence: u64, seconds: i64) -> BoxFuture<'a, Result<bool, JobError>>;
    /// Writes one of the attempt's own inputs into `into`, checked against its checksum.
    fn fetch<'a>(&'a self, attempt: &'a str, fence: u64, artifact: &'a str, into: &'a Path) -> BoxFuture<'a, Result<(), JobError>>;
    /// Sends one output: staged and hashed first, recorded under the attempt's token after.
    fn send<'a>(&'a self, attempt: &'a str, fence: u64, name: &'a str, from: &'a Path) -> BoxFuture<'a, Result<String, JobError>>;
    /// Sends a checkpoint a later attempt may pick up from, for a job that said it can.
    fn checkpoint<'a>(&'a self, attempt: &'a str, fence: u64, from: &'a Path) -> BoxFuture<'a, Result<String, JobError>>;
    fn complete<'a>(&'a self, attempt: &'a str, fence: u64, ending: Ending) -> BoxFuture<'a, Result<(), JobError>>;
}

/// A realm whose database is on this computer, reached through the library directly.
pub(crate) struct LocalQueue {
    realm: Arc<Mutex<Core>>,
    device_id: String,
}

impl LocalQueue {
    pub(crate) fn new(realm: Arc<Mutex<Core>>, device_id: &str) -> LocalQueue {
        LocalQueue { realm, device_id: device_id.to_owned() }
    }

    fn with<T>(&self, work: impl FnOnce(&mut Core) -> T) -> T {
        work(&mut self.realm.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

fn clock() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs() as i64).unwrap_or_default()
}

impl Queue for LocalQueue {
    fn device(&self) -> &str {
        &self.device_id
    }

    fn lease<'a>(&'a self, seconds: i64) -> BoxFuture<'a, Result<Option<JobLease>, JobError>> {
        Box::pin(async move { self.with(|core| core.lease_job(&self.device_id, seconds, clock())) })
    }

    fn start<'a>(&'a self, attempt: &'a str, fence: u64) -> BoxFuture<'a, Result<(), JobError>> {
        Box::pin(async move { self.with(|core| core.start_job_attempt(&self.device_id, attempt, fence, clock())).map(|_| ()) })
    }

    fn heartbeat<'a>(&'a self, attempt: &'a str, fence: u64, seconds: i64) -> BoxFuture<'a, Result<bool, JobError>> {
        Box::pin(async move { self.with(|core| core.heartbeat_job(&self.device_id, attempt, fence, seconds, clock())).map(|beat| beat.stop_requested) })
    }

    fn fetch<'a>(&'a self, attempt: &'a str, fence: u64, artifact: &'a str, into: &'a Path) -> BoxFuture<'a, Result<(), JobError>> {
        Box::pin(async move {
            let mut file = std::fs::File::create(into).map_err(|error| JobError::Trouble(format!("Cannot write this job's input on this computer: {error}")))?;
            self.with(|core| core.read_job_input(&self.device_id, attempt, fence, artifact, &mut file, clock())).map(|_| ())
        })
    }

    fn send<'a>(&'a self, attempt: &'a str, fence: u64, name: &'a str, from: &'a Path) -> BoxFuture<'a, Result<String, JobError>> {
        Box::pin(async move {
            let (bytes, sha256) = measure(from)?;
            let ticket = self.with(|core| core.prepare_job_output(&self.device_id, attempt, fence, name, bytes, &sha256, clock()))?;
            // Staged without the realm, exactly as the library asks: a large upload never holds it.
            let mut file = std::fs::File::open(from).map_err(|error| JobError::Trouble(format!("Cannot read this job's output on this computer: {error}")))?;
            let staged = ticket.stage(&mut file)?;
            self.with(|core| core.record_job_artifact(staged, clock())).map(|artifact| artifact.id)
        })
    }

    fn checkpoint<'a>(&'a self, attempt: &'a str, fence: u64, from: &'a Path) -> BoxFuture<'a, Result<String, JobError>> {
        Box::pin(async move {
            let (bytes, sha256) = measure(from)?;
            let ticket = self.with(|core| core.prepare_job_checkpoint(&self.device_id, attempt, fence, bytes, &sha256, clock()))?;
            let mut file = std::fs::File::open(from).map_err(|error| JobError::Trouble(format!("Cannot read this job's checkpoint on this computer: {error}")))?;
            let staged = ticket.stage(&mut file)?;
            self.with(|core| core.record_job_artifact(staged, clock())).map(|artifact| artifact.id)
        })
    }

    fn complete<'a>(&'a self, attempt: &'a str, fence: u64, ending: Ending) -> BoxFuture<'a, Result<(), JobError>> {
        Box::pin(async move { self.with(|core| core.complete_job_attempt(&self.device_id, attempt, fence, ending, clock())).map(|_| ()) })
    }
}

/// How many bytes a file is and what they hash to, read once, before anything is declared.
pub(crate) fn measure(path: &Path) -> Result<(u64, String), JobError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|error| JobError::Trouble(format!("Cannot read what this job made: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|error| JobError::Trouble(format!("Cannot read what this job made: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok((bytes, hex::encode(hasher.finalize())))
}

// ---- what the loop needs from this computer ----

/// One attempt, as the sandbox is asked to run it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Run {
    /// The job this is an attempt at.
    pub job: String,
    pub attempt: String,
    pub entrypoint: Entrypoint,
    /// Mounted read-only. Holds the job's inputs and the source it was given, each under its own
    /// logical name.
    pub inputs: PathBuf,
    /// The one folder the attempt may write. Its declared outputs are collected from here.
    pub outputs: PathBuf,
    pub needs: Resources,
    /// Handed to the job as `YOUGORI_JOB_DEDUP_KEY` when it has one, so the system it changes can
    /// recognise a repeat. Never a credential, and never a path.
    pub dedup_key: Option<String>,
    /// The longest this attempt may take, from now.
    pub seconds: i64,
}

/// How the attempt's program ended, as this computer saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ran {
    Exited(i32),
    /// The program or its sandbox ended abnormally.
    Crashed,
    /// It was stopped because the job was asked to stop, or this computer is shutting down.
    Stopped,
    /// It reached the job's time limit without ending. Whether it did its work is not known, so
    /// this computer reports nothing and lets the attempt lapse; the realm decides from there.
    TimedOut,
}

/// Running one attempt on this computer. The engine's container runtime behind it; a fake in tests.
pub(crate) trait Sandbox: Send + Sync {
    /// Runs the attempt to its end, or until `cancel`, in a sandbox made for it and removed after.
    fn run<'a>(&'a self, run: &'a Run, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<Ran, String>>;
}

/// Where an attempt's inputs and outputs appear inside its sandbox. Fixed here, so nothing a job
/// names ever becomes a path and no job can ask for a different place on this computer.
/// What an attempt calls the file it leaves for a later attempt to pick up from, in its output
/// folder. Fixed here, beside the outputs, so a job never names a place on a computer.
pub(crate) const CHECKPOINT: &str = "checkpoint";
pub(crate) const INPUTS_AT: &str = "/yougori/job/in";
pub(crate) const OUTPUTS_AT: &str = "/yougori/job/out";
/// Where the folder a job reads appears, read-only, when it was given one.
pub(crate) const SOURCE_AT: &str = "/yougori/job/source";
/// How much of what one attempt printed is kept, and how many attempts' worth per job.
const LOG_BYTES: usize = 256 * 1024;
const LOGS_PER_JOB: usize = 10;

/// The folders this computer's jobs read, by job, beside a setup's realm.
fn sources_file(meta: &Path) -> PathBuf {
    meta.join("sources.json")
}

/// Records the folder `job` reads. Written whole and moved into place.
pub(crate) fn remember_source(meta: &Path, job: &str, folder: &Path) -> Result<(), String> {
    std::fs::create_dir_all(meta).map_err(|error| format!("Yougori can't keep which folder this job reads: {error}"))?;
    let file = sources_file(meta);
    let mut known: BTreeMap<String, String> = std::fs::read(&file).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
    known.insert(job.to_owned(), folder.to_string_lossy().into_owned());
    let staged = meta.join("sources.json.new");
    std::fs::write(&staged, serde_json::to_vec(&known).unwrap_or_default()).map_err(|error| format!("Yougori can't keep which folder this job reads: {error}"))?;
    std::fs::rename(&staged, &file).map_err(|error| format!("Yougori can't keep which folder this job reads: {error}"))
}

/// The folder `job` reads, when it was given one.
pub(crate) fn source_of(meta: &Path, job: &str) -> Option<PathBuf> {
    let known: BTreeMap<String, String> = std::fs::read(sources_file(meta)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok())?;
    known.get(job).map(PathBuf::from)
}

/// The runs events started, by job resource.
fn runs_file(meta: &Path) -> PathBuf {
    meta.join("runs.json")
}

/// How many runs of one job events started are listed.
const RUNS_PER_JOB: usize = 50;

/// Notes that an event started `job` as a run of `resource`: the last fifty are kept.
pub(crate) fn remember_run(meta: &Path, resource: &str, job: &str, why: &str) {
    if std::fs::create_dir_all(meta).is_err() {
        return;
    }
    let file = runs_file(meta);
    let mut runs: BTreeMap<String, Vec<serde_json::Value>> = std::fs::read(&file).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
    let list = runs.entry(resource.to_owned()).or_default();
    list.push(serde_json::json!({"job": job, "why": why, "at": clock()}));
    let extra = list.len().saturating_sub(RUNS_PER_JOB);
    list.drain(..extra);
    let staged = meta.join("runs.json.new");
    if std::fs::write(&staged, serde_json::to_vec(&runs).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&staged, &file);
    }
}

/// The runs events started for `resource`, oldest first.
pub(crate) fn runs_of(meta: &Path, resource: &str) -> Vec<serde_json::Value> {
    let runs: BTreeMap<String, Vec<serde_json::Value>> = std::fs::read(runs_file(meta)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
    runs.get(resource).cloned().unwrap_or_default()
}

/// Where what a job's attempts printed is kept: one file per attempt.
pub(crate) fn logs_folder(meta: &Path, job: &str) -> PathBuf {
    let safe: String = job.chars().filter(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_')).collect();
    meta.join("logs").join(safe)
}

/// Keeps the end of what one attempt printed, and only the last few attempts of a job.
pub(crate) fn keep_log(meta: &Path, job: &str, attempt: &str, text: &str) {
    let folder = logs_folder(meta, job);
    if std::fs::create_dir_all(&folder).is_err() {
        return;
    }
    let start = text.len().saturating_sub(LOG_BYTES);
    let start = (start..text.len()).find(|at| text.is_char_boundary(*at)).unwrap_or(text.len());
    let safe: String = attempt.chars().filter(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_')).collect();
    let _ = std::fs::write(folder.join(format!("{}-{safe}.log", clock())), &text[start..]);
    let mut kept: Vec<PathBuf> = std::fs::read_dir(&folder).into_iter().flatten().flatten().map(|entry| entry.path()).filter(|path| path.extension().is_some_and(|ext| ext == "log")).collect();
    kept.sort();
    let extra = kept.len().saturating_sub(LOGS_PER_JOB);
    for old in kept.into_iter().take(extra) {
        let _ = std::fs::remove_file(old);
    }
}
/// The image an attempt runs in when its job named a program rather than an image.
const PLAIN_IMAGE: &str = "ubuntu:24.04";
/// Disk for one attempt's sandbox, in whole gigabytes, when the job asked for none.
const SANDBOX_DISK_GB: f64 = 20.0;
/// How often the sandbox is asked whether its program has ended.
const WATCH: Duration = Duration::from_secs(2);

/// The engine's own container runtime: a container of its own for every attempt, made when the
/// attempt starts and deleted when it ends.
///
/// Nothing is reused between attempts, not the container and not its storage. The attempt's input
/// folder is mounted read-only and its output folder read-write, both at fixed places; it is given
/// no other folder of this computer, no network, and no secret. Its command is the program and the
/// arguments the job declared, set as the container's entrypoint so that nothing is ever handed to
/// a shell.
pub(crate) struct EngineSandbox {
    app: crate::AppHandle,
    /// Where the setup keeps the folders its jobs read and what their attempts printed.
    meta: Option<PathBuf>,
}

impl EngineSandbox {
    pub(crate) fn new(app: crate::AppHandle) -> EngineSandbox {
        EngineSandbox { app, meta: None }
    }

    /// A sandbox for one setup's attempts: it mounts the folder a job was given and keeps what
    /// each attempt printed beside the setup's realm.
    pub(crate) fn for_setup(app: crate::AppHandle, meta: PathBuf) -> EngineSandbox {
        EngineSandbox { app, meta: Some(meta) }
    }

    fn runtime(&self) -> tauri::State<'_, crate::runtime::RuntimeManager> {
        use tauri::Manager;
        self.app.state::<crate::runtime::RuntimeManager>()
    }

    /// What the attempt runs and where, as the runtime wants it.
    fn options(run: &Run, source: Option<&Path>) -> Result<(String, yougori_cli::workload::Options, Vec<String>), String> {
        let bind = |folder: &Path, at: &str, read_only: bool| -> Result<yougori_cli::workload::Volume, String> {
            let source = folder.to_str().ok_or("This computer's folder name cannot be used in a sandbox.")?.to_owned();
            Ok(yougori_cli::workload::Volume { source, target: at.to_owned(), read_only })
        };
        let (image, entrypoint, args) = match &run.entrypoint {
            Entrypoint::Argv { argv } => (PLAIN_IMAGE.to_owned(), Some(argv.clone()), Some(Vec::new())),
            Entrypoint::Image { reference, args } => (reference.clone(), None, Some(args.clone())),
        };
        let mut environment = BTreeMap::new();
        environment.insert("YOUGORI_JOB_INPUTS".to_owned(), INPUTS_AT.to_owned());
        environment.insert("YOUGORI_JOB_OUTPUTS".to_owned(), OUTPUTS_AT.to_owned());
        if let Some(key) = &run.dedup_key {
            environment.insert("YOUGORI_JOB_DEDUP_KEY".to_owned(), key.clone());
        }
        let mut binds = vec![bind(&run.inputs, INPUTS_AT, true)?, bind(&run.outputs, OUTPUTS_AT, false)?];
        // The folder the person chose for the job to read, and nothing else of this computer.
        if let Some(source) = source {
            environment.insert("YOUGORI_JOB_SOURCE".to_owned(), SOURCE_AT.to_owned());
            binds.push(bind(source, SOURCE_AT, true)?);
        }
        let options = yougori_cli::workload::Options {
            environment,
            secret_environment: BTreeMap::new(),
            hosts: BTreeMap::new(),
            args,
            entrypoint,
            working_dir: Some(OUTPUTS_AT.to_owned()),
            user: None,
            volumes: Vec::new(),
            binds,
            restart: "no".to_owned(),
        };
        Ok((image, options, Vec::new()))
    }

    fn policy(needs: &Resources) -> crate::models::ResourcePolicy {
        let range = |amount: f64, least: f64| crate::models::ResourceRange { min: least, preferred: amount.max(least), max: amount.max(least), current: 0.0 };
        crate::models::ResourcePolicy {
            cpu: range(needs.cpu, 1.0),
            memory_gb: range(needs.memory_gb, 1.0),
            priority: crate::models::Priority::Normal,
            dynamic: true,
        }
    }
}

impl Sandbox for EngineSandbox {
    fn run<'a>(&'a self, run: &'a Run, cancel: &'a CancellationToken) -> BoxFuture<'a, Result<Ran, String>> {
        Box::pin(async move {
            let runtime = self.runtime();
            // One container per attempt, named after it, so nothing of an earlier attempt is here.
            let id = format!("job-{}", run.attempt);
            let source = self.meta.as_deref().and_then(|meta| source_of(meta, &run.job));
            if let Some(folder) = source.as_deref().filter(|folder| !folder.is_dir()) {
                return Err(format!("{}, the folder this job reads, isn't there.", folder.display()));
            }
            let (image, options, _) = Self::options(run, source.as_deref())?;
            runtime.save_workload_options(&id, &options)?;
            let disk = if run.needs.disk_gb > 0.0 { run.needs.disk_gb } else { SANDBOX_DISK_GB };
            let made = runtime.provision_container_with_storage(&id, &image, "", &Self::policy(&run.needs), false, run.needs.gpu, disk).await;
            let ran = match made {
                Ok(()) => match runtime.container_action(&id, "start", false).await {
                    Ok(()) => watch(&runtime, &id, run.seconds, cancel).await,
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            // What the attempt printed is kept before its sandbox goes, so a failure can be read.
            if let Some(meta) = &self.meta {
                if let Ok(printed) = runtime.container_logs(&id).await {
                    keep_log(meta, &run.job, &run.attempt, &printed);
                }
            }
            // The sandbox goes whichever way the attempt ended. A sandbox that cannot be removed
            // is reported rather than left silently: the next attempt must not find it.
            let _ = runtime.container_action(&id, "stop", false).await;
            runtime.forget_active_container(&id).await;
            if let Err(error) = runtime.delete_container(&id).await {
                return Err(format!("This computer could not clear away the sandbox for this attempt: {error}"));
            }
            ran
        })
    }
}

/// Waits for the attempt's program to end, for its time limit to pass, or for it to be asked to
/// stop. The runtime is asked how it ended; a sandbox that ended abnormally says so.
async fn watch(runtime: &crate::runtime::RuntimeManager, id: &str, seconds: i64, cancel: &CancellationToken) -> Result<Ran, String> {
    let until = tokio::time::Instant::now() + Duration::from_secs(seconds.max(1) as u64);
    loop {
        match runtime.container_exit_detail(id).await {
            Ok(Some((ok, _))) => return Ok(if ok { Ran::Exited(0) } else { Ran::Exited(1) }),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(Ran::Stopped),
            _ = tokio::time::sleep_until(until) => return Ok(Ran::TimedOut),
            _ = tokio::time::sleep(WATCH) => {}
        }
    }
}

// ---- the loop ----

/// What one turn of the loop did, so a caller (and a test) can see it without reading the realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Turn {
    /// The queue had no job this computer could take.
    Nothing,
    /// An attempt ran and was reported. The job's identifier and how the attempt ended.
    Reported { job: String, ending: &'static str },
    /// The attempt stopped being this computer's before anything it made was sent. Nothing was
    /// sent and nothing was reported.
    LostIt { job: String, because: String },
    /// The realm could not be reached, or could not be written to.
    Trouble(String),
}

pub(crate) struct JobWorker {
    queue: Arc<dyn Queue>,
    sandbox: Arc<dyn Sandbox>,
    /// Where attempts' folders are made. One folder per attempt, removed when it ends.
    root: PathBuf,
}

impl JobWorker {
    pub(crate) fn new(queue: Arc<dyn Queue>, sandbox: Arc<dyn Sandbox>, root: PathBuf) -> JobWorker {
        JobWorker { queue, sandbox, root }
    }

    /// Asks for one job and, if there is one, runs it to its end and reports it.
    pub(crate) async fn turn(&self, cancel: &CancellationToken) -> Turn {
        let leased = match self.queue.lease(LEASE_SECONDS).await {
            Ok(Some(lease)) => lease,
            Ok(None) => return Turn::Nothing,
            Err(error) => return Turn::Trouble(error.describe()),
        };
        let job = leased.job_id.clone();
        let folder = self.root.join(&leased.attempt_id);
        let outcome = self.attempt(&leased, &folder, cancel).await;
        // The attempt's folder goes whichever way it ended, so nothing it left is ever seen again.
        let _ = std::fs::remove_dir_all(&folder);
        match outcome {
            Ok(ending) => Turn::Reported { job, ending },
            Err(Stopped::Lost(because)) => Turn::LostIt { job, because },
            Err(Stopped::Trouble(because)) => Turn::Trouble(because),
        }
    }

    /// One attempt, from its folder to its ending.
    async fn attempt(&self, leased: &JobLease, folder: &Path, cancel: &CancellationToken) -> Result<&'static str, Stopped> {
        let inputs = folder.join("in");
        let outputs = folder.join("out");
        for each in [&inputs, &outputs] {
            std::fs::create_dir_all(each).map_err(|error| Stopped::Trouble(format!("Cannot make this job's folder on this computer: {error}")))?;
        }
        // The inputs and the source, each under the name the job gave it. The realm checks every
        // one against its checksum as it writes it, so a damaged input is a refusal, not a build.
        let mut fetching = Vec::new();
        for input in &leased.inputs {
            fetching.push((input.name.clone(), input.artifact_id.clone()));
        }
        if let Some(resume) = &leased.resume_from {
            fetching.push((CHECKPOINT.to_owned(), resume.artifact_id.clone()));
        }
        for (name, artifact) in fetching {
            if let Err(error) = self.queue.fetch(&leased.attempt_id, leased.fence, &artifact, &inputs.join(&name)).await {
                return self.report(leased, Ending::Failed(Failure::InputUnavailable), &error.describe()).await;
            }
        }
        // From here the attempt may have done anything the job does, so the realm is told first.
        if let Err(error) = self.queue.start(&leased.attempt_id, leased.fence).await {
            return Err(lost_or_trouble(error));
        }
        let run = Run {
            job: leased.job_id.clone(),
            attempt: leased.attempt_id.clone(),
            entrypoint: leased.entrypoint.clone(),
            inputs,
            outputs: outputs.clone(),
            needs: leased.needs,
            dedup_key: leased.dedup_key.clone(),
            seconds: (leased.deadline - clock()).max(1),
        };
        let stop = cancel.child_token();
        let ran = tokio::select! {
            ran = self.sandbox.run(&run, &stop) => ran,
            asked = self.watch(leased, &stop, cancel) => {
                stop.cancel();
                match asked {
                    Watched::Stop => Ok(Ran::Stopped),
                    Watched::Lost(because) => return Err(Stopped::Lost(because)),
                }
            }
        };
        // Nothing an attempt made is sent before the realm says this computer still holds it.
        match self.queue.heartbeat(&leased.attempt_id, leased.fence, LEASE_SECONDS).await {
            Ok(_) => {}
            Err(error) => return Err(lost_or_trouble(error)),
        }
        // A checkpoint goes back whichever way the attempt ended, because the point of one is the
        // attempt that did not finish. A job that cannot resume is refused here by the library and
        // the refusal is simply not an error for this attempt.
        let left = outputs.join(CHECKPOINT);
        if left.is_file() {
            match self.queue.checkpoint(&leased.attempt_id, leased.fence, &left).await {
                Ok(_) | Err(JobError::NoCheckpoints) => {}
                Err(error) if fencing(&error) => return Err(Stopped::Lost(error.describe())),
                // A checkpoint that could not be sent costs the next attempt time, nothing more.
                Err(_) => {}
            }
        }
        match ran {
            Ok(Ran::Exited(0)) => {
                for name in &leased.outputs {
                    let path = outputs.join(name);
                    if !path.is_file() {
                        return self.report(leased, Ending::Failed(Failure::Exited), &format!("the job did not leave a '{name}' behind")).await;
                    }
                    if let Err(error) = self.queue.send(&leased.attempt_id, leased.fence, name, &path).await {
                        if fencing(&error) {
                            return Err(Stopped::Lost(error.describe()));
                        }
                        return self.report(leased, Ending::Failed(Failure::Exited), &error.describe()).await;
                    }
                }
                self.report(leased, Ending::Succeeded, "it finished").await
            }
            Ok(Ran::Exited(_)) => self.report(leased, Ending::Failed(Failure::Exited), "the program ended with an error").await,
            Ok(Ran::Crashed) => self.report(leased, Ending::Failed(Failure::Crashed), "the program or its sandbox ended abnormally").await,
            Ok(Ran::Stopped) => self.report(leased, Ending::Stopped, "it was asked to stop").await,
            // A timeout is not a failure and not a success. Nothing is reported: the attempt's
            // reservation runs out and the realm settles it as an outcome nobody knows.
            Ok(Ran::TimedOut) => Err(Stopped::Lost("it reached this job's time limit without ending".into())),
            Err(trouble) => self.report(leased, Ending::Failed(Failure::Crashed), &trouble).await,
        }
    }

    /// Reports an ending. A refusal that means this computer no longer holds the attempt is not a
    /// failure of the job: the realm has already moved it on.
    async fn report(&self, leased: &JobLease, ending: Ending, _because: &str) -> Result<&'static str, Stopped> {
        let word = match ending {
            Ending::Succeeded => "succeeded",
            Ending::Stopped => "stopped",
            Ending::Failed(_) => "failed",
        };
        match self.queue.complete(&leased.attempt_id, leased.fence, ending).await {
            Ok(()) => Ok(word),
            Err(error) if fencing(&error) => Err(Stopped::Lost(error.describe())),
            Err(error) => Err(Stopped::Trouble(error.describe())),
        }
    }

    /// Keeps the reservation alive while the sandbox runs, and answers the moment the realm says
    /// the job was asked to stop, or that this computer no longer holds the attempt.
    async fn watch(&self, leased: &JobLease, stop: &CancellationToken, shutting_down: &CancellationToken) -> Watched {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(HEARTBEAT) => {}
                _ = stop.cancelled() => return Watched::Stop,
                _ = shutting_down.cancelled() => return Watched::Stop,
            }
            match self.queue.heartbeat(&leased.attempt_id, leased.fence, LEASE_SECONDS).await {
                Ok(true) => return Watched::Stop,
                Ok(false) => {}
                Err(error) if fencing(&error) => return Watched::Lost(error.describe()),
                // A momentary refusal from the realm is not a reason to throw work away; the
                // reservation runs out on its own if this really cannot be reached again.
                Err(_) => {}
            }
        }
    }
}

enum Watched {
    Stop,
    Lost(String),
}

enum Stopped {
    /// This computer no longer holds the attempt. Nothing is sent and nothing is reported.
    Lost(String),
    Trouble(String),
}

/// Whether a refusal means the attempt is no longer this computer's.
fn fencing(error: &JobError) -> bool {
    matches!(error, JobError::StaleFence | JobError::WrongComputer | JobError::LeaseLost | JobError::NoSuchAttempt | JobError::Finished)
}

fn lost_or_trouble(error: JobError) -> Stopped {
    if fencing(&error) || matches!(error, JobError::StopRequested) {
        Stopped::Lost(error.describe())
    } else {
        Stopped::Trouble(error.describe())
    }
}

/// Runs turns until it is told to stop. Nothing starts this on its own: a setup that declares jobs
/// does, through `setups::jobs`.
pub(crate) async fn run(worker: Arc<JobWorker>, cancel: CancellationToken) {
    while !cancel.is_cancelled() {
        let wait = match worker.turn(&cancel).await {
            Turn::Nothing => IDLE,
            Turn::Trouble(_) => AFTER_TROUBLE,
            _ => Duration::from_millis(0),
        };
        if wait.is_zero() {
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// The workers one computer is running, by the setup resource that asked for them. Off until a
/// setup fills this, and empty again when the setup is removed.
#[derive(Default)]
pub(crate) struct Workers {
    running: Mutex<BTreeMap<String, CancellationToken>>,
}

impl Workers {
    /// Starts `count` workers for a resource, unless it has them already: what they are running is
    /// never stopped by asking again.
    pub(crate) fn start(&self, resource: &str, count: usize, make: impl Fn(usize) -> Arc<JobWorker>) {
        if self.running(resource) {
            return;
        }
        let cancel = CancellationToken::new();
        for which in 0..count {
            let worker = make(which);
            let token = cancel.clone();
            tauri::async_runtime::spawn(async move { run(worker, token).await });
        }
        self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(resource.to_owned(), cancel);
    }

    /// Asks a resource's workers to stop. What is running finishes or is stopped by its own
    /// computer; nothing is killed, and nothing already recorded changes.
    pub(crate) fn stop(&self, resource: &str) {
        if let Some(cancel) = self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(resource) {
            cancel.cancel();
        }
    }

    pub(crate) fn running(&self, resource: &str) -> bool {
        self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(resource)
    }
}

#[cfg(test)]
mod tests;
