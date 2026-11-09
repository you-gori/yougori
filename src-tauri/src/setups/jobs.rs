//! Handlers for the two resources a template needs to put finite work on a grid's computers: the
//! job itself, and the bounded, checksummed store its results are kept in.
//!
//! The decisions are all in `yougori_grid::core::jobs` (the queue, the fencing, the attempts, the
//! retries, the artifacts) and in `setups::job_worker` (running one attempt in a sandbox of its
//! own). This file is the setup engine's side: what a declared job must say before anything is
//! created, what applying it does, and what removing it deletes.
//!
//! Three refusals happen at review, before a single thing exists, because each of them would
//! otherwise be found halfway through:
//!
//! * a job whose `compute` names something this setup does not declare, or declares as something
//!   other than a pool of computers;
//! * a job on a research grid — research has its own scope, its own reviewed steps and its own
//!   trust boundary, and a generic job is not a way around any of them (plan invariant 11);
//! * a job that may be tried more than once, changes something outside, and says neither
//!   `idempotent: true` nor `reconcile: manual`.
//!
//! What removal does, said plainly because it is the part people are surprised by. Removing a job
//! asks the queue to stop admitting it and asks whatever is still running to stop; it deletes the
//! job's record and nothing else. **Artifacts are kept.** They are removed by the grid's own
//! retention — so many days, so many bytes — and never by a removal, so a build whose results
//! somebody is still reading is never emptied out from under them. Removing the store itself is
//! the same: the setup stops using it, and what it holds stays until retention takes it.
#![allow(dead_code)]
use super::handler::{Admission, HandlerError, HandlerFuture, HealthReport, Observation, Outcome, Planned, Recovery, ResourceHandler, StepContext};
use super::job_worker::{self, EngineSandbox, JobWorker, LocalQueue, Workers};
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Health, Observed, Resource};
use super::ordinary::BoxFuture;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use yougori_setup::resource::Kind;

/// How many workers one computer runs for a job queue. One attempt at a time per computer keeps a
/// job's resource request meaningful; more computers, not more loops, is how this grows.
const WORKERS_PER_COMPUTER: usize = 1;

/// What a job's one result is called. The format names the store a job's results go to, not the
/// names inside it, so the name is fixed here and said in the review rather than left to guess at:
/// a job that declared a store writes one file called this, and that is what comes back.
const RESULT: &str = "result";

/// What the job handlers need from the grid underneath. `EngineJobs` is the real one; tests put a
/// fake behind it, so every refusal and every receipt here is proved without a realm or a sandbox.
pub(crate) trait JobCalls: Send + Sync {
    /// Makes sure the setup's queue exists and is admitting work, and answers its name.
    fn open_queue<'a>(&'a self, setup: &'a str, queue: &'a str) -> BoxFuture<'a, Result<String, String>>;
    /// Sends one job into the queue. The same declared job sent again under the same key comes
    /// back as the job already admitted, so applying twice never queues it twice.
    /// `inputs` are artifacts this job reads, each under a name of its own, already resolved from
    /// the stages before it.
    fn submit<'a>(&'a self, setup: &'a str, queue: &'a str, label: &'a str, spec: &'a Value, inputs: Vec<(String, String)>) -> BoxFuture<'a, Result<String, String>>;
    /// How a job is doing: its state and how many attempts it has had, or nothing when it is gone.
    fn look<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Option<Value>, String>>;
    /// What a job that succeeded handed back: each output's name and the artifact holding it.
    /// Empty for a job that has not succeeded, because only a succeeded job has outputs.
    fn outputs<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Vec<(String, String)>, String>>;
    /// Asks a job to stop and stops admitting it. Never deletes what it produced.
    fn withdraw<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// Stops the queue admitting work, or lets it admit again.
    fn admit<'a>(&'a self, setup: &'a str, queue: &'a str, open: bool) -> BoxFuture<'a, Result<(), String>>;
    /// Stops the queue admitting work, leaving this computer's workers on so what runs can end.
    /// With `drain`, running attempts run to their end; without, each is asked to stop, as a
    /// cancel asks. Nothing is killed and nothing is deleted.
    fn pause<'a>(&'a self, setup: &'a str, queue: &'a str, drain: bool) -> BoxFuture<'a, Result<(), String>>;
    /// Starts or stops this computer's workers for a queue. Off until this is called.
    fn workers<'a>(&'a self, setup: &'a str, queue: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>>;
    /// What the store holds now, in bytes, and how long things are kept.
    fn store<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Value, String>>;
    /// Sets how much and how long the grid keeps this setup's artifacts.
    fn keep<'a>(&'a self, setup: &'a str, max_gb: f64, days: Option<u32>) -> BoxFuture<'a, Result<(), String>>;
    /// Which realm the setup's jobs and store are in, once it has been made. Asking never makes
    /// one: `None` until the setup's first job or store did.
    fn realm_id<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        let _ = setup;
        Box::pin(async { Ok(None) })
    }
    /// Every result this setup's jobs handed back, newest first: its ID, the job, its name, size
    /// and checksum, when it was kept, and whether retention has removed its bytes.
    fn artifacts<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Vec<Value>, String>> {
        let _ = setup;
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Writes one result to `to` on this computer, checked against its checksum on the way, and
    /// answers how many bytes it is. A copy that fails the check is not left behind.
    fn save_artifact<'a>(&'a self, setup: &'a str, artifact: &'a str, to: &'a std::path::Path) -> BoxFuture<'a, Result<u64, String>> {
        let _ = (setup, artifact, to);
        Box::pin(async { Err("This computer keeps no results for this setup.".to_owned()) })
    }
    /// What the last attempts of a job printed, oldest first, as each attempt's end.
    fn logs<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Vec<Value>, String>> {
        let _ = (setup, job);
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Settles a job nobody knows the outcome of, after a person looked: it did its work, it
    /// didn't, or it should run again. Answers the job's state after.
    fn settle<'a>(&'a self, setup: &'a str, job: &'a str, outcome: &'a str) -> BoxFuture<'a, Result<String, String>> {
        let _ = (setup, job, outcome);
        Box::pin(async { Err("This computer has no job of that setup to settle.".to_owned()) })
    }
    /// Notes that an event started `job` as a run of `resource`.
    fn remember_run<'a>(&'a self, setup: &'a str, resource: &'a str, job: &'a str, why: &'a str) -> BoxFuture<'a, ()> {
        let _ = (setup, resource, job, why);
        Box::pin(async {})
    }
    /// The runs events started for `resource`, oldest first: each run's job ID, why and when.
    fn runs<'a>(&'a self, setup: &'a str, resource: &'a str) -> BoxFuture<'a, Vec<Value>> {
        let _ = (setup, resource);
        Box::pin(async { Vec::new() })
    }
    /// Whether the setup's queue admits work and holds work for this computer's workers: a job
    /// waiting for a computer, or one an attempt held when Yougori stopped. Asking never makes a
    /// realm, and a setup that has none has no work.
    fn waiting<'a>(&'a self, setup: &'a str, queue: &'a str) -> BoxFuture<'a, Result<bool, String>> {
        let _ = (setup, queue);
        Box::pin(async { Ok(false) })
    }
}

#[derive(Clone)]
pub(crate) struct Jobs {
    calls: Arc<dyn JobCalls>,
    /// Each job's event address while it is open (`setups::events`), by `SETUP/RESOURCE`.
    urls: Arc<Mutex<BTreeMap<String, String>>>,
}

impl Jobs {
    pub(crate) fn new(calls: Arc<dyn JobCalls>) -> Jobs {
        Jobs { calls, urls: Arc::default() }
    }

    /// The event addresses this job handler reads its `event_url` outputs from.
    pub(crate) fn urls(&self) -> Arc<Mutex<BTreeMap<String, String>>> {
        self.urls.clone()
    }

    /// One more run of a job of the setup, as an event asks (`setups::events`): sent under the
    /// event's own key, so it is a run of its own beside the one the setup recorded, and kept in
    /// the job's list of runs. The setup's queue and this computer's workers are opened for it as
    /// applying the job does; what is running already is left to finish.
    pub(crate) async fn run_again(&self, setup: &str, resource: &str, spec: &Value, environment: Option<&Value>, event: &str, why: &str) -> Result<String, String> {
        if !JobHandler::reads(spec).is_empty() {
            return Err(format!("{resource} reads what an earlier stage handed back, so an event can't run it on its own. Put the trigger on the first stage."));
        }
        let queue = queue_of(setup);
        let filled = sent_from(spec, environment);
        self.calls.open_queue(setup, &queue).await?;
        let job = self.calls.submit(setup, &queue, &format!("yougori/{setup}/{resource}/event/{event}"), &filled, Vec::new()).await?;
        self.calls.workers(setup, &queue, true).await?;
        self.calls.remember_run(setup, resource, &job, why).await;
        Ok(job)
    }

    /// The runs events started for one of the setup's jobs, newest last.
    pub(crate) async fn runs(&self, setup: &str, resource: &str) -> Vec<Value> {
        self.calls.runs(setup, resource).await
    }

    pub(crate) fn handlers(&self) -> Vec<Arc<dyn ResourceHandler>> {
        vec![Arc::new(JobHandler(self.clone())), Arc::new(ArtifactStoreHandler(self.clone()))]
    }

    /// The results a setup's jobs handed back, for the person to read (`setup_artifacts`).
    pub(crate) async fn artifacts(&self, setup: &str) -> Result<Vec<Value>, String> {
        self.calls.artifacts(setup).await
    }

    /// Copies one result to a file the person chose (`setup_artifact_save`).
    pub(crate) async fn save_artifact(&self, setup: &str, artifact: &str, to: &std::path::Path) -> Result<u64, String> {
        self.calls.save_artifact(setup, artifact, to).await
    }

    /// What a job's last attempts printed (`setup_job_logs`).
    pub(crate) async fn logs(&self, setup: &str, job: &str) -> Result<Vec<Value>, String> {
        self.calls.logs(setup, job).await
    }

    /// Settles a job nobody knows the outcome of (`setup_job_settle`). One settled to run again
    /// waits in the queue again, so this computer's workers are started for it, as applying the
    /// job starts them, unless the setup's queue is closed (a stopped setup stays stopped).
    pub(crate) async fn settle(&self, setup: &str, job: &str, outcome: &str) -> Result<String, String> {
        let state = self.calls.settle(setup, job, outcome).await?;
        if outcome == "run_again" {
            // The job is settled either way; one whose workers could not start runs once the
            // setup is started again.
            if let Err(error) = self.resume(setup).await {
                eprintln!("The workers of setup {setup} did not start for a job settled to run again: {}", crate::lifecycle::safe_diagnostic(&error));
            }
        }
        Ok(state)
    }

    /// Starts this computer's workers for a setup whose queue admits work and has work waiting
    /// (`JobCalls::waiting`). Workers live in memory only, so this is what brings them back after
    /// Yougori starts again; workers already running are left as they are. Whether they started.
    pub(crate) async fn resume(&self, setup: &str) -> Result<bool, String> {
        let queue = queue_of(setup);
        if !self.calls.waiting(setup, &queue).await? {
            return Ok(false);
        }
        self.calls.workers(setup, &queue, true).await?;
        Ok(true)
    }

    /// `resume` for each of `setups`, at the engine's start: one that can't be read is said in
    /// the log and leaves the others alone.
    pub(crate) async fn resume_all(&self, setups: Vec<String>) {
        for setup in setups {
            if let Err(error) = self.resume(&setup).await {
                eprintln!("The jobs of setup {setup} were not picked up again: {}", crate::lifecycle::safe_diagnostic(&error));
            }
        }
    }
}

fn invalid(message: &str) -> HandlerError {
    HandlerError::new(Outcome::NotStarted, "invalid_spec", message)
}

fn refused(message: &str) -> HandlerError {
    HandlerError::new(Outcome::Unsupported, "refused", message)
}

fn failed(error: String) -> HandlerError {
    HandlerError::new(Outcome::Failed, "job_failed", error)
}

fn receipt(runtime_id: Option<String>, observed: Observed, retained_data: bool) -> Receipt {
    Receipt { runtime_id, observed, retained_data, cost: Cost::Free, at: now(), adopted: false }
}

/// The queue a setup's jobs go into. One per setup, named after it, so two setups on one computer
/// never share a queue and removing one never empties the other.
fn queue_of(setup: &str) -> String {
    let name: String = setup.chars().filter(|letter| letter.is_ascii_alphanumeric() || *letter == '-' || *letter == '_').take(48).collect();
    if name.is_empty() {
        "jobs".to_owned()
    } else {
        name
    }
}

/// Whether a declared resource is a pool of computers this setup makes or joins, and whether that
/// pool's grid is a research grid.
fn pool<'a>(reference: &Value, others: &'a BTreeMap<String, (Kind, Value)>) -> Option<&'a (Kind, Value)> {
    let id = reference["resource"].as_str()?;
    others.get(id)
}

fn is_research(spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> bool {
    if spec["profile"].as_str() == Some(RESEARCH) {
        return true;
    }
    spec["grid"]["resource"]
        .as_str()
        .and_then(|id| others.get(id))
        .is_some_and(|(kind, grid)| *kind == Kind::Grid && grid["profile"].as_str() == Some(RESEARCH))
}

/// The research grid's profile, as templates write it (`setup::resource`).
const RESEARCH: &str = "swarm_mining_grid";

/// The characters that mean something to a shell. A job's command is never given to one, so a
/// line that uses them would not do what it says, and is refused rather than run differently.
const SHELL_MARKS: &[char] = &['|', ';', '&', '<', '>', '`', '$', '\n', '\r'];

/// A job's program and its arguments. A command of one part that has spaces in it is one line,
/// split into words as a shell splits them (quotes group words) but never handed to a shell; a
/// line that needs one (a pipe, a variable, a redirection) is refused with what to do instead.
pub(crate) fn argv(spec: &Value) -> Result<Vec<String>, String> {
    let parts: Vec<String> = spec["command"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(Value::as_str).map(str::to_owned).collect();
    let [line] = parts.as_slice() else { return Ok(parts) };
    if !line.contains(char::is_whitespace) && !line.contains(['"', '\'']) && !line.contains(SHELL_MARKS) {
        return Ok(parts);
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for letter in line.chars() {
        match (quote, letter) {
            (Some(open), _) if letter == open => quote = None,
            (Some(_), _) => word.push(letter),
            (None, '"' | '\'') => {
                quote = Some(letter);
                started = true;
            }
            (None, _) if letter.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (None, _) if SHELL_MARKS.contains(&letter) => {
                return Err(format!("A job's command runs a program directly, never through a shell, so {letter} means nothing to it. Put the steps in a script in the job's source and run that script."));
            }
            (None, _) => {
                word.push(letter);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err("A job's command has a quote that is never closed.".into());
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

/// The sandbox of this setup a job's attempts are made from (`compute: {resource: ENV}`), as it is
/// recorded or about to be made.
fn environment_of<'a>(context: &'a StepContext) -> Option<&'a Value> {
    let id = context.spec["compute"]["resource"].as_str()?;
    context.peers.get(id).or_else(|| context.planned.get(id)).filter(|peer| peer.kind == Kind::Environment).map(|peer| &peer.spec)
}

/// The job as it is sent: what its sandbox needs, filled in from the sandbox it names when it
/// says nothing itself. Its image, unless it names one, is that sandbox's; and so is its room.
fn sent(context: &StepContext) -> Value {
    sent_from(&context.spec, environment_of(context))
}

/// `sent`, from the job's spec and the sandbox it names, as they are recorded.
fn sent_from(spec: &Value, environment: Option<&Value>) -> Value {
    let mut spec = spec.clone();
    if let Some(environment) = environment {
        if spec["image"].as_str().is_none_or(str::is_empty) {
            if let Some(image) = environment["image"].as_str().filter(|image| !image.is_empty()) {
                spec["image"] = json!(image);
            }
        }
        if spec["resources"]["cpu"].is_null() {
            if let Some(cpu) = environment["cpu"].as_f64() {
                spec["resources"]["cpu"] = json!(cpu);
            }
        }
        if spec["resources"]["memory_gb"].is_null() {
            if let Some(memory) = environment["memory"].as_f64() {
                spec["resources"]["memory_gb"] = json!(memory);
            }
        }
    }
    spec
}

// ----- the job -----

pub(crate) struct JobHandler(Jobs);

/// Where a job has got to, as the setup registry records it. Three answers, because they mean
/// three different things to whoever applies the setup again: it is still going, it ended without
/// succeeding and may be sent again, or nobody knows and a person has to look first.
fn observed_from(state: &str) -> Observed {
    match state {
        "succeeded" => Observed::Present,
        "failed" | "cancelled" | "stopped" => Observed::Stopped,
        "outcomeUnknown" => Observed::Unknown,
        _ => Observed::Running,
    }
}

/// How often a stage asks whether the stage before it has finished.
const STAGE_POLL: std::time::Duration = std::time::Duration::from_secs(5);
/// How much longer than the stage before it could possibly take a stage waits before giving up.
const STAGE_SLACK: u64 = 3600;

impl JobHandler {
    /// The stages this one reads. Each is read under the name of the stage that produced it, so a
    /// job's command knows where to look without the template having to name it twice, and no
    /// name a person writes ever becomes a place on a computer.
    fn reads(spec: &Value) -> Vec<String> {
        spec["inputs"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|input| input["resource"].as_str().map(str::to_owned))
            .collect()
    }

    /// Everything this stage reads, resolved: it waits for each stage before it to succeed and
    /// takes the artifact that stage handed back.
    ///
    /// A stage that failed, was cancelled or was stopped fails this one, saying which: there is
    /// nothing to read, and queueing it anyway would only fail later and further from the cause. A
    /// stage whose outcome nobody knows stops this one without starting it, so a person settles
    /// that one first. Waiting gives way to the step being cancelled, and gives up once the stage
    /// before it has had longer than it could possibly take.
    async fn waited_for(&self, context: &StepContext) -> Result<Vec<(String, String)>, HandlerError> {
        let reads = Self::reads(&context.spec);
        if reads.is_empty() {
            return Ok(Vec::new());
        }
        let mut resolved = Vec::new();
        for stage in reads {
            let peer = context.peers.get(&stage).or_else(|| context.planned.get(&stage));
            let Some(job) = peer.and_then(|peer| peer.runtime_id.clone()) else {
                return Err(HandlerError::new(Outcome::NotStarted, "stage_missing", format!("The stage '{stage}' has not been sent yet, so there is nothing for this one to read.")));
            };
            let until = tokio::time::Instant::now() + std::time::Duration::from_secs(Self::longest(context, &stage));
            loop {
                let found = self.0.calls.look(&context.setup, &job).await.map_err(|error| HandlerError::new(Outcome::NotStarted, "grid_unavailable", error))?;
                let Some(found) = found else {
                    return Err(HandlerError::new(Outcome::Failed, "stage_missing", format!("The stage '{stage}' is no longer in the grid, so there is nothing for this one to read.")));
                };
                match found["state"].as_str().unwrap_or("queued") {
                    "succeeded" => break,
                    "failed" => return Err(HandlerError::new(Outcome::Failed, "stage_failed", format!("The stage '{stage}' failed, so this one has nothing to read. Fix that stage and apply the setup again; the stages that already succeeded are not run a second time."))),
                    "cancelled" | "stopped" => {
                        return Err(HandlerError::new(Outcome::Failed, "stage_stopped", format!("The stage '{stage}' was stopped, so this one has nothing to read.")))
                    }
                    "outcomeUnknown" => {
                        return Err(HandlerError::new(
                            Outcome::NotStarted,
                            "awaiting_settlement",
                            format!("Nobody knows yet whether the stage '{stage}' did its work, so this one was not started. Check what it did and settle it on the Queues view, then apply this setup again."),
                        ))
                    }
                    _ => {}
                }
                tokio::select! {
                    _ = context.cancel.cancelled() => return Err(HandlerError::new(Outcome::NotStarted, "cancelled", format!("Waiting for the stage '{stage}' was cancelled. Nothing was queued."))),
                    _ = tokio::time::sleep_until(until) => {
                        return Err(HandlerError::new(
                            Outcome::NotStarted,
                            "stage_slow",
                            format!("The stage '{stage}' has taken longer than it was allowed, so this one was not started. Look at it on the Queues view, then apply this setup again."),
                        ))
                    }
                    _ = tokio::time::sleep(STAGE_POLL) => {}
                }
            }
            let outputs = self.0.calls.outputs(&context.setup, &job).await.map_err(|error| HandlerError::new(Outcome::NotStarted, "grid_unavailable", error))?;
            let Some((_, artifact)) = outputs.into_iter().find(|(output, _)| output == RESULT) else {
                return Err(HandlerError::new(Outcome::Failed, "stage_empty", format!("The stage '{stage}' finished without handing anything back, so there is nothing for this one to read.")));
            };
            resolved.push((stage, artifact));
        }
        Ok(resolved)
    }

    /// The longest the stage before this one could take: its own time limit for every attempt it
    /// is allowed, and an hour for the waiting it does between them.
    fn longest(context: &StepContext, stage: &str) -> u64 {
        let spec = context.peers.get(stage).or_else(|| context.planned.get(stage)).map(|peer| peer.spec.clone()).unwrap_or(Value::Null);
        let seconds = spec["timeout_seconds"].as_u64().unwrap_or(3600);
        let attempts = spec["retry"]["attempts"].as_u64().unwrap_or(1).max(1);
        seconds.saturating_mul(attempts).saturating_add(STAGE_SLACK)
    }

    /// How many attempts a declared job may have. One unless it says otherwise.
    fn attempts(spec: &Value) -> u64 {
        spec["retry"]["attempts"].as_u64().unwrap_or(1)
    }

    /// Whether a job that may run more than once has said what repeating it does.
    fn may_repeat_safely(spec: &Value) -> bool {
        spec["idempotent"].as_bool() == Some(true) || spec["reconcile"].as_str() == Some("manual")
    }
}

impl ResourceHandler for JobHandler {
    fn kind(&self) -> Kind {
        Kind::Job
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if !spec["compute"].is_null() && spec["compute"]["resource"].as_str().is_none() {
            return Err(invalid("A job names where it runs with compute: {resource: ID}: one of this setup's sandboxes, or a pool of computers."));
        }
        let command = argv(spec).map_err(|why| invalid(&why))?;
        let Some(program) = command.first().map(String::as_str) else {
            return Err(invalid("A job's command is the program and its arguments, as a list."));
        };
        // The library refuses a shell as the program too; saying it here means a person hears it
        // while they are still editing the template rather than when a computer takes the job.
        if ["sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"].contains(&program.rsplit(['/', '\\']).next().unwrap_or(program)) {
            return Err(invalid("A job's command is a program and its arguments, never a line for a shell. Put the steps in a script in the job's source and run that."));
        }
        if !spec["secrets"].as_object().map(serde_json::Map::is_empty).unwrap_or(true) {
            return Err(refused("A job can't be given a secret yet. It runs with nothing of this computer in it."));
        }
        if spec["schedule"].as_str().is_some_and(|when| !when.is_empty()) {
            return Err(refused("Running a job on a schedule isn't available yet. Leave the schedule out and start the setup when you want it to run."));
        }
        if Self::attempts(spec) > 1 && !Self::may_repeat_safely(spec) {
            return Err(invalid(
                "A job that may be tried again has to say what repeating it does: idempotent: true when running it twice is harmless, or reconcile: manual so a person checks an unknown outcome first.",
            ));
        }
        Ok(())
    }

    fn review(&self, stage_id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if spec["compute"].is_null() {
            // On this computer, from its own image.
            if spec["image"].as_str().is_none_or(str::is_empty) {
                return Err(refused("A job that names no sandbox or pool runs from its own image. Say which with image:."));
            }
        } else {
            let Some((kind, compute)) = pool(&spec["compute"], others) else {
                return Err(refused("A job runs on this computer from one of this setup's sandboxes or its own image, or on a pool of computers this setup makes or joins. Name where with compute: {resource: ID}."));
            };
            if !matches!(kind, Kind::ComputePool | Kind::Environment) {
                return Err(refused("A job's compute: {resource: ID} names a sandbox of this setup or a pool of computers, not another kind of resource."));
            }
            if *kind == Kind::ComputePool && is_research(compute, others) {
                return Err(refused(
                    "A research grid runs no generic jobs. Research work goes through its own scope, where each step is reviewed before it runs. Put this job on a Neo Grid's computers instead.",
                ));
            }
        }
        if let Some(store) = spec["outputs"]["resource"].as_str() {
            match others.get(store) {
                Some((Kind::ArtifactStore, _)) => {}
                _ => return Err(refused("A job's outputs go to an artifact store this setup declares. Name one with outputs: {resource: ID}.")),
            }
        }
        for input in spec["inputs"].as_array().map(Vec::as_slice).unwrap_or_default() {
            let Some(id) = input["resource"].as_str() else {
                return Err(refused("A job's input names another of this setup's resources with {resource: ID}."));
            };
            if id == stage_id {
                return Err(refused("A job cannot read its own result. A stage reads the stage before it."));
            }
            // A stage reads what the stage before it produced. That is the only kind of input a
            // job can have: nothing of this computer, and nothing of another setup.
            match others.get(id) {
                Some((Kind::Job, _)) => {}
                Some(_) => return Err(refused("A job's input is the result of another job this setup declares. Name that job with {resource: ID}.")),
                None => return Err(refused("A job's input names a resource this setup does not declare.")),
            }
        }
        Ok(())
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let mut notes = Vec::new();
        match action {
            Action::Create | Action::Update => {
                notes.push(format!("{resource} runs once, to its end, when a computer with room takes it: this computer for a job made from one of this setup's sandboxes, the grid's computers for one sent to a pool."));
                notes.push("Each attempt runs in a sandbox of its own, with the job's source and inputs read-only, no network and nothing else of this computer in it.".into());
                if let Some(folder) = spec["source_folder"].as_str() {
                    notes.push(format!("It reads {folder}, the folder you chose, at /yougori/job/source. It can't change it."));
                }
                match spec["trigger"]["webhook"]["access"].as_str() {
                    Some("quick") => notes.push(format!("{resource} runs again whenever its event address is called. Anyone with that link can call it: it is a private output, so only you can read it.")),
                    Some("lan") => notes.push(format!("{resource} runs again whenever a computer of this network calls its event address. The address is a private output.")),
                    Some(_) => notes.push(format!("{resource} runs again whenever a program on this computer calls its event address. The address is a private output.")),
                    None => {}
                }
                if spec["trigger"]["source_changes"].as_bool() == Some(true) {
                    notes.push(format!("{resource} runs again when a file is added, changed or removed in the folder it reads, looked at every thirty seconds."));
                }
                if spec["trigger"].is_object() {
                    notes.push("Each event is one more run: never two at once, never sooner than ten seconds after the last, and never while the setup is stopped.".into());
                }
                if Self::attempts(spec) > 1 {
                    notes.push(format!("It may be tried up to {} times. Running it more than once is {}.", Self::attempts(spec), if spec["idempotent"].as_bool() == Some(true) { "harmless, as the template says" } else { "checked by a person first" }));
                }
                notes.push("Jobs run at least once, never exactly once: if a computer stops answering mid-run, the work may already have happened.".into());
            }
            Action::Remove => {
                notes.push(format!("{resource} stops being queued, and anything still running is asked to stop. Nothing is killed."));
                notes.push("What it already produced is kept, and is removed only by the grid's own retention.".into());
            }
            _ => {}
        }
        notes
    }

    /// A job is a thing that was sent, not a thing that is edited: a changed description is a new
    /// job, so the step is a create either way and the old one is withdrawn by its removal.
    ///
    /// This is also what lets a pipeline carry on after a stage failed. A stage that succeeded is
    /// `Unchanged`, so no step runs for it and its work is never done a second time; the stage
    /// that ended without succeeding is sent again, as a new job, and the stages after it follow.
    /// A stage whose outcome nobody knows is the one case where this refuses to decide: running it
    /// again might repeat something that already happened outside the grid, so a person settles it
    /// first and the refusal says so.
    fn plan(&self, current: Option<&Resource>, _spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        let Some(resource) = current else { return Ok(Planned::Step(Action::Create)) };
        if resource.runtime_id.is_none() || resource.spec_digest != spec_digest {
            return Ok(Planned::Step(Action::Create));
        }
        match resource.observed {
            // It failed, was cancelled or was stopped. Send it again.
            Observed::Stopped => Ok(Planned::Step(Action::Create)),
            Observed::Unknown => Err(HandlerError::new(
                Outcome::NotStarted,
                "awaiting_settlement",
                "Nobody knows yet whether this job did its work: the computer running it stopped answering. Check what it did and settle it on the Queues view, then apply this setup again.",
            )),
            _ => Ok(Planned::Unchanged),
        }
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            let Some(id) = context.runtime_id.clone() else { return Ok(Observation::Absent) };
            match self.0.calls.look(&context.setup, &id).await {
                Ok(Some(job)) => Ok(Observation::Present {
                    runtime_id: id,
                    observed: observed_from(job["state"].as_str().unwrap_or("queued")),
                    label: job["label"].as_str().map(str::to_owned),
                    retained_data: true,
                    cost: Cost::Free,
                }),
                Ok(None) => Ok(Observation::Absent),
                Err(error) => Ok(Observation::Unknown { reason: error }),
            }
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let queue = queue_of(&context.setup);
            match context.action {
                Action::Stop => {
                    // Stopping a setup stops this computer taking its work and stops the queue
                    // admitting more. What is already running finishes; nothing is killed.
                    self.0.calls.admit(&context.setup, &queue, false).await.map_err(failed)?;
                    self.0.calls.workers(&context.setup, &queue, false).await.map_err(failed)?;
                    // The job itself is untouched: `Stopped` here means "this job ended without
                    // succeeding", and stopping a setup does neither of those things.
                    return Ok(receipt(context.runtime_id.clone(), Observed::Present, true));
                }
                Action::Start => {
                    self.0.calls.admit(&context.setup, &queue, true).await.map_err(failed)?;
                    self.0.calls.workers(&context.setup, &queue, true).await.map_err(failed)?;
                    return Ok(receipt(context.runtime_id.clone(), Observed::Running, true));
                }
                _ => {}
            }
            // A job that reads a folder of this computer reads the one the person chose, and only
            // once there is one to read.
            if context.spec["source"]["binding"].is_string() {
                match context.spec["source_folder"].as_str() {
                    None => return Err(HandlerError::new(Outcome::NeedsInput, "binding_missing", "Choose the folder this job reads before it is sent.")),
                    Some(folder) if !std::path::Path::new(folder).is_dir() => {
                        return Err(HandlerError::new(Outcome::NotStarted, "folder_missing", format!("{folder}, the folder this job reads, isn't there. Choose it again or put it back, then apply the setup again.")))
                    }
                    Some(_) => {}
                }
            }
            // Everything this stage reads comes from a stage before it, which has to have
            // succeeded first. Nothing is queued until it has.
            let inputs = self.waited_for(context).await?;
            self.0.calls.open_queue(&context.setup, &queue).await.map_err(failed)?;
            // The step's own key is what the job is sent under, so applying the same step twice
            // finds the job it already sent instead of queueing a second one.
            let spec = sent(context);
            let id = self.0.calls.submit(&context.setup, &queue, &context.label, &spec, inputs).await.map_err(failed)?;
            self.0.calls.workers(&context.setup, &queue, true).await.map_err(failed)?;
            Ok(receipt(Some(id), Observed::Running, true))
        })
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        self.apply(context)
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let queue = queue_of(&context.setup);
            // Only what this setup recorded. A job it never sent is somebody else's.
            if let Some(id) = context.runtime_id.as_deref() {
                self.0.calls.withdraw(&context.setup, id).await.map_err(failed)?;
            }
            self.0.calls.workers(&context.setup, &queue, false).await.map_err(failed)?;
            // Artifacts are kept: retention removes them, a removal never does.
            Ok(receipt(None, Observed::Missing, true))
        })
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            let Some(id) = context.runtime_id.clone() else {
                return Ok(HealthReport { health: Health::Unknown, detail: "This job has not been sent yet.".into() });
            };
            match self.0.calls.look(&context.setup, &id).await {
                Ok(Some(job)) => {
                    let state = job["state"].as_str().unwrap_or("queued");
                    let (health, detail) = match state {
                        "succeeded" => (Health::Ready, "It finished and handed back everything it declared.".to_owned()),
                        "running" => (Health::Ready, "A computer is running it now.".to_owned()),
                        "queued" => (Health::WaitingForComputer, job["waitingBecause"].as_str().unwrap_or("It is waiting for a computer with room.").to_owned()),
                        "cancelRequested" => (Health::Unknown, "It was asked to stop, and its computer has not yet said that it has.".to_owned()),
                        "outcomeUnknown" => (
                            Health::Failed,
                            "Nobody knows yet whether it did its work: the computer running it stopped answering. Check what it did, then settle it.".to_owned(),
                        ),
                        _ => (Health::Failed, format!("It ended as '{state}'.")),
                    };
                    Ok(HealthReport { health, detail })
                }
                Ok(None) => Ok(HealthReport { health: Health::Unknown, detail: "This job is no longer in the grid.".into() }),
                Err(error) => Ok(HealthReport { health: Health::Unknown, detail: error }),
            }
        })
    }

    fn takes_work(&self) -> bool {
        true
    }

    /// A job waiting in its queue reads as running, but nothing runs it unless this computer's
    /// workers are on, and they live in memory only: after Yougori starts again none are. So a
    /// start always reaches a job, and its `Start` opens the queue and the workers.
    fn renews_when_running(&self, spec: &Value) -> bool {
        let _ = spec;
        true
    }

    /// Pauses or resumes new work for the setup's job queue. Every job of the setup shares it, so
    /// the first job asked settles it for all of them. This computer keeps running what it has, so
    /// that can end; a job that was never sent has no work to pause.
    fn admission<'a>(&'a self, context: &'a StepContext, change: Admission) -> HandlerFuture<'a, String> {
        Box::pin(async move {
            if context.runtime_id.is_none() {
                return Ok(format!("{} was never sent, so it has no work to pause or resume.", context.resource));
            }
            let queue = queue_of(&context.setup);
            Ok(match change {
                Admission::Pause { drain } => {
                    self.0.calls.pause(&context.setup, &queue, drain).await.map_err(failed)?;
                    if drain {
                        "New work for this setup's jobs is paused. What is running finishes; nothing new starts until you resume new work.".to_owned()
                    } else {
                        "New work for this setup's jobs is paused, and each running job was asked to stop, as a cancel asks. Nothing was killed or deleted.".to_owned()
                    }
                }
                Admission::Resume => {
                    self.0.calls.admit(&context.setup, &queue, true).await.map_err(failed)?;
                    // What waited runs only with this computer's workers on, and after Yougori
                    // started again with new work paused, none were started for it.
                    self.0.calls.workers(&context.setup, &queue, true).await.map_err(failed)?;
                    "This setup's jobs take new work again; the ones that waited start as computers have room.".to_owned()
                }
            })
        })
    }

    /// The job's ID, where it has got to, and the realm it is queued in. Nothing for a job not sent
    /// yet. Asking never makes a realm.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let mut outputs = BTreeMap::new();
            let Some(id) = context.runtime_id.clone() else { return Ok(outputs) };
            if let Some(job) = self.0.calls.look(&context.setup, &id).await.map_err(failed)? {
                if let Some(state) = job["state"].as_str() {
                    outputs.insert("status".to_owned(), state.to_owned());
                }
            }
            if let Ok(Some(realm)) = self.0.calls.realm_id(&context.setup).await {
                outputs.insert("realm_id".to_owned(), realm);
            }
            if let Some(url) = self.0.urls.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&format!("{}/{}", context.setup, context.resource)) {
                outputs.insert("event_url".to_owned(), url.clone());
            }
            outputs.insert("id".to_owned(), id);
            Ok(outputs)
        })
    }

    /// A job whose sending may or may not have happened is settled by looking for the one this
    /// step's key would have made, never by sending it again.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move { Ok(super::handler::recovery_from(context, self.observe(context).await?)) })
    }
}

// ----- the artifact store -----

pub(crate) struct ArtifactStoreHandler(Jobs);

impl ResourceHandler for ArtifactStoreHandler {
    fn kind(&self) -> Kind {
        Kind::ArtifactStore
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if spec["drive"].get("binding").is_some() {
            return Err(refused("Keeping a setup's results on another drive isn't available yet. Leave the drive out and they are kept beside the grid."));
        }
        if spec["access"].as_str() == Some("grid") {
            return Err(refused("Sharing one store between setups isn't available yet. Each setup keeps its own results."));
        }
        // What the person answers is what sweeps, so an answer the grid cannot hold to is refused
        // here with the bound named, rather than applied as something else.
        use yougori_grid::core::limits::{LEAST_JOB_ARTIFACT_BYTES, LONGEST_JOB_ARTIFACT_KEEP, MOST_JOB_ARTIFACT_BYTES, SHORTEST_JOB_ARTIFACT_KEEP};
        let wanted = retention_of(spec["max_gb"].as_f64().unwrap_or(10.0), spec["retention_days"].as_u64().map(|days| days as u32));
        if wanted.keep_bytes < LEAST_JOB_ARTIFACT_BYTES {
            return Err(invalid(&format!("A store keeps at least {} GB, which is room for one result of the largest size.", LEAST_JOB_ARTIFACT_BYTES >> 30)));
        }
        if wanted.keep_bytes > MOST_JOB_ARTIFACT_BYTES {
            return Err(invalid(&format!("A store keeps at most {} GB on this computer.", MOST_JOB_ARTIFACT_BYTES >> 30)));
        }
        if wanted.keep_seconds < SHORTEST_JOB_ARTIFACT_KEEP {
            return Err(invalid("Results are kept for at least one day, so nobody loses them before they could fetch them."));
        }
        if wanted.keep_seconds > LONGEST_JOB_ARTIFACT_KEEP {
            return Err(invalid(&format!("Results are kept for at most {} days.", LONGEST_JOB_ARTIFACT_KEEP / 86_400)));
        }
        Ok(())
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let size = spec["max_gb"].as_f64().unwrap_or(10.0);
        match action {
            Action::Create | Action::Update => vec![
                format!("{resource} keeps what this setup's jobs produce, up to {size} GB, each result checked against its checksum. That is what the grid sweeps to, not a larger default."),
                match spec["retention_days"].as_u64() {
                    Some(days) => format!("Results older than {days} days are removed, oldest first, and so are the oldest results once the store is full."),
                    None => "Once the store is full the oldest results are removed first. Nothing a job still in play needs is removed.".into(),
                },
            ],
            Action::Remove => vec![format!("{resource} stops being this setup's store. What it holds is kept and is removed only by the grid's own retention.")],
            _ => Vec::new(),
        }
    }

    /// A store does not run, so stopping and starting a setup leaves it alone.
    fn stoppable(&self) -> bool {
        false
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            match self.0.calls.store(&context.setup).await {
                Ok(store) if store["present"].as_bool() == Some(true) => Ok(Observation::Present {
                    runtime_id: context.runtime_id.clone().unwrap_or_else(|| format!("{}/artifacts", context.setup)),
                    observed: Observed::Present,
                    label: store["label"].as_str().map(str::to_owned),
                    retained_data: true,
                    cost: Cost::Free,
                }),
                Ok(_) => Ok(Observation::Absent),
                Err(error) => Ok(Observation::Unknown { reason: error }),
            }
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let max_gb = context.spec["max_gb"].as_f64().unwrap_or(10.0);
            let days = context.spec["retention_days"].as_u64().map(|days| days as u32);
            self.0.calls.keep(&context.setup, max_gb, days).await.map_err(failed)?;
            Ok(receipt(Some(format!("{}/artifacts", context.setup)), Observed::Present, true))
        })
    }

    /// The store's ID and the realm it keeps this setup's results in. Nothing for a store not made
    /// yet. Asking never makes a realm.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let mut outputs = BTreeMap::new();
            let Some(id) = context.runtime_id.clone() else { return Ok(outputs) };
            if let Ok(Some(realm)) = self.0.calls.realm_id(&context.setup).await {
                outputs.insert("realm_id".to_owned(), realm);
            }
            outputs.insert("id".to_owned(), id);
            Ok(outputs)
        })
    }

    /// The setup stops using the store. Nothing it holds is deleted: retention does that, on the
    /// schedule the store was given, and a removal never surprises anybody by emptying it.
    fn remove<'a>(&'a self, _context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move { Ok(receipt(None, Observed::Missing, true)) })
    }
}

// ----- the grid underneath -----

/// The real implementation: one Grid Core realm per setup, beside the setup registry, with this
/// computer offering itself to it and running the worker loops.
///
/// A setup's realm is its own. Two setups never share a queue, a shelf or a retention policy, and
/// removing one touches nothing of the other.
pub(crate) struct EngineJobs {
    app: crate::AppHandle,
    folder: PathBuf,
    open: Mutex<BTreeMap<String, Open>>,
    workers: Workers,
}

/// What a declared store becomes: how long and how much the grid keeps of this setup's results.
///
/// The person's answer is what sweeps. A store that says ten gigabytes keeps ten, not the grid's
/// own twenty, and a store that says seven days keeps seven. Only the library's own bounds are
/// applied here, and a declared number outside them is refused at validation with the bound named,
/// rather than quietly widened to fit.
pub(crate) fn retention_of(max_gb: f64, days: Option<u32>) -> yougori_grid::core::jobs::Retention {
    use yougori_grid::core::limits::KEEP_JOB_ARTIFACTS_FOR;
    yougori_grid::core::jobs::Retention {
        keep_seconds: days.map(|days| i64::from(days) * 86_400).unwrap_or(KEEP_JOB_ARTIFACTS_FOR),
        keep_bytes: (max_gb.max(0.0) * (1_u64 << 30) as f64) as u64,
    }
}

/// Unix seconds, which is the clock every door of the jobs library counts in. Not the setup
/// registry's own `now`, which is a readable timestamp for a receipt.
fn at() -> i64 {
    yougori_grid::now()
}

/// Where a setup's realm key is kept in this computer's own credential vault. One account per
/// setup, under the prefix Grid Core's own entries use, so nothing else reads or writes it.
fn key_account(setup: &str) -> String {
    format!("grid-core.setup-jobs.{setup}")
}

impl EngineJobs {
    pub(crate) fn new(app: crate::AppHandle, folder: PathBuf) -> EngineJobs {
        EngineJobs { app, folder, open: Mutex::new(BTreeMap::new()), workers: Workers::default() }
    }

    /// Where this computer keeps what it knows of a setup's jobs beside the realm: the folders
    /// they read and what each attempt printed.
    fn meta(&self, setup: &str) -> PathBuf {
        self.folder.join(format!("{setup}-meta"))
    }

    /// Whether the setup's realm was ever made. Reading never makes one.
    fn made(&self, setup: &str) -> bool {
        self.open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(setup) || self.folder.join(format!("{setup}.db")).exists()
    }

    /// The setup's realm, opened once and held. Made the first time, with a key minted here and
    /// kept in this computer's credential vault; opened from that key every time after.
    ///
    /// Who the setup acts as, and which computer runs its attempts, are written down beside the
    /// realm when it is made, so a later build reads them rather than guessing at them.
    fn realm(&self, setup: &str) -> Result<Open, String> {
        use yougori_grid::core::{realm::RealmKind, Core};
        if let Some(open) = self.open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(setup) {
            return Ok(open.clone());
        }
        let account = key_account(setup);
        let path = self.folder.join(format!("{setup}.db"));
        let who = self.folder.join(format!("{setup}.who.json"));
        std::fs::create_dir_all(&self.folder).map_err(|error| format!("Yougori can't make the folder for this setup's jobs: {error}"))?;
        let held = crate::projects::secrets::resolve_bytes(&account)?;
        let open = match held.and_then(|bytes| String::from_utf8(bytes).ok()).filter(|key| key.len() == 64) {
            Some(key) => {
                let core = Core::open(&path, &key)?;
                let noted: Value = serde_json::from_slice(&std::fs::read(&who).map_err(|error| format!("Yougori can't read who this setup's jobs run as: {error}"))?)
                    .map_err(|error| format!("Yougori can't read who this setup's jobs run as: {error}"))?;
                Open {
                    core: Arc::new(Mutex::new(core)),
                    person: noted["person"].as_str().unwrap_or_default().to_owned(),
                    device: noted["device"].as_str().unwrap_or_default().to_owned(),
                }
            }
            None if path.exists() => {
                return Err("This setup's jobs were set up with a key this computer no longer has, so its queue can't be opened. Remove the setup and apply it again; what it already produced stays where it is.".into())
            }
            None => {
                let key = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                crate::projects::secrets::store_bytes(&account, key.as_bytes())?;
                // Models is the capability a job's attempts hold their room under. A realm that
                // can do research is never made here, so a job can never reach research scope.
                let mut core = Core::create(&path, setup, RealmKind::Primary, &[yougori_grid::core::realm::Capability::Models], &key, at())?;
                let (person, device) = this_computer(&mut core)?;
                std::fs::write(&who, serde_json::to_vec(&json!({"person": person, "device": device})).unwrap_or_default())
                    .map_err(|error| format!("Yougori can't record who this setup's jobs run as: {error}"))?;
                Open { core: Arc::new(Mutex::new(core)), person, device }
            }
        };
        self.open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(setup.to_owned(), open.clone());
        Ok(open)
    }
}

/// One setup's realm, and who its work is placed by on this computer.
#[derive(Clone)]
pub(crate) struct Open {
    core: Arc<Mutex<yougori_grid::core::Core>>,
    person: String,
    device: String,
}

/// Enrols this computer in a freshly made realm: the person the setup acts as, and the computer
/// that offers its room and runs the attempts.
fn this_computer(core: &mut yougori_grid::core::Core) -> Result<(String, String), String> {
    use yougori_grid::core::{
        identity::{PrincipalKind, Role},
        work::{Commitment, Resources},
    };
    let at = at();
    let person = core.add_principal("owner", PrincipalKind::Person, "This setup", &[Role::Operator], at)?;
    let (device, _) = core.enrol_device(&person.id, "This computer", std::env::consts::OS, at)?;
    // What this computer offers is set on the grid's own tab in My setups, as it is for every
    // other profile. Until somebody sets it, a modest share that no job can mistake for the whole
    // machine.
    let share = Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 20.0, gpu: false, vram_gb: 0.0 };
    core.offer_host(&device.id, "This computer", share, share, Commitment::Share, at)?;
    Ok((person.id, device.id))
}

/// What a declared job becomes when it reaches the grid: the library's own description, built here
/// from the template's words and nothing else.
///
/// Nothing of this computer crosses over. A job gets the program and the arguments the template
/// declared, the outputs it named, the room it asked for and the retry policy it chose. It gets no
/// path on this computer, no shell and no secret: the library refuses the first two at its own door
/// as well, and the third is simply never put in.
fn described(spec: &Value, inputs: Vec<(String, String)>) -> Result<yougori_grid::core::jobs::JobSpec, String> {
    use yougori_grid::core::jobs::{Entrypoint, InputRef, JobSpec, Retry, SideEffects};
    let argv = argv(spec)?;
    let entrypoint = match spec["image"].as_str().filter(|image| !image.is_empty()) {
        Some(image) => Entrypoint::Image { reference: image.to_owned(), args: argv },
        None => Entrypoint::Argv { argv },
    };
    let attempts = spec["retry"]["attempts"].as_u64().unwrap_or(1).max(1) as u32;
    let side_effects = if spec["idempotent"].as_bool() == Some(true) { SideEffects::Repeatable } else { SideEffects::ManualReconcile };
    let needs = yougori_grid::core::work::Resources {
        cpu: spec["resources"]["cpu"].as_f64().unwrap_or(1.0),
        memory_gb: spec["resources"]["memory_gb"].as_f64().unwrap_or(1.0),
        disk_gb: spec["resources"]["disk_gb"].as_f64().unwrap_or(0.0),
        // The format counts GPUs; the grid asks whether a job needs one at all, and a computer
        // with none free is never given it either way.
        gpu: spec["resources"]["gpus"].as_u64().unwrap_or(0) > 0,
        vram_gb: 0.0,
    };
    JobSpec {
        entrypoint,
        inputs: inputs.into_iter().map(|(name, artifact_id)| InputRef { name, artifact_id }).collect(),
        outputs: spec["outputs"]["resource"].as_str().map(|_| vec![RESULT.to_owned()]).unwrap_or_default(),
        timeout_seconds: spec["timeout_seconds"].as_i64().unwrap_or(3600),
        needs,
        // The wait the template asked for between attempts, doubling after each, as it said.
        retry: Retry { max_attempts: attempts, backoff_seconds: spec["retry"]["backoff_seconds"].as_i64().unwrap_or(30).clamp(0, 3600) },
        side_effects,
        checkpoints: spec["checkpoint"].as_bool().unwrap_or(false),
    }
    .checked()
    .map_err(|refusal| refusal.describe())
}

impl JobCalls for EngineJobs {
    fn open_queue<'a>(&'a self, setup: &'a str, queue: &'a str) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            core.reopen_job_admission(&open.person, queue, at()).map_err(|refusal| refusal.describe())?;
            Ok(queue.to_owned())
        })
    }

    fn submit<'a>(&'a self, setup: &'a str, queue: &'a str, label: &'a str, spec: &'a Value, inputs: Vec<(String, String)>) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let mut wanted = described(spec, inputs)?;
            // The step's own key is what makes applying twice find the job already sent rather
            // than queue a second one. A job that is not safe to repeat keeps its own class.
            if wanted.side_effects == yougori_grid::core::jobs::SideEffects::Repeatable {
                wanted.side_effects = yougori_grid::core::jobs::SideEffects::DedupKey { key: label.to_owned() };
            }
            let id = {
                let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                core.submit_job(&open.person, &open.device, queue, wanted, at()).map(|sent| sent.job.id).map_err(|refusal| refusal.describe())?
            };
            // The folder a job reads is this computer's, so it stays on this computer: kept
            // beside the realm, by job, for the sandbox that runs its attempts here.
            if let Some(folder) = spec["source_folder"].as_str() {
                job_worker::remember_source(&self.meta(setup), &id, std::path::Path::new(folder))?;
            }
            Ok(id)
        })
    }

    fn look<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Option<Value>, String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(found) = core.job(job).map_err(|refusal| refusal.describe())? else { return Ok(None) };
            let waiting = core.why_job_waits(job, at()).ok().flatten();
            Ok(Some(json!({
                "state": found.state.word(),
                "finished": found.state.finished(),
                "attempts": found.attempts,
                "waitingBecause": waiting,
            })))
        })
    }

    fn outputs<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Vec<(String, String)>, String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            // `job_outputs` answers only for a job that succeeded, which is exactly the rule a
            // stage reading another stage has to keep.
            Ok(core.job_outputs(job).map_err(|refusal| refusal.describe())?.into_iter().map(|artifact| (artifact.name, artifact.id)).collect())
        })
    }

    fn withdraw<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            use yougori_grid::core::jobs::JobError;
            let open = self.realm(setup)?;
            let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match core.cancel_job(&open.person, job, at()) {
                // A job that has already ended needs no asking, and one this grid never had is
                // nothing a removal can delete either way.
                Ok(_) | Err(JobError::Finished) | Err(JobError::NoSuchJob) => Ok(()),
                Err(refusal) => Err(refusal.describe()),
            }
        })
    }

    fn admit<'a>(&'a self, setup: &'a str, queue: &'a str, admitting: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let result = if admitting {
                core.reopen_job_admission(&open.person, queue, at()).map(|_| ())
            } else {
                // What is running finishes. Stopping a setup never kills work mid-flight.
                core.close_job_admission(&open.person, queue, yougori_grid::core::jobs::InFlight::Finish, "this setup was stopped", at()).map(|_| ())
            };
            result.map_err(|refusal| refusal.describe())
        })
    }

    fn pause<'a>(&'a self, setup: &'a str, queue: &'a str, drain: bool) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            use yougori_grid::core::jobs::InFlight;
            let open = self.realm(setup)?;
            let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let (in_flight, reason) = if drain {
                (InFlight::Finish, "new work for this setup was paused")
            } else {
                (InFlight::Stop, "new work for this setup was paused and its running jobs asked to stop")
            };
            core.close_job_admission(&open.person, queue, in_flight, reason, at()).map(|_| ()).map_err(|refusal| refusal.describe())
        })
    }

    fn workers<'a>(&'a self, setup: &'a str, queue: &'a str, running: bool) -> BoxFuture<'a, Result<(), String>> {
        let _ = queue;
        Box::pin(async move {
            if !running {
                self.workers.stop(setup);
                return Ok(());
            }
            let open = self.realm(setup)?;
            let root = self.folder.join(format!("{setup}-work"));
            let meta = self.meta(setup);
            let app = self.app.clone();
            self.workers.start(setup, WORKERS_PER_COMPUTER, move |which| {
                Arc::new(JobWorker::new(
                    Arc::new(LocalQueue::new(open.core.clone(), &open.device)),
                    Arc::new(EngineSandbox::for_setup(app.clone(), meta.clone())),
                    root.join(format!("worker-{which}")),
                ))
            });
            Ok(())
        })
    }

    fn store<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let jobs = core.jobs().map_err(|refusal| refusal.describe())?;
            Ok(json!({"present": true, "jobs": jobs.len()}))
        })
    }

    /// Nothing here deletes anything. The sweep inside the library does, on exactly the policy set
    /// here, and never what a job still in play needs.
    fn keep<'a>(&'a self, setup: &'a str, max_gb: f64, days: Option<u32>) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let open = self.realm(setup)?;
            let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            core.set_job_retention(&open.person, retention_of(max_gb, days), at()).map(|_| ()).map_err(|refusal| refusal.describe())
        })
    }

    fn artifacts<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Vec<Value>, String>> {
        Box::pin(async move {
            if !self.made(setup) {
                return Ok(Vec::new());
            }
            let open = self.realm(setup)?;
            let core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut found = Vec::new();
            for job in core.jobs().map_err(|refusal| refusal.describe())? {
                for artifact in core.job_artifacts(&job.id).map_err(|refusal| refusal.describe())? {
                    if artifact.role != yougori_grid::core::jobs::ArtifactRole::Output {
                        continue;
                    }
                    found.push(json!({
                        "id": artifact.id, "job": artifact.job_id, "name": artifact.name, "bytes": artifact.bytes,
                        "sha256": artifact.sha256, "recordedAt": artifact.recorded_at,
                        "removed": artifact.removed_at.is_some(), "removedBecause": (!artifact.removed_reason.is_empty()).then_some(artifact.removed_reason),
                    }));
                }
            }
            found.sort_by(|a, b| b["recordedAt"].as_i64().cmp(&a["recordedAt"].as_i64()));
            Ok(found)
        })
    }

    fn save_artifact<'a>(&'a self, setup: &'a str, artifact: &'a str, to: &'a std::path::Path) -> BoxFuture<'a, Result<u64, String>> {
        Box::pin(async move {
            if !self.made(setup) {
                return Err("This setup has no results kept on this computer.".into());
            }
            let open = self.realm(setup)?;
            let parent = to.parent().filter(|parent| parent.is_dir()).ok_or("Choose a folder that exists for the copy.")?;
            // Written beside where it goes and moved into place only once its checksum matched,
            // so a damaged copy never stands where the person looks for it.
            let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(|error| format!("Yougori can't write the copy there: {error}"))?;
            let bytes = {
                let core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                core.read_job_artifact(&open.person, artifact, staged.as_file_mut()).map_err(|refusal| refusal.describe())?
            };
            staged.as_file().sync_all().map_err(|error| error.to_string())?;
            staged.persist(to).map_err(|error| format!("Yougori can't put the copy there: {}", error.error))?;
            Ok(bytes)
        })
    }

    fn logs<'a>(&'a self, setup: &'a str, job: &'a str) -> BoxFuture<'a, Result<Vec<Value>, String>> {
        Box::pin(async move {
            let folder = job_worker::logs_folder(&self.meta(setup), job);
            let mut files: Vec<PathBuf> = std::fs::read_dir(&folder).into_iter().flatten().flatten().map(|entry| entry.path()).filter(|path| path.extension().is_some_and(|ext| ext == "log")).collect();
            files.sort();
            Ok(files
                .into_iter()
                .filter_map(|path| {
                    let name = path.file_stem()?.to_string_lossy().into_owned();
                    let (when, attempt) = name.split_once('-')?;
                    let text = std::fs::read(&path).ok().map(|bytes| String::from_utf8_lossy(&bytes).into_owned())?;
                    Some(json!({"attempt": attempt, "at": when.parse::<i64>().ok(), "text": text}))
                })
                .collect())
        })
    }

    fn remember_run<'a>(&'a self, setup: &'a str, resource: &'a str, job: &'a str, why: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { job_worker::remember_run(&self.meta(setup), resource, job, why) })
    }

    fn runs<'a>(&'a self, setup: &'a str, resource: &'a str) -> BoxFuture<'a, Vec<Value>> {
        Box::pin(async move { job_worker::runs_of(&self.meta(setup), resource) })
    }

    fn settle<'a>(&'a self, setup: &'a str, job: &'a str, outcome: &'a str) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            use yougori_grid::core::jobs::Settled;
            let settled = match outcome {
                "succeeded" => Settled::Succeeded,
                "failed" => Settled::Failed,
                "run_again" => Settled::RunAgain,
                other => return Err(format!("{other} isn't a way to settle a job: say succeeded, failed or run_again.")),
            };
            if !self.made(setup) {
                return Err("This setup has no jobs on this computer.".into());
            }
            let open = self.realm(setup)?;
            let mut core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            core.settle_job(&open.person, job, settled, at()).map(|state| state.word().to_owned()).map_err(|refusal| refusal.describe())
        })
    }

    fn waiting<'a>(&'a self, setup: &'a str, queue: &'a str) -> BoxFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            use yougori_grid::core::jobs::JobState;
            if !self.made(setup) {
                return Ok(false);
            }
            let open = self.realm(setup)?;
            let core = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if !core.job_queue(queue).map_err(|refusal| refusal.describe())?.open {
                return Ok(false);
            }
            // Queued work, and work an attempt held when the last engine ended: the worker that
            // picks it up again settles what that attempt left. A job whose outcome is unknown
            // waits for a person, not a worker.
            Ok(core.jobs().map_err(|refusal| refusal.describe())?.iter().any(|job| matches!(job.state, JobState::Queued | JobState::Running | JobState::CancelRequested)))
        })
    }

    fn realm_id<'a>(&'a self, setup: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            // Only a realm already made is opened: asking which realm a setup is in never makes one.
            let held = self.open.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(setup);
            if !held && !self.folder.join(format!("{setup}.db")).exists() {
                return Ok(None);
            }
            let open = self.realm(setup)?;
            let id = open.core.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).realm().id.clone();
            Ok(Some(id))
        })
    }
}

// ----- tests -----

#[cfg(test)]
mod tests;
