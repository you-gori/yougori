//! Finite jobs: a command that runs on one of the realm's computers, finishes, and hands back what
//! it made (docs/template-platform-implementation-plan.md, section 9.3).
//!
//! A job is admitted into a named queue and waits there until a computer that offered enough room
//! asks for work. It is then run by one attempt at a time. Each attempt holds an ordinary
//! reservation in the realm's ledger, the same `leases` table every other profile places work
//! through, so a job and a model request can never both be given the same exclusive card or the
//! same gigabytes of memory on one computer, and a computer that is being emptied is given nothing
//! new by either.
//!
//! **Attempts are fenced.** Every attempt carries a number that only rises for its job. A computer
//! acting on an attempt presents the attempt and that number, and they are compared for equality: a
//! computer that went quiet, was replaced and woke up later is refused at its first step, and
//! nothing it sends afterwards can overwrite what the current attempt sends. The comparison is made
//! again inside the change that writes.
//!
//! **Execution is at least once, never exactly once.** An attempt whose computer stops answering
//! may still have done its work. What happens next depends on what the job said its effects are. A
//! repeatable job is tried again. A job that hands its own deduplication key to the system it
//! changes is tried again, and that system recognises the repeat. A job whose effects cannot be
//! repeated safely is never tried again by itself: once an attempt may have run, the job waits with
//! its outcome marked unknown until a person checks and settles it. An attempt that never started
//! has done nothing, whatever the job does, so it is placed again while attempts remain. A timeout
//! is an unknown outcome, not a failure.
//!
//! **Cancelling is a request.** A job nothing has started is cancelled at once. A running one is
//! asked to stop and its computer hears so on its next heartbeat; it is stopped when that computer
//! says it has, and its outcome is unknown if the computer stops answering first. Those three are
//! separate states and are never folded into one.
//!
//! **Artifacts are checked and tied to the attempt that made them.** Each is bounded in size, and
//! arrives in two steps so that a large upload never holds the realm: its bytes are staged first,
//! counted and hashed as they come and compared with what the computer declared, with nothing but a
//! ticket the realm issued; then the realm is taken briefly to record them against the attempt and
//! the fencing token that sent them, asking the fencing question again. Outputs are logical names,
//! never places on a computer; the bytes are kept beside the realm's database in a file named by
//! their checksum, so nothing a job names becomes part of a path.
//!
//! **A queue can stop admitting work.** Closing a queue, for a spent budget or anything else,
//! refuses new jobs and starts no new attempt, and says plainly what happens to the attempts already
//! running: they finish, or they are asked to stop. Nothing is killed by closing a queue.
//!
//! **A research grid runs no generic jobs.** Research has its own trust boundary, its own scopes and
//! its own reviewed steps, and a generic job is not a way around any of them. A research realm
//! refuses every job and so does its database, a job description has no field that could carry a
//! research step and is refused if it tries, and a researcher's role does not include placing
//! generic work.
//!
//! **Where the records live.** In the realm's own database, through the realm's one connection, in
//! four tables on a version track of their own, recorded beside them (see `rows`). The bytes of
//! artifacts are in the folder `shelf` names.
//!
//! **Keeping and copying.** A realm keeps finished jobs' artifacts for a bounded time and up to a
//! bounded number of bytes, never removing what a job still in play needs, and every copy of a
//! realm carries its artifacts with every checksum checked again (see `keeping`).
//!
//! What this does not do yet, said rather than implied. The portable backup shape does not carry
//! jobs, and a backup of a realm that holds them says so in its own words. A coordinator that is not
//! running places nothing and nothing takes over from it. The core reaches no computer: an attempt
//! is stopped by its own computer, which hears that it should on its next heartbeat or finds its
//! reservation gone.
mod keeping;
mod queue;
mod rows;
mod shelf;
mod spec;
#[cfg(test)]
mod tests;
mod worker;

pub use keeping::{Carried, Tidied};
pub(crate) use keeping::{artifact_folder, carry_artifacts};
pub use spec::{logical_name, Entrypoint, InputRef, JobSpec, Retry, SideEffects};
pub use worker::{ArtifactTicket, StagedArtifact};

use super::{
    audit::{Decision, Entry},
    realm::{Capability, RealmKind},
    store::Store,
    work::{Kind, Resources, Stage},
    Core,
};
use serde::{Deserialize, Serialize};

// The bounds the jobs doors enforce live in `limits`, beside every other bound the core has, each
// named there with the door that enforces it.
use super::limits::{MAX_ATTEMPTS_PER_JOB, MAX_BACKOFF_SECONDS};

// ---- What can go wrong ----

/// Why a job, an attempt or an artifact was refused, in words a person can act on.
///
/// `describe` is the sentence; `code` is a stable word a program can match on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobError {
    /// A research grid runs no generic jobs.
    ResearchRealm,
    /// A job description tried to carry something only the research profile does; the field is named.
    ResearchAction(String),
    /// A grid that only brokers credentials runs nothing on its computers.
    NoComputers,
    NotServing,
    /// The person or computer asking may not do this; the sentence says why.
    NotAllowed(String),
    /// The job description is not one this grid can run; the sentence says what to change.
    InvalidSpec(String),
    /// A name that is a place on a computer rather than a name.
    PathLikeName(String),
    /// A bound was reached; the sentence names it and its number.
    Limit(String),
    QueueClosed { queue: String, reason: String },
    DuplicateKey,
    NoSuchJob,
    NoSuchAttempt,
    NoSuchArtifact,
    /// An input that is not an output of a job that finished.
    InputNotReady,
    NotAWorker,
    Draining,
    /// The computer may not take work just now; the sentence says why.
    HostRefused(String),
    /// The attempt or token presented is not the job's current one.
    StaleFence,
    WrongComputer,
    /// The attempt's reservation has ended, whether it ran out or was taken back.
    LeaseLost,
    StopRequested,
    NotStarted,
    UndeclaredOutput(String),
    NoCheckpoints,
    OutputAlreadySent(String),
    OutputsMissing(Vec<String>),
    ChecksumMismatch,
    /// The bytes that arrived were not as many as declared; `None` means more arrived.
    SizeMismatch { declared: u64, arrived: Option<u64> },
    Damaged,
    /// The retention sweep removed this artifact's bytes; its record stays.
    ArtifactRemoved,
    /// Bytes that were staged are no longer there to record.
    StagedGone,
    NothingAskedToStop,
    Finished,
    AwaitingSettlement,
    NotUnknown,
    /// Something underneath the jobs failed: the database, the disk.
    Trouble(String),
}

impl JobError {
    /// What to tell whoever asked.
    pub fn describe(&self) -> String {
        match self {
            JobError::ResearchRealm => "Generic jobs do not run in a research grid. Research work goes through its scope, where each step is reviewed before it runs".into(),
            JobError::ResearchAction(field) => {
                format!("A generic job cannot carry research work ('{field}'). Research runs in its own grid, through its scope, where each step is reviewed")
            }
            JobError::NoComputers => "This grid only brokers credentials and runs nothing on its computers, so it takes no jobs".into(),
            JobError::NotServing => "This grid is not serving work at the moment".into(),
            JobError::NotAllowed(why) | JobError::InvalidSpec(why) | JobError::Limit(why) | JobError::Trouble(why) => why.clone(),
            JobError::PathLikeName(name) => {
                format!("'{name}' looks like a place on a computer. Jobs name their inputs and outputs: use letters, digits, dots, dashes and underscores")
            }
            JobError::QueueClosed { queue, reason } if reason.is_empty() => format!("The queue '{queue}' is not taking new jobs just now"),
            JobError::QueueClosed { queue, reason } => format!("The queue '{queue}' is not taking new jobs just now: {reason}"),
            JobError::DuplicateKey => "A job with this deduplication key was already sent with a different description. Different work needs a key of its own".into(),
            JobError::NoSuchJob => "No such job is in this grid".into(),
            JobError::NoSuchAttempt => "No such attempt is in this grid".into(),
            JobError::NoSuchArtifact => "No such artifact is in this grid".into(),
            JobError::InputNotReady => "An input has to be an output of a job that finished, and this one is not".into(),
            JobError::NotAWorker => "This computer is not offering resources to this grid".into(),
            JobError::Draining => "This computer is being emptied and takes no new jobs; what it is running may finish".into(),
            JobError::HostRefused(why) => format!("This computer takes no jobs right now: {why}"),
            JobError::StaleFence => "This attempt is not the job's current one, so nothing it sends is used. Stop it and ask for new work".into(),
            JobError::WrongComputer => "This attempt belongs to another computer".into(),
            JobError::LeaseLost => "This attempt no longer holds its computer. Stop it; nothing it sends now is used".into(),
            JobError::StopRequested => "This job was asked to stop, so this attempt should not start".into(),
            JobError::NotStarted => "Start the attempt before sending what it made".into(),
            JobError::UndeclaredOutput(name) => format!("This job did not declare an output called '{name}'"),
            JobError::NoCheckpoints => "This job did not say it can resume from a checkpoint".into(),
            JobError::OutputAlreadySent(name) => format!("This attempt already sent a different '{name}'. What an attempt sent is not replaced"),
            JobError::OutputsMissing(names) => format!("This attempt has not sent every output yet. Still to come: {}", names.join(", ")),
            JobError::ChecksumMismatch => "The bytes that arrived do not match the checksum that was declared, so nothing was recorded".into(),
            JobError::SizeMismatch { declared, arrived: Some(arrived) } => {
                format!("The artifact was declared as {declared} bytes and {arrived} arrived, so nothing was recorded")
            }
            JobError::SizeMismatch { declared, arrived: None } => format!("The artifact was declared as {declared} bytes and more than that arrived, so nothing was recorded"),
            JobError::Damaged => "The kept copy of this artifact no longer matches its checksum; it may have been damaged on this computer's disk".into(),
            JobError::ArtifactRemoved => "This artifact's bytes were removed under this grid's retention policy. Its record is kept: what it was, which attempt sent it and what it hashed to".into(),
            JobError::StagedGone => "The staged bytes are no longer here, so nothing was recorded. Send them again".into(),
            JobError::NothingAskedToStop => "Nothing asked this attempt to stop. Report how it ended instead".into(),
            JobError::Finished => "This job has already finished".into(),
            JobError::AwaitingSettlement => "Nobody knows yet whether this job did its work. Check what it did, then settle it".into(),
            JobError::NotUnknown => "Only a job whose outcome is not known is settled by hand".into(),
        }
    }

    /// A stable word for the refusal, for a program to match on.
    pub fn code(&self) -> &'static str {
        match self {
            JobError::ResearchRealm => "research_realm",
            JobError::ResearchAction(_) => "research_action",
            JobError::NoComputers => "no_computers",
            JobError::NotServing => "not_serving",
            JobError::NotAllowed(_) => "not_allowed",
            JobError::InvalidSpec(_) => "invalid_spec",
            JobError::PathLikeName(_) => "path_like_name",
            JobError::Limit(_) => "limit_reached",
            JobError::QueueClosed { .. } => "queue_closed",
            JobError::DuplicateKey => "duplicate_key",
            JobError::NoSuchJob => "no_such_job",
            JobError::NoSuchAttempt => "no_such_attempt",
            JobError::NoSuchArtifact => "no_such_artifact",
            JobError::InputNotReady => "input_not_ready",
            JobError::NotAWorker => "not_a_worker",
            JobError::Draining => "draining",
            JobError::HostRefused(_) => "host_refused",
            JobError::StaleFence => "stale_fence",
            JobError::WrongComputer => "wrong_computer",
            JobError::LeaseLost => "lease_lost",
            JobError::StopRequested => "stop_requested",
            JobError::NotStarted => "not_started",
            JobError::UndeclaredOutput(_) => "undeclared_output",
            JobError::NoCheckpoints => "no_checkpoints",
            JobError::OutputAlreadySent(_) => "output_already_sent",
            JobError::OutputsMissing(_) => "outputs_missing",
            JobError::ChecksumMismatch => "checksum_mismatch",
            JobError::SizeMismatch { .. } => "size_mismatch",
            JobError::Damaged => "damaged",
            JobError::ArtifactRemoved => "artifact_removed",
            JobError::StagedGone => "staged_gone",
            JobError::NothingAskedToStop => "nothing_asked_to_stop",
            JobError::Finished => "finished",
            JobError::AwaitingSettlement => "awaiting_settlement",
            JobError::NotUnknown => "not_unknown",
            JobError::Trouble(_) => "trouble",
        }
    }
}

impl std::fmt::Display for JobError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.describe())
    }
}

impl std::error::Error for JobError {}

/// What the rest of the core reports, which is a sentence about the database or the disk.
impl From<String> for JobError {
    fn from(trouble: String) -> JobError {
        JobError::Trouble(trouble)
    }
}

/// So a caller written against the core's sentences can use a job's refusal as one.
impl From<JobError> for String {
    fn from(error: JobError) -> String {
        error.describe()
    }
}

// ---- What is recorded ----

/// Where a job has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobState {
    /// Waiting for a computer, or for its backoff to pass.
    Queued,
    /// An attempt holds a computer for it. The attempt may still be preparing.
    Running,
    /// Somebody asked it to stop while it ran, and its computer has not yet said that it has.
    CancelRequested,
    /// An attempt finished and sent every output.
    Succeeded,
    /// It failed, and will not be tried again by itself.
    Failed,
    /// It was cancelled before anything ran.
    Cancelled,
    /// It was asked to stop while it ran, and it ended.
    Stopped,
    /// An attempt that may have done its work ended without saying so, and the job will not be
    /// tried again by itself. A person checks what happened and settles it.
    OutcomeUnknown,
}

impl JobState {
    pub fn word(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::CancelRequested => "cancelRequested",
            JobState::Succeeded => "succeeded",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
            JobState::Stopped => "stopped",
            JobState::OutcomeUnknown => "outcomeUnknown",
        }
    }

    fn from_word(word: &str) -> Option<JobState> {
        [
            JobState::Queued,
            JobState::Running,
            JobState::CancelRequested,
            JobState::Succeeded,
            JobState::Failed,
            JobState::Cancelled,
            JobState::Stopped,
            JobState::OutcomeUnknown,
        ]
        .into_iter()
        .find(|state| state.word() == word)
    }

    /// Whether nothing more will happen to it. A job whose outcome is unknown is waiting for a
    /// person, which is not the same as finished.
    pub fn finished(self) -> bool {
        matches!(self, JobState::Succeeded | JobState::Failed | JobState::Cancelled | JobState::Stopped)
    }
}

/// Where one attempt has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttemptState {
    /// A computer holds it and has not started it.
    Leased,
    /// The computer said it was starting it, so it may have done anything the job does.
    Running,
    Succeeded,
    /// Its computer said it failed.
    Failed,
    /// It was asked to stop, and it ended.
    Stopped,
    /// It was cancelled before it started.
    Cancelled,
    /// Its reservation ended without a word from its computer.
    Lost,
    /// It reached the job's time limit without finishing.
    TimedOut,
}

impl AttemptState {
    pub fn word(self) -> &'static str {
        match self {
            AttemptState::Leased => "leased",
            AttemptState::Running => "running",
            AttemptState::Succeeded => "succeeded",
            AttemptState::Failed => "failed",
            AttemptState::Stopped => "stopped",
            AttemptState::Cancelled => "cancelled",
            AttemptState::Lost => "lost",
            AttemptState::TimedOut => "timedOut",
        }
    }

    fn from_word(word: &str) -> Option<AttemptState> {
        [
            AttemptState::Leased,
            AttemptState::Running,
            AttemptState::Succeeded,
            AttemptState::Failed,
            AttemptState::Stopped,
            AttemptState::Cancelled,
            AttemptState::Lost,
            AttemptState::TimedOut,
        ]
        .into_iter()
        .find(|state| state.word() == word)
    }

    /// Whether it still holds, or is still meant to hold, a computer.
    pub fn live(self) -> bool {
        matches!(self, AttemptState::Leased | AttemptState::Running)
    }

    /// Where the core workload that held the attempt's room ends up.
    fn stage(self) -> Stage {
        match self {
            AttemptState::Leased => Stage::Leased,
            AttemptState::Running => Stage::Running,
            AttemptState::Succeeded => Stage::Completed,
            AttemptState::Stopped | AttemptState::Cancelled => Stage::Cancelled,
            AttemptState::Failed | AttemptState::Lost | AttemptState::TimedOut => Stage::Failed,
        }
    }
}

/// What an artifact is to its job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactRole {
    /// One of the outputs the job declared.
    Output,
    /// Where a later attempt can pick up from.
    Checkpoint,
}

impl ArtifactRole {
    pub fn word(self) -> &'static str {
        match self {
            ArtifactRole::Output => "output",
            ArtifactRole::Checkpoint => "checkpoint",
        }
    }

    fn from_word(word: &str) -> Option<ArtifactRole> {
        [ArtifactRole::Output, ArtifactRole::Checkpoint].into_iter().find(|role| role.word() == word)
    }
}

/// What happens to attempts already running when a queue stops admitting work. There is no
/// default: whoever closes a queue says which, and the record keeps what they said.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InFlight {
    /// They run to their end and what they send is kept. Nothing new starts, retries included.
    Finish,
    /// Each is asked to stop, exactly as a cancel asks, and its computer decides when that is safe.
    /// Nothing is killed.
    Stop,
}

impl InFlight {
    pub fn word(self) -> &'static str {
        match self {
            InFlight::Finish => "finish",
            InFlight::Stop => "stop",
        }
    }

    fn from_word(word: &str) -> Option<InFlight> {
        [InFlight::Finish, InFlight::Stop].into_iter().find(|policy| policy.word() == word)
    }
}

/// How a computer says an attempt failed. A closed set, so a member computer reporting a failure
/// never chooses the words that go into the realm's sealed history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Failure {
    /// The program ended with an error.
    Exited,
    /// The program or its sandbox ended abnormally.
    Crashed,
    /// The computer ended it itself: it was shutting down, or its person needed it back.
    Interrupted,
    /// An input could not be fetched, or did not match its checksum.
    InputUnavailable,
}

impl Failure {
    /// What the record says happened, in words fixed here.
    pub fn say(self) -> &'static str {
        match self {
            Failure::Exited => "the program ended with an error",
            Failure::Crashed => "the program or its sandbox ended abnormally",
            Failure::Interrupted => "its computer ended it",
            Failure::InputUnavailable => "an input could not be fetched intact",
        }
    }
}

/// How a computer says an attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Ending {
    /// It finished, and every declared output has been sent.
    Succeeded,
    Failed(Failure),
    /// It stopped because it was asked to.
    Stopped,
}

/// What a person found when they checked a job whose outcome was unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Settled {
    /// It did its work.
    Succeeded,
    /// It did not, and should not run again.
    Failed,
    /// Run it again: a person's decision, recorded with their name, and still held to the bound
    /// on attempts.
    RunAgain,
}

/// One job, as the realm keeps it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub realm_id: String,
    pub queue: String,
    /// Who sent it. Its attempts are work placed by them.
    pub principal_id: String,
    /// The computer it was sent from.
    pub device_id: String,
    pub spec: JobSpec,
    pub state: JobState,
    /// How many attempts it has had, started or not.
    pub attempts: u32,
    /// The fencing token of its newest attempt. Only rises.
    pub fence: u64,
    /// The attempt that holds a computer for it now; once it has finished, the attempt whose end
    /// decided it, whose outputs are the job's outputs when it succeeded.
    pub current_attempt: Option<String>,
    /// The newest checkpoint any of its attempts recorded.
    pub checkpoint: Option<String>,
    /// It is not given a computer before this.
    pub not_before: i64,
    /// Why it is where it is, in words fixed by this module.
    pub note: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

/// One attempt at a job, on one computer, under one fencing token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobAttempt {
    pub id: String,
    pub job_id: String,
    /// One for the first attempt, and one more for each after it.
    pub number: u32,
    pub fence: u64,
    pub host_id: String,
    /// The computer that holds it, which is the only one whose word about it is taken.
    pub device_id: String,
    /// The core workload whose reservation holds the attempt's room in the realm's ledger.
    pub workload_id: String,
    pub lease_id: String,
    pub state: AttemptState,
    pub granted_at: i64,
    pub started_at: Option<i64>,
    pub heartbeat_at: i64,
    /// When its reservation runs out unless its computer renews it.
    pub expires_at: i64,
    /// The job's time limit for this attempt, which no renewal passes.
    pub deadline: i64,
    pub ended_at: Option<i64>,
    /// How it ended, in words fixed by this module.
    pub ending: String,
}

/// One artifact an attempt sent: its name, its size, its checksum, and who sent it under which token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobArtifact {
    pub id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub fence: u64,
    pub role: ArtifactRole,
    pub name: String,
    pub bytes: u64,
    /// 64 lowercase hexadecimal characters, computed here over the bytes as they arrived.
    pub sha256: String,
    pub recorded_at: i64,
    /// When the retention sweep removed the bytes. The record stays, so what was sent, by whom and
    /// what it hashed to is never lost; only the bytes are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<i64>,
    /// Why the bytes were removed, in words fixed by this module.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub removed_reason: String,
}

/// How long, and how much, a realm keeps of its jobs' artifacts. Nothing a job still in play needs
/// is removed whatever its age; past these, the oldest of the rest goes first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retention {
    pub keep_seconds: i64,
    pub keep_bytes: u64,
}

impl Default for Retention {
    /// The defaults in `limits`: thirty days and twenty gigabytes.
    fn default() -> Retention {
        Retention { keep_seconds: super::limits::KEEP_JOB_ARTIFACTS_FOR, keep_bytes: super::limits::KEEP_JOB_ARTIFACT_BYTES }
    }
}

/// Whether a queue admits work, and what was said when that last changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobQueue {
    pub name: String,
    pub open: bool,
    /// What happens to running attempts while it is closed. Set when it is closed.
    pub in_flight: Option<InFlight>,
    pub reason: String,
    pub changed_by: String,
    pub changed_at: i64,
}

/// What a job's sender is told when it is admitted.
#[derive(Clone, Debug, PartialEq)]
pub struct Submitted {
    pub job: Job,
    /// True when this was the same work sent again under the same deduplication key, and the job
    /// already admitted is what came back. Nothing new was made.
    pub replayed: bool,
}

/// One artifact a computer is to fetch, with what it must hash to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeasedInput {
    pub name: String,
    pub artifact_id: String,
    pub bytes: u64,
    pub sha256: String,
}

/// What a computer is given with an attempt: everything it needs to run it, and the token it
/// presents with everything it sends.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobLease {
    pub job_id: String,
    pub attempt_id: String,
    pub number: u32,
    pub fence: u64,
    pub entrypoint: Entrypoint,
    pub inputs: Vec<LeasedInput>,
    pub outputs: Vec<String>,
    pub needs: Resources,
    /// The key to hand to the system the job changes, when it has one.
    pub dedup_key: Option<String>,
    /// A checkpoint an earlier attempt recorded, when the job can resume from one.
    pub resume_from: Option<LeasedInput>,
    pub expires_at: i64,
    pub deadline: i64,
}

/// What a computer hears back from a heartbeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Beat {
    /// When the attempt's reservation now runs out unless renewed again.
    pub expires_at: i64,
    pub deadline: i64,
    /// Somebody asked the job to stop. The computer stops it and says so with `Ending::Stopped`.
    pub stop_requested: bool,
}

/// How long a job waits before its next attempt, after `attempts` of them: the policy's backoff,
/// doubled for each attempt after the first, never more than `MAX_BACKOFF_SECONDS`.
pub fn backoff(retry: &Retry, attempts: u32) -> i64 {
    if retry.backoff_seconds <= 0 {
        return 0;
    }
    let doublings = attempts.saturating_sub(1).min(20);
    retry.backoff_seconds.saturating_mul(1_i64 << doublings).min(MAX_BACKOFF_SECONDS)
}

/// How an attempt ended without success, as far as deciding what happens next is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// Its computer said how.
    Reported(Failure),
    /// Its reservation ended without a word.
    Lost,
    /// It reached its time limit.
    TimedOut,
}

/// Where a job goes after one attempt ended without success, when it goes there, and the words
/// that say why. The one decision behind every way an attempt can end badly, so a failure, a
/// computer going quiet and a timeout cannot drift apart.
fn next_after(job: &Job, started: bool, ended: Ended, now: i64) -> (JobState, i64, &'static str) {
    let left = job.attempts < job.spec.retry.max_attempts.min(MAX_ATTEMPTS_PER_JOB);
    let again = (JobState::Queued, now.saturating_add(backoff(&job.spec.retry, job.attempts)), "Waiting to be tried again");
    if job.state == JobState::CancelRequested {
        return match ended {
            Ended::Reported(_) => (JobState::Stopped, now, "It ended after it was asked to stop"),
            _ if !started => (JobState::Cancelled, now, "It was cancelled before it started"),
            _ => (
                JobState::OutcomeUnknown,
                now,
                "It was asked to stop, and its computer stopped answering before saying it had. Check what it did, then settle it",
            ),
        };
    }
    if !started {
        // Nothing ran, so nothing outside has been done either, whatever the job does.
        return if left {
            (JobState::Queued, now.saturating_add(backoff(&job.spec.retry, job.attempts)), "Waiting for another computer: the last one never started it")
        } else {
            (JobState::Failed, now, "It never ran: every attempt it was allowed ended before it started")
        };
    }
    match (ended, &job.spec.side_effects) {
        (Ended::Reported(_), SideEffects::ManualReconcile) => {
            (JobState::Failed, now, "It failed. Its effects outside the grid cannot be repeated safely, so it is not tried again by itself")
        }
        (Ended::Reported(_), _) if left => again,
        (Ended::Reported(_), _) => (JobState::Failed, now, "It failed on every attempt it was allowed"),
        (_, SideEffects::ManualReconcile) => (
            JobState::OutcomeUnknown,
            now,
            "Its computer stopped answering while it ran, and its effects outside the grid cannot be repeated safely. Check what it did, then settle it",
        ),
        (_, _) if left => again,
        (_, _) => (
            JobState::OutcomeUnknown,
            now,
            "Its last attempt ended before it finished, so whether it did its work is not known. Check, then settle it",
        ),
    }
}

/// How one attempt is being ended: the attempt's own state and words, and where its job goes.
struct Closing<'a> {
    attempt: AttemptState,
    attempt_words: &'a str,
    job: JobState,
    not_before: i64,
    job_note: &'a str,
}

/// Which kind of core work holds a job attempt's room. The core has no kind for a generic job
/// yet, and adding one wants a step in the realm's own schema so that an older build refuses the
/// realm instead of failing to read one row of it. Until then an attempt is recorded under the
/// capability's own kind and told apart by its note, `job:` and the job's identifier, which is how
/// the core already tells a model request and a workspace placement apart.
fn attempt_kind(capability: Capability) -> Kind {
    match capability {
        Capability::Workspaces => Kind::Workspace,
        _ => Kind::Inference,
    }
}

impl Core {
    /// The capability a job's attempts are recorded under, which is also where the trust boundary
    /// is enforced first: a research realm has none to give.
    fn job_capability(&self) -> Result<Capability, JobError> {
        if self.realm.kind == RealmKind::Research || self.realm.can(Capability::Research) {
            return Err(JobError::ResearchRealm);
        }
        [Capability::Models, Capability::Workspaces].into_iter().find(|capability| self.realm.can(*capability)).ok_or(JobError::NoComputers)
    }

    /// Makes sure the jobs tables are there, for a door that writes.
    fn jobs_ready(&self) -> Result<(), JobError> {
        rows::ensure(self.store.connection()).map_err(JobError::from)
    }

    /// Whether this realm has ever had a job, for a door that only reads.
    fn has_jobs(&self) -> Result<bool, JobError> {
        rows::present(self.store.connection()).map_err(JobError::from)
    }

    fn job_or_fail(&self, job_id: &str) -> Result<Job, JobError> {
        if !self.has_jobs()? {
            return Err(JobError::NoSuchJob);
        }
        rows::job(self.store.connection(), &self.realm.id, job_id)?.ok_or(JobError::NoSuchJob)
    }

    fn job_shelf(&self) -> shelf::Shelf {
        shelf::Shelf::beside(self.store.path())
    }

    /// Writes one event about a job, in words chosen here. Every event names the job; the ones a
    /// computer caused name that computer and the core workload holding the attempt's room.
    #[allow(clippy::too_many_arguments)]
    fn note_job(&self, principal_id: &str, action: &str, job: &Job, from: Option<&str>, work: Option<&str>, because: &str, now: i64) -> Result<(), JobError> {
        let mut entry = Entry::new(&self.realm.id, principal_id, action, Decision::Allowed);
        entry = match self.job_capability() {
            Ok(capability) => entry.about(capability, &job.id),
            Err(_) => {
                entry.resource_id = Some(job.id.clone());
                entry
            }
        };
        if let Some(device) = from {
            entry = entry.from(device);
        }
        if let Some(work) = work {
            entry = entry.for_work(work);
        }
        self.note(entry.because(because), now).map_err(JobError::from)
    }

    /// Ends one attempt and moves its job on, in one change: the attempt's row, its reservation in
    /// the realm's ledger, the core workload that held it, and the job. The job moves only if it is
    /// still in the state and under the token the caller read, so an attempt that has been left
    /// behind can never move the job its successor now holds.
    fn close_attempt(&self, job: &Job, attempt: &JobAttempt, closing: Closing<'_>, now: i64) -> Result<Job, JobError> {
        let mut ended = attempt.clone();
        ended.state = closing.attempt;
        ended.ended_at = Some(now);
        ended.ending = closing.attempt_words.to_owned();
        let mut moved = job.clone();
        moved.state = closing.job;
        moved.not_before = closing.not_before;
        moved.note = closing.job_note.to_owned();
        moved.updated_at = now;
        if closing.job == JobState::Queued {
            // A job waiting again has no attempt, so the one that ended can no longer pass for current.
            moved.current_attempt = None;
        }
        if closing.job.finished() {
            moved.finished_at = Some(now);
        }
        let connection = self.store.connection();
        let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
        if !rows::move_attempt(&change, &ended, attempt.state)? {
            return Err(JobError::LeaseLost);
        }
        if let Some(mut lease) = self.store.lease(&attempt.lease_id)? {
            if lease.released_at.is_none() {
                lease.released_at = Some(now);
                Store::write_lease(&change, &lease)?;
            }
        }
        if let Some(mut work) = self.store.workload(&attempt.workload_id)? {
            // The core may already have ended it, by its own sweep or its own cancel; then it stays
            // as the core left it.
            if !work.stage.finished() && work.advance(closing.attempt.stage(), now).is_ok() {
                Store::write_workload(&change, &work)?;
            }
        }
        if !rows::move_job(&change, &moved, job.state, job.fence)? {
            return Err(JobError::Trouble("This job changed at the same moment; ask again".into()));
        }
        change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))?;
        Ok(moved)
    }

    /// The words and event name for where a job went after an attempt ended.
    fn note_job_moved(&self, by: &str, job: &Job, from: Option<&str>, work: Option<&str>, now: i64) -> Result<(), JobError> {
        let action = match job.state {
            JobState::Queued => "job.queued again",
            JobState::Running => "job.running",
            JobState::CancelRequested => "job.cancel requested",
            JobState::Succeeded => "job.succeeded",
            JobState::Failed => "job.failed",
            JobState::Cancelled => "job.cancelled",
            JobState::Stopped => "job.stopped",
            JobState::OutcomeUnknown => "job.outcome unknown",
        };
        self.note_job(by, action, job, from, work, &job.note, now)
    }
}
