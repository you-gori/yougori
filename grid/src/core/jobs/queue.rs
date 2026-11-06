//! The doors a person uses: sending a job, cancelling one, closing and reopening a queue, settling
//! a job whose outcome is unknown, and reading what the queue holds.
use super::{rows, shelf, spec, ArtifactRole, AttemptState, Closing, InFlight, Job, JobArtifact, JobAttempt, JobError, JobQueue, JobSpec, JobState, Settled, Submitted};
use crate::core::{
    audit::{Decision, Entry},
    identity::Action,
    limits::{self, MAX_ATTEMPTS_PER_JOB, MAX_JOB_QUEUES, MAX_QUEUED_JOBS},
    Core,
};
use std::io::Write;

impl Core {
    /// Admits a job into a queue, from one of the sender's own computers.
    ///
    /// The sender needs the permission to place work, which a researcher's role does not include.
    /// Sending the same work again under the same deduplication key finds the job already admitted
    /// and makes nothing new, so a sender who lost the answer can simply ask again.
    pub fn submit_job(&mut self, by: &str, device_id: &str, queue: &str, spec: JobSpec, now: i64) -> Result<Submitted, JobError> {
        if let Err(refused) = self.job_capability() {
            if refused == JobError::ResearchRealm {
                self.note_refused_job(by, now);
            }
            return Err(refused);
        }
        if !self.realm.lifecycle.serves() {
            return Err(JobError::NotServing);
        }
        let person = self.person(by).map_err(JobError::NotAllowed)?;
        if !person.active() {
            return Err(JobError::NotAllowed("This account is suspended".into()));
        }
        if !person.may(Action::PlaceWork) {
            return Err(JobError::NotAllowed(format!("{} may not place work here", person.name)));
        }
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or_else(|| JobError::NotAllowed("This computer is not in this grid".into()))?;
        if device.principal_id != person.id {
            return Err(JobError::NotAllowed("That computer belongs to someone else".into()));
        }
        let queue = spec::queue_name(queue)?;
        let spec = spec.checked()?;
        self.jobs_ready()?;
        let connection = self.store.connection();
        if let Some(key) = spec.side_effects.key() {
            if let Some(admitted) = rows::job_by_key(connection, &self.realm.id, key)? {
                if admitted.spec == spec && admitted.queue == queue && admitted.principal_id == person.id {
                    return Ok(Submitted { job: admitted, replayed: true });
                }
                return Err(JobError::DuplicateKey);
            }
        }
        if let Some(closed) = rows::queue(connection, &self.realm.id, &queue)?.filter(|found| !found.open) {
            return Err(JobError::QueueClosed { queue, reason: closed.reason });
        }
        if rows::unfinished_jobs(connection, &self.realm.id)? >= MAX_QUEUED_JOBS {
            return Err(JobError::Limit(limits::reached("jobs that have not finished", MAX_QUEUED_JOBS)));
        }
        for input in &spec.inputs {
            self.finished_output(&input.artifact_id)?;
        }
        let job = Job {
            id: format!("job-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            queue,
            principal_id: person.id.clone(),
            device_id: device.id.clone(),
            spec,
            state: JobState::Queued,
            attempts: 0,
            fence: 0,
            current_attempt: None,
            checkpoint: None,
            not_before: now,
            note: "Waiting for a computer with room".into(),
            created_at: now,
            updated_at: now,
            finished_at: None,
        };
        rows::insert_job(connection, &job)?;
        let because = format!("into the queue {}; its effects outside the grid are {}", job.queue, job.spec.side_effects.word());
        self.note_job(&person.id, "job.queued", &job, Some(&device.id), None, &because, now)?;
        Ok(Submitted { job, replayed: false })
    }

    /// A research realm is told about a generic job somebody tried to send it, when the somebody is
    /// one of its own. A stranger's name is not written into the history on the strength of asking.
    fn note_refused_job(&self, by: &str, now: i64) {
        let known = by == "owner" || self.store.principal(by).ok().flatten().is_some();
        if known {
            let _ = self.note(Entry::new(&self.realm.id, by, "job.refused", Decision::Refused).because("a research grid does not run generic jobs"), now);
        }
    }

    /// An artifact a new job may read: an output of a job that succeeded, sent by the attempt whose
    /// end decided it.
    fn finished_output(&self, artifact_id: &str) -> Result<JobArtifact, JobError> {
        let connection = self.store.connection();
        let artifact = rows::artifact(connection, &self.realm.id, artifact_id)?.ok_or(JobError::NoSuchArtifact)?;
        if artifact.removed_at.is_some() {
            return Err(JobError::ArtifactRemoved);
        }
        let producer = rows::job(connection, &self.realm.id, &artifact.job_id)?.ok_or(JobError::InputNotReady)?;
        let finished = producer.state == JobState::Succeeded && producer.current_attempt.as_deref() == Some(artifact.attempt_id.as_str());
        if artifact.role != ArtifactRole::Output || !finished {
            return Err(JobError::InputNotReady);
        }
        Ok(artifact)
    }

    /// Cancels a job, or asks it to stop when an attempt is already running it.
    ///
    /// A job nothing has started is cancelled at once, and so is one whose computer has been given
    /// it but has not begun: that computer's next step is refused. A job that is running is asked
    /// to stop, its computer hears so on its next heartbeat, and it is stopped once that computer
    /// says it has. The person who sent it may cancel it, and so may anyone who may place work.
    pub fn cancel_job(&mut self, by: &str, job_id: &str, now: i64) -> Result<JobState, JobError> {
        let job = self.job_or_fail(job_id)?;
        if by != job.principal_id {
            self.allowed(by, Action::PlaceWork).map_err(JobError::NotAllowed)?;
        }
        let why = if by == job.principal_id {
            "cancelled by the person who sent it".to_owned()
        } else {
            format!("cancelled by {}", self.person(by).map(|person| person.name).unwrap_or_else(|_| "the grid's owner".to_owned()))
        };
        self.ask_to_stop(by, job, &why, now)
    }

    /// The one cancel for jobs, behind both a person cancelling and a queue closing with `Stop`.
    fn ask_to_stop(&mut self, by: &str, job: Job, why: &str, now: i64) -> Result<JobState, JobError> {
        match job.state {
            JobState::CancelRequested => Ok(JobState::CancelRequested),
            JobState::OutcomeUnknown => Err(JobError::AwaitingSettlement),
            state if state.finished() => Err(JobError::Finished),
            JobState::Queued => {
                let mut moved = job.clone();
                moved.state = JobState::Cancelled;
                moved.note = "It was cancelled before it started".into();
                moved.updated_at = now;
                moved.finished_at = Some(now);
                if !rows::move_job(self.store.connection(), &moved, JobState::Queued, job.fence)? {
                    return Err(JobError::Trouble("This job changed at the same moment; ask again".into()));
                }
                self.note_job(by, "job.cancelled", &moved, None, None, why, now)?;
                Ok(moved.state)
            }
            _ => {
                let attempt = self.current_attempt_of(&job)?;
                if attempt.state == AttemptState::Leased {
                    let closing = Closing {
                        attempt: AttemptState::Cancelled,
                        attempt_words: "cancelled before it started",
                        job: JobState::Cancelled,
                        not_before: job.not_before,
                        job_note: "It was cancelled before it started",
                    };
                    let moved = self.close_attempt(&job, &attempt, closing, now)?;
                    self.note_job(by, "job.cancelled", &moved, None, Some(&attempt.workload_id), why, now)?;
                    return Ok(moved.state);
                }
                let mut moved = job.clone();
                moved.state = JobState::CancelRequested;
                moved.note = "Asked to stop; waiting for its computer to say that it has".into();
                moved.updated_at = now;
                if !rows::move_job(self.store.connection(), &moved, JobState::Running, job.fence)? {
                    return Err(JobError::Trouble("This job changed at the same moment; ask again".into()));
                }
                self.note_job(by, "job.cancel requested", &moved, None, Some(&attempt.workload_id), why, now)?;
                Ok(moved.state)
            }
        }
    }

    /// The attempt a running job names, which a running job always has.
    pub(super) fn current_attempt_of(&self, job: &Job) -> Result<JobAttempt, JobError> {
        let attempt_id = job.current_attempt.as_deref().ok_or(JobError::NoSuchAttempt)?;
        rows::attempt(self.store.connection(), &self.realm.id, attempt_id)?.ok_or(JobError::NoSuchAttempt)
    }

    /// Stops a queue admitting work, for a spent budget or any other reason, and says what happens
    /// to the attempts already running in it.
    ///
    /// New jobs are refused with `reason` in the refusal, and no job waiting in the queue is given
    /// a computer, retries included, until it is reopened. `in_flight` has no default because it is
    /// the decision that matters: `Finish` lets running attempts end and keeps what they send;
    /// `Stop` asks each of them to stop exactly as a cancel does. Neither kills anything.
    pub fn close_job_admission(&mut self, by: &str, queue: &str, in_flight: InFlight, reason: &str, now: i64) -> Result<JobQueue, JobError> {
        self.job_capability()?;
        self.allowed(by, Action::PlaceWork).map_err(JobError::NotAllowed)?;
        let name = spec::queue_name(queue)?;
        let reason: String = reason.chars().filter(|letter| !letter.is_control()).take(200).collect::<String>().trim().to_owned();
        let reason = if spec::carries_a_secret(&reason) { "withheld: this reason looked like a value".to_owned() } else { reason };
        self.jobs_ready()?;
        let connection = self.store.connection();
        if rows::queue(connection, &self.realm.id, &name)?.is_none() && rows::queue_count(connection, &self.realm.id)? >= MAX_JOB_QUEUES {
            return Err(JobError::Limit(limits::reached("job queues whose admission has been set", MAX_JOB_QUEUES)));
        }
        let closed = JobQueue { name: name.clone(), open: false, in_flight: Some(in_flight), reason: reason.clone(), changed_by: by.to_owned(), changed_at: now };
        rows::put_queue(connection, &self.realm.id, &closed)?;
        let said = if reason.is_empty() { in_flight.word().to_owned() } else { format!("{}: {reason}", in_flight.word()) };
        let mut entry = Entry::new(&self.realm.id, by, "jobs.admission closed", Decision::Allowed).because(&format!("queue {name}; running attempts {said}"));
        entry.resource_id = Some(name.clone());
        self.note(entry, now)?;
        if in_flight == InFlight::Stop {
            let why = "its queue stopped admitting work and asked running jobs to stop";
            for job in rows::running_in(self.store.connection(), &self.realm.id, &name)? {
                self.ask_to_stop(by, job, why, now)?;
            }
        }
        Ok(closed)
    }

    /// Lets a queue admit work again. Jobs that waited while it was closed are given computers in
    /// the order they arrived. A queue nobody closed is already open, and nothing is written for it.
    pub fn reopen_job_admission(&mut self, by: &str, queue: &str, now: i64) -> Result<JobQueue, JobError> {
        self.job_capability()?;
        self.allowed(by, Action::PlaceWork).map_err(JobError::NotAllowed)?;
        let name = spec::queue_name(queue)?;
        let set = self.has_jobs()? && rows::queue(self.store.connection(), &self.realm.id, &name)?.is_some();
        if !set {
            return self.job_queue(&name);
        }
        self.jobs_ready()?;
        let open = JobQueue { name: name.clone(), open: true, in_flight: None, reason: String::new(), changed_by: by.to_owned(), changed_at: now };
        rows::put_queue(self.store.connection(), &self.realm.id, &open)?;
        let mut entry = Entry::new(&self.realm.id, by, "jobs.admission reopened", Decision::Allowed).because(&format!("queue {name}"));
        entry.resource_id = Some(name);
        self.note(entry, now)?;
        Ok(open)
    }

    /// Whether a queue admits work. A queue nobody has closed does.
    pub fn job_queue(&self, queue: &str) -> Result<JobQueue, JobError> {
        let name = spec::queue_name(queue)?;
        let found = if self.has_jobs()? { rows::queue(self.store.connection(), &self.realm.id, &name)? } else { None };
        Ok(found.unwrap_or(JobQueue { name, open: true, in_flight: None, reason: String::new(), changed_by: String::new(), changed_at: 0 }))
    }

    /// Settles a job whose outcome is unknown, after somebody checked what it did.
    ///
    /// This is the manual reconciliation a job with unrepeatable effects needs. Running it again is
    /// a person's decision, recorded with their name, and it is still held to the bound on attempts.
    /// A job settled as having done its work keeps what its last attempt sent as its outputs, which
    /// may not be every output it declared; nothing is added on its behalf.
    pub fn settle_job(&mut self, by: &str, job_id: &str, settled: Settled, now: i64) -> Result<JobState, JobError> {
        let job = self.job_or_fail(job_id)?;
        if by != job.principal_id {
            self.allowed(by, Action::PlaceWork).map_err(JobError::NotAllowed)?;
        }
        if job.state != JobState::OutcomeUnknown {
            return Err(JobError::NotUnknown);
        }
        let mut moved = job.clone();
        moved.updated_at = now;
        let who = if by == job.principal_id {
            "the person who sent it".to_owned()
        } else {
            self.person(by).map(|person| person.name).unwrap_or_else(|_| "the grid's owner".to_owned())
        };
        let (state, note) = match settled {
            Settled::Succeeded => (JobState::Succeeded, format!("Settled by hand: {who} found that it did its work")),
            Settled::Failed => (JobState::Failed, format!("Settled by hand: {who} found that it did not do its work")),
            Settled::RunAgain => {
                if job.attempts >= MAX_ATTEMPTS_PER_JOB {
                    return Err(JobError::Limit(format!("A job can have at most {MAX_ATTEMPTS_PER_JOB} attempts")));
                }
                (JobState::Queued, format!("Waiting to run again: {who} decided it should"))
            }
        };
        moved.state = state;
        moved.note = note.chars().take(300).collect();
        moved.not_before = now;
        if state == JobState::Queued {
            moved.current_attempt = None;
        }
        if state.finished() {
            moved.finished_at = Some(now);
        }
        if !rows::move_job(self.store.connection(), &moved, JobState::OutcomeUnknown, job.fence)? {
            return Err(JobError::Trouble("This job changed at the same moment; ask again".into()));
        }
        self.note_job(by, "job.settled", &moved, None, None, &moved.note, now)?;
        Ok(moved.state)
    }

    // ---- Reading ----

    /// One job, as it stands.
    pub fn job(&self, job_id: &str) -> Result<Option<Job>, JobError> {
        if !self.has_jobs()? {
            return Ok(None);
        }
        Ok(rows::job(self.store.connection(), &self.realm.id, job_id)?)
    }

    /// Every job in the realm, in the order they arrived.
    pub fn jobs(&self) -> Result<Vec<Job>, JobError> {
        if !self.has_jobs()? {
            return Ok(Vec::new());
        }
        Ok(rows::jobs(self.store.connection(), &self.realm.id)?)
    }

    /// Every attempt a job has had, first to last.
    pub fn job_attempts(&self, job_id: &str) -> Result<Vec<JobAttempt>, JobError> {
        let job = self.job_or_fail(job_id)?;
        Ok(rows::attempts_of(self.store.connection(), &job.id)?)
    }

    /// Every artifact any of a job's attempts sent, each tied to the attempt and token that sent it.
    pub fn job_artifacts(&self, job_id: &str) -> Result<Vec<JobArtifact>, JobError> {
        let job = self.job_or_fail(job_id)?;
        Ok(rows::artifacts_of_job(self.store.connection(), &job.id)?)
    }

    /// A succeeded job's outputs: what the attempt that decided it sent, and nothing any other
    /// attempt did. Nothing at all for a job that has not succeeded.
    pub fn job_outputs(&self, job_id: &str) -> Result<Vec<JobArtifact>, JobError> {
        let job = self.job_or_fail(job_id)?;
        let Some(attempt_id) = job.current_attempt.as_deref().filter(|_| job.state == JobState::Succeeded) else { return Ok(Vec::new()) };
        Ok(rows::artifacts_of_attempt(self.store.connection(), attempt_id)?.into_iter().filter(|artifact| artifact.role == ArtifactRole::Output).collect())
    }

    /// Writes an artifact's bytes into `into`, checking them against their checksum on the way.
    ///
    /// The person who sent the job may read what it made, and so may anyone who may place work. If
    /// this refuses after writing, what was written is not the artifact and must be discarded.
    pub fn read_job_artifact(&self, by: &str, artifact_id: &str, into: &mut dyn Write) -> Result<u64, JobError> {
        if !self.has_jobs()? {
            return Err(JobError::NoSuchArtifact);
        }
        let connection = self.store.connection();
        let artifact = rows::artifact(connection, &self.realm.id, artifact_id)?.ok_or(JobError::NoSuchArtifact)?;
        let job = rows::job(connection, &self.realm.id, &artifact.job_id)?.ok_or(JobError::NoSuchJob)?;
        if by != job.principal_id {
            self.allowed(by, Action::PlaceWork).map_err(JobError::NotAllowed)?;
        }
        if artifact.removed_at.is_some() {
            return Err(JobError::ArtifactRemoved);
        }
        self.job_shelf().send(artifact.bytes, &artifact.sha256, into).map_err(|refusal| from_shelf(refusal, artifact.bytes))
    }

    /// Why a waiting job has not been given a computer yet, in words somebody can act on, or
    /// nothing when it is not waiting.
    pub fn why_job_waits(&self, job_id: &str, now: i64) -> Result<Option<String>, JobError> {
        let job = self.job_or_fail(job_id)?;
        if job.state != JobState::Queued {
            return Ok(None);
        }
        if let Some(closed) = rows::queue(self.store.connection(), &self.realm.id, &job.queue)?.filter(|queue| !queue.open) {
            return Ok(Some(if closed.reason.is_empty() {
                format!("Its queue, {}, is not admitting work just now", job.queue)
            } else {
                format!("Its queue, {}, is not admitting work just now: {}", job.queue, closed.reason)
            }));
        }
        if !self.realm.lifecycle.serves() {
            return Ok(Some("This grid is not serving work at the moment".into()));
        }
        if job.not_before > now {
            return Ok(Some(format!("It waits {} more seconds before it is tried again", job.not_before - now)));
        }
        if !self.store.principal(&job.principal_id)?.is_some_and(|person| person.active()) {
            return Ok(Some("The account that sent it is suspended".into()));
        }
        let still_here = self.store.active_devices()?;
        let taking: Vec<_> = self.store.hosts()?.into_iter().filter(|host| host.takes_work() && still_here.contains(&host.device_id)).collect();
        if taking.is_empty() {
            return Ok(Some("No computer in this grid is taking work right now".into()));
        }
        if !taking.iter().any(|host| host.offered.covers(&job.spec.needs)) {
            let needs = job.spec.needs;
            return Ok(Some(format!(
                "No computer in this grid offers enough for it: it needs {} CPUs, {} GB of memory and {} GB of disk{}",
                needs.cpu,
                needs.memory_gb,
                needs.disk_gb,
                if needs.gpu { format!(", and a GPU with {} GB of video memory", needs.vram_gb) } else { String::new() }
            )));
        }
        Ok(Some("Waiting for a computer with room".into()))
    }
}

/// What a refusal from the shelf means to whoever asked, for an artifact declared as `declared` bytes.
pub(super) fn from_shelf(refusal: shelf::Refusal, declared: u64) -> JobError {
    match refusal {
        shelf::Refusal::Mismatch => JobError::ChecksumMismatch,
        shelf::Refusal::Short(arrived) => JobError::SizeMismatch { declared, arrived: Some(arrived) },
        shelf::Refusal::Long => JobError::SizeMismatch { declared, arrived: None },
        shelf::Refusal::Damaged => JobError::Damaged,
        shelf::Refusal::Missing => JobError::Trouble("This artifact's bytes are no longer on this computer".into()),
        shelf::Refusal::Trouble(why) => JobError::Trouble(why),
    }
}
