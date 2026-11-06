//! The doors a computer uses: asking for a job, starting it, keeping its reservation alive, sending
//! what it made and saying how it ended; and the sweep that notices a computer that went quiet.
//!
//! Every door after the first is keyed on the attempt and its fencing token, and goes through
//! `holding` before it does anything, so a computer the job has moved on from is refused at its
//! first step whatever it sends.
use super::{
    attempt_kind, next_after,
    queue::from_shelf,
    rows,
    shelf::{Refusal, Shelf},
    spec, ArtifactRole, AttemptState, Beat, Closing, Ended, Ending, Job, JobArtifact, JobAttempt, JobError, JobLease, JobState, LeasedInput,
};
use crate::core::{
    limits::{self, MAX_ARTIFACTS_PER_ATTEMPT, MAX_ARTIFACT_BYTES, MAX_ATTEMPTS_PER_JOB, MAX_LEASE_SECONDS, MIN_LEASE_SECONDS},
    realm::Capability,
    store::{room, Store},
    work::{Commitment, Host, Lease, Stage, Workload},
    workspace, Core,
};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Leave to send one artifact for one attempt, given before a byte of it is sent.
///
/// It carries everything needed to stage the bytes without the realm: where they go, what they
/// must add up to, and which attempt and token they will be recorded under. Staging takes no lock
/// on anything but the one file it writes.
#[derive(Debug)]
pub struct ArtifactTicket {
    folder: PathBuf,
    device_id: String,
    attempt_id: String,
    fence: u64,
    role: ArtifactRole,
    name: String,
    bytes: u64,
    sha256: String,
}

impl ArtifactTicket {
    /// Streams the bytes into the staging folder, counting and hashing as they arrive, and checks
    /// them against what was declared. Needs nothing from the realm, so a large upload never holds
    /// it. Nothing is recorded until `Core::record_job_artifact` takes what this returns.
    pub fn stage(self, data: &mut dyn Read) -> Result<StagedArtifact, JobError> {
        let path = Shelf::at(self.folder.clone()).stage(self.bytes, &self.sha256, data).map_err(|refusal| from_shelf(refusal, self.bytes))?;
        Ok(StagedArtifact { ticket: self, path, kept: false })
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Bytes that arrived whole and matched their checksum, waiting to be recorded. Dropped without
/// being recorded, they are removed; a process that stopped before either leaves them for the jobs
/// sweep, which removes them once nothing has been written to them for a while.
#[derive(Debug)]
pub struct StagedArtifact {
    ticket: ArtifactTicket,
    path: PathBuf,
    kept: bool,
}

impl StagedArtifact {
    pub fn ticket(&self) -> &ArtifactTicket {
        &self.ticket
    }
}

impl Drop for StagedArtifact {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Core {
    /// Gives the computer behind `device_id` the oldest waiting job it has room for, as a new
    /// attempt holding `seconds` of reservation, or nothing when no job fits.
    ///
    /// The computer must be in the grid and taking work: not being emptied, not committed to
    /// nothing, within whatever its person agreed, and showing whatever the realm demands. Room is
    /// what it offered less every reservation on it in the realm's one ledger, whichever profile
    /// holds them, and a card that cannot be shared is never given to two pieces of work at once.
    /// Attempts whose reservations have ended are settled first, so a job whose computer went
    /// quiet is waiting again before anything new is handed out.
    pub fn lease_job(&mut self, device_id: &str, seconds: i64, now: i64) -> Result<Option<JobLease>, JobError> {
        let capability = self.job_capability()?;
        if !self.realm.lifecycle.serves() {
            return Err(JobError::NotServing);
        }
        let host = self.job_worker(device_id, now)?;
        // A realm that has never had a job has nothing to hand out, and a computer asking is not a
        // reason to make the tables.
        if !self.has_jobs()? {
            return Ok(None);
        }
        self.jobs_ready()?;
        self.settle_lapsed(now)?;
        if self.store.unfinished_count()? >= limits::MAX_UNFINISHED_WORK {
            return Err(JobError::Limit(limits::reached("pieces of work in flight at once", limits::MAX_UNFINISHED_WORK)));
        }
        let mut free = host.offered;
        let mut card_held = false;
        for taken in self.store.reserved_on(&host.id, now)? {
            free = free.less(&taken);
            card_held |= taken.gpu;
        }
        let card_taken = card_held && !host.gpu_isolation.shareable();
        let connection = self.store.connection();
        let closed = rows::closed_queues(connection, &self.realm.id)?;
        let mut chosen = None;
        for job in rows::waiting_jobs(connection, &self.realm.id, now)? {
            if closed.contains(&job.queue) || job.attempts >= job.spec.retry.max_attempts.min(MAX_ATTEMPTS_PER_JOB) {
                continue;
            }
            if !free.covers(&job.spec.needs) || (job.spec.needs.gpu && card_taken) {
                continue;
            }
            if !self.store.principal(&job.principal_id)?.is_some_and(|person| person.active()) {
                continue;
            }
            chosen = Some(job);
            break;
        }
        let Some(job) = chosen else { return Ok(None) };
        self.give_attempt(job, &host, device_id, capability, seconds, now).map(Some)
    }

    /// The computer behind `device_id`, when it may be given new work now.
    fn job_worker(&self, device_id: &str, now: i64) -> Result<Host, JobError> {
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or(JobError::NotAWorker)?;
        let host = self.store.host_of_device(&device.id)?.ok_or(JobError::NotAWorker)?;
        if host.draining {
            return Err(JobError::Draining);
        }
        if host.commitment == Commitment::None {
            return Err(JobError::HostRefused("this computer contributes nothing to the grid".into()));
        }
        // Its person's own terms, where they agreed any: a standing commitment, held to the same
        // rules a workspace is, including what the computer last said about itself.
        if let Some(pledge) = self.store.standing_pledge(&host.id)? {
            if let Some(why) = workspace::may_take(Some(&pledge), self.store.condition(&host.id)?.as_ref()) {
                return Err(JobError::HostRefused(why.into()));
            }
        }
        // And whatever the realm demands a computer shows about itself.
        if let Some(why) = self.may_host(&host.id, now)? {
            return Err(JobError::HostRefused(why));
        }
        Ok(host)
    }

    /// Makes the next attempt at `job` on `host`: the core workload and reservation that hold its
    /// room in the realm's ledger, the attempt under the job's next fencing token, and the job, in
    /// one change. What the computer is handed is worked out before the change commits.
    fn give_attempt(&mut self, job: Job, host: &Host, device_id: &str, capability: Capability, seconds: i64, now: i64) -> Result<JobLease, JobError> {
        let number = job.attempts + 1;
        let fence = job.fence + 1;
        let deadline = now.saturating_add(job.spec.timeout_seconds);
        let expires_at = now.saturating_add(seconds.clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS)).min(deadline);
        let mut work = Workload::new(&self.realm.id, capability, attempt_kind(capability), &job.principal_id, &job.device_id, job.spec.needs, self.store.policy_version()?, now);
        work.note = Some(format!("job:{}", job.id));
        work.expires_at = Some(deadline);
        work.advance(Stage::Validating, now)?;
        work.advance(Stage::Queued, now)?;
        let lease = Lease {
            id: format!("lease-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            host_id: host.id.clone(),
            workload_id: work.id.clone(),
            resources: job.spec.needs,
            // The reservation's generation is the attempt's token, so the two can never disagree
            // about which attempt holds the room.
            generation: fence,
            granted_at: now,
            expires_at,
            released_at: None,
        };
        work.lease_id = Some(lease.id.clone());
        work.advance(Stage::Leased, now)?;
        let attempt = JobAttempt {
            id: format!("attempt-{}", &crate::token()[..16]),
            job_id: job.id.clone(),
            number,
            fence,
            host_id: host.id.clone(),
            device_id: device_id.to_owned(),
            workload_id: work.id.clone(),
            lease_id: lease.id.clone(),
            state: AttemptState::Leased,
            granted_at: now,
            started_at: None,
            heartbeat_at: now,
            expires_at,
            deadline,
            ended_at: None,
            ending: String::new(),
        };
        let mut moved = job.clone();
        moved.state = JobState::Running;
        moved.attempts = number;
        moved.fence = fence;
        moved.current_attempt = Some(attempt.id.clone());
        moved.note = "An attempt holds a computer for it".into();
        moved.updated_at = now;
        let handed = self.lease_for(&moved, &attempt)?;
        {
            let connection = self.store.connection();
            let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
            Store::write_workload(&change, &work)?;
            Store::write_lease(&change, &lease)?;
            rows::insert_attempt(&change, &self.realm.id, &attempt)?;
            if !rows::move_job(&change, &moved, JobState::Queued, job.fence)? {
                return Err(JobError::Trouble("This job was given to another computer at the same moment; ask again".into()));
            }
            change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))?;
        }
        let because = format!("attempt {number} of at most {}", moved.spec.retry.max_attempts.min(MAX_ATTEMPTS_PER_JOB));
        self.note_job(&job.principal_id, "job.leased", &moved, Some(device_id), Some(&work.id), &because, now)?;
        Ok(handed)
    }

    /// What a computer is handed with an attempt.
    fn lease_for(&self, job: &Job, attempt: &JobAttempt) -> Result<JobLease, JobError> {
        let connection = self.store.connection();
        let mut inputs = Vec::with_capacity(job.spec.inputs.len());
        for input in &job.spec.inputs {
            let artifact = rows::artifact(connection, &self.realm.id, &input.artifact_id)?.ok_or(JobError::NoSuchArtifact)?;
            inputs.push(LeasedInput { name: input.name.clone(), artifact_id: artifact.id, bytes: artifact.bytes, sha256: artifact.sha256 });
        }
        let resume_from = match job.checkpoint.as_deref().filter(|_| job.spec.checkpoints) {
            Some(checkpoint) => rows::artifact(connection, &self.realm.id, checkpoint)?.map(|artifact| LeasedInput {
                name: artifact.name,
                artifact_id: artifact.id,
                bytes: artifact.bytes,
                sha256: artifact.sha256,
            }),
            None => None,
        };
        Ok(JobLease {
            job_id: job.id.clone(),
            attempt_id: attempt.id.clone(),
            number: attempt.number,
            fence: attempt.fence,
            entrypoint: job.spec.entrypoint.clone(),
            inputs,
            outputs: job.spec.outputs.clone(),
            needs: job.spec.needs,
            dedup_key: job.spec.side_effects.key().map(str::to_owned),
            resume_from,
            expires_at: attempt.expires_at,
            deadline: attempt.deadline,
        })
    }

    /// The attempt a computer is acting on, when that computer may still act on it: the job's
    /// current attempt under the token presented, held by this computer, which is still in the
    /// grid, with its reservation still standing in the realm's ledger.
    ///
    /// Fencing is asked first, so an attempt the job has moved on from is refused as exactly that,
    /// whatever else is true of it. Nothing is recorded for a refusal here: a computer that was left
    /// behind and keeps knocking is not something the history needs a row for each time.
    fn holding(&self, device_id: &str, attempt_id: &str, fence: u64, now: i64) -> Result<(Job, JobAttempt, Lease), JobError> {
        if !self.has_jobs()? {
            return Err(JobError::NoSuchAttempt);
        }
        let connection = self.store.connection();
        let attempt = rows::attempt(connection, &self.realm.id, attempt_id)?.ok_or(JobError::NoSuchAttempt)?;
        let job = rows::job(connection, &self.realm.id, &attempt.job_id)?.ok_or(JobError::NoSuchJob)?;
        if job.current_attempt.as_deref() != Some(attempt.id.as_str()) || job.fence != fence || attempt.fence != fence {
            return Err(JobError::StaleFence);
        }
        if attempt.device_id != device_id {
            return Err(JobError::WrongComputer);
        }
        if !self.store.device(device_id)?.is_some_and(|device| device.active()) {
            return Err(JobError::NotAWorker);
        }
        if !attempt.state.live() || !matches!(job.state, JobState::Running | JobState::CancelRequested) {
            return Err(JobError::LeaseLost);
        }
        let lease = self.store.lease(&attempt.lease_id)?.filter(|lease| lease.holds(now)).ok_or(JobError::LeaseLost)?;
        Ok((job, attempt, lease))
    }

    /// The computer's word that it is starting an attempt, and the realm's go-ahead.
    ///
    /// A computer does nothing the job does outside the grid until this has answered. That is what
    /// makes an attempt that was handed out and never started safe to place again: until it
    /// started, it did nothing. Asking twice is harmless.
    pub fn start_job_attempt(&mut self, device_id: &str, attempt_id: &str, fence: u64, now: i64) -> Result<JobAttempt, JobError> {
        let (job, attempt, _) = self.holding(device_id, attempt_id, fence, now)?;
        if attempt.state == AttemptState::Running {
            return Ok(attempt);
        }
        if job.state != JobState::Running {
            return Err(JobError::StopRequested);
        }
        let mut started = attempt.clone();
        started.state = AttemptState::Running;
        started.started_at = Some(now);
        started.heartbeat_at = now;
        {
            let connection = self.store.connection();
            let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
            if !rows::move_attempt(&change, &started, AttemptState::Leased)? {
                return Err(JobError::LeaseLost);
            }
            if let Some(mut work) = self.store.workload(&attempt.workload_id)? {
                for next in [Stage::Preparing, Stage::Running] {
                    if work.stage.may_become(next) {
                        work.advance(next, now)?;
                    }
                }
                Store::write_workload(&change, &work)?;
            }
            change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))?;
        }
        self.note_job(&job.principal_id, "job.started", &job, Some(device_id), Some(&attempt.workload_id), &format!("attempt {} started", attempt.number), now)?;
        Ok(started)
    }

    /// Keeps an attempt's reservation standing, and tells its computer whether somebody asked the
    /// job to stop. The reservation is renewed for `seconds`, within the bounds, and never past the
    /// attempt's deadline. A heartbeat is not an event in the history.
    pub fn heartbeat_job(&mut self, device_id: &str, attempt_id: &str, fence: u64, seconds: i64, now: i64) -> Result<Beat, JobError> {
        let (job, attempt, mut lease) = self.holding(device_id, attempt_id, fence, now)?;
        let expires_at = now.saturating_add(seconds.clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS)).min(attempt.deadline);
        let mut renewed = attempt.clone();
        renewed.heartbeat_at = now;
        renewed.expires_at = expires_at;
        lease.expires_at = expires_at;
        {
            let connection = self.store.connection();
            let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
            if !rows::move_attempt(&change, &renewed, attempt.state)? {
                return Err(JobError::LeaseLost);
            }
            Store::write_lease(&change, &lease)?;
            change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))?;
        }
        Ok(Beat { expires_at, deadline: attempt.deadline, stop_requested: job.state == JobState::CancelRequested })
    }

    /// Leave to send one of the job's declared outputs, asked for before a byte of it is sent.
    ///
    /// Everything that can be refused without the bytes is refused here: an attempt the job has
    /// moved on from, one that has not started, a name the job never declared, a size past the
    /// bound, a checksum that is not one, an attempt that has sent all it may, a disk without room.
    /// The bytes are then staged with `ArtifactTicket::stage`, which needs nothing from the realm,
    /// and recorded with `record_job_artifact`, which asks the fencing question again.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_job_output(&self, device_id: &str, attempt_id: &str, fence: u64, name: &str, bytes: u64, sha256: &str, now: i64) -> Result<ArtifactTicket, JobError> {
        self.prepare_artifact(device_id, attempt_id, fence, ArtifactRole::Output, name, bytes, sha256, now)
    }

    /// Leave to send a checkpoint, for a job that said it can resume from one. The newest
    /// checkpoint recorded is what the job's next attempt is handed.
    pub fn prepare_job_checkpoint(&self, device_id: &str, attempt_id: &str, fence: u64, bytes: u64, sha256: &str, now: i64) -> Result<ArtifactTicket, JobError> {
        self.prepare_artifact(device_id, attempt_id, fence, ArtifactRole::Checkpoint, "checkpoint", bytes, sha256, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_artifact(&self, device_id: &str, attempt_id: &str, fence: u64, role: ArtifactRole, name: &str, bytes: u64, sha256: &str, now: i64) -> Result<ArtifactTicket, JobError> {
        let (job, attempt, _) = self.holding(device_id, attempt_id, fence, now)?;
        let (name, sha256, _) = self.artifact_may_come(&job, &attempt, role, name, bytes, sha256)?;
        let shelf = self.job_shelf();
        room::enough_for(shelf.folder(), bytes, "for this artifact")?;
        Ok(ArtifactTicket { folder: shelf.folder().to_owned(), device_id: device_id.to_owned(), attempt_id: attempt.id, fence, role, name, bytes, sha256 })
    }

    /// What an artifact has to pass both before it is sent and when it is recorded. Answers its
    /// name and checksum as they are recorded, and the record already made when this is the same
    /// output sent again, as a computer does when it never heard the answer.
    fn artifact_may_come(&self, job: &Job, attempt: &JobAttempt, role: ArtifactRole, name: &str, bytes: u64, sha256: &str) -> Result<(String, String, Option<JobArtifact>), JobError> {
        if attempt.state != AttemptState::Running {
            return Err(JobError::NotStarted);
        }
        let name = spec::logical_name(name, "An output")?;
        match role {
            ArtifactRole::Output if !job.spec.outputs.contains(&name) => return Err(JobError::UndeclaredOutput(spec::shown(&name))),
            ArtifactRole::Checkpoint if !job.spec.checkpoints => return Err(JobError::NoCheckpoints),
            _ => {}
        }
        if bytes > MAX_ARTIFACT_BYTES {
            return Err(JobError::Limit(format!("An artifact can be at most {MAX_ARTIFACT_BYTES} bytes, which is one gigabyte")));
        }
        let sha256 = checksum(sha256)?;
        let sent = rows::artifacts_of_attempt(self.store.connection(), &attempt.id)?;
        if role == ArtifactRole::Output {
            if let Some(earlier) = sent.iter().find(|artifact| artifact.role == ArtifactRole::Output && artifact.name == name) {
                if earlier.sha256 == sha256 && earlier.bytes == bytes {
                    return Ok((name, sha256, Some(earlier.clone())));
                }
                return Err(JobError::OutputAlreadySent(spec::shown(&name)));
            }
        }
        if sent.len() >= MAX_ARTIFACTS_PER_ATTEMPT {
            return Err(JobError::Limit(format!("One attempt can send at most {MAX_ARTIFACTS_PER_ATTEMPT} artifacts")));
        }
        Ok((name, sha256, None))
    }

    /// Records bytes that were staged without the realm, under the attempt and token they were
    /// sent for. The realm is taken only for this, never for the upload itself.
    ///
    /// The fencing question is asked again here and once more by the statement that writes, so
    /// bytes staged for an attempt that has since been replaced are refused and removed, and
    /// nothing of them is kept. The same output staged twice finds the record made the first time.
    pub fn record_job_artifact(&mut self, staged: StagedArtifact, now: i64) -> Result<JobArtifact, JobError> {
        let mut staged = staged;
        let device_id = staged.ticket.device_id.clone();
        let attempt_id = staged.ticket.attempt_id.clone();
        let fence = staged.ticket.fence;
        let role = staged.ticket.role;
        let bytes = staged.ticket.bytes;
        let (job, attempt, _) = self.holding(&device_id, &attempt_id, fence, now)?;
        let (name, sha256, earlier) = self.artifact_may_come(&job, &attempt, role, &staged.ticket.name, bytes, &staged.ticket.sha256)?;
        if let Some(earlier) = earlier {
            return Ok(earlier);
        }
        let shelf = self.job_shelf();
        let made = shelf.keep_staged(&staged.path, &sha256).map_err(|refusal| match refusal {
            Refusal::Missing => JobError::StagedGone,
            other => from_shelf(other, bytes),
        })?;
        staged.kept = true;
        let artifact = JobArtifact {
            id: format!("artifact-{}", &crate::token()[..16]),
            job_id: job.id.clone(),
            attempt_id: attempt.id.clone(),
            fence,
            role,
            name,
            bytes,
            sha256,
            recorded_at: now,
            removed_at: None,
            removed_reason: String::new(),
        };
        let written = self.write_artifact(&job, &artifact, now);
        if !matches!(written, Ok(true)) {
            // Nothing was recorded, so the bytes this put in place go too, unless a record already
            // names the same bytes.
            if made && !rows::still_kept(self.store.connection(), &self.realm.id, &artifact.sha256).unwrap_or(true) {
                let _ = shelf.remove(&artifact.sha256);
            }
            return Err(written.err().unwrap_or(JobError::StaleFence));
        }
        let action = if role == ArtifactRole::Output { "job.output recorded" } else { "job.checkpoint recorded" };
        let because = format!("{} of {} bytes from attempt {}", artifact.name, artifact.bytes, attempt.number);
        self.note_job(&job.principal_id, action, &job, Some(&device_id), Some(&attempt.workload_id), &because, now)?;
        Ok(artifact)
    }

    /// Writes an artifact's record, and for a checkpoint the job's pointer to it, in one change,
    /// under the fencing check the statement itself makes. Answers whether the attempt was still
    /// the job's current one.
    fn write_artifact(&self, job: &Job, artifact: &JobArtifact, now: i64) -> Result<bool, JobError> {
        let connection = self.store.connection();
        let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
        if !rows::insert_artifact(&change, &self.realm.id, artifact)? {
            return Ok(false);
        }
        if artifact.role == ArtifactRole::Checkpoint {
            let mut moved = job.clone();
            moved.checkpoint = Some(artifact.id.clone());
            moved.updated_at = now;
            if !rows::move_job(&change, &moved, job.state, job.fence)? {
                return Ok(false);
            }
        }
        change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))?;
        Ok(true)
    }

    /// Writes one of an attempt's inputs, or the checkpoint it resumes from, into `into`, checked
    /// against its checksum on the way. An attempt reads its own job's inputs and nothing else.
    pub fn read_job_input(&self, device_id: &str, attempt_id: &str, fence: u64, artifact_id: &str, into: &mut dyn Write, now: i64) -> Result<u64, JobError> {
        let (job, _, _) = self.holding(device_id, attempt_id, fence, now)?;
        let its_own = job.spec.inputs.iter().any(|input| input.artifact_id == artifact_id) || (job.spec.checkpoints && job.checkpoint.as_deref() == Some(artifact_id));
        if !its_own {
            return Err(JobError::NotAllowed("An attempt reads its own job's inputs and nothing else".into()));
        }
        let artifact = rows::artifact(self.store.connection(), &self.realm.id, artifact_id)?.ok_or(JobError::NoSuchArtifact)?;
        if artifact.removed_at.is_some() {
            return Err(JobError::ArtifactRemoved);
        }
        self.job_shelf().send(artifact.bytes, &artifact.sha256, into).map_err(|refusal| from_shelf(refusal, artifact.bytes))
    }

    /// The computer's word on how an attempt ended.
    ///
    /// Success is taken only once every declared output has arrived from this same attempt. A
    /// failure goes wherever `next_after` says. `Stopped` answers a stop that was asked for and is
    /// refused when nothing asked. Success is accepted after a stop was asked for: the work
    /// finished before its computer heard, and the record says what actually happened.
    pub fn complete_job_attempt(&mut self, device_id: &str, attempt_id: &str, fence: u64, ending: Ending, now: i64) -> Result<JobState, JobError> {
        let (job, attempt, _) = self.holding(device_id, attempt_id, fence, now)?;
        let started = attempt.state == AttemptState::Running;
        let closing = match ending {
            Ending::Succeeded => {
                if !started {
                    return Err(JobError::NotStarted);
                }
                let sent: Vec<String> = rows::artifacts_of_attempt(self.store.connection(), &attempt.id)?
                    .into_iter()
                    .filter(|artifact| artifact.role == ArtifactRole::Output)
                    .map(|artifact| artifact.name)
                    .collect();
                let missing: Vec<String> = job.spec.outputs.iter().filter(|name| !sent.contains(name)).cloned().collect();
                if !missing.is_empty() {
                    return Err(JobError::OutputsMissing(missing));
                }
                Closing {
                    attempt: AttemptState::Succeeded,
                    attempt_words: "it finished and sent every output",
                    job: JobState::Succeeded,
                    not_before: job.not_before,
                    job_note: "Finished: every output arrived from the attempt that ran it",
                }
            }
            Ending::Failed(failure) => {
                let (state, not_before, note) = next_after(&job, started, Ended::Reported(failure), now);
                Closing { attempt: AttemptState::Failed, attempt_words: failure.say(), job: state, not_before, job_note: note }
            }
            Ending::Stopped => {
                if job.state != JobState::CancelRequested {
                    return Err(JobError::NothingAskedToStop);
                }
                Closing { attempt: AttemptState::Stopped, attempt_words: "it stopped when it was asked to", job: JobState::Stopped, not_before: job.not_before, job_note: "Stopped when it was asked to" }
            }
        };
        let words = closing.attempt_words;
        let moved = self.close_attempt(&job, &attempt, closing, now)?;
        self.note_job(&job.principal_id, "job.attempt ended", &moved, Some(device_id), Some(&attempt.workload_id), &format!("attempt {}: {words}", attempt.number), now)?;
        self.note_job_moved(&job.principal_id, &moved, Some(device_id), Some(&attempt.workload_id), now)?;
        Ok(moved.state)
    }

    /// Ends every attempt whose reservation has ended without a word from its computer, and moves
    /// each job on as `next_after` says. Returns how many attempts it ended.
    ///
    /// A reservation ends because its computer stopped renewing it, because the attempt reached the
    /// job's time limit, or because the realm took it back: the core's own sweep, a cancel of the
    /// work that held it, or the computer leaving the grid. The core's sweep may have got there
    /// first, and that changes nothing here. Like `Core::expire`, whoever opens the realm calls this
    /// on a timer; `lease_job` calls it too. Each call also runs one pass of
    /// `tidy_job_artifacts`: uploads nobody finished, and artifacts past what the realm keeps.
    pub fn expire_jobs(&mut self, now: i64) -> usize {
        let ended = self.settle_lapsed(now).unwrap_or(0);
        let _ = self.tidy_job_artifacts(now);
        ended
    }

    fn settle_lapsed(&mut self, now: i64) -> Result<usize, JobError> {
        if !self.has_jobs()? {
            return Ok(0);
        }
        let mut ended = 0;
        for attempt in rows::live_attempts(self.store.connection(), &self.realm.id)? {
            let lease = self.store.lease(&attempt.lease_id)?;
            if lease.as_ref().is_some_and(|lease| lease.holds(now)) {
                continue;
            }
            let (state, words, how) = if now >= attempt.deadline {
                (AttemptState::TimedOut, "it reached the job's time limit", Ended::TimedOut)
            } else if lease.as_ref().is_none_or(|lease| lease.released_at.is_some()) {
                (AttemptState::Lost, "the realm took its reservation back", Ended::Lost)
            } else {
                (AttemptState::Lost, "its computer stopped answering", Ended::Lost)
            };
            let Some(job) = rows::job(self.store.connection(), &self.realm.id, &attempt.job_id)? else { continue };
            if job.current_attempt.as_deref() != Some(attempt.id.as_str()) {
                // Not the attempt its job names, which none of the doors here leaves behind. It is
                // ended so that it stops holding anything, and its job is left where it is.
                self.end_stray_attempt(&attempt, words, now)?;
                ended += 1;
                continue;
            }
            let started = attempt.state == AttemptState::Running;
            let (next, not_before, note) = next_after(&job, started, how, now);
            let moved = self.close_attempt(&job, &attempt, Closing { attempt: state, attempt_words: words, job: next, not_before, job_note: note }, now)?;
            self.note_job(&job.principal_id, "job.attempt ended", &moved, Some(&attempt.device_id), Some(&attempt.workload_id), &format!("attempt {}: {words}", attempt.number), now)?;
            self.note_job_moved(&job.principal_id, &moved, None, Some(&attempt.workload_id), now)?;
            ended += 1;
        }
        Ok(ended)
    }

    /// Ends an attempt its job does not name, with its reservation and its core workload.
    fn end_stray_attempt(&self, attempt: &JobAttempt, words: &str, now: i64) -> Result<(), JobError> {
        let mut ended = attempt.clone();
        ended.state = AttemptState::Lost;
        ended.ended_at = Some(now);
        ended.ending = words.to_owned();
        let connection = self.store.connection();
        let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
        rows::move_attempt(&change, &ended, attempt.state)?;
        if let Some(mut lease) = self.store.lease(&attempt.lease_id)?.filter(|lease| lease.released_at.is_none()) {
            lease.released_at = Some(now);
            Store::write_lease(&change, &lease)?;
        }
        if let Some(mut work) = self.store.workload(&attempt.workload_id)?.filter(|work| !work.stage.finished()) {
            if work.advance(Stage::Failed, now).is_ok() {
                Store::write_workload(&change, &work)?;
            }
        }
        change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))
    }
}

/// A declared checksum as it is recorded: 64 lowercase hexadecimal characters, with an optional
/// `sha256:` in front taken off.
fn checksum(raw: &str) -> Result<String, JobError> {
    let text = raw.trim().to_ascii_lowercase();
    let hex = text.strip_prefix("sha256:").unwrap_or(&text);
    if hex.len() != 64 || !hex.bytes().all(|letter| letter.is_ascii_hexdigit()) {
        return Err(JobError::InvalidSpec("A checksum is the SHA-256 of the bytes, written as 64 hexadecimal characters".into()));
    }
    Ok(hex.to_owned())
}
