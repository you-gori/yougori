//! Job control over the journal, and reconciliation after a daemon restart (§3.10
//! line 652).
//!
//! Every start is treated as a restart; [`JobControl::start`] is the only way to open the
//! journal. The CORE-04 coordinator has recovered first ([`Coordinator::recover`]): it
//! revived no lease and retired every model activation, so no generation from before the
//! restart is used again. This start then reconciles actual state:
//!
//! 1. Leases and generations: no lease or GPU allocation from before this start may
//!    still be honoured or in use. The coordinator's own records are checked, whatever
//!    its recovery report lists: a lease or activation is from before the start when the
//!    report names it, when it was stamped on an earlier clock session than the
//!    coordinator's, or when an earlier start already ran on the coordinator's session,
//!    so the coordinator never restarted. One that survived stops the start, and
//!    progress under a retired allocation is refused at the source
//!    ([`super::ProgressPublisher::set_allocation`]).
//! 2. The start's incarnation is journaled with the coordinator's clock session; the
//!    incarnation must be above every earlier one.
//! 3. Jobs: every unfinished intent is resubmitted through the normal [`Loader`], the
//!    same entry fresh jobs use. The catalog decides what is committed: an object it
//!    publishes needs only placement, even if the journal missed the commit, and one it
//!    no longer publishes is imported again. Journaled extents travel as claims that the
//!    catalog's resumed import re-verifies (T05). Nothing is restored from GPU memory.
//!
//! Commands are idempotent: submitting an intent again, or cancelling again, has no
//! further effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use super::job::{
    ArtifactCommit, ImportState, JobIntent, JobOutcome, LoadRequest, ResumePoint, VerifiedExtent,
};
use super::journal::{JobRecord, Journal, JournalError, JournalOpened, JournalState, Recorded};
use super::ports::{CatalogObjects, Loader, PortError};
use crate::foundation::catalog::ObjectStatus;
use crate::foundation::coordination::{
    CapacityPort, Coordinator, GpuAllocationHandle, LeaseState,
    RecoveryReport as CoordinatorRecovery,
};
use crate::foundation::ids::{Clock, Incarnation, LeaseId, OperationId};

/// What restart reconciliation found and did (line 652).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    /// This start's incarnation, journaled; register the progress producer under it.
    pub incarnation: Incarnation,
    pub journal: JournalOpened,
    /// Leases from before the restart that its recovery did not revive, as the
    /// coordinator's report lists them and as the coordinator records them, in lease
    /// order; the coordinator honours none of them.
    pub leases_not_revived: Vec<LeaseId>,
    /// GPU allocations from before the restart, as the coordinator's report lists them
    /// and then as the coordinator records them; the coordinator refuses them, and so
    /// does every progress publisher.
    pub stale_allocations: Vec<GpuAllocationHandle>,
    /// Unfinished jobs resubmitted through the normal loader, in operation ID order.
    pub resubmitted: Vec<OperationId>,
    /// Jobs whose object the catalog publishes although the journal had not recorded the
    /// commit; the commit is journaled now.
    pub found_committed: Vec<OperationId>,
    /// Jobs whose journaled commit the catalog no longer publishes, or holds quarantined;
    /// they import again.
    pub reimport: Vec<OperationId>,
}

/// Why a start failed. Reconciliation stops at the first failure rather than assume an
/// answer; a later start, under a later incarnation, repeats it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Journal(JournalError),
    Port(PortError),
    /// The coordinator still honours, or may still be using, a lease from before this
    /// start: a lease never survives a restart.
    LeaseSurvived {
        lease: LeaseId,
    },
    /// The coordinator still honours a GPU allocation from before this start, or its
    /// activation is not retired: a generation from before a restart is never used
    /// again.
    AllocationSurvived {
        handle: GpuAllocationHandle,
    },
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "restart reconciliation: {error}"),
            Self::Port(error) => write!(f, "restart reconciliation: {error}"),
            Self::LeaseSurvived { lease } => write!(
                f,
                "restart reconciliation: lease {lease} from before the restart is still honoured"
            ),
            Self::AllocationSurvived { handle } => write!(
                f,
                "restart reconciliation: GPU allocation generation {} from before the restart \
                 is still honoured",
                handle.generations.gpu_allocation
            ),
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<JournalError> for RecoveryError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<PortError> for RecoveryError {
    fn from(error: PortError) -> Self {
        Self::Port(error)
    }
}

/// Why a job command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobError {
    Journal(JournalError),
    Port(PortError),
    UnknownOperation,
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => error.fmt(f),
            Self::Port(error) => error.fmt(f),
            Self::UnknownOperation => f.write_str("no job has this operation ID"),
        }
    }
}

impl std::error::Error for JobError {}

impl From<JournalError> for JobError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<PortError> for JobError {
    fn from(error: PortError) -> Self {
        Self::Port(error)
    }
}

/// What a submission did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// Journaled, then handed to the loader.
    Submitted,
    /// The loader has it already in this incarnation.
    AlreadySubmitted,
    AlreadyFinished(JobOutcome),
}

/// What a cancellation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancellation {
    Cancelled,
    AlreadyFinished(JobOutcome),
}

/// Job intent, artifact commits, verified extents and import state, journaled before
/// they take effect, with restart reconciliation on every start (§3.10 line 652).
pub struct JobControl {
    journal: Journal,
    incarnation: Incarnation,
    submitted: BTreeSet<OperationId>,
    /// Cancellations journaled but not yet delivered to the loader.
    undelivered_cancels: BTreeSet<OperationId>,
}

impl JobControl {
    /// Opens the journal in `dir` and reconciles as after a daemon restart.
    ///
    /// `incarnation` is this start's, from the boot counter the coordination authority
    /// keeps; the journal refuses one that is not above every incarnation it recorded.
    /// `coordinator` is the CORE-04 coordinator as [`Coordinator::recover`] returned it,
    /// with `recovered` its report; a host's very first start passes a new coordinator
    /// and an empty report. The report never narrows the check: every lease and
    /// activation the coordinator holds from before this start is checked as well.
    pub fn start<K, C, P, L>(
        dir: &Path,
        incarnation: Incarnation,
        catalog: &K,
        coordinator: &Coordinator<C, P>,
        recovered: &CoordinatorRecovery,
        loader: &mut L,
    ) -> Result<(Self, RecoveryReport), RecoveryError>
    where
        K: CatalogObjects,
        C: Clock,
        P: CapacityPort,
        L: Loader,
    {
        let (mut journal, opened) = Journal::open(dir)?;
        let session = coordinator.session();
        let never_restarted = journal.state().started_on(session).is_some();
        let leases_not_revived = check_leases(coordinator, recovered, never_restarted)?;
        let stale_allocations = check_allocations(coordinator, recovered, never_restarted)?;
        journal.begin_incarnation(incarnation, session)?;
        let mut report = RecoveryReport {
            incarnation,
            journal: opened,
            leases_not_revived,
            stale_allocations,
            resubmitted: Vec::new(),
            found_committed: Vec::new(),
            reimport: Vec::new(),
        };
        let unfinished: Vec<JobRecord> = journal.state().unfinished().cloned().collect();
        let mut submitted = BTreeSet::new();
        for job in unfinished {
            let resume = resume_point(&mut journal, &job, catalog, &mut report)?;
            let intent = job.intent().clone();
            let operation = intent.operation.clone();
            loader.submit(LoadRequest {
                intent,
                resume,
                incarnation,
            })?;
            submitted.insert(operation.clone());
            report.resubmitted.push(operation);
        }
        let control = Self {
            journal,
            incarnation,
            submitted,
            undelivered_cancels: BTreeSet::new(),
        };
        Ok((control, report))
    }

    pub fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    pub fn state(&self) -> &JournalState {
        self.journal.state()
    }

    /// Journals `intent`, then hands it to the normal loader. Submitting the same intent
    /// again has no further effect; another intent under the same operation ID is
    /// refused.
    pub fn submit<L: Loader>(
        &mut self,
        intent: JobIntent,
        loader: &mut L,
    ) -> Result<Submission, JobError> {
        let operation = intent.operation.clone();
        self.journal.record_intent(intent.clone())?;
        let job = self
            .journal
            .state()
            .job(&operation)
            .ok_or(JobError::UnknownOperation)?;
        if let Some(outcome) = job.outcome() {
            return Ok(Submission::AlreadyFinished(outcome));
        }
        if self.submitted.contains(&operation) {
            return Ok(Submission::AlreadySubmitted);
        }
        loader.submit(LoadRequest {
            intent,
            resume: ResumePoint::fresh(),
            incarnation: self.incarnation,
        })?;
        self.submitted.insert(operation);
        Ok(Submission::Submitted)
    }

    /// The catalog published the job's whole object (§3.10 "artifact commits").
    pub fn record_artifact_commit(
        &mut self,
        operation: &OperationId,
        commit: ArtifactCommit,
    ) -> Result<Recorded, JobError> {
        Ok(self.journal.record_artifact_commit(operation, commit)?)
    }

    /// One extent of the job's object was verified (§3.10 "resumable verified extents").
    pub fn record_verified_extent(
        &mut self,
        operation: &OperationId,
        extent: VerifiedExtent,
    ) -> Result<Recorded, JobError> {
        Ok(self.journal.record_verified_extent(operation, extent)?)
    }

    /// Where the job's import stands, as the catalog reports it.
    pub fn record_import_state(
        &mut self,
        operation: &OperationId,
        state: ImportState,
    ) -> Result<Recorded, JobError> {
        Ok(self.journal.record_import_state(operation, state)?)
    }

    /// Journals how the job ended. The same outcome again changes nothing; another is
    /// refused, and `Completed` needs the artifact commit first.
    pub fn finish(
        &mut self,
        operation: &OperationId,
        outcome: JobOutcome,
    ) -> Result<Recorded, JobError> {
        Ok(self.journal.record_finished(operation, outcome)?)
    }

    /// Journals the cancellation, then tells the loader. Cancelling again redelivers a
    /// cancellation the loader has not acknowledged and otherwise changes nothing.
    pub fn cancel<L: Loader>(
        &mut self,
        operation: &OperationId,
        loader: &mut L,
    ) -> Result<Cancellation, JobError> {
        let job = self
            .journal
            .state()
            .job(operation)
            .ok_or(JobError::UnknownOperation)?;
        match job.outcome() {
            Some(JobOutcome::Cancelled) if self.undelivered_cancels.contains(operation) => {}
            Some(outcome) => return Ok(Cancellation::AlreadyFinished(outcome)),
            None => {
                self.journal
                    .record_finished(operation, JobOutcome::Cancelled)?;
                self.undelivered_cancels.insert(operation.clone());
            }
        }
        loader.cancel(operation)?;
        self.undelivered_cancels.remove(operation);
        Ok(Cancellation::Cancelled)
    }
}

/// Refuses the start if a lease from before it is still honoured, or may still be in use
/// as the coordinator sees it (line 652: a lease never survives a restart). A lease is
/// from before the start when `recovered` names it, when it was stamped on an earlier
/// clock session than the coordinator's, or when the coordinator `never_restarted`.
/// Returns the leases from before the start that recovery did not revive.
fn check_leases<C: Clock, P: CapacityPort>(
    coordinator: &Coordinator<C, P>,
    recovered: &CoordinatorRecovery,
    never_restarted: bool,
) -> Result<Vec<LeaseId>, RecoveryError> {
    let session = coordinator.session();
    let now = coordinator.now();
    let survives = |lease: LeaseId| {
        coordinator.check_lease(lease).is_ok()
            || coordinator
                .lease_record(lease)
                .is_some_and(|record| record.may_be_in_use(now))
    };
    let mut not_revived: BTreeSet<LeaseId> = BTreeSet::new();
    for &lease in &recovered.leases_not_revived {
        if survives(lease) {
            return Err(RecoveryError::LeaseSurvived { lease });
        }
        not_revived.insert(lease);
    }
    for record in coordinator.leases() {
        let lease = record.lease().id();
        if !never_restarted && record.lease().clock() == session {
            continue;
        }
        if survives(lease) {
            return Err(RecoveryError::LeaseSurvived { lease });
        }
        if record.state() == LeaseState::NotRevived {
            not_revived.insert(lease);
        }
    }
    Ok(not_revived.into_iter().collect())
}

/// Refuses the start if a GPU allocation from before it is still honoured, or its
/// activation is not retired (line 652: stale generations are invalidated). An
/// activation is from before the start when `recovered` names its allocation, when its
/// authority was granted on an earlier clock session than the coordinator's, or when
/// the coordinator `never_restarted`. Returns the allocations from before the start.
fn check_allocations<C: Clock, P: CapacityPort>(
    coordinator: &Coordinator<C, P>,
    recovered: &CoordinatorRecovery,
    never_restarted: bool,
) -> Result<Vec<GpuAllocationHandle>, RecoveryError> {
    let session = coordinator.session();
    let mut stale: Vec<GpuAllocationHandle> = Vec::new();
    for handle in &recovered.retired_activations {
        if coordinator.check_gpu_handle(handle).is_ok() {
            return Err(RecoveryError::AllocationSurvived {
                handle: handle.clone(),
            });
        }
        if !stale.contains(handle) {
            stale.push(handle.clone());
        }
    }
    // The persisted view is the coordinator's public record of every model activation,
    // keyed here by execution, model and activation so the order is fixed.
    let mut earlier = BTreeMap::new();
    for models in coordinator.persist().models {
        for activation in models.activations() {
            let handle = GpuAllocationHandle {
                execution: models.execution().clone(),
                model: models.model(),
                generations: activation.generations(),
            };
            if never_restarted
                || activation.settings().authority.clock != session
                || recovered.retired_activations.contains(&handle)
            {
                let key = (
                    handle.execution.clone(),
                    handle.model,
                    handle.generations.activation,
                );
                earlier.insert(key, (handle, activation.state().is_retired()));
            }
        }
    }
    for (handle, retired) in earlier.into_values() {
        if !retired || coordinator.check_gpu_handle(&handle).is_ok() {
            return Err(RecoveryError::AllocationSurvived { handle });
        }
        if !stale.contains(&handle) {
            stale.push(handle);
        }
    }
    Ok(stale)
}

/// Where `job` resumes, from the catalog's actual state rather than the journal's
/// belief: only an object the catalog publishes now counts as committed.
fn resume_point<K: CatalogObjects>(
    journal: &mut Journal,
    job: &JobRecord,
    catalog: &K,
    report: &mut RecoveryReport,
) -> Result<ResumePoint, RecoveryError> {
    let intent = job.intent();
    let object = intent.object();
    match catalog.object_status(&intent.scope(), object)? {
        ObjectStatus::Published => {
            if job.artifact().is_none() {
                journal.record_artifact_commit(
                    &intent.operation,
                    ArtifactCommit {
                        object,
                        total_bytes: intent.total_bytes,
                    },
                )?;
                report.found_committed.push(intent.operation.clone());
            }
            return Ok(ResumePoint {
                artifact_committed: true,
                ..ResumePoint::fresh()
            });
        }
        ObjectStatus::Quarantined { .. } | ObjectStatus::Absent => {
            if job.artifact().is_some() {
                report.reimport.push(intent.operation.clone());
            }
        }
    }
    Ok(ResumePoint {
        artifact_committed: false,
        journaled_extents: job.verified_extents().copied().collect(),
        import: job.import_state().copied(),
    })
}
