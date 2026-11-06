//! One launch's jail on the host: its launcher session, its Firecracker process once found,
//! and its cleanup (VM-D15 line 3209; §6.4 lines 2322–2324: cleanup uses host-created
//! handles and never arbitrary paths; VM-P49 line 2824).
//!
//! Every privileged operation goes through [`Jail::perform`], which authorizes it in the
//! launch's [`LauncherSession`] before the launcher port sees it, so an operation out of
//! order, repeated, with other parameters or outside the closed set never reaches the
//! launcher. Cleanup is the launcher's own: it kills the jail through the launch's
//! cgroup, waits for the host to observe the end, and only then removes the cgroup, the
//! jail directory and the network namespace, each only if this launch created it and
//! each at most once. Nothing of a jail whose end the host has not observed is removed.

use serde::Serialize;

use super::launcher::{CleanupStep, LauncherRefusal, LauncherSession, PrivilegedOperation};
use super::names::{HostPath, JailId, JailIdentity};
use super::plan::LaunchPlan;
use super::ports::{
    HostObservationPort, LauncherFailure, LauncherPort, LauncherReport, ObservationFailure,
};
use super::proof::{JailTermination, NoJailProof};
use crate::foundation::process::{Ending, IdentityCheck, ProcessIdentity, ProcessRole};

/// Why a privileged operation was not performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StepError {
    /// The launch's session refused it; the launcher never saw it.
    Refused(LauncherRefusal),
    /// The launcher was asked and failed.
    Failed(LauncherFailure),
}

/// What became of one cleanup step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CleanupOutcome {
    /// The launcher performed the step.
    Performed,
    /// The launch never created what the step removes, so nothing was sent.
    NotCreated,
    /// The jail had already ended on its own, so it was not killed.
    NotNeeded,
    /// The launch's session refused the step; the launcher never saw it.
    Refused { refusal: LauncherRefusal },
    /// The launcher failed to perform the step. A step is taken at most once, so it is
    /// not sent again.
    Failed { detail: String },
    /// Not sent: the host has not observed the jail's end, and nothing of a jail that may
    /// still run is removed.
    Withheld,
}

impl CleanupOutcome {
    /// Whether the step is settled for good: performed, or nothing to do.
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Performed | Self::NotCreated | Self::NotNeeded)
    }

    /// Whether the step was decided and is never tried again.
    fn is_final(&self) -> bool {
        !matches!(self, Self::Withheld)
    }
}

/// One cleanup step and what became of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CleanupEntry {
    pub op: &'static str,
    pub outcome: CleanupOutcome,
}

/// Whether the host observed the jail's end.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum JailEnd {
    /// The jailer never ran, so no process of the launch ever existed.
    NothingStarted,
    Proven {
        proof: JailTermination,
    },
    NotProven {
        reason: NoJailProof,
    },
}

/// The state of a launch's cleanup after one round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CleanupReport {
    /// Every cleanup step of the launch, in the launcher's order.
    pub steps: Vec<CleanupEntry>,
    pub end: JailEnd,
}

impl CleanupReport {
    /// Whether the jail ended, or never started, and everything the launch created is
    /// removed.
    pub fn complete(&self) -> bool {
        !matches!(self.end, JailEnd::NotProven { .. })
            && self.steps.iter().all(|step| step.outcome.is_done())
    }

    /// The proof of the jail's end, if the host observed it.
    pub fn proof(&self) -> Option<&JailTermination> {
        match &self.end {
            JailEnd::Proven { proof } => Some(proof),
            JailEnd::NothingStarted | JailEnd::NotProven { .. } => None,
        }
    }
}

/// One launch's jail.
#[derive(Clone, Debug)]
pub(super) struct Jail {
    id: JailId,
    identity: JailIdentity,
    role: ProcessRole,
    cgroup: HostPath,
    session: LauncherSession,
    cleanup: Vec<CleanupStep>,
    outcomes: Vec<Option<CleanupOutcome>>,
    process: Option<ProcessIdentity>,
    proof: Option<JailTermination>,
}

impl Jail {
    /// The jail of `plan`, before any privileged operation: `identity` is the jail
    /// identity allocated to the launch, `role` what its process runs for and `cgroup`
    /// the launch's own cgroup on the host.
    pub(super) fn new(
        plan: &LaunchPlan,
        identity: JailIdentity,
        role: ProcessRole,
        cgroup: HostPath,
    ) -> Self {
        let cleanup = plan.launcher().cleanup().to_vec();
        Self {
            id: plan.jail_id().clone(),
            identity,
            role,
            cgroup,
            session: plan.launcher().session(),
            outcomes: vec![None; cleanup.len()],
            cleanup,
            process: None,
            proof: None,
        }
    }

    pub(super) fn id(&self) -> &JailId {
        &self.id
    }

    pub(super) fn identity(&self) -> JailIdentity {
        self.identity
    }

    pub(super) fn role(&self) -> &ProcessRole {
        &self.role
    }

    pub(super) fn process(&self) -> Option<ProcessIdentity> {
        self.process
    }

    /// Binds the jail's Firecracker process, as the host found it in the jail's cgroup.
    pub(super) fn bind_process(&mut self, process: ProcessIdentity) {
        self.process = Some(process);
    }

    /// Authorizes `operation` in the launch's session and only then asks the launcher to
    /// perform it.
    pub(super) fn perform<L: LauncherPort + ?Sized>(
        &mut self,
        launcher: &mut L,
        operation: &PrivilegedOperation,
    ) -> Result<LauncherReport, StepError> {
        let step = self
            .session
            .authorize(operation)
            .map_err(StepError::Refused)?;
        launcher
            .perform(&self.id, step, operation)
            .map_err(StepError::Failed)
    }

    /// Whether the setup step that creates what `step` removes was authorized.
    fn created(&self, step: &CleanupStep) -> bool {
        self.session.performed_setup() > step.created_by
    }

    /// Whether the jailer was authorized, so a process of the launch may exist.
    fn jailer_ran(&self) -> bool {
        self.cleanup.first().is_some_and(|kill| self.created(kill))
    }

    /// Whether every step is settled for good and the jail's end, if it started, is
    /// proven.
    pub(super) fn cleaned_up(&self) -> bool {
        (self.proof.is_some() || !self.jailer_ran())
            && self
                .outcomes
                .iter()
                .all(|outcome| outcome.as_ref().is_some_and(CleanupOutcome::is_done))
    }

    /// The host's observation of the jail's end: the launch's cgroup holds no process and
    /// the Firecracker process's identity names no live process. Nothing is killed here.
    pub(super) fn observe_end<H: HostObservationPort + ?Sized>(
        &self,
        host: &H,
        ending: Ending,
    ) -> Result<JailTermination, NoJailProof> {
        let unobservable = |failure: ObservationFailure| NoJailProof::Unobservable {
            detail: failure.detail,
        };
        if !host
            .cgroup_state(&self.cgroup)
            .map_err(unobservable)?
            .is_vacant()
        {
            return Err(NoJailProof::CgroupPopulated);
        }
        let process = match self.process {
            None => None,
            Some(process) => match host.check(&process).map_err(unobservable)? {
                IdentityCheck::Same => return Err(NoJailProof::ProcessStillNamed { process }),
                found => Some((process, found)),
            },
        };
        Ok(JailTermination::observed(
            self.id.clone(),
            self.cgroup.clone(),
            self.role.clone(),
            process,
            ending,
        ))
    }

    /// One round of the launcher's own cleanup. With `kill`, the jail is killed through
    /// its cgroup first, once; without, it must have ended on its own. Then, once the host
    /// observes the end, every removal not yet decided is performed in order. Steps already
    /// decided in an earlier round are not sent again.
    pub(super) fn clean_up<L, H>(&mut self, launcher: &mut L, host: &H, kill: bool) -> CleanupReport
    where
        L: LauncherPort + ?Sized,
        H: HostObservationPort + ?Sized,
    {
        let end = if !self.jailer_ran() {
            if let Some(slot) = self.outcomes.first_mut() {
                *slot = Some(CleanupOutcome::NotCreated);
            }
            JailEnd::NothingStarted
        } else if let Some(proof) = &self.proof {
            JailEnd::Proven {
                proof: proof.clone(),
            }
        } else {
            let killed = if kill {
                self.kill(launcher)
            } else {
                self.killed()
            };
            let ending = if killed {
                Ending::Killed { rounds: 1 }
            } else {
                Ending::Exited
            };
            match self.observe_end(host, ending) {
                Ok(proof) => {
                    if let Some(slot @ None) = self.outcomes.first_mut() {
                        *slot = Some(CleanupOutcome::NotNeeded);
                    }
                    self.proof = Some(proof.clone());
                    JailEnd::Proven { proof }
                }
                Err(reason) => JailEnd::NotProven { reason },
            }
        };
        let ended = !matches!(end, JailEnd::NotProven { .. });
        for index in 1..self.cleanup.len() {
            let decided = self
                .outcomes
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(CleanupOutcome::is_final);
            let Some(step) = self.cleanup.get(index).cloned() else {
                continue;
            };
            if decided {
                continue;
            }
            let outcome = if !self.created(&step) {
                CleanupOutcome::NotCreated
            } else if !ended {
                CleanupOutcome::Withheld
            } else {
                self.send(launcher, &step.operation)
            };
            if let Some(slot) = self.outcomes.get_mut(index) {
                *slot = Some(outcome);
            }
        }
        CleanupReport {
            steps: self.entries(),
            end,
        }
    }

    /// Kills the jail through its cgroup unless the kill was decided before; whether the
    /// kill was performed, now or earlier.
    fn kill<L: LauncherPort + ?Sized>(&mut self, launcher: &mut L) -> bool {
        if self.outcomes.first().is_some_and(Option::is_some) {
            return self.killed();
        }
        let Some(step) = self.cleanup.first().cloned() else {
            return false;
        };
        let outcome = self.send(launcher, &step.operation);
        let performed = outcome == CleanupOutcome::Performed;
        if let Some(slot) = self.outcomes.first_mut() {
            *slot = Some(outcome);
        }
        performed
    }

    /// Whether the jail was killed through its cgroup in an earlier round.
    fn killed(&self) -> bool {
        self.outcomes.first() == Some(&Some(CleanupOutcome::Performed))
    }

    fn send<L: LauncherPort + ?Sized>(
        &mut self,
        launcher: &mut L,
        operation: &PrivilegedOperation,
    ) -> CleanupOutcome {
        match self.perform(launcher, operation) {
            Ok(_) => CleanupOutcome::Performed,
            Err(StepError::Refused(LauncherRefusal::NothingCreated { .. })) => {
                CleanupOutcome::NotCreated
            }
            Err(StepError::Refused(refusal)) => CleanupOutcome::Refused { refusal },
            Err(StepError::Failed(failure)) => CleanupOutcome::Failed {
                detail: failure.detail,
            },
        }
    }

    fn entries(&self) -> Vec<CleanupEntry> {
        self.cleanup
            .iter()
            .zip(&self.outcomes)
            .map(|(step, outcome)| CleanupEntry {
                op: step.operation.tag(),
                outcome: outcome.clone().unwrap_or(CleanupOutcome::Withheld),
            })
            .collect()
    }
}
