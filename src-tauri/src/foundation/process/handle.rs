//! A host process held through a stable handle for its whole life (S04; VM part §6.4,
//! §6.5).
//!
//! The handle and the process's job are held until the value is dropped. Dropping it
//! closes the job, which kills every process left in it (kill-on-close), so nothing the
//! host started outlives its holder unobserved. Termination is a bounded ladder: a grace
//! period for the process to end on its own, then kill rounds of the whole job, each
//! waiting a bounded time for the host to observe the end.

use std::fmt;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::identity::{ProcessIdentity, ProcessRole};
use super::proof::{Ended, Ending, NoProof, TerminationProof};
use super::sys;
use super::usage::JobUsage;

/// The exit code the host gives the processes it kills.
pub const KILLED_EXIT_CODE: u32 = 1;

/// How many times [`HostProcess::terminate`] kills the job before it gives up: a process
/// created while the first kill ran is caught by the second.
pub const KILL_ROUNDS: u32 = 2;

/// How a process is ended (VM part §6.5: a stop within a stated bound).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    /// How long the process and every process of its job may take to end on their own,
    /// as asked through the caller's own channel, before the host kills them.
    pub grace: Duration,
    /// How long each kill round waits for the host to observe the end.
    pub kill_wait: Duration,
}

/// A host call, for errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCall {
    CreateJob,
    LimitJob,
    AssignToJob,
    CheckJob,
    ReadProcessTimes,
    ListThreads,
    ResumeThread,
    OpenProcess,
    WaitForProcess,
    ReadExitCode,
    QueryJob,
    TerminateJob,
    ReadJobUsage,
    DuplicateHandle,
}

impl fmt::Display for HostCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CreateJob => "create the job",
            Self::LimitJob => "set the job's limits",
            Self::AssignToJob => "assign the process to its job",
            Self::CheckJob => "check the process is in its job",
            Self::ReadProcessTimes => "read the process's creation time",
            Self::ListThreads => "list the process's threads",
            Self::ResumeThread => "resume the process's thread",
            Self::OpenProcess => "open the process",
            Self::WaitForProcess => "wait for the process",
            Self::ReadExitCode => "read the exit code",
            Self::QueryJob => "count the job's processes",
            Self::TerminateJob => "kill the job",
            Self::ReadJobUsage => "read the job's CPU time, processes and memory",
            Self::DuplicateHandle => "duplicate a handle into the holder's process",
        })
    }
}

/// Why a host process could not be started or looked up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ProcessError {
    /// This platform has no host process handle here; nothing was started.
    Unsupported { platform: String },
    /// The command could not be started.
    Spawn { detail: String },
    /// A host call failed. A process already started was killed before it ran.
    HostCall { call: HostCall, os_error: u32 },
    /// The process was not in its job after assignment, so it never ran; it was killed.
    NotInJob,
    /// No thread of the suspended process could be resumed; it was killed.
    NotResumed,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { platform } => write!(
                f,
                "host process handles are not available on {platform}; nothing was started"
            ),
            Self::Spawn { detail } => write!(f, "could not start the process: {detail}"),
            Self::HostCall { call, os_error } => {
                write!(f, "could not {call} (OS error {os_error})")
            }
            Self::NotInJob => f.write_str("the process was not in its job; it was killed"),
            Self::NotResumed => {
                f.write_str("the process could not be resumed; it was killed before it ran")
            }
        }
    }
}

impl std::error::Error for ProcessError {}

/// The job and process handles of one host process, duplicated into another process the
/// host started, its holder (VM-W26: the lifetime supervisor holds each VM through them;
/// [`HostProcess::share_with`]). Each number is a handle value in the holder's process,
/// meaningless in this one; the holder takes them with
/// [`AdoptedLifetime::adopt`](super::AdoptedLifetime::adopt), which checks they are the
/// named process and its job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedHandles {
    /// The job, with terminate and query access.
    pub job: u64,
    /// The process, with synchronize and limited query access.
    pub process: u64,
}

/// A process the host started and holds through a stable handle for its whole life,
/// inside its own job (VM part §6.4).
pub struct HostProcess {
    role: ProcessRole,
    identity: ProcessIdentity,
    process: sys::Process,
}

impl fmt::Debug for HostProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostProcess")
            .field("role", &self.role)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl HostProcess {
    /// Starts `command` for `role` inside a new job of its own. On Windows the process is
    /// created suspended and without a console window (the command's own creation flags
    /// are replaced), assigned to a job that kills every process in it when it closes and
    /// lets none break away, checked to be in that job, and only then resumed, so every
    /// process it starts is in the job too. A failure after creation kills the process
    /// before it runs.
    pub fn spawn(command: &mut Command, role: ProcessRole) -> Result<Self, ProcessError> {
        let (process, identity) = sys::spawn(command)?;
        Ok(Self {
            role,
            identity,
            process,
        })
    }

    /// The process's identity: its PID and creation time.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// What the process runs for.
    pub fn role(&self) -> &ProcessRole {
        &self.role
    }

    /// What the process's job has used so far, the process and every process it started
    /// included, read through the job handle the host holds; it changes nothing. A host
    /// call that fails is [`ProcessError::HostCall`] with [`HostCall::ReadJobUsage`].
    pub fn usage(&self) -> Result<JobUsage, ProcessError> {
        self.process.usage()
    }

    /// Looks once, without waiting: the proof, if the host observes that the process and
    /// every process of its job ended.
    pub fn check_ended(&self) -> Result<TerminationProof, NoProof> {
        self.wait_ended(Duration::ZERO)
    }

    /// Waits at most `within` for the process and every process of its job to end on
    /// their own; it kills nothing.
    pub fn wait_ended(&self, within: Duration) -> Result<TerminationProof, NoProof> {
        let started = Instant::now();
        let ended = self.process.observe(within)?;
        Ok(self.proof(ended, Ending::Exited, started))
    }

    /// Ends the process and every process of its job, and returns the host's proof:
    /// waits `escalation.grace` for them to end on their own, then kills the whole job
    /// and waits `escalation.kill_wait` for the end to be observed, at most
    /// [`KILL_ROUNDS`] times. Without that observation there is no proof, whatever was
    /// killed.
    pub fn terminate(&self, escalation: Escalation) -> Result<TerminationProof, NoProof> {
        let started = Instant::now();
        let mut last = match self.process.observe(escalation.grace) {
            Ok(ended) => return Ok(self.proof(ended, Ending::Exited, started)),
            Err(no_proof) => no_proof,
        };
        for rounds in 1..=KILL_ROUNDS {
            let killed = self.process.kill(KILLED_EXIT_CODE);
            match self.process.observe(escalation.kill_wait) {
                Ok(ended) => return Ok(self.proof(ended, Ending::Killed { rounds }, started)),
                Err(no_proof) => last = killed.err().unwrap_or(no_proof),
            }
        }
        Err(last)
    }

    fn proof(&self, ended: Ended, ending: Ending, started: Instant) -> TerminationProof {
        TerminationProof::observed(
            self.identity,
            self.role.clone(),
            ended,
            ending,
            started.elapsed(),
        )
    }
}

#[cfg(target_os = "linux")]
impl HostProcess {
    /// Starts `command` for `role` in a cgroup v2 group of its own limited by
    /// `containment`, without network when asked, as its unprivileged account when given,
    /// with no new privileges (see [`LinuxContainment`](super::LinuxContainment)), joined
    /// before the program runs.
    pub fn spawn_contained(
        command: &mut Command,
        role: ProcessRole,
        containment: &super::LinuxContainment,
    ) -> Result<Self, ProcessError> {
        let (process, identity) = sys::spawn_contained(command, containment)?;
        Ok(Self {
            role,
            identity,
            process,
        })
    }

    /// The process's group directory, to read its own accounting files.
    pub fn group_path(&self) -> &std::path::Path {
        self.process.group_path()
    }

    /// Nothing is duplicated into a holder on Linux: it opens its own pidfd for this
    /// process's identity and finds its group through it
    /// ([`AdoptedLifetime::adopt`](super::AdoptedLifetime::adopt)), so both values are 0. A
    /// group outlives every handle, so the process lives on whatever the holder holds.
    pub fn share_with(&self, _holder: &HostProcess) -> Result<SharedHandles, ProcessError> {
        Ok(SharedHandles { job: 0, process: 0 })
    }

    /// Nothing is duplicated on Linux: the holder opens its own pidfd for this host by the
    /// identity named with it ([`AdoptedProcess::adopt`](super::AdoptedProcess::adopt)).
    pub fn share_this_host_with(_holder: &HostProcess) -> Result<u64, ProcessError> {
        Ok(0)
    }

    /// Nothing to share on Linux: a group outlives the handles to it
    /// ([`OwnJob`](super::OwnJob)).
    pub fn share_own_job(&self) -> Result<u64, ProcessError> {
        Ok(0)
    }

    /// Nothing was duplicated on Linux, so nothing is closed.
    pub fn close_shared(&self, _handle: u64) {}
}

#[cfg(windows)]
impl HostProcess {
    /// Starts `command` for `role` confined by `confinement` (on Windows: in an AppContainer
    /// with no capabilities, inheriting no handle; see [`Confinement`](super::Confinement)),
    /// inside a new job of its own, through the same steps as [`HostProcess::spawn`]:
    /// created suspended and without a window, contained in a kill-on-close job with no
    /// breakaway, checked to be in it, and only then resumed. The program must be an
    /// absolute path. The command's standard streams and creation flags are not used (the
    /// standard handles are null), and the process's environment is only what the command
    /// sets, which must include `LOCALAPPDATA`.
    pub fn spawn_confined(
        command: &Command,
        role: ProcessRole,
        confinement: super::Confinement,
    ) -> Result<Self, ProcessError> {
        let (process, identity) = sys::spawn_confined(command, &confinement)?;
        Ok(Self {
            role,
            identity,
            process,
        })
    }

    /// Starts `command` for `role` under `start` (on Windows: a restricted, lowered copy of
    /// the host's own token, only the listed standard handles inherited, the selected
    /// mitigation policies always on; see [`RestrictedStart`](super::RestrictedStart)),
    /// inside a new job of its own with `start`'s limits, through the same steps as
    /// [`HostProcess::spawn`]. Returns what the host saw of the process while it was still
    /// suspended. The program must be an absolute path; the process's environment is only
    /// what the command sets. The start's desktop is held with the process for its life.
    pub fn spawn_restricted(
        command: &Command,
        role: ProcessRole,
        start: super::RestrictedStart,
    ) -> Result<(Self, super::StartObservation), ProcessError> {
        let (process, identity, observation) = sys::spawn_restricted(command, start)?;
        Ok((
            Self {
                role,
                identity,
                process,
            },
            observation,
        ))
    }

    /// The host's read-back of the process's token, job, mitigation policies and command
    /// line, through the handles it holds (see
    /// [`RestrictionReadback`](super::RestrictionReadback)).
    pub fn read_restrictions(&self) -> Result<super::RestrictionReadback, super::ReadbackError> {
        self.process.read_restrictions()
    }

    /// Duplicates this process's job handle (terminate and query access) and process handle
    /// (synchronize and limited query access) into `holder`'s process, so the holder can
    /// observe and end it, and keeps it alive while it holds the job (kill-on-close acts
    /// on the job's last handle). This host keeps its own handles. The holder adopts them
    /// with [`AdoptedLifetime::adopt`](super::AdoptedLifetime::adopt).
    pub fn share_with(&self, holder: &HostProcess) -> Result<SharedHandles, ProcessError> {
        self.process.share_with(&holder.process)
    }

    /// Duplicates a handle to this host's own process (synchronize and limited query
    /// access) into `holder`'s process: the holder sees this host end through it, never
    /// through a PID.
    pub fn share_this_host_with(holder: &HostProcess) -> Result<u64, ProcessError> {
        sys::share_current_process_with(&holder.process)
    }

    /// Duplicates this process's own job handle (query access) into this process, so its
    /// job stays open while the process runs, after this host's handle closed: a holder
    /// that must outlive this host holds its own job.
    pub fn share_own_job(&self) -> Result<u64, ProcessError> {
        self.process.share_own_job()
    }

    /// Closes the handle `handle` in this process (one [`HostProcess::share_with`] put
    /// there that the process refused); best effort.
    pub fn close_shared(&self, handle: u64) {
        self.process.close_in_process(handle);
    }

    /// [`HostProcess::share_with`] into the test process itself, which then holds them.
    #[cfg(test)]
    pub(crate) fn share_with_this_process(&self) -> Result<SharedHandles, ProcessError> {
        self.process.share_with_current()
    }
}
