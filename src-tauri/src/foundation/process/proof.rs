//! The host's proof that a process ended (S04; VM part §6.4; S2 CORE-04).
//!
//! A proof exists only when the host itself saw the process handle signalled, read the
//! exit code, and found no process left in the process's job, so a child still alive means
//! no proof. Only a held [`HostProcess`](super::HostProcess) produces one: it has no
//! public constructor and is never read back, so neither a runner's report about itself
//! nor the word of a runner that replaced it can stand in for it.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::handle::HostCall;
use super::identity::{ProcessIdentity, ProcessRole};
use crate::foundation::evidence::SourceClass;

/// What the host observed when a process and its job ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Ended {
    pub(super) exit_code: u32,
    /// Every process the job ever held, the first one included.
    pub(super) job_processes: u32,
}

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ending", rename_all = "snake_case")]
pub enum Ending {
    /// It ended, with every process of its job, before the host killed anything.
    Exited,
    /// The host killed its job, in `rounds` kill rounds, before it observed the end.
    Killed { rounds: u32 },
}

/// The host's proof that a process and every process of its job ended (S04).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminationProof {
    identity: ProcessIdentity,
    role: ProcessRole,
    exit_code: u32,
    ending: Ending,
    job_processes: u32,
    elapsed: Duration,
}

impl TerminationProof {
    pub(super) fn observed(
        identity: ProcessIdentity,
        role: ProcessRole,
        ended: Ended,
        ending: Ending,
        elapsed: Duration,
    ) -> Self {
        Self {
            identity,
            role,
            exit_code: ended.exit_code,
            ending,
            job_processes: ended.job_processes,
            elapsed,
        }
    }

    /// The process that ended.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// What it ran for, as bound when it started.
    pub fn role(&self) -> &ProcessRole {
        &self.role
    }

    /// The exit code the host read from the process handle.
    pub fn exit_code(&self) -> u32 {
        self.exit_code
    }

    /// Whether it ended on its own or was killed.
    pub fn ending(&self) -> Ending {
        self.ending
    }

    /// Every process its job ever held, the process itself and any the system started for
    /// it, such as a console host, included; none is left.
    pub fn job_processes(&self) -> u32 {
        self.job_processes
    }

    /// From the request to wait or terminate until the end was observed (VM part §6.5:
    /// measured, not promised).
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Who observed the end: always the host itself.
    pub fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }
}

/// Why the host has no proof that a process ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "no_proof", rename_all = "snake_case")]
pub enum NoProof {
    /// The process has not ended.
    StillRunning,
    /// The process ended with `exit_code`, but `active` processes of its job still run,
    /// such as a child it started.
    JobStillActive { exit_code: u32, active: u32 },
    /// A host call failed, so nothing was observed.
    HostCall { call: HostCall, os_error: u32 },
}

impl fmt::Display for NoProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StillRunning => f.write_str("the process has not ended"),
            Self::JobStillActive { exit_code, active } => write!(
                f,
                "the process exited with code {exit_code}, but {active} process(es) of its job \
                 still run"
            ),
            Self::HostCall { call, os_error } => {
                write!(f, "could not {call} (OS error {os_error})")
            }
        }
    }
}

impl std::error::Error for NoProof {}
