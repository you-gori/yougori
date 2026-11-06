//! Host processes held by a process other than the one that started them (VM part §6.2,
//! §6.4; VM-W26; VM-CP-19).
//!
//! The starter duplicates a process's job and process handles into a holder it also
//! started ([`HostProcess::share_with`](super::HostProcess::share_with)), and a handle to
//! itself ([`HostProcess::share_this_host_with`](super::HostProcess::share_this_host_with)).
//! The holder takes them here, after checking each names what the starter said: the
//! process handle's PID and creation time are the named [`ProcessIdentity`], and the
//! process is in the job. From then on the holder observes and ends the process only
//! through those handles: a PID reused by another process is never signalled, because no
//! PID is ever used to act. Holding the job keeps it open, so its kill-on-close acts only
//! when the starter's handle and the holder's are both closed.
//!
//! An end is observed as the starter observes it: the process handle signalled, its exit
//! code read and no active process left in the job.
//!
//! On Linux nothing is duplicated (`HostProcess::share_with` hands over no value): the
//! holder opens its own pidfd for the named [`ProcessIdentity`] and checks, through it, that
//! the PID still names that process (its start time read after the pidfd pinned it), finds
//! the process's cgroup through `/proc` while the pidfd pins it, and from then on observes
//! the end through the pidfd and the group's `cgroup.events` and ends it through
//! `cgroup.kill`. A Linux group outlives every handle, so nothing is needed to keep it.

use std::time::Duration;

use serde::Serialize;

use super::identity::ProcessIdentity;

#[cfg(target_os = "linux")]
#[path = "lifetime_linux.rs"]
mod platform;
#[cfg(windows)]
#[path = "lifetime_windows.rs"]
mod platform;

pub use platform::{AdoptedLifetime, AdoptedProcess, OwnJob};

/// Why handles handed to a holder were not taken. Nothing was taken: the values stay
/// open in the holder until the starter closes them
/// ([`HostProcess::close_shared`](super::HostProcess::close_shared)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum AdoptRefusal {
    /// The value is not a process handle of this process, or the host could not read it.
    NotAProcess,
    /// The handle names another process than the one named.
    OtherProcess {
        named: ProcessIdentity,
        found_pid: u32,
        found_start_time_ticks: u64,
    },
    /// The process is not in the job handed with it, or the job value is not a job.
    NotInJob,
}

impl std::fmt::Display for AdoptRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAProcess => f.write_str("the handle is not a readable process handle"),
            Self::OtherProcess { named, found_pid, .. } => write!(
                f,
                "the handle names process {found_pid}, not {} as named",
                named.pid
            ),
            Self::NotInJob => f.write_str("the process is not in the job handed with it"),
        }
    }
}

/// What a holder observed of an adopted process's end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LifetimeEnded {
    /// The exit code the holder read; `None` where the host does not tell a holder that is
    /// not the parent (Linux before 6.15, for an end the holder did not cause).
    pub exit_code: Option<u32>,
    /// Every process the job ever held (on Linux the most at once, `pids.peak`).
    pub job_processes: u32,
    /// The kill rounds the holder took; 0 when it ended without one.
    pub kill_rounds: u32,
    /// From the start of the observation (or the first kill) to the observed end.
    pub elapsed: Duration,
}
