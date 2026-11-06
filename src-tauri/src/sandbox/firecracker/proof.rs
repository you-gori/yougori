//! The host's proof that a launch's jail ended (§6.4 line 2322; VM-CP-19 line 3169: a
//! stale PID reused by another process is never signalled; VM-P49 line 2824).
//!
//! A jail ends through its own cgroup: the launcher writes the launch's `cgroup.kill`,
//! which names no PID, and the host then observes the cgroup empty and the Firecracker
//! process's identity no longer naming a live process (gone, or its PID taken by another
//! process, which is never acted on). Only then does the backend remove the cgroup, the
//! jail directory and the network namespace. A [`JailTermination`] exists only from that
//! observation: it has no public constructor and is never read back.
//!
//! It names the process by `foundation::process`'s [`ProcessIdentity`] and the
//! [`ProcessRole`] bound at launch, as a [`TerminationProof`](crate::foundation::process::TerminationProof)
//! does. That proof itself is made only by a Windows [`HostProcess`](crate::foundation::process::HostProcess)
//! today; until `foundation::process` has a Linux handle (pidfd and cgroup), this is the
//! Firecracker backend's equivalent.

use std::fmt;

use serde::Serialize;

use super::names::{HostPath, JailId};
use crate::foundation::evidence::SourceClass;
use crate::foundation::process::{Ending, IdentityCheck, ProcessIdentity, ProcessRole};

/// The host's proof that a jail's cgroup holds no process and its Firecracker process
/// ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JailTermination {
    jail: JailId,
    cgroup: HostPath,
    role: ProcessRole,
    process: Option<ProcessIdentity>,
    found: Option<IdentityCheck>,
    ending: Ending,
}

impl JailTermination {
    pub(super) fn observed(
        jail: JailId,
        cgroup: HostPath,
        role: ProcessRole,
        process: Option<(ProcessIdentity, IdentityCheck)>,
        ending: Ending,
    ) -> Self {
        Self {
            jail,
            cgroup,
            role,
            process: process.map(|(identity, _)| identity),
            found: process.map(|(_, found)| found),
            ending,
        }
    }

    pub fn jail(&self) -> &JailId {
        &self.jail
    }

    /// The launch's own cgroup, which the host observed empty.
    pub fn cgroup(&self) -> &HostPath {
        &self.cgroup
    }

    /// What the jail ran for, as bound at launch.
    pub fn role(&self) -> &ProcessRole {
        &self.role
    }

    /// The jail's Firecracker process; `None` when the launch ended before the host found
    /// one.
    pub fn process(&self) -> Option<ProcessIdentity> {
        self.process
    }

    /// What the host found at the process's PID: gone, or another process, never acted
    /// on.
    pub fn found(&self) -> Option<IdentityCheck> {
        self.found
    }

    /// Whether the jail ended on its own or was killed through its cgroup, in one kill
    /// round.
    pub fn ending(&self) -> Ending {
        self.ending
    }

    /// Who observed the end: always the host itself.
    pub fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }
}

/// Why the host has no proof that a jail ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "no_proof", rename_all = "snake_case")]
pub enum NoJailProof {
    /// A process is still in the jail's cgroup.
    CgroupPopulated,
    /// The Firecracker process's identity still names a process: running, or ended and
    /// not yet reaped.
    ProcessStillNamed { process: ProcessIdentity },
    /// The host could not observe the cgroup or the process.
    Unobservable { detail: String },
}

impl fmt::Display for NoJailProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CgroupPopulated => f.write_str("a process is still in the jail's cgroup"),
            Self::ProcessStillNamed { process } => {
                write!(f, "{process} has not ended")
            }
            Self::Unobservable { detail } => {
                write!(f, "the host could not observe the jail's end: {detail}")
            }
        }
    }
}

impl std::error::Error for NoJailProof {}
