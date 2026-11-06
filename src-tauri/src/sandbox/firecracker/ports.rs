//! The ports the Firecracker backend acts and observes through (VM-D15 line 3209: a narrow
//! privileged launcher around the official jailer; §6.4 line 2322: stable process handles,
//! identity checks on Linux, never a stored PID; VM-CP-02 and VM-CP-04, lines 3152 and
//! 3154: host-observed).
//!
//! They are traits only; nothing here performs I/O. A real implementation of each lives
//! with the host side of the backend and must keep the contract written on its trait:
//!
//! - [`LauncherPort`]: the privileged launcher, which performs one operation of VM-D15's
//!   closed set at a time and reports what it did. The backend sends only what the
//!   launch's [`LauncherSession`](super::LauncherSession) authorized; the launcher keeps
//!   its own session for the launch and refuses anything that session does not authorize.
//! - [`ApiPort`]: Firecracker's API, one request at a time over the socket Firecracker
//!   binds in the host-created socket directory of its jail.
//! - [`HostObservationPort`]: what the host reads itself about the jail's cgroup and its
//!   process, the process named by a `foundation::process` [`ProcessIdentity`] (its PID
//!   and start time), never by a PID alone. On Linux the start time is field 22 of
//!   `/proc/<pid>/stat`, in clock ticks since boot, read through a pidfd held for the
//!   reading, so a PID that another process took meanwhile is never read or acted on.
//! - [`ReservationBook`]: the CORE-03 ledger's record of the reservation a launch request
//!   names (S10: reserve before creating; the backend never reserves for itself).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::api::ApiCall;
use super::launcher::{Authorized, PrivilegedOperation};
use super::names::{HostPath, JailId};
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{Clock, ContentKey};
use crate::foundation::ledger::{Ledger, ReservationId, ReservationRecord};
use crate::foundation::process::{IdentityCheck, ProcessIdentity};
use crate::sandbox::backend::HostBuild;

/// What the privileged launcher reports after it performed one operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "report", rename_all = "snake_case")]
pub enum LauncherReport {
    /// The operation was performed.
    Done,
    /// An artifact was staged: the content key and length the launcher computed over the
    /// copy it made in the jail, read back after copying.
    Staged {
        content_key: ContentKey,
        length_bytes: u64,
    },
    /// The jailer ran and exited with `code`. With a new PID namespace, the jailer's
    /// first process exits once it has started the jailed Firecracker.
    JailerExited { code: i32 },
}

/// The launcher could not perform an authorized operation; `detail` is its own
/// description, kept as reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LauncherFailure {
    pub detail: String,
}

impl fmt::Display for LauncherFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for LauncherFailure {}

/// The narrow privileged launcher of VM-D15.
pub trait LauncherPort {
    /// Performs `operation` for the launch whose jail is `jail`. The backend's session for
    /// that launch authorized it as `step`; the launcher authorizes it again in its own
    /// session and refuses it, as a failure, if that session does not.
    fn perform(
        &mut self,
        jail: &JailId,
        step: Authorized,
        operation: &PrivilegedOperation,
    ) -> Result<LauncherReport, LauncherFailure>;
}

/// Firecracker's answer to one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApiReply {
    /// The call as the port wrote it to the socket.
    pub sent: ApiCall,
    /// The HTTP status code of the answer.
    pub status: u16,
    /// Firecracker's `fault_message`, when it refused the call.
    pub fault_message: Option<String>,
}

impl ApiReply {
    /// Whether Firecracker accepted the call: a 2xx status.
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Firecracker's description of itself (`GET /`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InstanceInfo {
    /// The instance id, which the jailer passes on from its own `--id`.
    pub id: String,
    /// The instance state, `Running` once started.
    pub state: String,
    /// The version of the running Firecracker.
    pub vmm_version: String,
}

/// The API socket could not be reached or answered with something that is not HTTP;
/// `detail` is the port's own description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApiFailure {
    pub detail: String,
}

impl fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ApiFailure {}

/// Firecracker's API over the host-created socket of one jail.
pub trait ApiPort {
    /// Sends `call` over the socket at `socket` and waits, within the port's own bound, for
    /// its answer. The backend sends the next call only after this one was accepted.
    fn send(&mut self, socket: &HostPath, call: &ApiCall) -> Result<ApiReply, ApiFailure>;

    /// Asks the Firecracker at `socket` to describe itself.
    fn describe(&mut self, socket: &HostPath) -> Result<InstanceInfo, ApiFailure>;
}

/// The host as it observes itself now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostState {
    pub build: HostBuild,
    /// The host configuration in force, as CORE-01's adapters fingerprint it.
    pub configuration: ConfigurationFingerprint,
}

/// A cgroup as the host reads it (`cgroup.events`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupState {
    /// A process is in the cgroup or one of its descendants.
    Populated,
    /// The cgroup exists and holds no process.
    Empty,
    /// No such cgroup exists.
    Absent,
}

impl CgroupState {
    /// Whether no process of the cgroup is left.
    pub const fn is_vacant(self) -> bool {
        matches!(self, Self::Empty | Self::Absent)
    }
}

/// What the host read about one process, each item as the kernel shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessObservation {
    /// The text of `/proc/<pid>/status`.
    pub status: String,
    /// The text of `/proc/<pid>/cgroup`.
    pub cgroup: String,
    /// The target of `/proc/<pid>/root`: the process's root directory.
    pub root: String,
    /// The target of every entry of `/proc/<pid>/fd`.
    pub descriptors: Vec<String>,
    /// The interface names in the process's network namespace.
    pub network_interfaces: BTreeSet<String>,
    /// The interface files of the cgroup the backend named, by name, each without its
    /// final newline.
    pub cgroup_files: BTreeMap<String, String>,
}

/// The host could not make an observation; `detail` is the port's own description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservationFailure {
    pub detail: String,
}

impl fmt::Display for ObservationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ObservationFailure {}

/// What the host observes itself. Every method reads; none changes anything.
pub trait HostObservationPort {
    /// The host's build and its configuration in force now.
    fn host(&self) -> Result<HostState, ObservationFailure>;

    /// The processes in the cgroup at `cgroup` (`cgroup.procs`), each as the host
    /// identifies it.
    fn cgroup_processes(
        &self,
        cgroup: &HostPath,
    ) -> Result<Vec<ProcessIdentity>, ObservationFailure>;

    /// Whether the cgroup at `cgroup` holds a process.
    fn cgroup_state(&self, cgroup: &HostPath) -> Result<CgroupState, ObservationFailure>;

    /// Reads `process` through a handle bound to its identity, with the interface files of
    /// the cgroup at `cgroup`. A process the identity no longer names is a failure, never
    /// another process's observation.
    fn observe(
        &self,
        process: &ProcessIdentity,
        cgroup: &HostPath,
    ) -> Result<ProcessObservation, ObservationFailure>;

    /// Whether `process`'s PID still names it, names no process, or names another one now.
    fn check(&self, process: &ProcessIdentity) -> Result<IdentityCheck, ObservationFailure>;
}

/// The CORE-03 ledger's records, as the backend reads them.
pub trait ReservationBook {
    /// The open reservation `reservation`, if the ledger holds one.
    fn reservation(&self, reservation: ReservationId) -> Option<ReservationRecord>;
}

impl<C: Clock> ReservationBook for Ledger<C> {
    fn reservation(&self, reservation: ReservationId) -> Option<ReservationRecord> {
        Ledger::reservation(self, reservation).cloned()
    }
}
