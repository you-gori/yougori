//! Who a host process is and what it runs for (VM part §6.4, VM-CP-19; S3.1).
//!
//! A process is named by its PID together with its creation time, read through a handle,
//! so a PID that another process took later never matches. What it runs for is bound when
//! it starts: the host process of one VM boot, under the sandbox lifecycle (RUNTIME), or
//! the runner of one model activation, under the model activations (MODELS). The two stay
//! distinct, so the end of one never settles the other's authority (S2 CORE-04; S3.1).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::handle::ProcessError;
use super::sys;
use crate::foundation::coordination::{ModelGenerations, ModelId, VmInstanceId};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, SandboxBootGeneration};

/// A process as the host identifies it: its PID and its creation time, in the platform's
/// ticks (on Windows, 100-nanosecond intervals since 1601, from `GetProcessTimes`). The
/// PID alone is never enough (VM part §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
}

impl ProcessIdentity {
    /// The digest domain of [`ProcessIdentity::digest`].
    pub const DOMAIN: &'static str = "yougori/process/identity/v1";

    /// The identity as a digest, such as the identity token of a VM handle.
    pub fn digest(&self) -> Digest {
        DigestBuilder::new(Self::DOMAIN)
            .u64(u64::from(self.pid))
            .u64(self.start_time_ticks)
            .finish()
    }

    /// The process that holds `pid` now, as the host observes it, or `None` when no
    /// process does.
    pub fn holder_of(pid: u32) -> Result<Option<Self>, ProcessError> {
        sys::holder_of(pid)
    }

    /// Whether this process still runs: its PID names it (by its creation time) and it has
    /// not exited. A process that exited still has a holder while some handle to it stays
    /// open, so [`ProcessIdentity::holder_of`] alone does not say it runs.
    pub fn running(&self) -> Result<bool, ProcessError> {
        sys::running(self)
    }

    /// Whether the PID still names this process, names no process, or names another
    /// process now (VM-CP-19: a stale PID reused by another process is never signalled).
    pub fn check(&self) -> Result<IdentityCheck, ProcessError> {
        Ok(match Self::holder_of(self.pid)? {
            None => IdentityCheck::Gone,
            Some(holder) if holder == *self => IdentityCheck::Same,
            Some(_) => IdentityCheck::Reused,
        })
    }
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "process {} started at tick {}",
            self.pid, self.start_time_ticks
        )
    }
}

/// What the host found at a recorded identity's PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCheck {
    /// The PID still names the process: running, or ended while something still holds
    /// it.
    Same,
    /// No process holds the PID.
    Gone,
    /// Another process holds the PID now. It is never acted on.
    Reused,
}

/// The authority a host process runs under (S2 CORE-04: VM lifecycle and model
/// activation keep distinct state machines and owners).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAuthority {
    /// The sandbox lifecycle (RUNTIME).
    VmLifecycle,
    /// The model activations (MODELS).
    ModelActivation,
}

impl fmt::Display for ProcessAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VmLifecycle => "the VM lifecycle",
            Self::ModelActivation => "the model activations",
        })
    }
}

/// What a host process runs for, bound when it starts (S3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ProcessRole {
    /// The host process of one VM boot, such as its hypervisor or VMM process.
    VmHost {
        execution: ExecutionId,
        vm: VmInstanceId,
        boot: SandboxBootGeneration,
    },
    /// The runner process of one model activation on the host, such as a host-process
    /// model runtime's (VM-D6).
    ModelRunner {
        execution: ExecutionId,
        model: ModelId,
        generations: ModelGenerations,
    },
    /// The guest relay of one sandbox (VM part §3.1, VM-W11): the confined process that
    /// parses the guest's requests and holds no provider secret, host path or lifecycle
    /// privilege. It is started and ended under the sandbox lifecycle, and its end settles
    /// no lease, grant or reservation.
    GuestRelay { execution: ExecutionId },
    /// The sandbox executor of one engine (VM part §3.1, VM-W12, VM-W28): the process that
    /// holds the sandbox vault and brokers every sandbox's relay, started by the engine in
    /// a kill-on-close job and ended with it. `execution` names the engine run it serves;
    /// its end settles no lease, grant or reservation.
    SandboxExecutor { execution: ExecutionId },
    /// The lifetime supervisor of one engine's VM sandboxes (VM part §6.2, VM-W26): the
    /// separately confined process that holds every VM's job and process handles beside the
    /// engine and ends them by the per-class policy of VM-D7 when the engine dies or stops
    /// answering. `execution` names the engine run it serves; its end settles no lease,
    /// grant or reservation (the engine's ledger does, through its own revocation).
    SandboxSupervisor { execution: ExecutionId },
}

crate::foundation::strict_serde::strict_tag!(ProcessRole, "role");

impl ProcessRole {
    /// The authority the process runs under.
    pub fn authority(&self) -> ProcessAuthority {
        match self {
            Self::VmHost { .. } => ProcessAuthority::VmLifecycle,
            Self::ModelRunner { .. } => ProcessAuthority::ModelActivation,
            Self::GuestRelay { .. }
            | Self::SandboxExecutor { .. }
            | Self::SandboxSupervisor { .. } => ProcessAuthority::VmLifecycle,
        }
    }

    /// The parent execution the process runs under.
    pub fn execution(&self) -> &ExecutionId {
        match self {
            Self::VmHost { execution, .. }
            | Self::ModelRunner { execution, .. }
            | Self::GuestRelay { execution }
            | Self::SandboxExecutor { execution }
            | Self::SandboxSupervisor { execution } => execution,
        }
    }
}

impl fmt::Display for ProcessRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VmHost {
                execution,
                vm,
                boot,
            } => write!(
                f,
                "the host process of VM {vm}, boot generation {boot} of execution {execution}"
            ),
            Self::ModelRunner {
                execution,
                model,
                generations,
            } => write!(
                f,
                "the runner of model {model}, {generations} of execution {execution}"
            ),
            Self::GuestRelay { execution } => {
                write!(f, "the guest relay of execution {execution}")
            }
            Self::SandboxExecutor { execution } => {
                write!(f, "the sandbox executor of engine run {execution}")
            }
            Self::SandboxSupervisor { execution } => {
                write!(f, "the sandbox lifetime supervisor of engine run {execution}")
            }
        }
    }
}
