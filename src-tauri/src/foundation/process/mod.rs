//! Host processes behind stable handles, and the host's proof that one ended
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 CORE-04, S3.1; VM part §6.1,
//! §6.4, VM-CP-19; docs/combined-plan-leftover-tasks.md S04).
//!
//! CORE-04 settles an old generation's leases and grants only when the old generation is
//! known to have stopped. For a process that the host runs, that knowledge is the host's
//! own observation through a handle it held for the process's whole life, never a stored
//! PID, the process's own report or the word of a runner that replaced it (VM part §6.4:
//! "use stable process/VM handles ... never terminate an unrelated process because a stored
//! PID was reused").
//!
//! - [`HostProcess`] starts a command inside its own Job object on Windows: suspended,
//!   assigned to a job with kill-on-close and no breakaway, checked to be in it, and only
//!   then resumed, so every process it starts stays in the job. It is named by its PID and
//!   creation time ([`ProcessIdentity`]) and bound at start to what it runs for
//!   ([`ProcessRole`]): one VM boot under the sandbox lifecycle, or one model activation
//!   under the model activations. Other platforms get a typed refusal.
//!   [`HostProcess::spawn_confined`] starts one the same way on Windows, confined
//!   ([`Confinement`]): in an AppContainer with no capabilities, inheriting no handle,
//!   such as the guest relay ([`ProcessRole::GuestRelay`], VM part §3.1).
//!   [`HostProcess::spawn_restricted`] starts one under a restricted, lowered copy of the
//!   host's own token ([`RestrictedStart`]: restricting SIDs, low integrity, only the listed
//!   standard handles inherited, mitigation policies always on), in a job with the caller's
//!   limits and on a [`SandboxDesktop`] of its own, such as the hypervisor of a VM boot
//!   (VM part §7.3), and [`HostProcess::read_restrictions`] reads back what is in effect
//!   through the handles the host holds ([`RestrictionReadback`], VM-CP-04).
//! - A [`TerminationProof`] exists only when the host saw the process handle signalled,
//!   read its exit code and found no process left in its job, within bounded waits; a
//!   child still alive means no proof. [`HostProcess::terminate`] waits a grace period,
//!   then kills the whole job and waits again for that observation.
//! - The adapters feed the proof to the coordinator as the host-observed source, each
//!   under its own authority (S3.1). [`ObservedTermination`] presents a VM backend as the
//!   coordinator's [`SandboxPort`](crate::foundation::coordination::SandboxPort): a VM
//!   counts as terminated, in termination, revocation and recovery, only on the proof
//!   that its host process ended, and a VM whose process the host does not hold running is
//!   never ready. [`RunnerProcesses`] binds each model runner role to one live process.
//!   [`settle_leases`] closes the leases a process held, and
//!   [`release_runner_reservations`] closes a model runner's reservations, only on the
//!   proof of the end of the process bound to that role.
//!
//! - A process another process holds: [`HostProcess::share_with`] duplicates a process's
//!   job and process handles into a holder the host started, and the holder takes them as
//!   an [`AdoptedLifetime`] after checking they name that process and its job, then
//!   observes and ends it through them alone (VM-W26: the lifetime supervisor).
//! - On Linux a process is held through a pidfd and a cgroup v2 group of its own, joined
//!   before the program runs, killed through `cgroup.kill` and observed empty through
//!   `cgroup.events`; [`HostProcess::spawn_contained`] also limits the group and starts the
//!   process without network, unprivileged and with no new privileges (`linux_host`). A
//!   holder there takes no value from the starter: it opens its own pidfd for the named
//!   identity and finds the group through it ([`AdoptedLifetime`]).
//!
//! Production callers adopt it at their spawn sites; nothing here starts a VM or a model.

mod handle;
mod identity;
mod proof;
mod runner;
mod settle;
mod usage;
mod vm;

#[cfg(windows)]
mod confined;
#[cfg(any(windows, target_os = "linux"))]
mod lifetime;
#[cfg(windows)]
mod restricted;
#[cfg(windows)]
mod station;
#[cfg(target_os = "linux")]
mod linux_host;
#[cfg(target_os = "linux")]
use linux_host as sys;
#[cfg(not(any(windows, target_os = "linux")))]
mod unsupported_host;
#[cfg(not(any(windows, target_os = "linux")))]
use unsupported_host as sys;
#[cfg(windows)]
mod windows_host;
#[cfg(windows)]
use windows_host as sys;

#[cfg(all(test, windows))]
mod tests;

#[cfg(windows)]
pub use confined::Confinement;
pub use handle::{
    Escalation, HostCall, HostProcess, ProcessError, SharedHandles, KILLED_EXIT_CODE, KILL_ROUNDS,
};
pub use identity::{IdentityCheck, ProcessAuthority, ProcessIdentity, ProcessRole};
#[cfg(any(windows, target_os = "linux"))]
pub use lifetime::{AdoptRefusal, AdoptedLifetime, AdoptedProcess, LifetimeEnded, OwnJob};
#[cfg(target_os = "linux")]
pub use linux_host::{end_leftover_groups, leave_own_group, LinuxContainment, RunAs};
pub use proof::{Ending, NoProof, TerminationProof};
#[cfg(windows)]
pub use restricted::{
    read_command_line, AdministratorsState, JobSettings, LoweredIntegrity, ObservedGroup,
    ObservedJobLimits, ReadbackError, RestrictedStart, RestrictingGroup, RestrictionReadback,
    StartMitigation, StartObservation,
};
pub use runner::RunnerProcesses;
pub use settle::{release_runner_reservations, settle_leases, BoundProcesses, SettleRefusal};
#[cfg(windows)]
pub use station::SandboxDesktop;
pub use usage::JobUsage;
pub use vm::{BindRefusal, ObservedTermination, ProcessBackedVms, VmProcesses};
