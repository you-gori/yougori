//! The lifetime supervisor: the separately confined process that holds every VM sandbox's
//! lifetime beside the engine (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part
//! §6.2 "The independent supervisor owns VM lifetimes. Engine failure denies new privileged
//! authorizations until reconciliation; existing operations follow their bounded leases",
//! §6.4, line 3062 "Supervisor: one small binary ... survives the engine; same-user IPC with
//! a per-process token; stable VM handles"; VM-W26; VM-D7; VM-CP-19).
//!
//! **What it is.** This binary started by the engine as `--sandbox-supervisor PIPE
//! ENGINE_PID JOURNAL_DIR` ([`process`]), restricted as the executor is (the engine's token
//! with every privilege disabled and Administrators deny-only, medium label, a desktop of
//! its own, no inherited handle, the start mitigations), in a job of its own (itself alone,
//! 128 MiB; [`client::SUPERVISOR_JOB`]) whose handle it holds itself, so it survives the
//! engine. It runs above normal priority, and its memory lies within the host ledger's
//! supervisor reserve, which no workload is ever granted (CORE-03).
//!
//! **What it holds.** At its hello, a handle to the engine's own process; at each launch,
//! the VM's job and process handles, duplicated into it by the engine
//! (`HostProcess::share_with`) and checked against the VM's identity before they are
//! taken (`AdoptedLifetime`). No PID is ever used to act: a PID reused by another process
//! is never signalled. Holding a VM's job keeps it open, so the VM no longer ends merely
//! because the engine's handle closed: it ends by the supervisor's rules, or when both the
//! engine's and the supervisor's handles closed (the job's kill-on-close, the OS cleanup
//! declared for the platform, `SupervisorDeathFallback::OsJobCleanup`).
//!
//! **What it decides** ([`policy`]): the engine's death, or its silence past the bound,
//! counts as the engine failing, and a task sandbox's VM ends with it while a service
//! sandbox's runs on to its own limits (VM-D7); every request carries the held sandboxes'
//! lease terms, and a VM whose limit passed by the grace without the engine's revocation is
//! ended (the backstop of §6.2's leases for an engine that is blocked); a gap in its own
//! ticks (sleep, or its own starvation) never extends authority. It enforces elapsed
//! limits before accepting queued messages, using the shared suspend-aware clock.
//!
//! **One ledger, one lifecycle.** The supervisor reserves and releases nothing: the
//! engine's CORE-03 ledger and its lifecycle supervisor (`sandbox::lifecycle`) stay the
//! only owners of capacity, authority and revocation. Each end the supervisor observes is
//! reported back on the next request, and the engine revokes the sandbox for it (the
//! engine's death or silence: `EngineDied`; a lease: `LeaseExpired`), so its own
//! observation of the VM's end, its proof and cleanup follow as for any VM that ended; an
//! end while no engine ran is in the supervisor's journal ([`journal`]), which the next
//! engine start records in each sandbox's audit stream.
//!
//! **What the engine does** (`sandbox_vm::engine`): starts the supervisor at the first
//! launch and hands it each VM before the launch returns (a VM it cannot hand over is
//! stopped and the launch refused); sends the lease terms at every poll; releases a VM it
//! stopped or revoked; notices the supervisor's death at the next poll, records it, starts
//! another and hands it every VM again (the VMs never depended on it while the engine
//! runs). A live supervisor that stops answering keeps its handles and deadlines:
//! a transport timeout never justifies removing the independent guard. Further
//! operations may be refused until the held VMs end and the channel is recovered.

pub mod client;
pub mod journal;
pub mod policy;
pub mod process;
pub mod protocol;

/// The argument that runs this binary as the lifetime supervisor.
pub const SUPERVISOR_MODE: &str = "--sandbox-supervisor";

pub use client::SupervisorClient;
pub use protocol::{EndCause, HeldEnd, SupervisorSettings};
