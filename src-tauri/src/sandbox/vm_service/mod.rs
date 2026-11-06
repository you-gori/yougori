//! The sandbox VM service: one engine-facing API over the QEMU backend, the guest link and
//! the terminal command path (leftover entries M02, M06 and M13;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: §6.1 launch transaction, line 2295;
//! §6.2 timeouts and leases, line 2307; §6.3 revocation protocol, lines 2315–2329; §6.4
//! supervisor safety, lines 2331–2337; §8.1 evidence records, lines 2444–2450; §11.1 step
//! 3, line 2713, "one verified VM launch"; VM-W16, VM-W24, VM-W25 and VM-W26, lines
//! 2641–2643).
//!
//! Every piece of the minimal VM path exists on its own: the lifecycle supervisor and the
//! sandbox host (`sandbox::host`), the QEMU backend over its three host ports
//! (`sandbox::qemu`), the checked link socket (`sandbox::link_transport`) and the link
//! itself (`sandbox::link`). A [`VmService`] composes them into the calls a product
//! entrypoint makes: [`VmService::launch`], [`VmService::exec`] (and its two halves
//! [`VmService::start_exec`] and [`VmService::wait_exec`]), [`VmService::cancel`],
//! [`VmService::stop`], [`VmService::revoke`], [`VmService::status`] and
//! [`VmService::shutdown`]. Its DTOs ([`LaunchSpec`], [`ExecRequest`], [`ExecOutcome`],
//! [`StopReport`], [`RevocationReport`], [`SandboxStatus`], [`ShutdownReport`],
//! [`VmServiceError`]) are what an engine method carries: `Serialize`, and strict
//! `Deserialize` where they are read back. `API.md` beside this module's harness states the
//! API as an engine method calls it.
//!
//! The routes, and what each keeps:
//!
//! 1. Launch (§6.1; VM-W24). The service refreshes the host's CORE-01 evidence for the
//!    hypervisor and the runtime category, admits the runtime as a VM sandbox, sets the
//!    launch profile (the pinned guest image and its configuration row, the backend build,
//!    the contract, device profile and required properties) and runs the launch
//!    transaction through the supervisor with the spec's resources reserved in the host's
//!    CORE-03 ledger and a task lease with the plan's defaults
//!    ([`LeaseLimits::defaults`](crate::sandbox::lifecycle::LeaseLimits::defaults)).
//!    Authority comes only after the backend's host-observed readiness. Then it connects the
//!    boot's `link.sock` through `LinkSocketEndpoint`, admitted only when its peer is the
//!    QEMU process the backend started; takes the bootstrap secret once from the host port;
//!    draws a connection nonce from the OS generator; opens the boot's channels; starts that
//!    boot's transport driver; and returns once the guest's hello completed the link's
//!    handshake. A failure at any step after the VM exists revokes the sandbox through the
//!    supervisor, which closes whatever channel opened and stops the VM through its handle
//!    with the host's proof, and the failure says how far that cleanup got
//!    ([`LaunchCleanup`]).
//! 2. Commands (§6.2; VM-W25). Each command is authorized as CORE-04 child work on fresh
//!    readiness (`Supervisor::authorize_observed_work` observes the VM again through the
//!    backend when the last observation is older than the configured age; §8.1 line 2450),
//!    runs on its own terminal stream (`SandboxHost::start_command`), counts as activity,
//!    and gives its lease back when it ends. Its output and exit code are the guest's word
//!    ([`GuestBytes`], source class `guest_report`), never host facts.
//! 3. Revocation and stop (§6.3; VM-W26). A revocation is the supervisor's: the durable
//!    epoch advances, the host closes the boot's channels, the service asks for new work
//!    once so the coordinator's refusal is the observed "new authorizations denied", the
//!    boot's pump writes what the close policy allows and shuts the stream down, which is
//!    the physical closure the host acknowledges as "channels closed" (never its session
//!    state alone), the supervisor stops the VM through its handle once the gate opens,
//!    the service checks the backend holds the host's proof that exactly that QEMU process
//!    ended, observes the private directory gone through the host port, and only then
//!    records the logical cleanup. Each is its own observed result with its own time
//!    ([`RevocationReport`]): the denial of new work, the physical closure of the
//!    channels, the process's end and the release of its files are four facts. A stop
//!    first asks the guest to shut down within a grace (the link's `Shutdown` message) and
//!    waits, in real time, for the host to observe the guest gone (its stream ended or its
//!    process ended); then it is a user-requested revocation, reported as the stop's
//!    milestones ([`StopReport`]).
//! 4. Status (§8.1). Each sandbox's state, its host-observed readiness with its time, its
//!    launch record's identity and accelerator, its link and transport, and its running
//!    commands; a guest report is never shown as a host fact.
//!
//! Threading: the service owns one `SandboxHost` behind a mutex, and one transport driver
//! thread per boot that steps the boot's session pump (reads into the host, writes what
//! the host queues), ticks the host about once per tick interval on the host clock, and
//! stops when the pump finished (the link closed, the boot lost its authority, the stream
//! ended) or the service shuts down. Every call takes the mutex briefly; `launch`, `exec`
//! and `wait_exec` then wait on a condition variable without holding it.
//! [`VmService::shutdown`] closes every channel, writes each boot's close frame and joins
//! every driver within a bound.
//!
//! 5. Recovery (§6.1 line 2292; VM-D7). [`VmService::persist`] is what to store after
//!    every call that changed the supervisor's state; [`VmService::recover`] starts a
//!    service from it after a restart of the engine: every stored handle is checked
//!    through the backend (a restarted host holds no process, so every VM of the earlier
//!    run is gone: on Windows its kill-on-close job ended it with the engine), no lease or
//!    authority is revived, and the report names what was found ([`RecoveryReport`]).
//!    The private directories an earlier run left are the host port owner's to sweep.
//!
//! 6. Publications and connections (M14; modules `publish` and `connect`): a launch's
//!    declared services and connection endpoints attach to the connection gate; the gate
//!    admits callers of a live publication and connections an owner granted at both ends.
//!
//! What the service does not do yet, by design: a reconnect of a boot's link after its
//! stream ended.

mod config;
mod connect;
mod delegation;
mod dto;
mod error;
mod ports;
mod runtime;
mod service;
mod egress;
mod ingress;
mod publish;
mod remote;
mod state;

#[cfg(test)]
pub(crate) mod fakes;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_remote;
#[cfg(test)]
mod tests_delegation;

pub use delegation::VmDelegation;

pub use config::{
    ConfigRefusal, DriverSettings, EvidenceSubjects, PinnedImage, VmServiceConfig, VmServiceParts,
};
pub use dto::{
    BootPhase, CancelledBy, ChannelsClosedOnShutdown, CommandId, DirectoryRemoval, ExecEnd,
    ExecOutcome, ExecRequest, GuestBytes, GuestShutdown, GuestShutdownOutcome, LaunchRecordView,
    LaunchSpec, LeaseTerms, LinkLoss, LinkView, Milestone, ReadinessBy, ReadinessView,
    RecoverRefusal, RecoveryReport, RevocationReport, RevocationView, RevokeReason, SandboxId,
    SandboxStatus, SharedVm, ShutdownNotRequested, ShutdownReport, StopReport, TransportView,
    VmResources, VmStop,
    MAX_EXEC_DEADLINE, TERMINAL_COLUMNS, TERMINAL_ROWS,
};
pub use error::{
    EvidenceStep, HostRefusal, LaunchCleanup, LaunchStep, RequestProblem, VmServiceError,
};
pub use ports::{HostProcessTable, ServiceLedger, SharedLedgerView, VmHostPort, VmPorts};
pub use runtime::ServiceRuntime;
pub use connect::{
    check_connect, CallerView, ConnectionEndpoint, ConnectionsView, EndpointView, GrantView,
    DEFAULT_CONNECTION_BUDGET_BYTES, MAX_CONNECTION_BUDGET_BYTES, MAX_CONNECTION_ENDPOINTS,
    MAX_CONNECTION_LIFETIME,
};
pub use egress::{EgressInbound, EgressPort, EgressView};
pub use publish::{
    check_published, BudgetView, PublicationAudience, PublicationView, PublicationsView,
    PublishedPort, SessionsPumped, MAX_PUBLICATION_LIFETIME, MAX_PUBLISHED_PORTS, OWNER_PRINCIPAL,
    OWNER_SESSION_RELEASE_BYTES, PUBLISHED_RESPONSE_BYTES,
};
pub use ingress::{
    CallerRoom, GuestIngress, GuestIngressWatch, IngressView, MAX_INBOUND_BYTES,
    MAX_OUTBOUND_BYTES,
};
pub use remote::{RemoteControlView, MAX_REMOTE_TTL, REMOTE_BOOTSTRAP};
pub use service::VmService;
pub use state::WORKSPACE_GRANT;
#[cfg(feature = "acceptance")]
pub use state::PLANT_GPU_REQUEST;

pub use crate::sandbox::host::{MAX_COMMAND_INPUT_BYTES, MAX_COMMAND_OUTPUT_BYTES};
