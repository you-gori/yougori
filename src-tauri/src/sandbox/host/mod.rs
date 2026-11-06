//! The sandbox host: one place that composes the runtime pieces of each running sandbox
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part: §3.1 lines 2019–2057, the
//! supervisor and relay rows; §3.2 lines 2059–2077; §6.1–§6.4 lines 2284–2326; §8.1 lines
//! 2433–2439; §8.2 lines 2441–2449; §16.1 lines 3042–3050, the `sandbox-host` binary in
//! mode `supervise`).
//!
//! The pieces are committed and used unchanged; until now nothing composed them for one
//! running sandbox. A [`SandboxHost`] owns:
//!
//! - the lifecycle supervisor (`sandbox::lifecycle::Supervisor`, over the CORE-04
//!   coordinator and the CORE-03 ledger) and a backend behind `sandbox::backend::VmBackend`
//!   (the QEMU or Firecracker backend over its ports, or the fake), reached for each
//!   supervisor call through integration's `BackendPort` over the host's `LaunchTable`, its
//!   CORE-01 registry and its reservation resolver ([`HostParts`]);
//! - the audit sink (`sandbox::integration::AuditSink`, durable and spooled in
//!   production), which receives after every supervisor call the lifecycle receipts, the
//!   refused launches and each new launch record ([`AuditDrain`]);
//! - per sandbox boot, a [`BootSession`]: the handle of the VM the host launched, the guest
//!   link (`sandbox::link::HostLink`) bound to that VM instance and boot generation and to
//!   the connection nonce the caller drew (M06-LC), the guest-file adapter
//!   (`sandbox::guest_files::GuestFiles`) of the link's file channel, and the commands on
//!   its terminal channel.
//!
//! The routes, and the guarantees they keep end to end:
//!
//! 1. Launch. The launch transaction runs in the supervisor ([`SandboxHost::launch`]); a
//!    failure before authority exposes no channel (§6.1 line 2292). A boot's channels open
//!    ([`SandboxHost::open_channels`]) only while it holds authority, bound to the VM
//!    instance and boot generation the coordinator recorded, to the handle the supervisor
//!    keeps and to the tenant and execution of the sandbox, never to anything a guest sends
//!    (§3.2 line 2073); the bootstrap secret is the caller's, per instance (line 2075).
//! 2. Readiness from fresh evidence. Work is authorized only through the supervisor's
//!    observed path ([`SandboxHost::authorize_work`]): readiness older than the configured
//!    age is observed again through the backend before work is admitted, and stale
//!    launch-time evidence is never presented as current (§8.1 line 2439). While the host
//!    finds the VM not ready, it refuses a guest's new file streams itself (`OpenRefused`
//!    with `Unavailable`); streams already open continue. A guest cannot make the host
//!    observe again: only the host's own calls do.
//! 3. Link messages to guest files. Bytes from the transport go to the boot's link
//!    ([`SandboxHost::receive`]); the file channel's events go to the adapter, which answers
//!    on the same link; guest reports and the link's other events are returned to the
//!    caller ([`Delivery`]), never as host facts (§8.1 line 2437). Guest traffic is never
//!    reported as activity (§6.2 line 2298). Each delivery first enforces the sandbox
//!    leases at the clock's reading, so a lapsed authority is not served (§6.3 line 2316:
//!    every enforcement point participates).
//! 4. Revocation closes channels and stops the VM. After every supervisor call, the host
//!    closes the channels of each boot that no longer holds authority: every grant is taken
//!    off the file channel (its streams cancelled as revoked, its bodies ended and their
//!    reservations released, nothing written), and the link is closed and dropped, its
//!    close frame handed to the caller for the transport, so the boot takes no further
//!    guest byte ([`ChannelClosure`]). For a sandbox under revocation with no channel left
//!    open, the host then acknowledges "channels closed" as a host observation
//!    ([`ChannelsAcknowledged`]) and advances the revocation, so the supervisor's gate
//!    stops the VM through its handle once the outstanding leases allow
//!    ([`RevocationAdvanced`]; §6.3 lines 2309–2311). The acknowledgment distinguishes the
//!    logical denial from the physical closure: a boot whose link a transport carries
//!    ([`TransportState`]) is acknowledged only once that stream ended, which the pump
//!    reports when it shut the stream down ([`SandboxHost::transport_ended`]); the host's
//!    own session state never stands for it. Each [`SandboxHost::tick`] advances every
//!    revocation whose VM has not stopped, whichever call decided it.
//! 5. Recovery. [`SandboxHost::shut_down`] closes every channel and hands back the parts
//!    that outlive the supervisor; [`SandboxHost::recover`] restarts the supervisor from its
//!    persisted state over them (§6.1 line 2292: recovery reconciles actual VM objects). No
//!    authority survives: no channel is open after recovery, a task found alive is ended,
//!    and a service kept without authority serves again only after
//!    [`SandboxHost::reauthorize`] and new channels.
//! 6. Teardown. Once the VM stopped, [`SandboxHost::teardown`] drops the boot's objects.
//! 7. Commands (VM-W24; §3.2 terminal channel). [`SandboxHost::start_command`] opens a
//!    terminal stream on a boot that holds authority, after the leases are enforced; the
//!    caller's bounded input goes out within the guest's credit and is ended, the guest's
//!    output is kept up to the caller's limit (the rest counted and dropped, the stream
//!    cancelled) and credited back as it is taken, and the guest's exit report ends the
//!    command ([`CommandResult`], in the deliveries' [`CommandEvent`]s).
//!    [`SandboxHost::cancel_command`] and the caller's time limit cancel the stream; a
//!    closure of the boot's channels ends every command with its cause (a revocation as
//!    revoked), in the [`ChannelClosure`]. Output and exit codes are guest data
//!    ([`GuestOutput`], `GuestReport`), never host facts.
//! 8. The stream. A [`SessionPump`] carries one boot's link over its byte stream with
//!    `sandbox::link_transport`'s bounded I/O: bytes read go to [`SandboxHost::receive`],
//!    frames come from [`SandboxHost::next_outbound`] one at a time, the stream's end or
//!    failure reaches [`SandboxHost::peer_closed`], and after the link or the boot's
//!    channels close it writes the close frame and shuts the stream down. On Windows the
//!    stream is the launch's AF_UNIX link socket, admitted only when its peer is the QEMU
//!    process the host started (`sandbox::link_transport::LinkSocketEndpoint`).
//!
//! Any other supervisor call goes through [`SandboxHost::with_supervisor`] and is followed
//! by the same closing of channels and recording to audit, so the guarantees above hold
//! whichever call took the authority away.
//!
//! Everything is pure and synchronous: time comes from the shared clock, the transport is
//! the caller's (bytes in and frames out, or a stream the caller's loop drives through a
//! pump; no thread is spawned here), and no process, VM, network or file is touched
//! here. The process split of §16.1 (supervisor, relay and file broker in separate
//! processes) is outside this module; it composes their logic in one place.

mod egress;
mod error;
mod ingress;
mod log;
mod pump;
mod sandbox_host;
mod session;
mod terminal;

#[cfg(test)]
pub(crate) mod fakes;
#[cfg(test)]
mod pump_tests;
#[cfg(test)]
mod tests;

pub use egress::{EgressEndCause, EgressEvent, EgressRefusal, MAX_PENDING_BYTES};
pub use error::HostError;
pub use ingress::{IngressEndCause, IngressEvent, IngressRefusal};
pub use log::{
    AuditDrain, ChannelClosure, ChannelsAcknowledged, ClosureCause, Delivery, HostLog, HostTick,
    RefusedOpen, RevocationAdvanced, TeardownReport,
};
pub use pump::{PumpEvent, PumpRefusal, SessionPump};
pub use sandbox_host::{HostParts, HostRecoveryFailure, HostShutdown, SandboxHost};
pub use session::{channel_operation, BootSession, ChannelSetup, TransportState, CHANNEL_DOMAIN};
pub use terminal::{
    CommandEnd, CommandEvent, CommandRefusal, CommandRequest, CommandResult, GuestOutput,
    MAX_COMMAND_INPUT_BYTES, MAX_COMMAND_OUTPUT_BYTES,
};
