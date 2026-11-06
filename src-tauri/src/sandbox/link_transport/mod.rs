//! The guest link's transport side: a bounded driver that moves bytes between a
//! [`HostLink`](crate::sandbox::link::HostLink) and any byte stream, and the
//! restricted-writer policy of each platform transport as checked data
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §3.2 lines 2059–2077, transport line
//! 2061, host-bound channel lines 2073–2074; VM-W06 line 2591; VM-P03 line 2778; VM-P28
//! and VM-P29 lines 2803–2804; VM-R25 line 2890, VM-R56 line 2921, VM-R64 line 2929;
//! §7.3 lines 2376–2386; tracker M06, carried forward from H02: "Validate the current
//! pre-authentication oversized-header behavior: any writer admitted to the per-instance
//! transport can close that link. Restrict transport writers and test the resulting
//! failure/recovery boundary").
//!
//! - [`driver`]: [`LinkDriver`] over any `Read + Write` pair: one read buffer, at most one
//!   outbound frame held, bounded reads and writes per call, a write stall timeout, and
//!   closed or failed transports as typed [`TransportEvent`]s. Its notes state what any
//!   writer can do before authentication and what recovery on a new connection refuses:
//!   [`LinkDriver::connect`] binds the link to the host's nonce for that connection.
//!   What a close still writes is the stream's close policy ([`stream_io`]): an orderly
//!   close drains the one frame already taken, bounded by the stall timeout; any other
//!   close submits no old bytes, discarding an unwritten frame and abandoning the
//!   transport ([`TransportEnd::Aborted`]) after a partial one (review finding R2).
//! - [`stream_io`]: those bounds as [`StreamIo`], shared by the driver and the sandbox
//!   host's session pump (`sandbox::host::SessionPump`), which carries the link the host
//!   owns; [`StreamShutdown`] ends a stream after its last frame.
//! - [`af_unix`]: the AF_UNIX link socket of a QEMU launch on Windows as a port: only the
//!   launch's `link.sock` is dialed, and a stream whose peer process is not the QEMU
//!   process the host started is refused before a byte is read.
//! - [`sddl`]: a strict reader and writer of the SDDL subset that states a pipe's owner,
//!   DACL and mandatory label.
//! - [`pipe`]: the Windows named pipe of one VM: per-instance name, first instance, one
//!   instance, remote clients rejected, a protected DACL for the host and the
//!   hypervisor's own SID, a low label; and the check of an observed pipe.
//! - [`unix_socket`]: the Unix-domain socket's directory and file owner, group and modes,
//!   and the peer's credentials, for a hypervisor running as the host and for
//!   Firecracker's jail.
//! - [`vsock`]: the guest's context id on the device, the host listener's address and the
//!   accepted peer, for kernel vsock and Firecracker's Unix-socket form.
//!
//! Everything is synchronous and deterministic: time comes from the shared clock, and no
//! pipe, socket or process is created here; the streams and lookups are ports. Applying a
//! pipe descriptor through the Windows API, binding sockets, reading the observations and
//! the client-process checks belong to the backends' adapters.

pub mod af_unix;
pub mod driver;
pub mod pipe;
pub mod sddl;
pub mod stream_io;
pub mod unix_socket;
pub mod vsock;

#[cfg(test)]
mod tests;

pub use af_unix::{
    CheckedStream, EndpointRefusal, LinkConnector, LinkSocketEndpoint, PeerProcess, ProcessTable,
};
pub use driver::{
    Closure, DriverCounters, DriverEvent, DriverLimits, DriverLimitsError, DriverPhase,
    DriverSetupError, FailureKind, LinkDriver, TransportEnd, TransportEvent, TransportFailure,
    TransportOperation, DEFAULT_READ_CHUNK_BYTES, MAX_READ_CHUNK_BYTES,
};
pub use pipe::{
    HostIdentity, HostKind, HypervisorIdentity, HypervisorKind, NamedPipePolicy, ObservedPipe,
    PipeFinding, PipePolicyError, HYPERVISOR_PIPE_ACCESS, LINK_PIPE_MAX_INSTANCES, LINK_PIPE_MODE,
    LINK_PIPE_OPEN_MODE, LINK_PIPE_PREFIX, PIPE_NAMESPACE,
};
pub use sddl::{
    Ace, AceFlags, AceType, Acl, AclFlags, SddlError, SddlErrorKind, SecurityDescriptor, Sid,
    MAX_ACES, MAX_SDDL_BYTES, MAX_SUB_AUTHORITIES,
};
pub use stream_io::{drains, FrameEnd, StreamIo, StreamShutdown, StreamStop, WriteStop};
pub use unix_socket::{
    NodeKind, NodePolicy, NodeRole, ObservedNode, ObservedUnixSocket, UnixIdentity,
    UnixPolicyError, UnixSocketFinding, UnixSocketPolicy,
};
pub use vsock::{
    GuestCid, ObservedVsock, ObservedVsockPeer, VsockFinding, VsockKind, VsockPolicy,
    VsockPolicyError, VsockPort,
};
