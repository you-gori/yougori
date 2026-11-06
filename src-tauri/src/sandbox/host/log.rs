//! What the host did and reports (module docs in `mod.rs`): what reached the audit sink,
//! the channels it closed and the acknowledgments it gave, what a delivery of guest bytes
//! produced, and what a teardown found. None of these is persisted; the audit stream is the
//! durable record, and these say how writing to it went.

use crate::foundation::coordination::{SandboxState, VmInstanceId};
use crate::foundation::events::AuditReceipt;
use crate::foundation::ids::{Digest, ExecutionId, MonotonicTime, SandboxBootGeneration};
use crate::sandbox::guest_files::{FilesCounters, FilesEvent};
use crate::sandbox::integration::{LaunchAudit, RefusedLaunch, SinkRefusal};
use crate::sandbox::lifecycle::{
    AckEffect, LifecycleReceipt, RevocationProgress, SupervisorError, TickReport,
};
use crate::sandbox::link::{
    CloseCause, CloseReason, GrantHandle, GuestReport, LinkEvent, SendRefusal, StreamId,
};
use crate::sandbox::link_transport::TransportEnd;

use super::egress::EgressEvent;
use super::ingress::IngressEvent;
use super::terminal::{CommandEvent, CommandResult};

/// What the audit sink was given after supervisor calls, in order, with each outcome. A
/// refusal is reported here and never stops the call that produced the record: a
/// revocation is never held back by its audit (§8.2 line 2445).
#[derive(Clone, Debug, Default)]
pub struct AuditDrain {
    /// Every lifecycle receipt the supervisor produced.
    pub receipts: Vec<(LifecycleReceipt, Result<AuditReceipt, SinkRefusal>)>,
    /// Every refused launch, with its typed refusal.
    pub refusals: Vec<(RefusedLaunch, Result<AuditReceipt, SinkRefusal>)>,
    /// Every new launch record, by its identity digest.
    pub launches: Vec<(Digest, Result<LaunchAudit, SinkRefusal>)>,
}

impl AuditDrain {
    /// Whether nothing was given to the sink.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty() && self.refusals.is_empty() && self.launches.is_empty()
    }

    /// How many records the sink refused.
    pub fn refused(&self) -> usize {
        self.receipts
            .iter()
            .filter(|(_, outcome)| outcome.is_err())
            .count()
            + self
                .refusals
                .iter()
                .filter(|(_, outcome)| outcome.is_err())
                .count()
            + self
                .launches
                .iter()
                .filter(|(_, outcome)| outcome.is_err())
                .count()
    }
}

/// Why the host closed a boot's channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureCause {
    /// The sandbox is under revocation (§6.3 step 2, line 2309).
    Revoked,
    /// The boot no longer holds authority otherwise: the sandbox is in `state` (absent when
    /// the coordinator no longer knows it), or a later boot replaced this one.
    AuthorityLost { state: Option<SandboxState> },
    /// The host is shutting down ([`super::SandboxHost::shut_down`]).
    Shutdown,
}

impl ClosureCause {
    /// The reason the link's close frame carries.
    pub const fn close_reason(self) -> CloseReason {
        match self {
            Self::Revoked | Self::AuthorityLost { .. } => CloseReason::Revoked,
            Self::Shutdown => CloseReason::Shutdown,
        }
    }
}

/// The host closed one boot's channels: what taking every grant off the file channel did,
/// how the link closed, and the frames left for the transport to write before it closes.
/// After a closure the boot takes no further guest byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelClosure {
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub vm: VmInstanceId,
    pub cause: ClosureCause,
    /// On the host clock.
    pub at: MonotonicTime,
    /// The grants taken off the file channel.
    pub grants: Vec<GrantHandle>,
    /// What the adapter did: streams cancelled as revoked, bodies ended, the link lost.
    pub files: Vec<FilesEvent>,
    /// The commands that were running, each ended with the closure's cause; their output
    /// stops where the closure found it.
    pub commands: Vec<CommandResult>,
    /// The egress streams that were open, each ended with the closure's cause.
    pub egress: Vec<EgressEvent>,
    /// The ingress streams that were open, each ended with the closure's cause.
    pub ingress: Vec<IngressEvent>,
    /// How the link had closed before the host closed it, if it had.
    pub link_closed_before: Option<CloseCause>,
    /// Why the link refused the close frame, if it did; the link was dropped all the same,
    /// with no close frame.
    pub close_refused: Option<SendRefusal>,
    /// The close frame for the transport, sealed; the transport writes it and closes. A
    /// session pump carrying the boot's stream writes it itself; a caller without one
    /// writes these.
    pub final_frames: Vec<Vec<u8>>,
}

/// The host acknowledged "channels closed" for a sandbox under revocation, as a host
/// observation (§6.3 step 3, lines 2310 and 2314): once no channel of it was open in the
/// host and, for a boot whose link a transport carried, once that stream had ended
/// ([`TransportState`](super::TransportState): shut down by its pump or dropped by its
/// owner). A closure the host recorded in its session state alone is not the
/// acknowledgment (review of 29 October: "`ChannelsClosed` is acknowledged from in-memory
/// boot-session state").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelsAcknowledged {
    pub execution: ExecutionId,
    pub at: MonotonicTime,
    /// How the boot's stream ended, when a transport carried its link; `None` when none
    /// ever did (the channels never left the host's memory).
    pub transport_end: Option<TransportEnd>,
    pub outcome: Result<AckEffect, SupervisorError>,
}

/// The host advanced a revocation (§6.3 steps 3–5): right after its own acknowledgment of
/// "channels closed", which opens the supervisor's gate, and on each tick while the VM has
/// not stopped, so a revocation the supervisor decided itself reaches the VM's stop too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationAdvanced {
    pub execution: ExecutionId,
    pub at: MonotonicTime,
    pub outcome: Result<RevocationProgress, SupervisorError>,
}

/// Everything the host recorded since the log was last taken
/// ([`super::SandboxHost::take_log`]), in order.
#[derive(Clone, Debug, Default)]
pub struct HostLog {
    pub audit: AuditDrain,
    pub closures: Vec<ChannelClosure>,
    pub acknowledgments: Vec<ChannelsAcknowledged>,
    pub advances: Vec<RevocationAdvanced>,
}

impl HostLog {
    /// Whether nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.audit.is_empty()
            && self.closures.is_empty()
            && self.acknowledgments.is_empty()
            && self.advances.is_empty()
    }

    /// The closure of `execution`'s channels, if one is in the log.
    pub fn closure_of(&self, execution: &ExecutionId) -> Option<&ChannelClosure> {
        self.closures
            .iter()
            .find(|closure| &closure.execution == execution)
    }
}

/// A new file stream the host refused itself, before the adapter, because the host did not
/// find the VM ready (§8.1 line 2439).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedOpen {
    pub stream: StreamId,
    pub grant: GrantHandle,
    /// Why the link did not take the refusal, if it did not.
    pub unsent: Option<SendRefusal>,
}

/// What one delivery of guest bytes, a disconnect or a tick of the link produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    /// What the guest-file adapter did with the file channel's events.
    pub files: Vec<FilesEvent>,
    /// What happened to the commands on the terminal channel; their output and exit
    /// reports are the guest's word.
    pub commands: Vec<CommandEvent>,
    /// What the guest reported: its word, never a host fact.
    pub reports: Vec<GuestReport>,
    /// New file streams refused by the host while readiness is unavailable.
    pub refused_opens: Vec<RefusedOpen>,
    /// What happened on the egress channel: opens accepted or refused, the guest's bytes
    /// for the port, streams ended.
    pub egress: Vec<EgressEvent>,
    /// What happened on the ingress channel: opens answered, the guest service's bytes for
    /// the caller, streams ended.
    pub ingress: Vec<IngressEvent>,
    /// The link's events no composed piece takes: requests of the other channels, frames
    /// the link refused, timed-out streams of the other channels.
    pub other: Vec<LinkEvent>,
    /// Set when the link closed in this delivery.
    pub closed: Option<CloseCause>,
}

/// What one tick of the host did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostTick {
    /// The supervisor's lease enforcement.
    pub supervisor: TickReport,
    /// Each open boot's link timeouts and transfer checks.
    pub deliveries: Vec<(ExecutionId, Delivery)>,
}

/// What tearing a stopped boot down found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeardownReport {
    pub execution: ExecutionId,
    pub boot: SandboxBootGeneration,
    pub vm: VmInstanceId,
    /// What the file channel counted over the boot.
    pub counters: FilesCounters,
    /// When the host closed the boot's channels.
    pub closed_at: Option<MonotonicTime>,
}
