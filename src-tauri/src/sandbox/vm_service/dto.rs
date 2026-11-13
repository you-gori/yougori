//! What the service's calls take and give (module docs in `mod.rs`): the DTOs an engine
//! method carries. Every one is `Serialize`; the ones read back from a caller
//! ([`SandboxId`], [`CommandId`], [`LaunchSpec`], [`VmResources`], [`ExecRequest`],
//! [`RevokeReason`]) read strictly: unknown fields are refused, identifiers are checked as
//! the committed identifier grammar checks them, and bytes travel as lowercase or
//! uppercase hex. Nothing secret is in any of them: no bootstrap secret, transfer key or
//! credential, and the `Debug` of caller input and guest output shows only their length.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{SandboxState, VmInstanceId};
use crate::foundation::evidence::{ConfigurationFingerprint, SourceClass};
use crate::foundation::ids::{Digest, ExecutionId, MonotonicTime, SandboxBootGeneration, TenantId};
use crate::foundation::process::{ProcessIdentity, SharedHandles};
use crate::sandbox::backend::{Accelerator, HostObserved};
use crate::sandbox::host::{ClosureCause, CommandEnd, CommandResult};
use crate::sandbox::lifecycle::{
    AckSource, Acknowledgment, RevocationCause, SandboxClass, DEFAULT_TASK_ABSOLUTE,
};
use crate::sandbox::link::{
    CancelCause, ChannelCloseCause, CloseCause, OpenRefusalCause, StreamId,
};
use crate::sandbox::link_transport::{DriverCounters, TransportEnd};
use crate::sandbox::qemu::{HostPath, ObserveFailure};

/// The longest a command may run: the task sandbox's default absolute limit, 24 hours.
pub const MAX_EXEC_DEADLINE: Duration = DEFAULT_TASK_ABSOLUTE;
/// The terminal size every command's stream opens with.
pub const TERMINAL_COLUMNS: u16 = 80;
pub const TERMINAL_ROWS: u16 = 24;

/// One sandbox, by its execution identity: the key the coordinator, the supervisor, the
/// ledger and the audit stream record it under. The service draws it at launch
/// (`exe-` and 32 hexadecimal digits from the OS generator).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SandboxId(ExecutionId);

impl SandboxId {
    pub fn new(execution: ExecutionId) -> Self {
        Self(execution)
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SandboxId({})", self.0)
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// One command of a sandbox: the number of its terminal stream on the sandbox's boot,
/// unique within the sandbox (a sandbox has one boot in this service).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandId(u32);

impl CommandId {
    pub const fn get(self) -> u32 {
        self.0
    }

    pub(super) fn of(stream: StreamId) -> Self {
        Self(stream.get())
    }

    pub(super) const fn from_number(number: u32) -> Self {
        Self(number)
    }

    /// The terminal stream, when the number can name one.
    pub(super) fn stream(self) -> Option<StreamId> {
        StreamId::new(self.0)
    }
}

impl fmt::Display for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "command {}", self.0)
    }
}

/// What a launch reserves in the host's CORE-03 ledger before anything is created (S10:
/// reserve before creating).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmResources {
    /// Host memory for the VM, in bytes; it must hold the guest memory the host layout
    /// gives the VM, or the QEMU profile refuses the launch.
    pub memory_bytes: u64,
    /// CPU slots reserved for this VM. The production QEMU layout exposes one vCPU
    /// per slot; the reservation remains held until the VM ends.
    pub cpu_slots: u64,
}

/// What [`VmService::launch`](super::VmService::launch) is asked for. The guest image, the
/// backend build and the confinement are the service's, pinned at construction; a launch
/// names only who pays and how much it reserves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    #[serde(default)]
    pub gpu: bool,
    /// Shared-GPU admission budget, held until HCS confirms VM removal. GPU-PV
    /// itself is scheduled by Windows and does not enforce a per-VM VRAM quota.
    #[serde(default)]
    pub gpu_memory: Vec<(crate::foundation::ids::GpuDeviceKey, u64)>,
    /// Explicit outbound NAT; false keeps the adapter absent. Every frame of the adapter
    /// passes the host's network filter: the public internet only, or with `targets` those
    /// alone.
    #[serde(default)]
    pub internet: bool,
    /// With `internet`, the only destinations its adapter reaches (resolved on this computer
    /// at launch); `None` is the public internet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<crate::sandbox::backend::NetworkTarget>>,
    /// An owner session: a VM its owner launched for an attended session in their terminal (an
    /// inference harness). Its publications reach only the owner, with a release account of
    /// [`super::publish::OWNER_SESSION_RELEASE_BYTES`] instead of VM-D12's 8 MiB.
    #[serde(default)]
    pub owner_session: bool,
    /// The tenant the reservation and the sandbox's authority are charged to.
    pub tenant: TenantId,
    pub resources: VmResources,
    /// The endpoints the guest may address by name over the link's egress channel; the
    /// guest learns them at boot (the relay serving them is attached separately).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_endpoints: Vec<crate::sandbox::backend::GuestEgressEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_image: Option<crate::sandbox_contract::oci::WorkloadImage>,
    /// The task sandbox's idle limit lowered below its default (VM-D12: how long it may go
    /// without a command); `None` keeps the default, zero disables the timer. A finite raise is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_limit: Option<Duration>,
    /// The task sandbox's absolute limit lowered below its default (how long it may live
    /// at all); `None` keeps the default, zero means until stopped. A finite raise is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_limit: Option<Duration>,
    /// The guest services the sandbox may publish (M14): its launch holds CORE-04's
    /// published-service grant for each, and nothing else is ever published.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub published: Vec<super::publish::PublishedPort>,
    /// The connection endpoints its guest's programs may use (M14): each reaches nothing
    /// until it is granted another sandbox's declared service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connect: Vec<super::connect::ConnectionEndpoint>,
}

impl LaunchSpec {
    /// The task lease limits of this launch: the defaults, lowered as asked.
    pub fn lease_limits(
        &self,
    ) -> Result<crate::sandbox::lifecycle::LeaseLimits, crate::sandbox::lifecycle::LimitRefusal>
    {
        use crate::sandbox::lifecycle::{LeaseLimits, LimitKind, SandboxClass};
        let mut limits = LeaseLimits::defaults(SandboxClass::Task);
        if let Some(idle) = self.idle_limit {
            limits = if idle.is_zero() { limits.without_timeout(LimitKind::Idle)? }
                else { limits.lower(LimitKind::Idle, idle)? };
        }
        if let Some(lifetime) = self.lifetime_limit {
            limits = if lifetime.is_zero() { limits.without_timeout(LimitKind::Absolute)? }
                else { limits.lower(LimitKind::Absolute, lifetime)? };
        }
        Ok(limits)
    }
}

/// One command for the guest's shell. Its `Debug` shows the input's length, never the
/// input.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    #[serde(default)]
    pub image_entrypoint: bool,
    /// The bytes for the shell's standard input, sent and then ended: at most
    /// [`MAX_COMMAND_INPUT_BYTES`](super::MAX_COMMAND_INPUT_BYTES). Hex in JSON.
    #[serde(with = "hex_bytes")]
    pub input: Vec<u8>,
    /// The most guest output kept, from 1 to
    /// [`MAX_COMMAND_OUTPUT_BYTES`](super::MAX_COMMAND_OUTPUT_BYTES); output beyond it is
    /// counted and dropped and the command ends.
    pub max_output_bytes: usize,
    /// How long the command may run from its start, on the host clock: from 1 ms to
    /// [`MAX_EXEC_DEADLINE`], or Duration::MAX until cancelled/stopped. Milliseconds in JSON (`deadline_ms`).
    #[serde(rename = "deadline_ms", with = "duration_millis")]
    pub deadline: Duration,
}

impl ExecRequest {
    pub fn new(input: impl Into<Vec<u8>>, max_output_bytes: usize, deadline: Duration) -> Self {
        Self {
            input: input.into(),
            image_entrypoint: false,
            max_output_bytes,
            deadline,
        }
    }
}

impl fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecRequest")
            .field("input_bytes", &self.input.len())
            .field("max_output_bytes", &self.max_output_bytes)
            .field("deadline", &self.deadline)
            .finish()
    }
}

/// Bytes a guest wrote: guest data (source class `guest_report`), never a host fact
/// (§8.1 line 2448). Hex in JSON; the `Debug` shows only the length.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GuestBytes(#[serde(serialize_with = "hex_bytes::serialize")] Vec<u8>);

impl GuestBytes {
    /// The only source class guest output has (CORE-01).
    pub const SOURCE: SourceClass = SourceClass::GuestReport;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub const fn source(&self) -> SourceClass {
        Self::SOURCE
    }
}

impl fmt::Debug for GuestBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GuestBytes({} bytes)", self.0.len())
    }
}

/// Who cancelled a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "side", rename_all = "snake_case")]
pub enum CancelledBy {
    /// The caller, through [`VmService::cancel`](super::VmService::cancel).
    Caller,
    /// The guest cancelled the stream, for this reason (the guest's word).
    GuestCancelled { cause: CancelCause },
    /// The guest refused to open the command's terminal (the guest's word).
    GuestRefused { cause: OpenRefusalCause },
}

/// How a command lost its link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkLoss {
    /// The link closed: the transport ended or failed, a protocol violation, the guest's
    /// close, a timeout.
    LinkClosed { cause: CloseCause },
    /// The link closed the terminal channel: the guest overran its window.
    TerminalClosed { cause: ChannelCloseCause },
    /// The guest did not answer the terminal open within the link's open timeout.
    OpenTimedOut,
    /// The boot lost its authority otherwise: the sandbox is in `state` (absent when the
    /// coordinator no longer knows it), or a later boot replaced it.
    AuthorityLost { state: Option<SandboxState> },
    /// The service shut down.
    ServiceShutDown,
}

/// How a command ended: exactly one of these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum ExecEnd {
    /// The guest ended the command: with its exit report (the outcome's `exit_code` is
    /// set) or by ending its output without one.
    Finished,
    /// The output passed the request's limit; the host cancelled the stream.
    OutputLimitReached,
    Cancelled {
        by: CancelledBy,
    },
    /// The request's deadline passed on the host clock; the host cancelled the stream.
    DeadlinePassed,
    /// The sandbox was revoked or stopped while the command ran.
    Revoked,
    LinkLost {
        loss: LinkLoss,
    },
}

/// One finished command. The output and the exit code are the guest's word.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecOutcome {
    pub command: CommandId,
    pub end: ExecEnd,
    /// The exit code the guest reported, when it reported one ([`ExecEnd::Finished`]).
    pub exit_code: Option<i32>,
    /// What the guest wrote, at most the request's limit.
    pub output: GuestBytes,
    /// Output that arrived beyond the limit and was dropped.
    pub output_dropped_bytes: u64,
    /// Input bytes the link took for the guest.
    pub input_sent_bytes: u64,
    /// On the host clock.
    pub started_at: MonotonicTime,
    pub ended_at: MonotonicTime,
}

impl ExecOutcome {
    /// The outcome of a command the host ended.
    pub(super) fn of(result: CommandResult) -> Self {
        let exit_code = result.exit_code();
        let end = match result.end {
            CommandEnd::Exited { .. } | CommandEnd::EndedWithoutExit => ExecEnd::Finished,
            CommandEnd::OutputLimitReached => ExecEnd::OutputLimitReached,
            CommandEnd::Cancelled => ExecEnd::Cancelled {
                by: CancelledBy::Caller,
            },
            CommandEnd::TimeLimitPassed => ExecEnd::DeadlinePassed,
            CommandEnd::OpenRefused { cause } => ExecEnd::Cancelled {
                by: CancelledBy::GuestRefused { cause },
            },
            CommandEnd::OpenTimedOut => ExecEnd::LinkLost {
                loss: LinkLoss::OpenTimedOut,
            },
            CommandEnd::GuestCancelled { cause } => ExecEnd::Cancelled {
                by: CancelledBy::GuestCancelled { cause },
            },
            CommandEnd::TerminalClosed { cause } => ExecEnd::LinkLost {
                loss: LinkLoss::TerminalClosed { cause },
            },
            CommandEnd::LinkClosed { cause } => ExecEnd::LinkLost {
                loss: LinkLoss::LinkClosed { cause },
            },
            CommandEnd::HostClosed {
                cause: ClosureCause::Revoked,
            } => ExecEnd::Revoked,
            CommandEnd::HostClosed {
                cause: ClosureCause::AuthorityLost { state },
            } => ExecEnd::LinkLost {
                loss: LinkLoss::AuthorityLost { state },
            },
            CommandEnd::HostClosed {
                cause: ClosureCause::Shutdown,
            } => ExecEnd::LinkLost {
                loss: LinkLoss::ServiceShutDown,
            },
        };
        Self {
            command: CommandId::of(result.stream),
            end,
            exit_code,
            output: GuestBytes(result.output.bytes().to_vec()),
            output_dropped_bytes: result.output.dropped_bytes(),
            input_sent_bytes: result.input_sent_bytes,
            started_at: result.started_at,
            ended_at: result.ended_at,
        }
    }
}

/// Why a stop did not ask the guest to shut down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ShutdownNotRequested {
    /// The boot's link had not completed its handshake, or had closed already.
    LinkNotOpen,
    /// The host had closed the boot's channels already (a revocation before the stop).
    ChannelsClosed,
    /// The host refused the request otherwise, in its own words.
    Refused { detail: String },
}

/// How a shutdown request ended, as the host observed it: never from the guest's word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum GuestShutdownOutcome {
    /// The guest closed its link, or its stream ended (it powered off), within the grace.
    LinkClosed { at: MonotonicTime },
    /// The VM's process ended within the grace, as the host observed through its handle.
    ProcessEnded { at: MonotonicTime },
    /// The grace passed with the guest still there; the stop goes on to revoke the sandbox
    /// and stop the VM through its handle.
    GraceExpired { waited_ms: u64 },
}

/// The first milestone of a stop: the guest asked to shut down within a grace (the link's
/// `Shutdown` message), and what the host then observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "guest_shutdown", rename_all = "snake_case")]
pub enum GuestShutdown {
    /// The request went to the guest at `at` on the host clock, naming `grace_seconds`.
    Requested {
        at: MonotonicTime,
        grace_seconds: u32,
        outcome: GuestShutdownOutcome,
    },
    NotRequested {
        reason: ShutdownNotRequested,
    },
}

/// Whether the VM stopped through its handle with the host's proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "vm_stop", rename_all = "snake_case")]
pub enum VmStop {
    /// The supervisor stopped the VM through its handle at `at`, and the backend holds the
    /// host's proof that exactly `process`, started as the host process of this VM boot,
    /// and every process of its job ended.
    Stopped {
        at: MonotonicTime,
        process: ProcessIdentity,
    },
    /// The supervisor recorded the VM stopped at `at`, but the backend holds no proof
    /// naming the process the service connected to; nothing is claimed about it.
    StoppedWithoutProof { at: MonotonicTime },
    /// The VM is not shown stopped: the acknowledgments still pending and how many
    /// outcomes the supervisor recorded as uncertain.
    NotStopped {
        pending: Vec<Acknowledgment>,
        uncertain: usize,
    },
}

impl VmStop {
    pub fn is_stopped(&self) -> bool {
        !matches!(self, Self::NotStopped { .. })
    }
}

/// Whether the launch's private directory is gone, as the host port observed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "directory", rename_all = "snake_case")]
pub enum DirectoryRemoval {
    /// The host observed the directory absent at `at`, on the host clock.
    Removed { at: MonotonicTime, path: HostPath },
    /// The host observed the directory still there.
    StillPresent { path: HostPath },
    /// The host could not observe it.
    NotObserved {
        path: HostPath,
        failure: ObserveFailure,
    },
    /// Not looked at: the VM is not shown stopped with the host's proof, and the host port
    /// removes the directory only after that proof; or the service knows no directory of
    /// the boot.
    NotChecked,
}

impl DirectoryRemoval {
    pub fn is_removed(&self) -> bool {
        matches!(self, Self::Removed { .. })
    }
}

/// What [`VmService::stop`](super::VmService::stop) observed, milestone by milestone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StopReport {
    pub sandbox: SandboxId,
    /// When the stop was asked, on the host clock.
    pub requested_at: MonotonicTime,
    /// 1. The guest asked to shut down within a grace.
    pub guest_shutdown: GuestShutdown,
    /// 2. The VM stopped through its handle, with the host's proof.
    pub vm_stop: VmStop,
    /// 3. The private directory gone.
    pub directory: DirectoryRemoval,
    /// The commands the stop ended; each one's outcome says `revoked`.
    pub commands_ended: Vec<CommandId>,
}

/// Why a caller revokes a sandbox. The supervisor's own causes (a lease that ran out, the
/// engine's death, a rolled-back clock, a service renewal) are its decisions, not a
/// caller's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    UserRequested,
    PolicyChanged,
    /// A clear violation (VM-D10).
    Violation,
    OwnerReclaimed,
}

impl RevokeReason {
    /// The supervisor's revocation cause.
    pub const fn cause(self) -> RevocationCause {
        match self {
            Self::UserRequested => RevocationCause::UserRequested,
            Self::PolicyChanged => RevocationCause::PolicyChanged,
            Self::Violation => RevocationCause::Violation,
            Self::OwnerReclaimed => RevocationCause::OwnerReclaimed,
        }
    }
}

/// One acknowledgment of a revocation (§6.3 line 2329).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "milestone", rename_all = "snake_case")]
pub enum Milestone {
    /// Observed at `at` on the host clock, established by `source`.
    Observed {
        at: MonotonicTime,
        source: Option<AckSource>,
    },
    /// Not observed yet.
    Pending,
}

impl Milestone {
    pub fn is_observed(&self) -> bool {
        matches!(self, Self::Observed { .. })
    }
}

/// What [`VmService::revoke`](super::VmService::revoke) observed: each acknowledgment of
/// §6.3 on its own, with its own time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationReport {
    pub sandbox: SandboxId,
    pub reason: RevokeReason,
    /// The supervisor's cause; another than `reason`'s when the sandbox was revoked
    /// before.
    pub cause: RevocationCause,
    /// The durable decision (§6.3 step 1), on the host clock.
    pub decided_at: Option<MonotonicTime>,
    /// "New authorizations denied": the first authorization refused after the decision.
    pub new_work_denied: Milestone,
    /// Every channel of the boot closed, as the host observed it.
    pub channels_closed: Milestone,
    /// The VM stopped through its handle.
    pub vm_stopped: Milestone,
    /// The logical cleanup done: the QEMU process ended with the host's proof and its
    /// private directory observed gone.
    pub cleanup_done: Milestone,
    /// The proof behind `vm_stopped`.
    pub vm_stop: VmStop,
    /// The observation behind `cleanup_done`.
    pub directory: DirectoryRemoval,
    /// The commands the revocation ended; each one's outcome says `revoked`.
    pub commands_ended: Vec<CommandId>,
    /// Outcomes the supervisor recorded as uncertain.
    pub uncertain: usize,
}

/// Where a sandbox's boot stands in the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootPhase {
    /// The VM runs and its link socket is connected; the guest's hello has not completed
    /// the link's handshake yet.
    Starting,
    /// The handshake completed: commands run.
    Ready,
    /// A stop or a revocation is under way and the VM is not shown stopped yet.
    Stopping,
    /// The VM stopped, or the launch failed and its VM was stopped.
    Ended,
}

/// How the host's last readiness observation was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessBy {
    /// The launch transaction's own host-observed readiness.
    Launch,
    /// The backend observed the VM again.
    Reobservation,
}

/// The host's last readiness observation of a sandbox (§8.1): host evidence with its time,
/// never a guest report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "readiness", rename_all = "snake_case")]
pub enum ReadinessView {
    Ready {
        observed_at: MonotonicTime,
        by: ReadinessBy,
    },
    /// The host did not find the VM ready, first at `since`; `detail` is the backend's
    /// report.
    Unavailable {
        since: MonotonicTime,
        detail: String,
    },
    /// No observation of the current boot exists.
    NotObserved,
}

/// The sandbox's guest link, as the host holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "link", rename_all = "snake_case")]
pub enum LinkView {
    /// The host's challenge is out; the guest's hello has not come.
    AwaitingHello,
    Open,
    Closed {
        cause: CloseCause,
    },
    /// The host closed the boot's channels (a revocation, a stop, a lost authority or the
    /// service's shutdown).
    ChannelsClosed,
    /// The host holds no channels of the sandbox.
    NoChannels,
}

/// The sandbox's link stream, as its transport driver carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TransportView {
    /// Whether the driver still carries the stream.
    pub connected: bool,
    pub counters: DriverCounters,
    /// How the driver finished with the stream, once it did.
    pub end: Option<TransportEnd>,
}

/// The launch record the backend sealed for the sandbox's boot: its identity, the image
/// and configuration it binds, and the accelerator the host observed (§8.1 line 2446).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchRecordView {
    pub identity: Digest,
    pub guest_image: Digest,
    pub configuration: ConfigurationFingerprint,
    pub accelerator: HostObserved<Accelerator>,
}

/// A revocation in progress or done.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationView {
    pub cause: RevocationCause,
    pub decided_at: MonotonicTime,
    pub acknowledged: Vec<(Acknowledgment, MonotonicTime)>,
    pub pending: Vec<Acknowledgment>,
}

/// One sandbox as [`VmService::status`](super::VmService::status) reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SandboxStatus {
    pub sandbox: SandboxId,
    pub tenant: TenantId,
    /// The launch transaction's state (§6.1).
    pub state: Option<SandboxState>,
    /// The service's boot phase; absent for a sandbox whose launch was refused before its
    /// VM existed.
    pub phase: Option<BootPhase>,
    pub boot: Option<SandboxBootGeneration>,
    pub vm: Option<VmInstanceId>,
    /// The QEMU process the backend holds for the VM, while it holds one.
    pub process: Option<ProcessIdentity>,
    pub readiness: ReadinessView,
    pub launch_record: Option<LaunchRecordView>,
    pub link: LinkView,
    pub transport: Option<TransportView>,
    pub running_commands: Vec<CommandId>,
    /// Ended commands whose outcome no caller has taken yet.
    pub unclaimed_outcomes: usize,
    /// The egress channel: whether a port is attached and how many streams are open.
    pub egress: super::egress::EgressView,
    /// The ingress channel: callers' streams open on the link and waiting to open.
    pub ingress: super::ingress::IngressView,
    pub revocation: Option<RevocationView>,
    /// Present only for a VM whose work is additionally gated by remote delegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_control: Option<super::remote::RemoteControlView>,
}

/// One sandbox's VM as a holder beside the service holds it (VM-W26, the lifetime
/// supervisor): the VM's host process, the sandbox's class (VM-D7) and the job and process
/// handles duplicated into the holder's process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SharedVm {
    pub sandbox: SandboxId,
    pub process: ProcessIdentity,
    pub class: SandboxClass,
    pub handles: SharedHandles,
}

/// What is left now of one sandbox's lease limits (§6.2), for the lifetime supervisor's
/// backstop (VM-W26). A limit the class does not have is `None`; an expired lease reads
/// zero for every limit it has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LeaseTerms {
    pub sandbox: SandboxId,
    pub class: SandboxClass,
    pub idle_left: Duration,
    pub absolute_left: Option<Duration>,
    pub renewal_left: Option<Duration>,
    /// Absolute host-boot elapsed time. Only the authenticated, same-host native
    /// supervisor consumes this; delegation gets no cleanup grace or IPC delay.
    pub delegation_deadline_host_ns: Option<u64>,
}

/// One sandbox whose channels the service's shutdown closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelsClosedOnShutdown {
    pub sandbox: SandboxId,
    /// Whether the link's close frame reached the stream before it was shut down.
    pub close_frame_written: bool,
    /// The commands the shutdown ended; each one's outcome says the link was lost to the
    /// shutdown.
    pub commands_ended: Vec<CommandId>,
}

/// What [`VmService::recover`](super::VmService::recover) found and did after a restart
/// of the engine: the supervisor's own report, and the sandboxes it knows afterwards, none
/// of which holds authority or a channel (§6.1 line 2292: recovery reconciles actual VM
/// objects; VM-D7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub supervisor: crate::sandbox::lifecycle::SupervisorRecovery,
    pub sandboxes: Vec<SandboxStatus>,
}

/// Why the service could not recover from a persisted state: the supervisor's recovery
/// failed, in its own words. Nothing of the state was acted on; the caller decides
/// whether to start afresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecoverRefusal {
    pub detail: String,
}

impl fmt::Display for RecoverRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the VM service could not recover: {}", self.detail)
    }
}

impl std::error::Error for RecoverRefusal {}

/// What [`VmService::shutdown`](super::VmService::shutdown) did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ShutdownReport {
    pub closed: Vec<ChannelsClosedOnShutdown>,
    /// Transport drivers that ended and were joined within the bound.
    pub drivers_joined: usize,
    /// Drivers that had not ended within the bound; their threads are left detached.
    pub drivers_not_joined: Vec<SandboxId>,
    /// Sandboxes whose VM the backend still held: a shutdown does not stop VMs (stop or
    /// revoke them first); what becomes of them is the host port's drop.
    pub vms_left_running: Vec<SandboxId>,
}

/// Bytes as hex in JSON, read back strictly.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

/// A duration as whole milliseconds in JSON.
mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_millis(u64::deserialize(deserializer)?))
    }
}
