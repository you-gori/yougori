//! The VM lifecycle of a sandbox (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part
//! §6 lines 2282–2353; §2.5 lines 1997–2002; §2.6 lines 2004–2016; §3.1 lines 2019–2058;
//! §5.5 lines 2266–2281; VM-W24–VM-W27 and VM-W29 lines 2630–2636; VM-D7, VM-D10 and
//! VM-D12 lines 3199–3207), the RUNTIME side of S4.
//!
//! The durable state machine, the typed generations, the leases, the revocation notices
//! and recovery come from the committed CORE-04 protocol
//! ([`crate::foundation::coordination`]); nothing here keeps a parallel epoch, lease or
//! incarnation. This module adds what the plan asks of the supervisor around it:
//!
//! - [`Supervisor`]: the launch transaction driven through the coordinator, the five
//!   lease limits with the VM-D12 starting values, activity that counts and traffic that
//!   does not, the revocation protocol of §6.3 with its five distinct acknowledgments
//!   (the first denied authorization and all channels closed taken from CORE-04's
//!   milestones with their sources), the revocation of one grant alone through CORE-04's
//!   per-grant tombstone with its own receipt and a record that survives recovery, the
//!   per-class rules of VM-D7 and VM-D10, recovery that trusts handles and never stored
//!   PIDs, warm-pool checkouts of §6.6 that take a clone only once capacity is granted,
//!   and readiness observed again after launch ([`Supervisor::observe_readiness`],
//!   [`ObservedReadiness`]): the supervisor asks the backend to observe the VM again, also
//!   before it admits work once the last readiness is older than its configured age
//!   ([`Supervisor::authorize_observed_work`]), and while the host does not find it ready
//!   no new work is authorized under the sandbox (§8.1 line 2439; leftover entries H01,
//!   S01, M02, M08).
//! - [`VmBackend`]: the small backend port this module needs (launch, stop, snapshot,
//!   restore, handle identity check), bridged to the coordinator's port; the real
//!   backend contract is adapted to it at integration.
//! - [`Binding`]: each channel and capability bound to the right tuple of stable sandbox
//!   identity, boot generation, snapshot identity, policy epoch, authorization epoch and
//!   credential lease (§6.1).
//! - [`ReplayGuard`]: nonces and generations scoped by issuer and sandbox, persisted
//!   replay protection and tombstones that compact only when no valid capability can
//!   exist (VM-W29).
//! - [`KillMeasurements`]: revoke-to-deny, channel close, VM stop and cleanup
//!   distributions reported separately through CORE-08, with the two-second figure
//!   recorded as a target and logical cleanup never reported as physical wiping (§6.5).
//! - [`model`]: the §12.3 lifecycle and snapshot/epoch models, enumerated exhaustively
//!   within stated bounds, and checked against the supervisor in the tests.
//!
//! Every tagged enum read back here, among them the records of [`PersistedSupervisor`] and
//! the bounded [`LifecycleMessage`]s of a [`MessageFrame`], reads through
//! [`crate::foundation::strict_serde`]: a tag that is not a string and a key repeated in
//! one record are refused, read at the top level and nested alike, and the written form
//! is unchanged (the E01Y follow-up of docs/combined-plan-leftover-tasks.md).
//!
//! Everything is pure and synchronous: time comes from the shared clock, the backend is a
//! port, and no VM, process or file is touched.

mod backend;
mod identity;
mod leases;
mod measurements;
pub mod model;
mod pool;
mod readiness;
mod replay;
mod revocation;
mod safety;
mod supervisor;

#[cfg(test)]
pub mod fakes;
#[cfg(test)]
mod strict_tests;
#[cfg(test)]
mod tests;

pub use backend::{
    BackendCapabilities, BackendFailure, BackendOperation, HandleIdentity, HandleTable, StateReset,
    StopOutcome, VmBackend, VmHandle,
};
pub use identity::{
    authorization_epoch_of, Binding, BindingField, BindingRefusal, BindingTuple, BoundKind,
    ClaimKind, GenerationClaim, SandboxIdentity,
};
pub use leases::{
    authorized_time_bound, child_lease_terms, remaining_authorized_time, remaining_effects_bound,
    ActivityKind, ActivityRefusal, BoundNotApplicable, CallTerms, EffectExposure, Expiry,
    LeaseLimits, LeaseRestoreRefusal, Limit, LimitKind, LimitOrigin, LimitRefusal, Remaining,
    RemoteEnforcement, RemoteLease, RenewalRefusal, SandboxClass, SandboxLease, SkewPolicy,
    DEFAULT_IDLE, DEFAULT_SERVICE_RENEWAL, DEFAULT_TASK_ABSOLUTE,
};
pub use measurements::{
    BootPath, CleanupReport, EncryptionDesign, FirstCommandSample, KillMeasurements,
    LogicalCleanupAction, PercentileReport, PhaseFailure, PhaseSample, PhaseSummary, PhysicalWipe,
    PoolCounts, SensitiveCopy, StopFailureCause, StopPhase, StopTarget, TargetAssessment,
    TargetClaim, STOP_TARGET,
};
pub use pool::{
    decide_checkout, CachePolicy, CheckoutDecision, ColdFallback, GoldenSnapshot, PoolRefusal,
    Profile, RenewalBehavior, RenewalPlanProblem, RollbackPlan, ServiceRenewalPlan, ShutdownMode,
    SnapshotProvenance, VolumeAttachment, VolumeKind, VolumeRefusal, WarmPool,
};
pub use readiness::{ObservedReadiness, MAX_READINESS_DETAIL_CHARS};
pub use replay::{
    CompactionReport, IssuerId, KeptReason, Nonce, NonceScope, ReplayGuard, ReplayRefusal,
    Tombstone,
};
pub use revocation::{
    AckEffect, AckRefusal, AckSource, Acknowledgment, CleanupState, GrantRevocationCause,
    ProviderAcknowledgment, ProviderBilling, RevocationCause, RevocationPolicy, RevocationProgress,
    RevocationRun, TerminationGate, TerminationTiming, Uncertain,
};
pub use safety::{
    CleanupPlan, CleanupRefusal, CleanupTarget, FrameRefusal, LifecycleMessage, ManagedRoot,
    ManagedRootId, ManagedRoots, MessageFrame, OpenMode, PathRefusal, PeerIdentity, RelativePath,
    SupervisorDeathFallback, WatchdogGraph, WatchdogId, WatchdogRefusal, MAX_FRAME_BYTES,
    MAX_PATH_BYTES,
};
pub use supervisor::{
    CheckoutReceipt, EngineDeathReport, EngineState, GrantRevocationRecord, GuiClosureReport,
    LaunchReceipt, LaunchRequest, LifecycleReceipt, Lockdown, MessageOutcome, PendingRenewal,
    PersistedSupervisor, RenewalReceipt, SandboxRecord, StopToken, Supervisor, SupervisorConfig,
    SupervisorError, SupervisorRecovery, TickReport, ViolationResponse,
};
