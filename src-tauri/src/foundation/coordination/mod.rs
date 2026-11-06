//! CORE-04: the coordination protocol for launch, child work, typed generation identities,
//! leases, cancellation, reconciliation and recovery
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 CORE-04, S3.1, S3.4, S3.5, S6
//! INT-02–INT-04, S7 lines 125 and 131, S10; VM part §6).
//!
//! Two state machines with separate owners meet only through the [`Coordinator`]'s
//! explicit adapter calls (S2 CORE-04; S3.1):
//!
//! - [`SandboxLifecycle`] (RUNTIME) is the durable VM sandbox launch transaction of VM
//!   part §6.1. It owns the boot generation, policy epoch and authorization epoch.
//! - [`ModelActivations`] (MODELS) owns the activation and GPU allocation generations of
//!   one model under one parent execution.
//!
//! Neither can advance the other's generations. Child work runs under its parent
//! execution, and every lease carries the generations it was issued under and an expiry
//! on the shared clock; it is honoured only while all of them are current. So revocation
//! blocks new child work at once, a restored identity never revives a lease, and model
//! eviction never renews sandbox authority. One grant under an authority can be revoked
//! alone ([`Coordinator::revoke_grant`]): a persisted tombstone, not an epoch advance,
//! that cancels only what is bound to the grant (VM part §6.3 step 1). Each revocation
//! milestone is recorded once with its source, the first denied authorization and all
//! channels closed included ([`RevocationMilestone`]). Recovery reconciles actual VMs and
//! reservations, revives nothing, and restores only when every applicable validator
//! passes; performance fallbacks during recovery pass the S3.5 guard. The owner's GPU
//! return is staged and measured, never promised in milliseconds.
//!
//! The host reservation ledger (CORE-03) is reached through the [`CapacityPort`], which
//! [`LedgerCapacity`] implements over the ledger, owned or shared with the ledger's other
//! clients ([`SharedLedger`]), and the VM backend through the [`SandboxPort`]; tests use
//! fakes for both and run the launch transaction through the real ledger too. Revocations
//! reach the CORE-06 event plane through [`RevocationEvents`].
//!
//! Lifecycle authority is durable (docs/combined-plan-remaining-only.md §8, S04 / M13 /
//! M17; VM part §6.3–§6.4; VM-W29): epochs and grants are scoped by host, issuer, run and
//! execution ([`ScopedEpoch`], [`ScopedGrant`]); authority-bearing messages pass a
//! persisted [`ReplayState`] once; the [`AuthorityFloor`] keeps a restored older state from
//! moving any generation, tombstone or replay limit back; watchers' cached views go stale
//! with every revocation ([`WatcherRegistry`]); tombstones leave only with an execution's
//! retirement, on a [`RetirementProof`]; and every admitted execution holds a revocation
//! slot in the supervisor's [`ControlChannel`], so revocation proceeds under overload.

mod capacity;
mod compaction;
mod control;
mod coordinator;
mod event_plane;
mod floor;
mod grants;
mod identity;
mod labelled;
mod lease;
mod ledger_adapter;
mod model;
mod port;
mod recovery;
mod recovery_events;
mod replay;
mod resource_return;
mod revocation;
mod sandbox;
mod scope;
mod store;
mod watchers;

#[cfg(test)]
mod durability_tests;
#[cfg(test)]
mod fakes;
#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod tests;

pub use crate::foundation::ids::{GrantId, LeaseId};
pub use capacity::{
    CapacityLimit, CapacityPort, CapacityRefusal, ExecutionCancellation, ReconcileReport,
    ReleaseOutcome, ReservationKey, ReservationPriority, ReservationPurpose, ReservationRequest,
    ReserveOutcome, ResourceKind, RetryProspect, ReturnHold,
};
pub use compaction::{
    CompactionPolicy, LeaseClosure, Retirement, RetirementBlocked, RetirementBlocker,
    RetirementProof,
};
pub use control::{
    ControlChannel, ControlConfig, ControlConfigError, ControlItem, ControlRefusal, ControlTotals,
    PendingRevocation, RevocationQueued, RevocationRequest,
};
pub use coordinator::{
    Compensation, CoordinationError, Coordinator, IncarnationNotPersisted, LaunchOutcome,
    LaunchPlan, StallCause, TerminationStalled,
};
pub use event_plane::{GrantRevocationPublished, RevocationEvents, RevocationPublished};
pub use floor::{
    AuthorityFloor, ExecutionFloor, FloorRefusal, FloorRegression, FloorRestore, FloorUpgrade,
    Regression, SandboxFloor, StaleEnded,
};
pub use grants::{network_grant_id, RevokedGrant};
pub use identity::{
    ModelGenerations, ModelId, PerimeterId, SandboxGenerations, SnapshotId, VmInstanceId,
};
pub use labelled::{LabelledAuthorization, LabelledRuntime};
pub use lease::{
    CancelCause, Lease, LeaseCancellation, LeaseKind, LeaseRecord, LeaseRefusal, LeaseState,
    LeaseTerms, ModelBinding, RenewalLimit, TermsProblem,
};
pub use ledger_adapter::{LedgerCapacity, LedgerHandle, SharedLedger};
pub use model::{
    Activation, ActivationDemand, ActivationHandle, ActivationState, ActivationStep, Completion,
    DemandProblem, GpuAllocationHandle, GpuDemand, GpuReservationState, Holding, HoldingId,
    HoldingMemory, ModelActivations, ModelRefusal, Retention, RetireReason,
};
pub use port::{
    BootRequest, ObservedVm, PortFailure, PortOperation, Readiness, ReadinessReport, SandboxPort,
};
pub use recovery::{
    validate_gpu_checkpoint, validate_model_cache, validate_vm_snapshot, verify_restored_vm,
    CacheDefect, CheckpointDefect, ComponentDefects, CompositeRecovery, FallbackContext,
    GpuCheckpointManifest, ModelCacheManifest, PersistedState, RecoveryComponent, RecoveryContext,
    RecoveryDecision, RecoveryFailure, RecoveryPath, RecoveryReport, RelaunchPlan, RelaunchReport,
    RestoreAction, RestoreExpectation, RestoreFailure, RestoreRefusal, RestoredVmReport,
    SandboxRecovery, SnapshotContent, SnapshotDefect, SnapshotManifest, SnapshotOrigin,
    ValidatorVerdict, VerifiedRestore,
};
pub use recovery_events::{
    open_recovery_log, publish_recovery_events, RecoveryEvent, RecoveryLog, RecoveryPublished,
};
pub use replay::{
    Delivery, LineFloor, MessageClass, Nonce, ReplayConfig, ReplayConfigError, ReplayRecord,
    ReplayRefusal, ReplayState, ScopeFloor, ScopeLimit, MAX_WINDOW,
};
pub use resource_return::{
    check_session_move, CancellationBoundary, DeviceReset, ExitRefusal, ForegroundImpact,
    GpuAssignment, ReleaseMechanism, ResourceReturn, ReturnMeasurements, ReturnRefusal,
    ReturnReport, ReturnStage, ReturnStep, SessionMove, SessionMoveRefusal, SessionRepresentation,
};
pub use revocation::{
    Denial, DeniedAuthorization, DeniedRequest, MilestoneSource, RevocationMilestone,
    RevocationNotice, RevocationOperation, RevocationStatus, UncertainOutcome,
};
pub use sandbox::{
    Applied, GenerationName, LaunchFailure, LoaderGrant, ReadinessEvidence, SandboxLifecycle,
    SandboxState, SandboxStep, SettingsGrant, StepKind, TransitionRecord, TransitionRefusal,
};
pub use scope::{AuthorityIssuer, HostId, IssuerId, ScopeRefusal, ScopedEpoch, ScopedGrant};
pub use store::{
    AuthorityHolder, AuthorityState, AuthorityStore, FileProblem, StateStanding, StoreError,
    StoreFile, StoreLoad, StorePersisted, StoreRecovery, StoreRestore,
};
pub use watchers::{
    AuthorityRevision, AuthorityView, ViewRefusal, WatcherEnd, WatcherHolder, WatcherId,
    WatcherRecord, WatcherRefusal, WatcherRegistration, WatcherRegistry, WatcherStanding,
};
