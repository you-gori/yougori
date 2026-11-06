//! The five boundaries of the model-memory control plane and the end-to-end flow over
//! them (docs/combined-gpu-memory-and-vm-sandbox-plan.md, GPU part §1 lines 272–295 and
//! §3.1 lines 477–491; S3.6 line 56).
//!
//! Each boundary is a trait whose signatures reach only what its §3.1 row allows, so the
//! "must not own" column holds by construction:
//!
//! | Boundary | Trait | Owns | Cannot reach |
//! | --- | --- | --- | --- |
//! | Artifact catalog/importer | [`ArtifactCatalog`], [`ArtifactImporter`] | verified immutable representations, provenance | requests, credentials, devices, leases |
//! | Placement governor | [`PlacementGovernor`] | admission, leases, priorities, transfer budgets | capacity the CORE-03 ledger did not grant (line 491); tensors |
//! | Transfer executor | [`TransferExecutor`] | bounded reads, verification, copies, decoding, events | any model but the one its [`TransferOrder`] pins |
//! | Runner adapter | [`RunnerAdapter`] | lifecycle, compatibility, readiness, exact dependencies | the ledger, the governor, the coordinator, queues or other runners |
//! | API/CLI/UI adapter | [`ApiAdapter`] | intent, progress, policy, diagnostics | raw GPU handles ([`NativeHandle`]), leases, grants, payloads |
//!
//! Native operations sit behind a narrow, versioned ABI ([`NativeAbi`], line 489); a
//! runner adapter reaches the flow only after its declared version is checked. A
//! [`PreparationToken`] never becomes [`ActionAuthority`] (S3.6): only the declared
//! workflow's [`WorkflowPolicy`] issues grants, and it reads time from the shared clock.
//!
//! Committed modules are used directly, with no ports:
//!
//! - the CORE-02 catalog (T05) holds every artifact, and P01's importer is its only
//!   writer for models; [`ModelStore`] implements boundary 1 over both, and serves the
//!   same verified sidecars to P03 as its catalog port ([`StoreManifests`]);
//! - P04's activation slot runs every activation's seven steps, its leases and its
//!   reclamation over the CORE-04 coordinator (T09), which issues activation generations
//!   with their GPU reservations and leases and confirms released memory;
//!   [`LedgerPolicyGovernor`] drives one slot per placement and epoch and, through the
//!   coordinator, the CORE-03 ledger (T04), the one capacity authority, of which the
//!   governor is only a policy client. The coordinator holds a model's weights apart from
//!   any activation, so the generations of a slot share them and count them once; when two
//!   generations cannot be resident together and the request or its placement consents,
//!   serving pauses for a reload with a visible status ([`ReloadStatus`], GPU-W05
//!   line 110);
//! - each lease carries the KV its request's shape writes, admitted against the
//!   activation's KV pool; a backend that grows its KV commits the pool in increments
//!   carved from the activation's own reservation ([`KvSpec`], GPU-W10 line 182);
//! - P03's portable path moves the bytes; [`PortableExecutor`] implements boundary 3 over
//!   it, carving every transfer destination from the reservation of the memory it lands
//!   in: the weights' own holding, or the activation's own memory;
//! - T08 residency computes each activation's §2.7 demand ([`activation_demand`]) and
//!   decides how a served session may leave ([`retain_session`]);
//! - the T06 request graph plans, and takes ready state only as [`RecheckedState`], made
//!   from a T07 [`RecheckedResidency`](crate::model_memory::identity::RecheckedResidency);
//! - T07 supplies every identity, the advertisement recheck and scoped grants;
//! - T03's §2.6 recurrence reports the overlap of loading and computation;
//! - request shapes are placement's (P04) and source kinds the transfer executor's (P03).
//!
//! Names are the owning modules': extents by decoded content key, stored objects by the
//! catalog's content keys, and verified artifacts by catalog object digests, as the
//! coordinator's settings grant names them.

mod abi;
mod api;
mod catalog;
mod declaration;
mod demand;
mod executor;
mod flow;
mod governor;
mod kv;
mod kv_evidence;
mod planning;
mod portable;
mod preparation;
mod retention;
mod runner;
mod store;
mod waits;

#[cfg(test)]
pub mod fakes;
#[cfg(test)]
mod tests;

pub use abi::{
    AbiDeclaration, AbiRefusal, CheckedRunner, NativeAbi, NativeAbiVersion, NativeHandle,
    NativeHandleKind, NativeOperation, NATIVE_ABI_VERSION,
};
pub use api::{report_diagnostics, ApiAdapter, Intent, RequestPolicy};
pub use catalog::{
    verify_submission, ArtifactCatalog, ArtifactImporter, CatalogRefusal, ExtentDescriptor,
    ExtentId, ExtentRef, ImportRefusal, ImportSubmission, ImportedExtent, Provenance, StoredExtent,
    VerifiedRepresentation,
};
pub use declaration::{
    ComputeGroup, DependencyNode, ExecutionDependencies, Materialization, NodeId,
    SecurityPartition, StateIdentity, StateRef,
};
pub use demand::{activation_demand, ActivationDemand, DemandError, DeviceBudget, DEMAND_WINDOW};
pub use executor::{
    ExtentCompletion, OrderRefusal, OrderedExtent, TransferExecutor, TransferFailure,
    TransferOrder, TransferRefusal, TransferTicket,
};
pub use flow::{
    serve, Boundaries, ExactRequest, FlowError, FlowEvent, FlowPhase, HintRefusal, OverlapReport,
    RequestContext, ServePath, ServeReceipt,
};
pub use governor::{
    vram_key, AbandonedActivation, ActivationExtent, ActivationSpec, Admission, AdmissionRefusal,
    AdmissionRequest, CapacityRefusal, ExecutionLease, GovernorError, GovernorPolicy, HostLedger,
    LedgerFault, LedgerGrant, LedgerPolicyGovernor, LimitKind, PendingActivation, PendingRefusal,
    PlacementGovernor, PlacementKey, PlacementOwner, PreparationLease, ReloadConsent, ReloadPhase,
    ReloadStatus, RequestAuthority, RetryOutlook, RuntimeBinding, RuntimeView, Shortfall,
    TransferBudget, TransferDestination, TransferDirection, HOST_RAM, STAGING,
};
pub use governor::{KvIncrement, KvScratch, KvTrimRefusal, KvTrimWork};
pub use governor::{
    EndedReload, LifecycleDecision, RecordingReport, ReloadEnd, ReloadResumption,
    UnrecordedDecision, MAX_ENDED_RELOADS, MAX_UNRECORDED,
};
pub use kv::{kv_bytes, KvGrowth, KvLayout, KvRefusal, KvSpec, KV_WAIT_LIMITS};
pub use kv_evidence::{evidenced_kv_growth, KvGrowthEvidence};
pub use planning::{plan_dependencies, DependencyPlan, PlanFault, RecheckedState};
pub use portable::{allocation_key, PortableExecutor, ALLOCATION_DOMAIN, JOB_DOMAIN, MAX_PUMPS};
pub use preparation::{
    ActionAuthority, ActionCredential, ActionRefusal, ActionRequest, ExternalAction,
    PreparationStep, PreparationToken, WorkflowActionGrant, WorkflowPolicy,
};
pub use retention::{retain_session, served_session, SessionRetention, SESSION_STATE_DOMAIN};
pub use runner::{
    ActivationOrder, Compatibility, ComputeAssignment, DependencyEvent, Incompatibility,
    PublishedModel, RequestPayload, ResidentState, RunnerAdapter, RunnerDiagnostics, RunnerProfile,
    RunnerRefusal, ServeOrder, ServeOutcome,
};
pub use store::{
    CatalogScope, ModelImport, ModelStore, StoreManifests, ORIGIN_DOMAIN, REVISION_DOMAIN,
};
pub use waits::{WaitDemand, WaitLimits, WaitQueue, WaitTurn, Waiter};
