//! Serving profiles (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S13 FAST-02, FAST-04
//! and FAST-05, lines 237 and 242–254; §1.2, line 317; Appendix A.1, lines 1481–1482).
//!
//! - [`audit`]: the read-only record of today's vLLM launch in model_server.py, and a check
//!   that reports any recorded flag that drifted (FAST-02 audit).
//! - [`ProfileSelector`]: FAST-02 choice of graph mode, concurrent-sequence limit,
//!   batched-token budget, KV format and context from checkpoint compatibility, measured
//!   free capacity and the request mix, each fact read from CORE-01's registry. Measured
//!   peer topology comes before any per-process NCCL choice; capacity and tool-semantics
//!   gaps are refusals.
//! - [`respond_to_failure`]: a startup failure reverts to a known-good profile within the
//!   same authorized execution category, judged against the settings CORE-04's authority
//!   record holds ([`AuthorityRecord`]); capacity, tool-semantics and security failures
//!   are refused, never silently downgraded.
//! - [`decide_drafting`]: FAST-04 drafting for one pinned engine, model and method, turned
//!   off or lowered where verification wastes capacity or harms the interactive objective.
//! - [`ServingProfileRecord`]: the FAST-05 evidence-bound record. Its proof is the CORE-08
//!   raw records of a Yougori measurement of exactly this profile ([`ProfileProof`]; a
//!   fake run is refused), and its gates and speed are derived from them. A changed image,
//!   model, launcher, parser, hardware class or resource contract invalidates it, and a
//!   reproducibly failing profile is withdrawn with its history kept.
//! - [`admit_kv_representation`]: a lossy KV representation needs its approximation
//!   configured under the model identity layers' fidelity rules (T07, §1.3) and, on top,
//!   per-model qualification, per-model support first (lines 248 and 250).
//!
//! Pure and synchronous: nothing here probes, launches or changes host state, and time
//! comes from [`crate::foundation::ids::Clock`]. Changes to model_server.py and the runners
//! belong to MODELS, and raw report digests name CORE-08 reports (S13 line 252).

/// `foundation::strict_serde`'s [`strict_tagged_enum!`](crate::foundation::strict_serde::strict_tagged_enum),
/// in this module's textual scope for the enums its child files declare with it.
macro_rules! strict_tagged_enum {
    ($($tokens:tt)*) => {
        $crate::foundation::strict_serde::strict_tagged_enum! { $($tokens)* }
    };
}

pub mod audit;
mod drafting;
mod formats;
mod guard;
mod observed;
mod record;
mod revert;
mod selection;
mod settings;

#[cfg(test)]
mod testkit;

pub use audit::{AuditItem, Drift, ServingAudit, TODAY};
pub use drafting::{
    decide_drafting, DraftMethod, DraftingBaseline, DraftingChange, DraftingCompatibility,
    DraftingDecision, DraftingMatrix, DraftingObjective, DraftingOff, DraftingRequest,
    DraftingSetting, DraftingTrial, InteractiveMeasure, LoadPoint, MatrixError, QualityEvidence,
    QualityLayer, RejectedTrial, TrialRejection,
};
pub use formats::{
    admit_kv_representation, check_kv_qualification, kv_fidelity, CheckResult, KvCheck,
    KvFormatQualification, KvFormatRefusal,
};
pub use guard::{AuthorityRecord, AuthorizedRuntime};
pub use observed::{EvidenceGap, ServingFact};
pub use record::{
    Cleanup, FailureKind, GateName, GateResult, HistoryEntry, Invalidation, ModelBinding,
    ModelBindingError, OfferedCapabilities, Origin, Parsers, Prerequisite, PrerequisiteFacts,
    ProfileBinding, ProfileCapabilities, ProfileDraft, ProfileGates, ProfileId, ProfileNeeds,
    ProfileProof, ProfileRecords, ProfileSelectionError, ProfileState, ProofField,
    PublicationAuthorization, PublicationRefusal, Qualification, QualificationHost, Qualifications,
    RecordRefusal, RecordsError, ResourceContract, Review, ServingProfileRecord, Unusable,
    WorkloadGate, REPRODUCED_FAILURE_REPORTS,
};
pub use revert::{
    respond_to_failure, CapacityResource, Excluded, Exclusion, ProfileFailure, Revert,
    RevertRefusal, SecurityFailure, StartupFailure, ToolSemanticsFailure,
};
pub use selection::{
    Candidate, CandidateRejection, CapacityError, CapacityShortfall, CheckpointCompatibility,
    CompatibilityError, DeviceMemory, KvCacheSupport, MeasuredCapacity, PassedOver, ProfileChoice,
    ProfileRefusal, ProfileRequest, ProfileSelector, ProfiledFootprint, RequestError, RequestMix,
    SelectionPolicy, ServingEvidence, ToolCalls,
};
pub use settings::{
    CommunicationRefusal, CommunicationScope, ComparisonConditions, ComputeCapability,
    ConditionMismatch, EngineRef, GraphMode, HardwareClass, MemoryFraction, NcclChoice,
    NotComparable, PeerAccess, PeerLink, PeerPath, PeerToPeer, PeerTopology, ServingSettings,
    SettingsError, TopologyError,
};
