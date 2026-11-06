//! Backend modes (docs/combined-gpu-memory-and-vm-sandbox-plan.md, GPU part §3.8).
//!
//! The six rows of the §3.8 table are typed declarations: each row's first-implementation
//! techniques, later experiments and critical boundary ([`ModeRow::declaration`]). Every
//! technique has an integration, capability or experiment gate (GPU part §1.1), and a
//! [`BackendRuntime`] admits one only on its own rows, on a platform that can run it, and
//! with the evidence, reported feature or approval its gate asks for.
//!
//! The rules compose `foundation::evidence` rather than restating it. Backend releases and
//! their mode rules are evidence's `BackendModeRules`, a runtime's modes come only from a
//! `LoaderPlan` made by evidence's gate for that runtime, queried capabilities count only
//! from a live report of the runtime, and a runtime's declared platform counts for CUDA
//! only where fresh CORE-01 `ComputePlatform` evidence shows it ([`PlatformRefusal`]). On
//! top of them:
//!
//! - sleep can discard KV, so no sleep level advertises session preservation, and KV
//!   retention is reported only where a level itself declares it ([`SleepPlan`]); each
//!   level runs as its own mode, and a level that discards the weights needs CORE-01
//!   `SleepWeightDiscard` evidence, a rule table that records it (cited where CORE-01's
//!   recorded rules do not) and a copy that residency's clean-eviction rule accepts as
//!   reconstructing them;
//! - zero-copy preload never runs beside sleep weight offloading where evidence records
//!   them as incompatible, which is checked again before any sleep or preload, neither
//!   runs once the evidence behind the runtime's plan has expired (a plan expires at its
//!   earliest evidence expiry), and preloaded weights are shared only within one user on
//!   one machine under a matching configuration fingerprint ([`PreloadDaemon`]);
//! - GGUF is never converted only to resemble another backend ([`GgufConversion`]);
//! - no second default engine without an attributable benefit, which only a CORE-08
//!   improvement claim from Yougori measurements backs ([`EngineRoster`],
//!   [`AttributableBenefit`]);
//! - CUDA mechanisms are never assumed on CPU, Metal or other platforms, whatever a check
//!   reports ([`ComputePlatform`], [`needs_cuda`]);
//! - Transformers loads rematerialize buffers and keep tied weights tied
//!   ([`check_materialization`]).
//!
//! Warm pools never fork after GPU driver initialization and keep CPU-only import warming
//! a different type from a retained, initialized GPU worker ([`WarmPool`]). Wake orders are
//! declared per backend and checked against the pinned release's queried capabilities,
//! and a wake admits requests only after every step completed in order ([`WakeOrder`],
//! [`WakeProgress`]).
//!
//! Pure library code tested against fakes; runner integration belongs to GPU-W01 and
//! GPU-W05.

mod capabilities;
mod declarations;
mod engines;
mod materialization;
mod platform;
mod preload;
mod runtime;
mod wake;
mod warm;

#[cfg(test)]
mod test_support;

pub use capabilities::{
    CapabilityRefusal, KvRetention, LevelSemantics, PinnedCapabilities, QueriedCapabilities,
    SleepLevel, WeightRetention, QUERY_MINIMUM_SOURCE,
};
pub use declarations::{
    needs_cuda, CapabilityCondition, ComputePlatform, CriticalBoundary, ModeDeclaration, ModeRow,
    PinnedFeature, Stage, Technique, TechniqueGate,
};
pub use engines::{
    ApprovedConversion, ArtifactFormat, AttributableBenefit, BenefitRefusal, Comparison,
    ConversionReason, ConversionRefusal, Engine, EngineRoster, GgufConversion, RosterRefusal,
    ServingFormat,
};
pub use materialization::{
    check_materialization, InventoryError, Materialization, MaterializationPlan,
    MaterializationRefusal, ModelInventory, TensorName, TensorRole,
};
pub use platform::PlatformRefusal;
pub use preload::{LocalPrincipal, PreloadAttachment, PreloadDaemon, PreloadRefusal};
pub use runtime::{
    AdmittedTechnique, BackendRuntime, CapabilityReport, ExperimentApproval,
    RetentionAdvertisement, RetentionClaim, RetentionRefusal, RowReport, RuntimeRefusal,
    SessionContinuity, SleepPlan, SleepRefusal, TechniqueRefusal, TechniqueStatus,
    VLLM_0_31_0_SLEEP_DOC,
};
pub use wake::{
    CheckedWakeOrder, WakeFailure, WakeOrder, WakeOrderRefusal, WakeProgress, WakeProgressRefusal,
    WakeStep,
};
pub use warm::{
    DriverState, ImportWarmProcess, ProcessRules, RetainedGpuWorker, WarmPool, WarmPoolRefusal,
    WarmPoolReport, WorkerId,
};
