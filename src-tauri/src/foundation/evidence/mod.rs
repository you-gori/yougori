//! CORE-01: the versioned capability/evidence envelope and probe registry
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2).
//!
//! An [`EvidenceEnvelope`] records what was observed: the subject, the configuration
//! fingerprint the observation depends on, its source, when it was observed and for how
//! long it stays fresh, and the result. Envelopes are made only by the
//! [`ProbeRegistry`] from typed [`ProbeAdapter`]s, which observe and never change host
//! state, and whose source class is fixed when they are registered. A [`Requirement`] is
//! satisfied only by fresh, sufficiently trusted evidence observed under the current
//! configuration; guest reports never satisfy host-only requirements.
//!
//! The same vocabulary carries the exact runtime-category matrix, where a runtime is
//! admitted only on host or provider evidence of its category (S5 G0, INT-07, VM part
//! §1.3); the optimization gate with backend-mode rules (INT-06, GPU part §1.1–§1.2, S7);
//! and the performance-fallback guard, which checks a fallback against the gate's plan
//! and its still-current evidence (S3.5). Every refusal is typed and names a [`Remedy`].

#[macro_use]
mod strict;

mod category;
mod envelope;
mod fallback;
mod modes;
mod optimization;
mod registry;
mod remedy;
mod requirement;
mod subject;

#[cfg(test)]
pub mod fakes;
#[cfg(test)]
mod tests;

pub use category::{
    AdmittedRuntime, CategoryRefusal, LabelledRuntimes, RequirementError, RuntimeOffer,
    RuntimeRequirement, SelectionRefusal,
};
pub use envelope::{
    Capability, CapabilityDomain, ClockReading, ClockSession, ComputePlatform,
    ConfigurationFingerprint, EvidenceEnvelope, FingerprintError, Observation, ObservationResult,
    PeerAccess, PeerLink, PeerPath, SchemaVersion, ShareableHandle, SourceClass, SupportDetail,
    UnknownReason, UnsupportedReason, UnsupportedSchemaVersion, EVIDENCE_SCHEMA_VERSION,
};
pub use fallback::{
    guard_fallback, AllowedChange, ApprovedFallback, ArtifactBypass, ArtifactVerification,
    AuthorityGrant, FallbackRefusal, FallbackViolation, NetworkGrant, Residency, RuntimeSettings,
};
pub use modes::{
    BackendModeRule, BackendModeRules, DocumentedConflict, ModePair, ModeRefusal, ModeRuleError,
    VLLM_0_31_0_PRELOAD_DOC,
};
pub use optimization::{
    EvidencePolicy, LoaderGate, LoaderPlan, LoaderRefusal, LoaderRequest, Necessity, NotEnabled,
    Optimization, RuntimeProfile,
};
pub use registry::{HostChange, ProbeAdapter, ProbeRegistry, RegistryError};
pub use remedy::Remedy;
pub use requirement::{EvidenceRefusal, EvidenceStore, Requirement, Satisfied, Staleness};
pub use subject::{
    Backend, BackendRelease, BackendVersion, CredentialScanSubject, CudaAllocationSubject,
    GpuDeviceSubject, GpuPairSubject, HostSubject, HypervisorKind, HypervisorProcessSubject,
    HypervisorSubject, ModelCheckpointSubject, OperatingSystemSubject, OsKind,
    PerimeterRuleSubject, ProviderKind, ProviderSubject, RuntimeSubject, SandboxBootSubject,
    SnapshotClonesSubject, Subject, SubjectKind, TransportBrokerSubject, VersionError,
    MAX_VERSION_LEN,
};
