//! Update trust, pinned configurations, vulnerability governance and artifact
//! provenance for the VM sandbox (docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! §8.3 lines 2451–2459, §10.6 rows VM-W45–VM-W48 lines 2668–2671 and the update
//! threat-model paragraph line 2677, VM-P23 line 2798, VM-P37 line 2812, VM-P48 line
//! 2823, VM-D13 line 3207, §19 from line 3215).
//!
//! Pure, synchronous library code on the committed foundation. Trust roots, keys,
//! metadata, pins, findings and exceptions are data the caller supplies; this module
//! ships no key and reads no environment.
//!
//! - **Update trust (VM-W45)**, the narrow TUF-style design VM-D13 records, documented
//!   in [`metadata`]: offline root keys with thresholds and one-version-at-a-time
//!   rotation; delegated online keys per role; versions and expiry on every file;
//!   freeze, rollback and mix-and-match protection through the timestamp → snapshot →
//!   targets references; a version-numbered revocation list for emergency revocation
//!   that applies offline and only accumulates; expired metadata as a refusal also when
//!   offline ([`UpdateClient`]). Verification yields a [`VerifiedTarget`] bound to the
//!   declared content key, and only [`VerifiedTarget::open`] produces the
//!   [`OpenedArtifact`] a launch takes, so the opened artifact is the verified artifact.
//!   Each role keeps a floor (the highest version accepted while its keys stayed the
//!   same) and the client keeps a time floor, so neither a rollback nor a clock set back
//!   revives what the client moved past.
//!   Signature verification is a port ([`SignatureScheme`]); the engine's Ed25519
//!   adapter over `ring` is wired by the lead, and the only scheme here is a test scheme
//!   the production profile refuses. The developer profile is granted only from host
//!   configuration or an operator command ([`ResolvedProfile`]), never from an inherited
//!   environment variable or guest input, and nothing verified under it becomes a
//!   [`ProductionRelease`].
//! - **Durable trust state**: [`UpdateClient::state`] writes the trusted files, versions,
//!   expiries, floors, time floor and revocations as a [`TrustState`], and
//!   [`UpdateClient::restore`] rebuilds the client from it after a restart, re-verifying
//!   every signed file from the pinned root. A [`TrustStore`] keeps it on a CORE-06
//!   durable stream with one owner; [`UpdateClient::keep_update`] keeps each update before
//!   it counts, and torn, truncated, rewritten or regressing state is refused, never
//!   reset.
//! - **Fetching** through a [`FetchPort`] the caller supplies (nothing here opens a
//!   connection or a file): every item is read within a bound ([`FetchLimits`]), and
//!   [`UpdateClient::refresh`] runs the VM-D13 order (root rotations, revocation list,
//!   timestamp, snapshot, targets), keeping each step. [`UpdateClient::fetch_artifact`]
//!   opens only the verified bytes.
//! - **Revocation reaching a running client**: a [`RevocationFeed`] shared with every
//!   client carries the keys, artifact classes and releases the host revoked; each takes
//!   effect at the client's next check, without a restart, and nothing verified under a
//!   revoked key launches afterwards. Revocations only accumulate and survive restarts.
//! - **Pinned configurations (VM-W46)**: a [`ConfigurationMatrix`] of
//!   [`PinnedConfiguration`] rows per OS, architecture and backend, each pinning
//!   runtime, guest kernel, guest image, firmware, the guest initrd and profile where the
//!   guest has them, and devices by exact version, content key and reproducible
//!   [`BuildInputs`], with a CORE-01 fingerprint per row. An unsupported configuration
//!   or device is absent, never "untested". A [`KnownVulnerabilityDecision`] records
//!   configuration, component, mitigation and owner.
//! - **Vulnerability governance (VM-W47)**: [`Governance::assess`] gates a [`Finding`]
//!   by applicability, reachability, severity, remediation window and a time-limited
//!   [`Exception`] with an owner; expiry is enforced by the clock and an expired
//!   exception blocks with its expiry named. A scan is one signal; a scan with no
//!   findings yields no blocker and the components it did not cover, never a claim. A
//!   fix is a component version ([`Remediation::FixAvailable`]) or, as scanners report
//!   it, a package release kept as stated ([`PackageFix`]).
//! - **Typed provenance (VM-W48)**: OCI, kernel, tool and model [`Provenance`] on four
//!   distinct catalog classes, judged by the catalog's own [`TrustPolicy`] per class
//!   and by the catalog's status of the object. Mutable tags, registry redirects,
//!   cross-user cache hits and corrupted local files are typed refusals. A
//!   [`VerifiedIdentity`] grants nothing; execution needs an [`ExecutionPermission`]
//!   for that exact object and the catalog's read authorization.
//!
//! Calendar time for expiries comes from the shared monotonic clock through a
//! caller-supplied anchor ([`TrustClock`]); tests drive it with `ManualClock`.

mod artifact;
mod client;
mod fetch;
mod fix;
mod metadata;
mod pinned;
mod profile;
mod provenance;
mod revocation;
mod signature;
mod state;
mod store;
mod time;
mod vulnerability;

#[cfg(test)]
mod strict_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_update;

pub use artifact::{
    AssuranceRefusal, OpenRefusal, OpenedArtifact, ProductionRelease, VerificationBasis,
    VerifiedTarget,
};
pub use client::{
    LaunchAdmission, RevocationApplied, RootRotation, TrustedVersions, UpdateClient, UpdateRefusal,
    MAX_TRUSTED_ROOTS,
};
pub use fetch::{
    ArtifactFetchRefusal, FetchError, FetchItem, FetchLimits, FetchPort, FetchRefusal,
    FetchRequest, RefreshFailure, RefreshRefusal, RefreshReport, RefreshStep,
};
pub use fix::{
    FixRefusal, PackageFix, MAX_FIX_PACKAGE_BYTES, MAX_FIX_REQUIREMENTS, MAX_FIX_REQUIREMENT_BYTES,
};
pub use metadata::{
    verify_threshold, MetaRef, MetadataError, MetadataFile, MetadataVersion, ReleaseVersion,
    RevocationMetadata, Role, RoleKeys, RootMetadata, SignatureFailure, SnapshotMetadata,
    TargetEntry, TargetName, TargetsMetadata, ThresholdWitness, TimestampMetadata, FILE_DOMAIN,
    MAX_REASON_BYTES, METADATA_DOMAIN,
};
pub use pinned::{
    AdvisoryId, Architecture, BootMethod, BuildInputs, ComponentKind, ComponentPin,
    ComponentVersion, ConfigurationKey, ConfigurationMatrix, DeviceModel, DeviceSupport,
    KnownVulnerabilityDecision, MatrixRefusal, Mitigation, Owner, PinRefusal, PinnedConfiguration,
    SandboxBackend, BUILD_INPUTS_DOMAIN,
};
pub use profile::{
    AssuranceProfile, ProfileRefusal, ProfileRequest, RequestOrigin, ResolvedProfile,
};
pub use provenance::{
    admit_cache_hit, admit_execution, admit_publisher, identify, verify_local_file, Attestation,
    CacheHit, ExecutionAdmission, ExecutionPermission, KernelProvenance, LocatorError,
    ModelProvenance, OciProvenance, OciReference, Provenance, ProvenanceClass, ProvenanceRecord,
    ProvenanceRefusal, RegistryHost, RepositoryPath, ToolName, ToolProvenance, VerifiedIdentity,
    MAX_LOCATOR_BYTES,
};
pub use revocation::{BadRevocationReason, HostRevocations, RevocationFeed, Revoked};
pub use signature::{
    DuplicateScheme, HexBytes, HmacSha256TestScheme, KeyId, PublicKey, SchemeKind, SchemeRegistry,
    Signature, SignatureRejection, SignatureScheme, KEY_DOMAIN,
};
pub use state::{Inconsistency, RestoreRefusal, RoleRecord, TrustState, TRUST_STATE_FORMAT};
pub use store::{
    KeptRefusal, MemoryOnly, Regression, StateKeeper, StoreOpened, StoreRefusal, TrustStore,
    TrustStoreConfig,
};
pub use time::{CalendarAnchor, ClockError, TrustClock, UnixSeconds};
pub use vulnerability::{
    Applicability, BlockReason, Disposition, Exception, ExceptionId, FalsePositiveReview, Finding,
    GateOutcome, Governance, GovernanceError, GovernancePolicy, Reachability, Remediation,
    ScanReport, Severity, Signal,
};

/// The catalog's trust policy type, re-exported so callers configure provenance with
/// the one policy there is (S2 CORE-08; VM-W48).
pub use crate::foundation::catalog::TrustPolicy;
