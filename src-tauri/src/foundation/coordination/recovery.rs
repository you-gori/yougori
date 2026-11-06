//! Recovery (S3.4; S6 INT-04; S7 line 125; S10 line 181; VM part §6.1, §6.6).
//!
//! After a crash, recovery reconciles the recorded state with the actual VMs and
//! reservations. It never revives authority, a lease or a GPU allocation: a VM found alive
//! returns to VM_created under a new authorization epoch and needs fresh readiness
//! evidence and a fresh grant; every lease is marked not revived; every activation retires,
//! and later activations get new generations. A stopped sandbox boots again either by a
//! composite restore that passes every applicable validator or by a cold boot and reload,
//! and a restored VM is verified before it receives authority. Performance fallbacks
//! during recovery pass the S3.5 guard.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capacity::{CapacityPort, ReconcileReport, ReservationKey, ResourceKind, ReturnHold};
use super::coordinator::{
    BootSource, BootTerms, Compensation, CoordinationError, Coordinator, LaunchOutcome,
    TerminationStalled,
};
use super::identity::{ModelId, SandboxGenerations, SnapshotId, VmInstanceId};
use super::lease::{self, CancelCause, LeaseRecord, LeaseTable};
use super::model::{
    ActivationDemand, ActivationHandle, GpuAllocationHandle, GpuDemand, ModelActivations,
    ModelRefusal, RetireReason,
};
use super::port::{ObservedVm, SandboxPort};
use super::resource_return::ResourceReturn;
use super::sandbox::{LaunchFailure, SandboxLifecycle, SandboxState, SandboxStep, SettingsGrant};
use crate::foundation::catalog::{ArtifactClass, ObjectId, Scope};
use crate::foundation::evidence::{
    guard_fallback, AdmittedRuntime, ApprovedFallback, ArtifactVerification, Capability,
    ClockSession, FallbackRefusal, LoaderGate, LoaderPlan, ProbeRegistry, RuntimeSettings,
    RuntimeSubject, Satisfied, SourceClass, Subject,
};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId, GrantId,
    Incarnation, LeaseId, MonotonicTime, PolicyEpoch, SandboxBootGeneration, TenantId,
};

/// What the S3.5 guard checks a recovery fallback's loader against: the optimization
/// gate, the evidence registry, and the plan the gate approved for the runtime of the
/// parent's current boot (INT-06).
pub struct FallbackContext<'a, R: Clock> {
    pub gate: &'a LoaderGate,
    pub registry: &'a ProbeRegistry<R>,
    pub plan: &'a LoaderPlan,
}

/// The S3.5 guard on a performance fallback during recovery. Every recovery fallback goes
/// through here; `authorized` always comes from the coordinator's own records.
pub(super) fn guard_recovery_fallback<R: Clock>(
    context: &FallbackContext<'_, R>,
    authorized: &RuntimeSettings,
    proposed: RuntimeSettings,
) -> Result<ApprovedFallback, FallbackRefusal> {
    guard_fallback(
        context.gate,
        context.registry,
        context.plan,
        authorized,
        proposed,
    )
}

/// A part of a composite recovery, each with its own validator (S3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryComponent {
    VmSnapshotReset,
    GpuCheckpointRestore,
    ModelCacheRecovery,
}

/// When a snapshot was taken (VM part §6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotOrigin {
    /// A golden snapshot taken before any tenant input, credential or external
    /// connection; the only kind eligible for restore.
    PreTenantGolden,
    /// A dirty workload snapshot; never a base for restore.
    TenantWorkload,
}

/// Something a snapshot must not contain (S10 line 181).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotContent {
    LiveTenantSecrets,
    AuthorizationEpochs,
    ApplicationIdentifiers,
    InMemoryCredentials,
}

/// What the host recorded about a snapshot when it took it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub snapshot: SnapshotId,
    pub origin: SnapshotOrigin,
    /// The image and ABI profile it was taken from.
    pub image_profile: Digest,
    /// Forbidden contents found in it; any one disqualifies it.
    pub contents: BTreeSet<SnapshotContent>,
    /// The VM it was taken from; a restored VM must have another handle.
    pub source_vm: VmInstanceId,
    /// The guest identifiers it carries; a restored VM must replace them.
    pub guest_identity: Digest,
}

/// Why a snapshot cannot be restored (VM part §6.6; S10 line 181).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "defect", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum SnapshotDefect {
    NotPreTenant,
    Contains { content: SnapshotContent },
    ImageProfileMismatch { expected: Digest, found: Digest },
}

crate::foundation::strict_serde::strict_tag!(SnapshotDefect, "defect");

/// The VM snapshot reset validator (S3.4): only a pre-tenant golden snapshot with none of
/// the forbidden contents, taken from the approved image profile, is restorable.
pub fn validate_vm_snapshot(
    manifest: &SnapshotManifest,
    expected_image_profile: Digest,
) -> Result<(), Vec<SnapshotDefect>> {
    let mut defects = Vec::new();
    if manifest.origin != SnapshotOrigin::PreTenantGolden {
        defects.push(SnapshotDefect::NotPreTenant);
    }
    for content in &manifest.contents {
        defects.push(SnapshotDefect::Contains { content: *content });
    }
    if manifest.image_profile != expected_image_profile {
        defects.push(SnapshotDefect::ImageProfileMismatch {
            expected: expected_image_profile,
            found: manifest.image_profile,
        });
    }
    if defects.is_empty() {
        Ok(())
    } else {
        Err(defects)
    }
}

/// A GPU checkpoint as recorded and as read now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuCheckpointManifest {
    /// The content identity recorded when the checkpoint was taken.
    pub recorded: ContentKey,
    /// The content identity of the checkpoint as read now.
    pub observed: ContentKey,
    /// The identity of the exact runtime it was taken on (`Subject::identity`).
    pub runtime: Digest,
}

/// Why a GPU checkpoint cannot be restored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "defect", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CheckpointDefect {
    /// CUDA checkpoint is capability-gated (S7); no evidence shows it on this runtime.
    NoCapabilityEvidence,
    EvidenceForOtherCapability {
        capability: Capability,
    },
    EvidenceForOtherRuntime {
        evidence: Digest,
        checkpoint: Digest,
    },
    /// The checkpoint was taken on another runtime than the one the relaunch boots; a
    /// checkpoint is restored only on the exact runtime it came from (INT-06).
    CheckpointForOtherRuntime {
        checkpoint: Digest,
        runtime: Digest,
    },
    /// The capability evidence is no longer fresh.
    StaleEvidence {
        fresh_until: MonotonicTime,
        now: MonotonicTime,
    },
    IntegrityMismatch,
}

crate::foundation::strict_serde::strict_tag!(CheckpointDefect, "defect");

/// The GPU checkpoint restore validator (S3.4; S7: a distinct, capability-gated
/// experiment; INT-06: the exact runtime): the checkpoint was taken on `runtime`, the one
/// the relaunch boots; CUDA checkpoint evidence about that runtime is still fresh at
/// `now`; and the checkpoint is intact.
pub fn validate_gpu_checkpoint(
    manifest: &GpuCheckpointManifest,
    evidence: Option<&Satisfied>,
    runtime: &RuntimeSubject,
    now: MonotonicTime,
) -> Result<(), Vec<CheckpointDefect>> {
    let mut defects = Vec::new();
    let target = Subject::Runtime(runtime.clone()).identity();
    if manifest.runtime != target {
        defects.push(CheckpointDefect::CheckpointForOtherRuntime {
            checkpoint: manifest.runtime,
            runtime: target,
        });
    }
    match evidence {
        None => defects.push(CheckpointDefect::NoCapabilityEvidence),
        Some(satisfied) => {
            if satisfied.capability() != Capability::CudaCheckpoint {
                defects.push(CheckpointDefect::EvidenceForOtherCapability {
                    capability: satisfied.capability(),
                });
            }
            if satisfied.subject() != manifest.runtime {
                defects.push(CheckpointDefect::EvidenceForOtherRuntime {
                    evidence: satisfied.subject(),
                    checkpoint: manifest.runtime,
                });
            }
            if now > satisfied.fresh_until() {
                defects.push(CheckpointDefect::StaleEvidence {
                    fresh_until: satisfied.fresh_until(),
                    now,
                });
            }
        }
    }
    if manifest.recorded != manifest.observed {
        defects.push(CheckpointDefect::IntegrityMismatch);
    }
    if defects.is_empty() {
        Ok(())
    } else {
        Err(defects)
    }
}

/// The cached model artifacts a recovery would load, by content identity. In the tenant's
/// catalog scope each one is a model-weights or sidecar object (CORE-02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCacheManifest {
    pub tenant: TenantId,
    pub artifacts: BTreeSet<ContentKey>,
}

/// Why a model cache cannot be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "defect", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CacheDefect {
    /// Another tenant's cache; equal bytes are not permission (S3.3).
    OtherTenant {
        tenant: TenantId,
    },
    VerificationBypassed,
    UnverifiedArtifacts {
        artifacts: BTreeSet<ContentKey>,
    },
}

crate::foundation::strict_serde::strict_tag!(CacheDefect, "defect");

/// The model-cache recovery validator (S3.4): the cache belongs to this tenant and holds
/// only artifacts the authorized runtime verified (INT-09). The verified set may name an
/// artifact by its content key or, as `Catalog::artifact_verification` does, as the
/// tenant's catalog object of that content (CORE-02); both name the same verified bytes,
/// and an object of another scope never stands for the tenant's own.
pub fn validate_model_cache(
    manifest: &ModelCacheManifest,
    tenant: &TenantId,
    verification: &ArtifactVerification,
) -> Result<(), Vec<CacheDefect>> {
    let mut defects = Vec::new();
    if &manifest.tenant != tenant {
        defects.push(CacheDefect::OtherTenant {
            tenant: manifest.tenant.clone(),
        });
    }
    match verification {
        ArtifactVerification::Bypassed => defects.push(CacheDefect::VerificationBypassed),
        ArtifactVerification::Verified { artifacts } => {
            let scope = Scope::tenant(tenant.clone());
            let unverified: BTreeSet<ContentKey> = manifest
                .artifacts
                .iter()
                .filter(|artifact| !verified_artifact(artifacts, &scope, **artifact))
                .copied()
                .collect();
            if !unverified.is_empty() {
                defects.push(CacheDefect::UnverifiedArtifacts {
                    artifacts: unverified,
                });
            }
        }
    }
    if defects.is_empty() {
        Ok(())
    } else {
        Err(defects)
    }
}

/// Whether `verified` names `artifact`: by its content key, or as the catalog object of
/// that content in `scope`, model weights or a sidecar over them.
fn verified_artifact(verified: &BTreeSet<Digest>, scope: &Scope, artifact: ContentKey) -> bool {
    verified.contains(artifact.digest())
        || [ArtifactClass::ModelWeights, ArtifactClass::ModelSidecar]
            .into_iter()
            .any(|class| verified.contains(&ObjectId::new(scope, class, artifact).digest()))
}

/// What one validator found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "component", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ComponentDefects {
    VmSnapshot { defects: Vec<SnapshotDefect> },
    GpuCheckpoint { defects: Vec<CheckpointDefect> },
    ModelCache { defects: Vec<CacheDefect> },
}

crate::foundation::strict_serde::strict_tag!(ComponentDefects, "component");

/// One validator's verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ValidatorVerdict {
    Passed,
    Failed { defects: ComponentDefects },
}

crate::foundation::strict_serde::strict_tag!(ValidatorVerdict, "verdict");

/// What a recovery would restore. Each part present is applicable and must pass its own
/// validator (S3.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeRecovery {
    pub vm_snapshot: Option<SnapshotManifest>,
    pub gpu_checkpoint: Option<GpuCheckpointManifest>,
    pub model_cache: Option<ModelCacheManifest>,
}

/// What the validators check against.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryContext<'a> {
    /// The image and ABI profile approved now.
    pub expected_image_profile: Digest,
    /// Satisfied CUDA checkpoint evidence about the exact runtime, from the evidence
    /// registry (CORE-01).
    pub checkpoint_evidence: Option<&'a Satisfied>,
    /// The artifacts the authorized runtime verified.
    pub artifact_verification: &'a ArtifactVerification,
}

/// Which way a recovery goes (S3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPath {
    /// Every applicable validator passed.
    Restore,
    /// A validator failed, or nothing was restorable: cold boot and reload, reviving no
    /// authority.
    ColdBootReload,
}

/// Every applicable validator's verdict and the path they decide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecision {
    pub verdicts: BTreeMap<RecoveryComponent, ValidatorVerdict>,
    pub path: RecoveryPath,
}

impl CompositeRecovery {
    /// The components present, each of which must pass.
    pub fn applicable(&self) -> BTreeSet<RecoveryComponent> {
        let mut applicable = BTreeSet::new();
        if self.vm_snapshot.is_some() {
            applicable.insert(RecoveryComponent::VmSnapshotReset);
        }
        if self.gpu_checkpoint.is_some() {
            applicable.insert(RecoveryComponent::GpuCheckpointRestore);
        }
        if self.model_cache.is_some() {
            applicable.insert(RecoveryComponent::ModelCacheRecovery);
        }
        applicable
    }

    /// Runs every applicable validator for a relaunch of `tenant`'s sandbox on `runtime`,
    /// with evidence judged at `now`. The recovery restores only if all of them pass;
    /// otherwise it cold-boots and reloads (S3.4).
    pub fn evaluate(
        &self,
        context: &RecoveryContext<'_>,
        tenant: &TenantId,
        runtime: &RuntimeSubject,
        now: MonotonicTime,
    ) -> RecoveryDecision {
        let mut verdicts = BTreeMap::new();
        if let Some(manifest) = &self.vm_snapshot {
            let verdict = match validate_vm_snapshot(manifest, context.expected_image_profile) {
                Ok(()) => ValidatorVerdict::Passed,
                Err(defects) => ValidatorVerdict::Failed {
                    defects: ComponentDefects::VmSnapshot { defects },
                },
            };
            verdicts.insert(RecoveryComponent::VmSnapshotReset, verdict);
        }
        if let Some(manifest) = &self.gpu_checkpoint {
            let checked =
                validate_gpu_checkpoint(manifest, context.checkpoint_evidence, runtime, now);
            let verdict = match checked {
                Ok(()) => ValidatorVerdict::Passed,
                Err(defects) => ValidatorVerdict::Failed {
                    defects: ComponentDefects::GpuCheckpoint { defects },
                },
            };
            verdicts.insert(RecoveryComponent::GpuCheckpointRestore, verdict);
        }
        if let Some(manifest) = &self.model_cache {
            let verdict =
                match validate_model_cache(manifest, tenant, context.artifact_verification) {
                    Ok(()) => ValidatorVerdict::Passed,
                    Err(defects) => ValidatorVerdict::Failed {
                        defects: ComponentDefects::ModelCache { defects },
                    },
                };
            verdicts.insert(RecoveryComponent::ModelCacheRecovery, verdict);
        }
        let path = if !verdicts.is_empty()
            && verdicts
                .values()
                .all(|verdict| *verdict == ValidatorVerdict::Passed)
        {
            RecoveryPath::Restore
        } else {
            RecoveryPath::ColdBootReload
        };
        RecoveryDecision { verdicts, path }
    }
}

/// What was done to a restored VM before it may receive authority (VM part §6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreAction {
    /// A unique generation was created and host-side resources bound to it.
    HostResourcesBound,
    /// Supported kernel randomness was reseeded.
    KernelEntropyReseeded,
    /// Application keys, user state and other randomness-dependent application state
    /// were recreated (S7 line 125).
    ApplicationStateRecreated,
    /// Cached UUIDs, tokens, keys, connection pools and TLS sessions were replaced.
    CachedSecretsReplaced,
    /// Clocks and deadlines were rebound.
    ClocksRebound,
    /// Prior approvals were invalidated.
    PriorApprovalsInvalidated,
    /// Capabilities of the old snapshot are denied.
    OldSnapshotCapabilitiesDenied,
    /// MAC addresses were rewritten; never a substitute for an application reset (S7 line
    /// 125).
    MacAddressRewritten,
    /// The guest was notified through VMGenID; never a substitute (S7 line 125).
    VmGenIdNotified,
    /// A packet filter was applied; never a substitute (S7 line 125).
    PacketFilterApplied,
    /// Pages were prefetched through userfaultfd; an optional optimization that replaces
    /// nothing (S10 line 181).
    UserfaultfdPrefetch,
    /// Preallocated network slots were used; an optional optimization that replaces
    /// nothing (S10 line 181).
    PreallocatedNetworkSlots,
}

impl RestoreAction {
    /// The actions every restored VM needs (VM part §6.6).
    pub const REQUIRED: [Self; 7] = [
        Self::HostResourcesBound,
        Self::KernelEntropyReseeded,
        Self::ApplicationStateRecreated,
        Self::CachedSecretsReplaced,
        Self::ClocksRebound,
        Self::PriorApprovalsInvalidated,
        Self::OldSnapshotCapabilitiesDenied,
    ];

    /// Whether every restored VM needs it.
    pub const fn is_required(self) -> bool {
        matches!(
            self,
            Self::HostResourcesBound
                | Self::KernelEntropyReseeded
                | Self::ApplicationStateRecreated
                | Self::CachedSecretsReplaced
                | Self::ClocksRebound
                | Self::PriorApprovalsInvalidated
                | Self::OldSnapshotCapabilitiesDenied
        )
    }
}

/// What the restored-VM verification hook found in a restored VM (S10 line 181; VM part
/// §6.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredVmReport {
    pub vm: VmInstanceId,
    pub boot: SandboxBootGeneration,
    pub snapshot: SnapshotId,
    pub guest_identity: Digest,
    pub actions: BTreeSet<RestoreAction>,
    pub attached_volumes: BTreeSet<Digest>,
    /// The policy epoch applied to the restored VM.
    pub policy: PolicyEpoch,
    pub image_profile: Digest,
    /// Authorization epochs found inside the restored VM; a fresh VM has none.
    pub presented_epochs: BTreeSet<AuthorizationEpoch>,
    /// Who observed all this; only a host probe counts.
    pub source: SourceClass,
}

/// What a restored VM is checked against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreExpectation {
    /// The new boot generation of the restore.
    pub boot: SandboxBootGeneration,
    pub snapshot: SnapshotManifest,
    pub authorized_volumes: BTreeSet<Digest>,
    /// The current policy epoch.
    pub policy: PolicyEpoch,
}

/// One reason a restored VM may not receive authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RestoreFailure {
    NotHostObserved {
        source: SourceClass,
    },
    WrongSnapshot {
        expected: SnapshotId,
        found: SnapshotId,
    },
    BootGenerationNotFresh {
        expected: SandboxBootGeneration,
        found: SandboxBootGeneration,
    },
    VmIdentityReused {
        vm: VmInstanceId,
    },
    GuestIdentityReused,
    /// A required action is missing; the actions that are never substitutes for it are
    /// listed when present.
    MissingAction {
        action: RestoreAction,
        substitutes: BTreeSet<RestoreAction>,
    },
    UnauthorizedVolumes {
        volumes: BTreeSet<Digest>,
    },
    PolicyNotCurrent {
        expected: PolicyEpoch,
        found: PolicyEpoch,
    },
    OldEpochsPresent {
        epochs: BTreeSet<AuthorizationEpoch>,
    },
    ImageProfileMismatch {
        expected: Digest,
        found: Digest,
    },
}

crate::foundation::strict_serde::strict_tag!(RestoreFailure, "failure");

impl fmt::Display for RestoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHostObserved { source } => {
                write!(
                    f,
                    "the restored VM was reported by a {source}, not the host"
                )
            }
            Self::WrongSnapshot { expected, found } => {
                write!(f, "snapshot {found} was restored instead of {expected}")
            }
            Self::BootGenerationNotFresh { expected, found } => {
                write!(f, "boot generation {found} is not the fresh {expected}")
            }
            Self::VmIdentityReused { vm } => write!(f, "VM handle {vm} is the snapshot's own"),
            Self::GuestIdentityReused => f.write_str("the guest identifiers were not replaced"),
            Self::MissingAction {
                action,
                substitutes,
            } => {
                write!(f, "{action:?} was not done")?;
                if !substitutes.is_empty() {
                    write!(f, ", and {substitutes:?} never substitute for it")?;
                }
                Ok(())
            }
            Self::UnauthorizedVolumes { volumes } => {
                write!(f, "{} unauthorized volume(s) are attached", volumes.len())
            }
            Self::PolicyNotCurrent { expected, found } => {
                write!(f, "policy epoch {found} was applied instead of {expected}")
            }
            Self::OldEpochsPresent { epochs } => {
                write!(
                    f,
                    "the restored VM still carries authorization epochs {epochs:?}"
                )
            }
            Self::ImageProfileMismatch { .. } => {
                f.write_str("the image profile differs from the snapshot's")
            }
        }
    }
}

/// A restored VM that may not receive authority; recovery cold-boots instead (S7 line
/// 125: a cold-boot fallback).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRefusal {
    failures: Vec<RestoreFailure>,
}

impl RestoreRefusal {
    /// Every reason, in check order.
    pub fn failures(&self) -> &[RestoreFailure] {
        &self.failures
    }
}

impl fmt::Display for RestoreRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the restored VM receives no authority: ")?;
        for (index, failure) in self.failures.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{failure}")?;
        }
        f.write_str("; cold boot instead")
    }
}

impl std::error::Error for RestoreRefusal {}

/// A restored VM that passed verification. Only [`verify_restored_vm`] makes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedRestore {
    vm: VmInstanceId,
    boot: SandboxBootGeneration,
    snapshot: SnapshotId,
}

impl VerifiedRestore {
    /// The verified VM.
    pub fn vm(&self) -> VmInstanceId {
        self.vm
    }

    /// Its fresh boot generation.
    pub fn boot(&self) -> SandboxBootGeneration {
        self.boot
    }

    /// The snapshot it was restored from.
    pub fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }
}

/// Verifies a restored VM before it receives authority (S10 line 181; S7 line 125; VM part
/// §6.6): host-observed, fresh boot generation, VM and guest identities, every required
/// reset action, only authorized volumes, the current policy, the snapshot's image profile
/// and no old authorization epoch. MAC rewrites, VMGenID, packet filters and optional
/// optimizations never stand in for a required action. Every failure is listed.
pub fn verify_restored_vm(
    report: &RestoredVmReport,
    expectation: &RestoreExpectation,
) -> Result<VerifiedRestore, RestoreRefusal> {
    let snapshot = &expectation.snapshot;
    let mut failures = Vec::new();
    if report.source != SourceClass::HostProbe {
        failures.push(RestoreFailure::NotHostObserved {
            source: report.source,
        });
    }
    if report.snapshot != snapshot.snapshot {
        failures.push(RestoreFailure::WrongSnapshot {
            expected: snapshot.snapshot,
            found: report.snapshot,
        });
    }
    if report.boot != expectation.boot {
        failures.push(RestoreFailure::BootGenerationNotFresh {
            expected: expectation.boot,
            found: report.boot,
        });
    }
    if report.vm == snapshot.source_vm {
        failures.push(RestoreFailure::VmIdentityReused { vm: report.vm });
    }
    if report.guest_identity == snapshot.guest_identity {
        failures.push(RestoreFailure::GuestIdentityReused);
    }
    let substitutes: BTreeSet<RestoreAction> = report
        .actions
        .iter()
        .copied()
        .filter(|action| !action.is_required())
        .collect();
    for action in RestoreAction::REQUIRED {
        if !report.actions.contains(&action) {
            failures.push(RestoreFailure::MissingAction {
                action,
                substitutes: substitutes.clone(),
            });
        }
    }
    let unauthorized: BTreeSet<Digest> = report
        .attached_volumes
        .difference(&expectation.authorized_volumes)
        .copied()
        .collect();
    if !unauthorized.is_empty() {
        failures.push(RestoreFailure::UnauthorizedVolumes {
            volumes: unauthorized,
        });
    }
    if report.policy != expectation.policy {
        failures.push(RestoreFailure::PolicyNotCurrent {
            expected: expectation.policy,
            found: report.policy,
        });
    }
    if !report.presented_epochs.is_empty() {
        failures.push(RestoreFailure::OldEpochsPresent {
            epochs: report.presented_epochs.clone(),
        });
    }
    if report.image_profile != snapshot.image_profile {
        failures.push(RestoreFailure::ImageProfileMismatch {
            expected: snapshot.image_profile,
            found: report.image_profile,
        });
    }
    if failures.is_empty() {
        Ok(VerifiedRestore {
            vm: report.vm,
            boot: report.boot,
            snapshot: report.snapshot,
        })
    } else {
        Err(RestoreRefusal { failures })
    }
}

/// What the coordinator persists so that recovery can reconcile (VM part §6.1: a single
/// durable state machine; §6.3: persist replay protection across restarts). Revocations
/// and resource returns in progress are not persisted: recovery revives no authority, so
/// both end with the crash, and recovery ends the ledger holds of the returns. The
/// tombstones of revoked grants are persisted: recovery revives no lease, but a relaunch
/// grants the last settings again, which must never include a revoked grant.
///
/// Store it durably, then pass it to [`Coordinator::confirm_persisted`]: the coordinator
/// issues no lease id at or above `next_lease` until a later state is confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedState {
    pub sandboxes: Vec<SandboxLifecycle>,
    pub models: Vec<ModelActivations>,
    pub leases: Vec<LeaseRecord>,
    /// The lease-id high-water mark: every lease issued before this state was taken, or
    /// after it until a later state is confirmed, has a lower id. Recovery starts here, so
    /// an id from an earlier run is never issued again (ids.rs).
    pub next_lease: LeaseId,
    /// The owner resource-return holds active in the ledger (S10 line 185); recovery
    /// ends them.
    pub return_holds: Vec<ReturnHold>,
    /// The incarnation of the run that persisted it; the run that recovers it is the next
    /// (ids::Incarnation).
    #[serde(default = "first_incarnation")]
    pub incarnation: Incarnation,
    /// The grants revoked under each execution's authority, never honoured there again
    /// (CORE-04 per-grant revocation; VM part §6.3 step 1: a tombstone).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revoked_grants: BTreeMap<ExecutionId, BTreeSet<GrantId>>,
}

fn first_incarnation() -> Incarnation {
    Incarnation::FIRST
}

/// A recovery that could not finish. The capacity port comes back as recovery left it,
/// which released nothing still in use, so the live VMs' reservations stay counted (S2
/// CORE-03: unknown usage is never free) and recovery can be tried again with it.
pub struct RecoveryFailure<P> {
    /// Why recovery stopped.
    pub error: CoordinationError,
    /// The capacity port the caller passed in.
    pub capacity: P,
}

impl<P> fmt::Debug for RecoveryFailure<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<P> fmt::Display for RecoveryFailure<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recovery did not finish: {}", self.error)
    }
}

impl<P> std::error::Error for RecoveryFailure<P> {}

/// What recovery did with one sandbox (INT-04).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "recovery", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum SandboxRecovery {
    AlreadyStopped,
    /// A launch that had created no VM was undone.
    PartialStartRolledBack {
        compensations: Vec<Compensation>,
    },
    /// The recorded VM is alive. Authority was not revived: the sandbox is back at
    /// VM_created under a new authorization epoch and needs fresh readiness evidence and a
    /// fresh grant.
    VmKeptWithoutAuthority {
        vm: VmInstanceId,
        generations: SandboxGenerations,
    },
    /// The recorded VM is gone; its resources were released.
    VmLost {
        compensations: Vec<Compensation>,
    },
    /// A revocation or termination in progress was completed.
    TerminationCompleted {
        compensations: Vec<Compensation>,
    },
    /// Cleanup stopped part-way; nothing still in use was released.
    Stalled {
        stall: TerminationStalled,
    },
}

crate::foundation::strict_serde::strict_tag!(SandboxRecovery, "recovery");

/// What recovery found and did (INT-04).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub sandboxes: BTreeMap<ExecutionId, SandboxRecovery>,
    /// VMs with no trusted record: an unknown execution, another handle or boot
    /// generation, or a stopped sandbox. Each was terminated through its handle.
    pub untrusted_vms_terminated: Vec<VmInstanceId>,
    pub leases_not_revived: Vec<LeaseId>,
    /// Activations ended by the crash; their generations are never reused.
    pub retired_activations: Vec<GpuAllocationHandle>,
    /// GPU reservations still counted because the VM using them is alive; unknown usage
    /// is never counted as free (S2 CORE-03). The runtime confirms each release.
    pub gpu_reservations_counted: Vec<ReservationKey>,
    pub reservations: BTreeMap<ExecutionId, ReconcileReport>,
    /// Owner resource-return holds from before the crash, ended (S10 line 185).
    pub return_holds_ended: Vec<ReturnHold>,
}

/// How a stopped sandbox boots again (S3.4; S7 line 125).
#[derive(Clone, Debug)]
pub struct RelaunchPlan {
    /// The runtime admitted for the new boot, on fresh category evidence (INT-07).
    pub runtime: AdmittedRuntime,
    pub demand: BTreeMap<ResourceKind, u64>,
    pub authority_lifetime: Duration,
    pub readiness_max_age: Duration,
    pub runtime_evidence_max_age: Duration,
    /// What a restore would use; nothing means a cold boot.
    pub recovery: CompositeRecovery,
    /// The data volumes a restored VM may attach (VM part §6.6).
    pub authorized_volumes: BTreeSet<Digest>,
}

/// How a relaunch went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelaunchReport {
    pub decision: RecoveryDecision,
    /// A restore whose VM failed verification and was undone before the cold boot.
    pub refused_restore: Option<LaunchOutcome>,
    pub outcome: LaunchOutcome,
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// What to persist for recovery. Store it durably, then confirm it with
    /// [`Coordinator::confirm_persisted`].
    pub fn persist(&self) -> PersistedState {
        PersistedState {
            sandboxes: self.sandboxes.values().cloned().collect(),
            models: self.models.values().cloned().collect(),
            leases: self.leases.records().cloned().collect(),
            next_lease: self.leases.high_water_mark(),
            return_holds: self.returns.values().map(ResourceReturn::hold).collect(),
            incarnation: self.incarnation,
            revoked_grants: self.grant_tombstones.clone(),
        }
    }

    /// `state`, from [`Coordinator::persist`], is stored durably: lease ids below its
    /// high-water mark may be issued (VM part §6.3: persist replay protection across
    /// restarts), and the incarnation it carries, if it is this run's, is handed out
    /// ([`Coordinator::current_incarnation`]). Until a state is confirmed, a fresh
    /// coordinator issues at most 2^20 lease ids and a recovered one issues none, and
    /// neither hands out its incarnation, so recovery never hands out an id or a number a
    /// holder from before a crash may still present.
    pub fn confirm_persisted(&mut self, state: &PersistedState) {
        self.leases.confirm_persisted(state.next_lease);
        if state.incarnation == self.incarnation {
            self.incarnation_persisted = true;
        }
    }

    /// No lease id at or above this is issued until a later persisted state is confirmed.
    pub fn lease_id_limit(&self) -> LeaseId {
        self.leases.limit()
    }

    /// Recovers after a VM, engine or governor crash (INT-04; VM part §6.1: recovery
    /// reconciles actual VM objects and resources rather than trusting old PIDs).
    ///
    /// No authority, lease or GPU allocation is revived, and no revoked grant either: the
    /// grants' tombstones are restored. A recorded VM found alive with its handle and boot
    /// generation returns to VM_created under a new authorization epoch. A VM that is gone
    /// is cleaned up, a partial start is undone, and any VM without a trusted record is
    /// terminated through its handle. Owner resource-return holds from before the crash
    /// are ended. Finally the ledger is reconciled for every execution; a cancelled
    /// reservation of an execution with no VM left, every one having been terminated
    /// through the host port or found gone, is closed as the host's observation of its
    /// release.
    ///
    /// The VMs are listed before anything changes. On any failure the capacity port is
    /// returned in the error with every reservation it still counts, so the caller retries
    /// with it and never with an empty ledger. Lease ids continue at the persisted
    /// high-water mark and the incarnation one above the persisted one; neither a lease id
    /// nor the incarnation is handed out until the recovered state is persisted and
    /// confirmed ([`Coordinator::confirm_persisted`]).
    ///
    /// `session` is the clock session after the restart; nothing stamped on an earlier
    /// session is honoured.
    pub fn recover(
        persisted: PersistedState,
        clock: C,
        session: ClockSession,
        capacity: P,
        port: &mut dyn SandboxPort,
    ) -> Result<(Self, RecoveryReport), RecoveryFailure<P>> {
        let observed = match port.list_vms() {
            Ok(observed) => observed,
            Err(failure) => {
                return Err(RecoveryFailure {
                    error: CoordinationError::Port { failure },
                    capacity,
                })
            }
        };
        let mut coordinator = Self::new(clock, session, capacity);
        match coordinator.reconcile_after_crash(persisted, &observed, port) {
            Ok(report) => Ok((coordinator, report)),
            Err(error) => Err(RecoveryFailure {
                error,
                capacity: coordinator.into_capacity(),
            }),
        }
    }

    /// The body of [`Coordinator::recover`], once the VMs are listed.
    fn reconcile_after_crash(
        &mut self,
        persisted: PersistedState,
        observed: &[ObservedVm],
        port: &mut dyn SandboxPort,
    ) -> Result<RecoveryReport, CoordinationError> {
        self.incarnation = persisted
            .incarnation
            .next()
            .ok_or(CoordinationError::IncarnationsExhausted)?;
        let (leases, not_revived) = LeaseTable::restored(persisted.next_lease, persisted.leases);
        self.leases = leases;
        self.grant_tombstones = persisted.revoked_grants;
        let mut report = RecoveryReport {
            leases_not_revived: not_revived,
            ..RecoveryReport::default()
        };
        for mut models in persisted.models {
            let execution = models.execution().clone();
            let model = models.model();
            for generations in models.retire_all(RetireReason::Recovered) {
                report.retired_activations.push(GpuAllocationHandle {
                    execution: execution.clone(),
                    model,
                    generations,
                });
            }
            self.models.insert((execution, model), models);
        }
        for sandbox in persisted.sandboxes {
            self.sandboxes.insert(sandbox.execution().clone(), sandbox);
        }
        let refused = |refusal| CoordinationError::Capacity { refusal };
        for hold in persisted.return_holds {
            self.capacity.end_hold(hold).map_err(refused)?;
            report.return_holds_ended.push(hold);
        }

        let executions: Vec<ExecutionId> = self.sandboxes.keys().cloned().collect();
        for execution in &executions {
            let outcome = self.recover_sandbox(
                execution,
                observed,
                port,
                &mut report.untrusted_vms_terminated,
            )?;
            report.sandboxes.insert(execution.clone(), outcome);
        }
        let mut unknown = BTreeSet::new();
        for vm in observed {
            if self.sandboxes.contains_key(&vm.execution) {
                continue;
            }
            port.terminate_vm(&vm.vm)
                .map_err(|failure| CoordinationError::Port { failure })?;
            report.untrusted_vms_terminated.push(vm.vm);
            unknown.insert(vm.execution.clone());
        }

        for execution in executions.iter().chain(unknown.iter()) {
            let expected = self.expected_reservations(execution);
            let mut reconciled = self
                .capacity
                .reconcile(execution, &expected)
                .map_err(refused)?;
            let vm_may_remain = matches!(
                report.sandboxes.get(execution),
                Some(SandboxRecovery::VmKeptWithoutAuthority { .. })
                    | Some(SandboxRecovery::Stalled { .. })
            );
            if !vm_may_remain {
                for key in std::mem::take(&mut reconciled.pending_orphans) {
                    self.capacity
                        .confirm_release(&key, SourceClass::HostProbe)
                        .map_err(refused)?;
                    reconciled.released_orphans.insert(key);
                }
            }
            report.reservations.insert(execution.clone(), reconciled);
        }
        report.gpu_reservations_counted = self
            .models
            .values()
            .flat_map(ModelActivations::counted_reservations)
            .collect();
        Ok(report)
    }

    fn recover_sandbox(
        &mut self,
        execution: &ExecutionId,
        observed: &[ObservedVm],
        port: &mut dyn SandboxPort,
        untrusted: &mut Vec<VmInstanceId>,
    ) -> Result<SandboxRecovery, CoordinationError> {
        let sandbox = self.sandbox_ref(execution)?;
        let (state, recorded, boot) = (sandbox.state(), sandbox.vm(), sandbox.generations().boot);
        let mut alive = None;
        for found in observed
            .iter()
            .filter(|found| &found.execution == execution)
        {
            if state != SandboxState::Stopped && Some(found.vm) == recorded && found.boot == boot {
                alive = Some(found.vm);
                continue;
            }
            port.terminate_vm(&found.vm)
                .map_err(|failure| CoordinationError::Port { failure })?;
            untrusted.push(found.vm);
        }
        let had_vm = matches!(
            state,
            SandboxState::VmCreated
                | SandboxState::BootEvidenceChecked
                | SandboxState::AuthorityActive
                | SandboxState::Running
        );
        if had_vm {
            self.apply_step(execution, SandboxStep::Reconcile)?;
            if let Some(vm) = alive {
                let generations = self.sandbox_ref(execution)?.generations();
                return Ok(SandboxRecovery::VmKeptWithoutAuthority { vm, generations });
            }
            self.apply_step(execution, SandboxStep::Terminate)?;
        } else {
            match state {
                SandboxState::Planned => {
                    self.apply_step(execution, SandboxStep::Stop)?;
                }
                SandboxState::ResourcesReserved | SandboxState::PerimeterReady => {
                    self.apply_step(execution, SandboxStep::BeginCleanup)?;
                }
                _ => {}
            }
        }
        let compensations = match self.finish_termination(execution, port)? {
            Ok(compensations) => compensations,
            Err(stall) => return Ok(SandboxRecovery::Stalled { stall }),
        };
        Ok(match state {
            SandboxState::Stopped => SandboxRecovery::AlreadyStopped,
            SandboxState::Planned
            | SandboxState::ResourcesReserved
            | SandboxState::PerimeterReady => {
                SandboxRecovery::PartialStartRolledBack { compensations }
            }
            SandboxState::Revoking | SandboxState::Terminating | SandboxState::CleanupPending => {
                SandboxRecovery::TerminationCompleted { compensations }
            }
            SandboxState::VmCreated
            | SandboxState::BootEvidenceChecked
            | SandboxState::AuthorityActive
            | SandboxState::Running => SandboxRecovery::VmLost { compensations },
        })
    }

    /// The reservations the records say `execution` still holds.
    fn expected_reservations(&self, execution: &ExecutionId) -> BTreeSet<ReservationKey> {
        let mut expected = BTreeSet::new();
        if let Some(sandbox) = self.sandboxes.get(execution) {
            if sandbox.state() != SandboxState::Stopped {
                expected.extend(sandbox.reservation());
            }
        }
        for ((owner, _), models) in &self.models {
            if owner == execution {
                expected.extend(models.counted_reservations());
            }
        }
        expected
    }

    /// Boots a stopped sandbox again (S3.4; S7 line 125; S10 line 181).
    ///
    /// The composite recovery restores only if every applicable validator passes;
    /// otherwise the VM cold-boots. Either way the boot gets a fresh boot generation and
    /// authorization epoch, and authority is granted afresh only after host-observed
    /// readiness and a recheck of the runtime's category evidence on `registry`. A restored
    /// VM is verified first; if verification fails, the restore is undone and the sandbox
    /// cold-boots.
    pub fn relaunch<R: Clock>(
        &mut self,
        execution: &ExecutionId,
        plan: RelaunchPlan,
        context: &RecoveryContext<'_>,
        port: &mut dyn SandboxPort,
        registry: &ProbeRegistry<R>,
    ) -> Result<RelaunchReport, CoordinationError> {
        let sandbox = self.sandbox_ref(execution)?;
        if sandbox.state() != SandboxState::Stopped {
            return Err(CoordinationError::NotStopped {
                state: sandbox.state(),
            });
        }
        let decision = plan.recovery.evaluate(
            context,
            sandbox.tenant(),
            plan.runtime.runtime(),
            self.monotonic_now(),
        );
        let settings = self.without_revoked(execution, sandbox.settings_grant().clone());
        let restore = match decision.path {
            RecoveryPath::Restore => plan.recovery.vm_snapshot.clone(),
            RecoveryPath::ColdBootReload => None,
        };
        let runtime = plan.runtime.runtime().clone();
        self.new_boot(execution, runtime.clone())?;
        let mut terms = BootTerms {
            runtime: plan.runtime,
            demand: plan.demand,
            authority_lifetime: plan.authority_lifetime,
            readiness_max_age: plan.readiness_max_age,
            runtime_evidence_max_age: plan.runtime_evidence_max_age,
            settings,
            source: match restore {
                Some(snapshot) => BootSource::Restore {
                    snapshot,
                    authorized_volumes: plan.authorized_volumes,
                },
                None => BootSource::Fresh,
            },
        };
        let outcome = self.drive(execution, &terms, port, registry)?;
        let refused = matches!(
            &outcome,
            LaunchOutcome::RolledBack {
                failure: LaunchFailure::RestoreRefused { .. },
                ..
            }
        );
        if !refused {
            return Ok(RelaunchReport {
                decision,
                refused_restore: None,
                outcome,
            });
        }
        self.new_boot(execution, runtime)?;
        terms.source = BootSource::Fresh;
        let cold = self.drive(execution, &terms, port, registry)?;
        Ok(RelaunchReport {
            decision,
            refused_restore: Some(outcome),
            outcome: cold,
        })
    }

    /// A new boot of a stopped sandbox on `runtime`: everything of the old boot ends. The
    /// transition comes first, so a refused boot, such as of a retired sandbox, changes
    /// nothing.
    fn new_boot(
        &mut self,
        execution: &ExecutionId,
        runtime: RuntimeSubject,
    ) -> Result<(), CoordinationError> {
        self.apply_step(execution, SandboxStep::NewBoot { runtime })?;
        self.revocations.remove(execution);
        for ((owner, _), models) in self.models.iter_mut() {
            if owner == execution {
                models.retire_all(RetireReason::Recovered);
            }
        }
        let now = self.monotonic_now();
        self.leases.cancel_where(
            |lease| lease.parent() == execution,
            CancelCause::NewBoot,
            now,
        );
        Ok(())
    }

    /// The settings the authority record authorizes for `model` under `execution` now: the
    /// baseline every S3.5 fallback, a recovery reload or a profile revert, is judged
    /// against, never a caller's settings (T01 review). Its execution category, the actual
    /// runtime's, and its network grants, verified artifacts and authority come from the
    /// parent's authority record, granted afresh and never revived; its loader, batch size
    /// and residency, which stay within that record, from the model's latest activation in
    /// a VM sandbox, or from the settings it was authorized with in a labelled runtime
    /// ([`Coordinator::authorize_labelled_model`]). The parent must hold current authority,
    /// and the model must have been activated or authorized under it or before.
    pub fn authorized_settings(
        &self,
        execution: &ExecutionId,
        model: ModelId,
    ) -> Result<RuntimeSettings, ModelRefusal> {
        if let Some(settings) = self.labelled_settings(execution, model) {
            return settings;
        }
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let context = self.lease_context(execution, None).map_err(parent)?;
        let grant = lease::parent_authority(&context, self.monotonic_now()).map_err(parent)?;
        let (category, granted) = self
            .sandboxes
            .get(execution)
            .map(|sandbox| (sandbox.runtime().category, sandbox.settings_grant().clone()))
            .unwrap_or((ExecutionCategory::VmSandbox, SettingsGrant::default()));
        let recorded = self
            .models
            .get(&(execution.clone(), model))
            .and_then(ModelActivations::latest)
            .map(|activation| activation.settings().clone())
            .ok_or(ModelRefusal::NoPriorActivation { model })?;
        Ok(RuntimeSettings {
            execution_category: category,
            network: granted.network,
            authority: grant,
            artifact_verification: ArtifactVerification::Verified {
                artifacts: granted.verified_artifacts,
            },
            ..recorded
        })
    }

    /// Activates a model again after recovery, with a performance fallback (S3.5):
    /// `proposed` may change the loader, batch size or residency, but never the execution
    /// category, network access, artifact verification or authority. The baseline is the
    /// coordinator's own authority record, never a caller's settings (T01 review): the
    /// network grants and verified artifacts granted with the parent's authority, under
    /// the authority the parent holds now, which was granted afresh and never revived;
    /// only the loader, batch size and residency come from the last activation. The loader
    /// is checked against `fallback.plan`, which must be the gate's plan for the runtime
    /// of the parent's current boot.
    pub fn reload_model<R: Clock>(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        fallback: &FallbackContext<'_, R>,
        proposed: RuntimeSettings,
        demand: GpuDemand,
    ) -> Result<GpuAllocationHandle, ModelRefusal> {
        let handle = self.reload_model_with(
            execution,
            model,
            fallback,
            proposed,
            ActivationDemand::gpu(demand),
        )?;
        Ok(GpuAllocationHandle {
            execution: handle.execution,
            model: handle.model,
            generations: handle.generations,
        })
    }

    /// [`Coordinator::reload_model`] with several devices and host memory. Nothing of an
    /// earlier boot or authorization epoch can be acquired (INT-04), so `demand` names
    /// new memory only.
    pub fn reload_model_with<R: Clock>(
        &mut self,
        execution: &ExecutionId,
        model: ModelId,
        fallback: &FallbackContext<'_, R>,
        proposed: RuntimeSettings,
        demand: ActivationDemand,
    ) -> Result<ActivationHandle, ModelRefusal> {
        let parent = |refusal| ModelRefusal::Parent { refusal };
        let context = self.new_work_context(execution, None).map_err(parent)?;
        lease::parent_authority(&context, self.monotonic_now()).map_err(parent)?;
        let runtime = self
            .sandboxes
            .get(execution)
            .map(|sandbox| sandbox.runtime().clone())
            .ok_or(ModelRefusal::Parent {
                refusal: lease::LeaseRefusal::UnknownExecution {
                    execution: execution.clone(),
                },
            })?;
        if fallback.plan.runtime() != &runtime {
            return Err(ModelRefusal::PlanForOtherRuntime {
                plan: fallback.plan.runtime().clone(),
                runtime,
            });
        }
        let authorized = self.authorized_settings(execution, model)?;
        let approved = guard_recovery_fallback(fallback, &authorized, proposed)
            .map_err(|refusal| ModelRefusal::Fallback { refusal })?;
        self.begin_activation_with(execution, model, approved.into_settings(), demand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::{Backend, BackendRelease};
    use crate::foundation::ids::digest;

    fn id(domain: &str, name: &str) -> Digest {
        digest(domain, &[name.as_bytes()])
    }

    fn golden() -> SnapshotManifest {
        SnapshotManifest {
            snapshot: SnapshotId::new(id("yougori/test/snapshot/v1", "golden")),
            origin: SnapshotOrigin::PreTenantGolden,
            image_profile: id("yougori/test/image/v1", "profile"),
            contents: BTreeSet::new(),
            source_vm: VmInstanceId::new(id("yougori/test/vm/v1", "builder")),
            guest_identity: id("yougori/test/guest/v1", "golden"),
        }
    }

    fn expectation() -> RestoreExpectation {
        RestoreExpectation {
            boot: SandboxBootGeneration::new(2),
            snapshot: golden(),
            authorized_volumes: BTreeSet::from([id("yougori/test/volume/v1", "data")]),
            policy: PolicyEpoch::FIRST,
        }
    }

    fn clean_report() -> RestoredVmReport {
        RestoredVmReport {
            vm: VmInstanceId::new(id("yougori/test/vm/v1", "restored")),
            boot: SandboxBootGeneration::new(2),
            snapshot: golden().snapshot,
            guest_identity: id("yougori/test/guest/v1", "fresh"),
            actions: RestoreAction::REQUIRED.into_iter().collect(),
            attached_volumes: BTreeSet::from([id("yougori/test/volume/v1", "data")]),
            policy: PolicyEpoch::FIRST,
            image_profile: golden().image_profile,
            presented_epochs: BTreeSet::new(),
            source: SourceClass::HostProbe,
        }
    }

    #[test]
    fn a_snapshot_must_be_pre_tenant_clean_and_of_the_approved_profile() {
        let profile = golden().image_profile;
        assert_eq!(validate_vm_snapshot(&golden(), profile), Ok(()));
        let mut dirty = golden();
        dirty.origin = SnapshotOrigin::TenantWorkload;
        dirty.contents = BTreeSet::from([
            SnapshotContent::LiveTenantSecrets,
            SnapshotContent::AuthorizationEpochs,
            SnapshotContent::ApplicationIdentifiers,
            SnapshotContent::InMemoryCredentials,
        ]);
        let defects =
            validate_vm_snapshot(&dirty, id("yougori/test/image/v1", "other")).unwrap_err();
        assert_eq!(defects.len(), 6);
        assert_eq!(defects[0], SnapshotDefect::NotPreTenant);
        assert!(matches!(
            defects[5],
            SnapshotDefect::ImageProfileMismatch { .. }
        ));
    }

    #[test]
    fn a_clean_restore_is_verified() {
        let verified = verify_restored_vm(&clean_report(), &expectation()).unwrap();
        assert_eq!(verified.boot(), SandboxBootGeneration::new(2));
        assert_eq!(verified.snapshot(), golden().snapshot);
    }

    #[test]
    fn identity_tricks_never_substitute_for_an_application_reset() {
        let mut report = clean_report();
        report
            .actions
            .remove(&RestoreAction::ApplicationStateRecreated);
        report.actions.extend([
            RestoreAction::MacAddressRewritten,
            RestoreAction::VmGenIdNotified,
            RestoreAction::PacketFilterApplied,
        ]);
        let refusal = verify_restored_vm(&report, &expectation()).unwrap_err();
        assert_eq!(
            refusal.failures(),
            [RestoreFailure::MissingAction {
                action: RestoreAction::ApplicationStateRecreated,
                substitutes: BTreeSet::from([
                    RestoreAction::MacAddressRewritten,
                    RestoreAction::VmGenIdNotified,
                    RestoreAction::PacketFilterApplied,
                ]),
            }]
        );
        assert!(refusal.to_string().contains("cold boot instead"));
    }

    #[test]
    fn optimizations_never_replace_fresh_identity_policy_or_host_readiness() {
        let mut report = clean_report();
        report.actions.extend([
            RestoreAction::UserfaultfdPrefetch,
            RestoreAction::PreallocatedNetworkSlots,
        ]);
        report.guest_identity = golden().guest_identity;
        report.vm = golden().source_vm;
        report.policy = PolicyEpoch::new(9);
        report.source = SourceClass::GuestReport;
        let failures = verify_restored_vm(&report, &expectation())
            .unwrap_err()
            .failures()
            .to_vec();
        assert!(failures.contains(&RestoreFailure::GuestIdentityReused));
        assert!(failures.contains(&RestoreFailure::VmIdentityReused {
            vm: golden().source_vm
        }));
        assert!(failures.contains(&RestoreFailure::PolicyNotCurrent {
            expected: PolicyEpoch::FIRST,
            found: PolicyEpoch::new(9)
        }));
        assert!(failures.contains(&RestoreFailure::NotHostObserved {
            source: SourceClass::GuestReport
        }));
    }

    #[test]
    fn a_restored_vm_carries_no_old_epoch_or_unauthorized_volume() {
        let mut report = clean_report();
        report.presented_epochs = BTreeSet::from([AuthorizationEpoch::new(3)]);
        report
            .attached_volumes
            .insert(id("yougori/test/volume/v1", "other-tenant"));
        report.boot = SandboxBootGeneration::FIRST;
        let failures = verify_restored_vm(&report, &expectation())
            .unwrap_err()
            .failures()
            .to_vec();
        assert_eq!(failures.len(), 3);
        assert!(matches!(
            failures[0],
            RestoreFailure::BootGenerationNotFresh { .. }
        ));
        assert!(matches!(
            failures[1],
            RestoreFailure::UnauthorizedVolumes { .. }
        ));
        assert!(matches!(
            failures[2],
            RestoreFailure::OldEpochsPresent { .. }
        ));
    }

    #[test]
    fn every_missing_required_action_is_listed() {
        let mut report = clean_report();
        report.actions.clear();
        let failures = verify_restored_vm(&report, &expectation())
            .unwrap_err()
            .failures()
            .to_vec();
        assert_eq!(failures.len(), RestoreAction::REQUIRED.len());
    }

    #[test]
    fn model_caches_need_this_tenant_and_verified_artifacts() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let weights = ContentKey::of(b"weights");
        let cache = ModelCacheManifest {
            tenant: tenant.clone(),
            artifacts: BTreeSet::from([weights]),
        };
        let verified = ArtifactVerification::Verified {
            artifacts: BTreeSet::from([*weights.digest()]),
        };
        assert_eq!(validate_model_cache(&cache, &tenant, &verified), Ok(()));
        let other = TenantId::new("tenant-b").unwrap();
        assert_eq!(
            validate_model_cache(&cache, &other, &verified),
            Err(vec![CacheDefect::OtherTenant { tenant }])
        );
        assert_eq!(
            validate_model_cache(&cache, &cache.tenant, &ArtifactVerification::Bypassed),
            Err(vec![CacheDefect::VerificationBypassed])
        );
        let empty = ArtifactVerification::Verified {
            artifacts: BTreeSet::new(),
        };
        assert_eq!(
            validate_model_cache(&cache, &cache.tenant, &empty),
            Err(vec![CacheDefect::UnverifiedArtifacts {
                artifacts: BTreeSet::from([weights])
            }])
        );
    }

    #[test]
    fn a_gpu_checkpoint_without_capability_evidence_never_restores() {
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: id("yougori/test/runtime/v1", "r"),
        };
        let taken_on = Subject::Runtime(runtime.clone()).identity();
        let manifest = GpuCheckpointManifest {
            recorded: ContentKey::of(b"checkpoint"),
            observed: ContentKey::of(b"checkpoint, corrupted"),
            runtime: taken_on,
        };
        let now = MonotonicTime::from_nanos(0);
        assert_eq!(
            validate_gpu_checkpoint(&manifest, None, &runtime, now),
            Err(vec![
                CheckpointDefect::NoCapabilityEvidence,
                CheckpointDefect::IntegrityMismatch
            ])
        );
        let other = RuntimeSubject {
            instance: id("yougori/test/runtime/v1", "other"),
            ..runtime
        };
        assert_eq!(
            validate_gpu_checkpoint(&manifest, None, &other, now),
            Err(vec![
                CheckpointDefect::CheckpointForOtherRuntime {
                    checkpoint: taken_on,
                    runtime: Subject::Runtime(other.clone()).identity(),
                },
                CheckpointDefect::NoCapabilityEvidence,
                CheckpointDefect::IntegrityMismatch
            ])
        );
    }
}
