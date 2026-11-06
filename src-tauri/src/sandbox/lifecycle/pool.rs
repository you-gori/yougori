//! Snapshot and warm-pool rules, and what a service renewal keeps (VM part §6.6 lines
//! 2166–2178; §5.5 lines 2266–2281; VM-W27 line 2633; BENCH-06 line 366).
//!
//! Only a golden snapshot taken before tenant inputs, credentials and external
//! connections is pool-eligible. A checkout gets a unique generation, invalidates prior
//! approvals and old capabilities and rebinds its deadlines; the coordinator's restore
//! verification enforces the rest. When the backend cannot reset a clone's state, the
//! checkout cold-boots, recorded as such. The volume kinds of §5.5 decide what a service
//! renewal keeps. No snapshot is taken here; this is the model only.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::backend::{BackendCapabilities, StateReset};
use crate::foundation::coordination::{
    validate_vm_snapshot, SnapshotDefect, SnapshotManifest, SnapshotOrigin,
};
use crate::foundation::ids::Digest;

/// When the snapshot was taken, relative to the three things that make a snapshot dirty
/// (§6.6 "before tenant inputs, credentials and external connections").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotProvenance {
    pub before_tenant_inputs: bool,
    pub before_credentials: bool,
    pub before_external_connections: bool,
}

/// Why a snapshot is not pool-eligible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum PoolRefusal {
    /// A dirty workload snapshot is never promoted to a shared base.
    NotGolden {
        origin: SnapshotOrigin,
    },
    TakenAfterTenantInputs,
    TakenAfterCredentials,
    TakenAfterExternalConnections,
    /// The CORE-04 snapshot validator found defects.
    Defects {
        defects: Vec<SnapshotDefect>,
    },
    /// The pool has no golden snapshot or none left.
    Depleted,
}

crate::foundation::strict_serde::strict_tag!(PoolRefusal, "refusal");

impl fmt::Display for PoolRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGolden { origin } => write!(
                f,
                "a {origin:?} snapshot is never promoted to a shared pool base"
            ),
            Self::TakenAfterTenantInputs => {
                f.write_str("the snapshot was taken after tenant inputs")
            }
            Self::TakenAfterCredentials => f.write_str("the snapshot was taken after credentials"),
            Self::TakenAfterExternalConnections => {
                f.write_str("the snapshot was taken after external connections")
            }
            Self::Defects { defects } => write!(f, "the snapshot has {} defect(s)", defects.len()),
            Self::Depleted => f.write_str("the pool has no golden snapshot available"),
        }
    }
}

impl std::error::Error for PoolRefusal {}

/// A snapshot certified pool-eligible. Only [`GoldenSnapshot::certify`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GoldenSnapshot {
    manifest: SnapshotManifest,
    provenance: SnapshotProvenance,
}

impl GoldenSnapshot {
    /// Certifies `manifest` for the pool: a pre-tenant golden origin, taken before
    /// inputs, credentials and connections, with no forbidden contents and the approved
    /// image profile (§6.6; S10 line 353).
    pub fn certify(
        manifest: SnapshotManifest,
        provenance: SnapshotProvenance,
        expected_image_profile: Digest,
    ) -> Result<Self, PoolRefusal> {
        if manifest.origin != SnapshotOrigin::PreTenantGolden {
            return Err(PoolRefusal::NotGolden {
                origin: manifest.origin,
            });
        }
        if !provenance.before_tenant_inputs {
            return Err(PoolRefusal::TakenAfterTenantInputs);
        }
        if !provenance.before_credentials {
            return Err(PoolRefusal::TakenAfterCredentials);
        }
        if !provenance.before_external_connections {
            return Err(PoolRefusal::TakenAfterExternalConnections);
        }
        validate_vm_snapshot(&manifest, expected_image_profile)
            .map_err(|defects| PoolRefusal::Defects { defects })?;
        Ok(Self {
            manifest,
            provenance,
        })
    }

    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }

    pub fn provenance(&self) -> SnapshotProvenance {
        self.provenance
    }
}

/// Why a checkout cold-boots instead of restoring (§6.6; VM-W27 "unsupported restore
/// falls back to cold boot").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fallback", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ColdFallback {
    /// The backend has no snapshot restore.
    RestoreUnsupported,
    /// The backend cannot reset the clone's application state.
    StateResetUnsupported { detail: String },
    /// The pool has no golden snapshot left.
    PoolDepleted,
    /// The coordinator's launch transaction restores only a stopped sandbox; a new
    /// execution's first boot is always cold.
    NewExecution,
    /// The restored clone failed verification and was cleaned up (§6.6 "deny old
    /// snapshot capabilities").
    CloneVerificationFailed,
}

crate::foundation::strict_serde::strict_tag!(ColdFallback, "fallback");

/// How a checkout proceeds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CheckoutDecision {
    Restore,
    ColdBoot { fallback: ColdFallback },
}

crate::foundation::strict_serde::strict_tag!(CheckoutDecision, "decision");

/// Decides a checkout from what the backend supports and what the pool holds. Never a
/// silent fallback: a cold boot names its reason.
pub fn decide_checkout(
    capabilities: &BackendCapabilities,
    pool_has_snapshot: bool,
    sandbox_is_stopped: bool,
) -> CheckoutDecision {
    let fallback = if !sandbox_is_stopped {
        Some(ColdFallback::NewExecution)
    } else if !capabilities.snapshot_restore {
        Some(ColdFallback::RestoreUnsupported)
    } else if let StateReset::Unsupported { detail } = &capabilities.state_reset {
        Some(ColdFallback::StateResetUnsupported {
            detail: detail.clone(),
        })
    } else if !pool_has_snapshot {
        Some(ColdFallback::PoolDepleted)
    } else {
        None
    };
    match fallback {
        Some(fallback) => CheckoutDecision::ColdBoot { fallback },
        None => CheckoutDecision::Restore,
    }
}

/// A warm pool of one golden snapshot with a bounded number of prepared clones
/// (BENCH-06 "limited warm pool, pool depletion/replenishment").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WarmPool {
    golden: Option<GoldenSnapshot>,
    available: u32,
    capacity: u32,
}

impl WarmPool {
    pub fn new(capacity: u32) -> Self {
        Self {
            golden: None,
            available: 0,
            capacity,
        }
    }

    /// Sets the pool's base; only a certified golden snapshot is accepted by the type.
    pub fn set_golden(&mut self, golden: GoldenSnapshot) {
        self.golden = Some(golden);
    }

    pub fn golden(&self) -> Option<&GoldenSnapshot> {
        self.golden.as_ref()
    }

    pub fn available(&self) -> u32 {
        self.available
    }

    /// Prepares clones up to the capacity.
    pub fn replenish(&mut self, clones: u32) -> u32 {
        let room = self.capacity.saturating_sub(self.available);
        let added = clones.min(room);
        self.available = self.available.saturating_add(added);
        added
    }

    /// Takes one prepared clone's snapshot, or reports depletion.
    pub fn take(&mut self) -> Result<&GoldenSnapshot, PoolRefusal> {
        if self.available == 0 {
            return Err(PoolRefusal::Depleted);
        }
        let golden = self.golden.as_ref().ok_or(PoolRefusal::Depleted)?;
        self.available = self.available.saturating_sub(1);
        Ok(golden)
    }
}

/// The §5.5 volume kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeKind {
    PureApplicationData,
    SourceWorkspace,
    ExecutableEnvironmentCache,
    CredentialState,
    UnreviewedOutput,
}

/// What a renewal does with a volume of each kind (§5.5 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalBehavior {
    /// Retained with application-level validation and backups.
    RetainWithValidation,
    /// Retained as untrusted code and data; executed only inside the next sandbox.
    RetainAsUntrusted,
    /// Rebuilt from a pinned manifest; the old bytes are not attached.
    RebuildFromManifest,
    /// Explicitly preserved with weaker persistence claims.
    PreserveWithWeakerClaims,
    /// Owned by the external broker; no copied long-lived credential is attached.
    ExternalBrokerOwnership,
    /// Quarantined until promotion; not attached as data.
    Quarantine,
}

/// The caller's choice for executable caches (§5.5: rebuild, or explicitly preserve).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    RebuildFromManifest,
    PreserveExplicitly,
}

/// The sandbox profile (VM-D3; §5.5 "no copied long-lived provider credentials in strict
/// profile").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Strict,
    Transport,
}

/// Why a volume is not attached to the next boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum VolumeRefusal {
    /// Credential state is the external broker's; the strict profile attaches no copy.
    CredentialCopyInStrictProfile,
    /// Unreviewed output stays quarantined until promotion.
    Quarantined,
    /// The cache is rebuilt from its pinned manifest.
    Rebuilt,
}

crate::foundation::strict_serde::strict_tag!(VolumeRefusal, "refusal");

/// Whether a volume rides into the next boot, and with what claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "attachment", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum VolumeAttachment {
    Attached { behavior: RenewalBehavior },
    NotAttached { refusal: VolumeRefusal },
}

crate::foundation::strict_serde::strict_tag!(VolumeAttachment, "attachment");

impl VolumeKind {
    /// The §5.5 renewal behaviour.
    pub const fn renewal_behavior(self, cache: CachePolicy) -> RenewalBehavior {
        match self {
            Self::PureApplicationData => RenewalBehavior::RetainWithValidation,
            Self::SourceWorkspace => RenewalBehavior::RetainAsUntrusted,
            Self::ExecutableEnvironmentCache => match cache {
                CachePolicy::RebuildFromManifest => RenewalBehavior::RebuildFromManifest,
                CachePolicy::PreserveExplicitly => RenewalBehavior::PreserveWithWeakerClaims,
            },
            Self::CredentialState => RenewalBehavior::ExternalBrokerOwnership,
            Self::UnreviewedOutput => RenewalBehavior::Quarantine,
        }
    }

    /// Whether a volume of this kind is attached to the renewed boot (§5.5).
    pub const fn at_renewal(self, cache: CachePolicy, profile: Profile) -> VolumeAttachment {
        let behavior = self.renewal_behavior(cache);
        match behavior {
            RenewalBehavior::ExternalBrokerOwnership => match profile {
                Profile::Strict => VolumeAttachment::NotAttached {
                    refusal: VolumeRefusal::CredentialCopyInStrictProfile,
                },
                Profile::Transport => VolumeAttachment::Attached { behavior },
            },
            RenewalBehavior::Quarantine => VolumeAttachment::NotAttached {
                refusal: VolumeRefusal::Quarantined,
            },
            RenewalBehavior::RebuildFromManifest => VolumeAttachment::NotAttached {
                refusal: VolumeRefusal::Rebuilt,
            },
            RenewalBehavior::RetainWithValidation
            | RenewalBehavior::RetainAsUntrusted
            | RenewalBehavior::PreserveWithWeakerClaims => VolumeAttachment::Attached { behavior },
        }
    }

    /// Whether cleanup must preserve the volume: user source data is never deleted
    /// (§6.4; VM-W24 "user data preserved").
    pub const fn is_user_source(self) -> bool {
        matches!(self, Self::SourceWorkspace)
    }
}

/// How the service shuts down for a renewal (§5.5 "application-consistent shutdown").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "shutdown", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ShutdownMode {
    /// The application quiesces and flushes before the stop.
    ApplicationConsistent { quiesce_within: Duration },
}

crate::foundation::strict_serde::strict_tag!(ShutdownMode, "shutdown");

/// How a failed renewal is rolled back (§5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rollback", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RollbackPlan {
    /// Boot the previous generation's retained volumes again, cold.
    ColdBootPreviousVolumes,
}

crate::foundation::strict_serde::strict_tag!(RollbackPlan, "rollback");

/// What a service renewal must define (§5.5: "shutdown, recovery, downtime, lease
/// revocation and rollback"). Every part is required by the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRenewalPlan {
    pub shutdown: ShutdownMode,
    /// Whether the application's own recovery runs in the next boot before it serves.
    pub application_recovery_before_serving: bool,
    pub downtime_bound: Duration,
    /// The old authority is revoked, never carried over.
    pub revoke_old_lease: bool,
    pub rollback: RollbackPlan,
    pub cache: CachePolicy,
}

/// Why a renewal plan is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RenewalPlanProblem {
    ZeroDowntimeBound,
    /// A renewal that keeps the old lease is not a renewal (§5.5; §6.2).
    KeepsOldLease,
    /// A renewal that skips application recovery proves nothing about the state (§5.5
    /// "keeping bytes identical after a restart is not enough").
    SkipsApplicationRecovery,
}

crate::foundation::strict_serde::strict_tag!(RenewalPlanProblem, "problem");

impl fmt::Display for RenewalPlanProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroDowntimeBound => "a renewal must bound its downtime",
            Self::KeepsOldLease => "a renewal revokes the old lease; it cannot keep it",
            Self::SkipsApplicationRecovery => {
                "a renewal runs application recovery before serving again"
            }
        })
    }
}

impl std::error::Error for RenewalPlanProblem {}

impl ServiceRenewalPlan {
    pub fn check(&self) -> Result<(), RenewalPlanProblem> {
        if self.downtime_bound.is_zero() {
            return Err(RenewalPlanProblem::ZeroDowntimeBound);
        }
        if !self.revoke_old_lease {
            return Err(RenewalPlanProblem::KeepsOldLease);
        }
        if !self.application_recovery_before_serving {
            return Err(RenewalPlanProblem::SkipsApplicationRecovery);
        }
        Ok(())
    }

    /// The volumes, by identity, that ride into the renewed boot.
    pub fn retained(&self, volumes: &[(Digest, VolumeKind)], profile: Profile) -> BTreeSet<Digest> {
        volumes
            .iter()
            .filter(|(_, kind)| {
                matches!(
                    kind.at_renewal(self.cache, profile),
                    VolumeAttachment::Attached { .. }
                )
            })
            .map(|(volume, _)| *volume)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::coordination::{SnapshotContent, SnapshotId, VmInstanceId};
    use crate::foundation::ids::digest;

    fn named(name: &str) -> Digest {
        digest("yougori/test/pool/v1", &[name.as_bytes()])
    }

    fn manifest(origin: SnapshotOrigin) -> SnapshotManifest {
        SnapshotManifest {
            snapshot: SnapshotId::new(named("golden")),
            origin,
            image_profile: named("image"),
            contents: BTreeSet::new(),
            source_vm: VmInstanceId::new(named("builder")),
            guest_identity: named("guest"),
        }
    }

    fn clean() -> SnapshotProvenance {
        SnapshotProvenance {
            before_tenant_inputs: true,
            before_credentials: true,
            before_external_connections: true,
        }
    }

    #[test]
    fn only_golden_snapshots_taken_before_tenant_state_are_pool_eligible() {
        assert!(GoldenSnapshot::certify(
            manifest(SnapshotOrigin::PreTenantGolden),
            clean(),
            named("image")
        )
        .is_ok());
        assert_eq!(
            GoldenSnapshot::certify(
                manifest(SnapshotOrigin::TenantWorkload),
                clean(),
                named("image")
            ),
            Err(PoolRefusal::NotGolden {
                origin: SnapshotOrigin::TenantWorkload
            })
        );
        for (provenance, refusal) in [
            (
                SnapshotProvenance {
                    before_tenant_inputs: false,
                    ..clean()
                },
                PoolRefusal::TakenAfterTenantInputs,
            ),
            (
                SnapshotProvenance {
                    before_credentials: false,
                    ..clean()
                },
                PoolRefusal::TakenAfterCredentials,
            ),
            (
                SnapshotProvenance {
                    before_external_connections: false,
                    ..clean()
                },
                PoolRefusal::TakenAfterExternalConnections,
            ),
        ] {
            assert_eq!(
                GoldenSnapshot::certify(
                    manifest(SnapshotOrigin::PreTenantGolden),
                    provenance,
                    named("image")
                ),
                Err(refusal)
            );
        }
        let mut dirty = manifest(SnapshotOrigin::PreTenantGolden);
        dirty.contents.insert(SnapshotContent::InMemoryCredentials);
        assert!(matches!(
            GoldenSnapshot::certify(dirty, clean(), named("image")),
            Err(PoolRefusal::Defects { .. })
        ));
        assert!(matches!(
            GoldenSnapshot::certify(
                manifest(SnapshotOrigin::PreTenantGolden),
                clean(),
                named("other-image")
            ),
            Err(PoolRefusal::Defects { .. })
        ));
    }

    #[test]
    fn a_checkout_cold_boots_when_the_backend_cannot_restore_or_reset() {
        let able = BackendCapabilities {
            snapshot_restore: true,
            state_reset: StateReset::Supported,
        };
        assert_eq!(
            decide_checkout(&able, true, true),
            CheckoutDecision::Restore
        );
        assert_eq!(
            decide_checkout(&able, true, false),
            CheckoutDecision::ColdBoot {
                fallback: ColdFallback::NewExecution
            }
        );
        assert_eq!(
            decide_checkout(&able, false, true),
            CheckoutDecision::ColdBoot {
                fallback: ColdFallback::PoolDepleted
            }
        );
        let no_restore = BackendCapabilities {
            snapshot_restore: false,
            state_reset: StateReset::Supported,
        };
        assert_eq!(
            decide_checkout(&no_restore, true, true),
            CheckoutDecision::ColdBoot {
                fallback: ColdFallback::RestoreUnsupported
            }
        );
        let no_reset = BackendCapabilities {
            snapshot_restore: true,
            state_reset: StateReset::Unsupported {
                detail: "no entropy reseed".to_owned(),
            },
        };
        assert_eq!(
            decide_checkout(&no_reset, true, true),
            CheckoutDecision::ColdBoot {
                fallback: ColdFallback::StateResetUnsupported {
                    detail: "no entropy reseed".to_owned()
                }
            }
        );
    }

    #[test]
    fn the_pool_depletes_and_replenishes_within_its_capacity() {
        let mut pool = WarmPool::new(2);
        assert_eq!(pool.take().unwrap_err(), PoolRefusal::Depleted);
        pool.set_golden(
            GoldenSnapshot::certify(
                manifest(SnapshotOrigin::PreTenantGolden),
                clean(),
                named("image"),
            )
            .unwrap(),
        );
        assert_eq!(pool.replenish(5), 2, "never above capacity");
        assert!(pool.take().is_ok());
        assert!(pool.take().is_ok());
        assert_eq!(pool.take().unwrap_err(), PoolRefusal::Depleted);
        assert_eq!(pool.replenish(1), 1);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn volume_kinds_decide_what_a_renewal_keeps() {
        use VolumeKind as V;
        let strict = Profile::Strict;
        assert_eq!(
            V::PureApplicationData.at_renewal(CachePolicy::RebuildFromManifest, strict),
            VolumeAttachment::Attached {
                behavior: RenewalBehavior::RetainWithValidation
            }
        );
        assert_eq!(
            V::SourceWorkspace.at_renewal(CachePolicy::RebuildFromManifest, strict),
            VolumeAttachment::Attached {
                behavior: RenewalBehavior::RetainAsUntrusted
            }
        );
        assert_eq!(
            V::ExecutableEnvironmentCache.at_renewal(CachePolicy::RebuildFromManifest, strict),
            VolumeAttachment::NotAttached {
                refusal: VolumeRefusal::Rebuilt
            }
        );
        assert_eq!(
            V::ExecutableEnvironmentCache.at_renewal(CachePolicy::PreserveExplicitly, strict),
            VolumeAttachment::Attached {
                behavior: RenewalBehavior::PreserveWithWeakerClaims
            }
        );
        assert_eq!(
            V::CredentialState.at_renewal(CachePolicy::RebuildFromManifest, strict),
            VolumeAttachment::NotAttached {
                refusal: VolumeRefusal::CredentialCopyInStrictProfile
            }
        );
        assert_eq!(
            V::CredentialState.at_renewal(CachePolicy::RebuildFromManifest, Profile::Transport),
            VolumeAttachment::Attached {
                behavior: RenewalBehavior::ExternalBrokerOwnership
            }
        );
        assert_eq!(
            V::UnreviewedOutput.at_renewal(CachePolicy::RebuildFromManifest, strict),
            VolumeAttachment::NotAttached {
                refusal: VolumeRefusal::Quarantined
            }
        );
        assert!(V::SourceWorkspace.is_user_source());
        assert!(!V::UnreviewedOutput.is_user_source());
    }

    #[test]
    fn a_renewal_plan_defines_every_part_and_keeps_only_retained_volumes() {
        let plan = ServiceRenewalPlan {
            shutdown: ShutdownMode::ApplicationConsistent {
                quiesce_within: Duration::from_secs(30),
            },
            application_recovery_before_serving: true,
            downtime_bound: Duration::from_secs(120),
            revoke_old_lease: true,
            rollback: RollbackPlan::ColdBootPreviousVolumes,
            cache: CachePolicy::RebuildFromManifest,
        };
        plan.check().unwrap();
        assert_eq!(
            ServiceRenewalPlan {
                downtime_bound: Duration::ZERO,
                ..plan
            }
            .check(),
            Err(RenewalPlanProblem::ZeroDowntimeBound)
        );
        assert_eq!(
            ServiceRenewalPlan {
                revoke_old_lease: false,
                ..plan
            }
            .check(),
            Err(RenewalPlanProblem::KeepsOldLease)
        );
        assert_eq!(
            ServiceRenewalPlan {
                application_recovery_before_serving: false,
                ..plan
            }
            .check(),
            Err(RenewalPlanProblem::SkipsApplicationRecovery)
        );
        let volumes = [
            (named("data"), VolumeKind::PureApplicationData),
            (named("src"), VolumeKind::SourceWorkspace),
            (named("cache"), VolumeKind::ExecutableEnvironmentCache),
            (named("creds"), VolumeKind::CredentialState),
            (named("out"), VolumeKind::UnreviewedOutput),
        ];
        assert_eq!(
            plan.retained(&volumes, Profile::Strict),
            BTreeSet::from([named("data"), named("src")])
        );
        assert!(serde_json::from_value::<ServiceRenewalPlan>(serde_json::json!({
            "shutdown": {"shutdown": "application_consistent", "quiesce_within": {"secs": 1, "nanos": 0}},
            "application_recovery_before_serving": true,
            "downtime_bound": {"secs": 1, "nanos": 0},
            "revoke_old_lease": true,
            "rollback": {"rollback": "cold_boot_previous_volumes"}
        }))
        .is_err(), "a plan without a cache policy is incomplete");
    }
}
