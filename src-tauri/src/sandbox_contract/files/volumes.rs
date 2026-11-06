//! Persistent volume classes and their renewal behaviour (VM part §5.5 lines 2091–2105;
//! VM-P17; VM-W24).
//!
//! A fresh root does not remove implants stored in a mounted workspace, virtual
//! environment, plugin database, loader configuration, migration script or shell
//! initialization file (line 2093). Each persisted volume is therefore classified, and its
//! class decides what renewal does with it, per the table of lines 2097–2103. The plan's
//! summary never says that mounted state is clean, however fresh the root and however
//! identical the bytes (line 2105): at best nothing was retained. Guest root changes never
//! become the next trusted base, and every persisted executable input is listed (VM-P17).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::Digest;

/// The five volume classes of the §5.5 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeClass {
    PureApplicationData,
    SourceWorkspace,
    ExecutableEnvironmentCache,
    CredentialState,
    UnreviewedOutput,
}

impl VolumeClass {
    pub const ALL: [Self; 5] = [
        Self::PureApplicationData,
        Self::SourceWorkspace,
        Self::ExecutableEnvironmentCache,
        Self::CredentialState,
        Self::UnreviewedOutput,
    ];

    /// The renewal behaviours the §5.5 table allows for the class.
    pub const fn renewal_behaviors(self) -> &'static [RenewalBehavior] {
        match self {
            Self::PureApplicationData => &[RenewalBehavior::RetainWithValidationAndBackups],
            Self::SourceWorkspace => &[RenewalBehavior::RetainAsUntrusted],
            Self::ExecutableEnvironmentCache => &[
                RenewalBehavior::RebuildFromPinnedManifest,
                RenewalBehavior::PreserveWithWeakerClaim,
            ],
            Self::CredentialState => &[RenewalBehavior::ExternalBrokerOwnership],
            Self::UnreviewedOutput => &[RenewalBehavior::QuarantineUntilPromotion],
        }
    }
}

/// The renewal behaviours of the §5.5 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalBehavior {
    /// Retain with application-level validation and backups.
    RetainWithValidationAndBackups,
    /// Retain as untrusted code and data; execute only inside the next sandbox.
    RetainAsUntrusted,
    /// Rebuild from a pinned manifest.
    RebuildFromPinnedManifest,
    /// Explicitly preserve, with weaker persistence claims.
    PreserveWithWeakerClaim,
    /// Owned by the external broker; no copied long-lived provider credentials in the
    /// strict profile.
    ExternalBrokerOwnership,
    /// Quarantined until promotion.
    QuarantineUntilPromotion,
}

strict_tagged_enum! {
    /// Who holds a credential volume's secrets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CredentialHolder (tag = "holder", wire = CredentialHolderWire, wire_name = "CredentialHolderWire") {
        /// The external broker, by its identity; nothing long-lived enters the volume.
        ExternalBroker { broker: Digest },
        /// Long-lived provider credentials copied into the volume.
        CopiedLongLived,
    }
}

strict_tagged_enum! {
    /// One volume's class and what its renewal needs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum VolumeRenewal (tag = "class", wire = VolumeRenewalWire, wire_name = "VolumeRenewalWire") {
        /// Needs an application-level validation and a backup.
        PureApplicationData { validation: Option<Digest>, backup: Option<Digest> },
        SourceWorkspace,
        ExecutableEnvironmentRebuild { pinned_manifest: Digest },
        /// Kept as it is; allowed only with the weaker claim acknowledged.
        ExecutableEnvironmentPreserve { weaker_claim_acknowledged: bool },
        CredentialState { holder: CredentialHolder },
        UnreviewedOutput,
    }
}

impl VolumeRenewal {
    pub const fn class(self) -> VolumeClass {
        match self {
            Self::PureApplicationData { .. } => VolumeClass::PureApplicationData,
            Self::SourceWorkspace => VolumeClass::SourceWorkspace,
            Self::ExecutableEnvironmentRebuild { .. }
            | Self::ExecutableEnvironmentPreserve { .. } => VolumeClass::ExecutableEnvironmentCache,
            Self::CredentialState { .. } => VolumeClass::CredentialState,
            Self::UnreviewedOutput => VolumeClass::UnreviewedOutput,
        }
    }
}

/// The persistence profile; the strict one refuses copied long-lived credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceProfile {
    Strict,
    Compatible,
}

/// Where a volume goes at renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountDisposition {
    /// Mounted into the next sandbox as it is.
    RetainedIntoNextSandbox,
    /// Rebuilt, then mounted into the next sandbox.
    RebuiltIntoNextSandbox,
    /// Not mounted; the broker serves operations instead.
    NotMounted,
    /// Reachable only through promotion.
    QuarantineOnly,
}

/// What may be said about a volume's state after renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "trust", rename_all = "snake_case")]
pub enum StateTrust {
    /// The application validated it; not a claim that it holds no implant.
    ApplicationValidated,
    Untrusted,
    RebuiltFromPinnedManifest {
        manifest: Digest,
    },
    PreservedWithWeakerClaim,
    BrokerOwned,
    Quarantined,
    /// Compatible profile only: long-lived credentials sit in the volume.
    CopiedCredentialsExposed,
}

/// One volume's renewal (§5.5 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RenewalPlan {
    pub volume: Digest,
    pub class: VolumeClass,
    pub behavior: RenewalBehavior,
    pub mount: MountDisposition,
    pub trust: StateTrust,
    /// Whether the volume carries executable inputs into the next sandbox (VM-P17).
    pub persists_executable_inputs: bool,
    /// Whether the host may execute its content. Never: persisted content executes only
    /// inside the next sandbox (line 2100).
    pub host_may_execute: bool,
}

/// What renewal may claim about mounted state (line 2093). There is no "clean" claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "claim", rename_all = "snake_case")]
pub enum MountedStateClaim {
    /// Nothing is retained as it was: every volume is rebuilt, broker-owned or
    /// quarantined.
    NoRetainedState,
    /// These volumes keep their bytes; a fresh root does not make them clean.
    NotProvenClean { retained: Vec<Digest> },
}

/// A renewal: the base image, the volumes, and whether the guest root's changes were
/// asked to be kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewalRequest {
    /// The pinned trusted base image the fresh root comes from.
    pub base_image: Digest,
    /// Asking to carry the guest root's changes into the next base; always refused.
    pub keep_guest_root_changes: bool,
    pub volumes: Vec<(Digest, VolumeRenewal)>,
    /// Whether the retained bytes were verified identical after the restart. It changes
    /// no claim (line 2105).
    pub bytes_verified_identical: bool,
}

/// The renewal of every volume and what may be claimed afterwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RenewalSummary {
    /// Always the request's base image: guest root changes never become it (VM-P17).
    pub next_base: Digest,
    pub plans: Vec<RenewalPlan>,
    pub mounted_state: MountedStateClaim,
    /// Every volume that carries executable inputs forward, named honestly (VM-P17).
    pub persisted_executable_inputs: Vec<Digest>,
}

/// Why a renewal was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RenewalRefusal {
    /// Guest root modifications never change the next trusted base (VM-P17).
    GuestRootNeverBecomesBase,
    DuplicateVolume {
        volume: Digest,
    },
    MissingValidation {
        volume: Digest,
    },
    MissingBackup {
        volume: Digest,
    },
    WeakerClaimNotAcknowledged {
        volume: Digest,
    },
    /// No copied long-lived provider credentials in the strict profile (line 2102).
    CopiedCredentialsInStrictProfile {
        volume: Digest,
    },
}

impl fmt::Display for RenewalRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestRootNeverBecomesBase => {
                f.write_str("guest root changes never become the next trusted base")
            }
            Self::DuplicateVolume { volume } => write!(f, "volume {volume} is listed twice"),
            Self::MissingValidation { volume } => {
                write!(f, "application data {volume} needs a validation")
            }
            Self::MissingBackup { volume } => write!(f, "application data {volume} needs a backup"),
            Self::WeakerClaimNotAcknowledged { volume } => write!(
                f,
                "preserving environment {volume} needs the weaker claim acknowledged"
            ),
            Self::CopiedCredentialsInStrictProfile { volume } => write!(
                f,
                "credential volume {volume} holds copied long-lived credentials"
            ),
        }
    }
}

impl std::error::Error for RenewalRefusal {}

fn plan_volume(
    volume: Digest,
    renewal: VolumeRenewal,
    profile: PersistenceProfile,
) -> Result<RenewalPlan, RenewalRefusal> {
    let class = renewal.class();
    let (behavior, mount, trust, persists_executable_inputs) = match renewal {
        VolumeRenewal::PureApplicationData { validation, backup } => {
            if validation.is_none() {
                return Err(RenewalRefusal::MissingValidation { volume });
            }
            if backup.is_none() {
                return Err(RenewalRefusal::MissingBackup { volume });
            }
            (
                RenewalBehavior::RetainWithValidationAndBackups,
                MountDisposition::RetainedIntoNextSandbox,
                StateTrust::ApplicationValidated,
                false,
            )
        }
        VolumeRenewal::SourceWorkspace => (
            RenewalBehavior::RetainAsUntrusted,
            MountDisposition::RetainedIntoNextSandbox,
            StateTrust::Untrusted,
            true,
        ),
        VolumeRenewal::ExecutableEnvironmentRebuild { pinned_manifest } => (
            RenewalBehavior::RebuildFromPinnedManifest,
            MountDisposition::RebuiltIntoNextSandbox,
            StateTrust::RebuiltFromPinnedManifest {
                manifest: pinned_manifest,
            },
            true,
        ),
        VolumeRenewal::ExecutableEnvironmentPreserve {
            weaker_claim_acknowledged,
        } => {
            if !weaker_claim_acknowledged {
                return Err(RenewalRefusal::WeakerClaimNotAcknowledged { volume });
            }
            (
                RenewalBehavior::PreserveWithWeakerClaim,
                MountDisposition::RetainedIntoNextSandbox,
                StateTrust::PreservedWithWeakerClaim,
                true,
            )
        }
        VolumeRenewal::CredentialState { holder } => match (holder, profile) {
            (CredentialHolder::ExternalBroker { .. }, _) => (
                RenewalBehavior::ExternalBrokerOwnership,
                MountDisposition::NotMounted,
                StateTrust::BrokerOwned,
                false,
            ),
            (CredentialHolder::CopiedLongLived, PersistenceProfile::Strict) => {
                return Err(RenewalRefusal::CopiedCredentialsInStrictProfile { volume })
            }
            (CredentialHolder::CopiedLongLived, PersistenceProfile::Compatible) => (
                RenewalBehavior::ExternalBrokerOwnership,
                MountDisposition::RetainedIntoNextSandbox,
                StateTrust::CopiedCredentialsExposed,
                false,
            ),
        },
        VolumeRenewal::UnreviewedOutput => (
            RenewalBehavior::QuarantineUntilPromotion,
            MountDisposition::QuarantineOnly,
            StateTrust::Quarantined,
            false,
        ),
    };
    Ok(RenewalPlan {
        volume,
        class,
        behavior,
        mount,
        trust,
        persists_executable_inputs,
        host_may_execute: false,
    })
}

/// Plans one renewal (§5.5; VM-P17).
pub fn plan_renewal(
    request: &RenewalRequest,
    profile: PersistenceProfile,
) -> Result<RenewalSummary, RenewalRefusal> {
    if request.keep_guest_root_changes {
        return Err(RenewalRefusal::GuestRootNeverBecomesBase);
    }
    let mut seen = BTreeSet::new();
    let mut plans = Vec::with_capacity(request.volumes.len());
    for (volume, renewal) in &request.volumes {
        if !seen.insert(*volume) {
            return Err(RenewalRefusal::DuplicateVolume { volume: *volume });
        }
        plans.push(plan_volume(*volume, *renewal, profile)?);
    }
    let retained: Vec<Digest> = plans
        .iter()
        .filter(|plan| plan.mount == MountDisposition::RetainedIntoNextSandbox)
        .map(|plan| plan.volume)
        .collect();
    let mounted_state = if retained.is_empty() {
        MountedStateClaim::NoRetainedState
    } else {
        MountedStateClaim::NotProvenClean { retained }
    };
    let persisted_executable_inputs = plans
        .iter()
        .filter(|plan| plan.persists_executable_inputs)
        .map(|plan| plan.volume)
        .collect();
    Ok(RenewalSummary {
        next_base: request.base_image,
        plans,
        mounted_state,
        persisted_executable_inputs,
    })
}

/// What a service renewal must define (line 2105): application-consistent shutdown,
/// recovery, downtime, lease revocation and rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRenewalContract {
    pub consistent_shutdown: Option<Digest>,
    pub recovery: Option<Digest>,
    pub max_downtime_seconds: Option<u64>,
    /// Whether the old generation's leases are revoked at renewal.
    pub revokes_leases: bool,
    pub rollback: Option<Digest>,
}

/// What a service renewal contract leaves undefined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRenewalProblem {
    NoConsistentShutdown,
    NoRecovery,
    NoDowntimeBound,
    LeasesNotRevoked,
    NoRollback,
}

impl ServiceRenewalContract {
    /// Refuses the first element the contract leaves undefined.
    pub fn check(&self) -> Result<(), ServiceRenewalProblem> {
        if self.consistent_shutdown.is_none() {
            return Err(ServiceRenewalProblem::NoConsistentShutdown);
        }
        if self.recovery.is_none() {
            return Err(ServiceRenewalProblem::NoRecovery);
        }
        if self.max_downtime_seconds.is_none() {
            return Err(ServiceRenewalProblem::NoDowntimeBound);
        }
        if !self.revokes_leases {
            return Err(ServiceRenewalProblem::LeasesNotRevoked);
        }
        if self.rollback.is_none() {
            return Err(ServiceRenewalProblem::NoRollback);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn id(name: &str) -> Digest {
        digest("yougori/test/volume/v1", &[name.as_bytes()])
    }

    fn request(volumes: Vec<(Digest, VolumeRenewal)>) -> RenewalRequest {
        RenewalRequest {
            base_image: id("base-image"),
            keep_guest_root_changes: false,
            volumes,
            bytes_verified_identical: false,
        }
    }

    fn one(
        renewal: VolumeRenewal,
        profile: PersistenceProfile,
    ) -> Result<RenewalPlan, RenewalRefusal> {
        plan_renewal(&request(vec![(id("v"), renewal)]), profile).map(|summary| summary.plans[0])
    }

    #[test]
    fn the_table_gives_each_class_its_renewal_behaviour() {
        use RenewalBehavior as B;
        assert_eq!(
            VolumeClass::PureApplicationData.renewal_behaviors(),
            &[B::RetainWithValidationAndBackups]
        );
        assert_eq!(
            VolumeClass::SourceWorkspace.renewal_behaviors(),
            &[B::RetainAsUntrusted]
        );
        assert_eq!(
            VolumeClass::ExecutableEnvironmentCache.renewal_behaviors(),
            &[B::RebuildFromPinnedManifest, B::PreserveWithWeakerClaim]
        );
        assert_eq!(
            VolumeClass::CredentialState.renewal_behaviors(),
            &[B::ExternalBrokerOwnership]
        );
        assert_eq!(
            VolumeClass::UnreviewedOutput.renewal_behaviors(),
            &[B::QuarantineUntilPromotion]
        );
        let renewals = [
            VolumeRenewal::PureApplicationData {
                validation: Some(id("check")),
                backup: Some(id("backup")),
            },
            VolumeRenewal::SourceWorkspace,
            VolumeRenewal::ExecutableEnvironmentRebuild {
                pinned_manifest: id("lock"),
            },
            VolumeRenewal::ExecutableEnvironmentPreserve {
                weaker_claim_acknowledged: true,
            },
            VolumeRenewal::CredentialState {
                holder: CredentialHolder::ExternalBroker {
                    broker: id("broker"),
                },
            },
            VolumeRenewal::UnreviewedOutput,
        ];
        for renewal in renewals {
            let plan = one(renewal, PersistenceProfile::Strict).unwrap();
            assert!(plan.class.renewal_behaviors().contains(&plan.behavior));
            assert!(!plan.host_may_execute);
        }
    }

    #[test]
    fn application_data_needs_validation_and_backups() {
        assert_eq!(
            one(
                VolumeRenewal::PureApplicationData {
                    validation: None,
                    backup: Some(id("backup"))
                },
                PersistenceProfile::Strict
            ),
            Err(RenewalRefusal::MissingValidation { volume: id("v") })
        );
        assert_eq!(
            one(
                VolumeRenewal::PureApplicationData {
                    validation: Some(id("check")),
                    backup: None
                },
                PersistenceProfile::Strict
            ),
            Err(RenewalRefusal::MissingBackup { volume: id("v") })
        );
    }

    #[test]
    fn a_workspace_is_retained_as_untrusted_and_never_run_on_the_host() {
        let plan = one(VolumeRenewal::SourceWorkspace, PersistenceProfile::Strict).unwrap();
        assert_eq!(plan.trust, StateTrust::Untrusted);
        assert_eq!(plan.mount, MountDisposition::RetainedIntoNextSandbox);
        assert!(plan.persists_executable_inputs);
        assert!(!plan.host_may_execute);
    }

    #[test]
    fn an_environment_is_rebuilt_or_kept_only_with_the_weaker_claim() {
        let rebuilt = one(
            VolumeRenewal::ExecutableEnvironmentRebuild {
                pinned_manifest: id("lock"),
            },
            PersistenceProfile::Strict,
        )
        .unwrap();
        assert_eq!(
            rebuilt.trust,
            StateTrust::RebuiltFromPinnedManifest {
                manifest: id("lock")
            }
        );
        assert_eq!(
            one(
                VolumeRenewal::ExecutableEnvironmentPreserve {
                    weaker_claim_acknowledged: false
                },
                PersistenceProfile::Strict
            ),
            Err(RenewalRefusal::WeakerClaimNotAcknowledged { volume: id("v") })
        );
        let kept = one(
            VolumeRenewal::ExecutableEnvironmentPreserve {
                weaker_claim_acknowledged: true,
            },
            PersistenceProfile::Strict,
        )
        .unwrap();
        assert_eq!(kept.trust, StateTrust::PreservedWithWeakerClaim);
        assert!(kept.persists_executable_inputs);
    }

    #[test]
    fn the_strict_profile_never_keeps_copied_long_lived_credentials() {
        let copied = VolumeRenewal::CredentialState {
            holder: CredentialHolder::CopiedLongLived,
        };
        assert_eq!(
            one(copied, PersistenceProfile::Strict),
            Err(RenewalRefusal::CopiedCredentialsInStrictProfile { volume: id("v") })
        );
        assert_eq!(
            one(copied, PersistenceProfile::Compatible).unwrap().trust,
            StateTrust::CopiedCredentialsExposed
        );
        let brokered = one(
            VolumeRenewal::CredentialState {
                holder: CredentialHolder::ExternalBroker {
                    broker: id("broker"),
                },
            },
            PersistenceProfile::Strict,
        )
        .unwrap();
        assert_eq!(brokered.mount, MountDisposition::NotMounted);
        assert_eq!(brokered.trust, StateTrust::BrokerOwned);
    }

    #[test]
    fn unreviewed_output_stays_quarantined_until_promotion() {
        let plan = one(VolumeRenewal::UnreviewedOutput, PersistenceProfile::Strict).unwrap();
        assert_eq!(plan.mount, MountDisposition::QuarantineOnly);
        assert_eq!(plan.trust, StateTrust::Quarantined);
    }

    #[test]
    fn a_fresh_root_never_makes_mounted_state_clean() {
        let mut renewal = request(vec![
            (id("workspace"), VolumeRenewal::SourceWorkspace),
            (
                id("venv"),
                VolumeRenewal::ExecutableEnvironmentPreserve {
                    weaker_claim_acknowledged: true,
                },
            ),
            (
                id("cache"),
                VolumeRenewal::ExecutableEnvironmentRebuild {
                    pinned_manifest: id("lock"),
                },
            ),
            (id("out"), VolumeRenewal::UnreviewedOutput),
        ]);
        renewal.bytes_verified_identical = true;
        let summary = plan_renewal(&renewal, PersistenceProfile::Strict).unwrap();
        assert_eq!(summary.next_base, id("base-image"));
        assert_eq!(
            summary.mounted_state,
            MountedStateClaim::NotProvenClean {
                retained: vec![id("workspace"), id("venv")]
            }
        );
        assert_eq!(
            summary.persisted_executable_inputs,
            vec![id("workspace"), id("venv"), id("cache")]
        );
        let nothing_kept = plan_renewal(
            &request(vec![(id("out"), VolumeRenewal::UnreviewedOutput)]),
            PersistenceProfile::Strict,
        )
        .unwrap();
        assert_eq!(
            nothing_kept.mounted_state,
            MountedStateClaim::NoRetainedState
        );
    }

    #[test]
    fn guest_root_changes_never_become_the_next_base() {
        let mut renewal = request(vec![]);
        renewal.keep_guest_root_changes = true;
        assert_eq!(
            plan_renewal(&renewal, PersistenceProfile::Compatible),
            Err(RenewalRefusal::GuestRootNeverBecomesBase)
        );
        assert_eq!(
            plan_renewal(
                &request(vec![
                    (id("v"), VolumeRenewal::SourceWorkspace),
                    (id("v"), VolumeRenewal::UnreviewedOutput)
                ]),
                PersistenceProfile::Strict
            ),
            Err(RenewalRefusal::DuplicateVolume { volume: id("v") })
        );
    }

    #[test]
    fn a_service_renewal_contract_defines_every_element() {
        let complete = ServiceRenewalContract {
            consistent_shutdown: Some(id("drain")),
            recovery: Some(id("replay")),
            max_downtime_seconds: Some(30),
            revokes_leases: true,
            rollback: Some(id("previous")),
        };
        assert_eq!(complete.check(), Ok(()));
        let cases = [
            (
                ServiceRenewalContract {
                    consistent_shutdown: None,
                    ..complete
                },
                ServiceRenewalProblem::NoConsistentShutdown,
            ),
            (
                ServiceRenewalContract {
                    recovery: None,
                    ..complete
                },
                ServiceRenewalProblem::NoRecovery,
            ),
            (
                ServiceRenewalContract {
                    max_downtime_seconds: None,
                    ..complete
                },
                ServiceRenewalProblem::NoDowntimeBound,
            ),
            (
                ServiceRenewalContract {
                    revokes_leases: false,
                    ..complete
                },
                ServiceRenewalProblem::LeasesNotRevoked,
            ),
            (
                ServiceRenewalContract {
                    rollback: None,
                    ..complete
                },
                ServiceRenewalProblem::NoRollback,
            ),
        ];
        for (contract, problem) in cases {
            assert_eq!(contract.check(), Err(problem));
        }
    }

    #[test]
    fn renewal_requests_refuse_unknown_fields() {
        let text = serde_json::to_string(&VolumeRenewal::UnreviewedOutput).unwrap();
        assert_eq!(text, "{\"class\":\"unreviewed_output\"}");
        assert!(
            serde_json::from_str::<VolumeRenewal>("{\"class\":\"unreviewed_output\",\"x\":1}")
                .is_err()
        );
        assert!(serde_json::from_str::<CredentialHolder>(
            "{\"holder\":\"copied_long_lived\",\"x\":1}"
        )
        .is_err());
    }
}
