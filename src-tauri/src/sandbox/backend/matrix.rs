//! The evidence matrix of §7.1 (lines 2356–2365): one row per supported combination of
//! host OS/build, architecture, backend and version, guest image, actual accelerator,
//! confinement profile, device set, network enforcement, lifecycle behaviour and test
//! result. Until a combination is validated it is experimental or unavailable, never
//! supported; and a passed test of another combination proves nothing for this one
//! (line 2365: an ordinary QEMU boot does not prove a restricted-token launch, a custom
//! device combination or a snapshot path works). A fake backend validates nothing (S2
//! line 206).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::accelerator::Accelerator;
use super::contract::{BackendIdentity, FactName};
use super::facets::{ConfinementControl, DeviceExposure, NetworkAuthority};
use super::observation::HostBuild;
use super::record::LaunchRecord;
use crate::foundation::ids::{Digest, DigestBuilder};

/// The digest domain of an evidence row's combination identity.
pub const EVIDENCE_ROW_DOMAIN: &str = "yougori/sandbox/evidence-row/v1";

/// A lifecycle behaviour a row's tests exercised (§7.1 "lifecycle behavior"; VM-W19
/// acceptance, line 2616: stop verified, no inherited sensitive handles).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleCheck {
    StopVerified,
    NoInheritedSensitiveHandles,
    CleanupBounded,
    SnapshotVerified,
    RestoreVerified,
}

impl LifecycleCheck {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::StopVerified => "stop_verified",
            Self::NoInheritedSensitiveHandles => "no_inherited_sensitive_handles",
            Self::CleanupBounded => "cleanup_bounded",
            Self::SnapshotVerified => "snapshot_verified",
            Self::RestoreVerified => "restore_verified",
        }
    }
}

/// The combination an evidence row is about (§7.1 lines 2360–2362).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRowKey {
    pub host: HostBuild,
    pub backend: BackendIdentity,
    pub guest_image: Digest,
    pub accelerator: Accelerator,
    /// The confinement profile: the controls the hypervisor process runs under.
    pub confinement: BTreeSet<ConfinementControl>,
    pub devices: DeviceExposure,
    /// The network enforcement: the channels the host permits.
    pub network: NetworkAuthority,
    pub lifecycle: BTreeSet<LifecycleCheck>,
}

impl EvidenceRowKey {
    /// The identity of this exact combination.
    pub fn identity(&self) -> Digest {
        let builder = DigestBuilder::new(EVIDENCE_ROW_DOMAIN)
            .str(self.host.os.tag())
            .str(self.host.build.as_str())
            .str(self.host.architecture.tag())
            .str(self.backend.kind.tag())
            .str(self.backend.version.as_str())
            .digest(&self.backend.artifact)
            .str(self.backend.hypervisor.tag())
            .digest(&self.guest_image);
        let builder = self.accelerator.bind(builder);
        let builder = self.confinement.iter().fold(
            builder.u64(self.confinement.len() as u64),
            |builder, control| builder.str(control.tag()),
        );
        let builder = self.devices.gpus.iter().fold(
            builder
                .u64(u64::from(self.devices.display))
                .u64(self.devices.gpus.len() as u64),
            |builder, gpu| builder.digest(&gpu.machine).digest(&gpu.device),
        );
        let builder = self.network.channels.iter().fold(
            builder.u64(self.network.channels.len() as u64),
            |builder, channel| builder.str(channel.tag()),
        );
        self.lifecycle
            .iter()
            .fold(
                builder.u64(self.lifecycle.len() as u64),
                |builder, check| builder.str(check.tag()),
            )
            .finish()
    }

    /// The combination a launch record ran, with the lifecycle behaviour the caller
    /// exercised on it.
    pub fn of_record(
        record: &LaunchRecord,
        lifecycle: BTreeSet<LifecycleCheck>,
    ) -> Result<Self, RowRefusal> {
        let observed = record.host_observed();
        let host = observed
            .host
            .value()
            .ok_or(RowRefusal::FactUnavailable {
                fact: FactName::Host,
            })?
            .clone();
        let confinement = observed
            .confinement
            .value()
            .ok_or(RowRefusal::FactUnavailable {
                fact: FactName::Confinement,
            })?
            .clone();
        let network = observed
            .network
            .value()
            .ok_or(RowRefusal::FactUnavailable {
                fact: FactName::Network,
            })?
            .clone();
        Ok(Self {
            host,
            backend: record.backend().clone(),
            guest_image: record.pinned().guest_image,
            accelerator: *record.accelerator().value(),
            confinement,
            devices: record.device_profile().devices.clone(),
            network,
            lifecycle,
        })
    }
}

/// Why a row key could not be derived from a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RowRefusal {
    FactUnavailable { fact: FactName },
}

impl fmt::Display for RowRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FactUnavailable { fact } => {
                write!(f, "the record has no host observation of the {fact}")
            }
        }
    }
}

impl std::error::Error for RowRefusal {}

/// The test result of a row (§7.1 "test result"; CORE-08 reports).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TestResult {
    NotRun,
    Failed {
        /// The CORE-08 report.
        report: Digest,
    },
    Passed {
        /// The CORE-08 report.
        report: Digest,
        /// The identity of the exact combination the test ran; a pass for any other
        /// combination validates nothing here.
        combination: Digest,
    },
}

/// Why a row is not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotSupported {
    /// A fake backend certifies nothing (S2 line 206).
    FakeBackend,
    NotTested,
    TestFailed {
        report: Digest,
    },
    /// The passed test ran another combination (§7.1 line 2365).
    TestOfOtherCombination {
        tested: Digest,
        this: Digest,
    },
}

impl fmt::Display for NotSupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FakeBackend => f.write_str("a fake backend validates no combination"),
            Self::NotTested => f.write_str("the combination was not tested"),
            Self::TestFailed { .. } => f.write_str("the combination's test failed"),
            Self::TestOfOtherCombination { .. } => {
                f.write_str("the passed test ran another combination")
            }
        }
    }
}

/// The support status of a combination (§7.1 line 2364).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    /// Validated: a passed test of exactly this combination on a real backend.
    Supported,
    /// A row exists but is not validated.
    Experimental,
    /// No row.
    Unavailable,
}

impl fmt::Display for SupportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Supported => "supported",
            Self::Experimental => "experimental",
            Self::Unavailable => "unavailable",
        })
    }
}

/// One row of the evidence matrix. Its status is computed, never written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRow {
    pub key: EvidenceRowKey,
    pub result: TestResult,
}

impl EvidenceRow {
    /// Why the row is not supported, or `None` when it is.
    pub fn not_supported(&self) -> Option<NotSupported> {
        if self.key.backend.kind.is_fake() {
            return Some(NotSupported::FakeBackend);
        }
        match self.result {
            TestResult::NotRun => Some(NotSupported::NotTested),
            TestResult::Failed { report } => Some(NotSupported::TestFailed { report }),
            TestResult::Passed { combination, .. } => {
                let this = self.key.identity();
                (combination != this).then_some(NotSupported::TestOfOtherCombination {
                    tested: combination,
                    this,
                })
            }
        }
    }

    pub fn status(&self) -> SupportStatus {
        if self.not_supported().is_none() {
            SupportStatus::Supported
        } else {
            SupportStatus::Experimental
        }
    }
}

/// Why a row was not added to a release profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    DuplicateRow { combination: Digest },
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRow { combination } => {
                write!(
                    f,
                    "the profile already has a row for combination {combination}"
                )
            }
        }
    }
}

impl std::error::Error for ProfileError {}

/// The evidence rows of one release, matched by combination (§7.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReleaseProfile {
    rows: BTreeMap<Digest, EvidenceRow>,
}

impl ReleaseProfile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a row; one row per combination.
    pub fn add(&mut self, row: EvidenceRow) -> Result<(), ProfileError> {
        let combination = row.key.identity();
        if self.rows.contains_key(&combination) {
            return Err(ProfileError::DuplicateRow { combination });
        }
        self.rows.insert(combination, row);
        Ok(())
    }

    pub fn row(&self, key: &EvidenceRowKey) -> Option<&EvidenceRow> {
        self.rows.get(&key.identity())
    }

    /// The status of a combination: unavailable without a row, and never supported
    /// without validation.
    pub fn status_of(&self, key: &EvidenceRowKey) -> SupportStatus {
        self.row(key)
            .map_or(SupportStatus::Unavailable, EvidenceRow::status)
    }

    /// The status of the combination a launch record ran.
    pub fn status_of_record(
        &self,
        record: &LaunchRecord,
        lifecycle: BTreeSet<LifecycleCheck>,
    ) -> Result<SupportStatus, RowRefusal> {
        Ok(self.status_of(&EvidenceRowKey::of_record(record, lifecycle)?))
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::contract::BackendKind;
    use super::super::facets::{ConfinementControl, NetworkChannel};
    use super::super::observation::{Architecture, BuildId};
    use super::*;
    use crate::foundation::evidence::{HypervisorKind, OsKind};
    use crate::foundation::ids::digest;

    fn artifact(name: &[u8]) -> Digest {
        digest("yougori/test/backend/v1", &[name])
    }

    fn key(kind: BackendKind) -> EvidenceRowKey {
        EvidenceRowKey {
            host: HostBuild {
                os: OsKind::Linux,
                build: BuildId::new("6.6.0").unwrap(),
                architecture: Architecture::X86_64,
            },
            backend: BackendIdentity::new(kind, "1.10.1", artifact(b"fc"), HypervisorKind::Kvm)
                .unwrap(),
            guest_image: digest("yougori/test/image/v1", &[b"alpine"]),
            accelerator: Accelerator::Hardware {
                hypervisor: HypervisorKind::Kvm,
            },
            confinement: ConfinementControl::all(),
            devices: DeviceExposure::cpu_only(),
            network: NetworkAuthority::offline(),
            lifecycle: [LifecycleCheck::StopVerified].into_iter().collect(),
        }
    }

    fn report() -> Digest {
        digest("yougori/test/report/v1", &[b"r1"])
    }

    #[test]
    fn a_row_is_supported_only_by_a_passed_test_of_exactly_its_combination() {
        let key = key(BackendKind::Firecracker);
        let not_run = EvidenceRow {
            key: key.clone(),
            result: TestResult::NotRun,
        };
        assert_eq!(not_run.not_supported(), Some(NotSupported::NotTested));
        assert_eq!(not_run.status(), SupportStatus::Experimental);

        let failed = EvidenceRow {
            key: key.clone(),
            result: TestResult::Failed { report: report() },
        };
        assert_eq!(
            failed.not_supported(),
            Some(NotSupported::TestFailed { report: report() })
        );

        // An ordinary boot without the restricted process identity passed; that proves
        // nothing for the confined combination (§7.1 line 2365).
        let mut ordinary = key.clone();
        ordinary
            .confinement
            .remove(&ConfinementControl::ProcessIdentity);
        let other = EvidenceRow {
            key: key.clone(),
            result: TestResult::Passed {
                report: report(),
                combination: ordinary.identity(),
            },
        };
        assert_eq!(
            other.not_supported(),
            Some(NotSupported::TestOfOtherCombination {
                tested: ordinary.identity(),
                this: key.identity(),
            })
        );
        assert_eq!(other.status(), SupportStatus::Experimental);

        let validated = EvidenceRow {
            key: key.clone(),
            result: TestResult::Passed {
                report: report(),
                combination: key.identity(),
            },
        };
        assert_eq!(validated.not_supported(), None);
        assert_eq!(validated.status(), SupportStatus::Supported);
        assert_eq!(SupportStatus::Supported.to_string(), "supported");

        // The status is computed, never a field.
        let json = serde_json::to_value(&validated).unwrap();
        assert!(json.get("status").is_none());
        let mut claimed = json.clone();
        claimed["status"] = "supported".into();
        assert!(serde_json::from_value::<EvidenceRow>(claimed).is_err());
        assert_eq!(
            serde_json::from_value::<EvidenceRow>(json).unwrap(),
            validated
        );
        assert!(serde_json::from_value::<TestResult>(serde_json::json!({
            "passed": {"report": report(), "combination": key.identity(), "supported": true}
        }))
        .is_err());
    }

    #[test]
    fn a_fake_backend_validates_nothing() {
        let key = key(BackendKind::Fake);
        let row = EvidenceRow {
            key: key.clone(),
            result: TestResult::Passed {
                report: report(),
                combination: key.identity(),
            },
        };
        assert_eq!(row.not_supported(), Some(NotSupported::FakeBackend));
        assert_eq!(row.status(), SupportStatus::Experimental);
        assert!(NotSupported::FakeBackend
            .to_string()
            .contains("validates no combination"));
    }

    #[test]
    fn every_field_of_the_combination_changes_its_identity() {
        let base = key(BackendKind::Firecracker);
        let mut identities = std::collections::BTreeSet::from([base.identity()]);
        let variants: Vec<(&str, EvidenceRowKey)> = vec![
            ("build", {
                let mut key = base.clone();
                key.host.build = BuildId::new("6.6.1").unwrap();
                key
            }),
            ("architecture", {
                let mut key = base.clone();
                key.host.architecture = Architecture::Aarch64;
                key
            }),
            ("os", {
                let mut key = base.clone();
                key.host.os = OsKind::Windows;
                key
            }),
            ("backend version", {
                let mut key = base.clone();
                key.backend.version =
                    crate::foundation::evidence::BackendVersion::new("1.10.2").unwrap();
                key
            }),
            ("backend artifact", {
                let mut key = base.clone();
                key.backend.artifact = artifact(b"other");
                key
            }),
            ("backend kind", key(BackendKind::Qemu)),
            ("guest image", {
                let mut key = base.clone();
                key.guest_image = digest("yougori/test/image/v1", &[b"other"]);
                key
            }),
            ("accelerator", {
                let mut key = base.clone();
                key.accelerator = Accelerator::Hardware {
                    hypervisor: HypervisorKind::Whpx,
                };
                key
            }),
            ("confinement", {
                let mut key = base.clone();
                key.confinement
                    .remove(&ConfinementControl::ResourceControls);
                key
            }),
            ("devices", {
                let mut key = base.clone();
                key.devices.display = true;
                key
            }),
            ("network", {
                let mut key = base.clone();
                key.network = NetworkAuthority::of([NetworkChannel::NamedTransportRoutes]);
                key
            }),
            ("lifecycle", {
                let mut key = base.clone();
                key.lifecycle.insert(LifecycleCheck::SnapshotVerified);
                key
            }),
        ];
        for (name, key) in variants {
            assert!(identities.insert(key.identity()), "{name}");
        }
        assert_eq!(base.identity(), key(BackendKind::Firecracker).identity());
    }

    #[test]
    fn a_profile_is_unavailable_without_a_row_and_keeps_one_row_per_combination() {
        let key = key(BackendKind::Firecracker);
        let mut profile = ReleaseProfile::new();
        assert!(profile.is_empty());
        assert_eq!(profile.status_of(&key), SupportStatus::Unavailable);
        let row = EvidenceRow {
            key: key.clone(),
            result: TestResult::NotRun,
        };
        profile.add(row.clone()).unwrap();
        assert_eq!(profile.len(), 1);
        assert_eq!(profile.status_of(&key), SupportStatus::Experimental);
        assert_eq!(profile.row(&key), Some(&row));
        let duplicate = profile.add(row).unwrap_err();
        assert_eq!(
            duplicate,
            ProfileError::DuplicateRow {
                combination: key.identity()
            }
        );
        assert!(duplicate.to_string().contains("already has a row"));
        let mut other = key;
        other.lifecycle.clear();
        assert_eq!(profile.status_of(&other), SupportStatus::Unavailable);
    }
}
