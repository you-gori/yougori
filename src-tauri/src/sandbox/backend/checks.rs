//! The required checks of a launch and their outcomes (§8.1 line 2433: "required
//! checks"; §1.3 lines 1897–1908). Each §1.3 facet is checked against host-observed
//! facts only; a guest assertion is named in the refusal and never counted (VM-W09,
//! line 2594; VM-P29, line 2799; VM-P50, line 2820).
//!
//! The rules per facet: isolation, hypervisor confinement and operator confidentiality
//! must be at least what is required; network authority, credential exposure and device
//! exposure must be at most what is required; persistence must match exactly; and the
//! evidence facet needs the host build observed and the booted guest image equal to the
//! pinned one. Device inventories must match the approved device profile exactly
//! (VM-P02, line 2782), and every assigned GPU needs all §7.5 checks with no unsafe
//! setting (VM-P39, line 2809).

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::accelerator::Accelerator;
use super::facets::{
    ConfinementControl, CredentialExposure, DeviceExposure, Facet, GpuIsolationCheck,
    NetworkAuthority, OperatorConfidentiality, Persistence, PhysicalHost, RequiredProperties,
    UnsafeDeviceSetting,
};
use super::observation::{
    FactSource, GuestAsserted, GuestAssertions, HostFact, HostObserved, ObservedProperties,
};
use super::request::{DeviceProfile, PinnedArtifacts};
use crate::foundation::evidence::UnknownReason;
use crate::foundation::ids::{Digest, GpuDeviceKey};

/// A facet's value, as required or as observed, for the record of a check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "facet", rename_all = "snake_case")]
pub enum FacetValue {
    Isolation {
        own_guest_kernel: bool,
        hardware_virtualized: bool,
        physical_host: PhysicalHost,
    },
    Confinement {
        controls: BTreeSet<ConfinementControl>,
    },
    Network {
        authority: NetworkAuthority,
    },
    Credentials {
        exposure: CredentialExposure,
    },
    Persistence {
        persistence: Persistence,
    },
    Devices {
        exposure: DeviceExposure,
    },
    Confidentiality {
        confidentiality: OperatorConfidentiality,
    },
    Evidence {
        max_age: Duration,
    },
}

fn list<'a>(tags: impl Iterator<Item = &'a str>) -> String {
    tags.collect::<Vec<&str>>().join(", ")
}

impl fmt::Display for FacetValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolation {
                own_guest_kernel,
                hardware_virtualized,
                physical_host,
            } => write!(
                f,
                "own guest kernel {own_guest_kernel}, hardware virtualization \
                 {hardware_virtualized}, {physical_host}"
            ),
            Self::Confinement { controls } => {
                write!(
                    f,
                    "controls [{}]",
                    list(controls.iter().map(|control| control.tag()))
                )
            }
            Self::Network { authority } if authority.is_offline() => f.write_str("offline"),
            Self::Network { authority } => write!(
                f,
                "channels [{}]",
                list(authority.channels.iter().map(|channel| channel.tag()))
            ),
            Self::Credentials { exposure } if exposure.credentials.is_empty() => {
                f.write_str("no credentials")
            }
            Self::Credentials { exposure } => write!(
                f,
                "credentials [{}]",
                list(exposure.credentials.iter().map(|kind| kind.tag()))
            ),
            Self::Persistence { persistence } => f.write_str(persistence.tag()),
            Self::Devices { exposure } => write!(
                f,
                "display {}, {} GPU{}",
                exposure.display,
                exposure.gpus.len(),
                if exposure.gpus.len() == 1 { "" } else { "s" }
            ),
            Self::Confidentiality { confidentiality } => f.write_str(confidentiality.tag()),
            Self::Evidence { max_age } => write!(f, "observations no older than {max_age:?}"),
        }
    }
}

/// Why a facet check failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum CheckFailure {
    /// The host has no observation of the facet.
    NotObserved { reason: UnknownReason },
    /// Only the guest asserted the facet; a guest assertion never satisfies a
    /// requirement.
    OnlyGuestAsserted { reason: UnknownReason },
    /// The host observation does not meet the requirement.
    NotMet {
        required: FacetValue,
        observed: FacetValue,
    },
    /// An assigned GPU lacks §7.5 isolation checks or has an unsafe setting.
    DeviceNotIsolated {
        device: GpuDeviceKey,
        missing: BTreeSet<GpuIsolationCheck>,
        unsafe_settings: BTreeSet<UnsafeDeviceSetting>,
    },
    /// The measured inventory is not the approved device profile (VM-P02).
    InventoryDiffersFromProfile {
        profile: DeviceExposure,
        observed: DeviceExposure,
    },
    /// The booted guest image is not the pinned one.
    ArtifactMismatch { pinned: Digest, observed: Digest },
    /// The backend passed the order of GPU checks and assignments, and it does not show
    /// this assigned GPU's checks made before its assignment: no order for it, more than
    /// one, or stamps that do not show the checks first (VM-CP-31, line 3181).
    NotCheckedBeforeAssignment { device: GpuDeviceKey },
}

impl fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObserved { reason } => write!(f, "no host observation ({reason})"),
            Self::OnlyGuestAsserted { reason } => write!(
                f,
                "only the guest asserted it and the host has no observation ({reason}); a \
                 guest assertion never satisfies a requirement"
            ),
            Self::NotMet { required, observed } => {
                write!(f, "required {required}, observed {observed}")
            }
            Self::DeviceNotIsolated {
                missing,
                unsafe_settings,
                ..
            } => write!(
                f,
                "an assigned GPU lacks {} isolation check{} and has {} unsafe setting{}",
                missing.len(),
                if missing.len() == 1 { "" } else { "s" },
                unsafe_settings.len(),
                if unsafe_settings.len() == 1 { "" } else { "s" }
            ),
            Self::InventoryDiffersFromProfile { .. } => {
                f.write_str("the measured device inventory is not the approved device profile")
            }
            Self::ArtifactMismatch { pinned, observed } => {
                write!(
                    f,
                    "the booted guest image {observed} is not the pinned {pinned}"
                )
            }
            Self::NotCheckedBeforeAssignment { device } => write!(
                f,
                "the host did not show the isolation checks of GPU {} made before it was \
                 assigned",
                device.device
            ),
        }
    }
}

/// The outcome of one facet check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    /// Satisfied by a host observation of this source.
    Satisfied {
        source: FactSource,
    },
    Failed {
        failure: CheckFailure,
    },
}

/// One required check and its outcome (§8.1). Only admission makes them: [`check_all`],
/// and admission's own rules for the configuration facts check_all does not see.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequiredCheck {
    facet: Facet,
    outcome: CheckOutcome,
}

impl RequiredCheck {
    pub fn facet(&self) -> Facet {
        self.facet
    }

    pub fn outcome(&self) -> &CheckOutcome {
        &self.outcome
    }

    pub fn is_satisfied(&self) -> bool {
        matches!(self.outcome, CheckOutcome::Satisfied { .. })
    }

    /// The failure, if the check failed.
    pub fn failure(&self) -> Option<&CheckFailure> {
        match &self.outcome {
            CheckOutcome::Satisfied { .. } => None,
            CheckOutcome::Failed { failure } => Some(failure),
        }
    }

    /// The same facet's check, failed with `failure`.
    pub(super) fn failing(&self, failure: CheckFailure) -> Self {
        Self {
            facet: self.facet,
            outcome: CheckOutcome::Failed { failure },
        }
    }
}

impl fmt::Display for RequiredCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.outcome {
            CheckOutcome::Satisfied { source } => write!(f, "{}: satisfied ({source})", self.facet),
            CheckOutcome::Failed { failure } => write!(f, "{}: {failure}", self.facet),
        }
    }
}

/// Checks every §1.3 facet of `required` against the host's facts. Guest assertions are
/// consulted only to name them in a refusal.
pub fn check_all(
    required: &RequiredProperties,
    profile: &DeviceProfile,
    pinned: &PinnedArtifacts,
    accelerator: &HostObserved<Accelerator>,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Vec<RequiredCheck> {
    let checks = [
        (
            Facet::Isolation,
            isolation(required, accelerator, observed, guest),
        ),
        (
            Facet::HypervisorConfinement,
            confinement(required, observed, guest),
        ),
        (Facet::NetworkAuthority, network(required, observed, guest)),
        (
            Facet::CredentialExposure,
            credentials(required, observed, guest),
        ),
        (Facet::Persistence, persistence(required, observed, guest)),
        (
            Facet::DeviceExposure,
            devices(required, profile, observed, guest),
        ),
        (
            Facet::OperatorConfidentiality,
            confidentiality(required, observed, guest),
        ),
        (Facet::Evidence, evidence(pinned, observed)),
    ];
    checks
        .into_iter()
        .map(|(facet, result)| RequiredCheck {
            facet,
            outcome: match result {
                Ok(source) => CheckOutcome::Satisfied { source },
                Err(failure) => CheckOutcome::Failed { failure },
            },
        })
        .collect()
}

/// The host observation of a fact, or the failure that says why there is none.
fn observation<'a, T, G>(
    fact: &'a HostFact<T>,
    guest: Option<&GuestAsserted<G>>,
) -> Result<&'a HostObserved<T>, CheckFailure> {
    match fact {
        HostFact::Observed { observation } => Ok(observation),
        HostFact::Unavailable { reason } => Err(if guest.is_some() {
            CheckFailure::OnlyGuestAsserted { reason: *reason }
        } else {
            CheckFailure::NotObserved { reason: *reason }
        }),
    }
}

/// The weaker of two host sources: verified only when both are.
fn weaker(first: FactSource, second: FactSource) -> FactSource {
    if first == FactSource::Verified && second == FactSource::Verified {
        FactSource::Verified
    } else {
        FactSource::HostObserved
    }
}

fn isolation(
    required: &RequiredProperties,
    accelerator: &HostObserved<Accelerator>,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.isolation, guest.isolation.as_ref())?;
    let value = fact.value();
    let hardware_virtualized = accelerator.value().is_hardware_virtualized();
    let physical_host = required.isolation.physical_host;
    if value.own_guest_kernel && hardware_virtualized && value.physical_host >= physical_host {
        Ok(weaker(fact.source(), accelerator.source()))
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Isolation {
                own_guest_kernel: true,
                hardware_virtualized: true,
                physical_host,
            },
            observed: FacetValue::Isolation {
                own_guest_kernel: value.own_guest_kernel,
                hardware_virtualized,
                physical_host: value.physical_host,
            },
        })
    }
}

fn confinement(
    required: &RequiredProperties,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.confinement, guest.confinement.as_ref())?;
    if required.confinement.is_subset(fact.value()) {
        Ok(fact.source())
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Confinement {
                controls: required.confinement.clone(),
            },
            observed: FacetValue::Confinement {
                controls: fact.value().clone(),
            },
        })
    }
}

fn network(
    required: &RequiredProperties,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.network, guest.network.as_ref())?;
    if fact.value().within(&required.network) {
        Ok(fact.source())
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Network {
                authority: required.network.clone(),
            },
            observed: FacetValue::Network {
                authority: fact.value().clone(),
            },
        })
    }
}

fn credentials(
    required: &RequiredProperties,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.credentials, guest.credentials.as_ref())?;
    if fact.value().within(&required.credentials) {
        Ok(fact.source())
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Credentials {
                exposure: required.credentials.clone(),
            },
            observed: FacetValue::Credentials {
                exposure: fact.value().clone(),
            },
        })
    }
}

fn persistence(
    required: &RequiredProperties,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.persistence, guest.persistence.as_ref())?;
    if *fact.value() == required.persistence {
        Ok(fact.source())
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Persistence {
                persistence: required.persistence.clone(),
            },
            observed: FacetValue::Persistence {
                persistence: fact.value().clone(),
            },
        })
    }
}

fn devices(
    required: &RequiredProperties,
    profile: &DeviceProfile,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.devices, guest.devices.as_ref())?;
    let inventory = fact.value();
    let exposure = inventory.exposure();
    if exposure != profile.devices {
        return Err(CheckFailure::InventoryDiffersFromProfile {
            profile: profile.devices.clone(),
            observed: exposure,
        });
    }
    if let Some(gpu) = inventory
        .gpus
        .iter()
        .find(|gpu| !gpu.isolation.is_isolated())
    {
        return Err(CheckFailure::DeviceNotIsolated {
            device: gpu.device,
            missing: gpu.isolation.missing(),
            unsafe_settings: gpu.isolation.unsafe_settings.clone(),
        });
    }
    if exposure.within(&required.devices) {
        Ok(fact.source())
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Devices {
                exposure: required.devices.clone(),
            },
            observed: FacetValue::Devices { exposure },
        })
    }
}

fn confidentiality(
    required: &RequiredProperties,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<FactSource, CheckFailure> {
    let fact = observation(&observed.confidentiality, guest.confidentiality.as_ref())?;
    let satisfied = match required.confidentiality {
        OperatorConfidentiality::None => true,
        OperatorConfidentiality::VerifiedConfidentialVm { .. } => {
            *fact.value() == required.confidentiality
        }
    };
    if satisfied {
        Ok(fact.source())
    } else {
        Err(CheckFailure::NotMet {
            required: FacetValue::Confidentiality {
                confidentiality: required.confidentiality,
            },
            observed: FacetValue::Confidentiality {
                confidentiality: *fact.value(),
            },
        })
    }
}

fn evidence(
    pinned: &PinnedArtifacts,
    observed: &ObservedProperties,
) -> Result<FactSource, CheckFailure> {
    let host = observation::<_, ()>(&observed.host, None)?;
    let image = observation::<_, ()>(&observed.guest_image, None)?;
    if *image.value() != pinned.guest_image {
        return Err(CheckFailure::ArtifactMismatch {
            pinned: pinned.guest_image,
            observed: *image.value(),
        });
    }
    Ok(weaker(host.source(), image.source()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facet_values_and_failures_display() {
        let offline = FacetValue::Network {
            authority: NetworkAuthority::offline(),
        };
        assert_eq!(offline.to_string(), "offline");
        let none = FacetValue::Credentials {
            exposure: CredentialExposure::none(),
        };
        assert_eq!(none.to_string(), "no credentials");
        let failure = CheckFailure::NotMet {
            required: FacetValue::Persistence {
                persistence: Persistence::EphemeralTask,
            },
            observed: FacetValue::Persistence {
                persistence: Persistence::DeclaredDataVolumes {
                    volumes: BTreeSet::new(),
                },
            },
        };
        assert_eq!(
            failure.to_string(),
            "required ephemeral_task, observed declared_data_volumes"
        );
        assert!(CheckFailure::OnlyGuestAsserted {
            reason: UnknownReason::NotTested
        }
        .to_string()
        .contains("never satisfies"));
        let json = serde_json::to_value(&failure).unwrap();
        assert_eq!(json["failure"], "not_met");
        assert_eq!(json["required"]["facet"], "persistence");
        let devices = FacetValue::Devices {
            exposure: DeviceExposure::cpu_only(),
        };
        assert_eq!(devices.to_string(), "display false, 0 GPUs");
        let isolation = FacetValue::Isolation {
            own_guest_kernel: true,
            hardware_virtualized: false,
            physical_host: PhysicalHost::Shared,
        };
        assert!(isolation
            .to_string()
            .contains("hardware virtualization false"));
        assert!(FacetValue::Confinement {
            controls: ConfinementControl::all()
        }
        .to_string()
        .starts_with("controls [account_identity"));
    }

    #[test]
    fn the_weaker_source_wins() {
        assert_eq!(
            weaker(FactSource::Verified, FactSource::Verified),
            FactSource::Verified
        );
        assert_eq!(
            weaker(FactSource::Verified, FactSource::HostObserved),
            FactSource::HostObserved
        );
        assert_eq!(
            weaker(FactSource::HostObserved, FactSource::Verified),
            FactSource::HostObserved
        );
    }
}
