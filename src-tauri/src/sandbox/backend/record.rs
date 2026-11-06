//! The launch record (§8.1 lines 2433–2439): an evidence record, not a security
//! certificate. It binds the sandbox and its generations, the contract digest, the
//! backend and artifact versions, the actual accelerator, the observed confinement, the
//! device profile, the required checks with their outcomes, the source of every fact and
//! the timestamp. Host-observed and guest-asserted facts are separate fields of separate
//! types. Where the network facet asked for an independent perimeter, the record also
//! binds the CORE-01 evidence of every block rule (§4.4). Where the backend passed them,
//! it binds the host's observations of the hypervisor configuration too: the golden
//! comparison (VM-CP-02), the listing check (VM-CP-03) and each assigned GPU's checks and
//! assignment in the order the host made them (VM-CP-31). A record without them
//! serializes as it did before they existed, so its identity is unchanged. The record has
//! an identity
//! digest over everything it binds and is Serialize only: nothing reads one back, so none
//! can be hand-written. Its facts are launch-time facts: once they go stale, only the
//! host's re-observation of the running VM, judged by the rules of admission, presents
//! the launch as current again ([`LaunchRecord::assert_current_with`]); that includes the
//! configuration facts the record binds, which the re-observation makes again or which
//! must still be current themselves.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::accelerator::Accelerator;
use super::admission::{evidence_bound, judge, judge_configuration, Terms};
use super::checks::RequiredCheck;
use super::configuration::{
    ConfigurationComparison, ConfigurationFacts, GpuAssignmentOrder, HostInterfaceListing,
};
use super::contract::{
    BackendIdentity, ConfigurationCheck, FactName, LaunchRefusal, ReobservationRefusal,
};
use super::facets::RequiredProperties;
use super::observation::{
    FactSource, GuestAssertions, HostFact, HostObserved, ObservationProblem, ObservedProperties,
};
use super::reobservation::Reobservation;
use super::request::{DeviceProfile, PinnedArtifacts};
use crate::foundation::coordination::{SandboxGenerations, SnapshotId, VmInstanceId};
use crate::foundation::evidence::{
    ClockReading, ClockSession, ConfigurationFingerprint, Satisfied, Staleness,
};
use crate::foundation::ids::{digest, Digest, ExecutionId, MonotonicTime, TenantId};
use crate::foundation::ledger::ReservationId;

/// The digest domain of a launch record's identity.
pub const LAUNCH_RECORD_DOMAIN: &str = "yougori/sandbox/launch-record/v1";

/// The sandbox a launch belongs to and the generations it was launched under (S3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SandboxBinding {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub generations: SandboxGenerations,
}

/// Everything a launch record binds; the identity is a digest of its serialized form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct RecordBody {
    pub(super) sandbox: SandboxBinding,
    pub(super) contract: Digest,
    pub(super) reservation: ReservationId,
    pub(super) backend: BackendIdentity,
    pub(super) pinned: PinnedArtifacts,
    pub(super) vm: VmInstanceId,
    pub(super) restored_from: Option<SnapshotId>,
    pub(super) device_profile: DeviceProfile,
    pub(super) required: RequiredProperties,
    pub(super) configuration: ConfigurationFingerprint,
    pub(super) hypervisor_evidence: Satisfied,
    /// The independent perimeter's evidence, one per block rule; absent from the
    /// serialized form when no perimeter was asked for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) perimeter_evidence: Vec<Satisfied>,
    pub(super) accelerator: HostObserved<Accelerator>,
    pub(super) host_observed: ObservedProperties,
    /// The golden comparison of the running configuration (VM-CP-02); absent from the
    /// serialized form when the backend passed none, so such records keep their identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) configuration_comparison: Option<HostObserved<ConfigurationComparison>>,
    /// The listing check of the running hypervisor (VM-CP-03); absent likewise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) interface_listing: Option<HostObserved<HostInterfaceListing>>,
    /// One order of checks and assignment per assigned GPU (VM-CP-31); absent likewise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) gpu_assignments: Vec<GpuAssignmentOrder>,
    pub(super) guest_asserted: GuestAssertions,
    pub(super) checks: Vec<RequiredCheck>,
    pub(super) clock: ClockSession,
    pub(super) recorded_at: MonotonicTime,
}

/// Why a record could not be sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    Unserializable { detail: String },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unserializable { detail } => {
                write!(f, "the record could not be serialized: {detail}")
            }
        }
    }
}

impl std::error::Error for RecordError {}

/// A sealed launch record (§8.1). Only admission seals one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchRecord {
    identity: Digest,
    #[serde(flatten)]
    body: RecordBody,
}

impl LaunchRecord {
    /// Seals `body` under its identity: the digest of its serialized form, so a change to
    /// any bound field changes the identity.
    pub(super) fn seal(body: RecordBody) -> Result<Self, RecordError> {
        let bytes = serde_json::to_vec(&body).map_err(|error| RecordError::Unserializable {
            detail: error.to_string(),
        })?;
        Ok(Self {
            identity: digest(LAUNCH_RECORD_DOMAIN, &[&bytes]),
            body,
        })
    }

    /// The record's identity digest.
    pub fn identity(&self) -> Digest {
        self.identity
    }

    pub fn sandbox(&self) -> &SandboxBinding {
        &self.body.sandbox
    }

    /// The contract digest, an opaque integrity identifier from the policy layer.
    pub fn contract(&self) -> Digest {
        self.body.contract
    }

    /// The CORE-03 reservation the launch ran inside.
    pub fn reservation(&self) -> ReservationId {
        self.body.reservation
    }

    pub fn backend(&self) -> &BackendIdentity {
        &self.body.backend
    }

    pub fn pinned(&self) -> PinnedArtifacts {
        self.body.pinned
    }

    pub fn vm(&self) -> VmInstanceId {
        self.body.vm
    }

    /// The snapshot the VM was restored from, for a restore.
    pub fn restored_from(&self) -> Option<SnapshotId> {
        self.body.restored_from
    }

    pub fn device_profile(&self) -> &DeviceProfile {
        &self.body.device_profile
    }

    pub fn required(&self) -> &RequiredProperties {
        &self.body.required
    }

    /// The host configuration the launch was decided under.
    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.body.configuration
    }

    /// The CORE-01 host-probe evidence that a hypervisor was available.
    pub fn hypervisor_evidence(&self) -> &Satisfied {
        &self.body.hypervisor_evidence
    }

    /// The CORE-01 host-probe evidence that each block rule of the independent perimeter
    /// was enforced for the launch's principal (§4.4; VM-CP-11), in rule order; empty when
    /// the network facet asked for no independent perimeter.
    pub fn perimeter_evidence(&self) -> &[Satisfied] {
        &self.body.perimeter_evidence
    }

    /// The accelerator the host observed the VM running on, never a requested flag
    /// (VM-W22).
    pub fn accelerator(&self) -> &HostObserved<Accelerator> {
        &self.body.accelerator
    }

    /// What the host observed about the boundary.
    pub fn host_observed(&self) -> &ObservedProperties {
        &self.body.host_observed
    }

    /// The host's comparison of the running hypervisor configuration with the approved
    /// profile's golden file (VM-CP-02), when the backend passed one to admission.
    pub fn configuration_comparison(&self) -> Option<&HostObserved<ConfigurationComparison>> {
        self.body.configuration_comparison.as_ref()
    }

    /// The host's listing check of the running hypervisor's host interfaces (VM-CP-03),
    /// when the backend passed one to admission.
    pub fn interface_listing(&self) -> Option<&HostObserved<HostInterfaceListing>> {
        self.body.interface_listing.as_ref()
    }

    /// Each assigned GPU's checks before assignment and its assignment, as the host made
    /// them (VM-CP-31); empty when the backend passed none.
    pub fn gpu_assignments(&self) -> &[GpuAssignmentOrder] {
        &self.body.gpu_assignments
    }

    /// What the guest asserted; recorded apart and never counted.
    pub fn guest_asserted(&self) -> &GuestAssertions {
        &self.body.guest_asserted
    }

    /// Every required check with its outcome; all satisfied in a sealed record.
    pub fn checks(&self) -> &[RequiredCheck] {
        &self.body.checks
    }

    pub fn clock(&self) -> ClockSession {
        self.body.clock
    }

    pub fn recorded_at(&self) -> MonotonicTime {
        self.body.recorded_at
    }

    /// The source of every host fact, by name.
    pub fn fact_sources(&self) -> Vec<(FactName, FactSource)> {
        let observed = &self.body.host_observed;
        vec![
            (FactName::HypervisorEvidence, FactSource::HostObserved),
            (FactName::Accelerator, self.body.accelerator.source()),
            (FactName::Host, observed.host.source()),
            (FactName::GuestImage, observed.guest_image.source()),
            (FactName::Isolation, observed.isolation.source()),
            (FactName::Confinement, observed.confinement.source()),
            (FactName::Network, observed.network.source()),
            (FactName::Credentials, observed.credentials.source()),
            (FactName::Persistence, observed.persistence.source()),
            (FactName::Devices, observed.devices.source()),
            (FactName::Confidentiality, observed.confidentiality.source()),
        ]
    }

    /// Whether every fact of the record may still be presented as current at `now`, under
    /// the record's own configuration and the required freshness (VM-W04 row, line 2589:
    /// stale evidence is not presented as current). The first stale fact is named; the
    /// independent perimeter's evidence is named as the network enforcement fact, which it
    /// is part of, and the configuration facts as the device inventory fact, which they
    /// qualify.
    pub fn assert_current(&self, now: ClockReading) -> Result<(), StaleFact> {
        let max_age = self.body.required.evidence.max_age;
        let configuration = self.body.configuration;
        if now.session() != self.body.clock {
            return Err(StaleFact {
                fact: FactName::HypervisorEvidence,
                problem: ObservationProblem::Stale {
                    staleness: Staleness::OtherClock,
                },
            });
        }
        evidence_current(
            FactName::HypervisorEvidence,
            &self.body.hypervisor_evidence,
            now,
        )?;
        for evidence in &self.body.perimeter_evidence {
            evidence_current(FactName::Network, evidence, now)?;
        }
        let current = |fact: FactName, observation: &HostObserved<Accelerator>| {
            observation
                .current_at(now, max_age, configuration)
                .map_err(|problem| StaleFact { fact, problem })
        };
        current(FactName::Accelerator, &self.body.accelerator)?;
        let observed = &self.body.host_observed;
        fact_current(FactName::Host, &observed.host, now, max_age, configuration)?;
        fact_current(
            FactName::GuestImage,
            &observed.guest_image,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Isolation,
            &observed.isolation,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Confinement,
            &observed.confinement,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Network,
            &observed.network,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Credentials,
            &observed.credentials,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Persistence,
            &observed.persistence,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Devices,
            &observed.devices,
            now,
            max_age,
            configuration,
        )?;
        fact_current(
            FactName::Confidentiality,
            &observed.confidentiality,
            now,
            max_age,
            configuration,
        )?;
        let devices = |problem: Result<(), ObservationProblem>| {
            problem.map_err(|problem| StaleFact {
                fact: FactName::Devices,
                problem,
            })
        };
        if let Some(comparison) = &self.body.configuration_comparison {
            devices(comparison.current_at(now, max_age, configuration))?;
        }
        if let Some(listing) = &self.body.interface_listing {
            devices(listing.current_at(now, max_age, configuration))?;
        }
        for order in &self.body.gpu_assignments {
            devices(order.checked.current_at(now, max_age, configuration))?;
            devices(order.assigned.current_at(now, max_age, configuration))?;
        }
        Ok(())
    }

    /// Whether the launch may be presented as current at `now` on the host's
    /// re-observation of its VM, once the launch-time facts are stale or before (§8.1 line
    /// 2439: re-evaluate relevant evidence; VM-W04 row, line 2589). `reobservation` must
    /// be of this record's launch and on its clock session; its CORE-01 hypervisor
    /// evidence must be bound as the record's is and fresh now, and so must every
    /// perimeter rule's; and its facts must pass the rules admission applied at launch,
    /// under the record's configuration and required freshness: the accelerator
    /// host-observed, current and this backend's hardware hypervisor, every observation
    /// current, and every §1.3 facet satisfied by host-observed facts, never by a guest
    /// assertion. The configuration facts it carries (VM-CP-02, VM-CP-03, VM-CP-31) must
    /// pass the rules admission applied to them at launch, a golden comparison must be with
    /// the launch's golden file, and every configuration fact the record binds that the
    /// re-observation does not carry must still be current itself, named as the device
    /// inventory fact it qualifies. The record itself is unchanged: it stays the
    /// launch-time evidence.
    pub fn assert_current_with(
        &self,
        now: ClockReading,
        reobservation: &Reobservation,
    ) -> Result<(), ReobservationRefusal> {
        let other_launch = || ReobservationRefusal::OtherLaunch {
            record: self.identity,
            reobserved: reobservation.record(),
        };
        if reobservation.record() != self.identity || reobservation.vm() != self.body.vm {
            return Err(other_launch());
        }
        let refused = ReobservationRefusal::refused;
        if now.session() != self.body.clock || reobservation.clock() != self.body.clock {
            return Err(refused(LaunchRefusal::ObservationNotCurrent {
                fact: FactName::HypervisorEvidence,
                problem: ObservationProblem::Stale {
                    staleness: Staleness::OtherClock,
                },
            }));
        }
        evidence_bound(
            reobservation.hypervisor_evidence(),
            self.body.hypervisor_evidence.subject(),
            self.body.configuration,
            now,
        )
        .map_err(refused)?;
        let perimeter = reobservation.perimeter_evidence();
        if perimeter.len() != self.body.perimeter_evidence.len()
            || perimeter
                .iter()
                .zip(&self.body.perimeter_evidence)
                .any(|(again, launched)| {
                    again.subject() != launched.subject()
                        || again.configuration() != launched.configuration()
                })
        {
            return Err(other_launch());
        }
        for evidence in perimeter {
            evidence_current(FactName::Network, evidence, now).map_err(|stale| {
                refused(LaunchRefusal::ObservationNotCurrent {
                    fact: stale.fact,
                    problem: stale.problem,
                })
            })?;
        }
        let terms = Terms {
            required: &self.body.required,
            device_profile: &self.body.device_profile,
            pinned: &self.body.pinned,
            configuration: self.body.configuration,
            backend: &self.body.backend,
        };
        let (_, checks) = judge(
            &terms,
            now,
            reobservation.accelerator(),
            reobservation.host_observed(),
            reobservation.guest_asserted(),
        )
        .map_err(refused)?;
        let again = reobservation.configuration_facts();
        judge_configuration(&terms, now, reobservation.host_observed(), &checks, &again)
            .map_err(refused)?;
        self.configuration_current_with(now, &again)
            .map_err(refused)
    }

    /// What a re-observation's configuration facts must show beyond the rules of
    /// admission, against the record's own: a golden comparison made again is with the
    /// launch's golden file, and every configuration fact the record binds that was not
    /// made again is still current itself under the record's configuration and required
    /// freshness. A GPU order counts as made again when the re-observation carries any,
    /// since admission's rules then require one for every GPU the host observes assigned.
    fn configuration_current_with(
        &self,
        now: ClockReading,
        again: &ConfigurationFacts,
    ) -> Result<(), LaunchRefusal> {
        let max_age = self.body.required.evidence.max_age;
        let configuration = self.body.configuration;
        let devices = |problem: ObservationProblem| LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Devices,
            problem,
        };
        match (&self.body.configuration_comparison, &again.comparison) {
            (Some(launched), Some(made)) if made.value().golden != launched.value().golden => {
                return Err(LaunchRefusal::ConfigurationNotApproved {
                    backend: self.body.backend.kind,
                    checks: BTreeSet::from([ConfigurationCheck::GoldenConfiguration]),
                    findings: vec![format!(
                        "the configuration was compared again with the golden file {}, not \
                         the launch's golden file {}",
                        made.value().golden,
                        launched.value().golden
                    )],
                });
            }
            (Some(launched), None) => launched
                .current_at(now, max_age, configuration)
                .map_err(devices)?,
            _ => {}
        }
        if let (Some(launched), None) = (&self.body.interface_listing, &again.listing) {
            launched
                .current_at(now, max_age, configuration)
                .map_err(devices)?;
        }
        if again.gpu_assignments.is_empty() {
            for order in &self.body.gpu_assignments {
                order
                    .checked
                    .current_at(now, max_age, configuration)
                    .map_err(devices)?;
                order
                    .assigned
                    .current_at(now, max_age, configuration)
                    .map_err(devices)?;
            }
        }
        Ok(())
    }
}

/// Checks that CORE-01 evidence is still fresh at `now`, on the record's clock session.
fn evidence_current(
    fact: FactName,
    evidence: &Satisfied,
    now: ClockReading,
) -> Result<(), StaleFact> {
    if now.at() > evidence.fresh_until() {
        return Err(StaleFact {
            fact,
            problem: ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: now.at().saturating_duration_since(evidence.observed_at()),
                    limit: evidence
                        .fresh_until()
                        .saturating_duration_since(evidence.observed_at()),
                },
            },
        });
    }
    Ok(())
}

/// Checks one host fact's currency; an unavailable fact has nothing to go stale.
pub(super) fn fact_current<T>(
    fact: FactName,
    host_fact: &HostFact<T>,
    now: ClockReading,
    max_age: Duration,
    configuration: ConfigurationFingerprint,
) -> Result<(), StaleFact> {
    match host_fact.observation() {
        Some(observation) => observation
            .current_at(now, max_age, configuration)
            .map_err(|problem| StaleFact { fact, problem }),
        None => Ok(()),
    }
}

/// A fact of a record that may no longer be presented as current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StaleFact {
    pub fact: FactName,
    pub problem: ObservationProblem,
}

impl fmt::Display for StaleFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the {} of this launch record is not current: {}",
            self.fact, self.problem
        )
    }
}

impl std::error::Error for StaleFact {}
