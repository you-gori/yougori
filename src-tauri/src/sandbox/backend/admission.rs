//! Admission of a launch: the checks every backend runs, in a fixed order, before and
//! after it creates a VM (§0.1 item 6, line 1830: evidence before exposure; VM-W16;
//! VM-W22; §8.1). Real backends call [`precheck`] before they create anything and
//! [`admit`] once the host has observed the running VM; a failed admission means the
//! backend removes the VM and reports the refusal. Where the network facet asks for an
//! independent perimeter, both also need CORE-01 host-probe evidence that every block
//! rule the launch relies on is enforced for its principal (§4.4 lines 2153–2165;
//! VM-CP-11 line 3161). A backend that observed the hypervisor configuration as well
//! (VM-CP-02, VM-CP-03 and VM-CP-31, lines 3152, 3153 and 3181) admits with
//! [`admit_with_configuration`], which judges those facts too and binds them in the
//! record.

use std::collections::BTreeSet;

use super::accelerator::Accelerator;
use super::checks::{check_all, CheckFailure, RequiredCheck};
use super::configuration::{ConfigurationFacts, GpuAssignmentOrder};
use super::contract::{
    BackendFeatures, BackendIdentity, BackendKind, ConfigurationCheck, FactName, Feature,
    HostEvidence, LaunchRefusal,
};
use super::facets::{
    DeviceExposure, Facet, OperatorConfidentiality, PerimeterRequirement, PhysicalHost,
    RequiredProperties,
};
use super::observation::{GuestAssertions, HostFact, HostObserved, ObservedProperties};
use super::record::{fact_current, LaunchRecord, RecordBody, SandboxBinding, StaleFact};
use super::request::{DeviceProfile, LaunchRequest, PinnedArtifacts};
use crate::foundation::coordination::{SnapshotId, VmInstanceId};
use crate::foundation::evidence::{
    Capability, ClockReading, ConfigurationFingerprint, EvidenceRefusal, HypervisorSubject,
    PerimeterRuleSubject, Requirement, Satisfied, SourceClass, Staleness, Subject,
};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, SandboxBootGeneration};

/// The digest domain of VM handles.
pub const VM_HANDLE_DOMAIN: &str = "yougori/sandbox/vm-handle/v1";

/// The stable handle of one boot of one sandbox on one backend: a digest, never a PID
/// (VM part §6.4, line 2322). The same sandbox and boot name the same handle, so a
/// repeated launch is the same object.
pub fn vm_handle(
    backend: BackendKind,
    execution: &ExecutionId,
    boot: SandboxBootGeneration,
) -> VmInstanceId {
    VmInstanceId::new(
        DigestBuilder::new(VM_HANDLE_DOMAIN)
            .str(backend.tag())
            .str(execution.as_str())
            .u64(boot.get())
            .finish(),
    )
}

/// What the host must have observed before anything is launched: that this backend's
/// hypervisor is available on this machine, by a host probe, under the current
/// configuration, no older than the required freshness (CORE-01; VM-W22).
pub fn hypervisor_requirement(request: &LaunchRequest, backend: &BackendIdentity) -> Requirement {
    Requirement::host_only(
        Capability::HypervisorAvailable,
        Subject::Hypervisor(HypervisorSubject {
            machine: request.machine,
            hypervisor: backend.hypervisor,
        }),
        request.required.evidence.max_age,
        request.configuration,
    )
}

/// What the host must have observed when the network facet asks for an independent
/// perimeter (§4.4 line 2164: "a must-probe uses a controlled endpoint ..., the same
/// identity as the actual broker, and evidence of the intended block"; VM-CP-11 line
/// 2986): for every block rule the launch relies on, host-probe evidence that the rule is
/// enforced on this machine's perimeter for the launch's principal, under the current
/// configuration and no older than the required freshness. One requirement per rule, in
/// rule order; none when no independent perimeter is asked for.
pub fn perimeter_requirements(request: &LaunchRequest) -> Vec<(PerimeterRuleSubject, Requirement)> {
    let PerimeterRequirement::Independent {
        perimeter,
        principal,
        rules,
    } = &request.required.perimeter
    else {
        return Vec::new();
    };
    rules
        .iter()
        .map(|rule| {
            let subject = PerimeterRuleSubject {
                machine: request.machine,
                perimeter: *perimeter,
                rule: *rule,
                principal: *principal,
            };
            let requirement = Requirement::host_only(
                Capability::PerimeterRuleEnforced,
                Subject::PerimeterRule(subject),
                request.required.evidence.max_age,
                request.configuration,
            );
            (subject, requirement)
        })
        .collect()
}

/// The independent perimeter's evidence now, one CORE-01 `Satisfied` per block rule, or
/// the refusal naming the first rule without it. Empty when none is asked for.
pub(super) fn perimeter_evidence(
    request: &LaunchRequest,
    host: &dyn HostEvidence,
) -> Result<Vec<Satisfied>, LaunchRefusal> {
    if let PerimeterRequirement::Independent {
        perimeter,
        principal,
        rules,
    } = &request.required.perimeter
    {
        if rules.is_empty() {
            return Err(LaunchRefusal::NoPerimeterRules {
                perimeter: *perimeter,
                principal: *principal,
            });
        }
    }
    perimeter_requirements(request)
        .into_iter()
        .map(|(rule, requirement)| {
            host.evaluate(&requirement)
                .map_err(|refusal| LaunchRefusal::PerimeterNotEvidenced { rule, refusal })
        })
        .collect()
}

/// The checks before anything is created: the request is pinned to this backend build,
/// every feature the request needs is offered, the host-only hypervisor requirement is
/// satisfied, and, where the network facet asks for an independent perimeter, every
/// block rule's host-only requirement is too. Returns the hypervisor evidence for
/// [`admit`], which checks the perimeter's again.
pub fn precheck(
    request: &LaunchRequest,
    backend: &BackendIdentity,
    features: &BackendFeatures,
    host: &dyn HostEvidence,
) -> Result<Satisfied, LaunchRefusal> {
    if request.pinned.backend != backend.artifact {
        return Err(LaunchRefusal::BackendArtifactMismatch {
            pinned: request.pinned.backend,
            actual: backend.artifact,
        });
    }
    let devices = &request.device_profile.devices;
    if devices.paravirtualized_gpu { features.require(Feature::GpuParavirtualization)?; }
    if !devices.gpus.is_empty() {
        features.require(Feature::GpuAssignment)?;
    }
    if devices.display {
        features.require(Feature::Display)?;
    }
    if matches!(
        request.required.confidentiality,
        OperatorConfidentiality::VerifiedConfidentialVm { .. }
    ) {
        features.require(Feature::ConfidentialVm)?;
    }
    if request.required.isolation.physical_host == PhysicalHost::Dedicated {
        features.require(Feature::DedicatedHost)?;
    }
    let hypervisor = host
        .evaluate(&hypervisor_requirement(request, backend))
        .map_err(|refusal| LaunchRefusal::Evidence { refusal })?;
    perimeter_evidence(request, host)?;
    Ok(hypervisor)
}

/// What a backend gathered about a VM it created, or observed again about one that runs,
/// for admission.
#[derive(Clone, Debug)]
pub struct LaunchFacts {
    /// The accelerator the host observed the VM running on.
    pub accelerator: HostFact<Accelerator>,
    pub observed: ObservedProperties,
    pub guest: GuestAssertions,
}

/// What a launch requires, as admission judges the host's facts against it: from the
/// request at launch, and from the sealed record when the VM is observed again.
pub(super) struct Terms<'a> {
    pub(super) required: &'a RequiredProperties,
    pub(super) device_profile: &'a DeviceProfile,
    pub(super) pinned: &'a PinnedArtifacts,
    /// The configuration the launch was decided under.
    pub(super) configuration: ConfigurationFingerprint,
    pub(super) backend: &'a BackendIdentity,
}

/// Checks that hypervisor evidence is CORE-01 host-probe `HypervisorAvailable` evidence
/// about `subject` under `configuration`, and still fresh at `now`.
pub(super) fn evidence_bound(
    evidence: &Satisfied,
    subject: Digest,
    configuration: ConfigurationFingerprint,
    now: ClockReading,
) -> Result<(), LaunchRefusal> {
    if evidence.capability() != Capability::HypervisorAvailable
        || evidence.subject() != subject
        || evidence.source() != SourceClass::HostProbe
        || evidence.configuration() != configuration
    {
        return Err(LaunchRefusal::EvidenceNotBound {
            capability: evidence.capability(),
            source: evidence.source(),
            subject: evidence.subject(),
            configuration: evidence.configuration(),
        });
    }
    if now.at() > evidence.fresh_until() {
        return Err(LaunchRefusal::Evidence {
            refusal: EvidenceRefusal::Stale {
                capability: Capability::HypervisorAvailable,
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

/// The rules admission applies to what the host observed of a VM, in order: the
/// accelerator was host-observed, is current and is this backend's hardware hypervisor
/// (VM-W22); every host observation is current under the launch's configuration and the
/// required freshness; and every §1.3 facet is satisfied by host-observed facts. Returns
/// the accelerator's observation and every check, all satisfied.
pub(super) fn judge(
    terms: &Terms<'_>,
    now: ClockReading,
    accelerator: &HostFact<Accelerator>,
    observed: &ObservedProperties,
    guest: &GuestAssertions,
) -> Result<(HostObserved<Accelerator>, Vec<RequiredCheck>), LaunchRefusal> {
    let max_age = terms.required.evidence.max_age;
    let configuration = terms.configuration;
    let backend = terms.backend;
    let accelerator = match accelerator {
        HostFact::Observed { observation } => observation.clone(),
        HostFact::Unavailable { reason } => {
            return Err(LaunchRefusal::AcceleratorNotObserved { reason: *reason });
        }
    };
    accelerator
        .current_at(now, max_age, configuration)
        .map_err(|problem| LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Accelerator,
            problem,
        })?;
    let observed_accelerator = *accelerator.value();
    match observed_accelerator.hypervisor() {
        None => {
            return Err(LaunchRefusal::NotHardwareVirtualized {
                observed: observed_accelerator,
            });
        }
        Some(hypervisor) if hypervisor != backend.hypervisor => {
            return Err(LaunchRefusal::UnexpectedAccelerator {
                expected: backend.hypervisor,
                observed: observed_accelerator,
            });
        }
        Some(_) => {}
    }

    let into = |result: Result<(), StaleFact>| {
        result.map_err(|stale| LaunchRefusal::ObservationNotCurrent {
            fact: stale.fact,
            problem: stale.problem,
        })
    };
    into(fact_current(
        FactName::Host,
        &observed.host,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::GuestImage,
        &observed.guest_image,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Isolation,
        &observed.isolation,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Confinement,
        &observed.confinement,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Network,
        &observed.network,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Credentials,
        &observed.credentials,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Persistence,
        &observed.persistence,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Devices,
        &observed.devices,
        now,
        max_age,
        configuration,
    ))?;
    into(fact_current(
        FactName::Confidentiality,
        &observed.confidentiality,
        now,
        max_age,
        configuration,
    ))?;

    let checks = check_all(
        terms.required,
        terms.device_profile,
        terms.pinned,
        &accelerator,
        observed,
        guest,
    );
    if checks.iter().any(|check| !check.is_satisfied()) {
        return Err(LaunchRefusal::PropertiesNotSatisfied { checks });
    }
    Ok((accelerator, checks))
}

/// The rules admission applies to the configuration facts a backend passed, and the record
/// applies to those a re-observation makes again
/// ([`LaunchRecord::assert_current_with`]), in order:
///
/// 1. each is current under the launch's configuration and the required freshness, an
///    assigned GPU's checks and its assignment alike; a stale one is named as the device
///    inventory fact it qualifies;
/// 2. the golden comparison shows the golden file's configuration with none of the devices
///    VM-CP-02 names, and the listing shows the restrictions of VM-CP-03; one refusal names
///    every check that failed and every finding;
/// 3. where GPU orders are given, every GPU the host observed assigned has exactly one
///    whose stamps show its checks made before its assignment, no order names a device
///    the host did not observe assigned, and each order's checks before assignment show
///    the four VM-CP-31 names passing and no unsafe setting. A failure is the device
///    exposure facet's.
pub(super) fn judge_configuration(
    terms: &Terms<'_>,
    now: ClockReading,
    observed: &ObservedProperties,
    checks: &[RequiredCheck],
    configuration: &ConfigurationFacts,
) -> Result<(), LaunchRefusal> {
    let max_age = terms.required.evidence.max_age;
    let current = |problem: Result<(), _>| {
        problem.map_err(|problem| LaunchRefusal::ObservationNotCurrent {
            fact: FactName::Devices,
            problem,
        })
    };
    if let Some(comparison) = &configuration.comparison {
        current(comparison.current_at(now, max_age, terms.configuration))?;
    }
    if let Some(listing) = &configuration.listing {
        current(listing.current_at(now, max_age, terms.configuration))?;
    }
    for order in &configuration.gpu_assignments {
        current(order.checked.current_at(now, max_age, terms.configuration))?;
        current(order.assigned.current_at(now, max_age, terms.configuration))?;
    }

    let mut failed = BTreeSet::new();
    let mut findings = Vec::new();
    if let Some(comparison) = &configuration.comparison {
        let found = comparison.value().findings_with_internet(
            terms.required.network.channels.contains(&super::NetworkChannel::Internet));
        if !found.is_empty() {
            failed.insert(ConfigurationCheck::GoldenConfiguration);
            findings.extend(found);
        }
    }
    if let Some(listing) = &configuration.listing {
        let found = listing.value().findings();
        if !found.is_empty() {
            failed.insert(ConfigurationCheck::HostInterfaces);
            findings.extend(found);
        }
    }
    if !failed.is_empty() {
        return Err(LaunchRefusal::ConfigurationNotApproved {
            backend: terms.backend.kind,
            checks: failed,
            findings,
        });
    }

    if configuration.gpu_assignments.is_empty() {
        return Ok(());
    }
    match assignment_failure(terms, observed, &configuration.gpu_assignments) {
        None => Ok(()),
        Some(failure) => Err(LaunchRefusal::PropertiesNotSatisfied {
            checks: checks
                .iter()
                .map(|check| {
                    if check.facet() == Facet::DeviceExposure {
                        check.failing(failure.clone())
                    } else {
                        check.clone()
                    }
                })
                .collect(),
        }),
    }
}

/// The first way `orders` do not show every assigned GPU checked before its assignment,
/// in the order of rule 3 of [`judge_configuration`].
fn assignment_failure(
    terms: &Terms<'_>,
    observed: &ObservedProperties,
    orders: &[GpuAssignmentOrder],
) -> Option<CheckFailure> {
    let inventory = observed.devices.value().cloned().unwrap_or_default();
    let exposure = inventory.exposure();
    let named: BTreeSet<_> = orders.iter().map(GpuAssignmentOrder::device).collect();
    if !named.is_subset(&exposure.gpus) {
        return Some(CheckFailure::InventoryDiffersFromProfile {
            profile: terms.device_profile.devices.clone(),
            observed: DeviceExposure {
                paravirtualized_gpu: false,
            display: exposure.display,
                gpus: exposure.gpus.union(&named).copied().collect(),
            },
        });
    }
    for gpu in &inventory.gpus {
        let mut of_gpu = orders.iter().filter(|order| order.device() == gpu.device);
        let (Some(order), None) = (of_gpu.next(), of_gpu.next()) else {
            return Some(CheckFailure::NotCheckedBeforeAssignment { device: gpu.device });
        };
        if !order.checked_before_assignment() {
            return Some(CheckFailure::NotCheckedBeforeAssignment { device: gpu.device });
        }
        let missing = order.missing_before_assignment();
        let unsafe_settings = &order.isolation().unsafe_settings;
        if !missing.is_empty() || !unsafe_settings.is_empty() {
            return Some(CheckFailure::DeviceNotIsolated {
                device: gpu.device,
                missing,
                unsafe_settings: unsafe_settings.clone(),
            });
        }
    }
    None
}

/// Admits a created VM and seals its launch record, or refuses. In order: the hypervisor
/// evidence is bound to this launch and still fresh; where the network facet asks for an
/// independent perimeter, every block rule's host-probe evidence is current now (§4.4);
/// the accelerator was host-observed and is this backend's hardware hypervisor (VM-W22);
/// every host observation is current under the request's configuration; every §1.3 facet
/// is satisfied by host-observed facts; then the record is sealed with the perimeter's
/// evidence beside the hypervisor's. The record binds no configuration facts; a backend
/// that has them admits with [`admit_with_configuration`].
pub fn admit(
    request: &LaunchRequest,
    backend: &BackendIdentity,
    host: &dyn HostEvidence,
    evidence: Satisfied,
    facts: LaunchFacts,
    vm: VmInstanceId,
    restored_from: Option<SnapshotId>,
) -> Result<LaunchRecord, LaunchRefusal> {
    admit_with_configuration(
        request,
        backend,
        host,
        evidence,
        facts,
        ConfigurationFacts::none(),
        vm,
        restored_from,
    )
}

/// [`admit`] with the host's observations of the hypervisor configuration: once every
/// rule of [`admit`] passed, the rules of [`judge_configuration`] judge `configuration`,
/// and the record binds it beside the §1.3 facts. With no configuration facts it is
/// [`admit`], and the record is the one [`admit`] seals, identity included. A backend that
/// admits with them makes them again when it observes the VM again
/// ([`reobserved_with_configuration`](super::reobserved_with_configuration)).
#[allow(clippy::too_many_arguments)]
pub fn admit_with_configuration(
    request: &LaunchRequest,
    backend: &BackendIdentity,
    host: &dyn HostEvidence,
    evidence: Satisfied,
    facts: LaunchFacts,
    configuration: ConfigurationFacts,
    vm: VmInstanceId,
    restored_from: Option<SnapshotId>,
) -> Result<LaunchRecord, LaunchRefusal> {
    let now = host.now();
    let requirement = hypervisor_requirement(request, backend);
    evidence_bound(
        &evidence,
        requirement.subject.identity(),
        request.configuration,
        now,
    )?;

    let perimeter = perimeter_evidence(request, host)?;

    let terms = Terms {
        required: &request.required,
        device_profile: &request.device_profile,
        pinned: &request.pinned,
        configuration: request.configuration,
        backend,
    };
    let (accelerator, checks) = judge(
        &terms,
        now,
        &facts.accelerator,
        &facts.observed,
        &facts.guest,
    )?;
    judge_configuration(&terms, now, &facts.observed, &checks, &configuration)?;
    let ConfigurationFacts {
        comparison,
        listing,
        gpu_assignments,
    } = configuration;

    LaunchRecord::seal(RecordBody {
        sandbox: SandboxBinding {
            execution: request.execution.clone(),
            tenant: request.tenant.clone(),
            generations: request.generations,
        },
        contract: request.contract,
        reservation: request.reservation,
        backend: backend.clone(),
        pinned: request.pinned,
        vm,
        restored_from,
        device_profile: request.device_profile.clone(),
        required: request.required.clone(),
        configuration: request.configuration,
        hypervisor_evidence: evidence,
        perimeter_evidence: perimeter,
        accelerator,
        host_observed: facts.observed,
        configuration_comparison: comparison,
        interface_listing: listing,
        gpu_assignments,
        guest_asserted: facts.guest,
        checks,
        clock: now.session(),
        recorded_at: now.at(),
    })
    .map_err(|error| LaunchRefusal::RecordNotSealed {
        detail: error.to_string(),
    })
}
