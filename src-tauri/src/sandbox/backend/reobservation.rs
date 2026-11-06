//! Observing a running VM again after its launch (§8.1 lines 2433–2439: a probe suite
//! demonstrates named properties at a time, and relevant evidence is re-evaluated; VM-W04
//! row, line 2589: stale evidence is not presented as current; leftover entries H01, S01,
//! M02 and M08: launch-time confinement evidence must not remain current indefinitely, and
//! readiness stays unavailable until the required fresh evidence exists).
//!
//! A [`Reobservation`] is what a backend observed about one running VM when asked again
//! through [`VmBackend::reobserve`](super::VmBackend::reobserve): the launch's CORE-01
//! requirements evaluated again on the registry, and every host fact stamped now. A
//! backend that hands admission the hypervisor configuration facts (VM-CP-02, VM-CP-03 and
//! VM-CP-31; §17 lines 3152, 3153 and 3181) makes them again too
//! ([`reobserved_with_configuration`]). Only [`reobserved`] and
//! [`reobserved_with_configuration`] make one, from the launch's own request and sealed
//! record, so it names that launch. The record judges it with the rules admission applied
//! at launch ([`LaunchRecord::assert_current_with`]); a guest assertion never counts.

use serde::Serialize;

use super::accelerator::Accelerator;
use super::admission::{hypervisor_requirement, perimeter_evidence, LaunchFacts};
use super::configuration::{
    ConfigurationComparison, ConfigurationFacts, GpuAssignmentOrder, HostInterfaceListing,
};
use super::contract::{BackendIdentity, HostEvidence, LaunchRefusal, ReobservationRefusal};
use super::observation::{GuestAssertions, HostFact, HostObserved, ObservedProperties};
use super::record::LaunchRecord;
use super::request::LaunchRequest;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::{ClockSession, Satisfied};
use crate::foundation::ids::{Digest, MonotonicTime};

/// What the host observed again about one running VM, stamped on the evidence clock.
/// Serialize only: a re-observation is never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Reobservation {
    vm: VmInstanceId,
    /// The identity of the launch record this re-observation refreshes.
    record: Digest,
    hypervisor_evidence: Satisfied,
    /// One per block rule of the independent perimeter; empty when none is asked for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    perimeter_evidence: Vec<Satisfied>,
    accelerator: HostFact<Accelerator>,
    host_observed: ObservedProperties,
    /// The golden comparison of the running configuration made again (VM-CP-02); absent
    /// from the serialized form when the backend made none, as before these facts existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration_comparison: Option<HostObserved<ConfigurationComparison>>,
    /// The listing check of the running hypervisor made again (VM-CP-03); absent likewise.
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_listing: Option<HostObserved<HostInterfaceListing>>,
    /// One order of checks and assignment per assigned GPU, made again (VM-CP-31); absent
    /// likewise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    gpu_assignments: Vec<GpuAssignmentOrder>,
    guest_asserted: GuestAssertions,
    clock: ClockSession,
    observed_at: MonotonicTime,
}

impl Reobservation {
    pub fn vm(&self) -> VmInstanceId {
        self.vm
    }

    /// The identity of the launch record it refreshes.
    pub fn record(&self) -> Digest {
        self.record
    }

    /// The CORE-01 host-probe evidence that the hypervisor is available, evaluated again.
    pub fn hypervisor_evidence(&self) -> &Satisfied {
        &self.hypervisor_evidence
    }

    /// The CORE-01 evidence of every block rule of the independent perimeter, evaluated
    /// again, in rule order.
    pub fn perimeter_evidence(&self) -> &[Satisfied] {
        &self.perimeter_evidence
    }

    /// The accelerator the host observed the VM running on now.
    pub fn accelerator(&self) -> &HostFact<Accelerator> {
        &self.accelerator
    }

    /// What the host observed about the boundary now.
    pub fn host_observed(&self) -> &ObservedProperties {
        &self.host_observed
    }

    /// The host's comparison of the running configuration with the launch's golden file
    /// made again (VM-CP-02), when the backend made one.
    pub fn configuration_comparison(&self) -> Option<&HostObserved<ConfigurationComparison>> {
        self.configuration_comparison.as_ref()
    }

    /// The host's listing check of the running hypervisor made again (VM-CP-03), when the
    /// backend made one.
    pub fn interface_listing(&self) -> Option<&HostObserved<HostInterfaceListing>> {
        self.interface_listing.as_ref()
    }

    /// Each assigned GPU's checks and assignment made again (VM-CP-31); empty when the
    /// backend made none.
    pub fn gpu_assignments(&self) -> &[GpuAssignmentOrder] {
        &self.gpu_assignments
    }

    /// The configuration facts made again, as admission takes them.
    pub(super) fn configuration_facts(&self) -> ConfigurationFacts {
        ConfigurationFacts {
            comparison: self.configuration_comparison.clone(),
            listing: self.interface_listing.clone(),
            gpu_assignments: self.gpu_assignments.clone(),
        }
    }

    /// What the guest asserted, recorded apart and never counted.
    pub fn guest_asserted(&self) -> &GuestAssertions {
        &self.guest_asserted
    }

    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }
}

/// The re-observation of the running VM of `record`, launched for `request` on `backend`:
/// the launch's host-only hypervisor requirement and, where the network facet asks for an
/// independent perimeter, every block rule's requirement are evaluated again on `host`
/// (CORE-01), and `facts` are what the host observed of the VM now. Refused when CORE-01
/// refuses a requirement now; the facts themselves are judged by the record. It carries no
/// configuration facts; a backend that makes them again re-observes with
/// [`reobserved_with_configuration`].
pub fn reobserved(
    request: &LaunchRequest,
    record: &LaunchRecord,
    backend: &BackendIdentity,
    host: &dyn HostEvidence,
    facts: LaunchFacts,
) -> Result<Reobservation, ReobservationRefusal> {
    reobserved_with_configuration(
        request,
        record,
        backend,
        host,
        facts,
        ConfigurationFacts::none(),
    )
}

/// [`reobserved`] with the host's observations of the hypervisor configuration made again
/// now, as [`admit_with_configuration`](super::admit_with_configuration) takes them at
/// launch. The record judges them with the rules admission applied to them, and refuses a
/// re-observation without one of them once the record's own has aged
/// ([`LaunchRecord::assert_current_with`]). With no configuration facts it is
/// [`reobserved`].
pub fn reobserved_with_configuration(
    request: &LaunchRequest,
    record: &LaunchRecord,
    backend: &BackendIdentity,
    host: &dyn HostEvidence,
    facts: LaunchFacts,
    configuration: ConfigurationFacts,
) -> Result<Reobservation, ReobservationRefusal> {
    let hypervisor_evidence = host
        .evaluate(&hypervisor_requirement(request, backend))
        .map_err(|refusal| ReobservationRefusal::refused(LaunchRefusal::Evidence { refusal }))?;
    let perimeter_evidence =
        perimeter_evidence(request, host).map_err(ReobservationRefusal::refused)?;
    let now = host.now();
    let ConfigurationFacts {
        comparison,
        listing,
        gpu_assignments,
    } = configuration;
    Ok(Reobservation {
        vm: record.vm(),
        record: record.identity(),
        hypervisor_evidence,
        perimeter_evidence,
        accelerator: facts.accelerator,
        host_observed: facts.observed,
        configuration_comparison: comparison,
        interface_listing: listing,
        gpu_assignments,
        guest_asserted: facts.guest,
        clock: now.session(),
        observed_at: now.at(),
    })
}
