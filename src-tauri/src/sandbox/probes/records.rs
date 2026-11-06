//! Check outcomes from sealed launch records (§8.1, lines 2433–2439; VM-W22, line 2621;
//! VM-W23, line 2622; §17, lines 3145–3188).
//!
//! A backend seals a [`LaunchRecord`] at every admission, with the facts the host observed:
//! the actual accelerator, the confinement controls, the device inventory, the booted
//! image, the configuration and how long each fact stays fresh. [`RecordResults`] turns
//! the records of one backend build on one host, and the backend's typed refusals of
//! controlled negative launches, into [`ProbeOutcome`]s for exactly the check parts they
//! decide:
//!
//! - an observation is decided only from host facts, as [`record_coverage`] lists them per
//!   check: the accelerator a record names, a sealed record as a normal launch, the
//!   generations and handles of records restored from one snapshot, the configuration
//!   facts a record binds when its backend passed them (the golden comparison of VM-CP-02,
//!   the listing check of VM-CP-03, and each assigned GPU's checks and assignment in the
//!   order of VM-CP-31), the outcome of a controlled negative launch, and the host's scans
//!   of its process list (`process_scan`: VM-CP-01's emulated hypervisors when the doctor
//!   examines, VM-CP-33's starts left by a refused launch). A record's guest assertions are
//!   never read;
//! - a part is decided when every observation of it that applies on the host is decided,
//!   or when one decided observation does not hold. Every other part is left out, so it
//!   stays not tested;
//! - a positive control the records do not show is left out too, so the judge keeps the
//!   check inconclusive (§17 line 3147);
//! - each observation keeps the stamps of the facts it was read from, exactly as the host
//!   made them, and nothing is stamped again, so the judge refuses it once any of them is
//!   stale or was observed under another configuration.
//!
//! Most of §17 is out of a record's reach: [`RecordCoverage::leaves`] says why for each
//! check. Nothing here runs a check or touches the host.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::catalog::{catalog, CheckId, ControlledCheck, Part};
use super::expect::{Expectation, ExpectationId, Observed};
use super::outcome::{FactStamp, Observations, ProbeOutcome, RecordRun, StampOrigin};
use super::drill::{ConnectionDrill, DrillCase};
use super::process_scan::{ProcessScan, ScanMoment};
use super::report::CheckInput;
use crate::foundation::coordination::SnapshotId;
use crate::foundation::evidence::{Capability, EvidenceRefusal, HypervisorKind};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox::backend::{
    Accelerator, BackendIdentity, CheckFailure, ConfigurationCheck, ConfigurationComparison,
    ConfigurationFact, Facet, FactName, Feature, GpuIsolationCheck, HostBuild,
    HostInterfaceListing, HostObserved, LaunchRecord, LaunchRefusal,
};

/// The digest domain of a clone's generation identity: its sandbox and boot generation.
pub const CLONE_GENERATION_DOMAIN: &str = "yougori/sandbox/probes/clone-generation/v1";

/// What a controlled negative launch made unavailable or wrong on purpose, in a test build
/// or a test launch (§17 lines 3151, 3153, 3173, 3181 and 3183).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledFault {
    /// The backend's hardware hypervisor forced or simulated unavailable (VM-CP-01,
    /// VM-CP-33).
    HypervisorUnavailable,
    /// The GPU path simulated unavailable for a launch that asks for a GPU (VM-CP-33).
    GpuPathUnavailable,
    /// A one-byte change in the root image the launch boots (VM-CP-23).
    RootImageChanged,
    /// A GPU whose IOMMU group is incomplete (VM-CP-31).
    IncompleteIommuGroup,
    /// A GPU that owns the host display (VM-CP-31).
    DisplayOwningGpu,
    /// A host filesystem share device added to the launch on purpose (VM-CP-03's positive
    /// control).
    PlantedShareDevice,
}

impl ControlledFault {
    pub const ALL: [Self; 6] = [
        Self::HypervisorUnavailable,
        Self::GpuPathUnavailable,
        Self::RootImageChanged,
        Self::IncompleteIommuGroup,
        Self::DisplayOwningGpu,
        Self::PlantedShareDevice,
    ];

    /// Whether the fault needs a launch that asks for a GPU.
    pub const fn needs_gpu(self) -> bool {
        matches!(
            self,
            Self::GpuPathUnavailable | Self::IncompleteIommuGroup | Self::DisplayOwningGpu
        )
    }

    /// Whether `refusal`, from a backend that launches with `hypervisor`, refuses the launch
    /// for this fault's reason. A refusal for any other reason shows nothing about the
    /// fault.
    pub fn refused_for(self, refusal: &LaunchRefusal, hypervisor: HypervisorKind) -> bool {
        match self {
            Self::HypervisorUnavailable => match refusal {
                LaunchRefusal::Evidence {
                    refusal:
                        EvidenceRefusal::Unsupported {
                            capability: Capability::HypervisorAvailable,
                            ..
                        },
                } => true,
                LaunchRefusal::HardwareVirtualizationFailed { failure } => {
                    failure.hypervisor == hypervisor
                }
                LaunchRefusal::UnexpectedAccelerator { expected, .. } => *expected == hypervisor,
                LaunchRefusal::AcceleratorNotObserved { .. }
                | LaunchRefusal::NotHardwareVirtualized { .. } => true,
                _ => false,
            },
            Self::GpuPathUnavailable => match refusal {
                LaunchRefusal::Unsupported { feature } => *feature == Feature::GpuAssignment,
                _ => failed(refusal, Facet::DeviceExposure, |_| true),
            },
            Self::RootImageChanged => failed(refusal, Facet::Evidence, |failure| {
                matches!(failure, CheckFailure::ArtifactMismatch { .. })
            }),
            Self::IncompleteIommuGroup => {
                isolation_missing(refusal, GpuIsolationCheck::CompleteIsolationGroup)
            }
            Self::DisplayOwningGpu => {
                isolation_missing(refusal, GpuIsolationCheck::NoHostDisplayOrOtherUsers)
            }
            Self::PlantedShareDevice => matches!(
                refusal,
                LaunchRefusal::ConfigurationNotApproved { checks, .. }
                    if checks.contains(&ConfigurationCheck::HostInterfaces)
            ),
        }
    }
}

impl fmt::Display for ControlledFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HypervisorUnavailable => "the hardware hypervisor made unavailable",
            Self::GpuPathUnavailable => "the GPU path made unavailable",
            Self::RootImageChanged => "a one-byte change in the root image",
            Self::IncompleteIommuGroup => "a GPU with an incomplete IOMMU group",
            Self::DisplayOwningGpu => "a GPU that owns the host display",
            Self::PlantedShareDevice => "a share device added on purpose",
        })
    }
}

/// Whether `refusal` lists a failed check of `facet` whose failure `matches`.
fn failed(refusal: &LaunchRefusal, facet: Facet, matches: impl Fn(&CheckFailure) -> bool) -> bool {
    refusal.failed_checks().iter().any(|check| {
        check.facet() == facet && check.failure().is_some_and(|failure| matches(failure))
    })
}

/// Whether `refusal` refuses an assigned GPU that lacks `missing` (§7.5).
fn isolation_missing(refusal: &LaunchRefusal, missing: GpuIsolationCheck) -> bool {
    failed(refusal, Facet::DeviceExposure, |failure| match failure {
        CheckFailure::DeviceNotIsolated {
            missing: lacking, ..
        } => lacking.contains(&missing),
        _ => false,
    })
}

/// What a controlled negative launch returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegativeOutcome {
    /// The backend refused, stamped on the evidence clock when the host observed the
    /// refusal, under the configuration the launch was decided under.
    Refused {
        refusal: HostObserved<LaunchRefusal>,
    },
    /// The backend launched anyway and sealed this record: the check's observation does
    /// not hold.
    Launched { record: Box<LaunchRecord> },
}

/// Which part of a record's golden comparison decides an observation of VM-CP-02.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonItem {
    /// The observed configuration's digest against the golden file's.
    GoldenFile,
    NetworkDevice,
    Console,
    Balloon,
    UndeclaredPciTransport,
}

impl ComparisonItem {
    /// The observation `comparison` makes of this item.
    pub fn observed(self, comparison: &ConfigurationComparison) -> Observed {
        let present = |present| Observed::Presence { present };
        match self {
            Self::GoldenFile => Observed::Comparison {
                observed: comparison.observed,
                reference: comparison.golden,
            },
            Self::NetworkDevice => present(comparison.network_device),
            Self::Console => present(comparison.console),
            Self::Balloon => present(comparison.balloon),
            Self::UndeclaredPciTransport => present(comparison.undeclared_pci_transport),
        }
    }
}

/// Which part of a record's listing check decides an observation of VM-CP-03.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListingItem {
    ShareDevice,
    ManagementListener,
    MonitorSocketPrivate,
    OldAgentPortForward,
}

impl ListingItem {
    /// The observation `listing` makes of this item: whether it is present.
    pub fn observed(self, listing: &HostInterfaceListing) -> Observed {
        Observed::Presence {
            present: match self {
                Self::ShareDevice => listing.share_device,
                Self::ManagementListener => listing.management_listener,
                Self::MonitorSocketPrivate => listing.monitor_socket_private,
                Self::OldAgentPortForward => listing.old_agent_port_forward,
            },
        }
    }
}

/// Where records decide one expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum RecordSource {
    /// The accelerator the sealed record of a normal launch names: the one the host
    /// observed the VM running on, never a requested flag (VM-W22).
    RecordedAccelerator,
    /// The sealed record of a normal launch: the launch succeeded and recorded its
    /// accelerator.
    NormalLaunch,
    /// The sandbox and boot generation of each of two or more records restored from one
    /// snapshot, which the host assigns.
    CloneGenerations,
    /// The VM handle of each of two or more records restored from one snapshot, which the
    /// host assigns per boot.
    CloneHandles,
    /// A controlled negative launch with `fault` on a backend that launches with one of
    /// `hypervisors`: a refusal for the fault's reason holds, a sealed record does not.
    NegativeLaunch {
        fault: ControlledFault,
        hypervisors: &'static [HypervisorKind],
    },
    /// `item` of the golden comparison the sealed record of a normal launch binds, when its
    /// backend passed one (VM-CP-02).
    RecordedComparison { item: ComparisonItem },
    /// `item` of the listing check the sealed record of a normal launch binds, when its
    /// backend passed one (VM-CP-03).
    RecordedListing { item: ListingItem },
    /// The order of each assigned GPU's checks and its assignment that the sealed record of
    /// a normal launch with a GPU binds, when its backend passed them (VM-CP-31): present
    /// when every assigned GPU's order shows `check` made, and passing, before its
    /// assignment.
    RecordedGpuOrder { check: GpuIsolationCheck },
    /// A controlled negative launch with `fault` whose refusal is the check detecting it,
    /// on a backend that launches with one of `hypervisors`: a refusal for the fault's
    /// reason is the detection, a sealed record shows none.
    NegativeDetection {
        fault: ControlledFault,
        hypervisors: &'static [HypervisorKind],
    },
    /// The host's scan of its process list taken when the doctor examined: whether any
    /// hypervisor runs emulated (VM-CP-01); decided only when every hypervisor's command
    /// line was read.
    ExaminationScan,
    /// The host's scans of its process list taken right after the backend refused a
    /// controlled negative launch with one of `faults`, each against the list taken right
    /// before the attempt: whether a start of the refused launch still runs (VM-CP-33).
    FallbackScan {
        faults: &'static [ControlledFault],
    },
    /// The host's observations of `case` in a connection drill (VM-CP-29): whether the attempt
    /// was refused with nothing asked of the callee.
    DrillAttempt { case: DrillCase },
    /// Whether a connection drill's VMs shared host state (VM-CP-29).
    DrillSharedState,
}

/// One expectation records decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RecordDecision {
    pub expectation: ExpectationId,
    pub source: RecordSource,
}

/// What records decide of one check, and why they decide nothing more. The plan gives no
/// such map; this is the module's reading of §17 and the expectation table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RecordCoverage {
    pub check: CheckId,
    /// The expectations records decide, in table order; empty when none.
    pub decides: &'static [RecordDecision],
    /// What records cannot decide of the check, and why.
    pub leaves: &'static str,
}

/// Every check's entry, in table order.
pub fn record_coverage() -> &'static [RecordCoverage] {
    &RECORD_COVERAGE
}

/// The entry of `check`. The map is in row order and `CheckId` is a row number by
/// construction; the record coverage test checks both.
pub fn record_coverage_of(check: CheckId) -> &'static RecordCoverage {
    &RECORD_COVERAGE[usize::from(check.number().clamp(CheckId::FIRST, CheckId::LAST) - 1)]
}

/// Where records decide `id`, if they do.
pub fn record_source(id: ExpectationId) -> Option<RecordSource> {
    RECORD_COVERAGE
        .iter()
        .flat_map(|entry| entry.decides)
        .find(|decision| decision.expectation == id)
        .map(|decision| decision.source)
}

/// Why records, or the inputs given for them, were not taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum RecordInputError {
    /// The record was sealed by another backend build than these results are about.
    OtherBackend { record: Digest },
    /// The record's host-observed build is not the host these results are about, or the
    /// host observed none.
    OtherHost { record: Digest },
    /// The record was given before.
    Duplicate { record: Digest },
    /// The controlled negative launch was refused for another reason than its fault, so it
    /// shows nothing about the fault.
    NotRefusedForFault { fault: ControlledFault },
    /// The controlled negative launch of a GPU fault was sealed without an assigned GPU,
    /// so it did not exercise the fault.
    FaultNotExercised {
        fault: ControlledFault,
        record: Digest,
    },
}

impl fmt::Display for RecordInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherBackend { record } => write!(
                f,
                "launch record {record} was sealed by another backend build"
            ),
            Self::OtherHost { record } => write!(
                f,
                "launch record {record} does not show this host's observed build"
            ),
            Self::Duplicate { record } => write!(f, "launch record {record} was given twice"),
            Self::NotRefusedForFault { fault } => write!(
                f,
                "the launch with {fault} was refused for another reason, so it shows nothing about it"
            ),
            Self::FaultNotExercised { fault, record } => write!(
                f,
                "the launch with {fault} sealed record {record} without an assigned GPU, so it did not exercise it"
            ),
        }
    }
}

impl std::error::Error for RecordInputError {}

/// One decided observation and the stamps of the facts it was read from.
#[derive(Clone)]
struct Decided {
    observed: Observed,
    read_from: Vec<FactStamp>,
}

/// The sealed launch records of one backend build on one host and the outcomes of its
/// controlled negative launches, as check results. Records and negative launches are kept
/// in the order given, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordResults {
    host: HostBuild,
    backend: BackendIdentity,
    normal: Vec<LaunchRecord>,
    negative: Vec<(ControlledFault, NegativeOutcome)>,
    scans: Vec<HostObserved<ProcessScan>>,
    drills: Vec<HostObserved<ConnectionDrill>>,
}

impl RecordResults {
    /// No records yet of `backend` on `host`.
    pub fn new(host: HostBuild, backend: BackendIdentity) -> Self {
        Self {
            host,
            backend,
            normal: Vec::new(),
            negative: Vec::new(),
            scans: Vec::new(),
            drills: Vec::new(),
        }
    }

    pub fn host(&self) -> &HostBuild {
        &self.host
    }

    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// How many sealed records of normal launches were given.
    pub fn normal_launches(&self) -> usize {
        self.normal.len()
    }

    /// How many controlled negative launches were given.
    pub fn negative_launches(&self) -> usize {
        self.negative.len()
    }

    /// Takes a host scan of the process list (`process_scan`), as the host stamped it.
    pub fn scan(&mut self, scan: HostObserved<ProcessScan>) {
        self.scans.push(scan);
    }

    /// How many process-list scans were given.
    pub fn process_scans(&self) -> usize {
        self.scans.len()
    }

    /// Takes the host's observations of a connection drill (`drill`), as the host stamped them.
    pub fn drill(&mut self, drill: HostObserved<ConnectionDrill>) {
        self.drills.push(drill);
    }

    /// How many connection drills were given.
    pub fn connection_drills(&self) -> usize {
        self.drills.len()
    }

    /// Takes the sealed record of a normal launch: one of this backend build, on this host,
    /// not given before.
    pub fn record(&mut self, record: LaunchRecord) -> Result<(), RecordInputError> {
        self.admissible(&record)?;
        self.normal.push(record);
        Ok(())
    }

    /// Takes a controlled negative launch with `fault`: a refusal for the fault's reason,
    /// or the record the backend sealed anyway. A refusal for another reason, or a sealed
    /// GPU fault launch without an assigned GPU, shows nothing about the fault and is
    /// refused.
    pub fn negative(
        &mut self,
        fault: ControlledFault,
        outcome: NegativeOutcome,
    ) -> Result<(), RecordInputError> {
        match &outcome {
            NegativeOutcome::Refused { refusal } => {
                if !fault.refused_for(refusal.value(), self.backend.hypervisor) {
                    return Err(RecordInputError::NotRefusedForFault { fault });
                }
            }
            NegativeOutcome::Launched { record } => {
                self.admissible(record)?;
                if fault.needs_gpu() && record.device_profile().devices.gpus.is_empty() {
                    return Err(RecordInputError::FaultNotExercised {
                        fault,
                        record: record.identity(),
                    });
                }
            }
        }
        self.negative.push((fault, outcome));
        Ok(())
    }

    /// The outcomes of every part the records decide, by check, in table order. A check
    /// or part they do not decide is absent.
    pub fn outcomes(&self) -> BTreeMap<CheckId, Vec<ProbeOutcome>> {
        let mut outcomes = BTreeMap::new();
        for row in catalog() {
            let decides = record_coverage_of(row.id).decides;
            if decides.is_empty() || !row.runs_on(self.host.os) {
                continue;
            }
            let parts: Vec<ProbeOutcome> = row
                .parts()
                .into_iter()
                .filter_map(|part| {
                    let run = self.part_run(row, part, decides)?;
                    ProbeOutcome::from_records(row.id, part, run).ok()
                })
                .collect();
            if !parts.is_empty() {
                outcomes.insert(row.id, parts);
            }
        }
        outcomes
    }

    /// [`RecordResults::outcomes`] as boundary report inputs.
    pub fn inputs(&self) -> BTreeMap<CheckId, CheckInput> {
        self.outcomes()
            .into_iter()
            .map(|(check_id, outcomes)| (check_id, CheckInput::Outcomes(outcomes)))
            .collect()
    }

    fn admissible(&self, record: &LaunchRecord) -> Result<(), RecordInputError> {
        let identity = record.identity();
        if *record.backend() != self.backend {
            return Err(RecordInputError::OtherBackend { record: identity });
        }
        if record.host_observed().host.value() != Some(&self.host) {
            return Err(RecordInputError::OtherHost { record: identity });
        }
        let mut given = self.normal.iter().chain(self.negative.iter().filter_map(
            |(_, outcome)| match outcome {
                NegativeOutcome::Launched { record } => Some(record.as_ref()),
                NegativeOutcome::Refused { .. } => None,
            },
        ));
        if given.any(|seen| seen.identity() == identity) {
            return Err(RecordInputError::Duplicate { record: identity });
        }
        Ok(())
    }

    /// The record run of `part` of `row`, when the records decide the part.
    fn part_run(
        &self,
        row: &ControlledCheck,
        part: Part,
        decides: &[RecordDecision],
    ) -> Option<RecordRun> {
        let source_of = |id: ExpectationId| {
            decides
                .iter()
                .find(|decision| decision.expectation == id)
                .map(|decision| decision.source)
        };
        let mut observations = Observations::new();
        let mut read_from = BTreeMap::new();
        let mut applicable = 0usize;
        let mut violated = false;
        for entry in row.observations_for(part, self.host.os) {
            applicable += 1;
            if let Some(found) = source_of(entry.id).and_then(|source| self.decide(entry, source)) {
                violated |= matches!(entry.expect.holds(&found.observed), Ok(false));
                observations.insert(entry.id, found.observed);
                read_from.insert(entry.id, found.read_from);
            }
        }
        if observations.is_empty() || (observations.len() < applicable && !violated) {
            return None;
        }
        if let Some(control) = row.control().filter(|control| control.part == part) {
            if let Some(found) =
                source_of(control.id).and_then(|source| self.decide(control, source))
            {
                observations.insert(control.id, found.observed);
                read_from.insert(control.id, found.read_from);
            }
        }
        Some(RecordRun::new(
            self.backend.clone(),
            self.host.clone(),
            observations,
            read_from,
        ))
    }

    /// What the records show for `entry`, read from `source`.
    fn decide(&self, entry: &Expectation, source: RecordSource) -> Option<Decided> {
        match source {
            RecordSource::RecordedAccelerator => pick(
                entry,
                self.normal.iter().map(|record| Decided {
                    observed: Observed::Value {
                        value: accelerator_tag(*record.accelerator().value()).to_owned(),
                    },
                    read_from: vec![accelerator_stamp(record)],
                }),
            ),
            RecordSource::NormalLaunch => self.normal.last().map(|record| Decided {
                observed: Observed::Attempt { refused: false },
                read_from: vec![accelerator_stamp(record)],
            }),
            RecordSource::CloneGenerations => self.clones(entry, generation_identity),
            RecordSource::CloneHandles => self.clones(entry, |record| record.vm().digest()),
            RecordSource::NegativeLaunch { fault, hypervisors } => {
                self.negatives(entry, fault, hypervisors, |refused| Observed::Attempt {
                    refused,
                })
            }
            RecordSource::NegativeDetection { fault, hypervisors } => {
                self.negatives(entry, fault, hypervisors, |refused| Observed::Event {
                    happened: refused,
                })
            }
            RecordSource::RecordedComparison { item } => pick(
                entry,
                self.normal.iter().filter_map(|record| {
                    let comparison = record.configuration_comparison()?;
                    Some(Decided {
                        observed: item.observed(comparison.value()),
                        read_from: vec![configuration_stamp(
                            record,
                            ConfigurationFact::Comparison,
                            comparison,
                        )],
                    })
                }),
            ),
            RecordSource::RecordedListing { item } => pick(
                entry,
                self.normal.iter().filter_map(|record| {
                    let listing = record.interface_listing()?;
                    Some(Decided {
                        observed: item.observed(listing.value()),
                        read_from: vec![configuration_stamp(
                            record,
                            ConfigurationFact::Listing,
                            listing,
                        )],
                    })
                }),
            ),
            RecordSource::RecordedGpuOrder { check } => pick(
                entry,
                self.normal
                    .iter()
                    .filter_map(|record| gpu_order(record, check)),
            ),
            RecordSource::ExaminationScan => pick(
                entry,
                self.scans.iter().filter_map(|scan| {
                    if scan.value().moment != ScanMoment::Examination {
                        return None;
                    }
                    let present = scan.value().emulated_hypervisor()?;
                    Some(Decided {
                        observed: Observed::Presence { present },
                        read_from: vec![FactStamp::of(
                            StampOrigin::ProcessScan {
                                moment: ScanMoment::Examination,
                            },
                            scan,
                        )],
                    })
                }),
            ),
            RecordSource::DrillAttempt { case } => pick(
                entry,
                self.drills.iter().filter_map(|drill| {
                    let refused = drill.value().attempts.get(&case)?.refused()?;
                    Some(Decided {
                        observed: Observed::Attempt { refused },
                        read_from: vec![FactStamp::of(StampOrigin::ConnectionDrill, drill)],
                    })
                }),
            ),
            RecordSource::DrillSharedState => pick(
                entry,
                self.drills.iter().filter_map(|drill| {
                    let present = drill.value().shared_state?;
                    Some(Decided {
                        observed: Observed::Presence { present },
                        read_from: vec![FactStamp::of(StampOrigin::ConnectionDrill, drill)],
                    })
                }),
            ),
            RecordSource::FallbackScan { faults } => pick(
                entry,
                self.scans.iter().filter_map(|scan| {
                    let moment = scan.value().moment;
                    match moment {
                        ScanMoment::AfterRefusal { fault } if faults.contains(&fault) => {}
                        _ => return None,
                    }
                    let present = scan.value().fallback_started()?;
                    Some(Decided {
                        observed: Observed::Presence { present },
                        read_from: vec![FactStamp::of(StampOrigin::ProcessScan { moment }, scan)],
                    })
                }),
            ),
        }
    }

    /// What the controlled negative launches with `fault` show, each as `observed` makes
    /// it from whether the launch was refused for the fault's reason; nothing when the
    /// backend launches with none of `hypervisors`.
    fn negatives(
        &self,
        entry: &Expectation,
        fault: ControlledFault,
        hypervisors: &[HypervisorKind],
        observed: fn(bool) -> Observed,
    ) -> Option<Decided> {
        if !hypervisors.contains(&self.backend.hypervisor) {
            return None;
        }
        pick(
            entry,
            self.negative
                .iter()
                .filter(|(tried, _)| *tried == fault)
                .map(|(_, outcome)| match outcome {
                    NegativeOutcome::Refused { refusal } => Decided {
                        observed: observed(true),
                        read_from: vec![FactStamp::of(StampOrigin::Refusal { fault }, refusal)],
                    },
                    NegativeOutcome::Launched { record } => Decided {
                        observed: observed(false),
                        read_from: vec![accelerator_stamp(record)],
                    },
                }),
        )
    }

    /// The identities `identity_of` gives each record of a snapshot restored at least
    /// twice, for one such snapshot.
    fn clones(
        &self,
        entry: &Expectation,
        identity_of: fn(&LaunchRecord) -> Digest,
    ) -> Option<Decided> {
        let mut restored: BTreeMap<SnapshotId, Vec<&LaunchRecord>> = BTreeMap::new();
        for record in &self.normal {
            if let Some(snapshot) = record.restored_from() {
                restored.entry(snapshot).or_default().push(record);
            }
        }
        pick(
            entry,
            restored
                .values()
                .filter(|clones| clones.len() >= 2)
                .map(|clones| Decided {
                    observed: Observed::Identities {
                        values: clones.iter().map(|record| identity_of(record)).collect(),
                    },
                    read_from: clones
                        .iter()
                        .map(|record| accelerator_stamp(record))
                        .collect(),
                }),
        )
    }
}

/// Of several readings of one observation, the last that does not hold, so a conclusive
/// failure is never hidden by a later pass; otherwise the last one.
fn pick(entry: &Expectation, readings: impl Iterator<Item = Decided>) -> Option<Decided> {
    let mut last = None;
    let mut failing = None;
    for reading in readings {
        if matches!(entry.expect.holds(&reading.observed), Ok(false)) {
            failing = Some(reading.clone());
        }
        last = Some(reading);
    }
    failing.or(last)
}

/// The stamp of the record's accelerator: when the host observed the VM running on it,
/// which dates the launch and is never later than the record.
fn accelerator_stamp(record: &LaunchRecord) -> FactStamp {
    FactStamp::of(
        StampOrigin::Record {
            record: record.identity(),
            fact: FactName::Accelerator,
        },
        record.accelerator(),
    )
}

/// The stamp of a configuration fact of the record, exactly as the host made it.
fn configuration_stamp<T>(
    record: &LaunchRecord,
    fact: ConfigurationFact,
    observed: &HostObserved<T>,
) -> FactStamp {
    FactStamp::of(
        StampOrigin::RecordConfiguration {
            record: record.identity(),
            fact,
        },
        observed,
    )
}

/// What the record shows of `check` before the assignment of its GPUs: nothing for a
/// record without an assigned GPU or without the orders; otherwise present when every
/// assigned GPU has an order that shows `check` made, and passing, before its
/// assignment, read from the stamps of every order.
fn gpu_order(record: &LaunchRecord, check: GpuIsolationCheck) -> Option<Decided> {
    let orders = record.gpu_assignments();
    let assigned = &record.host_observed().devices.value()?.gpus;
    if assigned.is_empty() || orders.is_empty() {
        return None;
    }
    let present = assigned.iter().all(|gpu| {
        orders
            .iter()
            .any(|order| order.device() == gpu.device && order.shows_before_assignment(check))
    });
    let read_from = orders
        .iter()
        .flat_map(|order| {
            let device = order.device();
            [
                configuration_stamp(
                    record,
                    ConfigurationFact::GpuChecked { device },
                    &order.checked,
                ),
                configuration_stamp(
                    record,
                    ConfigurationFact::GpuAssigned { device },
                    &order.assigned,
                ),
            ]
        })
        .collect();
    Some(Decided {
        observed: Observed::Presence { present },
        read_from,
    })
}

/// The name VM-CP-01 gives an accelerator.
fn accelerator_tag(accelerator: Accelerator) -> &'static str {
    match accelerator {
        Accelerator::Hardware { hypervisor } => hypervisor.tag(),
        Accelerator::Emulation { emulator } => emulator.tag(),
    }
}

/// A clone's generation identity: its sandbox and boot generation.
fn generation_identity(record: &LaunchRecord) -> Digest {
    let sandbox = record.sandbox();
    DigestBuilder::new(CLONE_GENERATION_DOMAIN)
        .str(sandbox.execution.as_str())
        .u64(sandbox.generations.boot.get())
        .finish()
}

const fn decision(expectation: &'static str, source: RecordSource) -> RecordDecision {
    RecordDecision {
        expectation: ExpectationId::of(expectation),
        source,
    }
}

const fn negative(fault: ControlledFault, hypervisors: &'static [HypervisorKind]) -> RecordSource {
    RecordSource::NegativeLaunch { fault, hypervisors }
}

const fn none(number: u8, reason: &'static str) -> RecordCoverage {
    deciding(number, &[], reason)
}

const fn deciding(
    number: u8,
    decisions: &'static [RecordDecision],
    reason: &'static str,
) -> RecordCoverage {
    RecordCoverage {
        check: CheckId::of(number),
        decides: decisions,
        leaves: reason,
    }
}

const ANY_HYPERVISOR: &[HypervisorKind] = &HypervisorKind::ALL;

/// Why a test of Yougori's own host code is out of a record's reach.
const OWN_CODE: &str = "It tests Yougori's own host code on a corpus, a fake provider or a \
    drill; no launch record holds what it observes.";

const fn comparison(item: ComparisonItem) -> RecordSource {
    RecordSource::RecordedComparison { item }
}

const fn listing(item: ListingItem) -> RecordSource {
    RecordSource::RecordedListing { item }
}

const fn before_assignment(check: GpuIsolationCheck) -> RecordSource {
    RecordSource::RecordedGpuOrder { check }
}

use ControlledFault::{
    DisplayOwningGpu, GpuPathUnavailable, HypervisorUnavailable, IncompleteIommuGroup,
    PlantedShareDevice, RootImageChanged,
};
use RecordSource::{CloneGenerations, CloneHandles, NormalLaunch, RecordedAccelerator};

/// The map, in row order (§17 lines 3151–3185).
static RECORD_COVERAGE: [RecordCoverage; 35] = [
    deciding(
        1,
        &[
            decision("cp01.accelerator", RecordedAccelerator),
            decision(
                "cp01.forced-unavailable-refused",
                negative(HypervisorUnavailable, ANY_HYPERVISOR),
            ),
            decision("cp01.no-tcg-hypervisor", RecordSource::ExaminationScan),
            decision("cp01.normal-launch-records-accelerator", NormalLaunch),
        ],
        "The process list is the host's scan taken when the doctor examines, not a record's \
         CORE-01 conclusion; it decides nothing while a hypervisor's command line cannot be \
         read.",
    ),
    deciding(
        2,
        &[
            decision(
                "cp02.golden-configuration",
                comparison(ComparisonItem::GoldenFile),
            ),
            decision(
                "cp02.network-device",
                comparison(ComparisonItem::NetworkDevice),
            ),
            decision("cp02.console", comparison(ComparisonItem::Console)),
            decision("cp02.balloon", comparison(ComparisonItem::Balloon)),
            decision(
                "cp02.undeclared-pci-transport",
                comparison(ComparisonItem::UndeclaredPciTransport),
            ),
        ],
        "Only a record whose backend passed its golden comparison to admission decides it; \
         the records of a backend that passes none leave it not tested. The row lists no \
         positive control: the golden file is versioned with the backend, whose build the \
         record binds.",
    ),
    deciding(
        3,
        &[
            decision(
                "cp03.shared-filesystem-device",
                listing(ListingItem::ShareDevice),
            ),
            decision(
                "cp03.management-tcp-listener",
                listing(ListingItem::ManagementListener),
            ),
            decision(
                "cp03.qmp-socket-private",
                listing(ListingItem::MonitorSocketPrivate),
            ),
            decision(
                "cp03.old-agent-port-forward",
                listing(ListingItem::OldAgentPortForward),
            ),
            decision(
                "cp03.planted-share-device-detected",
                RecordSource::NegativeDetection {
                    fault: PlantedShareDevice,
                    hypervisors: ANY_HYPERVISOR,
                },
            ),
        ],
        "Only a record whose backend passed its listing check to admission decides the \
         observations, and the control needs a test launch with a share device added on \
         purpose that the backend refused as failing the host interface check.",
    ),
    none(
        4,
        "A record states the confinement controls as categories; the check names exact \
         process state (uid, NoNewPrivs, Seccomp, namespace, cgroup and descriptor count, \
         token and Job, the helper's profile).",
    ),
    none(
        5,
        "The primary part is guest-reported, and a record's guest assertions are never used. \
         A record compares the host-observed booted image with the pinned one, not with the \
         signed manifest, and holds no kernel build record.",
    ),
    none(
        6,
        "Controlled external: the guest's connections and the controlled listeners are not in \
         a record.",
    ),
    none(
        7,
        "The transport broker's resolver harness observes it, not a launch.",
    ),
    none(
        8,
        "The address normalizer's corpus observes it, not a launch.",
    ),
    none(
        9,
        "The guest's refusals are guest-reported, and a record's network authority is the \
         channels the host enforces, not an observation that no packet left the VM.",
    ),
    none(10, OWN_CODE),
    none(
        11,
        "A record binds the perimeter's CORE-01 evidence when one is required, which is a \
         conclusion; the check's own observations and its control are not in it.",
    ),
    none(
        12,
        "A record's credential exposure is the kinds the host found exposed, not a scan of \
         the named locations for a fixture value.",
    ),
    none(13, OWN_CODE),
    none(14, OWN_CODE),
    none(15, OWN_CODE),
    none(16, OWN_CODE),
    none(
        17,
        "A record compares the booted image with the pinned one, not with the signed base, \
         and holds the attached volumes, not the persisted inventory of the writable paths \
         that survived.",
    ),
    none(18, OWN_CODE),
    none(19, OWN_CODE),
    none(
        20,
        "A stress drill from inside the guest; a record holds no reservation use.",
    ),
    deciding(
        21,
        &[
            decision("cp21.generation-ids", CloneGenerations),
            decision("cp21.boot-ids", CloneHandles),
        ],
        "The canary values and application identifiers are guest-reported, and the refusal of \
         a pre-snapshot approval is the executor's, so neither is in a record.",
    ),
    none(22, OWN_CODE),
    deciding(
        23,
        &[decision(
            "cp23.root-image-byte-change",
            negative(RootImageChanged, ANY_HYPERVISOR),
        )],
        "An unsigned manifest, expired metadata, a rolled-back version and a mixed-version set \
         are refused before a launch request exists, and a record shows the pinned set \
         launched, not that it is the signed set the control names.",
    ),
    none(
        24,
        "End to end on the authorized disposable environment; no record holds a workflow.",
    ),
    none(
        25,
        "The link parser's corpus and CORE-01's source floors observe it, not a launch.",
    ),
    none(26, OWN_CODE),
    none(27, OWN_CODE),
    none(28, OWN_CODE),
    deciding(
        29,
        &[
            decision("cp29.ungranted-connection", RecordSource::DrillAttempt { case: DrillCase::Ungranted }),
            decision("cp29.shared-caches-and-volumes", RecordSource::DrillSharedState),
            decision("cp29.granted-port", RecordSource::DrillAttempt { case: DrillCase::Granted }),
            decision("cp29.other-ports", RecordSource::DrillAttempt { case: DrillCase::OtherService }),
            decision("cp29.expired-grant", RecordSource::DrillAttempt { case: DrillCase::Expired }),
            decision("cp29.revoked-grant", RecordSource::DrillAttempt { case: DrillCase::Revoked }),
            decision("cp29.transitive-connection", RecordSource::DrillAttempt { case: DrillCase::Transitive }),
            decision("cp29.second-grant-passes", RecordSource::DrillAttempt { case: DrillCase::TransitiveControl }),
        ],
        "A connection drill's host observations decide it (`yougori sandbox drill vm-cp-29`: three \
         throwaway VMs the drill launches and stops); a record is one launch and holds none.",
    ),
    none(30, OWN_CODE),
    deciding(
        31,
        &[
            decision(
                "cp31.incomplete-iommu-group",
                negative(IncompleteIommuGroup, ANY_HYPERVISOR),
            ),
            decision(
                "cp31.display-owning-gpu",
                negative(DisplayOwningGpu, ANY_HYPERVISOR),
            ),
            decision(
                "cp31.reset-capability-checked",
                before_assignment(GpuIsolationCheck::SafeResetAndReassignment),
            ),
            decision(
                "cp31.acs-state-checked",
                before_assignment(GpuIsolationCheck::NoUnsafeAcsOrIommuBypass),
            ),
        ],
        "The checks before assignment are decided only by a record whose backend passed each \
         assigned GPU's checks and assignment to admission. The control needs nvidia-smi to \
         run in the guest, which no record holds, so records alone never pass the check. \
         Only a Linux host runs it.",
    ),
    none(
        32,
        "Remote leases and attestation fixtures; no remote or confidential platform is in a \
         record.",
    ),
    deciding(
        33,
        &[
            decision(
                "cp33.linux.kvm-unavailable",
                negative(HypervisorUnavailable, &[HypervisorKind::Kvm]),
            ),
            decision(
                "cp33.windows.whpx-unavailable",
                negative(HypervisorUnavailable, &[HypervisorKind::Whpx]),
            ),
            decision(
                "cp33.macos.framework-unavailable",
                negative(
                    HypervisorUnavailable,
                    &[HypervisorKind::Hvf, HypervisorKind::Vz],
                ),
            ),
            decision(
                "cp33.gpu-path-unavailable",
                negative(GpuPathUnavailable, ANY_HYPERVISOR),
            ),
            decision(
                "cp33.fallback-start",
                RecordSource::FallbackScan {
                    faults: &[HypervisorUnavailable, GpuPathUnavailable],
                },
            ),
        ],
        "The process list after a refusal is the host's scan taken right after it, against the \
         list taken right before the attempt; a scan without that earlier list decides \
         nothing.",
    ),
    none(34, "A research-tier comparison; no record holds it."),
    none(
        35,
        "Host policy over templates and the doctor's own reporting; no record holds them.",
    ),
];
