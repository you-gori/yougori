//! The VM backend contract (VM-W16 row, line 2615): launch, stop, optional snapshot and
//! restore, queries for the actual accelerator and the confinement evidence, a
//! re-observation of a running VM, a stable VM handle and typed refusals. Real backends
//! (VM-W17–VM-W21, lines 2616–2620) implement it; [`FakeBackend`](super::FakeBackend) is
//! the fake backend of VM-W16.
//!
//! No fallback may weaken a required property, and every unsupported feature is an
//! explicit refusal naming the feature (VM-W16 acceptance). Developer emulation is a
//! separate trait, [`DeveloperEmulation`], so nothing reached through
//! [`VmBackend::launch`] can retry into emulation (§1.3 line 1910; VM-W22 row, line
//! 2621).
//!
//! A real backend's refusal is stated by what the host observed: a profile or layout
//! that cannot provide the launch, a hypervisor configuration that is not the approved
//! profile (VM-CP-02, VM-CP-03, lines 3152–3153), confinement restrictions not in effect
//! (VM-CP-04, line 3154), a hypervisor process that ended or is not running, or a
//! backend-specific refusal; and a refused launch whose cleanup is incomplete says what
//! is left ([`LaunchRefusal::CleanupIncomplete`]) and never claims that nothing is.
//! [`VmBackend::reobserve`] observes a running VM again after launch, so launch-time
//! evidence does not stay current indefinitely (§8.1 line 2439: re-evaluate relevant
//! evidence; [`LaunchRecord::assert_current_with`]).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::accelerator::{Accelerator, Emulator, HardwareFailure};
use super::checks::RequiredCheck;
use super::observation::{HostObserved, ObservationProblem, ObservedProperties};
use super::record::LaunchRecord;
use super::reobservation::Reobservation;
use super::request::{EmulationRequest, LaunchRequest};
use crate::foundation::coordination::{
    RestoreRefusal, RestoredVmReport, SnapshotDefect, SnapshotManifest, SnapshotOrigin,
    VerifiedRestore, VmInstanceId,
};
use crate::foundation::evidence::{
    BackendVersion, Capability, ClockReading, ConfigurationFingerprint, EvidenceRefusal,
    HypervisorKind, PerimeterRuleSubject, ProbeRegistry, Requirement, Satisfied, SourceClass,
    UnknownReason, VersionError,
};
use crate::foundation::ids::{Clock, Digest, ExecutionId, SandboxBootGeneration};

/// The backend implementations the plan names (§10.3 lines 2613–2618) and the fake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// The scripted fake of VM-W16. It certifies nothing (S2 line 206: a shared contract
    /// can be developed against fakes; it cannot certify a real backend).
    Fake,
    /// The Linux reference backend (VM-W17).
    Firecracker,
    /// The validated QEMU profile (VM-W19).
    Qemu,
    /// The GPU VM backend's hypervisor (VM-W18; §7.5).
    CloudHypervisor,
    /// Windows Host Compute Service (VM-W20).
    Hcs,
    /// macOS Virtualization.framework (VM-W21).
    VirtualizationFramework,
}

impl BackendKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Fake => "fake",
            Self::Firecracker => "firecracker",
            Self::Qemu => "qemu",
            Self::CloudHypervisor => "cloud_hypervisor",
            Self::Hcs => "hcs",
            Self::VirtualizationFramework => "virtualization_framework",
        }
    }

    pub const fn is_fake(self) -> bool {
        matches!(self, Self::Fake)
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fake => "fake backend",
            Self::Firecracker => "Firecracker",
            Self::Qemu => "QEMU",
            Self::CloudHypervisor => "Cloud Hypervisor",
            Self::Hcs => "Host Compute Service",
            Self::VirtualizationFramework => "Virtualization.framework",
        })
    }
}

/// One backend build: its kind, exact version, artifact identity and the hypervisor
/// interface it launches with (§1.3 evidence facet, line 1906; §7.1 line 2360).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    pub kind: BackendKind,
    pub version: BackendVersion,
    /// The identity of the backend's own build artifact; a launch pinned to another is
    /// refused.
    pub artifact: Digest,
    /// The hardware hypervisor interface this backend uses.
    pub hypervisor: HypervisorKind,
}

impl BackendIdentity {
    pub fn new(
        kind: BackendKind,
        version: &str,
        artifact: Digest,
        hypervisor: HypervisorKind,
    ) -> Result<Self, VersionError> {
        Ok(Self {
            kind,
            version: BackendVersion::new(version)?,
            artifact,
            hypervisor,
        })
    }
}

impl fmt::Display for BackendIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} on {}", self.kind, self.version, self.hypervisor)
    }
}

/// A feature a backend may or may not offer. A request for one the backend lacks is
/// refused by name, never substituted (VM-W16 acceptance).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Snapshot,
    Restore,
    /// The separate non-sandbox facility of §1.3 line 1910.
    DeveloperEmulation,
    /// Explicit GPU assignment with §7.5 isolation evidence (VM-W18).
    GpuAssignment,
    /// Shared GPU-PV through the Windows GPU scheduler; not an exclusively assigned PCI device.
    GpuParavirtualization,
    Display,
    /// A verified confidential VM (§1.3 line 1905).
    ConfidentialVm,
    /// A dedicated physical host (§1.3 line 1899).
    DedicatedHost,
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Snapshot => "snapshots",
            Self::Restore => "snapshot restore",
            Self::DeveloperEmulation => "developer emulation",
            Self::GpuAssignment => "GPU assignment",
            Self::GpuParavirtualization => "shared GPU acceleration",
            Self::Display => "a display device",
            Self::ConfidentialVm => "confidential VMs",
            Self::DedicatedHost => "a dedicated physical host",
        })
    }
}

/// The features one backend offers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendFeatures {
    pub supported: BTreeSet<Feature>,
}

impl BackendFeatures {
    /// Launch and stop only.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn of(features: impl IntoIterator<Item = Feature>) -> Self {
        Self {
            supported: features.into_iter().collect(),
        }
    }

    pub fn supports(&self, feature: Feature) -> bool {
        self.supported.contains(&feature)
    }

    /// `Ok` if `feature` is offered, otherwise the refusal naming it.
    pub fn require(&self, feature: Feature) -> Result<(), LaunchRefusal> {
        if self.supports(feature) {
            Ok(())
        } else {
            Err(LaunchRefusal::Unsupported { feature })
        }
    }
}

/// The host's evidence and clock, as a backend sees them: the CORE-01 probe registry.
/// A backend judges requirements and dates its own observations through this port only,
/// so every fact in a launch record is on the clock that judges its freshness.
pub trait HostEvidence {
    /// The current reading of the evidence clock.
    fn now(&self) -> ClockReading;

    /// Evaluates `requirement` against the host's stored evidence (CORE-01).
    fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal>;
}

impl<C: Clock> HostEvidence for ProbeRegistry<C> {
    fn now(&self) -> ClockReading {
        ProbeRegistry::now(self)
    }

    fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        ProbeRegistry::evaluate(self, requirement)
    }
}

/// A launched VM: its stable handle and the sealed launch record (§8.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Launched {
    pub vm: VmInstanceId,
    pub record: LaunchRecord,
}

/// A VM restored from a snapshot into a fresh generation, verified before it may receive
/// authority (VM part §6.6; S10 line 353).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Restored {
    pub launched: Launched,
    /// What the host found in the restored VM.
    pub report: RestoredVmReport,
    pub verified: VerifiedRestore,
}

/// A VM of the developer emulation facility (§1.3 line 1910). It is not a sandbox: it has
/// no launch record, no required properties and no contract, and nothing converts it
/// into a [`Launched`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EmulatedVm {
    pub vm: VmInstanceId,
    pub execution: ExecutionId,
    pub emulator: Emulator,
}

/// The outcome of a stop. Stopping a VM that is already gone succeeds (VM part §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopOutcome {
    Stopped,
    AlreadyGone,
}

/// An operation of the contract that can fail in the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendOperation {
    Launch,
    Stop,
    Snapshot,
    Restore,
    Query,
    Emulate,
}

impl fmt::Display for BackendOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Launch => "launch the VM",
            Self::Stop => "stop the VM",
            Self::Snapshot => "snapshot the VM",
            Self::Restore => "restore the VM",
            Self::Query => "query the VM",
            Self::Emulate => "start the emulated VM",
        })
    }
}

/// Why an operation on a VM was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendRefusal {
    /// The backend does not offer the feature; nothing is substituted for it.
    Unsupported { feature: Feature },
    /// No VM of this backend has that handle.
    NoSuchVm { vm: VmInstanceId },
    /// The backend failed; `detail` is its own description.
    Failed {
        operation: BackendOperation,
        detail: String,
    },
}

impl fmt::Display for BackendRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { feature } => {
                write!(f, "this backend does not support {feature}")
            }
            Self::NoSuchVm { vm } => write!(f, "no VM has the handle {vm}"),
            Self::Failed { operation, detail } => write!(f, "could not {operation}: {detail}"),
        }
    }
}

impl std::error::Error for BackendRefusal {}

/// A host-observed fact of a launch, by name, for refusals that point at one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactName {
    HypervisorEvidence,
    Accelerator,
    Host,
    GuestImage,
    Isolation,
    Confinement,
    Network,
    Credentials,
    Persistence,
    Devices,
    Confidentiality,
}

impl fmt::Display for FactName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HypervisorEvidence => "hypervisor availability evidence",
            Self::Accelerator => "accelerator",
            Self::Host => "host build",
            Self::GuestImage => "guest image",
            Self::Isolation => "isolation",
            Self::Confinement => "hypervisor confinement",
            Self::Network => "network enforcement",
            Self::Credentials => "credential exposure",
            Self::Persistence => "persistence",
            Self::Devices => "device inventory",
            Self::Confidentiality => "operator confidentiality",
        })
    }
}

/// A check of the hypervisor's running configuration against the approved profile
/// (§17 lines 3152–3153).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationCheck {
    /// VM-CP-02: the exact build, arguments and API configuration are the approved
    /// golden file's.
    GoldenConfiguration,
    /// VM-CP-03: no host filesystem share device, no monitor on a network listener, the
    /// monitor socket only in the host-created private directory, and no host port
    /// forward to the old agent port.
    HostInterfaces,
}

impl ConfigurationCheck {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::GoldenConfiguration => "golden_configuration",
            Self::HostInterfaces => "host_interfaces",
        }
    }
}

impl fmt::Display for ConfigurationCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GoldenConfiguration => "the approved golden configuration (VM-CP-02)",
            Self::HostInterfaces => "the host interface restrictions (VM-CP-03)",
        })
    }
}

/// What the host observed of a hypervisor process that does not run as launched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VmProcessState {
    /// The process exited with this code.
    Exited { exit_code: u32 },
    /// The hypervisor reports the VM in another state than running, in its own word.
    NotRunning { status: String },
    /// The host finds no process of the launch.
    Gone,
    /// The process's identity now names another process: its PID was reused.
    Replaced,
}

impl VmProcessState {
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Exited { .. } => "exited",
            Self::NotRunning { .. } => "not_running",
            Self::Gone => "gone",
            Self::Replaced => "replaced",
        }
    }
}

impl fmt::Display for VmProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited { exit_code } => write!(f, "exited with code {exit_code}"),
            Self::NotRunning { status } => {
                let status: String = status.chars().take(64).collect();
                write!(f, "reported {status:?}, not running")
            }
            Self::Gone => f.write_str("gone"),
            Self::Replaced => f.write_str("replaced by another process under its PID"),
        }
    }
}

/// Something a refused launch created that its cleanup did not show removed; it may still
/// exist (VM part §6.4 line 2324: cleanup uses host-created handles).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "left", rename_all = "snake_case")]
pub enum LeftBehind {
    /// The VM's process: the host has not shown that it ended. The backend keeps the VM
    /// listed by [`VmBackend::running`] until a stop succeeds.
    Process { detail: String },
    /// A host resource the launch created (a directory, a cgroup, a namespace or a file),
    /// named by the cleanup step that removes it, with why that step is not done.
    HostResource { step: String, detail: String },
}

impl LeftBehind {
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Process { .. } => "process",
            Self::HostResource { .. } => "host_resource",
        }
    }
}

impl fmt::Display for LeftBehind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process { detail } => {
                write!(f, "the VM's process is not shown ended ({detail})")
            }
            Self::HostResource { step, detail } => write!(f, "{step} is not done ({detail})"),
        }
    }
}

/// Why a launch or restore was refused. Every variant is a typed refusal; none is a
/// fallback (S1; VM-W16 acceptance). Serialize only, like the record it stands in for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LaunchRefusal {
    /// CORE-01 refused the host-only hypervisor requirement: no evidence, a source too
    /// weak (a guest report never satisfies it), a changed configuration, stale evidence,
    /// an unsupported or an inconclusive result.
    Evidence { refusal: EvidenceRefusal },
    /// The evidence handed to admission is not host-probe hypervisor evidence for this
    /// host's hypervisor under the current configuration.
    EvidenceNotBound {
        capability: Capability,
        source: SourceClass,
        subject: Digest,
        configuration: ConfigurationFingerprint,
    },
    /// The network facet asks for an independent perimeter, and CORE-01 refused the
    /// host-only `PerimeterRuleEnforced` requirement of this rule for the launch's
    /// principal: no evidence, a source too weak (a guest report never counts), a changed
    /// configuration, stale evidence, a must-probe that connected (`NotEnforced`) or an
    /// inconclusive result (§4.4 lines 2153–2165; VM-CP-11).
    PerimeterNotEvidenced {
        rule: PerimeterRuleSubject,
        refusal: EvidenceRefusal,
    },
    /// The network facet asks for an independent perimeter but names no block rule, so
    /// nothing can show one (§4.4).
    NoPerimeterRules {
        perimeter: Digest,
        principal: Digest,
    },
    /// Hardware virtualization failed while launching; nothing retries into emulation
    /// (VM-W22).
    HardwareVirtualizationFailed { failure: HardwareFailure },
    /// The host did not observe which accelerator the VM runs on.
    AcceleratorNotObserved { reason: UnknownReason },
    /// The VM runs without hardware virtualization (VM-W22; VM-P42).
    NotHardwareVirtualized { observed: Accelerator },
    /// The VM runs under a hardware hypervisor other than the one this backend launches
    /// with, so the hypervisor evidence is about something else.
    UnexpectedAccelerator {
        expected: HypervisorKind,
        observed: Accelerator,
    },
    /// The backend does not offer a feature the request needs.
    Unsupported { feature: Feature },
    /// The request is pinned to another backend build.
    BackendArtifactMismatch { pinned: Digest, actual: Digest },
    /// This boot generation of this sandbox was already used; every boot gets a new one.
    BootGenerationUsed {
        execution: ExecutionId,
        boot: SandboxBootGeneration,
    },
    /// A host observation is stale or was made under another configuration.
    ObservationNotCurrent {
        fact: FactName,
        problem: ObservationProblem,
    },
    /// A required property is not satisfied by host-observed evidence; every check is
    /// listed, the failing ones included.
    PropertiesNotSatisfied { checks: Vec<RequiredCheck> },
    /// The snapshot fails the VM snapshot validator (S3.4 item 4; VM part §6.6).
    SnapshotNotRestorable { defects: Vec<SnapshotDefect> },
    /// The restored VM did not pass verification, so it did not yield a usable fresh
    /// generation (VM-P21; VM part §6.6).
    RestoreRefused { refusal: RestoreRefusal },
    /// The backend could not create the VM; nothing is left behind.
    CreateFailed { detail: String },
    /// The launch record could not be sealed.
    RecordNotSealed { detail: String },
    /// The backend's approved launch profile cannot provide the launch on this host: a
    /// required property its platform does not apply, a host input in a form it does not
    /// take, a reservation that does not cover the plan, or a plan that is not the
    /// approved configuration. Nothing was started; `detail` is the backend's own words.
    ProfileRefused {
        backend: BackendKind,
        detail: String,
    },
    /// The host's layout lacks an input of the launch, such as the pinned guest image or
    /// a declared data volume. Nothing was started.
    LayoutRefused {
        backend: BackendKind,
        detail: String,
    },
    /// The host observed the hypervisor running a configuration that is not the approved
    /// profile's (VM-CP-02, VM-CP-03): `checks` names the checks that failed and
    /// `findings` every finding, in the backend's own words.
    ConfigurationNotApproved {
        backend: BackendKind,
        checks: BTreeSet<ConfigurationCheck>,
        findings: Vec<String>,
    },
    /// Confinement restrictions the launch applies to the hypervisor's process are not in
    /// effect (VM-CP-04): every finding is listed; with `observed` false the host could
    /// not observe them at all, so none is shown in effect.
    ConfinementNotInEffect {
        backend: BackendKind,
        observed: bool,
        findings: Vec<String>,
    },
    /// The hypervisor's process ended or does not run as launched.
    ProcessNotRunning {
        backend: BackendKind,
        state: VmProcessState,
    },
    /// A refusal only this backend states, in its own words, such as an observation the
    /// host could not make.
    BackendSpecific {
        backend: BackendKind,
        detail: String,
    },
    /// The launch of `vm` was refused after the backend created something, and its
    /// cleanup is incomplete: `left` names what may remain. `refusal` is why the launch
    /// was refused. While its process is left, the VM stays listed by
    /// [`VmBackend::running`].
    CleanupIncomplete {
        vm: VmInstanceId,
        refusal: Box<LaunchRefusal>,
        left: Vec<LeftBehind>,
    },
}

impl LaunchRefusal {
    /// The feature named by an unsupported-feature refusal.
    pub fn unsupported_feature(&self) -> Option<Feature> {
        match self {
            Self::Unsupported { feature } => Some(*feature),
            _ => None,
        }
    }

    /// The checks that failed, when required properties were not satisfied.
    pub fn failed_checks(&self) -> Vec<&RequiredCheck> {
        match self {
            Self::PropertiesNotSatisfied { checks } => checks
                .iter()
                .filter(|check| !check.is_satisfied())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The VM and what may remain of it, when the refused launch's cleanup is incomplete.
    pub fn left_behind(&self) -> Option<(VmInstanceId, &[LeftBehind])> {
        match self {
            Self::CleanupIncomplete { vm, left, .. } => Some((*vm, left)),
            _ => None,
        }
    }

    /// The refusal behind an incomplete cleanup, or this refusal itself.
    pub fn cause(&self) -> &LaunchRefusal {
        match self {
            Self::CleanupIncomplete { refusal, .. } => refusal.cause(),
            refusal => refusal,
        }
    }
}

/// Writes up to the first four findings, then how many more there are.
fn write_findings(f: &mut fmt::Formatter<'_>, findings: &[String]) -> fmt::Result {
    const SHOWN: usize = 4;
    for (index, finding) in findings.iter().take(SHOWN).enumerate() {
        f.write_str(if index == 0 { ": " } else { "; " })?;
        let finding: String = finding.chars().take(160).collect();
        f.write_str(&finding)?;
    }
    if findings.len() > SHOWN {
        write!(f, "; and {} more", findings.len() - SHOWN)?;
    }
    Ok(())
}

impl fmt::Display for LaunchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence { refusal } => write!(f, "{refusal}"),
            Self::EvidenceNotBound { .. } => f.write_str(
                "the hypervisor evidence is not host-probe evidence for this host's hypervisor \
                 under the current configuration",
            ),
            Self::PerimeterNotEvidenced { rule, refusal } => write!(
                f,
                "the independent perimeter's block rule {} for principal {} is not shown \
                 enforced: {refusal}",
                rule.rule, rule.principal
            ),
            Self::NoPerimeterRules {
                perimeter,
                principal,
            } => write!(
                f,
                "the network facet asks for the independent perimeter {perimeter} but names \
                 no block rule for principal {principal}, so nothing can show it"
            ),
            Self::HardwareVirtualizationFailed { failure } => write!(
                f,
                "hardware virtualization failed, so the launch is refused and nothing is \
                 retried in emulation: {failure}"
            ),
            Self::AcceleratorNotObserved { reason } => write!(
                f,
                "the host did not observe which accelerator the VM runs on ({reason}); a \
                 production launch needs host-observed hardware virtualization"
            ),
            Self::NotHardwareVirtualized { observed } => write!(
                f,
                "the VM runs under {observed}; a production sandbox requires hardware \
                 virtualization"
            ),
            Self::UnexpectedAccelerator { expected, observed } => write!(
                f,
                "the VM runs under {observed}, not the {expected} this backend launches with"
            ),
            Self::Unsupported { feature } => {
                write!(f, "this backend does not support {feature}")
            }
            Self::BackendArtifactMismatch { pinned, actual } => write!(
                f,
                "the launch is pinned to backend artifact {pinned}, but this backend is {actual}"
            ),
            Self::BootGenerationUsed { execution, boot } => write!(
                f,
                "boot generation {boot} of {execution} was already used; every boot gets a new \
                 generation"
            ),
            Self::ObservationNotCurrent { fact, problem } => {
                write!(f, "the host's {fact} observation is not current: {problem}")
            }
            Self::PropertiesNotSatisfied { checks } => {
                let failed: Vec<&RequiredCheck> = checks
                    .iter()
                    .filter(|check| !check.is_satisfied())
                    .collect();
                write!(
                    f,
                    "{} required propert{} not satisfied",
                    failed.len(),
                    if failed.len() == 1 { "y is" } else { "ies are" }
                )?;
                for (index, check) in failed.iter().enumerate() {
                    f.write_str(if index == 0 { ": " } else { "; " })?;
                    write!(f, "{check}")?;
                }
                Ok(())
            }
            Self::SnapshotNotRestorable { defects } => write!(
                f,
                "the snapshot cannot be restored: {} defect{}",
                defects.len(),
                if defects.len() == 1 { "" } else { "s" }
            ),
            Self::RestoreRefused { refusal } => write!(f, "{refusal}"),
            Self::CreateFailed { detail } => {
                write!(f, "the backend could not create the VM: {detail}")
            }
            Self::RecordNotSealed { detail } => {
                write!(f, "the launch record could not be sealed: {detail}")
            }
            Self::ProfileRefused { backend, detail } => write!(
                f,
                "the {backend} launch profile cannot provide this launch, so nothing was \
                 started: {detail}"
            ),
            Self::LayoutRefused { backend, detail } => write!(
                f,
                "the host lacks an input of the {backend} launch, so nothing was started: \
                 {detail}"
            ),
            Self::ConfigurationNotApproved {
                backend,
                checks,
                findings,
            } => {
                let names: Vec<String> = checks.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "the host observed {backend} running a configuration that fails {}",
                    names.join(" and ")
                )?;
                write_findings(f, findings)
            }
            Self::ConfinementNotInEffect {
                backend,
                observed: false,
                ..
            } => write!(
                f,
                "the host could not observe the confinement of the {backend} process, so \
                 none of its restrictions is shown in effect (VM-CP-04)"
            ),
            Self::ConfinementNotInEffect {
                backend, findings, ..
            } => {
                write!(
                    f,
                    "{} confinement restriction{} of the {backend} process {} not in effect \
                     (VM-CP-04)",
                    findings.len(),
                    if findings.len() == 1 { "" } else { "s" },
                    if findings.len() == 1 { "is" } else { "are" }
                )?;
                write_findings(f, findings)
            }
            Self::ProcessNotRunning { backend, state } => {
                write!(
                    f,
                    "the {backend} process {state} before the launch was admitted"
                )
            }
            Self::BackendSpecific { backend, detail } => {
                write!(f, "{backend} refused the launch: {detail}")
            }
            Self::CleanupIncomplete { vm, refusal, left } => {
                write!(
                    f,
                    "{refusal}; the cleanup of VM {vm} is incomplete and {} item{} may remain",
                    left.len(),
                    if left.len() == 1 { "" } else { "s" }
                )?;
                for (index, item) in left.iter().take(4).enumerate() {
                    f.write_str(if index == 0 { ": " } else { "; " })?;
                    write!(f, "{item}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LaunchRefusal {}

/// Why a running VM could not be observed again, or its re-observation does not refresh a
/// launch record. Fresh evidence does not exist until a later re-observation succeeds.
/// Serialize only, like the refusals it carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReobservationRefusal {
    /// No VM of this backend runs with that handle.
    NoSuchVm { vm: VmInstanceId },
    /// The VM's launch was not admitted, so it has no record to refresh.
    NotAdmitted { vm: VmInstanceId },
    /// This backend cannot observe a VM again after launch; its launch-time facts go
    /// stale and stay so.
    Unsupported { backend: BackendKind },
    /// The re-observation is of another launch than the record it is judged with.
    OtherLaunch { record: Digest, reobserved: Digest },
    /// What the host found now refuses the VM as a launch would be refused: CORE-01
    /// evidence missing, stale or changed, the process not running, the configuration or
    /// confinement not the launch's, a stale observation, or a required property no
    /// longer satisfied.
    Refused { refusal: Box<LaunchRefusal> },
}

impl ReobservationRefusal {
    pub(super) fn refused(refusal: LaunchRefusal) -> Self {
        Self::Refused {
            refusal: Box::new(refusal),
        }
    }
}

impl fmt::Display for ReobservationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchVm { vm } => write!(f, "no VM has the handle {vm}"),
            Self::NotAdmitted { vm } => {
                write!(
                    f,
                    "the launch of VM {vm} was not admitted; nothing can be refreshed"
                )
            }
            Self::Unsupported { backend } => write!(
                f,
                "{backend} cannot observe a VM again after launch, so its launch-time evidence \
                 is not renewed"
            ),
            Self::OtherLaunch { record, reobserved } => write!(
                f,
                "the re-observation is of launch {reobserved}, not of the record {record}"
            ),
            Self::Refused { refusal } => write!(f, "observed again: {refusal}"),
        }
    }
}

impl std::error::Error for ReobservationRefusal {}

/// What a VM backend does (VM-W16; §3.1 supervisor row, line 2053: manage verified VM
/// objects, deadlines and generation epochs; never parse guest files).
///
/// Every method acts on host-created handles that are never a PID and survive PID reuse
/// (VM part §6.4). A launch that fails leaves no VM behind. A repeated launch of the same
/// sandbox and boot generation while that VM runs is the same object; a boot generation
/// is never used twice.
pub trait VmBackend {
    /// This backend build.
    fn identity(&self) -> &BackendIdentity;

    /// The features this backend offers; anything else is refused by name.
    fn features(&self) -> &BackendFeatures;

    /// Launches one boot of a sandbox under hardware virtualization and returns its handle
    /// with the sealed launch record, or a typed refusal.
    fn launch(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, LaunchRefusal>;

    /// Stops the VM through its handle; a VM that is already gone counts as stopped.
    fn stop(&mut self, vm: &VmInstanceId) -> Result<StopOutcome, BackendRefusal>;

    /// Takes a snapshot of the VM, recording its origin; refused by name when the backend
    /// offers none ([`Feature::Snapshot`]).
    fn snapshot(
        &mut self,
        vm: &VmInstanceId,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendRefusal>;

    /// Restores `snapshot` into the fresh boot generation of `request`, verified before
    /// it may receive authority, or refuses; refused by name when the backend offers none
    /// ([`Feature::Restore`]).
    fn restore(
        &mut self,
        request: &LaunchRequest,
        snapshot: &SnapshotManifest,
        host: &dyn HostEvidence,
    ) -> Result<Restored, LaunchRefusal>;

    /// The accelerator the host observed the VM running on (VM-W22).
    fn actual_accelerator(
        &self,
        vm: &VmInstanceId,
    ) -> Result<HostObserved<Accelerator>, BackendRefusal>;

    /// Everything the host observed about the VM's boundary (§8.1 "observed
    /// confinement").
    fn confinement_evidence(&self, vm: &VmInstanceId)
        -> Result<ObservedProperties, BackendRefusal>;

    /// The handles of every sandbox VM this backend runs, for reconciliation.
    fn running(&self) -> Vec<VmInstanceId>;

    /// Observes the running VM again now, through the same host ports as at launch, and
    /// returns the fresh host-observed facts (the accelerator, the confinement, the
    /// device exposure and the rest of the boundary) stamped now on the evidence clock,
    /// with the launch's CORE-01 requirements evaluated again
    /// ([`super::reobserved`]). A backend that passed configuration facts to admission
    /// makes them again too ([`super::reobserved_with_configuration`]). The record judges
    /// them ([`LaunchRecord::assert_current_with`]); a guest assertion is never taken. A
    /// backend that cannot observe again refuses, so its launch-time evidence goes stale
    /// and stays so.
    fn reobserve(
        &mut self,
        vm: &VmInstanceId,
        host: &dyn HostEvidence,
    ) -> Result<Reobservation, ReobservationRefusal> {
        let _ = (vm, host);
        Err(ReobservationRefusal::Unsupported {
            backend: self.identity().kind,
        })
    }
}

/// The separate developer emulation facility (§1.3 line 1910). It is not part of
/// [`VmBackend`]: a production launch has no path here, and an emulated VM carries no
/// production required properties or credentials.
pub trait DeveloperEmulation {
    /// Starts an emulated, non-sandbox VM, or refuses by name when the backend offers
    /// none ([`Feature::DeveloperEmulation`]).
    fn launch_emulated(
        &mut self,
        request: &EmulationRequest,
        host: &dyn HostEvidence,
    ) -> Result<EmulatedVm, BackendRefusal>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    #[test]
    fn features_are_refused_by_name() {
        let features = BackendFeatures::of([Feature::Snapshot]);
        assert!(features.supports(Feature::Snapshot));
        assert!(!features.supports(Feature::Restore));
        assert_eq!(features.require(Feature::Snapshot), Ok(()));
        let refusal = features.require(Feature::Restore).unwrap_err();
        assert_eq!(refusal.unsupported_feature(), Some(Feature::Restore));
        assert_eq!(
            refusal.to_string(),
            "this backend does not support snapshot restore"
        );
        assert!(BackendFeatures::none().supported.is_empty());
        let backend = BackendRefusal::Unsupported {
            feature: Feature::DeveloperEmulation,
        };
        assert!(backend.to_string().contains("developer emulation"));
        let json = serde_json::to_value(&backend).unwrap();
        assert_eq!(json["unsupported"]["feature"], "developer_emulation");
        assert_eq!(
            serde_json::from_value::<BackendRefusal>(json).unwrap(),
            backend
        );
        assert!(serde_json::from_value::<BackendRefusal>(serde_json::json!({
            "unsupported": {"feature": "snapshot", "fallback": "none"}
        }))
        .is_err());
    }

    #[test]
    fn backend_identities_are_exact() {
        let artifact = digest("yougori/test/backend/v1", &[b"fc"]);
        let backend = BackendIdentity::new(
            BackendKind::Firecracker,
            "1.10.1",
            artifact,
            HypervisorKind::Kvm,
        )
        .unwrap();
        assert_eq!(backend.to_string(), "Firecracker 1.10.1 on KVM");
        assert!(!backend.kind.is_fake());
        assert!(BackendKind::Fake.is_fake());
        assert!(
            BackendIdentity::new(BackendKind::Qemu, "", artifact, HypervisorKind::Whpx).is_err()
        );
        let json = serde_json::to_value(&backend).unwrap();
        assert_eq!(json["kind"], "firecracker");
        assert_eq!(
            serde_json::from_value::<BackendIdentity>(json.clone()).unwrap(),
            backend
        );
        let mut extra = json;
        extra["pid"] = 42.into();
        assert!(serde_json::from_value::<BackendIdentity>(extra).is_err());
    }

    #[test]
    fn refusals_name_what_they_refuse() {
        let refusal = LaunchRefusal::NotHardwareVirtualized {
            observed: Accelerator::Emulation {
                emulator: Emulator::Tcg,
            },
        };
        assert!(refusal
            .to_string()
            .contains("requires hardware virtualization"));
        assert!(refusal.failed_checks().is_empty());
        assert_eq!(refusal.unsupported_feature(), None);
        let json = serde_json::to_value(&refusal).unwrap();
        assert_eq!(json["kind"], "not_hardware_virtualized");
        assert_eq!(json["observed"]["emulation"]["emulator"], "tcg");

        let failed = LaunchRefusal::HardwareVirtualizationFailed {
            failure: HardwareFailure {
                hypervisor: HypervisorKind::Kvm,
                detail: "KVM_CREATE_VM: EPERM".to_owned(),
            },
        };
        assert!(failed
            .to_string()
            .contains("nothing is retried in emulation"));
        let used = LaunchRefusal::BootGenerationUsed {
            execution: ExecutionId::new("exe-1").unwrap(),
            boot: SandboxBootGeneration::new(3),
        };
        assert!(used.to_string().contains("boot generation 3 of exe-1"));
        let mismatch = LaunchRefusal::BackendArtifactMismatch {
            pinned: digest("yougori/test/backend/v1", &[b"a"]),
            actual: digest("yougori/test/backend/v1", &[b"b"]),
        };
        assert!(mismatch.to_string().contains("pinned to backend artifact"));
        assert!(LaunchRefusal::CreateFailed {
            detail: "boom".to_owned()
        }
        .to_string()
        .ends_with("boom"));
        assert_eq!(
            LaunchRefusal::SnapshotNotRestorable {
                defects: vec![SnapshotDefect::NotPreTenant]
            }
            .to_string(),
            "the snapshot cannot be restored: 1 defect"
        );
    }

    #[test]
    fn real_backend_refusals_are_named_by_what_the_host_observed() {
        let backend = BackendKind::Qemu;
        let cases = [
            (
                LaunchRefusal::ProfileRefused {
                    backend,
                    detail: "no vsock on this platform".to_owned(),
                },
                "profile_refused",
                "nothing was started",
            ),
            (
                LaunchRefusal::LayoutRefused {
                    backend,
                    detail: "the pinned guest image is not available".to_owned(),
                },
                "layout_refused",
                "nothing was started",
            ),
            (
                LaunchRefusal::ConfigurationNotApproved {
                    backend,
                    checks: BTreeSet::from([
                        ConfigurationCheck::GoldenConfiguration,
                        ConfigurationCheck::HostInterfaces,
                    ]),
                    findings: (0..6).map(|index| format!("finding {index}")).collect(),
                },
                "configuration_not_approved",
                "(VM-CP-03): finding 0; finding 1; finding 2; finding 3; and 2 more",
            ),
            (
                LaunchRefusal::ConfinementNotInEffect {
                    backend,
                    observed: true,
                    findings: vec!["the token is not low integrity".to_owned()],
                },
                "confinement_not_in_effect",
                "1 confinement restriction of the QEMU process is not in effect",
            ),
            (
                LaunchRefusal::ConfinementNotInEffect {
                    backend,
                    observed: false,
                    findings: Vec::new(),
                },
                "confinement_not_in_effect",
                "none of its restrictions is shown in effect",
            ),
            (
                LaunchRefusal::ProcessNotRunning {
                    backend,
                    state: VmProcessState::Exited { exit_code: 1 },
                },
                "process_not_running",
                "the QEMU process exited with code 1",
            ),
            (
                LaunchRefusal::ProcessNotRunning {
                    backend,
                    state: VmProcessState::NotRunning {
                        status: "paused".to_owned(),
                    },
                },
                "process_not_running",
                "reported \"paused\", not running",
            ),
            (
                LaunchRefusal::BackendSpecific {
                    backend: BackendKind::Firecracker,
                    detail: "the jailer exited with code 2".to_owned(),
                },
                "backend_specific",
                "Firecracker refused the launch: the jailer exited with code 2",
            ),
        ];
        for (refusal, kind, text) in cases {
            assert_eq!(serde_json::to_value(&refusal).unwrap()["kind"], kind);
            assert!(refusal.to_string().contains(text), "{refusal}");
            assert_eq!(refusal.left_behind(), None);
            assert_eq!(refusal.cause(), &refusal);
        }
        for (state, tag) in [
            (VmProcessState::Exited { exit_code: 0 }, "exited"),
            (
                VmProcessState::NotRunning {
                    status: String::new(),
                },
                "not_running",
            ),
            (VmProcessState::Gone, "gone"),
            (VmProcessState::Replaced, "replaced"),
        ] {
            assert_eq!(serde_json::to_value(&state).unwrap()["state"], tag);
            assert_eq!(state.tag(), tag);
        }
        assert_eq!(
            serde_json::to_value(ConfigurationCheck::HostInterfaces).unwrap(),
            "host_interfaces"
        );
        assert_eq!(
            ConfigurationCheck::GoldenConfiguration.tag(),
            "golden_configuration"
        );

        let vm = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"left"]));
        let nested = LaunchRefusal::CleanupIncomplete {
            vm,
            refusal: Box::new(LaunchRefusal::CleanupIncomplete {
                vm,
                refusal: Box::new(LaunchRefusal::BackendSpecific {
                    backend,
                    detail: "QMP could not be reached".to_owned(),
                }),
                left: Vec::new(),
            }),
            left: vec![
                LeftBehind::Process {
                    detail: "no proof of the end".to_owned(),
                },
                LeftBehind::HostResource {
                    step: "remove_private_directory".to_owned(),
                    detail: "withheld".to_owned(),
                },
            ],
        };
        assert!(matches!(
            nested.cause(),
            LaunchRefusal::BackendSpecific { .. }
        ));
        let (left_vm, left) = nested.left_behind().unwrap();
        assert_eq!(left_vm, vm);
        assert_eq!(
            left.iter().map(LeftBehind::tag).collect::<Vec<_>>(),
            ["process", "host_resource"]
        );
        let text = nested.to_string();
        assert!(text.contains("2 items may remain"), "{text}");
        assert!(
            text.contains("remove_private_directory is not done"),
            "{text}"
        );
    }
}
