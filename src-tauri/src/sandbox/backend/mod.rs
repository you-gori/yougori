//! The VM backend contract, launch record and fake backend of the VM sandbox part
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 and VM-W22 rows, lines
//! 2615 and 2621; §1.3 facets, lines 1893–1910; §7.1 evidence matrix, lines 2356–2365;
//! §8.1 launch records, lines 2433–2439; S3.4 role RUNTIME, §3.1 supervisor row).
//!
//! - [`VmBackend`]: launch, stop, optional snapshot and restore, queries for the actual
//!   accelerator and the confinement evidence, and a re-observation of a running VM,
//!   every refusal typed and every unsupported feature refused by name. A real backend's
//!   refusal says what the host observed (a profile or layout that cannot provide the
//!   launch, a configuration that is not the approved profile, confinement not in
//!   effect, a process that does not run, or its own), and a refused launch whose cleanup
//!   is incomplete says what may remain. [`DeveloperEmulation`] is a separate facility a
//!   production launch cannot reach.
//! - [`LaunchRequest`]: the sandbox and its CORE-04 generations, the opaque contract
//!   digest, the pinned artifacts, the device profile, the typed [`RequiredProperties`]
//!   of the §1.3 facets and the CORE-03 reservation the launch runs inside.
//! - [`precheck`] and [`admit`]: the admission every backend runs. A required property
//!   is satisfied only by host-observed evidence: CORE-01 host-probe evidence that the
//!   hypervisor is available, under the current configuration fingerprint and within
//!   the required freshness, and the host's own observations of the running VM. A guest
//!   assertion is recorded apart and never counts. Production launch requires hardware
//!   virtualization; a hardware failure refuses, and nothing retries into emulation.
//!   Where the network facet asks for an independent perimeter
//!   ([`PerimeterRequirement`]), admission also needs CORE-01 `PerimeterRuleEnforced`
//!   host-probe evidence for every block rule and the principal the launch uses, fresh
//!   and under the same configuration, and refuses by rule otherwise (§4.4 lines
//!   1978–1990; VM-CP-11 line 3161).
//! - [`LaunchRecord`]: the §8.1 evidence record with an identity digest, Serialize only,
//!   with host-observed and guest-asserted facts in separate types. Its facts are
//!   launch-time facts and go stale; [`Reobservation`] is the host's fresh observation of
//!   the running VM, made by [`reobserved`] with the launch's CORE-01 requirements
//!   evaluated again (by [`reobserved_with_configuration`] with the configuration facts
//!   made again too), and [`LaunchRecord::assert_current_with`] judges it by the rules of
//!   admission, so nothing is presented as current without fresh host evidence.
//! - [`ConfigurationFacts`] and [`admit_with_configuration`]: the host's observations of
//!   the hypervisor configuration beside the §1.3 facts, which admission judges and the
//!   record binds (§17 lines 3152, 3153 and 3181): VM-CP-02's [`ConfigurationComparison`]
//!   with the golden file, VM-CP-03's [`HostInterfaceListing`], and VM-CP-31's
//!   [`GpuAssignmentOrder`] of each assigned GPU's checks and its assignment. Each is
//!   optional; a record without them keeps the identity it had before they existed. A
//!   re-observation carries the same facts made again, and the record judges them as
//!   admission did. What a backend passes in:
//!   - `sandbox::qemu` (passes both, at launch and on re-observation): after
//!     `check_observed` passed on the listing, the comparison of `GoldenFile::compare` of
//!     the observed vector with the release's golden file in its settings (its `golden`
//!     and `observed` digests; the four device flags false, since the strict reading-back
//!     refuses a network, console, balloon or PCI argument); and the listing with every
//!     flag clear and the QMP socket private, which `check_observed` shows, since it
//!     refuses share devices, monitor listeners and port forwards and reads the QMP
//!     socket back as the launch's private one;
//!   - `sandbox::firecracker` (passes none yet): after `GoldenCheck::run` passed, the
//!     comparison of its golden file's digest and the running configuration's digest,
//!     with the device flags from its forbidden items (an undeclared network interface, a
//!     console, a balloon, the PCI transport), and the listing of the API socket in the
//!     jail's socket directory with no share device, listener or port forward, which the
//!     golden check and the jail's layout show;
//!   - a GPU backend (VM-W18): per assigned GPU, the host's checks stamped before the
//!     device is assigned (for example from `sandbox::host_checks`'s assessment) and the
//!     assignment stamped when it is made.
//! - [`EvidenceRow`] and [`ReleaseProfile`]: the §7.1 matrix, in which an unvalidated
//!   combination is experimental or unavailable and never supported.
//! - [`FakeBackend`]: a backend driven by a [`HostScript`] of what the host observes.
//!
//! Time comes from the CORE-01 registry's clock through [`HostEvidence`]; nothing here
//! touches a process, a hypervisor, the network or a file.

mod accelerator;
mod admission;
mod checks;
mod configuration;
mod contract;
mod facets;
pub mod fake;
mod matrix;
mod observation;
mod record;
mod reobservation;
mod request;

#[cfg(test)]
mod tests;

pub use accelerator::{Accelerator, Emulator, HardwareFailure};
pub use admission::{
    admit, admit_with_configuration, hypervisor_requirement, perimeter_requirements, precheck,
    vm_handle, LaunchFacts, VM_HANDLE_DOMAIN,
};
pub use checks::{check_all, CheckFailure, CheckOutcome, FacetValue, RequiredCheck};
pub use configuration::{
    ConfigurationComparison, ConfigurationFact, ConfigurationFacts, GpuAssignmentOrder,
    HostInterfaceListing, ACS_BYPASS_SETTINGS, CHECKED_BEFORE_ASSIGNMENT,
};
pub use contract::{
    BackendFeatures, BackendIdentity, BackendKind, BackendOperation, BackendRefusal,
    ConfigurationCheck, DeveloperEmulation, EmulatedVm, FactName, Feature, HostEvidence,
    LaunchRefusal, Launched, LeftBehind, ReobservationRefusal, Restored, StopOutcome, VmBackend,
    VmProcessState,
};
pub use facets::{
    check_endpoints, guest_endpoints_file, ConfinementControl, CredentialExposure,
    CredentialKind, DeviceExposure, DeviceInventory, EndpointError, EndpointKind,
    EvidenceRequirement, Facet,
    GpuIsolation, GpuIsolationCheck, GuestEgressEndpoint, IsolationObservation,
    IsolationRequirement, NetworkAuthority, NetworkChannel, ObservedGpu, OperatorConfidentiality,
    PerimeterRequirement, Persistence, PhysicalHost, RequiredProperties, UnsafeDeviceSetting,
    MAX_GUEST_EGRESS_ENDPOINTS,
};
pub use fake::{FakeBackend, FakeCall, GuestScript, HostScript, Scripted};
pub use matrix::{
    EvidenceRow, EvidenceRowKey, LifecycleCheck, NotSupported, ProfileError, ReleaseProfile,
    RowRefusal, SupportStatus, TestResult, EVIDENCE_ROW_DOMAIN,
};
pub use observation::{
    Architecture, BuildId, FactSource, GuestAsserted, GuestAssertions, HostBuild, HostFact,
    HostObserved, HostSource, ObservationProblem, ObservedProperties,
};
pub use record::{LaunchRecord, RecordError, SandboxBinding, StaleFact, LAUNCH_RECORD_DOMAIN};
pub use reobservation::{reobserved, reobserved_with_configuration, Reobservation};
pub use request::{DeviceProfile, EmulationRequest, LaunchRequest, PinnedArtifacts};
