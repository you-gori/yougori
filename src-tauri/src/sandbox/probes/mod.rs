//! Host and guest boundary probes as CORE-01 evidence: the pure (Tier 0) halves of VM-W09
//! and VM-W23 (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S2 CORE-01 row, line 210;
//! §1.3 facets, lines 1893–1910; §8.1, lines 2433–2439; VM-W09, line 2594; VM-W23, line
//! 2622; §12.1, lines 2760–2769; §12.2, lines 2770–2828; §17, lines 3145–3188). S4 role
//! EVIDENCE.
//!
//! - [`catalog`]: the §17 controlled checks as data, one [`ControlledCheck`] per VM-CP
//!   row: the VM-P families it serves, its side and source, its positive control (or the
//!   plan's note), the profiles that refuse to start on a failure and the facets it
//!   observes.
//! - [`expect`]: every expected observation as a typed [`Expectation`], with a typed
//!   predicate ([`Expect`]) over a typed [`Observed`] value. No expectation is a command.
//! - [`outcome`]: what a probe produced for one part of one check. A host or controlled
//!   external run is a backend `HostObserved` value stamped on the evidence clock; a
//!   guest run is built only from `sandbox::link` guest reports; a part not run is not
//!   tested, with its reason.
//! - [`rules`]: the §8.1 and VM-W09 rules, one function each, and [`judge`]. A guest
//!   report never satisfies a host-only part; a guest-reported check needs its named host
//!   corroboration; inconclusive and not tested never pass; stale or reconfigured
//!   outcomes are refused; a failed or missing positive control makes a result
//!   inconclusive.
//! - [`confinement`]: VM-CP-05 from the V15 verdict of `sandbox_contract::confinement`,
//!   whose evaluator is reused, stamped so that a stale verdict refuses.
//! - [`core01`]: one CORE-01 host-probe adapter per capability a check's host-observed
//!   parts state: hypervisor availability (VM-CP-01), perimeter rule enforcement
//!   (VM-CP-11), and the eight VM boundary facts of VM-CP-02 to VM-CP-05, VM-CP-07 to
//!   VM-CP-09, VM-CP-12, VM-CP-17, VM-CP-21, VM-CP-23 and VM-CP-31. Each runs its checks
//!   live through a host runner port and judges them with the pieces of [`judge`].
//! - [`coverage`]: the exact map from every check to the CORE-01 capability its host
//!   parts feed, with those parts, or to no capability, with the reason.
//! - [`records`]: check outcomes from sealed launch records and the backend's typed
//!   refusals of controlled negative launches ([`RecordResults`]), for exactly the check
//!   parts their host-observed facts decide, the configuration facts a record binds
//!   included (VM-CP-02, VM-CP-03, VM-CP-31), each observation stamped as the host stamped
//!   the facts it was read from; [`record_coverage`] says per check what records decide
//!   and why they decide nothing more. A record's guest assertions are never read.
//!
//! VM-CP-31 is scoped to Linux hosts (§7.5 lines 2398 and 2411), so on any other host the
//! judge, the CORE-01 adapter and the records read it as not tested.
//! - [`report`]: the [`BoundaryReport`] of one host profile per launch or doctor run:
//!   every check with its status, the facets left unsatisfied, the GPU path explained,
//!   a digest identity, and the changes since an earlier report. It changes nothing on
//!   the host.
//!
//! Nothing here runs a probe: runners are ports, and the only implementations are test
//! fakes. Time comes from the CORE-01 registry's clock as a `ClockReading`. No field,
//! variant or method computes a score.

pub mod catalog;
pub mod confinement;
pub mod core01;
pub mod coverage;
pub mod drill;
pub mod expect;
pub mod outcome;
pub mod process_scan;
pub mod records;
pub mod report;
pub mod rules;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod record_tests;
#[cfg(test)]
mod tests;

pub use catalog::{
    catalog, check, CheckId, ControlledCheck, CorroboratingFact, MustFor, Part, PlanNote,
    PositiveControl, RunProfile, ScenarioFamily, Side, SourceKind,
};
pub use confinement::{status_of_verdict, Vm05Evaluation};
pub use core01::{
    hypervisor_of, BootedImageMatchesManifestProbe, CloneIdentityResetProbe,
    CredentialAbsentFromScannedLocationsProbe, DestinationPolicyEnforcedProbe,
    DeviceAssignmentIsolatedProbe, HostCheckRunner, HypervisorAvailableProbe,
    HypervisorConfigurationMatchesProbe, HypervisorConfinedProbe, NoGuestNetworkDeviceProbe,
    PerimeterRuleProbe, HYPERVISOR_CHECK, PERIMETER_CHECK,
};
pub use coverage::{checks_for, core01_coverage, coverage_of, CheckCoverage, Core01Coverage};
pub use expect::{
    expectation, expectations, Expect, Expectation, ExpectationId, HostScope, ObservationError,
    Observed, ObservedKind, Role, VM_CP_01_ACCELERATORS,
};
pub use outcome::{
    Evidence, FactStamp, GuestRun, HostKind, IgnoredClaim, NotTestedReason, Observations,
    OutcomeError, ProbeOutcome, RecordAge, RecordRun, RunResult, RunnerInconclusive, StampOrigin,
    TestTier,
};
pub use drill::{ConnectionDrill, DrillAttempt, DrillCase};
pub use process_scan::{
    hypervisor_mode, is_hypervisor_image, HypervisorMode, LeftoverStart, ListedProcess,
    ProcessScan, ScanMoment, SeenHypervisor,
};
pub use records::{
    record_coverage, record_coverage_of, record_source, ComparisonItem, ControlledFault,
    ListingItem, NegativeOutcome, RecordCoverage, RecordDecision, RecordInputError, RecordResults,
    RecordSource, CLONE_GENERATION_DOMAIN,
};
pub use report::{
    Applicability, BoundaryReport, CheckChange, CheckEntry, CheckInput, EvidenceWindow, GpuPath,
    HostProfile, ReportChanges, ReportError, UnsatisfiedFacet, REPORT_DOMAIN, REPORT_NOTICE,
};
pub use rules::{
    control_holds, control_in_observations, current, evaluate_observations, evaluate_part, judge,
    source_accepted, CheckRefusal, CheckStatus, Failure, InconclusiveReason, JudgeContext,
    PartResult,
};
