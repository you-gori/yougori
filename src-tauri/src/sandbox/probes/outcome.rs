//! What a probe produced for one part of one check (§8.1 lines 2433–2439; §17 line 3147).
//!
//! A host or controlled external run is a backend [`HostObserved`] value: stamped on the
//! evidence clock with the configuration it depends on and its freshness, exactly as the
//! backend stamps its own facts, so the same staleness rules judge both. A guest run is
//! built only from `sandbox::link` [`GuestReport`]s, which carry the guest source class
//! fixed by the link; nothing in this module turns one into a host observation. A record
//! run ([`RecordRun`]) is read from sealed launch records and the backend's refusals of
//! controlled negative launches by [`super::records`]: each observation keeps the stamps
//! of the host facts it was read from (a §1.3 fact or a configuration fact of a record, or
//! a refusal), exactly as the host made them, and only that module builds one. A part that was not run is recorded as not tested, with its reason,
//! and is never a pass.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::catalog::{check, CheckId, Part, SourceKind};
use super::expect::{expectation, ExpectationId, Observed};
use super::records::ControlledFault;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::{
    ClockReading, ClockSession, ConfigurationFingerprint, OsKind, SourceClass,
};
use crate::foundation::ids::{Digest, MonotonicTime, SandboxBootGeneration};
use crate::sandbox::backend::{
    BackendIdentity, ConfigurationFact, FactName, FactSource, HostBuild, HostObserved,
};
use crate::sandbox::link::{GuestReport, ProbeOutcome as GuestVerdict, ReportBody};

/// The observations of one run, by expectation.
pub type Observations = BTreeMap<ExpectationId, Observed>;

/// Why a runner could not finish a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerInconclusive {
    /// The run did not finish in time; a timeout is never a refusal (§4.4, VM-CP-11).
    TimedOut,
    /// The subject or a controlled endpoint could not be reached.
    Unreachable,
    /// The run was interrupted before it observed everything.
    Interrupted,
}

impl fmt::Display for RunnerInconclusive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TimedOut => "the run timed out",
            Self::Unreachable => "the subject or a controlled endpoint could not be reached",
            Self::Interrupted => "the run was interrupted",
        })
    }
}

/// What a host or controlled external runner produced for one part of one check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "run", rename_all = "snake_case")]
pub enum RunResult {
    Observed { observations: Observations },
    Inconclusive { reason: RunnerInconclusive },
}

/// The §12.1 tiers above Tier 0 (lines 2762–2766): where a check that cannot run here
/// must run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTier {
    /// Separate restricted test services and fakes.
    ProcessIntegration,
    /// A disposable real VM in an explicitly authorized test environment.
    DisposableVm,
    /// GPU assignment, confidential computing, dedicated hosts or provider leases, with
    /// explicit environment and cost authorization.
    HardwareOrProvider,
    /// Specialist review of the implemented boundaries.
    IndependentAssessment,
}

/// Why a part was not tested. Not tested is never a pass (VM-CP-35, VM-P50; VM-W51:
/// "unavailable hardware is 'not tested', not a pass").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotTestedReason {
    /// Nothing ran the part.
    NotRun,
    /// The hardware the check needs is not on this host.
    UnavailableHardware,
    /// The check runs only at this tier, in an authorized environment.
    NeedsTier { tier: TestTier },
    /// A host-specific check has no observation for this operating system.
    NoObservationForHost { os: OsKind },
}

impl fmt::Display for NotTestedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRun => f.write_str("it was not run"),
            Self::UnavailableHardware => f.write_str("the hardware it needs is not on this host"),
            Self::NeedsTier { tier } => {
                write!(f, "it runs only at {tier:?} in an authorized environment")
            }
            Self::NoObservationForHost { os } => {
                write!(f, "the plan gives it no observation for a {os} host")
            }
        }
    }
}

/// Where a host-grade observation came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    Host,
    ControlledExternal,
}

impl HostKind {
    pub const fn source_kind(self) -> SourceKind {
        match self {
            Self::Host => SourceKind::Host,
            Self::ControlledExternal => SourceKind::ControlledExternal,
        }
    }
}

/// A guest report the run recorded but did not use (VM-CP-25: a forged "all probes
/// passed" satisfies nothing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "ignored", rename_all = "snake_case")]
pub enum IgnoredClaim {
    /// A blanket claim; it names no expectation, so it judges nothing.
    AllProbesPassed { probe_count: u32, sequence: u64 },
    /// A probe result that names no expectation of this check and part.
    OtherProbe { probe: String, sequence: u64 },
    /// A report that is not a probe result (hello, init stage, terminal exit).
    NotAProbeResult { sequence: u64 },
}

/// The guest's reports for one part of one check, collected by the host from one link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuestRun {
    source: SourceClass,
    vm: VmInstanceId,
    boot: SandboxBootGeneration,
    clock: ClockSession,
    collected_at: MonotonicTime,
    fresh_for: Duration,
    configuration: ConfigurationFingerprint,
    verdicts: BTreeMap<ExpectationId, GuestVerdict>,
    /// The link sequences of the reports used, in arrival order.
    used: Vec<u64>,
    ignored: Vec<IgnoredClaim>,
}

impl GuestRun {
    /// Always [`SourceClass::GuestReport`].
    pub const fn source(&self) -> SourceClass {
        self.source
    }

    pub const fn vm(&self) -> VmInstanceId {
        self.vm
    }

    pub const fn boot(&self) -> SandboxBootGeneration {
        self.boot
    }

    pub const fn clock(&self) -> ClockSession {
        self.clock
    }

    pub const fn collected_at(&self) -> MonotonicTime {
        self.collected_at
    }

    pub const fn fresh_for(&self) -> Duration {
        self.fresh_for
    }

    pub const fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// What the guest said about each expectation it reported.
    pub fn verdicts(&self) -> &BTreeMap<ExpectationId, GuestVerdict> {
        &self.verdicts
    }

    pub fn used(&self) -> &[u64] {
        &self.used
    }

    pub fn ignored(&self) -> &[IgnoredClaim] {
        &self.ignored
    }
}

/// Which host fact a [`FactStamp`] dates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum StampOrigin {
    /// A host-observed fact of the sealed launch record `record`.
    Record { record: Digest, fact: FactName },
    /// A host observation of the hypervisor configuration that the sealed launch record
    /// `record` binds beside its §1.3 facts: its golden comparison, its listing check, or
    /// an assigned GPU's checks or assignment (VM-CP-02, VM-CP-03, VM-CP-31).
    RecordConfiguration {
        record: Digest,
        fact: ConfigurationFact,
    },
    /// The backend's refusal of a controlled negative launch with `fault`, stamped when
    /// the host observed it.
    Refusal { fault: ControlledFault },
    /// A host scan of the process list taken at `moment` (`process_scan`).
    ProcessScan {
        moment: super::process_scan::ScanMoment,
    },
    /// The host's observations of a VM-CP-29 connection drill (`drill`).
    ConnectionDrill,
}

/// The stamp of one host fact a record run was read from, exactly as the host stamped it:
/// its clock session, when it was observed, how long it stays fresh and the configuration
/// it was observed under (§8.1 line 2435: observation source and timestamp). Serialize
/// only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FactStamp {
    origin: StampOrigin,
    source: FactSource,
    clock: ClockSession,
    observed_at: MonotonicTime,
    fresh_for: Duration,
    configuration: ConfigurationFingerprint,
}

impl FactStamp {
    /// The stamp of `observed`, unchanged.
    pub(super) fn of<T>(origin: StampOrigin, observed: &HostObserved<T>) -> Self {
        Self {
            origin,
            source: observed.source(),
            clock: observed.clock(),
            observed_at: observed.observed_at(),
            fresh_for: observed.fresh_for(),
            configuration: observed.configuration(),
        }
    }

    pub const fn origin(&self) -> StampOrigin {
        self.origin
    }

    /// Host-observed or verified: a host fact always has a host source.
    pub const fn source(&self) -> FactSource {
        self.source
    }

    pub const fn clock(&self) -> ClockSession {
        self.clock
    }

    pub const fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    pub const fn fresh_for(&self) -> Duration {
        self.fresh_for
    }

    pub const fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }
}

/// How old the oldest fact behind a record run is for a reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecordAge {
    /// Its oldest fact was observed this long before the reader's time.
    Observed { age: Duration },
    /// A fact was stamped on another clock session, such as before a restart, so its age
    /// cannot be known.
    OtherClock,
    /// A fact is dated after the reader's time.
    ObservedAfterNow,
}

/// What sealed launch records and the refusals of controlled negative launches showed for
/// one part of one check (§8.1 lines 2435–2437): host facts only, each observation with
/// the stamps of the facts it was read from. Only [`super::records`] builds one, so a
/// record run is never hand-written; Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecordRun {
    backend: BackendIdentity,
    host: HostBuild,
    observations: Observations,
    read_from: BTreeMap<ExpectationId, Vec<FactStamp>>,
}

impl RecordRun {
    pub(super) fn new(
        backend: BackendIdentity,
        host: HostBuild,
        observations: Observations,
        read_from: BTreeMap<ExpectationId, Vec<FactStamp>>,
    ) -> Self {
        Self {
            backend,
            host,
            observations,
            read_from,
        }
    }

    /// The backend build that sealed the records.
    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// The host build every record observed.
    pub fn host(&self) -> &HostBuild {
        &self.host
    }

    pub fn observations(&self) -> &Observations {
        &self.observations
    }

    /// The stamps of the facts the observation `id` was read from; empty for an
    /// observation the run did not make.
    pub fn read_from(&self, id: ExpectationId) -> &[FactStamp] {
        self.read_from.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Every stamp of the run, observation by observation.
    pub fn stamps(&self) -> impl Iterator<Item = &FactStamp> {
        self.read_from.values().flatten()
    }

    /// The sealed launch records the run read, by identity, each once, in order of first
    /// use.
    pub fn records(&self) -> Vec<Digest> {
        let mut records = Vec::new();
        for stamp in self.stamps() {
            if let StampOrigin::Record { record, .. }
            | StampOrigin::RecordConfiguration { record, .. } = stamp.origin
            {
                if !records.contains(&record) {
                    records.push(record);
                }
            }
        }
        records
    }

    /// How many refusals of controlled negative launches the run read.
    pub fn refusals(&self) -> usize {
        let mut refusals: Vec<&FactStamp> = Vec::new();
        for stamp in self.stamps() {
            if matches!(stamp.origin, StampOrigin::Refusal { .. }) && !refusals.contains(&stamp) {
                refusals.push(stamp);
            }
        }
        refusals.len()
    }

    /// How old the run's oldest fact is at `now`, on the reader's clock.
    pub fn age_at(&self, now: ClockReading) -> RecordAge {
        if self.stamps().any(|stamp| stamp.clock != now.session()) {
            return RecordAge::OtherClock;
        }
        if self.stamps().any(|stamp| stamp.observed_at > now.at()) {
            return RecordAge::ObservedAfterNow;
        }
        let oldest = self
            .stamps()
            .map(|stamp| stamp.observed_at)
            .min()
            .unwrap_or(now.at());
        RecordAge::Observed {
            age: now.at().saturating_duration_since(oldest),
        }
    }
}

/// The evidence of one part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "evidence", rename_all = "snake_case")]
pub enum Evidence {
    Host {
        kind: HostKind,
        observed: HostObserved<RunResult>,
    },
    Guest {
        run: GuestRun,
    },
    /// Host facts read from sealed launch records and the refusals of controlled negative
    /// launches, each judged by its own stamp.
    Record {
        run: RecordRun,
    },
    NotTested {
        reason: NotTestedReason,
    },
}

/// What a probe produced for one part of one check. Serialize only: a record of a probe
/// is never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeOutcome {
    check: CheckId,
    part: Part,
    evidence: Evidence,
}

impl ProbeOutcome {
    /// A host or controlled external run of `part` of `check`, observed now on the
    /// evidence clock under `configuration`. Every observation must name an expectation
    /// of that check and part.
    pub fn host(
        check_id: CheckId,
        part: Part,
        kind: HostKind,
        now: ClockReading,
        fresh_for: Duration,
        configuration: ConfigurationFingerprint,
        result: RunResult,
    ) -> Result<Self, OutcomeError> {
        known_part(check_id, part)?;
        if let RunResult::Observed { observations } = &result {
            for id in observations.keys() {
                belongs(*id, check_id, part)?;
            }
        }
        Ok(Self {
            check: check_id,
            part,
            evidence: Evidence::Host {
                kind,
                observed: HostObserved::stamp(result, now, fresh_for, configuration),
            },
        })
    }

    /// The guest's run of `part` of `check`, from the reports one link delivered for the
    /// VM `vm` at boot `boot`, collected now. A report from another instance or boot is
    /// refused; a probe result is used only when it names an expectation of this check
    /// and part; a blanket "all probes passed" and every other report are recorded as
    /// ignored claims.
    #[allow(clippy::too_many_arguments)]
    pub fn guest(
        check_id: CheckId,
        part: Part,
        reports: &[GuestReport],
        vm: VmInstanceId,
        boot: SandboxBootGeneration,
        now: ClockReading,
        fresh_for: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<Self, OutcomeError> {
        known_part(check_id, part)?;
        let mut verdicts = BTreeMap::new();
        let mut used = Vec::new();
        let mut ignored = Vec::new();
        for report in reports {
            if report.vm() != vm || report.boot() != boot {
                return Err(OutcomeError::OtherInstance {
                    sequence: report.sequence(),
                });
            }
            let sequence = report.sequence();
            match report.body() {
                ReportBody::Probe(result) => {
                    let named = ExpectationId::named(result.probe.as_str())
                        .filter(|id| belongs(*id, check_id, part).is_ok());
                    match named {
                        Some(id) => {
                            if verdicts.insert(id, result.outcome).is_some() {
                                return Err(OutcomeError::DuplicateGuestResult { expectation: id });
                            }
                            used.push(sequence);
                        }
                        None => ignored.push(IgnoredClaim::OtherProbe {
                            probe: result.probe.as_str().to_owned(),
                            sequence,
                        }),
                    }
                }
                ReportBody::AllProbesPassed(claim) => ignored.push(IgnoredClaim::AllProbesPassed {
                    probe_count: claim.probe_count,
                    sequence,
                }),
                ReportBody::Hello(_) | ReportBody::Init(_) | ReportBody::TerminalExit { .. } => {
                    ignored.push(IgnoredClaim::NotAProbeResult { sequence })
                }
            }
        }
        Ok(Self {
            check: check_id,
            part,
            evidence: Evidence::Guest {
                run: GuestRun {
                    source: GuestReport::SOURCE,
                    vm,
                    boot,
                    clock: now.session(),
                    collected_at: now.at(),
                    fresh_for,
                    configuration,
                    verdicts,
                    used,
                    ignored,
                },
            },
        })
    }

    /// The record run of `part` of `check`, from [`super::records`]. Every observation
    /// must name an expectation of that check and part.
    pub(super) fn from_records(
        check_id: CheckId,
        part: Part,
        run: RecordRun,
    ) -> Result<Self, OutcomeError> {
        known_part(check_id, part)?;
        for id in run.observations.keys() {
            belongs(*id, check_id, part)?;
        }
        Ok(Self {
            check: check_id,
            part,
            evidence: Evidence::Record { run },
        })
    }

    /// A part that was not tested, and why.
    pub fn not_tested(
        check_id: CheckId,
        part: Part,
        reason: NotTestedReason,
    ) -> Result<Self, OutcomeError> {
        known_part(check_id, part)?;
        Ok(Self {
            check: check_id,
            part,
            evidence: Evidence::NotTested { reason },
        })
    }

    pub const fn check(&self) -> CheckId {
        self.check
    }

    pub const fn part(&self) -> Part {
        self.part
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The kind of source behind the outcome; `None` for a part that was not tested.
    pub const fn source_kind(&self) -> Option<SourceKind> {
        match &self.evidence {
            Evidence::Host { kind, .. } => Some(kind.source_kind()),
            Evidence::Record { .. } => Some(SourceKind::Host),
            Evidence::Guest { .. } => Some(SourceKind::Guest),
            Evidence::NotTested { .. } => None,
        }
    }

    /// The CORE-01 source class behind the outcome; `None` for a part not tested.
    pub fn source_class(&self) -> Option<SourceClass> {
        self.source_kind().map(SourceKind::source_class)
    }
}

/// Why an outcome could not be recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum OutcomeError {
    /// The check has no such part.
    UnknownPart { check: CheckId, part: Part },
    /// An observation names an expectation of another check or part.
    ForeignExpectation {
        expectation: ExpectationId,
        check: CheckId,
        part: Part,
    },
    /// A guest report came from another VM instance or boot than the one under test.
    OtherInstance { sequence: u64 },
    /// The guest reported the same expectation twice in one run.
    DuplicateGuestResult { expectation: ExpectationId },
}

impl fmt::Display for OutcomeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPart { check, part } => write!(f, "{check} has no part {part}"),
            Self::ForeignExpectation {
                expectation,
                check,
                part,
            } => write!(
                f,
                "{expectation} is not an expectation of {part} of {check}"
            ),
            Self::OtherInstance { sequence } => write!(
                f,
                "guest report {sequence} came from another VM instance or boot than the one under test"
            ),
            Self::DuplicateGuestResult { expectation } => {
                write!(f, "the guest reported {expectation} twice in one run")
            }
        }
    }
}

impl std::error::Error for OutcomeError {}

fn known_part(check_id: CheckId, part: Part) -> Result<(), OutcomeError> {
    if check(check_id).parts().contains(&part) {
        Ok(())
    } else {
        Err(OutcomeError::UnknownPart {
            check: check_id,
            part,
        })
    }
}

fn belongs(id: ExpectationId, check_id: CheckId, part: Part) -> Result<(), OutcomeError> {
    match expectation(id) {
        Some(entry) if entry.check == check_id && entry.part == part => Ok(()),
        _ => Err(OutcomeError::ForeignExpectation {
            expectation: id,
            check: check_id,
            part,
        }),
    }
}
