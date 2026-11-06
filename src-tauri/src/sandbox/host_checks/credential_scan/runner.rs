//! The host check runner of VM-CP-12 (§17, line 3162; VM-P12, line 2787; VM-W09, line
//! 2594; §8.1, line 2439).
//!
//! [`CredentialScanRunner`] is a `sandbox::probes` [`HostCheckRunner`]: the CORE-01
//! adapter `CredentialAbsentFromScannedLocationsProbe` runs it live for one launch's
//! credential scan and judges what it returns. It is given the plans of the scans it may
//! run; for a subject that is one of them, it [`scan`]s the plan's locations through the
//! read-only port and reports exactly VM-CP-12's typed observations:
//!
//! - `cp12.launch-specification`, `cp12.relay-inputs-and-logs`, `cp12.audit`,
//!   `cp12.echoed-response` and `cp12.executor-request`, presences: per place, present
//!   when the fixture was found in what was read of its locations; absent only when every
//!   one of them was read without a gap, held at least one byte and showed no match;
//!   otherwise left out ([`ScanReport::presence`]).
//! - `cp12.coverage-stated`, an event: it happened when the run's report states coverage
//!   of every named location, each read without a gap; otherwise it is left out. The
//!   report ([`CredentialScanRunner::scan`]) always states what was covered.
//!
//! A location that could not be read, or not to its end, leaves its place's observation
//! out unless the fixture was found in what was read there, and always leaves the
//! coverage statement out, so the judge reads the run inconclusive and never a pass; a
//! fixture found where it must not be is still reported, and fails the check. A subject
//! that is not one of the plans (another kind, another launch or another set of
//! locations) is unreachable. The check is not specific to a host operating system, so
//! the runner observes on every host.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::plan::{LocationRole, ScanPlan};
use super::port::ScanReader;
use super::scan::{scan, LimitError, ScanLimits, ScanReport};
use crate::foundation::evidence::{ConfigurationFingerprint, OsKind, Subject};
use crate::foundation::ids::Digest;
use crate::sandbox::probes::{
    expectation, CheckId, Expect, ExpectationId, HostCheckRunner, Observations, Observed, Part,
    Role, RunResult, RunnerInconclusive,
};

/// The §17 row this runner answers.
pub const CREDENTIAL_SCAN_CHECK_NUMBER: u8 = 12;

/// The expectation of the coverage statement.
pub const COVERAGE_STATED: &str = "cp12.coverage-stated";

/// The most plans one runner may be given.
pub const MAX_PLANS: usize = 64;

/// What a runner is given besides its plans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanSettings {
    /// The host's operating system.
    pub os: OsKind,
    /// The configuration the observations depend on, such as the profile and the
    /// versions of the relay, the executor and the audit writer.
    pub configuration: ConfigurationFingerprint,
    /// How long an observation stays fresh.
    pub fresh_for: Duration,
    /// The bounds of each run.
    pub limits: ScanLimits,
}

/// Why a runner was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "settings", rename_all = "snake_case")]
pub enum ScanSettingsError {
    /// Observations that are never fresh.
    ZeroFreshness,
    /// A scan limit was refused.
    Limit { error: LimitError },
    /// More plans than [`MAX_PLANS`].
    TooManyPlans { limit: usize },
    /// Two plans have one subject.
    RepeatedSubject,
    /// The probes catalog has no VM-CP-12, or lacks one of its expectations as this
    /// runner reports it.
    UnknownExpectation { name: &'static str },
}

impl fmt::Display for ScanSettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroFreshness => f.write_str("observations must stay fresh for some time"),
            Self::Limit { error } => error.fmt(f),
            Self::TooManyPlans { limit } => write!(f, "more than {limit} scan plans were given"),
            Self::RepeatedSubject => f.write_str("two scan plans have the same subject"),
            Self::UnknownExpectation { name } => {
                write!(f, "the probes catalog has no VM-CP-12 expectation {name}")
            }
        }
    }
}

impl std::error::Error for ScanSettingsError {}

/// VM-CP-12 and the expectations this runner reports, looked up once.
#[derive(Clone, Copy, Debug)]
struct Cp12 {
    check: CheckId,
    /// By [`LocationRole::ALL`] order.
    places: [ExpectationId; 5],
    coverage: ExpectationId,
}

impl Cp12 {
    fn resolve() -> Result<Self, ScanSettingsError> {
        let check = CheckId::new(CREDENTIAL_SCAN_CHECK_NUMBER).ok_or(
            ScanSettingsError::UnknownExpectation {
                name: COVERAGE_STATED,
            },
        )?;
        let id = |name: &'static str, expect: Expect| {
            ExpectationId::named(name)
                .filter(|id| {
                    expectation(*id).is_some_and(|entry| {
                        entry.check == check
                            && entry.part == Part::Primary
                            && entry.role == Role::Observation
                            && entry.expect == expect
                    })
                })
                .ok_or(ScanSettingsError::UnknownExpectation { name })
        };
        let place = |role: LocationRole| {
            let expect = if role.must_contain() {
                Expect::Present
            } else {
                Expect::Absent
            };
            id(role.expectation(), expect)
        };
        let [launch, relay, audit, echoed, request] = LocationRole::ALL;
        Ok(Self {
            check,
            places: [
                place(launch)?,
                place(relay)?,
                place(audit)?,
                place(echoed)?,
                place(request)?,
            ],
            coverage: id(COVERAGE_STATED, Expect::Happens)?,
        })
    }
}

/// VM-CP-12 on this host, read through `R`.
pub struct CredentialScanRunner<R> {
    reader: R,
    settings: ScanSettings,
    /// By the identity of each plan's subject.
    plans: BTreeMap<Digest, ScanPlan>,
    cp12: Cp12,
}

impl<R: ScanReader> CredentialScanRunner<R> {
    pub fn new(
        reader: R,
        settings: ScanSettings,
        plans: Vec<ScanPlan>,
    ) -> Result<Self, ScanSettingsError> {
        if settings.fresh_for.is_zero() {
            return Err(ScanSettingsError::ZeroFreshness);
        }
        settings
            .limits
            .check()
            .map_err(|error| ScanSettingsError::Limit { error })?;
        if plans.len() > MAX_PLANS {
            return Err(ScanSettingsError::TooManyPlans { limit: MAX_PLANS });
        }
        let mut by_subject = BTreeMap::new();
        for plan in plans {
            let identity = Subject::CredentialScan(plan.subject()).identity();
            if by_subject.insert(identity, plan).is_some() {
                return Err(ScanSettingsError::RepeatedSubject);
            }
        }
        Ok(Self {
            reader,
            settings,
            plans: by_subject,
            cp12: Cp12::resolve()?,
        })
    }

    pub const fn settings(&self) -> &ScanSettings {
        &self.settings
    }

    /// The plan whose subject `subject` is.
    pub fn plan_for(&self, subject: &Subject) -> Option<&ScanPlan> {
        match subject {
            Subject::CredentialScan(_) => self.plans.get(&subject.identity()),
            _ => None,
        }
    }

    /// One run of the scan `subject` names, read now, with everything it read and found;
    /// for a doctor that explains a result. `None` when no plan has that subject.
    pub fn scan(&self, subject: &Subject) -> Option<ScanReport> {
        self.plan_for(subject)
            .map(|plan| scan(&self.reader, plan, self.settings.limits))
    }

    /// VM-CP-12's observations from one run's report.
    pub fn observations(&self, report: &ScanReport) -> Observations {
        let mut observations = Observations::new();
        for (role, id) in LocationRole::ALL.iter().zip(self.cp12.places) {
            if let Some(present) = report.presence(*role) {
                observations.insert(id, Observed::Presence { present });
            }
        }
        if report.covered() {
            observations.insert(self.cp12.coverage, Observed::Event { happened: true });
        }
        observations
    }
}

impl<R: ScanReader> HostCheckRunner for CredentialScanRunner<R> {
    fn configuration(&self) -> ConfigurationFingerprint {
        self.settings.configuration
    }

    fn fresh_for(&self) -> Duration {
        self.settings.fresh_for
    }

    fn os(&self) -> OsKind {
        self.settings.os
    }

    fn run(&self, check: CheckId, part: Part, subject: &Subject) -> RunResult {
        if check != self.cp12.check || part != Part::Primary {
            return RunResult::Observed {
                observations: Observations::new(),
            };
        }
        match self.scan(subject) {
            Some(report) => RunResult::Observed {
                observations: self.observations(&report),
            },
            None => RunResult::Inconclusive {
                reason: RunnerInconclusive::Unreachable,
            },
        }
    }
}
