//! The boundary report of one host profile, per launch or per doctor run (VM-W23's pure
//! half, line 2622: "host-specific capability/evidence doctor adapters ... with freshness
//! and effect on requirements. Report changes without altering host settings silently";
//! §8.1 lines 2433–2439: an evidence record of named checks at one time, not a security
//! certificate).
//!
//! The report lists every §17 check: those the profile requires and the rest, each with
//! its status, so "not tested" is explicit and never a pass. It names the §1.3 facets a
//! required check that did not pass leaves unsatisfied, explains why a requested GPU path
//! is unavailable, and has a digest identity over everything it states. It is assembled
//! from outcomes and changes nothing: no method touches a probe, a registry or the host.
//! A report made under another configuration, on another clock or too long ago is not
//! current, so re-evaluation after a configuration change is needed before it is used.
//!
//! Assembling a report renews nothing (review finding R3,
//! docs/manager-work-split/reviewer-findings.md): every check judged from evidence keeps
//! the window of that evidence, when its oldest part was observed and when its shortest
//! part expires, and [`BoundaryReport::current_at`] rechecks each window at the reader's
//! clock and maximum age after the report's own stamp. A cached report is current only
//! while the evidence it judged would still be, so a passing report assembled just before
//! its inputs expired stops being current when they do, and a report resting on a
//! short-lived required check lives no longer than that check. A status the judge refused
//! or could not test rests on no current evidence and has no window.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::catalog::{catalog, CheckId, RunProfile, ScenarioFamily};
use super::confinement::Vm05Evaluation;
use super::outcome::{Evidence, NotTestedReason, ProbeOutcome};
use super::rules::{judge, stamp_current, CheckStatus, JudgeContext};
use crate::foundation::evidence::{ClockReading, ClockSession, ConfigurationFingerprint, OsKind};
use crate::foundation::ids::{digest, Digest, MonotonicTime};
use crate::sandbox::backend::{BackendKind, Facet, HostBuild, ObservationProblem};

/// The digest domain of a report's identity.
pub const REPORT_DOMAIN: &str = "yougori/sandbox/probes/boundary-report/v1";

/// What every report states about itself (§8.1 line 2439).
pub const REPORT_NOTICE: &str = "an evidence record of named checks at one time; it is not a \
security certificate and does not show that no secret or unknown escape exists";

/// The check behind a GPU VM assignment (VM-CP-31).
const GPU_CHECK: CheckId = CheckId::of(31);

/// The host and the profiles a report is about (§7.1 line 2360: host OS, build and
/// architecture, backend).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostProfile {
    pub host: HostBuild,
    pub backend: BackendKind,
    /// The run profiles whose "must for" checks this host must pass (§17).
    pub profiles: BTreeSet<RunProfile>,
}

/// What the report is given for one check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckInput {
    /// The outcomes of the check's parts.
    Outcomes(Vec<ProbeOutcome>),
    /// VM-CP-05 only: the stamped V15 verdict.
    Vm05(Vm05Evaluation),
}

/// Whether the profile refuses to start when the check does not pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Applicability {
    Required,
    NotRequired,
}

/// When the evidence a check was judged from was observed and until when it stands: the
/// oldest observation of any part and the earliest expiry of any part (its observation
/// plus its own freshness), on the report's clock. A check's status is current for a
/// reader only while this window is: no older than the reader's maximum age and not yet
/// expired. The judge already refused any primary or corroborating part under another
/// configuration or clock, so the window is on the report's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceWindow {
    pub observed_at: MonotonicTime,
    pub valid_until: MonotonicTime,
}

impl EvidenceWindow {
    /// The window of `stamps`, each an observation time and its freshness; `None` for no
    /// stamp at all.
    fn of(stamps: impl IntoIterator<Item = (MonotonicTime, Duration)>) -> Option<Self> {
        let mut window: Option<Self> = None;
        for (observed_at, fresh_for) in stamps {
            let valid_until = observed_at.saturating_add(fresh_for);
            window = Some(match window {
                None => Self {
                    observed_at,
                    valid_until,
                },
                Some(so_far) => Self {
                    observed_at: so_far.observed_at.min(observed_at),
                    valid_until: so_far.valid_until.min(valid_until),
                },
            });
        }
        window
    }

    /// The window of both, when there are two.
    fn narrowed(self, other: Self) -> Self {
        Self {
            observed_at: self.observed_at.min(other.observed_at),
            valid_until: self.valid_until.min(other.valid_until),
        }
    }

    /// How long the window stands from its oldest observation: the shortest freshness
    /// that holds for every part.
    fn fresh_for(self) -> Duration {
        self.valid_until.saturating_duration_since(self.observed_at)
    }
}

/// One check in the report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckEntry {
    pub check: CheckId,
    pub families: &'static [ScenarioFamily],
    pub applicability: Applicability,
    pub status: CheckStatus,
    /// The window of the evidence the status rests on: present for a status the judge
    /// reached from accepted evidence (passed, failed, inconclusive), absent for a check
    /// not tested or whose evidence was refused.
    pub evidence: Option<EvidenceWindow>,
}

/// A §1.3 facet a required check that did not pass leaves unsatisfied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnsatisfiedFacet {
    pub facet: Facet,
    pub because: Vec<CheckId>,
}

/// The GPU path of the profile (VM-W23 acceptance: "unsafe/unavailable GPU paths
/// explained").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "gpu", rename_all = "snake_case")]
pub enum GpuPath {
    /// The profile does not ask for a GPU VM.
    NotRequested,
    /// VM-CP-31 passed.
    Available,
    /// VM-CP-31 did not pass; `why` says what stands in the way.
    Unavailable { status: CheckStatus, why: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ReportBody {
    notice: &'static str,
    profile: HostProfile,
    configuration: ConfigurationFingerprint,
    clock: ClockSession,
    assembled_at: MonotonicTime,
    max_age: Duration,
    entries: Vec<CheckEntry>,
    unsatisfied: Vec<UnsatisfiedFacet>,
    gpu: GpuPath,
}

/// The boundary report. Serialize only: a report is never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BoundaryReport {
    identity: Digest,
    #[serde(flatten)]
    body: ReportBody,
}

impl BoundaryReport {
    /// Judges every §17 check for `profile` at `context` and assembles the report. A check
    /// with no input is not tested: not run, or, for a check this host cannot run (VM-CP-31
    /// off Linux), given no observation for this host. The context must be about the
    /// profile's host.
    pub fn assemble(
        profile: HostProfile,
        mut inputs: BTreeMap<CheckId, CheckInput>,
        context: &JudgeContext,
    ) -> Result<Self, ReportError> {
        if profile.host.os != context.os {
            return Err(ReportError::OtherHost {
                profile: profile.host.os,
                context: context.os,
            });
        }
        let mut entries = Vec::with_capacity(catalog().len());
        for row in catalog() {
            let (status, window) = match inputs.remove(&row.id) {
                None => (judge(row, &[], context), None),
                Some(CheckInput::Outcomes(outcomes)) => (
                    judge(row, &outcomes, context),
                    EvidenceWindow::of(outcomes.iter().flat_map(evidence_stamps)),
                ),
                Some(CheckInput::Vm05(evaluation)) => {
                    if row.id != CheckId::of(5) {
                        return Err(ReportError::Vm05ForOtherCheck { check: row.id });
                    }
                    (
                        evaluation.status(context),
                        EvidenceWindow::of([(evaluation.evaluated_at(), evaluation.fresh_for())]),
                    )
                }
            };
            // Only a status the judge reached from accepted evidence rests on that
            // evidence's currency; a refusal or an untested check has nothing to expire.
            let evidence = match status {
                CheckStatus::Passed
                | CheckStatus::Failed { .. }
                | CheckStatus::Inconclusive { .. } => window,
                CheckStatus::NotTested { .. } | CheckStatus::Refused { .. } => None,
            };
            entries.push(CheckEntry {
                check: row.id,
                families: row.families,
                applicability: if row.required_for(&profile.profiles) {
                    Applicability::Required
                } else {
                    Applicability::NotRequired
                },
                status,
                evidence,
            });
        }

        let mut unsatisfied: BTreeMap<Facet, Vec<CheckId>> = BTreeMap::new();
        for (entry, row) in entries.iter().zip(catalog()) {
            if entry.applicability == Applicability::Required && !entry.status.passed() {
                for facet in row.facets.iter().copied().chain([Facet::Evidence]) {
                    unsatisfied.entry(facet).or_default().push(entry.check);
                }
            }
        }

        let gpu = if profile.profiles.contains(&RunProfile::GpuVm) {
            let status = entries
                .iter()
                .find(|entry| entry.check == GPU_CHECK)
                .map(|entry| entry.status.clone())
                .unwrap_or(CheckStatus::NotTested {
                    reason: NotTestedReason::NotRun,
                });
            if status.passed() {
                GpuPath::Available
            } else {
                let why = gpu_why(&status);
                GpuPath::Unavailable { status, why }
            }
        } else {
            GpuPath::NotRequested
        };

        let body = ReportBody {
            notice: REPORT_NOTICE,
            profile,
            configuration: context.configuration,
            clock: context.now.session(),
            assembled_at: context.now.at(),
            max_age: context.max_age,
            entries,
            unsatisfied: unsatisfied
                .into_iter()
                .map(|(facet, because)| UnsatisfiedFacet { facet, because })
                .collect(),
            gpu,
        };
        let bytes = serde_json::to_vec(&body).map_err(|error| ReportError::Unserializable {
            detail: error.to_string(),
        })?;
        Ok(Self {
            identity: digest(REPORT_DOMAIN, &[&bytes]),
            body,
        })
    }

    /// The report's identity: a digest of everything it states.
    pub fn identity(&self) -> Digest {
        self.identity
    }

    pub fn profile(&self) -> &HostProfile {
        &self.body.profile
    }

    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.body.configuration
    }

    pub fn entries(&self) -> &[CheckEntry] {
        &self.body.entries
    }

    /// The entry of `check`.
    pub fn entry(&self, check: CheckId) -> Option<&CheckEntry> {
        self.body.entries.iter().find(|entry| entry.check == check)
    }

    pub fn unsatisfied(&self) -> &[UnsatisfiedFacet] {
        &self.body.unsatisfied
    }

    pub fn gpu(&self) -> &GpuPath {
        &self.body.gpu
    }

    /// The required checks that did not pass: the profile refuses to start while any
    /// remains.
    pub fn blocking(&self) -> impl Iterator<Item = &CheckEntry> {
        self.body.entries.iter().filter(|entry| {
            entry.applicability == Applicability::Required && !entry.status.passed()
        })
    }

    /// Whether the profile may start on this report: every required check passed.
    pub fn allows_launch(&self) -> bool {
        self.blocking().next().is_none()
    }

    /// What changed since `earlier`, a report of the same host profile: the configuration
    /// and every check whose status changed (VM-W23: report changes, without altering host
    /// settings). A report of another host or backend is refused rather than compared.
    pub fn changes_since(&self, earlier: &BoundaryReport) -> Result<ReportChanges, ReportError> {
        let (now, then) = (&self.body.profile, &earlier.body.profile);
        if now.host != then.host || now.backend != then.backend {
            return Err(ReportError::OtherProfile);
        }
        let checks = self
            .body
            .entries
            .iter()
            .zip(&earlier.body.entries)
            .filter(|(after, before)| after.status != before.status)
            .map(|(after, before)| CheckChange {
                check: after.check,
                before: before.status.clone(),
                after: after.status.clone(),
            })
            .collect();
        Ok(ReportChanges {
            configuration_changed: self.body.configuration != earlier.body.configuration,
            launch_allowed_before: earlier.allows_launch(),
            launch_allowed_now: self.allows_launch(),
            checks,
        })
    }

    /// When the report was assembled, on its clock.
    pub fn assembled_at(&self) -> MonotonicTime {
        self.body.assembled_at
    }

    /// The oldest evidence the reader that assembled the report accepted.
    pub fn max_age(&self) -> Duration {
        self.body.max_age
    }

    /// The clock session the report and its evidence are stamped on.
    pub fn clock(&self) -> ClockSession {
        self.body.clock
    }

    /// The window of all the evidence the report's judged checks rest on: the oldest
    /// observation and the earliest expiry over every entry with evidence; `None` when
    /// no check was judged from evidence. This is how old the report's evidence is and
    /// how long it stands, for readers that show ages.
    pub fn evidence_window(&self) -> Option<EvidenceWindow> {
        self.body
            .entries
            .iter()
            .filter_map(|entry| entry.evidence)
            .reduce(EvidenceWindow::narrowed)
    }

    /// Whether the report is current for a reader at `now` that accepts nothing older
    /// than `max_age` under `configuration`: the report's own stamp first, then the
    /// evidence window of every judged check, each no older than `max_age` and not yet
    /// expired on the reader's clock. A report assembled under another configuration is
    /// never current, so a configuration change needs a new report; a report whose
    /// evidence has expired needs a new one too, however recently it was assembled. The
    /// first problem found is returned, in table order after the report's own.
    pub fn current_at(
        &self,
        now: ClockReading,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<(), ObservationProblem> {
        let context = JudgeContext {
            now,
            configuration,
            max_age,
            os: self.body.profile.host.os,
        };
        stamp_current(
            self.body.configuration,
            self.body.clock,
            self.body.assembled_at,
            self.body.max_age,
            &context,
        )?;
        for window in self.body.entries.iter().filter_map(|entry| entry.evidence) {
            stamp_current(
                self.body.configuration,
                self.body.clock,
                window.observed_at,
                window.fresh_for(),
                &context,
            )?;
        }
        Ok(())
    }
}

/// The observation time and freshness of every stamp an outcome's evidence carries: a
/// host observation's own, a guest run's collection, each fact a record run was read
/// from; nothing for a part not tested.
fn evidence_stamps(outcome: &ProbeOutcome) -> Vec<(MonotonicTime, Duration)> {
    match outcome.evidence() {
        Evidence::Host { observed, .. } => vec![(observed.observed_at(), observed.fresh_for())],
        Evidence::Guest { run } => vec![(run.collected_at(), run.fresh_for())],
        Evidence::Record { run } => run
            .stamps()
            .map(|stamp| (stamp.observed_at(), stamp.fresh_for()))
            .collect(),
        Evidence::NotTested { .. } => Vec::new(),
    }
}

/// Why VM-CP-31 leaves the GPU path unavailable, in words.
fn gpu_why(status: &CheckStatus) -> String {
    match status {
        CheckStatus::NotTested {
            reason: NotTestedReason::UnavailableHardware,
        } => "not tested: this host has no GPU hardware the check can use, so no GPU VM is \
              offered; a CPU VM or a remote VM remains"
            .to_owned(),
        CheckStatus::NotTested {
            reason: NotTestedReason::NoObservationForHost { os },
        } => format!(
            "not tested: GPU device assignment is checked on Linux hosts only (§7.5), so no \
             GPU VM is offered on this {os} host; a CPU VM or a remote VM remains"
        ),
        other => format!("{other}; no GPU VM is offered until VM-CP-31 passes"),
    }
}

/// One check whose status changed between two reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckChange {
    pub check: CheckId,
    pub before: CheckStatus,
    pub after: CheckStatus,
}

/// What changed between two reports of one host profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReportChanges {
    pub configuration_changed: bool,
    pub launch_allowed_before: bool,
    pub launch_allowed_now: bool,
    pub checks: Vec<CheckChange>,
}

/// Why a report could not be assembled or compared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ReportError {
    /// Two reports of different hosts or backends are not compared.
    OtherProfile,
    /// The judging context is about another host operating system than the profile.
    OtherHost {
        profile: OsKind,
        context: OsKind,
    },
    /// A V15 verdict was given for a check other than VM-CP-05.
    Vm05ForOtherCheck {
        check: CheckId,
    },
    Unserializable {
        detail: String,
    },
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherProfile => {
                f.write_str("the reports are about different hosts or backends")
            }
            Self::OtherHost { profile, context } => write!(
                f,
                "the report is about a {profile} host, and the outcomes were judged for a {context} host"
            ),
            Self::Vm05ForOtherCheck { check } => {
                write!(f, "a confinement verdict was given for {check}, not VM-CP-05")
            }
            Self::Unserializable { detail } => {
                write!(f, "the report could not be serialized: {detail}")
            }
        }
    }
}

impl std::error::Error for ReportError {}
