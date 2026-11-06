//! One examination of a host: a boundary report per candidate backend, its §7.1 label,
//! every check that did not pass in the engine's words with what it expects on this host,
//! and what changed since the previous examination (VM-W23, line 2622; §7.1, lines
//! 2356–2364; §8.1, lines 2433–2439: "A probe suite demonstrates named properties at a
//! time ... Re-evaluate relevant evidence after policy, firewall, backend, host-interface
//! or artifact changes").
//!
//! The previous reports live in the doctor and, through its
//! [`HistoryStore`](super::history::HistoryStore), across engine restarts: a doctor reads
//! its store once, at its first examination, and keeps every examination there for the
//! next one. A store that cannot be read or holds a damaged history is reported in the
//! report's [`History`] and ignored; one that cannot keep the report is reported too, and
//! the report stands.
//!
//! A backend's results may come from its sealed launch records
//! ([`RecordResults`]): [`Doctor::examine_with_records`] adds them to the results given
//! directly, and every examination lists, per backend, the results read from launch
//! records, the records behind each and how old its oldest fact is. Results read from the
//! records of another backend or host are refused.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::candidates::{candidates, no_candidates, Candidate};
use super::history::{
    decode_history, encode_history, BackendChanges, History, HistoryError, HistoryStore,
    MemoryOnly, RememberedReport,
};
use super::wording::{not_passed, CheckExplanation};
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{BackendKind, HostBuild};
use crate::sandbox::probes::{
    Applicability, BoundaryReport, CheckId, CheckInput, CheckStatus, Evidence, HostProfile,
    JudgeContext, Part, RecordAge, RecordResults, ReportError, RunProfile,
};

/// What every doctor report states about itself.
pub const DOCTOR_NOTICE: &str = "This report changes nothing on the host. A check without a result is not tested and never passes. A backend is validated on this host only when every check its run profiles require passed here; until then it is experimental or unavailable (section 7.1).";

/// The run profiles examined when none is asked for: the strict profile every VM sandbox
/// starts from.
pub const DEFAULT_PROFILES: [RunProfile; 1] = [RunProfile::Strict];

/// The run profile with the name the report uses for it (`strict`, `gpu_vm`, ...).
pub fn run_profile(name: &str) -> Option<RunProfile> {
    RunProfile::ALL.into_iter().find(|profile| {
        serde_json::to_value(profile)
            .ok()
            .and_then(|value| value.as_str().map(|text| text == name))
            .unwrap_or(false)
    })
}

/// The results a backend's checks produced, by check; a check that is absent was not run.
pub type CheckInputs = BTreeMap<CheckId, CheckInput>;

/// What the doctor examines: this host, under its configuration, for these run profiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorRequest {
    pub host: HostBuild,
    pub configuration: ConfigurationFingerprint,
    pub profiles: BTreeSet<RunProfile>,
}

/// A backend's standing on this host (§7.1: "Until validated, label it experimental or
/// unavailable").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    /// Every required check passed on this host.
    Validated,
    /// Some required checks passed and none failed or was refused; the rest are open.
    Experimental,
    /// No required check passed yet, or one failed or was refused.
    Unavailable,
}

/// How many checks have each status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatusCounts {
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub not_tested: usize,
    pub refused: usize,
}

impl StatusCounts {
    fn add(&mut self, status: &CheckStatus) {
        let count = match status {
            CheckStatus::Passed => &mut self.passed,
            CheckStatus::Failed { .. } => &mut self.failed,
            CheckStatus::Inconclusive { .. } => &mut self.inconclusive,
            CheckStatus::NotTested { .. } => &mut self.not_tested,
            CheckStatus::Refused { .. } => &mut self.refused,
        };
        *count += 1;
    }

    /// Every check counted.
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.inconclusive + self.not_tested + self.refused
    }
}

/// One result the examination read from sealed launch records (§8.1 lines 2435–2437:
/// observation source and timestamp).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecordedResult {
    pub check: CheckId,
    pub part: Part,
    /// The sealed launch records it was read from, by identity.
    pub records: Vec<Digest>,
    /// How many refusals of controlled negative launches it was read from.
    pub refusals: usize,
    /// How old its oldest fact was when the doctor examined it.
    pub age: RecordAge,
}

/// One candidate backend's examination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CandidateReport {
    pub candidate: Candidate,
    pub label: Label,
    /// The checks the run profiles require, by status.
    pub required: StatusCounts,
    /// Every check, by status.
    pub all: StatusCounts,
    /// The required checks that did not pass, in check order.
    pub blocking: Vec<CheckId>,
    /// Every check that did not pass, required or not, in check order: its status with the
    /// reason in the engine's words, and what it expects on this host in the plan's words.
    pub not_passed: Vec<CheckExplanation>,
    /// The results read from this backend's sealed launch records, in check order; their
    /// statuses are in the report.
    pub from_launch_records: Vec<RecordedResult>,
    pub report: BoundaryReport,
}

/// What changed for one backend since the previous examination. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum DoctorChange {
    /// The checks, the launch or the configuration changed on the same host build.
    Report {
        backend: BackendKind,
        changes: BackendChanges,
    },
    /// The host build or architecture changed, so earlier results say nothing about it.
    Host {
        backend: BackendKind,
        before: HostBuild,
        after: HostBuild,
    },
}

/// One examination. Serialize only: a report is never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub notice: &'static str,
    pub host: HostBuild,
    pub profiles: BTreeSet<RunProfile>,
    /// How many check results this examination was given.
    pub results: usize,
    /// How many of the results' parts were read from sealed launch records.
    pub from_launch_records: usize,
    /// Why the host has no candidate backend, when it has none.
    pub no_backend: Option<&'static str>,
    pub candidates: Vec<CandidateReport>,
    pub changes: Vec<DoctorChange>,
    /// What this examination was compared with, and whether it was kept for the next one.
    pub history: History,
}

/// Why an examination was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum DoctorError {
    /// A report needs at least one run profile.
    NoProfiles,
    /// Results were given for a backend this host's doctor does not examine.
    NotACandidate { backend: BackendKind },
    /// The boundary report refused its inputs.
    Report {
        backend: BackendKind,
        refusal: ReportError,
    },
    /// Results given for `backend` were read from the launch records of `records`.
    RecordsOfOtherBackend {
        backend: BackendKind,
        records: BackendKind,
    },
    /// Results given for `backend` were read from launch records of another host build.
    RecordsOfOtherHost { backend: BackendKind },
    /// Two sets of launch records were given for one backend.
    RecordsGivenTwice { backend: BackendKind },
    /// Launch records and a confinement verdict were both given for one check.
    ConflictingResults {
        backend: BackendKind,
        check: CheckId,
    },
}

impl fmt::Display for DoctorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProfiles => f.write_str("the doctor needs at least one run profile"),
            Self::NotACandidate { backend } => write!(
                f,
                "results were given for {backend:?}, which this host's doctor does not examine"
            ),
            Self::Report { backend, refusal } => {
                write!(f, "the {backend:?} boundary report was refused: {refusal}")
            }
            Self::RecordsOfOtherBackend { backend, records } => write!(
                f,
                "results given for {backend:?} were read from {records:?} launch records"
            ),
            Self::RecordsOfOtherHost { backend } => write!(
                f,
                "results given for {backend:?} were read from launch records of another host build"
            ),
            Self::RecordsGivenTwice { backend } => {
                write!(f, "launch records of {backend:?} were given twice")
            }
            Self::ConflictingResults { backend, check } => write!(
                f,
                "{check} of {backend:?} was given both launch-record results and a confinement verdict"
            ),
        }
    }
}

impl std::error::Error for DoctorError {}

fn label(report: &BoundaryReport) -> Label {
    let required: Vec<&CheckStatus> = report
        .entries()
        .iter()
        .filter(|entry| entry.applicability == Applicability::Required)
        .map(|entry| &entry.status)
        .collect();
    let passed = required.iter().filter(|status| status.passed()).count();
    let refused = required.iter().any(|status| {
        matches!(
            status,
            CheckStatus::Failed { .. } | CheckStatus::Refused { .. }
        )
    });
    if !required.is_empty() && passed == required.len() {
        Label::Validated
    } else if passed == 0 || refused {
        Label::Unavailable
    } else {
        Label::Experimental
    }
}

/// The doctor of one host: it keeps the previous report of each backend so the next
/// examination can say what changed, for as long as it lives and, through its store, after
/// the engine restarts.
#[derive(Clone, Debug, Default)]
pub struct Doctor<S = MemoryOnly> {
    previous: BTreeMap<BackendKind, RememberedReport>,
    store: S,
    /// Whether the store was read; it is read once, at the first examination.
    store_read: bool,
}

impl Doctor {
    /// A doctor that keeps its previous reports in memory only.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: HistoryStore> Doctor<S> {
    /// A doctor that reads its previous reports from `store` at its first examination and
    /// keeps every examination there for the next one.
    pub fn with_store(store: S) -> Self {
        Self {
            previous: BTreeMap::new(),
            store,
            store_read: false,
        }
    }

    /// Examines every candidate backend of `request.host` at `context`. `results` holds the
    /// check results each backend produced; a backend or check without results is not
    /// tested. Results read from launch records must be of the backend they are given for
    /// and of this host build, and are listed with their age. Nothing is run and nothing on
    /// the host changes; the store, if any, is read at the first examination and given
    /// every examination.
    pub fn examine(
        &mut self,
        request: &DoctorRequest,
        context: &JudgeContext,
        mut results: BTreeMap<BackendKind, CheckInputs>,
    ) -> Result<DoctorReport, DoctorError> {
        if request.profiles.is_empty() {
            return Err(DoctorError::NoProfiles);
        }
        let examined = candidates(request.host.os);
        if let Some(backend) = results.keys().find(|backend| {
            !examined
                .iter()
                .any(|candidate| candidate.backend == **backend)
        }) {
            return Err(DoctorError::NotACandidate { backend: *backend });
        }
        let given = results.values().map(BTreeMap::len).sum();
        let mut recorded = BTreeMap::new();
        for (backend, inputs) in &results {
            recorded.insert(
                *backend,
                recorded_results(*backend, inputs, request, context)?,
            );
        }
        let from_launch_records = recorded.values().map(Vec::len).sum();

        let mut reports = Vec::with_capacity(examined.len());
        for candidate in examined {
            let profile = HostProfile {
                host: request.host.clone(),
                backend: candidate.backend,
                profiles: request.profiles.clone(),
            };
            let inputs = results.remove(&candidate.backend).unwrap_or_default();
            let report = BoundaryReport::assemble(profile, inputs, context).map_err(|error| {
                DoctorError::Report {
                    backend: candidate.backend,
                    refusal: error,
                }
            })?;
            let mut required = StatusCounts::default();
            let mut all = StatusCounts::default();
            let mut blocking = Vec::new();
            for entry in report.entries() {
                all.add(&entry.status);
                if entry.applicability == Applicability::Required {
                    required.add(&entry.status);
                    if !entry.status.passed() {
                        blocking.push(entry.check);
                    }
                }
            }
            reports.push(CandidateReport {
                candidate: *candidate,
                label: label(&report),
                required,
                all,
                blocking,
                not_passed: not_passed(report.entries(), request.host.os),
                from_launch_records: recorded.remove(&candidate.backend).unwrap_or_default(),
                report,
            });
        }

        let mut history = History::default();
        if !self.store_read {
            self.store_read = true;
            match self.read_store() {
                Ok(kept) => self.previous = kept,
                Err(error) => history.ignoring(&error),
            }
        }
        let mut changes = Vec::new();
        for candidate in &reports {
            let backend = candidate.candidate.backend;
            let now = RememberedReport::of(&candidate.report);
            if let Some(before) = self.previous.get(&backend) {
                history.compared.push(backend);
                if before.host != now.host {
                    changes.push(DoctorChange::Host {
                        backend,
                        before: before.host.clone(),
                        after: now.host.clone(),
                    });
                } else {
                    let delta = before.changes_to(&now);
                    if delta.any() {
                        changes.push(DoctorChange::Report {
                            backend,
                            changes: delta,
                        });
                    }
                }
            }
            self.previous.insert(backend, now);
        }
        if let Err(error) = self.keep() {
            history.not_keeping(&error);
        }

        Ok(DoctorReport {
            notice: DOCTOR_NOTICE,
            host: request.host.clone(),
            profiles: request.profiles.clone(),
            results: given,
            from_launch_records,
            no_backend: no_candidates(request.host.os),
            candidates: reports,
            changes,
            history,
        })
    }

    /// [`Doctor::examine`] with, for each backend in `records`, the results its sealed
    /// launch records and controlled negative launches decide added to `results`. A check
    /// given outcomes both ways gets them all, so the judge refuses two for one part; a
    /// check given a confinement verdict and record outcomes is refused. Records of another
    /// host build, or two sets for one backend, are refused; records of a backend this host
    /// does not examine, such as the fake, are refused as not a candidate.
    pub fn examine_with_records(
        &mut self,
        request: &DoctorRequest,
        context: &JudgeContext,
        mut results: BTreeMap<BackendKind, CheckInputs>,
        records: &[RecordResults],
    ) -> Result<DoctorReport, DoctorError> {
        let mut seen = BTreeSet::new();
        for source in records {
            let backend = source.backend().kind;
            if !seen.insert(backend) {
                return Err(DoctorError::RecordsGivenTwice { backend });
            }
            if *source.host() != request.host {
                return Err(DoctorError::RecordsOfOtherHost { backend });
            }
            let inputs = results.entry(backend).or_default();
            for (check, outcomes) in source.outcomes() {
                match inputs.entry(check) {
                    Entry::Vacant(entry) => {
                        entry.insert(CheckInput::Outcomes(outcomes));
                    }
                    Entry::Occupied(mut entry) => match entry.get_mut() {
                        CheckInput::Outcomes(given) => given.extend(outcomes),
                        CheckInput::Vm05(_) => {
                            return Err(DoctorError::ConflictingResults { backend, check })
                        }
                    },
                }
            }
        }
        self.examine(request, context, results)
    }

    /// The previous reports the store keeps, by backend; none when it keeps nothing yet.
    fn read_store(&mut self) -> Result<BTreeMap<BackendKind, RememberedReport>, HistoryError> {
        let bytes = self
            .store
            .read()
            .map_err(|failure| HistoryError::Unreadable {
                detail: failure.to_string(),
            })?;
        let Some(bytes) = bytes else {
            return Ok(BTreeMap::new());
        };
        Ok(decode_history(&bytes)?
            .into_iter()
            .map(|report| (report.backend, report))
            .collect())
    }

    /// Gives the store every previous report, replacing what it kept.
    fn keep(&mut self) -> Result<(), HistoryError> {
        let bytes = encode_history(self.previous.values())?;
        self.store
            .replace(&bytes)
            .map_err(|failure| HistoryError::NotKept {
                detail: failure.to_string(),
            })
    }
}

/// The results of `inputs` read from launch records, in check order, after checking that
/// each is of `backend` and of the examined host build.
fn recorded_results(
    backend: BackendKind,
    inputs: &CheckInputs,
    request: &DoctorRequest,
    context: &JudgeContext,
) -> Result<Vec<RecordedResult>, DoctorError> {
    let mut recorded = Vec::new();
    for input in inputs.values() {
        let CheckInput::Outcomes(outcomes) = input else {
            continue;
        };
        for outcome in outcomes {
            let Evidence::Record { run } = outcome.evidence() else {
                continue;
            };
            if run.backend().kind != backend {
                return Err(DoctorError::RecordsOfOtherBackend {
                    backend,
                    records: run.backend().kind,
                });
            }
            if *run.host() != request.host {
                return Err(DoctorError::RecordsOfOtherHost { backend });
            }
            recorded.push(RecordedResult {
                check: outcome.check(),
                part: outcome.part(),
                records: run.records(),
                refusals: run.refusals(),
                age: run.age_at(context.now),
            });
        }
    }
    Ok(recorded)
}
