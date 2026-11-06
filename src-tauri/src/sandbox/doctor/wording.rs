//! A check's status in the engine's own words, and what a check that did not pass expects
//! on this host in the plan's words, so a reader shows the doctor's sentences instead of
//! rewording its records (VM-W23, line 2622: "unsafe/unavailable GPU paths explained";
//! §17, lines 3145–3188, the expectation table; §7.1, lines 2356–2364).

use serde::{Deserialize, Serialize};

use super::plan::{observations, PlannedObservation};
use crate::foundation::evidence::OsKind;
use crate::sandbox::probes::{check, Applicability, CheckEntry, CheckId, CheckStatus};

/// The kind of a check's status, named as the report names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusKind {
    Passed,
    Failed,
    Inconclusive,
    NotTested,
    Refused,
}

impl StatusKind {
    pub const fn of(status: &CheckStatus) -> Self {
        match status {
            CheckStatus::Passed => Self::Passed,
            CheckStatus::Failed { .. } => Self::Failed,
            CheckStatus::Inconclusive { .. } => Self::Inconclusive,
            CheckStatus::NotTested { .. } => Self::NotTested,
            CheckStatus::Refused { .. } => Self::Refused,
        }
    }
}

/// A check's status with its reason, as the engine words it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatusText {
    pub status: StatusKind,
    /// The status and its reason in the engine's words, such as "not tested: it was not
    /// run" or "failed: expected that ..." with the expectation table's sentence.
    pub reason: String,
}

impl StatusText {
    pub fn of(status: &CheckStatus) -> Self {
        Self {
            status: StatusKind::of(status),
            reason: status.to_string(),
        }
    }
}

/// A check that did not pass on this host, in the engine's words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckExplanation {
    pub check: CheckId,
    /// Whether the run profiles refuse to start until it passes.
    pub required: bool,
    #[serde(flatten)]
    pub status: StatusText,
    /// What it expects on this host, its positive control included, in the plan's words:
    /// the observations the plan's dry run lists for it.
    pub expects: Vec<PlannedObservation>,
}

/// Every check of `entries` that did not pass, in check order, explained for a host of
/// `os`.
pub(super) fn not_passed(entries: &[CheckEntry], os: OsKind) -> Vec<CheckExplanation> {
    entries
        .iter()
        .filter(|entry| !entry.status.passed())
        .map(|entry| CheckExplanation {
            check: entry.check,
            required: entry.applicability == Applicability::Required,
            status: StatusText::of(&entry.status),
            expects: observations(check(entry.check), os),
        })
        .collect()
}
