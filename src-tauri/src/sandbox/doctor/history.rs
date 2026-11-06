//! The doctor's previous reports, kept so that the next examination can say what changed,
//! also after the engine restarts (VM-W23, line 2622: "Report changes without altering
//! host settings silently"; §8.1, lines 2433–2439: "Re-evaluate relevant evidence after
//! policy, firewall, backend, host-interface or artifact changes").
//!
//! Per backend the doctor keeps what a later report is compared with: the host build, the
//! configuration, whether launch was allowed and every check's status in the engine's
//! words ([`RememberedReport`]). It reaches its store only through the [`HistoryStore`]
//! port, as bytes: [`encode_history`] writes one versioned document with a digest over the
//! reports it keeps, and [`decode_history`] reads one back strictly. A history larger than
//! [`HISTORY_LIMIT`], one that does not parse, names another format, fails its digest,
//! keeps a backend twice or does not list every check once in table order is damaged: the
//! doctor reports it, compares with no part of it and replaces it with its next report.
//! Nothing here touches a file; the engine's store is in `runtime/doctor.rs`.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, Deserializer, Unexpected};
use serde::{Deserialize, Serialize};

use super::wording::{StatusKind, StatusText};
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{digest, Digest};
use crate::sandbox::backend::{BackendKind, HostBuild};
use crate::sandbox::probes::{catalog, BoundaryReport, CheckId};

/// The format of a kept history, also the domain of its digest.
pub const HISTORY_FORMAT: &str = "yougori/sandbox/doctor/history/v1";

/// The most bytes a kept history may hold. A store reads at most one byte more, so a
/// larger one is refused as damaged without being read whole.
pub const HISTORY_LIMIT: usize = 1 << 20;

/// How much of a damaged history's own text a refusal repeats.
const SHOWN: usize = 160;

/// One check of a kept report: its status in the engine's words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberedCheck {
    #[serde(deserialize_with = "check_named")]
    pub check: CheckId,
    pub status: StatusKind,
    pub reason: String,
}

impl RememberedCheck {
    fn text(&self) -> StatusText {
        StatusText {
            status: self.status,
            reason: self.reason.clone(),
        }
    }
}

/// One backend's report as the doctor keeps it to compare the next one with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberedReport {
    pub backend: BackendKind,
    pub host: HostBuild,
    pub configuration: ConfigurationFingerprint,
    /// Whether the run profiles could start on it: every required check had passed.
    pub launch_allowed: bool,
    /// Every check, in table order.
    pub checks: Vec<RememberedCheck>,
}

impl RememberedReport {
    pub fn of(report: &BoundaryReport) -> Self {
        Self {
            backend: report.profile().backend,
            host: report.profile().host.clone(),
            configuration: report.configuration(),
            launch_allowed: report.allows_launch(),
            checks: report
                .entries()
                .iter()
                .map(|entry| {
                    let text = StatusText::of(&entry.status);
                    RememberedCheck {
                        check: entry.check,
                        status: text.status,
                        reason: text.reason,
                    }
                })
                .collect(),
        }
    }

    /// What changed from `self` to `now`, two reports of one backend on one host build that
    /// both list every check in table order: the configuration, the launch, and every check
    /// whose status or its wording changed.
    pub(super) fn changes_to(&self, now: &Self) -> BackendChanges {
        BackendChanges {
            configuration_changed: self.configuration != now.configuration,
            launch_allowed_before: self.launch_allowed,
            launch_allowed_now: now.launch_allowed,
            checks: self
                .checks
                .iter()
                .zip(&now.checks)
                .filter(|(before, after)| before != after)
                .map(|(before, after)| StatusChange {
                    check: after.check,
                    before: before.text(),
                    after: after.text(),
                })
                .collect(),
        }
    }
}

/// One check whose status changed since the previous report, both in the engine's words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatusChange {
    pub check: CheckId,
    pub before: StatusText,
    pub after: StatusText,
}

/// What changed in one backend's report since its previous one on the same host build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackendChanges {
    pub configuration_changed: bool,
    pub launch_allowed_before: bool,
    pub launch_allowed_now: bool,
    /// Every check whose status changed, in check order.
    pub checks: Vec<StatusChange>,
}

impl BackendChanges {
    /// Whether anything changed at all.
    pub fn any(&self) -> bool {
        self.configuration_changed
            || self.launch_allowed_before != self.launch_allowed_now
            || !self.checks.is_empty()
    }
}

/// What an examination was compared with, and whether it was kept for the next one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct History {
    /// The backends whose previous report this examination was compared with. A backend
    /// not listed had none, so nothing is said about what changed for it.
    pub compared: Vec<BackendKind>,
    /// Why the kept previous reports were ignored, when the store could not be read or
    /// held a damaged history.
    pub ignored: Option<String>,
    /// Why this examination was not kept for the next one, when it could not be.
    pub not_kept: Option<String>,
}

impl History {
    pub(super) fn ignoring(&mut self, error: &HistoryError) {
        self.ignored = Some(format!(
            "The previous reports were ignored, and nothing is compared with them: {error}."
        ));
    }

    pub(super) fn not_keeping(&mut self, error: &HistoryError) {
        self.not_kept = Some(format!(
            "This report could not be kept for the next examination: {error}."
        ));
    }
}

/// Why a store could not be read or written, in its own words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreFailure {
    pub detail: String,
}

impl fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for StoreFailure {}

/// Where a doctor keeps its previous reports between examinations, as bytes.
pub trait HistoryStore {
    /// What the store keeps, or `None` when it keeps nothing yet. A store returns at most
    /// [`HISTORY_LIMIT`] + 1 bytes.
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreFailure>;

    /// Replaces what the store keeps with `bytes`, whole or not at all.
    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreFailure>;
}

/// The store of a doctor that keeps its previous reports in memory only, for as long as
/// it lives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryOnly;

impl HistoryStore for MemoryOnly {
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreFailure> {
        Ok(None)
    }

    fn replace(&mut self, _bytes: &[u8]) -> Result<(), StoreFailure> {
        Ok(())
    }
}

/// Why kept previous reports were not used, or a report was not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryError {
    /// The store could not be read.
    Unreadable { detail: String },
    /// The store could not keep the history.
    NotKept { detail: String },
    /// The history could not be written.
    Unencodable { detail: String },
    /// The history is larger than [`HISTORY_LIMIT`].
    TooLarge { bytes: usize },
    /// It is not a doctor history.
    Unparsable { detail: String },
    /// It names a format this engine does not read.
    OtherFormat { format: String },
    /// Its digest does not match the reports it keeps.
    DigestMismatch,
    /// It keeps two reports of one backend.
    BackendTwice { backend: BackendKind },
    /// Its report of `backend` does not list every check once, in table order.
    ChecksNotInTableOrder { backend: BackendKind },
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { detail } => write!(f, "the store could not be read ({detail})"),
            Self::NotKept { detail } => write!(f, "the store could not keep it ({detail})"),
            Self::Unencodable { detail } => write!(f, "it could not be written ({detail})"),
            Self::TooLarge { bytes } => write!(
                f,
                "the kept history holds {bytes} bytes or more, beyond the {HISTORY_LIMIT} a history may hold"
            ),
            Self::Unparsable { detail } => {
                write!(f, "the kept history is not a doctor history ({detail})")
            }
            Self::OtherFormat { format } => write!(
                f,
                "the kept history is in the format {format:?}, not {HISTORY_FORMAT:?}"
            ),
            Self::DigestMismatch => {
                f.write_str("the kept history's digest does not match the reports it keeps")
            }
            Self::BackendTwice { backend } => {
                write!(f, "the kept history keeps two reports of {backend:?}")
            }
            Self::ChecksNotInTableOrder { backend } => write!(
                f,
                "the kept report of {backend:?} does not list every check once, in table order"
            ),
        }
    }
}

impl std::error::Error for HistoryError {}

/// The document a history is written as.
#[derive(Serialize)]
struct WrittenHistory<'a> {
    format: &'static str,
    digest: Digest,
    reports: &'a [&'a RememberedReport],
}

/// The same document read back.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadHistory {
    format: String,
    digest: Digest,
    reports: Vec<RememberedReport>,
}

fn reports_digest(reports: &impl Serialize) -> Result<Digest, serde_json::Error> {
    Ok(digest(HISTORY_FORMAT, &[&serde_json::to_vec(reports)?]))
}

/// `text` with control characters replaced and cut to [`SHOWN`] characters, for a refusal
/// that repeats what a damaged history holds.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(SHOWN)
        .collect()
}

/// The history document keeping `reports`, one per backend.
pub fn encode_history<'a>(
    reports: impl IntoIterator<Item = &'a RememberedReport>,
) -> Result<Vec<u8>, HistoryError> {
    let reports: Vec<&RememberedReport> = reports.into_iter().collect();
    let unencodable = |error: serde_json::Error| HistoryError::Unencodable {
        detail: error.to_string(),
    };
    let bytes = serde_json::to_vec(&WrittenHistory {
        format: HISTORY_FORMAT,
        digest: reports_digest(&reports).map_err(unencodable)?,
        reports: &reports,
    })
    .map_err(unencodable)?;
    if bytes.len() > HISTORY_LIMIT {
        return Err(HistoryError::TooLarge { bytes: bytes.len() });
    }
    Ok(bytes)
}

/// The reports a history document keeps, or why it is damaged.
pub fn decode_history(bytes: &[u8]) -> Result<Vec<RememberedReport>, HistoryError> {
    if bytes.len() > HISTORY_LIMIT {
        return Err(HistoryError::TooLarge { bytes: bytes.len() });
    }
    let read: ReadHistory =
        serde_json::from_slice(bytes).map_err(|error| HistoryError::Unparsable {
            detail: shown(&error.to_string()),
        })?;
    if read.format != HISTORY_FORMAT {
        return Err(HistoryError::OtherFormat {
            format: shown(&read.format),
        });
    }
    let kept = reports_digest(&read.reports).map_err(|error| HistoryError::Unparsable {
        detail: shown(&error.to_string()),
    })?;
    if kept != read.digest {
        return Err(HistoryError::DigestMismatch);
    }
    let mut backends = BTreeSet::new();
    for report in &read.reports {
        if !backends.insert(report.backend) {
            return Err(HistoryError::BackendTwice {
                backend: report.backend,
            });
        }
        if !report
            .checks
            .iter()
            .map(|entry| entry.check)
            .eq(catalog().iter().map(|row| row.id))
        {
            return Err(HistoryError::ChecksNotInTableOrder {
                backend: report.backend,
            });
        }
    }
    Ok(read.reports)
}

/// Reads a check by the name the report writes for it, `VM-CP-01` to `VM-CP-35`, exactly.
fn check_named<'de, D: Deserializer<'de>>(deserializer: D) -> Result<CheckId, D::Error> {
    let name = String::deserialize(deserializer)?;
    CheckId::all()
        .find(|id| id.to_string() == name)
        .ok_or_else(|| {
            de::Error::invalid_value(Unexpected::Str(&name), &"a check VM-CP-01 to VM-CP-35")
        })
}
