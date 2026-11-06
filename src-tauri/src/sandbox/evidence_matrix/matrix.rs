//! The evidence matrix: one row per combination, and what changed between two matrices
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §7.1, lines 2356–2364; VM-W23, line
//! 2622, "Report changes without altering host settings silently"; VM-W51, line 2674;
//! E02 of the leftover tracker: "Unsupported or unavailable combinations remain
//! explicit").
//!
//! A combination without a row is unavailable. Rows are kept by combination identity, one
//! each; a newer examination of the same combinations is a new matrix, and
//! [`EvidenceMatrix::changes_since`] says what changed: the combinations added and
//! removed, and for a combination in both, its label, the fields whose value, source,
//! freshness or availability changed, and what the doctor's checks did.

use std::collections::BTreeMap;
use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::field::RowField;
use super::row::MatrixRow;
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{BackendKind, HostBuild};
use crate::sandbox::doctor::Label;
use crate::sandbox::probes::ReportChanges;

/// What every matrix states about itself.
pub const MATRIX_NOTICE: &str = "The evidence matrix lists one row per combination that evidence exists for. A combination without a row is unavailable. Each row's label is the doctor's, as its basis states; a row is never supported by a test of another combination (section 7.1).";

/// Why a row was not added to a matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum MatrixError {
    /// The matrix already has a row for this combination.
    DuplicateCombination { combination: Digest },
}

impl fmt::Display for MatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCombination { combination } => write!(
                f,
                "the matrix already has a row for combination {combination}"
            ),
        }
    }
}

impl std::error::Error for MatrixError {}

/// The evidence rows of one matrix, by combination. Serialize only, as its notice and
/// its rows in combination order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvidenceMatrix {
    rows: BTreeMap<Digest, MatrixRow>,
}

impl EvidenceMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a row; one row per combination.
    pub fn add(&mut self, row: MatrixRow) -> Result<(), MatrixError> {
        let combination = row.combination();
        if self.rows.contains_key(&combination) {
            return Err(MatrixError::DuplicateCombination { combination });
        }
        self.rows.insert(combination, row);
        Ok(())
    }

    pub fn row(&self, combination: &Digest) -> Option<&MatrixRow> {
        self.rows.get(combination)
    }

    /// Every row, in combination order.
    pub fn rows(&self) -> impl Iterator<Item = &MatrixRow> {
        self.rows.values()
    }

    /// The label of a combination: its row's, and unavailable without a row.
    pub fn label_of(&self, combination: &Digest) -> Label {
        self.row(combination)
            .map_or(Label::Unavailable, MatrixRow::label)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// What changed since `earlier`, in combination order.
    pub fn changes_since(&self, earlier: &EvidenceMatrix) -> MatrixChanges {
        let added = self
            .rows
            .iter()
            .filter(|(combination, _)| !earlier.rows.contains_key(*combination))
            .map(|(_, row)| RowSummary::of(row))
            .collect();
        let removed = earlier
            .rows
            .iter()
            .filter(|(combination, _)| !self.rows.contains_key(*combination))
            .map(|(_, row)| RowSummary::of(row))
            .collect();
        let mut changed = Vec::new();
        let mut unchanged = 0;
        for (combination, now) in &self.rows {
            let Some(before) = earlier.rows.get(combination) else {
                continue;
            };
            if now == before {
                unchanged += 1;
                continue;
            }
            let fields = RowField::ALL
                .into_iter()
                .filter(|field| !now.same(before, *field))
                .collect();
            let report = match (now.result().value(), before.result().value()) {
                (Some(now), Some(before)) if now.report.identity() != before.report.identity() => {
                    now.report.changes_since(&before.report).ok()
                }
                _ => None,
            };
            changed.push(RowChange {
                summary: RowSummary::of(now),
                label_before: before.label(),
                fields,
                report,
            });
        }
        MatrixChanges {
            added,
            removed,
            changed,
            unchanged,
        }
    }
}

impl Serialize for EvidenceMatrix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let rows: Vec<&MatrixRow> = self.rows.values().collect();
        let mut state = serializer.serialize_struct("EvidenceMatrix", 2)?;
        state.serialize_field("notice", MATRIX_NOTICE)?;
        state.serialize_field("rows", &rows)?;
        state.end()
    }
}

/// A row, by its combination, host, backend and label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RowSummary {
    pub combination: Digest,
    pub host: Option<HostBuild>,
    pub backend: Option<BackendKind>,
    pub label: Label,
}

impl RowSummary {
    fn of(row: &MatrixRow) -> Self {
        Self {
            combination: row.combination(),
            host: row.host_build().cloned(),
            backend: row.backend_kind(),
            label: row.label(),
        }
    }
}

/// What changed for a combination in both matrices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RowChange {
    /// The combination with its label now.
    pub summary: RowSummary,
    pub label_before: Label,
    /// The fields whose value, source, freshness or availability changed, in row order.
    pub fields: Vec<RowField>,
    /// What the doctor's checks did, when the doctor's report changed.
    pub report: Option<ReportChanges>,
}

/// What changed between two matrices. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MatrixChanges {
    /// Combinations with a row now and none before.
    pub added: Vec<RowSummary>,
    /// Combinations with a row before and none now: unavailable now.
    pub removed: Vec<RowSummary>,
    pub changed: Vec<RowChange>,
    /// How many combinations have the same row in both.
    pub unchanged: usize,
}

impl MatrixChanges {
    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}
