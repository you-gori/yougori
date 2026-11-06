//! Capability rows per model, runner and dialect (S9 line 165; GPU-W11 line 1150; S12 G2).
//!
//! Each feature of a row is supported (citing the conformance run and passing cases that
//! exercised it), unsupported (with a reason) or untested. Rows are built only from a
//! conformance run of the row's own dialect, observed by the host's own harness against
//! the row's own model and runner: fixture runs prove this module, not a runner, a run
//! never describes a model or runner it did not contact, and a run in one dialect never
//! yields a row for another. A dialect is advertised only when no feature is untested
//! and the features every exchange uses are supported, under the configuration the
//! evidence was observed with, so one successful chat completion never advertises it.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use crate::foundation::evidence::{BackendRelease, ConfigurationFingerprint, SourceClass};
use crate::foundation::ids::{Digest, ExecutionCategory};
use crate::foundation::report::Label;

use super::conformance::{ConformanceRun, RunOrigin};
use super::dialect::{Dialect, Feature};
use super::request::RequestProfile;

/// The runner a row describes: one backend at an exact release, in a labelled execution
/// category, since the model-serving mode stays labelled under VM-D4–VM-D6 (S12 G2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RunnerRef {
    pub release: BackendRelease,
    pub category: ExecutionCategory,
}

/// A row's key (S9 line 165: "for each supported model/runner/dialect").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RowKey {
    /// The model's identity digest.
    pub model: Digest,
    pub runner: RunnerRef,
    pub dialect: Dialect,
}

/// The conformance evidence behind a supported feature (S9 line 165).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CellEvidence {
    /// [`ConformanceRun::identity`] of the run.
    pub run: Digest,
    /// The passing cases that exercised the feature.
    pub cases: Vec<Label>,
}

/// Why a feature is unsupported; an unsupported combination always says why
/// (S9 line 165).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnsupportedFeature {
    /// The dialect has no such feature (Chat Completions token counting).
    NotInDialect,
    /// A case exercising the feature failed in the row's run.
    ConformanceFailed { case: Label, mismatch: String },
    /// The runner's adapter declares it unsupported.
    DeclaredByRunner { explanation: String },
}

impl fmt::Display for UnsupportedFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInDialect => f.write_str("the dialect does not define it"),
            Self::ConformanceFailed { case, mismatch } => {
                write!(f, "conformance case {case} failed: {mismatch}")
            }
            Self::DeclaredByRunner { explanation } => {
                write!(f, "the runner does not support it: {explanation}")
            }
        }
    }
}

/// One feature's state in a row (S9 line 165; S11 "untested combinations are recorded as
/// such").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CellStatus {
    Supported { evidence: CellEvidence },
    Unsupported { reason: UnsupportedFeature },
    Untested,
}

static UNTESTED: CellStatus = CellStatus::Untested;

/// Why a row could not be built (S9 line 165).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowError {
    /// A run in one dialect cannot describe another: no generic proxy promises complete
    /// semantic conversion (S7 line 126).
    DialectMismatch { run: Dialect, row: Dialect },
    /// The run's observations do not come from the host's own harness against the
    /// runner; fixtures and declarations never show support.
    InsufficientSource {
        found: SourceClass,
        required: SourceClass,
    },
    /// The run contacted another model than the row's.
    OtherModel { run: Digest, row: Digest },
    /// The run contacted another runner than the row's.
    OtherRunner { run: RunnerRef, row: RunnerRef },
    /// A runner's declaration of an unsupported feature must say why.
    EmptyExplanation { feature: Feature },
}

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DialectMismatch { run, row } => {
                write!(f, "a {run} run cannot describe a {row} row")
            }
            Self::InsufficientSource { found, required } => {
                write!(
                    f,
                    "evidence from a {found} cannot show support; a {required} is required"
                )
            }
            Self::OtherModel { .. } => {
                f.write_str("the run observed another model, so it cannot describe this one")
            }
            Self::OtherRunner { run, row } => write!(
                f,
                "the run observed {} ({}), so it cannot describe {} ({})",
                run.release,
                run.category.label(),
                row.release,
                row.category.label()
            ),
            Self::EmptyExplanation { feature } => {
                write!(
                    f,
                    "the declaration that {feature} is unsupported gives no reason"
                )
            }
        }
    }
}

impl std::error::Error for RowError {}

/// Why a dialect is not advertised for a row (S9 line 165).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotAdvertised {
    pub untested: Vec<Feature>,
    /// Features every exchange uses that are not supported.
    pub unsupported_every_exchange: Vec<Feature>,
}

/// Why a request is refused for a model, runner and dialect (S9 line 165: unsupported
/// combinations return an explicit reason).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CapabilityRefusal {
    /// No row was published for this combination.
    NoRow {
        model: Digest,
        runner: RunnerRef,
        dialect: Dialect,
    },
    DialectMismatch {
        row: Dialect,
        request: Dialect,
    },
    /// The row's evidence was observed under another configuration (CORE-01).
    ConfigurationChanged {
        evidence: ConfigurationFingerprint,
        current: ConfigurationFingerprint,
    },
    NotAdvertised {
        reasons: NotAdvertised,
    },
    /// Features the request needs that the row does not support, with their reasons.
    Unsupported {
        features: Vec<(Feature, UnsupportedFeature)>,
    },
}

impl fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRow {
                runner, dialect, ..
            } => write!(
                f,
                "no capability row for this model on {} in {dialect}",
                runner.release
            ),
            Self::DialectMismatch { row, request } => {
                write!(f, "the row is for {row}, the request is {request}")
            }
            Self::ConfigurationChanged { .. } => {
                f.write_str("the configuration changed since the row's evidence was observed")
            }
            Self::NotAdvertised { reasons } => write!(
                f,
                "the dialect is not advertised: untested {:?}, unsupported {:?}",
                reasons.untested, reasons.unsupported_every_exchange
            ),
            Self::Unsupported { features } => {
                f.write_str("unsupported:")?;
                for (feature, reason) in features {
                    write!(f, " {feature} ({reason});")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for CapabilityRefusal {}

/// The published capabilities of one model, runner and dialect (S9 line 165).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityRow {
    key: RowKey,
    configuration: ConfigurationFingerprint,
    run: Digest,
    cells: BTreeMap<Feature, CellStatus>,
}

impl CapabilityRow {
    /// The only source whose conformance runs can show support: the host's own harness
    /// observing the runner's responses.
    pub const REQUIRED_SOURCE: SourceClass = SourceClass::HostProbe;

    /// Builds a row from a conformance run of `dialect` that the host's own harness made
    /// against exactly this `model` and `runner`. A feature is unsupported when the
    /// dialect lacks it, the runner declares it unsupported, or any case exercising it
    /// failed; supported when at least one case exercised it and all of them passed;
    /// untested otherwise.
    pub fn from_run(
        model: Digest,
        runner: RunnerRef,
        dialect: Dialect,
        run: &ConformanceRun,
        declared_unsupported: &[(Feature, String)],
    ) -> Result<Self, RowError> {
        if run.dialect() != dialect {
            return Err(RowError::DialectMismatch {
                run: run.dialect(),
                row: dialect,
            });
        }
        if !run.source().satisfies(Self::REQUIRED_SOURCE) {
            return Err(RowError::InsufficientSource {
                found: run.source(),
                required: Self::REQUIRED_SOURCE,
            });
        }
        let RunOrigin::LiveRunner {
            model: observed,
            runner: served,
            ..
        } = run.origin()
        else {
            return Err(RowError::InsufficientSource {
                found: run.source(),
                required: Self::REQUIRED_SOURCE,
            });
        };
        if *observed != model {
            return Err(RowError::OtherModel {
                run: *observed,
                row: model,
            });
        }
        if *served != runner {
            return Err(RowError::OtherRunner {
                run: served.clone(),
                row: runner,
            });
        }
        if let Some((feature, _)) = declared_unsupported
            .iter()
            .find(|(_, explanation)| explanation.trim().is_empty())
        {
            return Err(RowError::EmptyExplanation { feature: *feature });
        }
        let identity = run.identity();
        let mut cells = BTreeMap::new();
        for feature in Feature::ALL {
            let exercising = || {
                run.verdicts()
                    .iter()
                    .filter(move |verdict| verdict.exercised().contains(&feature))
            };
            let status = if !feature.in_dialect(dialect) {
                CellStatus::Unsupported {
                    reason: UnsupportedFeature::NotInDialect,
                }
            } else if let Some((_, explanation)) = declared_unsupported
                .iter()
                .find(|(declared, _)| *declared == feature)
            {
                CellStatus::Unsupported {
                    reason: UnsupportedFeature::DeclaredByRunner {
                        explanation: explanation.clone(),
                    },
                }
            } else if let Some(failed) = exercising().find(|verdict| !verdict.passed()) {
                CellStatus::Unsupported {
                    reason: UnsupportedFeature::ConformanceFailed {
                        case: failed.case().clone(),
                        mismatch: failed.mismatches().join("; "),
                    },
                }
            } else {
                let cases: Vec<Label> =
                    exercising().map(|verdict| verdict.case().clone()).collect();
                if cases.is_empty() {
                    CellStatus::Untested
                } else {
                    CellStatus::Supported {
                        evidence: CellEvidence {
                            run: identity,
                            cases,
                        },
                    }
                }
            };
            cells.insert(feature, status);
        }
        Ok(Self {
            key: RowKey {
                model,
                runner,
                dialect,
            },
            configuration: run.configuration(),
            run: identity,
            cells,
        })
    }

    /// The model, runner and dialect the row describes.
    pub fn key(&self) -> &RowKey {
        &self.key
    }

    /// The configuration the row's evidence was observed under.
    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// The state of one feature (S9 line 165).
    pub fn cell(&self, feature: Feature) -> &CellStatus {
        self.cells.get(&feature).unwrap_or(&UNTESTED)
    }

    /// The execution-category label the row is shown with (S12 G2: VM-D4–VM-D6).
    pub fn runtime_label(&self) -> &'static str {
        self.key.runner.category.label()
    }

    /// Whether the row's evidence lets the dialect be advertised for this model and
    /// runner (S9 line 165). The evidence holds only under [`Self::configuration`]: what
    /// is advertised now is [`CapabilityTable::advertised_dialects`], which checks it.
    pub fn advertisement(&self) -> Result<(), NotAdvertised> {
        let untested: Vec<Feature> = Feature::ALL
            .into_iter()
            .filter(|feature| *self.cell(*feature) == CellStatus::Untested)
            .collect();
        let unsupported_every_exchange: Vec<Feature> = Feature::EVERY_EXCHANGE
            .into_iter()
            .filter(|feature| !matches!(self.cell(*feature), CellStatus::Supported { .. }))
            .collect();
        if untested.is_empty() && unsupported_every_exchange.is_empty() {
            Ok(())
        } else {
            Err(NotAdvertised {
                untested,
                unsupported_every_exchange,
            })
        }
    }

    /// Admits a request whose every needed feature is supported, under the
    /// configuration the evidence was observed with (S9 line 165).
    pub fn admit(
        &self,
        request: &RequestProfile,
        configuration: ConfigurationFingerprint,
    ) -> Result<(), CapabilityRefusal> {
        if request.dialect() != self.key.dialect {
            return Err(CapabilityRefusal::DialectMismatch {
                row: self.key.dialect,
                request: request.dialect(),
            });
        }
        if configuration != self.configuration {
            return Err(CapabilityRefusal::ConfigurationChanged {
                evidence: self.configuration,
                current: configuration,
            });
        }
        self.advertisement()
            .map_err(|reasons| CapabilityRefusal::NotAdvertised { reasons })?;
        let mut features = Vec::new();
        for feature in request.needs() {
            match self.cell(*feature) {
                CellStatus::Supported { .. } => {}
                CellStatus::Unsupported { reason } => features.push((*feature, reason.clone())),
                // An advertised row has no untested feature; refused all the same.
                CellStatus::Untested => {
                    return Err(CapabilityRefusal::NotAdvertised {
                        reasons: NotAdvertised {
                            untested: vec![*feature],
                            unsupported_every_exchange: Vec::new(),
                        },
                    })
                }
            }
        }
        if features.is_empty() {
            Ok(())
        } else {
            Err(CapabilityRefusal::Unsupported { features })
        }
    }
}

/// The published rows (S9 line 165; GPU-W11: declared through CORE-07).
#[derive(Clone, Debug, Default)]
pub struct CapabilityTable {
    rows: BTreeMap<RowKey, CapabilityRow>,
}

impl CapabilityTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes a row, replacing an earlier one for the same key.
    pub fn publish(&mut self, row: CapabilityRow) -> Option<CapabilityRow> {
        self.rows.insert(row.key.clone(), row)
    }

    /// Every published row, in key order.
    pub fn rows(&self) -> impl Iterator<Item = &CapabilityRow> {
        self.rows.values()
    }

    /// The row for a combination, or the refusal that none was published.
    pub fn row(
        &self,
        model: Digest,
        runner: &RunnerRef,
        dialect: Dialect,
    ) -> Result<&CapabilityRow, CapabilityRefusal> {
        let key = RowKey {
            model,
            runner: runner.clone(),
            dialect,
        };
        self.rows.get(&key).ok_or(CapabilityRefusal::NoRow {
            model,
            runner: runner.clone(),
            dialect,
        })
    }

    /// Admits a request against the row of its own dialect.
    pub fn admit(
        &self,
        model: Digest,
        runner: &RunnerRef,
        request: &RequestProfile,
        configuration: ConfigurationFingerprint,
    ) -> Result<(), CapabilityRefusal> {
        self.row(model, runner, request.dialect())?
            .admit(request, configuration)
    }

    /// The dialects advertised for a model and runner launched under `configuration`:
    /// those whose row's evidence was observed under that same configuration and allows
    /// advertising, as [`Self::admit`] requires (CORE-01 fingerprint).
    pub fn advertised_dialects(
        &self,
        model: Digest,
        runner: &RunnerRef,
        configuration: ConfigurationFingerprint,
    ) -> Vec<Dialect> {
        Dialect::ALL
            .into_iter()
            .filter(|dialect| {
                self.row(model, runner, *dialect).is_ok_and(|row| {
                    row.configuration == configuration && row.advertisement().is_ok()
                })
            })
            .collect()
    }
}
