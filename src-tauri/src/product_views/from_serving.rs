//! A model's declared agent endpoint in the CORE-07 contract's shape (S2 CORE-07
//! "declared agent endpoint capabilities"; GPU-W11: "Declare supported agent endpoint
//! dialects and model/tool combinations through CORE-07"; S9 line 165).
//!
//! Each conversion reads the serving protocol's own types: a dialect and a feature map one
//! to one onto the contract's, a row's cell onto the contract's cell, and the conformance
//! run a row was built from onto the run the contract shows, through the protocol's own
//! summary of it ([`ProtocolCorrectness`]). Nothing here decides again whether a feature
//! is supported or a dialect advertised: the serving protocol's row decides each cell, and
//! the contract decides the evidence each stands on. A row is shown only with the run it
//! was built from, for the endpoint's own model and runner.

use std::fmt;
use std::time::Duration;

use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint};
use crate::foundation::ids::Digest;
use crate::foundation::product::{
    AgentEndpoint, CellShown, ConformanceShown, DialectShown, EndpointDialect, EndpointError,
    EndpointFeature, ShownText, UnsupportedReason,
};
use crate::serving_protocol::{
    CapabilityRow, CellStatus, ConformanceRun, Dialect, Feature, ProtocolCorrectness, RunOrigin,
    RunnerRef, UnsupportedFeature,
};

impl From<Dialect> for EndpointDialect {
    fn from(dialect: Dialect) -> Self {
        match dialect {
            Dialect::OpenAiChatCompletions => Self::OpenAiChatCompletions,
            Dialect::OpenAiResponses => Self::OpenAiResponses,
            Dialect::AnthropicMessages => Self::AnthropicMessages,
        }
    }
}

impl From<EndpointDialect> for Dialect {
    fn from(dialect: EndpointDialect) -> Self {
        match dialect {
            EndpointDialect::OpenAiChatCompletions => Self::OpenAiChatCompletions,
            EndpointDialect::OpenAiResponses => Self::OpenAiResponses,
            EndpointDialect::AnthropicMessages => Self::AnthropicMessages,
        }
    }
}

impl From<Feature> for EndpointFeature {
    fn from(feature: Feature) -> Self {
        match feature {
            Feature::RequestFields => Self::RequestFields,
            Feature::SystemContextPreservation => Self::SystemContextPreservation,
            Feature::ToolSchema => Self::ToolSchema,
            Feature::ToolChoice => Self::ToolChoice,
            Feature::StreamingDeltas => Self::StreamingDeltas,
            Feature::ParallelCalls => Self::ParallelCalls,
            Feature::FinishReason => Self::FinishReason,
            Feature::Usage => Self::Usage,
            Feature::TokenCounting => Self::TokenCounting,
            Feature::Errors => Self::Errors,
            Feature::Cancellation => Self::Cancellation,
        }
    }
}

impl From<EndpointFeature> for Feature {
    fn from(feature: EndpointFeature) -> Self {
        match feature {
            EndpointFeature::RequestFields => Self::RequestFields,
            EndpointFeature::SystemContextPreservation => Self::SystemContextPreservation,
            EndpointFeature::ToolSchema => Self::ToolSchema,
            EndpointFeature::ToolChoice => Self::ToolChoice,
            EndpointFeature::StreamingDeltas => Self::StreamingDeltas,
            EndpointFeature::ParallelCalls => Self::ParallelCalls,
            EndpointFeature::FinishReason => Self::FinishReason,
            EndpointFeature::Usage => Self::Usage,
            EndpointFeature::TokenCounting => Self::TokenCounting,
            EndpointFeature::Errors => Self::Errors,
            EndpointFeature::Cancellation => Self::Cancellation,
        }
    }
}

impl From<&UnsupportedFeature> for UnsupportedReason {
    fn from(reason: &UnsupportedFeature) -> Self {
        match reason {
            UnsupportedFeature::NotInDialect => Self::NotInDialect,
            UnsupportedFeature::ConformanceFailed { case, mismatch } => Self::ConformanceFailed {
                case: case.clone(),
                mismatch: ShownText::new(mismatch),
            },
            UnsupportedFeature::DeclaredByRunner { explanation } => Self::DeclaredByRunner {
                explanation: ShownText::new(explanation),
            },
        }
    }
}

/// A row's cell, citing how many passing cases exercised a supported feature.
impl From<&CellStatus> for CellShown {
    fn from(cell: &CellStatus) -> Self {
        match cell {
            CellStatus::Supported { evidence } => Self::Supported {
                cases: u64::try_from(evidence.cases.len()).unwrap_or(u64::MAX),
            },
            CellStatus::Unsupported { reason } => Self::Unsupported {
                reason: UnsupportedReason::from(reason),
            },
            CellStatus::Untested => Self::Untested,
        }
    }
}

/// The run as the serving protocol summarises it (S9 line 171), with the configuration it
/// observed and when.
impl From<&ConformanceRun> for ConformanceShown {
    fn from(run: &ConformanceRun) -> Self {
        let summary = ProtocolCorrectness::of_run(run);
        Self {
            run: summary.run,
            configuration: run.configuration(),
            observed_at: run.observed_at(),
            cases: summary.cases,
            failed: summary.failed,
        }
    }
}

/// One dialect's published capability row with the conformance run it was built from.
#[derive(Clone, Copy, Debug)]
pub struct PublishedRow<'a> {
    pub row: &'a CapabilityRow,
    pub run: &'a ConformanceRun,
}

/// What `model` served by `runner` declares, per dialect, from its published rows: a
/// dialect without a row is shown unpublished. Each row's features stand on its run,
/// observed under `current`, the runner's launch configuration now, judged at `now`, a
/// reading of the evidence clock the runs' times were read from, and current for
/// `fresh_for` after each run. Refused when a row or run is for another model or runner,
/// a dialect has two rows, a run is not the one its row was built from, or the contract
/// refuses what they show.
pub fn agent_endpoint(
    model: Digest,
    runner: &RunnerRef,
    rows: &[PublishedRow<'_>],
    current: ConfigurationFingerprint,
    now: ClockReading,
    fresh_for: Duration,
) -> Result<AgentEndpoint, EndpointSourceError> {
    let mut dialects = Vec::with_capacity(EndpointDialect::ALL.len());
    for dialect in EndpointDialect::ALL {
        let source = Dialect::from(dialect);
        let mut published = rows
            .iter()
            .filter(|published| published.row.key().dialect == source);
        let shown = match (published.next(), published.next()) {
            (None, _) => DialectShown::unpublished(dialect),
            (Some(_), Some(_)) => return Err(EndpointSourceError::DuplicateDialect { dialect }),
            (Some(published), None) => {
                belongs(model, runner, published, dialect)?;
                let row = published.row;
                DialectShown::published(
                    dialect,
                    ConformanceShown::from(published.run),
                    |feature| CellShown::from(row.cell(Feature::from(feature))),
                    current,
                    now,
                    fresh_for,
                )
                .map_err(EndpointSourceError::Contract)?
            }
        };
        dialects.push(shown);
    }
    AgentEndpoint::new(model, runner.release.clone(), runner.category, dialects)
        .map_err(EndpointSourceError::Contract)
}

/// The row is the endpoint's model and runner, and the run is the one it was built from:
/// the host's live run of the row's dialect against that model and runner, under the
/// row's configuration, and the run every supported cell cites.
fn belongs(
    model: Digest,
    runner: &RunnerRef,
    published: &PublishedRow<'_>,
    dialect: EndpointDialect,
) -> Result<(), EndpointSourceError> {
    let PublishedRow { row, run } = *published;
    let key = row.key();
    if key.model != model || key.runner != *runner {
        return Err(EndpointSourceError::OtherSubject { dialect });
    }
    let RunOrigin::LiveRunner {
        model: observed,
        runner: served,
        ..
    } = run.origin()
    else {
        return Err(EndpointSourceError::NotTheRowsRun { dialect });
    };
    let identity = run.identity();
    let cites_run = Feature::ALL
        .into_iter()
        .all(|feature| match row.cell(feature) {
            CellStatus::Supported { evidence } => evidence.run == identity,
            CellStatus::Unsupported { .. } | CellStatus::Untested => true,
        });
    if run.dialect() != key.dialect
        || *observed != key.model
        || *served != key.runner
        || run.configuration() != row.configuration()
        || !cites_run
    {
        return Err(EndpointSourceError::NotTheRowsRun { dialect });
    }
    Ok(())
}

/// Why the serving protocol's rows and runs do not make one endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointSourceError {
    /// A row is for another model or runner than the endpoint's.
    OtherSubject { dialect: EndpointDialect },
    /// A dialect has more than one row.
    DuplicateDialect { dialect: EndpointDialect },
    /// The run is not the one the row was built from.
    NotTheRowsRun { dialect: EndpointDialect },
    /// The contract refused what the rows and runs show.
    Contract(EndpointError),
}

impl fmt::Display for EndpointSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherSubject { dialect } => write!(
                f,
                "the {dialect} row describes another model or runner than this endpoint's"
            ),
            Self::DuplicateDialect { dialect } => {
                write!(f, "{dialect} has more than one published row")
            }
            Self::NotTheRowsRun { dialect } => write!(
                f,
                "the {dialect} conformance run is not the one its row was built from"
            ),
            Self::Contract(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for EndpointSourceError {}
