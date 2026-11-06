//! Typed refusals of the measurement contract (CORE-08). Nothing in this module panics or
//! falls back silently; every refusal names what was wrong (S1).

use std::fmt;

use super::bench::BenchId;
use super::claims::TrackedResource;
use super::compare::{BaselineRole, ConfigurationField};
use super::events::{EventName, IntervalKind};
use super::fidelity::QualityLayer;
use super::text::Label;

/// What is wrong with a URL offered as a public source (S7 public comparison).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlProblem {
    TooLong,
    NotHttps,
    InvalidCharacter,
    QueryOrFragment,
    Credentials,
    InvalidHost,
    PrivateHost,
    OpaqueSegment,
}

impl UrlProblem {
    const fn describe(self) -> &'static str {
        match self {
            Self::TooLong => "it is too long",
            Self::NotHttps => "it is not an https URL",
            Self::InvalidCharacter => "it contains a character outside a plain path",
            Self::QueryOrFragment => "it has a query string or fragment",
            Self::Credentials => "it carries user information",
            Self::InvalidHost => "its host is not a lowercase public host name without a port",
            Self::PrivateHost => "its host is local, private or an IP address",
            Self::OpaqueSegment => "a path segment looks like a token",
        }
    }
}

/// Why the measurement contract refused a value, record or report.
#[derive(Clone, Debug, PartialEq)]
pub enum ReportError {
    // Redaction (S8).
    EmptyLabel,
    LabelTooLong {
        max: usize,
    },
    InvalidLabelCharacter {
        character: char,
    },
    LabelInvalidStart,
    LooksLikePath,
    LooksLikeCredential,
    InvalidPublicUrl {
        problem: UrlProblem,
    },
    InvalidCommitHash,
    NotPublishable {
        fixture: Label,
    },
    // Numbers and format.
    InvalidNumber,
    UnsupportedSchemaVersion {
        found: u64,
    },
    Encoding,
    /// A JSON document that does not parse, located by position only: the parser's own
    /// message can quote the document, which may hold a prompt or a path (S8).
    Malformed {
        line: usize,
        column: usize,
    },
    // Events and clocks (S8, §2.1).
    EventFromAnotherRun,
    SequenceNotIncreasing,
    ClockWentBackwards,
    DuplicateEvent {
        event: EventName,
    },
    MissingEvent {
        event: EventName,
    },
    WrongEvent {
        interval: IntervalKind,
        expected: EventName,
        found: EventName,
    },
    DifferentRuns {
        interval: IntervalKind,
    },
    DifferentClocks {
        interval: IntervalKind,
    },
    EndBeforeStart {
        interval: IntervalKind,
    },
    NotIntendedGuest,
    VramAboveBaseline,
    DemandWorkOutsideFirstTokenClock,
    UndeclaredDemandWork,
    SwitchModeMismatch,
    ControlledGapNotHonoured {
        declared_nanos: u64,
        measured_nanos: u64,
    },
    NotSameRequest,
    DurationOverflow,
    // Run records (S8, S13 FAST-01).
    MissingStartState,
    InconsistentStartState,
    ScenarioCategoryMismatch,
    InvalidStagePrimary,
    MissingLicense,
    InvalidRetry,
    TokenCountMismatch {
        recorded: u64,
        events: u64,
    },
    InconsistentMeasurement,
    MissingScenarioMeasurement,
    NonceAltersPairedTask,
    SuccessAfterDeadline {
        interval: IntervalKind,
    },
    InconsistentDeadline,
    ReasoningCheckMismatch,
    ReasoningNotPassed,
    // Attempts and denominators (S8).
    DuplicateAttempt,
    UnknownFirstAttempt,
    RetryOfRetry,
    DuplicateRetryNumber,
    RetryAfterSuccess,
    MixedCases,
    NoAttempts,
    NoSuccessfulRuns,
    // Statistics (S8, S11, S13).
    SuccessesExceedAttempts,
    InvalidQuantile,
    InvalidDistribution,
    InvalidRatio,
    InconsistentSummary,
    DuplicatePairedItem,
    LowResolution {
        tail_samples: u64,
        bursts: u64,
    },
    EmptyObservationWindow,
    CountOverflow,
    TooManyPairsForExactTest {
        pairs: u64,
        max: u64,
    },
    // Fidelity (S9, S12, S13).
    ReferenceUnavailable,
    NotComparableEvidence,
    NotIdentical,
    RandomSampling,
    NoTokensCompared,
    IncompleteQualityEvidence {
        layer: QualityLayer,
    },
    // Cost (S8).
    WrongPriceUnit,
    PriceFromFuture,
    StalePrice,
    MissingConcurrencyCurve,
    CostUndefined,
    // Comparison (§1.1, §1.3, §2.1).
    MismatchedObjectiveDeclarations,
    DeclaredObjectiveNotMeasured,
    MissingConfiguration,
    NotComparable {
        fields: Vec<ConfigurationField>,
    },
    CategoryChanged,
    LossyWithoutAccuracyEvaluation,
    MultiplicationRefused {
        parts: usize,
    },
    WarmVersusColdMislabel,
    StateMismatch,
    MissingBaseline {
        which: BaselineRole,
    },
    AmbiguousOrdinaryBaseline,
    ThirdPartyNotReproduced,
    TooFewTrials {
        trials: u32,
        required: u32,
    },
    PredictableTrace,
    MissingAblation {
        component: Label,
    },
    UnknownAblation {
        component: Label,
    },
    NotImproved,
    // Claims and BENCH records (S7, S11, S12).
    TrimmedScoreNotReleaseEvidence,
    WrongScenarioForClaim,
    InsufficientBurstScale {
        claimed: u64,
        observed: u64,
    },
    SoakTooShort {
        seconds: u64,
        required: u64,
    },
    NoRepeatedCycles,
    RecycledDuringSoak {
        recycles: u64,
    },
    CanaryFailures {
        failures: u64,
    },
    MissingTrackedResource {
        resource: TrackedResource,
    },
    ResourceGrowth {
        resource: TrackedResource,
    },
    IncompleteApplicability {
        missing: BenchId,
    },
    DuplicateApplicability {
        bench: BenchId,
    },
    UnspecifiedClaimConfiguration,
    InvalidClaimDates,
    FakeRunnerIsNotReproduction,
    FakeSubstrateIsNotEvidence,
    ReproductionMismatch,
    ProvenanceNotReadable,
    NotReproduced {
        claimed: f64,
        measured: f64,
    },
    ClaimUnitMismatch,
    StatisticNotInRecord,
    NoIntervalsDeclared,
    StatisticalMethodMismatch,
    InconsistentRecord,
    PublicationReviewIncomplete,
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => f.write_str("the label is empty"),
            Self::LabelTooLong { max } => write!(f, "the label is longer than {max} characters"),
            Self::InvalidLabelCharacter { character } => write!(
                f,
                "the label contains {character:?}; labels are short identifiers, not free text"
            ),
            Self::LabelInvalidStart => f.write_str("a label must start with a letter or digit"),
            Self::LooksLikePath => f.write_str("the value looks like a path; record a digest instead"),
            Self::LooksLikeCredential => {
                f.write_str("the value looks like a credential; credentials are never recorded")
            }
            Self::InvalidPublicUrl { problem } => {
                write!(f, "the URL is not a public source: {}", problem.describe())
            }
            Self::InvalidCommitHash => f.write_str("a commit hash is 40 or 64 lowercase hexadecimal characters"),
            Self::NotPublishable { fixture } => write!(
                f,
                "fixture {fixture} is private; public artifacts use permitted synthetic or approved fixtures"
            ),
            Self::InvalidNumber => f.write_str("the number is not finite, is negative or is out of range"),
            Self::UnsupportedSchemaVersion { found } => write!(
                f,
                "report schema version {found} is not version {}",
                super::SCHEMA_VERSION
            ),
            Self::Encoding => f.write_str("the value could not be encoded"),
            Self::Malformed { line, column } => write!(
                f,
                "the report document does not parse at line {line}, column {column}"
            ),
            Self::EventFromAnotherRun => f.write_str("an event belongs to another run"),
            Self::SequenceNotIncreasing => f.write_str("event sequence numbers on a clock must rise"),
            Self::ClockWentBackwards => f.write_str("a monotonic clock went backwards"),
            Self::DuplicateEvent { event } => write!(f, "event {} occurs more than once", event.as_str()),
            Self::MissingEvent { event } => write!(f, "event {} is missing", event.as_str()),
            Self::WrongEvent {
                interval,
                expected,
                found,
            } => write!(
                f,
                "interval {} needs {} but was given {}",
                interval.as_str(),
                expected.as_str(),
                found.as_str()
            ),
            Self::DifferentRuns { interval } => {
                write!(f, "interval {} spans two runs", interval.as_str())
            }
            Self::DifferentClocks { interval } => {
                write!(f, "interval {} spans two clocks", interval.as_str())
            }
            Self::EndBeforeStart { interval } => {
                write!(f, "interval {} ends before it starts", interval.as_str())
            }
            Self::NotIntendedGuest => f.write_str("the guest command did not run in the intended guest"),
            Self::VramAboveBaseline => f.write_str("VRAM is above its declared baseline"),
            Self::DemandWorkOutsideFirstTokenClock => f.write_str(
                "a demand request's wake or load must lie inside its first-token clock",
            ),
            Self::UndeclaredDemandWork => {
                f.write_str("a request declared ready to serve shows demand wake or load")
            }
            Self::SwitchModeMismatch => f.write_str("the switch mode does not match the observed work"),
            Self::ControlledGapNotHonoured {
                declared_nanos,
                measured_nanos,
            } => write!(
                f,
                "the disclosed controlled gap of {declared_nanos} ns exceeds the measured {measured_nanos} ns"
            ),
            Self::NotSameRequest => f.write_str(
                "switch overhead needs a switch and a ready execution of the same request",
            ),
            Self::DurationOverflow => f.write_str("the duration does not fit"),
            Self::MissingStartState => f.write_str("the cache and sleep state is not recorded"),
            Self::InconsistentStartState => f.write_str("the cache and sleep state is inconsistent"),
            Self::ScenarioCategoryMismatch => {
                f.write_str("VM provisioning is measured only for a VM sandbox")
            }
            Self::InvalidStagePrimary => f.write_str("a stage scenario is judged by a stage interval"),
            Self::MissingLicense => f.write_str("the model records no license"),
            Self::InvalidRetry => f.write_str("a retry must name another first attempt and count from 1"),
            Self::TokenCountMismatch { recorded, events } => write!(
                f,
                "{recorded} output tokens are recorded but {events} token events"
            ),
            Self::InconsistentMeasurement => f.write_str("the measurements contradict each other"),
            Self::MissingScenarioMeasurement => {
                f.write_str("a successful attempt lacks its scenario tally")
            }
            Self::NonceAltersPairedTask => {
                f.write_str("a cold-test nonce must not alter a paired task's semantics")
            }
            Self::SuccessAfterDeadline { interval } => write!(
                f,
                "a success exceeded its deadline on {}; record a deadline failure",
                interval.as_str()
            ),
            Self::InconsistentDeadline => f.write_str(
                "a deadline failure needs a declared deadline that the attempt missed",
            ),
            Self::ReasoningCheckMismatch => {
                f.write_str("a reasoning check belongs only to a reasoning workload")
            }
            Self::ReasoningNotPassed => f.write_str(
                "a successful reasoning attempt needs a trace and a correct final answer; record an invalid result",
            ),
            Self::DuplicateAttempt => f.write_str("the attempt is already recorded and cannot be rewritten"),
            Self::UnknownFirstAttempt => f.write_str("the retry's first attempt is not recorded"),
            Self::RetryOfRetry => f.write_str("a retry links to its first attempt, not to another retry"),
            Self::DuplicateRetryNumber => f.write_str("the retry number is already used"),
            Self::RetryAfterSuccess => f.write_str("the attempt already succeeded"),
            Self::MixedCases => f.write_str("one ledger holds one case, variant and scenario"),
            Self::NoAttempts => f.write_str("there are no attempts"),
            Self::NoSuccessfulRuns => f.write_str("there are no successful runs"),
            Self::SuccessesExceedAttempts => f.write_str("successes exceed attempts"),
            Self::InvalidQuantile => f.write_str("the percentile is outside 1–10000 basis points or not reported"),
            Self::InvalidDistribution => f.write_str("the samples or distribution are invalid"),
            Self::InvalidRatio => f.write_str("the numerator exceeds the denominator"),
            Self::InconsistentSummary => {
                f.write_str("the summary does not match its samples, rate and failures")
            }
            Self::DuplicatePairedItem => f.write_str("a paired item appears twice"),
            Self::LowResolution {
                tail_samples,
                bursts,
            } => write!(
                f,
                "low resolution: {tail_samples} samples beyond the percentile from {bursts} bursts"
            ),
            Self::EmptyObservationWindow => f.write_str("the observation window or horizon is empty"),
            Self::CountOverflow => f.write_str("the counts do not fit in 64 bits"),
            Self::TooManyPairsForExactTest { pairs, max } => write!(
                f,
                "{pairs} discordant pairs exceed the {max} the exact test computes"
            ),
            Self::ReferenceUnavailable => {
                f.write_str("no comparable reference; this is recorded, never a pass")
            }
            Self::NotComparableEvidence => f.write_str("the evidence is not comparable"),
            Self::NotIdentical => f.write_str("the token sequences differ"),
            Self::RandomSampling => {
                f.write_str("output parity is never claimed under random sampling")
            }
            Self::NoTokensCompared => f.write_str("a parity claim needs compared tokens"),
            Self::IncompleteQualityEvidence { layer } => {
                write!(f, "quality evidence is incomplete at layer {layer:?}")
            }
            Self::WrongPriceUnit => f.write_str("the price is quoted in the wrong unit"),
            Self::PriceFromFuture => f.write_str("the price was observed after the analysis time"),
            Self::StalePrice => f.write_str("the price is older than the declared maximum age"),
            Self::MissingConcurrencyCurve => {
                f.write_str("an economic comparison needs measured concurrency curves")
            }
            Self::CostUndefined => f.write_str("the cost per task is undefined"),
            Self::MismatchedObjectiveDeclarations => {
                f.write_str("the sides use different percentiles or latency objectives")
            }
            Self::DeclaredObjectiveNotMeasured => {
                f.write_str("the declared objective is not measured on both sides")
            }
            Self::MissingConfiguration => {
                f.write_str("the record lacks the model, precision or workload to compare")
            }
            Self::NotComparable { fields } => {
                write!(f, "the configurations differ in {fields:?}")
            }
            Self::CategoryChanged => f.write_str("a comparison cannot change the execution category"),
            Self::LossyWithoutAccuracyEvaluation => {
                f.write_str("a lossy or non-equivalent mode needs an accuracy evaluation")
            }
            Self::MultiplicationRefused { parts } => write!(
                f,
                "{parts} separately measured improvements cannot be multiplied; measure the combination"
            ),
            Self::WarmVersusColdMislabel => {
                f.write_str("a warm-versus-cold comparison is not a cold-load improvement")
            }
            Self::StateMismatch => f.write_str("the start states do not match the comparison label"),
            Self::MissingBaseline { which } => {
                write!(f, "the {which:?} baseline is missing and no reason was given")
            }
            Self::AmbiguousOrdinaryBaseline => f.write_str("the ordinary workflow baseline is one side"),
            Self::ThirdPartyNotReproduced => {
                f.write_str("a third-party number is not a Yougori measurement until reproduced")
            }
            Self::TooFewTrials { trials, required } => {
                write!(f, "{trials} independent trials; at least {required} are needed")
            }
            Self::PredictableTrace => {
                f.write_str("cache and predictor effects need a mixed trace, not A/B alternation")
            }
            Self::MissingAblation { component } => write!(f, "component {component} has no ablation"),
            Self::UnknownAblation { component } => {
                write!(f, "ablation {component} names no enabled component")
            }
            Self::NotImproved => f.write_str("the declared objective did not improve"),
            Self::TrimmedScoreNotReleaseEvidence => {
                f.write_str("a trimmed external score is not release evidence")
            }
            Self::WrongScenarioForClaim => f.write_str("the attempts do not measure this claim"),
            Self::InsufficientBurstScale { claimed, observed } => write!(
                f,
                "a burst of {claimed} is claimed but the largest measured burst is {observed}"
            ),
            Self::SoakTooShort { seconds, required } => {
                write!(f, "a {seconds} s soak is shorter than the {required} s required")
            }
            Self::NoRepeatedCycles => f.write_str("the soak repeated no switches or wakes"),
            Self::RecycledDuringSoak { recycles } => write!(
                f,
                "{recycles} recycles flattened the soak; a recycle is a recovery event, not evidence of no leak"
            ),
            Self::CanaryFailures { failures } => write!(f, "{failures} canary checks failed"),
            Self::MissingTrackedResource { resource } => write!(f, "{resource:?} was not tracked"),
            Self::ResourceGrowth { resource } => write!(f, "{resource:?} grew beyond its allowance"),
            Self::IncompleteApplicability { missing } => {
                write!(f, "{} has no applicability record", missing.code())
            }
            Self::DuplicateApplicability { bench } => {
                write!(f, "{} is recorded twice", bench.code())
            }
            Self::UnspecifiedClaimConfiguration => {
                f.write_str("the claim states no configuration to reproduce")
            }
            Self::InvalidClaimDates => f.write_str("the dates are out of order"),
            Self::FakeRunnerIsNotReproduction => {
                f.write_str("a fake runner does not reproduce a real-world claim")
            }
            Self::FakeSubstrateIsNotEvidence => {
                f.write_str("a fake time-controlled run is not release or performance evidence")
            }
            Self::ReproductionMismatch => f.write_str("the record reproduces a different claim or case"),
            Self::ProvenanceNotReadable => f.write_str(
                "a measured or reproduced provenance is rebuilt from its records, never read",
            ),
            Self::NotReproduced { claimed, measured } => write!(
                f,
                "the reproduction measured {measured}, not the claimed {claimed} within the declared tolerance"
            ),
            Self::ClaimUnitMismatch => {
                f.write_str("the claim's unit does not match the comparison or its statistic")
            }
            Self::StatisticNotInRecord => {
                f.write_str("the record reports no such interval or percentile")
            }
            Self::NoIntervalsDeclared => f.write_str("the statistical method declares no intervals"),
            Self::StatisticalMethodMismatch => {
                f.write_str("the statistical method differs from this schema version's")
            }
            Self::InconsistentRecord => {
                f.write_str("the record's derived fields do not match its raw records")
            }
            Self::PublicationReviewIncomplete => f.write_str("the publication review is incomplete"),
        }
    }
}

impl std::error::Error for ReportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_explain_themselves() {
        let message = ReportError::EndBeforeStart {
            interval: IntervalKind::TimeToFirstToken,
        }
        .to_string();
        assert_eq!(
            message,
            "interval time_to_first_token ends before it starts"
        );
        assert!(ReportError::MultiplicationRefused { parts: 2 }
            .to_string()
            .contains("measure the combination"));
        assert!(ReportError::InvalidPublicUrl {
            problem: UrlProblem::Credentials
        }
        .to_string()
        .contains("user information"));
    }
}
