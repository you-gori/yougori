//! Conformance cases and runs: protocol correctness, the first of S9's three evidence
//! levels (S9 line 171; S11 BENCH-03; S12 G0 "offline protocol fixtures").
//!
//! A [`ConformanceCase`] pairs a request with a recorded response and the defined result
//! it must produce. [`run_case`] writes the recorded frames as an event stream, reads
//! them back (parser/serializer conformance), assembles them, validates any completed
//! turn and executes only validated calls. The features a case exercises follow from its
//! request and expectation, never from a label it gives itself, so a plain chat
//! completion can never stand in for tool, streaming or error evidence (S9 line 165).
//!
//! A case's own recorded response is fixture evidence, and so is every run made from it
//! ([`run_offline`]): it proves this module, not a runner. Host-probe evidence comes only
//! from `LiveHarness`, the host's own harness against one live runner, which judges
//! what that runner returned, never a case's recording, and binds the run to the model,
//! the runner and a digest of the transcript. Neither verdicts nor runs can be written
//! by hand.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::foundation::evidence::{ConfigurationFingerprint, SourceClass};
use crate::foundation::ids::{Clock, Digest, DigestBuilder, MonotonicTime};
use crate::foundation::report::{Label, ProtocolConformance};

use super::assembler::{assemble_frames, failed_before_stream};
use super::capability::RunnerRef;
use super::dialect::{Dialect, Feature};
use super::errors::ErrorClass;
use super::request::RequestProfile;
use super::sse::{decode_sse, encode_sse, SseEncodeError, SseFrame};
use super::turn::{
    AssembledToolCall, AssemblyLimits, OutcomeKind, StreamEnd, TurnOutcome, Usage, ViolationKind,
};
use super::validation::{execute_turn, validate_turn, RefusalKind, ToolExecutor};

/// One recorded frame. `data` holds a JSON payload, or a JSON string sent as raw text
/// (such as `[DONE]`); `data_text` holds raw text that need not be JSON.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedFrame {
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
    #[serde(default)]
    pub data_text: Option<String>,
}

impl RecordedFrame {
    /// The frame as sent; exactly one of `data` and `data_text` must be present.
    pub fn to_sse(&self) -> Result<SseFrame, CaseError> {
        let data = match (&self.data, &self.data_text) {
            (Some(Value::String(text)), None) | (None, Some(text)) => text.clone(),
            (Some(value), None) => value.to_string(),
            _ => return Err(CaseError::FrameData),
        };
        Ok(SseFrame {
            event: self.event.clone(),
            data,
        })
    }
}

fn http_ok() -> u16 {
    200
}

/// A recorded response: an HTTP failure before streaming, or frames and how the
/// transport ended (S9 line 167).
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedResponse {
    #[serde(default = "http_ok")]
    pub http_status: u16,
    #[serde(default)]
    pub error_body: Option<Value>,
    #[serde(default)]
    pub frames: Vec<RecordedFrame>,
    pub end: StreamEnd,
}

/// What happens to the turn's calls (S9 line 167).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedExecution {
    /// The turn completed, validated, and its calls ran.
    Executes,
    /// The turn completed in text; there was nothing to run.
    NoCalls,
    /// The turn completed but validation refused its calls.
    Refused,
    /// The turn did not complete; nothing can run.
    NotExecutable,
}

/// An exact expected call: index, id, name, and the arguments either as JSON (compared
/// structurally) or as exact text (for arguments that are not JSON).
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedToolCall {
    pub index: u32,
    pub call_id: String,
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
    #[serde(default)]
    pub arguments_text: Option<String>,
}

impl ExpectedToolCall {
    fn matches(&self, call: &AssembledToolCall) -> bool {
        let arguments = match (&self.arguments, &self.arguments_text) {
            (Some(expected), None) => {
                serde_json::from_str::<Value>(&call.arguments_json)
                    .ok()
                    .as_ref()
                    == Some(expected)
            }
            (None, Some(text)) => call.arguments_json == *text,
            _ => false,
        };
        arguments
            && call.index == self.index
            && call.call_id == self.call_id
            && call.name == self.name
    }
}

/// The defined result a case must produce (S9 line 167; S11 BENCH-03 "exact event,
/// arguments and finish reason conformance").
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub outcome: OutcomeKind,
    /// The exact wire finish reason, where the outcome carries one.
    #[serde(default)]
    pub finish: Option<String>,
    #[serde(default)]
    pub violation: Option<ViolationKind>,
    #[serde(default)]
    pub error_class: Option<ErrorClass>,
    /// Every call of a completed turn, in declared index order.
    #[serde(default)]
    pub tool_calls: Vec<ExpectedToolCall>,
    /// Calls that never became executable because the turn did not complete.
    #[serde(default)]
    pub dropped_tool_calls: usize,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub usage: Option<Usage>,
    pub execution: ExpectedExecution,
    #[serde(default)]
    pub refusal: Option<RefusalKind>,
}

/// One conformance case (S11 BENCH-03).
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceCase {
    pub case: Label,
    pub dialect: Dialect,
    /// What the case shows, in plain words.
    pub summary: String,
    pub request: Value,
    pub response: RecordedResponse,
    pub expect: Expectation,
}

/// Why a case or run is malformed (S11 BENCH-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaseError {
    /// A frame needs exactly one of `data` and `data_text`.
    FrameData,
    /// The expectation contradicts itself or the response.
    InconsistentExpectation { detail: String },
}

impl fmt::Display for CaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameData => f.write_str("a frame needs exactly one of data and data_text"),
            Self::InconsistentExpectation { detail } => {
                write!(f, "inconsistent expectation: {detail}")
            }
        }
    }
}

impl std::error::Error for CaseError {}

impl ConformanceCase {
    /// Checks that the expectation can be met at all, so a fixture cannot pass by
    /// asserting nothing.
    pub fn check(&self) -> Result<(), CaseError> {
        self.check_with(&self.response)
    }

    /// [`Self::check`] against `response`: the case's own recording, or what a live
    /// runner returned to the case's request.
    fn check_with(&self, response: &RecordedResponse) -> Result<(), CaseError> {
        let expect = &self.expect;
        let completed = expect.outcome == OutcomeKind::Completed;
        let rules = [
            (
                (expect.outcome == OutcomeKind::Violation) == expect.violation.is_some(),
                "a violation kind goes with, and only with, a violation outcome",
            ),
            (
                (expect.outcome == OutcomeKind::Failed) == expect.error_class.is_some(),
                "an error class goes with, and only with, a failed outcome",
            ),
            (
                (expect.execution == ExpectedExecution::Refused) == expect.refusal.is_some(),
                "a refusal kind goes with, and only with, a refused execution",
            ),
            (
                completed == (expect.execution != ExpectedExecution::NotExecutable),
                "only a completed turn can execute, refuse or end without calls",
            ),
            (
                completed || expect.tool_calls.is_empty(),
                "only a completed turn has assembled calls",
            ),
            (
                !completed || expect.dropped_tool_calls == 0,
                "a completed turn drops no calls",
            ),
            (
                expect.execution != ExpectedExecution::Executes || !expect.tool_calls.is_empty(),
                "an executing turn lists its calls",
            ),
            (
                expect.execution != ExpectedExecution::NoCalls || expect.tool_calls.is_empty(),
                "a turn without calls lists none",
            ),
            (
                expect.outcome != OutcomeKind::Cancelled || response.end == StreamEnd::ClientCancel,
                "only a client cancel can cancel a turn",
            ),
            (
                (response.http_status == 200) == response.error_body.is_none(),
                "an error body goes with, and only with, a non-200 status",
            ),
            (
                response.http_status == 200
                    || (response.frames.is_empty() && expect.outcome == OutcomeKind::Failed),
                "a non-200 response has no frames and fails",
            ),
        ];
        for (holds, rule) in rules {
            if !holds {
                return Err(CaseError::InconsistentExpectation {
                    detail: rule.to_owned(),
                });
            }
        }
        for frame in &response.frames {
            frame.to_sse()?;
        }
        if let Some(call) = expect
            .tool_calls
            .iter()
            .find(|call| call.arguments.is_some() == call.arguments_text.is_some())
        {
            return Err(CaseError::InconsistentExpectation {
                detail: format!(
                    "call {} needs exactly one of arguments and arguments_text",
                    call.index
                ),
            });
        }
        Ok(())
    }

    /// The features this case exercises, from its request and expectation (S9 line 165).
    pub fn exercised_features(&self, request: Option<&RequestProfile>) -> BTreeSet<Feature> {
        self.exercised_with(request, &self.response)
    }

    /// [`Self::exercised_features`] when `response` is the response judged.
    fn exercised_with(
        &self,
        request: Option<&RequestProfile>,
        response: &RecordedResponse,
    ) -> BTreeSet<Feature> {
        let expect = &self.expect;
        let mut features = BTreeSet::from([Feature::RequestFields]);
        // A request refused before streaming shows nothing about how it would have been
        // served, only how the refusal was mapped.
        let accepted = response.http_status == 200;
        if let Some(request) = request.filter(|_| accepted) {
            if request
                .needs()
                .contains(&Feature::SystemContextPreservation)
            {
                features.insert(Feature::SystemContextPreservation);
            }
            if request.streaming() {
                features.insert(Feature::StreamingDeltas);
            }
            if request.explicit_tool_choice() {
                features.insert(Feature::ToolChoice);
            }
            let schema_checked = expect.execution == ExpectedExecution::Executes
                || matches!(
                    expect.refusal,
                    Some(
                        RefusalKind::UndeclaredTool
                            | RefusalKind::MalformedArguments
                            | RefusalKind::ArgumentsNotObject
                            | RefusalKind::SchemaViolation
                    )
                );
            if request.has_tools() && schema_checked {
                features.insert(Feature::ToolSchema);
            }
        }
        if expect.tool_calls.len() >= 2 {
            features.insert(Feature::ParallelCalls);
        }
        if expect.finish.is_some() {
            features.insert(Feature::FinishReason);
        }
        if expect.usage.is_some() {
            features.insert(Feature::Usage);
        }
        if expect.outcome == OutcomeKind::Failed {
            features.insert(Feature::Errors);
        }
        // Only a cancelled turn shows cancellation: a client cancel that arrives after the
        // turn completed, with its calls run, shows nothing about it.
        if expect.outcome == OutcomeKind::Cancelled {
            features.insert(Feature::Cancellation);
        }
        features
    }
}

/// The result of running one case (S11 BENCH-03). Only [`run_case`] and the host's live
/// harness (`LiveHarness::observe`) make one, so no verdict is written by hand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaseVerdict {
    case: Label,
    dialect: Dialect,
    /// Where the judged response came from: a case's own recording is a fixture, a live
    /// runner's response observed by the host's harness is a host probe (CORE-01).
    source: SourceClass,
    exercised: BTreeSet<Feature>,
    outcome: OutcomeKind,
    executed_calls: usize,
    mismatches: Vec<String>,
}

impl CaseVerdict {
    /// The case judged.
    pub fn case(&self) -> &Label {
        &self.case
    }

    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// Where the judged response came from (CORE-01 source class).
    pub fn source(&self) -> SourceClass {
        self.source
    }

    /// The features the case exercised (S9 line 165).
    pub fn exercised(&self) -> &BTreeSet<Feature> {
        &self.exercised
    }

    /// The outcome the response assembled into.
    pub fn outcome(&self) -> OutcomeKind {
        self.outcome
    }

    /// How many validated calls the executor ran.
    pub fn executed_calls(&self) -> usize {
        self.executed_calls
    }

    /// Every way the result differed from the expectation; empty when the case passed.
    pub fn mismatches(&self) -> &[String] {
        &self.mismatches
    }

    /// Whether the result matched the expectation exactly.
    pub fn passed(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// Why a recorded response could not be replayed (S9 line 167).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    Frame(CaseError),
    Encode(SseEncodeError),
    /// The frames read back from the event stream differ from those written.
    RoundTrip,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "{error}"),
            Self::Encode(error) => write!(f, "{error}"),
            Self::RoundTrip => f.write_str("the frames did not survive an event-stream round trip"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// The outcome of a recorded response, after its frames are written as an event stream
/// and read back (S9 line 167: parser/serializer conformance).
pub fn replay_response(
    dialect: Dialect,
    response: &RecordedResponse,
    limits: AssemblyLimits,
) -> Result<TurnOutcome, ReplayError> {
    if response.http_status != 200 {
        let body = response.error_body.clone().unwrap_or(Value::Null);
        return Ok(failed_before_stream(dialect, response.http_status, &body));
    }
    let frames = response
        .frames
        .iter()
        .map(RecordedFrame::to_sse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReplayError::Frame)?;
    let text = encode_sse(&frames).map_err(ReplayError::Encode)?;
    let (decoded, tail) = decode_sse(&text);
    if decoded != frames || tail.discarded_partial_event {
        return Err(ReplayError::RoundTrip);
    }
    Ok(assemble_frames(dialect, &decoded, response.end, limits))
}

/// Runs one case: replays its own recorded response, compares the defined result,
/// validates a completed turn and executes only validated calls (S9 line 167). The
/// verdict is fixture evidence.
pub fn run_case(
    case: &ConformanceCase,
    limits: AssemblyLimits,
    executor: &mut dyn ToolExecutor,
) -> CaseVerdict {
    judge(case, &case.response, SourceClass::Fixture, limits, executor)
}

/// Judges `response`, which came from `source`, against `case`'s expectation.
fn judge(
    case: &ConformanceCase,
    response: &RecordedResponse,
    source: SourceClass,
    limits: AssemblyLimits,
    executor: &mut dyn ToolExecutor,
) -> CaseVerdict {
    let mut mismatches = Vec::new();
    if let Err(error) = case.check_with(response) {
        mismatches.push(error.to_string());
    }
    let request = RequestProfile::from_request(case.dialect, &case.request);
    if let Err(error) = &request {
        mismatches.push(format!("request: {error}"));
    }
    let request = request.ok();
    let outcome = match replay_response(case.dialect, response, limits) {
        Ok(outcome) => outcome,
        Err(error) => {
            mismatches.push(error.to_string());
            return CaseVerdict {
                case: case.case.clone(),
                dialect: case.dialect,
                source,
                exercised: case.exercised_with(request.as_ref(), response),
                outcome: OutcomeKind::Violation,
                executed_calls: 0,
                mismatches,
            };
        }
    };
    compare_outcome(&case.expect, &outcome, &mut mismatches);

    let (execution, refusal, executed_calls) = match (outcome.completed(), &request) {
        (Some(turn), Some(request)) => match validate_turn(turn, request) {
            Ok(validated) if validated.calls().is_empty() => (ExpectedExecution::NoCalls, None, 0),
            Ok(validated) => (
                ExpectedExecution::Executes,
                None,
                execute_turn(executor, &validated),
            ),
            Err(refusal) => (ExpectedExecution::Refused, Some(refusal.kind), 0),
        },
        // Without a readable request nothing can be validated, so nothing runs.
        _ => (ExpectedExecution::NotExecutable, None, 0),
    };
    if execution != case.expect.execution || refusal != case.expect.refusal {
        mismatches.push(format!(
            "execution {execution:?} ({refusal:?}), expected {:?} ({:?})",
            case.expect.execution, case.expect.refusal
        ));
    }
    CaseVerdict {
        case: case.case.clone(),
        dialect: case.dialect,
        source,
        exercised: case.exercised_with(request.as_ref(), response),
        outcome: outcome.kind(),
        executed_calls,
        mismatches,
    }
}

fn compare_outcome(expect: &Expectation, outcome: &TurnOutcome, mismatches: &mut Vec<String>) {
    if outcome.kind() != expect.outcome {
        let detail = match outcome {
            TurnOutcome::Violation { violation, .. } => format!(" ({violation})"),
            TurnOutcome::Failed { error, .. } => format!(" ({error})"),
            _ => String::new(),
        };
        mismatches.push(format!(
            "outcome {:?}{detail}, expected {:?}",
            outcome.kind(),
            expect.outcome
        ));
    }
    let finish = outcome.finish().map(|finish| finish.raw.as_str());
    if finish != expect.finish.as_deref() {
        mismatches.push(format!("finish {finish:?}, expected {:?}", expect.finish));
    }
    let violation = match outcome {
        TurnOutcome::Violation { violation, .. } => Some(violation.kind),
        _ => None,
    };
    if violation != expect.violation {
        mismatches.push(format!(
            "violation {violation:?}, expected {:?}",
            expect.violation
        ));
    }
    let error_class = match outcome {
        TurnOutcome::Failed { error, .. } => Some(error.class),
        _ => None,
    };
    if error_class != expect.error_class {
        mismatches.push(format!(
            "error class {error_class:?}, expected {:?}",
            expect.error_class
        ));
    }
    if outcome.dropped().len() != expect.dropped_tool_calls {
        mismatches.push(format!(
            "{} dropped calls, expected {}",
            outcome.dropped().len(),
            expect.dropped_tool_calls
        ));
    }
    let Some(turn) = outcome.completed() else {
        return;
    };
    let calls = turn.tool_calls();
    if calls.len() != expect.tool_calls.len() {
        mismatches.push(format!(
            "{} calls, expected {}",
            calls.len(),
            expect.tool_calls.len()
        ));
    }
    for (call, expected) in calls.iter().zip(&expect.tool_calls) {
        if !expected.matches(call) {
            mismatches.push(format!(
                "call {} {:?} {:?} {:?} differs from {:?}",
                call.index, call.call_id, call.name, call.arguments_json, expected
            ));
        }
    }
    if let Some(text) = &expect.text {
        if turn.text() != text {
            mismatches.push(format!("text {:?}, expected {text:?}", turn.text()));
        }
    }
    if let Some(usage) = &expect.usage {
        if turn.usage() != Some(usage) {
            mismatches.push(format!("usage {:?}, expected {usage:?}", turn.usage()));
        }
    }
}

/// Why a run cannot be recorded (S11 BENCH-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunError {
    NoCases,
    /// A verdict of another dialect than the run's.
    DialectMismatch {
        case: Label,
    },
    DuplicateCase {
        case: Label,
    },
    /// A verdict judged a response from another source than the run records: a case's
    /// own recording is fixture evidence and never joins a live run (S9 line 165).
    SourceMismatch {
        case: Label,
        found: SourceClass,
        required: SourceClass,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCases => f.write_str("a run needs at least one case"),
            Self::DialectMismatch { case } => write!(f, "case {case} is of another dialect"),
            Self::DuplicateCase { case } => write!(f, "case {case} appears twice"),
            Self::SourceMismatch {
                case,
                found,
                required,
            } => write!(
                f,
                "case {case} judged a response from a {found}; this run records only a \
                 {required}"
            ),
        }
    }
}

impl std::error::Error for RunError {}

/// Where a run's observations came from (S9 line 165; CORE-01 source class).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunOrigin {
    /// The cases' own recorded responses: fixture evidence about this module's parsers
    /// and assemblers, which names no model or runner (S2; S12 G0).
    Fixtures,
    /// The host's own harness against one runner serving one model, with the digest of
    /// every exchange it judged ([`LIVE_TRANSCRIPT_DOMAIN`]).
    LiveRunner {
        model: Digest,
        runner: RunnerRef,
        transcript: Digest,
    },
}

impl RunOrigin {
    /// The CORE-01 source class of the run's evidence.
    pub fn source(&self) -> SourceClass {
        match self {
            Self::Fixtures => SourceClass::Fixture,
            Self::LiveRunner { .. } => SourceClass::HostProbe,
        }
    }
}

/// One conformance run of one dialect: where its observations came from, under which
/// configuration, when, and every verdict (S11 BENCH-03; CORE-01 source and
/// fingerprint). Only [`run_offline`] and the host's live harness (`LiveHarness::finish`)
/// record one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConformanceRun {
    dialect: Dialect,
    origin: RunOrigin,
    configuration: ConfigurationFingerprint,
    observed_at: MonotonicTime,
    verdicts: Vec<CaseVerdict>,
}

/// Domain of [`ConformanceRun::identity`].
pub const CONFORMANCE_RUN_DOMAIN: &str = "yougori/serving-protocol/conformance-run/v2";

/// Domain of the transcript digest of a live run ([`RunOrigin::LiveRunner`]).
pub const LIVE_TRANSCRIPT_DOMAIN: &str = "yougori/serving-protocol/live-transcript/v1";

impl ConformanceRun {
    /// Records verdicts, stamping the time from `clock`. Every verdict must have judged a
    /// response of `origin`'s source class, so a case's recording never joins a live run.
    /// Visible only inside `serving_protocol`, whose recorders are [`run_offline`] and
    /// [`LiveHarness`].
    pub(super) fn record(
        dialect: Dialect,
        origin: RunOrigin,
        configuration: ConfigurationFingerprint,
        clock: &dyn Clock,
        verdicts: Vec<CaseVerdict>,
    ) -> Result<Self, RunError> {
        if verdicts.is_empty() {
            return Err(RunError::NoCases);
        }
        let required = origin.source();
        let mut seen = BTreeSet::new();
        for verdict in &verdicts {
            if verdict.dialect != dialect {
                return Err(RunError::DialectMismatch {
                    case: verdict.case.clone(),
                });
            }
            if verdict.source != required {
                return Err(RunError::SourceMismatch {
                    case: verdict.case.clone(),
                    found: verdict.source,
                    required,
                });
            }
            if !seen.insert(&verdict.case) {
                return Err(RunError::DuplicateCase {
                    case: verdict.case.clone(),
                });
            }
        }
        Ok(Self {
            dialect,
            origin,
            configuration,
            observed_at: clock.now(),
            verdicts,
        })
    }

    /// The dialect every verdict of the run belongs to.
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// Where the observations came from, with the model and runner of a live run.
    pub fn origin(&self) -> &RunOrigin {
        &self.origin
    }

    /// Where the observations came from (CORE-01 source class).
    pub fn source(&self) -> SourceClass {
        self.origin.source()
    }

    /// The configuration observed: the corpus digest offline, the runner's launch settings live.
    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// When the run was recorded, on the injected clock.
    pub fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    /// Every case's verdict, in run order.
    pub fn verdicts(&self) -> &[CaseVerdict] {
        &self.verdicts
    }

    /// The run's digest, which capability cells cite as their evidence. A live run's
    /// binds its model, runner and transcript.
    pub fn identity(&self) -> Digest {
        let mut builder = DigestBuilder::new(CONFORMANCE_RUN_DOMAIN)
            .str(self.dialect.tag())
            .str(source_tag(self.source()));
        if let RunOrigin::LiveRunner {
            model,
            runner,
            transcript,
        } = &self.origin
        {
            builder = builder
                .digest(model)
                .str(runner.release.backend.tag())
                .str(runner.release.version.as_str())
                .str(runner.category.label())
                .digest(transcript);
        }
        builder = builder
            .digest(&self.configuration.digest())
            .u64(self.observed_at.as_nanos());
        for verdict in &self.verdicts {
            builder = builder
                .str(verdict.case.as_str())
                .u64(u64::from(verdict.passed()))
                .u64(verdict.exercised.len() as u64);
            for feature in &verdict.exercised {
                builder = builder.str(feature.tag());
            }
        }
        builder.finish()
    }
}

fn source_tag(source: SourceClass) -> &'static str {
    match source {
        SourceClass::Fixture => "fixture",
        SourceClass::RecordedDeclaration => "recorded_declaration",
        SourceClass::GuestReport => "guest_report",
        SourceClass::ProviderApi => "provider_api",
        SourceClass::HostProbe => "host_probe",
    }
}

/// Runs every case of one dialect's corpus offline and records the run as fixture
/// evidence: it proves this module's parsers and assemblers, not any runner (S2: fakes
/// cannot certify a real backend; S12 G0).
pub fn run_offline(
    dialect: Dialect,
    cases: &[ConformanceCase],
    corpus: ConfigurationFingerprint,
    limits: AssemblyLimits,
    clock: &dyn Clock,
    executor: &mut dyn ToolExecutor,
) -> Result<ConformanceRun, RunError> {
    let verdicts = cases
        .iter()
        .map(|case| run_case(case, limits, executor))
        .collect();
    ConformanceRun::record(dialect, RunOrigin::Fixtures, corpus, clock, verdicts)
}

/// The host's own conformance harness against one runner serving one model: the only
/// source of host-probe conformance evidence, the only evidence a capability row accepts
/// (S9 line 165: a dialect is never advertised merely because a chat completion
/// succeeded; CORE-01).
///
/// For each case the host sends the case's request to the runner, and the harness judges
/// the response the host captured against the case's expectation; the case's own
/// recorded response is never read. Every exchange joins the run's transcript digest,
/// and the run names its model and runner, so its evidence cannot describe a model or
/// runner nobody contacted. Crate-private: the host's runner integration (GPU-W11, not
/// built yet, so only tests drive one now) owns it.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct LiveHarness {
    dialect: Dialect,
    model: Digest,
    runner: RunnerRef,
    configuration: ConfigurationFingerprint,
    limits: AssemblyLimits,
    exchanges: Vec<Digest>,
    verdicts: Vec<CaseVerdict>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl LiveHarness {
    /// A harness for `dialect` against `runner` serving `model`, launched under
    /// `configuration`, the runner's launch settings (CORE-01 fingerprint).
    pub(crate) fn new(
        dialect: Dialect,
        model: Digest,
        runner: RunnerRef,
        configuration: ConfigurationFingerprint,
        limits: AssemblyLimits,
    ) -> Self {
        Self {
            dialect,
            model,
            runner,
            configuration,
            limits,
            exchanges: Vec::new(),
            verdicts: Vec::new(),
        }
    }

    /// Judges `observed`, the response the runner returned to `case`'s request as the
    /// host captured it, executing only validated calls, and adds the exchange to the
    /// transcript. Refuses a case of another dialect and a case already judged.
    pub(crate) fn observe(
        &mut self,
        case: &ConformanceCase,
        observed: &RecordedResponse,
        executor: &mut dyn ToolExecutor,
    ) -> Result<CaseVerdict, RunError> {
        if case.dialect != self.dialect {
            return Err(RunError::DialectMismatch {
                case: case.case.clone(),
            });
        }
        if self
            .verdicts
            .iter()
            .any(|verdict| verdict.case == case.case)
        {
            return Err(RunError::DuplicateCase {
                case: case.case.clone(),
            });
        }
        let verdict = judge(
            case,
            observed,
            SourceClass::HostProbe,
            self.limits,
            executor,
        );
        self.exchanges.push(Self::exchange(case, observed));
        self.verdicts.push(verdict.clone());
        Ok(verdict)
    }

    /// Records the run, bound to the model, the runner and the transcript, stamping the
    /// time from `clock`.
    pub(crate) fn finish(self, clock: &dyn Clock) -> Result<ConformanceRun, RunError> {
        let transcript = self
            .exchanges
            .iter()
            .fold(
                DigestBuilder::new(LIVE_TRANSCRIPT_DOMAIN)
                    .str("transcript")
                    .str(self.dialect.tag())
                    .u64(self.exchanges.len() as u64),
                |builder, exchange| builder.digest(exchange),
            )
            .finish();
        ConformanceRun::record(
            self.dialect,
            RunOrigin::LiveRunner {
                model: self.model,
                runner: self.runner,
                transcript,
            },
            self.configuration,
            clock,
            self.verdicts,
        )
    }

    /// The digest of one exchange: the case, the request sent and the response captured.
    fn exchange(case: &ConformanceCase, observed: &RecordedResponse) -> Digest {
        fn optional(builder: DigestBuilder, part: Option<&str>) -> DigestBuilder {
            match part {
                Some(text) => builder.u64(1).str(text),
                None => builder.u64(0),
            }
        }
        let error_body = observed.error_body.as_ref().map(Value::to_string);
        let mut builder = optional(
            DigestBuilder::new(LIVE_TRANSCRIPT_DOMAIN)
                .str("exchange")
                .str(case.case.as_str())
                .str(&case.request.to_string())
                .u64(u64::from(observed.http_status)),
            error_body.as_deref(),
        )
        .str(match observed.end {
            StreamEnd::Eof => "eof",
            StreamEnd::ClientCancel => "client_cancel",
        })
        .u64(observed.frames.len() as u64);
        for frame in &observed.frames {
            let data = frame.data.as_ref().map(Value::to_string);
            builder = optional(builder, frame.event.as_deref());
            builder = optional(builder, data.as_deref());
            builder = optional(builder, frame.data_text.as_deref());
        }
        builder.finish()
    }
}

/// Protocol correctness, the first evidence level: request, response and event fixtures
/// conform to the dialect (S9 line 171).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolCorrectness {
    pub dialect: Dialect,
    pub run: Digest,
    pub source: SourceClass,
    pub cases: u64,
    pub failed: Vec<Label>,
}

impl ProtocolCorrectness {
    /// Summarises a run as the first evidence level (S9 line 171).
    pub fn of_run(run: &ConformanceRun) -> Self {
        Self {
            dialect: run.dialect,
            run: run.identity(),
            source: run.source(),
            cases: run.verdicts.len() as u64,
            failed: run
                .verdicts
                .iter()
                .filter(|verdict| !verdict.passed())
                .map(|verdict| verdict.case.clone())
                .collect(),
        }
    }

    /// Every case passed, and there was at least one.
    pub fn holds(&self) -> bool {
        self.cases > 0 && self.failed.is_empty()
    }

    /// The CORE-08 quality layer 1 (S13 line 250).
    pub fn layer(&self) -> ProtocolConformance {
        ProtocolConformance {
            fixtures: self.cases,
            failures: self.failed.len() as u64,
        }
    }
}
