//! Serving protocol conformance: offline BENCH-03 (docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! S7 lines 126–127, S9, S11 BENCH-03/BENCH-04, S12 G0/G2, S13 line 250; GPU-W11 line 1150).
//!
//! - [`CapabilityRow`]: per model, runner and [`Dialect`], each [`Feature`] is supported
//!   with conformance evidence, unsupported with a reason, or untested. Rows come only
//!   from the host's own harness against that model and runner (`LiveHarness`,
//!   crate-private), never from fixtures. A dialect is advertised only when no feature is
//!   untested and the features of every exchange are supported, under the configuration
//!   the evidence was observed with, so one successful chat completion never advertises
//!   it (S9 line 165).
//! - [`StreamAssembler`]: OpenAI Chat Completions, OpenAI Responses and Anthropic
//!   Messages streams, assembled by declared index and event order. Argument fragments
//!   are never judged mid-stream; every outcome other than [`TurnOutcome::Completed`]
//!   drops its calls, and only a [`ValidatedTurn`] reaches a [`ToolExecutor`]
//!   (S9 line 167).
//! - The three evidence levels of S9: [`ProtocolCorrectness`] is what this module
//!   proves; [`ModelFidelity`] is recorded only against a matched reference and
//!   otherwise names why the reference is unavailable; agent task utility is an
//!   [`AgentTaskRecord`]. Statistics and the report schema are CORE-08's
//!   (`foundation::report`).
//! - A synthetic JSONL corpus in `fixtures/`, embedded at build time.
//!
//! Pure and synchronous: no network, processes or runners. Time comes from
//! [`crate::foundation::ids::Clock`].

mod assembler;
mod capability;
mod chat_completions;
mod conformance;
mod dialect;
mod errors;
mod fidelity;
mod fixtures;
mod messages;
mod request;
mod responses;
mod schema;
mod sse;
mod turn;
mod utility;
mod validation;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use assembler::{assemble_frames, assemble_sse, failed_before_stream, StreamAssembler};
pub use capability::{
    CapabilityRefusal, CapabilityRow, CapabilityTable, CellEvidence, CellStatus, NotAdvertised,
    RowError, RowKey, RunnerRef, UnsupportedFeature,
};
pub use chat_completions::ChatCompletionsAssembler;
pub use conformance::{
    replay_response, run_case, run_offline, CaseError, CaseVerdict, ConformanceCase,
    ConformanceRun, Expectation, ExpectedExecution, ExpectedToolCall, ProtocolCorrectness,
    RecordedFrame, RecordedResponse, ReplayError, RunError, RunOrigin, CONFORMANCE_RUN_DOMAIN,
    LIVE_TRANSCRIPT_DOMAIN,
};
// The host's own conformance harness against a live runner; the runner integration
// (GPU-W11) drives it, so only tests use it now.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use conformance::LiveHarness;
pub use dialect::{Dialect, Feature};
pub use errors::{classify_http_error, ErrorClass, ServiceError};
pub use fidelity::{
    observe_pair, ModelFidelity, PairObservation, PairSide, PairedCorpus, ReferenceKind,
    ReferenceRun, ReferenceSource, ReferenceUnavailable,
};
pub use fixtures::{
    corpus_fingerprint, corpus_fixture, corpus_text, load_cases, load_paired_items, parse_cases,
    FixtureError, PairedItem, CORPUS_DOMAIN,
};
pub use messages::MessagesAssembler;
pub use request::{RequestError, RequestKind, RequestProfile, ToolChoice};
pub use responses::ResponsesAssembler;
pub use schema::{SchemaError, SchemaViolation, ToolSchema};
pub use sse::{decode_sse, encode_sse, SseDecoder, SseEncodeError, SseFrame, SseTail};
pub use turn::{
    AssembledToolCall, AssemblyLimits, CompletedTurn, FinishReason, Flow, OutcomeKind,
    PendingToolCall, ProtocolViolation, StreamEnd, TurnOutcome, Usage, ViolationKind, WireFinish,
};
pub use utility::{
    task_success, AgentTaskRecord, AgentTaskRecorder, AttemptKind, BudgetLimit, Milestone,
    MilestoneAt, TaskBudget, TaskOutcome, TaskRequirements, TaskStep, TaskSuccess,
    TaskSuccessError,
};
pub use validation::{
    execute_turn, schema_valid_calls, validate_turn, RefusalKind, ToolCallRefusal, ToolExecutor,
    ValidatedToolCall, ValidatedTurn,
};
