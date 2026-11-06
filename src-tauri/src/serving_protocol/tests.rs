//! Cross-module tests of the serving protocol contract (S7 lines 126–127, S9, S11
//! BENCH-03/BENCH-04, S12, S13 line 250).

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{json, Value};

use super::fakes::{served, RecordingExecutor};
use super::*;
use crate::foundation::evidence::{Backend, BackendRelease, ConfigurationFingerprint, SourceClass};
use crate::foundation::ids::{digest, ExecutionCategory, ManualClock, MonotonicTime, OperationId};
use crate::foundation::report::{
    AlignmentField, AlignmentKey, FailureKind, Label, ProtocolConformance, Ratio, ReportError,
    SuccessRate, ToolFidelityEvidence,
};

const CC: Dialect = Dialect::OpenAiChatCompletions;
const RS: Dialect = Dialect::OpenAiResponses;
const AM: Dialect = Dialect::AnthropicMessages;

const LIMITS: AssemblyLimits = AssemblyLimits {
    max_tool_calls: 16,
    max_argument_bytes: 4096,
    max_text_bytes: 4096,
};

fn label(text: &str) -> Label {
    Label::new(text).unwrap()
}

fn find(dialect: Dialect, id: &str) -> ConformanceCase {
    load_cases(dialect)
        .unwrap()
        .into_iter()
        .find(|case| case.case.as_str() == id)
        .unwrap_or_else(|| panic!("no case {id}"))
}

fn frames(case: &ConformanceCase) -> Vec<SseFrame> {
    case.response
        .frames
        .iter()
        .map(|frame| frame.to_sse().unwrap())
        .collect()
}

fn replay(case: &ConformanceCase) -> TurnOutcome {
    replay_response(case.dialect, &case.response, LIMITS).unwrap()
}

fn request(case: &ConformanceCase) -> RequestProfile {
    RequestProfile::from_request(case.dialect, &case.request).unwrap()
}

fn parallel_case(dialect: Dialect) -> ConformanceCase {
    let id = match dialect {
        CC => "cc-parallel-two-tools",
        RS => "rs-parallel-two-tools",
        AM => "am-parallel-two-tools",
    };
    find(dialect, id)
}

fn violation_kind(outcome: &TurnOutcome) -> Option<ViolationKind> {
    match outcome {
        TurnOutcome::Violation { violation, .. } => Some(violation.kind),
        _ => None,
    }
}

fn model() -> crate::foundation::ids::Digest {
    digest("yougori/test/model/v1", &[b"synthetic-model"])
}

fn runner() -> RunnerRef {
    RunnerRef {
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        category: ExecutionCategory::SharedKernelGpuRuntime,
    }
}

fn live_configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("launch", "synthetic-flags")]).unwrap()
}

/// The host's own harness against the test runner serving the test model.
fn harness(dialect: Dialect) -> LiveHarness {
    LiveHarness::new(dialect, model(), runner(), live_configuration(), LIMITS)
}

/// Every case of a corpus, sent by the host's harness to a fake runner that answers each
/// request as its case recorded.
fn live_run(dialect: Dialect, clock: &ManualClock) -> ConformanceRun {
    let mut executor = RecordingExecutor::default();
    let mut harness = harness(dialect);
    for case in load_cases(dialect).unwrap() {
        harness
            .observe(&case, &served(&case), &mut executor)
            .unwrap();
    }
    harness.finish(clock).unwrap()
}

// ---------------------------------------------------------------- fixtures

#[test]
fn the_fixtures_load() {
    let mut total = 0;
    for dialect in Dialect::ALL {
        let cases = load_cases(dialect).unwrap();
        assert!(cases.len() >= 15, "{dialect}: {}", cases.len());
        total += cases.len();
        let ids: BTreeSet<_> = cases.iter().map(|case| case.case.clone()).collect();
        assert_eq!(ids.len(), cases.len());
        assert!(cases.iter().all(|case| case.dialect == dialect));
    }
    assert_eq!(total, 63);
    let pairs = load_paired_items().unwrap();
    assert_eq!(pairs.len(), 10);
    // The digest ignores a checkout's line endings.
    for dialect in Dialect::ALL {
        let crlf = corpus_text(dialect).replace('\n', "\r\n");
        assert_eq!(
            parse_cases(dialect, &crlf).unwrap(),
            load_cases(dialect).unwrap()
        );
        assert_eq!(
            corpus_fixture(dialect).unwrap().digest,
            crate::foundation::report::FixtureRef::digesting(
                label("x"),
                corpus_text(dialect).replace("\r\n", "\n").as_bytes(),
                crate::foundation::report::Disclosure::PermittedSynthetic,
            )
            .digest
        );
    }
    assert_ne!(corpus_fingerprint(CC), corpus_fingerprint(RS));
}

#[test]
fn malformed_fixture_lines_are_refused() {
    let line = corpus_text(CC).lines().next().unwrap();
    let mut value: Value = serde_json::from_str(line).unwrap();
    let parse = |value: &Value| parse_cases(CC, &value.to_string());
    assert_eq!(parse(&value).unwrap().len(), 1);

    let mut extra = value.clone();
    extra["expect"]["note"] = json!("unknown field");
    assert!(matches!(
        parse(&extra),
        Err(FixtureError::Parse { line: 1, .. })
    ));
    let mut extra = value.clone();
    extra["response"]["frames"][0]["comment"] = json!("unknown field");
    assert!(matches!(parse(&extra), Err(FixtureError::Parse { .. })));
    let mut extra = value.clone();
    extra["expect"]["usage"]["reasoning_tokens"] = json!(1);
    assert!(matches!(parse(&extra), Err(FixtureError::Parse { .. })));

    assert!(matches!(
        parse_cases(RS, line),
        Err(FixtureError::WrongDialect { line: 1, found: CC })
    ));
    assert_eq!(
        parse_cases(CC, &format!("{line}\n{line}\n")),
        Err(FixtureError::DuplicateCase { line: 2 })
    );
    // An expectation that cannot be met is refused, so a case cannot pass vacuously.
    value["expect"]["violation"] = json!("duplicate_event");
    assert!(matches!(
        parse(&value),
        Err(FixtureError::Inconsistent { .. })
    ));
    let mut both = serde_json::from_str::<Value>(line).unwrap();
    both["response"]["frames"][1]["data_text"] = json!("{}");
    assert!(matches!(
        parse(&both),
        Err(FixtureError::Inconsistent { .. })
    ));
}

#[test]
fn the_fixtures_are_synthetic_and_carry_no_credentials() {
    for dialect in Dialect::ALL {
        let text = corpus_text(dialect);
        let lowered = text.to_ascii_lowercase();
        for marker in [
            "bearer ",
            "authorization",
            "api_key",
            "api-key",
            "x-api-key",
            "password",
            "secret",
        ] {
            assert!(!lowered.contains(marker), "{dialect}: {marker}");
        }
        for token in text.split(|character: char| {
            !(character.is_ascii_alphanumeric() || "-_".contains(character))
        }) {
            let lower = token.to_ascii_lowercase();
            assert!(
                !(lower.starts_with("sk-") || lower.starts_with("sk_")),
                "{dialect}: {token}"
            );
            let opaque = token.len() >= 24 && token.bytes().any(|byte| byte.is_ascii_digit());
            assert!(!opaque, "{dialect}: {token}");
        }
        for case in load_cases(dialect).unwrap() {
            let request = &case.request;
            let mut prompts: Vec<&Value> = Vec::new();
            for key in ["messages", "input"] {
                if let Some(Value::Array(items)) = request.get(key) {
                    prompts.extend(items.iter().filter_map(|item| item.get("content")));
                }
            }
            prompts.extend(
                ["system", "instructions"]
                    .iter()
                    .filter_map(|key| request.get(*key)),
            );
            assert!(!prompts.is_empty(), "{}", case.case);
            for prompt in prompts {
                assert!(
                    prompt
                        .as_str()
                        .is_some_and(|text| text.starts_with("synthetic")),
                    "{}: {prompt}",
                    case.case
                );
            }
        }
    }
}

// ---------------------------------------------------------------- assembly

#[test]
fn every_case_gives_its_defined_result() {
    let mut executor = RecordingExecutor::default();
    for dialect in Dialect::ALL {
        for case in load_cases(dialect).unwrap() {
            let verdict = run_case(&case, LIMITS, &mut executor);
            assert!(
                verdict.passed(),
                "{}: {:?}",
                case.case,
                verdict.mismatches()
            );
            assert_eq!(verdict.outcome(), case.expect.outcome, "{}", case.case);
            assert_eq!(verdict.source(), SourceClass::Fixture);
        }
    }
}

#[test]
fn each_dialect_assembles_two_parallel_tool_calls_exactly() {
    let expected_finish = [(CC, "tool_calls"), (RS, "completed"), (AM, "tool_use")];
    for (dialect, finish) in expected_finish {
        let case = parallel_case(dialect);
        let outcome = replay(&case);
        let turn = outcome
            .completed()
            .unwrap_or_else(|| panic!("{dialect}: {outcome:?}"));
        assert_eq!(turn.finish().raw, finish);
        assert_eq!(turn.finish().reason, FinishReason::ToolCalls);
        let calls: Vec<(u32, &str, &str, &str)> = turn
            .tool_calls()
            .iter()
            .map(|call| {
                (
                    call.index,
                    call.call_id.as_str(),
                    call.name.as_str(),
                    call.arguments_json.as_str(),
                )
            })
            .collect();
        let (first, second, base) = match dialect {
            CC => ("call_a", "call_b", 0),
            RS => ("call_a", "call_b", 0),
            AM => ("toolu_a", "toolu_b", 1),
        };
        assert_eq!(
            calls,
            vec![
                (base, first, "read_file", "{\"path\": \"src/lib.rs\"}"),
                (base + 1, second, "list_dir", "{\"path\": \"tests\"}"),
            ],
            "{dialect}"
        );
        let validated = validate_turn(turn, &request(&case)).unwrap();
        let mut executor = RecordingExecutor::default();
        assert_eq!(execute_turn(&mut executor, &validated), 2);
        assert_eq!(
            executor.executed,
            vec![
                (
                    first.to_owned(),
                    "read_file".to_owned(),
                    "{\"path\":\"src/lib.rs\"}".to_owned()
                ),
                (
                    second.to_owned(),
                    "list_dir".to_owned(),
                    "{\"path\":\"tests\"}".to_owned()
                ),
            ]
        );
    }
    // Fragments of two declared calls may interleave; each joins its own index.
    let outcome = replay(&find(CC, "cc-interleaved-fragments"));
    let turn = outcome.completed().unwrap();
    assert_eq!(
        turn.tool_calls()[0].arguments_json,
        "{\"path\": \"src/lib.rs\"}"
    );
    assert_eq!(turn.tool_calls()[1].arguments_json, "{\"path\": \"tests\"}");
}

#[test]
fn a_json_fragment_mid_stream_is_not_malformed() {
    for dialect in Dialect::ALL {
        let case = parallel_case(dialect);
        let complete = replay(&case).completed().unwrap().tool_calls()[0]
            .arguments_json
            .len();
        let all = frames(&case);
        let mut assembler = StreamAssembler::new(dialect, LIMITS);
        let mut saw_partial = false;
        for (position, frame) in all.iter().enumerate() {
            let flow = assembler.push(frame);
            if position + 1 < all.len() {
                assert_eq!(flow, Flow::Continue, "{dialect} frame {position}");
            }
            if let Some(first) = assembler.pending_tool_calls().first() {
                if first.received_argument_bytes > 0 && first.received_argument_bytes < complete {
                    // An incomplete JSON prefix was accepted without judgement.
                    saw_partial = true;
                    assert!(!first.arguments_closed);
                }
            }
        }
        assert!(saw_partial, "{dialect}");
        assert_eq!(
            assembler.finish(StreamEnd::Eof).kind(),
            OutcomeKind::Completed
        );
    }
}

#[test]
fn partial_arguments_are_never_executed() {
    for dialect in Dialect::ALL {
        for case in load_cases(dialect).unwrap() {
            let mut executor = RecordingExecutor::default();
            let verdict = run_case(&case, LIMITS, &mut executor);
            let outcome = replay(&case);
            if case.expect.execution == ExpectedExecution::Executes {
                assert_eq!(
                    executor.executed.len(),
                    case.expect.tool_calls.len(),
                    "{}",
                    case.case
                );
                assert_eq!(verdict.executed_calls(), executor.executed.len());
                continue;
            }
            assert!(
                executor.executed.is_empty(),
                "{} executed a call",
                case.case
            );
            assert_eq!(verdict.executed_calls(), 0);
            if outcome.completed().is_none() {
                // The calls a non-completed turn held are dropped, with no argument text.
                assert_eq!(
                    outcome.dropped().len(),
                    case.expect.dropped_tool_calls,
                    "{}",
                    case.case
                );
            }
        }
    }
    // A disconnect inside the arguments leaves a partial call that is only reported.
    let outcome = replay(&find(AM, "am-disconnect-mid-arguments"));
    assert!(outcome.completed().is_none());
    let dropped = &outcome.dropped()[0];
    assert_eq!(
        (dropped.call_id.as_str(), dropped.name.as_str()),
        ("toolu_a", "read_file")
    );
    assert_eq!(dropped.received_argument_bytes, "{\"path\": \"sr".len());
    assert!(!dropped.arguments_closed);
}

#[test]
fn each_fault_gives_its_defined_result() {
    // Disconnect mid-arguments, duplicate event, out-of-order index, tool refusal, quota
    // failure and context overflow, in every dialect (S9 line 167).
    let faults = [
        (CC, "cc-disconnect-mid-arguments", "disconnected"),
        (CC, "cc-duplicate-header", "violation:DuplicateEvent"),
        (CC, "cc-out-of-order-index", "violation:OutOfOrderIndex"),
        (CC, "cc-refusal", "refused:stop"),
        (CC, "cc-quota-mid-stream", "failed:QuotaExceeded"),
        (CC, "cc-context-overflow", "failed:ContextOverflow"),
        (RS, "rs-disconnect-mid-arguments", "disconnected"),
        (RS, "rs-duplicate-event", "violation:DuplicateEvent"),
        (RS, "rs-out-of-order-index", "violation:OutOfOrderIndex"),
        (RS, "rs-refusal", "refused:completed"),
        (RS, "rs-quota-error-event", "failed:QuotaExceeded"),
        (RS, "rs-context-overflow", "failed:ContextOverflow"),
        (AM, "am-disconnect-mid-arguments", "disconnected"),
        (AM, "am-duplicate-block-start", "violation:DuplicateEvent"),
        (AM, "am-out-of-order-index", "violation:OutOfOrderIndex"),
        (AM, "am-refusal", "refused:refusal"),
        (AM, "am-quota-billing-error", "failed:QuotaExceeded"),
        (
            AM,
            "am-context-window-exceeded",
            "truncated:model_context_window_exceeded",
        ),
    ];
    for (dialect, id, expected) in faults {
        let outcome = replay(&find(dialect, id));
        let result = match &outcome {
            TurnOutcome::Disconnected { .. } => "disconnected".to_owned(),
            TurnOutcome::Violation { violation, .. } => format!("violation:{:?}", violation.kind),
            TurnOutcome::Refused { finish, .. } => format!("refused:{}", finish.raw),
            TurnOutcome::Failed { error, .. } => format!("failed:{:?}", error.class),
            TurnOutcome::Truncated { finish, .. } => format!("truncated:{}", finish.raw),
            other => format!("{:?}", other.kind()),
        };
        assert_eq!(result, expected, "{id}");
        assert!(outcome.completed().is_none(), "{id}");
    }
}

#[test]
fn a_stream_cut_mid_event_is_a_disconnect() {
    for dialect in Dialect::ALL {
        let case = parallel_case(dialect);
        let text = encode_sse(&frames(&case)).unwrap();
        // Cut inside the event that carries the end of the first call's arguments.
        let cut = text.find("lib.rs").unwrap();
        let outcome = assemble_sse(dialect, &text[..cut], StreamEnd::Eof, LIMITS);
        assert_eq!(outcome.kind(), OutcomeKind::Disconnected, "{dialect}");
        assert_eq!(outcome.dropped().len(), 1, "{dialect}");
        // The whole text assembles; a client cancel after it changes nothing.
        let outcome = assemble_sse(dialect, &text, StreamEnd::ClientCancel, LIMITS);
        assert_eq!(outcome.kind(), OutcomeKind::Completed, "{dialect}");
    }
}

#[test]
fn anything_after_the_terminal_event_is_refused() {
    for dialect in Dialect::ALL {
        let case = parallel_case(dialect);
        let mut all = frames(&case);
        all.push(all[all.len() - 2].clone());
        let outcome = assemble_frames(dialect, &all, StreamEnd::Eof, LIMITS);
        assert_eq!(
            violation_kind(&outcome),
            Some(ViolationKind::EventAfterTerminal),
            "{dialect}"
        );
        assert_eq!(outcome.dropped().len(), 2);
    }
}

#[test]
fn late_events_break_the_declared_order() {
    // Messages: content blocks come before every message_delta.
    let mut all = frames(&find(AM, "am-text"));
    let stop = all.pop().unwrap();
    all.push(SseFrame::named(
        "content_block_start",
        json!({"type": "content_block_start", "index": 1,
               "content_block": {"type": "text", "text": ""}})
        .to_string(),
    ));
    all.push(stop);
    let outcome = assemble_frames(AM, &all, StreamEnd::Eof, LIMITS);
    assert_eq!(
        violation_kind(&outcome),
        Some(ViolationKind::UnexpectedEvent)
    );

    // Responses: after content_part.done, a delta is out of order and a second done is a
    // duplicate.
    let text = frames(&find(RS, "rs-text"));
    let part_done = text
        .iter()
        .position(|frame| frame.event.as_deref() == Some("response.content_part.done"))
        .unwrap();
    let prefix = &text[..=part_done];
    let next = |kind: &str, fields: Value| {
        let mut data = fields;
        data["type"] = json!(kind);
        data["sequence_number"] = json!(part_done + 1);
        SseFrame::named(kind, data.to_string())
    };
    let late_delta = next(
        "response.output_text.delta",
        json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "x"}),
    );
    let again = next(
        "response.content_part.done",
        json!({"item_id": "msg_1", "output_index": 0, "content_index": 0,
               "part": {"type": "output_text", "text": "Synthetic answer.", "annotations": []}}),
    );
    for (extra, expected) in [
        (late_delta, ViolationKind::UnexpectedEvent),
        (again, ViolationKind::DuplicateEvent),
    ] {
        let mut stream = prefix.to_vec();
        stream.push(extra);
        let outcome = assemble_frames(RS, &stream, StreamEnd::Eof, LIMITS);
        assert_eq!(violation_kind(&outcome), Some(expected));
    }

    // A request refused before streaming exercises only its error mapping.
    let overflow = find(CC, "cc-context-overflow");
    assert_eq!(
        overflow.exercised_features(Some(&request(&overflow))),
        BTreeSet::from([Feature::RequestFields, Feature::Errors])
    );
}

#[test]
fn a_forced_named_call_may_end_with_stop() {
    // OpenAI's form for a forced named tool choice: the turn completes with the raw
    // finish `stop`, marked as a stop that carries calls.
    let forced = find(CC, "cc-forced-named-stop");
    let outcome = replay(&forced);
    let turn = outcome.completed().unwrap();
    assert_eq!(
        turn.finish(),
        &WireFinish {
            raw: "stop".to_owned(),
            reason: FinishReason::StopWithToolCalls
        }
    );
    let validated = validate_turn(turn, &request(&forced)).unwrap();
    let mut executor = RecordingExecutor::default();
    assert_eq!(execute_turn(&mut executor, &validated), 1);
    assert_eq!(
        executor.executed,
        vec![(
            "call_a".to_owned(),
            "read_file".to_owned(),
            "{\"path\":\"src/lib.rs\"}".to_owned()
        )]
    );

    // The same stream under no, auto or required tool choice, and under a choice naming
    // another tool, is refused, and nothing runs.
    for (id, kind) in [
        ("cc-stop-with-tool-calls", RefusalKind::FinishReasonMismatch),
        ("cc-stop-with-calls-auto", RefusalKind::FinishReasonMismatch),
        (
            "cc-stop-with-calls-required",
            RefusalKind::FinishReasonMismatch,
        ),
        (
            "cc-forced-named-stop-other-tool",
            RefusalKind::ToolChoiceNamed,
        ),
    ] {
        let case = find(CC, id);
        assert_eq!(case.response.frames, forced.response.frames, "{id}");
        let outcome = replay(&case);
        let turn = outcome.completed().unwrap();
        assert_eq!(
            turn.finish().reason,
            FinishReason::StopWithToolCalls,
            "{id}"
        );
        let refusal = validate_turn(turn, &request(&case)).unwrap_err();
        assert_eq!((refusal.kind, refusal.index), (kind, Some(0)), "{id}");
        let mut executor = RecordingExecutor::default();
        let verdict = run_case(&case, LIMITS, &mut executor);
        assert!(verdict.passed(), "{id}: {:?}", verdict.mismatches());
        assert!(executor.executed.is_empty(), "{id}");
    }

    // Unchanged: a tool-call finish without calls is a violation, and Messages ends a
    // tool call only with tool_use.
    let empty = replay(&find(CC, "cc-tool-calls-without-calls"));
    assert_eq!(
        violation_kind(&empty),
        Some(ViolationKind::FinishReasonMismatch)
    );
    let messages = replay(&find(AM, "am-end-turn-with-tool-use"));
    assert_eq!(
        violation_kind(&messages),
        Some(ViolationKind::FinishReasonMismatch)
    );
    assert_eq!(messages.dropped().len(), 1);
}

#[test]
fn the_completed_response_must_match_the_streamed_items() {
    let case = parallel_case(RS);
    let mut all = frames(&case);
    let last = all.len() - 1;
    let mut data: Value = serde_json::from_str(&all[last].data).unwrap();
    data["response"]["output"][1]["arguments"] = json!("{\"path\": \"src\"}");
    all[last] = SseFrame::named("response.completed", data.to_string());
    let outcome = assemble_frames(RS, &all, StreamEnd::Eof, LIMITS);
    assert_eq!(
        violation_kind(&outcome),
        Some(ViolationKind::ContentMismatch)
    );
}

#[test]
fn limits_bound_what_a_stream_accumulates() {
    let case = parallel_case(CC);
    let all = frames(&case);
    let tight = |limits: AssemblyLimits| assemble_frames(CC, &all, StreamEnd::Eof, limits);
    let outcome = tight(AssemblyLimits {
        max_argument_bytes: 8,
        ..LIMITS
    });
    assert_eq!(violation_kind(&outcome), Some(ViolationKind::LimitExceeded));
    let outcome = tight(AssemblyLimits {
        max_tool_calls: 1,
        ..LIMITS
    });
    assert_eq!(violation_kind(&outcome), Some(ViolationKind::LimitExceeded));
    let text_case = find(CC, "cc-text-stream");
    let outcome = assemble_frames(
        CC,
        &frames(&text_case),
        StreamEnd::Eof,
        AssemblyLimits {
            max_text_bytes: 4,
            ..LIMITS
        },
    );
    assert_eq!(violation_kind(&outcome), Some(ViolationKind::LimitExceeded));
}

#[test]
fn validation_refuses_what_the_request_did_not_allow() {
    let case = parallel_case(CC);
    let outcome = replay(&case);
    let turn = outcome.completed().unwrap();
    // A turn validated against a request of another dialect.
    let messages_request = request(&parallel_case(AM));
    assert_eq!(
        validate_turn(turn, &messages_request).unwrap_err().kind,
        RefusalKind::DialectMismatch
    );
    // Schema accuracy ignores tool choice and parallel settings.
    let disabled = find(CC, "cc-parallel-disabled");
    let refused = replay(&disabled);
    let refused_turn = refused.completed().unwrap();
    assert_eq!(
        validate_turn(refused_turn, &request(&disabled))
            .unwrap_err()
            .kind,
        RefusalKind::ParallelNotAllowed
    );
    assert_eq!(schema_valid_calls(refused_turn, &request(&disabled)), 2);
    // The same named-choice turn is accepted when the request names the tool it called.
    let named = find(RS, "rs-tool-choice-named");
    let named_outcome = replay(&named);
    let mut body = named.request.clone();
    body["tool_choice"] = json!({"type": "function", "name": "read_file"});
    let accepting = RequestProfile::from_request(RS, &body).unwrap();
    assert_eq!(
        validate_turn(named_outcome.completed().unwrap(), &accepting)
            .unwrap()
            .calls()
            .len(),
        1
    );
    // Arguments that are JSON but not an object.
    let body = json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "synthetic"}],
                      "tools": [{"type": "function", "function": {"name": "read_file"}}]});
    let frames = [
        SseFrame::data(json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_a", "type": "function", "function": {"name": "read_file", "arguments": "[1]"}}]}}]}).to_string()),
        SseFrame::data(json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}).to_string()),
        SseFrame::data("[DONE]"),
    ];
    let outcome = assemble_frames(CC, &frames, StreamEnd::Eof, LIMITS);
    let refusal = validate_turn(
        outcome.completed().unwrap(),
        &RequestProfile::from_request(CC, &body).unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        (refusal.kind, refusal.index),
        (RefusalKind::ArgumentsNotObject, Some(0))
    );
}

// ---------------------------------------------------------------- capability rows

#[test]
fn a_fixture_run_cannot_advertise_a_dialect() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(5));
    let mut executor = RecordingExecutor::default();
    let cases = load_cases(CC).unwrap();
    let run = run_offline(
        CC,
        &cases,
        corpus_fingerprint(CC),
        LIMITS,
        &clock,
        &mut executor,
    )
    .unwrap();
    assert_eq!(run.source(), SourceClass::Fixture);
    assert_eq!(run.origin(), &RunOrigin::Fixtures);
    assert!(run
        .verdicts()
        .iter()
        .all(|verdict| verdict.source() == SourceClass::Fixture));
    assert_eq!(
        CapabilityRow::from_run(model(), runner(), CC, &run, &[]),
        Err(RowError::InsufficientSource {
            found: SourceClass::Fixture,
            required: SourceClass::HostProbe
        })
    );
}

#[test]
fn fixtures_never_advertise_a_model_or_runner_nobody_contacted() {
    // Review proof (R1-d): fixture verdicts recorded as a host probe advertised Chat
    // Completions for a model and runner nobody contacted, and a verdict could be written
    // by hand. Verdict fields are private now, only this module records a run, and a
    // case's own recording is fixture evidence that never joins a live run.
    let clock = ManualClock::new(MonotonicTime::from_nanos(7));
    let mut executor = RecordingExecutor::default();
    let verdicts: Vec<CaseVerdict> = load_cases(CC)
        .unwrap()
        .iter()
        .map(|case| run_case(case, LIMITS, &mut executor))
        .collect();
    let never_contacted = digest("yougori/test/model/v1", &[b"never-contacted"]);
    let other_runner = RunnerRef {
        release: BackendRelease::new(Backend::LlamaCpp, "b9999").unwrap(),
        category: ExecutionCategory::VmSandbox,
    };
    let relabelled = ConformanceRun::record(
        CC,
        RunOrigin::LiveRunner {
            model: never_contacted,
            runner: other_runner.clone(),
            transcript: digest("yougori/test/transcript/v1", &[b"none"]),
        },
        live_configuration(),
        &clock,
        verdicts,
    );
    assert!(matches!(
        relabelled,
        Err(RunError::SourceMismatch {
            found: SourceClass::Fixture,
            required: SourceClass::HostProbe,
            ..
        })
    ));

    // A live run names what it contacted and describes nothing else.
    let run = live_run(CC, &clock);
    assert_eq!(run.source(), SourceClass::HostProbe);
    assert!(matches!(
        run.origin(),
        RunOrigin::LiveRunner { model: contacted, runner: serving, .. }
            if *contacted == model() && *serving == runner()
    ));
    assert_eq!(
        CapabilityRow::from_run(never_contacted, runner(), CC, &run, &[]),
        Err(RowError::OtherModel {
            run: model(),
            row: never_contacted
        })
    );
    assert_eq!(
        CapabilityRow::from_run(model(), other_runner.clone(), CC, &run, &[]),
        Err(RowError::OtherRunner {
            run: runner(),
            row: other_runner.clone()
        })
    );
    let mut table = CapabilityTable::new();
    table.publish(CapabilityRow::from_run(model(), runner(), CC, &run, &[]).unwrap());
    assert_eq!(
        table.advertised_dialects(model(), &runner(), live_configuration()),
        vec![CC]
    );
    for (other_model, other) in [
        (never_contacted, runner()),
        (model(), other_runner.clone()),
        (never_contacted, other_runner),
    ] {
        assert!(table
            .advertised_dialects(other_model, &other, live_configuration())
            .is_empty());
    }
}

#[test]
fn a_live_run_binds_its_model_runner_and_transcript() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(9));
    let case = find(CC, "cc-text-stream");
    let answer = served(&case);
    // The same answer with another chunk id: still conforming, but another transcript.
    let mut other_answer = answer.clone();
    let first = other_answer.frames[0].data_text.take().unwrap();
    other_answer.frames[0].data_text = Some(first.replace("chatcmpl-synthetic", "chatcmpl-live"));
    let run_with = |model, answer: &RecordedResponse| {
        let mut executor = RecordingExecutor::default();
        let mut harness = LiveHarness::new(CC, model, runner(), live_configuration(), LIMITS);
        let verdict = harness.observe(&case, answer, &mut executor).unwrap();
        assert!(verdict.passed(), "{:?}", verdict.mismatches());
        assert_eq!(verdict.source(), SourceClass::HostProbe);
        harness.finish(&clock).unwrap()
    };
    let transcript = |run: &ConformanceRun| match run.origin() {
        RunOrigin::LiveRunner { transcript, .. } => *transcript,
        RunOrigin::Fixtures => panic!("not a live run"),
    };
    let run = run_with(model(), &answer);
    assert_eq!(run_with(model(), &answer), run);
    let other = run_with(model(), &other_answer);
    assert_ne!(transcript(&other), transcript(&run));
    assert_ne!(other.identity(), run.identity());
    let another_model = run_with(digest("yougori/test/model/v1", &[b"another"]), &answer);
    assert_eq!(transcript(&another_model), transcript(&run));
    assert_ne!(another_model.identity(), run.identity());
}

#[test]
fn one_successful_chat_completion_does_not_advertise_a_dialect() {
    let clock = ManualClock::default();
    let mut executor = RecordingExecutor::default();
    let case = find(CC, "cc-text-stream");
    let mut harness = harness(CC);
    let verdict = harness
        .observe(&case, &served(&case), &mut executor)
        .unwrap();
    assert!(verdict.passed());
    let run = harness.finish(&clock).unwrap();
    let row = CapabilityRow::from_run(model(), runner(), CC, &run, &[]).unwrap();
    assert!(matches!(
        row.cell(Feature::RequestFields),
        CellStatus::Supported { .. }
    ));
    assert_eq!(
        row.cell(Feature::TokenCounting),
        &CellStatus::Unsupported {
            reason: UnsupportedFeature::NotInDialect
        }
    );
    let reasons = row.advertisement().unwrap_err();
    assert_eq!(
        reasons.untested,
        vec![
            Feature::ToolSchema,
            Feature::ToolChoice,
            Feature::ParallelCalls,
            Feature::Errors,
            Feature::Cancellation
        ]
    );
    assert_eq!(reasons.unsupported_every_exchange, vec![Feature::Errors]);
    // Even the request that succeeded is refused: the dialect is not advertised.
    let plain = request(&find(CC, "cc-text-stream"));
    assert!(matches!(
        row.admit(&plain, live_configuration()),
        Err(CapabilityRefusal::NotAdvertised { .. })
    ));
}

#[test]
fn a_complete_run_advertises_and_admits() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(42));
    let run = live_run(CC, &clock);
    let row = CapabilityRow::from_run(model(), runner(), CC, &run, &[]).unwrap();
    for feature in Feature::ALL {
        match row.cell(feature) {
            CellStatus::Supported { evidence } => {
                assert_eq!(evidence.run, run.identity());
                assert!(!evidence.cases.is_empty());
            }
            other => assert_eq!(
                (feature, other),
                (
                    Feature::TokenCounting,
                    &CellStatus::Unsupported {
                        reason: UnsupportedFeature::NotInDialect
                    }
                )
            ),
        }
    }
    assert_eq!(row.advertisement(), Ok(()));
    let full = request(&parallel_case(CC));
    assert_eq!(row.admit(&full, live_configuration()), Ok(()));
    assert_eq!(
        row.runtime_label(),
        "GPU runtime (shared kernel), not a sandbox"
    );
    // Responses and Messages never ran a token count, so they stay unadvertised until
    // it is tested or the runner declares it unsupported.
    for dialect in [RS, AM] {
        let run = live_run(dialect, &clock);
        let row = CapabilityRow::from_run(model(), runner(), dialect, &run, &[]).unwrap();
        assert_eq!(row.cell(Feature::TokenCounting), &CellStatus::Untested);
        assert_eq!(
            row.advertisement().unwrap_err().untested,
            vec![Feature::TokenCounting]
        );
        let declared = [(
            Feature::TokenCounting,
            "no count endpoint in this release".to_owned(),
        )];
        let row = CapabilityRow::from_run(model(), runner(), dialect, &run, &declared).unwrap();
        assert_eq!(row.advertisement(), Ok(()));
    }
}

#[test]
fn the_capability_row_refuses_unsupported_combinations() {
    let clock = ManualClock::default();
    let run = live_run(CC, &clock);
    let declared = [(
        Feature::ParallelCalls,
        "this runner emits one call per turn".to_owned(),
    )];
    let row = CapabilityRow::from_run(model(), runner(), CC, &run, &declared).unwrap();
    assert_eq!(row.advertisement(), Ok(()));
    let parallel = request(&parallel_case(CC));
    match row.admit(&parallel, live_configuration()) {
        Err(CapabilityRefusal::Unsupported { features }) => {
            assert_eq!(features.len(), 1);
            assert_eq!(features[0].0, Feature::ParallelCalls);
            assert!(matches!(
                features[0].1,
                UnsupportedFeature::DeclaredByRunner { .. }
            ));
        }
        other => panic!("{other:?}"),
    }
    let mut body = parallel_case(CC).request;
    body["parallel_tool_calls"] = json!(false);
    let single = RequestProfile::from_request(CC, &body).unwrap();
    assert_eq!(row.admit(&single, live_configuration()), Ok(()));

    // Another configuration, another dialect, an unpublished combination.
    let other = ConfigurationFingerprint::from_settings([("launch", "other-flags")]).unwrap();
    assert!(matches!(
        row.admit(&single, other),
        Err(CapabilityRefusal::ConfigurationChanged { .. })
    ));
    let messages_request = request(&parallel_case(AM));
    assert_eq!(
        row.admit(&messages_request, live_configuration()),
        Err(CapabilityRefusal::DialectMismatch {
            row: CC,
            request: AM
        })
    );
    let mut table = CapabilityTable::new();
    assert!(table.publish(row).is_none());
    assert!(matches!(
        table.admit(model(), &runner(), &messages_request, live_configuration()),
        Err(CapabilityRefusal::NoRow { dialect: AM, .. })
    ));
    let llama = RunnerRef {
        release: BackendRelease::new(Backend::LlamaCpp, "b4000").unwrap(),
        category: ExecutionCategory::HostProcessModelRuntime,
    };
    assert!(matches!(
        table.row(model(), &llama, CC),
        Err(CapabilityRefusal::NoRow { .. })
    ));
    assert_eq!(
        table.admit(model(), &runner(), &single, live_configuration()),
        Ok(())
    );
    assert_eq!(
        table.advertised_dialects(model(), &runner(), live_configuration()),
        vec![CC]
    );

    // No row in one dialect comes from a run in another, and token counting does not
    // exist in Chat Completions at all.
    assert_eq!(
        CapabilityRow::from_run(model(), runner(), AM, &run, &[]),
        Err(RowError::DialectMismatch { run: CC, row: AM })
    );
    assert_eq!(
        RequestProfile::from_token_count_request(CC, &json!({"model": "m"})),
        Err(RequestError::FeatureNotInDialect {
            feature: Feature::TokenCounting
        })
    );
    assert_eq!(
        CapabilityRow::from_run(
            model(),
            runner(),
            CC,
            &run,
            &[(Feature::Usage, " ".to_owned())]
        ),
        Err(RowError::EmptyExplanation {
            feature: Feature::Usage
        })
    );
}

#[test]
fn a_failing_case_marks_what_it_exercised_unsupported() {
    let clock = ManualClock::default();
    let mut executor = RecordingExecutor::default();
    let mut harness = harness(CC);
    for mut case in load_cases(CC).unwrap() {
        // The runner answers as recorded; the expectation of one case differs.
        let answer = served(&case);
        if case.case.as_str() == "cc-parallel-two-tools" {
            case.expect.tool_calls[1].name = "read_file".to_owned();
        }
        harness.observe(&case, &answer, &mut executor).unwrap();
    }
    let run = harness.finish(&clock).unwrap();
    let failed: Vec<_> = run
        .verdicts()
        .iter()
        .filter(|verdict| !verdict.passed())
        .collect();
    assert_eq!(failed.len(), 1);
    assert!(failed[0].exercised().contains(&Feature::ParallelCalls));
    let row = CapabilityRow::from_run(model(), runner(), CC, &run, &[]).unwrap();
    match row.cell(Feature::ParallelCalls) {
        CellStatus::Unsupported {
            reason: UnsupportedFeature::ConformanceFailed { case, .. },
        } => assert_eq!(case.as_str(), "cc-parallel-two-tools"),
        other => panic!("{other:?}"),
    }
    // Errors were exercised only by passing cases and stay supported, but a failure in
    // a feature every exchange uses withholds the dialect.
    assert!(matches!(
        row.cell(Feature::Errors),
        CellStatus::Supported { .. }
    ));
    assert!(row
        .advertisement()
        .unwrap_err()
        .unsupported_every_exchange
        .contains(&Feature::RequestFields));
}

#[test]
fn runs_refuse_mixed_or_repeated_cases() {
    let clock = ManualClock::default();
    let mut executor = RecordingExecutor::default();
    let text = find(CC, "cc-text-stream");
    let other = find(AM, "am-text");
    // The live harness refuses a repeated case or one of another dialect, and records
    // nothing without a case.
    assert_eq!(harness(CC).finish(&clock), Err(RunError::NoCases));
    let mut live = harness(CC);
    live.observe(&text, &served(&text), &mut executor).unwrap();
    assert!(matches!(
        live.observe(&text, &served(&text), &mut executor),
        Err(RunError::DuplicateCase { .. })
    ));
    assert!(matches!(
        live.observe(&other, &served(&other), &mut executor),
        Err(RunError::DialectMismatch { .. })
    ));
    assert_eq!(live.finish(&clock).unwrap().verdicts().len(), 1);

    // So does the recorder, which also refuses a verdict of another source.
    let verdict = run_case(&text, LIMITS, &mut executor);
    let record = |verdicts: Vec<CaseVerdict>| {
        ConformanceRun::record(
            CC,
            RunOrigin::Fixtures,
            corpus_fingerprint(CC),
            &clock,
            verdicts,
        )
    };
    assert_eq!(record(Vec::new()), Err(RunError::NoCases));
    assert!(matches!(
        record(vec![verdict.clone(), verdict.clone()]),
        Err(RunError::DuplicateCase { .. })
    ));
    let other_verdict = run_case(&other, LIMITS, &mut executor);
    assert!(matches!(
        record(vec![verdict, other_verdict]),
        Err(RunError::DialectMismatch { .. })
    ));
    let observed = harness(CC)
        .observe(&text, &served(&text), &mut executor)
        .unwrap();
    assert_eq!(
        record(vec![observed]),
        Err(RunError::SourceMismatch {
            case: label("cc-text-stream"),
            found: SourceClass::HostProbe,
            required: SourceClass::Fixture
        })
    );
}

#[test]
fn a_dialect_is_advertised_only_under_the_configuration_it_was_observed_with() {
    // Review finding: advertised_dialects ignored the configuration fingerprint that
    // admit checks.
    let clock = ManualClock::default();
    let run = live_run(CC, &clock);
    let mut table = CapabilityTable::new();
    table.publish(CapabilityRow::from_run(model(), runner(), CC, &run, &[]).unwrap());
    assert_eq!(
        table.advertised_dialects(model(), &runner(), live_configuration()),
        vec![CC]
    );
    let relaunched = ConfigurationFingerprint::from_settings([("launch", "other-flags")]).unwrap();
    assert!(table
        .advertised_dialects(model(), &runner(), relaunched)
        .is_empty());
    let plain = request(&find(CC, "cc-text-stream"));
    assert!(matches!(
        table.admit(model(), &runner(), &plain, relaunched),
        Err(CapabilityRefusal::ConfigurationChanged { .. })
    ));
}

#[test]
fn a_cancel_after_the_turn_completed_is_no_cancellation_evidence() {
    // Review proof (R1-d): a case whose stream completed and whose calls ran was credited
    // with cancellation because its recorded end was a client cancel.
    let mut case = parallel_case(CC);
    case.response.end = StreamEnd::ClientCancel;
    let mut executor = RecordingExecutor::default();
    let verdict = run_case(&case, LIMITS, &mut executor);
    assert!(verdict.passed(), "{:?}", verdict.mismatches());
    assert_eq!(verdict.outcome(), OutcomeKind::Completed);
    assert_eq!(executor.executed.len(), 2, "both calls ran");
    assert!(!verdict.exercised().contains(&Feature::Cancellation));

    // Only a cancelled turn shows cancellation, and none of its calls runs.
    for (dialect, id) in [
        (CC, "cc-client-cancel"),
        (RS, "rs-client-cancel"),
        (AM, "am-client-cancel"),
    ] {
        let cancelled = find(dialect, id);
        let mut executor = RecordingExecutor::default();
        let verdict = run_case(&cancelled, LIMITS, &mut executor);
        assert!(verdict.passed(), "{id}: {:?}", verdict.mismatches());
        assert_eq!(verdict.outcome(), OutcomeKind::Cancelled);
        assert!(verdict.exercised().contains(&Feature::Cancellation));
        assert!(executor.executed.is_empty());
    }
    // A cancelled expectation without a client cancel cannot be met.
    let mut uncancelled = find(CC, "cc-client-cancel");
    uncancelled.response.end = StreamEnd::Eof;
    assert!(matches!(
        uncancelled.check(),
        Err(CaseError::InconsistentExpectation { .. })
    ));
}

// ---------------------------------------------------------------- evidence levels

#[test]
fn protocol_correctness_is_what_the_offline_corpus_proves() {
    for dialect in Dialect::ALL {
        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        let mut executor = RecordingExecutor::default();
        let cases = load_cases(dialect).unwrap();
        let run = run_offline(
            dialect,
            &cases,
            corpus_fingerprint(dialect),
            LIMITS,
            &clock,
            &mut executor,
        )
        .unwrap();
        assert_eq!(run.observed_at(), MonotonicTime::from_nanos(1_000));
        assert_eq!(run.configuration(), corpus_fingerprint(dialect));
        let correctness = ProtocolCorrectness::of_run(&run);
        assert!(correctness.holds(), "{dialect}: {:?}", correctness.failed);
        assert_eq!(correctness.source, SourceClass::Fixture);
        assert_eq!(
            correctness.layer(),
            ProtocolConformance {
                fixtures: cases.len() as u64,
                failures: 0
            }
        );
        // The run's identity is stable, and binds the time it was observed.
        let again = run_offline(
            dialect,
            &cases,
            corpus_fingerprint(dialect),
            LIMITS,
            &clock,
            &mut executor,
        )
        .unwrap();
        assert_eq!(again.identity(), run.identity());
        clock.advance(Duration::from_nanos(1));
        let later = run_offline(
            dialect,
            &cases,
            corpus_fingerprint(dialect),
            LIMITS,
            &clock,
            &mut executor,
        )
        .unwrap();
        assert_ne!(later.identity(), run.identity());
    }
}

fn alignment(kernel: &[u8]) -> AlignmentKey {
    AlignmentKey {
        tokenizer: digest("yougori/test/tokenizer/v1", &[b"synthetic"]),
        chat_template: digest("yougori/test/template/v1", &[b"synthetic"]),
        weights: digest("yougori/test/weights/v1", &[b"synthetic"]),
        quantization: label("bf16"),
        kernel_configuration: digest("yougori/test/kernel/v1", &[kernel]),
    }
}

fn paired_corpus() -> PairedCorpus {
    let pairs = load_paired_items().unwrap();
    PairedCorpus::from_observations(pairs.iter().map(|pair| {
        let reference_case = find(pair.dialect, pair.reference_case.as_str());
        let candidate_case = find(pair.dialect, pair.candidate_case.as_str());
        let (reference_outcome, candidate_outcome) =
            (replay(&reference_case), replay(&candidate_case));
        let (reference_request, candidate_request) =
            (request(&reference_case), request(&candidate_case));
        observe_pair(
            pair.item.clone(),
            PairSide {
                outcome: &reference_outcome,
                request: &reference_request,
            },
            PairSide {
                outcome: &candidate_outcome,
                request: &candidate_request,
            },
        )
    }))
}

#[test]
fn paired_metrics_keep_their_denominators() {
    let corpus = paired_corpus();
    let observed: Vec<(&str, u32, u32, u32)> = corpus
        .observations
        .iter()
        .map(|o| {
            (
                o.item.as_str(),
                o.reference_calls,
                o.candidate_calls,
                o.candidate_schema_valid_calls,
            )
        })
        .collect();
    assert_eq!(
        observed,
        vec![
            ("pair-01", 2, 2, 2),
            ("pair-02", 2, 1, 0),
            ("pair-03", 2, 2, 2),
            ("pair-04", 2, 2, 2),
            ("pair-05", 0, 1, 0),
            ("pair-06", 2, 0, 0),
            ("pair-07", 2, 0, 0),
            ("pair-08", 0, 0, 0),
            ("pair-09", 0, 0, 0),
        ]
    );
    // The reference of pair-10 failed mid-stream: set aside, never guessed.
    assert_eq!(corpus.reference_failed, vec![label("pair-10")]);

    let reference = ReferenceSource {
        label: label("controlled-baseline"),
        run: Some(ReferenceRun {
            kind: ReferenceKind::Controlled,
            authorized: true,
            alignment: alignment(b"same"),
        }),
    };
    let task_success = SuccessRate::new(1, 3).unwrap();
    let fidelity =
        ModelFidelity::assess(&alignment(b"same"), &reference, &corpus, task_success).unwrap();
    let ModelFidelity::Measured {
        metrics,
        reference_failed,
        ..
    } = &fidelity
    else {
        panic!("{fidelity:?}");
    };
    assert_eq!(
        (
            metrics.true_positives,
            metrics.false_positives,
            metrics.false_negatives,
            metrics.true_negatives
        ),
        (4, 1, 2, 2)
    );
    // Precision over the 5 candidate-triggered items, recall over the 6 reference-triggered
    // ones, F1 = 2TP / (2TP + FP + FN), schema accuracy over the 8 triggered calls.
    assert_eq!(metrics.precision, Ratio::new(4, 5).unwrap());
    assert_eq!(metrics.recall, Ratio::new(4, 6).unwrap());
    assert_eq!(metrics.f1, Ratio::new(8, 11).unwrap());
    assert_eq!(metrics.schema_accuracy, Ratio::new(6, 8).unwrap());
    assert_eq!(metrics.parallel_tool_success, Ratio::new(3, 6).unwrap());
    assert_eq!(
        (
            metrics.task_success.successes(),
            metrics.task_success.attempts()
        ),
        (1, 3)
    );
    assert_eq!(reference_failed, &vec![label("pair-10")]);
    assert!(matches!(
        fidelity.evidence(),
        ToolFidelityEvidence::Measured { .. }
    ));
}

#[test]
fn model_fidelity_needs_a_matched_reference() {
    let corpus = paired_corpus();
    let rate = SuccessRate::new(1, 1).unwrap();
    let assess = |run: Option<ReferenceRun>| {
        let source = ReferenceSource {
            label: label("vendor-api"),
            run,
        };
        ModelFidelity::assess(&alignment(b"candidate"), &source, &corpus, rate).unwrap()
    };
    let reference = |kind, authorized, kernel: &[u8]| ReferenceRun {
        kind,
        authorized,
        alignment: alignment(kernel),
    };
    let reason = |fidelity: ModelFidelity| match fidelity {
        ModelFidelity::ReferenceUnavailable { reason, .. } => reason,
        other => panic!("{other:?}"),
    };
    assert_eq!(reason(assess(None)), ReferenceUnavailable::NoReferenceRun);
    assert_eq!(
        reason(assess(Some(reference(
            ReferenceKind::Unlicensed,
            true,
            b"candidate"
        )))),
        ReferenceUnavailable::NotLicensed
    );
    assert_eq!(
        reason(assess(Some(reference(
            ReferenceKind::LicensedOfficial,
            false,
            b"candidate"
        )))),
        ReferenceUnavailable::NotAuthorized
    );
    // An official reference on other kernels: nothing about decoding, temperature zero
    // included, makes up for the mismatch, so fidelity is not recorded.
    assert_eq!(
        reason(assess(Some(reference(
            ReferenceKind::LicensedOfficial,
            true,
            b"vendor-kernels"
        )))),
        ReferenceUnavailable::SettingsMismatch {
            fields: vec![AlignmentField::KernelConfiguration]
        }
    );
    let unavailable = assess(None);
    assert_eq!(
        unavailable.evidence().metrics(),
        Err(ReportError::ReferenceUnavailable)
    );
    assert!(matches!(
        assess(Some(reference(
            ReferenceKind::LicensedOfficial,
            true,
            b"candidate"
        ))),
        ModelFidelity::Measured { .. }
    ));
    // The same item twice is refused.
    let mut doubled = corpus.clone();
    doubled.reference_failed.push(label("pair-01"));
    let source = ReferenceSource {
        label: label("baseline"),
        run: Some(reference(ReferenceKind::Controlled, true, b"candidate")),
    };
    assert_eq!(
        ModelFidelity::assess(&alignment(b"candidate"), &source, &doubled, rate),
        Err(ReportError::DuplicatePairedItem)
    );
}

#[test]
fn a_reference_that_stopped_early_still_has_a_trigger_label() {
    let truncated_case = find(CC, "cc-length-mid-arguments");
    let truncated = replay(&truncated_case);
    let side = PairSide {
        outcome: &truncated,
        request: &request(&truncated_case),
    };
    assert!(side.finished());
    assert_eq!((side.triggered_calls(), side.schema_valid_calls()), (0, 0));
    // A protocol violation has no finish reason at all.
    let violated_case = find(CC, "cc-duplicate-header");
    let violated = replay(&violated_case);
    let side = PairSide {
        outcome: &violated,
        request: &request(&violated_case),
    };
    assert!(!side.finished());
    assert_eq!(side.triggered_calls(), 0);
    // A `stop` that carries a call completes, so the call counts as triggered whatever
    // the tool choice; whether it may run is validation's question.
    let stopped_case = find(CC, "cc-stop-with-tool-calls");
    let stopped = replay(&stopped_case);
    let side = PairSide {
        outcome: &stopped,
        request: &request(&stopped_case),
    };
    assert!(side.finished());
    assert_eq!((side.triggered_calls(), side.schema_valid_calls()), (1, 1));
}

// ---------------------------------------------------------------- agent task utility

const BUDGET: TaskBudget = TaskBudget {
    max_turns: 8,
    max_tool_calls: 10,
    max_elapsed_seconds: 600,
};

fn op(id: &str) -> OperationId {
    OperationId::new(id).unwrap()
}

fn parallel_turn() -> ValidatedTurn {
    let case = parallel_case(CC);
    validate_turn(replay(&case).completed().unwrap(), &request(&case)).unwrap()
}

/// Two parallel tools, a file edit, a failing test, a repair and a passing test.
fn scripted_attempt(clock: &ManualClock, attempt: &str, kind: AttemptKind) -> AgentTaskRecord {
    let mut recorder = AgentTaskRecorder::start(
        clock,
        label("bench-03-fix-test"),
        op(attempt),
        kind,
        BUDGET,
        TaskRequirements::BENCH_03,
    );
    recorder.turn();
    recorder.tools_executed(&parallel_turn());
    clock.advance(Duration::from_secs(10));
    recorder.file_changed();
    recorder.test_run(false);
    recorder.turn();
    recorder.file_changed();
    clock.advance(Duration::from_secs(10));
    recorder.test_run(true);
    recorder.finish()
}

#[test]
fn an_agent_task_succeeds_only_with_every_step_in_budget() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(7));
    let record = scripted_attempt(&clock, "op-1", AttemptKind::Original);
    assert_eq!(record.outcome(), &TaskOutcome::Succeeded);
    assert_eq!(record.elapsed(), Duration::from_secs(20));
    assert_eq!((record.turns(), record.tool_calls()), (2, 2));
    assert_eq!(
        record.milestones()[0].milestone,
        Milestone::ToolsExecuted { calls: 2 }
    );
    assert_eq!(record.milestones()[0].at, MonotonicTime::from_nanos(7));
    assert_eq!(record.outcome().failure_kind(), None);

    let start = |requirements| {
        AgentTaskRecorder::start(
            &clock,
            label("task"),
            op("op-2"),
            AttemptKind::Original,
            BUDGET,
            requirements,
        )
    };
    // A passing test with no failure first and no tool execution shows no repair.
    let mut recorder = start(TaskRequirements::BENCH_03);
    recorder.file_changed();
    recorder.test_run(true);
    assert_eq!(
        recorder.finish().outcome(),
        &TaskOutcome::Incomplete {
            missing: vec![
                TaskStep::ToolExecution,
                TaskStep::ParallelCalls,
                TaskStep::FailingTest
            ]
        }
    );
    // A failing test, then a pass without any change in between, is not a repair.
    let mut recorder = start(TaskRequirements::BENCH_03);
    recorder.tools_executed(&parallel_turn());
    recorder.file_changed();
    recorder.test_run(false);
    recorder.test_run(true);
    assert_eq!(
        recorder.finish().outcome(),
        &TaskOutcome::Incomplete {
            missing: vec![TaskStep::Repair]
        }
    );
    // The scripted task wants three calls in one turn; two do not count.
    let mut recorder = start(TaskRequirements {
        min_parallel_calls: 3,
    });
    recorder.tools_executed(&parallel_turn());
    recorder.test_run(false);
    recorder.file_changed();
    recorder.test_run(true);
    let record = recorder.finish();
    assert_eq!(
        record.outcome(),
        &TaskOutcome::Incomplete {
            missing: vec![TaskStep::ParallelCalls]
        }
    );
    assert_eq!(
        record.outcome().failure_kind(),
        Some(FailureKind::InvalidResult)
    );
}

#[test]
fn an_agent_task_over_budget_fails() {
    let clock = ManualClock::default();
    let start = || {
        AgentTaskRecorder::start(
            &clock,
            label("task"),
            op("op-3"),
            AttemptKind::Original,
            BUDGET,
            TaskRequirements::BENCH_03,
        )
    };
    let complete = |recorder: &mut AgentTaskRecorder<&ManualClock>| {
        recorder.tools_executed(&parallel_turn());
        recorder.file_changed();
        recorder.test_run(false);
        recorder.file_changed();
        recorder.test_run(true);
    };
    let mut recorder = start();
    complete(&mut recorder);
    clock.advance(Duration::from_secs(601));
    let record = recorder.finish();
    assert_eq!(
        record.outcome(),
        &TaskOutcome::OverBudget {
            limit: BudgetLimit::ElapsedSeconds
        }
    );
    assert_eq!(
        record.outcome().failure_kind(),
        Some(FailureKind::DeadlineFailure)
    );
    let mut recorder = start();
    complete(&mut recorder);
    for _ in 0..9 {
        recorder.turn();
    }
    assert_eq!(
        recorder.finish().outcome(),
        &TaskOutcome::OverBudget {
            limit: BudgetLimit::Turns
        }
    );
    let mut recorder = start();
    for _ in 0..6 {
        complete(&mut recorder);
    }
    assert_eq!(
        recorder.finish().outcome(),
        &TaskOutcome::OverBudget {
            limit: BudgetLimit::ToolCalls
        }
    );
    // Exactly at the budget is within it.
    let mut recorder = start();
    complete(&mut recorder);
    clock.advance(Duration::from_secs(600));
    assert_eq!(recorder.finish().outcome(), &TaskOutcome::Succeeded);
    let record = start().abort(label("harness-stopped"));
    assert_eq!(
        record.outcome().failure_kind(),
        Some(FailureKind::EarlyTermination)
    );
}

#[test]
fn task_success_counts_original_attempts_only() {
    let clock = ManualClock::default();
    let succeeded = scripted_attempt(&clock, "op-a", AttemptKind::Original);
    let failed = AgentTaskRecorder::start(
        &clock,
        label("task"),
        op("op-b"),
        AttemptKind::Original,
        BUDGET,
        TaskRequirements::BENCH_03,
    )
    .finish();
    let aborted = AgentTaskRecorder::start(
        &clock,
        label("task"),
        op("op-c"),
        AttemptKind::Original,
        BUDGET,
        TaskRequirements::BENCH_03,
    )
    .abort(label("provider-lost"));
    let retry = scripted_attempt(
        &clock,
        "op-d",
        AttemptKind::Retry {
            first_attempt: op("op-b"),
        },
    );
    let records = vec![succeeded.clone(), failed.clone(), aborted, retry.clone()];
    let success = task_success(&records).unwrap();
    // 1 of 3 original attempts; the successful retry is reported apart and changes
    // neither number.
    assert_eq!(success.original_attempts, SuccessRate::new(1, 3).unwrap());
    assert_eq!(
        (
            success.retries.retries,
            success.retries.successful_retries,
            success.retries.recovered_first_attempts
        ),
        (1, 1, 1)
    );

    let orphan = scripted_attempt(
        &clock,
        "op-e",
        AttemptKind::Retry {
            first_attempt: op("op-x"),
        },
    );
    assert!(matches!(
        task_success(&[succeeded.clone(), orphan]),
        Err(TaskSuccessError::UnknownFirstAttempt { .. })
    ));
    let late = scripted_attempt(
        &clock,
        "op-f",
        AttemptKind::Retry {
            first_attempt: op("op-a"),
        },
    );
    assert!(matches!(
        task_success(&[succeeded.clone(), late]),
        Err(TaskSuccessError::RetryAfterSuccess { .. })
    ));
    assert!(matches!(
        task_success(&[succeeded.clone(), succeeded]),
        Err(TaskSuccessError::DuplicateAttempt { .. })
    ));
    assert_eq!(
        task_success(&[retry]),
        Err(TaskSuccessError::UnknownFirstAttempt {
            attempt: op("op-d")
        })
    );
    assert_eq!(
        task_success(&[]),
        Err(TaskSuccessError::Report(ReportError::NoAttempts))
    );
}
