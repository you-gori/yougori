use super::*;
use serde_json::json;

fn raw(kind: &str, outcome: &str) -> Value {
    json!({"id":1,"completionSequence":1,"kind":kind,"outcome":outcome,
           "elapsedMs":125.000001,"firstOutputMs":null,"stages":{}})
}

fn context(kind: AttemptKind) -> ReportContext {
    let source = core::RunRecord::from_json(core::RUN_RECORD_SAMPLE_JSON).unwrap();
    ReportContext {
        identity: ObservationIdentity::new(&"a".repeat(32), &"b".repeat(32), 1).unwrap(),
        expected_kind: kind,
        metadata: RunMetadata {
            attempt: source.attempt,
            substrate: source.substrate,
            build: source.build,
            execution_category: source.execution_category,
            model: source.model,
            precision: source.precision,
            engine: source.engine,
            host: source.host,
            workload: source.workload,
            client: source.client,
            load: source.load,
            state: source.state,
            launch: source.launch,
            price: source.price,
        },
    }
}

#[test]
fn decimal_milliseconds_convert_exactly_without_float_saturation() {
    for (input, expected) in [
        ("0", 0),
        ("0.0", 0),
        ("0.000001", 1),
        ("1e-6", 1),
        ("125.000001", 125_000_001),
        ("1.25e3", 1_250_000_000),
        ("1000000000000", 1_000_000_000_000_000_000),
    ] {
        assert_eq!(
            nanos(&serde_json::from_str(input).unwrap()),
            Ok(expected),
            "{input}"
        );
    }
    for input in [
        "-0.0",
        "-1",
        "0.0000001",
        "1e30",
        "18446744073709551615",
        "null",
        "true",
        "\"NaN\"",
        "[]",
        "{}",
    ] {
        assert_eq!(
            nanos(&serde_json::from_str(input).unwrap()),
            Err(AdapterError::InvalidDuration),
            "{input}"
        );
    }
    assert_eq!(parse_completed_bytes(b"NaN"), Err(AdapterError::Malformed));
    assert_eq!(
        parse_completed_bytes(b"Infinity"),
        Err(AdapterError::Malformed)
    );
}

#[test]
fn bounded_bytes_closed_fields_and_errors_retain_no_payload() {
    assert_eq!(
        parse_completed_bytes(&vec![b' '; MAX_COMPLETED_BYTES + 1]),
        Err(AdapterError::Oversized)
    );
    let value = raw("request", "ok");
    assert_eq!(
        parse_completed_bytes(&serde_json::to_vec(&value).unwrap()).unwrap(),
        parse_completed(&value).unwrap()
    );
    let mut malicious = value.clone();
    malicious["prompt"] = json!("secret-prompt-should-never-be-retained");
    let error = parse_completed(&malicious).unwrap_err();
    assert_eq!(error, AdapterError::UnexpectedFields);
    assert!(!format!("{error:?} {error}").contains("secret"));
    malicious = value.clone();
    malicious["outcome"] = json!("secret-credential-in-unknown-outcome");
    assert_eq!(
        parse_completed(&malicious),
        Err(AdapterError::UnknownOutcome)
    );
    malicious = value.clone();
    malicious["kind"] = json!("benchmark-v2");
    assert_eq!(parse_completed(&malicious), Err(AdapterError::UnknownKind));
    malicious = value.clone();
    malicious["stages"] = json!({"unknown-secret-stage":{"calls":1,"failedCalls":0,"elapsedMs":1}});
    assert_eq!(parse_completed(&malicious), Err(AdapterError::UnknownStage));
    malicious = value;
    malicious["stages"] =
        json!({"generation":{"calls":1,"failedCalls":0,"elapsedMs":1,"error":"secret"}});
    assert_eq!(
        parse_completed(&malicious),
        Err(AdapterError::UnexpectedFields)
    );
}

#[test]
fn exact_positive_safe_integer_counters_are_required() {
    for field in ["id", "completionSequence"] {
        for invalid in [
            json!(0),
            json!(-1),
            json!(true),
            json!(1.0),
            json!("1"),
            json!(MAX_COUNTER + 1),
        ] {
            let mut value = raw("load", "ok");
            value[field] = invalid;
            assert_eq!(parse_completed(&value), Err(AdapterError::InvalidCounter));
        }
    }
    let mut value = raw("load", "ok");
    value["id"] = json!(MAX_COUNTER);
    value["completionSequence"] = json!(MAX_COUNTER);
    assert!(parse_completed(&value).is_ok());
}

#[test]
fn completed_order_is_independent_of_start_order() {
    let mut later_start = raw("request", "ok");
    later_start["id"] = json!(2);
    let mut earlier_start = raw("request", "cancelled");
    earlier_start["completionSequence"] = json!(2);
    let first = parse_completed(&later_start).unwrap();
    let second = parse_completed(&earlier_start).unwrap();
    assert_eq!((first.id, first.completion_sequence), (2, 1));
    assert_eq!((second.id, second.completion_sequence), (1, 2));
    // Journal collector validates cross-record sequence continuity; this parser
    // must never sort by attempt ID or mistake completion order for start order.
}

#[test]
fn inclusive_stages_are_not_summed_or_promoted_to_disjoint_costs() {
    let mut value = raw("load", "ok");
    value["elapsedMs"] = json!(100);
    value["stages"] = json!({
        "checkpoint":{"calls":1,"failedCalls":0,"elapsedMs":90},
        "snapshot":{"calls":1,"failedCalls":0,"elapsedMs":80},
        "weight_hash":{"calls":2,"failedCalls":1,"elapsedMs":150}});
    let parsed = parse_completed(&value).unwrap();
    assert_eq!(parsed.stages[&Stage::WeightHash].elapsed_nanos, 150_000_000);
    let ctx = context(AttemptKind::Load);
    assert!(adapt(&parsed, &ctx.identity, &ctx)
        .unwrap()
        .gaps
        .contains(&ConversionGap::InclusiveStagesNotAdditive));
    value["stages"]["snapshot"]["failedCalls"] = json!(2);
    assert_eq!(
        parse_completed(&value),
        Err(AdapterError::InconsistentRecord)
    );
    value["stages"]["snapshot"]["failedCalls"] = json!(0);
    value["stages"]["snapshot"]["elapsedMs"] = json!(101);
    assert_eq!(
        parse_completed(&value),
        Err(AdapterError::InconsistentRecord)
    );
    value["stages"]["snapshot"]["calls"] = json!(0);
    assert_eq!(parse_completed(&value), Err(AdapterError::InvalidCounter));
}

#[test]
fn a_load_that_imports_its_model_files_keeps_the_import_stage() {
    // G04: a runner copies a folder or registry version into its own volume inside `import`.
    let mut value = raw("load", "ok");
    value["stages"] = json!({
        "checkpoint":{"calls":1,"failedCalls":0,"elapsedMs":120},
        "import":{"calls":1,"failedCalls":0,"elapsedMs":100.5},
        "weight_verification":{"calls":3,"failedCalls":0,"elapsedMs":12}});
    let parsed = parse_completed(&value).unwrap();
    assert_eq!(parsed.stages[&Stage::Import].elapsed_nanos, 100_500_000);
    assert_eq!(parsed.stages[&Stage::Import].calls, 1);
}

#[test]
fn first_output_and_load_outcomes_obey_actual_producer_contract() {
    let mut value = raw("request", "ok");
    value["firstOutputMs"] = json!(126);
    assert_eq!(
        parse_completed(&value),
        Err(AdapterError::InconsistentRecord)
    );
    value["firstOutputMs"] = json!(125.000001);
    assert!(parse_completed(&value).is_ok());
    value["kind"] = json!("load");
    assert_eq!(
        parse_completed(&value),
        Err(AdapterError::InconsistentRecord)
    );
    value["firstOutputMs"] = Value::Null;
    for outcome in ["cancelled", "busy", "invalid"] {
        value["outcome"] = json!(outcome);
        assert_eq!(
            parse_completed(&value),
            Err(AdapterError::InconsistentRecord)
        );
    }
}

#[test]
fn successful_load_produces_existing_ready_latency_with_unknown_resources() {
    let parsed = parse_completed(&raw("load", "ok")).unwrap();
    let ctx = context(AttemptKind::Load);
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    let report = result.record.unwrap();
    report.validate().unwrap();
    assert_eq!(
        report
            .interval(core::IntervalKind::ReadyLatency)
            .unwrap()
            .elapsed_nanos(),
        125_000_001
    );
    assert_eq!(report.attempt, ctx.metadata.attempt);
    assert_eq!(report.build, ctx.metadata.build);
    assert_eq!(report.execution_category, ctx.metadata.execution_category);
    assert_eq!(report.state, ctx.metadata.state);
    assert_eq!(report.substrate, core::RunSubstrate::FakeTimeControlled);
    assert!(!report.measurements.peak_gpu_memory_bytes.is_measured());
    assert!(!report.measurements.output_tokens.is_measured());
    assert!(!report.measurements.energy_joules.is_measured());
    assert!(report
        .interval(core::IntervalKind::TimeToFirstToken)
        .is_err());
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(&ctx.identity.instance_id));
    assert!(!serialized.contains(&ctx.identity.session_id));
    assert_eq!(core::RunRecord::from_json(&serialized).unwrap(), report);
    assert!(result
        .gaps
        .contains(&ConversionGap::DenominatorRequiresSealedJournal));
}

#[test]
fn buffered_first_output_does_not_fabricate_successful_serving_record() {
    let mut value = raw("request", "ok");
    value["firstOutputMs"] = json!(42);
    let parsed = parse_completed(&value).unwrap();
    let ctx = context(AttemptKind::Request);
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    assert!(!result
        .gaps
        .contains(&ConversionGap::DemandWorkBoundaryUnavailable));
    assert!(result.record.is_none());
    assert_eq!(result.observation.outcome, RunnerOutcome::Ok);
    assert_eq!(result.observation.first_output_nanos, Some(42_000_000));
    assert!(result
        .gaps
        .contains(&ConversionGap::ExactTokenTimingUnavailable));
    assert!(result
        .gaps
        .contains(&ConversionGap::QueueBoundaryUnavailable));
    assert!(result
        .gaps
        .contains(&ConversionGap::RequestCompletionBoundaryUnavailable));
}

#[test]
fn failed_load_never_claims_engine_ready() {
    let parsed = parse_completed(&raw("load", "error")).unwrap();
    let ctx = context(AttemptKind::Load);
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    let report = result.record.unwrap();
    report.validate().unwrap();
    assert_eq!(report.events.len(), 1);
    assert!(report.interval(core::IntervalKind::ReadyLatency).is_err());
    assert!(matches!(
        report.outcome,
        core::Outcome::Failed {
            failure: core::FailureKind::CommandFailure,
            ..
        }
    ));
}

#[test]
fn request_failures_preserve_outcome_without_invented_boundaries() {
    for (outcome, expected) in [
        ("cancelled", core::FailureKind::EarlyTermination),
        ("busy", core::FailureKind::Rejected),
        ("invalid", core::FailureKind::Rejected),
        ("error", core::FailureKind::CommandFailure),
    ] {
        let parsed = parse_completed(&raw("request", outcome)).unwrap();
        let ctx = context(AttemptKind::Request);
        let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
        let report = result.record.unwrap();
        report.validate().unwrap();
        assert!(report.events.is_empty());
        assert!(matches!(report.outcome,core::Outcome::Failed{failure,..} if failure == expected));
        assert_eq!(result.observation, parsed);
    }
}

#[test]
fn absent_cache_state_is_a_gap_never_inferred_from_a_timing() {
    let parsed = parse_completed(&raw("request", "error")).unwrap();
    let mut ctx = context(AttemptKind::Request);
    ctx.metadata.state = core::Measured::not_measured(core::NotMeasuredReason::NotRecorded);
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    assert!(result.record.is_none());
    assert!(result
        .gaps
        .contains(&ConversionGap::ServingStartStateUnavailable));
    assert_eq!(result.observation, parsed);
}

#[test]
fn run_context_cannot_cross_sessions_instances_attempts_or_kinds() {
    let parsed = parse_completed(&raw("load", "ok")).unwrap();
    let ctx = context(AttemptKind::Load);
    for changed in [
        ObservationIdentity::new(&"c".repeat(32), &ctx.identity.instance_id, 1).unwrap(),
        ObservationIdentity::new(&ctx.identity.session_id, &"d".repeat(32), 1).unwrap(),
        ObservationIdentity::new(&ctx.identity.session_id, &ctx.identity.instance_id, 2).unwrap(),
    ] {
        assert!(matches!(
            adapt(&parsed, &changed, &ctx),
            Err(AdapterError::ContextMismatch)
        ));
    }
    let mut wrong_kind = ctx.clone();
    wrong_kind.expected_kind = AttemptKind::Request;
    assert!(matches!(
        adapt(&parsed, &ctx.identity, &wrong_kind),
        Err(AdapterError::ContextMismatch)
    ));
    for invalid in [
        "",
        "AABBCCDDEEFF00112233445566778899",
        "credential-not-an-instance",
    ] {
        assert_eq!(
            ObservationIdentity::new(invalid, &ctx.identity.instance_id, 1),
            Err(AdapterError::InvalidIdentity)
        );
    }
    let mut malformed = ctx.identity.clone();
    malformed.attempt_id = 0;
    assert!(matches!(
        adapt(&parsed, &malformed, &ctx),
        Err(AdapterError::InvalidIdentity)
    ));
}

#[test]
fn invalid_report_metadata_is_rejected_not_silently_rewritten() {
    let parsed = parse_completed(&raw("load", "ok")).unwrap();
    let mut ctx = context(AttemptKind::Load);
    ctx.metadata.attempt.deadline_nanos = core::Measured::measured(1);
    assert!(matches!(
        adapt(&parsed, &ctx.identity, &ctx),
        Err(AdapterError::InvalidReportContext)
    ));
    // The raw observation remains available to the collector; failed conversion
    // must not rewrite a runner success into a model failure or lose its attempt.
    assert_eq!(parsed.outcome, RunnerOutcome::Ok);
}

#[test]
fn versioned_boundaries_preserve_success_without_inventing_tokens() {
    let mut value = raw("request", "ok");
    value["boundaries"] = json!({"version":1,"acceptedMs":2,"admittedMs":5,"completedMs":90});
    let parsed = parse_completed(&value).unwrap();
    let b = parsed.boundaries.as_ref().unwrap();
    assert_eq!(b.completed_nanos.unwrap() - b.accepted_nanos, 88_000_000);
    let ctx = context(AttemptKind::Request);
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    assert!(result.record.is_none());
    assert!(result
        .gaps
        .contains(&ConversionGap::ExactTokenTimingUnavailable));
    assert!(!result
        .gaps
        .contains(&ConversionGap::QueueBoundaryUnavailable));
    assert!(!result
        .gaps
        .contains(&ConversionGap::RequestCompletionBoundaryUnavailable));
    assert_eq!(result.observation, parsed);
}

#[test]
fn failure_reports_include_only_observed_wrapper_events() {
    let ctx = context(AttemptKind::Request);
    for (outcome, admitted) in [("busy", None), ("error", Some(5))] {
        let mut value = raw("request", outcome);
        value["boundaries"] =
            json!({"version":1,"acceptedMs":2,"admittedMs":admitted,"completedMs":null});
        let parsed = parse_completed(&value).unwrap();
        let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
        let report = result.record.unwrap();
        report.validate().unwrap();
        assert_eq!(report.events.len(), if admitted.is_some() { 2 } else { 1 });
        assert_eq!(report.events[0].event, core::EventKind::RequestAccepted);
        if admitted.is_some() {
            assert_eq!(
                report
                    .interval(core::IntervalKind::QueueWait)
                    .unwrap()
                    .elapsed_nanos(),
                3_000_000
            );
        }
        assert!(report.interval(core::IntervalKind::RequestLatency).is_err());
    }
}

#[test]
fn malformed_boundaries_are_rejected_not_downgraded_to_legacy() {
    let mut value = raw("request", "ok");
    let good = json!({"version":1,"acceptedMs":2,"admittedMs":5,"completedMs":90});
    for bad in [
        Value::Null,
        json!({}),
        json!({"version":1,"private":"secret"}),
    ] {
        value["boundaries"] = bad;
        assert!(parse_completed(&value).is_err());
    }
    for (field, invalid) in [
        ("version", json!(2)),
        ("version", json!(1.0)),
        ("version", json!(true)),
        ("acceptedMs", Value::Null),
        ("acceptedMs", json!(-1)),
        ("admittedMs", json!(1)),
        ("admittedMs", Value::Null),
        ("completedMs", json!(4)),
        ("completedMs", json!(126)),
    ] {
        value["boundaries"] = good.clone();
        value["boundaries"][field] = invalid;
        assert!(parse_completed(&value).is_err(), "{field}: {value}");
    }
    value["boundaries"] = good;
    value["kind"] = json!("load");
    assert!(parse_completed(&value).is_err());
    value["kind"] = json!("request");
    value["outcome"] = json!("cancelled");
    assert!(parse_completed(&value).is_err());
    value["outcome"] = json!("ok");
    for first in [1, 4, 91] {
        value["firstOutputMs"] = json!(first);
        assert!(parse_completed(&value).is_err());
    }
    value["firstOutputMs"] = json!(5);
    assert!(parse_completed(&value).is_ok());
    value.as_object_mut().unwrap().remove("boundaries");
    assert!(parse_completed(&value).unwrap().boundaries.is_none());
}

fn token_request() -> Value {
    let mut v = raw("request", "ok");
    v["boundaries"] = json!({"version":1,"acceptedMs":2,"admittedMs":5,"completedMs":90});
    v["tokens"] = json!({"version":1,"source":"openai-logprobs-flush","complete":true,
        "emittedMs":[10,10,30],"outputTokens":3});
    v
}

#[test]
fn exact_flushed_tokens_produce_successful_serving_report_and_round_trip() {
    let parsed = parse_completed(&token_request()).unwrap();
    let mut ctx = context(AttemptKind::Request);
    if let core::Measured::Measured { value } = &mut ctx.metadata.state {
        value.model_at_arrival = core::ModelAtArrival::ReadyToServe;
        value.temperature = core::StartTemperature::Hot;
    }
    let adapted = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    assert!(!adapted
        .gaps
        .contains(&ConversionGap::ExactTokenTimingUnavailable));
    let report = adapted.record.unwrap();
    report.validate().unwrap();
    assert_eq!(
        report.measurements.output_tokens,
        core::Measured::measured(3)
    );
    assert_eq!(report.events.len(), 6);
    assert_eq!(report.events[2].event, core::EventKind::TokenEmitted);
    assert_eq!(report.events[2].at_nanos, report.events[3].at_nanos);
    assert_eq!(
        report
            .interval(core::IntervalKind::TimeToFirstToken)
            .unwrap()
            .elapsed_nanos(),
        8_000_000
    );
    assert_eq!(
        core::RunRecord::from_json(&serde_json::to_string(&report).unwrap()).unwrap(),
        report
    );
}

#[test]
fn bounded_token_schema_refuses_bad_versions_times_counts_and_payloads() {
    for (field, value) in [
        ("version", json!(2)),
        ("source", json!("device-clock")),
        ("complete", json!(1)),
        ("emittedMs", json!([10, 9])),
        ("emittedMs", json!([4])),
        ("emittedMs", json!([91])),
        ("emittedMs", json!([])),
        ("emittedMs", json!(vec![10; 257])),
        ("outputTokens", json!(true)),
        ("outputTokens", json!(2)),
        ("private", json!("secret")),
    ] {
        let mut v = token_request();
        v["tokens"][field] = value;
        assert!(parse_completed(&v).is_err(), "{field}");
    }
    for field in ["acceptedMs", "admittedMs", "completedMs"] {
        let mut v = token_request();
        v["boundaries"][field] = Value::Null;
        assert!(parse_completed(&v).is_err());
    }
    let mut v = token_request();
    v["kind"] = json!("load");
    assert!(parse_completed(&v).is_err());
    v["kind"] = json!("request");
    v["outcome"] = json!("cancelled");
    assert!(parse_completed(&v).is_err());
}

#[test]
fn incomplete_traces_preserve_success_and_unknowns_without_conversion() {
    let mut v = token_request();
    v["tokens"]["complete"] = json!(false);
    let parsed = parse_completed(&v).unwrap();
    let ctx = context(AttemptKind::Request);
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    assert!(result.record.is_none());
    assert!(result
        .gaps
        .contains(&ConversionGap::ExactTokenTimingUnavailable));
    assert_eq!(result.observation, parsed);
}

#[test]
fn demand_and_missing_start_state_do_not_invent_backend_wake_clocks() {
    let parsed = parse_completed(&token_request()).unwrap();
    let mut ctx = context(AttemptKind::Request);
    if let core::Measured::Measured { value } = &mut ctx.metadata.state {
        value.model_at_arrival = core::ModelAtArrival::Asleep;
        value.temperature = core::StartTemperature::Warm;
    }
    let result = adapt(&parsed, &ctx.identity, &ctx).unwrap();
    assert!(result.record.is_none());
    assert!(result
        .gaps
        .contains(&ConversionGap::DemandWorkBoundaryUnavailable));
    ctx.metadata.state = core::Measured::not_measured(core::NotMeasuredReason::NotRecorded);
    assert!(adapt(&parsed, &ctx.identity, &ctx)
        .unwrap()
        .record
        .is_none());
}

fn demand_request() -> Value {
    let mut value = token_request();
    value["demandLoad"] = json!({"version":1,"source":"runner-load-call",
        "loadAttemptId":2,"startedMs":3,"readyMs":4});
    value
}

fn demand_context() -> ReportContext {
    let mut ctx = context(AttemptKind::Request);
    if let core::Measured::Measured { value } = &mut ctx.metadata.state {
        value.model_at_arrival = core::ModelAtArrival::NotLoaded;
        value.temperature = core::StartTemperature::Warm;
        value.cold_provenance = core::ColdProvenance::NotCold;
    }
    ctx
}

#[test]
fn correlated_load_produces_measured_demand_serving_report() {
    let observation = parse_completed(&demand_request()).unwrap();
    let ctx = demand_context();
    let adapted = adapt(&observation, &ctx.identity, &ctx).unwrap();
    assert!(!adapted
        .gaps
        .contains(&ConversionGap::DemandWorkBoundaryUnavailable));
    let report = adapted.record.unwrap();
    report.validate().unwrap();
    assert_eq!(report.events.len(), 8);
    assert_eq!(report.events[1].event, core::EventKind::LoadStarted);
    assert_eq!(report.events[2].event, core::EventKind::LoadCompleted);
    assert_eq!(
        report
            .interval(core::IntervalKind::TimeToFirstToken)
            .unwrap()
            .elapsed_nanos(),
        8_000_000
    );
    assert_eq!(
        core::RunRecord::from_json(&serde_json::to_string(&report).unwrap()).unwrap(),
        report
    );
}

#[test]
fn demand_load_schema_rejects_bad_identity_order_and_payload() {
    for (field, invalid) in [
        ("version", json!(true)),
        ("version", json!(2)),
        ("source", json!("device")),
        ("loadAttemptId", json!(true)),
        ("loadAttemptId", json!(0)),
        ("loadAttemptId", json!(1)),
        ("loadAttemptId", json!(9007199254740992u64)),
        ("startedMs", json!(1)),
        ("startedMs", json!(5)),
        ("readyMs", json!(6)),
        ("readyMs", json!(-1)),
        ("private", json!("secret")),
    ] {
        let mut value = demand_request();
        value["demandLoad"][field] = invalid;
        assert!(parse_completed(&value).is_err(), "{field}");
    }
    let mut value = demand_request();
    value.as_object_mut().unwrap().remove("boundaries");
    assert!(parse_completed(&value).is_err());
    value = demand_request();
    value["kind"] = json!("load");
    assert!(parse_completed(&value).is_err());
}

#[test]
fn demand_load_never_overrides_unknown_or_conflicting_start_state() {
    let observation = parse_completed(&demand_request()).unwrap();
    for state in [
        core::ModelAtArrival::ReadyToServe,
        core::ModelAtArrival::Asleep,
    ] {
        let mut ctx = demand_context();
        if let core::Measured::Measured { value } = &mut ctx.metadata.state {
            value.model_at_arrival = state;
        }
        let adapted = adapt(&observation, &ctx.identity, &ctx).unwrap();
        assert!(adapted.record.is_none());
        assert!(adapted
            .gaps
            .contains(&ConversionGap::ServingStartStateMismatch));
        assert_eq!(adapted.observation, observation);
    }
    let mut ctx = demand_context();
    ctx.metadata.state = core::Measured::not_measured(core::NotMeasuredReason::NotRecorded);
    let adapted = adapt(&observation, &ctx.identity, &ctx).unwrap();
    assert!(adapted.record.is_none());
    assert!(adapted
        .gaps
        .contains(&ConversionGap::ServingStartStateUnavailable));
}

#[test]
fn demand_load_does_not_invent_tokens_or_turn_failure_into_success() {
    let ctx = demand_context();
    let mut value = demand_request();
    value["tokens"]["complete"] = json!(false);
    let observation = parse_completed(&value).unwrap();
    let adapted = adapt(&observation, &ctx.identity, &ctx).unwrap();
    assert!(adapted.record.is_none());
    assert!(adapted
        .gaps
        .contains(&ConversionGap::ExactTokenTimingUnavailable));
    value["outcome"] = json!("error");
    value["boundaries"]["completedMs"] = Value::Null;
    let observation = parse_completed(&value).unwrap();
    let adapted = adapt(&observation, &ctx.identity, &ctx).unwrap();
    let report = adapted.record.unwrap();
    assert!(matches!(report.outcome, core::Outcome::Failed { .. }));
    report.validate().unwrap();
    assert_eq!(report.events[1].event, core::EventKind::LoadStarted);
    assert_eq!(report.events[2].event, core::EventKind::LoadCompleted);
}

fn backend_request(source: &str) -> Value {
    let mut value = token_request();
    value["backend"] = json!({"version":1,"source":source,"promptTokens":120,"cachedTokens":20,
        "queueMs":0.25,"prefillMs":50,"decodeMs":40,"outputTokens":3});
    value
}

fn ready_context() -> ReportContext {
    let mut ctx = context(AttemptKind::Request);
    if let core::Measured::Measured { value } = &mut ctx.metadata.state {
        value.model_at_arrival = core::ModelAtArrival::ReadyToServe;
        value.temperature = core::StartTemperature::Hot;
    }
    ctx
}

#[test]
fn backend_clocks_give_prefill_and_decode_rates_only_where_the_backend_bounds_them() {
    let rate = |measured: &core::Measured<core::NonNegative>| match measured {
        core::Measured::Measured { value } => Some(value.get()),
        _ => None,
    };
    let ctx = ready_context();
    // vLLM: 100 computed prompt tokens (20 were a prefix-cache hit) in 50 ms; 2 tokens after
    // the first in 40 ms.
    let report = adapt(
        &parse_completed(&backend_request("vllm-metrics-delta")).unwrap(),
        &ctx.identity,
        &ctx,
    )
    .unwrap()
    .record
    .unwrap();
    report.validate().unwrap();
    assert_eq!(
        rate(&report.measurements.prefill_tokens_per_second),
        Some(2000.0)
    );
    assert_eq!(
        rate(&report.measurements.aggregate_decode_tokens_per_second),
        Some(50.0)
    );
    // llama.cpp times every generated token in its generation span.
    let report = adapt(
        &parse_completed(&backend_request("llama-cpp-timings")).unwrap(),
        &ctx.identity,
        &ctx,
    )
    .unwrap()
    .record
    .unwrap();
    assert_eq!(
        rate(&report.measurements.prefill_tokens_per_second),
        Some(2000.0)
    );
    assert_eq!(
        rate(&report.measurements.aggregate_decode_tokens_per_second),
        Some(75.0)
    );
    // The Transformers first-token span includes a sampling step: no rate from it.
    let observation = parse_completed(&backend_request("transformers-first-token")).unwrap();
    assert_eq!(
        observation.backend.as_ref().unwrap().source,
        BackendSource::TransformersFirstToken
    );
    let report = adapt(&observation, &ctx.identity, &ctx)
        .unwrap()
        .record
        .unwrap();
    assert_eq!(rate(&report.measurements.prefill_tokens_per_second), None);
    assert_eq!(
        rate(&report.measurements.aggregate_decode_tokens_per_second),
        None
    );
}

#[test]
fn backend_observation_schema_refuses_unknown_sources_impossible_counts_and_other_records() {
    for (field, value) in [
        ("version", json!(2)),
        ("source", json!("device-clock")),
        ("promptTokens", json!(null)),
        ("prefillMs", json!(null)),
        ("cachedTokens", json!(121)),
        ("queueMs", json!(-1)),
        ("outputTokens", json!(1.5)),
        ("extra", json!(1)),
    ] {
        let mut changed = backend_request("vllm-metrics-delta");
        changed["backend"][field] = value;
        assert!(parse_completed(&changed).is_err(), "{field}");
    }
    // Only a successful request carries the backend's clocks.
    let clocks = backend_request("llama-cpp-timings")["backend"].clone();
    let mut failed = raw("request", "error");
    failed["backend"] = clocks.clone();
    assert!(parse_completed(&failed).is_err());
    let mut load = raw("load", "ok");
    load["backend"] = clocks;
    assert!(parse_completed(&load).is_err());
}

#[test]
fn a_demand_wake_is_reported_as_one_under_an_asleep_start_state_and_a_gap_otherwise() {
    let mut value = demand_request();
    value["demandLoad"]["source"] = json!("runner-wake-call");
    let observation = parse_completed(&value).unwrap();
    assert!(observation.demand_load.as_ref().unwrap().wake);
    let mut ctx = demand_context();
    if let core::Measured::Measured { value } = &mut ctx.metadata.state {
        value.model_at_arrival = core::ModelAtArrival::Asleep;
    }
    let report = adapt(&observation, &ctx.identity, &ctx)
        .unwrap()
        .record
        .unwrap();
    report.validate().unwrap();
    assert_eq!(report.events[1].event, core::EventKind::WakeStarted);
    assert_eq!(report.events[2].event, core::EventKind::WakeCompleted);
    // A wake declared as a load from scratch is a mismatch, kept raw.
    let declared = demand_context();
    let adapted = adapt(&observation, &declared.identity, &declared).unwrap();
    assert!(adapted.record.is_none());
    assert!(adapted
        .gaps
        .contains(&ConversionGap::ServingStartStateMismatch));
    let mut unknown = demand_request();
    unknown["demandLoad"]["source"] = json!("runner-sleep-call");
    assert!(parse_completed(&unknown).is_err());
}
