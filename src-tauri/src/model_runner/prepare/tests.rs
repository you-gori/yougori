use super::*;
use crate::foundation::evidence::Backend;
use crate::foundation::ids::ManualClock;

fn facts() -> Facts {
    let file = |path: &str, size: u64| (path.to_owned(), size, ContentKey::of(path.as_bytes()));
    Facts {
        model: "Qwen/Qwen2.5-0.5B-Instruct".into(),
        revision: Some("047ce6e2805bc97c9227b976b2664b1e141cde87f2387f03219cebfdf452bc10".into()),
        precision: "original".into(),
        files: vec![
            file("config.json", 659),
            file("generation_config.json", 242),
            file("model.safetensors", 988_097_824),
            file("tokenizer.json", 7_031_645),
            file("tokenizer_config.json", 7_305),
        ],
        config: br#"{"architectures":["Qwen2ForCausalLM"],"torch_dtype":"bfloat16"}"#.to_vec(),
        local_code: false,
        runner: BackendRelease::new(Backend::Transformers, "5.18.0").unwrap(),
        gpu_architecture: "sm_120".into(),
    }
}

#[test]
fn a_models_execution_identity_follows_every_fact_it_is_made_of_and_refuses_what_it_cannot_know() {
    let base = execution_identity(&facts()).unwrap();
    assert_eq!(base, execution_identity(&facts()).unwrap(), "stable");
    // Every input changes it: a file's content, the GPU, the runner, the dtype, local code.
    let mut changed = facts();
    changed.files[2].2 = ContentKey::of(b"other weights");
    assert_ne!(execution_identity(&changed).unwrap(), base);
    let mut changed = facts();
    changed.gpu_architecture = "sm_90".into();
    assert_ne!(execution_identity(&changed).unwrap(), base);
    let mut changed = facts();
    changed.runner = BackendRelease::new(Backend::Transformers, "5.19.0").unwrap();
    assert_ne!(execution_identity(&changed).unwrap(), base);
    let mut changed = facts();
    changed.config = br#"{"torch_dtype":"float16"}"#.to_vec();
    assert_ne!(execution_identity(&changed).unwrap(), base);
    let mut changed = facts();
    changed.local_code = true;
    assert_ne!(execution_identity(&changed).unwrap(), base);
    // What it cannot know is refused, never guessed.
    let mut unknown = facts();
    unknown.config = br#"{"architectures":["Qwen2ForCausalLM"]}"#.to_vec();
    assert!(execution_identity(&unknown)
        .unwrap_err()
        .contains("no dtype"));
    let mut quantized = facts();
    quantized.precision = "4bit".into();
    assert!(execution_identity(&quantized)
        .unwrap_err()
        .contains("precision"));
    let mut without_config = facts();
    without_config.files.remove(0);
    assert!(execution_identity(&without_config)
        .unwrap_err()
        .contains("config.json"));
}

fn entry(clock: &ManualClock, ready_within: Duration, keep: Duration) -> Entry {
    let target = PrepareTarget {
        model: execution_identity(&facts()).unwrap(),
        adapter: None,
    };
    let request = PrepareRequest {
        operation: OperationId::generate(),
        execution: ExecutionId::generate(),
        tenant: TenantId::new("owner").unwrap(),
        target,
        origin: CandidateOrigin::ExplicitUserIntent,
        deadline: clock.now().checked_add(ready_within).unwrap(),
        retention_ttl: keep,
        cancellation: CancellationToken::new(),
        work: vec![PrepareWork::Step {
            step: PreparationStep::Activate,
        }],
        assigned_request: None,
    };
    Entry {
        operation: PrepareOperation::admit(request, Duration::from_secs(30), &BOUNDS, clock)
            .unwrap(),
        target,
        estimate: Duration::from_secs(30),
        estimate_basis: "declared",
        started_at: None,
        started_model: false,
        failure: None,
        finished: false,
        ready_at: None,
        used: false,
        promoted: false,
    }
}

const READY: RunnerView = RunnerView::Ready {
    allocated_bytes: 988_097_536,
    used: false,
};
const IN_USE: RunnerView = RunnerView::Ready {
    allocated_bytes: 988_097_536,
    used: true,
};

#[test]
fn a_request_by_any_path_uses_the_preparation_and_a_model_in_use_is_never_stopped() {
    // Seen in use once ready (the loopback API, Neo Grid or Swarm, not only the engine's chat).
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let mut prepared = entry(&clock, Duration::from_secs(600), Duration::from_secs(60));
    prepared.started_model = true;
    assert_eq!(prepared.decide(&READY, &clock), Action::Watch);
    assert_eq!(prepared.decide(&IN_USE, &clock), Action::Finish);
    assert!(prepared.used && !prepared.promoted);
    assert!(matches!(prepared.operation.state(), PrepareState::Consumed { .. }));

    // In use the moment it is first seen ready: the request came while it loaded.
    let mut promoted = entry(&clock, Duration::from_secs(600), Duration::from_secs(60));
    promoted.started_model = true;
    assert_eq!(promoted.decide(&IN_USE, &clock), Action::Finish);
    assert!(promoted.used && promoted.promoted);

    // Its kept time ends while a request is being served: the model keeps serving.
    let mut busy = entry(&clock, Duration::from_secs(600), Duration::from_secs(60));
    busy.started_model = true;
    assert_eq!(busy.decide(&READY, &clock), Action::Watch);
    clock.advance(Duration::from_secs(61));
    assert_eq!(busy.decide(&IN_USE, &clock), Action::Finish);
    assert!(busy.used);
}

#[test]
fn a_preparation_accounts_for_what_it_saved_or_cost() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let started = Instant::now();
    let mut used = entry(&clock, Duration::from_secs(600), Duration::from_secs(60));
    used.started_model = true;
    used.started_at = Some(started);
    used.ready_at = Some(started + Duration::from_secs(12));
    assert_eq!(used.decide(&READY, &clock), Action::Watch);
    assert_eq!(used.decide(&IN_USE, &clock), Action::Finish);
    let account = used.account("env-a", started + Duration::from_secs(20));
    assert_eq!(account["outcome"], "used");
    assert_eq!(account["savedSeconds"], 12.0);
    assert!(account["wastedLoadSeconds"].is_null());

    let mut unused = entry(&clock, Duration::from_secs(600), Duration::from_secs(60));
    unused.started_model = true;
    unused.started_at = Some(started);
    unused.ready_at = Some(started + Duration::from_secs(10));
    assert_eq!(unused.decide(&READY, &clock), Action::Watch);
    clock.advance(Duration::from_secs(61));
    assert_eq!(unused.decide(&READY, &clock), Action::Stop);
    let account = unused.account("env-b", started + Duration::from_secs(70));
    assert_eq!(account["wastedLoadSeconds"], 10.0);
    assert!(account["savedSeconds"].is_null());
    let gib_seconds = account["wastedGibSeconds"].as_f64().unwrap();
    assert!((gib_seconds - 60.0 * 988_097_536.0 / (1u64 << 30) as f64).abs() < 1e-6);
}

#[test]
fn the_estimate_is_the_nearest_rank_95th_percentile_of_the_measured_starts() {
    let samples = [9u64, 12, 10, 40, 11].map(Duration::from_secs).into_iter().collect::<VecDeque<_>>();
    assert_eq!(estimate_of(&samples), Some(Duration::from_secs(40)));
    let one = [Duration::from_secs(7)].into_iter().collect::<VecDeque<_>>();
    assert_eq!(estimate_of(&one), Some(Duration::from_secs(7)));
    assert_eq!(estimate_of(&VecDeque::new()), None);
}

#[test]
fn a_preparation_starts_once_is_kept_ready_for_its_ttl_and_is_used_by_the_first_request() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let mut prepared = entry(&clock, Duration::from_secs(600), Duration::from_secs(900));
    assert_eq!(prepared.decide(&RunnerView::Stopped, &clock), Action::Start);
    prepared.started_model = true;
    assert_eq!(prepared.decide(&RunnerView::Loading, &clock), Action::Watch);
    clock.advance(Duration::from_secs(40));
    assert_eq!(prepared.decide(&READY, &clock), Action::Watch);
    assert!(matches!(
        prepared.operation.state(),
        PrepareState::Ready { .. }
    ));
    assert_eq!(prepared.operation.prepared_bytes(), 988_097_536);
    // The first request uses it; the model then serves as any started model.
    let target = prepared.target;
    assert!(matches!(
        prepared.operation.request_arrived(&target, &clock),
        Arrival::Used { .. }
    ));
    assert_eq!(prepared.decide(&READY, &clock), Action::Finish);
}

#[test]
fn an_unused_preparation_is_stopped_at_its_ttl_and_a_missed_deadline_or_a_cancel_stops_it() {
    // Unused: kept for its TTL, then stopped.
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let mut unused = entry(&clock, Duration::from_secs(600), Duration::from_secs(60));
    unused.started_model = true;
    assert_eq!(unused.decide(&READY, &clock), Action::Watch);
    clock.advance(Duration::from_secs(59));
    assert_eq!(unused.decide(&READY, &clock), Action::Watch);
    clock.advance(Duration::from_secs(2));
    assert_eq!(unused.decide(&READY, &clock), Action::Stop);
    assert!(matches!(
        unused.operation.state(),
        PrepareState::Released { .. }
    ));

    // A model still loading at its deadline is released and stopped.
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let mut late = entry(&clock, Duration::from_secs(60), Duration::from_secs(900));
    late.started_model = true;
    clock.advance(Duration::from_secs(61));
    assert_eq!(late.decide(&RunnerView::Loading, &clock), Action::Stop);

    // A cancel releases it; one the preparation never started is left as it is.
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let mut cancelled = entry(&clock, Duration::from_secs(600), Duration::from_secs(900));
    cancelled.started_model = true;
    cancelled.operation.cancel(CancelReason::Requester, &clock);
    assert_eq!(cancelled.decide(&RunnerView::Loading, &clock), Action::Stop);
    let mut never_started = entry(&clock, Duration::from_secs(600), Duration::from_secs(900));
    never_started
        .operation
        .cancel(CancelReason::Requester, &clock);
    assert_eq!(
        never_started.decide(&RunnerView::Stopped, &clock),
        Action::Finish
    );

    // A load that failed, or a prepared model stopped underneath, ends it with why.
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let mut failed = entry(&clock, Duration::from_secs(600), Duration::from_secs(900));
    failed.started_model = true;
    let failure = RunnerView::Failed {
        error: "out of memory".into(),
    };
    assert_eq!(failed.decide(&failure, &clock), Action::Stop);
    assert_eq!(failed.failure.as_deref(), Some("out of memory"));
    let mut stopped_underneath = entry(&clock, Duration::from_secs(600), Duration::from_secs(900));
    stopped_underneath.started_model = true;
    assert_eq!(stopped_underneath.decide(&READY, &clock), Action::Watch);
    assert_eq!(
        stopped_underneath.decide(&RunnerView::Stopped, &clock),
        Action::Finish
    );
    assert!(stopped_underneath.failure.is_some());
}

#[test]
fn admission_refuses_a_deadline_the_estimate_cannot_meet() {
    let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
    let target = PrepareTarget {
        model: execution_identity(&facts()).unwrap(),
        adapter: None,
    };
    let request = PrepareRequest {
        operation: OperationId::generate(),
        execution: ExecutionId::generate(),
        tenant: TenantId::new("owner").unwrap(),
        target,
        origin: CandidateOrigin::ExplicitUserIntent,
        deadline: clock.now().checked_add(Duration::from_secs(60)).unwrap(),
        retention_ttl: Duration::from_secs(900),
        cancellation: CancellationToken::new(),
        work: vec![PrepareWork::Step {
            step: PreparationStep::Activate,
        }],
        assigned_request: None,
    };
    let refused = PrepareOperation::admit(request, DECLARED_ESTIMATE, &BOUNDS, &clock).unwrap_err();
    assert!(
        refused.to_string().contains("after its deadline"),
        "{refused}"
    );
}
