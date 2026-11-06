use super::*;

const PIN: &str = "a9782714e1b2bc615af6766dc204e8c974345b4a20fdf2100349ca2ceb87dc4c";
const INSTANCE: &str = "0123456789abcdef0123456789abcdef";
const SESSION: &str = "fedcba9876543210fedcba9876543210";

fn attempt(prompt: usize, elapsed_millis: u64, reply: &str) -> Attempt {
    Attempt {
        prompt,
        operation: OperationId::generate().as_str().to_owned(),
        elapsed_nanos: elapsed_millis * 1_000_000,
        ok: true,
        reply_digest: Some(reply_digest(reply)),
        output_tokens: Some(3),
        error: None,
    }
}

fn phase(name: &str, millis: u64, replies: &[&str], peak: u64) -> Phase {
    Phase {
        name: name.into(),
        serving: json!({"served": "source_injection", "sha256": "x"}),
        attempts: replies
            .iter()
            .enumerate()
            .map(|(index, reply)| attempt(index % PROMPTS.len(), millis, reply))
            .collect(),
        peak_gpu_bytes: Some(peak),
        ready_millis: Some(4000),
        observed_requests: replies.len(),
        records: replies.len(),
        ..Phase::default()
    }
}

fn shadow_counts(calls: u64, disagreed: u64) -> Value {
    json!({"pin": PIN, "points": ["gpu_grant_terms", "gpu_capacity_demand"], "loadError": null,
           "calls": calls, "agreed": calls - disagreed, "disagreed": disagreed, "candidateErrors": 0,
           "dropped": 0, "uncompared": 0, "servingNanos": 40_000, "candidateNanos": 45_000,
           "candidateMaxNanos": 30_000, "candidatePeakBytes": 4096, "hung": false, "queued": 0,
           "differences": []})
}

fn criteria() -> Criteria {
    Criteria::with_requests(4)
}

const REPLIES: [&str; 4] = [
    "An API is a contract.",
    "Red, yellow, blue.",
    "144",
    "The sea is wide.",
];

fn passed() -> Judgement {
    Judgement {
        conclusive: true,
        passed: true,
        reasons: vec![],
    }
}

#[test]
fn a_shadow_trial_passes_only_when_every_decision_agreed_within_the_criteria() {
    let mut shadow = phase("shadow", 900, &REPLIES, 2 << 30);
    shadow.shadow = shadow_counts(3, 0);
    assert_eq!(
        judge(
            RolloutStage::Shadow,
            PIN,
            std::slice::from_ref(&shadow),
            &criteria()
        ),
        passed()
    );

    // The candidate's own failures are conclusive and named.
    let failures: Vec<(Box<dyn Fn(&mut Value)>, &str)> = vec![
        (
            Box::new(|counts| *counts = shadow_counts(3, 1)),
            "shadow-disagreed",
        ),
        (
            Box::new(|counts| counts["hung"] = json!(true)),
            "shadow-hung",
        ),
        (
            Box::new(|counts| counts["dropped"] = json!(2)),
            "shadow-decisions-not-compared",
        ),
        (
            Box::new(|counts| counts["candidateNanos"] = json!(90_000_000)),
            "shadow-time-over-budget",
        ),
        (
            Box::new(|counts| counts["candidatePeakBytes"] = json!(64 << 20)),
            "shadow-memory-over-budget",
        ),
        (
            Box::new(|counts| counts["loadError"] = json!("SyntaxError")),
            "shadow-load-failed",
        ),
        (
            Box::new(|counts| counts["candidateErrors"] = json!(1)),
            "shadow-candidate-failed",
        ),
    ];
    for (change, reason) in failures {
        let mut failing = shadow.clone();
        change(&mut failing.shadow);
        let judgement = judge(RolloutStage::Shadow, PIN, &[failing], &criteria());
        assert!(
            judgement.conclusive && !judgement.passed,
            "{reason}: {judgement:?}"
        );
        assert_eq!(judgement.reasons[0], reason);
        assert!(
            label("reason", &judgement.reasons[0]).is_ok(),
            "a journal label"
        );
    }

    // What says nothing about the candidate decides nothing: a candidate never given a
    // decision or not run at all, a serving path that failed, a measurement left incomplete.
    let undecided: Vec<(Box<dyn Fn(&mut Phase)>, &str)> = vec![
        (
            Box::new(|p| p.shadow = shadow_counts(0, 0)),
            "shadow-no-decisions",
        ),
        (
            Box::new(|p| p.shadow["pin"] = json!("another")),
            "shadow-not-run",
        ),
        (
            Box::new(|p| p.attempts[2].ok = false),
            "request-failed:shadow",
        ),
        (Box::new(|p| p.records = 3), "measurement-incomplete:shadow"),
        (
            Box::new(|p| p.error = Some("the trial runner failed to load: checksum".into())),
            "phase-failed:shadow:the-trial-runner-failed-to-load-checksum",
        ),
    ];
    for (change, reason) in undecided {
        let mut unclear = shadow.clone();
        change(&mut unclear);
        let judgement = judge(RolloutStage::Shadow, PIN, &[unclear], &criteria());
        assert!(
            !judgement.conclusive && !judgement.passed,
            "{reason}: {judgement:?}"
        );
        assert!(
            judgement.reasons.iter().any(|r| r == reason),
            "{reason}: {judgement:?}"
        );
    }

    // A shadow candidate the runner served instead of shadowing fails.
    let mut served = shadow.clone();
    served.serving = json!({"served": "bundle", "pin": PIN});
    assert_eq!(
        judge(RolloutStage::Shadow, PIN, &[served], &criteria()).reasons,
        vec!["shadow-candidate-served".to_owned()]
    );
}

#[test]
fn an_opt_in_or_default_trial_compares_the_served_candidate_with_its_baseline() {
    let baseline = phase("baseline", 800, &REPLIES, 2 << 30);
    let mut candidate = phase("candidate", 850, &REPLIES, (2 << 30) + (8 << 20));
    candidate.serving = json!({"served": "bundle", "pin": PIN, "sha256": "y"});
    for stage in [RolloutStage::OptIn, RolloutStage::BackendDefault] {
        assert_eq!(
            judge(
                stage,
                PIN,
                &[baseline.clone(), candidate.clone()],
                &criteria()
            ),
            passed()
        );
        // A vLLM or llama.cpp runner's phases, both read by the host probe, are compared.
        let (mut b, mut c) = (baseline.clone(), candidate.clone());
        b.peak_gpu_source = Some("host-probe-after-requests".into());
        c.peak_gpu_source = Some("host-probe-after-requests".into());
        assert_eq!(judge(stage, PIN, &[b, c], &criteria()), passed());
    }
    let failures: Vec<(Box<dyn Fn(&mut Phase, &mut Phase)>, &str)> = vec![
        (
            Box::new(|_, c| c.attempts[1].reply_digest = Some(reply_digest("Green."))),
            "replies-differ",
        ),
        (
            Box::new(|_, c| c.serving = json!({"served": "source_injection"})),
            "candidate-not-served",
        ),
        (
            Box::new(|_, c| {
                c.attempts
                    .iter_mut()
                    .for_each(|a| a.elapsed_nanos = 2_000_000_000)
            }),
            "latency-over-budget",
        ),
        (
            Box::new(|_, c| c.peak_gpu_bytes = Some(3 << 30)),
            "gpu-memory-over-budget",
        ),
        (
            Box::new(|_, c| c.attempts[0].ok = false),
            "request-failed:candidate",
        ),
        (
            Box::new(|_, c| c.error = Some("the trial runner failed to load".into())),
            "phase-failed:candidate:the-trial-runner-failed-to-load",
        ),
    ];
    for (change, reason) in failures {
        let (mut b, mut c) = (baseline.clone(), candidate.clone());
        change(&mut b, &mut c);
        let judgement = judge(RolloutStage::OptIn, PIN, &[b, c], &criteria());
        assert!(
            judgement.conclusive && !judgement.passed,
            "{reason}: {judgement:?}"
        );
        assert!(
            judgement.reasons.iter().any(|r| r == reason),
            "{reason}: {judgement:?}"
        );
    }
    let undecided: Vec<(Box<dyn Fn(&mut Phase, &mut Phase)>, &str)> = vec![
        (
            Box::new(|b, _| b.serving = json!({"served": "bundle", "pin": PIN})),
            "baseline-served-the-candidate",
        ),
        (
            Box::new(|_, c| c.peak_gpu_bytes = None),
            "gpu-memory-not-measured",
        ),
        (
            Box::new(|b, c| {
                b.peak_gpu_source = Some("runner-allocator".into());
                c.peak_gpu_source = Some("host-probe-after-requests".into());
            }),
            "gpu-memory-not-comparable",
        ),
        (
            Box::new(|b, _| b.attempts[3].ok = false),
            "request-failed:baseline",
        ),
        (
            Box::new(|_, c| c.records = 1),
            "measurement-incomplete:candidate",
        ),
        (
            Box::new(|b, _| b.error = Some("the trial runner did not start".into())),
            "phase-failed:baseline:the-trial-runner-did-not-start",
        ),
    ];
    for (change, reason) in undecided {
        let (mut b, mut c) = (baseline.clone(), candidate.clone());
        change(&mut b, &mut c);
        let judgement = judge(RolloutStage::OptIn, PIN, &[b, c], &criteria());
        assert!(!judgement.conclusive, "{reason}: {judgement:?}");
        assert!(
            judgement.reasons.iter().any(|r| r == reason),
            "{reason}: {judgement:?}"
        );
    }
    // The latency budget is the baseline's median times the ratio plus the slack.
    let mut slower = candidate.clone();
    slower
        .attempts
        .iter_mut()
        .for_each(|a| a.elapsed_nanos = 1_090_000_000);
    assert!(
        judge(
            RolloutStage::OptIn,
            PIN,
            &[baseline.clone(), slower],
            &criteria()
        )
        .passed
    );
    // Without its baseline the trial decides nothing.
    assert!(!judge(RolloutStage::OptIn, PIN, &[candidate], &criteria()).conclusive);
}

fn context(stage: RolloutStage) -> Context {
    Context {
        execution: ExecutionId::generate(),
        stage,
        plan: DigestBuilder::new(PLAN_DOMAIN).bytes(b"plan").finish(),
        runner_build: DigestBuilder::new(BUILD_DOMAIN).bytes(b"build").finish(),
        engine: core::EngineIdentity {
            name: report_label("transformers"),
            version: report_label("5.18.0"),
        },
        host: host_description(
            Some("NVIDIA GeForce RTX 5090 Laptop GPU"),
            Some(25_757_220_864),
        ),
        launch: core::LaunchDescription {
            image: DigestBuilder::new(IMAGE_DOMAIN)
                .bytes(b"docker.io/pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime")
                .finish(),
            backend: core::Label::new("wsl2-cuda").unwrap(),
        },
        paired: stage != RolloutStage::Shadow,
    }
}

/// A completed request as the runner's measurement window journals it, with the
/// Transformers streamer's token emissions when `exact`.
fn finished(attempt_id: u64, exact: bool) -> Value {
    let mut record = json!({
        "id": attempt_id, "completionSequence": attempt_id, "kind": "request", "outcome": "ok",
        "elapsedMs": 905.25, "firstOutputMs": 121.5,
        "stages": {"generation": {"calls": 1, "failedCalls": 0, "elapsedMs": 790.0}},
        "boundaries": {"version": 1, "acceptedMs": 0.25, "admittedMs": 1.5, "completedMs": 900.0},
    });
    record["tokens"] = json!({"version": 1, "source": "transformers-streamer-flush", "complete": exact,
                              "emittedMs": [121.5, 121.5, 480.0], "outputTokens": 3});
    json!({"event": "finish", "sequence": attempt_id + 1, "instanceId": INSTANCE, "attemptId": attempt_id, "record": record})
}

#[test]
fn every_measured_request_is_the_runners_own_observation_adapted_with_the_trials_context() {
    let context = context(RolloutStage::OptIn);
    let candidate = phase("candidate", 850, &REPLIES, 2 << 30);
    let mut events = vec![json!({"event": "instance", "sequence": 1, "instanceId": INSTANCE})];
    events.extend((1..=4).map(|id| finished(id, true)));
    let (records, observed, gaps) = records_of(&context, &candidate, 2, SESSION, &events);
    assert_eq!((records.len(), observed), (4, 4), "{gaps:?}");
    for (record, attempt) in records.iter().zip(&candidate.attempts) {
        assert_eq!(record.attempt.operation.as_str(), attempt.operation);
        assert_eq!(record.attempt.execution, context.execution);
        assert_eq!(record.attempt.burst, 2);
        assert!(record.is_success());
        assert_eq!(record.measurements.output_tokens.value(), Some(&3));
        assert!(
            matches!(&record.substrate, core::RunSubstrate::AuthorizedDisposable { authorization } if authorization.as_str() == "helper-trial")
        );
        record.validate().unwrap();
    }
    assert_eq!(
        records[0].attempt.variant.as_str(),
        "helper-trial-opt-in-candidate"
    );
    // Labels are redaction-safe: the host's names became labels; the prompts are a digest.
    let host = &records[0].host;
    assert_eq!(
        host.gpus.value().unwrap()[0].model.as_str(),
        "NVIDIA-GeForce-RTX-5090-Laptop-GPU"
    );
    assert!(!serde_json::to_string(&records)
        .unwrap()
        .contains("primary colors"));
    // The records' provenance is a Yougori measurement and they read back as written.
    assert!(Provenance::of_records(&records)
        .unwrap()
        .yougori_evidence()
        .is_ok());
    let encoded = serde_json::to_string(&records[0]).unwrap();
    assert_eq!(core::RunRecord::from_json(&encoded).unwrap(), records[0]);

    // An observation without exact token emissions becomes no record (the adapter's gap),
    // and a request the window lost is named; either leaves the phase's measurement short.
    let mut short = events.clone();
    short[2] = finished(2, false);
    short.pop();
    let (records, observed, gaps) = records_of(&context, &candidate, 2, SESSION, &short);
    assert_eq!((records.len(), observed), (2, 3));
    assert!(
        gaps.iter().any(|g| g == "ExactTokenTimingUnavailable"),
        "{gaps:?}"
    );
    assert!(
        gaps.iter().any(|g| g.contains("completed 3 requests")),
        "{gaps:?}"
    );
    let mut measured = candidate.clone();
    measured.records = records.len();
    let judgement = judge(
        RolloutStage::Shadow,
        PIN,
        &[Phase {
            name: "shadow".into(),
            shadow: shadow_counts(2, 0),
            ..measured
        }],
        &criteria(),
    );
    assert!(!judgement.conclusive);
}

fn stored(dir: &Path, passed: bool, stage: RolloutStage) -> (String, Provenance) {
    let context = context(stage);
    let shadow = phase("shadow", 900, &REPLIES, 2 << 30);
    let events: Vec<Value> = (1..=4).map(|id| finished(id, true)).collect();
    let (records, _, _) = records_of(&context, &shadow, 1, SESSION, &events);
    let provenance = Provenance::of_records(&records).unwrap();
    let trial = format!("trial-{}", uuid::Uuid::new_v4().simple());
    let summary = Summary {
        trial: trial.clone(),
        helper: "gpu-optimizer".into(),
        backend: "transformers".into(),
        pin: PIN.into(),
        stage: stage_tag(stage).into(),
        environment: "env-test".into(),
        criteria: criteria(),
        phases: vec![shadow],
        conclusive: true,
        passed,
        reasons: if passed {
            vec![]
        } else {
            vec!["shadow-disagreed".into()]
        },
        evidence: Some(provenance.comparable_evidence().unwrap().to_string()),
        measured: true,
    };
    store(dir, &summary, &records).unwrap();
    (trial, provenance)
}

#[test]
fn only_a_passed_trial_of_this_engines_store_is_evidence_for_its_pin_and_stage() {
    let dir = tempfile::tempdir().unwrap();
    let (trial, provenance) = stored(dir.path(), true, RolloutStage::Shadow);
    let evidence = evidence_of(dir.path(), &trial, PIN, RolloutStage::Shadow).unwrap();
    assert_eq!(evidence, provenance);
    // Another pin, another stage, a failed trial, an unknown or malformed id: refused.
    assert!(
        evidence_of(dir.path(), &trial, "another-pin", RolloutStage::Shadow)
            .unwrap_err()
            .contains("another bundle")
    );
    assert!(evidence_of(dir.path(), &trial, PIN, RolloutStage::OptIn)
        .unwrap_err()
        .contains("shadow stage"));
    let (failed, _) = stored(dir.path(), false, RolloutStage::Shadow);
    assert!(evidence_of(dir.path(), &failed, PIN, RolloutStage::Shadow)
        .unwrap_err()
        .contains("did not pass"));
    assert!(evidence_of(dir.path(), "trial-unknown", PIN, RolloutStage::Shadow).is_err());
    assert!(
        evidence_of(dir.path(), "../outside", PIN, RolloutStage::Shadow)
            .unwrap_err()
            .contains("not one this engine gives")
    );
    // Records changed after the trial no longer match its summary.
    let records = dir
        .path()
        .join(TRIALS_DIRECTORY)
        .join(&trial)
        .join(RECORDS_FILE);
    let mut value: Value = serde_json::from_slice(&std::fs::read(&records).unwrap()).unwrap();
    value["records"][0]["measurements"]["output_tokens"]["value"] = json!(3);
    value["records"][0]["build"]["runner_version"] = json!("9.9.9");
    std::fs::write(&records, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(evidence_of(dir.path(), &trial, PIN, RolloutStage::Shadow)
        .unwrap_err()
        .contains("no longer match"));
}

#[test]
fn the_trials_prompts_are_a_stable_synthetic_fixture_and_its_labels_redaction_safe() {
    let first = prompts_fixture();
    assert_eq!(first, prompts_fixture());
    assert_eq!(first.disclosure, core::Disclosure::PermittedSynthetic);
    assert_eq!(first.id.as_str(), "helper-trial-prompts-v1");
    assert_eq!(report_label("Windows 11 Home").as_str(), "Windows-11-Home");
    assert_eq!(report_label("1.2.0").as_str(), "1.2.0");
    assert_eq!(report_label("C:/Users/x").as_str(), "C-Users-x");
    assert_eq!(report_label("").as_str(), "unknown");
}
