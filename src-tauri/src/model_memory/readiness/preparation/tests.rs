use std::collections::BTreeMap;
use std::time::Duration;

use super::*;
use crate::foundation::report::{ReportError, Resolution};
use crate::model_memory::bench::rng::Variation;
use crate::model_memory::math::calibration::ModeThresholds;
use crate::model_memory::math::prefetch::Objective;
use crate::model_memory::readiness::claim::{ClaimOutcome, EvidenceClass, InconclusiveReason};
use crate::model_memory::readiness::test_support::{factory, label, profile, target, GB, MILLIS};

const MODELS: [&str; 4] = ["model-a", "model-b", "model-c", "model-d"];

fn trace_spec() -> TraceSpec {
    TraceSpec {
        models: MODELS.iter().map(|model| label(model)).collect(),
        episodes: 20,
        min_gap_nanos: 8_000 * MILLIS,
        max_gap_nanos: 20_000 * MILLIS,
        usual_successor_ppm: 500_000,
        workflow_ppm: 700_000,
        workflow_accuracy_ppm: 950_000,
        ui_ppm: 250_000,
        ui_accuracy_ppm: 850_000,
        hovers: 4,
        hover_spacing_nanos: 200 * MILLIS,
        min_think_nanos: 3_000 * MILLIS,
        follow_ups: 9,
    }
}

fn spec(trace: TraceSpec) -> PreparationSpec {
    PreparationSpec {
        trace,
        trials: 5,
        seed: 0x5EED_0412,
        targets: MODELS
            .iter()
            .map(|model| (label(model), target(model)))
            .collect(),
        execution: ExecutionId::new("exe-workflow").unwrap(),
        tenant: TenantId::new("tenant-a").unwrap(),
        bounds: PrepareBounds {
            max_lead: Duration::from_secs(120),
            max_retention_ttl: Duration::from_secs(60),
        },
        retention_ttl: Duration::from_secs(20),
        limits: WeakIntentLimits {
            selection_dwell: Duration::from_millis(500),
            hover_dwell: Duration::from_millis(1_500),
            min_interval: Duration::from_secs(5),
        },
        budget: PrefetchBudget {
            max_speculative_bytes: 16 * GB,
            capacity_bytes: 32 * GB,
            reserved_foreground_bytes: 8 * GB,
        },
        // One score per saved millisecond, 1e-7 per wasted byte, one per currency unit.
        prices: LifecyclePrices::new(Objective::new(1.0, 1e-7, 0.0, 1.0).unwrap(), 1e-10, 10.0)
            .unwrap(),
        thresholds: ModeThresholds {
            enter_below_confidence: 0.1,
            exit_at_confidence: 0.2,
            enter_above_load_fraction: 2.0,
            exit_at_load_fraction: 1.5,
            enter_above_calibration_error: 0.95,
            exit_at_calibration_error: 0.5,
            recovery_dwell: Duration::from_secs(10),
        },
        block_bytes: 64 * 1_048_576,
        max_output_tokens: 8,
        latency_objective: LatencyObjective {
            quantile: Quantile::P99,
            max_time_to_first_token_nanos: 10_000 * MILLIS,
        },
        p99_tolerance: 0.05,
        tie_tolerance: 0.02,
        calibration_bins: 10,
    }
}

fn run(spec: &PreparationSpec) -> PreparationExperiment {
    let factory = factory(profile(RunnerMode::FullProcessRestart), 41);
    run_experiment(&factory, spec).unwrap()
}

fn report(experiment: &PreparationExperiment, policy: Policy) -> &PolicyReport {
    experiment.report(policy).unwrap()
}

#[test]
fn three_policies_replay_the_same_traces_and_record_fake_substrate_evidence() {
    let experiment = run(&spec(trace_spec()));
    assert_eq!(experiment.design.check(), Ok(()));
    assert_eq!(experiment.traces.len(), 5);
    assert!(matches!(
        experiment.traces[0].pattern(),
        TracePattern::Mixed { .. }
    ));
    for policy in Policy::ALL {
        let report = report(&experiment, policy);
        // Same traces: every policy served the same 5 × 20 × 10 requests.
        assert_eq!(report.measurement.attempts(), 1_000);
        assert!(report.measurement.provenance.is_fake_substrate());
        assert_eq!(report.measurement.success_rate(), 1.0);
        // Foreground p99 over 1,000 requests in 5 bursts is resolved.
        let p99 = report.foreground_p99.as_ref().unwrap();
        assert_eq!(p99.resolution, Resolution::Resolved);
        // Hover is rate-limited away: it never prepares anything.
        assert!(report
            .preparations
            .iter()
            .all(|prep| prep.source != Some(IntentSource::Hover)));
    }
    let demand = report(&experiment, Policy::DemandOnly);
    assert!(demand.preparations.is_empty());
    assert_eq!(demand.prepared_bytes, 0);
    assert_eq!(demand.peak_retained_bytes, 0);
    assert_eq!(
        demand.lifecycle.verdict,
        PreparationVerdict::NothingPrepared
    );

    let intent = report(&experiment, Policy::WorkflowIntent);
    let markov = report(&experiment, Policy::RecencyMarkov);
    assert!(intent.used() > 0 && markov.used() > 0);
    assert!(intent.lifecycle.saved_score > 0.0);
    assert_eq!(intent.lifecycle.verdict, PreparationVerdict::Succeeded);
    assert!(
        intent.lifecycle.net_score > markov.lifecycle.net_score,
        "intent {} versus markov {}",
        intent.lifecycle.net_score,
        markov.lifecycle.net_score
    );
    assert!(intent.wasted_bytes < markov.wasted_bytes);
    assert!(intent.peak_retained_bytes > 0);
    assert!(intent.retained_byte_seconds > 0.0);
    assert_eq!(
        intent.wasted_bytes,
        intent
            .preparations
            .iter()
            .filter(|prep| !prep.used)
            .map(|prep| prep.prepared_bytes)
            .sum::<u64>()
    );
    // Both ablations ran, each preparing only from its own source.
    assert!(report(&experiment, Policy::QueuedWorkOnly)
        .preparations
        .iter()
        .all(|prep| prep.source == Some(IntentSource::QueuedWorkflow)));
    assert!(report(&experiment, Policy::UiIntentOnly)
        .preparations
        .iter()
        .all(|prep| prep.source == Some(IntentSource::UiSelection)));

    let claim = experiment.claim();
    assert_eq!(claim.evidence(), EvidenceClass::FakeSubstrate);
    assert_eq!(
        claim.provenance_label(),
        "fake time-controlled run, not a Yougori measurement"
    );
    assert_eq!(
        claim
            .cells()
            .iter()
            .map(|cell| (cell.label.as_str(), cell.verdict))
            .collect::<Vec<_>>(),
        vec![
            ("demand-only", CellVerdict::Better),
            ("recency-markov", CellVerdict::Better)
        ]
    );
    assert_eq!(
        claim.outcome(),
        &ClaimOutcome::Inconclusive {
            reason: InconclusiveReason::FakeSubstrateOnly
        }
    );
}

#[test]
fn intent_that_is_always_wrong_is_rejected() {
    let trace = TraceSpec {
        workflow_accuracy_ppm: 0,
        ui_accuracy_ppm: 0,
        episodes: 12,
        follow_ups: 0,
        ..trace_spec()
    };
    let experiment = run(&spec(trace));
    let intent = report(&experiment, Policy::WorkflowIntent);
    assert_eq!(intent.used(), 0);
    assert!(intent.wasted_bytes > 0);
    assert!(matches!(
        intent.lifecycle.verdict,
        PreparationVerdict::Failed { .. }
    ));
    assert!(experiment
        .claim()
        .cells()
        .iter()
        .all(|cell| cell.verdict == CellVerdict::Worse));
    assert_eq!(experiment.claim().outcome(), &ClaimOutcome::Rejected);
}

#[test]
fn a_released_preparation_never_serves_the_request() {
    // Every selection names the right model, but its two-second TTL ends long before the
    // request arrives, so the prepared state is released first.
    let trace = TraceSpec {
        episodes: 4,
        min_gap_nanos: 10_000 * MILLIS,
        max_gap_nanos: 12_000 * MILLIS,
        workflow_ppm: 0,
        ui_ppm: 1_000_000,
        ui_accuracy_ppm: 1_000_000,
        hovers: 0,
        follow_ups: 0,
        ..trace_spec()
    };
    let mut spec = spec(trace);
    spec.retention_ttl = Duration::from_secs(2);
    let experiment = run(&spec);
    let ui = report(&experiment, Policy::UiIntentOnly);
    assert!(!ui.preparations.is_empty());
    for prep in &ui.preparations {
        assert!(!prep.used);
        // Released state ran on a disposable runner, so it cannot serve the request.
        assert!(!prep.on_episode_runner);
        assert_eq!(
            prep.released_at.saturating_duration_since(prep.ready_at),
            Duration::from_secs(2)
        );
    }
    assert_eq!(
        ui.measurement.ttft_samples(),
        report(&experiment, Policy::DemandOnly)
            .measurement
            .ttft_samples()
    );
    assert!(matches!(
        ui.lifecycle.verdict,
        PreparationVerdict::Failed { .. }
    ));
}

#[test]
fn work_that_cannot_finish_by_its_deadline_is_never_started() {
    // Tools finish after 500 ms, faster than any host read of these models.
    let trace = TraceSpec {
        episodes: 4,
        min_gap_nanos: 500 * MILLIS,
        max_gap_nanos: 500 * MILLIS,
        workflow_ppm: 1_000_000,
        workflow_accuracy_ppm: 1_000_000,
        ui_ppm: 0,
        hovers: 0,
        min_think_nanos: 0,
        follow_ups: 0,
        ..trace_spec()
    };
    let experiment = run(&spec(trace));
    for policy in Policy::ALL {
        assert!(report(&experiment, policy).preparations.is_empty());
    }
    // Every queued intent was worth preparing but refused by its deadline.
    assert_eq!(report(&experiment, Policy::WorkflowIntent).refused, 20);
    assert_eq!(report(&experiment, Policy::QueuedWorkOnly).refused, 20);
    assert_eq!(
        experiment.claim().outcome(),
        &ClaimOutcome::Inconclusive {
            reason: InconclusiveReason::NoImprovement
        }
    );
}

#[test]
fn traces_are_seeded_mixed_and_checked() {
    let spec = trace_spec();
    let first = Trace::generate(&spec, 7).unwrap();
    assert_eq!(first, Trace::generate(&spec, 7).unwrap());
    assert_ne!(first, Trace::generate(&spec, 8).unwrap());
    assert_eq!(first.episodes.len(), 20);
    for pair in first.episodes.windows(2) {
        assert_eq!(pair[0].next, pair[1].from);
    }
    for episode in &first.episodes {
        assert_ne!(episode.from, episode.next);
        assert!((8_000 * MILLIS..=20_000 * MILLIS).contains(&episode.gap_nanos));
        for signal in &episode.signals {
            match signal.source {
                IntentSource::QueuedWorkflow => {
                    assert_eq!(signal.eta_offset_nanos, Some(episode.gap_nanos))
                }
                IntentSource::UiSelection => assert_eq!(signal.offset_nanos, 800 * MILLIS),
                IntentSource::Hover => assert!(signal.offset_nanos < 800 * MILLIS),
            }
        }
    }
    let invalid = |spec: TraceSpec| Trace::generate(&spec, 1).unwrap_err();
    assert!(matches!(
        invalid(TraceSpec {
            models: vec![label("model-a"), label("model-b")],
            ..trace_spec()
        }),
        ReadinessError::InvalidSpec {
            field: "models",
            ..
        }
    ));
    assert!(matches!(
        invalid(TraceSpec {
            workflow_ppm: 1_000_001,
            ..trace_spec()
        }),
        ReadinessError::InvalidSpec {
            field: "workflow_ppm",
            ..
        }
    ));
    assert!(matches!(
        invalid(TraceSpec {
            min_think_nanos: 7_500 * MILLIS,
            ..trace_spec()
        }),
        ReadinessError::InvalidSpec {
            field: "min_think_nanos",
            ..
        }
    ));
    assert!(matches!(
        invalid(TraceSpec {
            workflow_ppm: 800_000,
            ui_ppm: 300_000,
            ..trace_spec()
        }),
        ReadinessError::InvalidSpec {
            field: "ui_ppm",
            ..
        }
    ));
}

#[test]
fn preparation_work_follows_the_runner_mode_and_bounds_its_worst_case() {
    assert_eq!(
        PrepareAction::for_mode(RunnerMode::FullProcessRestart),
        PrepareAction::HostCopy
    );
    assert_eq!(
        PrepareAction::for_mode(RunnerMode::VerifiedReload),
        PrepareAction::HostCopy
    );
    assert_eq!(
        PrepareAction::for_mode(RunnerMode::VersionSupportedSleep),
        PrepareAction::LoadAsleep
    );
    assert_eq!(
        PrepareAction::for_mode(RunnerMode::RetainedProcess),
        PrepareAction::LoadRetained
    );
    let mut varied = profile(RunnerMode::FullProcessRestart);
    varied.variation = Variation::new(100_000).unwrap();
    let a = label("model-a");
    // 1,200 ms ± 10% is at most 1,320 ms.
    assert_eq!(
        PrepareAction::HostCopy
            .worst_case_nanos(&varied, &a)
            .unwrap(),
        1_320 * MILLIS
    );
    // Startup 2,000 + cold load 1,500 + capture 300 + sleep 350, each up to 10% longer.
    assert_eq!(
        PrepareAction::LoadAsleep
            .worst_case_nanos(&varied, &a)
            .unwrap(),
        4_565 * MILLIS
    );
    let exact = profile(RunnerMode::FullProcessRestart);
    assert_eq!(
        PrepareAction::LoadRetained
            .worst_case_nanos(&exact, &a)
            .unwrap(),
        3_800 * MILLIS
    );
    let close = |left: f64, right: f64| (left - right).abs() < 1e-9;
    assert!(close(
        PrepareAction::HostCopy.saved_seconds(&exact, &a).unwrap(),
        1.1
    ));
    assert!(close(
        PrepareAction::LoadAsleep.saved_seconds(&exact, &a).unwrap(),
        3.45
    ));
    assert!(close(
        PrepareAction::LoadRetained
            .saved_seconds(&exact, &a)
            .unwrap(),
        3.798
    ));
    assert!(PrepareAction::HostCopy
        .worst_case_nanos(&exact, &label("model-z"))
        .is_err());
}

#[test]
fn the_experiment_refuses_an_unsound_setup() {
    let factory = factory(profile(RunnerMode::FullProcessRestart), 41);
    let mut too_few = spec(trace_spec());
    too_few.trials = 3;
    assert_eq!(
        run_experiment(&factory, &too_few).unwrap_err(),
        ReadinessError::Report(ReportError::TooFewTrials {
            trials: 3,
            required: 5
        })
    );
    let mut missing = spec(trace_spec());
    missing.targets.remove(&label("model-d"));
    assert_eq!(
        run_experiment(&factory, &missing).unwrap_err(),
        ReadinessError::UnknownModel {
            model: "model-d".to_string()
        }
    );
    let mut shared = spec(trace_spec());
    shared.targets = MODELS
        .iter()
        .map(|model| (label(model), target("model-a")))
        .collect::<BTreeMap<_, _>>();
    assert!(matches!(
        run_experiment(&factory, &shared).unwrap_err(),
        ReadinessError::InvalidSpec {
            field: "targets",
            ..
        }
    ));
}
