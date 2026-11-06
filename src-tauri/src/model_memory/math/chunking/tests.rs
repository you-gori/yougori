use super::*;
use crate::model_memory::math::test_support::{close, SeededRng};

const MIB: u64 = 1 << 20;
const TOTAL_BYTES: u64 = 14_000_000_000;

fn stage_id(name: &str) -> StageId {
    StageId::new(name).unwrap()
}

/// A curve "measured" as `overhead + c / bandwidth`, scaled by `slowdown`.
fn curve(
    name: &str,
    non_preemptible: bool,
    overhead_seconds: f64,
    bytes_per_second: f64,
    slowdown: f64,
    sizes: &[u64],
) -> StageCurve {
    let points: Vec<(u64, f64)> = sizes
        .iter()
        .map(|&size| {
            (
                size,
                slowdown * (overhead_seconds + size as f64 / bytes_per_second),
            )
        })
        .collect();
    StageCurve::new(stage_id(name), non_preemptible, &points).unwrap()
}

#[test]
fn the_fit_recovers_alpha_and_bandwidth() {
    let samples: Vec<ServiceSample> = [MIB, 4 * MIB, 16 * MIB, 64 * MIB]
        .iter()
        .map(|&chunk_bytes| ServiceSample {
            chunk_bytes,
            seconds: 50e-6 + chunk_bytes as f64 / 7e9,
        })
        .collect();
    let fit = LinearServiceFit::fit(&samples).unwrap();
    assert!(close(fit.overhead_seconds(), 50e-6, 1e-12));
    assert!(close(fit.bandwidth_bytes_per_second(), 7e9, 1.0));
    assert!(fit.residual_rms_seconds() < 1e-15);
    assert_eq!(fit.samples(), 4);
    assert!(close(
        fit.seconds_for(8 * MIB),
        50e-6 + (8 * MIB) as f64 / 7e9,
        1e-12
    ));

    // Noisy measurements still fit closely, and the residual reports the noise.
    let mut rng = SeededRng::new(7);
    let noisy: Vec<ServiceSample> = (1..=64u64)
        .map(|step| {
            let chunk_bytes = step * MIB;
            ServiceSample {
                chunk_bytes,
                seconds: 50e-6 + chunk_bytes as f64 / 7e9 + rng.range(-2e-6, 2e-6),
            }
        })
        .collect();
    let fit = LinearServiceFit::fit(&noisy).unwrap();
    assert!(close(fit.overhead_seconds(), 50e-6, 2e-6));
    assert!((fit.bandwidth_bytes_per_second() / 7e9 - 1.0).abs() < 1e-3);
    assert!(fit.residual_rms_seconds() > 0.0 && fit.residual_rms_seconds() < 2e-6);
}

#[test]
fn the_fit_refuses_samples_the_model_cannot_describe() {
    let at = |chunk_bytes: u64, seconds: f64| ServiceSample {
        chunk_bytes,
        seconds,
    };
    assert_eq!(
        LinearServiceFit::fit(&[at(MIB, 1e-3), at(MIB, 2e-3)]),
        Err(ChunkingError::TooFewDistinctSizes)
    );
    assert!(matches!(
        LinearServiceFit::fit(&[at(MIB, 2e-3), at(2 * MIB, 1e-3)]),
        Err(ChunkingError::NonPositiveSlope { .. })
    ));
    // Time that falls below zero for small chunks has a negative fixed cost.
    assert!(matches!(
        LinearServiceFit::fit(&[at(MIB, 1e-3), at(2 * MIB, 3e-3)]),
        Err(ChunkingError::NegativeOverhead { .. })
    ));
    assert_eq!(
        LinearServiceFit::fit(&[]),
        Err(ChunkingError::Input(InputError::Empty { field: "samples" }))
    );
    assert!(LinearServiceFit::fit(&[at(0, 1e-3), at(MIB, 2e-3)]).is_err());
    assert!(LinearServiceFit::fit(&[at(MIB, f64::NAN), at(2 * MIB, 2e-3)]).is_err());
    assert!(LinearServiceFit::fit(&[at(MIB, -1e-3), at(2 * MIB, 2e-3)]).is_err());
}

#[test]
fn the_toy_optimum_minimises_completion_on_a_grid() {
    let model = ToyEqualStageModel::new(TOTAL_BYTES, 25e9, (4 * MIB) as f64).unwrap();
    let seed = model.seed_chunk_bytes();
    assert!(close(
        seed,
        (TOTAL_BYTES as f64 * (4 * MIB) as f64 / 2.0).sqrt(),
        1e-6
    ));
    let at_seed = model.completion_seconds(seed).unwrap();

    let mut best = (0.0, f64::INFINITY);
    for step in 1..=1000u32 {
        let chunk_bytes = f64::from(step) * 1e6;
        let seconds = model.completion_seconds(chunk_bytes).unwrap();
        assert!(
            seconds >= at_seed * (1.0 - 1e-12),
            "{chunk_bytes} beats the seed"
        );
        if seconds < best.1 {
            best = (chunk_bytes, seconds);
        }
    }
    assert!((best.0 - seed).abs() <= 1e6);

    // B(h) is half of Bmax, and T(c) follows its definition.
    assert!(close(
        model.bandwidth_bytes_per_second((4 * MIB) as f64).unwrap(),
        12.5e9,
        1e-3
    ));
    let chunk = 32e6;
    let expected = (TOTAL_BYTES as f64 + 2.0 * chunk) / (25e9 * chunk / (chunk + (4 * MIB) as f64));
    assert!(close(
        model.completion_seconds(chunk).unwrap(),
        expected,
        1e-12
    ));

    assert!(ToyEqualStageModel::new(0, 25e9, 1.0).is_err());
    assert!(ToyEqualStageModel::new(1, 0.0, 1.0).is_err());
    assert!(ToyEqualStageModel::new(1, 25e9, 0.0).is_err());
    assert!(model.completion_seconds(0.0).is_err());
}

#[test]
fn the_toy_model_is_three_equal_pipeline_stages() {
    let half_rate = MIB as f64;
    let total_bytes = 1024 * MIB;
    let chunk = 16 * MIB;
    let model = ToyEqualStageModel::new(total_bytes, 25e9, half_rate).unwrap();
    let per_batch = (chunk as f64 + half_rate) / 25e9;
    let stages: Vec<StageCurve> = ["a", "b", "c"]
        .iter()
        .map(|name| StageCurve::new(stage_id(name), false, &[(chunk, per_batch)]).unwrap())
        .collect();
    let limits = BatchLimits {
        alignment_bytes: MIB,
        staging_memory_bytes: u64::MAX,
        batches_in_memory: 3,
        max_non_preemptible_seconds: 1.0,
    };
    let choice = choose_batch_size(
        total_bytes,
        &[chunk],
        &stages,
        &limits,
        &ServingCondition::Idle,
    )
    .unwrap();
    assert!(close(
        choice.chosen.completion_seconds,
        model.completion_seconds(chunk as f64).unwrap(),
        1e-12
    ));
}

fn sizes() -> Vec<u64> {
    vec![
        2 * MIB,
        4 * MIB,
        16 * MIB,
        64 * MIB,
        128 * MIB,
        256 * MIB,
        512 * MIB,
    ]
}

fn stages(slowdown: f64) -> Vec<StageCurve> {
    let measured = sizes();
    vec![
        curve("read", false, 50e-6, 7e9, slowdown, &measured),
        curve("verify", false, 20e-6, 10e9, slowdown, &measured),
        curve("h2d", true, 10e-6, 25e9, slowdown, &measured),
        // Decode was not measured at 2 MiB.
        curve("decode", false, 30e-6, 40e9, slowdown, &measured[1..]),
    ]
}

const LIMITS: BatchLimits = BatchLimits {
    alignment_bytes: MIB,
    staging_memory_bytes: 1024 * MIB,
    batches_in_memory: 4,
    max_non_preemptible_seconds: 0.008,
};

fn candidates() -> Vec<u64> {
    let mut candidates = vec![MIB + MIB / 2];
    candidates.extend(sizes());
    candidates
}

fn serving() -> ServingCondition {
    let p99 = [
        (2 * MIB, 0.110),
        (4 * MIB, 0.112),
        (16 * MIB, 0.118),
        (64 * MIB, 0.160),
        (128 * MIB, 0.240),
        (256 * MIB, 0.400),
        (512 * MIB, 0.700),
    ];
    ServingCondition::ConcurrentServing(ConcurrentServing::new(&p99, 0.200, 2.0).unwrap())
}

fn rejection(outcomes: &[BatchOutcome], batch: u64) -> Option<&BatchRejection> {
    outcomes.iter().find_map(|outcome| match outcome {
        BatchOutcome::Rejected {
            batch_bytes,
            reason,
        } if *batch_bytes == batch => Some(reason),
        _ => None,
    })
}

#[test]
fn the_search_respects_memory_alignment_and_non_preemptible_limits() {
    let choice = choose_batch_size(
        TOTAL_BYTES,
        &candidates(),
        &stages(1.0),
        &LIMITS,
        &ServingCondition::Idle,
    )
    .unwrap();
    let outcomes = &choice.outcomes;
    assert_eq!(outcomes.len(), 8);
    assert_eq!(
        rejection(outcomes, MIB + MIB / 2),
        Some(&BatchRejection::Misaligned {
            alignment_bytes: MIB
        })
    );
    assert_eq!(
        rejection(outcomes, 2 * MIB),
        Some(&BatchRejection::Unmeasured {
            stage: stage_id("decode")
        })
    );
    assert!(matches!(
        rejection(outcomes, 256 * MIB),
        Some(BatchRejection::NonPreemptibleTooLong { stage, seconds, .. })
            if *stage == stage_id("h2d") && *seconds > 0.008
    ));
    assert_eq!(
        rejection(outcomes, 512 * MIB),
        Some(&BatchRejection::StagingMemory {
            required_bytes: Some(2048 * MIB),
            limit_bytes: 1024 * MIB,
        })
    );
    for outcome in outcomes {
        if let BatchOutcome::Feasible(evaluation) = outcome {
            assert_eq!(evaluation.batch_bytes % LIMITS.alignment_bytes, 0);
            assert!(
                evaluation.batch_bytes * LIMITS.batches_in_memory <= LIMITS.staging_memory_bytes
            );
            let h2d = stages(1.0)[2].seconds_for(evaluation.batch_bytes).unwrap();
            assert!(h2d <= LIMITS.max_non_preemptible_seconds);
            assert_eq!(
                evaluation.batches,
                TOTAL_BYTES.div_ceil(evaluation.batch_bytes)
            );
        }
    }
    assert_eq!(choice.chosen.batch_bytes, 64 * MIB);
    assert!(close(choice.chosen.completion_seconds, 2.0253, 1e-3));
}

#[test]
fn concurrent_serving_penalises_larger_batches_for_p99_ttft() {
    let idle = choose_batch_size(
        TOTAL_BYTES,
        &candidates(),
        &stages(1.0),
        &LIMITS,
        &ServingCondition::Idle,
    )
    .unwrap();
    let serving = choose_batch_size(
        TOTAL_BYTES,
        &candidates(),
        &stages(1.1),
        &LIMITS,
        &serving(),
    )
    .unwrap();
    assert_eq!(idle.chosen.batch_bytes, 64 * MIB);
    assert_eq!(serving.chosen.batch_bytes, 16 * MIB);
    assert_eq!(serving.chosen.p99_ttft_seconds, Some(0.118));
    assert_eq!(idle.chosen.p99_ttft_seconds, None);

    // 64 MiB still moves bytes faster while serving, but its p99 TTFT costs more.
    let feasible = |batch: u64| {
        serving
            .outcomes
            .iter()
            .find_map(|outcome| match outcome {
                BatchOutcome::Feasible(evaluation) if evaluation.batch_bytes == batch => {
                    Some(evaluation.clone())
                }
                _ => None,
            })
            .unwrap()
    };
    assert!(
        feasible(64 * MIB).throughput_bytes_per_second
            > feasible(16 * MIB).throughput_bytes_per_second
    );
    assert!(feasible(64 * MIB).score_seconds > feasible(16 * MIB).score_seconds);
    // 128 MiB is feasible when idle but over the p99 TTFT limit while serving.
    assert_eq!(
        rejection(&serving.outcomes, 128 * MIB),
        Some(&BatchRejection::P99TtftOverLimit {
            p99_ttft_seconds: 0.240,
            limit_seconds: 0.200,
        })
    );
    assert_eq!(rejection(&idle.outcomes, 128 * MIB), None);
}

#[test]
fn serving_impact_must_be_measured_for_each_candidate() {
    let partial = ServingCondition::ConcurrentServing(
        ConcurrentServing::new(&[(64 * MIB, 0.150)], 0.200, 2.0).unwrap(),
    );
    let choice = choose_batch_size(
        TOTAL_BYTES,
        &[16 * MIB, 64 * MIB],
        &stages(1.0),
        &LIMITS,
        &partial,
    )
    .unwrap();
    assert_eq!(
        rejection(&choice.outcomes, 16 * MIB),
        Some(&BatchRejection::ServingImpactUnmeasured)
    );
    assert_eq!(choice.chosen.batch_bytes, 64 * MIB);
}

#[test]
fn no_feasible_batch_reports_every_rejection() {
    let tight = BatchLimits {
        staging_memory_bytes: MIB,
        ..LIMITS
    };
    match choose_batch_size(
        TOTAL_BYTES,
        &[4 * MIB, 16 * MIB],
        &stages(1.0),
        &tight,
        &ServingCondition::Idle,
    ) {
        Err(ChunkingError::NoFeasibleBatch { outcomes }) => {
            assert_eq!(outcomes.len(), 2);
            assert!(outcomes.iter().all(|outcome| matches!(
                outcome,
                BatchOutcome::Rejected {
                    reason: BatchRejection::StagingMemory { .. },
                    ..
                }
            )));
        }
        other => panic!("expected no feasible batch, got {other:?}"),
    }
    let overflow = BatchLimits {
        batches_in_memory: u64::MAX,
        staging_memory_bytes: u64::MAX,
        ..LIMITS
    };
    assert!(matches!(
        choose_batch_size(TOTAL_BYTES, &[4 * MIB], &stages(1.0), &overflow, &ServingCondition::Idle),
        Err(ChunkingError::NoFeasibleBatch { outcomes })
            if matches!(outcomes[0], BatchOutcome::Rejected {
                reason: BatchRejection::StagingMemory { required_bytes: None, .. },
                ..
            })
    ));
}

#[test]
fn search_inputs_are_validated() {
    let idle = ServingCondition::Idle;
    let stages = stages(1.0);
    assert!(choose_batch_size(0, &[4 * MIB], &stages, &LIMITS, &idle).is_err());
    assert!(choose_batch_size(TOTAL_BYTES, &[], &stages, &LIMITS, &idle).is_err());
    assert!(choose_batch_size(TOTAL_BYTES, &[4 * MIB], &[], &LIMITS, &idle).is_err());
    assert_eq!(
        choose_batch_size(TOTAL_BYTES, &[4 * MIB, 4 * MIB], &stages, &LIMITS, &idle),
        Err(ChunkingError::Input(InputError::Duplicate {
            field: "candidates_bytes",
            name: (4 * MIB).to_string(),
        }))
    );
    let twice = vec![stages[0].clone(), stages[0].clone()];
    assert!(choose_batch_size(TOTAL_BYTES, &[4 * MIB], &twice, &LIMITS, &idle).is_err());
    let unaligned = BatchLimits {
        alignment_bytes: 0,
        ..LIMITS
    };
    assert!(choose_batch_size(TOTAL_BYTES, &[4 * MIB], &stages, &unaligned, &idle).is_err());
    let no_buffers = BatchLimits {
        batches_in_memory: 0,
        ..LIMITS
    };
    assert!(choose_batch_size(TOTAL_BYTES, &[4 * MIB], &stages, &no_buffers, &idle).is_err());
    let nan_limit = BatchLimits {
        max_non_preemptible_seconds: f64::NAN,
        ..LIMITS
    };
    assert!(choose_batch_size(TOTAL_BYTES, &[4 * MIB], &stages, &nan_limit, &idle).is_err());

    assert!(StageCurve::new(stage_id("read"), false, &[]).is_err());
    assert!(StageCurve::new(stage_id("read"), false, &[(MIB, 0.0)]).is_err());
    assert!(StageCurve::new(stage_id("read"), false, &[(0, 1.0)]).is_err());
    assert!(StageCurve::new(stage_id("read"), false, &[(MIB, 1.0), (MIB, 2.0)]).is_err());
    assert!(ConcurrentServing::new(&[], 0.2, 1.0).is_err());
    assert!(ConcurrentServing::new(&[(MIB, 0.1)], 0.0, 1.0).is_err());
    assert!(ConcurrentServing::new(&[(MIB, 0.1)], 0.2, -1.0).is_err());
    assert!(ConcurrentServing::new(&[(MIB, 0.1), (MIB, 0.2)], 0.2, 1.0).is_err());
}
