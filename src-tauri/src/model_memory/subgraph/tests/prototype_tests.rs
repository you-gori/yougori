//! The first prototype of line 898 on the fake substrate, recorded through CORE-08 with
//! fake-substrate provenance (S12 G0).

use std::sync::OnceLock;

use super::*;
use crate::foundation::report::{
    BaselineOutcome, BaselineRole, ImprovementClaim, ReportError, RunSubstrate, VerdictStatus,
};

fn outcome() -> &'static PrototypeOutcome {
    static OUTCOME: OnceLock<PrototypeOutcome> = OnceLock::new();
    OUTCOME.get_or_init(|| run_prototype(&WorkloadConfig::reference(11), scope()).unwrap())
}

fn pair(pair: PrototypePair) -> &'static PairOutcome {
    outcome().pair(pair).unwrap()
}

fn compute(outcome: &PairOutcome, strategy: Strategy) -> f64 {
    outcome.run(strategy).unwrap().compute_seconds
}

fn verdict(baseline: &BaselineOutcome) -> &crate::foundation::report::Verdict {
    match baseline {
        BaselineOutcome::Compared { verdict, .. } => verdict,
        BaselineOutcome::Unavailable { .. } => panic!("the baseline was measured"),
    }
}

#[test]
fn the_verified_pair_saves_compute_after_keying_and_lookup_costs() {
    let verified = pair(PrototypePair::VerifiedSharedPrefix);
    assert_eq!(verified.shared_operators, 6);
    let independent = compute(verified, Strategy::IndependentExecution);
    let per_model = compute(verified, Strategy::PerModelPrefixCaching);
    let candidate = compute(verified, Strategy::VerifiedSharedSubgraph);
    assert!(per_model < independent);
    assert!(candidate < per_model);
    assert!(verified.net_saving_seconds > 0.0);
    assert!((verified.net_saving_seconds - (per_model - candidate)).abs() < 1e-12);
    assert!(verified.incidence.eligible_requests() > 0);
    assert_eq!(
        verified.incidence.total_requests(),
        verified
            .run(Strategy::VerifiedSharedSubgraph)
            .unwrap()
            .attempts
    );
    assert_eq!(verified.exactness_violations(), 0);
    assert_eq!(verified.unauthorized_reuses(), 0);
    // Only the candidate reuses across variants.
    for strategy in [
        Strategy::IndependentExecution,
        Strategy::PerModelPrefixCaching,
    ] {
        assert_eq!(verified.run(strategy).unwrap().eligible_attempts, 0);
    }
}

#[test]
fn the_control_pairs_share_nothing_and_save_nothing() {
    for control in [
        PrototypePair::ControlFirstBlockDiffers,
        PrototypePair::EqualWeightsDifferentPositions,
    ] {
        let outcome = pair(control);
        assert_eq!(outcome.shared_operators, 0, "{control:?}");
        assert_eq!(outcome.incidence.eligible_requests(), 0);
        assert_eq!(outcome.net_saving_seconds, 0.0);
        assert_eq!(
            compute(outcome, Strategy::VerifiedSharedSubgraph),
            compute(outcome, Strategy::PerModelPrefixCaching)
        );
        assert_eq!(outcome.exactness_violations(), 0);
        assert_eq!(
            verdict(outcome.report.strongest_upstream()).status,
            VerdictStatus::NotImproved
        );
    }
}

#[test]
fn every_attempt_is_a_fake_substrate_record_and_backs_no_claim() {
    for outcome in &outcome().pairs {
        for run in &outcome.runs {
            assert_eq!(run.records.len() as u64, run.attempts);
            assert!(run
                .records
                .iter()
                .all(|record| record.substrate == RunSubstrate::FakeTimeControlled));
            assert!(run.records.iter().all(|record| record.validate().is_ok()));
            assert!(run
                .records
                .iter()
                .all(|record| record.attempt.burst < 5 && record.is_success()));
        }
        let report = &outcome.report;
        assert!(report.candidate().provenance.is_fake_substrate());
        assert_eq!(
            report
                .candidate()
                .provenance
                .yougori_evidence()
                .unwrap_err(),
            ReportError::FakeSubstrateIsNotEvidence
        );
        for role in [
            BaselineRole::OrdinaryWorkflow,
            BaselineRole::StrongestUpstream,
        ] {
            assert_eq!(
                ImprovementClaim::from_report(report, role).unwrap_err(),
                ReportError::FakeSubstrateIsNotEvidence
            );
        }
    }
}

#[test]
fn the_comparison_report_judges_first_token_time_against_both_baselines() {
    let verified = pair(PrototypePair::VerifiedSharedPrefix);
    let upstream = verdict(verified.report.strongest_upstream());
    let ordinary = verdict(verified.report.ordinary_workflow());
    assert!(upstream.declared.candidate < upstream.declared.baseline);
    assert!(ordinary.declared.candidate < ordinary.declared.baseline);
    assert!(ordinary.declared.baseline >= upstream.declared.baseline);
    // Retained boundary states cost fake cache memory beyond per-model caching; the
    // verdict reports that rather than hiding it.
    let candidate = verified.run(Strategy::VerifiedSharedSubgraph).unwrap();
    let per_model = verified.run(Strategy::PerModelPrefixCaching).unwrap();
    assert!(candidate.peak_cache_bytes > per_model.peak_cache_bytes);
    assert_eq!(
        verified
            .run(Strategy::IndependentExecution)
            .unwrap()
            .peak_cache_bytes,
        0
    );
    assert_ne!(upstream.status, VerdictStatus::Improved);
}

#[test]
fn the_prototype_is_reproducible_from_its_seed() {
    let config = WorkloadConfig {
        trials: 5,
        requests_per_trial: 6,
        ..WorkloadConfig::reference(5)
    };
    let family = family(PrototypePair::VerifiedSharedPrefix);
    let first = run_pair(&family, &config).unwrap();
    assert_eq!(first, run_pair(&family, &config).unwrap());
    let other = run_pair(&family, &WorkloadConfig { seed: 6, ..config }).unwrap();
    assert_ne!(first.runs, other.runs);
}

#[test]
fn another_tenant_never_reuses_state_it_holds_no_grant_for() {
    let config = WorkloadConfig {
        repeat_probability: 0.6,
        second_tenant_probability: 0.5,
        ..WorkloadConfig::reference(3)
    };
    let outcome = run_pair(&family(PrototypePair::VerifiedSharedPrefix), &config).unwrap();
    let candidate = outcome.run(Strategy::VerifiedSharedSubgraph).unwrap();
    assert!(candidate.cross_tenant_refusals > 0);
    assert_eq!(candidate.unauthorized_reuses, 0);
    assert_eq!(candidate.exactness_violations, 0);
}

#[test]
fn invalid_workloads_and_too_few_trials_are_refused() {
    let family = family(PrototypePair::VerifiedSharedPrefix);
    let reference = WorkloadConfig::reference(1);
    for (field, config) in [
        (
            "trials",
            WorkloadConfig {
                trials: 0,
                ..reference
            },
        ),
        (
            "fan_out_probability",
            WorkloadConfig {
                fan_out_probability: 1.5,
                ..reference
            },
        ),
        (
            "min_tokens",
            WorkloadConfig {
                min_tokens: 0,
                ..reference
            },
        ),
        (
            "jitter_fraction",
            WorkloadConfig {
                jitter_fraction: f64::NAN,
                ..reference
            },
        ),
    ] {
        assert_eq!(
            run_pair(&family, &config).unwrap_err(),
            PrototypeError::InvalidWorkload { field }
        );
    }
    assert!(matches!(
        run_pair(
            &family,
            &WorkloadConfig {
                arrival_interval_seconds: 1e-9,
                ..reference
            }
        )
        .unwrap_err(),
        PrototypeError::ServerBusy { trial: 0, .. }
    ));
    // CORE-08 compares only five or more independent trials.
    assert!(matches!(
        run_pair(
            &family,
            &WorkloadConfig {
                trials: 3,
                requests_per_trial: 4,
                ..reference
            }
        )
        .unwrap_err(),
        PrototypeError::Report(ReportError::TooFewTrials { trials: 3, .. })
    ));
}

#[test]
fn the_documented_fake_numbers_are_reproduced() {
    // Seed 11, reference workload: the numbers quoted in the module's claim record. They
    // come from the fake substrate and are not measurements.
    let verified = pair(PrototypePair::VerifiedSharedPrefix);
    let close = |left: f64, right: f64| (left - right).abs() < 1e-6;
    assert!(close(
        compute(verified, Strategy::IndependentExecution),
        2.807219
    ));
    assert!(close(
        compute(verified, Strategy::PerModelPrefixCaching),
        2.551277
    ));
    assert!(close(
        compute(verified, Strategy::VerifiedSharedSubgraph),
        1.812756
    ));
    assert_eq!(
        (
            verified.incidence.eligible_requests(),
            verified.incidence.total_requests()
        ),
        (57, 177)
    );
    let upstream = verdict(verified.report.strongest_upstream());
    assert_eq!(upstream.declared.baseline, 19_712_205.0);
    assert_eq!(upstream.declared.candidate, 14_841_358.0);
    assert_eq!(upstream.status, VerdictStatus::ImprovedWithRegressions);
    assert_eq!(
        upstream
            .regressions
            .iter()
            .map(|change| change.objective)
            .collect::<Vec<_>>(),
        vec![
            crate::foundation::report::Objective::PeakGpuMemory,
            crate::foundation::report::Objective::RetainedGpuMemory
        ]
    );
}
