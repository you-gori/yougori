//! The pass/stop rule of line 900 and the §4.17 claim record.

use super::*;
use crate::foundation::ids::Digest;

fn minimum() -> MinimumIncidence {
    MinimumIncidence::new(0.05).unwrap()
}

#[test]
fn incidence_is_judged_against_the_configured_minimum_without_rounding() {
    let judge =
        |eligible, total| judge_incidence(&Incidence::new(eligible, total).unwrap(), minimum());
    assert_eq!(judge(4, 100), IncidenceVerdict::Rare);
    assert_eq!(judge(5, 100), IncidenceVerdict::Common);
    assert_eq!(judge(30, 100), IncidenceVerdict::Common);
    assert_eq!(judge(0, 1), IncidenceVerdict::Rare);
    assert_eq!(judge(1, 20), IncidenceVerdict::Common);
    assert_eq!(judge(1, 21), IncidenceVerdict::Rare);
    assert!((Incidence::new(3, 12).unwrap().fraction() - 0.25).abs() < 1e-12);
    assert_eq!(
        Incidence::new(0, 0).unwrap_err(),
        DecisionError::InvalidIncidence {
            eligible: 0,
            total: 0
        }
    );
    assert!(Incidence::new(5, 4).is_err());
    for invalid in [0.0, -0.1, 1.5, f64::NAN] {
        assert_eq!(
            MinimumIncidence::new(invalid).unwrap_err(),
            DecisionError::InvalidMinimumIncidence
        );
    }
    assert_eq!(MinimumIncidence::new(1.0).unwrap().get(), 1.0);
}

fn prototype_outcome() -> PrototypeOutcome {
    run_prototype(
        &WorkloadConfig {
            requests_per_trial: 12,
            ..WorkloadConfig::reference(21)
        },
        scope(),
    )
    .unwrap()
}

#[test]
fn the_prototype_remains_optional_and_its_claim_is_inconclusive() {
    let outcome = prototype_outcome();
    let (evidence, provenance) = outcome.pass_stop_evidence(minimum()).unwrap();
    assert!(provenance.is_fake_substrate());
    assert_eq!(evidence.exactness_violations, 0);
    assert_eq!(evidence.unauthorized_reuses, 0);
    assert!(evidence.net_saving_seconds > 0.0);
    assert_eq!(evidence.workload, WorkloadSource::Synthetic { seed: 21 });
    let (decision, record) = outcome
        .decide(minimum(), LiteratureComparison::NotDone)
        .unwrap();
    assert!(matches!(
        decision,
        PassStopDecision::RemainOptional {
            missing_workload: true,
            missing_measurement: true,
            incidence_verdict: IncidenceVerdict::Common,
        }
    ));
    assert_eq!(
        record.result,
        ClaimResult::Inconclusive {
            missing: vec![
                MissingEvidence::RealisticWorkload,
                MissingEvidence::HardwareMeasurement,
                MissingEvidence::LiteratureComparison,
            ]
        }
    );
    // A literature comparison alone cannot lift a fake run above inconclusive.
    let (_, record) = outcome
        .decide(
            minimum(),
            LiteratureComparison::DifferenceDemonstrated {
                comparison: Digest::from_bytes([4; 32]),
            },
        )
        .unwrap();
    assert!(matches!(record.result, ClaimResult::Inconclusive { .. }));
}

#[test]
fn rare_eligible_prefixes_in_a_recorded_workload_narrow_support_to_explicit_families() {
    let outcome = prototype_outcome();
    let (mut evidence, provenance) = outcome.pass_stop_evidence(minimum()).unwrap();
    evidence.workload = WorkloadSource::Recorded {
        trace: Digest::from_bytes([3; 32]),
    };
    evidence.incidence = Incidence::new(2, 100).unwrap();
    let decision = decide_pass_stop(&evidence, &provenance).unwrap();
    assert_eq!(
        decision,
        PassStopDecision::NarrowToExplicitFamilies {
            incidence: Incidence::new(2, 100).unwrap()
        }
    );
    assert_eq!(
        claim_result(&decision, LiteratureComparison::NotDone),
        ClaimResult::Narrowed {
            incidence: Incidence::new(2, 100).unwrap()
        }
    );
    // Common prefixes in a recorded workload still need measurements to pass.
    evidence.incidence = Incidence::new(20, 100).unwrap();
    assert_eq!(
        decide_pass_stop(&evidence, &provenance).unwrap().missing(),
        vec![MissingEvidence::HardwareMeasurement]
    );
}

#[test]
fn a_failed_check_stops_the_mechanism_even_on_fakes() {
    let outcome = prototype_outcome();
    let (evidence, provenance) = outcome.pass_stop_evidence(minimum()).unwrap();
    let decide = |edit: &dyn Fn(&mut PassStopEvidence)| {
        let mut changed = evidence;
        edit(&mut changed);
        decide_pass_stop(&changed, &provenance).unwrap()
    };
    assert_eq!(
        decide(&|e| e.exactness_violations = 1),
        PassStopDecision::Stop(StopReason::ExactnessViolated { violations: 1 })
    );
    assert_eq!(
        decide(&|e| e.unauthorized_reuses = 2),
        PassStopDecision::Stop(StopReason::UnauthorizedSharing { reuses: 2 })
    );
    assert_eq!(
        decide(&|e| e.net_saving_seconds = 0.0),
        PassStopDecision::Stop(StopReason::NoNetSaving {
            net_saving_seconds: 0.0
        })
    );
    assert!(matches!(
        claim_result(
            &decide(&|e| e.net_saving_seconds = -1.0),
            LiteratureComparison::NotDone
        ),
        ClaimResult::Rejected(StopReason::NoNetSaving { .. })
    ));
    let mut broken = evidence;
    broken.net_saving_seconds = f64::INFINITY;
    assert_eq!(
        decide_pass_stop(&broken, &provenance).unwrap_err(),
        DecisionError::NetSavingNotFinite
    );
}

#[test]
fn a_mechanism_that_loses_to_its_baseline_on_fakes_is_rejected() {
    // Keying so expensive that no boundary is ever profitable: the candidate still pays
    // its lookups and loses to per-model prefix caching.
    let mut losing = family(PrototypePair::VerifiedSharedPrefix);
    losing.handoff.keying_seconds = 1.0;
    let config = WorkloadConfig {
        requests_per_trial: 12,
        ..WorkloadConfig::reference(21)
    };
    let verified = run_pair(&losing, &config).unwrap();
    assert!(verified.net_saving_seconds < 0.0);
    assert_eq!(verified.incidence.eligible_requests(), 0);
    let outcome = PrototypeOutcome {
        pairs: vec![verified],
        workload: WorkloadSource::Synthetic { seed: 21 },
    };
    let (decision, record) = outcome
        .decide(minimum(), LiteratureComparison::NotDone)
        .unwrap();
    assert!(matches!(
        decision,
        PassStopDecision::Stop(StopReason::NoNetSaving { .. })
    ));
    assert!(matches!(
        record.result,
        ClaimResult::Rejected(StopReason::NoNetSaving { .. })
    ));
}

#[test]
fn the_claim_record_names_its_prior_work_and_claims_no_priority() {
    let record = claim_record(ClaimResult::Inconclusive {
        missing: vec![MissingEvidence::LiteratureComparison],
    });
    for text in [
        record.contribution,
        record.closest_prior_work,
        record.difference_tested,
        record.smallest_counterexample,
        record.comparison,
    ] {
        assert!(!text.to_lowercase().contains("unprecedented"), "{text}");
        assert!(!text.is_empty());
    }
    assert!(!record.contribution.to_lowercase().contains("first"));
    assert!(record.closest_prior_work.contains("Mainstream"));
    assert!(record.comparison.contains("per-model prefix caching"));
    assert!(record.smallest_counterexample.contains("batch"));
    assert_eq!(record.assumptions.len(), 3);
}
