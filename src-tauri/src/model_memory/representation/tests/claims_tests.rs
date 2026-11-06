//! Claim records: wording, the outcome table and the evidence requirement.

use super::super::claims::*;
use crate::foundation::report::{
    Measured, NonNegative, NotMeasuredReason, Provenance, RunRecord, RunSubstrate,
    RUN_RECORD_SAMPLE_JSON,
};

/// Decoder or loader interference with active inference needs hardware.
pub(super) fn interference_not_measured() -> Measured<NonNegative> {
    Measured::not_measured(NotMeasuredReason::InstrumentUnavailable)
}

pub(super) fn fake_provenance() -> Provenance {
    let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    record.substrate = RunSubstrate::FakeTimeControlled;
    Provenance::of_records(&[record]).unwrap()
}

fn comparison(workload: &str, candidate: f64, baseline: f64) -> WorkloadComparison {
    WorkloadComparison::lower_is_better(workload, "seconds", candidate, baseline, "baseline")
}

#[test]
fn contributions_never_claim_priority() {
    for text in [
        DIFFERENTIAL_CLAIM,
        DELTA_CLAIM,
        SELECTION_CLAIM,
        POLICY_CLAIM,
    ] {
        assert_eq!(text.check(), Ok(()), "{}", text.clause);
        assert!(!text.closest_prior_work.is_empty());
        assert!(!text.assumptions.is_empty());
        assert!(!text.smallest_counterexample.is_empty());
        assert!(!text.required_infrastructure.is_empty());
        assert!(!text.pass_stop_rule.is_empty());
    }
    for word in ["First", "UNPRECEDENTED"] {
        let text = ClaimText {
            contribution: if word == "First" {
                "The First loader of its kind."
            } else {
                "An UNPRECEDENTED loader."
            },
            ..DIFFERENTIAL_CLAIM
        };
        assert!(matches!(
            text.check(),
            Err(ClaimError::ForbiddenWord { .. })
        ));
    }
    // A word that merely contains "first" is fine.
    let text = ClaimText {
        contribution: "Firstly-named sections are not priority claims.",
        ..DIFFERENTIAL_CLAIM
    };
    assert_eq!(text.check(), Ok(()));
}

#[test]
fn the_outcome_is_computed_from_the_comparisons_and_capped_at_inconclusive() {
    let provenance = fake_provenance();
    let decide = |comparisons| {
        ClaimRecord::decide(
            DIFFERENTIAL_CLAIM,
            comparisons,
            &provenance,
            interference_not_measured(),
        )
        .unwrap()
        .result
    };
    assert_eq!(
        decide(vec![comparison("a", 1.0, 2.0), comparison("b", 2.0, 2.0)]),
        ClaimOutcome::Inconclusive
    );
    assert_eq!(
        decide(vec![comparison("a", 1.0, 2.0), comparison("b", 3.0, 2.0)]),
        ClaimOutcome::Narrowed
    );
    assert_eq!(
        decide(vec![comparison("a", 3.0, 2.0), comparison("b", 2.0, 2.0)]),
        ClaimOutcome::Rejected
    );
    let record = ClaimRecord::decide(
        DIFFERENTIAL_CLAIM,
        vec![comparison("kept", 1.0, 2.0), comparison("lost", 3.0, 2.0)],
        &provenance,
        interference_not_measured(),
    )
    .unwrap();
    assert_eq!(record.kept_workloads(), vec!["kept"]);
    assert!(record.provenance.contains("not a Yougori measurement"));
    assert!(!record.interference_seconds.is_measured());
    assert_eq!(
        ClaimRecord::decide(
            DIFFERENTIAL_CLAIM,
            Vec::new(),
            &provenance,
            interference_not_measured()
        ),
        Err(ClaimError::NoComparisons)
    );
    assert!(matches!(
        ClaimRecord::decide(
            DIFFERENTIAL_CLAIM,
            vec![comparison("nan", f64::NAN, 1.0)],
            &provenance,
            interference_not_measured()
        ),
        Err(ClaimError::NotFinite { .. })
    ));
}
