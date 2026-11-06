//! §4.17 claim records: the decision rules, the wording rule, and each experiment's
//! computed decision on the fake substrate.

use crate::foundation::report::{
    BaselineRole, Label, Measured, NotMeasuredReason, Provenance, RunSubstrate,
};

use super::super::claims::*;
use super::super::experiments::{
    distributed_experiment, joint_routing_experiment, replication_experiment, DISTRIBUTED_CLAIM,
    JOINT_ROUTING_CLAIM, REPLICATION_CLAIM,
};
use super::super::fixtures::SyntheticFleet;
use super::evidence::{attempt, setup};
use super::support::*;

fn provenance(fake: bool) -> Provenance {
    let mut record = setup()
        .record(
            &Label::new("candidate").unwrap(),
            &attempt("op-claim", 0, false),
        )
        .unwrap();
    if !fake {
        record.substrate = RunSubstrate::AuthorizedDisposable {
            authorization: Label::new("disposable-test-run").unwrap(),
        };
    }
    Provenance::of_records(&[record]).unwrap()
}

fn outcome(regime: &str, verdict: RegimeVerdict, fake: bool) -> RegimeOutcome {
    RegimeOutcome {
        regime: regime.to_owned(),
        candidate: 1.0,
        strongest_baseline: 1.0,
        strongest_role: BaselineRole::StrongestUpstream,
        verdict,
        provenance: provenance(fake),
    }
}

fn regimes(verdicts: &[RegimeVerdict], fake: bool) -> Vec<RegimeOutcome> {
    verdicts
        .iter()
        .enumerate()
        .map(|(index, verdict)| outcome(&format!("r{index}"), *verdict, fake))
        .collect()
}

use RegimeVerdict::{Loses, Ties, Wins};

#[test]
fn losing_everywhere_rejects_and_losing_somewhere_narrows() {
    assert_eq!(
        decide(&regimes(&[Loses, Loses], true), None),
        Ok(ClaimResult::Rejected {
            lost: vec!["r0".into(), "r1".into()]
        })
    );
    assert_eq!(
        decide(&regimes(&[Wins, Loses, Ties], true), None),
        Ok(ClaimResult::Narrowed {
            kept: vec!["r0".into(), "r2".into()],
            dropped: vec!["r1".into()],
            missing: vec![
                MissingEvidence::HardwareMeasurement,
                MissingEvidence::LiteratureComparison
            ],
        })
    );
    assert_eq!(decide(&[], None), Err(ClaimError::NoComparison));
}

#[test]
fn fake_substrate_evidence_is_at_most_inconclusive_even_with_a_literature_review() {
    assert_eq!(
        decide(&regimes(&[Wins, Wins], true), None),
        Ok(ClaimResult::Inconclusive {
            missing: vec![
                MissingEvidence::HardwareMeasurement,
                MissingEvidence::LiteratureComparison
            ]
        })
    );
    assert_eq!(
        decide(
            &regimes(&[Wins], true),
            Some(LiteratureFinding::DifferenceNotCovered)
        ),
        Ok(ClaimResult::Inconclusive {
            missing: vec![MissingEvidence::HardwareMeasurement]
        })
    );
}

#[test]
fn only_measured_wins_with_a_literature_comparison_support_an_original_contribution() {
    assert_eq!(
        decide(&regimes(&[Wins, Ties], false), None),
        Ok(ClaimResult::Inconclusive {
            missing: vec![MissingEvidence::LiteratureComparison]
        })
    );
    assert_eq!(
        decide(
            &regimes(&[Wins, Ties], false),
            Some(LiteratureFinding::DifferenceNotCovered)
        ),
        Ok(ClaimResult::SupportedOriginalContribution)
    );
    assert_eq!(
        decide(
            &regimes(&[Ties, Ties], false),
            Some(LiteratureFinding::DifferenceNotCovered)
        ),
        Ok(ClaimResult::UsefulIntegration)
    );
    assert_eq!(
        decide(
            &regimes(&[Wins], false),
            Some(LiteratureFinding::PriorArtCoversDifference)
        ),
        Ok(ClaimResult::UsefulIntegration)
    );
}

#[test]
fn a_claim_is_never_worded_first_or_unprecedented() {
    for (contribution, word) in [
        ("The first router that ranks endpoints.", "first"),
        ("An UNPRECEDENTED schedule chooser.", "unprecedented"),
    ] {
        let text = ClaimText {
            contribution,
            ..JOINT_ROUTING_CLAIM
        };
        assert_eq!(
            ClaimRecord::new(
                Experiment::JointRoutingAndPlacement,
                text,
                regimes(&[Wins], true),
                Vec::new(),
                None
            ),
            Err(ClaimError::ForbiddenWord { word })
        );
    }
    let firstly = ClaimText {
        contribution: "Firstly-ordered targets are not the forbidden word.",
        ..JOINT_ROUTING_CLAIM
    };
    assert!(ClaimRecord::new(
        Experiment::JointRoutingAndPlacement,
        firstly,
        regimes(&[Wins], true),
        Vec::new(),
        None
    )
    .is_ok());
    for text in [JOINT_ROUTING_CLAIM, REPLICATION_CLAIM, DISTRIBUTED_CLAIM] {
        assert!(ClaimRecord::new(
            Experiment::TopologyAwareReplication,
            text,
            regimes(&[Ties], true),
            Vec::new(),
            None
        )
        .is_ok());
    }
}

fn verdicts(report: &super::super::experiments::ExperimentReport) -> Vec<RegimeVerdict> {
    report
        .regimes
        .iter()
        .map(|regime| regime.outcome.verdict)
        .collect()
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

const MISSING: [MissingEvidence; 2] = [
    MissingEvidence::HardwareMeasurement,
    MissingEvidence::LiteratureComparison,
];

#[test]
fn joint_routing_is_narrowed_its_hysteresis_loses_a_burst_on_an_overloaded_ready_gpu() {
    let synthetic = SyntheticFleet::new().unwrap();
    let authority = authority(&synthetic);
    let report = joint_routing_experiment(7, &authority.authority).unwrap();
    assert_eq!(verdicts(&report), vec![Loses, Ties, Ties]);
    assert_eq!(
        report.claim.result,
        ClaimResult::Narrowed {
            kept: names(&[
                "briefly-busy-ready-vs-idle-cold",
                "long-context-session-on-busy-home"
            ]),
            dropped: names(&["overloaded-ready-vs-idle-cold"]),
            missing: MISSING.to_vec(),
        }
    );
    // Against the startup-time baseline the router wins both kept regimes; the ordinary
    // workflow ties it there, so the strongest baseline per regime is the ordinary one.
    assert_eq!(
        report.regimes[1].outcome.strongest_role,
        BaselineRole::OrdinaryWorkflow
    );
    assert_eq!(
        report.claim.hardware_result,
        Measured::not_measured(NotMeasuredReason::InstrumentUnavailable)
    );
    assert_eq!(report.claim.text.closest_prior_work.name, "ServerlessLLM");
}

#[test]
fn topology_aware_replication_is_inconclusive_it_wins_two_regimes_and_ties_two() {
    let report = replication_experiment(11).unwrap();
    assert_eq!(verdicts(&report), vec![Ties, Wins, Wins, Ties]);
    assert_eq!(
        report.claim.result,
        ClaimResult::Inconclusive {
            missing: MISSING.to_vec()
        }
    );
    assert_eq!(report.claim.gated.len(), 4);
    assert_eq!(report.claim.text.closest_prior_work.name, "FlashBoot");
    // Independent sources tie: 4.5% ahead of the chain, inside the 5% band.
    let independent = &report.regimes[3].outcome;
    let gain = 1.0 - independent.candidate / independent.strongest_baseline;
    assert!(gain > 0.0 && gain < super::super::experiments::TIE_TOLERANCE);
}

#[test]
fn temporary_distributed_execution_is_narrowed_to_a_fast_lan_with_an_overloaded_donor() {
    let report = distributed_experiment(13).unwrap();
    assert_eq!(verdicts(&report), vec![Wins, Loses, Loses]);
    assert_eq!(
        report.claim.result,
        ClaimResult::Narrowed {
            kept: names(&["fast-lan-overloaded-donor"]),
            dropped: names(&["slow-lan-long-prompts", "idle-donor"]),
            missing: MISSING.to_vec(),
        }
    );
    assert_eq!(
        report.regimes[2].outcome.strongest_role,
        BaselineRole::StrongestUpstream
    );
    assert_eq!(report.claim.text.closest_prior_work.name, "λScale");
    // Seeded: the same seed reproduces the same report.
    assert_eq!(report, distributed_experiment(13).unwrap());
}

#[test]
fn a_regime_outcome_needs_a_valid_tolerance() {
    let synthetic = SyntheticFleet::new().unwrap();
    let report = super::super::experiments::run_window_regime(
        &super::super::experiments::WINDOW_REGIMES[0],
        3,
    )
    .unwrap();
    assert_eq!(
        regime_outcome("x", &report.report, -0.1),
        Err(ClaimError::InvalidTolerance)
    );
    let strict = regime_outcome("x", &report.report, 0.0).unwrap();
    assert_eq!(strict.verdict, Wins);
    assert_eq!(synthetic.epoch.get(), 1);
}
