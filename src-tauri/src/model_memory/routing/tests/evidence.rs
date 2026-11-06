//! Simulated results are CORE-08 records on the fake substrate: they validate schemas and
//! comparisons and back no improvement or release claim.

use crate::foundation::ids::OperationId;
use crate::foundation::report::{
    AttemptLedger, BaselineRole, CacheTier, ColdProvenance, FixtureFamily, ImprovementClaim, Label,
    ModelAtArrival, PrefillMode, Provenance, ReportError, RunSubstrate, StartState,
    StartTemperature,
};

use super::super::error::RoutingError;
use super::super::evidence::*;

pub(super) fn setup() -> FakeRunSetup {
    FakeRunSetup {
        experiment: Label::new("gpu-4-6-test").unwrap(),
        trace: Label::new("test-trace").unwrap(),
        family: FixtureFamily::Prose,
        max_output_tokens: 60,
        concurrent_requests: 1,
    }
}

fn hot() -> StartState {
    StartState {
        temperature: StartTemperature::Hot,
        model_at_arrival: ModelAtArrival::ReadyToServe,
        cache_tier: CacheTier::NoReusableState,
        prefill: PrefillMode::Fresh,
        cold_provenance: ColdProvenance::NotCold,
    }
}

fn warm() -> StartState {
    StartState {
        temperature: StartTemperature::Warm,
        model_at_arrival: ModelAtArrival::NotLoaded,
        cache_tier: CacheTier::LocalDisk,
        prefill: PrefillMode::Fresh,
        cold_provenance: ColdProvenance::NotCold,
    }
}

/// A served request: hot, or warm after a load from 0 to 2.8 s.
pub(super) fn attempt(name: &str, trial: u32, loaded: bool) -> SimulatedAttempt {
    SimulatedAttempt {
        operation: OperationId::new(name).unwrap(),
        trial,
        input_tokens: 1_000,
        arrival_seconds: 0.0,
        demand_load: loaded.then_some(DemandLoad {
            started_seconds: 0.0,
            completed_seconds: 2.8,
        }),
        service_start_seconds: if loaded { 2.8 } else { 0.5 },
        first_token_seconds: if loaded { 2.945 } else { 0.645 },
        completion_seconds: if loaded { 4.445 } else { 2.145 },
        state: if loaded { warm() } else { hot() },
        transferred_bytes: 0,
        storage_read_bytes: if loaded { 14_000_000_000 } else { 0 },
    }
}

#[test]
fn a_simulated_request_is_a_valid_record_on_the_fake_substrate() {
    let policy = Label::new("joint-router").unwrap();
    let record = setup().record(&policy, &attempt("op-a", 0, true)).unwrap();
    record.validate().unwrap();
    assert_eq!(record.substrate, RunSubstrate::FakeTimeControlled);
    let provenance = Provenance::of_records(&[record]).unwrap();
    assert!(provenance.is_fake_substrate());
    assert_eq!(
        provenance.yougori_evidence(),
        Err(ReportError::FakeSubstrateIsNotEvidence)
    );
    assert!(provenance.comparable_evidence().is_ok());
}

#[test]
fn start_temperatures_stay_in_separate_ledgers_and_the_side_pools_their_samples() {
    let policy = Label::new("joint-router").unwrap();
    let records = vec![
        setup().record(&policy, &attempt("op-a", 0, true)).unwrap(),
        setup().record(&policy, &attempt("op-b", 1, false)).unwrap(),
    ];
    assert_eq!(
        AttemptLedger::from_records(records.clone()).unwrap_err(),
        ReportError::MixedCases
    );
    let side = fake_side(
        "joint-router",
        &records,
        StartTemperature::Hot,
        crate::foundation::report::Quantile::P95,
    )
    .unwrap();
    // Nearest-rank p95 of {0.645 s, 2.945 s} is the slower one.
    assert_eq!(
        side.objectives
            .time_to_first_token_nanos
            .value()
            .map(|value| value.get()),
        Some(2_945_000_000.0)
    );
    assert!(side.provenance.is_fake_substrate());
}

#[test]
fn record_times_are_checked() {
    assert_eq!(
        trial_time("arrival_seconds", -1.0),
        Err(RoutingError::TimeOutOfRange {
            field: "arrival_seconds"
        })
    );
    assert!(trial_time("arrival_seconds", f64::NAN).is_err());
    assert!(trial_time("arrival_seconds", 1e12).is_err());
    assert_eq!(
        trial_time("arrival_seconds", 1.5).unwrap().as_nanos(),
        TRIAL_ORIGIN_NANOS + 1_500_000_000
    );
}

#[test]
fn a_fake_comparison_validates_but_backs_no_improvement_claim() {
    let synthetic = super::super::fixtures::SyntheticFleet::new().unwrap();
    let authority = super::support::authority(&synthetic);
    let report =
        super::super::experiments::joint_routing_experiment(7, &authority.authority).unwrap();
    for regime in &report.regimes {
        assert!(regime.report.candidate().provenance.is_fake_substrate());
        for role in [
            BaselineRole::OrdinaryWorkflow,
            BaselineRole::StrongestUpstream,
        ] {
            assert_eq!(
                ImprovementClaim::from_report(&regime.report, role).unwrap_err(),
                ReportError::FakeSubstrateIsNotEvidence
            );
        }
    }
}
