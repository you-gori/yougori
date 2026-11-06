//! §4.6 line 718: the two simulated runners, under the three policies.

use super::super::experiments::{routing_policy, routing_regimes, TRIAL_SPREAD_PPM};
use super::super::fixtures::SyntheticFleet;
use super::super::runners::*;
use super::support::*;

fn worst_first_token(served: &[ServedRequest]) -> f64 {
    served
        .iter()
        .map(|request| request.first_token_seconds - request.arrival_seconds)
        .fold(0.0, f64::max)
}

#[test]
fn trial_conditions_are_seeded_and_shared_by_every_policy() {
    let first = TrialConditions::draw(2, 2, 7, TRIAL_SPREAD_PPM).unwrap();
    assert_eq!(
        first,
        TrialConditions::draw(2, 2, 7, TRIAL_SPREAD_PPM).unwrap()
    );
    assert_ne!(
        first,
        TrialConditions::draw(3, 2, 7, TRIAL_SPREAD_PPM).unwrap()
    );
    for factor in first.load_factor.iter().chain(&first.compute_factor) {
        assert!((0.95..=1.05).contains(factor));
    }
    assert!(TrialConditions::draw(0, 2, 7, 1_000_000).is_err());
}

#[test]
fn on_two_simulated_runners_an_overloaded_ready_gpu_loses_to_a_cold_idle_one() {
    let synthetic = SyntheticFleet::new().unwrap();
    let authority = authority(&synthetic);
    let regimes = routing_regimes(&synthetic, &authority.authority).unwrap();
    let (_, fleet, trace, _) = &regimes[0];
    let conditions = TrialConditions::draw(0, 2, 7, 0).unwrap();
    let joint = simulate(
        fleet,
        trace,
        &SimPolicy::Joint(routing_policy().unwrap()),
        &conditions,
    )
    .unwrap();
    let ready = simulate(fleet, trace, &SimPolicy::RouteToReady, &conditions).unwrap();
    // The first request goes to the cold idle runner and waits for its 2.8 s load.
    assert_eq!(joint[0].runner, 1);
    let load = joint[0].demand_load.unwrap();
    assert_close(load.completed_seconds - load.started_seconds, 2.8);
    assert_eq!(joint[0].storage_read_bytes, 14_000_000_000);
    // Sticking to the ready runner queues every request behind its 8 s backlog.
    assert!(ready.iter().all(|request| request.runner == 0));
    assert_close(ready[0].first_token_seconds, 8.0 + 0.125 + 0.02);
    assert!(worst_first_token(&joint) < worst_first_token(&ready));
}

#[test]
fn a_session_continuation_stays_home_under_the_router_and_moves_under_the_startup_baseline() {
    let synthetic = SyntheticFleet::new().unwrap();
    let authority = authority(&synthetic);
    let regimes = routing_regimes(&synthetic, &authority.authority).unwrap();
    let (_, fleet, trace, _) = &regimes[2];
    let conditions = TrialConditions::draw(0, 2, 7, 0).unwrap();
    let joint = simulate(
        fleet,
        trace,
        &SimPolicy::Joint(routing_policy().unwrap()),
        &conditions,
    )
    .unwrap();
    assert_eq!(joint[0].runner, 0);
    assert_eq!(joint[0].migration, None);
    let startup = simulate(fleet, trace, &SimPolicy::LocalityStartup, &conditions).unwrap();
    assert_eq!(startup[0].runner, 1);
    assert_eq!(
        startup[0].migration,
        Some(super::super::joint::MigrationMechanism::TokenReconstruction)
    );
    // 131,072 tokens recomputed at 8,000 tokens/s before the turn's own prefill.
    assert!(startup[0].first_token_seconds > 16.384);
    assert!(joint[0].first_token_seconds < 6.2);
}
