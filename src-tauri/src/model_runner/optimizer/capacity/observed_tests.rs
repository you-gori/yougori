//! The runner's own usage reports recorded on its grant (S03: observed allocations).
use super::*;

#[test]
fn a_granted_runners_report_is_recorded_on_its_placement_reservation_as_a_guest_report() {
    let (sample, mut account) = test_accounting();
    account
        .settle_and_admit(&sample, "model-a", Some(Demand::vllm(8 << 30)))
        .unwrap();
    let child = account.grants["model-a"].child;
    // Before any report the reservation carries no observation.
    assert!(account
        .ledger
        .lock()
        .unwrap()
        .reservation(child)
        .unwrap()
        .observations()
        .is_empty());
    assert!(account.observe_runner_usage("model-a", 5 << 30).unwrap());
    assert!(account.observe_runner_usage("model-a", 6 << 30).unwrap());
    {
        let ledger = account.ledger.lock().unwrap();
        let record = ledger.reservation(child).unwrap();
        // Only the latest report per source class is kept; nothing reserved changed.
        let observations = record.observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].source, SourceClass::GuestReport);
        assert_eq!(
            observations[0].in_use.get(ResourceKey::vram(sample.device)),
            6 << 30
        );
        assert_eq!(
            ledger.reserved(ResourceKey::vram(sample.device)),
            Demand::vllm(8 << 30).reserved(sample.total)
        );
    }
    // A model without a grant has nowhere to record; the report is not an error.
    assert!(!account.observe_runner_usage("model-b", 1).unwrap());
    // A settle that releases every grant forgets where to record.
    account
        .settle_and_admit(&sample, "idle-reconciliation", None)
        .unwrap();
    assert!(account.grants.is_empty());
    assert!(!account.observe_runner_usage("model-a", 1).unwrap());
}

#[test]
fn nothing_is_recorded_before_the_engines_accounting_exists() {
    // The engine's host accounting is created by the first grant; an observation never
    // creates it. Another test in this binary may have created it, so only the "no grant"
    // answer is asserted.
    assert_eq!(local_observe_usage("never-granted-model", 1), Ok(false));
}
