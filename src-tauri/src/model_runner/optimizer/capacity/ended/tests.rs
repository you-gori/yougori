use super::*;
use crate::model_runner::optimizer::capacity::coadmit_tests::{kept, no_facts, none, transformers};
use crate::model_runner::optimizer::capacity::tests::{sample, world, GIB};

#[test]
fn an_acknowledged_end_releases_its_parent_and_child_without_options_or_a_marker() {
    let before = sample(GIB);
    let (_, mut account) = world(&before);
    account
        .settle_and_admit(&before, "deleted", Some(transformers(8 * GIB)))
        .unwrap();
    let receipt = account.capture_end("deleted").unwrap();
    account.confirm_end(receipt);
    assert_eq!(
        account.ledger.lock().unwrap().open_reservations().count(),
        2,
        "a runtime acknowledgment alone does not reclaim memory"
    );
    account.reconcile_ends(&sample(GIB)).unwrap();
    assert!(account.grants.is_empty());
    assert!(account.roots.is_empty());
    assert!(account.ended.is_empty());
    assert_eq!(
        account.ledger.lock().unwrap().open_reservations().count(),
        0
    );
    account.reconcile_ends(&sample(GIB)).unwrap(); // Idempotent without any metadata.
}

#[test]
fn capture_and_a_failed_or_cancelled_runtime_end_release_nothing() {
    let s = sample(GIB);
    let (_, mut account) = world(&s);
    account
        .settle_and_admit(&s, "model", Some(transformers(8 * GIB)))
        .unwrap();
    drop(account.capture_end("model"));
    account.reconcile_ends(&sample(GIB)).unwrap();
    assert!(account.grants.contains_key("model"));
    assert_eq!(
        account.ledger.lock().unwrap().open_reservations().count(),
        2
    );
}

#[test]
fn a_receipt_cannot_release_a_replacement_grant_for_the_same_environment() {
    let s = sample(GIB);
    let (_, mut account) = world(&s);
    account
        .settle_and_admit(&s, "model", Some(transformers(8 * GIB)))
        .unwrap();
    let old = account.capture_end("model").unwrap();
    account
        .settle_and_admit(&sample(GIB), "model", Some(transformers(9 * GIB)))
        .unwrap();
    let replacement = GrantIdentity::of(&account.grants["model"]);
    assert_ne!(old.identity, replacement);
    account.confirm_end(old);
    account.reconcile_ends(&sample(GIB)).unwrap();
    assert_eq!(GrantIdentity::of(&account.grants["model"]), replacement);
    assert!(account.ended.is_empty());
}

#[test]
fn queued_old_receipts_are_discarded_after_another_path_replaces_the_grant() {
    let s = sample(GIB);
    let (_, mut account) = world(&s);
    account
        .settle_and_admit(&s, "model", Some(transformers(8 * GIB)))
        .unwrap();
    account.confirm_end(account.capture_end("model").unwrap());
    account
        .settle_and_admit(&sample(GIB), "model", Some(transformers(9 * GIB)))
        .unwrap();
    let replacement = GrantIdentity::of(&account.grants["model"]);
    account.reconcile_ends(&sample(GIB)).unwrap();
    assert_eq!(GrantIdentity::of(&account.grants["model"]), replacement);
}

#[test]
fn a_fresh_matching_host_probe_is_required_and_failure_retains_the_receipt() {
    let s = sample(GIB);
    let (_, mut account) = world(&s);
    account
        .settle_and_admit(&s, "model", Some(transformers(8 * GIB)))
        .unwrap();
    account.confirm_end(account.capture_end("model").unwrap());
    let mut stale = sample(GIB);
    stale.observed = std::time::Instant::now() - MAX_AGE - Duration::from_secs(1);
    assert!(account.reconcile_ends(&stale).is_err());
    assert_eq!(account.ended.len(), 1);
    assert_eq!(
        account.ledger.lock().unwrap().open_reservations().count(),
        2
    );
    account.reconcile_ends(&sample(GIB)).unwrap();
    assert!(account.grants.is_empty());
}

#[test]
fn silent_or_paused_neighbours_keep_their_grants_and_outside_memory_stays_charged() {
    let before = sample(GIB);
    let (_, mut account) = world(&before);
    account
        .settle_and_admit(&before, "neighbour", Some(transformers(8 * GIB)))
        .unwrap();
    account
        .settle_and_coadmit(
            &sample(5 * GIB),
            "deleted",
            transformers(8 * GIB),
            None,
            None,
            &Residents {
                kept: &kept(&[("neighbour", 4 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap();
    let neighbour = GrantIdentity::of(&account.grants["neighbour"]);
    account.confirm_end(account.capture_end("deleted").unwrap());
    let after = sample(12 * GIB);
    account.reconcile_ends(&after).unwrap();
    assert_eq!(account.grants.len(), 1);
    assert_eq!(GrantIdentity::of(&account.grants["neighbour"]), neighbour);
    let resource = ResourceKey::vram(after.device);
    let ledger = account.ledger.lock().unwrap();
    assert_eq!(ledger.reserved(resource), 8 * GIB);
    assert_eq!(ledger.capacity(resource).unwrap().unmanaged_in_use, 4 * GIB);
    assert!(ledger.available(resource).unwrap() <= after.total - after.used);
    assert_eq!(ledger.open_reservations().count(), 2);
}
