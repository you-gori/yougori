use super::*;
use crate::foundation::ids::digest;
use crate::model_memory::math::test_support::close;

const DOMAIN: &str = "yougori/test/kv/v1";

fn requirement() -> KvRequirement {
    KvRequirement {
        state_identity: digest(DOMAIN, &[b"state"]),
        prefix_identity: digest(DOMAIN, &[b"prefix"]),
        current_epoch: AuthorizationEpoch::new(3),
    }
}

fn allowed(queue_seconds: f64, compute_seconds: f64) -> KvRecompute {
    let needed = requirement();
    KvRecompute {
        held_prefix: Some(needed.prefix_identity),
        produces_state: needed.state_identity,
        authorized_epoch: Some(needed.current_epoch),
        queue_seconds,
        compute_seconds,
    }
}

const TRANSFER: KvTransfer = KvTransfer {
    queue_seconds: 0.05,
    transfer_seconds: 0.20,
};

#[test]
fn recompute_wins_only_when_faster_including_queues() {
    let needed = requirement();
    let fast = choose_kv_restore(&needed, Some(&TRANSFER), Some(&allowed(0.0, 0.15))).unwrap();
    assert_eq!(fast.method, KvRestoreMethod::Recompute);
    assert_eq!(fast.completion_seconds, 0.15);
    assert!(close(
        fast.transfer_completion_seconds.unwrap(),
        0.25,
        1e-12
    ));
    assert_eq!(fast.recompute_refusal, None);

    // Faster compute behind a long queue loses to the transfer.
    let queued = choose_kv_restore(&needed, Some(&TRANSFER), Some(&allowed(0.30, 0.15))).unwrap();
    assert_eq!(queued.method, KvRestoreMethod::Transfer);
    assert!(close(queued.completion_seconds, 0.25, 1e-12));
    assert!(close(
        queued.recompute_completion_seconds.unwrap(),
        0.45,
        1e-12
    ));

    let tie = choose_kv_restore(&needed, Some(&TRANSFER), Some(&allowed(0.0, 0.25))).unwrap();
    assert_eq!(tie.method, KvRestoreMethod::Transfer);

    let only_recompute = choose_kv_restore(&needed, None, Some(&allowed(0.0, 0.5))).unwrap();
    assert_eq!(only_recompute.method, KvRestoreMethod::Recompute);
}

#[test]
fn recompute_is_refused_unless_available_authorized_and_identical() {
    let needed = requirement();
    let cases = [
        (
            KvRecompute {
                held_prefix: None,
                ..allowed(0.0, 0.01)
            },
            RecomputeRefusal::OriginalStateUnavailable,
        ),
        (
            KvRecompute {
                held_prefix: Some(digest(DOMAIN, &[b"another prefix"])),
                ..allowed(0.0, 0.01)
            },
            RecomputeRefusal::OriginalStateUnavailable,
        ),
        (
            KvRecompute {
                authorized_epoch: None,
                ..allowed(0.0, 0.01)
            },
            RecomputeRefusal::NotAuthorized,
        ),
        (
            KvRecompute {
                authorized_epoch: Some(AuthorizationEpoch::new(2)),
                ..allowed(0.0, 0.01)
            },
            RecomputeRefusal::NotAuthorized,
        ),
        (
            KvRecompute {
                produces_state: digest(DOMAIN, &[b"state under another adapter"]),
                ..allowed(0.0, 0.01)
            },
            RecomputeRefusal::NotSemanticallyIdentical,
        ),
    ];
    for (option, refusal) in cases {
        assert_eq!(check_recompute(&needed, &option), Err(refusal));
        // Even far faster, a refused recomputation never replaces the transfer.
        let decision = choose_kv_restore(&needed, Some(&TRANSFER), Some(&option)).unwrap();
        assert_eq!(decision.method, KvRestoreMethod::Transfer);
        assert_eq!(decision.recompute_refusal, Some(refusal));
        assert_eq!(decision.recompute_completion_seconds, None);
        assert_eq!(
            choose_kv_restore(&needed, None, Some(&option)),
            Err(RecomputeError::NoExactRestore {
                recompute_refusal: Some(refusal)
            })
        );
    }
    assert_eq!(check_recompute(&needed, &allowed(0.0, 0.01)), Ok(()));
    assert_eq!(
        choose_kv_restore(&needed, None, None),
        Err(RecomputeError::NoExactRestore {
            recompute_refusal: None
        })
    );
}

#[test]
fn discarding_recoverable_cache_differs_from_discarding_required_context() {
    let needed = requirement();
    let recoverable_by_copy = classify_discard(&needed, Some(&TRANSFER), None);
    assert_eq!(recoverable_by_copy, KvDiscard::RecoverableCache);
    assert_eq!(recoverable_by_copy.authorize_cache_eviction(), Ok(()));
    assert_eq!(
        classify_discard(&needed, None, Some(&allowed(0.0, 1.0))),
        KvDiscard::RecoverableCache
    );

    let unauthorized = KvRecompute {
        authorized_epoch: None,
        ..allowed(0.0, 1.0)
    };
    let required = classify_discard(&needed, None, Some(&unauthorized));
    assert_eq!(required, KvDiscard::RequiredContext);
    assert_eq!(
        required.authorize_cache_eviction(),
        Err(RecomputeError::RequiredContext)
    );
    assert_eq!(
        classify_discard(&needed, None, None),
        KvDiscard::RequiredContext
    );
}

#[test]
fn kv_inputs_are_validated() {
    let needed = requirement();
    let negative = KvTransfer {
        queue_seconds: -1.0,
        transfer_seconds: 0.1,
    };
    assert!(matches!(
        choose_kv_restore(&needed, Some(&negative), None),
        Err(RecomputeError::Input(InputError::Negative { .. }))
    ));
    assert!(matches!(
        choose_kv_restore(&needed, Some(&TRANSFER), Some(&allowed(0.0, f64::NAN))),
        Err(RecomputeError::Input(InputError::NotFinite { .. }))
    ));
}
