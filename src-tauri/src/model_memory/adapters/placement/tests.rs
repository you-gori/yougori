//! Worked numbers for line 636. KV size is 327,680 bytes per token (80 layers × 8 KV
//! heads × 128 dimensions × key and value × 2 bytes); prefill runs at 10,000 tokens/s;
//! serving the request itself takes 1.0 s on either worker.

use super::*;
use crate::model_memory::adapters::fakes::{
    close, execution_identity, id, kv_spec, request, trust, verified, NOW,
};
use crate::model_memory::adapters::kv::{check_kv_reuse, KvSharing, PublicPrefixSharing, StoredKv};
use crate::model_memory::identity::RevokedAuthorities;

const KV_BYTES_PER_TOKEN: u64 = 327_680;
const PREFILL_TOKENS_PER_SECOND: f64 = 10_000.0;

struct Session {
    grant: KvReuseGrant,
    requirement: KvRequirement,
    prefix_tokens: u64,
}

fn session(prefix_tokens: u64) -> Session {
    let stored = StoredKv {
        spec: kv_spec(
            execution_identity("base-70b"),
            None,
            prefix_tokens,
            "long document",
            "acme",
        ),
        trust_scope: trust(),
        sharing: KvSharing::TenantScoped,
    };
    let grant = check_kv_reuse(
        &stored,
        &request(stored.spec.clone()),
        &PublicPrefixSharing::none(),
        &RevokedAuthorities::new(),
        &verified(),
        NOW,
    )
    .unwrap();
    let requirement = KvRequirement {
        state_identity: grant.key(),
        prefix_identity: *stored.spec.scope.prefix.digest(),
        current_epoch: AuthorizationEpoch::new(1),
    };
    Session {
        grant,
        requirement,
        prefix_tokens,
    }
}

fn stay(session: &Session, queue_seconds: f64) -> StayOnCurrent {
    StayOnCurrent {
        grant: session.grant.clone(),
        queue_seconds,
        serve_seconds: 1.0,
    }
}

fn recompute(session: &Session) -> KvRecomputeEstimate {
    KvRecomputeEstimate {
        held_prefix: Some(session.requirement.prefix_identity),
        produces_state: session.requirement.state_identity,
        authorized_epoch: Some(session.requirement.current_epoch),
        prefix_tokens: session.prefix_tokens,
        prefill_tokens_per_second: PREFILL_TOKENS_PER_SECOND,
    }
}

fn target(session: &Session, link_bytes_per_second: f64, link_queue_seconds: f64) -> MoveToTarget {
    MoveToTarget {
        target_queue_seconds: 0.5,
        serve_seconds: 1.0,
        transfer: Some(KvTransferEstimate {
            grant: session.grant.clone(),
            kv_bytes: session.prefix_tokens * KV_BYTES_PER_TOKEN,
            link_bytes_per_second,
            link_queue_seconds,
        }),
        recompute: Some(recompute(session)),
    }
}

#[test]
fn transfer_wins_for_a_long_prefix_on_a_fast_link() {
    // 32,000 tokens = 10,485,760,000 bytes over 25 GB/s = 0.4194304 s, which arrives
    // before the target's 0.5 s queue clears: 0.5 + 1.0 = 1.5 s. Recomputing takes
    // 0.5 + 3.2 + 1.0 = 4.7 s; staying behind a 6.0 s queue takes 7.0 s.
    let session = session(32_000);
    let decision = decide_kv_placement(
        &session.requirement,
        Some(&stay(&session, 6.0)),
        Some(&target(&session, 25e9, 0.0)),
    )
    .unwrap();
    assert_eq!(decision.placement, KvPlacement::Transfer);
    assert!(close(decision.completion_seconds, 1.5));
    assert!(close(decision.stay_completion_seconds.unwrap(), 7.0));
    assert!(close(decision.transfer_completion_seconds.unwrap(), 1.5));
    assert!(close(decision.recompute_completion_seconds.unwrap(), 4.7));
    assert_eq!(decision.recompute_refusal, None);
}

#[test]
fn recompute_wins_when_the_link_is_queued() {
    // 2,000 tokens = 655,360,000 bytes over 1.25 GB/s = 0.524288 s, behind a 2.0 s link
    // queue: 2.524288 + 1.0 = 3.524288 s. Recomputing takes 0.5 + 0.2 + 1.0 = 1.7 s,
    // and staying 7.0 s, so the transfer loses to both.
    let session = session(2_000);
    let decision = decide_kv_placement(
        &session.requirement,
        Some(&stay(&session, 6.0)),
        Some(&target(&session, 1.25e9, 2.0)),
    )
    .unwrap();
    assert_eq!(decision.placement, KvPlacement::Recompute);
    assert!(close(decision.completion_seconds, 1.7));
    assert!(close(
        decision.transfer_completion_seconds.unwrap(),
        3.524288
    ));

    // Without the link queue the same transfer completes at 1.524288 s and wins.
    let unqueued = decide_kv_placement(
        &session.requirement,
        Some(&stay(&session, 6.0)),
        Some(&target(&session, 1.25e9, 0.0)),
    )
    .unwrap();
    assert_eq!(unqueued.placement, KvPlacement::Transfer);
    assert!(close(unqueued.completion_seconds, 1.524288));
}

#[test]
fn staying_wins_when_the_current_queue_is_short() {
    // A 0.25 s queue on the current worker: 1.25 s, against 1.5 s for the transfer.
    let session = session(32_000);
    let decision = decide_kv_placement(
        &session.requirement,
        Some(&stay(&session, 0.25)),
        Some(&target(&session, 25e9, 0.0)),
    )
    .unwrap();
    assert_eq!(decision.placement, KvPlacement::Stay);
    assert!(close(decision.completion_seconds, 1.25));

    // At equal completion (0.5 + 1.0 = 1.5 s both ways) the request stays.
    let tie = decide_kv_placement(
        &session.requirement,
        Some(&stay(&session, 0.5)),
        Some(&target(&session, 25e9, 0.0)),
    )
    .unwrap();
    assert_eq!(tie.placement, KvPlacement::Stay);
}

#[test]
fn recomputation_competes_only_when_exact() {
    let session = session(2_000);
    let refused = [
        (
            KvRecomputeEstimate {
                held_prefix: None,
                ..recompute(&session)
            },
            RecomputeRefusal::OriginalStateUnavailable,
        ),
        (
            KvRecomputeEstimate {
                authorized_epoch: Some(AuthorizationEpoch::new(0)),
                ..recompute(&session)
            },
            RecomputeRefusal::NotAuthorized,
        ),
        (
            KvRecomputeEstimate {
                produces_state: id("state on another adapter"),
                ..recompute(&session)
            },
            RecomputeRefusal::NotSemanticallyIdentical,
        ),
    ];
    for (estimate, refusal) in refused {
        let option = MoveToTarget {
            recompute: Some(estimate),
            ..target(&session, 1.25e9, 2.0)
        };
        let decision = decide_kv_placement(
            &session.requirement,
            Some(&stay(&session, 6.0)),
            Some(&option),
        )
        .unwrap();
        // Recomputation would have won at 1.7 s; refused, the transfer wins at 3.524288 s.
        assert_eq!(decision.placement, KvPlacement::Transfer);
        assert_eq!(decision.recompute_completion_seconds, None);
        assert_eq!(decision.recompute_refusal, Some(refusal));

        let only_recompute = MoveToTarget {
            transfer: None,
            ..option
        };
        assert_eq!(
            decide_kv_placement(&session.requirement, None, Some(&only_recompute)),
            Err(KvPlacementError::NoOption {
                recompute_refusal: Some(refusal)
            })
        );
        let with_stay = decide_kv_placement(
            &session.requirement,
            Some(&stay(&session, 6.0)),
            Some(&only_recompute),
        )
        .unwrap();
        assert_eq!(with_stay.placement, KvPlacement::Stay);
    }
}

#[test]
fn a_grant_for_another_state_is_refused() {
    let session = session(32_000);
    let other = session_with_other_tokens();
    assert_eq!(
        decide_kv_placement(&session.requirement, Some(&stay(&other, 0.0)), None),
        Err(KvPlacementError::GrantForAnotherState {
            granted: other.grant.key(),
            required: session.requirement.state_identity,
        })
    );
    let foreign_transfer = MoveToTarget {
        transfer: Some(KvTransferEstimate {
            grant: other.grant.clone(),
            kv_bytes: 1,
            link_bytes_per_second: 1.0,
            link_queue_seconds: 0.0,
        }),
        ..target(&session, 25e9, 0.0)
    };
    assert!(matches!(
        decide_kv_placement(&session.requirement, None, Some(&foreign_transfer)),
        Err(KvPlacementError::GrantForAnotherState { .. })
    ));
}

fn session_with_other_tokens() -> Session {
    session(31_999)
}

#[test]
fn invalid_numbers_are_refused() {
    let session = session(2_000);
    assert_eq!(
        decide_kv_placement(&session.requirement, Some(&stay(&session, -1.0)), None),
        Err(KvPlacementError::Input(InputError::Negative {
            field: "StayOnCurrent.queue_seconds"
        }))
    );
    assert_eq!(
        decide_kv_placement(
            &session.requirement,
            None,
            Some(&target(&session, 0.0, 0.0))
        ),
        Err(KvPlacementError::Input(InputError::NotPositive {
            field: "KvTransferEstimate.link_bytes_per_second"
        }))
    );
    let nan_serve = MoveToTarget {
        serve_seconds: f64::NAN,
        ..target(&session, 1e9, 0.0)
    };
    assert_eq!(
        decide_kv_placement(&session.requirement, None, Some(&nan_serve)),
        Err(KvPlacementError::Input(InputError::NotFinite {
            field: "MoveToTarget.serve_seconds"
        }))
    );
    assert_eq!(
        decide_kv_placement(&session.requirement, None, None),
        Err(KvPlacementError::NoOption {
            recompute_refusal: None
        })
    );
}
