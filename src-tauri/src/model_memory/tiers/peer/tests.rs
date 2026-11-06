use super::*;
use crate::foundation::ids::ContentKey;
use crate::model_memory::residency::eviction::Content;
use crate::model_memory::tiers::fakes::{
    at_seconds, clock_at, consumer, cut_id, operation, path, scope, source_id, tenant, weights, GB,
    GIB,
};

/// Appendix A.2 line 1495: today's peer grants expire within 300 s.
const GRANT_SECONDS: u64 = 300;

/// A peer authorized for `scopes` until 300 s with a 16 GiB donor budget, behind the
/// shared `lan-switch` uplink.
fn peer(scopes: &[Scope]) -> PeerSource {
    PeerSource::new(
        PeerAuthorization {
            scopes: scopes.iter().cloned().collect(),
            expires_at: at_seconds(GRANT_SECONDS),
            donor_budget_bytes: 16 * GIB,
        },
        vec![cut_id("lan-switch")],
    )
}

/// The consumer the offers are made for.
fn reader() -> Consumer {
    consumer("alice", "exe-alice-1")
}

/// A measured 1 GB/s path through the peer's uplink.
fn through_uplink() -> SourcePath {
    path(GB, 0.05, &["lan-switch"])
}

fn refusal(offer: Result<SourceOffer, OfferRefusal>) -> PeerRefusal {
    match offer {
        Err(OfferRefusal {
            tier: Tier::AuthorizedPeer,
            reason: TierRefusal::Peer(refusal),
            ..
        }) => refusal,
        other => panic!("expected a peer refusal, got {other:?}"),
    }
}

#[test]
fn the_authorization_expires() {
    let clock = clock_at(0);
    let mut donor = peer(&[scope("alice")]);
    let llama = weights("alice", "llama-8b");
    donor
        .hold(llama.clone(), PeerContent::ImmutableWeights, 10 * GIB)
        .unwrap();
    assert!(donor
        .offer(
            source_id("peer"),
            &llama,
            &reader(),
            through_uplink(),
            &clock
        )
        .is_ok());
    // Live strictly before the expiry...
    clock.advance_to(MonotonicTime::from_nanos(
        at_seconds(GRANT_SECONDS).as_nanos() - 1,
    ));
    assert_eq!(donor.authorized(&clock), Ok(()));
    donor.charge(GIB, &clock).unwrap();
    // ...and from the expiry on nothing is offered or charged.
    clock.advance_to(at_seconds(GRANT_SECONDS));
    let expired = PeerRefusal::Expired {
        expired_at: at_seconds(GRANT_SECONDS),
    };
    assert_eq!(donor.authorized(&clock), Err(expired.clone()));
    assert_eq!(donor.charge(GIB, &clock), Err(expired.clone()));
    assert_eq!(donor.served_bytes(), GIB);
    assert_eq!(
        refusal(donor.offer(
            source_id("peer"),
            &llama,
            &reader(),
            through_uplink(),
            &clock
        )),
        expired
    );
    assert_eq!(donor.authorization().expires_at, at_seconds(GRANT_SECONDS));
}

#[test]
fn the_donor_budget_bounds_what_is_served() {
    let clock = clock_at(0);
    let mut donor = peer(&[scope("alice")]);
    let llama = weights("alice", "llama-8b");
    donor
        .hold(llama.clone(), PeerContent::ImmutableWeights, 10 * GIB)
        .unwrap();
    donor.charge(10 * GIB, &clock).unwrap();
    assert_eq!(donor.donor_remaining_bytes(), 6 * GIB);
    // An offer covers no more than the donor still agreed to serve.
    let offer = donor
        .offer(
            source_id("peer"),
            &llama,
            &reader(),
            through_uplink(),
            &clock,
        )
        .unwrap();
    assert_eq!(
        (offer.tier(), offer.covers_bytes()),
        (Tier::AuthorizedPeer, 6 * GIB)
    );
    assert_eq!(
        donor.charge(7 * GIB, &clock),
        Err(PeerRefusal::DonorBudgetExhausted {
            donor_budget_bytes: 16 * GIB,
            served_bytes: 10 * GIB,
            requested_bytes: 7 * GIB,
        })
    );
    assert_eq!(donor.served_bytes(), 10 * GIB);
    donor.charge(6 * GIB, &clock).unwrap();
    assert_eq!(
        refusal(donor.offer(
            source_id("peer"),
            &llama,
            &reader(),
            through_uplink(),
            &clock
        )),
        PeerRefusal::DonorBudgetExhausted {
            donor_budget_bytes: 16 * GIB,
            served_bytes: 16 * GIB,
            requested_bytes: 10 * GIB,
        }
    );
    assert_eq!(donor.charge(0, &clock), Err(PeerRefusal::ZeroBytes));
    assert_eq!(donor.charge(u64::MAX, &clock), Err(PeerRefusal::Overflow));
}

#[test]
fn only_authorized_scopes_and_eligible_content_are_held() {
    let mut donor = peer(&[scope("alice"), Scope::Host]);
    // Bob's weights are outside the authorization, however equal their bytes.
    let bobs = ObjectRef {
        scope: scope("bob"),
        ..weights("alice", "llama-8b")
    };
    assert_eq!(
        donor.hold(bobs, PeerContent::ImmutableWeights, GIB),
        Err(PeerRefusal::ScopeNotAuthorized {
            scope: scope("bob")
        })
    );
    // Only model weights and their sidecars are eligible as weights.
    let image = ObjectRef {
        class: ArtifactClass::GuestImage,
        ..weights("alice", "guest disk")
    };
    assert_eq!(
        donor.hold(image.clone(), PeerContent::ImmutableWeights, GIB),
        Err(PeerRefusal::NotWeights { object: image })
    );
    let sidecar = ObjectRef {
        class: ArtifactClass::ModelSidecar,
        ..weights("alice", "llama-8b index")
    };
    donor
        .hold(sidecar.clone(), PeerContent::ImmutableWeights, GIB)
        .unwrap();
    assert_eq!(
        donor.hold(sidecar.clone(), PeerContent::ImmutableWeights, GIB),
        Err(PeerRefusal::AlreadyHeld { object: sidecar })
    );
    assert_eq!(
        donor.hold(weights("alice", "empty"), PeerContent::ImmutableWeights, 0),
        Err(PeerRefusal::ZeroBytes)
    );
    // State moves only with its own tenant's explicit consent.
    let state = weights("alice", "session state");
    let consent = |tenant_name: &str| PeerContent::TransferableState {
        consent: TransferConsent {
            tenant: tenant(tenant_name),
            operation: operation("op-move-session"),
        },
    };
    assert_eq!(
        donor.hold(state.clone(), consent("bob"), GIB),
        Err(PeerRefusal::ConsentFromAnotherTenant {
            consenting: tenant("bob"),
            owner: tenant("alice"),
        })
    );
    donor.hold(state, consent("alice"), GIB).unwrap();
    let host_state = ObjectRef {
        scope: Scope::Host,
        ..weights("alice", "host state")
    };
    assert_eq!(
        donor.hold(host_state.clone(), consent("alice"), GIB),
        Err(PeerRefusal::StateWithoutTenant { object: host_state })
    );
}

#[test]
fn an_offer_carries_the_peers_topology() {
    let clock = clock_at(0);
    let mut donor = peer(&[scope("alice")]);
    let llama = weights("alice", "llama-8b");
    donor
        .hold(llama.clone(), PeerContent::ImmutableWeights, 10 * GIB)
        .unwrap();
    // The planner must count the shared uplink (T03), so a path that leaves it out is
    // refused.
    assert_eq!(
        refusal(donor.offer(
            source_id("peer"),
            &llama,
            &reader(),
            path(GB, 0.05, &[]),
            &clock
        )),
        PeerRefusal::TopologyMissing {
            cut: cut_id("lan-switch")
        }
    );
    let offer = donor
        .offer(
            source_id("peer"),
            &llama,
            &reader(),
            through_uplink(),
            &clock,
        )
        .unwrap();
    assert_eq!(offer.path().cuts, [cut_id("lan-switch")]);
    assert_eq!(offer.source(), &source_id("peer"));
    assert_eq!(offer.requester(), &reader());
    let unheld = weights("alice", "mistral-7b");
    assert_eq!(
        refusal(donor.offer(
            source_id("peer"),
            &unheld,
            &reader(),
            through_uplink(),
            &clock
        )),
        PeerRefusal::NotHeld { object: unheld }
    );
    let bobs = ObjectRef {
        scope: scope("bob"),
        ..llama
    };
    assert_eq!(
        refusal(donor.offer(
            source_id("peer"),
            &bobs,
            &reader(),
            through_uplink(),
            &clock
        )),
        PeerRefusal::ScopeNotAuthorized {
            scope: scope("bob")
        }
    );
}

#[test]
fn a_peers_copy_never_rebuilds_a_dropped_gpu_copy() {
    let mut donor = peer(&[scope("alice")]);
    let llama = weights("alice", "llama-8b");
    donor
        .hold(llama.clone(), PeerContent::ImmutableWeights, 10 * GIB)
        .unwrap();
    // Unverified here and behind an expiring authorization (T08).
    let copy = donor.copy_of(&llama).unwrap();
    assert_eq!((&copy.object, copy.holder.as_ref()), (&llama, None));
    assert_eq!(copy.copy.tier, CopyTier::AuthorizedPeer);
    assert_eq!(copy.copy.verification, Verification::Unverified);
    assert!(!copy.copy.reconstructs(&Content::Immutable(llama.content)));
    let unheld = ObjectRef {
        content: ContentKey::of(b"not held"),
        ..llama
    };
    assert_eq!(donor.copy_of(&unheld), None);
}
