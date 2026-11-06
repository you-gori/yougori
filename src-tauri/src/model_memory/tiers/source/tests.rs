use std::collections::BTreeSet;

use super::*;
use crate::foundation::catalog::{GrantRequest, ObjectRole};
use crate::foundation::ids::ExecutionId;
use crate::model_memory::math::bounds::BandwidthBasis;
use crate::model_memory::residency::reservation::vram_resource;
use crate::model_memory::tiers::fakes::{
    at_seconds, charge, close, consumer, cut, cut_id, declare, device, execution, in_vm, path,
    publish, read_handle, scope, source_id, weights, world, World, GB, GIB, HYSTERESIS,
};
use crate::model_memory::tiers::gpu::GpuTier;
use crate::model_memory::tiers::peer::{PeerAuthorization, PeerContent, PeerSource};
use crate::model_memory::tiers::remote::{
    range_digest, RangeSpec, RemoteContent, RemotePolicy, RemoteSource,
};

const GIGABYTE: u64 = 1_000_000_000;

/// An offer a tier made for `requester` after its own checks.
fn offer(
    requester: &Consumer,
    tier: Tier,
    name: &str,
    object: &ObjectRef,
    path: SourcePath,
    covers_bytes: u64,
) -> Result<SourceOffer, OfferRefusal> {
    Ok(SourceOffer::new(
        tier,
        source_id(name),
        object.clone(),
        requester,
        path,
        covers_bytes,
    ))
}

fn request(
    requester: &Consumer,
    content: ContentKey,
    batches_bytes: Vec<u64>,
    cuts: Vec<CutSpec>,
) -> SourceRequest {
    SourceRequest {
        requester: requester.clone(),
        content,
        batches_bytes,
        cuts,
        policy: HYSTERESIS,
    }
}

#[test]
fn a_congested_donor_loses_to_local_nvme() {
    // Line 312: select by completion time, so a congested donor may lose to NVMe.
    let world = world(&["alice"]);
    let alice = consumer("alice", "exe-alice-1");
    let llama = weights("alice", "llama-8b");
    let eight_gigabytes = vec![GIGABYTE; 8];
    // Local NVMe reads 3 GB/s; the LAN donor's measured rate under congestion is 0.1 GB/s.
    let choice = choose_source(
        &request(
            &alice,
            llama.content,
            eight_gigabytes,
            vec![cut("nvme", 3.0 * GB), cut("lan", 0.1 * GB)],
        ),
        vec![
            offer(
                &alice,
                Tier::LocalStorage,
                "nvme",
                &llama,
                path(3.0 * GB, 0.005, &["nvme"]),
                8 * GIGABYTE,
            ),
            offer(
                &alice,
                Tier::AuthorizedPeer,
                "donor",
                &llama,
                path(0.1 * GB, 0.05, &["lan"]),
                8 * GIGABYTE,
            ),
        ],
        &world.catalog,
    )
    .unwrap();
    // NVMe finishes all eight in 0.005 + 8 / 3 = 2.672 s; one gigabyte from the donor
    // alone would take 0.05 + 10 = 10.05 s.
    assert_eq!(choice.assigned_bytes(&source_id("nvme")), 8 * GIGABYTE);
    assert_eq!(choice.assigned_bytes(&source_id("donor")), 0);
    assert!(close(
        choice.predicted_completion_seconds(),
        0.005 + 8.0 / 3.0,
        1e-9
    ));
    assert_eq!(
        choice.tier_of(&source_id("donor")),
        Some(Tier::AuthorizedPeer)
    );
    assert!(choice.excluded().is_empty());

    // No tier wins for what it is: the same donor uncongested at 1.25 GB/s beats a local
    // disk reading 0.2 GB/s.
    let choice = choose_source(
        &request(
            &alice,
            llama.content,
            vec![GIGABYTE; 4],
            vec![cut("disk", 0.2 * GB), cut("lan", 1.25 * GB)],
        ),
        vec![
            offer(
                &alice,
                Tier::LocalStorage,
                "disk",
                &llama,
                path(0.2 * GB, 0.005, &["disk"]),
                4 * GIGABYTE,
            ),
            offer(
                &alice,
                Tier::AuthorizedPeer,
                "donor",
                &llama,
                path(1.25 * GB, 0.05, &["lan"]),
                4 * GIGABYTE,
            ),
        ],
        &world.catalog,
    )
    .unwrap();
    // The donor finishes all four in 0.05 + 4 / 1.25 = 3.25 s; the disk would need
    // 5.005 s for one.
    assert_eq!(choice.assigned_bytes(&source_id("donor")), 4 * GIGABYTE);
    assert_eq!(choice.assigned_bytes(&source_id("disk")), 0);
    assert!(close(choice.predicted_completion_seconds(), 3.25, 1e-9));
    assert_eq!(choice.object_of(&source_id("donor")), Some(&llama));
}

#[test]
fn peers_behind_one_uplink_share_its_measured_capacity() {
    // Line 543: the peer tier is topology-aware; its offers carry the shared uplink, which
    // the planner counts once (T03: divided max-min fairly).
    let world = world(&["alice"]);
    let alice = consumer("alice", "exe-alice-1");
    let llama = weights("alice", "llama-8b");
    let clock = &world.clock;
    let peers: Vec<PeerSource> = (0..2)
        .map(|_| {
            let mut peer = PeerSource::new(
                PeerAuthorization {
                    scopes: BTreeSet::from([scope("alice")]),
                    expires_at: at_seconds(300),
                    donor_budget_bytes: 16 * GIB,
                },
                vec![cut_id("uplink")],
            );
            peer.hold(llama.clone(), PeerContent::ImmutableWeights, 2 * GIGABYTE)
                .unwrap();
            peer
        })
        .collect();
    let offers = peers
        .iter()
        .zip(["peer-a", "peer-b"])
        .map(|(peer, name)| {
            peer.offer(
                source_id(name),
                &llama,
                &alice,
                path(GB, 0.05, &["uplink"]),
                clock,
            )
        })
        .collect();
    let choice = choose_source(
        &request(
            &alice,
            llama.content,
            vec![GIGABYTE; 2],
            vec![cut("uplink", GB)],
        ),
        offers,
        &world.catalog,
    )
    .unwrap();
    // Each peer reads 1 GB/s alone, but together they get the uplink's 1 GB/s once:
    // 0.5 GB/s each, so one gigabyte each takes 0.05 + 2 = 2.05 s, not 1.05 s.
    for name in ["peer-a", "peer-b"] {
        assert!(close(
            choice
                .load()
                .rate_bytes_per_second(&source_id(name))
                .unwrap(),
            0.5 * GB,
            1e-3
        ));
        assert_eq!(choice.assigned_bytes(&source_id(name)), GIGABYTE);
    }
    assert!(close(choice.predicted_completion_seconds(), 2.05, 1e-9));
    let usage = choice.load().cut_usage();
    assert_eq!(usage.len(), 1);
    assert!(
        usage[0].allocated_bytes_per_second <= usage[0].capacity_bytes_per_second * (1.0 + 1e-12)
    );
}

#[test]
fn interference_moves_bytes_off_a_busy_donor() {
    let world = world(&["alice"]);
    let alice = consumer("alice", "exe-alice-1");
    let llama = weights("alice", "llama-8b");
    let choose = |interference_seconds_per_byte: f64| {
        let donor_path = SourcePath {
            interference_seconds_per_byte,
            ..path(2.0 * GB, 0.05, &["lan"])
        };
        choose_source(
            &request(
                &alice,
                llama.content,
                vec![GIGABYTE],
                vec![cut("nvme", GB), cut("lan", 2.0 * GB)],
            ),
            vec![
                offer(
                    &alice,
                    Tier::LocalStorage,
                    "nvme",
                    &llama,
                    path(GB, 0.005, &["nvme"]),
                    GIGABYTE,
                ),
                offer(
                    &alice,
                    Tier::AuthorizedPeer,
                    "donor",
                    &llama,
                    donor_path,
                    GIGABYTE,
                ),
            ],
            &world.catalog,
        )
        .unwrap()
    };
    // Free of interference the donor finishes first: 0.05 + 0.5 = 0.55 s against
    // 0.005 + 1 = 1.005 s.
    let idle = choose(0.0);
    assert_eq!(idle.assigned_bytes(&source_id("donor")), GIGABYTE);
    // Reading a gigabyte costs the donor's own users 1 s: 1.55 s of objective against
    // 1.005 s, so NVMe serves it.
    let busy = choose(1e-9);
    assert_eq!(busy.assigned_bytes(&source_id("nvme")), GIGABYTE);
    assert_eq!(busy.assigned_bytes(&source_id("donor")), 0);
}

#[test]
fn equal_content_in_another_scope_needs_a_grant_for_that_object() {
    // Line 546 and S3.3: content hashing establishes equality, not permission.
    let mut world = world(&["alice", "bob"]);
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    let bytes = b"llama-8b weights";
    let alices = publish(&mut world.catalog, &alice, bytes, ObjectRole::Original);
    let other = publish(
        &mut world.catalog,
        &alice,
        b"other weights",
        ObjectRole::Original,
    );
    // Bob's own copy would come from a remote into his scope.
    let bobs = ObjectRef {
        scope: bob.scope(),
        ..alices.clone()
    };
    let size = bytes.len() as u64;
    let choose = |world: &World| {
        choose_source(
            &request(
                &bob,
                alices.content,
                vec![size],
                vec![cut("nvme", 3.0 * GB), cut("wan", 0.05 * GB)],
            ),
            vec![
                offer(
                    &bob,
                    Tier::LocalStorage,
                    "alice-nvme",
                    &alices,
                    path(3.0 * GB, 0.005, &["nvme"]),
                    size,
                ),
                offer(
                    &bob,
                    Tier::Remote,
                    "hub",
                    &bobs,
                    path(0.05 * GB, 0.2, &["wan"]),
                    size,
                ),
            ],
            &world.catalog,
        )
        .unwrap()
    };
    let outside = ExcludedSource {
        source: source_id("alice-nvme"),
        tier: Tier::LocalStorage,
        reason: ExclusionReason::OutsideScope {
            object: alices.id(),
        },
    };
    let without_grant = choose(&world);
    assert_eq!(without_grant.excluded(), [outside.clone()]);
    assert_eq!(without_grant.assigned_bytes(&source_id("hub")), size);
    let grant = |world: &mut World, object: ObjectId, narrowed_to: Option<ExecutionId>| {
        world
            .catalog
            .grant(
                &alice.scope(),
                GrantRequest {
                    object,
                    grantee: bob.scope(),
                    execution: narrowed_to,
                    expires_at: at_seconds(3_600),
                },
            )
            .unwrap()
    };
    // A grant for another of Alice's objects does not reach this one...
    grant(&mut world, other.id(), None);
    assert_eq!(choose(&world).excluded(), [outside.clone()]);
    // ...nor does one narrowed to another of Bob's executions.
    grant(&mut world, alices.id(), Some(execution("exe-bob-2")));
    assert_eq!(choose(&world).excluded(), [outside.clone()]);
    // A grant for exactly that object lets the faster copy serve.
    grant(&mut world, alices.id(), None);
    let granted = choose(&world);
    assert!(granted.excluded().is_empty());
    assert_eq!(granted.assigned_bytes(&source_id("alice-nvme")), size);
    assert_eq!(granted.assigned_bytes(&source_id("hub")), 0);
    // When the grants expire the copy is excluded again.
    world.clock.advance_to(at_seconds(3_600));
    assert_eq!(choose(&world).excluded(), [outside]);
}

#[test]
fn refused_and_unfit_offers_are_excluded_with_their_reasons() {
    let world = world(&["alice"]);
    let alice = consumer("alice", "exe-alice-1");
    let llama = weights("alice", "llama-8b");
    let mistral = weights("alice", "mistral-7b");
    let clock = &world.clock;
    world.clock.advance_to(at_seconds(20));
    // A peer whose authorization ended at 10 s, and one whose donor budget covers 1 GiB.
    let expired = {
        let mut peer = PeerSource::new(
            PeerAuthorization {
                scopes: BTreeSet::from([scope("alice")]),
                expires_at: at_seconds(10),
                donor_budget_bytes: 16 * GIB,
            },
            vec![cut_id("lan")],
        );
        peer.hold(llama.clone(), PeerContent::ImmutableWeights, 2 * GIB)
            .unwrap();
        peer
    };
    let thrifty = {
        let mut peer = PeerSource::new(
            PeerAuthorization {
                scopes: BTreeSet::from([scope("alice")]),
                expires_at: at_seconds(300),
                donor_budget_bytes: GIB,
            },
            vec![cut_id("lan")],
        );
        peer.hold(llama.clone(), PeerContent::ImmutableWeights, 2 * GIB)
            .unwrap();
        peer
    };
    // A remote listing both models, with egress for both.
    let mut hub = RemoteSource::new(RemotePolicy {
        access: BTreeSet::from([scope("alice")]),
        egress_budget_bytes: 8 * GIB,
    });
    for object in [&llama, &mistral] {
        hub.list(
            object.class,
            object.content,
            RemoteContent::Original,
            vec![RangeSpec {
                offset: 0,
                length_bytes: 2 * GIB,
                digest: range_digest(0, b""),
            }],
        )
        .unwrap();
    }
    let lan = || path(GB, 0.05, &["lan"]);
    let wan = || path(0.1 * GB, 0.2, &["wan"]);
    let offers = || {
        vec![
            expired.offer(source_id("expired-peer"), &llama, &alice, lan(), clock),
            thrifty.offer(source_id("thrifty-peer"), &llama, &alice, lan(), clock),
            hub.offer(source_id("hub-mistral"), &mistral, &alice, wan()),
            hub.offer(source_id("hub"), &llama, &alice, wan()),
        ]
    };
    let llama_request = request(
        &alice,
        llama.content,
        vec![GIB, GIB],
        vec![cut("lan", GB), cut("wan", 0.1 * GB)],
    );
    let choice = choose_source(&llama_request, offers(), &world.catalog).unwrap();
    let reasons: Vec<(SourceId, ExclusionReason)> = choice
        .excluded()
        .iter()
        .map(|excluded| (excluded.source.clone(), excluded.reason.clone()))
        .collect();
    assert_eq!(
        reasons,
        [
            (
                source_id("expired-peer"),
                ExclusionReason::Refused(TierRefusal::Peer(PeerRefusal::Expired {
                    expired_at: at_seconds(10)
                }))
            ),
            // The planner may give every byte to one source, so a budget short of the whole
            // request excludes the source.
            (
                source_id("thrifty-peer"),
                ExclusionReason::CannotCover {
                    covers_bytes: GIB,
                    needed_bytes: 2 * GIB,
                }
            ),
            (
                source_id("hub-mistral"),
                ExclusionReason::DifferentContent {
                    offered: mistral.content
                }
            ),
        ]
    );
    assert_eq!(choice.assigned_bytes(&source_id("hub")), 2 * GIB);
    assert_eq!(choice.tier_of(&source_id("hub")), Some(Tier::Remote));
    assert_eq!(choice.tier_of(&source_id("thrifty-peer")), None);

    // With every offer excluded there is no plan, and every reason is reported.
    let nobody_request = request(
        &alice,
        ContentKey::of(b"a model nobody holds"),
        vec![GIB],
        Vec::new(),
    );
    match choose_source(&nobody_request, offers(), &world.catalog) {
        Err(SourceChoiceError::NoEligibleSource { excluded }) => assert_eq!(excluded.len(), 4),
        other => panic!("expected no eligible source, got {other:?}"),
    }
}

#[test]
fn the_planner_refuses_unmeasured_bandwidth_and_overflowing_requests() {
    let world = world(&["alice"]);
    let alice = consumer("alice", "exe-alice-1");
    let llama = weights("alice", "llama-8b");
    // An advertised figure is never a plan input (T03).
    let advertised = SourcePath {
        bandwidth: BandwidthRating::advertised(1.25 * GB).unwrap(),
        ..path(GB, 0.05, &[])
    };
    assert_eq!(
        choose_source(
            &request(&alice, llama.content, vec![GIGABYTE], Vec::new()),
            vec![offer(
                &alice,
                Tier::AuthorizedPeer,
                "donor",
                &llama,
                advertised,
                GIGABYTE
            )],
            &world.catalog,
        )
        .unwrap_err(),
        SourceChoiceError::Planner(SourcesError::UnusableBandwidth {
            name: "donor".to_string(),
            basis: BandwidthBasis::Advertised,
        })
    );
    assert_eq!(
        choose_source(
            &request(&alice, llama.content, vec![u64::MAX, 1], Vec::new()),
            vec![offer(
                &alice,
                Tier::LocalStorage,
                "nvme",
                &llama,
                path(GB, 0.0, &[]),
                u64::MAX
            )],
            &world.catalog,
        )
        .unwrap_err(),
        SourceChoiceError::Overflow
    );
    // The chosen plan dispatches only to planned sources.
    let mut choice = choose_source(
        &request(
            &alice,
            llama.content,
            vec![GIGABYTE; 2],
            vec![cut("nvme", GB)],
        ),
        vec![offer(
            &alice,
            Tier::LocalStorage,
            "nvme",
            &llama,
            path(GB, 0.0, &["nvme"]),
            2 * GIGABYTE,
        )],
        &world.catalog,
    )
    .unwrap();
    let dispatched = choice.load_mut().dispatch();
    assert!(!dispatched.is_empty());
    assert!(dispatched
        .iter()
        .all(|dispatch| dispatch.source == source_id("nvme")));
}

#[test]
fn an_offer_is_planned_only_for_the_consumer_it_was_checked_for() {
    // Review R1-c (S3.3; decision T07: device memory never crosses a VM boundary). The GPU
    // tier refuses the tenant's VM sandbox, and an offer it made for the same tenant's WSL
    // runner is not planned for the sandbox either.
    let mut world = world(&["alice"]);
    declare(
        &mut world.ledger,
        vram_resource(device(0)),
        64 * GIB,
        &["alice"],
    );
    let runner = consumer("alice", "exe-runner");
    let sandbox = in_vm("alice", "exe-vm");
    let bytes = b"weights in the wsl runtime";
    let object = publish(&mut world.catalog, &runner, bytes, ObjectRole::Original);
    let handle = read_handle(&mut world.catalog, &runner, &object).unwrap();
    let mut gpu = GpuTier::new(device(0), None);
    gpu.load_weights(
        &runner,
        &object,
        &handle,
        &world.catalog,
        GIB,
        &charge("op-load"),
        &mut world.ledger,
    )
    .unwrap();
    let route = || path(20.0 * GB, 0.001, &[]);
    assert!(matches!(
        gpu.offer(source_id("gpu0"), &object, &sandbox, route()),
        Err(OfferRefusal {
            reason: TierRefusal::Gpu(GpuRefusal::OutsideScope { .. }),
            ..
        })
    ));
    let for_runner = gpu
        .offer(source_id("gpu0"), &object, &runner, route())
        .unwrap();
    assert_eq!(for_runner.requester(), &runner);
    let size = bytes.len() as u64;
    let offered_to_runner = ExcludedSource {
        source: source_id("gpu0"),
        tier: Tier::Gpu,
        reason: ExclusionReason::OfferedToAnother {
            offered_to: Box::new(runner.clone()),
        },
    };
    // Neither the sandbox nor another execution may use an offer checked for the runner;
    // each must ask the tier itself.
    for other in [sandbox, consumer("alice", "exe-runner-2")] {
        match choose_source(
            &request(&other, object.content, vec![size], Vec::new()),
            vec![Ok(for_runner.clone())],
            &world.catalog,
        ) {
            Err(SourceChoiceError::NoEligibleSource { excluded }) => {
                assert_eq!(excluded, [offered_to_runner.clone()]);
            }
            other => panic!("expected the offer to be excluded, got {other:?}"),
        }
    }
    let choice = choose_source(
        &request(&runner, object.content, vec![size], Vec::new()),
        vec![Ok(for_runner)],
        &world.catalog,
    )
    .unwrap();
    assert_eq!(choice.tier_of(&source_id("gpu0")), Some(Tier::Gpu));
    assert_eq!(choice.assigned_bytes(&source_id("gpu0")), size);
}
