//! GPU-W09: expiring residency advertisements and stale-source fallback.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::foundation::ids::{ManualClock, ModelActivationGeneration};
use crate::model_memory::identity::{
    AdvertisementPurpose, AdvertisementRefusal, AdvertisementRequest, CurrentResidency, GrantedUse,
};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::sources::{
    SourceAuthorization, SourceSpec, SourcesError, StealPolicy,
};
use crate::model_memory::math::SourceId;

use super::super::advertisements::*;
use super::super::error::RoutingError;
use super::support::*;

const SECOND: Duration = Duration::from_secs(1);

fn book() -> AdvertisementBook {
    AdvertisementBook::new(AdvertisementPolicy::new(30 * SECOND).unwrap())
}

fn source(name: &str, bytes_per_second: f64, authorization: SourceAuthorization) -> SourceSpec {
    SourceSpec {
        id: SourceId::new(name).unwrap(),
        authorization,
        startup_seconds: 0.1,
        bandwidth: BandwidthRating::measured_directional(bytes_per_second).unwrap(),
        cuts: Vec::new(),
        max_in_flight: 2,
        interference_seconds_per_byte: 0.0,
    }
}

fn no_stealing() -> StealPolicy {
    StealPolicy {
        min_gain_seconds: 0.0,
        min_gain_fraction: 0.0,
        max_moves_per_batch: 0,
        max_moves_per_rebalance: 0,
    }
}

#[test]
fn advertisements_expire_within_the_maximum_and_never_go_back_a_generation() {
    let world = World::new();
    let residency = world.synthetic.residency(
        world.gpu("host-a"),
        world.synthetic.scope("host-a"),
        world.synthetic.single_execution().unwrap(),
    );
    let mut book = book();
    let first = ModelActivationGeneration::FIRST;
    assert_eq!(
        book.advertise(residency.clone(), first, Duration::ZERO, &world.clock),
        Err(AdvertiseRefusal::ZeroTtl)
    );
    assert_eq!(
        book.advertise(residency.clone(), first, 60 * SECOND, &world.clock),
        Err(AdvertiseRefusal::TtlAboveMaximum {
            ttl: 60 * SECOND,
            max_ttl: 30 * SECOND
        })
    );
    let second = ModelActivationGeneration::new(2);
    let entry = book
        .advertise(residency.clone(), second, 30 * SECOND, &world.clock)
        .unwrap();
    assert_eq!(
        entry.advertisement.expires_at,
        NOW.saturating_add(30 * SECOND)
    );
    assert_eq!(
        book.advertise(residency.clone(), first, 10 * SECOND, &world.clock),
        Err(AdvertiseRefusal::OlderGeneration {
            offered: first,
            held: second
        })
    );
    // The same generation renews.
    world.clock.advance(20 * SECOND);
    let renewed = book
        .advertise(residency.clone(), second, 30 * SECOND, &world.clock)
        .unwrap();
    assert_eq!(
        renewed.advertisement.expires_at,
        NOW.saturating_add(50 * SECOND)
    );
    world.clock.advance(30 * SECOND);
    assert_eq!(
        book.purge_expired(&world.clock),
        vec![(residency.device, residency.execution)]
    );
    assert!(book.is_empty());
    assert!(AdvertisementPolicy::new(Duration::ZERO).is_err());
}

#[test]
fn a_stale_peer_is_excluded_and_the_load_falls_back_to_the_origin() {
    let world = World::new();
    let execution = world.synthetic.single_execution().unwrap();
    let recipient = world.synthetic.scope("host-t");
    let mut book = book();
    let mut records = BTreeMap::new();
    let mut peers = Vec::new();
    for (machine, name, ttl) in [("host-a", "peer-a", 5), ("host-b", "peer-b", 30)] {
        let residency = world.synthetic.residency(
            world.gpu(machine),
            world.synthetic.scope(machine),
            execution,
        );
        book.advertise(
            residency.clone(),
            ModelActivationGeneration::FIRST,
            ttl * SECOND,
            &world.clock,
        )
        .unwrap();
        records.insert(
            (residency.device, execution),
            CurrentResidency {
                residency,
                generation: ModelActivationGeneration::FIRST,
            },
        );
        peers.push(PeerSource {
            device: world.gpu(machine),
            // A caller cannot authorize a peer: only the recheck can.
            spec: source(name, 1.25e9, SourceAuthorization::Authorized),
            grant: Some(
                world
                    .synthetic
                    .grant(
                        world.fleet_authority(),
                        recipient,
                        &[GrantedUse::Transfer],
                        FAR,
                    )
                    .unwrap(),
            ),
        });
    }
    let request = AdvertisementRequest {
        requester: world.synthetic.tenant.clone(),
        required: execution,
        purpose: AdvertisementPurpose::Transfer { recipient },
    };
    let batches = [1_000_000_000u64; 10];
    let origin = source("origin", 1.0e8, SourceAuthorization::Authorized);
    let plan_at = |clock: &ManualClock, origin: SourceSpec| {
        plan_with_fallback(
            &book,
            &request,
            &records,
            peers.clone(),
            origin,
            Vec::new(),
            &batches,
            no_stealing(),
            clock,
        )
    };

    world.clock.advance(10 * SECOND);
    let plan = plan_at(&world.clock, origin.clone()).unwrap();
    assert_eq!(plan.usable.len(), 1);
    assert_eq!(plan.usable[0].device, world.gpu("host-b"));
    assert_eq!(plan.usable[0].age, 10 * SECOND);
    assert!(matches!(
        plan.refused[0].reason,
        SourceRefusal::Advertisement(AdvertisementRefusal::Expired { .. })
    ));
    assert_eq!(plan.load.excluded(), &[SourceId::new("peer-a").unwrap()]);
    assert!(!plan.peers_exhausted);

    // Every peer stale: the origin alone loads every batch.
    world.clock.advance(30 * SECOND);
    let plan = plan_at(&world.clock, origin).unwrap();
    assert!(plan.peers_exhausted);
    assert_eq!(
        plan.load
            .batches_of(&SourceId::new("origin").unwrap())
            .len(),
        batches.len()
    );
    // Without an authorized origin nothing can load.
    assert_eq!(
        plan_at(
            &world.clock,
            source("origin", 1.0e8, SourceAuthorization::Unauthorized)
        )
        .unwrap_err(),
        RoutingError::Sources(SourcesError::NoAuthorizedSource)
    );
}

#[test]
fn a_source_is_usable_only_with_an_advertisement_a_record_and_a_current_generation() {
    let world = World::new();
    let execution = world.synthetic.single_execution().unwrap();
    let scope = world.synthetic.scope("host-a");
    let residency = world
        .synthetic
        .residency(world.gpu("host-a"), scope, execution);
    let request = AdvertisementRequest {
        requester: world.synthetic.tenant.clone(),
        required: execution,
        purpose: AdvertisementPurpose::Serve,
    };
    let grant = world
        .synthetic
        .grant(world.fleet_authority(), scope, &[GrantedUse::Serve], FAR)
        .unwrap();
    let mut book = book();
    let mut records = BTreeMap::new();
    let check = |book: &AdvertisementBook, records: &BTreeMap<_, CurrentResidency>| {
        book.recheck(
            &world.gpu("host-a"),
            &request,
            records,
            Some(&grant),
            &world.clock,
        )
    };
    assert_eq!(check(&book, &records), Err(SourceRefusal::NotAdvertised));
    book.advertise(
        residency.clone(),
        ModelActivationGeneration::FIRST,
        30 * SECOND,
        &world.clock,
    )
    .unwrap();
    assert_eq!(
        check(&book, &records),
        Err(SourceRefusal::NoAuthorityRecord)
    );
    records.insert(
        (residency.device, execution),
        CurrentResidency {
            residency: residency.clone(),
            generation: ModelActivationGeneration::new(2),
        },
    );
    assert!(matches!(
        check(&book, &records),
        Err(SourceRefusal::Advertisement(
            AdvertisementRefusal::OlderGeneration { .. }
        ))
    ));
    records.insert(
        (residency.device, execution),
        CurrentResidency {
            residency,
            generation: ModelActivationGeneration::FIRST,
        },
    );
    let usable = check(&book, &records).unwrap();
    assert_eq!(
        usable.rechecked.facts().generation,
        ModelActivationGeneration::FIRST
    );
}
