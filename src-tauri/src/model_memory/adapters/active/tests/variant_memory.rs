//! Memory of merged variants materialized on the activation (G06: "variant memory
//! accounting"; GPU-W10 line 1307; GPU §3.9): a CORE-03 child of the activation's
//! reservation, refused past it, and released through the ledger only once the variant
//! serves nothing and no request may use it.

use super::*;

fn grants_for(world: &World, adapters: &[&str]) -> Vec<ScopedGrant> {
    let mut grants = world.adapter_grants("acme", adapters);
    grants.push(world.grant("models", "acme", artifact("base-8b")));
    grants
}

fn materialize(
    world: &mut World,
    adapters: &[&str],
    bytes: u64,
) -> Result<VariantReceipt, VariantRefusal> {
    world.adapters.materialize_variant(
        &mut world.host,
        variant(adapters),
        bytes,
        &operation("materialize"),
    )
}

#[test]
fn a_materialized_variant_holds_its_memory_as_a_child_of_the_activation() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = grants_for(&world, &["sql"]);
    let receipt = materialize(&mut world, &["sql"], GIB).unwrap();
    assert!(receipt.newly_materialized);
    let record = world.record(receipt.reservation).unwrap();
    assert_eq!(record.parent(), Some(world.parent));
    assert_eq!(record.state(), ReservationState::InUse);
    assert_eq!(record.granted().get(vram()), GIB);
    assert_eq!(world.room(), 3 * GIB);
    assert_eq!(world.adapters.variant_bytes(), GIB);
    // Its memory is not an adapter's: the adapter limits are untouched.
    assert_eq!(world.adapters.resident_bytes(), 0);
    // Materializing it again reserves nothing more.
    let again = materialize(&mut world, &["sql"], GIB).unwrap();
    assert_eq!(again.reservation, receipt.reservation);
    assert!(!again.newly_materialized);
    assert_eq!(world.room(), 3 * GIB);

    // It serves until retired; a request in flight keeps its memory.
    let merged = receipt.variant;
    world
        .admit(1, Route::Merged(merged), "acme", &grants)
        .unwrap();
    assert_eq!(
        world
            .adapters
            .release_variant(&mut world.host, merged, SourceClass::GuestReport),
        Err(VariantReleaseRefusal::StillServing { variant: merged })
    );
    let drain = world.adapters.retire_variant(merged, NOW).unwrap();
    assert_eq!(
        drain.draining,
        vec![DrainingRequest {
            lease: LeaseId::new(1),
            route: Route::Merged(merged),
            bound_at: NOW.saturating_add(DRAIN),
            revoked: None,
        }]
    );
    assert!(drain.unload_variants.is_empty());
    assert_eq!(
        world.admit(2, Route::Merged(merged), "acme", &grants),
        Err(RouteRefusal::VariantRetired { variant: merged })
    );
    assert_eq!(
        world.adapters.retire_variant(merged, NOW),
        Err(VariantRefusal::Ended { variant: merged })
    );
    assert_eq!(
        materialize(&mut world, &["sql"], GIB),
        Err(VariantRefusal::Ended { variant: merged })
    );
    assert!(matches!(
        world
            .adapters
            .release_variant(&mut world.host, merged, SourceClass::GuestReport),
        Err(VariantReleaseRefusal::StillInUse { .. })
    ));
    assert_eq!(
        world.adapters.variant(&merged),
        Some(VariantView {
            reservation: Some(receipt.reservation),
            bytes: GIB,
            invalidated: None,
            retired: true,
            in_flight: 1,
        })
    );

    // Once the request ends, the runner unloads it and the ledger takes the memory back.
    assert_eq!(world.adapters.finish(LeaseId::new(1)), None);
    assert_eq!(world.adapters.unloadable_variants(), vec![merged]);
    let released = world
        .adapters
        .release_variant(&mut world.host, merged, SourceClass::GuestReport)
        .unwrap();
    assert!(matches!(released, ReleaseOutcome::Released { .. }));
    assert!(world.record(receipt.reservation).is_none());
    assert_eq!(world.room(), 4 * GIB);
    assert_eq!(world.adapters.variant(&merged), None);
    assert_eq!(world.adapters.variant_bytes(), 0);
}

#[test]
fn a_variant_past_the_activations_reservation_is_refused_and_left_unrecorded() {
    let mut world = World::new(TWO_SLOTS, 512 * MIB);
    let merged = execution(&variant(&["sql"]).logical).identity().unwrap();
    let Err(VariantRefusal::Ledger { refusal }) = materialize(&mut world, &["sql"], GIB) else {
        panic!("the ledger did not refuse the variant");
    };
    assert_eq!(refusal.limit, LimitKind::ParentReservation);
    assert_eq!(refusal.requested, GIB);
    assert_eq!(world.adapters.variant(&merged), None);
    assert_eq!(
        materialize(&mut world, &["sql"], 0),
        Err(VariantRefusal::NoBytes)
    );
    assert_eq!(world.adapters.variant(&merged), None);
    assert_eq!(world.room(), 512 * MIB);
    // A variant recorded without memory here keeps it elsewhere; this one materializes.
    world
        .adapters
        .record_variant(variant(&["sql"]), &world.host)
        .unwrap();
    assert_eq!(
        world
            .adapters
            .release_variant(&mut world.host, merged, SourceClass::GuestReport),
        Err(VariantReleaseRefusal::NoMemory { variant: merged })
    );
    let receipt = materialize(&mut world, &["sql"], 256 * MIB).unwrap();
    assert!(receipt.newly_materialized);
    assert_eq!(world.room(), 256 * MIB);
    let unknown = execution(&variant(&["legal"]).logical).identity().unwrap();
    assert_eq!(
        world.adapters.retire_variant(unknown, NOW),
        Err(VariantRefusal::NotRecorded { variant: unknown })
    );
    assert_eq!(
        world
            .adapters
            .release_variant(&mut world.host, unknown, SourceClass::GuestReport),
        Err(VariantReleaseRefusal::NotRecorded { variant: unknown })
    );
}

#[test]
fn a_revoked_input_releases_its_variants_memory_once_unused() {
    let mut world = World::new(TWO_SLOTS, 4 * GIB);
    let grants = grants_for(&world, &["sql", "legal"]);
    let idle = materialize(&mut world, &["sql"], GIB).unwrap().variant;
    let busy = materialize(&mut world, &["sql", "legal"], GIB)
        .unwrap()
        .variant;
    world
        .admit(1, Route::Merged(busy), "acme", &grants)
        .unwrap();
    assert_eq!(world.room(), 2 * GIB);
    let at = at_seconds(10);
    let revoked = world.revoke("sql", at, &[]);
    let effects = world.adapters.apply_revocation(&revoked);
    assert_eq!(
        effects.variants.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([idle, busy])
    );
    // The idle one unloads at once; the busy one once its request is past its bound.
    assert_eq!(effects.drain.unload_variants, vec![idle]);
    world
        .adapters
        .release_variant(&mut world.host, idle, SourceClass::GuestReport)
        .unwrap();
    let overdue = world.adapters.end_overdue(at.saturating_add(DRAIN));
    assert_eq!(overdue.unload_variants, vec![busy]);
    // A weaker source than the runtime's own report keeps the memory counted.
    assert!(matches!(
        world
            .adapters
            .release_variant(&mut world.host, busy, SourceClass::Fixture),
        Err(VariantReleaseRefusal::Ledger(_))
    ));
    assert_eq!(world.room(), 3 * GIB);
    world
        .adapters
        .release_variant(&mut world.host, busy, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(world.room(), 4 * GIB);
    assert_eq!(world.adapters.variant_bytes(), 0);
}
