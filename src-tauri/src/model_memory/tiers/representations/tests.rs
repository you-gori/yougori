use std::collections::BTreeSet;
use std::time::Duration;

use super::*;
use crate::foundation::catalog::{ArtifactClass, ObjectRole, ObjectStatus};
use crate::foundation::ids::ContentKey;
use crate::model_memory::tiers::fakes::{
    close, execution, lease, model, publish, publish_prepared, scope, trust, world, SeededRng,
    World, GIB,
};
use crate::model_memory::tiers::object::Consumer;

const DAY_SECONDS: f64 = 86_400.0;

fn store(budget: SpaceBudget) -> RepresentationStore {
    RepresentationStore::new(budget, DAY_SECONDS).unwrap()
}

fn explicit(gib: u64) -> SpaceBudget {
    SpaceBudget::Explicit {
        max_bytes: gib * GIB,
    }
}

fn forecast(uses: f64, saving: f64, preparation: f64, penalty: f64) -> ImportAmortization {
    ImportAmortization {
        expected_uses: uses,
        per_use_saving_seconds: saving,
        preparation_cost_seconds: preparation,
        retention_penalty_seconds: penalty,
    }
}

/// Stand-in bytes of a model's part named `name`. The store plans with the sizes it is
/// told; the catalog only needs the objects to exist with their roles.
fn part_bytes(model: &ModelKey, name: &str) -> Vec<u8> {
    format!("{}/{name}", model.model).into_bytes()
}

/// The object of the model's scope holding `part_bytes(model, name)`.
fn part(model: &ModelKey, name: &str) -> ObjectRef {
    ObjectRef {
        scope: model.scope.clone(),
        class: ArtifactClass::ModelWeights,
        content: ContentKey::of(&part_bytes(model, name)),
    }
}

/// The importer's execution in the model's scope.
fn owner(model: &ModelKey) -> Consumer {
    let tenant = model.scope.tenant_id().unwrap().clone();
    Consumer {
        trust: trust(tenant.as_str()),
        tenant,
        execution: execution("exe-importer"),
    }
}

/// The catalog's importer publishes the model's original `name`.
fn publish_original(world: &mut World, model: &ModelKey, name: &str) -> ObjectRef {
    let object = publish(
        &mut world.catalog,
        &owner(model),
        &part_bytes(model, name),
        ObjectRole::Original,
    );
    assert_eq!(object, part(model, name));
    object
}

/// The catalog's importer publishes `name`, prepared from the model's part `from`.
fn publish_derived(world: &mut World, model: &ModelKey, name: &str, from: &str) -> ObjectRef {
    let object = publish_prepared(
        &mut world.catalog,
        &owner(model),
        &part_bytes(model, name),
        &[&part(model, from)],
    );
    assert_eq!(object, part(model, name));
    object
}

fn original(model: &ModelKey, name: &str, gib: u64) -> RepresentationProposal {
    RepresentationProposal::Original {
        model: model.clone(),
        object: part(model, name),
        bytes: gib * GIB,
    }
}

fn derived(
    model: &ModelKey,
    name: &str,
    kind: DerivedKind,
    tier: Tier,
    gib: u64,
    forecast: ImportAmortization,
) -> RepresentationProposal {
    RepresentationProposal::Derived {
        model: model.clone(),
        object: part(model, name),
        kind,
        tier,
        bytes: gib * GIB,
        forecast,
    }
}

/// Raw prepared that amortizes: 21 * 8 = 168 > 120 + 40.
fn raw(model: &ModelKey, gib: u64) -> RepresentationProposal {
    derived(
        model,
        "raw",
        DerivedKind::RawPrepared,
        Tier::LocalStorage,
        gib,
        forecast(21.0, 8.0, 120.0, 40.0),
    )
}

/// A host copy named `name` that amortizes: 10 * 10 = 100 > 0 + 10.
fn host_copy(model: &ModelKey, name: &str, gib: u64) -> RepresentationProposal {
    derived(
        model,
        name,
        DerivedKind::HostCopy,
        Tier::ReclaimableHost,
        gib,
        forecast(10.0, 10.0, 0.0, 10.0),
    )
}

#[test]
fn without_an_explicit_budget_a_model_keeps_one_representation() {
    let world = world(&["alice", "bob", "carol"]);
    let clock = &world.clock;
    let alice = model("alice", "llama-8b");
    let bob = model("bob", "llama-8b");
    let mut unbudgeted = store(SpaceBudget::Unset);
    unbudgeted
        .admit(original(&alice, "original", 14), clock)
        .unwrap();
    // Another model keeps its own one representation.
    unbudgeted
        .admit(original(&bob, "original", 14), clock)
        .unwrap();
    let alices_raw = raw(&alice, 14);
    assert_eq!(
        unbudgeted.admit(alices_raw.clone(), clock),
        Err(RepresentationRefusal::NoExplicitBudget {
            held: RepresentationKind::Original
        })
    );
    assert_eq!(
        unbudgeted.plan_room(&alices_raw, &world.catalog, clock),
        Err(RepresentationRefusal::NoExplicitBudget {
            held: RepresentationKind::Original
        })
    );
    assert_eq!(unbudgeted.held_bytes(), 28 * GIB);

    // A publisher-prepared form with no original is that model's one representation.
    let carol = model("carol", "mistral-7b");
    unbudgeted
        .admit(
            derived(
                &carol,
                "compressed",
                DerivedKind::CompressedPrepared,
                Tier::LocalStorage,
                4,
                forecast(10.0, 5.0, 10.0, 5.0),
            ),
            clock,
        )
        .unwrap();
    assert_eq!(
        unbudgeted.admit(original(&carol, "original", 14), clock),
        Err(RepresentationRefusal::NoExplicitBudget {
            held: RepresentationKind::CompressedPrepared
        })
    );

    // With an explicit budget the second representation is admitted, and the budget
    // cannot then be unset.
    unbudgeted.set_budget(explicit(64)).unwrap();
    unbudgeted.admit(alices_raw, clock).unwrap();
    assert_eq!(
        unbudgeted.set_budget(SpaceBudget::Unset),
        Err(RepresentationRefusal::SeveralRepresentationsHeld {
            model: alice.clone()
        })
    );
    assert_eq!(unbudgeted.budget(), explicit(64));
    assert_eq!(unbudgeted.representations_of(&alice).len(), 2);
}

#[test]
fn the_budget_refuses_an_extra_representation() {
    let world = world(&["alice"]);
    let clock = &world.clock;
    let alice = model("alice", "llama-8b");
    let mut budgeted = store(explicit(30));
    budgeted
        .admit(original(&alice, "original", 14), clock)
        .unwrap();
    budgeted.admit(raw(&alice, 14), clock).unwrap();
    let compressed = derived(
        &alice,
        "compressed",
        DerivedKind::CompressedPrepared,
        Tier::LocalStorage,
        10,
        forecast(400.0, 2.0, 300.0, 10.0),
    );
    assert_eq!(
        budgeted.admit(compressed, clock),
        Err(RepresentationRefusal::OverBudget {
            max_bytes: 30 * GIB,
            held_bytes: 28 * GIB,
            requested_bytes: 10 * GIB,
        })
    );
    assert_eq!(budgeted.held_bytes(), 28 * GIB);
    assert_eq!(budgeted.representations_of(&alice).len(), 2);

    // Original, raw prepared, compressed prepared and host copy together need a budget
    // that covers all four: 14 + 14 + 8 + 4 = 40 GiB (line 548).
    let four_kinds = |budget| {
        let mut held = store(budget);
        held.admit(original(&alice, "original", 14), clock)?;
        held.admit(raw(&alice, 14), clock)?;
        held.admit(
            derived(
                &alice,
                "compressed",
                DerivedKind::CompressedPrepared,
                Tier::LocalStorage,
                8,
                forecast(400.0, 2.0, 300.0, 10.0),
            ),
            clock,
        )?;
        held.admit(host_copy(&alice, "host-copy", 4), clock)?;
        Ok::<u64, RepresentationRefusal>(held.held_bytes())
    };
    assert_eq!(four_kinds(explicit(40)), Ok(40 * GIB));
    assert_eq!(
        four_kinds(explicit(39)),
        Err(RepresentationRefusal::OverBudget {
            max_bytes: 39 * GIB,
            held_bytes: 36 * GIB,
            requested_bytes: 4 * GIB,
        })
    );
    assert_eq!(
        four_kinds(SpaceBudget::Unset),
        Err(RepresentationRefusal::NoExplicitBudget {
            held: RepresentationKind::Original
        })
    );
}

#[test]
fn a_derived_representation_must_amortize_to_be_prepared() {
    let world = world(&["alice"]);
    let clock = &world.clock;
    let alice = model("alice", "llama-8b");
    let mut roomy = store(explicit(1_000));
    roomy
        .admit(original(&alice, "original", 14), clock)
        .unwrap();
    // 20 * 8 = 160 is not more than 120 + 40, even with room to spare (line 550).
    assert_eq!(
        roomy.admit(
            derived(
                &alice,
                "raw",
                DerivedKind::RawPrepared,
                Tier::LocalStorage,
                14,
                forecast(20.0, 8.0, 120.0, 40.0),
            ),
            clock
        ),
        Err(RepresentationRefusal::DoesNotAmortize {
            expected_saving_seconds: 160.0,
            total_cost_seconds: 160.0,
        })
    );
    // A forecast that is not a number is refused, not clamped.
    assert_eq!(
        roomy.admit(
            derived(
                &alice,
                "raw",
                DerivedKind::RawPrepared,
                Tier::LocalStorage,
                14,
                forecast(f64::NAN, 8.0, 120.0, 40.0),
            ),
            clock
        ),
        Err(RepresentationRefusal::Amortization(
            AmortizationError::NotFinite {
                term: "expected_uses"
            }
        ))
    );
    // The same must hold to make room for it.
    let mut full = store(explicit(20));
    full.admit(original(&alice, "original", 14), clock).unwrap();
    assert!(matches!(
        full.plan_room(
            &derived(
                &alice,
                "compressed",
                DerivedKind::CompressedPrepared,
                Tier::LocalStorage,
                8,
                forecast(155.0, 2.0, 300.0, 10.0),
            ),
            &world.catalog,
            clock
        ),
        Err(RepresentationRefusal::DoesNotAmortize { .. })
    ));
    roomy.admit(raw(&alice, 14), clock).unwrap();
    assert_eq!(roomy.held_bytes(), 28 * GIB);
}

#[test]
fn representations_stay_in_their_tiers_and_scope() {
    let world = world(&["alice", "bob"]);
    let clock = &world.clock;
    let alice = model("alice", "llama-8b");
    let mut budgeted = store(explicit(100));
    assert_eq!(
        RepresentationKind::ALL.map(RepresentationKind::tiers),
        [
            &[Tier::LocalStorage][..],
            &[Tier::LocalStorage][..],
            &[Tier::LocalStorage][..],
            &[Tier::PinnedHost, Tier::ReclaimableHost][..],
        ]
    );
    assert_eq!(RepresentationKind::Original.derived(), None);
    for kind in [
        DerivedKind::RawPrepared,
        DerivedKind::CompressedPrepared,
        DerivedKind::HostCopy,
    ] {
        assert_eq!(kind.kind().derived(), Some(kind));
    }
    let cheap = forecast(10.0, 5.0, 1.0, 1.0);
    for (kind, tier) in [
        (DerivedKind::HostCopy, Tier::LocalStorage),
        (DerivedKind::RawPrepared, Tier::PinnedHost),
        (DerivedKind::CompressedPrepared, Tier::Gpu),
        (DerivedKind::RawPrepared, Tier::AuthorizedPeer),
        (DerivedKind::HostCopy, Tier::Remote),
    ] {
        assert_eq!(
            budgeted.admit(derived(&alice, "x", kind, tier, 1, cheap), clock),
            Err(RepresentationRefusal::WrongTier {
                kind: kind.kind(),
                tier
            })
        );
    }
    // A representation of Alice's model in Bob's scope would leave its scope, even with
    // equal content (line 546).
    let misplaced = RepresentationProposal::Original {
        model: alice.clone(),
        object: ObjectRef {
            scope: scope("bob"),
            ..part(&alice, "original")
        },
        bytes: GIB,
    };
    assert_eq!(
        budgeted.admit(misplaced, clock),
        Err(RepresentationRefusal::ScopeMismatch {
            model: scope("alice"),
            object: scope("bob"),
        })
    );
    assert_eq!(
        budgeted.admit(original(&alice, "original", 0), clock),
        Err(RepresentationRefusal::ZeroBytes)
    );
    budgeted
        .admit(original(&alice, "original", 14), clock)
        .unwrap();
    assert_eq!(
        budgeted.admit(original(&alice, "another", 14), clock),
        Err(RepresentationRefusal::AlreadyHeld {
            kind: RepresentationKind::Original
        })
    );
    // A "prepared" form that is the original's own object is not a second representation.
    let same_object = derived(
        &alice,
        "original",
        DerivedKind::RawPrepared,
        Tier::LocalStorage,
        14,
        cheap,
    );
    assert_eq!(
        budgeted.admit(same_object, clock),
        Err(RepresentationRefusal::SameObjectAsHeld {
            kind: RepresentationKind::Original
        })
    );
    assert_eq!(budgeted.held_bytes(), 14 * GIB);
}

#[test]
fn room_is_made_by_measured_reuse_value() {
    let mut world = world(&["alice"]);
    let alice = model("alice", "llama-8b");
    publish_original(&mut world, &alice, "original");
    publish_derived(&mut world, &alice, "raw", "original");
    let clock = world.clock.clone();
    let mut budgeted = store(explicit(40));
    budgeted
        .admit(original(&alice, "original", 14), &clock)
        .unwrap();
    budgeted.admit(raw(&alice, 14), &clock).unwrap();
    budgeted
        .admit(
            derived(
                &alice,
                "host-copy",
                DerivedKind::HostCopy,
                Tier::ReclaimableHost,
                8,
                forecast(11.0, 3.0, 0.0, 30.0),
            ),
            &clock,
        )
        .unwrap();
    // One day: the raw form is loaded 100 times saving 8 s each, the host copy twice
    // saving 3 s each.
    for _ in 0..100 {
        clock.advance(Duration::from_secs(864));
        budgeted
            .record_use(&alice, RepresentationKind::RawPrepared, 8.0, &clock)
            .unwrap();
    }
    for _ in 0..2 {
        budgeted
            .record_use(&alice, RepresentationKind::HostCopy, 3.0, &clock)
            .unwrap();
    }
    // Measured: raw 100 * 8 - (120 + 40) = 640 s; host copy 2 * 3 - 30 = -24 s.
    let value = |kind| {
        let terms = budgeted
            .measured_amortization(&alice, kind, &clock)
            .unwrap();
        terms.expected_saving_seconds().unwrap() - terms.total_cost_seconds().unwrap()
    };
    let raw_value = value(DerivedKind::RawPrepared);
    assert!(close(raw_value, 640.0, 1e-6));
    assert!(close(value(DerivedKind::HostCopy), -24.0, 1e-9));

    // A compressed form forecast at 200 * 2.5 - 310 = 190 s needs 6 GiB more than fits.
    let compressed = derived(
        &alice,
        "compressed",
        DerivedKind::CompressedPrepared,
        Tier::LocalStorage,
        10,
        forecast(200.0, 2.5, 300.0, 10.0),
    );
    assert!(matches!(
        budgeted.admit(compressed.clone(), &clock),
        Err(RepresentationRefusal::OverBudget { .. })
    ));
    // The host copy is worth least per byte, and its 8 GiB cover the 6 GiB needed.
    let plan = budgeted
        .plan_room(&compressed, &world.catalog, &clock)
        .unwrap();
    assert_eq!(
        plan,
        [PlannedEviction {
            model: alice.clone(),
            object: part(&alice, "host-copy"),
            kind: DerivedKind::HostCopy,
            tier: Tier::ReclaimableHost,
            bytes: 8 * GIB,
        }]
    );
    assert_eq!(budgeted.forget(&plan[0]), Ok(8 * GIB));
    budgeted.admit(compressed, &clock).unwrap();
    assert_eq!(budgeted.held_bytes(), 38 * GIB);

    // The compressed form is still being imported, so the catalog has none of it to
    // evict. Room for a 4 GiB copy can come only from the raw form, which is worth more
    // than the newcomer's 100 * 2 - 10 = 190 s.
    let pinned_copy = derived(
        &alice,
        "host-copy-2",
        DerivedKind::HostCopy,
        Tier::PinnedHost,
        4,
        forecast(100.0, 2.0, 0.0, 10.0),
    );
    assert_eq!(
        budgeted.plan_room(&pinned_copy, &world.catalog, &clock),
        Err(RepresentationRefusal::DisplacementNotWorthIt {
            displaced_value_seconds: raw_value,
            newcomer_value_seconds: 190.0,
        })
    );
    // While the raw form is leased the catalog would evict nothing, so there is no room
    // at all.
    let importer = owner(&alice);
    let raw_lease = lease(&mut world.catalog, &importer, &part(&alice, "raw")).unwrap();
    assert_eq!(
        budgeted.plan_room(&pinned_copy, &world.catalog, &clock),
        Err(RepresentationRefusal::NoRoom {
            needed_bytes: 2 * GIB,
            evictable_bytes: 0,
        })
    );

    // An original outranks every cache entry: once the lease ends it displaces the raw
    // form whatever its measured value.
    world
        .catalog
        .release_lease(&importer.scope(), &importer.execution, raw_lease)
        .unwrap();
    let qwen = model("alice", "qwen-7b");
    let plan = budgeted
        .plan_room(&original(&qwen, "original", 8), &world.catalog, &clock)
        .unwrap();
    assert_eq!(
        plan.iter()
            .map(|eviction| eviction.kind)
            .collect::<Vec<_>>(),
        [DerivedKind::RawPrepared]
    );
}

#[test]
fn representations_are_kept_only_while_measured_reuse_amortizes() {
    let mut world = world(&["alice"]);
    let alice = model("alice", "llama-8b");
    publish_original(&mut world, &alice, "original");
    publish_derived(&mut world, &alice, "raw", "original");
    publish_derived(&mut world, &alice, "compressed", "original");
    let clock = world.clock.clone();
    let mut budgeted = store(explicit(100));
    budgeted
        .admit(original(&alice, "original", 14), &clock)
        .unwrap();
    budgeted.admit(raw(&alice, 14), &clock).unwrap();
    budgeted
        .admit(
            derived(
                &alice,
                "compressed",
                DerivedKind::CompressedPrepared,
                Tier::LocalStorage,
                8,
                forecast(400.0, 2.0, 300.0, 10.0),
            ),
            &clock,
        )
        .unwrap();
    // One day: the raw form is used 30 times (240 > 160), the compressed one 50 times
    // (100 < 310), far short of its 400-use forecast.
    for step in 0..60 {
        clock.advance(Duration::from_secs(1_440));
        if step < 30 {
            budgeted
                .record_use(&alice, RepresentationKind::RawPrepared, 8.0, &clock)
                .unwrap();
        }
        if step < 50 {
            budgeted
                .record_use(&alice, RepresentationKind::CompressedPrepared, 2.0, &clock)
                .unwrap();
        }
    }
    let review = budgeted.review(&world.catalog, &clock).unwrap();
    assert_eq!(review.len(), 1);
    assert_eq!(review[0].kind, DerivedKind::CompressedPrepared);
    assert_eq!(review[0].tier, Tier::LocalStorage);

    // What the catalog would not evict now, such as a leased representation, is kept.
    let importer = owner(&alice);
    let held = lease(&mut world.catalog, &importer, &part(&alice, "compressed")).unwrap();
    assert!(budgeted.review(&world.catalog, &clock).unwrap().is_empty());
    world
        .catalog
        .release_lease(&importer.scope(), &importer.execution, held)
        .unwrap();

    // A second idle day halves the raw form's measured rate: 15 * 8 = 120 < 160. Both
    // leave, least measured value per byte first: compressed (50 - 310) / 8 GiB, then raw
    // (120 - 160) / 14 GiB.
    clock.advance(Duration::from_secs(86_400));
    let review = budgeted.review(&world.catalog, &clock).unwrap();
    assert_eq!(
        review
            .iter()
            .map(|eviction| eviction.kind)
            .collect::<Vec<_>>(),
        [DerivedKind::CompressedPrepared, DerivedKind::RawPrepared]
    );
    // The original is never reviewed.
    assert!(review
        .iter()
        .all(|eviction| eviction.object != part(&alice, "original")));
}

#[test]
fn enforcing_a_smaller_budget_never_evicts_an_original() {
    let mut world = world(&["alice"]);
    let alice = model("alice", "llama-70b");
    publish_original(&mut world, &alice, "original");
    publish_derived(&mut world, &alice, "raw", "original");
    // The catalog holds this one as prepared, and so would evict it, but the store holds
    // it as a model's original: neither side alone may make an original evictable.
    let quantized = model("alice", "llama-70b-q4");
    publish_prepared(
        &mut world.catalog,
        &owner(&quantized),
        &part_bytes(&quantized, "imported"),
        &[&part(&alice, "original")],
    );
    let clock = world.clock.clone();
    let mut budgeted = store(explicit(60));
    budgeted
        .admit(original(&alice, "original", 30), &clock)
        .unwrap();
    budgeted.admit(raw(&alice, 8), &clock).unwrap();
    budgeted
        .admit(
            RepresentationProposal::Original {
                model: quantized.clone(),
                object: part(&quantized, "imported"),
                bytes: 4 * GIB,
            },
            &clock,
        )
        .unwrap();
    budgeted.set_budget(explicit(20)).unwrap();

    let enforcement = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
    assert_eq!(enforcement.evictions.len(), 1);
    assert_eq!(enforcement.evictions[0].kind, DerivedKind::RawPrepared);
    // 42 GiB held against 20: evicting the raw form leaves 14 GiB unmet, which the
    // originals hold and keep.
    assert_eq!(enforcement.unmet_bytes, 14 * GIB);
    assert_eq!(budgeted.forget(&enforcement.evictions[0]), Ok(8 * GIB));
    let kinds: Vec<RepresentationKind> = budgeted
        .representations()
        .into_iter()
        .map(|held| held.kind)
        .collect();
    assert_eq!(
        kinds,
        [RepresentationKind::Original, RepresentationKind::Original]
    );

    let again = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
    assert!(again.evictions.is_empty());
    assert_eq!(again.unmet_bytes, 14 * GIB);
    assert_eq!(budgeted.held_bytes(), 34 * GIB);
    // Under no budget at all nothing is planned either.
    budgeted.set_budget(explicit(1_000)).unwrap();
    assert_eq!(
        budgeted.enforce_budget(&world.catalog, &clock).unwrap(),
        BudgetEnforcement {
            evictions: Vec::new(),
            unmet_bytes: 0,
        }
    );
}

#[test]
fn evictions_go_least_measured_value_per_retained_byte_first() {
    // §2.7 line 448: marginal saved latency per retained byte, here measured (line 548).
    let mut world = world(&["alice"]);
    let llama = model("alice", "llama-8b");
    let mistral = model("alice", "mistral-7b");
    let qwen = model("alice", "qwen-7b");
    publish_original(&mut world, &llama, "original");
    publish_derived(&mut world, &llama, "raw", "original");
    let clock = world.clock.clone();
    let mut budgeted = store(explicit(40));
    budgeted
        .admit(host_copy(&llama, "copy", 8), &clock)
        .unwrap();
    budgeted
        .admit(host_copy(&mistral, "copy", 2), &clock)
        .unwrap();
    budgeted.admit(host_copy(&qwen, "copy", 4), &clock).unwrap();
    budgeted.admit(raw(&llama, 10), &clock).unwrap();
    // One day of uses saving 10 s each, against a 10 s retention penalty: llama's copy
    // 9 * 10 - 10 = 80 s over 8 GiB (10 s/GiB), mistral's 5 * 10 - 10 = 40 s over 2 GiB
    // (20 s/GiB) and qwen's 3 * 10 - 10 = 20 s over 4 GiB (5 s/GiB). The raw form is
    // never used: 0 - 160 s over 10 GiB (-16 s/GiB).
    clock.advance(Duration::from_secs(86_400));
    for (model, uses) in [(&llama, 9), (&mistral, 5), (&qwen, 3)] {
        for _ in 0..uses {
            budgeted
                .record_use(model, RepresentationKind::HostCopy, 10.0, &clock)
                .unwrap();
        }
    }
    // While the raw form is leased the catalog would not evict it, so the host copies go
    // in order of value per byte: qwen's, then llama's, covering the 10 GiB over budget.
    let importer = owner(&llama);
    let held = lease(&mut world.catalog, &importer, &part(&llama, "raw")).unwrap();
    budgeted.set_budget(explicit(14)).unwrap();
    let enforcement = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
    assert_eq!(
        enforcement
            .evictions
            .iter()
            .map(|eviction| (eviction.model.clone(), eviction.bytes))
            .collect::<Vec<_>>(),
        [(qwen.clone(), 4 * GIB), (llama.clone(), 8 * GIB)]
    );
    assert_eq!(enforcement.unmet_bytes, 0);
    // Once the lease ends the unused raw form, worth least, leaves first and alone.
    world
        .catalog
        .release_lease(&importer.scope(), &importer.execution, held)
        .unwrap();
    let enforcement = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
    assert_eq!(enforcement.evictions.len(), 1);
    assert_eq!(enforcement.evictions[0].object, part(&llama, "raw"));
    assert_eq!(enforcement.evictions[0].tier, Tier::LocalStorage);
}

#[test]
fn forgetting_needs_the_held_object() {
    let world = world(&["alice"]);
    let clock = &world.clock;
    let alice = model("alice", "llama-8b");
    let mut budgeted = store(explicit(100));
    budgeted
        .admit(original(&alice, "original", 14), clock)
        .unwrap();
    budgeted.admit(raw(&alice, 14), clock).unwrap();
    let stranger = PlannedEviction {
        model: alice.clone(),
        object: part(&alice, "not-held"),
        kind: DerivedKind::RawPrepared,
        tier: Tier::LocalStorage,
        bytes: GIB,
    };
    assert_eq!(
        budgeted.forget(&stranger),
        Err(RepresentationRefusal::NotHeld {
            model: alice.clone(),
            kind: RepresentationKind::RawPrepared,
        })
    );
    assert_eq!(
        budgeted.record_use(&alice, RepresentationKind::HostCopy, 1.0, clock),
        Err(RepresentationRefusal::NotHeld {
            model: alice.clone(),
            kind: RepresentationKind::HostCopy,
        })
    );
    assert_eq!(
        budgeted.record_use(&alice, RepresentationKind::RawPrepared, -1.0, clock),
        Err(RepresentationRefusal::Input(InputError::Negative {
            field: "saved_seconds"
        }))
    );
    // After the owner's local model deletion every representation of the model leaves
    // this budget.
    assert_eq!(budgeted.forget_model(&alice), 28 * GIB);
    assert_eq!(budgeted.held_bytes(), 0);
    assert!(budgeted.representations().is_empty());
    assert_eq!(
        RepresentationStore::new(SpaceBudget::Unset, 0.0),
        Err(RepresentationRefusal::Input(InputError::NotPositive {
            field: "horizon_seconds"
        }))
    );
}

/// Carries out planned evictions: local storage through the catalog's cache eviction,
/// which refuses an original, host copies by dropping them.
fn carry_out(world: &mut World, budgeted: &mut RepresentationStore, evictions: &[PlannedEviction]) {
    for eviction in evictions {
        if eviction.tier == Tier::LocalStorage {
            world
                .catalog
                .evict_cache(&eviction.object.scope, &[eviction.object.id()])
                .unwrap();
        }
        budgeted.forget(eviction).unwrap();
    }
}

#[test]
fn random_admissions_keep_the_budget_and_every_original() {
    let mut world = world(&["alice"]);
    let clock = world.clock.clone();
    let mut rng = SeededRng::new(0x5EED_0002);
    let mut max_bytes = 96 * GIB;
    let mut budgeted = store(SpaceBudget::Explicit { max_bytes });
    let models: Vec<ModelKey> = (0..6)
        .map(|index| model("alice", &format!("model-{index}")))
        .collect();
    // Every prepared form is derived from its model's source file, which stays published.
    for model in &models {
        publish_original(&mut world, model, "source");
    }
    let mut originals = Vec::new();
    let mut evicted = 0usize;
    for step in 0..200u64 {
        clock.advance(Duration::from_secs(60));
        let model = &models[rng.below(6) as usize];
        let kind = RepresentationKind::ALL[rng.below(4) as usize];
        let bytes = (1 + rng.below(16)) * GIB;
        let name = format!("object-{step}");
        let proposal = match kind.derived() {
            None => RepresentationProposal::Original {
                model: model.clone(),
                object: part(model, &name),
                bytes,
            },
            Some(derived) => RepresentationProposal::Derived {
                model: model.clone(),
                object: part(model, &name),
                kind: derived,
                tier: derived.kind().tiers()[0],
                bytes,
                forecast: forecast(
                    rng.below(200) as f64,
                    1.0 + rng.below(10) as f64,
                    rng.below(500) as f64,
                    rng.below(100) as f64,
                ),
            },
        };
        let admitted = match budgeted.admit(proposal.clone(), &clock) {
            Ok(()) => true,
            Err(RepresentationRefusal::OverBudget { .. }) => {
                match budgeted.plan_room(&proposal, &world.catalog, &clock) {
                    Ok(evictions) => {
                        carry_out(&mut world, &mut budgeted, &evictions);
                        evicted += evictions.len();
                        budgeted.admit(proposal.clone(), &clock).unwrap();
                        true
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };
        if admitted && proposal.tier() == Tier::LocalStorage {
            // The importer publishes what the store admitted to local storage.
            match kind.derived() {
                None => {
                    publish_original(&mut world, model, &name);
                }
                Some(_) => {
                    publish_derived(&mut world, model, &name, "source");
                }
            }
        }
        if admitted && kind == RepresentationKind::Original {
            originals.push(proposal.object().clone());
        }
        for held in budgeted.representations() {
            if rng.below(3) == 0 {
                budgeted
                    .record_use(&held.model, held.kind, rng.below(10) as f64, &clock)
                    .unwrap();
            }
        }
        if step % 50 == 49 {
            max_bytes -= 16 * GIB;
            budgeted
                .set_budget(SpaceBudget::Explicit { max_bytes })
                .unwrap();
            let enforcement = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
            carry_out(&mut world, &mut budgeted, &enforcement.evictions);
            evicted += enforcement.evictions.len();
            if enforcement.unmet_bytes > 0 {
                assert!(budgeted
                    .representations()
                    .iter()
                    .all(|held| held.kind == RepresentationKind::Original));
            }
        }
        let held = budgeted.representations();
        assert_eq!(
            budgeted.held_bytes(),
            held.iter().map(|held| held.bytes).sum::<u64>()
        );
        assert!(
            budgeted.held_bytes() <= max_bytes
                || held
                    .iter()
                    .all(|held| held.kind == RepresentationKind::Original)
        );
        let held_objects: BTreeSet<ObjectRef> = held.into_iter().map(|held| held.object).collect();
        for kept in &originals {
            assert!(held_objects.contains(kept), "an original was evicted");
            assert_eq!(
                world.catalog.status(&kept.scope, kept.id()),
                ObjectStatus::Published
            );
        }
    }
    assert!(!originals.is_empty());
    assert!(evicted > 0);
}
