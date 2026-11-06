use std::collections::BTreeSet;
use std::time::Duration;

use super::*;
use crate::foundation::catalog::ImportAmortization;
use crate::foundation::catalog::{ArtifactClass, Holder, ReadError, RootKind, VerifyError};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::ContentKey;
use crate::foundation::ledger::{Limit, ReleaseOutcome, ReservationState, RetryProspect};
use crate::model_memory::residency::eviction::{EvictionAction, NotDroppable, WriteBack};
use crate::model_memory::residency::reservation::vram_resource;
use crate::model_memory::tiers::fakes::{
    charge, consumer, corrupt_stored, declare, device, empty_ledger, execution, lease, model, path,
    publish, publish_in, root, scope, source_id, tenant, world, World, GB, GIB, KIB, MIB, STORAGE,
};
use crate::model_memory::tiers::gpu::{AllocationHandle, GpuTier};
use crate::model_memory::tiers::representations::{
    RepresentationProposal, RepresentationStore, SpaceBudget,
};

fn pool(name: &str) -> PoolId {
    PoolId::new(name).unwrap()
}

/// The user selected pool-c and pool-e; pool-d is not selected and pool-e is unplugged.
fn pools() -> LocalStorageTier {
    with_pools(LocalStorageTier::new())
}

/// The ledger budget the host's supervisor named for Yougori's own artifacts.
fn holder() -> HostBudgetHolder {
    HostBudgetHolder::new(tenant("host-budget"))
}

/// The pools of [`pools`] in a tier that charges host-scope artifacts to [`holder`].
fn host_pools() -> LocalStorageTier {
    with_pools(LocalStorageTier::with_host_budget_holder(holder()))
}

fn with_pools(mut local: LocalStorageTier) -> LocalStorageTier {
    for (name, selection, presence) in [
        ("pool-c", PoolSelection::UserSelected, PoolPresence::Present),
        ("pool-d", PoolSelection::NotSelected, PoolPresence::Present),
        ("pool-e", PoolSelection::UserSelected, PoolPresence::Missing),
    ] {
        local
            .add_pool(StoragePool {
                id: pool(name),
                selection,
                presence,
            })
            .unwrap();
    }
    local
}

/// A world whose ledger has 4 MiB of storage with unlimited quotas for alice and bob.
fn setup() -> World {
    let mut world = world(&["alice", "bob"]);
    declare(&mut world.ledger, STORAGE, 4 * MIB, &["alice", "bob"]);
    world
}

fn object_of(owner: &Consumer, bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        scope: owner.scope(),
        class: ArtifactClass::ModelWeights,
        content: ContentKey::of(bytes),
    }
}

/// A guest image of Yougori's own host scope.
fn host_object(bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        scope: Scope::Host,
        class: ArtifactClass::GuestImage,
        content: ContentKey::of(bytes),
    }
}

/// An import of a guest image into `into` by the host's updater: storage is reserved
/// against the host's budget holder, the catalog's importer publishes it in the host
/// scope, and the tier records the publication.
fn import_host(
    local: &mut LocalStorageTier,
    world: &mut World,
    into: &str,
    bytes: &[u8],
    role: ObjectRole,
) -> ObjectRef {
    let object = host_object(bytes);
    let updater = execution("exe-updater");
    let reservation = local
        .reserve_import(
            &pool(into),
            object.clone(),
            bytes.len() as u64,
            &updater,
            &charge("op-update"),
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(
        publish_in(
            &mut world.catalog,
            Scope::Host,
            &updater,
            ArtifactClass::GuestImage,
            bytes,
            role
        ),
        object
    );
    local.record_published(reservation, &world.catalog).unwrap();
    object
}

/// `importer` reserves storage for `object` in `into` before writing anything.
fn reserve(
    local: &mut LocalStorageTier,
    world: &mut World,
    into: &str,
    importer: &Consumer,
    object: &ObjectRef,
    bytes: u64,
) -> Result<StorageReservation, LocalRefusal> {
    local.reserve_import(
        &pool(into),
        object.clone(),
        bytes,
        &importer.execution,
        &charge("op-import"),
        &mut world.ledger,
    )
}

/// An import into `into`: storage is reserved, the catalog's importer publishes, and the
/// tier records the publication.
fn import(
    local: &mut LocalStorageTier,
    world: &mut World,
    into: &str,
    owner: &Consumer,
    bytes: &[u8],
    role: ObjectRole,
) -> ObjectRef {
    let object = object_of(owner, bytes);
    let reservation = reserve(local, world, into, owner, &object, bytes.len() as u64).unwrap();
    assert_eq!(publish(&mut world.catalog, owner, bytes, role), object);
    local.record_published(reservation, &world.catalog).unwrap();
    object
}

fn prepared_from(sources: &[&ObjectRef]) -> ObjectRole {
    ObjectRole::Prepared {
        derived_from: sources.iter().map(|source| source.id()).collect(),
    }
}

fn planned(object: &ObjectRef, kind: DerivedKind, tier: Tier) -> PlannedEviction {
    PlannedEviction {
        model: model("alice", "llama-8b"),
        object: object.clone(),
        kind,
        tier,
        bytes: KIB,
    }
}

#[test]
fn only_user_selected_pools_that_are_present_are_used() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    assert_eq!(local.eligible_pools(), [pool("pool-c")]);
    let object = object_of(&alice, b"llama weights");
    assert_eq!(
        reserve(&mut local, &mut world, "pool-d", &alice, &object, 13),
        Err(LocalRefusal::PoolNotUserSelected {
            pool: pool("pool-d")
        })
    );
    assert_eq!(
        reserve(&mut local, &mut world, "pool-e", &alice, &object, 13),
        Err(LocalRefusal::PoolMissing {
            pool: pool("pool-e")
        })
    );
    assert_eq!(
        reserve(&mut local, &mut world, "pool-x", &alice, &object, 13),
        Err(LocalRefusal::UnknownPool {
            pool: pool("pool-x")
        })
    );
    assert_eq!(world.ledger.reserved(STORAGE), 0);
    // Yougori never creates or picks a pool; it records the user's.
    assert_eq!(
        local.add_pool(StoragePool {
            id: pool("pool-c"),
            selection: PoolSelection::UserSelected,
            presence: PoolPresence::Present,
        }),
        Err(LocalRefusal::DuplicatePool {
            pool: pool("pool-c")
        })
    );
    local
        .observe_pool(&pool("pool-e"), PoolPresence::Present)
        .unwrap();
    assert_eq!(local.eligible_pools(), [pool("pool-c"), pool("pool-e")]);
    assert_eq!(
        local.observe_pool(&pool("pool-x"), PoolPresence::Present),
        Err(LocalRefusal::UnknownPool {
            pool: pool("pool-x")
        })
    );
    assert_eq!(
        PoolId::new(""),
        Err(crate::model_memory::math::InputError::Empty { field: "PoolId" })
    );

    // A stored object is offered only while its pool is present.
    let stored = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama weights",
        ObjectRole::Original,
    );
    let route = || path(3.0 * GB, 0.005, &[]);
    let offer = local
        .offer(source_id("nvme"), &stored, &alice, route(), &world.catalog)
        .unwrap();
    assert_eq!(offer.requester(), &alice);
    assert_eq!(
        (offer.tier(), offer.covers_bytes()),
        (Tier::LocalStorage, 13)
    );
    local
        .observe_pool(&pool("pool-c"), PoolPresence::Missing)
        .unwrap();
    assert_eq!(
        local
            .offer(source_id("nvme"), &stored, &alice, route(), &world.catalog)
            .unwrap_err()
            .reason,
        TierRefusal::Local(LocalRefusal::PoolMissing {
            pool: pool("pool-c")
        })
    );
    let unstored = object_of(&alice, b"never imported");
    assert_eq!(
        local
            .offer(
                source_id("nvme"),
                &unstored,
                &alice,
                route(),
                &world.catalog
            )
            .unwrap_err()
            .reason,
        TierRefusal::Local(LocalRefusal::NotStored { object: unstored })
    );
}

#[test]
fn an_import_reserves_its_tenants_quota_before_it_writes() {
    let mut world = setup();
    world
        .ledger
        .set_tenant_budget(tenant("alice"), STORAGE, 2_500)
        .unwrap();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    let first = object_of(&alice, b"first");
    let reservation = reserve(&mut local, &mut world, "pool-c", &alice, &first, 1_000).unwrap();
    assert_eq!(
        (
            reservation.pool(),
            reservation.object(),
            reservation.bytes()
        ),
        (&pool("pool-c"), &first, 1_000)
    );
    assert_eq!(world.ledger.reserved(STORAGE), 1_000);
    let record = world.ledger.reservation(reservation.reservation()).unwrap();
    // Reserved before creation, and creation has started: the bytes count from here on.
    assert_eq!(record.state(), ReservationState::InUse);
    assert_eq!(record.provenance().purpose, CostPurpose::Storage);
    assert_eq!(record.provenance().tenant, tenant("alice"));
    assert_eq!(local.importing(), [reservation.reservation()]);
    // The quota is the tenant's storage budget in the ledger.
    let second = object_of(&alice, b"second");
    match reserve(&mut local, &mut world, "pool-c", &alice, &second, 2_000) {
        Err(LocalRefusal::Ledger(LedgerError::Capacity(capacity))) => {
            assert_eq!(capacity.resource(), STORAGE);
            assert_eq!(
                capacity.limiting().limit,
                Limit::TenantBudget {
                    tenant: tenant("alice")
                }
            );
            assert_eq!(
                (capacity.limiting().requested, capacity.limiting().available),
                (2_000, 1_500)
            );
        }
        other => panic!("expected the quota to refuse, got {other:?}"),
    }
    // Yougori's own host-scope artifacts are charged to the host's budget holder; this
    // tier was built without one, so it refuses them and reserves nothing.
    let image = host_object(b"guest image");
    assert_eq!(
        local.reserve_import(
            &pool("pool-c"),
            image.clone(),
            1_000,
            &execution("exe-updater"),
            &charge("op-update"),
            &mut world.ledger,
        ),
        Err(LocalRefusal::NoHostBudgetHolder {
            object: image.clone()
        })
    );
    assert_eq!(local.host_budget_holder(), None);
    assert_eq!(world.ledger.reserved(STORAGE), 1_000);
    assert_eq!(
        reserve(&mut local, &mut world, "pool-c", &alice, &second, 0),
        Err(LocalRefusal::ZeroBytes)
    );
    // An abandoned import gives its reservation back; what it wrote counts until the host
    // observes it gone.
    let released = local.abandon(reservation, &mut world.ledger).unwrap();
    assert_eq!(released.outcome, ReleaseOutcome::Pending);
    assert!(local.importing().is_empty());
    world
        .ledger
        .confirm_release(released.reservation, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(world.ledger.reserved(STORAGE), 0);
}

#[test]
fn only_the_importer_writes_and_consumers_read_only() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    let bytes = b"llama-8b weights, imported once";
    let object = object_of(&alice, bytes);
    let reservation = reserve(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        &object,
        bytes.len() as u64,
    )
    .unwrap();
    // Nothing is recorded before the catalog's importer has published the object; the
    // reservation comes back for a retry or an abandon.
    let NotRecorded {
        refusal,
        reservation,
    } = local
        .record_published(reservation, &world.catalog)
        .unwrap_err();
    assert_eq!(
        refusal,
        LocalRefusal::NotPublished {
            object: object.clone(),
            status: ObjectStatus::Absent,
        }
    );
    assert_eq!(local.reservation_of(object.id()), None);
    publish(&mut world.catalog, &alice, bytes, ObjectRole::Original);
    local.record_published(reservation, &world.catalog).unwrap();
    // The tier keeps the role the catalog recorded.
    assert_eq!(local.role_of(object.id()), Some(&ObjectRole::Original));
    assert!(local.importing().is_empty());
    assert_eq!(
        local.used_bytes(&pool("pool-c"), &alice.tenant),
        bytes.len() as u64
    );

    // A consumer reads the committed bytes through a read-only handle, which offers no
    // way to write and stops reading when its lease ends (line 546; §1.1 line 306).
    let reader = consumer("alice", "exe-alice-2");
    let held = lease(&mut world.catalog, &reader, &object).unwrap();
    let mut handle = world
        .catalog
        .open_read(&reader.scope(), &reader.execution, held)
        .unwrap();
    assert_eq!(handle.read_all().unwrap(), bytes);
    world
        .catalog
        .release_lease(&reader.scope(), &reader.execution, held)
        .unwrap();
    assert_eq!(handle.read_all(), Err(ReadError::LeaseReleased));

    // A publication of another length than was reserved is refused.
    let other_bytes = b"mistral-7b weights";
    let other = object_of(&alice, other_bytes);
    let reserved_bytes = other_bytes.len() as u64 + 1;
    let reservation = reserve(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        &other,
        reserved_bytes,
    )
    .unwrap();
    publish(
        &mut world.catalog,
        &alice,
        other_bytes,
        ObjectRole::Original,
    );
    let NotRecorded {
        refusal,
        reservation,
    } = local
        .record_published(reservation, &world.catalog)
        .unwrap_err();
    assert_eq!(
        refusal,
        LocalRefusal::LengthMismatch {
            object: other,
            reserved_bytes,
            published_bytes: other_bytes.len() as u64,
        }
    );
    local.abandon(reservation, &mut world.ledger).unwrap();

    // Repeated imports do not multiply disk usage (GPU-W03).
    assert_eq!(
        reserve(
            &mut local,
            &mut world,
            "pool-c",
            &alice,
            &object,
            bytes.len() as u64
        ),
        Err(LocalRefusal::AlreadyStored {
            object: object.clone(),
            pool: pool("pool-c"),
        })
    );
    // A stored copy is published, so verified, and stays: it can rebuild a dropped GPU
    // copy (T08).
    let copy = local.copy_of(&object, &world.catalog).unwrap();
    assert_eq!((&copy.object, copy.holder.as_ref()), (&object, None));
    assert_eq!(copy.copy.tier, CopyTier::LocalStorage);
    assert!(copy.copy.reconstructs(&Content::Immutable(object.content)));
    assert_eq!(
        local.copy_of(&object_of(&alice, b"never imported"), &world.catalog),
        None
    );
    // A copy on an unplugged pool rebuilds nothing.
    local
        .observe_pool(&pool("pool-c"), PoolPresence::Missing)
        .unwrap();
    assert_eq!(local.copy_of(&object, &world.catalog), None);
}

#[test]
fn cache_eviction_never_deletes_an_original() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    let original = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama original",
        ObjectRole::Original,
    );
    let raw = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama raw prepared",
        prepared_from(&[&original]),
    );
    let compressed = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama compressed prepared",
        prepared_from(&[&original]),
    );
    let reserved = world.ledger.reserved(STORAGE);
    // Named as a prepared form, the original is still refused by the catalog, and the
    // whole eviction removes nothing (line 552).
    assert_eq!(
        local.evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[
                planned(&raw, DerivedKind::RawPrepared, Tier::LocalStorage),
                planned(&original, DerivedKind::RawPrepared, Tier::LocalStorage),
            ],
            &mut world.ledger,
        ),
        Err(LocalRefusal::Eviction(EvictionRefusal::UserOriginal {
            object: original.id()
        }))
    );
    for kept in [&original, &raw] {
        assert_eq!(
            world.catalog.status(&kept.scope, kept.id()),
            ObjectStatus::Published
        );
        assert!(local.reservation_of(kept.id()).is_some());
    }
    assert_eq!(world.ledger.reserved(STORAGE), reserved);
    // A leased prepared form stays too.
    let held = lease(&mut world.catalog, &alice, &compressed).unwrap();
    assert_eq!(
        local.evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[planned(
                &compressed,
                DerivedKind::CompressedPrepared,
                Tier::LocalStorage
            )],
            &mut world.ledger,
        ),
        Err(LocalRefusal::Eviction(EvictionRefusal::Leased {
            object: compressed.id()
        }))
    );
    world
        .catalog
        .release_lease(&alice.scope(), &alice.execution, held)
        .unwrap();

    // Only prepared forms of local storage are cache evictions here.
    for (kind, tier) in [
        (DerivedKind::HostCopy, Tier::LocalStorage),
        (DerivedKind::RawPrepared, Tier::PinnedHost),
    ] {
        assert_eq!(
            local.evict_cache(
                &pool("pool-c"),
                &mut world.catalog,
                &[planned(&raw, kind, tier)],
                &mut world.ledger,
            ),
            Err(LocalRefusal::WrongEviction { tier, kind })
        );
    }
    let bobs = object_of(&consumer("bob", "exe-bob-1"), b"bob's prepared form");
    assert_eq!(
        local.evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[
                planned(&raw, DerivedKind::RawPrepared, Tier::LocalStorage),
                planned(&bobs, DerivedKind::RawPrepared, Tier::LocalStorage),
            ],
            &mut world.ledger,
        ),
        Err(LocalRefusal::ScopesDiffer {
            first: scope("alice"),
            other: scope("bob"),
        })
    );
    assert_eq!(
        local.evict_cache(
            &pool("pool-e"),
            &mut world.catalog,
            &[planned(&raw, DerivedKind::RawPrepared, Tier::LocalStorage)],
            &mut world.ledger,
        ),
        Err(LocalRefusal::InOtherPool {
            object: raw.clone(),
            pool: pool("pool-c"),
        })
    );
    let unstored = object_of(&alice, b"never imported");
    assert_eq!(
        local.evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[planned(
                &unstored,
                DerivedKind::RawPrepared,
                Tier::LocalStorage
            )],
            &mut world.ledger,
        ),
        Err(LocalRefusal::NotStored { object: unstored })
    );

    // Prepared forms the catalog may evict leave, and their storage comes back.
    let removal = local
        .evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[
                planned(&raw, DerivedKind::RawPrepared, Tier::LocalStorage),
                planned(
                    &compressed,
                    DerivedKind::CompressedPrepared,
                    Tier::LocalStorage,
                ),
            ],
            &mut world.ledger,
        )
        .unwrap();
    let evicted: BTreeSet<ObjectId> = removal.catalog.evicted.iter().copied().collect();
    assert_eq!(evicted, BTreeSet::from([raw.id(), compressed.id()]));
    assert_eq!(removal.released.len(), 2);
    assert!(removal
        .released
        .iter()
        .all(|released| released.outcome == ReleaseOutcome::Pending));
    assert_eq!(local.reservation_of(raw.id()), None);
    assert_eq!(
        world.catalog.status(&original.scope, original.id()),
        ObjectStatus::Published
    );
    assert_eq!(local.role_of(original.id()), Some(&ObjectRole::Original));
    // Nothing to evict is an empty eviction.
    assert_eq!(
        local
            .evict_cache(&pool("pool-c"), &mut world.catalog, &[], &mut world.ledger)
            .unwrap(),
        Removal {
            catalog: CacheEviction::default(),
            released: Vec::new(),
            unreleased: Vec::new(),
        }
    );
}

#[test]
fn local_model_deletion_and_source_file_deletion_are_distinct() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    let original = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama original",
        ObjectRole::Original,
    );
    let prepared = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama prepared",
        prepared_from(&[&original]),
    );
    let owner = alice.scope();
    world
        .catalog
        .set_root(
            &owner,
            RootKind::SourceFile,
            root("llama-src"),
            BTreeSet::from([original.id()]),
        )
        .unwrap();
    world
        .catalog
        .set_root(
            &owner,
            RootKind::LocalModel,
            root("llama"),
            BTreeSet::from([original.id(), prepared.id()]),
        )
        .unwrap();
    let reserved = world.ledger.reserved(STORAGE);

    // Local model deletion removes the model's root and no bytes; the original stays
    // reachable through its source-file root.
    let deletion = local
        .delete_local_model(&pool("pool-c"), &mut world.catalog, &owner, &root("llama"))
        .unwrap();
    assert_eq!(deletion.now_unreachable, [prepared.id()]);
    assert!(local.reservation_of(prepared.id()).is_some());
    assert_eq!(world.ledger.reserved(STORAGE), reserved);
    assert_eq!(
        local.delete_local_model(&pool("pool-c"), &mut world.catalog, &owner, &root("llama")),
        Err(LocalRefusal::Delete(DeleteRefusal::NoSuchRoot {
            kind: RootKind::LocalModel,
            name: root("llama"),
        }))
    );
    // Collection waits out the catalog's 60 s grace period, then removes what the deletion
    // left and gives its storage back.
    let early = local
        .collect_garbage(&pool("pool-c"), &mut world.catalog, &mut world.ledger)
        .unwrap();
    assert_eq!(early.catalog.kept_in_grace, [prepared.id()]);
    assert!(early.released.is_empty());
    world.clock.advance(Duration::from_secs(61));
    let collected = local
        .collect_garbage(&pool("pool-c"), &mut world.catalog, &mut world.ledger)
        .unwrap();
    assert_eq!(collected.catalog.removed, [prepared.id()]);
    assert_eq!(collected.released.len(), 1);
    assert_eq!(local.reservation_of(prepared.id()), None);
    assert_eq!(local.role_of(original.id()), Some(&ObjectRole::Original));

    // Source-file deletion is its own action, on the user's explicit request; a lease
    // holds it back and nothing is removed.
    let held = lease(&mut world.catalog, &alice, &original).unwrap();
    assert_eq!(
        local.delete_source_file(
            &pool("pool-c"),
            &mut world.catalog,
            &owner,
            &SourceFileTarget::Root(root("llama-src")),
            &mut world.ledger,
        ),
        Err(LocalRefusal::Delete(DeleteRefusal::InUse {
            object: original.id(),
            holder: Holder::Lease,
        }))
    );
    assert!(local.reservation_of(original.id()).is_some());
    world
        .catalog
        .release_lease(&owner, &alice.execution, held)
        .unwrap();
    let removal = local
        .delete_source_file(
            &pool("pool-c"),
            &mut world.catalog,
            &owner,
            &SourceFileTarget::Root(root("llama-src")),
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(removal.catalog.deleted, [original.id()]);
    assert_eq!(removal.released.len(), 1);
    assert_eq!(
        world.catalog.status(&owner, original.id()),
        ObjectStatus::Absent
    );
    assert_eq!(local.role_of(original.id()), None);
    assert_eq!(
        local.delete_local_model(&pool("pool-x"), &mut world.catalog, &owner, &root("llama")),
        Err(LocalRefusal::UnknownPool {
            pool: pool("pool-x")
        })
    );
}

#[test]
fn a_smaller_budget_is_met_by_cache_eviction_never_by_deleting_the_original() {
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    let llama = model("alice", "llama-8b");
    let original_bytes = [1u8; 3_000];
    let raw_bytes = [2u8; 2_000];
    let original = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        &original_bytes,
        ObjectRole::Original,
    );
    let raw = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        &raw_bytes,
        prepared_from(&[&original]),
    );
    let clock = world.clock.clone();
    let mut budgeted =
        RepresentationStore::new(SpaceBudget::Explicit { max_bytes: 5_000 }, 86_400.0).unwrap();
    budgeted
        .admit(
            RepresentationProposal::Original {
                model: llama.clone(),
                object: original.clone(),
                bytes: 3_000,
            },
            &clock,
        )
        .unwrap();
    budgeted
        .admit(
            RepresentationProposal::Derived {
                model: llama.clone(),
                object: raw.clone(),
                kind: DerivedKind::RawPrepared,
                tier: Tier::LocalStorage,
                bytes: 2_000,
                forecast: ImportAmortization {
                    expected_uses: 21.0,
                    per_use_saving_seconds: 8.0,
                    preparation_cost_seconds: 120.0,
                    retention_penalty_seconds: 40.0,
                },
            },
            &clock,
        )
        .unwrap();
    // The budget shrinks below what is held: the prepared form leaves through cache
    // eviction.
    budgeted
        .set_budget(SpaceBudget::Explicit { max_bytes: 3_000 })
        .unwrap();
    let enforcement = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
    assert_eq!(enforcement.unmet_bytes, 0);
    let removal = local
        .evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &enforcement.evictions,
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(removal.catalog.evicted, [raw.id()]);
    assert_eq!(removal.catalog.freed_bytes, 2_000);
    for eviction in &enforcement.evictions {
        budgeted.forget(eviction).unwrap();
    }
    // Below the original's own size the shortfall is reported, never met by deleting it.
    budgeted
        .set_budget(SpaceBudget::Explicit { max_bytes: 1_000 })
        .unwrap();
    let enforcement = budgeted.enforce_budget(&world.catalog, &clock).unwrap();
    assert!(enforcement.evictions.is_empty());
    assert_eq!(enforcement.unmet_bytes, 2_000);
    assert_eq!(
        world.catalog.status(&original.scope, original.id()),
        ObjectStatus::Published
    );
    assert_eq!(local.used_bytes(&pool("pool-c"), &alice.tenant), 3_000);
}

#[test]
fn a_copy_the_catalog_no_longer_has_never_justifies_a_clean_drop() {
    // Review R1-c: another holder of the pool's catalog may evict, collect or quarantine
    // an object, so this tier's records never vouch for a copy by themselves (§1.1 line
    // 307, decision T08).
    let mut world = setup();
    declare(
        &mut world.ledger,
        vram_resource(device(0)),
        64 * GIB,
        &["alice"],
    );
    let alice = consumer("alice", "exe-alice-1");
    let owner = alice.scope();
    let mut local = pools();
    let original = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama original",
        ObjectRole::Original,
    );
    let mut prepared = Vec::new();
    for name in ["evicted", "collected", "quarantined"] {
        let bytes = format!("llama prepared, later {name}");
        prepared.push(import(
            &mut local,
            &mut world,
            "pool-c",
            &alice,
            bytes.as_bytes(),
            prepared_from(&[&original]),
        ));
    }
    let [evicted, collected, quarantined] = [&prepared[0], &prepared[1], &prepared[2]];
    // Roots keep the original and the form that will be quarantined; nothing roots the
    // one that will be collected.
    world
        .catalog
        .set_root(
            &owner,
            RootKind::SourceFile,
            root("llama-src"),
            BTreeSet::from([original.id()]),
        )
        .unwrap();
    world
        .catalog
        .set_root(
            &owner,
            RootKind::LocalModel,
            root("llama"),
            BTreeSet::from([quarantined.id()]),
        )
        .unwrap();
    // The GPU holds clean weights loaded from each prepared form.
    let mut gpu = GpuTier::new(device(0), None);
    let mut allocations: Vec<AllocationHandle> = Vec::new();
    for object in &prepared {
        let held = lease(&mut world.catalog, &alice, object).unwrap();
        let handle = world
            .catalog
            .open_read(&owner, &alice.execution, held)
            .unwrap();
        allocations.push(
            gpu.load_weights(
                &alice,
                object,
                &handle,
                &world.catalog,
                GIB,
                &charge("op-load"),
                &mut world.ledger,
            )
            .unwrap(),
        );
        drop(handle);
        world
            .catalog
            .release_lease(&owner, &alice.execution, held)
            .unwrap();
    }
    let action = |world: &World, local: &LocalStorageTier, index: usize| {
        let copies: Vec<ObjectCopy> = local
            .copy_of(&prepared[index], &world.catalog)
            .into_iter()
            .collect();
        gpu.eviction_action(allocations[index], &copies, WriteBack::Unavailable)
            .unwrap()
    };
    // While the catalog publishes them, the stored copies let the GPU copies drop clean.
    for index in 0..3 {
        assert_eq!(
            action(&world, &local, index),
            EvictionAction::DropClean {
                source: CopyTier::LocalStorage,
            }
        );
    }

    // Another holder of the catalog evicts one, collects another past the 60 s grace
    // period, and a disk fault quarantines the third.
    world.catalog.evict_cache(&owner, &[evicted.id()]).unwrap();
    world.clock.advance(Duration::from_secs(61));
    let collection = world.catalog.collect_garbage().unwrap();
    assert!(collection.removed.contains(&collected.id()));
    corrupt_stored(&world, quarantined);
    assert!(matches!(
        world.catalog.verify_object(&owner, quarantined.id()),
        Err(VerifyError::Quarantined { .. })
    ));

    // None of them has a copy here any more, so each GPU copy is kept, not dropped, and
    // none is offered as a source.
    for (index, object) in [evicted, collected, quarantined].into_iter().enumerate() {
        assert_eq!(local.copy_of(object, &world.catalog), None);
        assert_eq!(
            action(&world, &local, index),
            EvictionAction::Retain {
                because: NotDroppable::NoVerifiedCopy,
            }
        );
        let refusal = local
            .offer(
                source_id("nvme"),
                object,
                &alice,
                path(3.0 * GB, 0.005, &[]),
                &world.catalog,
            )
            .unwrap_err();
        assert!(matches!(
            refusal.reason,
            TierRefusal::Local(LocalRefusal::NotPublished { .. })
        ));
    }
    assert_eq!(
        world.catalog.status(&owner, evicted.id()),
        ObjectStatus::Absent
    );
    assert!(matches!(
        world.catalog.status(&owner, quarantined.id()),
        ObjectStatus::Quarantined { .. }
    ));
    // The original, still published, still vouches for itself.
    assert!(local.copy_of(&original, &world.catalog).is_some());
}

#[test]
fn a_refused_release_never_loses_the_catalogs_report() {
    // Review R1-c: the catalog has already removed the bytes when the ledger is asked, so
    // the tier forgets the object first and reports a refused release instead of failing.
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = pools();
    let original = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama original",
        ObjectRole::Original,
    );
    let raw_bytes = b"llama raw prepared";
    let raw = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        raw_bytes,
        prepared_from(&[&original]),
    );
    let reservation = local.reservation_of(raw.id()).unwrap();
    let reserved = world.ledger.reserved(STORAGE);
    // A ledger that never issued the reservation refuses to take it back.
    let mut stranger = empty_ledger(world.clock.clone());
    let removal = local
        .evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[planned(&raw, DerivedKind::RawPrepared, Tier::LocalStorage)],
            &mut stranger,
        )
        .unwrap();
    assert_eq!(removal.catalog.evicted, [raw.id()]);
    assert!(removal.released.is_empty());
    assert_eq!(
        removal.unreleased,
        [UnreleasedReservation {
            object: raw.id(),
            reservation,
            bytes: raw_bytes.len() as u64,
            error: LedgerError::UnknownReservation { reservation },
        }]
    );
    // The tier forgot the object; the real ledger still holds its reservation for
    // reconciliation.
    assert_eq!(local.reservation_of(raw.id()), None);
    assert_eq!(local.copy_of(&raw, &world.catalog), None);
    assert_eq!(world.ledger.reserved(STORAGE), reserved);
    assert!(local.copy_of(&original, &world.catalog).is_some());
}

#[test]
fn an_original_a_deleted_model_left_behind_leaves_only_when_named() {
    // Line 552 with the T05 review fix: collection never removes an original, and a
    // source-file deletion may name one that no root holds.
    let mut world = setup();
    let alice = consumer("alice", "exe-alice-1");
    let owner = alice.scope();
    let mut local = pools();
    let original = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama original",
        ObjectRole::Original,
    );
    let prepared = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama prepared",
        prepared_from(&[&original]),
    );
    world
        .catalog
        .set_root(
            &owner,
            RootKind::LocalModel,
            root("llama"),
            BTreeSet::from([original.id(), prepared.id()]),
        )
        .unwrap();
    local
        .delete_local_model(&pool("pool-c"), &mut world.catalog, &owner, &root("llama"))
        .unwrap();
    // Past the grace period collection takes the prepared form and keeps the original.
    world.clock.advance(Duration::from_secs(61));
    let collected = local
        .collect_garbage(&pool("pool-c"), &mut world.catalog, &mut world.ledger)
        .unwrap();
    assert_eq!(collected.catalog.removed, [prepared.id()]);
    assert_eq!(collected.catalog.kept_originals, [original.id()]);
    assert_eq!(collected.released.len(), 1);
    assert!(local.copy_of(&original, &world.catalog).is_some());
    // Only a prepared form is never named as an original.
    let left = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"another prepared form",
        prepared_from(&[&original]),
    );
    assert_eq!(
        local.delete_source_file(
            &pool("pool-c"),
            &mut world.catalog,
            &owner,
            &SourceFileTarget::Original(left.id()),
            &mut world.ledger,
        ),
        Err(LocalRefusal::Delete(DeleteRefusal::NotAnOriginal {
            object: left.id()
        }))
    );
    // Named on the user's request, the original leaves and its storage comes back.
    let removal = local
        .delete_source_file(
            &pool("pool-c"),
            &mut world.catalog,
            &owner,
            &SourceFileTarget::Original(original.id()),
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(removal.catalog.root, None);
    assert_eq!(removal.catalog.deleted, [original.id()]);
    assert_eq!(removal.released.len(), 1);
    assert!(removal.unreleased.is_empty());
    assert_eq!(local.reservation_of(original.id()), None);
    assert_eq!(local.copy_of(&original, &world.catalog), None);
}

#[test]
fn the_hosts_own_artifacts_are_charged_to_its_budget_holder_and_never_to_a_tenant() {
    // The owner of host storage quota (P02's integration item): the host's supervisor
    // names a ledger budget for Yougori's own artifacts and builds the tier with it.
    let mut world = setup();
    let host = holder();
    world
        .ledger
        .set_tenant_budget(host.id().clone(), STORAGE, 2_500)
        .unwrap();
    let updater = execution("exe-updater");
    let alice = consumer("alice", "exe-alice-1");
    let mut local = host_pools();
    assert_eq!(local.host_budget_holder(), Some(&host));
    let image_bytes = b"guest kernel image";
    let image = host_object(image_bytes);
    let reservation = local
        .reserve_import(
            &pool("pool-c"),
            image.clone(),
            18,
            &updater,
            &charge("op-update"),
            &mut world.ledger,
        )
        .unwrap();
    // Reserved against the host's budget and no tenant's; the record names the holder as
    // the charged party.
    let record = world.ledger.reservation(reservation.reservation()).unwrap();
    assert_eq!(record.provenance().tenant, *host.id());
    assert_eq!(record.provenance().purpose, CostPurpose::Storage);
    assert_eq!(record.provenance().execution, updater);
    assert_eq!(record.state(), ReservationState::InUse);
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 18);
    for name in ["alice", "bob"] {
        assert_eq!(world.ledger.tenant_reserved(&tenant(name), STORAGE), 0);
    }
    // Recorded once the catalog publishes it in the host scope, like a tenant's object.
    assert_eq!(
        publish_in(
            &mut world.catalog,
            Scope::Host,
            &updater,
            ArtifactClass::GuestImage,
            image_bytes,
            ObjectRole::Original
        ),
        image
    );
    local.record_published(reservation, &world.catalog).unwrap();
    assert_eq!(local.role_of(image.id()), Some(&ObjectRole::Original));
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 18);
    assert!(local.copy_of(&image, &world.catalog).is_some());
    // A tenant's tally never counts host objects, not even under the holder's name, and
    // a tenant's import leaves the host's budget alone.
    import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama weights",
        ObjectRole::Original,
    );
    assert_eq!(local.used_bytes(&pool("pool-c"), &alice.tenant), 13);
    assert_eq!(local.used_bytes(&pool("pool-c"), host.id()), 0);
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 18);
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 18);
    assert_eq!(world.ledger.tenant_reserved(&alice.tenant, STORAGE), 13);
    assert_eq!(world.ledger.reserved(STORAGE), 31);

    // The host cannot spend beyond its budget, however much a tenant has left: the
    // ledger's actionable error names the storage quota and the host's holder.
    let large = host_object(b"a large guest image");
    match local.reserve_import(
        &pool("pool-c"),
        large.clone(),
        2_500,
        &updater,
        &charge("op-update"),
        &mut world.ledger,
    ) {
        Err(LocalRefusal::Ledger(LedgerError::Capacity(capacity))) => {
            assert_eq!(capacity.resource(), STORAGE);
            assert_eq!(
                capacity.limiting().limit,
                Limit::TenantBudget {
                    tenant: host.id().clone()
                }
            );
            assert_eq!(
                (capacity.limiting().requested, capacity.limiting().available),
                (2_500, 2_482)
            );
            assert_eq!(
                capacity.limiting().prospect,
                RetryProspect::FitsAfterRelease { shortfall: 18 }
            );
            assert!(capacity.to_string().contains("storage quota"));
        }
        other => panic!("expected the host's budget to refuse, got {other:?}"),
    }
    assert!(local.importing().is_empty());
    // A tenant cannot spend the host's budget: a tenant scope named like the holder is
    // refused before the ledger is asked.
    let impostor = consumer("host-budget", "exe-impostor");
    let claimed = object_of(&impostor, b"claimed by a tenant");
    assert_eq!(
        reserve(&mut local, &mut world, "pool-c", &impostor, &claimed, 100),
        Err(LocalRefusal::TenantIsHostBudgetHolder {
            object: claimed,
            holder: host.clone(),
        })
    );
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 18);
    assert_eq!(world.ledger.reserved(STORAGE), 31);
    // With a holder that has no storage budget, the refusal is the ledger's capacity
    // error naming the storage quota, and no tenant's budget is touched.
    let unfunded = HostBudgetHolder::new(tenant("host-unfunded"));
    let mut tier = with_pools(LocalStorageTier::with_host_budget_holder(unfunded.clone()));
    match tier.reserve_import(
        &pool("pool-c"),
        large.clone(),
        100,
        &updater,
        &charge("op-update"),
        &mut world.ledger,
    ) {
        Err(LocalRefusal::Ledger(LedgerError::Capacity(capacity))) => {
            assert_eq!(capacity.resource(), STORAGE);
            assert_eq!(
                capacity.limiting().limit,
                Limit::TenantBudget {
                    tenant: unfunded.id().clone()
                }
            );
            assert_eq!(
                capacity.limiting().prospect,
                RetryProspect::ExceedsLimit { limit: 0 }
            );
            assert!(!capacity.retry_can_progress());
        }
        other => panic!("expected an unfunded holder to be refused, got {other:?}"),
    }
    assert_eq!(world.ledger.reserved(STORAGE), 31);
    // An abandoned host import gives the host's reservation back once the host observes
    // its bytes gone.
    let abandoned = local
        .reserve_import(
            &pool("pool-c"),
            large,
            100,
            &updater,
            &charge("op-update"),
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 118);
    let released = local.abandon(abandoned, &mut world.ledger).unwrap();
    assert_eq!(released.outcome, ReleaseOutcome::Pending);
    world
        .ledger
        .confirm_release(released.reservation, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 18);
    assert_eq!(world.ledger.tenant_reserved(&alice.tenant, STORAGE), 13);
    // The refusals read as sentences.
    assert_eq!(host.to_string(), "the host's budget holder host-budget");
    assert!(LocalRefusal::NoHostBudgetHolder {
        object: image.clone()
    }
    .to_string()
    .contains("no host budget holder"));
    assert!(LocalRefusal::TenantIsHostBudgetHolder {
        object: image,
        holder: host,
    }
    .to_string()
    .contains("cannot spend the host's budget"));
}

#[test]
fn host_objects_follow_the_same_recording_eviction_and_collection_rules() {
    let mut world = setup();
    let host = holder();
    world
        .ledger
        .set_tenant_budget(host.id().clone(), STORAGE, MIB)
        .unwrap();
    let alice = consumer("alice", "exe-alice-1");
    let mut local = host_pools();
    let image = import_host(
        &mut local,
        &mut world,
        "pool-c",
        b"guest image",
        ObjectRole::Original,
    );
    let unpacked = import_host(
        &mut local,
        &mut world,
        "pool-c",
        b"guest image, unpacked",
        prepared_from(&[&image]),
    );
    let compressed = import_host(
        &mut local,
        &mut world,
        "pool-c",
        b"guest image, compressed",
        prepared_from(&[&image]),
    );
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 55);
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 55);
    // A publication of another length than was reserved is refused for the host too.
    let short = host_object(b"short image");
    let updater = execution("exe-updater");
    let reservation = local
        .reserve_import(
            &pool("pool-c"),
            short.clone(),
            12,
            &updater,
            &charge("op-update"),
            &mut world.ledger,
        )
        .unwrap();
    publish_in(
        &mut world.catalog,
        Scope::Host,
        &updater,
        ArtifactClass::GuestImage,
        b"short image",
        ObjectRole::Original,
    );
    let NotRecorded {
        refusal,
        reservation,
    } = local
        .record_published(reservation, &world.catalog)
        .unwrap_err();
    assert_eq!(
        refusal,
        LocalRefusal::LengthMismatch {
            object: short,
            reserved_bytes: 12,
            published_bytes: 11,
        }
    );
    let abandoned = local.abandon(reservation, &mut world.ledger).unwrap();
    world
        .ledger
        .confirm_release(abandoned.reservation, SourceClass::HostProbe)
        .unwrap();

    // An original is never cache-evicted, whoever owns it, and one eviction stays in one
    // scope: the host's and a tenant's objects do not mix.
    assert_eq!(
        local.evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[
                planned(&unpacked, DerivedKind::RawPrepared, Tier::LocalStorage),
                planned(&image, DerivedKind::RawPrepared, Tier::LocalStorage),
            ],
            &mut world.ledger,
        ),
        Err(LocalRefusal::Eviction(EvictionRefusal::UserOriginal {
            object: image.id()
        }))
    );
    let weights = import(
        &mut local,
        &mut world,
        "pool-c",
        &alice,
        b"llama weights",
        ObjectRole::Original,
    );
    assert_eq!(
        local.evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[
                planned(&unpacked, DerivedKind::RawPrepared, Tier::LocalStorage),
                planned(&weights, DerivedKind::RawPrepared, Tier::LocalStorage),
            ],
            &mut world.ledger,
        ),
        Err(LocalRefusal::ScopesDiffer {
            first: Scope::Host,
            other: scope("alice"),
        })
    );
    // A prepared form leaves and its storage returns to the host's holder.
    let evicted = local
        .evict_cache(
            &pool("pool-c"),
            &mut world.catalog,
            &[planned(
                &unpacked,
                DerivedKind::RawPrepared,
                Tier::LocalStorage,
            )],
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(evicted.catalog.evicted, [unpacked.id()]);
    assert_eq!(evicted.released.len(), 1);
    assert!(evicted.unreleased.is_empty());
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 34);
    assert_eq!(local.used_bytes(&pool("pool-c"), &alice.tenant), 13);
    assert_eq!(local.copy_of(&unpacked, &world.catalog), None);
    assert!(local.copy_of(&image, &world.catalog).is_some());

    // Local model deletion removes a root and no bytes; collection past the grace period
    // takes the prepared form and keeps the original, in the host scope as in a tenant's.
    world
        .catalog
        .set_root(
            &Scope::Host,
            RootKind::LocalModel,
            root("guest"),
            BTreeSet::from([image.id(), compressed.id()]),
        )
        .unwrap();
    let deletion = local
        .delete_local_model(
            &pool("pool-c"),
            &mut world.catalog,
            &Scope::Host,
            &root("guest"),
        )
        .unwrap();
    let unreachable: BTreeSet<ObjectId> = deletion.now_unreachable.iter().copied().collect();
    assert_eq!(unreachable, BTreeSet::from([image.id(), compressed.id()]));
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 34);
    world.clock.advance(Duration::from_secs(61));
    let collected = local
        .collect_garbage(&pool("pool-c"), &mut world.catalog, &mut world.ledger)
        .unwrap();
    assert_eq!(collected.catalog.removed, [compressed.id()]);
    assert!(collected.catalog.kept_originals.contains(&image.id()));
    assert_eq!(collected.released.len(), 1);
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 11);
    // The original leaves only through a source-file deletion that names it.
    let deleted = local
        .delete_source_file(
            &pool("pool-c"),
            &mut world.catalog,
            &Scope::Host,
            &SourceFileTarget::Original(image.id()),
            &mut world.ledger,
        )
        .unwrap();
    assert_eq!(deleted.catalog.deleted, [image.id()]);
    assert_eq!(deleted.released.len(), 1);
    assert_eq!(local.host_used_bytes(&pool("pool-c")), 0);
    assert_eq!(local.copy_of(&image, &world.catalog), None);
    // Every release returns to the host's holder once the host observes it; alice's
    // object and budget are untouched throughout.
    for released in evicted
        .released
        .iter()
        .chain(&collected.released)
        .chain(&deleted.released)
    {
        assert_eq!(released.outcome, ReleaseOutcome::Pending);
        world
            .ledger
            .confirm_release(released.reservation, SourceClass::HostProbe)
            .unwrap();
    }
    assert_eq!(world.ledger.tenant_reserved(host.id(), STORAGE), 0);
    assert_eq!(world.ledger.tenant_reserved(&alice.tenant, STORAGE), 13);
    assert_eq!(local.used_bytes(&pool("pool-c"), &alice.tenant), 13);
    assert!(local.copy_of(&weights, &world.catalog).is_some());
}
