use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::catalog::{GrantRequest, ObjectRole, ReadRefusal};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{ContentKey, ExecutionCategory, ManualClock, TrustScope};
use crate::foundation::ledger::{Limit, ReleaseOutcome};
use crate::model_memory::residency::eviction::{CopyTier, NotDroppable, Verification};
use crate::model_memory::residency::vram::{admit_vram, KvBound, ProcessVram, VramError, VramPlan};
use crate::model_memory::residency::Capacity;
use crate::model_memory::tiers::fakes::{
    at_seconds, charge, clock_at, consumer, declare, device, empty_ledger,
    execution as execution_id, in_vm, open_catalog, operation, path, publish, read_handle, scope,
    source_id, TestCatalog, GB, GIB,
};

struct Setup {
    clock: Arc<ManualClock>,
    catalog: TestCatalog,
    ledger: Ledger<Arc<ManualClock>>,
    gpu: GpuTier,
}

/// One device with `vram_bytes` of VRAM for alice and bob, and a catalog for both.
fn setup(vram_bytes: u64) -> Setup {
    let clock = Arc::new(clock_at(0));
    let catalog = open_catalog(clock.clone(), &["alice", "bob"]);
    let mut ledger = empty_ledger(clock.clone());
    declare(
        &mut ledger,
        vram_resource(device(0)),
        vram_bytes,
        &["alice", "bob"],
    );
    Setup {
        clock,
        catalog,
        ledger,
        gpu: GpuTier::new(device(0), None),
    }
}

impl Setup {
    /// Publishes `bytes` as alice's original and loads it as `physical_bytes` of weights.
    fn load(&mut self, owner: &Consumer, bytes: &[u8], physical_bytes: u64) -> AllocationHandle {
        let object = publish(
            &mut self.catalog.catalog,
            owner,
            bytes,
            ObjectRole::Original,
        );
        let handle = read_handle(&mut self.catalog.catalog, owner, &object).unwrap();
        self.gpu
            .load_weights(
                owner,
                &object,
                &handle,
                &self.catalog.catalog,
                physical_bytes,
                &charge("op-load"),
                &mut self.ledger,
            )
            .unwrap()
    }
}

fn capacity(refusal: GpuRefusal) -> crate::foundation::ledger::CapacityError {
    match refusal {
        GpuRefusal::Ledger(LedgerError::Capacity(error)) => error,
        other => panic!("expected a capacity refusal, got {other:?}"),
    }
}

#[test]
fn physical_allocations_count_once_and_mapped_bytes_never() {
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let weights = setup.load(&alice, b"llama-8b weights", 10 * GIB);
    for _ in 0..3 {
        setup.gpu.map(weights, 10 * GIB).unwrap();
    }
    assert_eq!(setup.gpu.mapped_bytes(), 30 * GIB);
    assert_eq!(setup.gpu.physical_bytes(), 10 * GIB);
    // The ledger holds the physical bytes once; mappings reserved nothing.
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 10 * GIB);
    assert_eq!(
        setup.ledger.available(vram_resource(device(0))),
        Some(14 * GIB)
    );

    // KV is a separate mutable allocation and takes the rest of the device.
    let kv = setup
        .gpu
        .allocate_state(
            &alice,
            MutableState::KvCache,
            14 * GIB,
            &charge("op-kv"),
            &mut setup.ledger,
        )
        .unwrap();
    assert!(setup.gpu.content(kv).unwrap().is_mutable());
    assert!(!setup.gpu.content(weights).unwrap().is_mutable());
    // One more physical byte is refused although 30 GiB are "mapped".
    let refusal = setup
        .gpu
        .allocate_state(
            &alice,
            MutableState::Scratch,
            1,
            &charge("op-scratch"),
            &mut setup.ledger,
        )
        .unwrap_err();
    let error = capacity(refusal);
    assert_eq!(error.resource(), vram_resource(device(0)));
    assert_eq!(error.limiting().limit, Limit::PhysicalCapacity);
    assert_eq!(error.limiting().available, 0);

    assert_eq!(
        setup.gpu.map(weights, 10 * GIB + 1),
        Err(GpuRefusal::MappingExceedsAllocation {
            mapped_bytes: 10 * GIB + 1,
            physical_bytes: 10 * GIB,
        })
    );
    assert_eq!(setup.gpu.map(weights, 0), Err(GpuRefusal::ZeroBytes));
}

#[test]
fn two_14_gb_weight_sets_do_not_fit_on_a_24_gb_gpu() {
    // §2.7 line 444: even before KV and workspace.
    let mut setup = setup(24_000_000_000);
    let alice = consumer("alice", "exe-alice-1");
    setup.load(&alice, b"first 14 GB model", 14_000_000_000);
    let second = publish(
        &mut setup.catalog.catalog,
        &alice,
        b"second 14 GB model",
        ObjectRole::Original,
    );
    let handle = read_handle(&mut setup.catalog.catalog, &alice, &second).unwrap();
    let refusal = setup
        .gpu
        .load_weights(
            &alice,
            &second,
            &handle,
            &setup.catalog.catalog,
            14_000_000_000,
            &charge("op-load-2"),
            &mut setup.ledger,
        )
        .unwrap_err();
    let error = capacity(refusal);
    assert_eq!(error.resource(), vram_resource(device(0)));
    assert_eq!(error.limiting().requested, 14_000_000_000);
    assert_eq!(error.limiting().available, 10_000_000_000);
    // A release of 4 GB would let it fit, so a retry can make progress.
    assert!(error.retry_can_progress());
    assert_eq!(setup.gpu.physical_bytes(), 14_000_000_000);
    assert!((setup.gpu.physical_bytes() as f64) < 24.0 * GB);
}

#[test]
fn shared_weights_count_once_and_separate_copies_count_twice() {
    let mut setup = setup(24 * GIB);
    let first = consumer("alice", "exe-alice-1");
    let second = consumer("alice", "exe-alice-2");
    let shared = setup.load(&first, b"shared weights", 8 * GIB);
    for holder in [&first, &second] {
        setup
            .gpu
            .add_reference(shared, ReferenceHolder::Execution(holder.clone()))
            .unwrap();
    }
    assert_eq!(setup.gpu.references(shared), Ok(2));
    assert_eq!(setup.gpu.physical_bytes(), 8 * GIB);
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 8 * GIB);
    // Without a way to share, a second process loads its own physical copy, which counts.
    setup.load(&second, b"its own copy", 8 * GIB);
    assert_eq!(setup.gpu.physical_bytes(), 16 * GIB);
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 16 * GIB);
}

#[test]
fn references_and_mappings_keep_physical_memory_alive() {
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let weights = setup.load(&alice, b"weights", 8 * GIB);
    let holder = ReferenceHolder::Graph {
        owner: alice.clone(),
        graph: crate::foundation::ids::digest("yougori/test/graph/v1", &[b"decode"]),
    };
    setup.gpu.add_reference(weights, holder.clone()).unwrap();
    assert_eq!(
        setup.gpu.add_reference(weights, holder.clone()),
        Err(GpuRefusal::DuplicateReference)
    );
    let mapping = setup.gpu.map(weights, 8 * GIB).unwrap();
    assert_eq!(
        setup.gpu.free(weights, &mut setup.ledger),
        Err(GpuRefusal::StillReferenced { references: 1 })
    );
    setup.gpu.drop_reference(weights, &holder).unwrap();
    assert_eq!(
        setup.gpu.drop_reference(weights, &holder),
        Err(GpuRefusal::UnknownReference)
    );
    assert_eq!(
        setup.gpu.free(weights, &mut setup.ledger),
        Err(GpuRefusal::StillMapped { mappings: 1 })
    );
    setup.gpu.unmap(weights, mapping).unwrap();
    assert_eq!(
        setup.gpu.unmap(weights, mapping),
        Err(GpuRefusal::UnknownMapping { mapping })
    );
    let reservation = setup.gpu.reservation(weights).unwrap();
    let released = setup.gpu.free(weights, &mut setup.ledger).unwrap();
    assert_eq!(released.bytes, 8 * GIB);
    assert_eq!(released.reservation, reservation);
    // The memory existed, so the ledger counts it until the host observes the release.
    assert_eq!(released.outcome, ReleaseOutcome::Pending);
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 8 * GIB);
    setup
        .ledger
        .confirm_release(reservation, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 0);

    // The freed handle is stale for good, and generations are never reused.
    let stale = GpuRefusal::StaleHandle {
        generation: weights.generation(),
    };
    assert_eq!(setup.gpu.map(weights, 1), Err(stale.clone()));
    assert_eq!(setup.gpu.references(weights), Err(stale.clone()));
    assert!(matches!(
        setup.gpu.free(weights, &mut setup.ledger),
        Err(GpuRefusal::StaleHandle { .. })
    ));
    let next = setup.load(&alice, b"next", GIB);
    assert!(next.generation() > weights.generation());
    assert_eq!(setup.gpu.physical_bytes(), GIB);
}

#[test]
fn state_and_weights_stay_in_their_tenant_and_trust_scope() {
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let weights = setup.load(&alice, b"weights", 4 * GIB);
    let kv = setup
        .gpu
        .allocate_state(
            &alice,
            MutableState::KvCache,
            GIB,
            &charge("op-kv"),
            &mut setup.ledger,
        )
        .unwrap();
    assert_eq!(setup.gpu.owner(kv), Ok(&alice));
    let bob = consumer("bob", "exe-bob-1");
    // The same tenant in a VM sandbox is another trust scope.
    let alice_in_vm = Consumer {
        trust: TrustScope::named(ExecutionCategory::VmSandbox, "alice"),
        ..consumer("alice", "exe-alice-vm")
    };
    for allocation in [weights, kv] {
        for stranger in [&bob, &alice_in_vm] {
            assert_eq!(
                setup
                    .gpu
                    .add_reference(allocation, ReferenceHolder::Execution(stranger.clone())),
                Err(GpuRefusal::OutsideScope {
                    holder: Box::new(stranger.clone()),
                    owner: Box::new(alice.clone()),
                })
            );
        }
    }
    setup
        .gpu
        .add_reference(
            weights,
            ReferenceHolder::Import {
                importer: consumer("alice", "exe-alice-loader"),
                operation: operation("op-load"),
            },
        )
        .unwrap();
}

#[test]
fn weights_load_only_through_a_read_handle_for_that_object() {
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    let first = publish(
        &mut setup.catalog.catalog,
        &alice,
        b"first",
        ObjectRole::Original,
    );
    let second = publish(
        &mut setup.catalog.catalog,
        &alice,
        b"second",
        ObjectRole::Original,
    );
    let handle = read_handle(&mut setup.catalog.catalog, &alice, &first).unwrap();
    assert_eq!(
        setup.gpu.load_weights(
            &alice,
            &second,
            &handle,
            &setup.catalog.catalog,
            GIB,
            &charge("op-load"),
            &mut setup.ledger
        ),
        Err(GpuRefusal::HandleMismatch {
            named: second.id(),
            handle: first.id(),
        })
    );
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 0);

    // Bob holds no grant, so the catalog gives him no handle on Alice's object at all.
    assert!(matches!(
        read_handle(&mut setup.catalog.catalog, &bob, &first),
        Err(ReadRefusal::NotGranted { .. })
    ));
    // Under a grant for exactly that object he reads it, read-only, into his own memory.
    setup
        .catalog
        .catalog
        .grant(
            &alice.scope(),
            GrantRequest {
                object: first.id(),
                grantee: bob.scope(),
                execution: None,
                expires_at: at_seconds(3_600),
            },
        )
        .unwrap();
    let granted = read_handle(&mut setup.catalog.catalog, &bob, &first).unwrap();
    let loaded = setup
        .gpu
        .load_weights(
            &bob,
            &first,
            &granted,
            &setup.catalog.catalog,
            GIB,
            &charge("op-load"),
            &mut setup.ledger,
        )
        .unwrap();
    assert_eq!(setup.gpu.owner(loaded), Ok(&bob));
    assert_eq!(
        setup.gpu.content(loaded),
        Ok(&GpuContent::ImmutableWeights {
            object: first.clone()
        })
    );
    setup.clock.advance(Duration::from_secs(1));
    assert_eq!(setup.gpu.resident(&first), vec![loaded]);
}

#[test]
fn resident_weights_are_offered_only_within_the_trust_scope() {
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let object = publish(
        &mut setup.catalog.catalog,
        &alice,
        b"weights",
        ObjectRole::Original,
    );
    let handle = read_handle(&mut setup.catalog.catalog, &alice, &object).unwrap();
    setup
        .gpu
        .load_weights(
            &alice,
            &object,
            &handle,
            &setup.catalog.catalog,
            6 * GIB,
            &charge("op-load"),
            &mut setup.ledger,
        )
        .unwrap();
    let other_execution = consumer("alice", "exe-alice-2");
    let offer = setup
        .gpu
        .offer(
            source_id("gpu0"),
            &object,
            &other_execution,
            path(20.0 * GB, 0.001, &[]),
        )
        .unwrap();
    assert_eq!(offer.tier(), Tier::Gpu);
    assert_eq!(offer.covers_bytes(), 6 * GIB);

    let refusal = setup
        .gpu
        .offer(
            source_id("gpu0"),
            &object,
            &consumer("bob", "exe-bob-1"),
            path(20.0 * GB, 0.001, &[]),
        )
        .unwrap_err();
    assert_eq!(refusal.tier, Tier::Gpu);
    assert!(matches!(
        refusal.reason,
        TierRefusal::Gpu(GpuRefusal::OutsideScope { .. })
    ));
    let elsewhere = ObjectRef {
        scope: object.scope.clone(),
        class: object.class,
        content: crate::foundation::ids::ContentKey::of(b"not loaded"),
    };
    assert_eq!(
        setup
            .gpu
            .offer(
                source_id("gpu0"),
                &elsewhere,
                &alice,
                path(20.0 * GB, 0.001, &[])
            )
            .unwrap_err()
            .reason,
        TierRefusal::Gpu(GpuRefusal::NotResident { object: elsewhere })
    );
}

/// A process that maps `maps` for ten seconds with a 0.5 GB context and 2 GB of KV.
fn runner(name: &str, owner: &Consumer, maps: &[String]) -> ProcessVram {
    ProcessVram {
        process: name.to_string(),
        sharing_domain: owner.trust,
        lifetime: ten_seconds(),
        maps: maps.to_vec(),
        context_bytes: 500_000_000,
        graph_pool_bytes: 0,
        kv: KvBound::Reserved {
            bytes: 2_000_000_000,
        },
        transients: Vec::new(),
    }
}

fn ten_seconds() -> Interval {
    Interval::new(at_seconds(0), at_seconds(10)).unwrap()
}

/// T08's §2.7 plan for a 24 GB device with a 1 GB safety reserve.
fn plan_24_gb(allocations: Vec<ImmutableAllocation>, processes: Vec<ProcessVram>) -> VramPlan {
    VramPlan {
        device: device(0),
        usable_vram: Capacity::Physical {
            bytes: 24_000_000_000,
        },
        safety_reserve_bytes: 1_000_000_000,
        allocations,
        processes,
    }
}

#[test]
fn the_vram_plan_counts_each_physical_allocation_once() {
    let mut setup = setup(64 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let other = consumer("alice", "exe-alice-2");
    let object = publish(
        &mut setup.catalog.catalog,
        &alice,
        b"14 GB weights",
        ObjectRole::Original,
    );
    let handle = read_handle(&mut setup.catalog.catalog, &alice, &object).unwrap();
    let shared = setup
        .gpu
        .load_weights(
            &alice,
            &object,
            &handle,
            &setup.catalog.catalog,
            14_000_000_000,
            &charge("op-load"),
            &mut setup.ledger,
        )
        .unwrap();
    setup
        .gpu
        .allocate_state(
            &alice,
            MutableState::KvCache,
            GIB,
            &charge("op-kv"),
            &mut setup.ledger,
        )
        .unwrap();
    // One immutable allocation however many map it; KV is a per-process term, not one.
    let allocations = setup.gpu.immutable_allocations(ten_seconds());
    assert_eq!(allocations.len(), 1);
    assert_eq!(allocations[0].key, setup.gpu.allocation_key(shared));
    assert_eq!(allocations[0].kind, ImmutableKind::Weights);
    assert_eq!(allocations[0].bytes, 14_000_000_000);
    assert_eq!(allocations[0].sharing_domain, alice.trust);
    let key = allocations[0].key.clone();

    // §2.7: two processes map the shared allocation, which counts once:
    // 14 + 2 × (0.5 + 2) + 1 = 20 GB of 24.
    let plan = plan_24_gb(
        allocations.clone(),
        vec![
            runner("runner-1", &alice, &[key.clone()]),
            runner("runner-2", &other, &[key.clone()]),
        ],
    );
    let evaluation = admit_vram(&plan).unwrap();
    assert_eq!(evaluation.peak().unwrap().total_bytes, 20_000_000_000);
    assert_eq!(
        evaluation
            .peak()
            .unwrap()
            .demand
            .unique_resident_weights_bytes,
        14_000_000_000
    );

    // A second physical copy of the same object counts again (line 444: two 14 GB weight
    // sets do not fit on a 24 GB GPU).
    let copy = setup
        .gpu
        .load_weights(
            &other,
            &object,
            &handle,
            &setup.catalog.catalog,
            14_000_000_000,
            &charge("op-load-2"),
            &mut setup.ledger,
        )
        .unwrap();
    let copy_key = setup.gpu.allocation_key(copy);
    let plan = plan_24_gb(
        setup.gpu.immutable_allocations(ten_seconds()),
        vec![
            runner("runner-1", &alice, &[key.clone()]),
            runner("runner-2", &other, &[copy_key]),
        ],
    );
    assert!(matches!(admit_vram(&plan), Err(VramError::DoesNotFit(_))));

    // The allocation is shareable only inside its owner's trust scope (S3.3).
    let sandboxed = in_vm("alice", "exe-alice-vm");
    let plan = plan_24_gb(
        allocations,
        vec![runner("runner-vm", &sandboxed, &[key.clone()])],
    );
    assert_eq!(
        admit_vram(&plan).unwrap_err(),
        VramError::CrossDomainSharing {
            allocation: key,
            process: "runner-vm".to_string(),
        }
    );
}

#[test]
fn clean_weights_drop_only_with_a_verified_copy_of_that_object_that_stays_available() {
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let weights = setup.load(&alice, b"weights", 8 * GIB);
    let object = match setup.gpu.content(weights).unwrap() {
        GpuContent::ImmutableWeights { object } => object.clone(),
        other => panic!("expected weights, got {other:?}"),
    };
    let kv = setup
        .gpu
        .allocate_state(
            &alice,
            MutableState::KvCache,
            GIB,
            &charge("op-kv"),
            &mut setup.ledger,
        )
        .unwrap();
    let copy = |of: &ObjectRef, holder: Option<&Consumer>, tier, verification| ObjectCopy {
        object: of.clone(),
        holder: holder.cloned(),
        copy: ReconstructibleCopy { tier, verification },
    };
    let verified = Verification::Verified {
        content: Content::Immutable(object.content),
    };
    let stored = |tier| copy(&object, None, tier, verified);
    let pinned_by = |holder: &Consumer| copy(&object, Some(holder), CopyTier::PinnedHost, verified);
    let action = |handle, copies: &[ObjectCopy], write_back| {
        setup
            .gpu
            .eviction_action(handle, copies, write_back)
            .unwrap()
    };
    // Without a copy, clean weights are written back or kept, never dropped (line 307).
    assert_eq!(
        action(weights, &[], WriteBack::Available),
        EvictionAction::WriteBackThenDrop {
            d2h_bytes: 8 * GIB,
            because: NotDroppable::NoVerifiedCopy,
        }
    );
    let other_content = ObjectRef {
        content: ContentKey::of(b"other"),
        ..object.clone()
    };
    let equal_content_of_bob = ObjectRef {
        scope: scope("bob"),
        ..object.clone()
    };
    let unavailable = [
        // Reclaimable host RAM may vanish and a peer's or remote's copy can expire (T08).
        copy(&object, Some(&alice), CopyTier::ReclaimableHost, verified),
        stored(CopyTier::AuthorizedPeer),
        stored(CopyTier::RemoteSource),
        // An unverified copy never counts.
        copy(
            &object,
            None,
            CopyTier::LocalStorage,
            Verification::Unverified,
        ),
        // Nor does a copy of another object: other content, or equal content in another
        // scope (S3.3).
        copy(
            &other_content,
            None,
            CopyTier::LocalStorage,
            Verification::Verified {
                content: Content::Immutable(other_content.content),
            },
        ),
        copy(
            &equal_content_of_bob,
            None,
            CopyTier::LocalStorage,
            verified,
        ),
        // Nor a pin in another tenant's or trust scope's memory.
        pinned_by(&consumer("bob", "exe-bob-1")),
        pinned_by(&in_vm("alice", "exe-alice-vm")),
    ];
    assert_eq!(
        action(weights, &unavailable, WriteBack::Unavailable),
        EvictionAction::Retain {
            because: NotDroppable::NoVerifiedCopy,
        }
    );
    // A verified copy of that object in local storage, or pinned in the owner's tenant
    // and trust scope, lets it drop clean, pinned first.
    assert_eq!(
        action(
            weights,
            &[stored(CopyTier::LocalStorage)],
            WriteBack::Unavailable
        ),
        EvictionAction::DropClean {
            source: CopyTier::LocalStorage,
        }
    );
    assert_eq!(
        action(
            weights,
            &[
                stored(CopyTier::LocalStorage),
                pinned_by(&consumer("alice", "exe-alice-2"))
            ],
            WriteBack::Unavailable
        ),
        EvictionAction::DropClean {
            source: CopyTier::PinnedHost,
        }
    );
    // Mutable KV is dirty: written back or kept, whatever copies exist.
    assert_eq!(
        action(kv, &[stored(CopyTier::LocalStorage)], WriteBack::Available),
        EvictionAction::WriteBackThenDrop {
            d2h_bytes: GIB,
            because: NotDroppable::Dirty,
        }
    );
    assert_eq!(
        action(kv, &[pinned_by(&alice)], WriteBack::Unavailable),
        EvictionAction::Retain {
            because: NotDroppable::Dirty,
        }
    );
    // A freed allocation has no eviction action.
    setup.gpu.free(kv, &mut setup.ledger).unwrap();
    assert!(matches!(
        setup.gpu.eviction_action(kv, &[], WriteBack::Available),
        Err(GpuRefusal::StaleHandle { .. })
    ));
}

#[test]
fn a_read_handle_never_lets_another_tenant_load_private_weights() {
    // Review R1-c: a read handle does not record who opened it, so the tier asks the
    // catalog whether the owner itself may read the object (line 546).
    let mut setup = setup(24 * GIB);
    let alice = consumer("alice", "exe-alice-1");
    let bob = consumer("bob", "exe-bob-1");
    let private = publish(
        &mut setup.catalog.catalog,
        &alice,
        b"alice's private weights",
        ObjectRole::Original,
    );
    let alices_handle = read_handle(&mut setup.catalog.catalog, &alice, &private).unwrap();
    let load = |setup: &mut Setup, owner: &Consumer| {
        setup.gpu.load_weights(
            owner,
            &private,
            &alices_handle,
            &setup.catalog.catalog,
            GIB,
            &charge("op-load"),
            &mut setup.ledger,
        )
    };
    assert_eq!(
        load(&mut setup, &bob),
        Err(GpuRefusal::Unreadable(ReadRefusal::NotGranted {
            object: private.id()
        }))
    );
    assert_eq!(setup.gpu.physical_bytes(), 0);
    assert_eq!(setup.ledger.reserved(vram_resource(device(0))), 0);
    let grant = |setup: &mut Setup, execution| {
        setup
            .catalog
            .catalog
            .grant(
                &alice.scope(),
                GrantRequest {
                    object: private.id(),
                    grantee: bob.scope(),
                    execution,
                    expires_at: at_seconds(3_600),
                },
            )
            .unwrap();
    };
    // A grant narrowed to another of Bob's executions does not reach this one.
    grant(&mut setup, Some(execution_id("exe-bob-2")));
    assert!(matches!(
        load(&mut setup, &bob),
        Err(GpuRefusal::Unreadable(ReadRefusal::NotGranted { .. }))
    ));
    // Under a grant for exactly that object and execution Bob may load it into memory he
    // owns; Alice always may.
    grant(&mut setup, None);
    let loaded = load(&mut setup, &bob).unwrap();
    assert_eq!(setup.gpu.owner(loaded), Ok(&bob));
    load(&mut setup, &alice).unwrap();
}
