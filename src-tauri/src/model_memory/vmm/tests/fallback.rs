//! The fallback without CUDA VMM (§3.7; Appendix E step 9): one backend allocation per
//! artifact, explicit destruction and rebinding of views, no pool freed under live views,
//! and graphs recaptured without pointer stability.

use super::*;

/// P1 holds artifact `name` in one backend allocation, filled and published.
fn pool_world(name: &str, length_bytes: u64) -> (World, MappingKey) {
    let mut world = World::new();
    let key = world
        .model
        .plan_pool(
            P1,
            named(name),
            content_of(name),
            whole(name, length_bytes),
            true,
        )
        .unwrap();
    world.fill(key, name, 1);
    (world, key)
}

fn graph_key(model: &str) -> GraphExecutionKey {
    GraphExecutionKey {
        model: named(model),
        kernels: named(&format!("{model}/kernels")),
        shapes: named(&format!("{model}/shapes")),
        arguments: named(&format!("{model}/arguments")),
    }
}

#[test]
fn appendix_e_step_9_sequence() {
    let (mut world, key) = pool_world("a", 3 * MIB);
    let view = world.model.create_view(key, 0, 3 * MIB).unwrap();
    let event = world.call(view).unwrap();
    world.driver.complete(event);
    world.model.destroy_view(view).unwrap();
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.released_bytes, 3 * MIB);
    assert_eq!(
        report.unmapped_bytes, 0,
        "a pool allocation has no VMM mapping"
    );
    world.model.wake(key).unwrap();
    world.fill(key, "a", 1);
    let rebound = world.model.create_view(key, 0, 3 * MIB).unwrap();
    world.call(rebound).unwrap();
    assert_eq!(
        world.calls_of(P1),
        [
            "backend pool allocate",
            "enqueue",
            "enqueue",
            "backend pool free",
            "backend pool allocate",
            "enqueue",
            "enqueue",
        ]
    );
    assert!(world.driver.calls().iter().any(|call| call.call
        == DriverCall::PoolAllocate {
            size_bytes: 3 * MIB,
            expandable_segments: true,
        }));
    assert_eq!(world.model.reservation(key), None);
    world.assert_no_refusals();
}

#[test]
fn a_pool_is_never_freed_while_live_views_reference_it() {
    let (mut world, key) = pool_world("a", 3 * MIB);
    let physical = world.physical_of(key, 0);
    let first = world.model.create_view(key, 0, MIB).unwrap();
    let second = world.model.create_view(key, MIB, 2 * MIB).unwrap();
    assert_eq!(
        world.model.references(physical, P1).unwrap(),
        ReferenceCount {
            mappings: 1,
            views: 2,
            ..ReferenceCount::default()
        }
    );
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.released_bytes, 0);
    assert_eq!(report.retained[0].references.views, 2);
    assert_eq!(world.count_calls("backend pool free"), 0);
    assert_eq!(world.driver.used_bytes(DEVICE), 3 * MIB);
    assert_eq!(
        world.call(first),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Parked,
        })
    );
    world.model.destroy_view(first).unwrap();
    assert_eq!(
        world.close(P1, physical),
        Err(VmmError::StillReferenced {
            physical,
            references: ReferenceCount {
                views: 1,
                ..ReferenceCount::default()
            },
        })
    );
    world.model.destroy_view(second).unwrap();
    assert_eq!(
        world.model.destroy_view(second),
        Err(VmmError::UnknownView { view: second })
    );
    assert_eq!(world.close(P1, physical), Ok(3 * MIB));
    assert_eq!(world.count_calls("backend pool free"), 1);
    world.assert_no_refusals();
}

#[test]
fn views_of_a_replaced_allocation_are_rebuilt() {
    let (mut world, key) = pool_world("a", 3 * MIB);
    let old_view = world.model.create_view(key, 0, 3 * MIB).unwrap();
    let old = world.physical_of(key, 0);
    world.park(key, clean_drop("a")).unwrap();
    world.model.wake(key).unwrap();
    world.fill(key, "a", 1);
    let new = world.physical_of(key, 0);
    assert_ne!(old, new);
    let generations = (
        world.model.physical(old).unwrap().generation,
        world.model.physical(new).unwrap().generation,
    );
    assert_eq!(
        world.call(old_view),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::StaleAllocation {
                bound: generations.0,
                current: Some(generations.1),
            },
        }),
        "a view of the old allocation is never callable"
    );
    let new_view = world.model.create_view(key, 0, 3 * MIB).unwrap();
    assert!(world.call(new_view).is_ok());
    world.model.destroy_view(old_view).unwrap();
    assert_eq!(world.close(P1, old), Ok(3 * MIB));
    world.assert_no_refusals();
}

#[test]
fn graphs_over_a_reallocated_pool_are_recaptured_even_at_an_equal_pointer() {
    let (mut world, key) = pool_world("a", 3 * MIB);
    let resources = vec![GraphResource::Artifact {
        artifact: named("a"),
        offset_bytes: 0,
        length_bytes: 3 * MIB,
    }];
    let graph = world
        .model
        .capture_graph(P1, graph_key("a"), resources.clone())
        .unwrap();
    let before = world.model.batch(key, 0).unwrap().address;
    world.model.detach_graph(&mut world.driver, graph).unwrap();
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.released_bytes, 3 * MIB);
    world.model.wake(key).unwrap();
    world.fill(key, "a", 1);
    assert_eq!(
        world.model.batch(key, 0).unwrap().address,
        before,
        "the allocator handed back the same pointer value"
    );
    assert_eq!(
        world.model.launch_graph(&mut world.driver, graph, STREAM),
        Err(VmmError::GraphDetached { graph })
    );
    assert_eq!(
        world
            .model
            .reuse_graph(&mut world.driver, graph, graph_key("a"), &resources),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Reallocated { resource: 0 },
        }),
        "without pointer stability an equal pointer proves nothing"
    );
    world.model.destroy_graph(&mut world.driver, graph).unwrap();
    let recaptured = world
        .model
        .capture_graph(P1, graph_key("a"), resources)
        .unwrap();
    assert!(world
        .model
        .launch_graph(&mut world.driver, recaptured, STREAM)
        .is_ok());
    world.assert_no_refusals();
}

#[test]
fn a_pool_view_needs_memory_behind_it() {
    let mut world = World::new();
    let key = world
        .model
        .plan_pool(P1, named("a"), content_of("a"), whole("a", 3 * MIB), false)
        .unwrap();
    assert_eq!(
        world.model.create_view(key, 0, MIB),
        Err(VmmError::BatchState {
            key,
            batch: 0,
            state: BatchState::Empty,
            operation: "bind a view",
        })
    );
    assert_eq!(
        world.back(key, 1),
        Err(VmmError::UnknownBatch { key, batch: 1 }),
        "a pool artifact is one allocation"
    );
    assert_eq!(
        world
            .model
            .plan_pool(P1, named("a"), content_of("a"), whole("a", 3 * MIB), false),
        Err(VmmError::AlreadyPlanned { key })
    );
    assert_eq!(
        world
            .model
            .plan_pool(P1, named("b"), content_of("b"), whole("b", 0), false),
        Err(VmmError::EmptyBatch { batch: 0 })
    );
    assert_eq!(
        world.model.plan_pool(
            ProcessId(9),
            named("b"),
            content_of("b"),
            whole("b", MIB),
            false
        ),
        Err(VmmError::UnknownProcess {
            process: ProcessId(9)
        })
    );
}
