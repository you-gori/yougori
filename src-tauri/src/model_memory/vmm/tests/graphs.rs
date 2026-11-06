//! CUDA graph reuse needs compatible kernels, shapes, arguments, addresses, workspaces and
//! resource lifetimes; an address reservation alone never suffices (§3.7; §1.1 row 305).

use super::*;

fn graph_key(model: &str) -> GraphExecutionKey {
    GraphExecutionKey {
        model: named(model),
        kernels: named(&format!("{model}/kernels")),
        shapes: named(&format!("{model}/shapes")),
        arguments: named(&format!("{model}/arguments")),
    }
}

fn over(artifact: &str, offset_bytes: u64, length_bytes: u64) -> GraphResource {
    GraphResource::Artifact {
        artifact: named(artifact),
        offset_bytes,
        length_bytes,
    }
}

fn capture(world: &mut World, model: &str, resources: &[GraphResource]) -> GraphId {
    world
        .model
        .capture_graph(P1, graph_key(model), resources.to_vec())
        .unwrap()
}

fn reuse(
    world: &mut World,
    graph: GraphId,
    key: GraphExecutionKey,
    resources: &[GraphResource],
) -> Result<(), VmmError> {
    world
        .model
        .reuse_graph(&mut world.driver, graph, key, resources)
}

fn launch(world: &mut World, graph: GraphId) -> Result<EventId, VmmError> {
    world.model.launch_graph(&mut world.driver, graph, STREAM)
}

#[test]
fn reuse_needs_every_component_to_match() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB, 4 * MIB], private());
    let workspace = world.model.create_workspace(P1, MIB).unwrap();
    let resources = [
        over("a", 0, 8 * MIB),
        GraphResource::Workspace { workspace },
    ];
    let graph = capture(&mut world, "a", &resources);
    let base = graph_key("a");
    assert_eq!(reuse(&mut world, graph, base, &resources), Ok(()));

    let changed = [
        (
            GraphExecutionKey {
                kernels: named("other kernels"),
                ..base
            },
            GraphMismatch::Kernels,
        ),
        (
            GraphExecutionKey {
                shapes: named("other shapes"),
                ..base
            },
            GraphMismatch::Shapes,
        ),
        (
            GraphExecutionKey {
                arguments: named("other arguments"),
                ..base
            },
            GraphMismatch::Arguments,
        ),
        (
            GraphExecutionKey {
                model: named("other model"),
                ..base
            },
            GraphMismatch::Model,
        ),
    ];
    for (requested, mismatch) in changed {
        assert_eq!(
            reuse(&mut world, graph, requested, &resources),
            Err(VmmError::GraphIncompatible { graph, mismatch })
        );
    }
    assert_eq!(
        reuse(
            &mut world,
            graph,
            base,
            &[
                over("a", 0, 4 * MIB),
                GraphResource::Workspace { workspace }
            ]
        ),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Resources,
        })
    );

    assert_eq!(
        world.model.reallocate_workspace(workspace, MIB),
        Err(VmmError::WorkspaceInUse {
            workspace,
            graphs: vec![graph],
        }),
        "a workspace never ends before the graph that holds it"
    );
    world.model.detach_graph(&mut world.driver, graph).unwrap();
    world.model.reallocate_workspace(workspace, MIB).unwrap();
    assert_eq!(
        reuse(&mut world, graph, base, &resources),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Workspace { workspace },
        })
    );
    world.model.free_workspace(workspace).unwrap();
    assert_eq!(
        reuse(&mut world, graph, base, &resources),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Workspace { workspace },
        })
    );

    let fresh = world.model.create_workspace(P1, MIB).unwrap();
    let resources = [
        over("a", 0, 8 * MIB),
        GraphResource::Workspace { workspace: fresh },
    ];
    let graph = capture(&mut world, "a", &resources);
    world
        .model
        .begin_park(&mut world.driver, key, clean_drop("a"))
        .unwrap();
    assert_eq!(
        reuse(&mut world, graph, base, &resources),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Unavailable {
                resource: 0,
                reason: NotCallableReason::Draining,
            },
        }),
        "a resource that cannot be used now does not live through a replay"
    );
    world.assert_no_refusals();
}

#[test]
fn an_address_reservation_alone_never_makes_graphs_interchangeable() {
    let mut world = World::new();
    world.load(P1, "a", &[4 * MIB], private());
    let resources = [over("a", 0, 4 * MIB)];
    let graph = capture(&mut world, "a", &resources);
    assert_eq!(
        reuse(&mut world, graph, graph_key("b"), &resources),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Model,
        }),
        "another model's request over the very same addresses is refused"
    );
    let unrelated = GraphExecutionKey {
        model: named("a"),
        ..graph_key("b")
    };
    assert_eq!(
        reuse(&mut world, graph, unrelated, &resources),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Kernels,
        })
    );
    assert!(launch(&mut world, graph).is_ok());
    world.assert_no_refusals();
}

#[test]
fn a_detached_graph_is_rebound_after_a_vmm_wake() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let resources = [over("a", 0, 4 * MIB)];
    let graph = capture(&mut world, "a", &resources);
    let old = world.physical_of(key, 0);
    world.model.detach_graph(&mut world.driver, graph).unwrap();
    assert_eq!(world.model.graph_attached(graph), Some(false));
    assert!(world.model.references(old, P1).unwrap().graphs == 0);
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(
        report.released_bytes,
        4 * MIB,
        "the detached graph holds nothing"
    );
    world.model.wake(key).unwrap();
    world.fill(key, "a", 1);
    assert_eq!(
        launch(&mut world, graph),
        Err(VmmError::GraphDetached { graph })
    );
    reuse(&mut world, graph, graph_key("a"), &resources).unwrap();
    let new = world.physical_of(key, 0);
    assert_eq!(world.model.references(new, P1).unwrap().graphs, 1);
    assert_eq!(world.model.graph_attached(graph), Some(true));
    assert!(launch(&mut world, graph).is_ok());
    world.assert_no_refusals();
}

#[test]
fn a_retained_graph_is_stale_after_a_wake_until_checked() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let resources = [over("a", 0, 4 * MIB)];
    let graph = capture(&mut world, "a", &resources);
    let old = world.physical_of(key, 0);
    let report = world.park(key, clean_drop("a")).unwrap();
    assert_eq!(report.retained[0].references.graphs, 1);
    world.model.wake(key).unwrap();
    world.fill(key, "a", 1);
    assert_eq!(world.driver.used_bytes(DEVICE), 8 * MIB);
    assert_eq!(
        launch(&mut world, graph),
        Err(VmmError::GraphIncompatible {
            graph,
            mismatch: GraphMismatch::Generation { resource: 0 },
        }),
        "the memory behind the graph was re-created"
    );
    reuse(&mut world, graph, graph_key("a"), &resources).unwrap();
    assert!(world.model.references(old, P1).unwrap().is_zero());
    assert_eq!(world.close(P1, old), Ok(4 * MIB));
    assert_eq!(world.driver.used_bytes(DEVICE), 4 * MIB);
    assert!(launch(&mut world, graph).is_ok());
    world.assert_no_refusals();
}

#[test]
fn graphs_never_replay_over_unmapped_memory() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let graph = capture(&mut world, "a", &[over("a", 0, 4 * MIB)]);
    world
        .model
        .begin_park(&mut world.driver, key, clean_drop("a"))
        .unwrap();
    assert_eq!(
        launch(&mut world, graph),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Draining,
        })
    );
    world.model.finish_park(&mut world.driver, key).unwrap();
    assert_eq!(
        launch(&mut world, graph),
        Err(VmmError::NotCallable {
            key,
            reason: NotCallableReason::Parked,
        })
    );
    assert!(matches!(
        world
            .model
            .capture_graph(P1, graph_key("a"), vec![over("a", 0, 4 * MIB)]),
        Err(VmmError::NotCallable { .. })
    ));
    assert_eq!(
        world.count_calls("enqueue"),
        1,
        "only the populating copy ran"
    );
    world.assert_no_refusals();
}

#[test]
fn graphs_are_detached_destroyed_and_parked_only_when_quiescent() {
    let mut world = World::new();
    let key = world.load(P1, "a", &[4 * MIB], private());
    let graph = capture(&mut world, "a", &[over("a", 0, 4 * MIB)]);
    let replay = launch(&mut world, graph).unwrap();
    let busy = Err(VmmError::NotQuiescent {
        events: vec![replay],
    });
    assert_eq!(world.model.detach_graph(&mut world.driver, graph), busy);
    assert_eq!(world.model.destroy_graph(&mut world.driver, graph), busy);
    assert_eq!(
        reuse(&mut world, graph, graph_key("a"), &[over("a", 0, 4 * MIB)]),
        busy
    );
    world
        .model
        .begin_park(&mut world.driver, key, clean_drop("a"))
        .unwrap();
    assert_eq!(
        world.model.finish_park(&mut world.driver, key).map(|_| ()),
        busy,
        "a running graph that touches the range blocks the unmap"
    );
    world.driver.complete(replay);
    world.model.destroy_graph(&mut world.driver, graph).unwrap();
    world.model.finish_park(&mut world.driver, key).unwrap();
    assert_eq!(
        world.model.destroy_graph(&mut world.driver, graph),
        Err(VmmError::UnknownGraph { graph })
    );
    assert_eq!(world.model.graph_attached(graph), None);
    world.assert_no_refusals();
}

#[test]
fn workspaces_held_by_graphs_are_neither_freed_nor_reallocated() {
    let mut world = World::new();
    world.load(P1, "a", &[4 * MIB], private());
    let workspace = world.model.create_workspace(P1, MIB).unwrap();
    let graph = capture(
        &mut world,
        "a",
        &[
            over("a", 0, 4 * MIB),
            GraphResource::Workspace { workspace },
        ],
    );
    assert_eq!(
        world.model.free_workspace(workspace),
        Err(VmmError::WorkspaceInUse {
            workspace,
            graphs: vec![graph],
        })
    );
    world.model.destroy_graph(&mut world.driver, graph).unwrap();
    world.model.free_workspace(workspace).unwrap();
    assert_eq!(
        world.model.free_workspace(workspace),
        Err(VmmError::WorkspaceFreed { workspace })
    );
    assert_eq!(
        world.model.capture_graph(
            P1,
            graph_key("a"),
            vec![
                over("a", 0, 4 * MIB),
                GraphResource::Workspace { workspace }
            ],
        ),
        Err(VmmError::WorkspaceFreed { workspace })
    );
    assert_eq!(world.model.create_workspace(P1, 0), Err(VmmError::ZeroSize));
    assert_eq!(
        world
            .model
            .capture_graph(P2, graph_key("a"), vec![over("a", 0, 4 * MIB)],),
        Err(VmmError::UnknownArtifact {
            key: MappingKey {
                process: P2,
                artifact: named("a"),
            }
        }),
        "a graph uses only memory its own process holds"
    );
}

#[test]
fn a_graph_needs_artifact_memory() {
    let mut world = World::new();
    world.load(P1, "a", &[4 * MIB], private());
    let workspace = world.model.create_workspace(P1, MIB).unwrap();
    assert_eq!(
        world.model.capture_graph(
            P1,
            graph_key("a"),
            vec![GraphResource::Workspace { workspace }],
        ),
        Err(VmmError::EmptyGraph)
    );
    assert_eq!(
        world.model.capture_graph(P1, graph_key("a"), Vec::new()),
        Err(VmmError::EmptyGraph)
    );
    assert!(matches!(
        world
            .model
            .capture_graph(P1, graph_key("a"), vec![over("a", 2 * MIB, 4 * MIB)]),
        Err(VmmError::ViewOutOfRange { .. })
    ));
}
