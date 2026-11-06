//! The activation's §2.7 demand, computed by T08 (GPU §2.7, §3.1 line 491).

use super::support::*;
use crate::foundation::ids::MonotonicTime;
use crate::model_memory::boundaries::*;
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::residency::reservation::PlacementError;
use crate::model_memory::residency::vram::{VramBreakdown, VramError};

fn budget(usable_bytes: u64) -> DeviceBudget {
    DeviceBudget {
        device: gpu(0),
        usable_bytes,
        safety_reserve_bytes: SAFETY_RESERVE_BYTES,
    }
}

fn every_node(dependencies: &ExecutionDependencies) -> Vec<NodeId> {
    dependencies.nodes.iter().map(|node| node.id).collect()
}

fn demand_of(
    dependencies: &ExecutionDependencies,
    held: &[NodeId],
    budget: &DeviceBudget,
) -> Result<ActivationDemand, DemandError> {
    activation_demand(dependencies, held, scope(), budget, MonotonicTime::ZERO)
}

#[test]
fn the_activation_demand_is_t08_s_peak_without_the_safety_reserve() {
    let world = World::new();
    let dependencies = model_a_dependencies(&world.scenario);
    let demand = demand_of(
        &dependencies,
        &every_node(&dependencies),
        &budget(SANDBOX_VRAM_BYTES),
    )
    .unwrap();
    assert_eq!(demand.device, gpu(0));
    assert_eq!(
        demand.peak,
        VramBreakdown {
            unique_resident_weights_bytes: 8 * GIB + 128 * MIB,
            kv_bytes: 2 * GIB,
            adapters_bytes: 512 * MIB,
            contexts_bytes: GIB,
            graph_pools_bytes: 256 * MIB,
            peak_workspaces_bytes: 0,
            staging_bytes: 0,
            activation_overlap_bytes: GIB,
            safety_reserve_bytes: SAFETY_RESERVE_BYTES,
        }
    );
    // The ledger is asked for every term but the reserve, which it keeps itself.
    assert_eq!(demand.device_bytes, MODEL_DEMAND_BYTES);
    assert_eq!(
        demand.peak.total_bytes(),
        Some(MODEL_DEMAND_BYTES + SAFETY_RESERVE_BYTES)
    );

    // Only the nodes the activation holds count: without the adapter, 512 MiB less.
    let without_adapter: Vec<NodeId> = every_node(&dependencies)
        .into_iter()
        .filter(|id| *id != NodeId::new(ADAPTER))
        .collect();
    assert_eq!(
        demand_of(&dependencies, &without_adapter, &budget(SANDBOX_VRAM_BYTES))
            .unwrap()
            .device_bytes,
        MODEL_DEMAND_BYTES - 512 * MIB
    );

    // KV blocks join the reserved KV bound, and no transition peak means no overlap term.
    let mut with_kv = dependencies.clone();
    with_kv.transition_peak_device_bytes = 0;
    with_kv.nodes.push(node(
        9,
        NodeKind::KvBlock,
        "prefix-kv",
        64 * MIB,
        ms(10),
        &[],
        Materialization::Reconstruct,
    ));
    let demand = demand_of(&with_kv, &every_node(&with_kv), &budget(SANDBOX_VRAM_BYTES)).unwrap();
    assert_eq!(demand.peak.kv_bytes, 2 * GIB + 64 * MIB);
    assert_eq!(demand.peak.activation_overlap_bytes, 0);
    assert_eq!(demand.device_bytes, MODEL_DEMAND_BYTES - GIB + 64 * MIB);
}

#[test]
fn t08_refuses_a_demand_that_does_not_fit() {
    let world = World::new();
    let dependencies = model_a_dependencies(&world.scenario);
    let held = every_node(&dependencies);
    // The inequality holds with equality: demand plus reserve equals the budget.
    let exact = MODEL_DEMAND_BYTES + SAFETY_RESERVE_BYTES;
    assert!(demand_of(&dependencies, &held, &budget(exact)).is_ok());
    let Err(DemandError::Residency(PlacementError::Vram(VramError::DoesNotFit(overcommit)))) =
        demand_of(&dependencies, &held, &budget(exact - 1))
    else {
        panic!("one byte short does not fit");
    };
    assert_eq!(overcommit.excess_bytes(), 1);
    assert_eq!(overcommit.usable_vram_bytes, exact - 1);
}

#[test]
fn t08_rules_bind_the_declaration() {
    let world = World::new();
    let dependencies = model_a_dependencies(&world.scenario);
    let held = every_node(&dependencies);

    // A safety reserve for consumers outside managed allocations is required (line 491).
    let no_reserve = DeviceBudget {
        safety_reserve_bytes: 0,
        ..budget(SANDBOX_VRAM_BYTES)
    };
    assert_eq!(
        demand_of(&dependencies, &held, &no_reserve),
        Err(DemandError::Residency(PlacementError::Vram(
            VramError::NoSafetyReserve { device: gpu(0) }
        )))
    );

    // Every process has a context of its own: a runner that declares none is refused.
    let mut no_context = dependencies.clone();
    for node in &mut no_context.nodes {
        if node.kind == NodeKind::EngineInitialization {
            node.device_bytes = 0;
        }
    }
    assert_eq!(
        demand_of(&no_context, &held, &budget(SANDBOX_VRAM_BYTES)),
        Err(DemandError::Residency(PlacementError::Vram(
            VramError::MissingContext {
                process: "runner".to_owned()
            }
        )))
    );

    // Request work is never state, and only declared nodes are held.
    let mut work = dependencies.clone();
    work.nodes[0].kind = NodeKind::Compute;
    assert_eq!(
        demand_of(&work, &held, &budget(SANDBOX_VRAM_BYTES)),
        Err(DemandError::NotState {
            node: NodeId::new(TOKENIZER)
        })
    );
    assert_eq!(
        demand_of(
            &dependencies,
            &[NodeId::new(42)],
            &budget(SANDBOX_VRAM_BYTES)
        ),
        Err(DemandError::UnknownNode {
            node: NodeId::new(42)
        })
    );
}

#[test]
fn state_shared_with_another_activation_counts_again() {
    let mut world = World::new();
    let (a, b) = (world.scenario.model_a, world.scenario.model_b);
    let request = world.request("a", a);
    world.serve(&request).unwrap();
    let request = world.request("b", b);
    let receipt = world.serve(&request).unwrap();
    // B reused A's resident base and transferred only its adapter, yet its activation
    // reserves the whole demand: weights count once within a placement's slot, and B is
    // another placement, so state shared with A's activation counts twice while both live
    // and is never left uncounted when one retires.
    assert_eq!(receipt.transferred, ids(&[ADAPTER]));
    assert_eq!(receipt.reserved_device_bytes, MODEL_DEMAND_BYTES);
    let mut both = model_a_holdings(1);
    both.extend(model_a_holdings(1));
    both.sort_by_key(|(bytes, _)| *bytes);
    assert_eq!(world.holdings(), both);
    assert_eq!(
        world.vram_room(),
        SANDBOX_VRAM_BYTES - 2 * MODEL_DEMAND_BYTES
    );
}
