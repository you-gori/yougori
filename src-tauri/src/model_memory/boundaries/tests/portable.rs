//! Boundary 3 over P03's portable path, and the GPU §1 flow over the committed boundaries:
//! the catalog store, the governor driving P04 slots on the host's one ledger, and P03
//! behind the executor boundary, with only the native backend in memory.

use std::collections::BTreeMap;
use std::time::Duration;

use super::committed::*;
use super::support::*;
use crate::foundation::coordination::HoldingId;
use crate::foundation::evidence::ArtifactVerification;
use crate::foundation::ids::{Clock, ContentKey};
use crate::foundation::ledger::{Priority, Requester, ReservationId};
use crate::model_memory::boundaries::*;
use crate::model_memory::executor::{SourceKind, Stage, TransferEventKind};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::placement::SupportedShape;

/// The extents of the weights file, in order, as an order names them.
fn weights_order(world: &Committed) -> Vec<OrderedExtent> {
    let weights = ContentKey::of(world.folder.weights());
    world
        .representation
        .extents()
        .iter()
        .filter(|descriptor| {
            descriptor
                .stored
                .is_some_and(|stored| stored.representation == weights)
        })
        .map(|descriptor| OrderedExtent {
            extent: ExtentRef {
                artifact: world.artifact,
                extent: descriptor.extent,
            },
            digest: descriptor.digest,
            length_bytes: descriptor.length_bytes,
            stored: descriptor.stored,
        })
        .collect()
}

/// The ledger reservation behind the weights the serving activation reads, held apart
/// from its own memory.
fn weights_reservation(world: &Committed) -> ReservationId {
    let placement = placement_of(world.model);
    let coordinator = world.governor.coordinator();
    let activations = coordinator
        .model_activations(&owner(), placement.model_id())
        .unwrap();
    let holding = activations
        .serving()
        .unwrap()
        .holdings()
        .iter()
        .filter(|holding| matches!(holding, HoldingId::Gpu { .. }))
        .filter_map(|holding| activations.holding(*holding))
        .find(|holding| holding.holds_weights())
        .unwrap();
    coordinator
        .capacity()
        .record(&holding.reservations()[0])
        .unwrap()
        .id()
}

/// The transfer reservations carved from `parent`, open or closed.
fn transfers_within(world: &Committed, parent: ReservationId) -> usize {
    world.ledger(|ledger| {
        ledger
            .closed_records()
            .iter()
            .chain(ledger.open_reservations())
            .filter(|record| {
                record.provenance().requester == Requester::Transfer
                    && record.parent() == Some(parent)
            })
            .count()
    })
}

#[test]
fn the_flow_runs_over_the_committed_boundaries() {
    let mut world = Committed::new();
    let request = world.request("committed");
    let receipt = world.serve(&request).unwrap();
    assert_eq!(receipt.path, ServePath::Materialized);
    assert_eq!(receipt.transferred, ids(&[WEIGHTS]));
    let mut reconstructed = receipt.reconstructed.clone();
    reconstructed.sort();
    assert_eq!(reconstructed, ids(&[TOKENIZER, ENGINE, CONTEXT]));
    // T08's demand: 4 GiB of weights, 1 GiB of context, 256 MiB of graph pool, a 2 GiB KV
    // pool and a 1 GiB transition peak.
    assert_eq!(receipt.reserved_device_bytes, 8 * GIB + 256 * MIB);

    // P03 read only the weights file, from the catalog's local source, and copied exactly
    // its verified bytes to the GPU, each extent at its offset in the file.
    let weights = world.folder.weights().to_vec();
    let state = world.backend.state();
    assert!(state
        .read_log
        .iter()
        .all(|(source, _, _)| *source == local()));
    let copied: u64 = state
        .copies
        .iter()
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    assert_eq!(copied, weights.len() as u64);
    for (range, bytes) in &state.copies {
        let start = range.offset_bytes as usize;
        assert_eq!(&weights[start..start + bytes.len()], &bytes[..]);
    }
    drop(state);

    // P03's own events report its reads from the catalog's local source and the job's
    // completion.
    let events = world.events.events();
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        TransferEventKind::StageMeasured(measured)
            if measured.stage == Stage::Read && measured.source == Some(local())
    )));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TransferEventKind::Completed)));
    drop(events);

    // Every destination was carved from the reservation of the weights it lands in, held
    // apart from the activation's own memory, so the memory counted once; the executor
    // finished and forgot its job.
    let order = weights_order(&world);
    assert_eq!(
        transfers_within(&world, weights_reservation(&world)),
        order.len()
    );
    assert!(world.executor.portable().is_idle());

    // The generation the slot published was verified as the store's artifact, and its
    // coordinator activation verifies exactly the store's catalog objects, which the
    // sandbox's authority granted at launch.
    let placement = placement_of(world.model);
    let slot = world.governor.slot(&placement, world.epoch()).unwrap();
    let published = slot.published().unwrap();
    assert_eq!(published.generation, receipt.generation);
    assert_eq!(published.artifact, world.artifact);
    let coordinator = world.governor.coordinator();
    let serving = coordinator
        .model_activations(&owner(), placement.model_id())
        .unwrap()
        .serving()
        .unwrap();
    assert_eq!(
        serving.settings().artifact_verification,
        ArtifactVerification::Verified {
            artifacts: world.representation.verified_artifacts()
        }
    );
}

#[test]
fn a_corrupted_extent_is_a_hash_mismatch_and_nothing_is_published() {
    let mut world = Committed::new();
    world.backend.state().corrupt.insert((local(), 0));
    let request = world.request("corrupted");
    let error = world.serve(&request).unwrap_err();
    let first = weights_order(&world)[0];
    assert_eq!(first.stored.unwrap().offset_bytes, 0);
    assert!(
        matches!(
            &error,
            FlowError::Transfer {
                failure: TransferFailure::HashMismatch { extent, expected, actual }
            } if *extent == first.extent && *expected == first.digest && actual != expected
        ),
        "{error:?}"
    );
    // P03 never copied the unverified bytes, and nothing serves.
    assert!(world
        .backend
        .state()
        .copies
        .iter()
        .all(|(range, _)| range.offset_bytes != 0));
    let placement = placement_of(world.model);
    assert!(world.governor.current_residency(&placement).is_none());
}

#[test]
fn an_order_lands_in_the_activations_own_reservation_or_not_at_all() {
    let mut world = Committed::new();
    let placement = placement_of(world.model);
    let dependencies = committed_dependencies(
        world.artifact,
        &world.representation,
        ContentKey::of(world.folder.weights()),
    );
    let held: Vec<NodeId> = dependencies.nodes.iter().map(|node| node.id).collect();
    let budget = world.governor.runtime(runner_owner()).unwrap().budget;
    let demand =
        activation_demand(&dependencies, &held, scope(), &budget, world.clock.now()).unwrap();
    let order = weights_order(&world);
    let declared = SupportedShape {
        max_context_tokens: 4_096,
        max_batch_sequences: 1,
    };
    let request = AdmissionRequest {
        authority: RequestAuthority {
            execution: owner(),
            operation: op("direct"),
            tenant: tenant(),
            epoch: world.epoch(),
        },
        placement,
        priority: Priority::Foreground,
        activation: Some(demand),
        spec: Some(ActivationSpec {
            verified: world.representation.clone(),
            extents: dependencies
                .nodes
                .iter()
                .filter(|node| node.kind == NodeKind::ArtifactExtent)
                .map(|node| ActivationExtent {
                    node: node.id,
                    identity: node.identity,
                    device_bytes: node.device_bytes,
                    ready: false,
                    transfers: match &node.materialization {
                        Materialization::Transfer { extents } => extents.clone(),
                        Materialization::Reconstruct => Vec::new(),
                    },
                })
                .collect(),
            declared,
            kv: KvSpec::bounded_by_pool(demand.peak.kv_bytes, &declared),
            reload: ReloadConsent::Never,
            reload_estimate: Duration::from_secs(5),
        }),
        transfer: order
            .iter()
            .map(|ordered| (ordered.extent, ordered.length_bytes))
            .collect(),
    };
    let admission = world.governor.admit(&request).unwrap();
    let pending = admission.activation.as_ref().unwrap();
    let budget = admission.transfer_budget.clone().unwrap();
    // The weights land in their own holding, apart from the activation's own memory,
    // which takes whatever has no destination of its own.
    let own = budget.destination().unwrap();
    assert_eq!(Some(own.allocation), pending.allocation());
    assert_eq!(own.capacity_bytes, demand.device_bytes - 4 * GIB);
    let destination = budget.destination_of(&order[0].extent).unwrap();
    assert_ne!(destination.allocation, own.allocation);
    assert_eq!(destination.capacity_bytes, 4 * GIB);
    assert!(order
        .iter()
        .all(|ordered| budget.destination_of(&ordered.extent) == Some(destination)));

    let token = PreparationToken::issue(owner(), op("direct"), tenant(), world.epoch(), placement);
    let transfer = TransferOrder::new(&token, &budget, order.clone()).unwrap();
    assert_eq!(transfer.destination(), Some(own));
    assert!(order
        .iter()
        .all(|ordered| transfer.destination_of(&ordered.extent) == Some(destination)));
    assert_eq!(transfer.tenant(), &tenant());
    let ticket = world.executor.submit(&transfer).unwrap();
    for ordered in &order {
        let completion = world
            .executor
            .await_extent(ticket, &ordered.extent)
            .unwrap();
        assert_eq!(completion.extent, ordered.extent);
        assert_eq!(completion.verified_digest, ordered.digest);
        assert_eq!(completion.bytes_read, ordered.length_bytes);
        assert_eq!(completion.source, SourceKind::LocalFile);
    }
    // One destination per extent, each carved from the weights' reservation, none from
    // the activation's own.
    assert_eq!(
        transfers_within(&world, destination.reservation),
        order.len()
    );
    assert_eq!(transfers_within(&world, own.reservation), 0);

    // An order with no reserved destination, or naming an extent no catalog object holds,
    // is refused before anything starts.
    let bare = TransferBudget::inbound(
        order
            .iter()
            .map(|ordered| (ordered.extent, ordered.length_bytes))
            .collect::<BTreeMap<_, _>>(),
        gpu(0),
    )
    .unwrap();
    assert_eq!(
        world
            .executor
            .submit(&TransferOrder::new(&token, &bare, order.clone()).unwrap()),
        Err(TransferRefusal::NoDestination)
    );
    let unstored: Vec<OrderedExtent> = order
        .iter()
        .map(|ordered| OrderedExtent {
            stored: None,
            ..*ordered
        })
        .collect();
    assert_eq!(
        world
            .executor
            .submit(&TransferOrder::new(&token, &budget, unstored).unwrap()),
        Err(TransferRefusal::NotStored {
            extent: order[0].extent
        })
    );
    assert!(world.executor.portable().is_idle());
}
