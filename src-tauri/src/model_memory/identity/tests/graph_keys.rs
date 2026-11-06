//! §1.1, line 305: CUDA graph reuse needs an execution key and every graph resource;
//! addresses alone do not establish correctness.

use crate::foundation::ids::GpuAllocationGeneration;

use super::super::*;
use super::support::*;

fn changed(role: &str, fields: Vec<GraphResourceField>) -> GraphDifference {
    GraphDifference::ResourceChanged {
        role: label(role),
        fields,
    }
}

fn refused(differences: Vec<GraphDifference>) -> Result<GraphExecutionKey, GraphReuseRefusal> {
    Err(GraphReuseRefusal::Mismatch { differences })
}

/// A change to one field of one resource.
type Mutation = (GraphResourceField, fn(&mut GraphResource));

#[test]
fn the_graph_key_changes_with_every_graph_resource() {
    let captured = graph_spec();
    let key = captured.key().unwrap();
    assert_eq!(captured.check_reuse(&graph_spec()), Ok(key));

    let mut keys = vec![("captured".to_owned(), key)];
    for index in 0..captured.resources.len() {
        let role = captured.resources[index].role.as_str().to_owned();
        let mutations: [Mutation; 6] = [
            (GraphResourceField::Kind, |resource| {
                resource.kind = GraphResourceKind::MemoryPool
            }),
            (GraphResourceField::Content, |resource| {
                resource.content = d("other-content")
            }),
            (GraphResourceField::Allocation, |resource| {
                resource.allocation = GpuAllocationGeneration::new(10)
            }),
            (GraphResourceField::DeviceAddress, |resource| {
                resource.device_address += 256
            }),
            (GraphResourceField::Length, |resource| {
                resource.length_bytes += 1
            }),
            (GraphResourceField::Layout, |resource| {
                resource.layout = label("f16[4096]")
            }),
        ];
        for (field, mutate) in mutations {
            let mut current = graph_spec();
            mutate(&mut current.resources[index]);
            assert_eq!(
                captured.check_reuse(&current),
                refused(vec![changed(&role, vec![field])]),
                "{role} {field:?}"
            );
            keys.push((format!("{role} {field:?}"), current.key().unwrap()));
        }
    }

    let mut missing = graph_spec();
    let removed = missing.resources.remove(4);
    assert_eq!(
        captured.check_reuse(&missing),
        refused(vec![GraphDifference::ResourceMissing {
            role: removed.role
        }])
    );
    keys.push(("missing".to_owned(), missing.key().unwrap()));

    let mut added = graph_spec();
    added.resources.push(graph_resource(
        "lora_slot",
        GraphResourceKind::AdapterSlot,
        0x7f50_0000_0000,
    ));
    assert_eq!(
        captured.check_reuse(&added),
        refused(vec![GraphDifference::ResourceAdded {
            role: label("lora_slot")
        }])
    );
    keys.push(("added".to_owned(), added.key().unwrap()));

    let others = [
        (
            "execution",
            GraphCaptureSpec {
                execution: ExecutionSpec {
                    compile: CompileConfiguration::Compiled {
                        configuration: d("cuda-graph-capture"),
                    },
                    ..execution_spec()
                }
                .identity()
                .unwrap(),
                ..graph_spec()
            },
            GraphDifference::Execution,
        ),
        (
            "device",
            GraphCaptureSpec {
                device: gpu("host-a", "GPU-1"),
                ..graph_spec()
            },
            GraphDifference::Device,
        ),
        (
            "sequences",
            GraphCaptureSpec {
                shape: CaptureShape {
                    sequences: 16,
                    tokens: 8,
                },
                ..graph_spec()
            },
            GraphDifference::Shape,
        ),
        (
            "tokens",
            GraphCaptureSpec {
                shape: CaptureShape {
                    sequences: 8,
                    tokens: 16,
                },
                ..graph_spec()
            },
            GraphDifference::Shape,
        ),
    ];
    for (name, current, difference) in others {
        assert_eq!(
            captured.check_reuse(&current),
            refused(vec![difference]),
            "{name}"
        );
        keys.push((name.to_owned(), current.key().unwrap()));
    }

    let named: Vec<(&str, GraphExecutionKey)> = keys
        .iter()
        .map(|(name, key)| (name.as_str(), *key))
        .collect();
    assert_all_distinct(&named);
}

#[test]
fn stable_addresses_alone_never_allow_reuse() {
    let captured = graph_spec();

    // Every address is the same, but the allocation behind one was replaced.
    let mut reallocated = graph_spec();
    for resource in &mut reallocated.resources {
        resource.allocation = GpuAllocationGeneration::new(10);
    }
    let addresses = |spec: &GraphCaptureSpec| {
        spec.resources
            .iter()
            .map(|resource| resource.device_address)
            .collect::<Vec<_>>()
    };
    assert_eq!(addresses(&reallocated), addresses(&captured));
    match captured.check_reuse(&reallocated) {
        Err(GraphReuseRefusal::Mismatch { differences }) => {
            assert_eq!(differences.len(), captured.resources.len());
            assert!(differences.iter().all(|difference| matches!(
                difference,
                GraphDifference::ResourceChanged { fields, .. }
                    if fields == &vec![GraphResourceField::Allocation]
            )));
        }
        other => panic!("expected a mismatch, got {other:?}"),
    }

    // Same addresses and allocations, other weights: the content decides.
    let mut reloaded = graph_spec();
    reloaded.resources[0].content = d("other-weights");
    assert_eq!(
        captured.check_reuse(&reloaded),
        refused(vec![changed("weights", vec![GraphResourceField::Content])])
    );

    // Same memory, another execution identity.
    let rebuilt = GraphCaptureSpec {
        execution: ExecutionSpec {
            kernel_layout: versioned("flash-attn", "3.0.0"),
            ..execution_spec()
        }
        .identity()
        .unwrap(),
        ..graph_spec()
    };
    assert_eq!(
        captured.check_reuse(&rebuilt),
        refused(vec![GraphDifference::Execution])
    );
}

#[test]
fn resource_order_carries_no_meaning() {
    let captured = graph_spec();
    let mut random = SplitMix64::new(0x9a9a);
    for _ in 0..32 {
        let mut current = graph_spec();
        random.shuffle(&mut current.resources);
        assert_eq!(captured.check_reuse(&current), Ok(captured.key().unwrap()));
    }
}

#[test]
fn a_graph_must_declare_each_resource_once() {
    let empty = GraphCaptureSpec {
        resources: Vec::new(),
        ..graph_spec()
    };
    assert_eq!(empty.key(), Err(IdentityError::NoGraphResources));
    assert_eq!(
        graph_spec().check_reuse(&empty),
        Err(GraphReuseRefusal::InvalidCurrent(
            IdentityError::NoGraphResources
        ))
    );
    assert_eq!(
        empty.check_reuse(&graph_spec()),
        Err(GraphReuseRefusal::InvalidCapture(
            IdentityError::NoGraphResources
        ))
    );

    let mut duplicated = graph_spec();
    duplicated.resources.push(graph_resource(
        "weights",
        GraphResourceKind::Weights,
        0x7f60_0000_0000,
    ));
    assert_eq!(
        duplicated.key(),
        Err(IdentityError::DuplicateGraphResource {
            role: "weights".to_owned()
        })
    );
}
