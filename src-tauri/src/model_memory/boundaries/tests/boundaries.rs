//! What each boundary cannot reach (GPU §3.1), the versioned native ABI (line 489) and
//! S3.6: preparing a model never authorizes an external action.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::support::*;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, ExecutionCategory, ExecutionId,
    GpuAllocationGeneration, ManualClock, MonotonicTime, TrustScope,
};
use crate::model_memory::boundaries::fakes::{ExecutorMode, FakeCatalog, RunnerCall};
use crate::model_memory::boundaries::*;
use crate::model_memory::executor::SourceKind;

fn tool(name: &str) -> ExternalAction {
    ExternalAction::InvokeTool {
        tool: digest("yougori/test/tool/v1", &[name.as_bytes()]),
    }
}

fn every_action() -> [ExternalAction; 5] {
    let target = |name: &str| digest("yougori/test/target/v1", &[name.as_bytes()]);
    [
        ExternalAction::OutboundNetwork {
            destination: target("network"),
        },
        ExternalAction::WriteExternalStore {
            store: target("store"),
        },
        tool("search"),
        ExternalAction::SendMessage {
            recipient: target("person"),
        },
        ExternalAction::PublishOutput {
            recipient: target("channel"),
        },
    ]
}

#[test]
fn an_abi_mismatch_is_refused() {
    let mut world = World::new();
    let abi = NativeAbi::current();
    assert_eq!(abi.version(), NATIVE_ABI_VERSION);
    assert_eq!(abi.provided().len(), NativeOperation::ALL.len());

    // Any other version is refused, newer or older: the ABI is exact.
    for declared in [
        NativeAbiVersion { major: 1, minor: 1 },
        NativeAbiVersion { major: 2, minor: 0 },
        NativeAbiVersion { major: 0, minor: 9 },
    ] {
        world.runner.set_abi(AbiDeclaration {
            version: declared,
            operations: BTreeSet::new(),
        });
        assert_eq!(
            abi.admit(&mut world.runner).err(),
            Some(AbiRefusal::VersionMismatch {
                provided: NATIVE_ABI_VERSION,
                declared,
            })
        );
    }
    let refusal = AbiRefusal::VersionMismatch {
        provided: NATIVE_ABI_VERSION,
        declared: NativeAbiVersion { major: 1, minor: 1 },
    };
    assert_eq!(
        refusal.to_string(),
        "the runner adapter was built for native ABI 1.1; this host provides 1.0"
    );

    // An operation this host does not provide is refused at the right version too.
    let partial = NativeAbi::new(
        NATIVE_ABI_VERSION,
        BTreeSet::from([NativeOperation::CopyToDeviceAsync]),
    );
    world.runner.set_abi(AbiDeclaration {
        version: NATIVE_ABI_VERSION,
        operations: BTreeSet::from([
            NativeOperation::CopyToDeviceAsync,
            NativeOperation::RecordCompletionEvent,
        ]),
    });
    assert_eq!(
        partial.admit(&mut world.runner).err(),
        Some(AbiRefusal::OperationNotProvided {
            version: NATIVE_ABI_VERSION,
            operation: NativeOperation::RecordCompletionEvent,
        })
    );
    // An adapter that calls only upstream facilities still declares its version.
    world.runner.set_abi(AbiDeclaration {
        version: NATIVE_ABI_VERSION,
        operations: BTreeSet::new(),
    });
    assert_eq!(
        partial.admit(&mut world.runner).unwrap().version(),
        NATIVE_ABI_VERSION
    );

    // Only checked runners reach the flow: with the refused one left out, nothing serves.
    let request = world.request("refused", world.scenario.model_a);
    let mut boundaries = Boundaries {
        catalog: &world.catalog,
        governor: &mut world.governor,
        executor: &mut world.executor,
        runners: Vec::new(),
        api: &mut world.api,
    };
    assert_eq!(
        serve(&*world.clock, &mut boundaries, &request).unwrap_err(),
        FlowError::NoCompatibleRunner {
            reasons: Vec::new()
        }
    );
    assert!(world.children().is_empty());
}

#[test]
fn raw_handles_and_payloads_never_print() {
    let handle = NativeHandle::new(
        NativeHandleKind::DevicePointer,
        0xdead_beef,
        GpuAllocationGeneration::FIRST,
    );
    let text = format!("{handle:?}");
    assert!(text.contains("<redacted>"));
    assert!(!text.contains("deadbeef") && !text.contains(&0xdead_beef_u64.to_string()));
    assert_eq!(handle.raw(), 0xdead_beef);
    assert_eq!(handle.kind(), NativeHandleKind::DevicePointer);
    assert_eq!(handle.allocation(), GpuAllocationGeneration::FIRST);

    let payload = RequestPayload::new(b"a private prompt".to_vec());
    assert_eq!(
        format!("{payload:?}"),
        "RequestPayload(<16 bytes redacted>)"
    );
}

#[test]
fn the_ui_adapter_never_sees_raw_handles() {
    let mut world = World::new();
    let (a, b) = (world.scenario.model_a, world.scenario.model_b);
    for (name, model) in [("first", a), ("second", a), ("variant", b)] {
        let request = world.request(name, model);
        world.serve(&request).unwrap();
    }
    let mut unknown = world.request("unknown", a);
    unknown.intent.model = execution_of("not-served-here");
    world.serve(&unknown).unwrap_err();
    let checked = NativeAbi::current().admit(&mut world.runner).unwrap();
    report_diagnostics(&[checked], &mut world.api);

    // The runner holds raw handles as a device-owning runtime does.
    let raws = world.runner.handle_raws();
    assert!(raws.len() >= 10);
    let transcript = world.api.transcript();
    assert!(transcript.len() > 1_000);
    for raw in raws {
        for text in [
            raw.to_string(),
            format!("{raw:x}"),
            format!("{raw:X}"),
            format!("{raw:#x}"),
        ] {
            assert!(
                !transcript.contains(&text),
                "{text} reached the API adapter"
            );
        }
    }
    // Prompts never reach it either (§3.10).
    assert!(!transcript.contains("the prompt of"));
    // Diagnostics are typed and name what is published.
    let diagnostics = &world.api.diagnostics[0][0];
    assert_eq!(diagnostics.owner, runner_owner());
    assert_eq!(diagnostics.category, ExecutionCategory::VmSandbox);
    assert_eq!(
        diagnostics
            .published
            .iter()
            .map(|published| published.model)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([a, b])
    );
}

#[test]
fn preparation_grants_no_external_action() {
    let mut world = World::new();
    let request = world.request("prepared", world.scenario.model_a);
    world.serve(&request).unwrap();
    // Even a workflow that declares every action authorizes none for a preparation token.
    let policy = WorkflowPolicy::declare(
        owner(),
        world.epoch(),
        every_action().into_iter().collect(),
        HOUR,
    );
    let tokens = world.runner.tokens().to_vec();
    assert_eq!(tokens.len(), 8);
    for token in &tokens {
        assert_eq!(token.steps(), &PreparationStep::ALL);
        assert_eq!(token.model(), world.scenario.model_a);
        for action in every_action() {
            let asked = ActionRequest {
                execution: owner(),
                action,
            };
            assert_eq!(
                policy.authorize(ActionCredential::Preparation(token), &asked, &world.clock),
                Err(ActionRefusal::PreparationIsNotActionAuthority)
            );
        }
    }
    // The refusal is the credential's: the same workflow's own grant authorizes.
    let grant = policy.issue(tool("search"), &world.clock).unwrap();
    let asked = ActionRequest {
        execution: owner(),
        action: tool("search"),
    };
    assert!(policy
        .authorize(ActionCredential::Workflow(&grant), &asked, &world.clock)
        .is_ok());
}

/// The review's proof minted a grant for any action and any expiry, then passed its own
/// time. A grant has no public constructor now: only the declared workflow's policy issues
/// one, for an action it declares, expiring on the shared clock, and authorizing reads the
/// same clock.
#[test]
fn only_the_declared_workflow_issues_grants_and_the_clock_keeps_time() {
    use ActionCredential::Workflow;
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let epoch = AuthorizationEpoch::FIRST;
    let declared = tool("search");
    let policy = WorkflowPolicy::declare(owner(), epoch, BTreeSet::from([declared]), HOUR);

    // The proof's action, outbound network to anywhere, is not declared: no grant for it.
    let anywhere = ExternalAction::OutboundNetwork {
        destination: digest("r1d/dest/v1", &[b"anywhere"]),
    };
    assert_eq!(
        policy.issue(anywhere, &clock),
        Err(ActionRefusal::NotDeclared)
    );

    // A declared action's grant expires one grant lifetime after the clock's now.
    let grant = policy.issue(declared, &clock).unwrap();
    assert_eq!(grant.expires_at(), MonotonicTime::ZERO.saturating_add(HOUR));
    assert_eq!(
        (grant.action(), grant.execution(), grant.epoch()),
        (declared, &owner(), epoch)
    );
    let request = ActionRequest {
        execution: owner(),
        action: declared,
    };
    let authority = policy
        .authorize(Workflow(&grant), &request, &clock)
        .unwrap();
    assert_eq!(
        (authority.action(), authority.execution(), authority.epoch()),
        (declared, &owner(), epoch)
    );

    // The grant serves its one action and its execution only.
    let other = ExecutionId::new("exe-other").unwrap();
    for (asked, refusal) in [
        (
            ActionRequest {
                execution: owner(),
                action: anywhere,
            },
            ActionRefusal::ActionNotGranted,
        ),
        (
            ActionRequest {
                execution: other.clone(),
                action: declared,
            },
            ActionRefusal::OtherExecution,
        ),
    ] {
        assert_eq!(
            policy.authorize(Workflow(&grant), &asked, &clock),
            Err(refusal)
        );
    }
    // Another execution's policy, a policy of the next epoch (after a revocation) and a
    // workflow that stopped declaring the action honour none of this policy's grants.
    let declared_only = BTreeSet::from([declared]);
    for (honouring, refusal) in [
        (
            WorkflowPolicy::declare(other, epoch, declared_only.clone(), HOUR),
            ActionRefusal::OtherExecution,
        ),
        (
            WorkflowPolicy::declare(owner(), epoch.next().unwrap(), declared_only, HOUR),
            ActionRefusal::OtherEpoch,
        ),
        (
            WorkflowPolicy::declare(owner(), epoch, BTreeSet::new(), HOUR),
            ActionRefusal::NotDeclared,
        ),
    ] {
        assert_eq!(
            honouring.authorize(Workflow(&grant), &request, &clock),
            Err(refusal)
        );
    }

    // Time is the clock's: the grant holds until one nanosecond before its expiry and not
    // at it, and no caller supplies another time.
    clock.advance(HOUR - Duration::from_nanos(1));
    assert!(policy.authorize(Workflow(&grant), &request, &clock).is_ok());
    clock.advance(Duration::from_nanos(1));
    assert_eq!(
        policy.authorize(Workflow(&grant), &request, &clock),
        Err(ActionRefusal::Expired)
    );
    // An expiry past the clock's range is refused, never wrapped.
    let endless = WorkflowPolicy::declare(
        owner(),
        epoch,
        BTreeSet::from([declared]),
        Duration::from_nanos(u64::MAX),
    );
    assert_eq!(
        endless.issue(declared, &clock),
        Err(ActionRefusal::ExpiryOverflow)
    );
}

fn submission(extents: Vec<ImportedExtent>) -> ImportSubmission {
    ImportSubmission {
        scope: scope(),
        provenance: provenance("submitted"),
        extents,
    }
}

fn imported(index: u32, bytes: Vec<u8>) -> ImportedExtent {
    ImportedExtent {
        extent: ExtentId::new(index),
        claimed_digest: ContentKey::of(&bytes),
        content: bytes,
    }
}

#[test]
fn imports_are_verified_before_anything_is_published() {
    let mut catalog = FakeCatalog::new();
    let bytes = content("x", 0, 100);
    assert_eq!(
        catalog.import(submission(Vec::new())),
        Err(ImportRefusal::NoExtents)
    );
    assert_eq!(
        catalog.import(submission(vec![
            imported(0, bytes.clone()),
            imported(0, bytes.clone())
        ])),
        Err(ImportRefusal::DuplicateExtent {
            extent: ExtentId::new(0)
        })
    );
    assert_eq!(
        catalog.import(submission(vec![imported(0, Vec::new())])),
        Err(ImportRefusal::EmptyExtent {
            extent: ExtentId::new(0)
        })
    );
    let mut wrong = imported(1, bytes.clone());
    wrong.claimed_digest = ContentKey::of(b"other bytes");
    assert_eq!(
        catalog.import(submission(vec![imported(0, bytes.clone()), wrong])),
        Err(ImportRefusal::DigestMismatch {
            extent: ExtentId::new(1),
            claimed: ContentKey::of(b"other bytes"),
            actual: ContentKey::of(&bytes),
        })
    );
    // A refused import publishes nothing, not even its good extents.
    assert_eq!(catalog.contents().count(), 0);

    let artifact = catalog
        .import(submission(vec![imported(0, bytes.clone())]))
        .unwrap();
    let own = SecurityPartition::new(scope());
    let representation = catalog.representation(&artifact, &own).unwrap();
    assert_eq!(representation.artifact(), artifact);
    assert_eq!(representation.scope(), scope());
    assert_eq!(representation.provenance(), &provenance("submitted"));
    assert_eq!(
        representation.extents(),
        &[ExtentDescriptor {
            extent: ExtentId::new(0),
            digest: ContentKey::of(&bytes),
            length_bytes: 100,
            stored: None,
        }]
    );
    // The identity binds every extent: one changed byte is another artifact.
    let mut changed = bytes.clone();
    changed[99] ^= 1;
    let other = verify_submission(&submission(vec![imported(0, changed)])).unwrap();
    assert_ne!(other.artifact(), artifact);

    // Reads stay inside the partition unless a read grant names the scope (S3.3).
    let foreign_scope = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-b/sandbox");
    let foreign = SecurityPartition::new(foreign_scope);
    assert_eq!(
        catalog.representation(&artifact, &foreign),
        Err(CatalogRefusal::OutsidePartition { artifact })
    );
    assert!(catalog
        .representation(&artifact, &foreign.with_read_grant(scope()))
        .is_ok());
    assert_eq!(
        catalog.representation(&other.artifact(), &own),
        Err(CatalogRefusal::UnknownArtifact {
            artifact: other.artifact()
        })
    );
}

#[test]
fn a_transfer_order_pins_one_model_and_its_budget() {
    let world = World::new();
    let placement = world.placement(world.scenario.model_a);
    let token = PreparationToken::issue(
        owner(),
        op("order"),
        tenant(),
        AuthorizationEpoch::FIRST,
        placement,
    );
    let (base, adapter) = (world.scenario.base, world.scenario.adapter_a);
    let budget = TransferBudget::inbound(
        BTreeMap::from([(extent(base, 0), 2_000), (extent(base, 1), 2_000)]),
        gpu(0),
    )
    .unwrap();
    assert_eq!(budget.direction(), TransferDirection::Inbound);
    assert_eq!(budget.max_bytes(), 4_000);
    let ordered = |extent, length_bytes| OrderedExtent {
        extent,
        digest: ContentKey::of(b"expected"),
        length_bytes,
        stored: None,
    };

    assert_eq!(
        TransferOrder::new(&token, &budget, Vec::new()),
        Err(OrderRefusal::NoExtents)
    );
    assert_eq!(
        TransferOrder::new(&token, &budget, vec![ordered(extent(adapter, 0), 1_000)]),
        Err(OrderRefusal::OutsideBudget {
            extent: extent(adapter, 0)
        })
    );
    assert_eq!(
        TransferOrder::new(
            &token,
            &budget,
            vec![ordered(extent(base, 0), 1), ordered(extent(base, 0), 1)]
        ),
        Err(OrderRefusal::DuplicateExtent {
            extent: extent(base, 0)
        })
    );
    assert_eq!(
        TransferOrder::new(
            &token,
            &budget,
            vec![
                ordered(extent(base, 0), 3_000),
                ordered(extent(base, 1), 2_000)
            ]
        ),
        Err(OrderRefusal::ExceedsBudget {
            total_bytes: 5_000,
            budget_bytes: 4_000
        })
    );
    assert_eq!(
        TransferBudget::inbound(
            BTreeMap::from([(extent(base, 0), u64::MAX), (extent(base, 1), 1)]),
            gpu(0)
        ),
        None
    );

    let order = TransferOrder::new(
        &token,
        &budget,
        vec![
            ordered(extent(base, 0), 2_000),
            ordered(extent(base, 1), 2_000),
        ],
    )
    .unwrap();
    assert_eq!(order.model(), world.scenario.model_a);
    assert_eq!(order.execution(), &owner());
    assert_eq!(order.recipient(), gpu(0));
    assert_eq!((order.total_bytes(), order.budget_bytes()), (4_000, 4_000));
    assert!(order.expected(&extent(adapter, 0)).is_none());
}

/// Serves model A with the executor set up by `prepare` and returns the refusal, after
/// checking that nothing was published or left reserved.
fn refused_transfer(prepare: impl FnOnce(&mut World)) -> FlowError {
    let mut world = World::new();
    prepare(&mut world);
    let a = world.scenario.model_a;
    let request = world.request("switched", a);
    let error = world.serve(&request).unwrap_err();
    assert_eq!(world.governor.current_residency(&world.placement(a)), None);
    assert!(world.runner.held_generations(&a).is_empty());
    assert!(!world
        .runner
        .calls()
        .iter()
        .any(|call| matches!(call, RunnerCall::Activate { .. })));
    assert!(!world.runner.is_resident(&state("base-0")));
    assert_eq!(world.executor.cancelled().len(), 1);
    assert!(world.children().is_empty(), "everything was released");
    assert_eq!(world.api.refusals, vec![(op("switched"), error.clone())]);
    error
}

#[test]
fn the_executor_cannot_switch_the_model() {
    // Delivering another artifact's extent for the ordered one.
    let error = refused_transfer(|world| {
        let (adapter_a, adapter_b) = (world.scenario.adapter_a, world.scenario.adapter_b);
        world.executor.set_mode(ExecutorMode::Substitute {
            requested: extent(adapter_a, 0),
            delivered: extent(adapter_b, 0),
        });
    });
    assert!(matches!(error, FlowError::ExecutorSwitchedModel { .. }));

    // Labelling other bytes as the ordered extent.
    let error = refused_transfer(|world| {
        let (base, adapter_a) = (world.scenario.base, world.scenario.adapter_a);
        world.executor.set_mode(ExecutorMode::Relabel {
            requested: extent(adapter_a, 0),
            content_of: extent(base, 1),
        });
    });
    let FlowError::DigestMismatch {
        extent: refused,
        expected,
        delivered,
    } = error
    else {
        panic!("expected a digest mismatch, got {error:?}");
    };
    assert_eq!(expected, ContentKey::of(&content("adapter-a", 0, 1_000)));
    assert_eq!(delivered, ContentKey::of(&content("base", 1, 2_000)));
    assert_eq!(refused.extent, ExtentId::new(0));

    // Reading past the budget: 2,001 + 2,001 + 1,001 bytes of a 5,000-byte order.
    let error = refused_transfer(|world| {
        world
            .executor
            .set_mode(ExecutorMode::OverRead { extra_bytes: 1 })
    });
    assert_eq!(
        error,
        FlowError::TransferBudgetExceeded {
            budget_bytes: 5_000,
            read_bytes: 5_003
        }
    );

    // A corrupt source is a failure, never a warning followed by use (§3.5).
    let error = refused_transfer(|world| {
        let base = world.scenario.base;
        world.executor.corrupt(&extent(base, 1));
    });
    assert!(matches!(
        error,
        FlowError::Transfer {
            failure: TransferFailure::HashMismatch { .. }
        }
    ));

    // An import-only bind is never a read source (Appendix A.3).
    let error = refused_transfer(|world| {
        let base = world.scenario.base;
        world.executor.add_source(
            extent(base, 0),
            content("base", 0, 2_000),
            SourceKind::ImportOnlyBind,
        );
    });
    assert_eq!(
        error,
        FlowError::NotAReadSource {
            extent: extent(world_base(), 0)
        }
    );
}

/// The base artifact every world imports first.
fn world_base() -> crate::model_memory::identity::ArtifactIdentity {
    let mut catalog = FakeCatalog::new();
    import(&mut catalog, "base", &[2_000, 2_000])
}
