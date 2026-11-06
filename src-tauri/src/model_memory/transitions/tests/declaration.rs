//! Lines 846–852: every declared input is validated and nothing is clamped into range.

use super::support::*;
use crate::foundation::ids::ContentKey;
use crate::model_memory::residency::eviction::CopyTier;
use crate::model_memory::residency::Capacity;
use crate::model_memory::transitions::*;

fn refused(declaration: &WorkflowDeclaration) -> DeclarationError {
    match CheckedWorkflow::check(declaration) {
        Err(TransitionError::Declaration(error)) => error,
        other => panic!("expected a declaration error, got {other:?}"),
    }
}

fn simple() -> WorkflowDeclaration {
    declaration(
        vec![base("model-a", 4 * GB), base("model-b", 4 * GB)],
        vec![stage("s1", &["model-a"]), stage("s2", &["model-b"])],
        chain(&["s1", "s2"]),
    )
}

#[test]
fn a_valid_declaration_is_checked_and_unrolled() {
    let checked = CheckedWorkflow::check(&simple()).unwrap();
    assert_eq!(checked.resources().len(), 2);
    assert_eq!(checked.tree().len(), 2);
    assert!(checked.is_linear());
    assert_eq!(checked.tree()[0].children(), &[1]);
    assert_eq!(checked.tree()[1].aggregation(), Aggregation::Leaf);
}

#[test]
fn identifiers_follow_the_shared_grammar() {
    assert!(ResourceKey::new("").is_err());
    assert!(ResourceKey::new("has space").is_err());
    assert!(StageId::new("-leading").is_err());
    assert!(StageId::new("s1").is_ok());
}

#[test]
fn a_workflow_needs_stages_and_unique_resources() {
    let mut empty = simple();
    empty.stages.clear();
    assert_eq!(refused(&empty), DeclarationError::NoStages);

    let mut duplicate = simple();
    duplicate.resources.push(base("model-a", GB));
    assert!(matches!(
        refused(&duplicate),
        DeclarationError::DuplicateResource { .. }
    ));

    let mut many = simple();
    many.limits.max_resources = 1;
    assert_eq!(
        refused(&many),
        DeclarationError::TooManyResources { count: 2, limit: 1 }
    );
}

#[test]
fn one_identity_is_one_shared_resource_never_two_copies() {
    // Line 862: states represent shared physical resources. Declaring the same base under
    // two names would let a plan count it twice.
    let mut twice = simple();
    let mut copy = base("model-a", 4 * GB);
    copy.key = key("model-a-again");
    twice.resources.push(copy);
    assert_eq!(
        refused(&twice),
        DeclarationError::DuplicateIdentity {
            first: "model-a".into(),
            second: "model-a-again".into()
        }
    );
}

#[test]
fn sizes_contents_and_holder_contexts_must_match_the_kind() {
    let mut zero = simple();
    zero.resources[0].device_bytes = 0;
    assert!(matches!(refused(&zero), DeclarationError::ZeroBytes { .. }));

    let mut no_content = simple();
    no_content.resources[0].content = None;
    assert!(matches!(
        refused(&no_content),
        DeclarationError::ContentMismatch { .. }
    ));

    let mut holder = simple();
    holder.resources[0].holder_context_bytes = 1;
    assert!(matches!(
        refused(&holder),
        DeclarationError::HolderContext { .. }
    ));

    let mut session_content = simple();
    let mut kv = session("session-1", "model-a", &[1, 2, 3], GB, Vec::new());
    kv.content = Some(ContentKey::of(b"not a session"));
    session_content.resources.push(kv);
    assert!(matches!(
        refused(&session_content),
        DeclarationError::ContentMismatch { .. }
    ));

    let mut no_holder = simple();
    let mut kv = session("session-1", "model-a", &[1, 2, 3], GB, Vec::new());
    kv.holder_context_bytes = 0;
    no_holder.resources.push(kv);
    assert!(matches!(
        refused(&no_holder),
        DeclarationError::HolderContext { .. }
    ));
}

#[test]
fn prerequisites_must_exist_and_follow_the_kinds() {
    let mut unknown = simple();
    unknown.resources[0].prerequisites = vec![key("missing")];
    assert!(matches!(
        refused(&unknown),
        DeclarationError::UnknownResource { .. }
    ));

    let mut base_with_prerequisite = simple();
    base_with_prerequisite.resources[0].prerequisites = vec![key("model-b")];
    assert!(matches!(
        refused(&base_with_prerequisite),
        DeclarationError::PrerequisiteShape { .. }
    ));

    let mut adapter_on_adapter = simple();
    adapter_on_adapter
        .resources
        .push(adapter("adapter-x", "model-a", GB));
    let mut second = adapter("adapter-y", "model-a", GB);
    second.prerequisites = vec![key("adapter-x")];
    adapter_on_adapter.resources.push(second);
    assert!(matches!(
        refused(&adapter_on_adapter),
        DeclarationError::PrerequisiteShape { .. }
    ));

    let mut cycle = simple();
    let mut x = adapter("adapter-x", "model-a", GB);
    x.prerequisites = vec![key("adapter-y")];
    let mut y = adapter("adapter-y", "model-a", GB);
    y.prerequisites = vec![key("adapter-x")];
    cycle.resources.extend([x, y]);
    assert!(matches!(
        refused(&cycle),
        DeclarationError::PrerequisiteCycle { .. }
    ));

    let mut wrong_base = simple();
    let mut x = adapter("adapter-x", "model-a", GB);
    x.prerequisites = vec![key("model-b")];
    wrong_base.resources.push(x);
    assert!(matches!(
        refused(&wrong_base),
        DeclarationError::BaseMismatch { .. }
    ));
}

#[test]
fn a_session_of_another_tenant_or_execution_is_refused() {
    let mut foreign = simple();
    let mut kv = session("session-1", "model-a", &[1], GB, Vec::new());
    if let StateIdentity::Session { spec } = &mut kv.identity {
        spec.tenant = crate::foundation::ids::TenantId::new("tenant-2").unwrap();
    }
    foreign.resources.push(kv);
    assert!(matches!(
        refused(&foreign),
        DeclarationError::ForeignSession { .. }
    ));
}

#[test]
fn stage_requirements_hold_one_weights_node_and_bounded_kv() {
    let mut empty = simple();
    empty.stages[0].requires.clear();
    assert!(matches!(
        refused(&empty),
        DeclarationError::EmptyRequirement { .. }
    ));

    let mut two_bases = simple();
    two_bases.stages[0].requires = vec![key("model-a"), key("model-b")];
    assert!(matches!(
        refused(&two_bases),
        DeclarationError::RequirementShape { .. }
    ));

    let mut duplicate = simple();
    duplicate.stages.push(stage("s1", &["model-a"]));
    assert!(matches!(
        refused(&duplicate),
        DeclarationError::DuplicateStage { .. }
    ));

    let mut no_context = simple();
    no_context.stages[0].process.context_bytes = 0;
    assert!(matches!(
        refused(&no_context),
        DeclarationError::NoContext { .. }
    ));

    let mut produced_base = simple();
    produced_base.stages[0].produces = Some(key("model-b"));
    assert!(matches!(
        refused(&produced_base),
        DeclarationError::ProducedShape { .. }
    ));

    // A stage producing 3 GB of session KV with a 2 GB pool: unbounded growth (§2.7).
    let mut small_pool = simple();
    small_pool
        .resources
        .push(session("session-1", "model-a", &[1], 3 * GB, Vec::new()));
    small_pool.stages[0].produces = Some(key("session-1"));
    assert!(matches!(
        refused(&small_pool),
        DeclarationError::KvPoolTooSmall { .. }
    ));
}

#[test]
fn edges_form_a_rooted_acyclic_graph() {
    let mut unknown = simple();
    unknown
        .edges
        .push(edge("s2", "nowhere", BranchWeight::Unknown));
    assert!(matches!(
        refused(&unknown),
        DeclarationError::UnknownStage { .. }
    ));

    let mut duplicate = simple();
    duplicate
        .edges
        .push(edge("s1", "s2", BranchWeight::Unknown));
    assert!(matches!(
        refused(&duplicate),
        DeclarationError::DuplicateEdge { .. }
    ));

    let mut back_to_root = simple();
    back_to_root
        .edges
        .push(edge("s2", "s1", BranchWeight::Unknown));
    assert!(matches!(
        refused(&back_to_root),
        DeclarationError::RootHasPredecessor { .. }
    ));

    let mut unreachable = simple();
    unreachable.edges.clear();
    assert!(matches!(
        refused(&unreachable),
        DeclarationError::Unreachable { .. }
    ));

    let mut cycle = simple();
    cycle.stages.push(stage("s3", &["model-a"]));
    cycle.edges.push(edge("s2", "s3", BranchWeight::Unknown));
    cycle.edges.push(edge("s3", "s2", BranchWeight::Unknown));
    assert!(matches!(refused(&cycle), DeclarationError::Cycle { .. }));
}

fn branching(weights: [BranchWeight; 2]) -> WorkflowDeclaration {
    declaration(
        vec![base("model-a", 4 * GB), base("model-b", 4 * GB)],
        vec![
            stage("s1", &["model-a"]),
            stage("s2", &["model-b"]),
            stage("s3", &["model-a"]),
        ],
        vec![edge("s1", "s2", weights[0]), edge("s1", "s3", weights[1])],
    )
}

#[test]
fn probabilities_are_used_only_where_evidence_supports_them() {
    // Line 849: every branch with consistent observed counts, or none.
    let checked =
        CheckedWorkflow::check(&branching([evidence(70, 100), evidence(30, 100)])).unwrap();
    assert_eq!(checked.tree()[0].aggregation(), Aggregation::Expected);
    let unknown =
        CheckedWorkflow::check(&branching([BranchWeight::Unknown, BranchWeight::Unknown])).unwrap();
    assert_eq!(unknown.tree()[0].aggregation(), Aggregation::WorstCase);

    assert!(matches!(
        refused(&branching([evidence(70, 100), BranchWeight::Unknown])),
        DeclarationError::MixedBranchEvidence { .. }
    ));
    assert!(matches!(
        refused(&branching([evidence(70, 100), evidence(20, 100)])),
        DeclarationError::InconsistentBranchEvidence { .. }
    ));
    assert!(matches!(
        refused(&branching([evidence(100, 100), evidence(0, 100)])),
        DeclarationError::InconsistentBranchEvidence { .. }
    ));
    assert!(matches!(
        refused(&branching([evidence(7, 10), evidence(3, 10)])),
        DeclarationError::InsufficientBranchEvidence {
            observed: 10,
            required: 20,
            ..
        }
    ));
}

#[test]
fn sessions_exist_only_after_the_stage_that_produces_them() {
    let mut consumed_first = simple();
    consumed_first
        .resources
        .push(session("session-1", "model-a", &[1], GB, Vec::new()));
    consumed_first.stages[0].requires = vec![key("session-1")];
    assert!(matches!(
        refused(&consumed_first),
        DeclarationError::SessionNotProduced { .. }
    ));

    let mut twice = simple();
    twice
        .resources
        .push(session("session-1", "model-a", &[1], GB, Vec::new()));
    twice.stages[0].produces = Some(key("session-1"));
    twice.stages.push(stage("s3", &["model-a"]));
    twice.stages[2].produces = Some(key("session-1"));
    twice.edges.push(edge("s2", "s3", BranchWeight::Unknown));
    assert!(matches!(
        refused(&twice),
        DeclarationError::SessionProducedTwice { .. }
    ));
}

#[test]
fn the_initial_state_is_closed_immutable_state() {
    let mut session_initial = simple();
    session_initial
        .resources
        .push(session("session-1", "model-a", &[1], GB, Vec::new()));
    session_initial.initial = vec![key("session-1")];
    assert!(matches!(
        refused(&session_initial),
        DeclarationError::InitialSession { .. }
    ));

    let mut open = simple();
    open.resources.push(adapter("adapter-x", "model-a", GB));
    open.initial = vec![key("adapter-x")];
    assert!(matches!(
        refused(&open),
        DeclarationError::InitialNotClosed { .. }
    ));
}

#[test]
fn budgets_curves_weights_and_limits_are_refused_out_of_range() {
    let mut virtual_capacity = simple();
    virtual_capacity.budgets.usable_vram = Capacity::VirtualReservation { bytes: 80 * GB };
    assert_eq!(
        refused(&virtual_capacity),
        DeclarationError::VirtualCapacity
    );

    let mut no_reserve = simple();
    no_reserve.budgets.safety_reserve_bytes = 0;
    assert!(matches!(
        refused(&no_reserve),
        DeclarationError::NotPositive { .. }
    ));

    let mut reclaimable = simple();
    reclaimable.budgets.write_back = Some(CopyTier::ReclaimableHost);
    assert_eq!(
        refused(&reclaimable),
        DeclarationError::WriteBackTierNotGuaranteed {
            tier: CopyTier::ReclaimableHost
        }
    );

    let mut nan = simple();
    nan.curves.host_to_device.bytes_per_second = f64::NAN;
    assert!(matches!(refused(&nan), DeclarationError::NotFinite { .. }));

    let mut spread = simple();
    spread.curves.relative_spread = 1.0;
    assert!(matches!(
        refused(&spread),
        DeclarationError::OutOfRange { .. }
    ));

    let mut weight = simple();
    weight.weights.preparation_seconds_per_byte = -1.0;
    assert!(matches!(
        refused(&weight),
        DeclarationError::OutOfRange { .. }
    ));

    let mut prefill = simple();
    prefill.stages[0].prefill_seconds = 0.0;
    assert!(matches!(
        refused(&prefill),
        DeclarationError::NotPositive { .. }
    ));

    let mut deadline = simple();
    deadline.stages[0].readiness_deadline_seconds = Some(f64::INFINITY);
    assert!(matches!(
        refused(&deadline),
        DeclarationError::NotFinite { .. }
    ));

    let mut tree = simple();
    tree.limits.max_tree_nodes = 1;
    assert_eq!(
        refused(&tree),
        DeclarationError::TooManyTreeNodes { limit: 1 }
    );
}
