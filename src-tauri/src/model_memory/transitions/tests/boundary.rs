//! S3.6 and line 844: the plan describes memory transitions and preparation only; no
//! output authorizes or executes an external workflow action.

use std::collections::BTreeSet;
use std::time::Duration;

use super::support::*;
use crate::foundation::ids::{digest, AuthorizationEpoch};
use crate::model_memory::boundaries::{
    ActionCredential, ActionRefusal, ActionRequest, ExternalAction, PreparationStep, WorkflowPolicy,
};
use crate::model_memory::residency::Capacity;
use crate::model_memory::transitions::*;

const EXTERNAL_WORDS: [&str; 5] = [
    "outbound_network",
    "write_external_store",
    "invoke_tool",
    "send_message",
    "publish_output",
];

fn tool() -> ExternalAction {
    ExternalAction::InvokeTool {
        tool: digest("yougori/test/tool/v1", &[b"search"]),
    }
}

fn message() -> ExternalAction {
    ExternalAction::SendMessage {
        recipient: digest("yougori/test/recipient/v1", &[b"customer"]),
    }
}

#[test]
fn no_plan_output_can_authorize_an_external_action() {
    // The workflow calls a tool after s1 and sends a message after s2; the plan prepares
    // the models around them and never touches the actions.
    let mut declared = aba();
    declared.stages[0].external_actions = vec![tool()];
    declared.stages[1].external_actions = vec![message()];
    let holds = FakeHolds::honoured();
    let clock = clock();
    let plan = compile(&declared, &holds, &holds, &clock).unwrap();
    assert_eq!(plan.workflow().stages()[0].external_actions(), &[tool()]);

    // Every action is a preparation step of the boundaries' S3.6 list, or a release.
    let mut steps = BTreeSet::new();
    for action in plan.actions() {
        match action.preparation_step() {
            Some(step) => {
                assert!(PreparationStep::ALL.contains(&step));
                steps.insert(step);
            }
            None => assert!(matches!(action, PlanAction::Evict { .. })),
        }
    }
    assert!(steps.contains(&PreparationStep::InboundTransfer));

    // Nothing the plan or the runtime outputs carries an external action.
    let nodes = serde_json::to_string(plan.nodes()).unwrap();
    let mut runtime = PlanRuntime::new(plan.clone());
    let mut directives = Vec::new();
    for (stage, model) in [("s1", "model-a"), ("s2", "model-b"), ("s3", "model-a")] {
        let identity = plan.workflow().resources()
            [plan.workflow().resource_index(&key(model)).unwrap()]
        .identity()
        .clone();
        let outcome = runtime
            .advance(
                &BoundaryObservation {
                    next_stage: stage_id(stage),
                    presented: vec![identity],
                    usable_vram: Capacity::Physical { bytes: 24 * GB },
                    previous_stage_seconds: None,
                    holds: &holds,
                    objects: &holds,
                },
                &clock,
            )
            .unwrap();
        directives.push(serde_json::to_string(&outcome).unwrap());
    }
    for text in std::iter::once(&nodes).chain(directives.iter()) {
        for word in EXTERNAL_WORDS {
            assert!(!text.contains(word), "{word} in {text}");
        }
    }

    // The declared workflow's policy (VM-N1) stays the only issuer of action grants:
    // preparing models changes none of its decisions.
    let policy = WorkflowPolicy::declare(
        execution_id(),
        AuthorizationEpoch::FIRST,
        BTreeSet::from([tool()]),
        Duration::from_secs(60),
    );
    assert_eq!(
        policy.issue(message(), &clock).unwrap_err(),
        ActionRefusal::NotDeclared
    );
    let grant = policy.issue(tool(), &clock).unwrap();
    let request = ActionRequest {
        execution: execution_id(),
        action: tool(),
    };
    assert!(policy
        .authorize(ActionCredential::Workflow(&grant), &request, &clock)
        .is_ok());
}

#[test]
fn branch_preparation_never_runs_the_branch() {
    // Preparing a likely branch loads its weights during the current stage; it neither
    // takes the branch nor performs the branch's declared action.
    let mut declared = declaration(
        vec![
            base("model-a", 6 * GB),
            base("model-b", 6 * GB),
            base("model-c", 6 * GB),
        ],
        vec![
            stage("s1", &["model-a"]),
            stage("s2", &["model-b"]),
            stage("s3", &["model-c"]),
        ],
        vec![
            edge("s1", "s2", evidence(80, 100)),
            edge("s1", "s3", evidence(20, 100)),
        ],
    );
    declared.stages[1].external_actions = vec![tool()];
    let plan = compile(
        &declared,
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    )
    .unwrap();
    let root = &plan.nodes()[0];
    assert!(!root.prefetch.is_empty());
    for action in &root.actions {
        assert!(matches!(
            action,
            PlanAction::Materialize { .. }
                | PlanAction::Prefetch { .. }
                | PlanAction::Retain { .. }
        ));
    }
}
