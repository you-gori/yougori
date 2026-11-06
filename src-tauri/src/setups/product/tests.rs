//! The setup's product document on a manual evidence clock: permissions, the migration
//! inventory, refusals for records the rule cannot read, the documents a plan and a setup's
//! read-back permissions carry, and the strict reader taking each document back. Nothing here
//! touches a setup on disk.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use yougori_setup::dto::SourceRef;
use yougori_setup::resource::Kind;

use super::{attach, configuration, declarations, of_plan, view};
use crate::foundation::evidence::SourceClass;
use crate::foundation::product::test_support::Probes;
use crate::foundation::product::{
    read_view, MigrationOutcome, MigrationStatus, ProductView, Read, ReadPurpose,
    PRODUCT_CONTRACT_VERSION,
};
use crate::setups::journal::{Action, OperationKind};
use crate::setups::model::{InstanceChange, Source};
use crate::setups::service::{PlannedStep, ReviewedPlan};

fn capabilities(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

fn document(environments: &[(&str, Value)]) -> crate::foundation::product::ProductView {
    let probes = Probes::new(SourceClass::HostProbe);
    let environments: Vec<(&str, &Value)> =
        environments.iter().map(|(id, spec)| (*id, spec)).collect();
    view(
        "legacy-lab",
        3,
        Some("lock-1"),
        &[],
        &environments,
        probes.now(),
    )
    .unwrap()
}

#[test]
fn each_permission_a_chosen_capability_asks_for_is_requested_once() {
    let probes = Probes::new(SourceClass::HostProbe);
    let chosen = capabilities(&[
        "models.cloud",
        "tools.builtin",
        "tools.provider_access",
        "models.local",
        "no.such_capability",
    ]);
    // A draft: nothing was agreed yet, so each line is only requested.
    let shown = view("shop", 1, None, &chosen, &[], probes.now()).unwrap();
    let json = serde_json::to_value(&shown).unwrap();
    let kinds: Vec<&str> = json["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["sign_in_to_provider", "run_containers", "serve_models"]
    );
    for line in json["permissions"].as_array().unwrap() {
        assert_eq!(
            line["status"],
            json!({"status": "requested"}),
            "asking grants nothing: {line}"
        );
    }
    assert!(json.get("migration").is_none() && json.get("refusals").is_none());
    assert_eq!(json["subject"], json!({"kind": "setup", "id": "shop"}));
}

#[test]
fn every_owned_environment_is_inventoried_by_the_one_rule_and_nothing_changes() {
    let shown = document(&[
        ("web", json!({"type": "vm", "image": "web:1"})),
        ("api", json!({"image": "api:2", "ports": ["8080:80"]})),
        ("trainer", json!({"type": "container", "gpu": true})),
        ("pod", json!({"type": "cloud"})),
    ]);
    let migration = shown.migration.as_ref().unwrap();
    assert_eq!(migration.status(), MigrationStatus::Pending);
    assert!(migration.backup().is_none());
    let outcomes: Vec<(&str, &MigrationOutcome)> = migration
        .items()
        .iter()
        .map(|item| (item.subject().as_str(), item.outcome()))
        .collect();
    assert!(matches!(
        outcomes[0],
        ("web", MigrationOutcome::Unchanged { .. })
    ));
    assert!(
        matches!(outcomes[1], ("api", MigrationOutcome::Strengthened { .. })),
        "a record without a type is a container"
    );
    assert!(matches!(
        outcomes[2],
        ("trainer", MigrationOutcome::NeedsDecision { .. })
    ));
    assert!(matches!(
        outcomes[3],
        ("pod", MigrationOutcome::NeedsDecision { .. })
    ));
    let reasons: Vec<&str> = shown
        .refusals
        .iter()
        .map(|refusal| refusal.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        2,
        "one open decision each for the GPU container and the provider container: {reasons:?}"
    );
    assert!(reasons[0].starts_with("\"trainer\": ") && reasons[1].starts_with("\"pod\": "));
    for refusal in &shown.refusals {
        assert_eq!(refusal.code.as_str(), "migration_decision_required");
    }
}

#[test]
fn a_type_the_rule_does_not_know_is_refused_by_name_and_the_rest_is_still_inventoried() {
    let shown = document(&[
        ("strange", json!({"type": "quantum"})),
        ("broken", json!({"type": "vm", "gpu": "yes"})),
        ("web", json!({"type": "microvm"})),
    ]);
    let refusals: Vec<(&str, &str)> = shown
        .refusals
        .iter()
        .map(|refusal| (refusal.code.as_str(), refusal.reason.as_str()))
        .collect();
    assert_eq!(refusals.len(), 2, "{refusals:?}");
    assert_eq!(refusals[0].0, "unknown_legacy_choice");
    assert!(
        refusals[0].1.starts_with("\"strange\": ") && refusals[0].1.contains("quantum"),
        "{refusals:?}"
    );
    assert_eq!(refusals[1].0, "unknown_legacy_choice");
    assert!(refusals[1].1.starts_with("\"broken\": "), "{refusals:?}");
    let items: Vec<&str> = shown
        .migration
        .as_ref()
        .unwrap()
        .items()
        .iter()
        .map(|item| item.subject().as_str())
        .collect();
    assert_eq!(items, ["web"]);
}

#[test]
fn a_setup_without_environments_has_no_migration_part() {
    let shown = document(&[]);
    assert!(shown.migration.is_none() && shown.refusals.is_empty() && shown.permissions.is_empty());
}

#[test]
fn the_document_reads_back_strictly_as_the_current_contract() {
    let shown = document(&[
        ("api", json!({"type": "container"})),
        ("pod", json!({"type": "cloud"})),
    ]);
    let text = shown.to_json().unwrap();
    match read_view(&text, ReadPurpose::Act).unwrap() {
        Read::Current(read) => assert_eq!(read, shown),
        other => panic!("expected the current version, got {other:?}"),
    }
    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["contract_version"], json!(PRODUCT_CONTRACT_VERSION));
}

#[test]
fn the_configuration_names_the_setup_its_revision_and_its_applied_lock() {
    let base = configuration("shop", 1, Some("lock-1")).unwrap();
    assert_eq!(base, configuration("shop", 1, Some("lock-1")).unwrap());
    assert_ne!(base, configuration("shop", 2, Some("lock-1")).unwrap());
    assert_ne!(base, configuration("shop", 1, Some("lock-2")).unwrap());
    assert_ne!(base, configuration("shop", 1, None).unwrap());
    assert_ne!(base, configuration("other", 1, Some("lock-1")).unwrap());
}

#[test]
fn a_setup_id_the_contract_cannot_name_gives_no_document() {
    let probes = Probes::new(SourceClass::HostProbe);
    let refused = view("has space", 1, None, &[], &[], probes.now()).unwrap_err();
    assert!(
        refused.contains("cannot name a product document"),
        "{refused}"
    );
}

/// A reviewed plan that creates setup `setup-new` with the capabilities `chosen` on, and one
/// GPU container among its steps.
fn creating(chosen: &[&str]) -> ReviewedPlan {
    ReviewedPlan {
        plan_id: "plan-1".into(),
        setup_id: "setup-new".into(),
        intent: OperationKind::Create,
        base_revision: 0,
        digest: "digest-1".into(),
        steps: vec![PlannedStep {
            id: "step-1".into(),
            resource: "trainer".into(),
            kind: Kind::Environment,
            action: Action::Create,
            depends_on: Vec::new(),
            requires: Vec::new(),
            spec: json!({"type": "container", "gpu": true, "image": "trainer:1"}),
            generation: 1,
            owner: None,
        }],
        change: Some(InstanceChange {
            name: "New".into(),
            source: Source {
                reference: SourceRef::Hub {
                    publisher: "example".into(),
                    name: "hello".into(),
                    version: "1.0.0".into(),
                },
                digest: "sha256:0000".into(),
            },
            format_version: 2,
            protocol_version: 1,
            lock_digest: Some("lock-new".into()),
            answers: BTreeMap::new(),
            capabilities: capabilities(chosen),
            secret_bindings: BTreeMap::new(),
            lock: None,
        }),
        notes: Vec::new(),
        offered: Vec::new(),
        expires_at: String::new(),
        source_digest: None,
        package: None,
    }
}

fn kinds_and_statuses(shown: &ProductView) -> Vec<(String, Value)> {
    let json = serde_json::to_value(shown).unwrap();
    json["permissions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|line| {
            (
                line["kind"].as_str().unwrap().to_owned(),
                line["status"].clone(),
            )
        })
        .collect()
}

fn reads_back_as_itself(shown: &ProductView) {
    match read_view(&shown.to_json().unwrap(), ReadPurpose::Act).unwrap() {
        Read::Current(read) => assert_eq!(&read, shown),
        other => panic!("expected the current version, got {other:?}"),
    }
}

/// PROVES a plan's document says what its chosen capabilities ask for, each once and only
/// as requested, about the setup the plan makes, and inventories nothing: a GPU container the
/// plan creates is not an old record waiting for a migration decision.
#[test]
fn a_plan_asks_for_what_its_chosen_capabilities_ask_for_and_inventories_nothing() {
    let probes = Probes::new(SourceClass::HostProbe);
    let plan = creating(&[
        "web.service",
        "run.service",
        "data.volumes",
        "web.quick_link",
        "no.such_capability",
    ]);
    let shown = of_plan(&plan, probes.now()).unwrap();
    let requested = json!({"status": "requested"});
    assert_eq!(
        kinds_and_statuses(&shown),
        [
            ("run_containers".to_owned(), requested.clone()),
            ("reserve_storage".to_owned(), requested.clone()),
            ("open_public_url".to_owned(), requested),
        ]
    );
    assert!(shown.migration.is_none() && shown.refusals.is_empty());
    assert_eq!(shown.subject.id(), "setup-new");
    assert_ne!(
        shown.shown_at.configuration,
        configuration("setup-new", 0, Some("lock-new")).unwrap(),
        "a plan binds its digest as well as the setup revision and candidate lock"
    );
    let mut other = plan.clone();
    other.digest = "another-reviewed-plan".into();
    assert_ne!(
        shown.shown_at.configuration,
        of_plan(&other, probes.now())
            .unwrap()
            .shown_at
            .configuration
    );
    reads_back_as_itself(&shown);
}

#[test]
fn a_plan_that_changes_no_setup_record_has_no_document() {
    let probes = Probes::new(SourceClass::HostProbe);
    let mut plan = creating(&["web.service"]);
    plan.intent = OperationKind::Stop;
    plan.change = None;
    let refused = of_plan(&plan, probes.now()).unwrap_err();
    assert!(refused.contains("changes no setup record"), "{refused}");
}

/// PROVES an applied setup's own document and its read-back permissions list the same lines,
/// each requested by its capabilities, under the same configuration, so the two documents about one
/// setup agree; only the setup's own document inventories its environments.
#[test]
fn an_applied_setup_and_permissions_readback_keep_requests_ungranted() {
    let probes = Probes::new(SourceClass::HostProbe);
    let chosen = capabilities(&["web.service", "run.service", "data.volumes", "web.domain"]);
    let environments = [("web", json!({"type": "container"}))];
    let environments: Vec<(&str, &Value)> =
        environments.iter().map(|(id, spec)| (*id, spec)).collect();
    let own = view(
        "shop",
        4,
        Some("lock-4"),
        &chosen,
        &environments,
        probes.now(),
    )
    .unwrap();
    let contract = declarations("shop", 4, Some("lock-4"), &chosen, probes.now()).unwrap();
    assert_eq!(contract.shown_at, own.shown_at);
    assert_eq!(contract.subject, own.subject);
    assert!(contract.migration.is_none() && contract.refusals.is_empty());
    assert!(
        own.migration.is_some(),
        "the setup's own document keeps its inventory"
    );
    assert_eq!(own.permissions, contract.permissions);
    let lines = kinds_and_statuses(&contract);
    assert_eq!(lines.len(), 3, "{lines:?}");
    for (_, status) in &lines {
        assert_eq!(status, &json!({"status": "requested"}));
    }
    let draft = view(
        "shop",
        4,
        Some("lock-4"),
        &chosen,
        &environments,
        probes.now(),
    )
    .unwrap();
    for (_, status) in kinds_and_statuses(&draft) {
        assert_eq!(
            status,
            json!({"status": "requested"}),
            "a draft's lines are only asked for"
        );
    }
    reads_back_as_itself(&contract);
    reads_back_as_itself(&own);
}

#[test]
fn a_reply_carries_the_document_or_why_there_is_none_beside_its_own_fields() {
    let probes = Probes::new(SourceClass::HostProbe);
    let reply = json!({"setupId": "shop", "known": true, "permissions": ["Run containers on this computer."]});
    let shown = declarations(
        "shop",
        1,
        None,
        &capabilities(&["web.service"]),
        probes.now(),
    )
    .unwrap();
    let with = attach(reply.clone(), Ok(shown.clone()));
    assert_eq!(with["product"], serde_json::to_value(&shown).unwrap());
    assert!(with.get("productUnavailable").is_none());
    assert_eq!(
        with["permissions"], reply["permissions"],
        "every field it had is kept"
    );
    let without = attach(
        reply,
        Err("the engine's evidence clock is not available: starting".into()),
    );
    assert!(without.get("product").is_none());
    assert_eq!(
        without["productUnavailable"],
        "the engine's evidence clock is not available: starting"
    );
}
