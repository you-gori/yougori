//! The three-way update merge, exercised through the public API with a realistic update that raises
//! several conflicts at once. The per-conflict cases live in the unit tests; this proves they compose
//! in one update, keep every local choice, and come out in a stable, deterministic order.

use std::collections::{BTreeMap, BTreeSet};

use yougori_setup::format::{CapabilityUse, Input, Selection, Template};
use yougori_setup::merge::{merge, new_grants, Base, ConflictAction, ConflictCode, Customization};

fn input(id: &str, kind: &str, required: bool) -> Input {
    Input {
        id: Some(id.to_owned()),
        kind: if kind.is_empty() { None } else { Some(kind.to_owned()) },
        required: Some(required),
        ..Input::default()
    }
}

fn cap(id: &str, selection: Selection) -> CapabilityUse {
    CapabilityUse { id: id.to_owned(), selection, locked: false, when: None }
}

#[test]
fn a_realistic_update_composes_every_conflict_and_keeps_local_choices() {
    // Installed version: a name and a region question, a web service the person could turn off, and a
    // volume. The person renamed it, turned the web service off, and the volume holds data.
    let base_template = Template {
        inputs: vec![input("name", "text", true), input("region", "text", false)],
        capabilities: vec![cap("web.service", Selection::Optional), cap("data.volumes", Selection::Optional)],
        ..Template::default()
    };
    let base = Base {
        template: base_template,
        answers: [("name".to_string(), "starter".to_string()), ("region".to_string(), "eu".to_string())].into(),
    };
    let local = Customization {
        answers: [("name".to_string(), "myapp".to_string()), ("region".to_string(), "eu".to_string())].into(),
        capabilities: [("web.service".to_string(), false)].into(),
        added: ["run.health_logs".to_string()].into(),
    };

    // New version: drops the region question, makes the web service required, adds a required owner
    // question, and no longer declares the volume (whose data must be kept).
    let upstream = Template {
        inputs: vec![input("name", "text", true), input("owner", "text", true)],
        capabilities: vec![cap("web.service", Selection::Required)],
        ..Template::default()
    };
    let retained: BTreeSet<String> = ["data.volumes".to_string()].into();

    let merged = merge(&base, &local, &upstream, &retained, &BTreeMap::new(), &BTreeMap::new());

    // Local choices are kept: the renamed instance, and the added capability.
    assert_eq!(merged.answers.get("name").map(String::as_str), Some("myapp"));
    assert!(merged.added.contains("run.health_logs"));
    assert_eq!(merged.capabilities.get("run.health_logs"), Some(&true));
    // The web service was off locally but is required now: on, with a conflict.
    assert_eq!(merged.capabilities.get("web.service"), Some(&true));
    // The removed region answer is dropped, not applied.
    assert!(!merged.answers.contains_key("region"));

    // Every expected conflict is present.
    let codes: Vec<ConflictCode> = merged.conflicts.iter().map(|c| c.code).collect();
    assert!(codes.contains(&ConflictCode::ResourceRemovedWithData));
    assert!(codes.contains(&ConflictCode::CapabilityNowRequired));
    assert!(codes.contains(&ConflictCode::QuestionRemoved));
    assert!(codes.contains(&ConflictCode::NewRequiredQuestion));

    // Data safety comes first and is a retain, never a delete.
    assert_eq!(merged.conflicts[0].code, ConflictCode::ResourceRemovedWithData);
    assert_eq!(merged.conflicts[0].action, ConflictAction::RetainData);
    assert!(merged.conflicts.iter().all(|c| c.action != ConflictAction::KeepLocal || !c.message.is_empty()));

    // Deterministic: the same inputs give the same conflicts in the same order.
    let again = merge(&base, &local, &upstream, &retained, &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(merged, again);
}

#[test]
fn a_same_version_update_is_a_no_op() {
    let template = Template {
        inputs: vec![input("name", "text", true)],
        capabilities: vec![cap("web.service", Selection::Default)],
        ..Template::default()
    };
    let base = Base { template: template.clone(), answers: [("name".to_string(), "app".to_string())].into() };
    let local = Customization {
        answers: [("name".to_string(), "app".to_string())].into(),
        capabilities: [("web.service".to_string(), true)].into(),
        added: BTreeSet::new(),
    };
    let merged = merge(&base, &local, &template, &BTreeSet::new(), &BTreeMap::new(), &BTreeMap::new());
    assert!(merged.is_clean());
}

#[test]
fn only_new_grants_are_raised() {
    let installed: BTreeSet<String> = ["run_containers".to_string(), "reserve_storage".to_string()].into();
    let updated: BTreeSet<String> = ["run_containers".to_string(), "reserve_storage".to_string(), "open_public_url".to_string()].into();
    let conflicts = new_grants(&installed, &updated);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].subject, "open_public_url");
}
