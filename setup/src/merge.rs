//! The three-way update merge: installed base, the setup's local customizations, and a new template
//! version, combined into the selections and answers to apply — with every conflict kept visible and
//! no local choice overwritten silently.
//!
//! This is pure. The same three inputs always give the same merged result and the same conflicts, in
//! the same order, so a review built from it is reproducible. It changes nothing; the engine decides
//! what to do with the conflicts (ask the newly required questions, show the new grants, plan a
//! retain or detach for data that would otherwise be lost), never this function.
//!
//! The rule, from plan 5.5 and 7.4: upstream defaults apply only where the person never chose; a
//! local choice is never overwritten; a change upstream that would undo or endanger a local choice,
//! or that needs a new decision or grant, becomes a conflict rather than a silent edit.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::format::{Selection, Template};

/// What the person chose on top of the installed template: which optional/default capabilities they
/// turned on or off, the answers they gave, and any capabilities they added that the template did not
/// declare. Recorded by the engine when the setup was created or last configured.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Customization {
    /// Capability id to the person's on/off choice, for capabilities the template left optional or
    /// default. A capability the person never touched is absent, so an upstream default can apply.
    #[serde(default)]
    pub capabilities: BTreeMap<String, bool>,
    /// The public answers the person gave, by input id. Absent means they kept the default.
    #[serde(default)]
    pub answers: BTreeMap<String, String>,
    /// Capabilities the person added that the template did not declare (through "Add capability").
    /// These are kept across an update; they are the person's, not the template's.
    #[serde(default)]
    pub added: BTreeSet<String>,
}

/// The installed base of an update: the template version in use and the answers it was applied with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Base {
    pub template: Template,
    #[serde(default)]
    pub answers: BTreeMap<String, String>,
}

/// One conflict an update raises: a stable code, a plain sentence, the field it is about, and what
/// the engine must do next. It is never resolved by silently dropping a local choice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// A stable identifier for this kind of conflict.
    pub code: ConflictCode,
    /// A plain sentence a person can read.
    pub message: String,
    /// What the conflict is about: a capability id, an input id, or a resource id.
    pub subject: String,
    /// What the engine should do about it.
    pub action: ConflictAction,
}

/// The kinds of conflict an update can raise. Stable; a reader switches on these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictCode {
    /// A question the person answered was removed upstream.
    QuestionRemoved,
    /// A question the person answered changed type upstream, so the old answer may not fit.
    QuestionRetyped,
    /// A capability the person turned off is now required upstream.
    CapabilityNowRequired,
    /// A value the person set is now locked to a different value upstream.
    LockedValueChanged,
    /// A resource with retained data was removed upstream; its data must not be deleted.
    ResourceRemovedWithData,
    /// A new required question upstream the person has not answered.
    NewRequiredQuestion,
    /// A new grant or download upstream that must be reviewed before it applies.
    NewGrantToReview,
}

/// What the engine should do about a conflict. Never "delete"; a resource with data is retained or
/// detached by an explicit, reviewed step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictAction {
    /// Ask the person this question before applying.
    Ask,
    /// Show this for review and get agreement before applying.
    Review,
    /// Keep the person's local choice; the upstream change does not apply.
    KeepLocal,
    /// Plan to retain the resource's data (do not delete it) and tell the person.
    RetainData,
}

/// The result of a three-way merge: the selections and answers to apply, and every conflict, in a
/// stable order. `conflicts` empty means the update is clean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Merged {
    /// Capability id to on/off, as the update should apply it. Local choices win; upstream defaults
    /// fill only where the person never chose; a capability newly required upstream is on.
    pub capabilities: BTreeMap<String, bool>,
    /// The answers to apply: the person's where they gave one, the upstream default otherwise. A
    /// removed or retyped question's old answer is dropped (and raised as a conflict).
    pub answers: BTreeMap<String, String>,
    /// Capabilities the person added that the template still does not declare; kept as theirs.
    pub added: BTreeSet<String>,
    /// Every conflict, most structural first, each deterministic.
    pub conflicts: Vec<Conflict>,
}

impl Merged {
    /// Whether the update applies with nothing to ask or review.
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// A template's inputs indexed by id, with the type each declares (empty string when untyped).
fn inputs_by_id(template: &Template) -> BTreeMap<String, String> {
    template
        .inputs
        .iter()
        .filter_map(|input| input.id.clone().map(|id| (id, input.kind.clone().unwrap_or_default())))
        .collect()
}

/// Whether an input is required for everyone: required (the format's default when `required:` is
/// left out) and no `when:` guard (a guarded question is only asked when its condition holds, so it
/// is not unconditionally required), with no default to fall back on.
fn is_required(template: &Template, id: &str) -> bool {
    template
        .inputs
        .iter()
        .find(|input| input.id.as_deref() == Some(id))
        .is_some_and(|input| input.required.unwrap_or(true) && input.when.is_none() && input.default.is_none())
}

/// A template's capability selections (id → selection, locked).
fn capabilities_by_id(template: &Template) -> BTreeMap<String, (Selection, bool)> {
    template
        .capabilities
        .iter()
        .map(|use_| (use_.id.clone(), (use_.selection, use_.locked)))
        .collect()
}

/// Perform the three-way merge. `retained_data` names the resource ids that currently hold data the
/// person would lose if the resource were removed; a resource in this set removed upstream becomes a
/// retain conflict rather than a deletion. `locked_values` maps an input id a template locks to the
/// value it locks it to, for the base and upstream versions, so a changed lock is detected.
pub fn merge(
    base: &Base,
    local: &Customization,
    upstream: &Template,
    retained_data: &BTreeSet<String>,
    base_locked: &BTreeMap<String, String>,
    upstream_locked: &BTreeMap<String, String>,
) -> Merged {
    let base_inputs = inputs_by_id(&base.template);
    let upstream_inputs = inputs_by_id(upstream);
    let upstream_caps = capabilities_by_id(upstream);

    let mut conflicts: Vec<Conflict> = Vec::new();

    // ---- Answers ----
    //
    // A person's answer wins; where they never answered, the upstream default (an answer carried from
    // the base) fills in. An answer to a question that upstream removed or retyped is dropped and
    // raised, so a stale value is never applied.
    let mut answers: BTreeMap<String, String> = BTreeMap::new();
    // Start from the base answers (defaults carried from the installed version), then layer local.
    for (id, value) in &base.answers {
        if upstream_inputs.contains_key(id) {
            answers.insert(id.clone(), value.clone());
        }
    }
    for (id, value) in &local.answers {
        match upstream_inputs.get(id) {
            None => {
                // The person answered a question upstream removed.
                conflicts.push(Conflict {
                    code: ConflictCode::QuestionRemoved,
                    message: format!("The question \"{id}\" was removed in the new version; your answer no longer applies."),
                    subject: id.clone(),
                    action: ConflictAction::Review,
                });
            }
            Some(upstream_type) => {
                let base_type = base_inputs.get(id);
                if base_type.is_some_and(|t| t != upstream_type) {
                    // The question changed type; the old answer may not fit the new question.
                    conflicts.push(Conflict {
                        code: ConflictCode::QuestionRetyped,
                        message: format!("The question \"{id}\" changed type in the new version; please answer it again."),
                        subject: id.clone(),
                        action: ConflictAction::Ask,
                    });
                    // Drop the stale answer; the new required-question handling will ask it.
                } else {
                    // The person's answer wins over any upstream default.
                    answers.insert(id.clone(), value.clone());
                }
            }
        }
    }

    // New required questions the person has not answered: ask only those (plan 7.4).
    for (id, _type) in &upstream_inputs {
        if !is_required(upstream, id) {
            continue;
        }
        let answered = answers.contains_key(id);
        let is_new = !base_inputs.contains_key(id);
        if is_new && !answered {
            conflicts.push(Conflict {
                code: ConflictCode::NewRequiredQuestion,
                message: format!("The new version needs an answer to \"{id}\"."),
                subject: id.clone(),
                action: ConflictAction::Ask,
            });
        }
    }

    // A value the person set that is now locked upstream to a different value: their choice is kept,
    // but the changed lock is surfaced for review.
    for (id, upstream_value) in upstream_locked {
        let locally_set = local.answers.get(id);
        let base_lock = base_locked.get(id);
        let lock_changed = base_lock.is_none_or(|b| b != upstream_value);
        if lock_changed {
            if let Some(local_value) = locally_set {
                if local_value != upstream_value {
                    conflicts.push(Conflict {
                        code: ConflictCode::LockedValueChanged,
                        message: format!("The new version locks \"{id}\" to a different value than you chose; review the change."),
                        subject: id.clone(),
                        action: ConflictAction::Review,
                    });
                }
            }
        }
    }

    // ---- Capabilities ----
    //
    // Local on/off wins. Upstream default fills only where the person never chose. A capability now
    // required upstream that the person turned off is turned on, with a conflict so they see it.
    let mut capabilities: BTreeMap<String, bool> = BTreeMap::new();
    for (id, (selection, _locked)) in &upstream_caps {
        let default_on = matches!(selection, Selection::Required | Selection::Default);
        let chosen = local.capabilities.get(id).copied();
        let on = match (selection, chosen) {
            // Required upstream: always on. If the person had turned it off, say so.
            (Selection::Required, Some(false)) => {
                conflicts.push(Conflict {
                    code: ConflictCode::CapabilityNowRequired,
                    message: format!("\"{id}\" is required in the new version, so it is turned on."),
                    subject: id.clone(),
                    action: ConflictAction::Review,
                });
                true
            }
            (Selection::Required, _) => true,
            // Optional or default: the person's choice wins; otherwise the upstream default.
            (_, Some(choice)) => choice,
            (_, None) => default_on,
        };
        capabilities.insert(id.clone(), on);
    }
    // A capability the person added that upstream still does not declare stays theirs and on.
    let mut added: BTreeSet<String> = BTreeSet::new();
    for id in &local.added {
        if !upstream_caps.contains_key(id) {
            added.insert(id.clone());
            capabilities.insert(id.clone(), true);
        }
    }

    // ---- Resources with retained data removed upstream ----
    //
    // A resource the base had, that upstream no longer declares, whose data the person would lose:
    // never delete it. Plan to retain it and tell them.
    let base_resource_ids: BTreeSet<&String> = base.template.capabilities.iter().map(|c| &c.id).collect();
    let upstream_resource_ids: BTreeSet<&String> = upstream.capabilities.iter().map(|c| &c.id).collect();
    for id in retained_data {
        // A retained-data resource that the base declared but upstream dropped.
        let in_base = base_resource_ids.contains(id) || base_inputs.contains_key(id);
        let in_upstream = upstream_resource_ids.contains(id) || upstream_inputs.contains_key(id);
        if in_base && !in_upstream {
            conflicts.push(Conflict {
                code: ConflictCode::ResourceRemovedWithData,
                message: format!("\"{id}\" was removed in the new version but holds data; it is kept, not deleted."),
                subject: id.clone(),
                action: ConflictAction::RetainData,
            });
        }
    }

    // Order conflicts so the output is deterministic and reads structurally: by code, then subject.
    conflicts.sort_by(|a, b| {
        code_order(a.code).cmp(&code_order(b.code)).then_with(|| a.subject.cmp(&b.subject))
    });

    Merged { capabilities, answers, added, conflicts }
}

/// The order conflicts are shown in: data safety first, then structure, then new decisions.
fn code_order(code: ConflictCode) -> u8 {
    match code {
        ConflictCode::ResourceRemovedWithData => 0,
        ConflictCode::CapabilityNowRequired => 1,
        ConflictCode::LockedValueChanged => 2,
        ConflictCode::QuestionRemoved => 3,
        ConflictCode::QuestionRetyped => 4,
        ConflictCode::NewRequiredQuestion => 5,
        ConflictCode::NewGrantToReview => 6,
    }
}

/// Raise review conflicts for grants or downloads the new version adds that the installed one did not
/// have. `base_grants`/`upstream_grants` are the permission or download identifiers each version
/// requests; anything new must be reviewed before it applies. Kept separate from [`merge`] so a
/// caller that computes grants from the plan can fold them into the same conflict list.
pub fn new_grants(base_grants: &BTreeSet<String>, upstream_grants: &BTreeSet<String>) -> Vec<Conflict> {
    let mut conflicts: Vec<Conflict> = upstream_grants
        .difference(base_grants)
        .map(|grant| Conflict {
            code: ConflictCode::NewGrantToReview,
            message: format!("The new version asks for \"{grant}\", which the installed version did not."),
            subject: grant.clone(),
            action: ConflictAction::Review,
        })
        .collect();
    conflicts.sort_by(|a, b| a.subject.cmp(&b.subject));
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{CapabilityUse, Input};

    fn input(id: &str, kind: &str, required: bool) -> Input {
        Input {
            id: Some(id.to_owned()),
            kind: if kind.is_empty() { None } else { Some(kind.to_owned()) },
            required: Some(required),
            ..Input::default()
        }
    }

    fn capability(id: &str, selection: Selection, locked: bool) -> CapabilityUse {
        CapabilityUse { id: id.to_owned(), selection, locked, when: None }
    }

    fn template(inputs: Vec<Input>, capabilities: Vec<CapabilityUse>) -> Template {
        Template { inputs, capabilities, ..Template::default() }
    }

    fn base(template: Template, answers: &[(&str, &str)]) -> Base {
        Base {
            template,
            answers: answers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn local(answers: &[(&str, &str)], capabilities: &[(&str, bool)], added: &[&str]) -> Customization {
        Customization {
            answers: answers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            capabilities: capabilities.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            added: added.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn empty() -> (BTreeSet<String>, BTreeMap<String, String>, BTreeMap<String, String>) {
        (BTreeSet::new(), BTreeMap::new(), BTreeMap::new())
    }

    #[test]
    fn a_clean_update_keeps_local_choices_and_fills_only_new_defaults() {
        let base_t = template(vec![input("name", "text", true)], vec![capability("web.service", Selection::Default, false)]);
        let upstream = template(
            vec![input("name", "text", true), input("region", "text", false)],
            vec![capability("web.service", Selection::Default, false)],
        );
        let (data, bl, ul) = empty();
        let merged = merge(&base(base_t, &[("name", "app")]), &local(&[("name", "myapp")], &[], &[]), &upstream, &data, &bl, &ul);
        assert!(merged.is_clean());
        assert_eq!(merged.answers.get("name").map(String::as_str), Some("myapp")); // local wins
        assert_eq!(merged.capabilities.get("web.service"), Some(&true)); // default on, never chosen off
    }

    #[test]
    fn a_removed_question_with_a_local_answer_is_a_conflict() {
        let base_t = template(vec![input("region", "text", false)], vec![]);
        let upstream = template(vec![], vec![]);
        let (data, bl, ul) = empty();
        let merged = merge(&base(base_t, &[]), &local(&[("region", "eu")], &[], &[]), &upstream, &data, &bl, &ul);
        assert_eq!(merged.conflicts.len(), 1);
        assert_eq!(merged.conflicts[0].code, ConflictCode::QuestionRemoved);
        assert!(!merged.answers.contains_key("region")); // stale answer dropped
    }

    #[test]
    fn a_retyped_question_asks_again_and_drops_the_old_answer() {
        let base_t = template(vec![input("size", "text", false)], vec![]);
        let upstream = template(vec![input("size", "number", false)], vec![]);
        let (data, bl, ul) = empty();
        let merged = merge(&base(base_t, &[]), &local(&[("size", "big")], &[], &[]), &upstream, &data, &bl, &ul);
        assert_eq!(merged.conflicts[0].code, ConflictCode::QuestionRetyped);
        assert!(!merged.answers.contains_key("size"));
    }

    #[test]
    fn a_capability_turned_off_but_now_required_is_turned_on_with_a_conflict() {
        let base_t = template(vec![], vec![capability("web.service", Selection::Optional, false)]);
        let upstream = template(vec![], vec![capability("web.service", Selection::Required, false)]);
        let (data, bl, ul) = empty();
        let merged = merge(&base(base_t, &[]), &local(&[], &[("web.service", false)], &[]), &upstream, &data, &bl, &ul);
        assert_eq!(merged.conflicts[0].code, ConflictCode::CapabilityNowRequired);
        assert_eq!(merged.capabilities.get("web.service"), Some(&true));
    }

    #[test]
    fn a_changed_lock_over_a_local_value_is_a_conflict_but_keeps_the_local_value() {
        let base_t = template(vec![input("port", "number", false)], vec![]);
        let upstream = template(vec![input("port", "number", false)], vec![]);
        let data = BTreeSet::new();
        let base_lock: BTreeMap<String, String> = [("port".to_string(), "8080".to_string())].into();
        let upstream_lock: BTreeMap<String, String> = [("port".to_string(), "9090".to_string())].into();
        let merged = merge(&base(base_t, &[]), &local(&[("port", "3000")], &[], &[]), &upstream, &data, &base_lock, &upstream_lock);
        assert!(merged.conflicts.iter().any(|c| c.code == ConflictCode::LockedValueChanged));
        assert_eq!(merged.answers.get("port").map(String::as_str), Some("3000"));
    }

    #[test]
    fn a_new_required_question_is_asked() {
        let base_t = template(vec![], vec![]);
        let upstream = template(vec![input("owner", "text", true)], vec![]);
        let (data, bl, ul) = empty();
        let merged = merge(&base(base_t, &[]), &local(&[], &[], &[]), &upstream, &data, &bl, &ul);
        assert_eq!(merged.conflicts[0].code, ConflictCode::NewRequiredQuestion);
    }

    #[test]
    fn a_resource_with_data_removed_upstream_is_retained_never_deleted() {
        let base_t = template(vec![], vec![capability("data.volumes", Selection::Optional, false)]);
        let upstream = template(vec![], vec![]);
        let data: BTreeSet<String> = ["data.volumes".to_string()].into();
        let (_d, bl, ul) = empty();
        let merged = merge(&base(base_t, &[]), &local(&[], &[], &[]), &upstream, &data, &bl, &ul);
        let conflict = merged.conflicts.iter().find(|c| c.code == ConflictCode::ResourceRemovedWithData).unwrap();
        assert_eq!(conflict.action, ConflictAction::RetainData);
    }

    #[test]
    fn an_added_capability_survives_an_update() {
        let base_t = template(vec![], vec![]);
        let upstream = template(vec![], vec![]);
        let (data, bl, ul) = empty();
        let merged = merge(&base(base_t, &[]), &local(&[], &[], &["run.health_logs"]), &upstream, &data, &bl, &ul);
        assert!(merged.added.contains("run.health_logs"));
        assert_eq!(merged.capabilities.get("run.health_logs"), Some(&true));
    }

    #[test]
    fn a_no_op_update_to_the_same_version_changes_nothing() {
        let t = template(vec![input("name", "text", true)], vec![capability("web.service", Selection::Default, false)]);
        let (data, bl, ul) = empty();
        let base = base(t.clone(), &[("name", "app")]);
        let local = local(&[("name", "app")], &[("web.service", true)], &[]);
        let merged = merge(&base, &local, &t, &data, &bl, &ul);
        assert!(merged.is_clean());
        assert_eq!(merged.answers.get("name").map(String::as_str), Some("app"));
        assert_eq!(merged.capabilities.get("web.service"), Some(&true));
    }

    #[test]
    fn the_merge_is_deterministic() {
        let base_t = template(vec![input("a", "text", false), input("b", "text", false)], vec![]);
        let upstream = template(vec![input("c", "text", true)], vec![]);
        let (data, bl, ul) = empty();
        let run = || merge(&base(base_t.clone(), &[]), &local(&[("a", "1"), ("b", "2")], &[], &[]), &upstream, &data, &bl, &ul);
        assert_eq!(run(), run());
    }

    #[test]
    fn new_grants_are_raised_for_review() {
        let base: BTreeSet<String> = ["run_containers".to_string()].into();
        let upstream: BTreeSet<String> = ["run_containers".to_string(), "open_public_url".to_string()].into();
        let conflicts = new_grants(&base, &upstream);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].code, ConflictCode::NewGrantToReview);
        assert_eq!(conflicts[0].subject, "open_public_url");
    }
}
