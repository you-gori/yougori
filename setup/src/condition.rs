//! Typed conditions over earlier, non-secret answers. No free-form expressions.
//!
//! The v1 shorthand stays: a mapping is AND between its inputs, and a list of answers is
//! membership (OR between them). Format 2 adds `{all: [...]}`, `{any: [...]}` and `{not: ...}`,
//! nested at most eight deep. A condition may only name an input that comes earlier and is not
//! a secret; an unknown, forward, secret or self-referencing input is an error when the template
//! is checked, never at run time.
use crate::{
    dto::Diagnostic,
    format::{Question, QuestionKind},
    limits,
};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// The input's answer is one of `values`; with `contains`, a multiple-choice answer that
    /// includes any of them.
    Input { id: String, values: Vec<String>, contains: bool },
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    /// A v1 condition list: AND between the inputs. `None` when the list is empty.
    pub fn terms(terms: Vec<(String, Vec<String>, bool)>) -> Option<Condition> {
        let mut terms: Vec<Condition> = terms.into_iter().map(|(id, values, contains)| Condition::Input { id, values, contains }).collect();
        match terms.len() {
            0 => None,
            1 => terms.pop(),
            _ => Some(Condition::All(terms)),
        }
    }

    /// Whether the condition holds for the answers so far. An input without an answer (it was not
    /// asked, or not yet) never matches.
    pub fn holds(&self, answers: &BTreeMap<String, String>) -> bool {
        match self {
            Condition::Input { id, values, contains } => answers.get(id).is_some_and(|answer| {
                values.iter().any(|value| if *contains { answer.split(',').any(|v| v == value) } else { answer == value })
            }),
            Condition::All(items) => items.iter().all(|c| c.holds(answers)),
            Condition::Any(items) => items.iter().any(|c| c.holds(answers)),
            Condition::Not(inner) => !inner.holds(answers),
        }
    }

    /// The inputs the condition reads.
    pub fn inputs(&self, out: &mut BTreeSet<String>) {
        match self {
            Condition::Input { id, .. } => {
                out.insert(id.clone());
            }
            Condition::All(items) | Condition::Any(items) => items.iter().for_each(|c| c.inputs(out)),
            Condition::Not(inner) => inner.inputs(out),
        }
    }

    /// The condition as plain sentences for a review: one line per AND term, as v1 writes them.
    pub fn describe(&self) -> Vec<String> {
        match self {
            Condition::All(items) => items.iter().flat_map(Condition::describe).collect(),
            other => vec![other.sentence()],
        }
    }

    fn sentence(&self) -> String {
        match self {
            Condition::Input { id, values, contains } => format!("{id} {} {}", if *contains { "contains any of" } else { "is one of" }, serde_json::json!(values)),
            Condition::All(items) => format!("all of: {}", items.iter().map(Condition::sentence).collect::<Vec<_>>().join("; ")),
            Condition::Any(items) => format!("any of: {}", items.iter().map(Condition::sentence).collect::<Vec<_>>().join("; ")),
            Condition::Not(inner) => format!("not: {}", inner.sentence()),
        }
    }
}

fn scalar_text(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(text) => Some(text.clone()),
        Yaml::Number(number) => Some(number.to_string()),
        Yaml::Bool(value) => Some(if *value { "yes" } else { "no" }.into()),
        _ => None,
    }
}

fn problem(code: &'static str, message: String, path: &str) -> Diagnostic {
    Diagnostic::error(code, message).at(path.to_owned())
}

/// Reads a `when:` value against the inputs it may use (the earlier ones for an input, every
/// input for a resource, a tool, a step or a capability).
pub fn parse(when: &Yaml, questions: &[Question], path: &str) -> Result<Condition, Vec<Diagnostic>> {
    let mut problems = Vec::new();
    let condition = node(when, questions, 1, path, &mut problems);
    match condition {
        // A review shows a condition as one sentence per AND term, so that is bounded too: nested
        // all: lists would otherwise read as hundreds of lines, or be cut.
        Some(condition) if problems.is_empty() && !limits::CONDITION_TERMS.allows(condition.describe().len()) => {
            Err(vec![problem("limit_exceeded", format!("{} Each input and each any or not counts as one.", limits::CONDITION_TERMS.exceeded(condition.describe().len())), path)])
        }
        Some(condition) if problems.is_empty() => Ok(condition),
        _ => Err(problems),
    }
}

fn node(value: &Yaml, questions: &[Question], depth: usize, path: &str, problems: &mut Vec<Diagnostic>) -> Option<Condition> {
    if !limits::CONDITION_DEPTH.allows(depth) {
        problems.push(problem("condition_too_deep", limits::CONDITION_DEPTH.exceeded(depth), path));
        return None;
    }
    let Some(map) = value.as_mapping() else {
        problems.push(problem("invalid_condition", "when must be a mapping: an input and its answer, or all, any or not.".into(), path));
        return None;
    };
    if map.is_empty() {
        problems.push(problem("invalid_condition", "when needs at least one input and its answer.".into(), path));
        return None;
    }
    let keys: Vec<String> = map.keys().filter_map(scalar_text).collect();
    let combinators: Vec<&String> = keys.iter().filter(|k| matches!(k.as_str(), "all" | "any" | "not")).collect();
    if !combinators.is_empty() {
        if keys.len() != 1 {
            problems.push(problem("invalid_condition", "all, any and not stand alone: write {all: [...]}, {any: [...]} or {not: {...}}, not beside inputs or each other.".into(), path));
            return None;
        }
        let key = combinators[0].as_str();
        let inner = map.get(key)?;
        return match key {
            "not" => node(inner, questions, depth + 1, &format!("{path}.not"), problems).map(|c| Condition::Not(Box::new(c))),
            _ => {
                let Some(items) = inner.as_sequence() else {
                    problems.push(problem("invalid_condition", format!("{key} needs a list of conditions."), path));
                    return None;
                };
                if items.is_empty() {
                    problems.push(problem("invalid_condition", format!("{key} needs at least one condition."), path));
                    return None;
                }
                if !limits::CONDITION_TERMS.allows(items.len()) {
                    problems.push(problem("limit_exceeded", limits::CONDITION_TERMS.exceeded(items.len()), path));
                    return None;
                }
                let parsed: Vec<Option<Condition>> = items.iter().enumerate().map(|(i, item)| node(item, questions, depth + 1, &format!("{path}.{key}[{i}]"), problems)).collect();
                let items: Option<Vec<Condition>> = parsed.into_iter().collect();
                items.map(|items| if key == "all" { Condition::All(items) } else { Condition::Any(items) })
            }
        };
    }
    if !limits::CONDITION_TERMS.allows(map.len()) {
        problems.push(problem("limit_exceeded", limits::CONDITION_TERMS.exceeded(map.len()), path));
        return None;
    }
    let mut terms = Vec::new();
    for (key, value) in map {
        let Some(id) = scalar_text(key) else {
            problems.push(problem("invalid_condition", "when names inputs by their id.".into(), path));
            continue;
        };
        let Some(earlier) = questions.iter().find(|q| q.id == id) else {
            problems.push(problem("unknown_input", format!("when names {}, which is not an earlier input.", crate::text::shown(&id)), path));
            continue;
        };
        if earlier.kind == QuestionKind::Secret {
            problems.push(problem("secret_in_condition", "when cannot depend on a secret.".into(), path));
            continue;
        }
        let items = match value {
            Yaml::Sequence(items) => items.clone(),
            other => vec![other.clone()],
        };
        if items.is_empty() || !limits::CONDITION_VALUES.allows(items.len()) {
            problems.push(problem("invalid_condition", format!("when needs 1 to {} possible answers per input.", limits::CONDITION_VALUES.max), path));
            continue;
        }
        let mut values = Vec::new();
        for item in items {
            let Some(text) = scalar_text(&item) else {
                problems.push(problem("invalid_condition", "when answers must be scalar values.".into(), path));
                continue;
            };
            match earlier.answer(&text, None) {
                Ok(normal) => {
                    if earlier.kind == QuestionKind::MultiChoice && normal.contains(',') {
                        problems.push(problem("invalid_condition", "Use a YAML list for alternative when answers.".into(), path));
                        continue;
                    }
                    values.push(normal);
                }
                Err(error) => problems.push(problem("invalid_value", format!("when {id}: {} is not an answer to {id}. {error}", crate::text::shown(&text)), path)),
            }
        }
        terms.push(Condition::Input { id, values, contains: earlier.kind == QuestionKind::MultiChoice });
    }
    Condition::terms(terms.into_iter().map(|t| match t {
        Condition::Input { id, values, contains } => (id, values, contains),
        _ => unreachable!(),
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{self, Input, Choice};

    fn questions() -> Vec<Question> {
        let inputs = vec![
            Input { id: Some("access".into()), question: Some("Where?".into()), kind: Some("choice".into()), choices: vec![
                Choice { value: Some("quick".into()), label: Some("Quick".into()), ..Choice::default() },
                Choice { value: Some("domain".into()), label: Some("Domain".into()), ..Choice::default() },
                Choice { value: Some("none".into()), label: Some("None".into()), ..Choice::default() },
            ], group: Some("website_api".into()), ..Input::default() },
            Input { id: Some("providers".into()), question: Some("Which?".into()), kind: Some("multichoice".into()), choices: vec![
                Choice { value: Some("codex".into()), label: Some("Codex".into()), ..Choice::default() },
                Choice { value: Some("claude".into()), label: Some("Claude".into()), ..Choice::default() },
            ], group: Some("ai_models".into()), ..Input::default() },
            Input { id: Some("key".into()), question: Some("Key?".into()), kind: Some("secret".into()), group: Some("ai_models".into()), required: Some(false), ..Input::default() },
            Input { id: Some("count".into()), question: Some("How many?".into()), kind: Some("number".into()), group: Some("grid_workers".into()), min: Some(1.0), max: Some(8.0), ..Input::default() },
        ];
        let mut problems = Vec::new();
        let questions = format::questions(&inputs, true, &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
        questions
    }

    fn parsed(text: &str) -> Result<Condition, Vec<Diagnostic>> {
        parse(&serde_yaml_ng::from_str(text).unwrap(), &questions(), "when")
    }

    fn answers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn the_v1_shorthand_and_the_combinators_parse_and_hold() {
        let shorthand = parsed("{access: domain, providers: [codex, claude]}").unwrap();
        assert_eq!(shorthand, Condition::All(vec![
            Condition::Input { id: "access".into(), values: vec!["domain".into()], contains: false },
            Condition::Input { id: "providers".into(), values: vec!["codex".into(), "claude".into()], contains: true },
        ]));
        assert!(shorthand.holds(&answers(&[("access", "domain"), ("providers", "claude,codex")])));
        assert!(!shorthand.holds(&answers(&[("access", "domain")])), "an unanswered input never matches");
        let any = parsed("{any: [{access: domain}, {not: {providers: codex}}]}").unwrap();
        assert!(any.holds(&answers(&[("access", "quick"), ("providers", "claude")])));
        assert!(!any.holds(&answers(&[("access", "quick"), ("providers", "codex")])));
        assert_eq!(any.describe(), vec!["any of: access is one of [\"domain\"]; not: providers contains any of [\"codex\"]"]);
        assert_eq!(shorthand.describe().len(), 2);
        assert_eq!(parsed("{count: 3}").unwrap(), Condition::Input { id: "count".into(), values: vec!["3".into()], contains: false });
        let mut used = BTreeSet::new();
        any.inputs(&mut used);
        assert_eq!(used, ["access".to_owned(), "providers".to_owned()].into());
    }

    #[test]
    fn unknown_forward_secret_and_deep_conditions_are_refused() {
        let said = |text: &str| parsed(text).unwrap_err().into_iter().map(|p| format!("{}: {}", p.code, p.message)).collect::<Vec<_>>().join("\n");
        assert!(said("{nothing: x}").contains("unknown_input"));
        assert!(said("{key: x}").contains("secret_in_condition"));
        assert!(said("{access: elsewhere}").contains("is not an answer to access"));
        assert!(said("{}").contains("at least one input"));
        assert!(said("{all: [{access: quick}], access: quick}").contains("stand alone"));
        assert!(said("{any: []}").contains("at least one condition"));
        assert!(said("[access]").contains("must be a mapping"));
        let mut deep = "{access: quick}".to_owned();
        for _ in 0..9 {
            deep = format!("{{not: {deep}}}");
        }
        assert!(said(&deep).contains("condition_too_deep"));
        let earlier_only = parse(&serde_yaml_ng::from_str("{count: 2}").unwrap(), &questions()[..1], "when").unwrap_err();
        assert_eq!(earlier_only[0].code, "unknown_input", "a later input is a forward reference");
    }
}
