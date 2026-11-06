//! Placeholders: `{{inputs.ID}}`, `{{secrets.ID}}`, `{{instance}}`, `{{env.NAME}}`,
//! `{{public.NAME}}` and, in steps and outputs only, `{{outputs.RESOURCE.NAME}}`. They are
//! replaced inside string values after the YAML is parsed, in one pass, so an answer can never
//! change the structure of a file or bring in another placeholder.
//!
//! A v2 resource spec is typed: a string that is exactly one `{{inputs.ID}}` becomes the answer
//! in its own type (a number question gives a number, a yes/no question a boolean, a
//! multiple-choice question a list), so a count stays a count. Text with a placeholder inside it
//! stays text. A v1-style environment keeps the v1 behaviour: every answer is text.
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placeholder {
    Instance,
    Input(String),
    Secret(String),
    Env(String),
    Public(String),
    /// A resource's output, once it exists: `{{outputs.RESOURCE.NAME}}`.
    Output(String, String),
}

/// Where a string is: each placeholder is allowed in some places only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// Any string value of a resource spec or a v1-style environment, except a `secrets:` value.
    Spec,
    /// A value that may hold a secret binding as a whole: an environment's `secrets:` values and
    /// the few fields a kind declares.
    SpecSecret,
    /// A `public:` entry's access or domain.
    Public,
    Step,
    Output,
}

const KINDS: &str = "Use {{inputs.ID}}, {{secrets.ID}}, {{instance}}, {{env.NAME}}, {{public.NAME}} or {{outputs.RESOURCE.NAME}}";

fn id(text: &str) -> bool {
    !text.is_empty() && text.len() <= 80 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn read(inner: &str) -> Option<Placeholder> {
    let inner = inner.trim();
    if inner == "instance" {
        return Some(Placeholder::Instance);
    }
    let (kind, name) = inner.split_once('.')?;
    if kind == "outputs" {
        let (resource, output) = name.rsplit_once('.')?;
        if !id(resource) || !id(output) || output.contains('.') {
            return None;
        }
        return Some(Placeholder::Output(resource.to_owned(), output.to_owned()));
    }
    if !id(name) {
        return None;
    }
    let name = name.to_owned();
    Some(match kind {
        "inputs" => Placeholder::Input(name),
        "secrets" => Placeholder::Secret(name),
        "env" => Placeholder::Env(name),
        "public" => Placeholder::Public(name),
        _ => return None,
    })
}

/// A string as text and placeholders, in order.
pub enum Piece<'a> {
    Text(&'a str),
    Placeholder(Placeholder, &'a str),
}

pub fn pieces(text: &str) -> Result<Vec<Piece<'_>>, String> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        if start > 0 {
            pieces.push(Piece::Text(&rest[..start]));
        }
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or_else(|| format!("\"{}\" has {{{{ without }}}}. {KINDS}.", short(text)))?;
        let raw = &rest[start..start + 2 + end + 2];
        let placeholder = read(&after[..end]).ok_or_else(|| format!("{raw} is not a placeholder. {KINDS}."))?;
        pieces.push(Piece::Placeholder(placeholder, raw));
        rest = &after[end + 2..];
    }
    if !rest.is_empty() {
        pieces.push(Piece::Text(rest));
    }
    Ok(pieces)
}

fn short(text: &str) -> String {
    let shown: String = text.chars().filter(|c| !c.is_control()).take(80).collect();
    if text.chars().count() > 80 { format!("{shown}…") } else { shown }
}

/// The input id when `text` is exactly one `{{inputs.ID}}`, with nothing around it.
pub fn whole_input(text: &str) -> Option<String> {
    match pieces(text).ok()?.as_slice() {
        [Piece::Placeholder(Placeholder::Input(name), _)] => Some(name.clone()),
        _ => None,
    }
}

/// The secret input id when `text` is exactly one `{{secrets.ID}}`.
pub fn whole_secret(text: &str) -> Option<String> {
    match pieces(text).ok()?.as_slice() {
        [Piece::Placeholder(Placeholder::Secret(name), _)] => Some(name.clone()),
        _ => None,
    }
}

/// What a template declares, for checking its placeholders.
#[derive(Clone, Debug, Default)]
pub struct Known {
    /// Input id and whether it is a secret.
    pub inputs: BTreeMap<String, bool>,
    /// Environments: v1-style ones and resources of kind environment.
    pub environments: BTreeSet<String>,
    /// Environments with a `public:` entry.
    pub public: BTreeSet<String>,
    /// Resource id to the outputs its kind has.
    pub outputs: BTreeMap<String, Vec<&'static str>>,
}

/// Checks every placeholder of `text` for where it is.
pub fn check(text: &str, place: Place, known: &Known) -> Result<(), String> {
    let pieces = pieces(text)?;
    for piece in &pieces {
        let Piece::Placeholder(placeholder, raw) = piece else { continue };
        match placeholder {
            Placeholder::Instance => {}
            Placeholder::Input(name) => match known.inputs.get(name) {
                None => return Err(format!("{raw} names no input. {}", list("The inputs are", known.inputs.keys()))),
                Some(true) => return Err(format!("{raw} would put a secret in plain text. Use {{{{secrets.{name}}}}} as a whole value where the format allows a secret.")),
                Some(false) => {}
            },
            Placeholder::Secret(name) => {
                if known.inputs.get(name) != Some(&true) {
                    return Err(format!("{raw} needs a secret input with id {name}."));
                }
                if place != Place::SpecSecret || pieces.len() != 1 {
                    return Err(format!("{raw} works only as a whole value where the format allows a secret, for example secrets: {{API_KEY: \"{raw}\"}} under an environment."));
                }
            }
            Placeholder::Env(name) => {
                if !known.environments.contains(name) {
                    return Err(format!("{raw} names no environment. {}", list("The environments are", known.environments.iter())));
                }
            }
            Placeholder::Public(name) => {
                if place != Place::Output {
                    return Err(format!("{raw} works only in outputs."));
                }
                if !known.public.contains(name) {
                    return Err(format!("{raw} needs a public: entry for the environment {name}."));
                }
            }
            Placeholder::Output(resource, output) => {
                if !matches!(place, Place::Step | Place::Output) {
                    return Err(format!("{raw} works only in steps and outputs."));
                }
                match known.outputs.get(resource) {
                    None => return Err(format!("{raw} names no resource. {}", list("The resources are", known.outputs.keys()))),
                    Some(outputs) if !outputs.contains(&output.as_str()) => {
                        return Err(format!("{raw}: {resource} has no output {output}. Its outputs are: {}.", outputs.join(", ")));
                    }
                    Some(_) => {}
                }
            }
        }
    }
    Ok(())
}

fn list<'a>(said: &str, names: impl Iterator<Item = &'a String>) -> String {
    let names: Vec<&str> = names.map(String::as_str).collect();
    if names.is_empty() { format!("{said}: none.") } else { format!("{said}: {}.", names.join(", ")) }
}

/// The type an answer takes when it stands alone in a typed spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typed {
    Text,
    Number,
    Bool,
    List,
}

/// The values placeholders take in one instance.
#[derive(Clone, Debug, Default)]
pub struct Values {
    pub instance: String,
    /// Answers to inputs that were asked; an input that was not asked is absent.
    pub inputs: BTreeMap<String, String>,
    /// The type each input's answer takes when it stands alone in a typed spec.
    pub types: BTreeMap<String, Typed>,
    /// Secret input id to the name of the binding that holds it; never the value.
    pub secrets: BTreeMap<String, String>,
    /// Environment name to its public address, once known.
    pub public: BTreeMap<String, String>,
    /// Environment name to the sandbox's real name, once the engine made it; otherwise
    /// `INSTANCE-NAME`.
    pub names: BTreeMap<String, String>,
    /// Resource id to its outputs, once they exist.
    pub outputs: BTreeMap<String, BTreeMap<String, String>>,
    /// Leave `{{env.NAME}}`, `{{public.NAME}}` and `{{outputs.…}}` as written when their value
    /// is not known yet, for text the engine finishes after the setup exists.
    pub partial: bool,
}

/// The binding that holds a secret answer: `hub-INSTANCE-ID`, as v1 names it.
pub fn secret_name(instance: &str, id: &str) -> String {
    format!("hub-{instance}-{id}")
}

/// Replaces every placeholder in one pass; what an answer contains is never read again.
pub fn render(text: &str, values: &Values) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    for piece in pieces(text)? {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Placeholder(placeholder, raw) => out.push_str(&match placeholder {
                Placeholder::Instance => values.instance.clone(),
                Placeholder::Input(name) => values.inputs.get(&name).cloned().unwrap_or_default(),
                Placeholder::Secret(name) => values.secrets.get(&name).cloned().ok_or_else(|| format!("{raw} has no stored secret"))?,
                Placeholder::Env(name) => match values.names.get(&name) {
                    Some(name) => name.clone(),
                    None if values.partial => raw.to_owned(),
                    None => format!("{}-{name}", values.instance),
                },
                Placeholder::Public(name) => match values.public.get(&name) {
                    Some(address) => address.clone(),
                    None if values.partial => raw.to_owned(),
                    None => "(not public)".into(),
                },
                Placeholder::Output(resource, output) => match values.outputs.get(&resource).and_then(|o| o.get(&output)) {
                    Some(value) => value.clone(),
                    None if values.partial => raw.to_owned(),
                    None => "(not ready)".into(),
                },
            }),
        }
    }
    Ok(out)
}

fn key_text(key: &Yaml) -> String {
    match key {
        Yaml::String(text) => text.clone(),
        Yaml::Number(number) => number.to_string(),
        Yaml::Bool(value) => value.to_string(),
        _ => String::from("?"),
    }
}

/// A path through a YAML tree, as messages and policies write it: `files[0].source`.
pub fn join(parts: &[String]) -> String {
    let mut out = String::new();
    for part in parts {
        if !out.is_empty() && !part.starts_with('[') {
            out.push('.');
        }
        out.push_str(part);
    }
    out
}

/// A path with every index removed, for matching a policy: `files[0].source` is `files[].source`.
pub fn pattern_of(path: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for c in path.chars() {
        match c {
            '[' => {
                inside = true;
                out.push('[');
            }
            ']' => {
                inside = false;
                out.push(']');
            }
            _ if inside => {}
            _ => out.push(c),
        }
    }
    out
}

/// Whether `path` (indexes removed) is under one of `patterns`: a pattern ending in `.*` matches
/// every path below it, and a plain pattern matches itself and everything below it.
pub fn under(path: &str, patterns: &[&str]) -> bool {
    let plain = pattern_of(path);
    patterns.iter().any(|pattern| {
        let base = pattern.strip_suffix(".*").unwrap_or(pattern);
        plain == base || plain.strip_prefix(base).is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
    })
}

/// Every string scalar of a parsed YAML tree with its path and where it is. `secret_paths` says
/// which paths may hold a secret binding.
pub fn strings(value: &Yaml, secret_paths: &[&str]) -> Result<Vec<(String, String, Place)>, String> {
    let mut found = Vec::new();
    collect(value, &mut Vec::new(), secret_paths, &mut found)?;
    Ok(found)
}

fn collect(value: &Yaml, path: &mut Vec<String>, secret_paths: &[&str], found: &mut Vec<(String, String, Place)>) -> Result<(), String> {
    match value {
        Yaml::String(text) => {
            let at = join(path);
            let place = if under(&at, secret_paths) { Place::SpecSecret } else { Place::Spec };
            found.push((text.clone(), at, place));
        }
        Yaml::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(format!("[{index}]"));
                collect(item, path, secret_paths, found)?;
                path.pop();
            }
        }
        Yaml::Mapping(map) => {
            for (key, item) in map {
                let name = key_text(key);
                if name.contains("{{") {
                    return Err(format!("Placeholders work in values, not in names: {}.", short(&name)));
                }
                path.push(name);
                collect(item, path, secret_paths, found)?;
                path.pop();
            }
        }
        Yaml::Tagged(tagged) => collect(&tagged.value, path, secret_paths, found)?,
        _ => {}
    }
    Ok(())
}

fn typed(answer: &str, kind: Typed) -> Yaml {
    match kind {
        Typed::Text => Yaml::String(answer.to_owned()),
        Typed::Number => answer
            .parse::<i64>()
            .map(|n| Yaml::Number(n.into()))
            .or_else(|_| answer.parse::<f64>().map(|n| Yaml::Number(n.into())))
            .unwrap_or_else(|_| Yaml::String(answer.to_owned())),
        Typed::Bool => Yaml::Bool(answer == "yes"),
        Typed::List => Yaml::Sequence(answer.split(',').filter(|s| !s.is_empty()).map(|s| Yaml::String(s.to_owned())).collect()),
    }
}

/// Replaces the placeholders of a YAML tree in place. With `typed_specs`, a string that is
/// exactly one `{{inputs.ID}}` takes the answer's own type, and one whose input was not asked is
/// left out entirely (its key or list item disappears, so the kind's default applies); without
/// it every answer is text, as v1 does. A secret binding that was not given leaves its key out,
/// so no binding that does not exist is named.
pub fn substitute(value: &mut Yaml, values: &Values, secret_paths: &[&str], typed_specs: bool) -> Result<(), String> {
    if walk(value, &mut Vec::new(), values, secret_paths, typed_specs)? {
        *value = Yaml::Null;
    }
    Ok(())
}

/// Returns whether the value should be left out by its parent.
fn walk(value: &mut Yaml, path: &mut Vec<String>, values: &Values, secret_paths: &[&str], typed_specs: bool) -> Result<bool, String> {
    match value {
        Yaml::String(text) => {
            if typed_specs {
                if let Some(name) = whole_input(text) {
                    let kind = values.types.get(&name).copied().unwrap_or(Typed::Text);
                    return match values.inputs.get(&name) {
                        Some(answer) => {
                            *value = typed(answer, kind);
                            Ok(false)
                        }
                        None => Ok(true),
                    };
                }
            }
            *text = render(text, values)?;
        }
        Yaml::Sequence(items) => {
            let mut kept = Vec::with_capacity(items.len());
            for (index, mut item) in std::mem::take(items).into_iter().enumerate() {
                path.push(format!("[{index}]"));
                let drop = walk(&mut item, path, values, secret_paths, typed_specs)?;
                path.pop();
                if !drop {
                    kept.push(item);
                }
            }
            *items = kept;
        }
        Yaml::Mapping(map) => {
            let mut unanswered = Vec::new();
            for (key, item) in map.iter_mut() {
                let name = key_text(key);
                if name.contains("{{") {
                    return Err(format!("Placeholders work in values, not in names: {}.", short(&name)));
                }
                path.push(name);
                let at = join(path);
                let missing = under(&at, secret_paths)
                    && item.as_str().and_then(whole_secret).is_some_and(|name| !values.secrets.contains_key(&name));
                let drop = if missing { true } else { walk(item, path, values, secret_paths, typed_specs)? };
                if drop {
                    unanswered.push(key.clone());
                }
                path.pop();
            }
            for key in unanswered {
                map.remove(&key);
            }
        }
        Yaml::Tagged(tagged) => return walk(&mut tagged.value, path, values, secret_paths, typed_specs),
        _ => {}
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> Known {
        Known {
            inputs: [("access".to_owned(), false), ("domain".to_owned(), false), ("openai_key".to_owned(), true)].into(),
            environments: ["web".to_owned(), "paid".to_owned()].into(),
            public: ["web".to_owned()].into(),
            outputs: [("company".to_owned(), vec!["realm_id", "join_address", "name"])].into(),
        }
    }

    #[test]
    fn placeholders_are_checked_for_where_they_are() {
        let known = known();
        assert!(check("yougori codex --environment {{env.paid}} for {{ instance }}", Place::Step, &known).is_ok());
        assert!(check("{{inputs.access}}", Place::Public, &known).is_ok());
        assert!(check("{{public.web}}", Place::Output, &known).is_ok());
        assert!(check("{{secrets.openai_key}}", Place::SpecSecret, &known).is_ok());
        assert!(check("Join with {{outputs.company.join_address}}", Place::Step, &known).is_ok());
        for (text, place, said) in [
            ("{{public.web}}", Place::Step, "works only in outputs"),
            ("{{public.paid}}", Place::Output, "needs a public: entry"),
            ("{{secrets.openai_key}}", Place::Spec, "works only as a whole value"),
            ("prefix-{{secrets.openai_key}}", Place::SpecSecret, "works only as a whole value"),
            ("{{secrets.access}}", Place::SpecSecret, "needs a secret input with id access"),
            ("{{inputs.openai_key}}", Place::Spec, "would put a secret in plain text"),
            ("{{inputs.nope}}", Place::Spec, "names no input. The inputs are: access, domain, openai_key."),
            ("{{env.db}}", Place::Step, "names no environment. The environments are: paid, web."),
            ("{{outputs.company.url}}", Place::Step, "company has no output url"),
            ("{{outputs.nothing.url}}", Place::Output, "names no resource"),
            ("{{outputs.company.name}}", Place::Spec, "works only in steps and outputs"),
            ("{{user.name}}", Place::Step, "is not a placeholder"),
            ("{{ .Values.x }}", Place::Spec, "is not a placeholder"),
            ("open {{inputs.access", Place::Step, "without }}"),
        ] {
            let error = check(text, place, &known).unwrap_err();
            assert!(error.contains(said), "{text}: {error}");
        }
    }

    fn values() -> Values {
        Values {
            instance: "my-api".into(),
            inputs: [("title".to_owned(), "x".to_owned()), ("count".to_owned(), "3".to_owned()), ("gpu".to_owned(), "yes".to_owned()), ("providers".to_owned(), "codex,claude".to_owned())].into(),
            types: [("title".to_owned(), Typed::Text), ("count".to_owned(), Typed::Number), ("gpu".to_owned(), Typed::Bool), ("providers".to_owned(), Typed::List), ("other".to_owned(), Typed::Number)].into(),
            secrets: [("openai_key".to_owned(), secret_name("my-api", "openai_key"))].into(),
            public: [("web".to_owned(), "https://a.trycloudflare.com".to_owned())].into(),
            ..Values::default()
        }
    }

    #[test]
    fn rendering_fills_values_once() {
        let mut values = values();
        values.inputs.insert("title".into(), "{{instance}} and {{inputs.title}}".into());
        assert_eq!(render("[{{inputs.title}}]", &values).unwrap(), "[{{instance}} and {{inputs.title}}]", "an answer is never expanded again");
        assert_eq!(render("{{env.web}} {{instance}} {{public.web}} {{public.db}} '{{inputs.unasked}}'", &values).unwrap(), "my-api-web my-api https://a.trycloudflare.com (not public) ''");
        assert_eq!(render("{{secrets.openai_key}}", &values).unwrap(), "hub-my-api-openai_key");
        values.partial = true;
        assert_eq!(render("{{env.web}} {{public.db}} {{outputs.company.name}}", &values).unwrap(), "{{env.web}} {{public.db}} {{outputs.company.name}}", "unknown values stay as written when partial");
    }

    #[test]
    fn typed_substitution_keeps_native_types() {
        let mut tree: Yaml = serde_yaml_ng::from_str("count: \"{{inputs.count}}\"\ngpu: \"{{inputs.gpu}}\"\nproviders: \"{{inputs.providers}}\"\nname: \"w-{{inputs.count}}\"\nmissing: \"{{inputs.other}}\"\nsecrets:\n  KEY: \"{{secrets.openai_key}}\"\n  OPTIONAL: \"{{secrets.other}}\"\n").unwrap();
        substitute(&mut tree, &values(), &["secrets.*"], true).unwrap();
        assert_eq!(tree["count"], Yaml::Number(3.into()));
        assert_eq!(tree["gpu"], Yaml::Bool(true));
        assert_eq!(tree["providers"], serde_yaml_ng::from_str::<Yaml>("[codex, claude]").unwrap());
        assert_eq!(tree["name"].as_str(), Some("w-3"));
        assert!(tree.get("missing").is_none(), "an input that was not asked leaves its field out");
        let mut list: Yaml = serde_yaml_ng::from_str("items: [\"{{inputs.other}}\", \"{{inputs.title}}\"]\n").unwrap();
        substitute(&mut list, &values(), &[], true).unwrap();
        assert_eq!(list["items"].as_sequence().unwrap().len(), 1, "an unanswered list item disappears");
        assert_eq!(tree["secrets"]["KEY"].as_str(), Some("hub-my-api-openai_key"));
        assert!(tree["secrets"].get("OPTIONAL").is_none(), "a secret that was not given is left out");
        let mut legacy: Yaml = serde_yaml_ng::from_str("count: \"{{inputs.count}}\"\n").unwrap();
        substitute(&mut legacy, &values(), &[], false).unwrap();
        assert_eq!(legacy["count"].as_str(), Some("3"), "a v1-style environment keeps text");
    }

    #[test]
    fn paths_and_policies_match_without_indexes() {
        assert_eq!(join(&["files".into(), "[0]".into(), "source".into()]), "files[0].source");
        assert_eq!(pattern_of("files[12].source"), "files[].source");
        assert!(under("files[3].source", &["files[].source"]));
        assert!(under("secrets.KEY", &["secrets.*"]));
        assert!(under("admin.password", &["admin.password"]));
        assert!(!under("secrets_list", &["secrets.*"]));
        assert!(!under("environment.KEY", &["secrets.*"]));
        let found = strings(&serde_yaml_ng::from_str("a: x\nsecrets: {K: y}\nlist: [z]\n").unwrap(), &["secrets.*"]).unwrap();
        assert_eq!(found, vec![("x".to_owned(), "a".to_owned(), Place::Spec), ("y".to_owned(), "secrets.K".to_owned(), Place::SpecSecret), ("z".to_owned(), "list[0]".to_owned(), Place::Spec)]);
        assert!(strings(&serde_yaml_ng::from_str("\"{{inputs.x}}\": 1\n").unwrap(), &[]).unwrap_err().contains("not in names"));
    }
}
