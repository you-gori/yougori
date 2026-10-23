//! Placeholders: `{{inputs.ID}}`, `{{secrets.ID}}`, `{{instance}}`, `{{env.NAME}}` and
//! `{{public.NAME}}`. They are replaced inside string values after the YAML is parsed, in one
//! pass, so an answer can never change the structure of a file or bring in another placeholder.
use crate::manifest;
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placeholder {
    Instance,
    Input(String),
    Secret(String),
    Env(String),
    Public(String),
}

/// Where a string is: each placeholder is allowed in some places only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// Any string value of the project, except a `secrets:` value.
    Project,
    /// A value under an environment's `secrets:`.
    ProjectSecret,
    Public,
    Step,
    Output,
}

const KINDS: &str = "Use {{inputs.ID}}, {{secrets.ID}}, {{instance}}, {{env.NAME}} or {{public.NAME}}";

fn id(text: &str) -> bool {
    !text.is_empty() && text.len() <= 80 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn read(inner: &str) -> Option<Placeholder> {
    let inner = inner.trim();
    if inner == "instance" {
        return Some(Placeholder::Instance);
    }
    let (kind, name) = inner.split_once('.')?;
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

/// What a template declares, for checking its placeholders.
pub struct Known {
    /// Input ID and whether it is a secret.
    pub inputs: BTreeMap<String, bool>,
    pub environments: BTreeSet<String>,
    /// Environments with a `public:` entry.
    pub public: BTreeSet<String>,
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
                Some(true) => return Err(format!("{raw} would put a secret in plain text. Use {{{{secrets.{name}}}}} as a whole value under secrets: in the project.")),
                Some(false) => {}
            },
            Placeholder::Secret(name) => {
                if known.inputs.get(name) != Some(&true) {
                    return Err(format!("{raw} needs a secret input with id {name}."));
                }
                if place != Place::ProjectSecret || pieces.len() != 1 {
                    return Err(format!("{raw} works only as a whole value under an environment's secrets: in the project, for example secrets: {{API_KEY: \"{raw}\"}}."));
                }
            }
            Placeholder::Env(name) => {
                if !known.environments.contains(name) {
                    return Err(format!("{raw} names no environment. {}", list("The project's environments are", known.environments.iter())));
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
        }
    }
    Ok(())
}

fn list<'a>(said: &str, names: impl Iterator<Item = &'a String>) -> String {
    let names: Vec<&str> = names.map(String::as_str).collect();
    if names.is_empty() { format!("{said}: none.") } else { format!("{said}: {}.", names.join(", ")) }
}

/// The values placeholders take in one instance.
#[derive(Clone, Debug, Default)]
pub struct Values {
    pub instance: String,
    /// Answers to inputs that were asked; an input that was not asked is empty.
    pub inputs: BTreeMap<String, String>,
    /// Secret input ID to the deployment secret's name.
    pub secrets: BTreeMap<String, String>,
    /// Environment name to its public address, once known.
    pub public: BTreeMap<String, String>,
    /// Environment name to the sandbox's real name, once the engine made it (a replaced sandbox
    /// is called `INSTANCE-NAME-1a2b3c`); otherwise `INSTANCE-NAME`.
    pub names: BTreeMap<String, String>,
}

/// The deployment secret that holds a secret answer: `hub-INSTANCE-ID`.
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
                Placeholder::Env(name) => values.names.get(&name).cloned().unwrap_or_else(|| format!("{}-{name}", values.instance)),
                Placeholder::Public(name) => values.public.get(&name).cloned().unwrap_or_else(|| "(not public)".into()),
            }),
        }
    }
    Ok(out)
}

/// Changes a run makes to the project besides its placeholders.
#[derive(Clone, Debug, Default)]
pub struct Adjust {
    /// Run without a GPU: `type: gpu` becomes a container and `gpu: true` is turned off.
    pub without_gpu: bool,
    /// Extra secret bindings per environment, such as a tool's API key.
    pub secrets: BTreeMap<String, BTreeMap<String, String>>,
}

/// The host ports a project fixes (`8080:80`), as `ENVIRONMENT HOST:CONTAINER`. Two copies of a
/// template could never both start with one, so a run opens container ports only.
pub fn host_ports(project: &manifest::Project) -> Vec<String> {
    project.environments.iter().flat_map(|(name, environment)| {
        environment.ports.iter().filter_map(move |port| match port.values() {
            Ok((guest, Some(host))) => Some(format!("{name} {host}:{guest}")),
            _ => None,
        })
    }).collect()
}

/// Every port as the container port alone: Yougori then picks a free port on this computer.
fn container_ports(environment: &mut serde_yaml_ng::Mapping) {
    let Some(ports) = environment.get_mut("ports").and_then(Yaml::as_sequence_mut) else { return };
    for port in ports.iter_mut() {
        if let Ok((guest, _)) = serde_yaml_ng::from_value::<manifest::Port>(port.clone()).and_then(|p| p.values().map_err(serde::de::Error::custom)) {
            *port = Yaml::Number(guest.into());
        }
    }
}

/// Every string scalar of a parsed YAML tree with where it is, for checks.
pub fn strings(value: &Yaml) -> Result<Vec<(String, Place)>, String> {
    let mut found = Vec::new();
    collect(value, &mut Vec::new(), &mut found)?;
    Ok(found)
}

fn key_text(key: &Yaml) -> String {
    match key {
        Yaml::String(text) => text.clone(),
        Yaml::Number(number) => number.to_string(),
        Yaml::Bool(value) => value.to_string(),
        _ => String::from("?"),
    }
}

fn secret_value(path: &[String]) -> bool {
    path.len() == 4 && path[0] == "environments" && path[2] == "secrets"
}

fn collect(value: &Yaml, path: &mut Vec<String>, found: &mut Vec<(String, Place)>) -> Result<(), String> {
    match value {
        Yaml::String(text) => found.push((text.clone(), if secret_value(path) { Place::ProjectSecret } else { Place::Project })),
        Yaml::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                collect(item, path, found)?;
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
                collect(item, path, found)?;
                path.pop();
            }
        }
        Yaml::Tagged(tagged) => collect(&tagged.value, path, found)?,
        _ => {}
    }
    Ok(())
}

fn substitute(value: &mut Yaml, path: &mut Vec<String>, values: &Values) -> Result<(), String> {
    match value {
        Yaml::String(text) => *text = render(text, values)?,
        Yaml::Sequence(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                path.push(index.to_string());
                substitute(item, path, values)?;
                path.pop();
            }
        }
        Yaml::Mapping(map) => {
            let mut unanswered = Vec::new();
            for (key, item) in map.iter_mut() {
                let name = key_text(key);
                if name.contains("{{") {
                    return Err(format!("Placeholders work in values, not in names: {}.", short(&name)));
                }
                path.push(name);
                // An optional secret that was not given leaves its binding out, rather than
                // naming a deployment secret that does not exist.
                let missing = secret_value(path)
                    && item.as_str().and_then(|text| match pieces(text).ok()?.as_slice() {
                        [Piece::Placeholder(Placeholder::Secret(name), _)] => Some(!values.secrets.contains_key(name)),
                        _ => None,
                    }) == Some(true);
                if missing {
                    unanswered.push(key.clone());
                } else {
                    substitute(item, path, values)?;
                }
                path.pop();
            }
            for key in unanswered {
                map.remove(&key);
            }
        }
        Yaml::Tagged(tagged) => substitute(&mut tagged.value, path, values)?,
        _ => {}
    }
    Ok(())
}

/// The project an instance runs: placeholders replaced in string values, the instance's name as
/// the project name, and any run adjustments; then checked with the same strict rules as
/// `yougori up`. Returns the YAML to write and the parsed project.
pub fn project(text: &str, values: &Values, adjust: &Adjust) -> Result<(String, manifest::Project), String> {
    let mut tree: Yaml = serde_yaml_ng::from_str(text).map_err(|e| format!("Invalid yougori.yaml: {e}"))?;
    substitute(&mut tree, &mut Vec::new(), values)?;
    let root = tree.as_mapping_mut().ok_or("yougori.yaml must be a mapping with project: and environments:")?;
    root.insert(Yaml::String("project".into()), Yaml::String(values.instance.clone()));
    if let Some(environments) = root.get_mut("environments").and_then(Yaml::as_mapping_mut) {
        for (name, environment) in environments.iter_mut() {
            let Some(environment) = environment.as_mapping_mut() else { continue };
            container_ports(environment);
            if adjust.without_gpu {
                if environment.get("type").and_then(Yaml::as_str) == Some("gpu") {
                    environment.insert("type".into(), "container".into());
                }
                if environment.get("gpu").and_then(Yaml::as_bool) == Some(true) {
                    environment.insert("gpu".into(), false.into());
                }
            }
            if let Some(extra) = adjust.secrets.get(&key_text(name)) {
                let secrets = environment.entry("secrets".into()).or_insert_with(|| Yaml::Mapping(Default::default()));
                let secrets = secrets.as_mapping_mut().ok_or("secrets: must be a mapping of variable names to secret names")?;
                for (variable, reference) in extra {
                    secrets.insert(variable.as_str().into(), reference.as_str().into());
                }
            }
        }
    }
    let yaml = serde_yaml_ng::to_string(&tree).map_err(|e| e.to_string())?;
    let parsed = manifest::parse(&yaml)?;
    Ok((yaml, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> Known {
        Known {
            inputs: [("access".to_owned(), false), ("domain".to_owned(), false), ("openai_key".to_owned(), true)].into(),
            environments: ["web".to_owned(), "paid".to_owned()].into(),
            public: ["web".to_owned()].into(),
        }
    }

    #[test]
    fn placeholders_are_checked_for_where_they_are() {
        let known = known();
        assert!(check("yougori codex --environment {{env.paid}} for {{ instance }}", Place::Step, &known).is_ok());
        assert!(check("{{inputs.access}}", Place::Public, &known).is_ok());
        assert!(check("{{public.web}}", Place::Output, &known).is_ok());
        assert!(check("{{secrets.openai_key}}", Place::ProjectSecret, &known).is_ok());
        for (text, place, said) in [
            ("{{public.web}}", Place::Step, "works only in outputs"),
            ("{{public.paid}}", Place::Output, "needs a public: entry"),
            ("{{secrets.openai_key}}", Place::Project, "works only as a whole value under an environment's secrets:"),
            ("prefix-{{secrets.openai_key}}", Place::ProjectSecret, "works only as a whole value"),
            ("{{secrets.access}}", Place::ProjectSecret, "needs a secret input with id access"),
            ("{{inputs.openai_key}}", Place::Project, "would put a secret in plain text"),
            ("{{inputs.nope}}", Place::Project, "names no input. The inputs are: access, domain, openai_key."),
            ("{{env.db}}", Place::Step, "names no environment. The project's environments are: paid, web."),
            ("{{user.name}}", Place::Step, "is not a placeholder"),
            ("{{ .Values.x }}", Place::Project, "is not a placeholder"),
            ("open {{inputs.access", Place::Step, "without }}"),
        ] {
            let error = check(text, place, &known).unwrap_err();
            assert!(error.contains(said), "{text}: {error}");
        }
    }

    fn values() -> Values {
        Values {
            instance: "my-api".into(),
            inputs: [("title".to_owned(), "x".to_owned())].into(),
            secrets: [("openai_key".to_owned(), secret_name("my-api", "openai_key"))].into(),
            public: [("web".to_owned(), "https://a.trycloudflare.com".to_owned())].into(),
            names: BTreeMap::new(),
        }
    }

    #[test]
    fn rendering_fills_values_once() {
        let mut values = values();
        values.inputs.insert("title".into(), "{{instance}} and {{inputs.title}}".into());
        assert_eq!(render("[{{inputs.title}}]", &values).unwrap(), "[{{instance}} and {{inputs.title}}]", "an answer is never expanded again");
        assert_eq!(render("{{env.web}} {{instance}} {{public.web}} {{public.db}} '{{inputs.unasked}}'", &values).unwrap(),
            "my-api-web my-api https://a.trycloudflare.com (not public) ''");
        assert_eq!(render("{{secrets.openai_key}}", &values).unwrap(), "hub-my-api-openai_key");
    }

    const PROJECT: &str = r#"project: ignored-name
environments:
  web:
    image: node:24
    environment:
      TITLE: "{{inputs.title}}"
      WHERE: "{{env.web}}"
    secrets:
      OPENAI_API_KEY: "{{secrets.openai_key}}"
      OPTIONAL_KEY: "{{secrets.optional_key}}"
    ports: ["3000"]
  ai:
    type: gpu
    image: ubuntu:24.04
"#;

    #[test]
    fn answers_cannot_change_the_structure_of_the_project() {
        for answer in [
            "line one\nproject: evil\nenvironments: {}",
            "key: value",
            "{{instance}}",
            "\"quoted\" and 'single'",
            "- item",
            "&anchor *alias !!tag",
            "# not a comment",
            "",
        ] {
            let mut values = values();
            values.inputs.insert("title".into(), answer.into());
            let (yaml, parsed) = project(PROJECT, &values, &Adjust::default()).unwrap();
            assert_eq!(parsed.project, "my-api", "the instance name replaces the project's own");
            assert_eq!(parsed.environments.keys().collect::<Vec<_>>(), ["ai", "web"]);
            let web = &parsed.environments["web"];
            assert_eq!(web.environment["TITLE"], answer, "{yaml}");
            assert_eq!(web.environment["WHERE"], "my-api-web");
            assert_eq!(web.environment.len(), 2);
            assert_eq!(web.secrets.get("OPENAI_API_KEY").map(String::as_str), Some("hub-my-api-openai_key"));
            assert!(!web.secrets.contains_key("OPTIONAL_KEY"), "an optional secret that was not given is left out");
            assert_eq!(crate::manifest::parse(&yaml).unwrap(), parsed);
        }
    }

    #[test]
    fn a_run_without_a_gpu_and_tool_keys_adjust_the_project() {
        let adjust = Adjust {
            without_gpu: true,
            secrets: [("web".to_owned(), [("AIDER_KEY".to_owned(), "hub-my-api-key-aider".to_owned())].into())].into(),
        };
        let (_, parsed) = project(PROJECT, &values(), &adjust).unwrap();
        assert_eq!(parsed.environments["ai"].kind, "container");
        assert!(!parsed.environments["ai"].gpu);
        assert_eq!(parsed.environments["web"].secrets["AIDER_KEY"], "hub-my-api-key-aider");
        let (_, kept) = project(PROJECT, &values(), &Adjust::default()).unwrap();
        assert_eq!(kept.environments["ai"].kind, "gpu");
    }

    #[test]
    fn every_port_opens_as_a_container_port_so_copies_never_clash() {
        let text = "project: x\nenvironments:\n  web:\n    image: nginx\n    ports: [80, \"8080:81\", \"127.0.0.1:8443:443\", \"9000/tcp\", {target: 3000, published: 3001}]\n";
        let raw: crate::manifest::Project = serde_yaml_ng::from_str(text).unwrap();
        assert_eq!(host_ports(&raw), ["web 8080:81", "web 8443:443", "web 3001:3000"]);
        let (_, parsed) = project(text, &values(), &Adjust::default()).unwrap();
        let ports: Vec<_> = parsed.environments["web"].ports.iter().map(|p| p.values().unwrap()).collect();
        assert_eq!(ports, [(80, None), (81, None), (443, None), (9000, None), (3000, None)]);
        assert!(host_ports(&parsed).is_empty());
    }

    #[test]
    fn env_placeholders_name_the_real_sandbox_once_known() {
        let mut values = values();
        assert_eq!(render("{{env.web}}", &values).unwrap(), "my-api-web");
        values.names.insert("web".into(), "my-api-web-1a2b3c".into());
        assert_eq!(render("yougori terminal {{env.web}}", &values).unwrap(), "yougori terminal my-api-web-1a2b3c");
    }

    #[test]
    fn placeholders_in_names_and_invalid_results_are_refused() {
        let named = "project: x\nenvironments:\n  web:\n    image: alpine\n    environment:\n      \"{{inputs.title}}\": value\n";
        assert!(project(named, &values(), &Adjust::default()).unwrap_err().contains("not in names"));
        assert!(strings(&serde_yaml_ng::from_str(named).unwrap()).unwrap_err().contains("not in names"));
        let mut bad = values();
        bad.inputs.insert("title".into(), "has space".into());
        let image = "project: x\nenvironments:\n  web:\n    image: \"{{inputs.title}}\"\n";
        assert!(project(image, &bad, &Adjust::default()).unwrap_err().contains("an OCI image is required"), "the strict project rules still apply");
        let places = strings(&serde_yaml_ng::from_str(PROJECT).unwrap()).unwrap();
        assert!(places.contains(&("{{secrets.openai_key}}".to_owned(), Place::ProjectSecret)));
        assert!(places.contains(&("{{inputs.title}}".to_owned(), Place::Project)));
    }
}
