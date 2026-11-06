//! The versioned template and project formats. No format_version means the v1 format.
//!
//! `yougori-template.yaml` is the package entry point and `yougori.yaml` the project. A file
//! that says `format_version: 2` is read here; a file without one is the v1 format, which the
//! clients' existing code keeps reading. Every v1 field keeps its name and meaning in format 2.
//!
//! Nothing here reads a file system: a package is a map of paths to bytes, so a folder on this
//! computer, a download and an upload are checked by exactly the same code. Every problem is
//! listed, each saying what to change.
use crate::{
    capability::{self, Group},
    condition::{self, Condition},
    dto::Diagnostic,
    limits,
    pattern::Pattern,
    placeholder::{self, Known, Place, Typed, Values},
    resource::{self, Kind},
    text,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

pub const TEMPLATE_FILE: &str = "yougori-template.yaml";
pub const TOOL_FILE: &str = "yougori-tool.yaml";
pub const MODELS_FILE: &str = "yougori-models.yaml";
pub const PROJECT_FILE: &str = "yougori.yaml";

/// The format this crate writes and reads in full.
pub const FORMAT_VERSION: u64 = 2;

/// The first Yougori release that reads format 2. A format 2 template must require at least
/// this, so an older Yougori refuses it before creating anything.
pub const MINIMUM_YOUGORI: &str = "1.2.0";

pub const LICENSES: &[&str] = &[
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0", "Zlib",
    "BSL-1.0", "MPL-2.0", "EPL-2.0", "EUPL-1.2", "Artistic-2.0", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
];

pub const PLATFORMS: &[&str] = &["windows-x86_64", "windows-aarch64", "macos-x86_64", "macos-aarch64", "linux-x86_64", "linux-aarch64"];

/// The tools every Yougori installs by name.
pub const BUILT_IN_TOOLS: &[&str] = &["codex", "claude", "gemini", "ollama", "opencode", "kilo", "openclaw"];

/// The built-in tools with a subscription sign-in flow.
pub const SUBSCRIPTION_TOOLS: &[&str] = &["codex", "claude", "gemini", "opencode", "kilo"];

/// The standard views a setup page can show beside its overview, activity and settings. A
/// template lists the ones that apply; nothing else is rendered from template text.
pub const VIEWS: &[&str] = &[
    "computers", "workers", "models", "workspaces", "people", "credentials", "policies", "approvals", "audit",
    "findings", "reports", "attempts", "jobs", "queues", "files", "storage", "api", "keys", "usage", "costs",
    "budget", "publications", "teams", "images", "quotas", "logs", "diagram",
];

/// What a name must look like, for messages.
pub const NAME_RULE: &str = "lowercase letters, digits, - or _, starting with a letter or digit, at most 64 characters";

pub const ID_RULE: &str = "lowercase letters, digits or _, starting with a letter (at most 32)";

pub type Files = BTreeMap<String, Vec<u8>>;
pub type Problems = Vec<Diagnostic>;

pub(crate) fn problem(code: &'static str, message: impl Into<String>) -> Diagnostic {
    Diagnostic::error(code, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatVersion {
    V1,
    V2,
}

impl FormatVersion {
    pub fn number(self) -> u64 {
        match self {
            FormatVersion::V1 => 1,
            FormatVersion::V2 => 2,
        }
    }
}

/// Reads YAML once its size is known to be safe: every value is counted, with aliases expanded,
/// before any tree is built, and a file past [`limits::YAML_VALUES`] is refused. Everything that
/// reads a template, project or lock file reads it through this.
pub fn read_yaml<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, String> {
    let text = text.trim_start_matches('\u{feff}');
    yaml_values(text)?;
    serde_yaml_ng::from_str(text).map_err(|e| e.to_string())
}

/// YAML text of a template or a project, as generated and exported packages write it.
pub fn write_yaml<T: Serialize>(value: &T) -> Result<String, String> {
    serde_yaml_ng::to_string(value).map_err(|e| e.to_string())
}

/// A JSON value as a YAML one, for a default or a spec.
pub fn yaml_of(value: &Json) -> Yaml {
    serde_yaml_ng::to_value(value).unwrap_or(Yaml::Null)
}

/// How many values `text` holds with its aliases expanded, or the refusal once that passes the
/// limit. Nothing is kept while counting, so a hostile file costs little to refuse.
pub fn yaml_values(text: &str) -> Result<usize, String> {
    use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
    use std::cell::Cell;

    #[derive(Clone, Copy)]
    struct Count<'a>(&'a Cell<usize>);
    impl Count<'_> {
        fn one<E: de::Error>(self) -> Result<(), E> {
            let seen = self.0.get() + 1;
            self.0.set(seen);
            if limits::YAML_VALUES.allows(seen) { Ok(()) } else { Err(E::custom(format!("{} Remove repeated aliases or split the file.", limits::YAML_VALUES.exceeded(seen)))) }
        }
    }
    impl<'de> DeserializeSeed<'de> for Count<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Count<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("YAML")
        }
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
            self.one()
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
            self.one()
        }
        fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> {
            self.one()
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
            self.one()
        }
        fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> {
            self.one()
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
            self.one()
        }
        fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
            self.one()
        }
        fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<(), E> {
            self.one()
        }
        fn visit_unit<E: de::Error>(self) -> Result<(), E> {
            self.one()
        }
        fn visit_none<E: de::Error>(self) -> Result<(), E> {
            self.one()
        }
        fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
        fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            self.one()?;
            while seq.next_element_seed(self)?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            self.one()?;
            while map.next_key_seed(self)?.is_some() {
                map.next_value_seed(self)?;
            }
            Ok(())
        }
        // A tagged value (`!tag value`): the tag and its value.
        fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<(), A::Error> {
            let ((), value) = data.variant_seed(self)?;
            value.newtype_variant_seed(self)
        }
    }

    let seen = Cell::new(0);
    for document in serde_yaml_ng::Deserializer::from_str(text) {
        Count(&seen).deserialize(document).map_err(|e| e.to_string())?;
    }
    Ok(seen.get())
}

/// Which format a template or project file is written in, from its `format_version` alone:
/// absent (or 1) is v1, 2 is v2, and anything else is a template this Yougori does not read.
/// That refusal comes before anything is created, with the same words everywhere.
pub fn format_version(text: &str) -> Result<FormatVersion, Diagnostic> {
    if let Err(error) = yaml_values(text.trim_start_matches('\u{feff}')) {
        return Err(problem(if error.contains(limits::YAML_VALUES.what) { "limit_exceeded" } else { "invalid_yaml" }, format!("The file is not valid YAML: {error}")));
    }
    let value: Yaml = serde_yaml_ng::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| problem("invalid_yaml", format!("The file is not valid YAML: {e}")))?;
    let Some(map) = value.as_mapping() else {
        return Err(problem("invalid_format", "The file must be a mapping of fields."));
    };
    match map.get("format_version") {
        None | Some(Yaml::Null) => Ok(FormatVersion::V1),
        Some(Yaml::Number(n)) if n.as_u64() == Some(1) => Ok(FormatVersion::V1),
        Some(Yaml::Number(n)) if n.as_u64() == Some(2) => Ok(FormatVersion::V2),
        Some(Yaml::String(s)) if s.trim() == "1" => Ok(FormatVersion::V1),
        Some(Yaml::String(s)) if s.trim() == "2" => Ok(FormatVersion::V2),
        Some(other) => Err(needs_newer(&scalar_text(other).unwrap_or_else(|| "?".into()))),
    }
}

/// The refusal for a format this Yougori does not read.
pub fn needs_newer(found: &str) -> Diagnostic {
    problem("needs_newer_yougori", format!("This template needs a newer Yougori. It is written in format {}, and this Yougori reads formats 1 and 2. Update with yougori update.", text::shown(found)))
}

/// Any YAML scalar as text, so `version: 1.0` is refused as a version rather than as a type.
fn scalar<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    use serde::de::Error;
    Ok(match Option::<Yaml>::deserialize(deserializer)? {
        None | Some(Yaml::Null) => None,
        Some(Yaml::String(text)) => Some(text),
        Some(Yaml::Number(number)) => Some(number.to_string()),
        Some(Yaml::Bool(value)) => Some(value.to_string()),
        Some(_) => return Err(D::Error::custom("expected a single value, not a list or a mapping")),
    })
}

pub(crate) fn scalar_text(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(text) => Some(text.clone()),
        Yaml::Number(number) => Some(number.to_string()),
        Yaml::Bool(value) => Some(if *value { "yes" } else { "no" }.into()),
        _ => None,
    }
}

// ---- The template file ----

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Template {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// One line under the title: "Workspaces for people on your computers."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<String>,
    /// Other names people search for: old product names, plain words.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changelog: Option<String>,
    /// The grid profile this template sets up (neo_grid, sandbox_grid, access_grid,
    /// swarm_mining_grid), when it is one of the four; ordinary templates leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Requires::is_empty")]
    pub requires: Requires,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityUse>,
    /// Installation-time bindings: a folder, a drive or a file the person chooses on their own
    /// computer when the setup is applied. Private to the installation; never in a public lock.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    /// Pinned components from other Hub templates, by the namespace their resources take.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub imports: BTreeMap<String, Import>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Input>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_options: BTreeMap<String, ToolOptions>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public: Vec<Public>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<Output>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<Retention>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub views: Vec<String>,
    /// The most the setup may use (`run.quotas`): totals of what it creates, each a number or an
    /// answer to a number question. A plan or change that would pass one is refused.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, Yaml>,
}

/// What a template's `limits:` may cap, with how a review says each.
pub const LIMITS: &[(&str, &str)] = &[
    ("cpu", "processor cores across its sandboxes"),
    ("memory_gb", "GB of memory across its sandboxes"),
    ("disk_gb", "GB of disk across its sandboxes"),
    ("sandboxes", "sandboxes"),
    ("jobs", "jobs"),
    ("models", "model services"),
    ("people", "people"),
    ("workspaces", "workspaces"),
    ("runs_per_day", "runs a day that events start, for each job"),
];

impl Template {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }
    /// The title, or the name when there is none.
    pub fn title(&self) -> &str {
        self.title.as_deref().filter(|title| !text::js_trim(title).is_empty()).unwrap_or_else(|| self.name())
    }
    pub fn version(&self) -> &str {
        self.version.as_deref().unwrap_or_default()
    }
    pub fn project_path(&self) -> &str {
        self.project.as_deref().unwrap_or(PROJECT_FILE)
    }
    /// The manifest the Hub stores: the parsed file as JSON, always with its kind.
    pub fn manifest(&self) -> Json {
        let mut value = serde_json::to_value(self).unwrap_or(Json::Null);
        value["kind"] = "template".into();
        value
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Requires {
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub yougori: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
}

impl Requires {
    pub fn is_empty(&self) -> bool {
        self.yougori.is_none() && self.gpu.is_none() && self.platforms.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<Choice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Yaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    /// Format 2: the capability group the question is shown under (one of the six group ids).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Format 2: whether the person running the template may change the answer. A fixed answer
    /// needs a default. Its requirements and permissions stay visible either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// How a template uses one capability from the registry.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityUse {
    pub id: String,
    #[serde(default)]
    pub selection: Selection,
    /// The person running the template cannot change the selection.
    #[serde(default)]
    pub locked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    /// Always part of the setup.
    #[default]
    Required,
    /// Off unless the person turns it on.
    Optional,
    /// On unless the person turns it off.
    Default,
}

impl Selection {
    pub fn id(self) -> &'static str {
        match self {
            Selection::Required => "required",
            Selection::Optional => "optional",
            Selection::Default => "default",
        }
    }
}

/// A pinned component: one version of one Hub template, with the digest of its files.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Import {
    /// `PUBLISHER/NAME`.
    pub item: String,
    #[serde(deserialize_with = "scalar")]
    pub version: Option<String>,
    pub digest: String,
    /// Answers to the component's inputs: fixed values, or `{{inputs.ID}}` and `{{secrets.ID}}`
    /// of this template. The component's questions are never asked again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, Yaml>,
    /// The component's optional capabilities that are turned on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
    #[serde(default)]
    pub signin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signin_when: Option<Yaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signin_hint: Option<String>,
    /// A choice input with values `computer` and `new`, asked before sandbox creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signin_source: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Public {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Output {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Format 2: a stable id for scripts (`yougori template status --format json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Format 2: shown once to the owner and never kept in public projections: an invitation, a
    /// key shown once.
    #[serde(default)]
    pub private: bool,
    /// Format 2: shown only when the condition holds, like a step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
}

/// An output after its checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckedOutput {
    pub key: Option<String>,
    pub label: String,
    pub value: String,
    pub private: bool,
    pub when: Option<Condition>,
}

/// An installation-time binding a template declares.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `folder`, `drive`, `file` or `resource`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// For type resource: the resource kind to choose from (grid, environment, model_service...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// For a grid: the profile it must have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
    /// For type folder: `false` lets the sandbox change files in the folder (asked again, as a
    /// consent, when the setup is applied). Default `true`: read only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// For type folder: `mount` (the sandbox reaches the folder itself, through `pc_access`) or
    /// `sync` (the sandbox keeps its own copy, kept in step through `sync`). Default `mount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// A binding after its checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckedBinding {
    pub id: String,
    pub kind: resource::BindingKind,
    /// For type resource: the kind of resource to choose.
    pub resource: Option<Kind>,
    pub profile: Option<capability::GridProfile>,
    pub question: String,
    pub hint: String,
    pub required: bool,
    pub when: Option<Condition>,
    /// For a folder: whether the sandbox may only read it. Other kinds: true.
    #[serde(default = "always")]
    pub read_only: bool,
    /// For a folder: how it reaches the sandbox. Other kinds: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<resource::FolderMode>,
}

fn always() -> bool {
    true
}

/// What happens to a setup's data when it stops or is removed. Deleting data is never a default:
/// it is a separate operation that names what it deletes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    #[serde(default)]
    pub on_stop: Keep,
    #[serde(default)]
    pub on_remove: Keep,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Keep {
    /// Keep the data.
    #[default]
    Keep,
    /// Ask what to do, with the data kept unless the person chooses otherwise.
    Ask,
}

impl Keep {
    pub fn id(self) -> &'static str {
        match self {
            Keep::Keep => "keep",
            Keep::Ask => "ask",
        }
    }
}

/// [`MODELS_FILE`]: where models started with `--template` go.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Models {
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub command: Vec<String>,
}

// ---- Tools ----

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changelog: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signin: Option<Signin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<Needs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<Service>,
    /// What the tool says it reaches once installed. A declaration for the review only: a
    /// sandbox gets what its own settings and the person's answers give it, never what a tool
    /// asks for here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<ToolAccess>,
    /// The variables the tool reads when it runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<ToolInput>,
    /// What the tool leaves in the sandbox for others to read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<ToolOutput>,
}

/// A tool's declared access, as its review shows it. Nothing here grants anything.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolAccess {
    /// Whether the tool reaches the internet once installed (`needs.internet` is what its
    /// installer needs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internet: Option<bool>,
    /// Folders inside the sandbox the tool writes to, as absolute paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<String>,
}

/// A variable a tool reads when it runs.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolInput {
    /// The environment variable's name.
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default)]
    pub required: bool,
    /// The value is a secret: it reaches the sandbox only through the person's own answers.
    #[serde(default)]
    pub secret: bool,
}

/// Something a tool leaves in the sandbox.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolOutput {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// Where in the sandbox it is written, as an absolute path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Signin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Needs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
    #[serde(default, deserialize_with = "scalar", skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internet: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Service {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Tool {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }
    pub fn title(&self) -> &str {
        self.title.as_deref().filter(|title| !text::js_trim(title).is_empty()).unwrap_or_else(|| self.name())
    }
    pub fn version(&self) -> &str {
        self.version.as_deref().unwrap_or_default()
    }
    pub fn signin_method(&self) -> &str {
        self.signin.as_ref().and_then(|s| s.method.as_deref()).unwrap_or("none")
    }
    /// The variable an API key goes into, for tools that sign in with one.
    pub fn key_variable(&self) -> Option<&str> {
        (self.signin_method() == "api-key").then(|| self.signin.as_ref().and_then(|s| s.variable.as_deref())).flatten()
    }
    pub fn gpu(&self) -> &str {
        self.needs.as_ref().and_then(|n| n.gpu.as_deref()).unwrap_or("none")
    }
    /// The memory the tool needs, in GB, when it says.
    pub fn memory_gb(&self) -> Option<f64> {
        let memory = self.needs.as_ref()?.memory.as_deref()?;
        gib(&Json::String(memory.into())).ok().or_else(|| memory.parse::<f64>().ok().filter(|n| *n > 0.0))
    }
    pub fn manifest(&self) -> Json {
        let mut value = serde_json::to_value(self).unwrap_or(Json::Null);
        value["kind"] = "tool".into();
        value
    }
    /// What the tool declares it reaches, one short phrase each, for a review: the internet,
    /// the folders it writes and the variables it reads. Empty when it declares nothing.
    pub fn declared_access(&self) -> Vec<String> {
        let mut said = Vec::new();
        if let Some(access) = &self.access {
            match access.internet {
                Some(true) => said.push("uses the internet".to_owned()),
                Some(false) => said.push("does not use the internet".to_owned()),
                None => {}
            }
            if !access.folders.is_empty() {
                said.push(format!("writes {}", access.folders.join(", ")));
            }
        }
        let secrets: Vec<&str> = self.inputs.iter().filter(|input| input.secret).map(|input| input.name.as_str()).collect();
        let plain: Vec<&str> = self.inputs.iter().filter(|input| !input.secret).map(|input| input.name.as_str()).collect();
        if !secrets.is_empty() {
            said.push(format!("reads the secret{} {}", if secrets.len() == 1 { "" } else { "s" }, secrets.join(", ")));
        }
        if !plain.is_empty() {
            said.push(format!("reads {}", plain.join(", ")));
        }
        said
    }
}

/// A size in GiB from a number or a text such as `512MB` or `4GB`.
pub fn gib(value: &Json) -> Result<f64, String> {
    if let Some(n) = value.as_f64() {
        return if n.is_finite() && n > 0.0 { Ok(n) } else { Err("Resource values must be positive".into()) };
    }
    let s = value.as_str().ok_or("Use a number in GiB, or a size such as 512MB / 4GB")?.trim().to_ascii_lowercase();
    for (suffix, factor) in [("gib", 1.0), ("gb", 1.0), ("g", 1.0), ("mib", 1.0 / 1024.0), ("mb", 1.0 / 1024.0), ("m", 1.0 / 1024.0)] {
        if let Some(n) = s.strip_suffix(suffix) {
            return gib(&serde_json::json!(n.trim().parse::<f64>().map_err(|_| "Invalid resource size")? * factor));
        }
    }
    Err("Use a number in GiB, or a size such as 512MB / 4GB".into())
}

// ---- The project file ----

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Project {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u64>,
    #[serde(default)]
    pub project: String,
    /// v1-style environments, kept as written: the v1 fields with their v1 meaning.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environments: BTreeMap<String, Yaml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<Yaml>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub publish: BTreeMap<String, Yaml>,
    /// Format 2: typed resources by logical id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, Resource>,
}

/// One resource as written in a v2 project.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: String,
    /// The template capability this resource belongs to; left out of the plan when that
    /// capability is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Readiness only: these resources exist before this one is created. Never connectivity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Yaml>,
    /// An existing resource of another setup, attached by its stable ids and never destroyed by
    /// this setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrow: Option<Borrow>,
    /// What happens to this resource's data on stop and removal; the template's default otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<Retention>,
    #[serde(default)]
    pub spec: Yaml,
}

/// `GridProfile` by its id.
pub fn grid_profile(text: &str) -> Option<capability::GridProfile> {
    capability::GridProfile::GRIDS.into_iter().chain([capability::GridProfile::Generic]).find(|profile| profile.id() == text)
}

/// An existing resource of another setup: named by the setup's and the resource's stable ids in
/// a private template, or by a binding of type resource in a public one, chosen when the setup
/// is applied. The borrowing setup never destroys it.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Borrow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

impl Borrow {
    /// Why the borrow is malformed, if it is.
    pub fn problem(&self) -> Option<String> {
        match (&self.setup, &self.resource, &self.binding) {
            (Some(_), Some(_), None) | (None, None, Some(_)) => None,
            _ => Some("borrow names either setup: ID and resource: ID, or binding: ID of a binding of type resource".into()),
        }
    }
}

/// A v1 connection as written: `web -> db`, or a detailed mapping.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyConnection {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

pub fn connection(value: &Yaml) -> Result<LegacyConnection, String> {
    match value {
        Yaml::String(text) => {
            let (from, to) = text.split_once("->").ok_or("Connections use 'frontend -> database'")?;
            Ok(LegacyConnection { from: from.trim().to_owned(), to: to.trim().to_owned(), ports: Vec::new(), permissions: Vec::new() })
        }
        Yaml::Mapping(_) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Detailed {
                from: String,
                to: String,
                #[serde(default)]
                ports: Vec<u16>,
                #[serde(default)]
                permissions: Vec<String>,
            }
            let detailed: Detailed = serde_yaml_ng::from_value(value.clone()).map_err(|e| format!("a connection is from:, to:, ports: and permissions: ({e})"))?;
            Ok(LegacyConnection { from: detailed.from, to: detailed.to, ports: detailed.ports, permissions: detailed.permissions })
        }
        _ => Err("Connections use 'frontend -> database'".into()),
    }
}

// ---- Questions ----

/// The kinds of question a template asks. Format 2 keeps the v1 kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionKind {
    Choice,
    #[serde(rename = "multichoice")]
    MultiChoice,
    Text,
    Number,
    Secret,
    Domain,
    #[serde(rename = "yesno")]
    YesNo,
}

impl QuestionKind {
    pub fn read(text: &str) -> Option<QuestionKind> {
        Some(match text {
            "choice" => QuestionKind::Choice,
            "multichoice" => QuestionKind::MultiChoice,
            "text" => QuestionKind::Text,
            "number" => QuestionKind::Number,
            "secret" => QuestionKind::Secret,
            "domain" => QuestionKind::Domain,
            "yesno" => QuestionKind::YesNo,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            QuestionKind::Choice => "choice",
            QuestionKind::MultiChoice => "multichoice",
            QuestionKind::Text => "text",
            QuestionKind::Number => "number",
            QuestionKind::Secret => "secret",
            QuestionKind::Domain => "domain",
            QuestionKind::YesNo => "yesno",
        }
    }
    /// The type an answer takes when it stands alone in a typed spec.
    pub fn typed(self) -> Typed {
        match self {
            QuestionKind::Number => Typed::Number,
            QuestionKind::YesNo => Typed::Bool,
            QuestionKind::MultiChoice => Typed::List,
            _ => Typed::Text,
        }
    }
}

/// One option of a choice question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceOption {
    pub value: String,
    pub label: String,
    pub hint: String,
}

/// A question after its checks, ready to be asked.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub question: String,
    pub kind: QuestionKind,
    pub required: bool,
    pub default: Option<String>,
    pub when: Option<Condition>,
    pub hint: String,
    pub choices: Vec<ChoiceOption>,
    pub pattern: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub min_length: Option<usize>,
    pub group: Option<Group>,
    pub editable: bool,
}

/// Values that must never be the default of a question that holds a credential.
///
/// Note that this is the opposite verdict from `scan::placeholder` in the CLI, which uses much the
/// same words to decide that some text is *not* a real key, so a scan can pass over it. The words
/// are the same; what they mean here is the reverse. A placeholder in a README is doing its job.
/// The same word as the default of a password question is a live password that someone will keep,
/// because defaults are what people accept.
const DEMONSTRATION_PASSWORDS: &[&str] = &[
    "changeme", "change-me", "change_me", "change me", "password", "password1", "passwd", "pass",
    "pass123", "admin", "admin123", "administrator", "root", "toor", "secret", "letmein",
    "welcome", "default", "test", "testing", "demo", "example", "sample", "qwerty", "abc123",
    "123456", "1234567", "12345678", "123456789", "000000", "guest", "user", "temp", "temporary",
];

/// Fragments that mark text as a stand-in rather than a value, wherever they appear in it.
const STAND_IN_FRAGMENTS: &[&str] = &[
    "changeme", "change-me", "change_me", "your-", "your_", "yourpassword", "placeholder",
    "replace", "redacted", "dummy", "xxxxxx", "******", "<", "${", "todo", "fixme",
];

/// Whether `text` is a demonstration password rather than a real one.
pub fn demonstration_password(text: &str) -> bool {
    let plain = text.trim().to_lowercase();
    if plain.is_empty() {
        return false;
    }
    DEMONSTRATION_PASSWORDS.contains(&plain.as_str())
        || STAND_IN_FRAGMENTS.iter().any(|fragment| plain.contains(fragment))
}

/// Whether a question holds a credential, by what it is called and what it asks. Secrets cannot
/// have a default at all, so this is about the ordinary text questions that nonetheless end up
/// being a password: `admin_password`, `api_key`, `join token`.
///
/// It is a reading of words, so it is neither complete nor certain. It is used only to refuse a
/// default that is a demonstration password, where being wrong costs a template author one clear
/// message telling them to leave the default out.
pub fn credential_question(id: &str, question: &str) -> bool {
    let words = format!("{id} {question}").to_lowercase();
    ["password", "passphrase", "secret", "token", "credential", "api key", "api_key", "apikey", "private key", "private_key"]
        .iter()
        .any(|word| words.contains(word))
}

fn number_text(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e15 { format!("{}", number as i64) } else { number.to_string() }
}

impl Question {
    /// Whether this question is asked, given the answers so far.
    pub fn asked(&self, answers: &BTreeMap<String, String>) -> bool {
        self.when.as_ref().is_none_or(|when| when.holds(answers))
    }

    /// An answer as stored, or why it is not one. `domains` lists the saved domains when known.
    pub fn answer(&self, given: &str, domains: Option<&[String]>) -> Result<String, String> {
        let given = if self.kind == QuestionKind::Secret { given } else { given.trim() };
        if self.kind == QuestionKind::MultiChoice {
            if given.is_empty() && !self.required {
                return Ok(String::new());
            }
            let selected: BTreeSet<&str> = given.split(',').map(str::trim).collect();
            if selected.iter().any(|v| !self.choices.iter().any(|c| c.value == *v)) {
                return Err(format!("Choose from: {} (separate values with commas).", self.choices.iter().map(|c| c.value.as_str()).collect::<Vec<_>>().join(", ")));
            }
            return Ok(self.choices.iter().filter(|c| selected.contains(c.value.as_str())).map(|c| c.value.as_str()).collect::<Vec<_>>().join(","));
        }
        if given.is_empty() {
            return Err("Give an answer.".into());
        }
        match self.kind {
            QuestionKind::MultiChoice => unreachable!(),
            QuestionKind::Choice => self
                .choices
                .iter()
                .find(|choice| choice.value == given || choice.label.eq_ignore_ascii_case(given))
                .map(|choice| choice.value.clone())
                .ok_or_else(|| format!("Choose one of: {}.", self.choices.iter().map(|c| c.value.as_str()).collect::<Vec<_>>().join(", "))),
            QuestionKind::YesNo => match given.to_ascii_lowercase().as_str() {
                "yes" | "y" | "true" => Ok("yes".into()),
                "no" | "n" | "false" => Ok("no".into()),
                _ => Err("Answer yes or no.".into()),
            },
            QuestionKind::Number => {
                let number: f64 = given.parse().ok().filter(|n: &f64| n.is_finite()).ok_or("Give a number, such as 3 or 2.5.")?;
                if self.min.is_some_and(|min| number < min) || self.max.is_some_and(|max| number > max) {
                    return Err(match (self.min, self.max) {
                        (Some(min), Some(max)) => format!("Give a number from {} to {}.", number_text(min), number_text(max)),
                        (Some(min), None) => format!("Give a number of at least {}.", number_text(min)),
                        (_, max) => format!("Give a number of at most {}.", number_text(max.unwrap_or_default())),
                    });
                }
                Ok(number_text(number))
            }
            QuestionKind::Text => {
                if self.min_length.is_some_and(|min| given.chars().count() < min) {
                    return Err(format!("Use at least {} characters.", self.min_length.unwrap_or_default()));
                }
                if given.chars().count() > limits::TEXT_ANSWER_CHARS.max {
                    return Err(format!("Keep the answer to {} characters.", limits::TEXT_ANSWER_CHARS.max));
                }
                if given.chars().any(|c| c.is_control() && c != '\t') {
                    return Err("Give one line of text.".into());
                }
                if let Some(pattern) = &self.pattern {
                    if !Pattern::parse(pattern)?.matches(given)? {
                        return Err(if self.hint.is_empty() { "That answer does not have the form this question asks for.".into() } else { format!("That answer does not have the form this question asks for. {}", self.hint) });
                    }
                }
                Ok(given.to_owned())
            }
            QuestionKind::Domain => {
                let name = given.to_ascii_lowercase();
                if !hostname(&name) {
                    return Err("Give a domain name such as app.example.com.".into());
                }
                match domains {
                    Some(saved) if !saved.iter().any(|d| d.eq_ignore_ascii_case(&name)) => Err(if saved.is_empty() {
                        "No domains are saved on this computer. Save one with yougori domain add HOST --tunnel-port PORT --file - --yes, then run this again.".into()
                    } else {
                        format!("{name} is not a saved domain. Saved domains: {}.", saved.join(", "))
                    }),
                    _ => Ok(name),
                }
            }
            QuestionKind::Secret => {
                if self.min_length.is_some_and(|min| given.chars().count() < min) {
                    return Err(format!("Use at least {} characters.", self.min_length.unwrap_or_default()));
                }
                if given.len() > limits::SECRET_BYTES.max || given.contains(['\0', '\r', '\n']) {
                    return Err("A secret must be one line of at most 64 KiB.".into());
                }
                Ok(given.to_owned())
            }
        }
    }

    /// A representative answer for checking a template without asking anything.
    pub fn sample(&self) -> String {
        if let Some(default) = &self.default {
            return default.clone();
        }
        match self.kind {
            QuestionKind::Choice | QuestionKind::MultiChoice => self.choices.first().map(|c| c.value.clone()).unwrap_or_default(),
            QuestionKind::Text => self.pattern.as_deref().and_then(|text| Pattern::parse(text).ok())
                .filter(|pattern| !pattern.matches("sample").unwrap_or(false))
                .and_then(|pattern| pattern.example()).unwrap_or_else(|| "sample".into()),
            QuestionKind::Number => number_text(self.min.or(self.max).unwrap_or(1.0)),
            QuestionKind::Secret => String::new(),
            QuestionKind::Domain => "app.example.com".into(),
            QuestionKind::YesNo => "yes".into(),
        }
    }
}

pub fn hostname(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A Hub name: lowercase letters, digits, `-` or `_`, starting with a letter or digit, at most 64.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.as_bytes()[0].is_ascii_alphanumeric() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// An id of an input, a binding or an output key: lowercase letters, digits or `_`, starting
/// with a letter, at most 32.
pub fn valid_id(id: &str) -> bool {
    id.len() <= limits::ID_CHARS.max && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A resource id or an import namespace, as the website stores it too: lowercase letters,
/// digits, `_` or `-`, starting with a letter, at most 63.
pub fn valid_resource_id(id: &str) -> bool {
    id.len() <= 63 && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

pub const RESOURCE_ID_RULE: &str = "lowercase letters, digits, _ or -, starting with a letter (at most 63)";

/// A spec with every conditional list entry kept and its `when` removed: all a spec may ever
/// grant, whatever the answers, as a review shows it.
pub fn every_entry(spec: &Yaml) -> Yaml {
    match spec {
        Yaml::Sequence(items) => Yaml::Sequence(items.iter().map(|item| match item {
            Yaml::Mapping(map) if map.contains_key("when") => {
                let mut map = map.clone();
                map.remove("when");
                every_entry(&Yaml::Mapping(map))
            }
            other => every_entry(other),
        }).collect()),
        Yaml::Mapping(map) => Yaml::Mapping(map.iter().map(|(key, value)| (key.clone(), every_entry(value))).collect()),
        other => other.clone(),
    }
}

/// A spec with its conditional list entries decided: any list item that is a mapping with
/// `when:` stays when the condition holds for `inputs`, and the `when` key is removed. Every
/// condition is checked against `questions` either way.
pub fn select_entries(spec: &Yaml, questions: &[Question], inputs: &BTreeMap<String, String>, path: &str) -> Result<Yaml, Problems> {
    fn walk(value: &Yaml, questions: &[Question], inputs: &BTreeMap<String, String>, path: &str, problems: &mut Problems) -> Option<Yaml> {
        match value {
            Yaml::Sequence(items) => {
                let mut kept = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let at = format!("{path}[{index}]");
                    if let Some(when) = item.as_mapping().and_then(|m| m.get("when")) {
                        match condition::parse(when, questions, &format!("{at}.when")) {
                            Ok(condition) => {
                                if !condition.holds(inputs) {
                                    continue;
                                }
                            }
                            Err(errors) => {
                                problems.extend(errors);
                                continue;
                            }
                        }
                        let mut map = item.as_mapping().cloned().unwrap_or_default();
                        map.remove("when");
                        if let Some(inner) = walk(&Yaml::Mapping(map), questions, inputs, &at, problems) {
                            kept.push(inner);
                        }
                    } else if let Some(inner) = walk(item, questions, inputs, &at, problems) {
                        kept.push(inner);
                    }
                }
                Some(Yaml::Sequence(kept))
            }
            Yaml::Mapping(map) => {
                let mut out = serde_yaml_ng::Mapping::new();
                for (key, item) in map {
                    let name = scalar_text(key).unwrap_or_default();
                    if let Some(inner) = walk(item, questions, inputs, &format!("{path}.{name}"), problems) {
                        out.insert(key.clone(), inner);
                    }
                }
                Some(Yaml::Mapping(out))
            }
            other => Some(other.clone()),
        }
    }
    let mut problems = Vec::new();
    let selected = walk(spec, questions, inputs, path, &mut problems).unwrap_or(Yaml::Null);
    if problems.is_empty() { Ok(selected) } else { Err(problems) }
}

/// `MAJOR.MINOR.PATCH` with an optional `-prerelease`, as the Hub stores versions.
pub fn parse_version(text: &str) -> Result<semver::Version, String> {
    let refuse = || format!("{} is not a version. Use MAJOR.MINOR.PATCH such as 1.0.0, optionally with -beta.1.", text::shown(text));
    if text.contains('+') || text.len() > 64 {
        return Err(refuse());
    }
    let version = semver::Version::parse(text).map_err(|_| refuse())?;
    if [version.major, version.minor, version.patch].iter().any(|part| *part > 999_999_999) {
        return Err(refuse());
    }
    Ok(version)
}

/// Whether `candidate` is a newer version than `current`; false when either is not a version.
pub fn newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Ok(a), Ok(b)) => a > b,
        _ => false,
    }
}

/// A SHA-256 digest as the Hub writes it: 64 lowercase hex characters.
pub fn valid_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---- Paths ----

pub const FORBIDDEN: &[char] = &['\\', ':', '*', '?', '"', '<', '>', '|'];

/// Windows device names, which no folder can hold whatever their extension: CON, PRN, AUX, NUL,
/// CONIN$, CONOUT$, COM0-COM9, LPT0-LPT9 and COM/LPT with a superscript 1, 2 or 3, in any case,
/// as the website's `checkPath` reads them.
fn reserved_windows_name(part: &str) -> bool {
    let lower = part.to_ascii_lowercase();
    let device = |stem: &str| {
        if matches!(stem, "con" | "prn" | "aux" | "nul" | "conin$" | "conout$") {
            return true;
        }
        let mut chars = stem.chars();
        let prefix: String = chars.by_ref().take(3).collect();
        (prefix == "com" || prefix == "lpt") && matches!((chars.next(), chars.next()), (Some('0'..='9' | '¹' | '²' | '³'), None))
    };
    match lower.split_once('.') {
        None => device(&lower),
        // An extension does not help (`(?:\..*)?$`), unless it holds a line break.
        Some((stem, extension)) => device(stem) && !extension.contains(['\n', '\r', '\u{2028}', '\u{2029}']),
    }
}

/// A path as a package stores it: relative, `/` between folders, bounded, no `.` or `..` part,
/// nothing a computer cannot store or show, and no Windows device name. The same rule in
/// authoring, on the website and on download.
pub fn check_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("A file has an empty name. Rename it.".into());
    }
    if text::utf16_len(path) > limits::PATH_CHARS.max {
        return Err(format!("{} is longer than {} characters. Use a shorter path.", text::shown(path), limits::PATH_CHARS.max));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(format!("{} is not a relative file path. Use a path inside the folder, such as app/server.js.", text::shown(path)));
    }
    if path.chars().any(|c| FORBIDDEN.contains(&c) || matches!(c, '\0'..='\u{1F}' | '\u{7F}') || text::invisible(c)) {
        return Err(format!("{} has a character some computers cannot store or show (\\ : * ? \" < > | or an invisible one). Rename it.", text::shown(path)));
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!("{} has an empty, \".\" or \"..\" part. Use a plain relative path.", text::shown(path)));
        }
        if text::utf16_len(part) > limits::PATH_PART_CHARS.max {
            return Err(format!("{} has a name longer than {} characters. Use a shorter name.", text::shown(path), limits::PATH_PART_CHARS.max));
        }
        if part.ends_with(['.', ' ']) || reserved_windows_name(part) {
            return Err(format!("{} cannot be stored on Windows. Rename it.", text::shown(path)));
        }
    }
    Ok(())
}

/// Two paths one computer would store as a single file: the same once accents are composed and
/// letter case is ignored (NFC, then lowercase, the website's `pathKey`), or a file with the name
/// of a folder.
pub fn clashing<'a>(paths: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let paths: Vec<&str> = paths.into_iter().collect();
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for path in &paths {
        if let Some(other) = seen.insert(crate::unicode::path_key(path), path) {
            return Some(format!("{} and {} are the same file on Windows and macOS (their names differ only in letter case or accent encoding). Rename one of them.", text::shown(other), text::shown(path)));
        }
    }
    for path in &paths {
        let key = crate::unicode::path_key(path);
        let parts: Vec<&str> = key.split('/').collect();
        for depth in 1..parts.len() {
            if let Some(file) = seen.get(&parts[..depth].join("/")) {
                return Some(format!("{} is inside a folder that has the same name as the file {}. Rename one of them.", text::shown(path), text::shown(file)));
            }
        }
    }
    None
}

/// A path inside the package written as `./site` or `site/`: the plain relative form, or why not.
pub fn inside(base: &str, path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.starts_with('\\') || trimmed.contains(':') {
        return Err("must be a path inside the template folder".into());
    }
    let mut parts: Vec<&str> = base.split('/').filter(|p| !p.is_empty()).collect();
    for part in trimmed.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("must stay inside the template folder".into());
                }
            }
            part => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

/// Whether `files` has a file at `path` or a folder there.
pub fn exists(files: &Files, path: &str) -> bool {
    path.is_empty() || files.contains_key(path) || files.keys().any(|file| file.strip_prefix(path).is_some_and(|rest| rest.starts_with('/')))
}

// ---- Text rules ----

/// Text the Hub shows as typed, by the website's rules: trimmed, at most `max` characters as it
/// counts them, no control characters, on one line unless `lines`, and nothing invisible.
fn hub_text(problems: &mut Vec<String>, value: Option<&str>, field: &str, max: usize, lines: bool, missing: Option<String>) {
    let text = value.map(text::js_trim).unwrap_or_default();
    if text.is_empty() {
        problems.extend(missing);
        return;
    }
    if text::utf16_len(text) > max {
        problems.push(format!("{field} is longer than {max} characters."));
    }
    if text.chars().any(text::control) || (!lines && text.contains(['\r', '\n', '\t'])) {
        problems.push(if lines { format!("{field} contains control characters. Write it in plain text.") } else { format!("{field} must be one line, without tabs or control characters.") });
    }
    if text.chars().any(text::invisible) || text::stacked_marks(text) {
        problems.push(format!("{field} contains invisible characters or stacked accents. Write it in plain text."));
    }
}

/// What the website would refuse in a text it shows.
pub fn text_problems(value: &str, field: &str, max: usize, lines: bool) -> Vec<String> {
    let mut problems = Vec::new();
    hub_text(&mut problems, Some(value), field, max, lines, None);
    problems
}

fn whole_word(text: &str, word: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let joins = |byte: Option<&u8>| byte.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    lower.match_indices(word).any(|(at, _)| !joins(at.checked_sub(1).and_then(|before| bytes.get(before))) && !joins(bytes.get(at + word.len())))
}

/// A subtitle or an alias, held to the title's badge rule (the website's `checkListingWords`).
fn listing_words(field: &str, text: &str) -> Vec<String> {
    badge_words(text, field, "").into_iter().take(1).collect()
}

/// Only Yougori shows the Verified badge: a title or summary may not imitate it.
pub fn badge_words(title: &str, title_field: &str, summary: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (field, text, title) in [(title_field, title, true), ("summary", summary, false)] {
        let checks = text.chars().any(|c| matches!(c, '\u{2611}' | '\u{2705}' | '\u{2713}' | '\u{2714}' | '\u{1F5F8}'));
        if checks || whole_word(text, "verified") || (title && whole_word(text, "official")) {
            problems.push(format!("Only Yougori shows the Verified badge; leave that word{} and check marks out of the {field}.", if title { " (and \"official\")" } else { "" }));
        }
    }
    problems
}

/// Problems with a field: missing, too long or more than one line.
fn text_field(problems: &mut Vec<String>, value: Option<&str>, field: &str, max: usize, missing: Option<String>) {
    match value.map(str::trim) {
        None | Some("") => {
            if let Some(missing) = missing {
                problems.push(missing);
            }
        }
        Some(text) if text.chars().count() > max => problems.push(format!("{field} is longer than {max} characters.")),
        Some(text) if !text::one_line(text) => problems.push(format!("{field} must be one line.")),
        Some(_) => {}
    }
}

fn topic(text: &str) -> bool {
    !text.is_empty() && text.len() <= 32 && text.as_bytes()[0].is_ascii_alphanumeric() && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The name, title, summary, version, licence, topics and changelog every item has.
#[allow(clippy::too_many_arguments)]
fn metadata(problems: &mut Vec<String>, kind: &str, file: &str, declared: Option<&str>, name: Option<&str>, title: Option<&str>, summary: Option<&str>, version: Option<&str>, license: Option<&str>, topics: &[String], changelog: Option<&str>) {
    if declared.is_some_and(|declared| declared != kind) {
        problems.push(format!("kind in {file} must be {kind} (templates use {TEMPLATE_FILE}, tools {TOOL_FILE})."));
    }
    match name {
        None => problems.push(format!("Add name: the {kind}'s Hub name, using {NAME_RULE}.")),
        Some(name) if !valid_name(name) => problems.push(format!("name {} is not a Hub name: use {NAME_RULE}.", text::shown(name))),
        Some(_) => {}
    }
    hub_text(problems, title, "title", limits::TITLE_CHARS.max, false, None);
    hub_text(problems, summary, "summary", limits::SUMMARY_CHARS.max, false, Some(format!("Add summary: one line of at most {} characters about what the {kind} does.", limits::SUMMARY_CHARS.max)));
    let named = title.filter(|title| !text::js_trim(title).is_empty());
    let shown_title = named.or(name).unwrap_or_default();
    problems.extend(badge_words(shown_title, if named.is_some() { "title" } else { "name (the title when there is none)" }, summary.unwrap_or_default()));
    match version {
        None => problems.push("Add version: MAJOR.MINOR.PATCH such as 1.0.0.".into()),
        Some(version) => {
            if let Err(error) = parse_version(version) {
                problems.push(format!("version: {error}"));
            }
        }
    }
    match license {
        None => problems.push("Add license: an open-source licence such as MIT or Apache-2.0. Everything on the Hub is open source.".into()),
        Some(license) if !LICENSES.contains(&license) => problems.push(format!("license {} is not an accepted open-source licence. Use one of: {}.", text::shown(license), LICENSES.join(", "))),
        Some(_) => {}
    }
    if topics.iter().collect::<BTreeSet<_>>().len() > limits::TOPICS.max {
        problems.push(format!("Use at most {} topics.", limits::TOPICS.max));
    }
    for item in topics.iter().filter(|item| !topic(item)) {
        problems.push(format!("topic {}: use lowercase words with dashes, such as ai or website.", text::shown(item)));
    }
    hub_text(problems, changelog, "changelog", limits::CHANGELOG_CHARS.max, true, None);
}

/// Reads a UTF-8 text file of the package.
fn file_text<'a>(files: &'a Files, path: &str) -> Result<&'a str, String> {
    let bytes = files.get(path).ok_or_else(|| format!("{path} is missing."))?;
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{path} must be UTF-8 text."))?;
    Ok(text.trim_start_matches('\u{feff}'))
}

fn parse_yaml<T: serde::de::DeserializeOwned>(files: &Files, path: &str, max: usize) -> Result<T, String> {
    let text = file_text(files, path)?;
    if text.len() > max {
        return Err(format!("{path} is larger than {} bytes.", max));
    }
    read_yaml(text).map_err(|e| format!("{path} is not valid: {e}"))
}

/// A single shell line for a tool: not empty, one line, bounded.
fn shell_line(problems: &mut Vec<String>, value: Option<&str>, field: &str, required: bool) {
    match value {
        None | Some("") if required => problems.push(format!("Add {field}: one shell line.")),
        None | Some("") => {}
        Some(line) if line.chars().count() > limits::SHELL_LINE_CHARS.max => problems.push(format!("{field} is longer than {} characters.", limits::SHELL_LINE_CHARS.max)),
        Some(line) if line.contains(['\n', '\r', '\0']) => problems.push(format!("{field} must be a single shell line.")),
        Some(line) if line.chars().any(|c| text::control(c) || text::hidden(c)) => problems.push(format!("{field} contains invisible or control characters. Write it in plain text.")),
        Some(_) => {}
    }
}

fn variable_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && name.bytes().enumerate().all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

/// A tool folder: `prefix` is where it sits in `files` (empty for the folder itself).
pub fn tool(files: &Files, prefix: &str) -> Result<Tool, Vec<String>> {
    let path = if prefix.is_empty() { TOOL_FILE.to_owned() } else { format!("{prefix}/{TOOL_FILE}") };
    let tool: Tool = parse_yaml(files, &path, limits::MANIFEST_BYTES.max).map_err(|e| vec![e])?;
    let mut problems = Vec::new();
    metadata(&mut problems, "tool", TOOL_FILE, tool.kind.as_deref(), tool.name.as_deref(), tool.title.as_deref(), tool.summary.as_deref(), tool.version.as_deref(), tool.license.as_deref(), &tool.topics, tool.changelog.as_deref());
    shell_line(&mut problems, tool.command.as_deref(), "command", true);
    shell_line(&mut problems, tool.check.as_deref(), "check", true);
    if !limits::INSTALL_LINES.allows(tool.install.len()) {
        problems.push(format!("install has more than {} lines.", limits::INSTALL_LINES.max));
    }
    for (index, line) in tool.install.iter().enumerate() {
        shell_line(&mut problems, Some(line.as_str()), &format!("install line {}", index + 1), true);
    }
    if let Some(signin) = &tool.signin {
        let method = signin.method.as_deref().unwrap_or("none");
        match method {
            "none" | "browser" | "device" | "api-key" => {}
            other => problems.push(format!("signin.method {} is not a sign-in method. Use none, browser, device or api-key.", text::shown(other))),
        }
        if matches!(method, "browser" | "device") {
            shell_line(&mut problems, signin.command.as_deref(), "signin.command", true);
        } else if signin.command.is_some() {
            problems.push("signin.command works only with method: browser or device.".into());
        }
        match (method, signin.variable.as_deref()) {
            ("api-key", None) => problems.push("Add signin.variable: the environment variable the API key goes into, such as OPENAI_API_KEY.".into()),
            ("api-key", Some(variable)) if !variable_name(variable) => problems.push(format!("signin.variable {} is not an environment variable name.", text::shown(variable))),
            ("api-key", Some(_)) => {}
            (_, Some(_)) => problems.push("signin.variable works only with method: api-key.".into()),
            _ => {}
        }
    }
    if let Some(needs) = &tool.needs {
        if needs.gpu.as_deref().is_some_and(|gpu| !matches!(gpu, "none" | "optional" | "required")) {
            problems.push("needs.gpu must be none, optional or required.".into());
        }
        if let Some(memory) = &needs.memory {
            if gib(&Json::String(memory.clone())).or_else(|_| gib(&serde_json::json!(memory.parse::<f64>().unwrap_or(-1.0)))).map_or(true, |gb| gb > 1024.0) {
                problems.push(format!("needs.memory {} is not a size such as 4GB.", text::shown(memory)));
            }
        }
    }
    if let Some(service) = &tool.service {
        shell_line(&mut problems, service.command.as_deref(), "service.command", true);
        if service.port.is_none_or(|port| port == 0) {
            problems.push("service.port must be a port from 1 to 65535.".into());
        }
    }
    tool_metadata(&mut problems, &tool);
    if problems.is_empty() { Ok(tool) } else { Err(problems) }
}

/// A folder a tool declares inside the sandbox: absolute, plain text, bounded, never leaving
/// where it points.
fn sandbox_folder(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= limits::PATH_CHARS.max
        && !path.chars().any(|c| text::control(c) || text::hidden(c) || c.is_whitespace())
        && !path.split('/').any(|part| part == "..")
}

/// The portable metadata of a tool: its declared access, inputs and outputs, bounded like the
/// template's own inputs and outputs. A problem names the entry.
fn tool_metadata(problems: &mut Vec<String>, tool: &Tool) {
    let about = |problems: &mut Vec<String>, text: Option<&str>, at: &str| {
        if let Some(text) = text {
            if text.chars().count() > limits::HINT_CHARS.max || !text::one_line(text) {
                problems.push(format!("{at}.about must be one line of at most {} characters.", limits::HINT_CHARS.max));
            }
        }
    };
    if let Some(access) = &tool.access {
        if !limits::OUTPUTS.allows(access.folders.len()) {
            problems.push(format!("access.folders has more than {} entries.", limits::OUTPUTS.max));
        }
        for folder in &access.folders {
            if !sandbox_folder(folder) {
                problems.push(format!("access.folders: {} is not an absolute folder inside the sandbox.", text::shown(folder)));
            }
        }
    }
    if !limits::INPUTS.allows(tool.inputs.len()) {
        problems.push(limits::INPUTS.exceeded(tool.inputs.len()));
    }
    let mut seen = BTreeSet::new();
    for (index, input) in tool.inputs.iter().enumerate() {
        let at = format!("inputs[{}]", index + 1);
        if !variable_name(&input.name) {
            problems.push(format!("{at}: name {} is not an environment variable name.", text::shown(&input.name)));
        } else if !seen.insert(input.name.as_str()) {
            problems.push(format!("inputs lists {} twice.", input.name));
        }
        about(problems, input.about.as_deref(), &at);
    }
    if let Some(variable) = tool.key_variable() {
        if tool.inputs.iter().any(|input| input.name == variable && !input.secret) {
            problems.push(format!("inputs: {variable} is the sign-in key, so it must say secret: true."));
        }
    }
    if !limits::OUTPUTS.allows(tool.outputs.len()) {
        problems.push(limits::OUTPUTS.exceeded(tool.outputs.len()));
    }
    let mut seen = BTreeSet::new();
    for (index, output) in tool.outputs.iter().enumerate() {
        let at = format!("outputs[{}]", index + 1);
        if output.name.is_empty() || output.name.len() > limits::ID_CHARS.max || !output.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            problems.push(format!("{at}: name {} must be lowercase letters, digits and underscores, at most {} characters.", text::shown(&output.name), limits::ID_CHARS.max));
        } else if !seen.insert(output.name.as_str()) {
            problems.push(format!("outputs lists {} twice.", output.name));
        }
        if output.path.as_deref().is_some_and(|path| !sandbox_folder(path)) {
            problems.push(format!("{at}: path {} is not an absolute path inside the sandbox.", text::shown(output.path.as_deref().unwrap_or_default())));
        }
        about(problems, output.about.as_deref(), &at);
    }
}

/// Where a template's tool comes from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Source {
    BuiltIn { name: String },
    /// A folder in the template, with its checked tool file.
    Bundled { folder: String, tool: Box<Tool> },
    /// `PUBLISHER/NAME`, optionally pinned to a version.
    Hub { item: String, version: Option<String> },
}

/// A Hub tool as the engine resolved it before the review: its checked tool file, the version
/// and digest of its files as downloaded, and whether the Hub marks that version Verified. Set
/// by the resolver after the template is checked, never read from the template itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedTool {
    pub tool: Tool,
    pub version: String,
    /// SHA-256 of the tool's files, in hex, as the Hub publishes it.
    pub digest: String,
    pub verified: bool,
}

/// One tool installed into one environment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolUse {
    pub environment: String,
    /// As written in `tools:`.
    pub spec: String,
    pub source: Source,
    pub when: Option<Condition>,
    pub signin: bool,
    pub signin_when: Option<Condition>,
    pub signin_hint: Option<String>,
    pub signin_source: Option<String>,
    /// A Hub tool's files, once fetched and checked. `None` until resolved, and always for
    /// built-in and bundled tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<ResolvedTool>,
}

impl ToolUse {
    /// The tool's checked file, when its files are at hand: a bundled tool's from the template,
    /// a Hub tool's once resolved. `None` for a built-in tool or an unresolved Hub tool.
    pub fn tool(&self) -> Option<&Tool> {
        match &self.source {
            Source::Bundled { tool, .. } => Some(tool),
            Source::Hub { .. } => self.resolved.as_ref().map(|resolved| &resolved.tool),
            Source::BuiltIn { .. } => None,
        }
    }
    pub fn selected(&self, answers: &BTreeMap<String, String>) -> bool {
        self.when.as_ref().is_none_or(|when| when.holds(answers))
    }
    pub fn needs_signin(&self, answers: &BTreeMap<String, String>) -> bool {
        self.signin && self.selected(answers) && self.signin_when.as_ref().is_none_or(|when| when.holds(answers))
    }
    /// Whether the person chose to copy this computer's credentials (`computer`) or sign in anew.
    pub fn copy_credentials(&self, answers: &BTreeMap<String, String>) -> Option<bool> {
        match self.signin_source.as_ref().and_then(|id| answers.get(id)).map(String::as_str) {
            Some("computer") => Some(true),
            Some("new") => Some(false),
            _ => None,
        }
    }
    /// The tool's name as the review shows it.
    pub fn name(&self) -> String {
        match &self.source {
            Source::BuiltIn { name } => name.clone(),
            Source::Bundled { tool, .. } => tool.name().to_owned(),
            Source::Hub { item, .. } => item.clone(),
        }
    }
    pub fn source_name(&self) -> &'static str {
        match &self.source {
            Source::BuiltIn { .. } => "built-in",
            Source::Bundled { .. } => "bundled",
            Source::Hub { .. } => "hub",
        }
    }
}

/// `hub/PUBLISHER/NAME[@VERSION]` as `(PUBLISHER/NAME, VERSION)`.
pub fn hub_ref(spec: &str) -> Result<(String, Option<String>), String> {
    let rest = spec.strip_prefix("hub/").ok_or("Use hub/PUBLISHER/NAME, optionally with @VERSION.")?.trim_end_matches('/');
    let (item, version) = match rest.split_once('@') {
        Some((item, version)) => (item, Some(version)),
        None => (rest, None),
    };
    let parts: Vec<&str> = item.split('/').collect();
    let [publisher, name] = parts.as_slice() else {
        return Err(format!("{} needs a publisher and a name. Use hub/PUBLISHER/NAME, optionally with @VERSION.", text::shown(spec)));
    };
    for part in [publisher, name] {
        if !valid_name(part) {
            let lower = part.to_ascii_lowercase();
            return Err(if lower != *part && valid_name(&lower) {
                format!("Hub names are lowercase: use {}.", spec.replace(*part, &lower))
            } else {
                format!("{} is not a valid Hub name: use {NAME_RULE}.", text::shown(part))
            });
        }
    }
    if let Some(version) = version {
        parse_version(version)?;
    }
    Ok((format!("{publisher}/{name}"), version.map(str::to_owned)))
}

// ---- Questions from inputs ----

/// Checks `inputs` in order and returns the questions. With `v2`, every input needs a group and
/// a fixed input needs a default.
pub fn questions(inputs: &[Input], v2: bool, problems: &mut Problems) -> Vec<Question> {
    let mut questions: Vec<Question> = Vec::new();
    if !limits::INPUTS.allows(inputs.len()) {
        problems.push(problem("limit_exceeded", limits::INPUTS.exceeded(inputs.len())).at("inputs".to_owned()));
    }
    for (index, input) in inputs.iter().enumerate() {
        let label = input.id.clone().unwrap_or_else(|| format!("input {}", index + 1));
        let path = format!("inputs[{index}]");
        let when = match &input.when {
            None => None,
            Some(when) => match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => Some(when),
                Err(errors) => {
                    problems.extend(errors.into_iter().map(|mut e| {
                        e.message = format!("inputs: {label}: {}", e.message);
                        e
                    }));
                    None
                }
            },
        };
        let mut bad = |code: &'static str, text: String| problems.push(problem(code, format!("inputs: {label}: {text}")).at(path.clone()));
        let id = input.id.clone().unwrap_or_default();
        if input.id.is_none() {
            bad("missing_field", format!("add id: {ID_RULE}."));
        } else if !valid_id(&id) {
            bad("invalid_value", format!("id must be {ID_RULE}."));
        } else if v2 && matches!(id.as_str(), "all" | "any" | "not") {
            // when: reads these as its own words, so an input with one of them could never be named.
            bad("invalid_value", format!("{id} is a word when: uses for itself; give the input another id."));
        } else if questions.iter().any(|q| q.id == id) {
            bad("duplicate_id", "this id is used twice.".into());
        }
        let question = input.question.clone().unwrap_or_default();
        if question.trim().is_empty() {
            bad("missing_field", "add question: the sentence the person answers.".into());
        } else if question.chars().count() > limits::QUESTION_CHARS.max || !text::one_line(&question) {
            bad("invalid_value", format!("question must be one line of at most {} characters.", limits::QUESTION_CHARS.max));
        }
        let hint = input.hint.clone().unwrap_or_default();
        if hint.chars().count() > limits::HINT_CHARS.max || !text::one_line(&hint) {
            bad("invalid_value", format!("hint must be one line of at most {} characters.", limits::HINT_CHARS.max));
        }
        let kind = match input.kind.as_deref().map(QuestionKind::read) {
            None => {
                bad("missing_field", "add type: choice, multichoice, text, number, secret, domain or yesno.".into());
                QuestionKind::Text
            }
            Some(None) => {
                bad("invalid_value", format!("type {} is not a question type. Use choice, multichoice, text, number, secret, domain or yesno.", text::shown(input.kind.as_deref().unwrap_or_default())));
                QuestionKind::Text
            }
            Some(Some(kind)) => kind,
        };
        let mut choices = Vec::new();
        if matches!(kind, QuestionKind::Choice | QuestionKind::MultiChoice) {
            if !(2..=limits::CHOICES.max).contains(&input.choices.len()) {
                bad("invalid_value", format!("a choice needs 2 to {} choices.", limits::CHOICES.max));
            }
            for choice in &input.choices {
                let value = choice.value.clone().unwrap_or_default();
                if !valid_name(&value) {
                    bad("invalid_value", format!("choice value {} must be lowercase letters, digits, - or _ (at most 64).", text::shown(&value)));
                } else if choices.iter().any(|c: &ChoiceOption| c.value == value) {
                    bad("duplicate_id", format!("choice value {value} is used twice."));
                }
                let label = choice.label.clone().unwrap_or_default();
                if label.trim().is_empty() || label.chars().count() > limits::LABEL_CHARS.max || !text::one_line(&label) {
                    bad("invalid_value", format!("choice {value} needs a label of one line, at most {} characters.", limits::LABEL_CHARS.max));
                }
                let hint = choice.hint.clone().unwrap_or_default();
                if hint.chars().count() > limits::HINT_CHARS.max || !text::one_line(&hint) {
                    bad("invalid_value", format!("choice {value}: hint must be one line of at most {} characters.", limits::HINT_CHARS.max));
                }
                choices.push(ChoiceOption { value, label, hint });
            }
        } else if !input.choices.is_empty() {
            bad("invalid_value", "choices work only with type: choice or multichoice.".into());
        }
        if input.pattern.is_some() && kind != QuestionKind::Text {
            bad("invalid_value", "pattern works only with type: text.".into());
        }
        if let Some(pattern) = &input.pattern {
            if let Err(error) = Pattern::parse(pattern) {
                bad("invalid_value", error);
            }
        }
        if (input.min.is_some() || input.max.is_some()) && kind != QuestionKind::Number {
            bad("invalid_value", "min and max work only with type: number.".into());
        }
        if input.min.zip(input.max).is_some_and(|(min, max)| min > max) {
            bad("invalid_value", "min is larger than max.".into());
        }
        if input.min_length.is_some() && !matches!(kind, QuestionKind::Text | QuestionKind::Secret) {
            bad("invalid_value", "min_length works only with text or secret inputs.".into());
        }
        if input.min_length.is_some_and(|n| n == 0 || n > if kind == QuestionKind::Text { limits::TEXT_ANSWER_CHARS.max } else { limits::SECRET_BYTES.max }) {
            bad("invalid_value", "min_length is outside the allowed answer size.".into());
        }
        let group = match input.group.as_deref() {
            None if v2 => {
                bad("missing_field", format!("add group: one of {}.", Group::ALL.iter().map(|g| g.id()).collect::<Vec<_>>().join(", ")));
                None
            }
            None => None,
            Some(name) => match Group::parse(name) {
                Some(group) => Some(group),
                None => {
                    bad("unknown_group", format!("group {} is not a capability group. Use one of {}.", text::shown(name), Group::ALL.iter().map(|g| g.id()).collect::<Vec<_>>().join(", ")));
                    None
                }
            },
        };
        let editable = input.editable.unwrap_or(true);
        let default = match &input.default {
            None | Some(Yaml::Null) => None,
            Some(Yaml::String(text)) => Some(text.clone()),
            Some(Yaml::Number(number)) => Some(number.to_string()),
            Some(Yaml::Bool(value)) => Some(if *value { "yes" } else { "no" }.to_owned()),
            Some(Yaml::Sequence(items)) if kind == QuestionKind::MultiChoice => {
                if items.iter().any(|v| !matches!(v, Yaml::String(_))) {
                    bad("invalid_value", "multichoice defaults must be a list of choice values.".into());
                }
                Some(items.iter().filter_map(scalar_text).collect::<Vec<_>>().join(","))
            }
            Some(_) => {
                bad("invalid_value", "default must be a single value (or a list for multichoice).".into());
                None
            }
        };
        if !editable && default.is_none() {
            bad("missing_field", "editable: false fixes the answer, so the input needs a default.".into());
        }
        if !editable && kind == QuestionKind::Secret {
            bad("invalid_value", "a secret cannot be fixed by the template: secrets never live in files.".into());
        }
        let mut question = Question {
            id,
            question,
            kind,
            required: input.required.unwrap_or(true),
            default: None,
            when,
            hint,
            choices,
            pattern: input.pattern.clone(),
            min: input.min,
            max: input.max,
            min_length: input.min_length,
            group,
            editable,
        };
        if let Some(default) = default {
            if kind == QuestionKind::Secret {
                bad("invalid_value", "a secret cannot have a default: secrets never live in files.".into());
            } else if credential_question(&question.id, &question.question) && demonstration_password(&default) {
                // A default is what people accept. Shipped on a password question, a word out of a
                // README becomes the real password of every setup made from this template.
                bad("invalid_value", format!(
                    "default {} is a demonstration password, and a default is what most people keep. Leave it out so each person sets their own, or make it a type: secret so it is never written in the files.",
                    text::shown(&default),
                ));
            } else if kind != QuestionKind::Domain {
                match question.answer(&default, None) {
                    Ok(normal) => question.default = Some(normal),
                    Err(error) => bad("invalid_value", format!("default {} is not a valid answer. {error}", text::shown(&default))),
                }
            } else {
                question.default = Some(default.to_ascii_lowercase());
            }
        }
        questions.push(question);
    }
    questions
}

// ---- A checked package ----

/// A capability as a checked template uses it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckedCapability {
    pub id: String,
    pub selection: Selection,
    pub locked: bool,
    pub when: Option<Condition>,
}

/// A resource as a checked template declares it, placeholders included.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckedResource {
    pub id: String,
    pub kind: Kind,
    pub capability: Option<String>,
    pub depends_on: Vec<String>,
    pub when: Option<Condition>,
    pub borrow: Option<Borrow>,
    pub retention: Option<Retention>,
    pub spec: Yaml,
}

/// A `public:` entry after its checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckedPublic {
    pub environment: String,
    pub port: u16,
    pub access: Access,
    /// The domain as written: a saved domain or `{{inputs.ID}}` of a domain input.
    pub domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// `quick`, `domain` or `none`.
    Fixed(String),
    /// The id of the choice input that decides.
    Asked(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckedStep {
    pub title: String,
    pub detail: Option<String>,
    pub command: Option<String>,
    pub when: Option<Condition>,
}

/// A template package after every check: what a plan, a review and an upload need.
#[derive(Clone, Debug)]
pub struct Checked {
    pub format: FormatVersion,
    pub template: Template,
    pub project_path: String,
    pub project_text: String,
    pub project: Project,
    pub profile: Option<capability::GridProfile>,
    pub questions: Vec<Question>,
    pub capabilities: Vec<CheckedCapability>,
    pub bindings: Vec<CheckedBinding>,
    pub tools: Vec<ToolUse>,
    /// v1-style environments as written, placeholders included.
    pub environments: BTreeMap<String, Yaml>,
    pub connections: Vec<LegacyConnection>,
    pub public: Vec<CheckedPublic>,
    pub resources: BTreeMap<String, CheckedResource>,
    pub steps: Vec<CheckedStep>,
    pub outputs: Vec<CheckedOutput>,
    pub retention: Retention,
    pub views: Vec<String>,
    pub models: Option<Models>,
}

impl Checked {
    /// What the template declares, for checking placeholders.
    pub fn known(&self) -> Known {
        let mut outputs: BTreeMap<String, Vec<&'static str>> = self.environments.keys().map(|name| (name.clone(), Kind::Environment.outputs().to_vec())).collect();
        for (id, resource) in &self.resources {
            outputs.insert(id.clone(), resource.kind.outputs().to_vec());
        }
        for (name, import) in &self.template.imports {
            let _ = import;
            // An imported component's outputs are known only once it is resolved; a step may
            // still name `{{outputs.NAME.ID.OUTPUT}}`, which the planner checks against the
            // resolved component. Until then the namespace is accepted with no outputs listed.
            outputs.entry(name.clone()).or_default();
        }
        Known {
            inputs: self.questions.iter().map(|q| (q.id.clone(), q.kind == QuestionKind::Secret)).collect(),
            environments: self.environments.keys().cloned().chain(self.resources.values().filter(|r| r.kind == Kind::Environment).map(|r| r.id.clone())).collect(),
            public: self.public.iter().map(|p| p.environment.clone()).collect(),
            outputs,
        }
    }

    /// Environments that use a GPU: v1-style ones and environment resources.
    pub fn gpu_environments(&self) -> Vec<String> {
        let uses_gpu = |spec: &Yaml| spec.get("gpu").and_then(Yaml::as_bool) == Some(true) || spec.get("type").and_then(Yaml::as_str) == Some("gpu");
        self.environments.iter().filter(|(_, spec)| uses_gpu(spec)).map(|(name, _)| name.clone())
            .chain(self.resources.values().filter(|r| r.kind == Kind::Environment && uses_gpu(&r.spec)).map(|r| r.id.clone()))
            .collect()
    }

    /// none, optional or required: what the template declares, or required when it uses a GPU.
    pub fn gpu(&self) -> &str {
        match self.template.requires.gpu.as_deref() {
            Some(declared) => declared,
            None if !self.gpu_environments().is_empty() => "required",
            None if self.tools.iter().any(|t| matches!(&t.source, Source::Bundled { tool, .. } if tool.gpu() == "required")) => "required",
            None => "none",
        }
    }

    /// The questions with their answer types, for typed substitution.
    pub fn types(&self) -> BTreeMap<String, Typed> {
        self.questions.iter().map(|q| (q.id.clone(), q.kind.typed())).collect()
    }
}

/// Answers used to check a template without asking anything.
pub fn sample_values(checked: &Checked) -> Values {
    let instance: String = checked.template.name().chars().take(40).collect::<String>().trim_end_matches(['-', '_']).to_owned();
    let instance = if instance.is_empty() { "template".to_owned() } else { instance };
    let mut values = Values { instance: instance.clone(), types: checked.types(), ..Values::default() };
    for question in &checked.questions {
        if question.kind == QuestionKind::Secret {
            values.secrets.insert(question.id.clone(), placeholder::secret_name(&instance, &question.id));
        } else {
            values.inputs.insert(question.id.clone(), question.sample());
        }
    }
    values
}

/// Whether an environment can receive secrets as variables (a tool's API key, a secret input).
pub fn key_ready(spec: &resource::EnvironmentSpec) -> bool {
    matches!(spec.kind.as_str(), "container" | "gpu") || (spec.kind == "microvm" && !spec.image.is_empty())
}

/// What is wrong with the paths an environment reads on this computer: its files, its PC folders
/// and a VM's boot source must be fixed paths inside the package. No answer may choose them.
pub fn environment_paths(spec: &Yaml, base: &str, files: &Files) -> Vec<String> {
    let mut problems = Vec::new();
    let mut checks: Vec<(String, String, bool)> = Vec::new();
    if let Some(source) = spec.get("source").and_then(Yaml::as_str).filter(|s| *s != "builtin:alpine") {
        checks.push(("source".into(), source.to_owned(), false));
    }
    for file in spec.get("files").and_then(Yaml::as_sequence).into_iter().flatten() {
        if let Some(source) = file.get("source").and_then(Yaml::as_str) {
            checks.push(("files source".into(), source.to_owned(), false));
        }
    }
    for volume in spec.get("volumes").and_then(Yaml::as_sequence).into_iter().flatten() {
        // Anything but a plain `bind: false` (or no bind at all) is checked as a folder of this
        // computer: a placeholder there is refused elsewhere, and must never skip this check.
        let plain_volume = match volume.get("bind") {
            None | Some(Yaml::Null) => true,
            Some(bind) => bind.as_bool() == Some(false),
        };
        if !plain_volume {
            if let Some(source) = volume.get("source").and_then(Yaml::as_str) {
                checks.push(("the PC folder".into(), source.to_owned(), true));
            }
        }
    }
    for access in spec.get("pc_access").and_then(Yaml::as_sequence).into_iter().flatten() {
        if let Some(path) = access.get("path").and_then(Yaml::as_str) {
            checks.push(("the PC folder".into(), path.to_owned(), true));
        }
    }
    let mut refused = Vec::new();
    for (what, path, _) in &checks {
        if path.contains("{{") {
            problems.push(format!("{what} {} cannot contain a placeholder: a path on this computer is part of the template, never an answer.", text::shown(path)));
            refused.push(path.clone());
        }
    }
    for (what, path, folder) in checks {
        if refused.contains(&path) {
            continue;
        }
        match (inside(base, &path), folder) {
            (Ok(found), _) if exists(files, &found) => {}
            (Ok(_), true) => problems.push(format!("the PC folder {} is not in the template folder. Add a file to it, such as {}/.keep.", text::shown(&path), text::shown(path.trim_end_matches('/')))),
            (Ok(_), false) => problems.push(format!("{what} {} is not in the template folder.", text::shown(&path))),
            (Err(_), true) => problems.push(format!("a template cannot use folders outside its own folder ({}). Use a folder inside the template.", text::shown(&path))),
            (Err(why), false) => problems.push(format!("{what} {} {why}.", text::shown(&path))),
        }
    }
    problems
}

/// What answers changed about the folders of this computer an environment reaches. The written
/// spec was checked; once rendered, every mounted host folder and every PC folder must be one it
/// already named, mounted no more widely than it said. Anything else is refused.
pub fn host_access_widened(written: &Yaml, rendered: &Yaml) -> Vec<String> {
    let mut problems = Vec::new();
    let list = |spec: &Yaml, key: &str| spec.get(key).and_then(Yaml::as_sequence).cloned().unwrap_or_default();
    let text_of = |entry: &Yaml, key: &str| entry.get(key).and_then(Yaml::as_str).map(str::to_owned);
    let is_true = |entry: &Yaml, key: &str| entry.get(key).and_then(Yaml::as_bool) == Some(true);
    let written_volumes = list(written, "volumes");
    for volume in list(rendered, "volumes") {
        if !is_true(&volume, "bind") {
            continue;
        }
        let source = text_of(&volume, "source").unwrap_or_default();
        let declared = written_volumes.iter().find(|entry| text_of(entry, "source").as_deref() == Some(source.as_str()) && is_true(entry, "bind"));
        match declared {
            None => problems.push(format!("the PC folder {} is mounted with these answers, but the template never names it as one. A folder of this computer is part of the template, never an answer.", text::shown(&source))),
            Some(entry) if is_true(entry, "read_only") && !is_true(&volume, "read_only") => problems.push(format!("the PC folder {} becomes writable with these answers, but the template mounts it read only.", text::shown(&source))),
            Some(_) => {}
        }
    }
    let written_access = list(written, "pc_access");
    for access in list(rendered, "pc_access") {
        // A folder binding is the person's own choice at setup, never an answer: it must be the
        // binding the template wrote, with nothing added to it.
        if let Some(binding) = text_of(&access, "binding") {
            let declared = written_access.iter().find(|entry| text_of(entry, "binding").as_deref() == Some(binding.as_str()));
            match declared {
                None => problems.push(format!("the folder binding {} is reached with these answers, but the template never names it there.", text::shown(&binding))),
                Some(entry) if access.get("path") != entry.get("path") || access.get("read_only") != entry.get("read_only") => problems.push(format!("the folder binding {} gets a path or access with these answers; the person's choice and the binding decide those.", text::shown(&binding))),
                Some(_) => {}
            }
            continue;
        }
        let path = text_of(&access, "path").unwrap_or_default();
        let declared = written_access.iter().find(|entry| entry.get("binding").is_none() && text_of(entry, "path").as_deref() == Some(path.as_str()));
        // A PC folder is read only unless the template says plainly that it isn't.
        let read_only = |entry: &Yaml| entry.get("read_only").and_then(Yaml::as_bool) != Some(false);
        match declared {
            None => problems.push(format!("the PC folder {} is reached with these answers, but the template never names it.", text::shown(&path))),
            Some(entry) if read_only(entry) && !read_only(&access) => problems.push(format!("the PC folder {} becomes writable with these answers, but the template gives it read only.", text::shown(&path))),
            Some(_) => {}
        }
    }
    let written_sync = list(written, "sync");
    for entry in list(rendered, "sync") {
        let mut bare = entry.clone();
        if let Yaml::Mapping(map) = &mut bare {
            map.remove("when");
        }
        let declared = written_sync.iter().any(|written| {
            let mut written = written.clone();
            if let Yaml::Mapping(map) = &mut written {
                map.remove("when");
            }
            written == bare
        });
        if !declared {
            problems.push(format!("a synced folder ({}) differs with these answers from what the template wrote.", text::shown(&text_of(&entry, "binding").unwrap_or_default())));
        }
    }
    problems
}

/// What stands for the folder the person chooses for a folder binding.
#[derive(Clone, Copy, Debug)]
pub enum Folders<'a> {
    /// Checking or publishing a template: words that say the folder is chosen at setup.
    Described,
    /// Planning: the folders the person chose, by binding id. An entry whose binding has no folder
    /// (an optional binding left empty, or one whose condition does not hold) is left out.
    Chosen(&'a BTreeMap<String, String>),
}

/// How a review names a folder the person chooses at setup.
pub fn described_folder(binding: &str) -> String {
    format!("the folder you choose for {binding}")
}

/// Why a folder chosen for a folder binding can't be used, if it can't: it must be the full path
/// of a folder, written plainly. Whether it exists is checked where the folder is.
pub fn folder_choice_problem(value: &str) -> Option<String> {
    let text = value.trim();
    let bytes = text.as_bytes();
    let windows_drive = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/');
    let absolute = text.starts_with('/') || windows_drive || text.starts_with("\\\\");
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Some("give the full path of a folder on this computer".into());
    }
    if !absolute {
        return Some(format!("{} is not a full path; give the full path of a folder on this computer", text::shown(text)));
    }
    if text.split(['/', '\\']).any(|part| part == "..") {
        return Some(format!("{} goes up with ..; give the folder's own full path", text::shown(text)));
    }
    None
}

/// Puts the folder of each `pc_access` and `sync` entry that names a folder binding
/// (`{binding: ID}`) in place, with the access the binding declares: `path` is the person's
/// choice (or words saying it is chosen at setup), `read_only` the binding's. A binding is not a
/// placeholder: only the person chooses its folder, at setup, and no answer can. Returns what is
/// wrong, each as a sentence.
pub fn bind_folders(spec: &mut Yaml, bindings: &[CheckedBinding], folders: Folders) -> Vec<String> {
    let mut problems = Vec::new();
    for (list, mode) in [("pc_access", resource::FolderMode::Mount), ("sync", resource::FolderMode::Sync)] {
        let Some(entries) = spec.get_mut(list).and_then(Yaml::as_sequence_mut) else { continue };
        let mut kept = Vec::with_capacity(entries.len());
        let mut seen = BTreeSet::new();
        for mut entry in entries.drain(..) {
            let Some(named) = entry.get("binding").cloned() else {
                if list == "sync" {
                    problems.push("sync: each entry names the folder binding it keeps in step, with binding: ID.".into());
                }
                kept.push(entry);
                continue;
            };
            let Some(id) = named.as_str().map(str::to_owned) else {
                problems.push(format!("{list}: binding must be the id of a folder binding declared under bindings:."));
                continue;
            };
            let Some(declared) = bindings.iter().find(|b| b.id == id) else {
                problems.push(format!("{list}: the binding {} is not declared under bindings: in {TEMPLATE_FILE}.", text::shown(&id)));
                continue;
            };
            if declared.kind != resource::BindingKind::Folder {
                problems.push(format!("{list}: {id} is a {} binding; a folder of this computer needs a binding of type folder.", declared.kind.id()));
                continue;
            }
            if declared.mode != Some(mode) {
                problems.push(format!(
                    "{list}: the folder binding {id} has mode {}; {list} needs mode {} ({}).",
                    declared.mode.unwrap_or_default().id(),
                    mode.id(),
                    if mode == resource::FolderMode::Mount { "the sandbox reaches the folder itself" } else { "the sandbox keeps a copy that Yougori keeps in step" }
                ));
                continue;
            }
            if entry.get("path").is_some() {
                problems.push(format!("{list}: {id} takes its folder from the person's choice at setup; remove path: from this entry."));
                continue;
            }
            if entry.get("read_only").is_some() {
                problems.push(format!("{list}: {id} takes read only or writable from its binding; remove read_only: from this entry and set it on the binding."));
                continue;
            }
            if !seen.insert(id.clone()) {
                problems.push(format!("{list} names the binding {id} twice."));
                continue;
            }
            let folder = match folders {
                Folders::Described => Some(described_folder(&id)),
                Folders::Chosen(chosen) => chosen.get(&id).map(|value| value.trim().to_owned()).filter(|value| !value.is_empty()),
            };
            let Some(folder) = folder else { continue };
            if let Yaml::Mapping(map) = &mut entry {
                map.insert(Yaml::from("path"), Yaml::from(folder));
                map.insert(Yaml::from("read_only"), Yaml::from(declared.read_only));
            }
            kept.push(entry);
        }
        *entries = kept;
    }
    problems
}

/// Why a folder binding can't be used where a resource of `kind` names it, if it can't: a VM
/// sandbox's workspace is a staged folder, and a staged folder is only a VM sandbox's workspace.
/// (A sandbox's `pc_access` and `sync` are checked by [`bind_folders`].)
fn staged_use(kind: Kind, declared: &CheckedBinding) -> Option<String> {
    if declared.kind != resource::BindingKind::Folder {
        return None;
    }
    let staged = declared.mode == Some(resource::FolderMode::Staged);
    match (kind == Kind::VmSandbox, staged) {
        (true, false) => Some(format!("the folder binding {} has mode {}; a VM sandbox's workspace needs mode staged (the sandbox works on a copy, and the folder changes only with files you approve after a review).", declared.id, declared.mode.unwrap_or_default().id())),
        (false, true) => Some(format!("the folder binding {} has mode staged, which only a VM sandbox's workspace uses.", declared.id)),
        _ => None,
    }
}

/// The folder bindings an environment names, as written: (`pc_access` or `sync`, binding id).
pub fn folder_uses(spec: &Yaml) -> Vec<(&'static str, String)> {
    let mut found = Vec::new();
    for list in ["pc_access", "sync"] {
        for entry in spec.get(list).and_then(Yaml::as_sequence).into_iter().flatten() {
            if let Some(id) = entry.get("binding").and_then(Yaml::as_str) {
                found.push((list, id.to_owned()));
            }
        }
    }
    found
}

/// The v1 template rules for one environment, on its written form.
fn environment_rules(name: &str, spec: &Yaml, base: &str, files: &Files, path: &str, problems: &mut Problems) {
    let bad = |problems: &mut Problems, code: &'static str, text: String| problems.push(problem(code, format!("{name}: {text}")).at(path.to_owned()));
    let kind = spec.get("type").and_then(Yaml::as_str).unwrap_or("container");
    if !matches!(kind, "container" | "gpu" | "microvm" | "vm") {
        bad(problems, "unsupported_here", format!("type {} cannot be in a template: a template creates its sandboxes on the computer that runs it. Use container, gpu, microvm or vm.", text::shown(kind)));
    }
    if spec.get("storage_drive").is_some_and(|v| !v.is_null()) {
        bad(problems, "invalid_value", "remove storage_drive; each computer chooses its own drive.".into());
    }
    if spec.get("health").and_then(|h| h.get("bearer_secret")).is_some_and(|v| !v.is_null()) {
        bad(problems, "invalid_value", "health.bearer_secret cannot be used in a template; a template's secrets come from secret inputs.".into());
    }
    if spec.get("tools").is_some_and(|v| !v.is_null()) {
        bad(problems, "invalid_value", "tools: in a sandbox is filled from the template's tools: and tool_options:, never written in the project; a sign-in copy is the runner's choice there.".into());
    }
    for problem_text in environment_paths(spec, base, files) {
        bad(problems, "host_path", problem_text);
    }
}

/// Checks every placeholder of a spec: syntax, known inputs, secrets only where allowed, and no
/// placeholder in a path on this computer.
fn spec_placeholders(spec: &Yaml, kind: Kind, known: &Known, path: &str, problems: &mut Problems) {
    let policy = resource::policy(kind);
    match placeholder::strings(spec, policy.secrets) {
        Ok(strings) => {
            for (text, at, place) in strings {
                if text.contains("{{") && placeholder::under(&at, policy.no_placeholders) {
                    problems.push(problem("host_path", format!("{at}: {} cannot contain a placeholder: a path on this computer is part of the template, never an answer.", text::shown(&text))).at(format!("{path}.{at}")));
                    continue;
                }
                // A secret value is a reference to a secret input and nothing else: a template
                // cannot name a stored secret of this computer and pull it into a sandbox.
                if place == Place::SpecSecret && placeholder::whole_secret(&text).is_none() {
                    problems.push(problem("invalid_value", format!("{at}: a secret must be {{{{secrets.ID}}}} of a secret input; a template cannot name a stored secret directly ({}).", text::shown(&text))).at(format!("{path}.{at}")));
                    continue;
                }
                if let Err(error) = placeholder::check(&text, place, known) {
                    problems.push(problem("invalid_placeholder", format!("{at}: {error}")).at(format!("{path}.{at}")));
                }
            }
        }
        Err(error) => problems.push(problem("invalid_placeholder", error).at(path.to_owned())),
    }
}

/// A spec with sample answers filled in, parsed as its kind: the check before any real answer.
#[allow(clippy::too_many_arguments)]
fn spec_sample(spec: &Yaml, kind: Kind, values: &Values, questions: &[Question], bindings: &[CheckedBinding], legacy: bool, path: &str, problems: &mut Problems) -> Option<resource::Spec> {
    let mut rendered = match select_entries(spec, questions, &values.inputs, path) {
        Ok(selected) => selected,
        Err(errors) => {
            problems.extend(errors);
            return None;
        }
    };
    if let Err(error) = placeholder::substitute(&mut rendered, values, resource::policy(kind).secrets, !legacy) {
        problems.push(problem("invalid_placeholder", error).at(path.to_owned()));
        return None;
    }
    if kind == Kind::Environment {
        let widened = host_access_widened(spec, &rendered);
        if !widened.is_empty() {
            problems.extend(widened.into_iter().map(|text| problem("host_path", format!("with sample answers: {text}")).at(path.to_owned())));
            return None;
        }
        let bound = bind_folders(&mut rendered, bindings, Folders::Described);
        if !bound.is_empty() {
            problems.extend(bound.into_iter().map(|text| problem("host_path", text).at(path.to_owned())));
            return None;
        }
    }
    match resource::parse_spec(kind, &rendered) {
        Ok(parsed) => {
            for error in parsed.validate() {
                problems.push(problem("invalid_value", format!("with sample answers: {error}")).at(path.to_owned()));
            }
            Some(parsed)
        }
        Err(error) => {
            problems.push(problem("invalid_value", format!("with sample answers: {error}")).at(path.to_owned()));
            None
        }
    }
}

/// What a volume's scheduled backup needs beyond its own fields (ADR-0001 section 16): the
/// capabilities that deliver it are always on, and the sandbox it is read through is a container
/// that mounts it, beside another sandbox to stop while a consistent copy is made.
fn backup_rules(project_path: &str, backed_up: &[(String, String, resource::VolumeSpec)], environments: &BTreeMap<String, resource::EnvironmentSpec>, always: &[&str], problems: &mut Problems) {
    for (id, path, volume) in backed_up {
        for capability in ["run.backups", "run.schedule"] {
            if !always.contains(&capability) {
                problems.push(problem("capability_requires", format!("{project_path}: {id}: backup_schedule needs {capability} in {TEMPLATE_FILE} with selection: required, so the backup is part of every setup made from it.")).at(format!("{path}.spec.backup_schedule")));
            }
        }
        // An unknown or wrongly typed sandbox is refused with the other references.
        let Some((through, helper)) = volume.backup_through.as_ref().and_then(|r| r.local()).and_then(|through| environments.get(through).map(|spec| (through, spec))) else { continue };
        let mounts = |spec: &resource::EnvironmentSpec| spec.volumes.iter().any(|mount| !mount.bind && mount.source == *id);
        if !matches!(helper.kind.as_str(), "container" | "gpu") {
            problems.push(problem("unsupported_here", format!("{project_path}: {id}: backup_through: {through} is a {}; Yougori reads and restores volumes through container sandboxes.", helper.kind)).at(format!("{path}.spec.backup_through")));
        }
        if !mounts(helper) {
            problems.push(problem("invalid_value", format!("{project_path}: {id}: backup_through names {through}, which doesn't mount {id}. Add {{source: {id}, target: /PATH}} to its volumes.")).at(format!("{path}.spec.backup_through")));
        }
        let others = environments.iter().any(|(name, spec)| name != through && mounts(spec));
        if volume.backup_consistency.unwrap_or_default() == resource::BackupConsistency::Stop && !others {
            problems.push(problem("invalid_value", format!("{project_path}: {id}: backup_consistency: stop stops the other sandboxes that use {id} while it is copied, but only {through} uses it, and it keeps running. Give the backup its own small sandbox in backup_through, or say backup_consistency: live.")).at(format!("{path}.spec.backup_consistency")));
        }
    }
}

/// Reads and checks a format 2 template package. Every problem is listed, each saying what to
/// change. A v1 package is refused here with `v1_format`: the clients' v1 code reads those.
pub fn template(files: &Files) -> Result<Checked, Problems> {
    let template_text = file_text(files, TEMPLATE_FILE).map_err(|e| vec![problem("missing_file", e)])?;
    if template_text.len() > limits::MANIFEST_BYTES.max {
        return Err(vec![problem("limit_exceeded", limits::MANIFEST_BYTES.exceeded(template_text.len())).at(TEMPLATE_FILE.to_owned())]);
    }
    match format_version(template_text) {
        Ok(FormatVersion::V2) => {}
        Ok(FormatVersion::V1) => return Err(vec![problem("v1_format", format!("{TEMPLATE_FILE} is a format 1 template; add format_version: 2 to use the format 2 fields."))]),
        Err(refusal) => return Err(vec![refusal]),
    }
    let template: Template = serde_yaml_ng::from_str(template_text).map_err(|e| vec![problem("invalid_format", format!("{TEMPLATE_FILE} is not valid: {e}")).at(TEMPLATE_FILE.to_owned())])?;
    let mut problems: Problems = Vec::new();
    let mut plain = Vec::new();
    metadata(&mut plain, "template", TEMPLATE_FILE, template.kind.as_deref(), template.name.as_deref(), template.title.as_deref(), template.summary.as_deref(), template.version.as_deref(), template.license.as_deref(), &template.topics, template.changelog.as_deref());
    hub_text(&mut plain, template.subtitle.as_deref(), "subtitle", limits::SUBTITLE_CHARS.max, false, None);
    // The subtitle sits beside the title and aliases find items in search: the title's rules.
    if let Some(subtitle) = template.subtitle.as_deref().map(text::js_trim).filter(|s| !s.is_empty()) {
        plain.extend(listing_words("subtitle", subtitle));
    }
    if !limits::ALIASES.allows(template.aliases.len()) {
        plain.push(limits::ALIASES.exceeded(template.aliases.len()));
    }
    for alias in &template.aliases {
        let trimmed = text::js_trim(alias);
        if trimmed.is_empty() || text::utf16_len(trimmed) > limits::ALIAS_CHARS.max || !text::one_line(trimmed) {
            plain.push(format!("alias {} must be one line of 1 to {} characters.", text::shown(alias), limits::ALIAS_CHARS.max));
        } else if text::stacked_marks(trimmed) {
            plain.push(format!("alias {} contains stacked accents. Write it in plain text.", text::shown(alias)));
        } else {
            plain.extend(listing_words("aliases", trimmed));
        }
    }
    if template.aliases.iter().map(|a| text::js_trim(a).to_lowercase()).collect::<BTreeSet<_>>().len() != template.aliases.len() {
        plain.push("aliases lists a name twice.".into());
    }
    problems.extend(plain.into_iter().map(|p| problem("invalid_value", p).at(TEMPLATE_FILE.to_owned())));
    // Requirements: a format 2 template says which Yougori reads it.
    match template.requires.yougori.as_deref() {
        None => problems.push(problem("missing_field", format!("Add requires.yougori: {MINIMUM_YOUGORI} or newer, so an older Yougori refuses this template before creating anything.")).at("requires.yougori".to_owned())),
        Some(version) => match parse_version(version) {
            Err(error) => problems.push(problem("invalid_value", format!("requires.yougori: {error}")).at("requires.yougori".to_owned())),
            Ok(parsed) if parsed < semver::Version::parse(MINIMUM_YOUGORI).unwrap_or_else(|_| semver::Version::new(1, 2, 0)) => {
                problems.push(problem("invalid_value", format!("requires.yougori must be {MINIMUM_YOUGORI} or newer: that is the first Yougori that reads format 2.")).at("requires.yougori".to_owned()));
            }
            Ok(_) => {}
        },
    }
    let mut platforms = BTreeSet::new();
    for platform in &template.requires.platforms {
        if !PLATFORMS.contains(&platform.as_str()) {
            problems.push(problem("invalid_value", format!("requires.platforms: {} is not a platform. Use {}.", text::shown(platform), PLATFORMS.join(", "))).at("requires.platforms".to_owned()));
        } else if !platforms.insert(platform) {
            problems.push(problem("duplicate_id", format!("requires.platforms lists {platform} twice.")).at("requires.platforms".to_owned()));
        }
    }
    // The project file.
    let project_path = template.project_path().to_owned();
    if let Err(error) = check_path(&project_path) {
        problems.push(problem("invalid_path", format!("project: {error}")).at("project".to_owned()));
    }
    if project_path == TEMPLATE_FILE {
        problems.push(problem("invalid_value", format!("project must name the {PROJECT_FILE} project, not {TEMPLATE_FILE}.")).at("project".to_owned()));
    }
    let project_text = match file_text(files, &project_path) {
        Ok(text) => text.to_owned(),
        Err(_) if !files.contains_key(&project_path) => {
            problems.push(problem("missing_file", format!("The template has no {project_path}. Add the project next to {TEMPLATE_FILE}, or name it with project:.")));
            return Err(problems);
        }
        Err(error) => {
            problems.push(problem("invalid_format", error));
            return Err(problems);
        }
    };
    if project_text.len() > limits::PROJECT_BYTES.max {
        problems.push(problem("limit_exceeded", limits::PROJECT_BYTES.exceeded(project_text.len())).at(project_path.clone()));
        return Err(problems);
    }
    match format_version(&project_text) {
        Ok(FormatVersion::V2) => {}
        Ok(FormatVersion::V1) => {
            problems.push(problem("v1_format", format!("{project_path} must say format_version: 2, the same format as {TEMPLATE_FILE}.")).at(project_path.clone()));
            return Err(problems);
        }
        Err(refusal) => {
            problems.push(refusal);
            return Err(problems);
        }
    }
    let project: Project = match serde_yaml_ng::from_str(&project_text) {
        Ok(project) => project,
        Err(error) => {
            problems.push(problem("invalid_format", format!("{project_path} is not a valid project: {error}")).at(project_path.clone()));
            return Err(problems);
        }
    };
    if !project.publish.is_empty() {
        problems.push(problem("invalid_value", format!("{project_path}: use public: in {TEMPLATE_FILE} instead of publish:, so every run sets up access the same way.")).at(format!("{project_path}.publish")));
    }
    let base = project_path.rsplit_once('/').map_or("", |(folder, _)| folder);
    // The grid profile, when the template is one of the four.
    let profile = match template.profile.as_deref() {
        None => None,
        Some(text) => match grid_profile(text) {
            Some(capability::GridProfile::Generic) | None => {
                problems.push(problem("invalid_value", format!("profile {} is not a grid profile. Use {}, or leave profile out.", text::shown(text), capability::GridProfile::GRIDS.iter().map(|p| p.id()).collect::<Vec<_>>().join(", "))).at("profile".to_owned()));
                None
            }
            Some(profile) => Some(profile),
        },
    };
    // Questions.
    let questions = questions(&template.inputs, true, &mut problems);
    // Bindings.
    let mut bindings: Vec<CheckedBinding> = Vec::new();
    for (index, binding) in template.bindings.iter().enumerate() {
        let path = format!("bindings[{index}]");
        let label = binding.id.clone().unwrap_or_else(|| format!("binding {}", index + 1));
        let id = binding.id.clone().unwrap_or_default();
        if binding.id.is_none() || !valid_id(&id) {
            problems.push(problem("invalid_value", format!("bindings: {label}: id must be {ID_RULE}.")).at(path.clone()));
        } else if bindings.iter().any(|b| b.id == id) || questions.iter().any(|q| q.id == id) {
            problems.push(problem("duplicate_id", format!("bindings: {label}: this id is used twice (bindings and inputs share one namespace).")).at(path.clone()));
        }
        let kind = match binding.kind.as_deref().and_then(resource::BindingKind::parse) {
            Some(kind) => kind,
            None => {
                problems.push(problem("invalid_value", format!("bindings: {label}: type {} must be folder, drive, file or resource.", text::shown(binding.kind.as_deref().unwrap_or_default()))).at(path.clone()));
                resource::BindingKind::Folder
            }
        };
        let resource_kind = match (kind, binding.resource.as_deref()) {
            (resource::BindingKind::Resource, Some(text)) => match Kind::parse(text) {
                Some(kind) => Some(kind),
                None => {
                    problems.push(problem("unknown_kind", format!("bindings: {label}: resource {} is not a resource kind. Use one of {}.", text::shown(text), Kind::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", "))).at(path.clone()));
                    None
                }
            },
            (resource::BindingKind::Resource, None) => {
                problems.push(problem("missing_field", format!("bindings: {label}: type resource needs resource: the kind to choose from, such as grid or environment.")).at(path.clone()));
                None
            }
            (_, Some(_)) => {
                problems.push(problem("invalid_value", format!("bindings: {label}: resource: works with type: resource.")).at(path.clone()));
                None
            }
            (_, None) => None,
        };
        let binding_profile = match binding.profile.as_deref() {
            None => None,
            Some(text) => match grid_profile(text) {
                Some(profile) if resource_kind == Some(Kind::Grid) => Some(profile),
                Some(_) => {
                    problems.push(problem("invalid_value", format!("bindings: {label}: profile: works with resource: grid.")).at(path.clone()));
                    None
                }
                None => {
                    problems.push(problem("invalid_value", format!("bindings: {label}: profile {} is not a grid profile.", text::shown(text))).at(path.clone()));
                    None
                }
            },
        };
        let question = binding.question.clone().unwrap_or_default();
        if question.trim().is_empty() || question.chars().count() > limits::QUESTION_CHARS.max || !text::one_line(&question) {
            problems.push(problem("invalid_value", format!("bindings: {label}: question must be one line of 1 to {} characters.", limits::QUESTION_CHARS.max)).at(path.clone()));
        }
        let hint = binding.hint.clone().unwrap_or_default();
        if hint.chars().count() > limits::HINT_CHARS.max || !text::one_line(&hint) {
            problems.push(problem("invalid_value", format!("bindings: {label}: hint must be one line of at most {} characters.", limits::HINT_CHARS.max)).at(path.clone()));
        }
        let when = match &binding.when {
            None => None,
            Some(when) => match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => Some(when),
                Err(errors) => {
                    problems.extend(errors);
                    None
                }
            },
        };
        let mode = match (kind, binding.mode.as_deref()) {
            (resource::BindingKind::Folder, None) => Some(resource::FolderMode::Mount),
            (resource::BindingKind::Folder, Some(text)) => match resource::FolderMode::parse(text) {
                Some(mode) => Some(mode),
                None => {
                    problems.push(problem("invalid_value", format!("bindings: {label}: mode {} must be mount (the sandbox reaches the folder itself), sync (the sandbox keeps a copy that Yougori keeps in step) or staged (a VM sandbox works on a copy, and the folder changes only with files you approve after a review).", text::shown(text))).at(path.clone()));
                    Some(resource::FolderMode::Mount)
                }
            },
            (_, Some(_)) => {
                problems.push(problem("invalid_value", format!("bindings: {label}: mode: works with type: folder.")).at(path.clone()));
                None
            }
            (_, None) => None,
        };
        if binding.read_only.is_some() && kind != resource::BindingKind::Folder {
            problems.push(problem("invalid_value", format!("bindings: {label}: read_only: works with type: folder.")).at(path.clone()));
        }
        if binding.read_only == Some(false) && mode == Some(resource::FolderMode::Staged) {
            problems.push(problem("invalid_value", format!("bindings: {label}: a staged folder is never written by the sandbox; it changes only with files you approve after a review. Remove read_only: false.")).at(path.clone()));
        }
        let read_only = kind != resource::BindingKind::Folder || binding.read_only != Some(false);
        bindings.push(CheckedBinding { id, kind, resource: resource_kind, profile: binding_profile, question, hint, required: binding.required.unwrap_or(true), when, read_only, mode });
    }
    // Capabilities.
    let mut capabilities = Vec::new();
    if !limits::CAPABILITIES.allows(template.capabilities.len()) {
        problems.push(problem("limit_exceeded", limits::CAPABILITIES.exceeded(template.capabilities.len())).at("capabilities".to_owned()));
    }
    for (index, use_) in template.capabilities.iter().enumerate() {
        let path = format!("capabilities[{index}]");
        let Some(found) = capability::find(&use_.id) else {
            problems.push(problem("unknown_capability", format!("capabilities: {} is not a capability this Yougori offers. Run yougori template capabilities for the list.", text::shown(&use_.id))).at(path.clone()));
            continue;
        };
        // The private build's own capabilities never go in a template, so none can be published.
        if found.status == capability::Status::PrivateBuild {
            problems.push(problem("capability_not_enableable", format!("capabilities: {} is only in the private build and never goes in a template.", use_.id)).at(path.clone()));
            continue;
        }
        if capabilities.iter().any(|c: &CheckedCapability| c.id == use_.id) {
            problems.push(problem("duplicate_id", format!("capabilities: {} is listed twice.", use_.id)).at(path.clone()));
            continue;
        }
        let when = match &use_.when {
            None => None,
            Some(when) => match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => Some(when),
                Err(errors) => {
                    problems.extend(errors);
                    None
                }
            },
        };
        capabilities.push(CheckedCapability { id: use_.id.clone(), selection: use_.selection, locked: use_.locked, when });
    }
    // A locked optional capability can never be turned on, so it satisfies nothing; a locked
    // default one, like a required one, is always on unless a condition says otherwise.
    let can_be_on = |c: &CheckedCapability| !(c.locked && c.selection == Selection::Optional);
    let always_on = |c: &CheckedCapability| c.when.is_none() && (c.selection == Selection::Required || (c.locked && c.selection == Selection::Default));
    let declared: Vec<&str> = capabilities.iter().filter(|c| can_be_on(c)).map(|c| c.id.as_str()).collect();
    for use_ in capabilities.iter().filter(|c| can_be_on(c)) {
        let Some(cap) = capability::find(&use_.id) else { continue };
        for group in cap.missing_for(&declared, profile) {
            problems.push(problem("capability_requires", format!("capabilities: {} needs one of {} declared as well.", use_.id, group.join(", "))).at("capabilities".to_owned()));
        }
        // Two capabilities that exclude each other cannot both be always on; with conditions,
        // or when the person may turn one off, the planner decides for the actual answers.
        if always_on(use_) {
            for other in capabilities.iter().filter(|c| always_on(c) && c.id > use_.id && cap.conflicts.contains(&c.id.as_str())) {
                problems.push(problem("capability_conflict", format!("capabilities: {} and {} cannot both be always on; they exclude each other. Give each a when: condition, or let the person turn one off.", use_.id, other.id)).at("capabilities".to_owned()));
            }
        }
    }
    // Imports.
    if !limits::IMPORTS.allows(template.imports.len()) {
        problems.push(problem("limit_exceeded", limits::IMPORTS.exceeded(template.imports.len())).at("imports".to_owned()));
    }
    for (name, import) in &template.imports {
        let path = format!("imports.{name}");
        if !valid_resource_id(name) {
            problems.push(problem("invalid_value", format!("imports: {} must be {RESOURCE_ID_RULE}: it becomes the namespace of the component's resources.", text::shown(name))).at(path.clone()));
        }
        if project.environments.contains_key(name) || project.resources.contains_key(name) {
            problems.push(problem("duplicate_id", format!("imports: {name} is also a resource name; use a different namespace.")).at(path.clone()));
        }
        let parts: Vec<&str> = import.item.split('/').collect();
        if parts.len() != 2 || !parts.iter().all(|p| valid_name(p)) {
            problems.push(problem("invalid_value", format!("imports: {name}: item must be PUBLISHER/NAME.")).at(format!("{path}.item")));
        }
        match import.version.as_deref() {
            None => problems.push(problem("missing_field", format!("imports: {name}: add version: the component's exact version.")).at(format!("{path}.version"))),
            Some(version) => {
                if let Err(error) = parse_version(version) {
                    problems.push(problem("invalid_value", format!("imports: {name}: version: {error}")).at(format!("{path}.version")));
                }
            }
        }
        if !valid_digest(&import.digest) {
            problems.push(problem("invalid_value", format!("imports: {name}: digest must be the component's SHA-256 (64 hex characters), as yougori template info shows it.")).at(format!("{path}.digest")));
        }
        for (id, value) in &import.inputs {
            if !valid_id(id) {
                problems.push(problem("invalid_value", format!("imports: {name}: input {} must be {ID_RULE}.", text::shown(id))).at(format!("{path}.inputs")));
            }
            match value {
                Yaml::String(text) if text.contains("{{") => {
                    let known = Known { inputs: questions.iter().map(|q| (q.id.clone(), q.kind == QuestionKind::Secret)).collect(), ..Known::default() };
                    let whole = placeholder::whole_input(text).is_some() || placeholder::whole_secret(text).is_some();
                    if !whole {
                        problems.push(problem("invalid_placeholder", format!("imports: {name}: input {id} must be a fixed value, {{{{inputs.ID}}}} or {{{{secrets.ID}}}} on its own.")).at(format!("{path}.inputs.{id}")));
                    } else if let Err(error) = placeholder::check(text, Place::SpecSecret, &known) {
                        problems.push(problem("invalid_placeholder", format!("imports: {name}: input {id}: {error}")).at(format!("{path}.inputs.{id}")));
                    }
                }
                Yaml::String(_) | Yaml::Number(_) | Yaml::Bool(_) => {}
                Yaml::Sequence(items) if items.iter().all(|i| matches!(i, Yaml::String(_))) => {}
                _ => problems.push(problem("invalid_value", format!("imports: {name}: input {id} must be a single value, a list of choice values, or a placeholder.")).at(format!("{path}.inputs.{id}"))),
            }
        }
        for id in &import.capabilities {
            if capability::find(id).is_none() {
                problems.push(problem("unknown_capability", format!("imports: {name}: {} is not a capability this Yougori offers.", text::shown(id))).at(format!("{path}.capabilities")));
            }
        }
    }
    // v1-style environments.
    let environments: BTreeMap<String, Yaml> = project.environments.clone();
    let mut known = Known {
        inputs: questions.iter().map(|q| (q.id.clone(), q.kind == QuestionKind::Secret)).collect(),
        environments: environments.keys().cloned().collect(),
        public: template.public.iter().filter_map(|p| p.environment.clone()).collect(),
        outputs: BTreeMap::new(),
    };
    let values = {
        let instance: String = template.name().chars().take(40).collect::<String>().trim_end_matches(['-', '_']).to_owned();
        let instance = if instance.is_empty() { "template".to_owned() } else { instance };
        let mut values = Values { instance: instance.clone(), types: questions.iter().map(|q| (q.id.clone(), q.kind.typed())).collect(), ..Values::default() };
        for question in &questions {
            if question.kind == QuestionKind::Secret {
                values.secrets.insert(question.id.clone(), placeholder::secret_name(&instance, &question.id));
            } else {
                values.inputs.insert(question.id.clone(), question.sample());
            }
        }
        values
    };
    let mut environment_specs: BTreeMap<String, resource::EnvironmentSpec> = BTreeMap::new();
    for (name, spec) in &environments {
        let path = format!("{project_path}.environments.{name}");
        if !spec.is_mapping() {
            problems.push(problem("invalid_format", format!("{project_path}: {name}: an environment is a mapping of its settings.")).at(path));
            continue;
        }
        if !workload_identifier(name) || project.project.len() + name.len() + 1 > 80 {
            problems.push(problem("invalid_value", format!("{project_path}: {} is not an environment name: use letters, digits, dots, dashes or underscores.", text::shown(name))).at(path.clone()));
        } else if !valid_resource_id(name) {
            // In format 2 an environment is a resource, so its name is a resource id the Hub reads.
            problems.push(problem("invalid_value", format!("{project_path}: {} is not an environment name in format 2: it becomes a resource id, so use {RESOURCE_ID_RULE}.", text::shown(name))).at(path.clone()));
        }
        environment_rules(name, spec, base, files, &path, &mut problems);
        spec_placeholders(spec, Kind::Environment, &known, &path, &mut problems);
        if let Some(resource::Spec::Environment(parsed)) = spec_sample(spec, Kind::Environment, &values, &questions, &bindings, true, &path, &mut problems) {
            environment_specs.insert(name.clone(), *parsed);
        }
    }
    for (name, spec) in &environment_specs {
        for dependency in &spec.depends_on {
            if dependency == name || !(environments.contains_key(dependency) || project.resources.contains_key(dependency)) {
                problems.push(problem("unknown_resource", format!("{project_path}: {name}: unknown/self dependency {dependency}.")).at(format!("{project_path}.environments.{name}.depends_on")));
            }
        }
    }
    // Connections.
    let mut connections = Vec::new();
    for (index, value) in project.connections.iter().enumerate() {
        let path = format!("{project_path}.connections[{index}]");
        match connection(value) {
            Ok(connection) => {
                if connection.from == connection.to || !environments.contains_key(&connection.from) || !environments.contains_key(&connection.to) {
                    problems.push(problem("unknown_resource", format!("{project_path}: connection {} -> {} refers to an unknown environment or itself.", connection.from, connection.to)).at(path));
                } else if connection.ports.contains(&0) || connection.permissions.iter().any(|p| !resource::CONNECTION_PERMISSIONS.contains(&p.as_str())) {
                    problems.push(problem("invalid_value", format!("{project_path}: connection {} -> {}: ports must be 1 to 65535 and permissions one of {}.", connection.from, connection.to, resource::CONNECTION_PERMISSIONS.join(", "))).at(path));
                } else {
                    connections.push(connection);
                }
            }
            Err(error) => problems.push(problem("invalid_value", format!("{project_path}: {error}")).at(path)),
        }
    }
    // Resources.
    let mut resources: BTreeMap<String, CheckedResource> = BTreeMap::new();
    for (id, resource) in &project.resources {
        let path = format!("{project_path}.resources.{id}");
        if !valid_resource_id(id) {
            problems.push(problem("invalid_value", format!("{project_path}: resource {} must be {RESOURCE_ID_RULE}.", text::shown(id))).at(path.clone()));
            continue;
        }
        if environments.contains_key(id) {
            problems.push(problem("duplicate_id", format!("{project_path}: {id} is both an environment and a resource; use one name per thing.")).at(path.clone()));
            continue;
        }
        let Some(kind) = Kind::parse(&resource.kind) else {
            problems.push(problem("unknown_kind", format!("{project_path}: {id}: kind {} is not a resource kind. Use one of {}.", text::shown(&resource.kind), Kind::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", "))).at(format!("{path}.kind")));
            continue;
        };
        if let Some(capability) = &resource.capability {
            if !capabilities.iter().any(|c| &c.id == capability) {
                problems.push(problem("unknown_capability", format!("{project_path}: {id}: capability {} is not declared in {TEMPLATE_FILE}.", text::shown(capability))).at(format!("{path}.capability")));
            }
        }
        let when = match &resource.when {
            None => None,
            Some(when) => match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => Some(when),
                Err(errors) => {
                    problems.extend(errors);
                    None
                }
            },
        };
        resources.insert(id.clone(), CheckedResource { id: id.clone(), kind, capability: resource.capability.clone(), depends_on: resource.depends_on.clone(), when, borrow: resource.borrow.clone(), retention: resource.retention, spec: resource.spec.clone() });
    }
    for resource in resources.values() {
        known.outputs.insert(resource.id.clone(), resource.kind.outputs().to_vec());
        if resource.kind == Kind::Environment {
            known.environments.insert(resource.id.clone());
        }
    }
    for name in environments.keys() {
        known.outputs.insert(name.clone(), Kind::Environment.outputs().to_vec());
    }
    let ids: BTreeMap<String, Kind> = environments.keys().map(|n| (n.clone(), Kind::Environment)).chain(resources.values().map(|r| (r.id.clone(), r.kind))).collect();
    // Volumes with a backup schedule, checked against the sandboxes once all are read.
    let mut backed_up: Vec<(String, String, resource::VolumeSpec)> = Vec::new();
    for resource in resources.values() {
        let path = format!("{project_path}.resources.{}", resource.id);
        if !limits::DEPENDS_ON.allows(resource.depends_on.len()) {
            problems.push(problem("limit_exceeded", limits::DEPENDS_ON.exceeded(resource.depends_on.len())).at(format!("{path}.depends_on")));
        }
        for dependency in &resource.depends_on {
            let namespaced = dependency.split_once('.').is_some_and(|(ns, rest)| template.imports.contains_key(ns) && valid_resource_id(rest));
            if dependency == &resource.id {
                problems.push(problem("dependency_cycle", format!("{project_path}: {} depends on itself.", resource.id)).at(format!("{path}.depends_on")));
            } else if !ids.contains_key(dependency) && !namespaced {
                problems.push(problem("unknown_resource", format!("{project_path}: {}: depends_on names {}, which is not a resource.", resource.id, text::shown(dependency))).at(format!("{path}.depends_on")));
            }
        }
        if resource.kind == Kind::Environment {
            environment_rules(&resource.id, &resource.spec, base, files, &path, &mut problems);
        }
        if resource.kind == Kind::ComputePool && resource.spec.get("cloud").and_then(|cloud| cloud.get("identity_path")).is_some_and(|value| !value.is_null()) {
            problems.push(problem("host_path", format!("{project_path}: {}: remove cloud.identity_path; the key file is the one the person chooses for identity_file.", resource.id)).at(format!("{path}.spec.cloud.identity_path")));
        }
        if resource.kind == Kind::WorkerGroup && resource.spec.get("source_folder").is_some_and(|value| !value.is_null()) {
            problems.push(problem("host_path", format!("{project_path}: {}: remove source_folder; a worker's source is the folder the person chooses for its binding.", resource.id)).at(format!("{path}.spec.source_folder")));
        }
        if resource.kind == Kind::VmSandbox && resource.spec.get("workspace_folder").is_some_and(|value| !value.is_null()) {
            problems.push(problem("host_path", format!("{project_path}: {}: remove workspace_folder; a VM sandbox's workspace is the folder the person chooses for its binding.", resource.id)).at(format!("{path}.spec.workspace_folder")));
        }
        if resource.kind == Kind::Job && resource.spec.get("source_folder").is_some_and(|value| !value.is_null()) {
            problems.push(problem("host_path", format!("{project_path}: {}: remove source_folder; a job's source is the folder the person chooses for its binding.", resource.id)).at(format!("{path}.spec.source_folder")));
        }
        spec_placeholders(&resource.spec, resource.kind, &known, &path, &mut problems);
        if resource.kind == Kind::Environment {
            // Tools install into environment resources as into v1-style environments.
            if let Some(resource::Spec::Environment(parsed)) = spec_sample(&resource.spec, Kind::Environment, &values, &questions, &bindings, false, &path, &mut Vec::new()) {
                environment_specs.insert(resource.id.clone(), *parsed);
            }
        }
        if let Some(borrow) = &resource.borrow {
            if let Some(why) = borrow.problem() {
                problems.push(problem("invalid_value", format!("{project_path}: {}: {why}.", resource.id)).at(format!("{path}.borrow")));
            }
            if let Some(binding) = &borrow.binding {
                match bindings.iter().find(|b| &b.id == binding) {
                    Some(declared) if declared.kind == resource::BindingKind::Resource && declared.resource == Some(resource.kind) => {}
                    Some(declared) => problems.push(problem("invalid_value", format!("{project_path}: {}: borrow names the binding {}, which is not a resource binding of kind {}.", resource.id, declared.id, resource.kind.as_str())).at(format!("{path}.borrow"))),
                    None => problems.push(problem("unknown_binding", format!("{project_path}: {}: borrow names the binding {}, which {TEMPLATE_FILE} does not declare.", resource.id, text::shown(binding))).at(format!("{path}.borrow"))),
                }
            }
        }
        if let Some(parsed) = spec_sample(&resource.spec, resource.kind, &values, &questions, &bindings, false, &path, &mut problems) {
            for (field, reference, allowed) in parsed.references() {
                if let Some(binding) = &reference.binding {
                    match bindings.iter().find(|b| &b.id == binding) {
                        Some(declared) if declared.kind == resource::BindingKind::Resource && declared.resource.is_some_and(|k| allowed.contains(&k)) => {
                            if let (Some(output), Some(kind)) = (&reference.output, declared.resource) {
                                if !kind.outputs().contains(&output.as_str()) {
                                    problems.push(problem("unknown_output", format!("{project_path}: {}: {field}: a {} has no output {output}.", resource.id, kind.as_str())).at(format!("{path}.spec.{field}")));
                                }
                            }
                        }
                        Some(declared) => problems.push(problem("invalid_value", format!("{project_path}: {}: {field} names the binding {}, which is not a resource binding of kind {}.", resource.id, declared.id, allowed.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(" or "))).at(format!("{path}.spec.{field}"))),
                        None => problems.push(problem("unknown_binding", format!("{project_path}: {}: {field} names the binding {}, which {TEMPLATE_FILE} does not declare.", resource.id, text::shown(binding))).at(format!("{path}.spec.{field}"))),
                    }
                    continue;
                }
                let Some(target) = reference.local() else { continue };
                let namespaced = target.split_once('.').is_some_and(|(ns, rest)| template.imports.contains_key(ns) && valid_resource_id(rest));
                match ids.get(target) {
                    None if namespaced => {}
                    None => problems.push(problem("unknown_resource", format!("{project_path}: {}: {field} names {}, which is not a resource.", resource.id, text::shown(target))).at(format!("{path}.spec.{field}"))),
                    Some(kind) if !allowed.contains(kind) => problems.push(problem("invalid_value", format!("{project_path}: {}: {field} must name a {} resource; {target} is a {}.", resource.id, allowed.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(" or "), kind.as_str())).at(format!("{path}.spec.{field}"))),
                    Some(kind) => {
                        if let Some(output) = &reference.output {
                            if !kind.outputs().contains(&output.as_str()) {
                                problems.push(problem("unknown_output", format!("{project_path}: {}: {field}: {target} has no output {output}. Its outputs are: {}.", resource.id, kind.outputs().join(", "))).at(format!("{path}.spec.{field}")));
                            }
                        }
                    }
                }
                if target == resource.id {
                    problems.push(problem("dependency_cycle", format!("{project_path}: {}: {field} refers to the resource itself.", resource.id)).at(format!("{path}.spec.{field}")));
                }
            }
            for (field, binding, kind) in parsed.bindings() {
                match bindings.iter().find(|b| b.id == binding) {
                    None => problems.push(problem("unknown_binding", format!("{project_path}: {}: {field} names the binding {}, which {TEMPLATE_FILE} does not declare under bindings:.", resource.id, text::shown(binding))).at(format!("{path}.spec.{field}"))),
                    Some(declared) if declared.kind != kind => problems.push(problem("invalid_value", format!("{project_path}: {}: {field} needs a {} binding; {} is a {}.", resource.id, kind.id(), declared.id, declared.kind.id())).at(format!("{path}.spec.{field}"))),
                    Some(declared) => {
                        if let Some(problem_text) = staged_use(resource.kind, declared) {
                            problems.push(problem("invalid_value", format!("{project_path}: {}: {field}: {problem_text}", resource.id)).at(format!("{path}.spec.{field}")));
                        }
                    }
                }
            }
            if let resource::Spec::Grid(grid) = &parsed {
                if grid.mode == resource::GridMode::Attach && resource.borrow.is_none() {
                    problems.push(problem("missing_field", format!("{project_path}: {}: mode: attach needs borrow: {{setup: ID, resource: ID}} naming the existing grid.", resource.id)).at(format!("{path}.borrow")));
                }
                if profile.is_some_and(|p| p != grid.profile) {
                    problems.push(problem("invalid_value", format!("{project_path}: {}: profile {} does not match the template's profile {}.", resource.id, grid.profile.id(), profile.map(|p| p.id()).unwrap_or_default())).at(format!("{path}.spec.profile")));
                }
            }
            if let resource::Spec::Volume(volume) = &parsed {
                if volume.backup_schedule.is_some() {
                    backed_up.push((resource.id.clone(), path.clone(), volume.clone()));
                }
            }
        }
    }
    let always: Vec<&str> = capabilities.iter().filter(|c| always_on(c)).map(|c| c.id.as_str()).collect();
    backup_rules(&project_path, &backed_up, &environment_specs, &always, &mut problems);
    // A folder the person syncs has one copy in one sandbox: two syncs of the same folder would
    // each take the other's changes for edits.
    let mut synced: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, spec) in environments.iter().chain(resources.values().filter(|r| r.kind == Kind::Environment).map(|r| (&r.id, &r.spec))) {
        for (list, binding) in folder_uses(spec) {
            if list == "sync" {
                synced.entry(binding).or_default().push(name.clone());
            }
        }
    }
    for (binding, users) in synced.iter().filter(|(_, users)| users.len() > 1) {
        problems.push(problem("invalid_value", format!("{project_path}: the folder binding {binding} is synced by {}; a synced folder has one copy, in one sandbox.", users.join(" and "))).at(project_path.clone()));
    }
    if environments.is_empty() && resources.is_empty() {
        problems.push(problem("missing_field", format!("{project_path} creates nothing: add environments: or resources:.")).at(project_path.clone()));
    }
    let total = environments.len() + resources.len();
    if !limits::RESOURCES.allows(total) {
        problems.push(problem("limit_exceeded", limits::RESOURCES.exceeded(total)).at(project_path.clone()));
    }
    // Tools.
    let mut tools = Vec::new();
    for (environment, specs) in &template.tools {
        let path = format!("tools.{environment}");
        let Some(spec_environment) = environment_specs.get(environment) else {
            if !environments.contains_key(environment) && !resources.get(environment).is_some_and(|r| r.kind == Kind::Environment) {
                problems.push(problem("unknown_resource", format!("tools: {} is not an environment in {project_path}.", text::shown(environment))).at(path));
            }
            continue;
        };
        let local = matches!(spec_environment.kind.as_str(), "container" | "gpu") || (spec_environment.kind == "microvm" && spec_environment.image.is_empty());
        if !local && !specs.is_empty() {
            problems.push(problem("unsupported_here", format!("tools: {environment} is a {}; tools install into containers and microVMs without an image.", spec_environment.kind)).at(path.clone()));
        }
        if !spec_environment.internet && !specs.is_empty() {
            problems.push(problem("unsupported_here", format!("tools: {environment} has internet: false, so its tools cannot be installed.")).at(path.clone()));
        }
        let mut seen = BTreeSet::new();
        for spec in specs {
            let source = if BUILT_IN_TOOLS.contains(&spec.as_str()) {
                Source::BuiltIn { name: spec.clone() }
            } else if spec.starts_with("hub/") {
                match hub_ref(spec) {
                    Ok((item, version)) => Source::Hub { item, version },
                    Err(error) => {
                        problems.push(problem("invalid_value", format!("tools: {environment}: {error}")).at(path.clone()));
                        continue;
                    }
                }
            } else {
                let folder = match inside("", spec) {
                    Ok(folder) if !folder.is_empty() && (spec.contains('/') || files.contains_key(&format!("{folder}/{TOOL_FILE}"))) => folder,
                    _ => {
                        problems.push(problem("invalid_value", format!("tools: {environment}: {} is not a built-in tool ({}), a tool folder in the template (such as tools/NAME) or hub/PUBLISHER/NAME.", text::shown(spec), BUILT_IN_TOOLS.join(", "))).at(path.clone()));
                        continue;
                    }
                };
                if !files.contains_key(&format!("{folder}/{TOOL_FILE}")) {
                    problems.push(problem("missing_file", format!("tools: {environment}: {folder} has no {TOOL_FILE}. Bundled tools are folders with their own {TOOL_FILE}.")).at(path.clone()));
                    continue;
                }
                match tool(files, &folder) {
                    Ok(tool) => {
                        if let (Some(needed), Ok(has)) = (tool.memory_gb(), gib(&spec_environment.memory)) {
                            if needed > has {
                                problems.push(problem("invalid_value", format!("tools: {} needs {needed} GB of memory, but {environment} has {has} GB.", tool.name())).at(path.clone()));
                            }
                        }
                        if tool.gpu() == "required" && !(spec_environment.gpu || spec_environment.kind == "gpu") {
                            problems.push(problem("invalid_value", format!("tools: {} needs a GPU, but {environment} has none. Set type: gpu for {environment}.", tool.name())).at(path.clone()));
                        }
                        if tool.key_variable().is_some() && !key_ready(spec_environment) {
                            problems.push(problem("unsupported_here", format!("tools: {} signs in with an API key, which {environment} cannot receive: a microVM gets keys only with an image. Use a container, or give {environment} an image.", tool.name())).at(path.clone()));
                        }
                        Source::Bundled { folder, tool: Box::new(tool) }
                    }
                    Err(errors) => {
                        problems.extend(errors.into_iter().map(|error| problem("invalid_value", format!("{folder}/{TOOL_FILE}: {error}")).at(format!("{folder}/{TOOL_FILE}"))));
                        continue;
                    }
                }
            };
            let use_ = ToolUse { environment: environment.clone(), spec: spec.clone(), source, when: None, signin: false, signin_when: None, signin_hint: None, signin_source: None, resolved: None };
            if !seen.insert(use_.name()) {
                problems.push(problem("duplicate_id", format!("tools: {environment} lists {} twice.", use_.name())).at(path.clone()));
                continue;
            }
            tools.push(use_);
        }
    }
    for (key, options) in &template.tool_options {
        let path = format!("tool_options.{key}");
        let Some(use_) = tools.iter_mut().find(|t| format!("{}/{}", t.environment, t.name()) == *key) else {
            problems.push(problem("unknown_resource", format!("tool_options: {key} is not a declared environment/tool.")).at(path));
            continue;
        };
        if !matches!(use_.source, Source::BuiltIn { .. }) {
            problems.push(problem("unsupported_here", format!("tool_options: {key}: options currently apply only to built-in tools.")).at(path.clone()));
        }
        if options.signin && !matches!(&use_.source, Source::BuiltIn { name } if SUBSCRIPTION_TOOLS.contains(&name.as_str())) {
            problems.push(problem("unsupported_here", format!("tool_options: {key} has no supported subscription sign-in flow.")).at(path.clone()));
        }
        if let Some(when) = &options.when {
            match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => use_.when = Some(when),
                Err(errors) => problems.extend(errors),
            }
        }
        use_.signin = options.signin;
        if !options.signin && (options.signin_when.is_some() || options.signin_hint.is_some() || options.signin_source.is_some()) {
            problems.push(problem("invalid_value", format!("tool_options: {key}: signin_when, signin_hint and signin_source need signin: true.")).at(path.clone()));
        }
        if let Some(when) = &options.signin_when {
            match condition::parse(when, &questions, &format!("{path}.signin_when")) {
                Ok(when) => use_.signin_when = Some(when),
                Err(errors) => problems.extend(errors),
            }
        }
        if let Some(hint) = &options.signin_hint {
            if hint.chars().count() > limits::SIGNIN_HINT_CHARS.max || !text::one_line(hint) {
                problems.push(problem("invalid_value", format!("tool_options: {key}: signin_hint must be one line of at most {} characters.", limits::SIGNIN_HINT_CHARS.max)).at(path.clone()));
            }
            if let Err(error) = placeholder::check(hint, Place::Step, &known) {
                problems.push(problem("invalid_placeholder", format!("tool_options: {key}: {error}")).at(path.clone()));
            }
        }
        use_.signin_hint = options.signin_hint.clone();
        if let Some(id) = &options.signin_source {
            match questions.iter().find(|q| q.id == *id) {
                Some(q) if q.kind == QuestionKind::Choice && q.choices.len() == 2 && q.choices.iter().all(|c| matches!(c.value.as_str(), "computer" | "new")) => {
                    // Copying this computer's sign-in is the runner's explicit choice: a template
                    // cannot answer it for them with a default, nor fix it.
                    if q.default.is_some() || !q.editable {
                        problems.push(problem("invalid_value", format!("tool_options: {key}: the sign-in source input {id} must have no default and stay editable: copying this computer's sign-in is the person's choice at setup, never the template's.")).at(path.clone()));
                    }
                }
                _ => problems.push(problem("invalid_value", format!("tool_options: {key}: signin_source must name a choice input with exactly computer and new options.")).at(path.clone())),
            }
        }
        use_.signin_source = options.signin_source.clone();
    }
    // Public access.
    let mut public = Vec::new();
    let mut public_seen = BTreeSet::new();
    for (index, entry) in template.public.iter().enumerate() {
        let path = format!("public[{index}]");
        let Some(name) = entry.environment.as_deref() else {
            problems.push(problem("missing_field", "public: each entry needs environment: and port:.").at(path));
            continue;
        };
        let Some(spec) = environment_specs.get(name) else {
            if !environments.contains_key(name) && !resources.get(name).is_some_and(|r| r.kind == Kind::Environment) {
                problems.push(problem("unknown_resource", format!("public: {} is not an environment in {project_path}.", text::shown(name))).at(path));
            }
            continue;
        };
        if !public_seen.insert(name.to_owned()) {
            problems.push(problem("duplicate_id", format!("public: {name} appears twice; each environment has one public address.")).at(path.clone()));
        }
        let ports: Vec<u16> = spec.ports.iter().filter_map(|p| p.values().ok()).map(|(guest, _)| guest).collect();
        let port = match entry.port {
            None => {
                problems.push(problem("missing_field", format!("public: {name} needs port: one of its ports ({}).", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))).at(path.clone()));
                0
            }
            Some(port) if !ports.contains(&port) => {
                problems.push(problem("invalid_value", format!("public: port {port} is not one of {name}'s ports in {project_path}. Add it to ports: or choose one of: {}.", if ports.is_empty() { "none yet".to_owned() } else { ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ") })).at(path.clone()));
                port
            }
            Some(port) => port,
        };
        let access_text = entry.access.as_deref().unwrap_or("quick");
        let (access, may_be_domain) = match access_text {
            "quick" | "none" => (Access::Fixed(access_text.to_owned()), false),
            "domain" => (Access::Fixed("domain".to_owned()), true),
            text => match placeholder::whole_input(text) {
                Some(id) => match questions.iter().find(|q| q.id == id) {
                    Some(q) if q.kind == QuestionKind::Choice && q.choices.iter().all(|c| matches!(c.value.as_str(), "quick" | "domain" | "none")) => {
                        let domain = q.choices.iter().any(|c| c.value == "domain");
                        (Access::Asked(id), domain)
                    }
                    Some(_) => {
                        problems.push(problem("invalid_value", format!("public: {name}: access {text} must come from a choice input whose values are quick, domain or none.")).at(path.clone()));
                        (Access::Fixed("quick".into()), false)
                    }
                    None => {
                        problems.push(problem("unknown_input", format!("public: {name}: {text} names no input.")).at(path.clone()));
                        (Access::Fixed("quick".into()), false)
                    }
                },
                None => {
                    problems.push(problem("invalid_value", format!("public: {name}: access must be quick, domain or none, or {{{{inputs.ID}}}} of a choice input with those values.")).at(path.clone()));
                    (Access::Fixed("quick".into()), false)
                }
            },
        };
        match entry.domain.as_deref() {
            None if may_be_domain => problems.push(problem("missing_field", format!("public: {name} needs domain: a saved domain, usually {{{{inputs.ID}}}} of a domain input.")).at(path.clone())),
            None => {}
            Some(domain) => {
                if domain.contains("{{") {
                    if let Err(error) = placeholder::check(domain, Place::Public, &known) {
                        problems.push(problem("invalid_placeholder", format!("public: {name}: {error}")).at(path.clone()));
                    }
                } else if !hostname(&domain.to_ascii_lowercase()) {
                    problems.push(problem("invalid_value", format!("public: {name}: domain {} is not a domain name.", text::shown(domain))).at(path.clone()));
                }
            }
        }
        public.push(CheckedPublic { environment: name.to_owned(), port, access, domain: entry.domain.clone() });
    }
    // Models started with `yougori run MODEL --template INSTANCE` go to one environment.
    let models = if files.contains_key(MODELS_FILE) {
        match parse_yaml::<Models>(files, MODELS_FILE, limits::MANIFEST_BYTES.max) {
            Ok(models) => {
                if !environments.contains_key(&models.environment) && !resources.get(&models.environment).is_some_and(|r| r.kind == Kind::Environment) {
                    problems.push(problem("unknown_resource", format!("{MODELS_FILE}: environment {} is not an environment in {project_path}.", text::shown(&models.environment))).at(MODELS_FILE.to_owned()));
                }
                if models.command.is_empty() || models.command.len() > 16 || models.command.iter().any(|part| part.is_empty() || part.chars().count() > 512 || !text::one_line(part)) {
                    problems.push(problem("invalid_value", format!("{MODELS_FILE}: command is the program and its arguments, such as [python, /app/register.py]: 1 to 16 one-line parts.")).at(MODELS_FILE.to_owned()));
                }
                Some(models)
            }
            Err(error) => {
                problems.push(problem("invalid_format", error).at(MODELS_FILE.to_owned()));
                None
            }
        }
    } else {
        None
    };
    // A connection that attaches a model to the package's models environment: only to a model
    // service, and only from the environment yougori-models.yaml names.
    for resource in resources.values().filter(|r| r.kind == Kind::Connection && r.spec.get("model_request").and_then(Yaml::as_bool) == Some(true)) {
        let path = format!("{project_path}.resources.{}.spec.model_request", resource.id);
        let from = resource.spec.get("from").and_then(|f| f.get("resource")).and_then(Yaml::as_str).unwrap_or_default();
        let to = resource.spec.get("to");
        let to_kind = to.and_then(|t| t.get("resource")).and_then(Yaml::as_str).and_then(|id| ids.get(id).copied())
            .or_else(|| to.and_then(|t| t.get("binding")).and_then(Yaml::as_str).and_then(|id| bindings.iter().find(|b| b.id == id)).and_then(|b| b.resource));
        if to_kind != Some(Kind::ModelService) {
            problems.push(problem("invalid_value", format!("{project_path}: {}: model_request needs to: a model_service resource, or a binding of type resource with resource: model_service.", resource.id)).at(path.clone()));
        }
        match &models {
            Some(models) if models.environment == from => {}
            Some(_) => problems.push(problem("invalid_value", format!("{project_path}: {}: model_request runs {MODELS_FILE}'s command in its environment, so from: must be that environment.", resource.id)).at(path)),
            None => problems.push(problem("missing_file", format!("{project_path}: {}: model_request needs {MODELS_FILE} in the package, naming the environment and the command that attaches a model.", resource.id)).at(path)),
        }
    }
    // Steps and outputs.
    let mut steps = Vec::new();
    if !limits::STEPS.allows(template.steps.len()) {
        problems.push(problem("limit_exceeded", limits::STEPS.exceeded(template.steps.len())).at("steps".to_owned()));
    }
    for (index, step) in template.steps.iter().enumerate() {
        let label = format!("steps: step {}", index + 1);
        let path = format!("steps[{index}]");
        let mut plain = Vec::new();
        text_field(&mut plain, step.title.as_deref(), &format!("{label}: title"), limits::STEP_TITLE_CHARS.max, Some(format!("{label}: add title.")));
        if step.detail.as_deref().is_some_and(|d| d.chars().count() > limits::STEP_DETAIL_CHARS.max) {
            plain.push(format!("{label}: detail is longer than {} characters.", limits::STEP_DETAIL_CHARS.max));
        }
        text_field(&mut plain, step.command.as_deref(), &format!("{label}: command"), limits::STEP_COMMAND_CHARS.max, None);
        problems.extend(plain.into_iter().map(|p| problem("invalid_value", p).at(path.clone())));
        for text in [&step.title, &step.detail, &step.command].into_iter().flatten() {
            if let Err(error) = placeholder::check(text, Place::Step, &known) {
                problems.push(problem("invalid_placeholder", format!("{label}: {error}")).at(path.clone()));
            }
        }
        let when = match &step.when {
            None => None,
            Some(when) => match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => Some(when),
                Err(errors) => {
                    problems.extend(errors);
                    None
                }
            },
        };
        steps.push(CheckedStep { title: step.title.clone().unwrap_or_default(), detail: step.detail.clone(), command: step.command.clone(), when });
    }
    if !limits::OUTPUTS.allows(template.outputs.len()) {
        problems.push(problem("limit_exceeded", limits::OUTPUTS.exceeded(template.outputs.len())).at("outputs".to_owned()));
    }
    let mut output_keys = BTreeSet::new();
    let mut outputs = Vec::new();
    for (index, output) in template.outputs.iter().enumerate() {
        let label = format!("outputs: output {}", index + 1);
        let path = format!("outputs[{index}]");
        let mut plain = Vec::new();
        text_field(&mut plain, output.label.as_deref(), &format!("{label}: label"), limits::LABEL_CHARS.max, Some(format!("{label}: add label.")));
        text_field(&mut plain, output.value.as_deref(), &format!("{label}: value"), limits::OUTPUT_VALUE_CHARS.max, Some(format!("{label}: add value.")));
        if let Some(key) = &output.key {
            if !valid_id(key) {
                plain.push(format!("{label}: key must be {ID_RULE}."));
            } else if !output_keys.insert(key.clone()) {
                plain.push(format!("{label}: key {key} is used twice."));
            }
        }
        problems.extend(plain.into_iter().map(|p| problem("invalid_value", p).at(path.clone())));
        for text in [&output.label, &output.value].into_iter().flatten() {
            if let Err(error) = placeholder::check(text, Place::Output, &known) {
                problems.push(problem("invalid_placeholder", format!("{label}: {error}")).at(path.clone()));
            }
        }
        let when = match &output.when {
            None => None,
            Some(when) => match condition::parse(when, &questions, &format!("{path}.when")) {
                Ok(when) => Some(when),
                Err(errors) => {
                    problems.extend(errors);
                    None
                }
            },
        };
        outputs.push(CheckedOutput { key: output.key.clone(), label: output.label.clone().unwrap_or_default(), value: output.value.clone().unwrap_or_default(), private: output.private, when });
    }
    // Views and retention.
    if !limits::VIEWS.allows(template.views.len()) {
        problems.push(problem("limit_exceeded", limits::VIEWS.exceeded(template.views.len())).at("views".to_owned()));
    }
    for (key, value) in &template.limits {
        let at = format!("limits.{key}");
        if !LIMITS.iter().any(|(known, _)| known == key) {
            problems.push(problem("unknown_field", format!("limits: {} is not something a template can cap. Use one of {}.", text::shown(key), LIMITS.iter().map(|(known, _)| *known).collect::<Vec<_>>().join(", "))).at(at));
            continue;
        }
        let fine = match value {
            Yaml::Number(number) => number.as_f64().is_some_and(|number| number.is_finite() && number > 0.0),
            Yaml::String(text) => placeholder::whole_input(text).is_some_and(|input| questions.iter().any(|question| question.id == input && question.kind == QuestionKind::Number)),
            _ => false,
        };
        if !fine {
            problems.push(problem("invalid_value", format!("limits: {key} is a number above zero, or {{{{inputs.ID}}}} of a number question.")).at(at));
        }
    }
    let mut views_seen = BTreeSet::new();
    for view in &template.views {
        if !VIEWS.contains(&view.as_str()) && !matches!(view.as_str(), "overview" | "activity" | "settings") {
            problems.push(problem("unknown_view", format!("views: {} is not a standard view. Use one of {}.", text::shown(view), VIEWS.join(", "))).at("views".to_owned()));
        } else if !views_seen.insert(view.clone()) {
            problems.push(problem("duplicate_id", format!("views lists {view} twice.")).at("views".to_owned()));
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    let checked = Checked {
        format: FormatVersion::V2,
        retention: template.retention.unwrap_or_default(),
        views: template.views.clone(),
        template,
        project_path,
        project_text,
        project,
        profile,
        questions,
        capabilities,
        bindings,
        tools,
        environments,
        connections,
        public,
        resources,
        steps,
        outputs,
        models,
    };
    // A cycle is refused here, not first when someone runs the template: the graph is built as
    // the planner builds it. What an import adds is checked when the import is resolved.
    match crate::graph::Graph::from_checked(&checked) {
        Ok(graph) => {
            if let Some(path) = graph.cycle() {
                return Err(vec![problem("dependency_cycle", format!("The resources depend on each other in a cycle: {}. Remove one of these dependencies.", path.join(" -> ")))]);
            }
        }
        Err(problems) => return Err(problems),
    }
    Ok(checked)
}

/// An environment or project name as the engine accepts it.
pub fn workload_identifier(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_demonstration_password_is_never_a_default_on_a_question_that_holds_one() {
        // A default is what most people keep. "changeme" shipped as the default of an admin
        // password is the real password of every setup made from that template, and the person
        // running it never typed anything, so they never thought about it.
        for weak in ["changeme", "CHANGEME", " password ", "admin123", "letmein", "123456", "your-password-here", "REPLACE_ME", "TODO", "xxxxxx"] {
            assert!(demonstration_password(weak), "{weak} should be refused as a default");
        }
        // Real-looking values are left alone; this must not refuse someone's actual choice.
        for fine in ["", "a7f3Qp2xLm9", "the shop's own key", "correct horse battery staple"] {
            assert!(!demonstration_password(fine), "{fine:?} should be allowed");
        }

        // It applies to the questions that hold a credential, by what they are called.
        assert!(credential_question("admin_password", "Admin password?"));
        assert!(credential_question("api_key", "Which key?"));
        assert!(credential_question("join", "The join token for the cluster?"));
        assert!(credential_question("x", "Your API key"));
        // And not to ordinary ones, where "example" is a perfectly good default.
        assert!(!credential_question("title", "What is it called?"));
        assert!(!credential_question("port", "Which port?"));

        // End to end, through the real check.
        let template = |extra: &str| format!(
            "format_version: 2\nkind: template\nname: shop\nsummary: A shop.\nversion: 1.0.0\nlicense: MIT\nrequires: {{yougori: 1.2.0}}\ninputs:\n{extra}public:\n  - {{environment: web, port: 8080}}\n"
        );
        let project = "format_version: 2\nproject: shop\nenvironments:\n  web:\n    image: nginx:1.27\n    ports: [8080]\n";
        let package = |text: &str| -> Vec<Diagnostic> {
            let files: Files = [(TEMPLATE_FILE.to_owned(), text.as_bytes().to_vec()), ("yougori.yaml".to_owned(), project.as_bytes().to_vec())].into_iter().collect();
            super::template(&files).err().unwrap_or_default()
        };

        let said = package(&template("  - {id: admin_password, question: Admin password?, type: text, group: people_access, default: changeme}\n"));
        assert!(
            said.iter().any(|d| d.message.contains("demonstration password")),
            "a demonstration password default should be refused: {:?}",
            said.iter().map(|d| d.message.as_str()).collect::<Vec<_>>(),
        );

        // The same question with a real default is fine, so the rule is about the value.
        let said = package(&template("  - {id: admin_password, question: Admin password?, type: text, group: people_access, default: a7f3Qp2xLm9}\n"));
        assert!(!said.iter().any(|d| d.message.contains("demonstration password")), "{said:?}");

        // And an ordinary question keeps its ordinary default.
        let said = package(&template("  - {id: title, question: Title?, type: text, group: website_api, default: example}\n"));
        assert!(!said.iter().any(|d| d.message.contains("demonstration password")), "{said:?}");
    }

    #[test]
    fn the_format_version_decides_who_reads_the_file() {
        assert_eq!(format_version("name: x\n").unwrap(), FormatVersion::V1);
        assert_eq!(format_version("format_version: 1\nname: x\n").unwrap(), FormatVersion::V1);
        assert_eq!(format_version("format_version: 2\nname: x\n").unwrap(), FormatVersion::V2);
        assert_eq!(format_version("format_version: \"2\"\n").unwrap(), FormatVersion::V2);
        let newer = format_version("format_version: 3\n").unwrap_err();
        assert_eq!(newer.code, "needs_newer_yougori");
        assert!(newer.message.starts_with("This template needs a newer Yougori."), "{}", newer.message);
        assert_eq!(format_version("format_version: soon\n").unwrap_err().code, "needs_newer_yougori");
        assert_eq!(format_version("- a\n").unwrap_err().code, "invalid_format");
        assert_eq!(format_version("a: [\n").unwrap_err().code, "invalid_yaml");
    }

    #[test]
    fn names_versions_digests_and_paths_follow_the_hub_rules() {
        assert!(valid_name("my-api") && !valid_name("My API") && !valid_name("-x"));
        assert!(valid_id("web_1") && !valid_id("Web") && !valid_id("1web") && !valid_id(&"a".repeat(33)));
        assert!(parse_version("1.2.0").is_ok() && parse_version("1.2").is_err() && parse_version("1.0.0+build").is_err());
        assert!(newer("1.2.0", "1.1.2") && !newer("1.1.2", "1.2.0") && !newer("x", "1.0.0"));
        assert!(valid_digest(&"a".repeat(64)) && !valid_digest(&"A".repeat(64)) && !valid_digest("abc"));
        assert!(check_path("app/server.js").is_ok());
        for bad in ["", "/abs", "a/../b", "a/./b", "con.txt", "x/COM1", "name. ", "a\u{200b}b", "a:b", "a\\b"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert!(clashing(["App/a.js", "app/A.js"]).unwrap().contains("same file"));
        assert!(clashing(["readme", "readme/x"]).unwrap().contains("inside a folder"));
        assert!(clashing(["a", "b/a"]).is_none());
        assert_eq!(inside("", "./site/").unwrap(), "site");
        assert!(inside("", "../out").is_err());
        assert_eq!(hub_ref("hub/acme/my-api@1.2.0").unwrap(), ("acme/my-api".to_owned(), Some("1.2.0".to_owned())));
        assert!(hub_ref("hub/Acme/x").unwrap_err().contains("lowercase"));
        assert_eq!(gib(&serde_json::json!("512MB")).unwrap(), 0.5);
        assert!(hostname("app.example.com") && !hostname("localhost"));
    }

    const HTTPIE: &str = "kind: tool\nname: httpie\ntitle: HTTPie\nsummary: A command-line HTTP client.\nversion: 1.0.0\nlicense: MIT\ncommand: http\ninstall:\n  - python3 -m pip install --user httpie==3.2.4\ncheck: http --version\nsignin: {method: api-key, variable: HTTPIE_TOKEN}\nneeds: {internet: true}\n";

    fn tool_of(extra: &str) -> Result<Tool, Vec<String>> {
        let files = Files::from([(TOOL_FILE.to_owned(), format!("{HTTPIE}{extra}").into_bytes())]);
        tool(&files, "")
    }

    /// PROVES the portable tool metadata (declared access, inputs, outputs) is read, bounded and
    /// checked like the fields beside it, and summed up in words for a review.
    #[test]
    fn a_tools_declared_access_inputs_and_outputs_are_checked_and_said_in_words() {
        let declared = tool_of("access: {internet: true, folders: [/workspace/.httpie]}\ninputs:\n  - {name: HTTPIE_TOKEN, secret: true, about: The token sent with every request.}\n  - {name: HTTPIE_CONFIG_DIR}\noutputs:\n  - {name: report, path: /workspace/report.json, about: The last response.}\n").unwrap();
        assert_eq!(declared.access.as_ref().unwrap().folders, ["/workspace/.httpie"]);
        assert_eq!(declared.inputs.len(), 2);
        assert!(declared.inputs[0].secret && !declared.inputs[0].required);
        assert_eq!(declared.outputs[0].path.as_deref(), Some("/workspace/report.json"));
        assert_eq!(declared.declared_access(), ["uses the internet", "writes /workspace/.httpie", "reads the secret HTTPIE_TOKEN", "reads HTTPIE_CONFIG_DIR"]);
        assert!(tool_of("").unwrap().declared_access().is_empty(), "nothing declared, nothing said");

        let said = |extra: &str| tool_of(extra).unwrap_err().join("\n");
        assert!(said("inputs: [{name: 1bad}]\n").contains("name 1bad is not an environment variable name"), "{}", said("inputs: [{name: 1bad}]\n"));
        assert!(said("inputs: [{name: A}, {name: A}]\n").contains("inputs lists A twice"));
        assert!(said("inputs: [{name: HTTPIE_TOKEN}]\n").contains("HTTPIE_TOKEN is the sign-in key, so it must say secret: true"));
        assert!(said(&format!("inputs: [{{name: A, about: {}}}]\n", "x".repeat(limits::HINT_CHARS.max + 1))).contains("inputs[1].about must be one line"));
        assert!(said("access: {folders: [relative/x]}\n").contains("relative/x is not an absolute folder inside the sandbox"));
        assert!(said("access: {folders: [/a/../b]}\n").contains("is not an absolute folder"));
        assert!(said("outputs: [{name: Report}]\n").contains("name Report must be lowercase letters, digits and underscores"));
        assert!(said("outputs: [{name: r, path: workspace}]\n").contains("path workspace is not an absolute path"));
        assert!(said("outputs: [{name: r}, {name: r}]\n").contains("outputs lists r twice"));
        let many = (0..=limits::INPUTS.max).map(|n| format!("  - {{name: V{n}}}\n")).collect::<String>();
        assert!(said(&format!("inputs:\n{many}")).contains("Too many inputs"));
        assert!(said("access: {network: all}\n").contains("not valid"), "an unknown key under access is refused rather than ignored");
    }

    /// PROVES a Hub tool's use carries what the resolver found, and reads as a bundled tool does.
    #[test]
    fn a_resolved_hub_tool_reads_like_a_bundled_one() {
        let files = Files::from([(TOOL_FILE.to_owned(), HTTPIE.as_bytes().to_vec())]);
        let httpie = tool(&files, "").unwrap();
        let mut use_ = ToolUse { environment: "web".into(), spec: "hub/acme/httpie@1.0.0".into(), source: Source::Hub { item: "acme/httpie".into(), version: Some("1.0.0".into()) }, when: None, signin: false, signin_when: None, signin_hint: None, signin_source: None, resolved: None };
        assert!(use_.tool().is_none(), "unresolved, its file is not at hand");
        use_.resolved = Some(ResolvedTool { tool: httpie.clone(), version: "1.0.0".into(), digest: "a".repeat(64), verified: false });
        assert_eq!(use_.tool(), Some(&httpie));
        assert_eq!(use_.name(), "acme/httpie", "the review still names the Hub item");
        let again: ToolUse = serde_json::from_value(serde_json::to_value(&use_).unwrap()).unwrap();
        assert_eq!(again, use_);
        let built_in = ToolUse { source: Source::BuiltIn { name: "codex".into() }, resolved: None, ..use_.clone() };
        assert!(built_in.tool().is_none());
        assert!(!serde_json::to_string(&built_in).unwrap().contains("resolved"));
    }
}
