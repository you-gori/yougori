//! The template and tool formats (docs/hub.md sections 3 and 4) and every rule they follow. A
//! folder is read from its files, so a folder on this computer, a downloaded version and an
//! upload are checked by exactly the same code.
use super::{
    pattern::Pattern,
    refs::{self, Ref},
    render::{self, Known, Place},
    scan::{self, Files},
    unicode,
};
use crate::manifest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml_ng::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

pub const TEMPLATE_FILE: &str = "yougori-template.yaml";
pub const TOOL_FILE: &str = "yougori-tool.yaml";

pub const LICENSES: &[&str] = &[
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "CC0-1.0", "Zlib",
    "BSL-1.0", "MPL-2.0", "EPL-2.0", "EUPL-1.2", "Artistic-2.0", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
];

pub const PLATFORMS: &[&str] = &["windows-x86_64", "windows-aarch64", "macos-x86_64", "macos-aarch64", "linux-x86_64", "linux-aarch64"];

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

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Template {
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
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changelog: Option<String>,
    #[serde(default, skip_serializing_if = "Requires::is_empty")]
    pub requires: Requires,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Input>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public: Vec<Public>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<Output>,
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
    fn is_empty(&self) -> bool {
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
    pub when: Option<BTreeMap<String, Yaml>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
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
}

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
    /// The title, or the name when there is none.
    pub fn title(&self) -> &str {
        self.title.as_deref().filter(|title| !unicode::js_trim(title).is_empty()).unwrap_or_else(|| self.name())
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
    /// The manifest the Hub stores: the parsed file as JSON, always with its kind.
    pub fn manifest(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or(Value::Null);
        value["kind"] = "tool".into();
        value
    }
}

impl Template {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }
    /// The title, or the name when there is none.
    pub fn title(&self) -> &str {
        self.title.as_deref().filter(|title| !unicode::js_trim(title).is_empty()).unwrap_or_else(|| self.name())
    }
    pub fn version(&self) -> &str {
        self.version.as_deref().unwrap_or_default()
    }
    pub fn project_path(&self) -> &str {
        self.project.as_deref().unwrap_or("yougori.yaml")
    }
    pub fn manifest(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or(Value::Null);
        value["kind"] = "template".into();
        value
    }
}

/// The kinds of question a template asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Choice,
    Text,
    Number,
    Secret,
    Domain,
    YesNo,
}

impl Kind {
    fn read(text: &str) -> Option<Kind> {
        Some(match text {
            "choice" => Kind::Choice,
            "text" => Kind::Text,
            "number" => Kind::Number,
            "secret" => Kind::Secret,
            "domain" => Kind::Domain,
            "yesno" => Kind::YesNo,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::Choice => "choice",
            Kind::Text => "text",
            Kind::Number => "number",
            Kind::Secret => "secret",
            Kind::Domain => "domain",
            Kind::YesNo => "yesno",
        }
    }
}

/// One option of a choice question.
#[derive(Clone, Debug, PartialEq)]
pub struct Option_ {
    pub value: String,
    pub label: String,
    pub hint: String,
}

/// A question after its checks, ready to be asked.
#[derive(Clone, Debug)]
pub struct Question {
    pub id: String,
    pub question: String,
    pub kind: Kind,
    pub required: bool,
    pub default: Option<String>,
    /// Asked only when the earlier input `.0` was answered `.1`.
    pub when: Option<(String, String)>,
    pub hint: String,
    pub choices: Vec<Option_>,
    pub pattern: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

fn number_text(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e15 { format!("{}", number as i64) } else { number.to_string() }
}

impl Question {
    /// Whether this question is asked, given the answers so far.
    pub fn asked(&self, answers: &BTreeMap<String, String>) -> bool {
        self.when.as_ref().is_none_or(|(id, value)| answers.get(id) == Some(value))
    }
    /// An answer as stored, or why it is not one. `domains` lists the saved domains when known.
    pub fn answer(&self, given: &str, domains: Option<&[String]>) -> Result<String, String> {
        let given = if self.kind == Kind::Secret { given } else { given.trim() };
        if given.is_empty() {
            return Err("Give an answer.".into());
        }
        match self.kind {
            Kind::Choice => self.choices.iter().find(|choice| choice.value == given || choice.label.eq_ignore_ascii_case(given))
                .map(|choice| choice.value.clone())
                .ok_or_else(|| format!("Choose one of: {}.", self.choices.iter().map(|c| c.value.as_str()).collect::<Vec<_>>().join(", "))),
            Kind::YesNo => match given.to_ascii_lowercase().as_str() {
                "yes" | "y" | "true" => Ok("yes".into()),
                "no" | "n" | "false" => Ok("no".into()),
                _ => Err("Answer yes or no.".into()),
            },
            Kind::Number => {
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
            Kind::Text => {
                if given.chars().count() > 500 {
                    return Err("Keep the answer to 500 characters.".into());
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
            Kind::Domain => {
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
            Kind::Secret => {
                if given.len() > 65536 || given.contains(['\0', '\r', '\n']) {
                    return Err("A secret must be one line of at most 64 KiB.".into());
                }
                Ok(given.to_owned())
            }
        }
    }
    /// A representative answer for checking a template without asking anything.
    fn sample(&self) -> String {
        if let Some(default) = &self.default {
            return default.clone();
        }
        match self.kind {
            Kind::Choice => self.choices.first().map(|c| c.value.clone()).unwrap_or_default(),
            Kind::Text => "sample".into(),
            Kind::Number => number_text(self.min.or(self.max).unwrap_or(1.0)),
            Kind::Secret => String::new(),
            Kind::Domain => "app.example.com".into(),
            Kind::YesNo => "yes".into(),
        }
    }
}

pub fn hostname(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Where a template's tool comes from.
#[derive(Clone, Debug)]
pub enum Source {
    BuiltIn(String),
    /// A folder in the template, with its checked tool file.
    Bundled { folder: String, tool: Box<Tool> },
    Hub(Ref),
}

/// One tool installed into one environment.
#[derive(Clone, Debug)]
pub struct ToolUse {
    pub environment: String,
    /// As written in `tools:`.
    pub spec: String,
    pub source: Source,
}

impl ToolUse {
    /// The tool's name as the review shows it.
    pub fn name(&self) -> String {
        match &self.source {
            Source::BuiltIn(name) => name.clone(),
            Source::Bundled { tool, .. } => tool.name().to_owned(),
            Source::Hub(reference) => reference.item(),
        }
    }
}

/// A template folder after every check: what a run, a review and an upload need.
#[derive(Clone, Debug)]
pub struct Folder {
    pub template: Template,
    pub project_path: String,
    pub project_text: String,
    /// The project as written, placeholders included.
    pub project: manifest::Project,
    pub questions: Vec<Question>,
    pub tools: Vec<ToolUse>,
}

impl Folder {
    /// Whether an environment uses a GPU.
    pub fn gpu_environments(&self) -> Vec<String> {
        self.project.environments.iter().filter(|(_, e)| e.gpu || e.kind == "gpu").map(|(name, _)| name.clone()).collect()
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
    /// Environments with PC folders or PC access.
    pub fn pc_access(&self) -> bool {
        self.project.environments.values().any(|e| e.permissions.pc || !e.pc_access.is_empty() || e.volumes.iter().any(|v| v.bind))
    }
}

/// One line of plain text: no control characters and nothing invisible that could make it read
/// as something else (bidi controls, zero-width characters).
fn one_line(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || unicode::hidden(c))
}

/// Text the Hub shows as typed, by the website's rules: trimmed, at most `max` characters as it
/// counts them (UTF-16 units), no control characters, on one line unless `lines`, and nothing
/// invisible or stacked accents.
fn hub_text(problems: &mut Vec<String>, value: Option<&str>, field: &str, max: usize, lines: bool, missing: Option<String>) {
    let text = value.map(unicode::js_trim).unwrap_or_default();
    if text.is_empty() {
        problems.extend(missing);
        return;
    }
    if unicode::utf16_len(text) > max {
        problems.push(format!("{field} is longer than {max} characters."));
    }
    if text.chars().any(unicode::control) || (!lines && text.contains(['\r', '\n', '\t'])) {
        problems.push(if lines { format!("{field} contains control characters. Write it in plain text.") } else { format!("{field} must be one line, without tabs or control characters.") });
    }
    if text.chars().any(unicode::hidden) || unicode::stacked_marks(text) {
        problems.push(format!("{field} contains invisible characters or stacked accents. Write it in plain text."));
    }
}

/// What the website would refuse in a text it shows (a report's details, a changelog): see
/// [`hub_text`].
pub fn text_problems(value: &str, field: &str, max: usize, lines: bool) -> Vec<String> {
    let mut problems = Vec::new();
    hub_text(&mut problems, Some(value), field, max, lines, None);
    problems
}

/// Whether `word` stands on its own in `text`, as `\bWORD\b` with `i` reads it (ASCII letters).
fn whole_word(text: &str, word: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let joins = |byte: Option<&u8>| byte.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    lower.match_indices(word).any(|(at, _)| !joins(at.checked_sub(1).and_then(|before| bytes.get(before))) && !joins(bytes.get(at + word.len())))
}

/// Only Yougori shows the Verified badge: a title or summary may not imitate it with the word
/// verified, check marks, or (in a title) the word official. `title_field` names where the title
/// comes from: the title, or the name when there is none.
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
        Some(text) if !one_line(text) => problems.push(format!("{field} must be one line.")),
        Some(_) => {}
    }
}

fn topic(text: &str) -> bool {
    !text.is_empty() && text.len() <= 32 && text.as_bytes()[0].is_ascii_alphanumeric()
        && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The name, title, summary, version, licence, topics and changelog every item has.
#[allow(clippy::too_many_arguments)]
fn metadata(problems: &mut Vec<String>, kind: &str, file: &str, declared: Option<&str>, name: Option<&str>, title: Option<&str>, summary: Option<&str>, version: Option<&str>, license: Option<&str>, topics: &[String], changelog: Option<&str>) {
    if declared.is_some_and(|declared| declared != kind) {
        problems.push(format!("kind in {file} must be {kind} (templates use {TEMPLATE_FILE}, tools {TOOL_FILE})."));
    }
    match name {
        None => problems.push(format!("Add name: the {kind}'s Hub name, using {}.", refs::NAME_RULE)),
        Some(name) if !refs::valid_name(name) => problems.push(format!("name {} is not a Hub name: use {}.", scan::shown(name), refs::NAME_RULE)),
        Some(_) => {}
    }
    hub_text(problems, title, "title", 80, false, None);
    hub_text(problems, summary, "summary", 200, false, Some(format!("Add summary: one line of at most 200 characters about what the {kind} does.")));
    let named = title.filter(|title| !unicode::js_trim(title).is_empty());
    let shown_title = named.or(name).unwrap_or_default();
    problems.extend(badge_words(shown_title, if named.is_some() { "title" } else { "name (the title when there is none)" }, summary.unwrap_or_default()));
    match version {
        None => problems.push("Add version: MAJOR.MINOR.PATCH such as 1.0.0.".into()),
        Some(version) => {
            if let Err(error) = refs::parse_version(version) {
                problems.push(format!("version: {error}"));
            }
        }
    }
    match license {
        None => problems.push("Add license: an open-source licence such as MIT or Apache-2.0. Everything on the Hub is open source.".into()),
        Some(license) if !LICENSES.contains(&license) => problems.push(format!("license {} is not an accepted open-source licence. Use one of: {}.", scan::shown(license), LICENSES.join(", "))),
        Some(_) => {}
    }
    // The website counts each topic once.
    if topics.iter().collect::<BTreeSet<_>>().len() > 10 {
        problems.push("Use at most 10 topics.".into());
    }
    for item in topics.iter().filter(|item| !topic(item)) {
        problems.push(format!("topic {}: use lowercase words with dashes, such as ai or website.", scan::shown(item)));
    }
    hub_text(problems, changelog, "changelog", 4000, true, None);
}

fn parse_yaml<T: serde::de::DeserializeOwned>(files: &Files, path: &str) -> Result<T, String> {
    let bytes = files.get(path).ok_or_else(|| format!("{path} is missing."))?;
    let text = scan::text(bytes).ok_or_else(|| format!("{path} must be UTF-8 text."))?;
    serde_yaml_ng::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("{path} is not valid: {e}"))
}

/// A single shell line for a tool: not empty, one line, at most 4096 characters.
fn shell_line(problems: &mut Vec<String>, value: Option<&str>, field: &str, required: bool) {
    match value {
        None | Some("") if required => problems.push(format!("Add {field}: one shell line.")),
        None | Some("") => {}
        Some(line) if line.chars().count() > 4096 => problems.push(format!("{field} is longer than 4096 characters.")),
        Some(line) if line.contains(['\n', '\r', '\0']) => problems.push(format!("{field} must be a single shell line.")),
        // The review shows every line as written: nothing may hide or reorder what it runs.
        Some(line) if line.chars().any(|c| unicode::control(c) || unicode::hidden(c)) => problems.push(format!("{field} contains invisible or control characters. Write it in plain text.")),
        Some(_) => {}
    }
}

/// A tool folder: `prefix` is where it sits in `files` (empty for the folder itself).
pub fn tool(files: &Files, prefix: &str) -> Result<Tool, Vec<String>> {
    let path = if prefix.is_empty() { TOOL_FILE.to_owned() } else { format!("{prefix}/{TOOL_FILE}") };
    let tool: Tool = parse_yaml(files, &path).map_err(|e| vec![e])?;
    let mut problems = Vec::new();
    metadata(&mut problems, "tool", TOOL_FILE, tool.kind.as_deref(), tool.name.as_deref(), tool.title.as_deref(), tool.summary.as_deref(), tool.version.as_deref(), tool.license.as_deref(), &tool.topics, tool.changelog.as_deref());
    shell_line(&mut problems, tool.command.as_deref(), "command", true);
    shell_line(&mut problems, tool.check.as_deref(), "check", true);
    if tool.install.len() > 32 {
        problems.push("install has more than 32 lines.".into());
    }
    for (index, line) in tool.install.iter().enumerate() {
        shell_line(&mut problems, Some(line.as_str()), &format!("install line {}", index + 1), true);
    }
    if let Some(signin) = &tool.signin {
        let method = signin.method.as_deref().unwrap_or("none");
        match method {
            "none" | "browser" | "device" | "api-key" => {}
            other => problems.push(format!("signin.method {} is not a sign-in method. Use none, browser, device or api-key.", scan::shown(other))),
        }
        if matches!(method, "browser" | "device") {
            shell_line(&mut problems, signin.command.as_deref(), "signin.command", true);
        } else if signin.command.is_some() {
            problems.push("signin.command works only with method: browser or device.".into());
        }
        match (method, signin.variable.as_deref()) {
            ("api-key", None) => problems.push("Add signin.variable: the environment variable the API key goes into, such as OPENAI_API_KEY.".into()),
            ("api-key", Some(variable)) if !variable_name(variable) => problems.push(format!("signin.variable {} is not an environment variable name.", scan::shown(variable))),
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
            if manifest::gib(&Value::String(memory.clone())).or_else(|_| manifest::gib(&serde_json::json!(memory.parse::<f64>().unwrap_or(-1.0)))).map_or(true, |gb| gb > 1024.0) {
                problems.push(format!("needs.memory {} is not a size such as 4GB.", scan::shown(memory)));
            }
        }
    }
    if let Some(service) = &tool.service {
        shell_line(&mut problems, service.command.as_deref(), "service.command", true);
        if service.port.is_none_or(|port| port == 0) {
            problems.push("service.port must be a port from 1 to 65535.".into());
        }
    }
    if problems.is_empty() { Ok(tool) } else { Err(problems) }
}

/// Whether an environment can receive secrets as variables (a tool's API key, a secret input).
pub fn key_ready(environment: &manifest::Environment) -> bool {
    matches!(environment.kind.as_str(), "container" | "gpu") || (environment.kind == "microvm" && !environment.image.is_empty())
}

/// The memory a tool needs, in GB, when it says.
pub fn tool_memory(tool: &Tool) -> Option<f64> {
    let memory = tool.needs.as_ref()?.memory.as_deref()?;
    manifest::gib(&Value::String(memory.into())).ok().or_else(|| memory.parse::<f64>().ok().filter(|n| *n > 0.0))
}

fn variable_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && name.bytes().enumerate().all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

/// A path inside the template written as `./site` or `site/`: the plain relative form, or why not.
fn inside(base: &str, path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.starts_with('\\') || std::path::Path::new(trimmed).is_absolute() || trimmed.contains(':') {
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

/// What is wrong with the paths an environment reads on this computer: its files, its PC
/// folders and a VM's boot source must be fixed paths inside the template folder. No answer may
/// choose them: a placeholder there could reach any folder on the computer.
fn environment_paths(environment: &manifest::Environment, base: &str, files: &Files) -> Vec<String> {
    let mut problems = Vec::new();
    let mut placeholder = |what: &str, path: &str| {
        let found = path.contains("{{");
        if found {
            problems.push(format!("{what} {} cannot contain a placeholder: a path on this computer is part of the template, never an answer.", scan::shown(path)));
        }
        found
    };
    let mut checks: Vec<(String, &str, bool)> = Vec::new();
    if let Some(source) = environment.source.as_deref().filter(|s| *s != "builtin:alpine") {
        checks.push(("source".into(), source, false));
    }
    for file in &environment.files {
        checks.push(("files source".into(), file.source.as_str(), false));
    }
    for folder in environment.volumes.iter().filter(|v| v.bind).map(|v| v.source.as_str()).chain(environment.pc_access.iter().map(|p| p.path.as_str())) {
        checks.push(("the PC folder".into(), folder, true));
    }
    let mut refused = Vec::new();
    for (what, path, _) in &checks {
        if placeholder(what, path) {
            refused.push(*path);
        }
    }
    for (what, path, folder) in checks {
        if refused.contains(&path) {
            continue;
        }
        match (inside(base, path), folder) {
            (Ok(found), _) if exists(files, &found) => {}
            (Ok(_), true) => problems.push(format!("the PC folder {} is not in the template folder. Add a file to it, such as {}/.keep.", scan::shown(path), scan::shown(path.trim_end_matches('/')))),
            (Ok(_), false) => problems.push(format!("{what} {} is not in the template folder.", scan::shown(path))),
            (Err(_), true) => problems.push(format!("a template cannot use folders outside its own folder ({}). Use a folder inside the template.", scan::shown(path))),
            (Err(why), false) => problems.push(format!("{what} {} {why}.", scan::shown(path))),
        }
    }
    problems
}

/// Checks the project a run is about to apply once more, after its placeholders were filled in:
/// every path it reads on this computer is still inside the instance's files.
pub fn rendered_paths(project: &manifest::Project, project_path: &str, files: &Files) -> Result<(), String> {
    let base = project_path.rsplit_once('/').map_or("", |(folder, _)| folder);
    let problems: Vec<String> = project.environments.iter()
        .flat_map(|(name, environment)| environment_paths(environment, base, files).into_iter().map(move |p| format!("{name}: {p}")))
        .collect();
    if problems.is_empty() { Ok(()) } else { Err(format!("The project would read outside its own files, so nothing was created: {}", problems.join(" "))) }
}

/// Rules for check and publish only. A run converts host ports to container ports instead (an
/// upload made without this CLI never passed these), and resolves an unpinned tool to its latest
/// version with a warning.
pub fn publishing_problems(folder: &Folder) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, environment) in &folder.project.environments {
        for port in &environment.ports {
            if let Ok((guest, Some(host))) = port.values() {
                problems.push(format!("{}: {name}: ports fixes host port {host} for {guest}, so a second copy of the template could never start. List the container port only (ports: [{guest}]); Yougori picks a free port on each computer, and public: gives the internet address.", folder.project_path));
            }
        }
    }
    for use_ in &folder.tools {
        if let Source::Hub(reference) = &use_.source {
            if reference.version.is_none() {
                problems.push(format!("tools: {}: pin {} to a version, such as {}@1.0.0, so everyone who runs this template installs the same files.", use_.environment, use_.spec, use_.spec));
            }
        }
    }
    problems
}

/// Whether `files` has a file at `path` or a folder there.
fn exists(files: &Files, path: &str) -> bool {
    path.is_empty() || files.contains_key(path) || files.keys().any(|file| file.strip_prefix(path).is_some_and(|rest| rest.starts_with('/')))
}

fn input_problems(problems: &mut Vec<String>, inputs: &[Input]) -> Vec<Question> {
    let mut questions: Vec<Question> = Vec::new();
    if inputs.len() > 50 {
        problems.push("Use at most 50 inputs.".into());
    }
    for (index, input) in inputs.iter().enumerate() {
        let label = input.id.clone().unwrap_or_else(|| format!("input {}", index + 1));
        let mut bad = |text: String| problems.push(format!("inputs: {label}: {text}"));
        let id = input.id.clone().unwrap_or_default();
        let valid_id = id.len() <= 32 && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if input.id.is_none() {
            bad("add id: lowercase letters, digits or _, starting with a letter (at most 32).".into());
        } else if !valid_id {
            bad("id must be lowercase letters, digits or _, starting with a letter (at most 32).".into());
        } else if questions.iter().any(|q| q.id == id) {
            bad("this id is used twice.".into());
        }
        let question = input.question.clone().unwrap_or_default();
        if question.trim().is_empty() {
            bad("add question: the sentence the person answers.".into());
        } else if question.chars().count() > 200 || !one_line(&question) {
            bad("question must be one line of at most 200 characters.".into());
        }
        let hint = input.hint.clone().unwrap_or_default();
        if hint.chars().count() > 160 || !one_line(&hint) {
            bad("hint must be one line of at most 160 characters.".into());
        }
        let kind = match input.kind.as_deref().map(Kind::read) {
            None => {
                bad("add type: choice, text, number, secret, domain or yesno.".into());
                Kind::Text
            }
            Some(None) => {
                bad(format!("type {} is not a question type. Use choice, text, number, secret, domain or yesno.", scan::shown(input.kind.as_deref().unwrap_or_default())));
                Kind::Text
            }
            Some(Some(kind)) => kind,
        };
        let mut choices = Vec::new();
        if kind == Kind::Choice {
            if !(2..=12).contains(&input.choices.len()) {
                bad("a choice needs 2 to 12 choices.".into());
            }
            for choice in &input.choices {
                let value = choice.value.clone().unwrap_or_default();
                if !refs::valid_name(&value) {
                    bad(format!("choice value {} must be lowercase letters, digits, - or _ (at most 64).", scan::shown(&value)));
                } else if choices.iter().any(|c: &Option_| c.value == value) {
                    bad(format!("choice value {value} is used twice."));
                }
                let label = choice.label.clone().unwrap_or_default();
                if label.trim().is_empty() || label.chars().count() > 60 || !one_line(&label) {
                    bad(format!("choice {value} needs a label of one line, at most 60 characters."));
                }
                let hint = choice.hint.clone().unwrap_or_default();
                if hint.chars().count() > 160 || !one_line(&hint) {
                    bad(format!("choice {value}: hint must be one line of at most 160 characters."));
                }
                choices.push(Option_ { value, label, hint });
            }
        } else if !input.choices.is_empty() {
            bad("choices work only with type: choice.".into());
        }
        if input.pattern.is_some() && kind != Kind::Text {
            bad("pattern works only with type: text.".into());
        }
        if let Some(pattern) = &input.pattern {
            if let Err(error) = Pattern::parse(pattern) {
                bad(error);
            }
        }
        if (input.min.is_some() || input.max.is_some()) && kind != Kind::Number {
            bad("min and max work only with type: number.".into());
        }
        if input.min.zip(input.max).is_some_and(|(min, max)| min > max) {
            bad("min is larger than max.".into());
        }
        let default = match &input.default {
            None | Some(Yaml::Null) => None,
            Some(Yaml::String(text)) => Some(text.clone()),
            Some(Yaml::Number(number)) => Some(number.to_string()),
            Some(Yaml::Bool(value)) => Some(if *value { "yes" } else { "no" }.to_owned()),
            Some(_) => {
                bad("default must be a single value.".into());
                None
            }
        };
        let when = match &input.when {
            None => None,
            Some(map) if map.len() != 1 => {
                bad("when names exactly one earlier input and its answer, such as when: {access: domain}.".into());
                None
            }
            Some(map) => {
                let (other, value) = map.iter().next().unwrap();
                let value = match value {
                    Yaml::String(text) => text.clone(),
                    Yaml::Number(number) => number.to_string(),
                    Yaml::Bool(value) => if *value { "yes" } else { "no" }.to_owned(),
                    _ => String::new(),
                };
                match questions.iter().find(|q| &q.id == other) {
                    None => bad(format!("when names {}, which is not an earlier input.", scan::shown(other))),
                    Some(earlier) if earlier.kind == Kind::Secret => bad("when cannot depend on a secret.".into()),
                    Some(earlier) => {
                        if let Err(error) = earlier.answer(&value, None) {
                            bad(format!("when {other}: {} is not an answer to {other}. {error}", scan::shown(&value)));
                        }
                    }
                }
                Some((other.clone(), value))
            }
        };
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
        };
        if let Some(default) = default {
            if kind == Kind::Secret {
                bad("a secret cannot have a default: secrets never live in files.".into());
            } else if kind != Kind::Domain {
                match question.answer(&default, None) {
                    Ok(normal) => question.default = Some(normal),
                    Err(error) => bad(format!("default {} is not a valid answer. {error}", scan::shown(&default))),
                }
            } else {
                question.default = Some(default.to_ascii_lowercase());
            }
        }
        questions.push(question);
    }
    questions
}

/// Answers used to check a template without asking anything.
pub fn sample_values(folder_name: &str, questions: &[Question]) -> render::Values {
    let instance: String = folder_name.chars().take(40).collect::<String>().trim_end_matches(['-', '_']).to_owned();
    let instance = if instance.is_empty() { "template".to_owned() } else { instance };
    let mut values = render::Values { instance: instance.clone(), ..Default::default() };
    for question in questions {
        if question.kind == Kind::Secret {
            values.secrets.insert(question.id.clone(), render::secret_name(&instance, &question.id));
        } else {
            values.inputs.insert(question.id.clone(), question.sample());
        }
    }
    values
}

/// Reads and checks a template folder. Every problem is listed, each saying what to change.
pub fn template(files: &Files) -> Result<Folder, Vec<String>> {
    let template: Template = parse_yaml(files, TEMPLATE_FILE).map_err(|e| vec![e])?;
    let mut problems = Vec::new();
    metadata(&mut problems, "template", TEMPLATE_FILE, template.kind.as_deref(), template.name.as_deref(), template.title.as_deref(), template.summary.as_deref(), template.version.as_deref(), template.license.as_deref(), &template.topics, template.changelog.as_deref());
    // The project file.
    let project_path = template.project_path().to_owned();
    if let Err(error) = scan::check_path(&project_path) {
        problems.push(format!("project: {error}"));
    }
    if project_path == TEMPLATE_FILE {
        problems.push(format!("project must name the yougori.yaml project, not {TEMPLATE_FILE}."));
    }
    let project_text = match files.get(&project_path).map(|bytes| scan::text(bytes)) {
        None => {
            problems.push(format!("The template has no {project_path}. Add the project next to {TEMPLATE_FILE}, or name it with project:."));
            return Err(problems);
        }
        Some(None) => {
            problems.push(format!("{project_path} must be UTF-8 text."));
            return Err(problems);
        }
        Some(Some(text)) => text.trim_start_matches('\u{feff}').to_owned(),
    };
    let project: manifest::Project = match serde_yaml_ng::from_str(&project_text) {
        Ok(project) => project,
        Err(error) => {
            problems.push(format!("{project_path} is not a valid project: {error}"));
            return Err(problems);
        }
    };
    let base = project_path.rsplit_once('/').map_or("", |(folder, _)| folder);
    let environments: BTreeSet<String> = project.environments.keys().cloned().collect();
    if !project.publish.is_empty() {
        problems.push(format!("{project_path}: use public: in {TEMPLATE_FILE} instead of publish:, so every run sets up access the same way."));
    }
    for (name, environment) in &project.environments {
        let mut bad = |text: String| problems.push(format!("{project_path}: {name}: {text}"));
        if !matches!(environment.kind.as_str(), "container" | "gpu" | "microvm" | "vm") {
            bad(format!("type {} cannot be in a template: a template creates its sandboxes on the computer that runs it. Use container, gpu, microvm or vm.", environment.kind));
        }
        if environment.storage_drive.is_some() {
            bad("remove storage_drive; each computer chooses its own drive.".into());
        }
        if environment.health.as_ref().is_some_and(|health| health.bearer_secret.is_some()) {
            bad("health.bearer_secret cannot be used in a template; a template's secrets come from secret inputs.".into());
        }
        for problem in environment_paths(environment, base, files) {
            bad(problem);
        }
    }
    let questions = input_problems(&mut problems, &template.inputs);
    let known = Known {
        inputs: questions.iter().map(|q| (q.id.clone(), q.kind == Kind::Secret)).collect(),
        environments: environments.clone(),
        public: template.public.iter().filter_map(|p| p.environment.clone()).collect(),
    };
    // Placeholders in the project.
    match serde_yaml_ng::from_str::<Yaml>(&project_text).map_err(|e| e.to_string()).and_then(|tree| render::strings(&tree)) {
        Ok(strings) => {
            for (text, place) in strings {
                if let Err(error) = render::check(&text, place, &known) {
                    problems.push(format!("{project_path}: {error}"));
                }
            }
        }
        Err(error) => problems.push(format!("{project_path}: {error}")),
    }
    // Requirements.
    if let Some(version) = &template.requires.yougori {
        if let Err(error) = refs::parse_version(version) {
            problems.push(format!("requires.yougori: {error}"));
        }
    }
    match template.requires.gpu.as_deref() {
        None | Some("optional" | "required") => {}
        Some("none") => {
            if let Some((name, _)) = project.environments.iter().find(|(_, e)| e.gpu || e.kind == "gpu") {
                problems.push(format!("requires.gpu is none, but {name} uses a GPU. Set requires.gpu to required, or to optional if it also runs without one."));
            }
        }
        Some(other) => problems.push(format!("requires.gpu {} must be none, optional or required.", scan::shown(other))),
    }
    let mut platforms = BTreeSet::new();
    for platform in &template.requires.platforms {
        if !PLATFORMS.contains(&platform.as_str()) {
            problems.push(format!("requires.platforms: {} is not a platform. Use {}.", scan::shown(platform), PLATFORMS.join(", ")));
        } else if !platforms.insert(platform) {
            problems.push(format!("requires.platforms lists {platform} twice."));
        }
    }
    // Tools.
    let mut tools = Vec::new();
    for (environment, specs) in &template.tools {
        let Some(spec_environment) = project.environments.get(environment) else {
            problems.push(format!("tools: {} is not an environment in {project_path}.", scan::shown(environment)));
            continue;
        };
        let local = matches!(spec_environment.kind.as_str(), "container" | "gpu") || (spec_environment.kind == "microvm" && spec_environment.image.is_empty());
        if !local && !specs.is_empty() {
            problems.push(format!("tools: {environment} is a {}; tools install into containers and microVMs without an image.", spec_environment.kind));
        }
        if !spec_environment.internet && !specs.is_empty() {
            problems.push(format!("tools: {environment} has internet: false, so its tools cannot be installed."));
        }
        let mut seen = BTreeSet::new();
        for spec in specs {
            let source = if crate::container_tools::TOOLS.contains(&spec.as_str()) {
                Source::BuiltIn(spec.clone())
            } else if spec.starts_with("hub/") {
                match refs::parse(spec, "") {
                    Ok(reference) => Source::Hub(reference),
                    Err(error) => {
                        problems.push(format!("tools: {environment}: {error}"));
                        continue;
                    }
                }
            } else {
                let folder = match inside("", spec) {
                    Ok(folder) if !folder.is_empty() && (spec.contains('/') || files.contains_key(&format!("{folder}/{TOOL_FILE}"))) => folder,
                    _ => {
                        problems.push(format!("tools: {environment}: {} is not a built-in tool ({}), a tool folder in the template (such as tools/NAME) or hub/PUBLISHER/NAME.", scan::shown(spec), crate::container_tools::TOOLS.join(", ")));
                        continue;
                    }
                };
                if !files.contains_key(&format!("{folder}/{TOOL_FILE}")) {
                    problems.push(format!("tools: {environment}: {folder} has no {TOOL_FILE}. Bundled tools are folders with their own {TOOL_FILE}."));
                    continue;
                }
                match tool(files, &folder) {
                    Ok(tool) => {
                        let gb = tool_memory(&tool);
                        let memory = manifest::gib(&spec_environment.memory).ok();
                        if let (Some(needed), Some(has)) = (gb, memory) {
                            if needed > has {
                                problems.push(format!("tools: {} needs {needed} GB of memory, but {environment} has {has} GB.", tool.name()));
                            }
                        }
                        if tool.gpu() == "required" && !(spec_environment.gpu || spec_environment.kind == "gpu") {
                            problems.push(format!("tools: {} needs a GPU, but {environment} has none. Set type: gpu for {environment}.", tool.name()));
                        }
                        if tool.key_variable().is_some() && !key_ready(spec_environment) {
                            problems.push(format!("tools: {} signs in with an API key, which {environment} cannot receive: a microVM gets keys only with an image. Use a container, or give {environment} an image.", tool.name()));
                        }
                        Source::Bundled { folder, tool: Box::new(tool) }
                    }
                    Err(errors) => {
                        problems.extend(errors.into_iter().map(|error| format!("{folder}/{TOOL_FILE}: {error}")));
                        continue;
                    }
                }
            };
            let use_ = ToolUse { environment: environment.clone(), spec: spec.clone(), source };
            if !seen.insert(use_.name()) {
                problems.push(format!("tools: {environment} lists {} twice.", use_.name()));
                continue;
            }
            tools.push(use_);
        }
    }
    // Public access.
    let mut public_seen = BTreeSet::new();
    for entry in &template.public {
        let Some(name) = entry.environment.as_deref() else {
            problems.push("public: each entry needs environment: and port:.".into());
            continue;
        };
        let Some(environment) = project.environments.get(name) else {
            problems.push(format!("public: {} is not an environment in {project_path}.", scan::shown(name)));
            continue;
        };
        if !public_seen.insert(name.to_owned()) {
            problems.push(format!("public: {name} appears twice; each environment has one public address."));
        }
        let ports: Vec<u16> = environment.ports.iter().filter_map(|p| p.values().ok()).map(|(guest, _)| guest).collect();
        match entry.port {
            None => problems.push(format!("public: {name} needs port: one of its ports ({}).", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))),
            Some(port) if !ports.contains(&port) => problems.push(format!("public: port {port} is not one of {name}'s ports in {project_path}. Add it to ports: or choose one of: {}.", if ports.is_empty() { "none yet".to_owned() } else { ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ") })),
            Some(_) => {}
        }
        let access = entry.access.as_deref().unwrap_or("quick");
        let may_be_domain = match access {
            "quick" | "none" => false,
            "domain" => true,
            text => match render::pieces(text) {
                Ok(pieces) => match pieces.as_slice() {
                    [render::Piece::Placeholder(render::Placeholder::Input(id), _)] => match questions.iter().find(|q| &q.id == id) {
                        Some(q) if q.kind == Kind::Choice && q.choices.iter().all(|c| matches!(c.value.as_str(), "quick" | "domain" | "none")) => q.choices.iter().any(|c| c.value == "domain"),
                        Some(_) => {
                            problems.push(format!("public: {name}: access {text} must come from a choice input whose values are quick, domain or none."));
                            false
                        }
                        None => {
                            problems.push(format!("public: {name}: {text} names no input."));
                            false
                        }
                    },
                    _ => {
                        problems.push(format!("public: {name}: access must be quick, domain or none, or {{{{inputs.ID}}}} of a choice input with those values."));
                        false
                    }
                },
                Err(error) => {
                    problems.push(format!("public: {name}: {error}"));
                    false
                }
            },
        };
        match entry.domain.as_deref() {
            None if may_be_domain => problems.push(format!("public: {name} needs domain: a saved domain, usually {{{{inputs.ID}}}} of a domain input.")),
            None => {}
            Some(domain) => {
                if domain.contains("{{") {
                    if let Err(error) = render::check(domain, Place::Public, &known) {
                        problems.push(format!("public: {name}: {error}"));
                    }
                } else if !hostname(&domain.to_ascii_lowercase()) {
                    problems.push(format!("public: {name}: domain {} is not a domain name.", scan::shown(domain)));
                }
            }
        }
    }
    // Steps and outputs.
    if template.steps.len() > 20 {
        problems.push("Use at most 20 steps.".into());
    }
    for (index, step) in template.steps.iter().enumerate() {
        let label = format!("steps: step {}", index + 1);
        text_field(&mut problems, step.title.as_deref(), &format!("{label}: title"), 120, Some(format!("{label}: add title.")));
        if step.detail.as_deref().is_some_and(|d| d.chars().count() > 500) {
            problems.push(format!("{label}: detail is longer than 500 characters."));
        }
        text_field(&mut problems, step.command.as_deref(), &format!("{label}: command"), 500, None);
        for text in [&step.title, &step.detail, &step.command].into_iter().flatten() {
            if let Err(error) = render::check(text, Place::Step, &known) {
                problems.push(format!("{label}: {error}"));
            }
        }
    }
    if template.outputs.len() > 20 {
        problems.push("Use at most 20 outputs.".into());
    }
    for (index, output) in template.outputs.iter().enumerate() {
        let label = format!("outputs: output {}", index + 1);
        text_field(&mut problems, output.label.as_deref(), &format!("{label}: label"), 60, Some(format!("{label}: add label.")));
        text_field(&mut problems, output.value.as_deref(), &format!("{label}: value"), 500, Some(format!("{label}: add value.")));
        for text in [&output.label, &output.value].into_iter().flatten() {
            if let Err(error) = render::check(text, Place::Output, &known) {
                problems.push(format!("{label}: {error}"));
            }
        }
    }
    // The project as a run would write it, with sample answers, under the strict rules of `up`.
    if problems.is_empty() {
        let values = sample_values(template.name(), &questions);
        if let Err(error) = render::project(&project_text, &values, &render::Adjust::default()) {
            problems.push(format!("{project_path} with sample answers: {error}"));
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(Folder { template, project_path, project_text, project, questions, tools })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn files(entries: &[(&str, &str)]) -> Files {
        entries.iter().map(|(path, text)| (path.to_string(), text.as_bytes().to_vec())).collect()
    }

    const TEMPLATE: &str = r#"name: my-api
summary: A private model API website.
version: 1.0.0
license: MIT
topics: [ai, api]
requires: {yougori: 1.1.0, gpu: optional}
inputs:
  - id: access
    question: Where should the website be reachable?
    type: choice
    choices:
      - {value: quick, label: Quick link}
      - {value: domain, label: My own domain}
      - {value: none, label: Only this computer}
    default: quick
  - id: domain
    question: Which saved domain?
    type: domain
    when: {access: domain}
  - id: admin_email
    question: Admin email
    type: text
    pattern: "^[^@\\s]+@[^@\\s]+$"
  - id: openai_key
    question: OpenAI API key (optional)
    type: secret
    required: false
tools:
  paid: [codex, claude]
  web: [tools/gateway]
public:
  - {environment: web, port: 3000, access: "{{inputs.access}}", domain: "{{inputs.domain}}"}
steps:
  - title: Sign in to Codex
    command: yougori codex --environment {{env.paid}}
outputs:
  - {label: Website, value: "{{public.web}}"}
"#;
    const PROJECT: &str = r#"project: my-api
environments:
  web:
    image: node:24
    memory: 4GB
    ports: ["3000"]
    environment: {ADMIN: "{{inputs.admin_email}}"}
    secrets: {OPENAI_API_KEY: "{{secrets.openai_key}}"}
    files: [{source: ./app, target: /app}]
  paid:
    image: ubuntu:24.04
  ai:
    type: gpu
    image: ubuntu:24.04
connections: [web -> paid]
"#;
    const GATEWAY: &str = "kind: tool\nname: gateway\nsummary: A gateway.\nversion: 0.1.0\nlicense: MIT\ncommand: gateway\ninstall: [npm install -g gateway@1.0.0]\ncheck: gateway --version\nneeds: {memory: 1GB}\n";

    fn folder(changes: &[(&str, &str)]) -> Files {
        let mut files = files(&[(TEMPLATE_FILE, TEMPLATE), ("yougori.yaml", PROJECT), ("app/server.js", "ok"), ("tools/gateway/yougori-tool.yaml", GATEWAY)]);
        for (path, text) in changes {
            if text.is_empty() { files.remove(*path); } else { files.insert(path.to_string(), text.as_bytes().to_vec()); }
        }
        files
    }

    fn problems(changes: &[(&str, &str)]) -> String {
        template(&folder(changes)).err().map(|p| p.join("\n")).unwrap_or_default()
    }

    #[test]
    fn a_complete_template_passes_every_rule() {
        let checked = template(&folder(&[])).unwrap_or_else(|p| panic!("{}", p.join("\n")));
        assert_eq!(checked.template.name(), "my-api");
        assert_eq!(checked.questions.len(), 4);
        assert_eq!(checked.questions[1].when, Some(("access".into(), "domain".into())));
        assert_eq!(checked.tools.iter().map(ToolUse::name).collect::<Vec<_>>(), ["codex", "claude", "gateway"]);
        assert_eq!(checked.gpu(), "optional");
        assert_eq!(checked.template.manifest()["kind"], "template");
    }

    #[test]
    fn metadata_rules_have_plain_messages() {
        for (from, to, said) in [
            ("name: my-api", "name: My API", "name My API is not a Hub name"),
            ("summary: A private model API website.", "summary: \"\"", "Add summary"),
            ("version: 1.0.0", "version: 1.0", "is not a version. Use MAJOR.MINOR.PATCH"),
            ("license: MIT", "license: Proprietary", "license Proprietary is not an accepted open-source licence"),
            ("license: MIT\n", "", "Add license"),
            ("topics: [ai, api]", "topics: [AI]", "topic AI: use lowercase words"),
            ("topics: [ai, api]", "topics: [a, b, c, d, e, f, g, h, i, j, k]", "at most 10 topics"),
            ("name: my-api", "kind: tool\nname: my-api", "kind in yougori-template.yaml must be template"),
            ("name: my-api", "name: my-api\nunknown: 1", "unknown field `unknown`"),
            ("requires: {yougori: 1.1.0, gpu: optional}", "requires: {yougori: soon, gpu: always, platforms: [amiga]}", "requires.yougori"),
            ("requires: {yougori: 1.1.0, gpu: optional}", "requires: {gpu: none}", "requires.gpu is none, but ai uses a GPU"),
        ] {
            let text = TEMPLATE.replacen(from, to, 1);
            let said_now = problems(&[(TEMPLATE_FILE, &text)]);
            assert!(said_now.contains(said), "{to}: {said_now}");
        }
        let title = TEMPLATE.replacen("summary:", &format!("title: {}\nsummary:", "t".repeat(81)), 1);
        assert!(problems(&[(TEMPLATE_FILE, &title)]).contains("title is longer than 80 characters"));
        let long = TEMPLATE.replacen("summary: A private model API website.", &format!("summary: {}", "s".repeat(201)), 1);
        assert!(problems(&[(TEMPLATE_FILE, &long)]).contains("summary is longer than 200 characters"));
    }

    #[test]
    fn titles_and_summaries_follow_the_websites_text_rules() {
        let with = |title: &str, summary: &str| {
            let text = TEMPLATE.replacen("summary: A private model API website.", &format!("title: {}\nsummary: {}", serde_json::to_string(title).unwrap(), serde_json::to_string(summary).unwrap()), 1);
            problems(&[(TEMPLATE_FILE, &text)])
        };
        // Lengths are counted as the website counts them: 40 emoji are 80 UTF-16 units.
        assert!(!with(&"\u{1f600}".repeat(40), "Fine.").contains("longer than"));
        assert!(with(&format!("{}x", "\u{1f600}".repeat(40)), "Fine.").contains("title is longer than 80 characters"));
        for (title, summary, said) in [
            ("Shop \u{202e}pohS", "Fine.", "title contains invisible characters or stacked accents"),
            ("Shop", "Zero\u{200b}width", "summary contains invisible characters or stacked accents"),
            ("Z\u{351}\u{34b}\u{34c}algo", "Fine.", "title contains invisible characters or stacked accents"),
            ("Shop\ttabs", "Fine.", "title must be one line, without tabs or control characters"),
            ("Verified shop", "Fine.", "Only Yougori shows the Verified badge; leave that word (and \"official\") and check marks out of the title."),
            ("Official shop", "Fine.", "out of the title"),
            ("Shop \u{2705}", "Fine.", "out of the title"),
            ("Shop", "A VERIFIED-quality shop.", "Only Yougori shows the Verified badge; leave that word and check marks out of the summary."),
            ("Shop", "Ships \u{2714} fast.", "out of the summary"),
        ] {
            let said_now = with(title, summary);
            assert!(said_now.contains(said), "{title:?} / {summary:?}: {said_now}");
        }
        for (title, summary) in [("Unverified ideas", "Officially fun, not verifiedly."), ("Shop", "An official API client."), ("e\u{301}\u{302} shop", "Fine.")] {
            assert!(!with(title, summary).contains("badge") && !with(title, summary).contains("invisible"), "{title} / {summary}");
        }
        let named = TEMPLATE.replacen("name: my-api", "name: verified-api", 1);
        assert!(problems(&[(TEMPLATE_FILE, &named)]).contains("out of the name (the title when there is none)"), "a template without a title is shown by its name");
        let changelog = TEMPLATE.replacen("summary: A private model API website.", "summary: A private model API website.\nchangelog: \"Fixed\\n\\tthe \\u001b[2J bug\"", 1);
        assert!(problems(&[(TEMPLATE_FILE, &changelog)]).contains("changelog contains control characters"));
    }

    #[test]
    fn input_rules_are_enforced() {
        let replace = |from: &str, to: &str| problems(&[(TEMPLATE_FILE, &TEMPLATE.replacen(from, to, 1))]);
        assert!(replace("id: admin_email", "id: Admin").contains("inputs: Admin: id must be lowercase"));
        assert!(replace("id: admin_email", "id: access").contains("this id is used twice"));
        assert!(replace("type: text", "type: date").contains("type date is not a question type"));
        let one_choice = TEMPLATE.replacen("      - {value: domain, label: My own domain}\n      - {value: none, label: Only this computer}\n", "", 1);
        assert!(problems(&[(TEMPLATE_FILE, &one_choice)]).contains("a choice needs 2 to 12 choices"));
        assert!(replace("{value: none, label: Only this computer}", "{value: None!, label: Only this computer}").contains("choice value None! must be lowercase"));
        assert!(replace("{value: none, label: Only this computer}", "{value: quick, label: Again}").contains("choice value quick is used twice"));
        assert!(replace("default: quick", "default: everywhere").contains("default everywhere is not a valid answer"));
        assert!(replace("when: {access: domain}", "when: {access: elsewhere}").contains("is not an answer to access"));
        assert!(replace("when: {access: domain}", "when: {admin_email: x}").contains("not an earlier input"));
        assert!(replace("pattern: \"^[^@\\\\s]+@[^@\\\\s]+$\"", "pattern: \"(?=x)\"").contains("lookahead"));
        assert!(replace("    required: false", "    required: false\n    default: sk-abc").contains("a secret cannot have a default"));
        assert!(replace("    type: domain", "    type: domain\n    min: 1").contains("min and max work only with type: number"));
        assert!(replace("    type: domain", "    type: domain\n    pattern: x").contains("pattern works only with type: text"));
    }

    #[test]
    fn placeholder_tool_public_step_and_output_rules_are_enforced() {
        let project = |from: &str, to: &str| problems(&[("yougori.yaml", &PROJECT.replacen(from, to, 1))]);
        let template = |from: &str, to: &str| problems(&[(TEMPLATE_FILE, &TEMPLATE.replacen(from, to, 1))]);
        assert!(project("{{inputs.admin_email}}", "{{inputs.openai_key}}").contains("would put a secret in plain text"));
        assert!(project("{{inputs.admin_email}}", "{{inputs.missing}}").contains("names no input"));
        assert!(project("{{inputs.admin_email}}", "{{secrets.openai_key}}").contains("works only as a whole value under an environment's secrets:"));
        assert!(project("{{inputs.admin_email}}", "{{public.web}}").contains("works only in outputs"));
        assert!(project("{{inputs.admin_email}}", "{{user}}").contains("is not a placeholder"));
        assert!(project("image: node:24", "image: node:24\n    storage_drive: D:/x").contains("remove storage_drive"));
        assert!(project("connections: [web -> paid]", "publish: {web: app.example.com}").contains("use public: in yougori-template.yaml instead of publish:"));
        assert!(project("  ai:\n    type: gpu", "  ai:\n    type: cloud\n    cloud: {}").contains("type cloud cannot be in a template"));
        assert!(project("./app", "./missing").contains("files source ./missing is not in the template folder"));
        assert!(project("./app", "../outside").contains("must stay inside the template folder"));
        assert!(project("    image: ubuntu:24.04\n  ai:", "    image: ubuntu:24.04\n    permissions: {pc: true}\n    volumes: [{source: C:/Users, target: /pc, bind: true, read_only: true}]\n  ai:").contains("cannot use folders outside its own folder"));
        assert!(project("memory: 4GB", "memory: 512MB").contains("gateway needs 1 GB of memory, but web has 0.5 GB"));
        assert!(template("  web: [tools/gateway]", "  web: [tools/missing]").contains("tools/missing has no yougori-tool.yaml"));
        assert!(template("  web: [tools/gateway]", "  db: [codex]").contains("tools: db is not an environment"));
        assert!(template("  web: [tools/gateway]", "  web: [hub/Acme/x]").contains("Hub names are lowercase"));
        assert!(template("  paid: [codex, claude]", "  paid: [codex, codex]").contains("lists codex twice"));
        assert!(template("  paid: [codex, claude]", "  paid: [vscode]").contains("vscode is not a built-in tool"));
        assert!(problems(&[("tools/gateway/yougori-tool.yaml", &GATEWAY.replace("check: gateway --version\n", ""))]).contains("tools/gateway/yougori-tool.yaml: Add check"));
        assert!(template("port: 3000", "port: 8080").contains("port 8080 is not one of web's ports"));
        assert!(template("{environment: web,", "{environment: db,").contains("public: db is not an environment"));
        assert!(template("access: \"{{inputs.access}}\"", "access: everywhere").contains("access must be quick, domain or none"));
        assert!(template("access: \"{{inputs.access}}\"", "access: \"{{inputs.admin_email}}\"").contains("must come from a choice input"));
        assert!(template(", domain: \"{{inputs.domain}}\"", "").contains("public: web needs domain:"));
        assert!(template("{{env.paid}}", "{{env.db}}").contains("steps: step 1: {{env.db}} names no environment"));
        assert!(template("value: \"{{public.web}}\"", "value: \"{{public.paid}}\"").contains("needs a public: entry for the environment paid"));
        assert!(template("  - title: Sign in to Codex\n", "  - detail: no title\n").contains("steps: step 1: add title"));
        let unchecked = problems(&[("yougori.yaml", &PROJECT.replacen("ports: [\"3000\"]", "ports: [\"3000\", \"{{inputs.admin_email}}\"]", 1))]);
        assert!(unchecked.contains("with sample answers"), "the strict project rules apply with sample answers: {unchecked}");
        assert!(problems(&[("yougori.yaml", "")]).contains("The template has no yougori.yaml"));
    }

    #[test]
    fn no_answer_can_choose_a_path_on_this_computer() {
        let template = TEMPLATE.replacen("  - id: domain\n", "  - id: data\n    question: Data folder?\n    type: text\n    default: ../../..\n  - id: domain\n", 1);
        for (from, to) in [
            ("    files: [{source: ./app, target: /app}]", "    files: [{source: \"{{inputs.data}}\", target: /app}]"),
            ("    image: ubuntu:24.04\n  ai:", "    image: ubuntu:24.04\n    permissions: {pc: true, edit: true}\n    volumes: [{source: \"{{inputs.data}}\", target: /pc, bind: true}]\n  ai:"),
            ("    image: ubuntu:24.04\n  ai:", "    image: ubuntu:24.04\n    permissions: {pc: true}\n    pc_access: [{path: \"{{inputs.data}}\"}]\n  ai:"),
        ] {
            let said = problems(&[(TEMPLATE_FILE, &template), ("yougori.yaml", &PROJECT.replacen(from, to, 1))]);
            assert!(said.contains("cannot contain a placeholder: a path on this computer is part of the template"), "{to}: {said}");
        }
        let project: manifest::Project = serde_yaml_ng::from_str("project: x\nenvironments:\n  web:\n    image: nginx\n    permissions: {pc: true}\n    pc_access: [{path: ../../..}]\n").unwrap();
        assert!(rendered_paths(&project, "yougori.yaml", &files(&[("yougori.yaml", "")])).unwrap_err().contains("would read outside its own files"), "the second guard after rendering");
        let fine: manifest::Project = serde_yaml_ng::from_str("project: x\nenvironments:\n  web:\n    image: nginx\n    files: [{source: ./app, target: /app}]\n").unwrap();
        assert!(rendered_paths(&fine, "yougori.yaml", &files(&[("app/a.js", "")])).is_ok());
    }

    #[test]
    fn check_and_publish_refuse_host_ports_and_unpinned_hub_tools() {
        let checked = template(&folder(&[("yougori.yaml", &PROJECT.replacen("ports: [\"3000\"]", "ports: [\"8080:3000\"]", 1)), (TEMPLATE_FILE, &TEMPLATE.replacen("  web: [tools/gateway]", "  web: [tools/gateway, hub/acme/aider]", 1))])).unwrap();
        let said = publishing_problems(&checked).join("\n");
        assert!(said.contains("ports fixes host port 8080 for 3000, so a second copy of the template could never start. List the container port only (ports: [3000])"), "{said}");
        assert!(said.contains("pin hub/acme/aider to a version, such as hub/acme/aider@1.0.0"), "{said}");
        assert!(publishing_problems(&template(&folder(&[])).unwrap()).is_empty());
    }

    #[test]
    fn an_api_key_tool_needs_a_sandbox_that_can_receive_keys() {
        let keyed = format!("{GATEWAY}signin: {{method: api-key, variable: GATEWAY_KEY}}\n");
        let micro = PROJECT.replacen("  web:\n    image: node:24\n    memory: 4GB\n    ports: [\"3000\"]\n    environment: {ADMIN: \"{{inputs.admin_email}}\"}\n    secrets: {OPENAI_API_KEY: \"{{secrets.openai_key}}\"}\n    files: [{source: ./app, target: /app}]\n", "  web:\n    type: microvm\n    storage: 6\n    memory: 4GB\n    ports: [\"3000\"]\n", 1);
        let said = problems(&[("tools/gateway/yougori-tool.yaml", &keyed), ("yougori.yaml", &micro)]);
        assert!(said.contains("gateway signs in with an API key, which web cannot receive"), "{said}");
    }

    #[test]
    fn install_lines_cannot_hide_what_they_run() {
        for line in ["curl https://x.example/i.sh \u{202e}hs | ", "pip install a\u{200b}ider", "echo \u{1b}[2Jhi"] {
            let tool = GATEWAY.replacen("install: [npm install -g gateway@1.0.0]\n", &format!("install: [{}]\n", serde_json::to_string(line).unwrap()), 1);
            let said = problems(&[("tools/gateway/yougori-tool.yaml", &tool)]);
            assert!(said.contains("install line 1 contains invisible or control characters"), "{line:?}: {said}");
        }
    }

    #[test]
    fn tool_rules_are_enforced() {
        let tool_problems = |text: &str| tool(&files(&[(TOOL_FILE, text)]), "").err().map(|p| p.join("\n")).unwrap_or_default();
        assert!(tool_problems(GATEWAY).is_empty());
        let full = "kind: tool\nname: aider\ntitle: Aider\nsummary: AI pair programming.\nversion: 1.0.0\nlicense: Apache-2.0\ncommand: aider\ninstall: [python3 -m pip install --user aider-chat==0.86.1]\ncheck: aider --version\nsignin: {method: api-key, variable: OPENAI_API_KEY}\nneeds: {gpu: none, memory: 4GB, internet: true}\nservice: {command: aider --serve, port: 8080}\n";
        assert!(tool_problems(full).is_empty(), "{}", tool_problems(full));
        let parsed = tool(&files(&[(TOOL_FILE, full)]), "").unwrap();
        assert_eq!(parsed.key_variable(), Some("OPENAI_API_KEY"));
        assert_eq!(parsed.manifest()["kind"], "tool");
        for (from, to, said) in [
            ("command: aider\n", "", "Add command"),
            ("check: aider --version", "check: \"a\\nb\"", "check must be a single shell line"),
            ("{method: api-key, variable: OPENAI_API_KEY}", "{method: api-key}", "Add signin.variable"),
            ("{method: api-key, variable: OPENAI_API_KEY}", "{method: browser}", "Add signin.command"),
            ("{method: api-key, variable: OPENAI_API_KEY}", "{method: password}", "signin.method password is not a sign-in method"),
            ("{method: api-key, variable: OPENAI_API_KEY}", "{method: api-key, variable: 1KEY}", "is not an environment variable name"),
            ("gpu: none", "gpu: maybe", "needs.gpu must be none, optional or required"),
            ("memory: 4GB", "memory: lots", "needs.memory lots is not a size"),
            ("port: 8080", "port: 0", "service.port must be a port"),
            ("kind: tool", "kind: template", "kind in yougori-tool.yaml must be tool"),
        ] {
            let said_now = tool_problems(&full.replacen(from, to, 1));
            assert!(said_now.contains(said), "{to}: {said_now}");
        }
        let many = format!("{}install: [{}]\n", full.replacen("install: [python3 -m pip install --user aider-chat==0.86.1]\n", "", 1), vec!["true"; 33].join(", "));
        assert!(tool_problems(&many).contains("more than 32 lines"));
        let long = full.replacen("command: aider", &format!("command: {}", "a".repeat(4097)), 1);
        assert!(tool_problems(&long).contains("command is longer than 4096 characters"));
    }

    #[test]
    fn answers_are_checked_and_normalised() {
        let checked = template(&folder(&[])).unwrap();
        let [access, domain, email, secret] = &checked.questions[..] else { panic!() };
        assert_eq!(access.answer("Quick link", None).unwrap(), "quick");
        assert!(access.answer("everywhere", None).unwrap_err().contains("quick, domain, none"));
        assert_eq!(email.answer(" admin@example.com ", None).unwrap(), "admin@example.com");
        assert!(email.answer("not an email", None).is_err());
        let saved = vec!["app.example.com".to_owned()];
        assert_eq!(domain.answer("APP.example.com", Some(&saved)).unwrap(), "app.example.com");
        assert!(domain.answer("other.example.com", Some(&saved)).unwrap_err().contains("not a saved domain"));
        assert!(domain.answer("x.example.com", Some(&[])).unwrap_err().contains("yougori domain add"));
        assert!(secret.answer("line\nbreak", None).is_err());
        assert!(!domain.asked(&BTreeMap::from([("access".to_owned(), "quick".to_owned())])));
        assert!(domain.asked(&BTreeMap::from([("access".to_owned(), "domain".to_owned())])));
        let number = Question { kind: Kind::Number, min: Some(1.0), max: Some(8.0), ..access.clone() };
        assert_eq!(number.answer("4", None).unwrap(), "4");
        assert!(number.answer("9", None).unwrap_err().contains("from 1 to 8"));
        let yesno = Question { kind: Kind::YesNo, ..access.clone() };
        assert_eq!(yesno.answer("Y", None).unwrap(), "yes");
    }
}
