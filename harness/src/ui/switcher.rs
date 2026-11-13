//! Switching harness from the screen (/harness): the harnesses this session may switch to (the
//! spec's `harnesses`), each one's own questions asked here with the meaning `yougori inference
//! run` gives them (cli/src/inference.rs), whether the harness comes into this VM or starts in a
//! new one, and the switch command (`runtime.py switch`, harness/README.md) that carries it out.
use super::dialog;
use super::input::Editor;
use super::overlay::{choice_line, panel, window};
use super::text::{self, span, wrap_text};
use super::theme::Theme;
use crate::spec::{EngineSpec, HarnessChoice};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::text::{Line, Span};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::time::Duration;

/// Yougori's own agent: it needs no pack, so the screen can always switch back to it.
pub const YOUGORI: &str = "yougori";
/// The screen's exit code once a new-VM switch is accepted: the launcher starts that VM.
pub const NEW_VM_EXIT: i32 = 75;
/// What /harness says in a session that cannot switch (an older launcher or image).
pub const OLDER: &str = "This Yougori cannot switch harnesses here. Update Yougori: yougori update";
/// The variable the VM gives the screen alone, which it passes to the switch command only.
pub const SWITCH_TOKEN: &str = "YOUGORI_SWITCH_TOKEN";
/// How long a cancelled switch command has to tell the VM before it is killed.
const CANCEL_WAIT: Duration = Duration::from_secs(20);

// ------------------------------------------------------------------------------- the questions

/// What a harness asks, as the website describes each question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Choice,
    /// Yes or no.
    Confirm,
    /// A folder: inside the VM, this session's own folder.
    Folder,
    /// Typed masked; it reaches the engine only in its environment.
    Secret,
    /// Items separated by commas.
    List,
    /// The practice app inside the VM, or addresses to test.
    Target,
}

/// A named check of a typed answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Url,
    Host,
    Target,
    Path,
    Text,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pick {
    pub value: String,
    pub label: String,
    pub note: String,
}

/// When a question is asked: an earlier answer is given (or not), or is not a value.
#[derive(Clone, Debug, PartialEq)]
pub enum When {
    Present(String, bool),
    Not(String, String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub id: String,
    pub kind: Kind,
    pub question: String,
    pub note: String,
    pub required: bool,
    pub placeholder: String,
    pub check: Option<Check>,
    pub choices: Vec<Pick>,
    pub default: Option<String>,
    /// A confirmation that must be yes, or nothing starts: `refusal` says so.
    pub must: bool,
    pub refusal: String,
    pub when: Option<When>,
    pub workspace: bool,
    pub reach: bool,
}

/// One line of the website's words as the screen shows them: no control characters.
fn plain(text: &str, most: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(most).collect::<String>().trim().to_owned()
}

fn answer_id(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// One question from the catalogue, as the CLI reads it; an error names what cannot be asked.
fn question(item: &Value) -> Result<Question, String> {
    let words = |key: &str, most: usize| -> Result<String, String> {
        match &item[key] {
            Value::Null => Ok(String::new()),
            Value::String(text) if text.chars().count() <= most && !text.chars().any(char::is_control) => Ok(text.trim().to_owned()),
            _ => Err(format!("an invalid {key}")),
        }
    };
    let flag = |key: &str| -> Result<bool, String> {
        match &item[key] {
            Value::Null => Ok(false),
            Value::Bool(value) => Ok(*value),
            _ => Err(format!("an invalid {key}")),
        }
    };
    let id = item["id"].as_str().filter(|id| answer_id(id)).ok_or("a question without a valid id")?.to_owned();
    let kind = match item["type"].as_str() {
        Some("text") => Kind::Text,
        Some("choice") => Kind::Choice,
        Some("confirm") => Kind::Confirm,
        Some("folder") => Kind::Folder,
        Some("secret") => Kind::Secret,
        Some("list") => Kind::List,
        Some("target") => Kind::Target,
        _ => return Err(format!("question {id} of a type this Yougori does not know")),
    };
    let check = match &item["validate"] {
        Value::Null => None,
        Value::String(check) => Some(match check.as_str() {
            "url" => Check::Url,
            "host" => Check::Host,
            "target" => Check::Target,
            "path" => Check::Path,
            "text" => Check::Text,
            _ => return Err(format!("question {id} with a check this Yougori does not know")),
        }),
        _ => return Err(format!("question {id} with an invalid check")),
    };
    let mut choices: Vec<Pick> = Vec::new();
    match &item["choices"] {
        Value::Null => {}
        Value::Array(list) if list.len() <= 32 => {
            for pick in list {
                let value = pick["value"]
                    .as_str()
                    .filter(|value| {
                        (1..=64).contains(&value.len())
                            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    })
                    .ok_or_else(|| format!("question {id} with an invalid choice"))?;
                let label = pick["label"]
                    .as_str()
                    .map(|label| plain(label, 300))
                    .filter(|label| !label.is_empty())
                    .ok_or_else(|| format!("question {id} with an unnamed choice"))?;
                if choices.iter().any(|known| known.value == value) {
                    return Err(format!("question {id} with a choice twice"));
                }
                choices.push(Pick {
                    value: value.to_owned(),
                    label,
                    note: pick["note"].as_str().map(|note| plain(note, 300)).unwrap_or_default(),
                });
            }
        }
        _ => return Err(format!("question {id} with invalid choices")),
    }
    let default = match &item["default"] {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Bool(yes) => Some(if *yes { "yes" } else { "no" }.to_owned()),
        _ => return Err(format!("question {id} with an invalid default")),
    };
    let when = match &item["when"] {
        Value::Null => None,
        Value::Object(when) => {
            let other = when
                .get("id")
                .and_then(Value::as_str)
                .filter(|other| answer_id(other))
                .ok_or_else(|| format!("question {id} with an invalid condition"))?;
            match (when.get("present").and_then(Value::as_bool), when.get("not").and_then(Value::as_str)) {
                (Some(present), None) => Some(When::Present(other.to_owned(), present)),
                (None, Some(not)) => Some(When::Not(other.to_owned(), not.to_owned())),
                _ => return Err(format!("question {id} with a condition this Yougori does not know")),
            }
        }
        _ => return Err(format!("question {id} with an invalid condition")),
    };
    let reach = match &item["reach"] {
        Value::Null => false,
        Value::String(reach) if reach == "targets" => true,
        _ => return Err(format!("question {id} with a reach this Yougori does not know")),
    };
    let asked = Question {
        question: words("question", 300)?,
        note: words("note", 300)?,
        required: flag("required")?,
        placeholder: words("placeholder", 300)?,
        must: flag("must")?,
        refusal: words("refusal", 300)?,
        workspace: flag("workspace")?,
        id,
        kind,
        check,
        choices,
        default,
        when,
        reach,
    };
    if asked.question.is_empty() || (kind == Kind::Choice && asked.choices.is_empty()) {
        return Err(format!("question {} without its wording or choices", asked.id));
    }
    Ok(asked)
}

/// Whether a question may come with a default, as the CLI allows: never what the VM gets or
/// reaches, a secret or a must-confirm.
fn takes_default(question: &Question) -> bool {
    !question.reach
        && match question.kind {
            Kind::Choice | Kind::List => true,
            Kind::Confirm => !question.must,
            Kind::Text => !matches!(question.check, Some(Check::Path | Check::Target)),
            Kind::Folder | Kind::Secret | Kind::Target => false,
        }
}

/// A harness's questions, in the order they are asked, with the CLI's rules: a condition names an
/// earlier question, at most one folder becomes the workspace and every folder must, only a
/// question that takes one has a default, and a must-confirm is required.
pub fn questions(values: &[Value]) -> Result<Vec<Question>, String> {
    if values.len() > 32 {
        return Err("more questions than Yougori asks".into());
    }
    let mut asked: Vec<Question> = Vec::new();
    for item in values {
        let next = question(item)?;
        let earlier = |id: &str| asked.iter().any(|known| known.id == id);
        if earlier(&next.id) {
            return Err(format!("question {} twice", next.id));
        }
        if let Some(When::Present(other, _) | When::Not(other, _)) = &next.when {
            if !earlier(other) {
                return Err(format!("question {} asked after a later question", next.id));
            }
        }
        if (next.kind == Kind::Folder) != next.workspace
            || (next.workspace && asked.iter().any(|known| known.workspace))
            || (next.must && next.kind != Kind::Confirm)
            || (next.reach && next.kind != Kind::Target)
        {
            return Err(format!("question {} this Yougori cannot deliver", next.id));
        }
        if next.default.is_some() && !takes_default(&next) && !(next.kind == Kind::Confirm && next.must) {
            return Err(format!("its question {} comes with an answer chosen in advance", next.id));
        }
        if next.must && !next.required {
            return Err(format!("its question {} must be answered yes but may be skipped", next.id));
        }
        asked.push(next);
    }
    Ok(asked)
}

// --------------------------------------------------------------------------------- the answers

/// An answer to one of a harness's questions. Secrets are kept apart.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    /// A text, or the chosen choice's value.
    Text(String),
    Yes(bool),
    List(Vec<String>),
    /// A folder inside the VM: this session's own folder.
    Folder(String),
    /// Addresses to test, each as given, with the `host:port` the VM must reach for it.
    Targets(Vec<(String, String)>),
    /// The practice app inside the VM.
    Practice,
}

impl Answer {
    /// Whether the answer is `value`, for a condition's `not`.
    fn is(&self, value: &str) -> bool {
        match self {
            Answer::Text(text) => text == value,
            Answer::Yes(yes) => value == if *yes { "yes" } else { "no" },
            Answer::Practice => value == "practice",
            _ => false,
        }
    }

    /// The answer in the answers the switch command gets, as the CLI writes them for the VM.
    pub fn json(&self) -> Value {
        match self {
            Answer::Text(text) => json!(text),
            Answer::Yes(yes) => json!(yes),
            Answer::List(items) => json!(items),
            Answer::Folder(folder) => json!(folder),
            Answer::Targets(entries) => json!(entries.iter().map(|(entry, _)| entry).collect::<Vec<_>>()),
            Answer::Practice => json!("practice"),
        }
    }
}

/// One line of text: no control characters, at most `most` characters.
fn check_text(value: &str, most: usize) -> Result<String, String> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        return Err("Use one line of plain text.".into());
    }
    if value.chars().count() > most {
        return Err(format!("Use at most {most} characters."));
    }
    Ok(value.to_owned())
}

fn this_computer(raw: &str) -> String {
    format!("{raw} is this computer: run the app inside the VM (the practice app is there), or give its network address.")
}

/// One target the VM may reach: `host:port`, or a host alone for each of its ports. A DNS name (a
/// single label only with a port) or an IPv4 address; never this computer or a link-local,
/// multicast or broadcast address (as the CLI and the launcher take it).
fn target_host(entry: &str) -> Result<String, String> {
    let raw = entry.trim();
    let text = raw.to_ascii_lowercase();
    let parts: Vec<&str> = text.split(':').collect();
    let (host, port) = match parts[..] {
        [host] => (host, None),
        [host, port] => {
            let number = port.parse::<u32>().ok().filter(|n| (1..=65535).contains(n));
            if port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) || port.starts_with('0') || number.is_none() {
                return Err(format!("{raw} has no valid port (1 to 65535)."));
            }
            (host, Some(port))
        }
        _ => return Err(format!("{raw} is not a host such as staging.example.com:443 (IPv6 addresses are not taken).")),
    };
    let octets: Vec<&str> = host.split('.').collect();
    let host = if octets.len() == 4 && octets.iter().all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())) {
        let numbers: Vec<u32> = octets.iter().map(|part| part.parse::<u32>().unwrap_or(256)).collect();
        if octets.iter().zip(&numbers).any(|(part, number)| part.len() > 3 || *number > 255 || (part.len() > 1 && part.starts_with('0'))) {
            return Err(format!("{raw} is not an IPv4 address."));
        }
        if numbers[0] == 127 {
            return Err(this_computer(raw));
        }
        if numbers[0] == 0 || numbers[0] >= 224 || (numbers[0], numbers[1]) == (169, 254) {
            return Err(format!("{raw} is not an address of a computer to test."));
        }
        host.to_owned()
    } else {
        let name = host.strip_suffix('.').unwrap_or(host);
        let labels: Vec<&str> = name.split('.').collect();
        if labels.last() == Some(&"localhost") {
            return Err(this_computer(raw));
        }
        let label_ok = |label: &&str| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        let last = labels.last().copied().unwrap_or("");
        if !(1..=253).contains(&host.len())
            || !labels.iter().all(label_ok)
            || (labels.len() == 1 && port.is_none())
            || last.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("{raw} is not a host such as staging.example.com or staging.example.com:443."));
        }
        name.to_owned()
    };
    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// What the VM must reach for a web address to test: its host and port.
fn url_host(value: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(value).map_err(|_| format!("{value} is not a web address such as https://staging.example.com."))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{value} is not an http or https address."));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Give the login in its own question, not in the address.".into());
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty() && !host.starts_with('['))
        .ok_or_else(|| format!("{value} needs a host name or an IPv4 address (IPv6 addresses are not taken)."))?;
    target_host(&format!("{host}:{}", url.port_or_known_default().unwrap_or(443)))
}

/// The addresses a target question takes, each as given with what the VM must reach for it:
/// http(s) URLs, host[:port] or IPv4[:port], separated by commas, 1 to 16, each once.
pub fn target_entries(value: &str) -> Result<Vec<(String, String)>, String> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for raw in value.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let (given, host) = if raw.contains("://") {
            (raw.to_owned(), url_host(raw)?)
        } else {
            let host = target_host(raw)?;
            (host.clone(), host)
        };
        if !entries.iter().any(|(entry, _)| *entry == given) {
            entries.push((given, host));
        }
    }
    if entries.is_empty() || entries.len() > 16 {
        return Err("Give 1 to 16 addresses, separated by commas, such as https://staging.example.com.".into());
    }
    Ok(entries)
}

/// A typed answer to a text, list or address question: empty is no answer, which only an
/// optional question takes.
fn typed_answer(question: &Question, text: &str) -> Result<Option<Answer>, String> {
    let text = text.trim();
    if text.is_empty() {
        return if question.required { Err("This question needs an answer.".into()) } else { Ok(None) };
    }
    let answer = match question.kind {
        Kind::List => {
            let items = text
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| check_text(item, 500))
                .collect::<Result<Vec<_>, _>>()?;
            if items.len() > 64 {
                return Err("Give at most 64 items.".into());
            }
            if items.is_empty() {
                return typed_answer(question, "");
            }
            Answer::List(items)
        }
        Kind::Target => {
            if text.eq_ignore_ascii_case("practice") {
                Answer::Practice
            } else {
                Answer::Targets(target_entries(text)?)
            }
        }
        _ => match question.check.unwrap_or(Check::Text) {
            Check::Text => Answer::Text(check_text(text, 8000)?),
            Check::Url => {
                url_host(text)?;
                Answer::Text(text.to_owned())
            }
            Check::Host => Answer::Text(target_host(text)?),
            Check::Target => {
                if text.eq_ignore_ascii_case("practice") {
                    Answer::Practice
                } else {
                    Answer::Targets(target_entries(text)?)
                }
            }
            Check::Path => {
                let path = check_text(text, 4000)?;
                if !path.starts_with('/') {
                    return Err("Give a folder inside the VM, such as /run/yougori/workspace.".into());
                }
                Answer::Text(path)
            }
        },
    };
    Ok(Some(answer))
}

/// A secret: 1 to 4096 characters on one line.
fn check_secret(value: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > 4096 || value.chars().any(char::is_control) {
        return Err("Give 1 to 4096 characters on one line.".into());
    }
    Ok(())
}

/// The choices of a target question: the practice app, or addresses typed in.
fn target_picks(question: &Question) -> Vec<Pick> {
    if question.choices.iter().any(|pick| pick.value == "practice") && question.choices.iter().any(|pick| pick.value != "practice") {
        return question.choices.clone();
    }
    vec![
        Pick {
            value: "practice".into(),
            label: "A practice app inside the VM".into(),
            note: "a deliberately vulnerable app Yougori starts inside the VM, safe to try".into(),
        },
        Pick {
            value: "address".into(),
            label: "A website or address I give".into(),
            note: "http(s) URLs, host:port or IPv4 addresses, separated by commas".into(),
        },
    ]
}

// ------------------------------------------------------------------------------ where it runs

/// Where the next harness runs.
#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    /// Its pack comes into this VM, which keeps its folder and reach.
    InPlace,
    /// The launcher starts a new VM for it: `why` in words, the targets it must reach, the memory.
    NewVm { why: String, targets: Vec<String>, memory: u32 },
}

/// A switch the person asked for, ready for the switch command.
#[derive(Clone)]
pub struct Pending {
    pub entry: HarnessChoice,
    pub model: String,
    pub answers: BTreeMap<String, Answer>,
    /// Secret answers, by question id: in memory only.
    pub secrets: BTreeMap<String, String>,
    pub mode: Mode,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("harness", &self.entry.id)
            .field("model", &self.model)
            .field("answers", &self.answers)
            // Never a secret's value: only which questions have one.
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .field("mode", &self.mode)
            .finish()
    }
}

impl PartialEq for Pending {
    fn eq(&self, other: &Pending) -> bool {
        self.entry == other.entry && self.model == other.model && self.answers == other.answers && self.mode == other.mode
    }
}

impl Pending {
    /// Back to Yougori's own agent, which needs no pack and nothing from the launcher.
    pub fn yougori(spec: &EngineSpec, model: &str) -> Pending {
        let entry = spec.session.harnesses.iter().find(|entry| entry.id == YOUGORI).cloned().unwrap_or_else(|| HarnessChoice {
            id: YOUGORI.into(),
            name: "Yougori".into(),
            category: "coding".into(),
            ready: true,
            ..HarnessChoice::default()
        });
        Pending { entry, model: model.to_owned(), answers: BTreeMap::new(), secrets: BTreeMap::new(), mode: Mode::InPlace }
    }

    /// The request the switch command reads on stdin. Secrets go in it only for a new VM, which the
    /// launcher starts with them; in place, the engine gets them from this process's memory.
    pub fn request(&self) -> Value {
        let answers: Map<String, Value> = self.answers.iter().map(|(id, answer)| (id.clone(), answer.json())).collect();
        let mut request = json!({"harness": self.entry.id, "model": self.model, "answers": answers,
                                 "mode": if self.mode == Mode::InPlace { "in-place" } else { "new-vm" }});
        if let Mode::NewVm { targets, memory, .. } = &self.mode {
            request["targets"] = json!(targets);
            request["memory"] = json!(memory);
            request["secrets"] = json!(self.secrets);
        }
        request
    }
}

/// What a person calls a base image a harness needs.
fn base_words(base: &str) -> String {
    match base {
        "chromium" => "Chromium".into(),
        "postgres" => "PostgreSQL".into(),
        "" | "base" => "another VM image".into(),
        other => format!("the {other} VM image"),
    }
}

/// Whether the VM's reach holds `target` (`host:port`, or a host for each port).
fn held(spec: &EngineSpec, target: &str) -> bool {
    let reach = &spec.reach;
    if reach.mode == "full" {
        return true;
    }
    reach.mode == "targets"
        && reach.targets.iter().any(|given| {
            let given = given.to_ascii_lowercase();
            given == target || (!given.contains(':') && target.split(':').next() == Some(given.as_str()))
        })
}

/// Where `entry` runs with these answers: in place when it starts on this VM's base, needs no more
/// memory and its targets are within this VM's reach (the practice app always is); otherwise in a
/// new VM, with why.
pub fn mode(spec: &EngineSpec, entry: &HarnessChoice, answers: &BTreeMap<String, Answer>) -> Mode {
    let session = &spec.session;
    let mut targets: Vec<String> = Vec::new();
    for answer in answers.values() {
        if let Answer::Targets(entries) = answer {
            for (_, host) in entries {
                if !targets.contains(host) {
                    targets.push(host.clone());
                }
            }
        }
    }
    let mut needs: Vec<String> = Vec::new();
    if entry.id != YOUGORI && !entry.base.is_empty() && entry.base != session.vm_base {
        needs.push(base_words(&entry.base));
    }
    if entry.memory > session.vm_memory && session.vm_memory > 0 {
        needs.push(format!("{} GB of memory", entry.memory));
    }
    let wider: Vec<&String> = targets.iter().filter(|target| !held(spec, target)).collect();
    if needs.is_empty() && wider.is_empty() {
        return Mode::InPlace;
    }
    let name = &entry.name;
    let why = match (wider.is_empty(), needs.is_empty()) {
        (false, true) => format!("{name} starts in a new VM that reaches only {} and this inference.", targets.join(", ")),
        (false, false) => format!(
            "{name} starts in a new VM that reaches only {} and this inference (it needs {}).",
            targets.join(", "),
            needs.join(" and ")
        ),
        _ => format!("{name} starts in a new VM (it needs {}).", needs.join(" and ")),
    };
    Mode::NewVm { why, targets, memory: entry.memory.max(session.vm_memory) }
}

// -------------------------------------------------------------------------------- the panel

enum Step {
    /// Which harness.
    Pick,
    /// One of its questions: the choice under the cursor, or the text typed.
    Ask { index: usize, choice: usize, editor: Editor },
    /// The addresses of a target question.
    Address { index: usize, editor: Editor },
    /// A new VM, confirmed.
    Confirm { why: String },
}

/// What a key did to the panel.
#[derive(Debug, PartialEq)]
pub enum FlowOutcome {
    Stay,
    Close,
    Start(Box<Pending>),
}

/// The /harness panel: the harnesses, then the chosen one's questions, then a new VM's confirmation.
pub struct Flow {
    spec: EngineSpec,
    model: String,
    entries: Vec<HarnessChoice>,
    filter: Editor,
    selected: usize,
    chosen: Option<usize>,
    questions: Vec<Question>,
    answers: BTreeMap<String, Answer>,
    secrets: BTreeMap<String, String>,
    /// The questions asked, in order, for Back.
    trail: Vec<usize>,
    step: Step,
    error: Option<String>,
}

impl Flow {
    /// The panel for this session, on `model`, with `named` chosen when /harness named one (what
    /// that choice leads to comes with it: its first question, or the start when it asks none). An
    /// error says why it cannot open.
    pub fn open(spec: &EngineSpec, model: &str, named: Option<&str>) -> Result<(Flow, FlowOutcome), String> {
        if !spec.session.switchable() {
            return Err(OLDER.into());
        }
        let entries = spec.session.harnesses.clone();
        let current = entries.iter().position(|entry| entry.id == spec.harness).unwrap_or(0);
        let mut flow = Flow {
            spec: spec.clone(),
            model: model.to_owned(),
            entries,
            filter: Editor::default(),
            selected: current,
            chosen: None,
            questions: Vec::new(),
            answers: BTreeMap::new(),
            secrets: BTreeMap::new(),
            trail: Vec::new(),
            step: Step::Pick,
            error: None,
        };
        if let Some(named) = named.map(str::trim).filter(|named| !named.is_empty()) {
            let wanted = named.to_lowercase();
            let found = flow
                .entries
                .iter()
                .position(|entry| entry.id == wanted || entry.name.to_lowercase() == wanted)
                .ok_or_else(|| format!("There is no harness {named} here. /harness lists them."))?;
            flow.selected = found;
            if let Some(refused) = flow.choose(found) {
                return Err(refused);
            }
            let outcome = flow.next_question(0);
            return Ok((flow, outcome));
        }
        Ok((flow, FlowOutcome::Stay))
    }

    /// The entries the filter shows, by index.
    fn visible(&self) -> Vec<usize> {
        let filter = self.filter.text().trim().to_lowercase();
        (0..self.entries.len())
            .filter(|&i| {
                let entry = &self.entries[i];
                filter.is_empty()
                    || entry.name.to_lowercase().contains(&filter)
                    || entry.id.contains(&filter)
                    || entry.description.to_lowercase().contains(&filter)
            })
            .collect()
    }

    /// Chooses entry `index`: its questions start, or why it cannot be chosen (returned when the
    /// panel was opened for it, shown otherwise).
    fn choose(&mut self, index: usize) -> Option<String> {
        let entry = &self.entries[index];
        let refused = if entry.id == self.spec.harness {
            Some(format!("{} is running now.", entry.name))
        } else if !entry.ready {
            Some(if entry.reason.is_empty() { format!("{} cannot start here yet.", entry.name) } else { plain(&entry.reason, 300) })
        } else {
            match questions(&entry.questions) {
                Ok(asked) => {
                    self.questions = asked;
                    None
                }
                Err(detail) => Some(format!("This Yougori cannot ask {}'s questions ({detail}). Update Yougori: yougori update", entry.name)),
            }
        };
        if refused.is_some() {
            self.error = refused.clone();
            return refused;
        }
        self.chosen = Some(index);
        self.answers.clear();
        self.secrets.clear();
        self.trail.clear();
        self.error = None;
        None
    }

    fn entry(&self) -> &HarnessChoice {
        &self.entries[self.chosen.unwrap_or(self.selected)]
    }

    /// Whether `question` is asked with the answers so far.
    fn applies(&self, question: &Question) -> bool {
        match &question.when {
            None => true,
            Some(When::Present(other, present)) => {
                (self.answers.contains_key(other) || self.secrets.contains_key(other)) == *present
            }
            Some(When::Not(other, value)) => !self.answers.get(other).is_some_and(|answer| answer.is(value)),
        }
    }

    /// The next question from `start` that applies (dropping the answers of those that do not), or,
    /// when none is left, the start or a new VM's confirmation.
    fn next_question(&mut self, start: usize) -> FlowOutcome {
        let mut index = start;
        while index < self.questions.len() {
            let question = self.questions[index].clone();
            if self.applies(&question) {
                self.trail.push(index);
                self.ask(index);
                return FlowOutcome::Stay;
            }
            self.answers.remove(&question.id);
            self.secrets.remove(&question.id);
            index += 1;
        }
        self.finish()
    }

    /// Shows question `index`, its earlier answer (or default) chosen or typed.
    fn ask(&mut self, index: usize) {
        let question = &self.questions[index];
        let previous = self.answers.get(&question.id);
        let mut editor = Editor::default();
        let choice = match question.kind {
            Kind::Choice => {
                let current = match previous {
                    Some(Answer::Text(value)) => Some(value.as_str()),
                    _ => question.default.as_deref(),
                };
                current.and_then(|value| question.choices.iter().position(|pick| pick.value == value)).unwrap_or(0)
            }
            Kind::Confirm => {
                // On No for a must-confirm, so a stray Enter never gives its yes.
                let no = match previous {
                    Some(answer) => *answer != Answer::Yes(true),
                    None => question.must || question.default.as_deref() == Some("no"),
                };
                usize::from(no)
            }
            Kind::Target => {
                let picks = target_picks(question);
                match previous {
                    Some(Answer::Targets(_)) => picks.iter().position(|pick| pick.value != "practice").unwrap_or(0),
                    _ => picks.iter().position(|pick| pick.value == "practice").unwrap_or(0),
                }
            }
            Kind::Folder => usize::from(previous.is_none() && !question.required),
            Kind::Text | Kind::List => {
                let before = match previous {
                    Some(Answer::Text(text)) => text.clone(),
                    Some(Answer::List(items)) => items.join(", "),
                    Some(Answer::Targets(entries)) => entries.iter().map(|(entry, _)| entry.as_str()).collect::<Vec<_>>().join(", "),
                    _ => String::new(),
                };
                editor.set(&before);
                0
            }
            Kind::Secret => 0,
        };
        self.step = Step::Ask { index, choice, editor };
        self.error = None;
    }

    /// The choices a choice-like question shows, as (label, note).
    fn options(&self, index: usize) -> Vec<(String, String)> {
        let question = &self.questions[index];
        let mut options: Vec<(String, String)> = match question.kind {
            Kind::Choice => question.choices.iter().map(|pick| (pick.label.clone(), pick.note.clone())).collect(),
            Kind::Confirm => vec![
                ("Yes".into(), String::new()),
                ("No".into(), if question.must { "nothing is started".into() } else { String::new() }),
            ],
            Kind::Target => target_picks(question).into_iter().map(|pick| (pick.label, pick.note)).collect(),
            Kind::Folder => vec![("This session's folder".into(), self.spec.cwd.display().to_string())],
            Kind::Text | Kind::List | Kind::Secret => Vec::new(),
        };
        if !question.required && matches!(question.kind, Kind::Choice | Kind::Target | Kind::Folder) {
            options.push(("None".into(), "skip this question".into()));
        }
        options
    }

    /// Records an answer to question `index` (None: no answer) and goes on.
    fn answered(&mut self, index: usize, answer: Option<Answer>) -> FlowOutcome {
        let id = self.questions[index].id.clone();
        match answer {
            Some(answer) => self.answers.insert(id, answer),
            None => self.answers.remove(&id),
        };
        self.next_question(index + 1)
    }

    /// No question left: in place, the switch starts; a new VM is confirmed first.
    fn finish(&mut self) -> FlowOutcome {
        let entry = self.entry().clone();
        let mode = mode(&self.spec, &entry, &self.answers);
        if let Mode::NewVm { why, .. } = &mode {
            self.step = Step::Confirm { why: why.clone() };
            self.error = None;
            return FlowOutcome::Stay;
        }
        FlowOutcome::Start(Box::new(self.pending(mode)))
    }

    fn pending(&self, mode: Mode) -> Pending {
        Pending {
            entry: self.entry().clone(),
            model: self.model.clone(),
            answers: self.answers.clone(),
            secrets: self.secrets.clone(),
            mode,
        }
    }

    /// Esc: the question before, the harnesses from the first question, closed from the harnesses.
    fn back(&mut self) -> FlowOutcome {
        self.error = None;
        match &self.step {
            Step::Pick => FlowOutcome::Close,
            Step::Address { index, .. } => {
                let index = *index;
                self.ask(index);
                FlowOutcome::Stay
            }
            Step::Ask { .. } | Step::Confirm { .. } => {
                if matches!(self.step, Step::Ask { .. }) {
                    self.trail.pop();
                }
                match self.trail.pop() {
                    Some(index) => {
                        self.trail.push(index);
                        self.ask(index);
                    }
                    None => {
                        self.chosen = None;
                        self.step = Step::Pick;
                    }
                }
                FlowOutcome::Stay
            }
        }
    }

    /// Text pasted into the panel: into the field being typed, as one line.
    pub fn paste(&mut self, pasted: &str) {
        let line: String = pasted.chars().filter(|c| !c.is_control()).collect();
        match &mut self.step {
            Step::Ask { editor, .. } | Step::Address { editor, .. } => editor.insert(&line),
            Step::Pick => self.filter.insert(&line),
            Step::Confirm { .. } => {}
        }
    }

    pub fn key(&mut self, key: KeyEvent) -> FlowOutcome {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if control && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
            return FlowOutcome::Close;
        }
        if key.code == KeyCode::Esc {
            return self.back();
        }
        match &mut self.step {
            Step::Pick => {
                let visible = self.visible();
                match key.code {
                    KeyCode::Up | KeyCode::BackTab => self.move_by(&visible, -1),
                    KeyCode::Down | KeyCode::Tab => self.move_by(&visible, 1),
                    KeyCode::Enter => {
                        let at = visible.iter().copied().find(|i| *i == self.selected).or(visible.first().copied());
                        if let Some(index) = at {
                            self.selected = index;
                            if self.choose(index).is_none() {
                                return self.next_question(0);
                            }
                        }
                    }
                    _ => {
                        let before = self.filter.text().to_owned();
                        dialog::edit(&mut self.filter, key);
                        if self.filter.text() != before {
                            self.error = None;
                            let visible = self.visible();
                            if !visible.contains(&self.selected) {
                                self.selected = visible.first().copied().unwrap_or(self.selected);
                            }
                        }
                    }
                }
                FlowOutcome::Stay
            }
            Step::Ask { index, .. } => {
                let index = *index;
                if matches!(self.questions[index].kind, Kind::Text | Kind::List | Kind::Secret) {
                    let Step::Ask { editor, .. } = &mut self.step else { return FlowOutcome::Stay };
                    if key.code == KeyCode::Enter {
                        let typed = editor.text().to_owned();
                        return self.typed(index, &typed);
                    }
                    dialog::edit(editor, key);
                    self.error = None;
                    return FlowOutcome::Stay;
                }
                let count = self.options(index).len().max(1);
                let Step::Ask { choice, .. } = &mut self.step else { return FlowOutcome::Stay };
                let picked = match key.code {
                    KeyCode::Up | KeyCode::BackTab => {
                        *choice = (*choice + count - 1) % count;
                        None
                    }
                    KeyCode::Down | KeyCode::Tab => {
                        *choice = (*choice + 1) % count;
                        None
                    }
                    KeyCode::Home => {
                        *choice = 0;
                        None
                    }
                    KeyCode::End => {
                        *choice = count - 1;
                        None
                    }
                    KeyCode::Char(c @ '1'..='9') if !control && (c as usize - '1' as usize) < count => {
                        *choice = c as usize - '1' as usize;
                        Some(*choice)
                    }
                    KeyCode::Enter => Some(*choice),
                    _ => None,
                };
                match picked {
                    Some(picked) => self.picked(index, picked),
                    None => FlowOutcome::Stay,
                }
            }
            Step::Address { index, editor } => {
                let index = *index;
                if key.code == KeyCode::Enter {
                    return match target_entries(editor.text()) {
                        Ok(entries) => self.answered(index, Some(Answer::Targets(entries))),
                        Err(error) => {
                            self.error = Some(error);
                            FlowOutcome::Stay
                        }
                    };
                }
                dialog::edit(editor, key);
                self.error = None;
                FlowOutcome::Stay
            }
            Step::Confirm { .. } => match key.code {
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let entry = self.entry().clone();
                    let mode = mode(&self.spec, &entry, &self.answers);
                    FlowOutcome::Start(Box::new(self.pending(mode)))
                }
                KeyCode::Char('n') | KeyCode::Char('N') => self.back(),
                _ => FlowOutcome::Stay,
            },
        }
    }

    fn move_by(&mut self, visible: &[usize], by: isize) {
        if visible.is_empty() {
            return;
        }
        let at = visible.iter().position(|i| *i == self.selected).unwrap_or(0) as isize;
        let count = visible.len() as isize;
        self.selected = visible[(at + by).rem_euclid(count) as usize];
        self.error = None;
    }

    /// The choice `picked` of a choice-like question.
    fn picked(&mut self, index: usize, picked: usize) -> FlowOutcome {
        let question = self.questions[index].clone();
        let skip = !question.required && picked + 1 == self.options(index).len();
        match question.kind {
            Kind::Choice if skip => self.answered(index, None),
            Kind::Choice => {
                let value = question.choices.get(picked).map(|pick| pick.value.clone());
                self.answered(index, value.map(Answer::Text))
            }
            Kind::Confirm if picked == 0 => self.answered(index, Some(Answer::Yes(true))),
            Kind::Confirm if question.must => {
                self.error = Some(if question.refusal.is_empty() { "Nothing was started.".into() } else { question.refusal.clone() });
                FlowOutcome::Stay
            }
            Kind::Confirm => self.answered(index, Some(Answer::Yes(false))),
            Kind::Target if skip => self.answered(index, None),
            Kind::Target => {
                let picks = target_picks(&question);
                if picks.get(picked).is_some_and(|pick| pick.value == "practice") {
                    return self.answered(index, Some(Answer::Practice));
                }
                let mut editor = Editor::default();
                if let Some(Answer::Targets(entries)) = self.answers.get(&question.id) {
                    editor.set(&entries.iter().map(|(entry, _)| entry.as_str()).collect::<Vec<_>>().join(", "));
                }
                self.step = Step::Address { index, editor };
                self.error = None;
                FlowOutcome::Stay
            }
            Kind::Folder if skip => self.answered(index, None),
            Kind::Folder => {
                let folder = self.spec.cwd.display().to_string();
                self.answered(index, Some(Answer::Folder(folder)))
            }
            Kind::Text | Kind::List | Kind::Secret => FlowOutcome::Stay,
        }
    }

    /// The text typed for question `index`.
    fn typed(&mut self, index: usize, typed: &str) -> FlowOutcome {
        let question = self.questions[index].clone();
        if question.kind == Kind::Secret {
            if typed.is_empty() {
                if question.required {
                    self.error = Some("This question needs an answer.".into());
                    return FlowOutcome::Stay;
                }
                self.secrets.remove(&question.id);
                return self.next_question(index + 1);
            }
            if let Err(error) = check_secret(typed) {
                self.error = Some(error);
                return FlowOutcome::Stay;
            }
            self.secrets.insert(question.id.clone(), typed.to_owned());
            return self.next_question(index + 1);
        }
        match typed_answer(&question, typed) {
            Ok(answer) => self.answered(index, answer),
            Err(error) => {
                self.error = Some(error);
                FlowOutcome::Stay
            }
        }
    }

    /// The panel's lines for this width and at most `rows` rows, and where the cursor goes.
    pub fn lines(&self, theme: &Theme, width: usize, rows: usize) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
        let room = width.saturating_sub(3).max(1);
        let mut body: Vec<Vec<Span<'static>>> = Vec::new();
        let mut cursor = None;
        let notes = |body: &mut Vec<Vec<Span<'static>>>, text: &str| {
            if !text.is_empty() {
                body.extend(wrap_text(text, theme.muted(), room, &[], &[]).into_iter().map(|line| line.spans));
            }
        };
        let (title, hint) = match &self.step {
            Step::Pick => {
                let typed = self.filter.text();
                body.push(if typed.is_empty() {
                    vec![span("› ", theme.accent()), span("Type to filter", theme.muted())]
                } else {
                    vec![span("› ", theme.accent()), span(typed.to_owned(), ratatui::style::Style::default())]
                });
                cursor = Some((1, 3 + 2 + text::width(&typed[..self.filter.cursor()])));
                let visible = self.visible();
                let labels: Vec<String> = self.entries.iter().map(label).collect();
                let label_width = labels.iter().map(|l| text::width(l)).max().unwrap_or(0).min(28);
                let at = visible.iter().position(|i| *i == self.selected).unwrap_or(0);
                let shown = window(visible.len(), at, rows.saturating_sub(4));
                for &i in &visible[shown.0..shown.1] {
                    let entry = &self.entries[i];
                    let hint = if entry.id == self.spec.harness {
                        "running now".to_owned()
                    } else if !entry.ready {
                        plain(&entry.reason, 300)
                    } else {
                        let elsewhere = (entry.id != YOUGORI && !entry.base.is_empty() && entry.base != self.spec.session.vm_base)
                            || (entry.memory > self.spec.session.vm_memory && self.spec.session.vm_memory > 0);
                        let description = plain(&entry.description, 300);
                        match (elsewhere, description.is_empty()) {
                            (true, true) => "starts in a new VM".to_owned(),
                            (true, false) => format!("{description} · new VM"),
                            (false, _) => description,
                        }
                    };
                    let enabled = entry.ready && entry.id != self.spec.harness;
                    body.push(choice_line(theme, &labels[i], &hint, i == self.selected, enabled, label_width));
                }
                if visible.is_empty() {
                    body.push(vec![span("Nothing matches.", theme.muted())]);
                } else if shown.1 - shown.0 < visible.len() {
                    body.push(vec![span(format!("{} of {}", at + 1, visible.len()), theme.muted())]);
                }
                ("Switch harness".to_owned(), "↑↓ move · enter choose · esc close")
            }
            Step::Ask { index, choice, editor } => {
                let question = &self.questions[*index];
                notes(&mut body, &question.note);
                match question.kind {
                    Kind::Text | Kind::List | Kind::Secret => {
                        let shown = if question.kind == Kind::Secret {
                            "•".repeat(editor.text().chars().count())
                        } else {
                            editor.text().to_owned()
                        };
                        let before = if question.kind == Kind::Secret {
                            editor.text()[..editor.cursor()].chars().count()
                        } else {
                            text::width(&editor.text()[..editor.cursor()])
                        };
                        if !question.placeholder.is_empty() && matches!(question.kind, Kind::Text | Kind::List) {
                            notes(&mut body, &format!("Such as {}", question.placeholder));
                        }
                        if !question.required {
                            notes(&mut body, "Optional: Enter skips it.");
                        }
                        cursor = Some((body.len() + 1, 3 + 2 + before));
                        body.push(vec![span("› ", theme.accent()), span(shown, ratatui::style::Style::default())]);
                    }
                    _ => {
                        let options = self.options(*index);
                        let label_width = options.iter().map(|(l, _)| text::width(l)).max().unwrap_or(0).min(40);
                        for (i, (option, note)) in options.iter().enumerate() {
                            body.push(choice_line(theme, option, note, i == *choice, true, label_width));
                        }
                    }
                }
                let hint = if matches!(question.kind, Kind::Text | Kind::List | Kind::Secret) {
                    "enter next · esc back"
                } else {
                    "↑↓ move · enter choose · esc back"
                };
                (format!("{} · {}", self.entry().name, question.question), hint)
            }
            Step::Address { index, editor } => {
                let question = &self.questions[*index];
                notes(&mut body, "http(s) URLs, host:port or IPv4 addresses, separated by commas");
                if !question.placeholder.is_empty() {
                    notes(&mut body, &format!("Such as {}", question.placeholder));
                }
                cursor = Some((body.len() + 1, 3 + 2 + text::width(&editor.text()[..editor.cursor()])));
                body.push(vec![span("› ", theme.accent()), span(editor.text().to_owned(), ratatui::style::Style::default())]);
                (format!("{} · Website or address to test", self.entry().name), "enter next · esc back")
            }
            Step::Confirm { why } => {
                notes(&mut body, why);
                notes(&mut body, "Changes made so far stay in this VM's copy for review.");
                (format!("Start {} in a new VM?", self.entry().name), "enter start · esc back")
            }
        };
        if let Some(error) = &self.error {
            body.extend(wrap_text(error, theme.bad(), room, &[], &[]).into_iter().map(|line| line.spans));
        }
        (panel(theme, &title, body, hint, width), cursor)
    }
}

/// A harness's name in the list.
fn label(entry: &HarnessChoice) -> String {
    if entry.category == "security" {
        format!("{} (security)", entry.name)
    } else {
        entry.name.clone()
    }
}

// --------------------------------------------------------------------- the switch command

/// How a switch ended.
#[derive(Debug, PartialEq)]
pub enum Switched {
    /// The next harness's spec, its pack in this VM.
    InPlace(Box<EngineSpec>),
    /// The launcher starts a new VM for it once the screen exits [`NEW_VM_EXIT`].
    NewVm,
    /// Why not, and whether the harness before can start again.
    Failed { reason: String, kept: bool },
}

/// Asks the switch command to stop: SIGTERM, so it tells the VM.
fn terminate(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: a signal to this process's own child, by its id while it has not been reaped.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        return;
    }
    let _ = child.start_kill();
}

/// The switch command: the engine's environment (its secrets filled in) and the switch token this
/// process got from the VM, which no engine or service is ever given; in the workspace.
fn switch_command(spec: &EngineSpec, program: &str, arguments: &[String], token: Option<std::ffi::OsString>) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(spec.environment())
        .current_dir(&spec.cwd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        command.env(SWITCH_TOKEN, token);
    }
    command
}

/// Runs the spec's switch command with `request` on stdin (harness/README.md): its progress lines
/// go to `progress`, `cancel` stops it. The environment is the engine's, plus the switch token this
/// process got from the VM.
pub async fn run(
    spec: EngineSpec,
    request: Value,
    progress: tokio::sync::mpsc::UnboundedSender<String>,
    cancel: tokio::sync::oneshot::Receiver<()>,
) -> Switched {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let mut cancel = cancel;
    let Some((program, arguments)) = spec.session.switch.split_first() else {
        return Switched::Failed { reason: OLDER.into(), kept: true };
    };
    if cancel.try_recv().is_ok() {
        // Esc while the harness before was stopping: nothing was asked of the VM.
        return Switched::Failed { reason: "Cancelled.".into(), kept: true };
    }
    let mut command = switch_command(&spec, program, arguments, std::env::var_os(SWITCH_TOKEN));
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Switched::Failed { reason: format!("Could not start the switch: {error}."), kept: true },
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(request.to_string().as_bytes()).await;
        let _ = stdin.shutdown().await;
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let printed = tokio::spawn(async move {
        let mut out = Vec::new();
        if let Some(stdout) = stdout {
            let _ = stdout.take(16 << 20).read_to_end(&mut out).await;
        }
        out
    });
    let said = tokio::spawn(async move {
        let mut last: Option<(String, bool)> = None;
        if let Some(stderr) = stderr {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(value) = serde_json::from_str::<Value>(&line) else { continue };
                if let Some(text) = value["progress"].as_str() {
                    let _ = progress.send(plain(text, 300));
                } else if let Some(error) = value["error"].as_str() {
                    last = Some((plain(error, 600), value["kept"].as_bool().unwrap_or(true)));
                }
            }
        }
        last
    });
    let status = tokio::select! {
        status = child.wait() => status,
        _ = cancel => {
            terminate(&mut child);
            match tokio::time::timeout(CANCEL_WAIT, child.wait()).await {
                Ok(status) => status,
                Err(_) => {
                    let _ = child.start_kill();
                    child.wait().await
                }
            }
        }
    };
    let out = printed.await.unwrap_or_default();
    let said = said.await.ok().flatten();
    match status {
        Ok(status) if status.success() => {
            // Its whole output, or its last line (a program may say something before it).
            let value = serde_json::from_slice::<Value>(&out).ok().or_else(|| {
                String::from_utf8_lossy(&out).lines().rev().find(|line| !line.trim().is_empty()).and_then(|line| serde_json::from_str(line).ok())
            });
            let Some(value) = value else {
                return Switched::Failed { reason: "The switch printed no harness to start.".into(), kept: false };
            };
            if value["new_vm"] == json!(true) {
                return Switched::NewVm;
            }
            match serde_json::from_value::<EngineSpec>(value) {
                Ok(next) if next.check().is_ok() => Switched::InPlace(Box::new(next)),
                _ => Switched::Failed { reason: "The switch printed a harness this Yougori cannot start.".into(), kept: false },
            }
        }
        Ok(status) => {
            let (reason, kept) = said.unwrap_or_else(|| (format!("The switch stopped (exit code {}).", status.code().unwrap_or(-1)), true));
            Switched::Failed { reason, kept }
        }
        Err(error) => Switched::Failed { reason: format!("The switch could not finish: {error}."), kept: true },
    }
}

#[cfg(test)]
mod tests;
