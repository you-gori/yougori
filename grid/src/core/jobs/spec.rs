//! What a job is, and the checks it passes before any computer is asked to run it.
//!
//! A command is a program and its arguments as a list, or a prepared image's own entrypoint with
//! its arguments as a list. Nothing here is ever joined into one line and handed to a shell. A list
//! can still smuggle a command line in by naming a shell as its program and handing it the line,
//! so a shell as the program is refused here, with a sentence saying what to do instead.
//!
//! Names are logical. An input, an output and a queue are each called something, and none of those
//! names is ever a place on a computer: no separators, no drive letters, no step up and out.
use super::JobError;
use crate::core::{
    credential::looks_like_a_secret,
    limits::{LONGEST_JOB, MAX_ARGS, MAX_ARG_BYTES, MAX_ATTEMPTS_PER_JOB, MAX_BACKOFF_SECONDS, MAX_COMMAND_BYTES, MAX_INPUTS, MAX_OUTPUTS, MAX_SPEC_BYTES},
    work::{Resources, TRIES},
    workspace::looks_like_a_path,
};
use serde::{Deserialize, Serialize};

/// Everything a job says about itself, checked by `checked` before it is admitted.
///
/// What is stored is exactly this, so the computer that runs an attempt is told what the person
/// who sent the job said, and nothing a computer reports later can change it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSpec {
    /// What to run.
    pub entrypoint: Entrypoint,
    /// Outputs of jobs that already finished in this grid, each read under a name of this job's own.
    #[serde(default)]
    pub inputs: Vec<InputRef>,
    /// The names of what this job hands back. A successful attempt sends every one of them.
    #[serde(default)]
    pub outputs: Vec<String>,
    /// The longest one attempt may take, in seconds, counted from the moment a computer is given it.
    pub timeout_seconds: i64,
    /// What one attempt needs on the computer that runs it.
    #[serde(default)]
    pub needs: Resources,
    /// How many attempts it may have and how long it waits between them.
    #[serde(default)]
    pub retry: Retry,
    /// What running it does outside the grid, which decides whether it may ever be run again by itself.
    #[serde(default)]
    pub side_effects: SideEffects,
    /// Whether it can pick up from a checkpoint one of its earlier attempts recorded.
    #[serde(default)]
    pub checkpoints: bool,
}

/// What a job runs. Never a line of text for a shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Entrypoint {
    /// A program and its arguments, as a list. The first item is the program.
    Argv { argv: Vec<String> },
    /// A prepared image's own entrypoint, named by reference, with arguments as a list.
    Image {
        reference: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

/// One input: an output a finished job in this grid produced, read under a name of this job's own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputRef {
    pub name: String,
    pub artifact_id: String,
}

/// How many attempts a job may have, and how long it waits before each one after the first.
///
/// The wait doubles with each attempt, from `backoff_seconds`, and never passes
/// `MAX_BACKOFF_SECONDS`. Every attempt counts, whether or not it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retry {
    pub max_attempts: u32,
    #[serde(default)]
    pub backoff_seconds: i64,
}

impl Default for Retry {
    /// The same three tries the core gives any other piece of work, half a minute apart at first.
    fn default() -> Retry {
        Retry { max_attempts: TRIES as u32, backoff_seconds: 30 }
    }
}

/// What running a job does outside the grid.
///
/// The default is the careful one: a job that does not say otherwise is treated as changing
/// something that cannot recognise a repeat, so nothing runs it a second time without a person.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "class")]
pub enum SideEffects {
    /// Running it twice does no harm: a build, a conversion, a calculation over its inputs.
    Repeatable,
    /// It changes something outside and hands that system this key, so a second run is
    /// recognised there and does nothing more. It may be tried again; it is still never promised
    /// to have run exactly once.
    DedupKey { key: String },
    /// It changes something outside that cannot recognise a repeat. Once an attempt may have run,
    /// it is never run again by itself; a person checks what happened and settles it.
    #[default]
    ManualReconcile,
}

impl SideEffects {
    /// The word it is recorded under.
    pub fn word(&self) -> &'static str {
        match self {
            SideEffects::Repeatable => "repeatable",
            SideEffects::DedupKey { .. } => "dedupKey",
            SideEffects::ManualReconcile => "manualReconcile",
        }
    }

    /// The deduplication key, when the job hands one to the system it changes.
    pub fn key(&self) -> Option<&str> {
        match self {
            SideEffects::DedupKey { key } => Some(key),
            _ => None,
        }
    }
}

impl JobSpec {
    /// Reads a job description sent as JSON, refusing anything that is not part of a job.
    ///
    /// Strict at the door and nowhere else: a field this build does not know is refused here with
    /// its name, rather than dropped, because a dropped field is a setting somebody believes is in
    /// force. What is stored is read back leniently, so a later build that adds a field does not
    /// make an earlier one unable to read the queue.
    pub fn from_json(text: &str) -> Result<JobSpec, JobError> {
        if text.len() > MAX_SPEC_BYTES {
            return Err(JobError::Limit(format!("A job description can be at most {MAX_SPEC_BYTES} bytes")));
        }
        let value: serde_json::Value = serde_json::from_str(text).map_err(|error| JobError::InvalidSpec(format!("This job description is not readable JSON: {error}")))?;
        refuse_research(&value)?;
        only_known(&value, &SPEC_FIELDS, "a job")?;
        if let Some(entrypoint) = value.get("entrypoint") {
            only_known(entrypoint, &ENTRYPOINT_FIELDS, "a job's command")?;
        }
        if let Some(inputs) = value.get("inputs").and_then(serde_json::Value::as_array) {
            for input in inputs {
                only_known(input, &INPUT_FIELDS, "a job's input")?;
            }
        }
        for (field, allowed, what) in [("needs", &NEEDS_FIELDS[..], "what a job needs"), ("retry", &RETRY_FIELDS[..], "a job's retry policy"), ("sideEffects", &SIDE_EFFECT_FIELDS[..], "a job's side effects")] {
            if let Some(inner) = value.get(field) {
                only_known(inner, allowed, what)?;
            }
        }
        let spec: JobSpec = serde_json::from_value(value).map_err(|error| JobError::InvalidSpec(format!("This job description does not describe a job: {error}")))?;
        spec.checked()
    }

    /// The same job, checked: every bound, every name and every part of its command.
    pub fn checked(self) -> Result<JobSpec, JobError> {
        self.entrypoint.check()?;
        if self.inputs.len() > MAX_INPUTS {
            return Err(JobError::Limit(format!("A job can read at most {MAX_INPUTS} inputs")));
        }
        let mut seen: Vec<&str> = Vec::new();
        for input in &self.inputs {
            logical_name(&input.name, "An input")?;
            if seen.contains(&input.name.as_str()) {
                return Err(JobError::InvalidSpec(format!("Two inputs are called '{}'; give each its own name", shown(&input.name))));
            }
            seen.push(&input.name);
            identifier(&input.artifact_id, "artifact-", "An input names an artifact by its identifier, such as artifact-0123abcd")?;
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(JobError::Limit(format!("A job can declare at most {MAX_OUTPUTS} outputs")));
        }
        let mut seen: Vec<&str> = Vec::new();
        for output in &self.outputs {
            logical_name(output, "An output")?;
            if seen.contains(&output.as_str()) {
                return Err(JobError::InvalidSpec(format!("Two outputs are called '{}'; give each its own name", shown(output))));
            }
            seen.push(output);
        }
        if !(1..=LONGEST_JOB).contains(&self.timeout_seconds) {
            return Err(JobError::InvalidSpec(format!("A job's time limit is between one second and {} hours", LONGEST_JOB / 3600)));
        }
        let needs = self.needs;
        if [needs.cpu, needs.memory_gb, needs.disk_gb, needs.vram_gb].iter().any(|amount| !amount.is_finite() || *amount < 0.0) {
            return Err(JobError::InvalidSpec("What a job needs is an amount of zero or more of each resource".into()));
        }
        if needs.vram_gb > 0.0 && !needs.gpu {
            return Err(JobError::InvalidSpec("A job that needs video memory needs a GPU too".into()));
        }
        if self.retry.max_attempts == 0 {
            return Err(JobError::InvalidSpec("A job has at least one attempt".into()));
        }
        if self.retry.max_attempts > MAX_ATTEMPTS_PER_JOB {
            return Err(JobError::Limit(format!("A job can have at most {MAX_ATTEMPTS_PER_JOB} attempts")));
        }
        if !(0..=MAX_BACKOFF_SECONDS).contains(&self.retry.backoff_seconds) {
            return Err(JobError::InvalidSpec(format!("A job waits between nought and {MAX_BACKOFF_SECONDS} seconds before trying again")));
        }
        if let SideEffects::DedupKey { key } = &self.side_effects {
            dedup_key(key)?;
        }
        Ok(self)
    }
}

impl Entrypoint {
    fn check(&self) -> Result<(), JobError> {
        match self {
            Entrypoint::Argv { argv } => {
                let Some(program) = argv.first() else {
                    return Err(JobError::InvalidSpec("A job's command names the program to run first".into()));
                };
                if argv.len() > MAX_ARGS {
                    return Err(JobError::Limit(format!("A job's command can have at most {MAX_ARGS} parts")));
                }
                arguments(argv)?;
                program_name(program)?;
                // `env` runs whatever it is handed, so the program is the first thing after it that
                // is neither an option nor a setting.
                if base_name(program) == "env" {
                    if let Some(next) = argv[1..].iter().find(|part| !part.starts_with('-') && !part.contains('=')) {
                        program_name(next)?;
                    }
                }
                Ok(())
            }
            Entrypoint::Image { reference, args } => {
                image_reference(reference)?;
                if args.len() >= MAX_ARGS {
                    return Err(JobError::Limit(format!("A job's command can have at most {MAX_ARGS} parts")));
                }
                arguments(args)
            }
        }
    }
}

/// The fields a job description may have, at each level. Anything else is refused by name.
const SPEC_FIELDS: [&str; 8] = ["entrypoint", "inputs", "outputs", "timeoutSeconds", "needs", "retry", "sideEffects", "checkpoints"];
const ENTRYPOINT_FIELDS: [&str; 4] = ["kind", "argv", "reference", "args"];
const INPUT_FIELDS: [&str; 2] = ["name", "artifactId"];
const NEEDS_FIELDS: [&str; 5] = ["cpu", "memoryGb", "diskGb", "gpu", "vramGb"];
const RETRY_FIELDS: [&str; 2] = ["maxAttempts", "backoffSeconds"];
const SIDE_EFFECT_FIELDS: [&str; 2] = ["class", "key"];

/// Words that belong to the research profile. A job description that uses one of them as a field,
/// at any depth, or as the kind of its command, is trying to carry a research step, and is told so
/// in those words rather than as an unknown field.
const RESEARCH_WORDS: [&str; 9] = ["research", "scope", "scopeid", "activity", "admission", "finding", "enclosure", "authorisation", "authorization"];

fn refuse_research(value: &serde_json::Value) -> Result<(), JobError> {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, inner) in fields {
                if RESEARCH_WORDS.contains(&name.to_ascii_lowercase().as_str()) {
                    return Err(JobError::ResearchAction(shown(name)));
                }
                if name == "kind" && inner.as_str().is_some_and(|kind| RESEARCH_WORDS.contains(&kind.to_ascii_lowercase().as_str())) {
                    return Err(JobError::ResearchAction(shown(inner.as_str().unwrap_or_default())));
                }
                refuse_research(inner)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => items.iter().try_for_each(refuse_research),
        _ => Ok(()),
    }
}

fn only_known(value: &serde_json::Value, allowed: &[&str], what: &str) -> Result<(), JobError> {
    if let Some(fields) = value.as_object() {
        if let Some(stranger) = fields.keys().find(|name| !allowed.contains(&name.as_str())) {
            return Err(JobError::InvalidSpec(format!("'{}' is not part of {what}", shown(stranger))));
        }
    }
    Ok(())
}

/// A name as it is shown back in a sentence: printable, and short.
pub(super) fn shown(text: &str) -> String {
    let printable: String = text.chars().filter(|letter| !letter.is_control()).take(64).collect();
    if text.chars().count() > 64 {
        format!("{printable}…")
    } else {
        printable
    }
}

/// A logical name: an input, an output or a queue. Letters, digits, dots, dashes and underscores,
/// starting with a letter or a digit, at most 64 of them, and never a place on a computer.
pub fn logical_name(text: &str, what: &str) -> Result<String, JobError> {
    if text.is_empty() {
        return Err(JobError::InvalidSpec(format!("{what} needs a name")));
    }
    if looks_like_a_path(text) || text.contains('/') || text.contains(':') || text.starts_with('.') || text.contains("..") || text.starts_with('~') {
        return Err(JobError::PathLikeName(shown(text)));
    }
    if text.len() > 64 {
        return Err(JobError::InvalidSpec(format!("{what}'s name can be at most 64 characters")));
    }
    if !text.chars().all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '.' | '-' | '_')) || !text.starts_with(|letter: char| letter.is_ascii_alphanumeric()) {
        return Err(JobError::InvalidSpec(format!(
            "'{}' is not a name {} can have: use letters, digits, dots, dashes and underscores, starting with a letter or a digit",
            shown(text),
            what.to_lowercase()
        )));
    }
    Ok(text.to_owned())
}

/// A queue's name, which follows the same rules as any other logical name.
pub(super) fn queue_name(text: &str) -> Result<String, JobError> {
    logical_name(text, "A queue")
}

/// An identifier this grid issued: its prefix and up to 48 lowercase hexadecimal characters.
fn identifier(text: &str, prefix: &str, sentence: &str) -> Result<(), JobError> {
    let fits = text.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty() && rest.len() <= 48 && rest.bytes().all(|letter| letter.is_ascii_hexdigit()));
    if fits {
        Ok(())
    } else {
        Err(JobError::InvalidSpec(sentence.to_owned()))
    }
}

/// A deduplication key: up to 128 printable characters with no spaces, and a name for a piece of
/// work rather than a secret, because it is shown to every computer that runs the job.
fn dedup_key(key: &str) -> Result<(), JobError> {
    if key.is_empty() || key.len() > 128 || !key.chars().all(|letter| letter.is_ascii_graphic()) {
        return Err(JobError::InvalidSpec("A deduplication key is 1 to 128 printable characters with no spaces".into()));
    }
    if carries_a_secret(key) {
        return Err(JobError::InvalidSpec("A deduplication key names a piece of work and is shown to the computers that run it; this one looks like a secret".into()));
    }
    Ok(())
}

/// Every part of a command: bounded, printable, and carrying no secret value.
fn arguments(parts: &[String]) -> Result<(), JobError> {
    let mut total = 0usize;
    for part in parts {
        if part.len() > MAX_ARG_BYTES {
            return Err(JobError::Limit(format!("Each part of a job's command can be at most {MAX_ARG_BYTES} bytes")));
        }
        total += part.len();
        if part.chars().any(char::is_control) {
            return Err(JobError::InvalidSpec("Each part of a job's command is one line of printable text".into()));
        }
        if carries_a_secret(part) {
            return Err(JobError::InvalidSpec(
                "A job's command carries no secret values, and one part of this one looks like one. Give the job a reference its computer resolves instead".into(),
            ));
        }
    }
    if total > MAX_COMMAND_BYTES {
        return Err(JobError::Limit(format!("A job's whole command can be at most {MAX_COMMAND_BYTES} bytes")));
    }
    Ok(())
}

/// The program, which must be a program: not a line of shell, and not a shell.
fn program_name(program: &str) -> Result<(), JobError> {
    if program.trim().is_empty() {
        return Err(JobError::InvalidSpec("A job's command names the program to run first".into()));
    }
    if program.chars().any(|letter| letter.is_whitespace() || matches!(letter, ';' | '|' | '&' | '$' | '`' | '<' | '>' | '(' | ')' | '{' | '}' | '*' | '?' | '!' | '"' | '\'')) {
        return Err(JobError::InvalidSpec(
            "The program's name looks like a line of shell. Give the program and each of its arguments as separate items; a job never runs through a shell".into(),
        ));
    }
    if SHELLS.contains(&base_name(program).as_str()) {
        return Err(JobError::InvalidSpec(
            "Jobs do not run a shell. Name the program to run, or the script itself, and give its arguments as a list".into(),
        ));
    }
    Ok(())
}

/// Programs that read a line of text and run it.
const SHELLS: [&str; 14] = ["sh", "bash", "zsh", "dash", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox", "cmd", "powershell", "pwsh"];

/// A program's name without its folder or a Windows `.exe`, in lower case.
fn base_name(program: &str) -> String {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program).to_ascii_lowercase();
    name.strip_suffix(".exe").map(str::to_owned).unwrap_or(name)
}

/// An image reference: a registry path with an optional tag and an optional pinned digest.
fn image_reference(reference: &str) -> Result<(), JobError> {
    let fits = !reference.is_empty()
        && reference.len() <= 512
        && reference.chars().all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '.' | '_' | '-' | '/' | ':' | '@'))
        && reference.starts_with(|letter: char| letter.is_ascii_alphanumeric())
        && !reference.contains("..");
    if !fits {
        return Err(JobError::InvalidSpec("An image is named by a reference such as registry.example/team/tool:1.2, with nothing else in it".into()));
    }
    if let Some((_, digest)) = reference.split_once('@') {
        let pinned = digest.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|letter| letter.is_ascii_hexdigit()));
        if !pinned {
            return Err(JobError::InvalidSpec("An image pinned by digest ends in @sha256: and 64 hexadecimal characters".into()));
        }
    }
    Ok(())
}

/// Whether a part of a command or a key carries a secret value, by the realm's own rule for that.
///
/// `looks_like_a_secret` is asked about the whole text and about each piece of it between
/// separators, each with a full stop after it. The full stop is deliberate: the rule's last test
/// calls any long unbroken run of letters, digits, dashes and underscores a value, and in a command
/// that is a commit name, a digest, a generated identifier or a long snake_case file name far more
/// often than it is a token. With the full stop that test cannot match, so what answers is the
/// rule's markers and prefixes, which a value actually carries: `token=`, `password=`, `Bearer `, a
/// PEM block, a provider's key prefix, wherever in the text it sits.
pub(super) fn carries_a_secret(text: &str) -> bool {
    std::iter::once(text).chain(text.split(['/', '=', ':', ',', '@', '?', '&', ';'])).any(|piece| !piece.is_empty() && looks_like_a_secret(&format!("{piece}.")))
}
