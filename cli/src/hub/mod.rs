//! The Yougori Hub from the command line: templates (whole setups as a folder), tools, and
//! running and publishing them through yougori.com. The contract is docs/hub.md: section 5 for
//! the commands, section 6 for the website's answers and section 7 for the review.
pub mod capture;
pub mod client;
pub mod components;
pub mod format;
pub mod instances;
pub mod lifecycle;
pub mod pattern;
pub mod personal;
pub mod plan;
pub mod publish;
pub mod refs;
pub mod render;
pub mod review;
pub mod run;
pub mod scan;
pub mod setups;
pub mod tools;
pub mod unicode;
mod unicode_data;
pub mod views;

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const TEMPLATE_USAGE: &str = "Yougori Hub templates: whole setups, shared on yougori.com/hub

  yougori run hub/PUBLISHER/NAME[@VERSION] [--name INSTANCE] [--input ID=VALUE]... [--inputs FILE]
                                           [--secrets -] [--yes] [--allow-pc-access] [--dry-run]
  yougori template run hub/PUBLISHER/NAME[@VERSION] | ./FOLDER   (same options, and for a format 2
                                           template [--binding ID=VALUE]... [--storage-drive DRIVE])
  yougori template continue INSTANCE [--yes] [--input ID=VALUE]... [--inputs FILE] [--secrets -]
                                     [--allow-pc-access]
  yougori template status [INSTANCE] | list | down INSTANCE
  yougori template update INSTANCE [--yes] [--allow-pc-access] [--input ID=VALUE]... [--secrets -]
                                   [--binding ID=VALUE]...   (bindings: a format 2 setup)
  yougori template rm INSTANCE --yes [--delete-data]
  yougori template new [NAME] | check [FOLDER] | capture ENV... [--output FOLDER]
  yougori template publish [FOLDER] [--yes] [--publisher NAME]
  yougori template download REF [FOLDER] | info REF
  yougori template search [WORDS] [--sort popular|trending|stars|new|updated] [--kind template|tool] [--page N]
  yougori template fork REF [--name NAME] | star REF | unstar REF
  yougori template report REF --reason harmful|stolen|abuse|other [--details TEXT]
  yougori template delete REF --yes
  yougori template capabilities [--group grid|models|web|people|data|automation]
  yougori template plan hub/PUBLISHER/NAME[@VERSION] | ./FOLDER | INSTANCE [--name INSTANCE] [--input ID=VALUE]... [--inputs FILE] [--dry-run]
  yougori template configure INSTANCE [--input ID=VALUE]... [--inputs FILE] [--binding ID=VALUE]...
                                      [--secrets -] [--yes] [--allow-pc-access] [--dry-run]
  yougori template start INSTANCE | stop INSTANCE
  yougori template logs INSTANCE [--follow] [--cursor N] | --sandbox NAME
  yougori template jobs INSTANCE JOB [--settle succeeded|failed|run_again]
  yougori template artifacts INSTANCE [--save ID --to FOLDER]
  yougori template usage INSTANCE
  yougori template join [--yes]   (a script: {\"invitation\": \"…\", \"password\": \"…\"} on stdin)
  yougori template export INSTANCE [FOLDER]
  yougori template reveal INSTANCE [KEY]
  yougori template permissions INSTANCE

Yougori checks only its own uploads, which show Verified. Verified (collateral) means the publisher
holds $100 collateral, lost if Yougori removes their work for harmful code; Yougori has not checked
those files, so they get the same warning as every community item. A run downloads the files,
checks every SHA-256 and the version digest, checks this computer, and shows a review built from
the files before anything is created, and says when the Hub page describes the version differently
from those files. A run that stopped (Ctrl+C, a closed window, a failure) carries on with template
continue INSTANCE, with the same files and answers; a setup waiting for a secret is answered with
template configure INSTANCE --secrets -. In a terminal each
question offers Back and Ctrl+C stops; scripts pass --yes, --input/--inputs and --secrets - (JSON
on stdin; secrets never go on the command line or in --inputs). A change that lets a sandbox
change files in a folder you chose asks you to agree; a script agrees with --allow-pc-access.
template join takes the invitation without showing it, shows what joining does, then takes the
grid's company password the same way; a script pipes {\"invitation\": \"…\", \"password\": \"…\"}
to it with --yes (an invitation that starts with yougori-invite: carries your account and may
come alone, as plain text). A fork always starts from an item's latest version. Text in a
terminal, JSON when piped or with --format json.";

pub const TOOL_USAGE: &str = "Yougori tools: programs installed into a sandbox

  yougori tool new [NAME] | check [FOLDER]
  yougori tool add FOLDER | hub/PUBLISHER/NAME[@VERSION] [--yes]
  yougori tool list | remove NAME --yes
  yougori tool install NAME --environment ENV [--secrets -]
  yougori tool open NAME --environment ENV
  yougori tool publish [FOLDER] [--yes] [--publisher NAME]

Built-in tools (codex, claude, gemini, ollama, opencode, kilo, openclaw) keep their shortcuts:
tool open codex --environment ENV is yougori codex --environment ENV. Added tools live in
~/.yougori/tools/NAME; their install lines run in the sandbox and must pass their check. A tool
that signs in with an API key asks for it (hidden) or reads {\"key\": \"...\"} from --secrets -, and keeps
it as the deployment secret tool-NAME.";

/// `yougori setup …`: the commands about setups that are not about one setup's lifecycle. Each
/// one has its own `--help` with the detail.
pub const SETUP_USAGE: &str = "Yougori setup: reading and recovering what your setups hold

  yougori setup backups SETUP | check … | restore …   the backups a setup keeps, and putting one back
  yougori setup telemetry [SETUP]                     a read-only reading of your setups
  yougori setup migration inventory|backup|verify|rehearse …
                                                      check a copy of a Yougori data folder

Add --help to any of them for what it does and what it leaves alone. A restore is the only one
that can change anything, and it describes what it would do and stops until you confirm.";

/// A Hub command's answer: JSON for scripts, text for people (empty when the screen already
/// shows it), and the exit code.
pub struct Reply {
    pub value: Value,
    pub text: Option<String>,
    pub code: i32,
}

/// The commands this module answers: `template …`, `tool …` and `run hub/…`, where the first
/// word of `run` that is not an option (or an option's value) is a Hub address. `run template
/// SOURCE` is answered too (see [`template_run`]).
pub fn requested(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("template" | "tool") => true,
        // `yougori setup migration …`: the dry run that checks a copy of a data folder before
        // anything is moved into a setup.
        Some("setup") => true,
        Some("run") => template_run(args).is_some() || first_run_word(args).is_some_and(|at| refs::looks_like_ref(&args[at], &client::website())),
        _ => false,
    }
}

/// Where the first word of `run` that is not an option (or an option's value) is in `args`.
fn first_run_word(args: &[String]) -> Option<usize> {
    let mut at = 1;
    while let Some(word) = args.get(at) {
        if word == "--" {
            return None;
        }
        if !word.starts_with('-') {
            return Some(at);
        }
        if RUN_VALUES.iter().any(|name| word == &format!("--{name}")) {
            at += 1;
        }
        at += 1;
    }
    None
}

/// `yougori run template SOURCE …` as people type it: `yougori template run SOURCE …`, so a
/// folder that is not there is reported as such rather than pulled as an image named `template`.
fn template_run(args: &[String]) -> Option<Vec<String>> {
    if args.first().map(String::as_str) != Some("run") {
        return None;
    }
    let at = first_run_word(args)?;
    let source = args.get(at + 1)?;
    (args[at] == "template" && !source.starts_with('-')).then(|| {
        let rest = args.iter().enumerate().skip(1).filter(|(i, _)| *i != at).map(|(_, word)| word.clone());
        ["template".to_owned(), "run".to_owned()].into_iter().chain(rest).collect()
    })
}

/// Whether the desktop app opened this command in a console of its own (`YOUGORI_HUB_CONSOLE=1`).
pub fn console_requested(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim() == "1")
}

pub fn console() -> bool {
    console_requested(std::env::var("YOUGORI_HUB_CONSOLE").ok().as_deref())
}

/// Keeps an app-opened console window until the person has read it. Enter or Ctrl+C closes it.
pub async fn press_enter() {
    use std::io::Write;
    eprint!("\nPress Enter to close this window.");
    let _ = std::io::stderr().flush();
    // The read waits on its own thread, so Ctrl+C is heard on every system.
    let read = tokio::task::spawn_blocking(|| {
        let _ = std::io::stdin().read_line(&mut String::new());
    });
    tokio::select! {
        _ = read => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Words and options of one command.
#[derive(Debug, Default)]
struct Parsed {
    words: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
    switches: BTreeSet<String>,
}

impl Parsed {
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|v| v.last()).map(String::as_str)
    }
    fn has(&self, name: &str) -> bool {
        self.switches.contains(name)
    }
}

/// Reads `args`: `with_value` options take the next word (or `=VALUE`); `switches` take none.
fn parse(args: &[String], with_value: &[&str], switches: &[&str], usage: &str) -> Result<Parsed, String> {
    let mut parsed = Parsed::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--").filter(|n| !n.is_empty()) {
            let (name, inline) = name.split_once('=').map_or((name, None), |(n, v)| (n, Some(v.to_owned())));
            if with_value.contains(&name) {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        index += 1;
                        args.get(index).filter(|v| !v.starts_with("--") || *v == "-").cloned().ok_or_else(|| format!("--{name} needs a value.\n{usage}"))?
                    }
                };
                parsed.values.entry(name.to_owned()).or_default().push(value);
            } else if switches.contains(&name) && inline.is_none() {
                parsed.switches.insert(name.to_owned());
            } else {
                return Err(format!("Unknown option --{name}.\n{usage}"));
            }
        } else if arg == "-h" {
            parsed.switches.insert("help".into());
        } else {
            parsed.words.push(arg.clone());
        }
        index += 1;
    }
    if let Some(format) = parsed.value("format") {
        if !matches!(format, "json" | "text" | "table") {
            return Err("--format must be json or text.".into());
        }
    }
    Ok(parsed)
}

/// How a command shows its answer.
#[derive(Clone, Copy)]
struct Mode {
    /// Text rather than JSON.
    text: bool,
    /// A person is at the keyboard: prompts, spinners and Back are allowed.
    interactive: bool,
}

fn mode(parsed: &Parsed) -> Mode {
    use std::io::IsTerminal;
    let stdout = std::io::stdout().is_terminal();
    let text = match parsed.value("format") {
        Some("json") => false,
        Some(_) => true,
        None => stdout,
    };
    Mode { text, interactive: text && stdout && std::io::stdin().is_terminal() }
}

fn reply(value: Value, mode: Mode, view: impl FnOnce(&Value) -> String) -> Reply {
    let text = mode.text.then(|| view(&value));
    Reply { value, text, code: 0 }
}

fn run_options(parsed: &Parsed, source: String) -> Result<run::Options, String> {
    let mut inputs = Vec::new();
    for pair in parsed.values.get("input").into_iter().flatten() {
        let (id, value) = pair.split_once('=').ok_or_else(|| format!("--input takes ID=VALUE, such as --input access=quick (got {}).", scan::shown(pair)))?;
        inputs.push((id.trim().to_owned(), value.to_owned()));
    }
    let secrets = match parsed.value("secrets") {
        None => false,
        Some("-") => true,
        Some(_) => return Err("Secrets are read from stdin only: use --secrets - with a JSON object such as {\"openai_key\": \"…\"}. Never put a secret on the command line.".into()),
    };
    let mut bindings = Vec::new();
    for pair in parsed.values.get("binding").into_iter().flatten() {
        let (id, value) = pair.split_once('=').ok_or_else(|| format!("--binding takes ID=VALUE, such as --binding data=D:/shop or --binding grid=SETUP/RESOURCE (got {}).", scan::shown(pair)))?;
        bindings.push((id.trim().to_owned(), value.to_owned()));
    }
    Ok(run::Options {
        source,
        name: parsed.value("name").map(str::to_owned),
        inputs,
        bindings,
        inputs_file: parsed.value("inputs").map(str::to_owned),
        secrets_stdin: secrets,
        yes: parsed.has("yes"),
        allow_pc_access: parsed.has("allow-pc-access"),
        dry_run: parsed.has("dry-run"),
        storage_drive: parsed.value("storage-drive").map(str::to_owned),
    })
}

const RUN_VALUES: &[&str] = &["name", "input", "inputs", "binding", "secrets", "storage-drive", "format"];
const RUN_SWITCHES: &[&str] = &["yes", "allow-pc-access", "dry-run", "help"];

/// The end of a run or an update, as the mode wants it. An interactive run already showed it.
fn instance_reply(value: Value, mode: Mode) -> Reply {
    let text = mode.text.then(|| if mode.interactive { String::new() } else { views::instance(&value) });
    Reply { value, text, code: 0 }
}

/// One word after the command, or the usage.
/// The template a `run` or `plan` names. One word is an address, a folder or an instance, as
/// before. Several words are joined only when together they name a template Yougori publishes —
/// `yougori run my api` — so typing several words by mistake is still the usage error it was, and
/// no stray word can turn into a reference.
fn source_words(parsed: &Parsed, usage: &str) -> Result<String, String> {
    if parsed.words.len() > 1 {
        let joined = parsed.words.join(" ");
        if setups::resolve_alias(&joined).is_some() {
            return Ok(joined);
        }
    }
    one(parsed, 0, usage)
}

fn one(parsed: &Parsed, at: usize, usage: &str) -> Result<String, String> {
    parsed.words.get(at).cloned().filter(|_| parsed.words.len() == at + 1).ok_or_else(|| usage.to_owned())
}

/// What Ctrl+C says for the command it stopped: what was left, and how to go on.
fn stopped(args: &[String]) -> String {
    stopped_message(args, instances::current().as_ref())
}

/// [`stopped`], given the instance the command had saved by then, if any.
fn stopped_message(args: &[String], current: Option<&instances::State>) -> String {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let named = |index: usize| words.iter().skip(index).find(|word| !word.starts_with('-')).copied().unwrap_or("INSTANCE").to_owned();
    match words.as_slice() {
        ["run", ..] | ["template", "run", ..] => run::stopped_with(current, "Cancelled. Nothing was created."),
        ["template", "continue" | "update", ..] => run::stopped_with(current, "Stopped. Nothing was changed."),
        ["template", "rm", ..] => format!("Stopped. Part of {0} may already be removed; run yougori template rm {0} --yes again to finish.", named(2)),
        ["template", "down", ..] => format!("Stopped. See where {0} is with yougori template status {0}.", named(2)),
        ["template" | "tool", "publish", ..] => publish::STOPPED.to_owned(),
        ["template", "capture", ..] => "Stopped. If the output folder was started, remove it before capturing again.".to_owned(),
        ["template", "download", ..] => "Stopped. If the folder was started, remove it before downloading again.".to_owned(),
        // These send an operation to the engine, which keeps running after Ctrl+C. The command only
        // stopped watching it, so it never claims nothing changed; it says where to look.
        ["template", "configure" | "start" | "stop", ..] => format!("Stopped watching. The operation may still be running; follow it with yougori template logs {}.", named(2)),
        ["template", "plan", ..] => "Stopped. A plan changes nothing, so nothing was created.".to_owned(),
        ["template", "capabilities", ..] => "Stopped.".to_owned(),
        // The join is applied only after the review and the password; once it was, the engine
        // carries it on whether or not anyone watches.
        ["template", "join", ..] => "Stopped. If the join had already been applied, the engine carries on with it: see it with yougori template list. Otherwise nothing was joined.".to_owned(),
        ["template", "export", ..] => "Stopped. If a folder was started, remove it before exporting again.".to_owned(),
        // Reading and rehearsing change nothing at all, so stopping one leaves nothing behind.
        ["setup", "migration", "inventory" | "rehearse" | "verify", ..] => "Stopped. Nothing was read out and nothing was changed.".to_owned(),
        ["setup", "migration", "backup", ..] => "Stopped. The folder that was read is untouched; if a backup folder was started, remove it before backing up again.".to_owned(),
        // Reading the backups, checking one and the operations reading all change nothing.
        ["setup", "backups", "check", ..] => "Stopped. The backup was not changed, and neither was the volume.".to_owned(),
        // A restore that was interrupted is in the engine's hands, not this command's: it says
        // where to look rather than claiming the data is as it was.
        ["setup", "backups", "restore", ..] => "Stopped watching. If the restore had already started it keeps going; see where it got to with yougori setup backups SETUP.".to_owned(),
        ["setup", "backups", ..] | ["setup", "telemetry", ..] => "Stopped. Nothing was read out and nothing was changed.".to_owned(),
        ["tool", "install" | "open", ..] => format!("Stopped. The sandbox keeps running; run the same command again to install {} there.", named(2)),
        ["tool", "add", ..] => "Stopped. Nothing was added.".to_owned(),
        _ => "Stopped. Nothing was changed.".to_owned(),
    }
}

/// Runs a `template`, `tool` or `run hub/…` command.
pub async fn run(args: &[String]) -> Result<Reply, String> {
    let args = &template_run(args).unwrap_or_else(|| args.to_vec());
    let interrupted = async {
        // Interactive screens catch Ctrl+C as a key; this catches it everywhere else, with what
        // the command had done by then and how to go on.
        let _ = tokio::signal::ctrl_c().await;
        Err::<Reply, String>(crate::wire::cancelled(&stopped(args)))
    };
    tokio::select! {
        biased;
        outcome = dispatch(args) => outcome,
        stopped = interrupted => stopped,
    }
}

async fn dispatch(args: &[String]) -> Result<Reply, String> {
    let help = args.iter().any(|a| a == "--help" || a == "-h");
    match args.first().map(String::as_str) {
        Some("run") => {
            if help {
                return Ok(Reply { value: json!({"usage": TEMPLATE_USAGE}), text: Some(format!("{TEMPLATE_USAGE}\n")), code: 0 });
            }
            let parsed = parse(&args[1..], RUN_VALUES, RUN_SWITCHES, TEMPLATE_USAGE)?;
            let source = source_words(&parsed, "Usage: yougori run hub/PUBLISHER/NAME[@VERSION] [--name INSTANCE] [--yes]")?;
            let mode = mode(&parsed);
            let value = run::run(run_options(&parsed, source)?, mode.interactive).await?;
            Ok(instance_reply(value, mode))
        }
        Some("template") => {
            if help || args.len() == 1 {
                return Ok(Reply { value: json!({"usage": TEMPLATE_USAGE}), text: Some(format!("{TEMPLATE_USAGE}\n")), code: 0 });
            }
            template(&args[1], &args[2..]).await
        }
        Some("setup") => match args.get(1).map(String::as_str) {
            Some("migration") if !help => migration(&args[2..]).await,
            Some("migration") => Ok(Reply { value: json!({"usage": setups::MIGRATION_USAGE}), text: Some(format!("{}\n", setups::MIGRATION_USAGE)), code: 0 }),
            Some("backups") if !help => backups(&args[2..]).await,
            Some("backups") => Ok(Reply { value: json!({"usage": setups::BACKUPS_USAGE}), text: Some(format!("{}\n", setups::BACKUPS_USAGE)), code: 0 }),
            Some("telemetry") if !help => telemetry(&args[2..]).await,
            Some("telemetry") => Ok(Reply { value: json!({"usage": setups::TELEMETRY_USAGE}), text: Some(format!("{}\n", setups::TELEMETRY_USAGE)), code: 0 }),
            _ => Ok(Reply { value: json!({"usage": SETUP_USAGE}), text: Some(format!("{SETUP_USAGE}\n")), code: 0 }),
        },
        Some("tool") => {
            if help || args.len() == 1 {
                return Ok(Reply { value: json!({"usage": TOOL_USAGE}), text: Some(format!("{TOOL_USAGE}\n")), code: 0 });
            }
            tool(&args[1], &args[2..]).await
        }
        _ => Err(TEMPLATE_USAGE.into()),
    }
}

/// `yougori setup migration inventory|backup|verify|rehearse …` (plan 19.1, 19.3 steps 1–4).
///
/// `--allow-live` is only ever sent because the person typed it; nothing here adds it. Without it
/// the engine refuses the data folder it is using itself, so a dry run can never read, let alone
/// disturb, a running installation.
async fn migration(args: &[String]) -> Result<Reply, String> {
    let usage = setups::MIGRATION_USAGE;
    let Some(verb) = args.first().map(String::as_str) else { return Err(usage.to_owned()) };
    let parsed = parse(&args[1..], &["format", "into"], &["allow-live"], usage)?;
    let mode = mode(&parsed);
    let allow_live = parsed.has("allow-live");
    match verb {
        "inventory" => {
            let path = one(&parsed, 0, "Usage: yougori setup migration inventory PATH")?;
            let value = run::wait(mode.interactive, "Reading the folder", setups::migration_inventory(&path, allow_live)).await?;
            Ok(reply(value, mode, setups::inventory_view))
        }
        "backup" => {
            let path = one(&parsed, 0, "Usage: yougori setup migration backup PATH --into FOLDER")?;
            let into = parsed.value("into").ok_or("Usage: yougori setup migration backup PATH --into FOLDER")?.to_owned();
            let value = run::wait(mode.interactive, "Backing up the records", setups::migration_backup(&path, &into, allow_live)).await?;
            Ok(reply(value, mode, setups::backup_view))
        }
        "verify" => {
            let folder = one(&parsed, 0, "Usage: yougori setup migration verify FOLDER")?;
            let value = run::wait(mode.interactive, "Checking the backup", setups::migration_verify(&folder)).await?;
            Ok(reply(value, mode, setups::verify_view))
        }
        "rehearse" => {
            let path = one(&parsed, 0, "Usage: yougori setup migration rehearse PATH")?;
            let value = run::wait(mode.interactive, "Rehearsing on the copy", setups::migration_rehearse(&path, allow_live)).await?;
            Ok(reply(value, mode, setups::rehearse_view))
        }
        other => Err(format!("Unknown migration command {}.\n{usage}", scan::shown(other))),
    }
}

/// `yougori setup backups …`: the list, the check and the reviewed restore.
///
/// A restore is two calls, always. The first one changes nothing and answers with what it would
/// do and a confirmation word for exactly that restore; `--yes` sends the second with that word.
/// Without `--yes` the review is all that happens, so no backup can be put back by a typo, and
/// `--yes` can never apply to a restore the person did not see described.
async fn backups(args: &[String]) -> Result<Reply, String> {
    let usage = setups::BACKUPS_USAGE;
    let verb = args.first().map(String::as_str).unwrap_or("");
    // `yougori setup backups SETUP` — the list, where the first word is the setup rather than a verb.
    let (verb, rest) = match verb {
        "check" | "restore" | "now" => (verb, &args[1..]),
        _ => ("list", args),
    };
    let parsed = parse(rest, &["format", "volume", "backup"], &["yes", "over-original"], usage)?;
    let mode = mode(&parsed);
    let setup = one(&parsed, 0, "Usage: yougori setup backups SETUP")?;
    match verb {
        "list" => {
            let value = run::wait(mode.interactive, "Reading the backups", setups::backups_list(&setup)).await?;
            Ok(reply(value, mode, setups::backups_view))
        }
        "check" => {
            let (volume, backup) = which(&parsed, "check")?;
            let value = run::wait(mode.interactive, "Checking the backup", setups::backup_check(&setup, &volume, &backup)).await?;
            Ok(reply(value, mode, setups::backup_check_view))
        }
        "now" => {
            let volume = parsed.value("volume").ok_or("Say which volume to back up: yougori setup backups now SETUP --volume VOLUME. yougori setup backups SETUP lists them.")?.to_owned();
            let value = run::wait(mode.interactive, "Asking for a backup", setups::backup_now(&setup, &volume)).await?;
            Ok(reply(value, mode, |v| views::done(vec![v["said"].as_str().unwrap_or("The backup has started.").to_owned()])))
        }
        _ => {
            let (volume, backup) = which(&parsed, "restore")?;
            let over_original = parsed.has("over-original");
            let review = run::wait(
                mode.interactive,
                "Working out what would be restored",
                setups::backup_restore_review(&setup, &volume, &backup, over_original),
            )
            .await?;
            if !parsed.has("yes") {
                // The whole answer, and nothing done. This is the only outcome without --yes.
                return Ok(reply(review, mode, setups::restore_review_view));
            }
            let confirm = review["confirm"]
                .as_str()
                .ok_or("Yougori could not work out what this restore would do, so nothing was changed. Try yougori setup backups SETUP to see what is kept.")?
                .to_owned();
            // The review is shown even when it is going ahead: a person who typed --yes should
            // still read what was replaced.
            let shown = setups::restore_review_view(&review);
            let done = run::wait(
                mode.interactive,
                "Putting the backup back",
                setups::backup_restore_confirm(&setup, &volume, &backup, over_original, &confirm),
            )
            .await?;
            let text = mode.text.then(|| format!("{shown}{}", setups::restore_done_view(&done)));
            Ok(Reply { value: done, text, code: 0 })
        }
    }
}

/// The volume and the backup a check or a restore is about. Both are named, never guessed: the
/// newest backup is not assumed, because "the newest" is not what a person checking a restore
/// means.
fn which(parsed: &Parsed, verb: &str) -> Result<(String, String), String> {
    let usage = format!("Usage: yougori setup backups {verb} SETUP --volume VOLUME --backup BACKUP");
    let volume = parsed.value("volume").filter(|name| !name.trim().is_empty()).ok_or_else(|| format!("Say which volume with --volume.\n{usage}"))?;
    let backup = parsed.value("backup").filter(|id| !id.trim().is_empty()).ok_or_else(|| {
        format!("Say which backup with --backup. yougori setup backups SETUP lists them.\n{usage}")
    })?;
    Ok((volume.to_owned(), backup.to_owned()))
}

/// `yougori setup telemetry [SETUP]`: the read-only operations reading. It changes nothing, so
/// there is nothing to confirm and nothing to undo.
async fn telemetry(args: &[String]) -> Result<Reply, String> {
    let parsed = parse(args, &["format", "limit", "cursor"], &[], setups::TELEMETRY_USAGE)?;
    let mode = mode(&parsed);
    let number = |name: &str| -> Result<Option<u64>, String> {
        match parsed.value(name) {
            None => Ok(None),
            Some(given) => given.trim().parse::<u64>().map(Some).map_err(|_| format!("--{name} takes a whole number, such as --{name} 20.")),
        }
    };
    let setup = parsed.words.first().cloned();
    let value = run::wait(mode.interactive, "Reading your setups", setups::telemetry(setup.as_deref(), number("cursor")?, number("limit")?)).await?;
    Ok(reply(value, mode, setups::telemetry_view))
}

async fn template(action: &str, rest: &[String]) -> Result<Reply, String> {
    let usage = TEMPLATE_USAGE;
    match action {
        "run" => {
            let parsed = parse(rest, RUN_VALUES, RUN_SWITCHES, usage)?;
            let source = source_words(&parsed, "Usage: yougori template run hub/PUBLISHER/NAME[@VERSION] | ./FOLDER [--name INSTANCE] [--yes]")?;
            let mode = mode(&parsed);
            let value = run::run(run_options(&parsed, source)?, mode.interactive).await?;
            Ok(instance_reply(value, mode))
        }
        "continue" => {
            let parsed = parse(rest, &["format", "input", "inputs", "secrets"], &["yes", "allow-pc-access"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template continue INSTANCE [--yes]")?;
            let mode = mode(&parsed);
            // An engine setup carries on from its last change that did not finish, as Try again
            // does on its page: only the steps that did not finish run again.
            if let Some(setup_id) = setups::setup_named(&name).await {
                let given = run_options(&parsed, String::new())?;
                let inputs_given = !given.inputs.is_empty() || given.inputs_file.is_some();
                let secrets = if given.secrets_stdin { Some(setups::read_secret_values().await?) } else { None };
                let value = setups::continue_setup(&name, &setup_id, inputs_given, secrets, mode.interactive).await?;
                return Ok(reply(value, mode, move |v| {
                    views::done(vec![if v["continued"] == true {
                        format!("{name} finished the change it had left. Only what had not finished ran again.")
                    } else {
                        format!("Nothing to continue: the last change to {name} finished.")
                    }])
                }));
            }
            let value = run::continue_instance(&name, run_options(&parsed, String::new())?, mode.interactive, true).await?;
            Ok(instance_reply(value, mode))
        }
        "status" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template status [INSTANCE]".into());
            }
            let mode = mode(&parsed);
            // A named engine setup shows its own detail; a v1 instance (or no name) is unchanged.
            if let Some(name) = parsed.words.first() {
                if let Some(setup_id) = setups::setup_named(name).await {
                    let value = run::wait(mode.interactive, "Reading the setup", setups::get_setup(&setup_id)).await?;
                    return Ok(reply(value, mode, setups::setup_view));
                }
            }
            let value = lifecycle::status(parsed.words.first().map(String::as_str), mode.interactive).await?;
            Ok(reply(value, mode, |v| if v["instances"].is_array() { views::list(v) } else { views::instance(v) }))
        }
        "list" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if !parsed.words.is_empty() {
                return Err("Usage: yougori template list".into());
            }
            let mode = mode(&parsed);
            // v1 instances unchanged; engine setups added under a new `setups` key (additive).
            let mut value = lifecycle::list()?;
            let setups = setups::list_setups().await;
            if !setups.is_empty() {
                value["setups"] = json!(setups);
            }
            Ok(reply(value, mode, |v| {
                let mut text = views::list(v);
                let setups_view = setups::setups_list_view(v["setups"].as_array().map(Vec::as_slice).unwrap_or_default());
                if !setups_view.is_empty() {
                    text.push_str("\n\n");
                    text.push_str(&setups_view);
                }
                text
            }))
        }
        "update" => {
            let parsed = parse(rest, &["format", "input", "inputs", "binding", "secrets"], &["yes", "allow-pc-access"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template update INSTANCE [--yes]")?;
            let mode = mode(&parsed);
            // An engine setup moves to its template's newest version through the engine.
            if setups::setup_named(&name).await.is_some() {
                let options = run_options(&parsed, String::new())?;
                let value = setups::update(&name, &options.inputs, &options.bindings, options.inputs_file.as_deref(), options.secrets_stdin, options.yes, options.allow_pc_access, mode.interactive).await?;
                return Ok(reply(value, mode, move |v| {
                    let mut lines: Vec<String> = v["plan"]["conflicts"].as_array().into_iter().flatten().filter_map(|conflict| conflict["message"].as_str()).map(|said| format!("▲ {}", views::clean(said))).collect();
                    if v["applied"] == true {
                        lines.push(format!("Updated {name}."));
                        return views::done(lines);
                    }
                    lines.extend(setups::plan_review_lines(&v["plan"]));
                    if v["needsConfirmation"] == true {
                        lines.push(format!("Apply it with: yougori template update {name} --yes{}", setups::agreement_flags(&v["plan"])));
                    }
                    lines.join("\n")
                }));
            }
            let options = run_options(&parsed, String::new())?;
            // Bindings belong to setups made from format 2 templates; a format 1 instance has none
            // to change, and a flag that did nothing would read as if it had.
            if !options.bindings.is_empty() && instances::Instances::standard().ok().and_then(|store| store.load(&name).ok().flatten()).is_some() {
                return Err(format!("{name} is a format 1 instance, which has no bindings: --binding is for setups made from format 2 templates. Nothing was changed."));
            }
            let value = lifecycle::update(&name, options, mode.interactive).await?;
            if value["updated"] == false {
                let said = value["said"].as_str().unwrap_or_default().to_owned();
                return Ok(reply(value, mode, |_| views::done(vec![said])));
            }
            Ok(instance_reply(value, mode))
        }
        "down" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template down INSTANCE")?;
            let mode = mode(&parsed);
            // An engine setup stops through setup_action; a v1 instance is unchanged.
            if let Some(setup_id) = setups::setup_named(&name).await {
                let value = setups::action(&setup_id, "stop", mode.interactive).await?;
                return Ok(reply(value, mode, move |_| views::done(vec![format!("{name} stopped. Its sandboxes, files and data are kept.")])));
            }
            let value = lifecycle::down(&name, mode.interactive).await?;
            Ok(reply(value, mode, |v| views::done(vec![format!("{} stopped. Its sandboxes, files and data are kept.", v["instance"].as_str().unwrap_or_default()), format!("Start it again: {}", v["start"].as_str().unwrap_or_default())])))
        }
        "rm" => {
            let parsed = parse(rest, &["format"], &["yes", "delete-data"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template rm INSTANCE --yes [--delete-data]")?;
            let mode = mode(&parsed);
            // An engine setup is reviewed by the engine first (nothing changes), then removed as
            // reviewed; a script must pass --yes. Its data is kept unless its template asks and the
            // person agrees (--delete-data). A v1 instance keeps its own removal flow unchanged.
            if let Some(setup_id) = setups::setup_named(&name).await {
                let value = setups::remove_setup(&setup_id, parsed.has("yes"), parsed.has("delete-data"), mode.interactive).await?;
                return Ok(reply(value, mode, move |v| {
                    if v["removed"] == true {
                        let mut lines = vec![format!("{name} was removed. Borrowed resources and other setups are untouched.")];
                        let deleted: Vec<&str> = v["deleted"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                        if !deleted.is_empty() {
                            lines.push(format!("Deleted with it, as you chose: {}. That can't be undone.", deleted.join(", ")));
                        }
                        views::done(lines)
                    } else {
                        let mut lines = setups::removal_lines(&v["plan"]);
                        lines.push(format!("Remove it with: yougori template rm {name} --yes"));
                        let offered = setups::offered_deletions(&v["plan"]);
                        if !offered.is_empty() {
                            lines.push("Add --delete-data as well to also delete what it offers; that can't be undone:".to_owned());
                            lines.extend(offered.iter().map(|(_, message)| format!("  {}", views::clean(message))));
                        }
                        lines.join("\n")
                    }
                }));
            }
            let value = lifecycle::rm(&name, parsed.has("yes"), parsed.has("delete-data"), mode.interactive).await?;
            Ok(reply(value, mode, |v| {
                let mut lines = vec![format!("{} was removed: {} sandboxes and the instance folder.", v["instance"].as_str().unwrap_or_default(), v["removed"]["environments"].as_array().map_or(0, Vec::len))];
                let kept: Vec<&str> = v["kept"]["volumes"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                if !kept.is_empty() {
                    lines.push(format!("Kept with their data: {}. Remove them with yougori volume rm {} --yes.", kept.join(", "), kept.join(" ")));
                }
                if let Some(backups) = v["kept"]["backups"].as_str() {
                    lines.push(format!("Backups of files you changed are still in {backups}."));
                }
                let missing: Vec<&str> = v["notFound"]["volumes"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                if !missing.is_empty() {
                    lines.push(format!("Not found, so not removed: {}. Look for them with yougori volume ls --scan.", missing.join(", ")));
                }
                views::done(lines)
            }))
        }
        "new" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template new [NAME]".into());
            }
            let mode = mode(&parsed);
            // In a terminal, walk the six capability groups; a script gets the starter folder.
            let value = setups::new_setup(parsed.words.first().map(String::as_str), mode.interactive).await?;
            Ok(reply(value, mode, |v| views::done(std::iter::once(format!("Created {}", v["created"].as_str().unwrap_or_default())).chain(v["next"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| format!("Next: {s}"))).collect())))
        }
        "check" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template check [FOLDER]".into());
            }
            let folder = parsed.words.first().cloned().unwrap_or_else(|| ".".into());
            // Either format: a format 2 package is checked by the shared crate and shown with
            // its resources and capabilities; a format 1 package exactly as before.
            let value = plan::check_report(&folder).await?;
            Ok(reply(value, mode(&parsed), |v| if v["format"] == 2 { plan::check_view(v) } else { views::checked(v) }))
        }
        "capture" => {
            let parsed = parse(rest, &["format", "output"], &[], usage)?;
            let mode = mode(&parsed);
            let value = capture::capture(&parsed.words, parsed.value("output"), mode.interactive).await?;
            Ok(reply(value, mode, |v| {
                let mut lines = vec![format!("Captured {} into {}", v["captured"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", "), v["folder"].as_str().unwrap_or_default()), "Left out:".to_owned()];
                lines.extend(v["leftOut"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| format!("  - {s}")));
                lines.extend(v["next"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| format!("Next: {s}")));
                views::done(lines)
            }))
        }
        "publish" => {
            let parsed = parse(rest, &["format", "publisher"], &["yes"], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template publish [FOLDER] [--yes]".into());
            }
            let folder = parsed.words.first().cloned().unwrap_or_else(|| ".".into());
            let mode = mode(&parsed);
            let value = publish::publish("template", &folder, parsed.has("yes"), parsed.value("publisher"), mode.interactive).await?;
            Ok(reply(value, mode, published))
        }
        "download" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let reference = publish::item(parsed.words.first().ok_or("Usage: yougori template download REF [FOLDER]")?)?;
            if parsed.words.len() > 2 {
                return Err("Usage: yougori template download REF [FOLDER]".into());
            }
            let mode = mode(&parsed);
            let value = download(&reference, parsed.words.get(1).map(String::as_str), mode.interactive).await?;
            Ok(reply(value, mode, |v| views::done(vec![format!("Saved {} {} in {} ({} files, checked).", v["downloaded"].as_str().unwrap_or_default(), v["version"].as_str().unwrap_or_default(), v["folder"].as_str().unwrap_or_default(), v["files"]), "Run it from there with yougori template run FOLDER, or from the Hub with yougori run hub/PUBLISHER/NAME.".into()])))
        }
        "info" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let reference = publish::item(&one(&parsed, 0, "Usage: yougori template info REF")?)?;
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Reading the Hub", info(&reference)).await?;
            Ok(reply(value, mode, views::info))
        }
        "search" => {
            let parsed = parse(rest, &["format", "sort", "kind", "page"], &[], usage)?;
            let sort = parsed.value("sort");
            if sort.is_some_and(|s| !matches!(s, "popular" | "trending" | "stars" | "new" | "updated")) {
                return Err("--sort must be popular, trending, stars, new or updated.".into());
            }
            let kind = parsed.value("kind");
            if kind.is_some_and(|k| !matches!(k, "template" | "tool")) {
                return Err("--kind must be template or tool.".into());
            }
            let page = parsed.value("page").map(|p| p.parse::<u32>().ok().filter(|p| (1..=1000).contains(p)).ok_or("--page must be a number from 1 to 1000.")).transpose()?;
            let mode = mode(&parsed);
            let site = client::Site::configured()?;
            let words = parsed.words.join(" ");
            let value = run::wait(mode.interactive, "Searching the Hub", async { site.search(&words, sort, kind, page).await.map_err(String::from) }).await?;
            Ok(reply(value, mode, views::search))
        }
        "fork" => {
            let parsed = parse(rest, &["format", "name", "publisher"], &[], usage)?;
            let reference = publish::item(&one(&parsed, 0, "Usage: yougori template fork REF [--name NAME]")?)?;
            let mode = mode(&parsed);
            let value = publish::fork(&reference, parsed.value("name"), parsed.value("publisher"), mode.interactive).await?;
            Ok(reply(value, mode, |v| views::done(vec![format!("Forked {} as {}. It keeps a link to the original and its licence ({}).", reference.item(), v["ref"].as_str().unwrap_or_default(), v["license"].as_str().unwrap_or_default()), format!("Page: {}/hub/{}", client::website(), v["ref"].as_str().unwrap_or_default())])))
        }
        "star" | "unstar" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let reference = publish::item(&one(&parsed, 0, &format!("Usage: yougori template {action} REF"))?)?;
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Updating your star", publish::star(&reference, action == "star")).await?;
            Ok(reply(value, mode, |v| views::done(vec![format!("{} {} · {} stars", reference.item(), if v["starred"] == true { "is starred" } else { "is no longer starred" }, v["stars"])])))
        }
        "report" => {
            let parsed = parse(rest, &["format", "reason", "details"], &[], usage)?;
            let reference = publish::item(&one(&parsed, 0, "Usage: yougori template report REF --reason harmful|stolen|abuse|other [--details TEXT]")?)?;
            let reason = parsed.value("reason").ok_or("Add --reason harmful, stolen, abuse or other.")?;
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Sending the report", publish::report(&reference, reason, parsed.value("details"))).await?;
            Ok(reply(value, mode, |_| views::done(vec![format!("Reported {}. Yougori will look at it.", reference.item())])))
        }
        "delete" => {
            let parsed = parse(rest, &["format"], &["yes"], usage)?;
            let reference = publish::item(&one(&parsed, 0, "Usage: yougori template delete REF --yes")?)?;
            if !parsed.has("yes") {
                return Err(format!("Deleting {} takes it off the Hub for everyone; its name can never be used again. Instances already running keep working. Repeat with --yes only if this is intended.", reference.item()));
            }
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Deleting it from the Hub", publish::delete(&reference)).await?;
            Ok(reply(value, mode, |_| views::done(vec![format!("{} was deleted from the Hub. Instances already running keep working.", reference.item())])))
        }
        "capabilities" => {
            let parsed = parse(rest, &["format", "group"], &[], usage)?;
            if !parsed.words.is_empty() {
                return Err("Usage: yougori template capabilities [--group grid|models|web|people|data|automation]".into());
            }
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Reading the capabilities", setups::capabilities(parsed.value("group"))).await?;
            Ok(reply(value, mode, setups::capabilities_view))
        }
        "plan" => {
            let parsed = parse(rest, &["format", "input", "inputs", "binding", "name"], &["dry-run"], usage)?;
            let source = source_words(&parsed, "Usage: yougori template plan hub/PUBLISHER/NAME[@VERSION] | ./FOLDER | INSTANCE [--name INSTANCE]")?;
            let options = run_options(&parsed, source.clone())?;
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Working out the plan", setups::plan(&source, options.name.as_deref(), &options.inputs, options.inputs_file.as_deref(), &options.bindings)).await?;
            Ok(reply(value, mode, setups::plan_view))
        }
        "configure" => {
            let parsed = parse(rest, &["format", "input", "inputs", "binding", "secrets"], &["yes", "allow-pc-access", "dry-run"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template configure INSTANCE [--input ID=VALUE]... [--dry-run]")?;
            let options = run_options(&parsed, String::new())?;
            let mode = mode(&parsed);
            let value = setups::configure(&name, &options.inputs, &options.bindings, options.inputs_file.as_deref(), options.secrets_stdin, options.yes, options.allow_pc_access, options.dry_run, mode.interactive).await?;
            Ok(reply(value, mode, |v| {
                if v["applied"] == true {
                    views::done(vec![format!("Configured {name}.")])
                } else if v["needsConfirmation"] == true {
                    let mut lines = setups::plan_review_lines(&v["plan"]);
                    lines.push(format!("Apply it with: yougori template configure {name} --yes{}", setups::agreement_flags(&v["plan"])));
                    lines.join("\n")
                } else {
                    setups::plan_review_lines(&v["plan"]).join("\n")
                }
            }))
        }
        "start" | "stop" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let name = one(&parsed, 0, &format!("Usage: yougori template {action} INSTANCE"))?;
            let mode = mode(&parsed);
            let value = setups::action(&name, action, mode.interactive).await?;
            let word = if action == "start" { "started" } else { "stopped. Its sandboxes, files and data are kept" };
            Ok(reply(value, mode, move |_| views::done(vec![format!("{name} {word}.")])))
        }
        "logs" => {
            let parsed = parse(rest, &["format", "cursor", "sandbox"], &["follow"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template logs INSTANCE [--follow] [--cursor N] | --sandbox NAME")?;
            if let Some(sandbox) = parsed.value("sandbox") {
                let mode = mode(&parsed);
                let value = setups::sandbox_logs(&name, sandbox).await?;
                return Ok(reply(value, mode, setups::sandbox_logs_view));
            }
            let cursor = parsed.value("cursor").map(|c| c.parse::<u64>().map_err(|_| "--cursor must be a whole number.")).transpose()?;
            let mode = mode(&parsed);
            if parsed.has("follow") {
                return setups::follow_logs(&name, cursor, mode.text).await;
            }
            let value = setups::logs(&name, cursor).await?;
            Ok(reply(value, mode, setups::logs_view))
        }
        "jobs" => {
            let parsed = parse(rest, &["format", "settle"], &[], usage)?;
            const JOBS: &str = "Usage: yougori template jobs INSTANCE JOB [--settle succeeded|failed|run_again]";
            if parsed.words.len() != 2 {
                return Err(JOBS.into());
            }
            let settle = parsed.value("settle");
            if let Some(outcome) = settle.filter(|outcome| !matches!(*outcome, "succeeded" | "failed" | "run_again")) {
                return Err(format!("--settle is succeeded, failed or run_again, not {}. {JOBS}", scan::shown(outcome)));
            }
            let mode = mode(&parsed);
            let value = setups::job(&parsed.words[0], &parsed.words[1], settle).await?;
            Ok(reply(value, mode, setups::job_view))
        }
        "usage" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template usage INSTANCE")?;
            let mode = mode(&parsed);
            let value = setups::usage(&name).await?;
            Ok(reply(value, mode, setups::usage_view))
        }
        "artifacts" => {
            let parsed = parse(rest, &["format", "save", "to"], &[], usage)?;
            const ARTIFACTS: &str = "Usage: yougori template artifacts INSTANCE [--save ID --to FOLDER]";
            let name = one(&parsed, 0, ARTIFACTS)?;
            let save = match (parsed.value("save"), parsed.value("to")) {
                (Some(id), Some(folder)) => Some((id, folder)),
                (None, None) => None,
                _ => return Err(format!("--save and --to go together. {ARTIFACTS}")),
            };
            let mode = mode(&parsed);
            let value = setups::artifacts(&name, save).await?;
            Ok(reply(value, mode, setups::artifacts_view))
        }
        "join" => {
            let parsed = parse(rest, &["format"], &["yes"], usage)?;
            if !parsed.words.is_empty() {
                return Err(format!("Usage: yougori template join [--yes]. The invitation is never an argument. {}", setups::JOIN_STDIN));
            }
            let mode = mode(&parsed);
            let value = setups::join(parsed.has("yes"), mode.interactive).await?;
            Ok(reply(value, mode, join_view))
        }
        "export" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template export INSTANCE [FOLDER]").or_else(|_| parsed.words.first().cloned().ok_or("Usage: yougori template export INSTANCE [FOLDER]".to_owned()))?;
            if parsed.words.len() > 2 {
                return Err("Usage: yougori template export INSTANCE [FOLDER]".into());
            }
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Exporting the recipe", setups::export(&name, parsed.words.get(1).map(String::as_str))).await?;
            Ok(reply(value, mode, |v| views::done(vec![format!("Exported {} into {} (runtime data and secrets left out).", v["exported"].as_str().unwrap_or_default(), v["folder"].as_str().unwrap_or_default())])))
        }
        "reveal" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let shape = "Usage: yougori template reveal INSTANCE [KEY]";
            let name = parsed.words.first().cloned().ok_or(shape)?;
            if parsed.words.len() > 2 {
                return Err(shape.into());
            }
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Asking for it", setups::reveal(&name, parsed.words.get(1).map(String::as_str))).await?;
            Ok(reply(value, mode, move |v| setups::reveal_view(&name, v)))
        }
        "permissions" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template permissions INSTANCE")?;
            let mode = mode(&parsed);
            let value = run::wait(mode.interactive, "Reading what it is allowed to do", setups::permissions(&name)).await?;
            Ok(reply(value, mode, setups::permissions_view))
        }
        other => Err(format!("Unknown template command {}.\n{usage}", scan::shown(other))),
    }
}

/// `template join` as text: the setup it joined, by the name the engine keeps, or, when a script
/// left out `--yes`, the review, that nothing was joined, and the command that joins.
fn join_view(value: &Value) -> String {
    if value["joined"] == true {
        let setup_id = value["setupId"].as_str().unwrap_or_default();
        return views::done(vec![
            format!("Joined {}.", value["setup"].as_str().filter(|name| !name.is_empty()).unwrap_or(setup_id)),
            format!("See it with yougori template status {setup_id}"),
        ]);
    }
    let mut lines = setups::join_lines(&value["plan"]);
    lines.push("Nothing was joined.".to_owned());
    lines.push(if value["passwordNeeded"] == false {
        "Join it with yougori template join --yes, giving the invitation on stdin again.".to_owned()
    } else {
        "Join it with yougori template join --yes, giving {\"invitation\": \"…\", \"password\": \"…\"} on stdin: the invitation again and the grid's company password.".to_owned()
    });
    views::done(lines)
}

fn published(value: &Value) -> String {
    views::done(vec![
        format!("Published {} {} ({} files).", value["published"].as_str().unwrap_or_default(), value["version"].as_str().unwrap_or_default(), value["files"]),
        format!("Page: {}", value["page"].as_str().unwrap_or_default()),
        format!("Anyone can run it with: {}", value["run"].as_str().unwrap_or_default()),
    ])
}

async fn tool(action: &str, rest: &[String]) -> Result<Reply, String> {
    let usage = TOOL_USAGE;
    match action {
        "new" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori tool new [NAME]".into());
            }
            let value = tools::new(parsed.words.first().map(String::as_str))?;
            Ok(reply(value, mode(&parsed), |v| views::done(std::iter::once(format!("Created {}", v["created"].as_str().unwrap_or_default())).chain(v["next"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| format!("Next: {s}"))).collect())))
        }
        "check" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori tool check [FOLDER]".into());
            }
            let mut value = tools::check_folder(parsed.words.first().map(String::as_str).unwrap_or("."))?;
            value["next"] = json!(format!("yougori tool add {}", shell_words::quote(parsed.words.first().map(String::as_str).unwrap_or("."))));
            Ok(reply(value, mode(&parsed), views::checked))
        }
        "add" => {
            let parsed = parse(rest, &["format"], &["yes"], usage)?;
            let source = one(&parsed, 0, "Usage: yougori tool add FOLDER | hub/PUBLISHER/NAME[@VERSION] [--yes]")?;
            let mode = mode(&parsed);
            let yes = parsed.has("yes");
            let value = tools::add(&source, yes, mode.interactive).await?;
            // A person who agreed at the review has read it; anyone else sees it now.
            let reviewed = mode.interactive && !yes && value["source"] == "hub";
            Ok(reply(value, mode, |v| {
                let mut lines = Vec::new();
                if !reviewed && v["source"] == "hub" && v["verified"] != true {
                    lines.extend(views::unverified());
                    lines.push(String::new());
                }
                lines.push(format!("Added {} {} from {}.", v["added"].as_str().unwrap_or_default(), v["version"].as_str().unwrap_or_default(), v["from"].as_str().unwrap_or_default()));
                if let Some(notice) = v["notice"].as_str() {
                    lines.push(format!("Note: {notice}"));
                }
                if !reviewed {
                    lines.push(String::new());
                    lines.extend(views::tool_review(&v["review"]));
                    lines.push(String::new());
                }
                lines.push(format!("Next: {}", v["next"].as_str().unwrap_or_default()));
                views::done(lines)
            }))
        }
        "list" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if !parsed.words.is_empty() {
                return Err("Usage: yougori tool list".into());
            }
            Ok(reply(tools::listing()?, mode(&parsed), views::tools))
        }
        "remove" => {
            let parsed = parse(rest, &["format"], &["yes"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori tool remove NAME --yes")?;
            if crate::container_tools::TOOLS.contains(&name.as_str()) {
                return Err(format!("{name} is a built-in tool; it cannot be removed."));
            }
            if !parsed.has("yes") {
                return Err(format!("This removes the added tool {name} from this computer (sandboxes keep what was installed). Repeat with --yes only if this is intended."));
            }
            let removed = tools::Added::standard()?.remove(&name)?;
            if !removed {
                return Err(format!("There is no added tool named {}. See yougori tool list.", scan::shown(&name)));
            }
            Ok(reply(json!({"removed": name}), mode(&parsed), |_| views::done(vec![format!("Removed {name} from this computer. Sandboxes keep what was installed.")])))
        }
        "install" | "open" => {
            let parsed = parse(rest, &["format", "environment", "secrets"], &[], usage)?;
            let name = one(&parsed, 0, &format!("Usage: yougori tool {action} NAME --environment ENV"))?;
            let environment = parsed.value("environment").ok_or_else(|| format!("Add --environment ENV: the sandbox to {action} {name} in (see yougori ps)."))?.to_owned();
            let mode = mode(&parsed);
            if action == "open" {
                if !mode.interactive {
                    return Err(format!("yougori tool open needs an interactive terminal. In scripts, install it with yougori tool install {name} --environment ENV."));
                }
                let value = tools::open(&name, &environment).await?;
                return Ok(Reply { value, text: Some(String::new()), code: 0 });
            }
            let key = match parsed.value("secrets") {
                None => None,
                Some("-") => Some(tool_key().await?),
                Some(_) => return Err("The API key is read from stdin only: --secrets - with {\"key\": \"…\"}. Never put a key on the command line.".into()),
            };
            let value = tools::install_added(&name, &environment, mode.interactive, key).await?;
            Ok(reply(value, mode, |v| {
                let mut lines = Vec::new();
                if let (Some(warning), false) = (v["warning"].as_str(), mode.interactive) {
                    lines.push(format!("Note: {warning}"));
                }
                lines.push(format!("{} is installed in {} and its check passed.", v["tool"].as_str().unwrap_or_default(), v["environment"].as_str().unwrap_or_default()));
                lines.extend(v["steps"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| format!("Next: {s}")));
                if let Some(open) = v["open"].as_str() {
                    lines.push(format!("Open it: {open}"));
                }
                views::done(lines)
            }))
        }
        "publish" => {
            let parsed = parse(rest, &["format", "publisher"], &["yes"], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori tool publish [FOLDER] [--yes]".into());
            }
            let folder = parsed.words.first().cloned().unwrap_or_else(|| ".".into());
            let mode = mode(&parsed);
            let value = publish::publish("tool", &folder, parsed.has("yes"), parsed.value("publisher"), mode.interactive).await?;
            Ok(reply(value, mode, published))
        }
        other => Err(format!("Unknown tool command {}.\n{usage}", scan::shown(other))),
    }
}

/// A tool's API key from stdin: `{"key": "…"}`, read on its own thread so Ctrl+C still stops a
/// read that waits on a terminal.
async fn tool_key() -> Result<zeroize::Zeroizing<String>, String> {
    let bytes = run::read_stdin("the key on stdin").await?;
    parse_key(&bytes)
}

fn parse_key(bytes: &[u8]) -> Result<zeroize::Zeroizing<String>, String> {
    let object: BTreeMap<String, Value> = serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)).map_err(|_| "--secrets - reads {\"key\": \"…\"} on stdin.")?;
    match object.into_iter().find(|(name, _)| name == "key").map(|(_, value)| value) {
        Some(Value::String(key)) if !key.is_empty() && key.len() <= 65536 && !key.contains(['\0', '\r', '\n']) => Ok(zeroize::Zeroizing::new(key)),
        _ => Err("--secrets - reads {\"key\": \"…\"} on stdin: one line of text, at most 64 KiB.".into()),
    }
}

/// `template new [NAME]`: a template folder to fill in, valid as it stands.
pub fn new_template(name: Option<&str>) -> Result<Value, String> {
    let name = name.unwrap_or("my-template");
    if !refs::valid_name(name) {
        return Err(format!("{} is not a template name: use {}.", scan::shown(name), refs::NAME_RULE));
    }
    let folder = std::env::current_dir().map_err(|e| e.to_string())?.join(name);
    if folder.exists() {
        return Err(format!("{} already exists. Choose another name or folder.", folder.display()));
    }
    let files = new_files(name);
    format::template(&files).map_err(|problems| problems.join("\n"))?;
    client::write_files(&folder, &files)?;
    Ok(json!({"created": folder, "files": files.keys().collect::<Vec<_>>(), "next": [
        format!("Edit {name}/{} and {name}/yougori.yaml.", format::TEMPLATE_FILE),
        format!("yougori template check {name}"),
        format!("yougori template run ./{name}"),
        format!("yougori template publish {name}"),
    ]}))
}

fn new_files(name: &str) -> scan::Files {
    let template = format!("kind: template\nname: {name}\ntitle: {name}\nsummary: One line about what this sets up.\nversion: 0.1.0\nlicense: MIT\ntopics: [website]\n\nrequires:\n  yougori: {}\n\n# Questions asked when someone runs the template. Use them as {{{{inputs.ID}}}} in yougori.yaml.\ninputs:\n  - id: access\n    question: Where should the website be reachable?\n    type: choice\n    choices:\n      - {{value: quick, label: Quick link, hint: Free HTTPS link from Cloudflare. It can change after a restart.}}\n      - {{value: domain, label: My own domain, hint: A domain you saved with yougori domain add.}}\n      - {{value: none, label: Only this computer}}\n    default: quick\n  - id: domain\n    question: Which saved domain?\n    type: domain\n    when: {{access: domain}}\n\npublic:\n  - environment: web\n    port: 8080\n    access: \"{{{{inputs.access}}}}\"\n    domain: \"{{{{inputs.domain}}}}\"\n\nsteps:\n  - title: Look inside the website's sandbox\n    command: yougori terminal {{{{env.web}}}}\n\noutputs:\n  - label: Website\n    value: \"{{{{public.web}}}}\"\n", env!("CARGO_PKG_VERSION"));
    let project = format!("project: {name}\nenvironments:\n  web:\n    image: python:3.12-slim\n    cpu: 1\n    memory: 1GB\n    storage: 6GB\n    working_dir: /app\n    files:\n      - {{source: ./site, target: /app}}\n    command: [python, -m, http.server, \"8080\"]\n    ports: [\"8080\"]\n    restart: always\n");
    let readme = format!("# {name}\n\nWhat this template sets up, and what someone needs before running it.\n\n```text\nyougori template check .\nyougori template run .\nyougori template publish .\n```\n");
    let page = format!("<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>{name}</title></head>\n<body><h1>{name}</h1><p>Served from a Yougori sandbox.</p></body>\n</html>\n");
    [
        (format::TEMPLATE_FILE.to_owned(), template.into_bytes()),
        ("yougori.yaml".to_owned(), project.into_bytes()),
        ("README.md".to_owned(), readme.into_bytes()),
        ("site/index.html".to_owned(), page.into_bytes()),
    ].into()
}

/// `template download REF [FOLDER]`: a checked copy of a version's files.
async fn download(reference: &refs::Ref, folder: Option<&str>, interactive: bool) -> Result<Value, String> {
    let target = std::env::current_dir().map_err(|e| e.to_string())?.join(folder.unwrap_or(&reference.name));
    if target.exists() && std::fs::read_dir(&target).map(|mut d| d.next().is_some()).unwrap_or(true) {
        return Err(format!("{} already exists and is not empty. Give another folder.", target.display()));
    }
    let site = client::Site::configured()?;
    let got = run::wait(interactive, "Downloading and checking the files", client::obtain(&site, &client::Cache::standard()?, reference)).await?;
    client::write_files(&target, &got.bundle.files)?;
    // A computer counts once per item; never more than five seconds, after the files are saved.
    if got.detail.is_some() {
        if let Ok(id) = client::home().and_then(|home| client::install_id(&home)) {
            let _ = run::wait(interactive, "Telling the Hub", async { Ok(site.count_clone(reference, &got.bundle.version, &id).await) }).await;
        }
    }
    Ok(json!({"downloaded": reference.item(), "version": got.bundle.version, "kind": got.bundle.kind, "verified": got.bundle.verified, "digest": got.bundle.digest, "folder": target, "files": got.bundle.files.len(), "notice": got.notice}))
}

/// `template info REF`: the item, its counts, and its review built from the files here.
async fn info(reference: &refs::Ref) -> Result<Value, String> {
    let site = client::Site::configured()?;
    let cache = client::Cache::standard()?;
    info_at(&site, &cache, reference).await
}

/// [`info`] from `site`, with checked copies kept in `cache`.
async fn info_at(site: &client::Site, cache: &client::Cache, reference: &refs::Ref) -> Result<Value, String> {
    let detail = site.item(reference).await.map_err(String::from)?;
    let mut value = json!({"item": detail, "version": detail["version"]["version"], "notices": detail["version"]["notices"]});
    if let Some(reason) = client::removed(&detail) {
        value["removed"] = json!(reason);
        return Ok(value);
    }
    let version = detail["version"]["version"].as_str().unwrap_or_default().to_owned();
    if detail["kind"] == "tool" {
        let got = client::obtain(site, cache, &reference.at(&version)).await?;
        let tool = format::tool_file(&got.bundle.files, "").map_err(|problems| tools::list(&reference.item(), &problems))?;
        let wallet: Vec<String> = scan::scan(&got.bundle.files).wallet_notice().into_iter().collect();
        // The shared file, not the installer's view: the review then shows what the tool declares.
        value["review"] = review::tool_file(&tool, &wallet);
        value["run"] = json!(format!("yougori tool add hub/{}", reference.item()));
        return Ok(value);
    }
    // Read in the template's own format: the format 1 reader refuses a format 2 template's fields.
    let prepared = match run::read(site, cache, &run::Wanted::Hub(reference.at(&version))).await? {
        run::Read::V1(prepared) => prepared,
        run::Read::V2(fetched) => {
            info_v2(site, cache, &fetched, &mut value).await?;
            value["run"] = json!(format!("yougori run hub/{}", reference.item()));
            return Ok(value);
        }
    };
    value["review"] = prepared.review.clone();
    value["pageDiffers"] = json!(prepared.differs);
    if prepared.differs {
        value["notices"] = json!(["The Hub page's summary differs from the files. This review was built from the files themselves."]);
    }
    value["run"] = json!(format!("yougori run hub/{}", reference.item()));
    Ok(value)
}

/// `template info` of a format 2 template: the review its files produce, written as `template
/// publish` wrote the page's (every format 1 part, plus its resources, capabilities and what each
/// pinned component grants, which are fetched and checked first), and the page check against what
/// the Hub says about that version, by the one rule `template plan` and the engine apply. Nothing
/// is created and no engine is needed.
async fn info_v2(site: &client::Site, cache: &client::Cache, fetched: &run::Fetched, value: &mut Value) -> Result<(), String> {
    let item = match &fetched.origin {
        run::Wanted::Hub(reference) => Some(reference.item()),
        run::Wanted::Folder(_) => None,
    };
    let package = components::package(site, cache, &fetched.files, item, Some(fetched.digest.clone())).await.map_err(|problems| plan::problems_text("This template", &problems))?;
    let wallet: Vec<String> = scan::scan(&fetched.files).wallet_notice().into_iter().collect();
    let review = review::template_v2(&package, &wallet).map_err(|error| format!("This template's review can't be built here: {error}"))?;
    let page = review::page_check(&package, &fetched.files, fetched.detail.as_ref(), &fetched.version);
    value["format"] = json!(2);
    value["review"] = review;
    value["page"] = review::page_json(&page);
    value["pageDiffers"] = json!(matches!(&page, Ok(differences) if !differences.is_empty()));
    // What the page check found joins the Hub's own notices: a page that says something else, or
    // why there was nothing to compare, which must never read as a clean check.
    let said = match &page {
        Ok(differences) if !differences.is_empty() => Some(format!("The Hub page describes this version differently from its files ({}). This review was built from the files themselves.", differences.join(", "))),
        Ok(_) => None,
        Err(why) => Some(why.clone()),
    };
    if let Some(said) = said {
        let mut notices: Vec<Value> = value["notices"].as_array().cloned().unwrap_or_default();
        notices.push(json!(said));
        value["notices"] = json!(notices);
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn several_words_are_a_template_name_only_when_they_name_one() {
        // `yougori run my api` should work: people say names, they do not type identifiers. But
        // only a name Yougori publishes is joined, so a stray word is still the usage error it
        // was, rather than turning two arguments into a reference to something.
        let usage = "Usage: yougori run NAME";
        let parsed = parse(&["my".to_owned(), "api".to_owned()], RUN_VALUES, RUN_SWITCHES, usage).unwrap();
        assert_eq!(source_words(&parsed, usage).unwrap(), "my api");

        let parsed = parse(&["swarm".to_owned(), "mining".to_owned(), "grid".to_owned()], RUN_VALUES, RUN_SWITCHES, usage).unwrap();
        assert_eq!(source_words(&parsed, usage).unwrap(), "swarm mining grid");

        // Two words that name nothing: the usage line, not a guess.
        let parsed = parse(&["./shop".to_owned(), "oops".to_owned()], RUN_VALUES, RUN_SWITCHES, usage).unwrap();
        assert_eq!(source_words(&parsed, usage).unwrap_err(), usage);

        // One word is untouched, whatever it is.
        let parsed = parse(&["hub/acme/x".to_owned()], RUN_VALUES, RUN_SWITCHES, usage).unwrap();
        assert_eq!(source_words(&parsed, usage).unwrap(), "hub/acme/x");
        let parsed = parse(&["my api".to_owned()], RUN_VALUES, RUN_SWITCHES, usage).unwrap();
        assert_eq!(source_words(&parsed, usage).unwrap(), "my api", "the quoted form still works");
    }
    use super::*;

    fn words(text: &str) -> Vec<String> {
        shell_words::split(text).unwrap()
    }

    #[test]
    fn only_hub_commands_are_taken() {
        for command in ["template list", "tool list", "run hub/acme/my-api", "run https://yougori.com/hub/acme/my-api@1.0.0", "template", "tool --help", "run --name shop --yes hub/acme/my-api"] {
            assert!(requested(&words(command)), "{command}");
        }
        for command in ["run nginx", "run -d nginx", "run hf.co/acme/model", "status", "tools", "run hub/nginx", "run --name hub nginx", "run -p 8080:80 nginx hub/acme/x", "run -- hub/acme/x"] {
            assert!(!requested(&words(command)), "{command}");
        }
    }

    #[test]
    fn run_template_is_read_as_template_run() {
        let typed = words("run --name shop template ./examples/hub/my-api --yes");
        assert!(requested(&typed));
        assert_eq!(template_run(&typed), Some(words("template run --name shop ./examples/hub/my-api --yes")));
        assert_eq!(template_run(&words("run template hub/acme/my-api")), Some(words("template run hub/acme/my-api")));
        for command in ["run template", "run template --yes", "run -d template", "run nginx template hub/acme/x", "run -- template hub/acme/x"] {
            assert!(template_run(&words(command)).is_none() && !requested(&words(command)), "{command}");
        }
    }

    #[test]
    fn the_app_console_is_asked_for_by_one_exact_value() {
        assert!(console_requested(Some("1")) && console_requested(Some(" 1 ")));
        for value in [None, Some(""), Some("0"), Some("true"), Some("yes")] {
            assert!(!console_requested(value), "{value:?}");
        }
    }

    #[test]
    fn options_are_read_strictly_and_secrets_never_from_arguments() {
        let parsed = parse(&words("hub/acme/x --name shop --input a=1 --input=b=two words --yes --format json"), RUN_VALUES, RUN_SWITCHES, "usage").unwrap();
        assert_eq!(parsed.words, ["hub/acme/x", "words"]);
        assert_eq!(parsed.value("name"), Some("shop"));
        assert_eq!(parsed.values["input"], ["a=1", "b=two"]);
        assert!(parsed.has("yes"));
        let options = run_options(&parsed, "hub/acme/x".into()).unwrap();
        assert_eq!(options.inputs, [("a".to_owned(), "1".to_owned()), ("b".to_owned(), "two".to_owned())]);
        assert!(parse(&words("x --colour red"), RUN_VALUES, RUN_SWITCHES, "usage").unwrap_err().starts_with("Unknown option --colour"));
        assert!(parse(&words("x --name"), RUN_VALUES, RUN_SWITCHES, "usage").unwrap_err().contains("--name needs a value"));
        assert!(parse(&words("x --format yaml"), RUN_VALUES, RUN_SWITCHES, "usage").is_err());
        let secret = parse(&words("x --secrets sk-live-key"), RUN_VALUES, RUN_SWITCHES, "usage").unwrap();
        assert!(run_options(&secret, "x".into()).unwrap_err().contains("Never put a secret on the command line"));
        let stdin = parse(&words("x --secrets -"), RUN_VALUES, RUN_SWITCHES, "usage").unwrap();
        assert!(run_options(&stdin, "x".into()).unwrap().secrets_stdin);
        let pair = parse(&words("x --input novalue"), RUN_VALUES, RUN_SWITCHES, "usage").unwrap();
        assert!(run_options(&pair, "x".into()).unwrap_err().contains("--input takes ID=VALUE"));
    }

    #[test]
    fn a_new_template_passes_its_own_check() {
        let files = new_files("shop");
        let checked = format::template(&files).unwrap_or_else(|p| panic!("{}", p.join("\n")));
        assert_eq!(checked.template.name(), "shop");
        assert!(scan::scan(&files).refused.is_empty());
        assert!(publish::top_level(std::str::from_utf8(&files[format::TEMPLATE_FILE]).unwrap(), "version").as_deref() == Some("0.1.0"));
    }

    #[test]
    fn ctrl_c_says_what_each_command_left_and_how_to_go_on() {
        let said = |command: &str| stopped_message(&words(command), None);
        assert_eq!(said("run hub/acme/shop --yes"), "Cancelled. Nothing was created.");
        assert_eq!(said("template continue shop --yes"), "Stopped. Nothing was changed.");
        assert_eq!(said("template rm shop --yes"), "Stopped. Part of shop may already be removed; run yougori template rm shop --yes again to finish.");
        assert_eq!(said("template rm --yes shop"), "Stopped. Part of shop may already be removed; run yougori template rm shop --yes again to finish.");
        assert_eq!(said("template publish ./shop --yes"), publish::STOPPED);
        assert_eq!(said("tool publish ./aider --yes"), publish::STOPPED);
        assert!(said("tool install aider --environment web").contains("install aider there"));
        assert_eq!(said("template search shop"), "Stopped. Nothing was changed.");
        let mut shop = instances::State { instance: "shop".into(), ..Default::default() };
        shop.environments.insert("web".into(), "env-1".into());
        let kept = stopped_message(&words("template continue shop"), Some(&shop));
        assert_eq!(kept, "Stopped. The instance folder and its sandbox were kept. Continue: yougori template continue shop · Remove: yougori template rm shop --yes");
    }

    #[test]
    fn a_tool_key_is_one_line_from_stdin() {
        assert_eq!(parse_key(b"{\"key\": \"sk-abc\"}").unwrap().as_str(), "sk-abc");
        assert_eq!(parse_key(b"\xef\xbb\xbf{\"key\": \"sk-abc\"}").unwrap().as_str(), "sk-abc");
        for bad in [&b"{\"key\": \"\"}"[..], b"{\"key\": \"a\\nb\"}", b"{\"token\": \"x\"}", b"sk-abc"] {
            assert!(parse_key(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[tokio::test]
    async fn info_reviews_a_format_2_hub_template_from_its_own_files_and_a_format_1_one_as_before() {
        // PROVES `template info` works for a format 2 Hub template. It read every template with
        // the format 1 reader, which refuses a format 2 template's fields, so it failed for all of
        // them. Now the template's own format decides: format 2 gets the review `template publish`
        // writes, and the page check by the one rule `template plan` uses. The Hub is this test's.
        use crate::hub::client::tests::{bundle_json, serve, Fixture};
        let template = "format_version: 2\nkind: template\nname: shop\nsummary: A shop.\nversion: 1.0.0\nlicense: MIT\nrequires: {yougori: 1.2.0}\ninputs:\n  - {id: title, question: Title?, type: text, group: website_api, default: Hi}\npublic:\n  - {environment: web, port: 8080}\n";
        let project = "format_version: 2\nproject: shop\nenvironments:\n  web:\n    image: nginx:1.27\n    ports: [8080]\n    environment: {TITLE: \"{{inputs.title}}\"}\n";
        let v2: scan::Files = [(format::TEMPLATE_FILE, template), ("yougori.yaml", project)].iter().map(|(path, text)| ((*path).to_owned(), text.as_bytes().to_vec())).collect();
        let checked = plan::check_files(&v2).unwrap_or_else(|problems| panic!("{}", plan::problems_text("the package", &problems)));
        let honest = review::template_v2(&yougori_setup::plan::Package { checked, components: BTreeMap::new(), item: None, digest: None }, &[]).unwrap();
        let info_with = |files: scan::Files, published: Value| async move {
            let fixture = Fixture::default();
            *fixture.detail.lock().unwrap() = json!({"ref": "acme/shop", "kind": "template", "state": "active", "title": "Shop", "summary": "A shop.", "license": "MIT", "latestVersion": "1.0.0", "counts": {}, "version": {"version": "1.0.0", "digest": scan::digest_of(&files), "verified": false, "review": published, "notices": ["Published by acme."]}});
            *fixture.bundle.lock().unwrap() = bundle_json("acme", "shop", "1.0.0", &files);
            let site = client::Site::at(&serve(fixture).await).unwrap();
            let root = tempfile::tempdir().unwrap();
            let cache = client::Cache { root: root.path().to_path_buf() };
            info_at(&site, &cache, &refs::Ref { publisher: "acme".into(), name: "shop".into(), version: None }).await
        };
        let shown = info_with(v2.clone(), honest.clone()).await.unwrap_or_else(|said| panic!("info was refused: {said}"));
        assert_eq!(shown["format"], 2);
        assert_eq!(shown["review"], honest, "the review the page was published with, built again from the files");
        assert_eq!((&shown["page"]["compared"], &shown["page"]["differs"], &shown["pageDiffers"]), (&json!(true), &json!(false), &json!(false)));
        assert_eq!(shown["notices"], json!(["Published by acme."]), "nothing to add when the page agrees");
        assert_eq!(shown["run"], "yougori run hub/acme/shop");
        let text = views::info(&shown);
        assert!(text.contains("Sandboxes (1)") && text.contains("Run it: yougori run hub/acme/shop"), "{text}");

        // A page that promises less than the files: said, and named.
        let mut quiet = honest.clone();
        quiet["public"] = json!([]);
        let shown = info_with(v2.clone(), quiet).await.unwrap();
        assert_eq!(shown["pageDiffers"], true);
        let notices = shown["notices"].to_string();
        assert!(notices.contains("Published by acme.") && notices.contains("describes this version differently from its files"), "{notices}");
        // Nothing to compare is said as such, never as a clean check.
        let shown = info_with(v2, json!({})).await.unwrap();
        assert_eq!((&shown["page"]["compared"], &shown["pageDiffers"]), (&json!(false), &json!(false)));
        assert!(shown["notices"].to_string().contains("published without a review"), "{}", shown["notices"]);

        // A format 1 template is read as it always was.
        let v1 = scan::collect(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/hub/hello-site")).unwrap().files;
        let shown = info_with(v1, json!({})).await.unwrap_or_else(|said| panic!("info of a format 1 template was refused: {said}"));
        assert!(shown.get("format").is_none() && shown.get("page").is_none(), "{shown}");
        assert_eq!(shown["review"]["format"], review::FORMAT);
        assert_eq!(shown["pageDiffers"], false);
    }

    #[test]
    fn a_template_join_says_what_it_joined_or_that_it_joined_nothing() {
        let joined = join_view(&json!({"joined": true, "setup": "Acme Sandbox Grid", "setupId": "setup-j"}));
        assert_eq!(joined, "Joined Acme Sandbox Grid.\nSee it with yougori template status setup-j\n");
        // Never an empty name: the setup's id stands in.
        assert!(join_view(&json!({"joined": true, "setup": "", "setupId": "setup-j"})).starts_with("Joined setup-j."));
        let reviewed = join_view(&json!({"joined": false, "needsConfirmation": true, "passwordNeeded": false, "plan": {"headline": "Create this setup: 1 step.", "steps": [{"title": "Create membership (grid)"}]}}));
        assert!(reviewed.contains("Create membership (grid)") && reviewed.contains("Nothing was joined.") && reviewed.contains("giving the invitation on stdin again") && !reviewed.contains("Joined"), "{reviewed}");
        let said = stopped_message(&words("template join --yes"), None);
        assert!(said.contains("carries on with it") && said.contains("Otherwise nothing was joined"), "{said}");
    }

    #[test]
    fn usage_names_every_command_of_the_spec() {
        for command in ["run", "continue", "status", "list", "update", "down", "rm", "new", "check", "capture", "publish", "download", "info", "search", "fork", "star", "unstar", "report", "delete"] {
            assert!(TEMPLATE_USAGE.contains(command), "{command}");
        }
        for command in ["new", "check", "add", "list", "remove", "install", "open", "publish"] {
            assert!(TOOL_USAGE.contains(&format!("tool {command}")) || TOOL_USAGE.contains(&format!("| {command}")), "{command}");
        }
    }
}
