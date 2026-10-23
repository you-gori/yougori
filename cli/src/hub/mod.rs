//! The Yougori Hub from the command line: templates (whole setups as a folder), tools, and
//! running and publishing them through yougori.com. The contract is docs/hub.md: section 5 for
//! the commands, section 6 for the website's answers and section 7 for the review.
pub mod capture;
pub mod client;
pub mod format;
pub mod instances;
pub mod lifecycle;
pub mod pattern;
pub mod publish;
pub mod refs;
pub mod render;
pub mod review;
pub mod run;
pub mod scan;
pub mod tools;
pub mod unicode;
mod unicode_data;
pub mod views;

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const TEMPLATE_USAGE: &str = "Yougori Hub templates: whole setups, shared on yougori.com/hub

  yougori run hub/PUBLISHER/NAME[@VERSION] [--name INSTANCE] [--input ID=VALUE]... [--inputs FILE]
                                           [--secrets -] [--yes] [--allow-pc-access] [--dry-run]
  yougori template run hub/PUBLISHER/NAME[@VERSION] | ./FOLDER   (same options)
  yougori template continue INSTANCE [--yes] [--input ID=VALUE]... [--inputs FILE] [--secrets -]
                                     [--allow-pc-access]
  yougori template status [INSTANCE] | list | down INSTANCE
  yougori template update INSTANCE [--yes] [--allow-pc-access] [--input ID=VALUE]... [--secrets -]
  yougori template rm INSTANCE --yes [--delete-data]
  yougori template new [NAME] | check [FOLDER] | capture ENV... [--output FOLDER]
  yougori template publish [FOLDER] [--yes] [--publisher NAME]
  yougori template download REF [FOLDER] | info REF
  yougori template search [WORDS] [--sort popular|trending|stars|new|updated] [--kind template|tool] [--page N]
  yougori template fork REF [--name NAME] | star REF | unstar REF
  yougori template report REF --reason harmful|stolen|abuse|other [--details TEXT]
  yougori template delete REF --yes

Nothing on the Hub is checked by Yougori unless it shows Verified. A run downloads the files,
checks every SHA-256 and the version digest, checks this computer, and shows a review built from
the files before anything is created. A run that stopped (Ctrl+C, a closed window, a failure)
carries on with template continue INSTANCE, with the same files and answers. In a terminal each
question offers Back and Ctrl+C stops; scripts pass --yes, --input/--inputs and --secrets - (JSON
on stdin; secrets never go on the command line or in --inputs). Text in a terminal, JSON when
piped or with --format json.";

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

/// A Hub command's answer: JSON for scripts, text for people (empty when the screen already
/// shows it), and the exit code.
pub struct Reply {
    pub value: Value,
    pub text: Option<String>,
    pub code: i32,
}

/// The commands this module answers: `template …`, `tool …` and `run hub/…`, where the first
/// word of `run` that is not an option (or an option's value) is a Hub address.
pub fn requested(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("template" | "tool") => true,
        Some("run") => {
            let mut words = args[1..].iter();
            while let Some(word) = words.next() {
                if word == "--" {
                    return false;
                }
                if word.starts_with('-') {
                    if RUN_VALUES.iter().any(|name| word == &format!("--{name}")) {
                        words.next();
                    }
                    continue;
                }
                return refs::looks_like_ref(word, &client::website());
            }
            false
        }
        _ => false,
    }
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
    Ok(run::Options {
        source,
        name: parsed.value("name").map(str::to_owned),
        inputs,
        inputs_file: parsed.value("inputs").map(str::to_owned),
        secrets_stdin: secrets,
        yes: parsed.has("yes"),
        allow_pc_access: parsed.has("allow-pc-access"),
        dry_run: parsed.has("dry-run"),
    })
}

const RUN_VALUES: &[&str] = &["name", "input", "inputs", "secrets", "format"];
const RUN_SWITCHES: &[&str] = &["yes", "allow-pc-access", "dry-run", "help"];

/// The end of a run or an update, as the mode wants it. An interactive run already showed it.
fn instance_reply(value: Value, mode: Mode) -> Reply {
    let text = mode.text.then(|| if mode.interactive { String::new() } else { views::instance(&value) });
    Reply { value, text, code: 0 }
}

/// One word after the command, or the usage.
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
        ["tool", "install" | "open", ..] => format!("Stopped. The sandbox keeps running; run the same command again to install {} there.", named(2)),
        ["tool", "add", ..] => "Stopped. Nothing was added.".to_owned(),
        _ => "Stopped. Nothing was changed.".to_owned(),
    }
}

/// Runs a `template`, `tool` or `run hub/…` command.
pub async fn run(args: &[String]) -> Result<Reply, String> {
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
            let source = one(&parsed, 0, "Usage: yougori run hub/PUBLISHER/NAME[@VERSION] [--name INSTANCE] [--yes]")?;
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
        Some("tool") => {
            if help || args.len() == 1 {
                return Ok(Reply { value: json!({"usage": TOOL_USAGE}), text: Some(format!("{TOOL_USAGE}\n")), code: 0 });
            }
            tool(&args[1], &args[2..]).await
        }
        _ => Err(TEMPLATE_USAGE.into()),
    }
}

async fn template(action: &str, rest: &[String]) -> Result<Reply, String> {
    let usage = TEMPLATE_USAGE;
    match action {
        "run" => {
            let parsed = parse(rest, RUN_VALUES, RUN_SWITCHES, usage)?;
            let source = one(&parsed, 0, "Usage: yougori template run hub/PUBLISHER/NAME[@VERSION] | ./FOLDER [--name INSTANCE] [--yes]")?;
            let mode = mode(&parsed);
            let value = run::run(run_options(&parsed, source)?, mode.interactive).await?;
            Ok(instance_reply(value, mode))
        }
        "continue" => {
            let parsed = parse(rest, &["format", "input", "inputs", "secrets"], &["yes", "allow-pc-access"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template continue INSTANCE [--yes]")?;
            let mode = mode(&parsed);
            let value = run::continue_instance(&name, run_options(&parsed, String::new())?, mode.interactive, true).await?;
            Ok(instance_reply(value, mode))
        }
        "status" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template status [INSTANCE]".into());
            }
            let mode = mode(&parsed);
            let value = lifecycle::status(parsed.words.first().map(String::as_str), mode.interactive).await?;
            Ok(reply(value, mode, |v| if v["instances"].is_array() { views::list(v) } else { views::instance(v) }))
        }
        "list" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if !parsed.words.is_empty() {
                return Err("Usage: yougori template list".into());
            }
            Ok(reply(lifecycle::list()?, mode(&parsed), views::list))
        }
        "update" => {
            let parsed = parse(rest, &["format", "input", "inputs", "secrets"], &["yes", "allow-pc-access"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template update INSTANCE [--yes]")?;
            let mode = mode(&parsed);
            let value = lifecycle::update(&name, run_options(&parsed, String::new())?, mode.interactive).await?;
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
            let value = lifecycle::down(&name, mode.interactive).await?;
            Ok(reply(value, mode, |v| views::done(vec![format!("{} stopped. Its sandboxes, files and data are kept.", v["instance"].as_str().unwrap_or_default()), format!("Start it again: {}", v["start"].as_str().unwrap_or_default())])))
        }
        "rm" => {
            let parsed = parse(rest, &["format"], &["yes", "delete-data"], usage)?;
            let name = one(&parsed, 0, "Usage: yougori template rm INSTANCE --yes [--delete-data]")?;
            let mode = mode(&parsed);
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
                views::done(lines)
            }))
        }
        "new" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template new [NAME]".into());
            }
            let value = new_template(parsed.words.first().map(String::as_str))?;
            Ok(reply(value, mode(&parsed), |v| views::done(std::iter::once(format!("Created {}", v["created"].as_str().unwrap_or_default())).chain(v["next"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| format!("Next: {s}"))).collect())))
        }
        "check" => {
            let parsed = parse(rest, &["format"], &[], usage)?;
            if parsed.words.len() > 1 {
                return Err("Usage: yougori template check [FOLDER]".into());
            }
            let folder = parsed.words.first().cloned().unwrap_or_else(|| ".".into());
            let (upload, _) = publish::template(std::path::Path::new(&folder))?;
            let bytes: usize = upload.files.values().map(Vec::len).sum();
            let value = json!({"ok": true, "name": upload.name, "version": upload.version, "files": upload.files.len(), "bytes": bytes, "review": upload.review, "next": format!("yougori template run {}", shell_words::quote(&folder))});
            Ok(reply(value, mode(&parsed), views::checked))
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
        other => Err(format!("Unknown template command {}.\n{usage}", scan::shown(other))),
    }
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
    let detail = site.item(reference).await.map_err(String::from)?;
    let mut value = json!({"item": detail, "version": detail["version"]["version"], "notices": detail["version"]["notices"]});
    if let Some(reason) = client::removed(&detail) {
        value["removed"] = json!(reason);
        return Ok(value);
    }
    let version = detail["version"]["version"].as_str().unwrap_or_default().to_owned();
    let cache = client::Cache::standard()?;
    if detail["kind"] == "tool" {
        let got = client::obtain(&site, &cache, &reference.at(&version)).await?;
        let tool = format::tool(&got.bundle.files, "").map_err(|problems| tools::list(&reference.item(), &problems))?;
        let wallet: Vec<String> = scan::scan(&got.bundle.files).wallet_notice().into_iter().collect();
        value["review"] = review::tool(&tool, &wallet);
        value["run"] = json!(format!("yougori tool add hub/{}", reference.item()));
        return Ok(value);
    }
    let prepared = run::prepare(&site, &cache, &run::Wanted::Hub(reference.at(&version))).await?;
    value["review"] = prepared.review.clone();
    value["pageDiffers"] = json!(prepared.differs);
    if prepared.differs {
        value["notices"] = json!(["The Hub page's summary differs from the files. This review was built from the files themselves."]);
    }
    value["run"] = json!(format!("yougori run hub/{}", reference.item()));
    Ok(value)
}

#[cfg(test)]
mod tests {
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
