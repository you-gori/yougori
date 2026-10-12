//! `yougori help` and the agent guide (skills/yougori/references/cli.txt) must name
//! every command the CLI accepts. Advanced routes are found by asking `parse` itself,
//! so a new route fails these tests until both documents describe it.
use crate::{bounty, container_tools, execution, logs, parse, public, security, terminal, GUIDE};
use std::collections::BTreeSet;

/// The word choices at each position of one command, such as `[{env}, {start, stop}]`.
type Command<'a> = Vec<BTreeSet<&'a str>>;

/// Groups that only alias another group.
const ALIASES: &[(&str, &str)] = &[("environment", "env")];

/// Top-level commands main.rs dispatches before `public::handle` and `parse`.
const MAIN_COMMANDS: &[&str] = &[
    "cli", "launch", "status", "top", "doctor", "update", "uninstall", "login", "logout", "account",
    "connect", "confidential", "vault", "bounty", "schema", "skills", "terminal", "download", "agent",
    "app", "help", "monitor", "audit", "lockdown", "unlock",
];

/// Subcommands parsed outside `parse` (main.rs, public.rs and their helpers). Add new ones here.
const PUBLIC_SUBCOMMANDS: &[&[&str]] = &[
    &["start", "bounty"],
    &["app", "start"], &["app", "show"], &["app", "autostart"],
    &["agent", "discover"], &["agent", "inventory"],
    &["skills", "print"], &["skills", "status"], &["skills", "install"],
    &["download", "on"],
    &["vm", "run"], &["machine", "run"], &["microvm", "run"],
    &["deployment", "status"], &["deployment", "secret", "set"], &["deployment", "secret", "delete"],
    &["image", "rm"], &["image", "prune"],
    &["volume", "ls"], &["volume", "inspect"], &["volume", "rm"], &["volume", "prune"], &["volume", "cp"],
    &["prefs", "path"], &["prefs", "show"], &["prefs", "remember"], &["prefs", "forget"],
    &["model", "run"], &["model", "chat"], &["model", "stop"], &["model", "unshare"], &["model", "status"],
    &["model", "api"], &["model", "usage"], &["model", "access"], &["model", "history"],
    &["model", "optimize"], &["model", "support"], &["model", "decide"], &["model", "preflight"],
    &["model", "auth", "login"], &["model", "auth", "status"], &["model", "auth", "logout"],
    &["model", "library"], &["model", "publish"], &["model", "upload"], &["model", "download"],
    &["model", "connect"], &["model", "permissions"], &["model", "versions"],
    &["vault", "mcp"], &["vault", "identity"], &["vault", "status"], &["vault", "open"],
    &["vault", "approve"], &["vault", "add"], &["vault", "help"],
];

/// `yougori bounty ACTION`, documented by `yougori bounty --help`. Add new actions here.
const BOUNTY_ACTIONS: &[&str] = &[
    "workers", "bounties", "apply", "status", "offers", "details", "accept", "skip", "chat", "messages",
    "submit", "leave", "pause", "resume", "stop", "delete", "reports", "rewards", "doctor", "practice",
    "memory",
];

/// Public commands whose parsers name their options in a usage message.
const USAGES: &[(&str, &str)] = &[
    ("exec", execution::USAGE), ("logs", logs::USAGE), ("terminal", terminal::USAGE),
    ("monitor", security::MONITOR_USAGE), ("audit", security::AUDIT_USAGE),
    ("lockdown", security::LOCKDOWN_USAGE), ("unlock", security::UNLOCK_USAGE),
];

fn is_word(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_lowercase())
        && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Reads a synopsis such as `cloud scan HOST [--port 22] | test|add --file F` as the
/// commands `[{cloud}, {scan}]` and `[{cloud}, {test, add}]`. Placeholders, options,
/// option values and bracketed parts are not command words. A clause after ` | `
/// replaces the last word, or the whole command when it repeats the first word
/// (`storage location | storage reclaim`).
fn commands(synopsis: &str) -> Vec<Command<'_>> {
    // Commands may follow a pipe or a prompt: `printf … | yougori model chat ENV`.
    let synopsis = synopsis.find("yougori ").map_or(synopsis, |start| &synopsis[start + "yougori ".len()..]);
    let mut clauses = vec![Command::new()];
    let (mut depth, mut option) = (0usize, false);
    for token in synopsis.split_whitespace() {
        if token == "|" && depth == 0 {
            clauses.push(Command::new());
            option = false;
            continue;
        }
        // The previous option takes this token as its value: `--action inspect|start|stop`.
        let value = std::mem::take(&mut option) && !token.starts_with(['-', '[']);
        let pieces: Vec<&str> = token.split('|').collect();
        let (mut choices, mut leading) = (BTreeSet::new(), false);
        for (index, piece) in pieces.iter().enumerate() {
            let outside = depth == 0 && !piece.starts_with('[');
            depth = (depth + piece.matches('[').count()).saturating_sub(piece.matches(']').count());
            if !outside || value {
                continue;
            }
            if piece.starts_with('-') {
                option = index + 1 == pieces.len() && !token.ends_with(']');
            } else if is_word(piece) {
                leading |= index == 0;
                choices.insert(*piece);
            }
        }
        let clause = clauses.last_mut().unwrap();
        if !leading && !clause.is_empty() {
            // `app start [--engine]|status|show`: words after a bracket are alternatives of the previous word.
            clause.last_mut().unwrap().extend(choices);
        } else if !choices.is_empty() {
            clause.push(choices);
        }
    }
    let mut clauses = clauses.into_iter().filter(|clause| !clause.is_empty());
    let Some(first) = clauses.next() else { return Vec::new() };
    let mut commands = vec![first.clone()];
    for clause in clauses {
        let kept = if clause[0].iter().any(|word| first[0].contains(word)) { 0 } else { first.len() - 1 };
        commands.push(first[..kept].iter().cloned().chain(clause).collect());
    }
    commands
}

/// Help synopses: lines indented by exactly two spaces, up to the two spaces before
/// their description.
fn help_synopses(help: &str) -> Vec<&str> {
    help.lines()
        .filter_map(|line| line.strip_prefix("  ").filter(|line| !line.starts_with(' ')))
        .map(|line| line.split("  ").next().unwrap_or(line))
        .collect()
}

/// Guide synopses: lines of ```text blocks without their `# comments`, and inline code.
fn guide_synopses(guide: &str) -> Vec<&str> {
    let mut fence = None;
    let mut synopses = Vec::new();
    for line in guide.lines() {
        if let Some(language) = line.trim_start().strip_prefix("```") {
            fence = if fence.is_some() { None } else { Some(language) };
        } else if fence == Some("text") {
            synopses.push(line.split(" #").next().unwrap_or(line));
        } else if fence.is_none() {
            synopses.extend(line.split('`').skip(1).step_by(2));
        }
    }
    synopses
}

fn all_commands<'a>(synopses: &[&'a str]) -> Vec<Command<'a>> {
    synopses.iter().flat_map(|synopsis| commands(synopsis)).collect()
}

/// Whether a command starts with these words, such as `["env", "start"]`.
fn documents(commands: &[Command], path: &[&str]) -> bool {
    commands.iter().any(|command| {
        command.len() >= path.len() && path.iter().zip(command).all(|(word, choices)| choices.contains(word))
    })
}

/// Every `GROUP ACTION` that `parse` accepts. Route patterns are quoted words in
/// parse.rs, so every pair of those words is tried; only pairs without a route are
/// refused with "Unknown command". `call METHOD` takes any method and is checked alone.
fn parser_routes() -> BTreeSet<(&'static str, &'static str)> {
    let words: BTreeSet<&str> = include_str!("parse.rs").split('"').filter(|text| is_word(text)).collect();
    let mut routes = BTreeSet::new();
    for &group in words.iter().filter(|group| **group != "call") {
        for &action in &words {
            let refused = parse::parse(&[group.to_owned(), action.to_owned()], |_| Err("No input".into()))
                .is_err_and(|error| error.starts_with("Unknown command"));
            if !refused {
                let group = ALIASES.iter().find(|(alias, _)| *alias == group).map_or(group, |(_, name)| *name);
                routes.insert((group, action));
            }
        }
    }
    routes
}

/// Each path that a source does not document, as "`env start` is missing from NAME".
fn missing<'a>(paths: impl IntoIterator<Item = Vec<&'a str>>, sources: &[(&str, &[Command])]) -> Vec<String> {
    paths.into_iter().flat_map(|path| {
        sources.iter()
            .filter(|(_, commands)| !documents(commands, &path))
            .map(|(name, _)| format!("`{}` is missing from {name}", path.join(" ")))
            .collect::<Vec<_>>()
    }).collect()
}

/// Option names such as `--limit` in a synopsis or usage message.
fn options(synopsis: &str) -> impl Iterator<Item = &str> {
    synopsis.split(|c: char| c.is_whitespace() || "[]|=".contains(c)).filter(|word| word.len() > 2 && word.starts_with("--"))
}

#[test]
fn every_parser_route_is_in_the_advanced_help_and_the_guide() {
    let routes = parser_routes();
    assert!(routes.len() > 100, "Found only {} parser routes", routes.len());
    assert!(routes.contains(&("env", "recover-report")) && !routes.contains(&("environment", "list")));
    let help = all_commands(&help_synopses(parse::HELP));
    let guide = all_commands(&guide_synopses(GUIDE));
    let sources = [("the advanced list of yougori help (parse::HELP)", &help[..]), ("cli.txt", &guide[..])];
    let mut gaps = missing(routes.iter().map(|(group, action)| vec![*group, *action]), &sources);
    gaps.extend(missing([vec!["call"]], &sources));
    assert!(gaps.is_empty(), "Document these commands:\n{}", gaps.join("\n"));
}

#[test]
fn every_public_command_is_in_the_help_and_the_guide() {
    let text = format!("{}\n{}", public::HELP, parse::HELP);
    let help = all_commands(&help_synopses(&text));
    let guide = all_commands(&guide_synopses(GUIDE));
    let words = public::COMMANDS.iter().chain(container_tools::TOOLS).chain(MAIN_COMMANDS).map(|word| vec![*word]);
    let mut gaps = missing(
        words.chain(PUBLIC_SUBCOMMANDS.iter().map(|path| path.to_vec())),
        &[("yougori help", &help[..]), ("cli.txt", &guide[..])],
    );
    let bounty = all_commands(&help_synopses(bounty::HELP));
    gaps.extend(missing(
        BOUNTY_ACTIONS.iter().map(|action| vec!["bounty", *action]),
        &[("yougori bounty --help", &bounty[..]), ("cli.txt", &guide[..])],
    ));
    assert!(gaps.is_empty(), "Document these commands:\n{}", gaps.join("\n"));
}

#[test]
fn every_option_in_a_usage_message_is_in_the_help_and_the_guide() {
    let text = format!("{}\n{}", public::HELP, parse::HELP);
    let mut gaps = Vec::new();
    for &(command, usage) in USAGES {
        assert!(options(usage).next().is_some(), "{usage}");
        for (name, synopses) in [("yougori help", help_synopses(&text)), ("cli.txt", guide_synopses(GUIDE))] {
            let documented: BTreeSet<&str> = synopses.into_iter()
                .filter(|synopsis| documents(&commands(synopsis), &[command]))
                .flat_map(options)
                .collect();
            gaps.extend(options(usage).filter(|option| !documented.contains(option)).map(|option| format!("`{command} {option}` is missing from {name}")));
        }
    }
    assert!(gaps.is_empty(), "Document these options:\n{}", gaps.join("\n"));
}

#[test]
fn synopses_name_commands_but_not_placeholders_options_or_values() {
    let read = |synopsis: &str| commands(synopsis).into_iter().map(|command| {
        command.into_iter().map(|choices| choices.into_iter().collect::<Vec<_>>().join("|")).collect::<Vec<_>>().join(" ")
    }).collect::<Vec<_>>();
    assert_eq!(read("cloud scan HOST [--port 22] | test|add --file request.json --yes | connect ENV"), ["cloud scan", "cloud add|test", "cloud connect"]);
    assert_eq!(read("cloud deploy --file F --risk-acknowledged true | power ENV --action inspect|start|stop"), ["cloud deploy", "cloud power"]);
    assert_eq!(read("app start [--engine]|status|show|quit"), ["app quit|show|start|status"]);
    assert_eq!(read("skills print [--topic TOPIC|--all]|status|install [--path DIR]"), ["skills install|print|status"]);
    assert_eq!(read("app startup-report | autostart on [--dashboard]|off"), ["app startup-report", "app autostart off|on"]);
    assert_eq!(read("storage location [--set PATH --yes] | storage reclaim --yes"), ["storage location", "storage reclaim"]);
    assert_eq!(read("yougori model auth login | status | logout"), ["model auth login", "model auth status", "model auth logout"]);
    assert_eq!(read("printf '%s\\n' hi | yougori login | logout"), ["login", "logout"]);
    assert!(documents(&commands("yougori volume ls [--scan] | rm NAME --yes"), &["volume", "rm"]));
    assert!(!documents(&commands("yougori volume ls [--scan] | rm NAME --yes"), &["rm"]));
}
