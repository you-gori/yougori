//! Turning what somebody typed into one command.
//!
//! Nothing here reads a secret. An option that carries one is written down and read afterwards,
//! from a hidden prompt or from stdin, so that parsing stays something a test can run and so
//! that a password can never arrive in an argument, where process listings and shell history
//! keep it.

use super::fault::{Code, Fault};
use super::{find, verbs_of, Verb, NOUNS};
use serde_json::{json, Map, Value};

/// Options that stand alone: giving them a value is a mistake, not a shorthand.
pub const BARE: &[&str] = &[
    "yes",
    "dry-run",
    "explain",
    "full",
    "mine",
    "sso",
    "suggested",
    "ask",
    "never",
    "reveal",
    "off",
    "passwordless",
    "ready-made",
    "help",
];

/// Options whose value is a number.
pub const NUMBERS: &[&str] = &[
    "percent", "idle-after", "cpu", "memory-gb", "disk-gb", "port", "limit", "hours", "budget-minutes", "computers", "tasks", "rounds", "redirect-port", "desks", "after",
];

/// Options whose value is true or false.
pub const FLAGS: &[&str] = &["gpu", "idle-only", "require-two-step"];

/// Options that carry a secret. They are read from stdin with `-`, or asked for without showing,
/// and never taken from an argument.
pub const SECRETS: &[&str] = &["password", "value", "passphrase"];

/// Options that name a file whose contents become the request body.
pub const FILES: &[&str] = &["file"];

/// Options whose value is a list, separated by commas.
pub const LISTS: &[&str] = &["methods", "teams", "workers"];

/// What one option of one verb carries. `--computers` is a count for a team of models and a list
/// of computers for a model plan, so the verb decides rather than the option's name alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Number,
    Flag,
    List,
    /// One `Name: value`, given again for another.
    Header,
    Text,
}

fn kind_of(known: &Verb, name: &str) -> Kind {
    match (known.noun, known.verb, name) {
        ("models", "add", "computers") => Kind::List,
        // A header holds a colon and may hold a comma, so it is never split on either; give the
        // option again for a second header.
        (_, _, "header") => Kind::Header,
        _ if LISTS.contains(&name) => Kind::List,
        _ if NUMBERS.contains(&name) => Kind::Number,
        _ if FLAGS.contains(&name) => Kind::Flag,
        _ => Kind::Text,
    }
}

/// One command, as typed.
#[derive(Clone, Debug, PartialEq)]
pub struct Typed {
    pub noun: &'static str,
    pub verb: &'static str,
    pub grid: Option<String>,
    pub request: Map<String, Value>,
    pub confirmed: bool,
    pub dry_run: bool,
    /// `json`, `text`, or nothing, in which case a terminal gets words and a pipe gets JSON.
    pub format: Option<String>,
    pub explain: bool,
    /// Which request keys still have to be filled in from stdin or a hidden prompt.
    pub secrets: Vec<String>,
    /// Which of those were named with `-`, meaning stdin rather than a prompt.
    pub from_stdin: Vec<String>,
    /// Which request key still has to be read from a file.
    pub file: Option<String>,
}

impl Typed {
    pub fn method(&self) -> &'static str {
        super::method_for(self.noun).unwrap_or("grids_realm")
    }
    pub fn known(&self) -> &'static Verb {
        find(self.noun, self.verb).expect("a typed command always names a verb that exists")
    }
    /// What this is called in the words a person typed.
    pub fn said_as(&self) -> String {
        if self.noun == "realm" {
            format!("grids {}", self.verb)
        } else {
            format!("grids {} {}", self.noun, self.verb)
        }
    }
    /// Whether a secret was named as coming from stdin with `-`, rather than left to a prompt.
    pub fn named_on_stdin(&self, secret: &str) -> bool {
        self.from_stdin.iter().any(|named| named == secret)
    }
    /// The whole request, for the wire.
    pub fn params(&self) -> Value {
        let mut request = self.request.clone();
        request.insert("do".into(), json!(self.verb));
        let mut params = Map::new();
        if let Some(grid) = &self.grid {
            params.insert("grid".into(), json!(grid));
        }
        params.insert("request".into(), Value::Object(request));
        Value::Object(params)
    }
}

/// Which noun and verb a list of words names.
fn pick(words: &[String]) -> Result<(&'static Verb, usize), Fault> {
    // `yougori grids` on its own reads as the plural does: every grid on this computer.
    if words.is_empty() {
        return Ok((find("realm", "list").expect("listing the grids is always a verb"), 0));
    }
    let first = words.first().map(String::as_str).unwrap_or_default();
    let (noun, verb, consumed) = if NOUNS.contains(&first) && first != "realm" {
        let verb = words.get(1).map(String::as_str).unwrap_or_default();
        (first, verb, 2)
    } else {
        ("realm", first, 1)
    };
    if verb.is_empty() {
        let choices: Vec<&str> = verbs_of(noun).iter().map(|known| known.verb).collect();
        return Err(Fault::new(
            Code::MissingWords,
            format!("Say what to do: {}.", super::join_words(&choices)),
        ));
    }
    match find(noun, verb) {
        Some(known) => Ok((known, consumed)),
        None if noun == "realm" => Err(Fault::new(
            Code::UnknownWords,
            format!("There is no such thing as grids {verb}. The nouns are {}.", typed_nouns().join(", ")),
        )),
        None => {
            let choices: Vec<&str> = verbs_of(noun).iter().map(|known| known.verb).collect();
            Err(Fault::new(
                Code::UnknownWords,
                format!("There is no such thing as grids {noun} {verb}. This noun takes {}.", super::join_words(&choices)),
            ))
        }
    }
}

/// Reads `yougori grids …` into one command. `args` starts at the word after `grids`.
pub fn parse(args: &[String]) -> Result<Typed, Fault> {
    let mut words: Vec<String> = Vec::new();
    let mut options: Vec<(String, Option<String>)> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].strip_prefix("--") {
            None => words.push(args[index].clone()),
            Some(flag) => {
                let (name, inline) = flag.split_once('=').map_or((flag, None), |(name, value)| (name, Some(value.to_owned())));
                if name.is_empty() {
                    return Err(Fault::new(Code::UnknownWords, "Write an option as --name value."));
                }
                let value = if BARE.contains(&name) {
                    if inline.is_some() {
                        return Err(Fault::new(Code::ValueUnusable, format!("--{name} stands on its own; it takes no value.")));
                    }
                    None
                } else {
                    match inline.or_else(|| args.get(index + 1).filter(|next| !next.starts_with("--")).cloned()) {
                        Some(value) => {
                            if !flag.contains('=') {
                                index += 1;
                            }
                            Some(value)
                        }
                        None => return Err(Fault::new(Code::MissingWords, format!("--{name} needs a value."))),
                    }
                };
                options.push((name.to_owned(), value));
            }
        }
        index += 1;
    }

    // `--help` is a question, not a command. It is answered before anything else is read, so
    // `yougori grids models --help` works without naming a verb.
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        let noun = words.first().map(String::as_str).filter(|word| NOUNS.contains(word)).unwrap_or("realm");
        return Err(help_fault(noun));
    }
    let (known, consumed) = pick(&words)?;
    let targets = &words[consumed.min(words.len())..];
    if targets.len() > known.targets.len() {
        return Err(Fault::new(
            Code::UnknownWords,
            format!("{} takes {}.", capitalise(&said_as(known)), what_it_takes(known)),
        ));
    }

    let mut typed = Typed {
        noun: known.noun,
        verb: known.verb,
        grid: None,
        request: Map::new(),
        confirmed: false,
        dry_run: false,
        format: None,
        explain: false,
        secrets: Vec::new(),
        from_stdin: Vec::new(),
        file: None,
    };
    for (position, word) in targets.iter().enumerate() {
        typed.request.insert(known.targets[position].to_owned(), json!(word));
    }

    for (name, value) in options {
        match name.as_str() {
            "yes" => typed.confirmed = true,
            "dry-run" => typed.dry_run = true,
            "explain" => typed.explain = true,
            "help" => return Err(help_fault(known.noun)),
            "grid" => typed.grid = value,
            "format" => {
                let value = value.unwrap_or_default();
                if value != "json" && value != "text" {
                    return Err(Fault::new(Code::ValueUnusable, "Ask for --format json or --format text."));
                }
                typed.format = Some(value);
            }
            _ => {
                if !known.options.contains(&name.as_str()) && !known.targets.contains(&name.as_str()) {
                    return Err(Fault::new(
                        Code::UnknownWords,
                        format!("--{name} does not belong to {}. It takes {}.", said_as(known), what_it_takes(known)),
                    ));
                }
                if SECRETS.contains(&name.as_str()) {
                    if value.as_deref().is_some_and(|value| value != "-") {
                        return Err(Fault::new(
                            Code::SecretInArguments,
                            format!("Never type the {name} into the command: leave it out to be asked for it, or use --{name} - to read it from stdin."),
                        ));
                    }
                    typed.secrets.push(name.clone());
                    if value.as_deref() == Some("-") {
                        typed.from_stdin.push(name.clone());
                    }
                    continue;
                }
                if FILES.contains(&name.as_str()) {
                    typed.file = Some(value.unwrap_or_else(|| "-".into()));
                    continue;
                }
                let value = match (value, kind_of(known, &name)) {
                    (None, _) => json!(true),
                    // A whole number stays whole, because a port and a count are written down as
                    // integers and a half of either is not a thing anybody meant.
                    (Some(text), Kind::Number) => match text.parse::<f64>() {
                        Ok(number) if number.is_finite() && number.fract() == 0.0 && number >= 0.0 => json!(number as u64),
                        Ok(number) if number.is_finite() => json!(number),
                        _ => return Err(Fault::new(Code::ValueUnusable, format!("--{name} is a number."))),
                    },
                    (Some(text), Kind::Flag) => match text.as_str() {
                        "true" => json!(true),
                        "false" => json!(false),
                        _ => return Err(Fault::new(Code::ValueUnusable, format!("--{name} is true or false."))),
                    },
                    (Some(text), Kind::List) => Value::Array(text.split(',').map(str::trim).filter(|piece| !piece.is_empty()).map(|piece| json!(piece)).collect()),
                    (Some(text), Kind::Header) => json!([text]),
                    (Some(text), Kind::Text) => json!(text),
                };
                // A request key keeps the option's own spelling, so `--memory-gb` is `memory-gb` here
                // and `alias::product_call` is the one place that knows what each product calls it.
                // An option that carries a list may be given more than once and the values join up.
                match (typed.request.get_mut(&name), kind_of(known, &name)) {
                    (Some(Value::Array(already)), Kind::List | Kind::Header) => {
                        if let Value::Array(more) = value {
                            already.extend(more);
                        }
                    }
                    (Some(_), _) => return Err(Fault::new(Code::UnknownWords, format!("--{name} was given twice."))),
                    (None, _) => {
                        typed.request.insert(name.clone(), value);
                    }
                }
            }
        }
    }
    // A secret that was not named at all is still needed by the verb; the caller asks for it.
    for secret in known.options.iter().filter(|option| SECRETS.contains(option)) {
        if !typed.secrets.iter().any(|named| named == secret) && needs_secret(known, secret) {
            typed.secrets.push((*secret).to_owned());
        }
    }
    Ok(typed)
}

/// Whether this verb cannot run without that secret.
fn needs_secret(known: &Verb, secret: &str) -> bool {
    matches!(
        (known.noun, known.verb, secret),
        ("realm", "new", "password")
            | ("realm", "password", "password")
            | ("realm", "backup", "passphrase")
            | ("realm", "restore-backup", "passphrase")
            | ("people", "add", "password")
            | ("people", "password", "password")
            | ("credentials", "add", "value")
            | ("credentials", "rotate", "value")
    )
}

fn said_as(known: &Verb) -> String {
    if known.noun == "realm" {
        format!("grids {}", known.verb)
    } else {
        format!("grids {} {}", known.noun, known.verb)
    }
}

fn capitalise(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
        None => String::new(),
    }
}

fn what_it_takes(known: &Verb) -> String {
    let targets: Vec<String> = known.targets.iter().map(|target| target.to_uppercase()).collect();
    let options: Vec<String> = known.options.iter().map(|option| format!("--{option}")).collect();
    match (targets.is_empty(), options.is_empty()) {
        (true, true) => "no words and no options".to_owned(),
        (false, true) => format!("{}, and no options", targets.join(" ")),
        (true, false) => options.join(", "),
        (false, false) => format!("{} and {}", targets.join(" "), options.join(", ")),
    }
}

/// `--help` on a noun is not a failure, but it travels the same way a refusal does so that one
/// path prints it. The caller recognises this code and prints the help without an error.
pub fn help_fault(noun: &str) -> Fault {
    Fault::new(Code::MissingWords, help(noun)).about("help")
}

/// The nouns a person types. `realm` is only the internal name for the verbs typed without a
/// noun, and `pick` refuses it, so it is never offered as a word to type.
fn typed_nouns() -> Vec<&'static str> {
    NOUNS.iter().filter(|name| **name != "realm").copied().collect()
}

/// The help for one noun, built from the one table, so it cannot drift from what parses.
pub fn help(noun: &str) -> String {
    let mut lines = Vec::new();
    if noun == "realm" {
        lines.push("Usage: yougori grids VERB [TARGET] [--grid NAME]".to_owned());
        lines.push("       yougori grids NOUN VERB [TARGET] [--grid NAME]".to_owned());
        lines.push(String::new());
        lines.push(format!("Nouns: {}", typed_nouns().join(", ")));
        lines.push(String::new());
    } else {
        lines.push(format!("Usage: yougori grids {noun} VERB [TARGET] [--grid NAME]"));
        lines.push(String::new());
    }
    // Plain lines in two columns, lined up by spaces. No box, no border, no glyph.
    let spelled: Vec<(String, &str)> = verbs_of(noun)
        .iter()
        .map(|known| {
            let words = if noun == "realm" { format!("grids {}", known.verb) } else { format!("grids {noun} {}", known.verb) };
            let targets: String = known.targets.iter().map(|target| format!(" {}", target.to_uppercase())).collect();
            (format!("  yougori {words}{targets}"), known.says)
        })
        .collect();
    let widest = spelled.iter().map(|(left, _)| left.chars().count()).max().unwrap_or(0);
    for (left, says) in spelled {
        let padding = " ".repeat(widest + 2 - left.chars().count());
        lines.push(format!("{left}{padding}{says}"));
    }
    lines.push(String::new());
    lines.push("Every command takes --format json or --format text, and every change takes --dry-run.".to_owned());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(words: &[&str]) -> Result<Typed, Fault> {
        parse(&words.iter().map(|word| (*word).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn a_noun_and_a_verb_become_one_request() {
        let typed = read(&["models", "add", "--model", "hf.co/Qwen/Qwen3-8B", "--percent", "50"]).unwrap();
        assert_eq!((typed.noun, typed.verb), ("models", "add"));
        assert_eq!(typed.method(), "grids_models");
        assert_eq!(typed.params(), json!({"request":{"do":"add","model":"hf.co/Qwen/Qwen3-8B","percent":50}}));
        assert_eq!(typed.said_as(), "grids models add");
    }

    #[test]
    fn a_realm_verb_is_typed_without_its_noun() {
        let typed = read(&["status", "--grid", "acme"]).unwrap();
        assert_eq!((typed.noun, typed.verb), ("realm", "status"));
        assert_eq!(typed.grid.as_deref(), Some("acme"));
        assert_eq!(typed.said_as(), "grids status");
        assert_eq!(read(&["list"]).unwrap().verb, "list");
    }

    #[test]
    fn a_password_is_never_read_from_an_argument() {
        let refused = read(&["new", "Acme", "--ip", "10.0.0.5", "--password", "hunter2"]).unwrap_err();
        assert_eq!(refused.code, Code::SecretInArguments);
        assert!(refused.said.starts_with("Never type the password into the command"));
        let stdin = read(&["new", "Acme", "--ip", "10.0.0.5", "--password", "-"]).unwrap();
        assert_eq!(stdin.secrets, vec!["password".to_owned()]);
        assert!(!stdin.request.contains_key("password"), "nothing of the secret is in the request yet");
        // Left out altogether, it is still needed, and the caller asks for it.
        assert_eq!(read(&["new", "Acme", "--ip", "10.0.0.5"]).unwrap().secrets, vec!["password".to_owned()]);
    }

    #[test]
    fn unknown_words_are_refused_in_a_sentence() {
        for words in [vec!["models", "invent"], vec!["invent"], vec!["models", "add", "one", "two"]] {
            let refused = read(&words).unwrap_err();
            assert!(matches!(refused.code, Code::UnknownWords), "{words:?} gave {:?}", refused.code);
            assert!(refused.said.ends_with('.'), "{}", refused.said);
            assert!(!refused.said.contains('_'), "{}", refused.said);
        }
        assert_eq!(read(&["models"]).unwrap_err().code, Code::MissingWords);
        assert_eq!(read(&["models", "add", "--nonsense", "x"]).unwrap_err().code, Code::UnknownWords);
    }

    #[test]
    fn numbers_lists_and_plain_flags_are_read_as_what_they_are() {
        let typed = read(&["models", "add-team", "--team", "research", "--lead", "hf.co/a/b", "--workers", "hf.co/c/d,hf.co/e/f", "--computers", "5"]).unwrap();
        assert_eq!(typed.request["workers"], json!(["hf.co/c/d", "hf.co/e/f"]));
        assert_eq!(typed.request["computers"], json!(5));
        let share = read(&["share", "set", "DESKTOP-ABC", "--gpu", "true", "--suggested"]).unwrap();
        assert_eq!(share.request["computer"], json!("DESKTOP-ABC"));
        assert_eq!(share.request["gpu"], json!(true));
        assert_eq!(share.request["suggested"], json!(true));
        assert_eq!(read(&["models", "add", "--percent", "half"]).unwrap_err().code, Code::ValueUnusable);
        assert_eq!(read(&["share", "set", "A", "--gpu", "maybe"]).unwrap_err().code, Code::ValueUnusable);
        assert_eq!(read(&["status", "--full=yes"]).unwrap_err().code, Code::ValueUnusable);
    }

    #[test]
    fn the_plural_on_its_own_lists_every_grid() {
        let typed = read(&[]).unwrap();
        assert_eq!((typed.noun, typed.verb), ("realm", "list"));
        assert_eq!(typed.params(), json!({"request":{"do":"list"}}));
    }

    #[test]
    fn the_help_of_a_noun_is_built_from_the_one_table() {
        let text = help("models");
        for known in verbs_of("models") {
            assert!(text.contains(&format!("grids models {}", known.verb)), "{} is missing", known.verb);
        }
        assert!(help("realm").contains("Nouns: people, computers"));
        assert_eq!(read(&["models", "--help"]).unwrap_err().about.as_deref(), Some("help"));
    }

    /// A refusal that names `realm` would send somebody to type `yougori grids realm list`,
    /// which `pick` refuses, so the refusal and the help offer the same words.
    #[test]
    fn a_refusal_never_offers_a_noun_that_cannot_be_typed() {
        let said = read(&["invent"]).unwrap_err().said;
        assert!(said.contains("The nouns are people, computers"), "{said}");
        assert!(!said.contains("realm"), "{said}");
        for noun in NOUNS.iter().filter(|name| **name != "realm") {
            assert!(said.contains(*noun), "{noun} is not offered: {said}");
        }
        assert_eq!(read(&["realm", "list"]).unwrap_err().code, Code::UnknownWords);
    }
}
