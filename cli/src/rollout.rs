//! `yougori rollout …`: moving this computer's grids onto Grid Core, one stage at a time.
//!
//! It is a separate word from `yougori grids …` because it is about this computer's own
//! deployment rather than about one grid: no grid is looked up, nothing a grid holds is changed,
//! and every file it writes is in the operations folder beside the products' own.
//!
//! Nothing here reaches a network, nothing is uploaded and nothing is sent to the vendor. A
//! survey is a file on this computer and sending it, if the administrator chooses to, is their
//! own act over whatever channel they already use.
use crate::{client, public::call};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

pub const USAGE: &str = "Usage: yougori rollout status
       yougori rollout survey
       yougori rollout rehearse
       yougori rollout backup [--keep-for-days 90] [--stage NAME]
       yougori rollout verify --stamp STAMP
       yougori rollout restore --product neo|sandbox|swarm|access --stamp STAMP
       yougori rollout observe
       yougori rollout coverage --profile models|workspaces|research|credentials
       yougori rollout read --product neo|sandbox|swarm|access [--stamp STAMP]
       yougori rollout advance --profile PROFILE --yes | back --profile PROFILE --yes
       yougori rollout retire --profile PROFILE [--keep-for-days 90] --yes
       yougori rollout unretire --stamp STAMP --yes
       yougori rollout forget --stamp STAMP [--force] --yes

Every verb is local and reversible except forget, which deletes a retired record and refuses
until its retention has run out. Nothing is uploaded anywhere.";

/// The verbs, in the order the runbook uses them. Each one is a word somebody types.
pub const VERBS: &[&str] = &[
    "status", "survey", "rehearse", "backup", "verify", "restore", "observe", "coverage", "read", "advance", "back", "retire", "unretire", "forget",
];

/// Verbs that change something and are therefore confirmed before they run.
const CONFIRMED: &[&str] = &["advance", "back", "retire", "unretire", "forget"];

pub fn requested(args: &[String]) -> bool {
    args.first().is_some_and(|word| word == "rollout")
}

/// What one typed command becomes on the wire.
pub fn plan(args: &[String]) -> Result<Value, String> {
    let verb = args.get(1).map(String::as_str).unwrap_or_default();
    if verb.is_empty() || verb == "--help" || verb == "-h" {
        return Err(USAGE.to_owned());
    }
    if !VERBS.contains(&verb) {
        return Err(format!("A rollout cannot be asked to '{verb}'.\n{USAGE}"));
    }
    let mut request = Map::new();
    request.insert("do".into(), json!(verb));
    let mut index = 2;
    let mut yes = false;
    while index < args.len() {
        let word = args[index].as_str();
        let mut value = |name: &str| -> Result<String, String> {
            index += 1;
            args.get(index).cloned().ok_or_else(|| format!("{name} takes a value.\n{USAGE}"))
        };
        match word {
            "--yes" => yes = true,
            "--force" => {
                request.insert("force".into(), json!(true));
            }
            "--profile" => {
                let given = value("--profile")?;
                request.insert("profile".into(), json!(given));
            }
            "--product" => {
                let given = value("--product")?;
                request.insert("product".into(), json!(given));
            }
            "--stamp" => {
                let given = value("--stamp")?;
                request.insert("stamp".into(), json!(given));
            }
            "--stage" => {
                let given = value("--stage")?;
                request.insert("stage".into(), json!(given));
            }
            "--keep-for-days" => {
                let given = value("--keep-for-days")?;
                let days: u64 = given.parse().map_err(|_| "--keep-for-days is a number of days".to_owned())?;
                request.insert("keepForDays".into(), json!(days));
            }
            other => return Err(format!("'{other}' is not one of this command's words.\n{USAGE}")),
        }
        index += 1;
    }
    if CONFIRMED.contains(&verb) && !yes {
        return Err(format!("Add --yes to {verb}: it changes where this computer stands in the rollout.\n{USAGE}"));
    }
    Ok(json!({"request": Value::Object(request)}))
}

/// Runs one `yougori rollout` command and hands back the engine's answer.
pub async fn run(args: &[String]) -> Result<Value, String> {
    let params = plan(args)?;
    let verb = args.get(1).map(String::as_str).unwrap_or("status");
    waiting("Starting Yougori", client::start(None)).await?;
    waiting(label(verb), call("grids_rollout", params)).await
}

/// What the spinner says while this one runs. Every wait has one, because a command that may
/// copy a whole deployment and run two imports has to look like it is doing something.
fn label(verb: &str) -> &'static str {
    match verb {
        "survey" => "Taking an inventory of this computer",
        "rehearse" => "Running the move on copies",
        "backup" => "Copying every record and reading it back",
        "verify" => "Checking the backup",
        "restore" => "Putting a record back",
        "observe" => "Asking both paths the same questions",
        "read" => "Reading the record",
        "retire" | "unretire" | "forget" => "Moving the old record",
        _ => "Asking where the rollout stands",
    }
}

async fn waiting<T>(label: &str, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        crate::cli_ui::busy(label, work).await
    } else {
        work.await
    }
}

/// What a person reads. The engine already writes the sentences, because the counting and the
/// judging are in the crate that owns the records; this prints them and adds nothing.
pub fn render(value: &Value) -> String {
    match value["said"].as_str() {
        Some(said) => said.to_owned(),
        None => serde_json::to_string_pretty(value).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES that each verb becomes the request the engine's contract declares, that a verb
    /// which changes where the rollout stands needs `--yes`, and that an unknown word is refused
    /// with the usage rather than sent.
    ///
    /// DOES NOT PROVE that the engine does what the request asks: that is the engine's own
    /// tests, and the work itself is in the grid crate.
    #[test]
    fn every_verb_becomes_a_request_and_the_ones_that_change_things_need_yes() {
        assert_eq!(plan(&["rollout".into(), "status".into()]).unwrap(), json!({"request": {"do": "status"}}));
        assert_eq!(
            plan(&["rollout".into(), "backup".into(), "--keep-for-days".into(), "120".into(), "--stage".into(), "cutover".into()]).unwrap(),
            json!({"request": {"do": "backup", "keepForDays": 120, "stage": "cutover"}})
        );
        assert_eq!(
            plan(&["rollout".into(), "read".into(), "--product".into(), "neo".into()]).unwrap(),
            json!({"request": {"do": "read", "product": "neo"}})
        );
        for verb in CONFIRMED {
            let refused = plan(&["rollout".into(), (*verb).into(), "--profile".into(), "models".into()]).unwrap_err();
            assert!(refused.starts_with(&format!("Add --yes to {verb}")), "{refused}");
        }
        assert!(plan(&["rollout".into(), "advance".into(), "--profile".into(), "models".into(), "--yes".into()]).is_ok());
        assert!(plan(&["rollout".into(), "invent".into()]).unwrap_err().contains("cannot be asked to 'invent'"));
        assert!(plan(&["rollout".into()]).unwrap_err().starts_with("Usage: yougori rollout"));
        assert!(plan(&["rollout".into(), "verify".into(), "--stamp".into()]).unwrap_err().starts_with("--stamp takes a value"));
    }

    /// PROVES that the one help line a person is most likely to read names the flag each of
    /// these two verbs is actually answered with. The engine's retire arm makes the stamped
    /// folder's name itself and never reads a `--stamp`; its unretire arm takes the product from
    /// that folder's own manifest and never reads a `--profile`. A line offering both flags to
    /// both verbs reads as though either worked, and one of them is silently dropped.
    ///
    /// DOES NOT PROVE that the parser refuses the flag it does not use. It still accepts and
    /// discards it: per-verb flag checking exists nowhere else in this module, and with nothing
    /// documenting the combination there is nothing left to be misled by.
    #[test]
    fn the_public_help_names_the_flag_each_of_these_verbs_is_answered_with() {
        let line = crate::public::HELP.lines().find(|line| line.contains("rollout retire")).expect("the public help has a line for retiring a record");
        assert!(line.contains("rollout retire --profile PROFILE"), "{line}");
        assert!(line.contains("unretire --stamp STAMP"), "{line}");
        assert!(!line.contains("retire|unretire"), "retire and unretire do not take the same flags: {line}");
        // And the module's own usage, which has had it right all along, still agrees.
        assert!(USAGE.contains("rollout retire --profile PROFILE") && USAGE.contains("rollout unretire --stamp STAMP"));
    }

    /// PROVES that every verb this command accepts is in its own usage message and has a
    /// spinner label, so nothing a person can type is undocumented and no wait is silent.
    ///
    /// DOES NOT PROVE that the engine has a verb for each: that is the engine's refusal, in its
    /// own words.
    #[test]
    fn every_verb_is_in_the_usage_and_has_something_to_say_while_it_waits() {
        for verb in VERBS {
            assert!(USAGE.contains(&format!("rollout {verb}")), "{verb} is not in the usage message");
            assert!(!label(verb).is_empty());
        }
        assert!(USAGE.contains("Nothing is uploaded anywhere"), "the usage has to say what this does not do");
    }
}
