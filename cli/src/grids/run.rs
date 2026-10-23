//! Running one `yougori grids …` command.
//!
//! The work is split in two on purpose. Everything that may ask a person something happens
//! first, with nothing covering the screen; only the wait on the engine is wrapped in the
//! spinner, because a spinner over a hidden password prompt is worse than no spinner at all.
//!
//! One thing worth saying plainly rather than implying: the guided questions offer Back, but the
//! single hidden prompt for a password does not. Escape and Ctrl+C there cancel and change
//! nothing, which is what the four products already do.

use super::fault::Fault;
use super::render::{self, Format};
use super::words::{self, Typed};
use crate::{client, wire};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read};

/// What `prepare` worked out: either a question to answer here, or a command to send.
pub enum Prepared {
    /// `--help`, which is a question rather than a command.
    Help(String),
    Ask(Box<Asked>),
}

/// One command, ready to send.
pub struct Asked {
    typed: Typed,
    request: wire::Request,
}

impl Asked {
    /// Words or JSON, with what was typed winning over the environment and the environment over
    /// the terminal test.
    pub fn format(&self, environment: Option<&str>, terminal: bool) -> Format {
        render::chosen(self.typed.format.as_deref(), environment, terminal)
    }
    pub fn explain(&self) -> bool {
        self.typed.explain
    }
    /// What this is called in the words a person typed, for the spinner's own line.
    pub fn said_as(&self) -> String {
        self.typed.said_as()
    }
    pub fn request(&self) -> &wire::Request {
        &self.request
    }
    /// The answer to this command, in words: a grid's lists read for what was asked about.
    pub fn show(&self, value: &Value) -> String {
        match serde_json::from_value::<super::answer::Answer>(value.clone()) {
            Ok(answer) => render::render_about(&answer, self.typed.noun),
            Err(_) => show(value),
        }
    }
}

/// Reads one line of a file, or of stdin for `-`.
fn read_file(path: &str) -> Result<Value, String> {
    let mut bytes = Vec::new();
    let mut source: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path).map_err(|error| format!("Cannot read that file: {error}"))?)
    };
    source
        .as_mut()
        .take(wire::MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > wire::MAX_REQUEST {
        return Err("That file is larger than a megabyte, which is more than one request may carry.".into());
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(bytes).map_err(|error| format!("That file is not the JSON this expects: {error}"))
}

/// What a secret is called when somebody is asked for it.
fn ask_for(secret: &str) -> &'static str {
    match secret {
        "passphrase" => "Passphrase (hidden): ",
        "value" => "Credential value (hidden): ",
        _ => "Password (hidden): ",
    }
}

/// Everything that may ask a person something. Nothing here waits on the engine.
pub fn prepare(args: &[String]) -> Result<Prepared, String> {
    let mut typed = match words::parse(args) {
        Ok(typed) => typed,
        Err(fault) if fault.about.as_deref() == Some("help") => return Ok(Prepared::Help(fault.said)),
        Err(fault) => {
            // A refusal this door decided carries its own code, exactly as one the engine sent
            // does. The sentence is what is shown; the code travels beside it.
            // In a pipe the code is already in `errorDetails`; the muted line is for a person.
            let explain = args.iter().any(|arg| arg == "--explain") && std::io::stdout().is_terminal();
            client::remember_error(fault.said.clone(), fault.details());
            return Err(render::render_fault(&fault, explain));
        }
    };
    if let Some(path) = typed.file.clone() {
        typed.request.insert("file".into(), read_file(&path)?);
    }
    for secret in typed.secrets.clone() {
        let value = match (typed.named_on_stdin(&secret), std::io::stdin().is_terminal()) {
            (true, _) => crate::grid::stdin_line(&mut std::io::stdin().lock())?,
            // Escape or Ctrl+C at this prompt cancels and changes nothing. There is no Back
            // here, which is what the four products already do with a hidden prompt.
            (false, true) => crate::grid::hidden(ask_for(&secret))?,
            (false, false) => return Err(format!("Not in a terminal: supply the {secret} on stdin with --{secret} -.")),
        };
        if value.is_empty() {
            return Err(format!("Nothing was typed for the {secret}, so nothing was changed."));
        }
        typed.request.insert(secret, json!(value));
    }
    let request = wire::Request {
        version: wire::VERSION,
        method: typed.method().to_owned(),
        params: typed.params(),
        confirmed: typed.confirmed,
        dry_run: typed.dry_run,
    };
    Ok(Prepared::Ask(Box::new(Asked { typed, request })))
}

/// How long to wait for work the engine queues: the same hour every other command waits.
const WAIT: u64 = 3600;

/// The one wait. Everything that could ask a person something has already happened.
pub async fn ask(asked: &Asked) -> Result<Value, String> {
    let answered = async {
        client::start(None).await?;
        let value = client::call(&asked.request).await?;
        if value["accepted"] != true {
            return Ok(value);
        }
        // A change the engine takes as a piece of work answers with that work rather than with
        // the answer itself, exactly as it does for every other command. Waiting for it belongs
        // here, so that what comes back from this door is always one answer.
        let work = value["jobId"].as_str().ok_or("The engine took the command but did not say which piece of work it is.")?.to_owned();
        client::wait_job(&work, WAIT).await
    }
    .await;
    match answered {
        Ok(value) => Ok(value),
        Err(said) if asked.explain() => Err(match client::latest_error_details() {
            Some(details) => format!("{said}\nCode: {} - trying again would {}", details.code, if details.retryable { "be worth it" } else { "not help" }),
            None => said,
        }),
        Err(said) => Err(said),
    }
}

/// The answer, in words.
pub fn show(value: &Value) -> String {
    match serde_json::from_value::<super::answer::Answer>(value.clone()) {
        Ok(answer) => render::render(&answer),
        // An answer this build cannot read is shown as it arrived rather than as nothing.
        Err(_) => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

/// A refusal in words, for a caller that already holds one.
pub fn refusal(fault: &Fault, explain: bool) -> String {
    render::render_fault(fault, explain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_is_answered_here_rather_than_sent_anywhere() {
        let Ok(Prepared::Help(text)) = prepare(&["models".to_string(), "--help".to_string()]) else {
            panic!("--help must be answered without the engine");
        };
        assert!(text.contains("yougori grids models add"));
    }

    #[test]
    fn a_command_becomes_one_request_with_the_verb_inside_it() {
        let Ok(Prepared::Ask(asked)) = prepare(&["models".to_string(), "list".to_string()]) else {
            panic!("a plain read needs nothing from anybody");
        };
        assert_eq!(asked.request().method, "grids_models");
        assert_eq!(asked.request().params, json!({"request":{"do":"list"}}));
        assert!(!asked.request().dry_run && !asked.request().confirmed);
        assert_eq!(asked.said_as(), "grids models list");
        assert_eq!(asked.format(None, true), Format::Words);
        assert_eq!(asked.format(None, false), Format::Json);
    }

    #[test]
    fn a_secret_typed_into_the_command_is_refused_before_anything_is_sent() {
        let Err(refused) = prepare(&["new".to_string(), "Acme".to_string(), "--ip".to_string(), "10.0.0.5".to_string(), "--password".to_string(), "hunter2".to_string()]) else {
            panic!("a password in an argument is never sent anywhere");
        };
        assert!(refused.starts_with("Never type the password into the command"));
        assert!(!refused.contains('_'));
    }

    #[test]
    fn an_answer_this_build_cannot_read_is_shown_as_it_arrived() {
        let shown = show(&json!({"something":"from a newer engine"}));
        assert!(shown.contains("from a newer engine"));
        let answer = super::super::answer::Answer::new("keen-heron-3f1a", "One grid on this computer: Acme.");
        let value = serde_json::to_value(&answer).unwrap();
        assert!(show(&value).starts_with("One grid on this computer: Acme."));
    }
}
