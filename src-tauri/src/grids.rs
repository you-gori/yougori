//! One door onto all four grids.
//!
//! Twelve wire methods, one per noun, with the verb inside the request. Each one finds the grid
//! the command is about, refuses in words anything that grid does not do, and then calls the
//! product handler that already exists. The old methods keep their own handlers and their own
//! words, untouched: this is a second door onto the same code, never a replacement for it.
//!
//! What this door adds that the old one does not have: one shape for every answer, a code
//! travelling beside every refusal, a dry run that checks against the real grid and writes
//! nothing, and one readable name per typed command that the record can be asked about.

pub mod registry;

use crate::automation::dispatch;
use serde_json::{Map, Value};
use crate::AppHandle;
use yougori_cli::grids::alias;
use yougori_cli::grids::answer::{Answer, Change, Named};
use yougori_cli::grids::fault::{Code, Fault};
use yougori_cli::grids::{admissible, find, noun_for, Capability, Product};

/// One typed command, answered.
pub(crate) async fn answer(app: &AppHandle, method: &str, params: &Value, dry_run: bool) -> Result<Value, String> {
    let command = yougori_grid::core::name::fresh_command();
    match run(app, method, params, dry_run, &command).await {
        Ok(answer) => serde_json::to_value(answer).map_err(|error| error.to_string()),
        Err(fault) => Err(fault.wire()),
    }
}

/// The order is fixed, and it is what the tests assert: the grid is found before one argument of
/// the command is looked at, and what the grid may be asked is settled before anything is read.
/// A credential command sent to a grid that holds none is refused without the credential ever
/// being deserialised, let alone read.
async fn run(app: &AppHandle, method: &str, params: &Value, dry_run: bool, command: &str) -> Result<Answer, Fault> {
    let noun = noun_for(method).ok_or_else(|| Fault::new(Code::UnknownWords, "That is not one of the twelve things a grid is made of."))?;
    let request = params
        .get("request")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| Fault::new(Code::MissingWords, "Say what to do with this grid."))?;
    let verb = request.get("do").and_then(Value::as_str).unwrap_or_default().to_owned();
    let known = find(noun, &verb).ok_or_else(|| {
        let choices: Vec<&str> = yougori_cli::grids::verbs_of(noun).iter().map(|verb| verb.verb).collect();
        Fault::new(Code::UnknownWords, format!("A grid's {noun} can be asked to {}.", yougori_cli::grids::join_words(&choices)))
    })?;

    // Three things no single grid can answer. Listing them, because none of them knows about the
    // others; and the two about health, because a checkup is read from a realm's own database
    // rather than from a product hub, and because an operator asking whether their grids are
    // healthy has to be answered on a computer where a product is in trouble.
    if alias::answered_by_the_register(noun, &verb) {
        if verb == "health" {
            let full = request.get("full").is_some();
            let found = crate::grid_observe::checkups(app, full);
            return Ok(Answer::new(command, crate::grid_observe::describe(&found)).found(found));
        }
        if verb == "observe" {
            return observing(app, command, &request, dry_run).await;
        }
        let all = registry::grids(app).await;
        let said = match all.len() {
            0 => "This computer is not in a grid yet.".to_owned(),
            1 => format!("One grid on this computer: {}.", all[0].name),
            count => format!("{count} grids on this computer."),
        };
        let found = serde_json::to_value(&all).map_err(|error| Fault::new(Code::GridRefused, error.to_string()))?;
        return Ok(Answer::new(command, said).found(found));
    }

    let wanted = params.get("grid").and_then(Value::as_str);
    let grid = if alias::chosen_by_the_words(noun, &verb) {
        // Looking the grid up at all is skipped once `--serve` has said what it is for.
        let found = match request.contains_key("serve") {
            true => None,
            false => registry::find(app, wanted, known.needs).await.ok(),
        };
        from_the_words(&verb, &request, found)?
    } else {
        registry::find(app, wanted, known.needs).await?
    };
    if known.mutating && grid.lifecycle != "open" {
        return Err(Fault::new(Code::GridNotOpen, "This grid is being deleted, so nothing more can be changed in it.").about(&grid.name));
    }
    admissible(known, &[registry::product_of(&grid).capability()]).map_err(|fault| fault.about(&grid.name))?;

    let product = registry::product_of(&grid);
    let (old_method, old_params) = alias::product_call(product, noun, &verb, &request).map_err(|fault| fault.about(&grid.name))?;
    // The engine's own contract for the handler this reaches, checked here rather than inside it,
    // so a rehearsal finds the same mistakes a real run would.
    let contract = yougori_cli::catalog::find(old_method).map_err(|error| Fault::new(Code::GridRefused, error))?;
    contract.validate(&old_params).map_err(|error| Fault::new(Code::ValueUnusable, sentence(&error)).about(&grid.name))?;

    if dry_run {
        // What it would actually cost is worked out here, where the record is reachable, so
        // rehearsal() stays a plain piece of wording with nothing to look up.
        let charge = rented_gpu_charge(app, noun, &verb, &old_params).await;
        return Ok(rehearsal(command, &grid, noun, &verb, charge.as_deref().or(known.confirmation), &old_params));
    }
    let raw = dispatch::dispatch(app, old_method, &old_params)
        .await
        .map_err(|error| Fault::new(Code::GridRefused, refusal(error)).about(&grid.name))?;
    Ok(answered(command, grid, noun, &verb, known.mutating, raw))
}

/// Turning the health endpoint on or off.
///
/// The token is in the answer and nowhere else. It is never written to a file, never logged and
/// never put in an audit reason: the person who turned the endpoint on is handed it once, and if
/// they lose it they turn the endpoint off and on again, which makes a new one and makes the old
/// one useless.
async fn observing(app: &AppHandle, command: &str, request: &Map<String, Value>, dry_run: bool) -> Result<Answer, Fault> {
    let off = request.contains_key("off");
    let port = request.get("port").and_then(Value::as_u64).map(|port| port as u16);
    if dry_run {
        let said = if off {
            "Would stop answering health and readings on this computer.".to_owned()
        } else {
            format!(
                "Would answer /healthz and /metrics on 127.0.0.1 port {}, to anything on this computer that has the token this would hand back. Nothing outside this computer could reach it.",
                port.unwrap_or(crate::grid_observe::PORT)
            )
        };
        return Ok(Answer::new(command, said).rehearsed());
    }
    if off {
        let found = crate::grid_observe::stop(app).await.map_err(|error| Fault::new(Code::GridRefused, error))?;
        let said = if found["stopped"] == true { "This computer has stopped answering health and readings." } else { "This computer was not answering health and readings." };
        return Ok(Answer::new(command, said).found(found));
    }
    let found = crate::grid_observe::serve(app, port).await.map_err(|error| Fault::new(Code::GridRefused, error))?;
    let said = format!(
        "Answering /healthz and /metrics on 127.0.0.1 port {}, on this computer only. Give your monitoring agent the token in this answer as a bearer token; it is shown once and is not written anywhere.",
        found["port"].as_u64().unwrap_or(0)
    );
    Ok(Answer::new(command, said).found(found))
}

/// Which grid a command that cannot be about an existing one is about.
///
/// Starting a grid, joining one and asking this computer for an address all happen on a computer
/// that may be in no grid at all, so there is nothing to look up and the words have to say which
/// product answers. `found` is whatever the register could make of this computer, which is
/// nothing on a fresh one and is only consulted when `--serve` was left out.
pub(crate) fn from_the_words(verb: &str, request: &Map<String, Value>, found: Option<Named>) -> Result<Named, Fault> {
    if let Some(word) = request.get("serve").and_then(Value::as_str) {
        let capability = Capability::from_word(word).ok_or_else(|| {
            Fault::new(Code::ValueUnusable, "A grid either serves models, hosts desks, brokers credentials or runs research. Say which one with --serve.")
        })?;
        return Ok(registry::fresh(Product::serving(capability), request.get("name").and_then(Value::as_str)));
    }
    match found {
        // Joining names a grid somebody else runs, so the one kind of grid already on this
        // computer says which product answers.
        Some(found) if verb != "new" => Ok(found),
        // An address is about this computer rather than about any grid, and every product
        // answers it the same way.
        _ if verb == "address" => Ok(registry::fresh(Product::Neo, None)),
        _ => Err(Fault::new(
            Code::MissingWords,
            "Say what this grid is for with --serve models, --serve desks, --serve credentials or --serve research.",
        )),
    }
}

/// A refusal from a product handler, in words.
///
/// A handler that answers the wire may answer with a token and a clause, which the wire turns
/// into a code for a program to read. Nobody reads a token, so this door says the same thing as a
/// sentence instead, and leaves a handler that already wrote one exactly as it was.
pub(crate) fn refusal(error: String) -> String {
    match error.split_once(": ") {
        Some(("YOUGORI_JOB_NOT_FOUND", _)) => "There is no work by that name on this computer.".to_owned(),
        Some(("YOUGORI_NOT_CANCELLABLE", _)) => "This work has to finish or be put right; stopping it would not undo what it has already done.".to_owned(),
        Some((token, rest)) if token.starts_with("YOUGORI_") && !rest.is_empty() => sentence(rest),
        _ => error,
    }
}

/// A refusal from a contract reads as a sentence rather than as a line of a schema.
fn sentence(error: &str) -> String {
    let trimmed = error.trim_end_matches('.');
    let mut characters = trimmed.chars();
    let said = match characters.next() {
        Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
        None => "That cannot be used here".to_owned(),
    };
    format!("{said}.")
}

/// What a rehearsal says.
///
/// This is honest about what it did and did not do. It found the grid on this computer, read
/// what that grid is allowed to do, turned the words into the call the product would receive and
/// checked that call against the engine's own contract. It did not run the product handler, so
/// nothing was written anywhere: not in the grid's record, not in the operating system's vault.
/// What stopping rented GPUs would actually cost, for the two verbs that stop them: how many are
/// charging and what they come to an hour, so the person sees that before repeating with --yes.
/// Pods still powering on count, because they are already billing.
///
/// None whenever there is nothing to say — no pods, none charging, or the record unreadable — and
/// the written sentence stands. A refusal must never fail because it could not count.
async fn rented_gpu_charge(app: &AppHandle, noun: &str, verb: &str, params: &Value) -> Option<String> {
    if noun != "models" {
        return None;
    }
    let only = match verb {
        "remove-gpu" => Some(params["environmentId"].as_str().unwrap_or_default().to_owned()),
        "stop-gpus" => None,
        _ => return None,
    };
    // Exactly what the stop would reach, which is narrower than "every pod that is billing".
    // Stopping only touches pods in this grid, and leaves alone any a Swarm worker is using, so
    // counting every billing pod on the computer promises more than the command does — and then
    // the answer afterwards says every one of them was stopped. Two overstatements about money,
    // in the two sentences somebody reads while deciding and while being told it is done.
    let members = crate::grid_neocloud::member_pods(app).await;
    // Checked, not assumed. `in_use` turns "Swarm's record could not be read" into "no worker
    // uses any pod", which here would count somebody's working pod among the ones this stop
    // reaches and promise to stop more than it will. The sentence is optional; being wrong
    // about what a command is about to do to paid work is not.
    let Ok(busy_with_swarm) = crate::swarm::rented::in_use_checked(app).await else { return None };
    let charging = crate::rented_gpu::pods(app)
        .into_iter()
        .filter(|(id, pod)| {
            members.contains(id)
                && !busy_with_swarm.contains_key(id)
                && crate::rented_gpu::billing(&pod.state)
                && only.as_deref().is_none_or(|wanted| id == wanted)
        })
        .collect::<Vec<_>>();
    let hourly: f64 = charging.iter().map(|(_, pod)| pod.hourly_usd).sum();
    // A price nobody recorded is not a price of nothing. Saying "$0.00 an hour" about a pod that
    // is certainly costing something is the one number here worse than no number at all.
    let cost = (hourly > 0.0).then(|| format!(" costing ${hourly:.2} an hour"));
    match (charging.len(), cost) {
        (0, _) => None,
        (1, Some(cost)) => Some(format!("This stops 1 rented GPU{cost}.")),
        (1, None) => Some("This stops 1 rented GPU, at a price this computer has not recorded.".to_owned()),
        (count, Some(cost)) => Some(format!("This stops {count} rented GPUs{cost} together.")),
        (count, None) => Some(format!("This stops {count} rented GPUs, at prices this computer has not recorded.")),
    }
}

fn rehearsal(command: &str, grid: &Named, noun: &str, verb: &str, confirmation: Option<&str>, old_params: &Value) -> Answer {
    let what = thing(noun);
    let which = names(old_params).unwrap_or_else(|| grid.name.clone());
    let (present, _) = reading(verb);
    let answer = Answer::new(command, format!("This would {present} {what} {which} in {}, and has not.", grid.name))
        .about(grid.clone())
        .changed(vec![Change::new(what, &format!("would {present}"), which)])
        .rehearsed();
    match confirmation {
        Some(sentence) => answer.next(format!("{sentence} Repeat with --yes to do it.")),
        None => answer,
    }
}

/// What a command did.
fn answered(command: &str, grid: Named, noun: &str, verb: &str, mutating: bool, raw: Value) -> Answer {
    let what = thing(noun);
    let which = names(&raw).unwrap_or_else(|| grid.name.clone());
    let said = if mutating {
        format!("{} {what} {which} in {}.", capitalise(reading(verb).1), grid.name)
    } else if noun == "realm" {
        format!("{}, as it is now.", grid.name)
    } else {
        format!("{}: its {}.", grid.name, things(noun))
    };
    let mut answer = Answer::new(command, said).about(grid).found(raw);
    if mutating {
        answer = answer.changed(vec![Change::new(what, reading(verb).1, which)]);
    }
    // Every grid still keeps its own record, in its own hub, and none of them yet writes the
    // name of the command that caused an event. Grid Core does, from version seven of its
    // database; a product reports its events here on the day it moves onto it.
    answer.correlated = false;
    answer
}

/// The same thing in the plural, for a read.
fn things(noun: &str) -> &'static str {
    match noun {
        "people" => "people",
        "computers" => "computers",
        "share" => "computer shares",
        "models" => "model plans",
        "desks" => "desks",
        "credentials" => "credentials",
        "requests" => "waiting requests",
        "research" => "research workers",
        "connectors" => "connectors",
        "work" => "work",
        _ => "record",
    }
}

fn capitalise(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
        None => String::new(),
    }
}

/// How a verb reads in a sentence: what it would do, and what it did.
///
/// The word somebody types is a word for a table, not a word for a sentence: `reset-two-step` and
/// `cloud-fallback` are names of settings rather than things to say. A verb that is not named here
/// still reads as English rather than as the word that was typed, and the table is checked against
/// the verb table by a test so the two cannot drift apart.
pub(crate) fn reading(verb: &str) -> (&'static str, &'static str) {
    match verb {
        "add" | "add-team" | "add-key" | "add-image" | "add-size" => ("add", "added"),
        "import-image" => ("take in", "taken in"),
        "set" | "settings" | "rotate" | "limit" | "share" | "password" | "my-password" | "sso" | "two-step" | "parking" | "cloud-fallback" | "memory" | "manage" => ("change", "changed"),
        "remove" | "remove-team" | "remove-rule" | "remove-image" | "remove-size" => ("remove", "removed"),
        "revoke-key" | "revoke" => ("revoke", "revoked"),
        "drain" => ("stop using", "drained"),
        "bring-back" => ("bring back", "brought back"),
        "new" => ("start", "started"),
        "join" => ("join", "joined"),
        "leave" => ("leave", "left"),
        "delete" => ("delete", "deleted"),
        "restore" => ("bring back", "restored"),
        "backup" => ("back up", "backed up"),
        "restore-backup" => ("put back", "put back"),
        "assign" => ("give away", "assigned"),
        "retry" => ("build again", "built again"),
        "refresh" => ("refresh", "refreshed"),
        "sign-in" => ("sign in", "signed in"),
        "sign-out" | "sign-out-others" => ("sign out", "signed out"),
        "reset-two-step" => ("reset two-step sign-in for", "reset two-step sign-in for"),
        "forget" => ("forget", "forgotten"),
        "run-team" => ("run", "run"),
        "allow" => ("write a rule for", "allowed"),
        "use" => ("make a call with", "used"),
        "reveal" => ("ask to see", "asked to see"),
        "approve" => ("agree to", "agreed to"),
        "deny" => ("refuse", "refused"),
        "skip" => ("pass on", "passed on"),
        "chat" => ("say something to", "spoken to"),
        "pause" => ("pause", "paused"),
        "resume" => ("let carry on", "let carry on"),
        "stop" => ("stop", "stopped"),
        "credential" => ("give its credential to", "given its credential"),
        "test" => ("sign in and check", "checked"),
        "provision" => ("give an account to", "given an account"),
        "cancel" => ("cancel", "cancelled"),
        "export" => ("carry out the record of", "carried out"),
        // A read writes nothing, so it only ever reaches the rehearsal sentence.
        "list" | "mine" | "offers" | "bounties" | "messages" | "reports" | "rewards" | "activity" => ("list", "listed"),
        "show" | "details" | "status" | "address" => ("show", "shown"),
        "check" | "verify" => ("check", "checked"),
        "portal" => ("open", "opened"),
        _ => ("change", "changed"),
    }
}

/// What kind of thing a noun is about, in the words a person uses for it.
fn thing(noun: &str) -> &'static str {
    match noun {
        "realm" => "grid",
        "people" => "person",
        "computers" => "computer",
        "share" => "computer share",
        "models" => "model plan",
        "desks" => "desk",
        "credentials" => "credential",
        "requests" => "request",
        "research" => "research worker",
        "connectors" => "connector",
        "work" => "work",
        _ => "record",
    }
}

/// The memorable name of whatever a call is about, never its identifier.
fn names(value: &Value) -> Option<String> {
    for key in ["name", "person", "username", "desk", "credential", "computer", "model", "harness", "worker", "company"] {
        if let Some(found) = value.get(key).and_then(Value::as_str) {
            return Some(found.to_owned());
        }
        if let Some(found) = value.get("request").and_then(|request| request.get(key)).and_then(Value::as_str) {
            return Some(found.to_owned());
        }
    }
    None
}

/// Whether the engine answers this method at all, for the queue and the dispatcher.
pub(crate) fn handles(method: &str) -> bool {
    noun_for(method).is_some()
}

#[cfg(test)]
mod tests;
