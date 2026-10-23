//! The same answer, in words.
//!
//! One command gives both outputs. Which one is chosen is decided in one place and in one order,
//! written down here rather than guessed at each call site. Words are plain lines: no icons, no
//! boxes, no borders, nothing a person has to decode.

use super::answer::Answer;
use super::fault::Fault;

/// How an answer is to be shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Words,
    Json,
}

/// Words or JSON, decided in this order and no other:
///   1. `--format json` or `--format text`, when it was given.
///   2. `YOUGORI_FORMAT`, for an agent driving a terminal that lies about being one.
///   3. otherwise words in a terminal, JSON when the output is piped or redirected.
pub fn chosen(flag: Option<&str>, environment: Option<&str>, terminal: bool) -> Format {
    match flag.or(environment) {
        Some("json") => Format::Json,
        Some("text") => Format::Words,
        _ if terminal => Format::Words,
        _ => Format::Json,
    }
}

/// One answer as plain lines.
pub fn render(answer: &Answer) -> String {
    render_with(answer, None)
}

/// One answer as plain lines, read for what a command about `noun` asked: the computers, the
/// model plans and keys, or the desks in a grid's own lists, each with the ID commands take.
pub fn render_about(answer: &Answer, noun: &str) -> String {
    render_with(answer, Some(noun))
}

fn render_with(answer: &Answer, noun: Option<&str>) -> String {
    let mut lines = vec![answer.said.clone()];
    for change in &answer.changed {
        let detail = if change.detail.is_empty() { String::new() } else { format!("   {}", change.detail) };
        lines.push(format!("  {} {} {}{detail}", change.how, change.what, change.which));
    }
    if let Some(found) = &answer.found {
        let (shown, left_out) = match noun.and_then(|noun| grid_lists(found, noun)) {
            Some(listed) => (listed, true),
            None => read(found, unix_now()),
        };
        lines.extend(shown);
        // Words never quietly drop part of an answer: what they leave out is one flag away.
        if left_out {
            lines.push("Add --format json to see the whole answer.".to_owned());
        }
    }
    if let Some(next) = &answer.next {
        lines.push(next.clone());
    }
    if answer.rehearsed {
        lines.push("Nothing was changed: this was a rehearsal.".to_owned());
    }
    if !answer.recorded.is_empty() {
        let sequences: Vec<String> = answer.recorded.iter().map(u64::to_string).collect();
        lines.push(format!("Recorded as {}, in events {}.", answer.command, sequences.join(", ")));
    } else {
        lines.push(format!("This command is called {}.", answer.command));
    }
    lines.join("\n")
}

/// A refusal in a terminal: the sentence alone, and the code only when it was asked for.
pub fn render_fault(fault: &Fault, explain: bool) -> String {
    if explain {
        format!("{}\n{}", fault.said, fault.explained())
    } else {
        fault.said.clone()
    }
}

/// The rows a read found, as lines.
#[cfg(test)]
fn rows(found: &serde_json::Value) -> Vec<String> {
    read(found, unix_now()).0
}

/// What an answer found, as lines, and whether anything in it was left out of them.
///
/// A list of grids, people or plans reads as one line each. An answer that hands something over
/// once (an API key, a two-step secret, a token, a credential's value, the request to check back
/// with) shows it in full, labelled: those are the reason the command was run, and an answer
/// that hid them at a terminal left the person with nothing. Anything else is left to JSON
/// rather than flattened into something misleading, and the person is told it is there.
fn read(found: &serde_json::Value, now: i64) -> (Vec<String>, bool) {
    if let Some(lines) = rented_gpus(found, now) {
        return (lines, false);
    }
    match found {
        serde_json::Value::Array(items) => {
            let lines: Vec<String> = items
                .iter()
                .filter_map(|item| {
                    let name = item.get("name").and_then(|value| value.as_str()).or_else(|| item.get("handle").and_then(|value| value.as_str()))?;
                    let does = item
                        .get("does")
                        .and_then(|value| value.as_array())
                        .map(|values| values.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default();
                    let role = item.get("role").and_then(|value| value.as_str()).unwrap_or_default();
                    // The identifier, where the thing has one. These lists are what the refusals
                    // send people to — "give the computer's ID, this list shows it" — and the
                    // hubs match on identifiers rather than names, so a list without them sends
                    // somebody to look up a thing it does not show. It goes last: the name is
                    // what they recognise, the identifier is what they have to copy.
                    let which = ["id", "memberId", "planId", "keyId", "deskId", "harnessId"]
                        .iter()
                        .find_map(|key| item.get(*key).and_then(|value| value.as_str()))
                        .filter(|found| !found.is_empty() && *found != name)
                        .unwrap_or_default();
                    Some(format!("  {name}   {does}   {role}   {which}").trim_end().to_owned())
                })
                .collect();
            let left_out = lines.len() < items.len();
            (lines, left_out)
        }
        serde_json::Value::Object(fields) => handed_over(fields, now),
        serde_json::Value::String(text) if !text.trim().is_empty() => (vec![format!("  {}", text.trim())], false),
        serde_json::Value::Null | serde_json::Value::String(_) => (Vec::new(), false),
        _ => (Vec::new(), true),
    }
}

/// The parts of a one-off answer a person came for, labelled, in the order they are used.
const HANDED_OVER: &[(&str, &str)] = &[
    ("apiKey", "API key"),
    ("baseUrl", "Address"),
    ("secret", "Secret"),
    ("link", "Authenticator link"),
    ("token", "Token"),
    ("port", "Port"),
    ("credential", "Credential"),
];

/// Parts of a credential's value that arrive as an object, such as short-lived cloud keys.
const VALUE_PARTS: &[(&str, &str)] = &[
    ("accessKeyId", "Access key ID"),
    ("secretAccessKey", "Secret access key"),
    ("sessionToken", "Session token"),
    ("region", "Region"),
];

/// Fields the lines already say in other words, so leaving them out hides nothing.
const SAID_ELSEWHERE: &[&str] = &["already", "shortLived", "tokenType", "message", "warning", "expiresAt", "certificate", "id", "state", "decidedBy", "reason", "error", "value"];

/// An answer that is one object, read for what it hands over.
fn handed_over(fields: &serde_json::Map<String, serde_json::Value>, now: i64) -> (Vec<String>, bool) {
    let text = |key: &str| fields.get(key).and_then(scalar);
    let mut lines = Vec::new();
    for (key, label) in HANDED_OVER {
        if let Some(value) = text(key) {
            lines.push(format!("  {label}: {value}"));
        }
    }
    match fields.get("value") {
        Some(serde_json::Value::Object(parts)) => {
            for (key, label) in VALUE_PARTS {
                if let Some(part) = parts.get(*key).and_then(scalar) {
                    lines.push(format!("  {label}: {part}"));
                }
            }
            for (key, part) in parts.iter().filter(|(key, _)| !VALUE_PARTS.iter().any(|(known, _)| known == key)) {
                if let Some(part) = scalar(part) {
                    lines.push(format!("  {key}: {part}"));
                }
            }
        }
        Some(value) => {
            if let Some(value) = scalar(value) {
                lines.push(format!("  Value: {value}"));
            }
        }
        None => {}
    }
    // A request somebody has to check back on is no use without its ID.
    if let (Some(id), Some(state)) = (text("id"), text("state")) {
        let decided = text("decidedBy").map(|who| format!(", decided by {who}")).unwrap_or_default();
        lines.push(format!("  Request {id}: {}{decided}", request_state(&state)));
        for (key, label) in [("reason", "Reason"), ("error", "What went wrong")] {
            if let Some(why) = text(key) {
                lines.push(format!("  {label}: {why}"));
            }
        }
    }
    if let Some(at) = fields.get("expiresAt").and_then(serde_json::Value::as_i64) {
        lines.push(format!("  {}", expiry(at, now)));
    }
    if text("apiKey").is_some() {
        // The engine's own note names its JSON fields, which these lines do not use.
        lines.push("Shown once. Apps call the address above with this key, and trust the certificate below, saved as grid.pem.".to_owned());
    } else if let Some(message) = text("message") {
        lines.push(message);
    }
    if let Some(warning) = text("warning") {
        lines.push(warning);
    }
    if let Some(certificate) = text("certificate") {
        lines.extend(certificate.lines().map(|line| format!("  {line}")));
    }
    let left_out = fields.iter().any(|(key, value)| {
        !value.is_null() && !HANDED_OVER.iter().any(|(known, _)| known == key) && !SAID_ELSEWHERE.contains(&key.as_str())
    });
    (lines, left_out)
}

/// A string or a number as it is shown; anything else is not a single value.
fn scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) if !text.is_empty() => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Where a request has got to, in words.
fn request_state(state: &str) -> &'static str {
    match state {
        "waiting" => "waiting for an approver",
        "running" => "approved and running",
        "done" => "done",
        "denied" => "denied",
        "failed" => "failed",
        _ => "in an unknown state",
    }
}

/// When something handed over stops working, from now.
fn expiry(at: i64, now: i64) -> String {
    let left = at - now;
    match left {
        ..=0 => "It has already expired.".to_owned(),
        1..=89 => "It expires within a minute or so.".to_owned(),
        90..=5399 => format!("It expires in about {} minutes.", (left + 30) / 60),
        5400..=129_599 => format!("It expires in about {} hours.", (left + 1800) / 3600),
        _ => format!("It expires in about {} days.", (left + 43_200) / 86_400),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)
}

/// The rented GPUs in a grid, which arrives as an object rather than a list.
///
/// Money is the reason this is not left to JSON like every other shape `rows` does not know.
/// Each line here is a pod somebody is paying for by the hour, and the two things they need at a
/// glance — what it costs and whether it is doing anything — are the two things that are hardest
/// to find in a reply with nine fields per entry.
fn rented_gpus(found: &serde_json::Value, now: i64) -> Option<Vec<String>> {
    let members = found.get("members")?.as_array()?;
    // Without a grid hosted here, its pods were stopped and kept so they can be removed, and no
    // other can join: adding one is refused, so none is offered. An older engine does not say.
    let hosting = found.get("hosting").and_then(serde_json::Value::as_bool).unwrap_or(true);
    let candidates = match found.get("candidates").and_then(|value| value.as_array()) {
        Some(candidates) if hosting => candidates.as_slice(),
        _ => &[],
    };
    let name_of = |entry: &serde_json::Value| entry.get("name").and_then(|value| value.as_str()).unwrap_or("A rented GPU").to_owned();
    // The ID is what `models add-gpu` and `models remove-gpu` take, so it stands beside the name.
    let id_of = |entry: &serde_json::Value| entry.get("environmentId").and_then(|value| value.as_str()).unwrap_or_default().to_owned();
    let card_of = |entry: &serde_json::Value| {
        let card = entry.get("gpu").and_then(|value| value.as_str()).unwrap_or("GPU").to_owned();
        match entry.get("gpuCount").and_then(serde_json::Value::as_u64).unwrap_or(1) {
            0 | 1 => card,
            many => format!("{card} x{many}"),
        }
    };
    let price_of = |entry: &serde_json::Value| match entry.get("hourlyUsd").and_then(serde_json::Value::as_f64) {
        Some(usd) if usd > 0.0 => format!("${usd:.2} an hour"),
        _ => "price unknown".to_owned(),
    };

    let hourly = found.get("hourlyUsd").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
    let most = found.get("max").and_then(serde_json::Value::as_u64).unwrap_or(8);
    // Running pods whose price NeoCloud did not record are left out of `hourlyUsd`, so with any
    // of them the sum is a floor, never the total.
    let unpriced = found.get("unpriced").and_then(serde_json::Value::as_u64).unwrap_or(0);
    let cost = |until: &str| match (hourly > 0.0, unpriced) {
        (true, 0) => Some(format!("${hourly:.2} an hour {until}")),
        (true, n) => Some(format!("at least ${hourly:.2} an hour {until}; NeoCloud has no price for {n} of them")),
        (false, 0) => None,
        (false, n) => Some(format!("price unknown {until}: NeoCloud has no price for {n} of them")),
    };
    let kept = |count: usize| if count == 1 { "1 rented GPU is".to_owned() } else { format!("{count} rented GPUs are") };
    let mut lines = vec![match (hosting, members.len()) {
        (_, 0) => "No rented GPUs are in this grid.".to_owned(),
        (true, count) => match cost("while they run") {
            Some(cost) => format!("{count} of {most} rented GPUs in this grid, {cost}."),
            None => format!("{count} of {most} rented GPUs in this grid, none of them running."),
        },
        (false, count) => match cost("until they stop") {
            Some(cost) => format!("{} kept from a grid this computer no longer hosts, {cost}.", kept(count)),
            None => format!("{} kept from a grid this computer no longer hosts, none of them running.", kept(count)),
        },
    }];
    if !hosting && !members.is_empty() {
        lines.push("No grid here can use them, so they were stopped and kept for you to remove: yougori grids models remove-gpu ID --yes".to_owned());
    }

    // Columns wide enough for the longest of each, so the prices line up under one another and
    // can be read down the page. That is the column somebody is scanning for.
    let widest = members.iter().map(|entry| name_of(entry).chars().count()).max().unwrap_or(0);
    let widest_card = members.iter().map(|entry| card_of(entry).chars().count()).max().unwrap_or(0);
    let widest_id = members.iter().map(|entry| id_of(entry).chars().count()).max().unwrap_or(0);
    let widest_price = members.iter().map(|entry| price_of(entry).chars().count()).max().unwrap_or(0);
    for entry in members {
        let name = match widest_id {
            0 => name_of(entry),
            _ => format!("{:<widest$}   {:<widest_id$}", name_of(entry), id_of(entry)),
        };
        let widest = if widest_id == 0 { widest } else { widest + 3 + widest_id };
        let doing = in_plain_words(entry.get("state").and_then(|value| value.as_str()).unwrap_or_default());
        let because = entry.get("reason").and_then(|value| value.as_str()).filter(|reason| !reason.is_empty());
        let tail = match because {
            Some(reason) => format!("{doing}. {reason}"),
            None => doing.to_owned(),
        };
        lines.push(format!("  {name:<widest$}   {:<widest_card$}   {:<widest_price$}   {tail}", card_of(entry), price_of(entry)));
    }
    for entry in candidates {
        let id = id_of(entry);
        let id = if id.is_empty() { String::new() } else { format!("{id}, ") };
        lines.push(format!("  Rented, not in this grid: {} ({id}{}, {})", name_of(entry), card_of(entry), price_of(entry)));
    }
    // How the latest stops went, newest first. A warning is a pod that may still be billing.
    let notices: Vec<(String, &str, bool)> = found
        .get("notices")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .rev()
        .filter_map(|notice| {
            let text = notice.get("text").and_then(|value| value.as_str()).filter(|text| !text.trim().is_empty())?;
            let when = notice.get("at").and_then(serde_json::Value::as_i64).map_or_else(|| "earlier".to_owned(), |at| ago(at, now));
            Some((when, text.trim(), notice.get("warning").and_then(serde_json::Value::as_bool).unwrap_or(false)))
        })
        .collect();
    if !notices.is_empty() {
        lines.push("Recent stops, newest first:".to_owned());
        let widest_when = notices.iter().map(|(when, ..)| when.chars().count()).max().unwrap_or(0);
        for (when, text, warning) in &notices {
            let mark = if *warning { "Warning: " } else { "" };
            lines.push(format!("  {when:<widest_when$}   {mark}{text}"));
        }
    }
    if let Some(notice) = found.get("notice").and_then(|value| value.as_str()).filter(|notice| !notice.is_empty()) {
        lines.push(notice.to_owned());
    }
    Some(lines)
}

/// One list in a grid's status: where it is, what it is called, and what each line says.
struct Section {
    list: &'static str,
    heading: &'static str,
    none: &'static str,
    /// The field a person recognises the entry by.
    name: &'static str,
    detail: fn(&serde_json::Value) -> String,
}

/// A grid's own lists, read for the noun that was asked about.
///
/// Every command that changes a computer, plan, key or desk takes its ID, because that is what the
/// grid's hub matches. Each line is the name a person recognises, then the ID the command needs,
/// aligned so either column can be read down. `None` when the answer holds no such list, such as
/// on a computer that is a member rather than the grid's host.
fn grid_lists(found: &serde_json::Value, noun: &str) -> Option<Vec<String>> {
    let hub = ["hub", "host"].into_iter().find_map(|key| found.get(key).filter(|hub| hub.is_object()))?;
    let sections: &[Section] = match noun {
        "computers" => &[Section { list: "members", heading: "Computers", none: "No computers have joined yet.", name: "name", detail: computer }],
        "share" => &[Section { list: "members", heading: "Computers, and what the grid may use of each", none: "No computers have joined yet.", name: "name", detail: share }],
        "models" => &[
            Section { list: "plans", heading: "Model plans", none: "No model plans yet.", name: "model", detail: plan },
            Section { list: "keys", heading: "API keys", none: "No API keys yet.", name: "name", detail: key },
            Section { list: "harnesses", heading: "Teams", none: "No teams yet.", name: "name", detail: team },
        ],
        "desks" => &[Section { list: "desks", heading: "Desks", none: "No desks yet.", name: "name", detail: desk }],
        _ => return None,
    };
    if !sections.iter().any(|section| hub.get(section.list).is_some_and(serde_json::Value::is_array)) {
        return None;
    }
    let text = |item: &serde_json::Value, key: &str| item.get(key).and_then(|value| value.as_str()).unwrap_or_default().to_owned();
    let mut lines = Vec::new();
    for section in sections {
        let items = hub.get(section.list).and_then(|value| value.as_array()).map(Vec::as_slice).unwrap_or_default();
        if items.is_empty() {
            lines.push(section.none.to_owned());
            continue;
        }
        lines.push(format!("{}:", section.heading));
        let widest = items.iter().map(|item| text(item, section.name).chars().count()).max().unwrap_or(0);
        let widest_id = items.iter().map(|item| text(item, "id").chars().count()).max().unwrap_or(0);
        for item in items {
            let line = format!("  {:<widest$}   {:<widest_id$}   {}", text(item, section.name), text(item, "id"), (section.detail)(item));
            lines.push(line.trim_end().to_owned());
        }
    }
    Some(lines)
}

fn computer(item: &serde_json::Value) -> String {
    let mut said = vec![if item.get("online").and_then(serde_json::Value::as_bool) == Some(true) { "online".to_owned() } else { "offline".to_owned() }];
    if item.get("excluded").and_then(serde_json::Value::as_bool) == Some(true) {
        said.push("drained".to_owned());
    }
    match item.get("desks").and_then(serde_json::Value::as_u64).unwrap_or(0) {
        0 => {}
        1 => said.push("hosting 1 desk".to_owned()),
        many => said.push(format!("hosting {many} desks")),
    }
    said.join(", ")
}

fn share(item: &serde_json::Value) -> String {
    let Some(share) = item.get("share").filter(|share| share.is_object()) else { return "nothing set yet".to_owned() };
    let number = |key: &str| {
        let value = share.get(key).and_then(serde_json::Value::as_f64).unwrap_or(0.0);
        if value.fract() == 0.0 { format!("{}", value as i64) } else { format!("{value:.1}") }
    };
    let mut said = format!("{} CPU, {} GB memory, {} GB disk", number("cpu"), number("memoryGb"), number("diskGb"));
    if share.get("gpu").and_then(serde_json::Value::as_bool) == Some(true) {
        said.push_str(", GPU");
    }
    if share.get("idleOnly").and_then(serde_json::Value::as_bool) == Some(true) {
        said.push_str(", only while nobody is using it");
    }
    if item.get("shareSet").and_then(serde_json::Value::as_bool) != Some(true) {
        said.push_str(" (suggested)");
    }
    said
}

fn plan(item: &serde_json::Value) -> String {
    let number = |key: &str| item.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0);
    format!("{} percent of the computers, {} of {} ready", number("percent"), number("ready"), number("target"))
}

fn key(item: &serde_json::Value) -> String {
    match item.get("prefix").and_then(|value| value.as_str()) {
        Some(prefix) if !prefix.is_empty() => format!("starts {prefix}"),
        _ => String::new(),
    }
}

fn team(item: &serde_json::Value) -> String {
    if item.get("ready").and_then(serde_json::Value::as_bool) == Some(true) { "ready".to_owned() } else { "waiting for its models".to_owned() }
}

fn desk(item: &serde_json::Value) -> String {
    let person = item.get("person").and_then(|value| value.as_str()).filter(|person| !person.is_empty()).unwrap_or("nobody");
    let state = item.get("state").and_then(|value| value.as_str()).unwrap_or_default();
    match item.get("note").and_then(|value| value.as_str()).filter(|note| !note.is_empty()) {
        Some(note) => format!("for {person}, {state}. {note}"),
        None => format!("for {person}, {state}"),
    }
}

/// How long ago `at` (Unix seconds) was, in words.
fn ago(at: i64, now: i64) -> String {
    match now - at {
        ..=59 => "just now".to_owned(),
        60..=119 => "a minute ago".to_owned(),
        120..=5399 => format!("{} minutes ago", (now - at + 30) / 60),
        5400..=129_599 => format!("{} hours ago", (now - at + 1800) / 3600),
        _ => format!("{} days ago", (now - at + 43_200) / 86_400),
    }
}

/// What a rented GPU is doing, in words rather than in the engine's own.
fn in_plain_words(state: &str) -> &'static str {
    match state {
        // The stop is owed and NeoCloud has not confirmed it: never "stopped" until it has.
        "stopping" => "being stopped",
        "available" => "ready for work",
        "busy" => "working",
        "outside_schedule" => "outside the hours its plan allows",
        "preparing" => "getting ready",
        "loading" => "loading its model",
        "starting" => "starting",
        "stopped" => "stopped",
        "idle" => "waiting for work",
        "error" => "needs attention",
        _ => "state unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::super::answer::{Answer, Change};
    use super::super::fault::{Code, Fault};
    use super::*;

    #[test]
    fn one_command_gives_both_outputs_and_the_choice_is_made_in_one_place() {
        assert_eq!(chosen(Some("json"), None, true), Format::Json);
        assert_eq!(chosen(Some("text"), None, false), Format::Words);
        assert_eq!(chosen(None, Some("json"), true), Format::Json);
        assert_eq!(chosen(Some("text"), Some("json"), false), Format::Words, "what was typed wins over the environment");
        assert_eq!(chosen(None, None, true), Format::Words);
        assert_eq!(chosen(None, None, false), Format::Json);
    }

    /// PROVES that the rented GPUs read as money and work rather than as a reply.
    ///
    /// Every line here is a pod somebody is paying for by the hour. The shape is an object, not
    /// a list, so it fell past the only thing `rows` knew how to read and the whole answer came
    /// out as nothing at all in a terminal — a status command that showed no status. The two
    /// facts worth having at a glance are what it costs and whether it is doing anything, and
    /// both are hard to find in nine fields per entry.
    #[test]
    fn rented_gpus_read_as_what_they_cost_and_what_they_are_doing() {
        let found = serde_json::json!({
            "hosting": true, "max": 8, "hourlyUsd": 3.51,
            "members": [
                {"name": "Render PC", "gpu": "NVIDIA RTX 4090", "gpuCount": 1, "hourlyUsd": 0.69, "state": "busy", "reason": ""},
                {"name": "Big", "gpu": "NVIDIA A100", "gpuCount": 2, "hourlyUsd": 2.82, "state": "stopped", "reason": "Start it in NeoCloud to use it again."},
            ],
            "candidates": [{"name": "Spare", "gpu": "NVIDIA H100", "gpuCount": 1, "hourlyUsd": 3.49}],
            "notice": null,
        });
        let lines = rows(&found);
        assert_eq!(lines[0], "2 of 8 rented GPUs in this grid, $3.51 an hour while they run.");
        assert_eq!(lines[1], "  Render PC   NVIDIA RTX 4090   $0.69 an hour   working");
        // The price column starts at the same place on both lines, which is the column somebody
        // reads down when they are working out what this is costing them.
        assert_eq!(lines[1].find("$0.69"), lines[2].find("$2.82"));
        assert_eq!(lines[2], "  Big         NVIDIA A100 x2    $2.82 an hour   stopped. Start it in NeoCloud to use it again.");
        assert_eq!(lines[3], "  Rented, not in this grid: Spare (NVIDIA H100, $3.49 an hour)");
        assert_eq!(lines.len(), 4, "a null notice is not a line: {lines:?}");

        // Nothing rented, and nothing running, each say so rather than showing an empty list.
        let empty = rows(&serde_json::json!({"max": 8, "hourlyUsd": 0.0, "members": [], "candidates": []}));
        assert_eq!(empty, ["No rented GPUs are in this grid."]);
        let resting = rows(&serde_json::json!({"max": 8, "hourlyUsd": 0.0, "members": [{"name": "Big", "gpu": "A100", "state": "stopped"}], "candidates": []}));
        assert_eq!(resting[0], "1 of 8 rented GPUs in this grid, none of them running.");
        assert!(resting[1].contains("price unknown"), "a price the engine did not send is said, not shown as $0.00: {resting:?}");

        // A state this build has not heard of is still a line, and never the engine's own word.
        let later = rows(&serde_json::json!({"max": 8, "members": [{"name": "New", "gpu": "A100", "state": "quiesced"}], "candidates": []}));
        assert!(later[1].ends_with("state unknown"), "{later:?}");
        // A sum that leaves out running pods with no recorded price is a floor, and said so.
        let floor = rows(&serde_json::json!({"max": 8, "hourlyUsd": 0.69, "unpriced": 1, "members": [{"name": "A", "gpu": "A100", "state": "busy"}, {"name": "B", "gpu": "A100", "hourlyUsd": 0.69, "state": "busy"}], "candidates": []}));
        assert_eq!(floor[0], "2 of 8 rented GPUs in this grid, at least $0.69 an hour while they run; NeoCloud has no price for 1 of them.");
        let unknown = rows(&serde_json::json!({"max": 8, "hourlyUsd": 0.0, "unpriced": 2, "members": [{"name": "A", "gpu": "A100", "state": "busy"}, {"name": "B", "gpu": "A100", "state": "busy"}], "candidates": []}));
        assert_eq!(unknown[0], "2 of 8 rented GPUs in this grid, price unknown while they run: NeoCloud has no price for 2 of them.", "never \"none of them running\"");
        // A stop NeoCloud has not confirmed is never "stopped".
        let owed = rows(&serde_json::json!({"max": 8, "members": [{"name": "Big", "gpu": "A100", "hourlyUsd": 2.82, "state": "stopping", "reason": "Yougori is stopping this pod and tries again until NeoCloud confirms it."}], "candidates": []}));
        assert!(owed[1].contains("an hour   being stopped. Yougori is stopping this pod") && !owed[1].contains("an hour   stopped"), "{owed:?}");

        // And the shapes this already read are untouched.
        assert_eq!(rows(&serde_json::json!([{"name": "Acme", "role": "host"}])), ["  Acme      host"]);
        // A list a refusal sends somebody to shows the identifier they are told to give.
        let listed = rows(&serde_json::json!([{"name": "Studio PC", "role": "capable", "memberId": "member-7f3a"}]));
        assert_eq!(listed, ["  Studio PC      capable   member-7f3a"]);
        // And an identifier that is only the name again is not shown twice.
        assert_eq!(rows(&serde_json::json!([{"name": "Acme", "id": "Acme"}])), ["  Acme"]);
        assert!(rows(&serde_json::json!({"anything": "else"})).is_empty());
    }

    /// PROVES that how the latest stops went reads newest first, with a pod that may still be
    /// billing marked, and that a computer hosting no grid offers nothing it would refuse.
    #[test]
    fn rented_gpu_stops_read_newest_first_and_a_grid_not_hosted_here_offers_nothing() {
        let now = 1_800_000_000;
        let found = serde_json::json!({
            "hosting": true, "max": 8, "hourlyUsd": 0.0,
            "members": [
                {"name": "Render", "gpu": "RTX 4090", "hourlyUsd": 0.69, "state": "stopped"},
                {"name": "Big", "gpu": "A100", "hourlyUsd": 12.5, "state": "error"},
            ],
            "candidates": [],
            "notices": [
                {"at": now - 7200, "text": "Pod B, the rented GPU of your Neo Grid, was stopped, so it is no longer billed.", "warning": false},
                {"at": now - 30, "text": "Pod A, the rented GPU of your Neo Grid, could not be stopped (timeout). Stop it in NeoCloud to end its billing; Yougori keeps trying.", "warning": true},
                {"at": now, "text": " ", "warning": false},
            ],
        });
        let (lines, left_out) = read(&found, now);
        assert!(!left_out);
        // Prices of different widths still leave the state column straight.
        assert_eq!(lines[1].find("stopped"), lines[2].find("needs attention"), "{lines:?}");
        assert_eq!(lines[3], "Recent stops, newest first:");
        assert_eq!(lines[4], "  just now      Warning: Pod A, the rented GPU of your Neo Grid, could not be stopped (timeout). Stop it in NeoCloud to end its billing; Yougori keeps trying.");
        assert_eq!(lines[5], "  2 hours ago   Pod B, the rented GPU of your Neo Grid, was stopped, so it is no longer billed.");
        assert_eq!(lines.len(), 6, "a notice with no text is not a line: {lines:?}");

        // No grid hosted here: its pods are kept to remove, and nothing is offered to add.
        let kept = serde_json::json!({
            "hosting": false, "max": 8, "hourlyUsd": 0.0,
            "members": [{"environmentId": "env-1", "name": "Render", "gpu": "RTX 4090", "hourlyUsd": 0.69, "state": "stopped"}],
            "candidates": [{"environmentId": "env-2", "name": "Spare", "gpu": "H100", "hourlyUsd": 3.49}],
        });
        let (lines, _) = read(&kept, now);
        assert_eq!(lines[0], "1 rented GPU is kept from a grid this computer no longer hosts, none of them running.");
        assert!(lines[1].contains("stopped and kept for you to remove") && lines[1].contains("remove-gpu ID --yes"), "{lines:?}");
        assert!(lines.iter().all(|line| !line.contains("Spare")), "a GPU it would refuse to add is not offered: {lines:?}");
        assert_eq!(ago(now - 90, now), "a minute ago");
        assert_eq!(ago(now - 3 * 86_400, now), "3 days ago");
    }

    /// PROVES that what a command hands over once reaches the person at a terminal.
    ///
    /// Each of these is the reason the command was run, and each arrives as an object, which the
    /// words view used to drop without a trace: an API key, a two-step secret, a token and a
    /// credential's value all came out as one sentence and nothing else.
    #[test]
    fn what_a_command_hands_over_once_is_shown_in_words() {
        let now = 1_000_000;
        let key = serde_json::json!({
            "key": {"id": "key-1", "name": "billing"}, "apiKey": "ygk_abc", "baseUrl": "https://grid.example:7443",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", "message": "Shown once. Apps call baseUrl.",
        });
        let (lines, left_out) = read(&key, now);
        assert_eq!(lines[0], "  API key: ygk_abc");
        assert_eq!(lines[1], "  Address: https://grid.example:7443");
        assert!(lines.iter().any(|line| line == "  -----BEGIN CERTIFICATE-----"), "{lines:?}");
        assert!(!lines.iter().any(|line| line.contains("baseUrl")), "a JSON field name is not words: {lines:?}");
        assert!(left_out, "the key's own record is still in JSON, and the person is told so");

        let (lines, left_out) = read(&serde_json::json!({"secret": "JBSWY3DP", "link": "otpauth://totp/Acme?secret=JBSWY3DP", "message": "Add it to your authenticator app."}), now);
        assert_eq!(lines, ["  Secret: JBSWY3DP", "  Authenticator link: otpauth://totp/Acme?secret=JBSWY3DP", "Add it to your authenticator app."]);
        assert!(!left_out);

        let (lines, left_out) = read(&serde_json::json!({"port": 7466, "token": "f00d", "already": false}), now);
        assert_eq!(lines, ["  Token: f00d", "  Port: 7466"]);
        assert!(!left_out);

        let (lines, _) = read(&serde_json::json!({"id": "req-7", "state": "done", "credential": "Stripe", "decidedBy": "grace", "value": "sk_live_1", "warning": "Rotate it when the task is done.", "expiresAt": now + 3600}), now);
        assert_eq!(lines, ["  Credential: Stripe", "  Value: sk_live_1", "  Request req-7: done, decided by grace", "  It expires in about 60 minutes.", "Rotate it when the task is done."]);

        let (lines, _) = read(&serde_json::json!({"value": {"accessKeyId": "AKIA1", "secretAccessKey": "s3", "sessionToken": "t0", "region": "eu-west-1"}}), now);
        assert_eq!(lines, ["  Access key ID: AKIA1", "  Secret access key: s3", "  Session token: t0", "  Region: eu-west-1"]);

        // Asking to see a credential waits for an approver; the ID to check back with is the answer.
        let (lines, _) = read(&serde_json::json!({"state": "waiting", "id": "req-9", "expiresAt": now + 600, "message": "An approver decides. Check back with the request ID."}), now);
        assert_eq!(lines, ["  Request req-9: waiting for an approver", "  It expires in about 10 minutes.", "An approver decides. Check back with the request ID."]);
    }

    /// PROVES that every refusal asking for an ID can be followed from the words view.
    ///
    /// The hubs match computers, plans, keys and desks by ID, and the words view showed none of
    /// them: "Name the computer" could not be done with anything on the screen.
    #[test]
    fn a_grids_lists_show_the_id_each_command_takes() {
        let status = serde_json::json!({"hub": {
            "members": [{"id": "m-1", "name": "Render PC", "online": true, "desks": 2}, {"id": "m-22", "name": "Old", "online": false, "excluded": true}],
            "plans": [{"id": "plan-1", "model": "hf.co/acme/chat", "percent": 50, "ready": 1, "target": 2}],
            "keys": [{"id": "key-1", "name": "billing", "prefix": "ygk_ab12"}],
            "harnesses": [],
            "desks": [{"id": "desk-1", "name": "Design", "person": "Ada", "state": "ready", "note": ""}],
        }});
        assert_eq!(grid_lists(&status, "computers").unwrap(), ["Computers:", "  Render PC   m-1    online, hosting 2 desks", "  Old         m-22   offline, drained"]);
        assert_eq!(
            grid_lists(&status, "models").unwrap(),
            ["Model plans:", "  hf.co/acme/chat   plan-1   50 percent of the computers, 1 of 2 ready", "API keys:", "  billing   key-1   starts ygk_ab12", "No teams yet."]
        );
        assert_eq!(grid_lists(&status, "desks").unwrap(), ["Desks:", "  Design   desk-1   for Ada, ready"]);
        // A member computer's status has no lists, and is left to the general reading.
        assert!(grid_lists(&serde_json::json!({"hub": null, "member": {}}), "computers").is_none());
        assert!(grid_lists(&status, "people").is_none());
        let answer = Answer::new("keen-heron-3f1a", "Acme: its computers.").found(status);
        let text = render_about(&answer, "computers");
        assert!(text.contains("\n  Render PC   m-1    online, hosting 2 desks\n"), "{text}");
        assert!(text.contains("Add --format json to see the whole answer."));

        // A rented GPU carries the ID adding or removing one takes.
        let rented = rows(&serde_json::json!({"max": 8, "hourlyUsd": 0.69, "members": [{"environmentId": "env-1", "name": "Render", "gpu": "RTX 4090", "hourlyUsd": 0.69, "state": "busy"}], "candidates": [{"environmentId": "env-2", "name": "Spare", "gpu": "H100", "hourlyUsd": 3.49}]}));
        assert_eq!(rented[1], "  Render   env-1   RTX 4090   $0.69 an hour   working");
        assert_eq!(rented[2], "  Rented, not in this grid: Spare (env-2, H100, $3.49 an hour)");
    }

    #[test]
    fn an_answer_the_words_cannot_show_says_where_it_is() {
        let answer = Answer::new("keen-heron-3f1a", "Acme: its waiting requests.").found(serde_json::json!({"waiting": [{"id": "req-1"}]}));
        assert!(render(&answer).contains("\nAdd --format json to see the whole answer.\n"));
        // A list somebody can read in full has nothing more to point to.
        let listed = Answer::new("keen-heron-3f1a", "One grid on this computer: Acme.").found(serde_json::json!([{"name": "Acme", "role": "host"}]));
        assert!(!render(&listed).contains("--format json"));
        // A list with lines the words cannot show points to JSON as well.
        let partly = Answer::new("keen-heron-3f1a", "Acme: its people.").found(serde_json::json!([{"name": "Ada"}, {"id": "p-2"}]));
        assert!(render(&partly).contains("Add --format json to see the whole answer."));
    }

    #[test]
    fn words_are_plain_lines_with_no_icons_and_no_boxes() {
        let answer = Answer::new("keen-heron-3f1a", "Running Qwen3-8B on half of Acme's computers.")
            .changed(vec![Change::new("model plan", "added", "Qwen3-8B").detail("50 percent, any time")])
            .next("Four computers take it at their next check-in.");
        let text = render(&answer);
        assert!(text.starts_with("Running Qwen3-8B on half of Acme's computers.\n"));
        assert!(text.contains("  added model plan Qwen3-8B   50 percent, any time"));
        assert!(text.ends_with("This command is called keen-heron-3f1a."));
        for forbidden in ['\u{2502}', '\u{250c}', '\u{2500}', '\u{2713}', '\u{2717}', '\u{2192}'] {
            assert!(!text.contains(forbidden), "{forbidden} has no place in this output");
        }
    }

    #[test]
    fn a_rehearsal_says_so_and_a_recorded_command_names_its_events() {
        let mut answer = Answer::new("wise-otter-00ab", "Ada Lovelace would be added.").rehearsed();
        assert!(render(&answer).contains("Nothing was changed: this was a rehearsal."));
        answer.rehearsed = false;
        answer.recorded = vec![412, 413];
        assert!(render(&answer).ends_with("Recorded as wise-otter-00ab, in events 412, 413."));
    }

    #[test]
    fn a_refusal_shows_the_sentence_and_the_code_only_when_it_is_asked_for() {
        let fault = Fault::new(Code::CapabilityOff, "This grid does not broker credentials.");
        assert_eq!(render_fault(&fault, false), "This grid does not broker credentials.");
        let explained = render_fault(&fault, true);
        assert!(explained.starts_with("This grid does not broker credentials.\n"));
        assert!(explained.contains("capability_off"));
    }
}
