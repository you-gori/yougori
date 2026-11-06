//! Swarm harnesses: one call to the grid's API puts a team of models on several computers.
//!
//! The admin names a harness, say `research`, and apps call the model `swarm/research` as they
//! would any other. A harness works in one of two ways, both from work on multi-agent systems:
//!
//! - **Plan** (a lead and its workers): the lead model splits the request into independent tasks,
//!   each with a brief that says what to produce and where to stop, so no two workers repeat each
//!   other. Workers solve the tasks at the same time, each in its own context, and the lead
//!   combines their results. A later round may fill the gaps the lead finds.
//! - **Mixture** (Mixture-of-Agents): several workers answer the same request and the lead writes
//!   one answer from all of them, which does better than picking the best of them. A second layer
//!   first lets the workers improve on each other's answers.
//!
//! Every computer serves one request at a time, so with `computers` requests in flight at most
//! that many computers work on one call. Work beyond that waits for the next free computer.
//!
//! Every request the team sends must also fit what a grid computer's model server takes (see
//! `SERVER_CHARACTERS` and the limits beside it). Results too long for one request are cut to
//! fit, and the trace says which.

use crate::{hub::plan_model, model_key, now, token};
use futures_util::{future::BoxFuture, stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Instant;

/// Apps call a harness as the model `swarm/NAME`.
pub const PREFIX: &str = "swarm/";
pub const MAX_HARNESSES: usize = 16;
pub const MAX_COMPUTERS: u8 = 32;
pub const MAX_TASKS: u8 = 32;
const MAX_WORKER_MODELS: usize = 8;
const BRIEF_LIMIT: usize = 4_000;
const PLAN_TOKENS: u32 = 1_200;
const WORKER_TOKENS: u32 = 2_048;
/// The final answer's length when the caller sets none: the most a grid model writes.
const FINAL_TOKENS: u32 = SERVER_MAX_TOKENS;

// What one chat request to a grid computer may carry. Every computer in a grid, an office
// computer or a rented NeoCloud pod, serves its model through Yougori's model server, which
// refuses a request past any of these limits: see `validate_chat` and `Handler.do_POST` in
// src-tauri/src/model_server.py, and keep these in step with them. (Swarm Mining's agent API
// raises the character and body limits; these are what every model server takes.)

/// The most tokens one answer may have: "max_tokens must be 1–4096".
pub const SERVER_MAX_TOKENS: u32 = 4_096;
/// The most characters in one request's messages: "Conversation exceeds 32,768 characters". It
/// counts each message's content and its tool calls as Python writes them, `[]` for none.
pub const SERVER_CHARACTERS: usize = 32_768;
/// The largest body of one request: "Send a JSON body of at most 64 KiB".
pub const SERVER_BODY_BYTES: usize = 64 * 1024;
/// The most messages in one request: "Provide 1–128 chat messages".
pub const SERVER_MESSAGES: usize = 128;
/// How the server begins its answer to any request it turns down, whether the request broke a
/// limit or overflowed the model's context window. It gives no reason, so the harness gives one.
const SERVER_REFUSAL: &str = "Invalid model request";

/// The harness fills a request to a little under the server's limits.
const CHARACTER_ROOM: usize = SERVER_CHARACTERS - 512;
const BYTE_ROOM: usize = SERVER_BODY_BYTES - 1_024;
/// What the team keeps of every request for its own instructions, briefs and results; an app's
/// request may have the rest.
const TEAM_CHARACTERS: usize = 8_192;
const TEAM_BYTES: usize = 16 * 1024;
/// How a result cut to fit ends, so the model reading it knows there was more.
const CUT: &str = "… [shortened]";
/// How much of the failed tasks' errors reaches the lead, each and all together, in characters.
const ERROR_LIMIT: usize = 160;
const MISSING_LIMIT: usize = 2_000;
/// No cap on the results beyond what the request has room for.
const UNCAPPED: (usize, usize) = (usize::MAX, usize::MAX);

const _: () = assert!(PLAN_TOKENS <= SERVER_MAX_TOKENS && WORKER_TOKENS <= SERVER_MAX_TOKENS);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Strategy {
    /// The lead splits the request into tasks for the workers and combines their results.
    Plan,
    /// Workers each answer the whole request and the lead synthesizes one answer.
    Mixture,
}

impl Strategy {
    fn max_rounds(self) -> u8 {
        match self {
            Strategy::Plan => 3,
            // A third layer tends to over-correct rather than improve.
            Strategy::Mixture => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Harness {
    pub id: String,
    /// Apps call `swarm/NAME`.
    pub name: String,
    pub strategy: Strategy,
    /// Plans and combines the work (plan), or writes the final answer (mixture).
    pub lead: String,
    /// The workers' models, taken in turn for each task.
    pub workers: Vec<String>,
    /// At most this many requests in flight, so at most this many computers on one call.
    pub computers: u8,
    /// Plan: at most this many tasks per round. Mixture: answers per layer.
    pub tasks: u8,
    /// Plan: rounds of tasks (1–3). Mixture: layers of answers (1–2).
    pub rounds: u8,
    pub created_at: i64,
}

impl Harness {
    /// Checks an admin's choices. Models are stored as the keys computers serve them under.
    pub fn new(name: &str, strategy: Strategy, lead: &str, workers: &[String], computers: u8, tasks: u8, rounds: u8) -> Result<Harness, String> {
        let name = name.trim().to_ascii_lowercase();
        let name = name.trim_start_matches(PREFIX).to_owned();
        if name.is_empty() || name.len() > 40 || name.starts_with('-') || name.ends_with('-') || !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return Err("Name the harness with 1–40 lowercase letters, digits and dashes, such as research".into());
        }
        let model = |raw: &str| -> Result<String, String> {
            let key = model_key(&plan_model(raw)?);
            if key.starts_with(PREFIX) {
                return Err("A harness runs models, not other harnesses".into());
            }
            Ok(key)
        };
        let lead = model(lead)?;
        let mut chosen: Vec<String> = Vec::new();
        for worker in workers {
            let key = model(worker)?;
            if !chosen.contains(&key) {
                chosen.push(key);
            }
        }
        if chosen.is_empty() || chosen.len() > MAX_WORKER_MODELS {
            return Err(format!("Choose 1–{MAX_WORKER_MODELS} worker models"));
        }
        if !(1..=MAX_COMPUTERS).contains(&computers) {
            return Err(format!("Choose 1–{MAX_COMPUTERS} computers"));
        }
        if !(1..=MAX_TASKS).contains(&tasks) {
            return Err(format!("Choose 1–{MAX_TASKS} {}", if strategy == Strategy::Plan { "tasks" } else { "answers" }));
        }
        if !(1..=strategy.max_rounds()).contains(&rounds) {
            return Err(format!("Choose 1–{} {}", strategy.max_rounds(), if strategy == Strategy::Plan { "rounds" } else { "layers" }));
        }
        Ok(Harness { id: format!("swarm-{}", &token()[..12]), name, strategy, lead, workers: chosen, computers, tasks, rounds, created_at: now() })
    }

    pub fn model(&self) -> String {
        format!("{PREFIX}{}", self.name)
    }

    /// Every model the harness needs a computer for.
    pub fn models(&self) -> Vec<String> {
        let mut models = vec![self.lead.clone()];
        models.extend(self.workers.iter().filter(|worker| **worker != self.lead).cloned());
        models
    }
}

/// One answer from a computer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Answer {
    pub text: String,
    /// The computer that answered, when known.
    pub computer: Option<String>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl Answer {
    /// Reads an OpenAI chat completion.
    pub fn from_completion(value: &Value, computer: Option<String>) -> Result<Answer, String> {
        let content = &value["choices"][0]["message"]["content"];
        let text = match content {
            Value::String(text) => text.clone(),
            Value::Array(parts) => parts.iter().filter_map(|part| part["text"].as_str()).collect::<Vec<_>>().join(""),
            _ => return Err(value["error"]["message"].as_str().unwrap_or("The model sent no answer").to_owned()),
        };
        let usage = &value["usage"];
        Ok(Answer { text, computer, prompt_tokens: usage["prompt_tokens"].as_u64().unwrap_or(0), completion_tokens: usage["completion_tokens"].as_u64().unwrap_or(0) })
    }
}

/// Sends one chat completion request to a computer running `model`.
pub trait Ask: Sync {
    fn ask<'a>(&'a self, model: &'a str, request: Value) -> BoxFuture<'a, Result<Answer, String>>;
}

/// What one call produced: the answer, and a record of who did what.
#[derive(Debug)]
pub struct Run {
    pub answer: String,
    pub trace: Value,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub title: String,
    pub brief: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub tasks: Vec<Task>,
    pub done: bool,
}

/// The conversation as plain text for the team: the user's message alone when that is all there
/// is, otherwise a transcript with the instructions first.
pub fn request_text(messages: &[Value]) -> Result<String, String> {
    let text = |message: &Value| match &message["content"] {
        Value::String(text) => text.trim().to_owned(),
        Value::Array(parts) => parts.iter().filter_map(|part| part["text"].as_str()).collect::<Vec<_>>().join("\n").trim().to_owned(),
        _ => String::new(),
    };
    let turns: Vec<(&str, String)> = messages.iter().map(|message| (message["role"].as_str().unwrap_or("user"), text(message))).filter(|(_, text)| !text.is_empty()).collect();
    if !turns.iter().any(|(role, _)| *role == "user") {
        return Err("Send at least one user message".into());
    }
    let system: Vec<&str> = turns.iter().filter(|(role, _)| matches!(*role, "system" | "developer")).map(|(_, text)| text.as_str()).collect();
    let chat: Vec<&(&str, String)> = turns.iter().filter(|(role, _)| !matches!(*role, "system" | "developer")).collect();
    let mut out = String::new();
    if !system.is_empty() {
        out.push_str(&format!("Instructions: {}\n\n", system.join("\n")));
    }
    if chat.len() == 1 {
        out.push_str(&chat[0].1);
    } else {
        for (role, text) in chat {
            out.push_str(&format!("{}: {text}\n\n", if *role == "assistant" { "Assistant" } else { "User" }));
        }
    }
    Ok(out.trim().to_owned())
}

/// The tasks a lead listed, read leniently: the JSON may sit in a code fence or among other
/// words, tasks may be plain strings, and anything past `max` is dropped.
pub fn parse_plan(text: &str, max: usize) -> Option<Plan> {
    let object = text.char_indices().filter(|(_, c)| *c == '{').find_map(|(start, _)| {
        let value = serde_json::Deserializer::from_str(&text[start..]).into_iter::<Value>().next()?.ok()?;
        (value.get("tasks").is_some() || value.get("done").is_some()).then_some(value)
    })?;
    let done = object["done"].as_bool().unwrap_or(false);
    let clip = |value: &str, limit: usize| value.trim().chars().take(limit).collect::<String>();
    let tasks = object["tasks"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, task)| {
            let (title, brief) = match task {
                Value::String(brief) => (String::new(), brief.clone()),
                Value::Object(_) => {
                    let field = |names: &[&str]| names.iter().find_map(|name| task[*name].as_str()).unwrap_or_default().to_owned();
                    (field(&["title", "name"]), field(&["brief", "instructions", "description", "task"]))
                }
                _ => return None,
            };
            let brief = clip(&brief, BRIEF_LIMIT);
            let title = clip(&title, 80);
            (!brief.is_empty()).then(|| Task { title: if title.is_empty() { format!("Task {}", index + 1) } else { title }, brief })
        })
        .take(max)
        .collect();
    Some(Plan { tasks, done })
}

fn plan_prompt(max: u8) -> String {
    format!(
        "You lead a team of AI workers, each running on its own computer. Split the user's request into independent tasks that the workers can do at the same time without seeing each other's work.\n\n\
         Rules:\n\
         - Use as few tasks as the request needs, at most {max}. A simple request needs one task.\n\
         - Split only work that is independent. If one part needs another part's result, keep them in one task.\n\
         - Give each task a brief a capable worker could follow alone: the objective, what to produce and in what form, and where to stop, so no two workers do the same work.\n\
         - Do not answer the request yourself.\n\n\
         Reply with only a JSON object, no other words:\n\
         {{\"tasks\": [{{\"title\": \"short name\", \"brief\": \"full instructions for one worker\"}}]}}"
    )
}

const WORKER_PROMPT: &str = "You are one worker on a team of AI models. Do only your task, thoroughly, in the form it asks for. Other workers handle the rest of the request, so do not do their parts or write an introduction or conclusion for the whole request.";

const COMBINE_PROMPT: &str = "You lead a team of AI workers. Each did one part of the user's request. Write the final answer to the request from their results: combine them into one coherent response, resolve contradictions, remove repetition and fill small gaps yourself. Answer the request directly; do not describe the team or how the work was split.";

/// Mixture-of-Agents: improve on several answers rather than pick one.
fn synthesis_prompt(answers: &[String]) -> String {
    let mut prompt = String::from(
        "You are given several responses from other AI models to the user's latest message. Write one answer of your own that is better than any of them: check each response critically, since some may be wrong or biased, keep what is correct and useful, and fix or drop the rest. Do not mention the other responses; reply to the user directly.\n\nResponses:",
    );
    for (index, answer) in answers.iter().enumerate() {
        prompt.push_str(&format!("\n\n{}. {answer}", index + 1));
    }
    prompt
}

/// A request for one answer written from `answers`: the instructions with the answers, then the
/// conversation as the caller sent it.
fn synthesis_request(answers: &[String], messages: &[Value], max_tokens: u32, temperature: f64) -> Value {
    let mut chat = vec![json!({"role": "system", "content": synthesis_prompt(answers)})];
    chat.extend(messages.iter().cloned());
    json!({"messages": chat, "max_tokens": max_tokens, "temperature": temperature, "stream": false})
}

fn request(system: &str, user: String, max_tokens: u32, temperature: f64) -> Value {
    json!({"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "max_tokens": max_tokens, "temperature": temperature, "stream": false})
}

/// `head`, then each result under its task's title as `shown`, then `tail`.
fn with_results(head: &str, results: &[(String, String)], shown: &[String], tail: &str) -> String {
    let mut ask = head.to_owned();
    for ((title, _), body) in results.iter().zip(shown) {
        ask.push_str(&format!("\n\n### {title}\n{body}"));
    }
    ask.push_str(tail);
    ask
}

/// Counts `messages` as the model server does: every message's content, its text parts joined by
/// newlines, and its tool calls as Python writes them (`[]` for none). Python's JSON is a little
/// longer than serde_json's, so tool calls are counted generously.
fn server_characters(messages: &[Value]) -> usize {
    messages
        .iter()
        .map(|message| {
            let content = match &message["content"] {
                Value::String(text) => text.chars().count(),
                Value::Array(parts) => parts.iter().map(|part| part["text"].as_str().map_or(0, |text| text.chars().count())).sum::<usize>() + parts.len().saturating_sub(1),
                _ => 0,
            };
            // Python puts a space after every `,` and `:` and writes `\uXXXX` for all but ASCII.
            let calls = message.get("tool_calls").map_or(2, |calls| {
                calls
                    .to_string()
                    .chars()
                    .map(|c| match c {
                        ',' | ':' => 2,
                        ' '..='~' => 1,
                        _ => 12,
                    })
                    .sum()
            });
            content + calls
        })
        .sum()
}

/// How many bytes `text` takes inside a JSON string, as serde_json writes it.
fn json_bytes(text: &str) -> usize {
    text.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            '\0'..='\u{1f}' => 6,
            c => c.len_utf8(),
        })
        .sum()
}

/// Why a grid computer would refuse `request` for its size, if it would. Such a request is never
/// sent.
fn oversized(request: &Value) -> Option<String> {
    let tokens = request["max_tokens"].as_u64().unwrap_or(0);
    if !(1..=u64::from(SERVER_MAX_TOKENS)).contains(&tokens) {
        return Some(format!("A grid model writes 1 to {} tokens in one answer, and this request asked for {}, so it was not sent.", grouped(SERVER_MAX_TOKENS as usize), grouped(tokens as usize)));
    }
    let messages = request["messages"].as_array().map_or(&[][..], Vec::as_slice);
    let (characters, bytes) = (server_characters(messages), request.to_string().len());
    (messages.len() > SERVER_MESSAGES || characters > SERVER_CHARACTERS || bytes > SERVER_BODY_BYTES).then(|| {
        format!(
            "This request is too long for a grid model: it has {} characters ({} KiB) in {} messages, and a grid model takes at most {} characters ({} KiB) in {SERVER_MESSAGES} messages, so it was not sent. Send a shorter request.",
            grouped(characters),
            bytes.div_ceil(1024),
            messages.len(),
            grouped(SERVER_CHARACTERS),
            SERVER_BODY_BYTES / 1024
        )
    })
}

/// The model server's refusal in words that say what to do; other errors already do. The team
/// keeps every request within the server's limits, so what is left is most often the model's
/// own context window.
fn plain(model: &str, tokens: u32, error: String) -> String {
    if !error.starts_with(SERVER_REFUSAL) {
        return error;
    }
    format!(
        "{model} could not take the request: with an answer of up to {} tokens it is probably more than the model's context window holds. Choose a model with a larger context window, send a shorter request, or ask for a shorter answer.",
        grouped(tokens as usize)
    )
}

/// Turns down at once a request too long for a team, rather than once the work is done: every
/// step sends a model the request along with the team's own instructions and results.
fn check_length(mixture: bool, text: &str, messages: &[Value]) -> Result<(), String> {
    // A mixture hands every model the conversation as sent, and the lead one message more.
    if mixture && messages.len() >= SERVER_MESSAGES {
        return Err(format!(
            "This conversation has {} messages, and a swarm takes at most {}: a grid model reads up to {SERVER_MESSAGES} at a time, and the team adds one of its own. Start a new chat, or send it to one of the grid's models directly.",
            messages.len(),
            SERVER_MESSAGES - 1
        ));
    }
    let (characters, bytes) = if mixture { (server_characters(messages), serde_json::to_vec(messages).map_or(usize::MAX, |body| body.len())) } else { (text.chars().count(), json_bytes(text)) };
    let (most_characters, most_bytes) = (CHARACTER_ROOM - TEAM_CHARACTERS, BYTE_ROOM - TEAM_BYTES);
    if characters <= most_characters && bytes <= most_bytes {
        return Ok(());
    }
    let (size, most) = if characters > most_characters {
        (format!("{} characters", grouped(characters)), format!("{} characters", grouped(most_characters)))
    } else {
        (format!("{} KiB", bytes.div_ceil(1024)), format!("{} KiB", most_bytes / 1024))
    };
    Err(format!(
        "This request is too long for a swarm: it is {size}, and a swarm takes at most {most}. A grid model reads up to {} characters ({} KiB) at a time, and the team needs the rest for its own instructions and the workers' results. Shorten the request, or send it to one of the grid's models directly.",
        grouped(SERVER_CHARACTERS),
        SERVER_BODY_BYTES / 1024
    ))
}

/// Shows `results` in the request `make` builds around them, cutting the longest just enough for
/// the request to fit what a grid computer takes, and for the results to take at most `most`
/// characters and bytes. Every result cut is cut to the same length, so a short result is never
/// cut to make room for a long one, and each keeps its place. Returns the results as shown and
/// the indices of those cut, or `None` when not even the request around them fits.
fn fit(results: &[(String, String)], most: (usize, usize), make: impl Fn(&[String]) -> Value) -> Option<(Vec<String>, Vec<usize>)> {
    let around = make(&vec![String::new(); results.len()]);
    let characters = CHARACTER_ROOM.checked_sub(server_characters(around["messages"].as_array()?))?.min(most.0);
    let bytes = BYTE_ROOM.checked_sub(around.to_string().len())?.min(most.1);
    let show = |keep: usize| results.iter().map(|(_, text)| cut(text, keep)).collect::<Vec<_>>();
    let fits = |shown: &[String]| shown.iter().map(|text| text.chars().count()).sum::<usize>() <= characters && shown.iter().map(|text| json_bytes(text)).sum::<usize>() <= bytes;
    if !fits(&show(0)) {
        return None;
    }
    // The most of each result that fits, found by halving; only what fits is ever kept.
    let (mut low, mut high) = (0, results.iter().map(|(_, text)| text.chars().count()).max().unwrap_or(0));
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if fits(&show(middle)) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let shown = show(low);
    let cut = (0..results.len()).filter(|&index| shown[index] != results[index].1).collect();
    Some((shown, cut))
}

/// The first `keep` characters of `text` and a mark that there was more, or all of it when that
/// would be no shorter.
fn cut(text: &str, keep: usize) -> String {
    if text.chars().count() <= keep + CUT.chars().count() {
        return text.to_owned();
    }
    let mut shown: String = text.chars().take(keep).collect();
    shown.push_str(CUT);
    shown
}

/// At most `limit` characters of `text`, ending in "…" when cut.
fn clip(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    format!("{}…", text.chars().take(limit.saturating_sub(1)).collect::<String>())
}

/// 32768 as "32,768".
fn grouped(number: usize) -> String {
    let digits = number.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// The names of the results at `indices`, each once, in order.
fn labels<'a>(results: &'a [(String, String)], indices: &[usize]) -> Vec<&'a str> {
    let mut labels: Vec<&str> = Vec::new();
    for &index in indices {
        if !labels.contains(&results[index].0.as_str()) {
            labels.push(&results[index].0);
        }
    }
    labels
}

/// "A", "A and B", "A, B and C"; past eight names, how many more.
fn names(labels: &[&str]) -> String {
    let mut words: Vec<String> = labels.iter().take(8).map(|label| label.to_string()).collect();
    if labels.len() > 8 {
        words.push(format!("{} more", labels.len() - 8));
    }
    match words.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    }
}

/// The note for a step that saw only the start of some results.
fn shortened(lead_in: &str, labels: &[&str]) -> String {
    format!("{lead_in}: {} did not fit whole in one request to a grid model, so only the start of {} was sent.", names(labels), if labels.len() == 1 { "it" } else { "each" })
}

/// Adds a sentence to the call's note, which says what the caller should know about how the
/// answer was made.
fn add_note(trace: &mut Value, sentence: &str) {
    let note = match trace["note"].as_str() {
        Some(earlier) => format!("{earlier} {sentence}"),
        None => sentence.to_owned(),
    };
    trace["note"] = json!(note);
}

/// One worker's part of a call, as the trace shows it.
struct Done {
    index: usize,
    title: String,
    brief: String,
    model: String,
    seconds: f64,
    result: Result<Answer, String>,
}

impl Done {
    fn trace(&self) -> Value {
        let mut entry = json!({"title": self.title, "model": self.model, "seconds": (self.seconds * 10.0).round() / 10.0});
        if !self.brief.is_empty() {
            entry["brief"] = json!(self.brief);
        }
        match &self.result {
            Ok(answer) => {
                entry["computer"] = json!(answer.computer);
                entry["answer"] = json!(answer.text.chars().take(600).collect::<String>());
            }
            Err(error) => entry["error"] = json!(error),
        }
        entry
    }
}

/// Runs work with at most `limit` requests in flight, keeping the order the work was given in.
async fn fan_out<A: Ask>(asker: &A, limit: u8, work: Vec<(String, String, String, Value)>) -> Vec<Done> {
    let mut done: Vec<Done> = stream::iter(work.into_iter().enumerate().map(|(index, (title, brief, model, request))| async move {
        let started = Instant::now();
        let result = send(asker, &model, request).await;
        Done { index, title, brief, model, seconds: started.elapsed().as_secs_f64(), result }
    }))
    .buffer_unordered(usize::from(limit.max(1)))
    .collect()
    .await;
    done.sort_by_key(|item| item.index);
    done
}

/// Counts tokens and remembers which computers took part.
#[derive(Default)]
struct Tally {
    prompt: u64,
    completion: u64,
    computers: Vec<String>,
}

impl Tally {
    fn add(&mut self, answer: &Answer) {
        self.prompt += answer.prompt_tokens;
        self.completion += answer.completion_tokens;
        if let Some(computer) = &answer.computer {
            if !self.computers.contains(computer) {
                self.computers.push(computer.clone());
            }
        }
    }
}

/// Answers `messages` with the team the harness describes.
pub async fn run<A: Ask>(harness: &Harness, asker: &A, messages: &[Value]) -> Result<Run, String> {
    run_with(harness, asker, messages, None).await
}

/// Whether any message carries something other than text (an image, audio, a file).
pub fn has_attachments(messages: &[Value]) -> bool {
    messages.iter().any(|message| message["content"].as_array().is_some_and(|parts| parts.iter().any(|part| part["type"].as_str().is_some_and(|kind| kind != "text"))))
}

/// The same, with the caller's cap on the final answer's length when they gave one.
pub async fn run_with<A: Ask>(harness: &Harness, asker: &A, messages: &[Value], final_tokens: Option<u32>) -> Result<Run, String> {
    let started = Instant::now();
    let text = request_text(messages)?;
    // A plan is written from the request's text alone; a request with images goes to every model
    // whole instead, so nothing the caller sent is left out.
    let mixture = harness.strategy == Strategy::Mixture || has_attachments(messages);
    check_length(mixture, &text, messages)?;
    let mut tally = Tally::default();
    let mut trace = json!({"harness": harness.model(), "strategy": harness.strategy, "lead": harness.lead, "workers": harness.workers, "computers": harness.computers});
    if harness.strategy == Strategy::Plan && mixture {
        add_note(&mut trace, "The request carries images or files, which a plan cannot split into tasks; the team answered it as a mixture, each model seeing the whole request.");
    }
    let asked = final_tokens.unwrap_or(FINAL_TOKENS);
    let final_tokens = asked.clamp(1, SERVER_MAX_TOKENS);
    if asked > SERVER_MAX_TOKENS {
        add_note(&mut trace, &format!("The answer was capped at {} tokens, the most a grid model writes in one reply; the request asked for {}.", grouped(SERVER_MAX_TOKENS as usize), grouped(asked as usize)));
    }
    let answer = if mixture {
        run_mixture(harness, asker, messages, final_tokens, &mut tally, &mut trace).await?
    } else {
        run_plan(harness, asker, &text, final_tokens, &mut tally, &mut trace).await?
    };
    trace["computersUsed"] = json!(tally.computers);
    trace["seconds"] = json!((started.elapsed().as_secs_f64() * 10.0).round() / 10.0);
    Ok(Run { answer, trace, prompt_tokens: tally.prompt, completion_tokens: tally.completion })
}

/// Sends `request` to a computer running `model`, unless the computer would refuse it for its
/// size; such a request is never sent.
async fn ask_within<A: Ask>(asker: &A, model: &str, request: Value) -> Result<Answer, String> {
    match oversized(&request) {
        Some(problem) => Err(problem),
        None => asker.ask(model, request).await,
    }
}

/// The same, with the model server's refusal put in words that say what to do.
async fn send<A: Ask>(asker: &A, model: &str, request: Value) -> Result<Answer, String> {
    let tokens = request["max_tokens"].as_u64().and_then(|tokens| u32::try_from(tokens).ok()).unwrap_or(0);
    ask_within(asker, model, request).await.map_err(|error| plain(model, tokens, error))
}

/// The lead's last step: the answer written from `results`, in a request `make` builds to fit a
/// grid computer, with the results cut if they must be (`lead_in` starts the note that says
/// which). A model that turns the request down gets one more, with half as much of the results
/// and a shorter answer: the request kept the server's limits, so most often it overflowed the
/// model's context window, and by now all the team's work is done.
async fn finish<A: Ask>(asker: &A, lead: &str, results: &[(String, String)], final_tokens: u32, trace: &mut Value, lead_in: &str, make: impl Fn(&[String], u32) -> Value) -> Result<Answer, String> {
    let (mut most, mut tokens, mut refused) = (UNCAPPED, final_tokens, None);
    loop {
        let Some((shown, cut)) = fit(results, most, |shown| make(shown, tokens)) else {
            return Err(refused.unwrap_or_else(|| "The request and the team's results do not fit in one request to a grid model, even with every result cut short. Send a shorter request, or use fewer tasks or rounds.".to_owned()));
        };
        match ask_within(asker, lead, make(&shown, tokens)).await {
            Ok(answer) => {
                if refused.is_some() {
                    add_note(trace, &format!("{lead} turned down the full request, most likely as too long for its context window, so it was asked again with half as much of the results and an answer of up to {} tokens.", grouped(tokens as usize)));
                }
                if !cut.is_empty() {
                    add_note(trace, &shortened(lead_in, &labels(results, &cut)));
                }
                return Ok(answer);
            }
            Err(error) if refused.is_none() && error.starts_with(SERVER_REFUSAL) => {
                refused = Some(plain(lead, tokens, error));
                most = (shown.iter().map(|text| text.chars().count()).sum::<usize>() / 2, shown.iter().map(|text| json_bytes(text)).sum::<usize>() / 2);
                tokens = tokens.min(SERVER_MAX_TOKENS / 2);
            }
            Err(error) => return Err(plain(lead, tokens, error)),
        }
    }
}

async fn run_plan<A: Ask>(harness: &Harness, asker: &A, text: &str, final_tokens: u32, tally: &mut Tally, trace: &mut Value) -> Result<String, String> {
    let mut rounds: Vec<Value> = Vec::new();
    let mut results: Vec<(String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    for round in 1..=harness.rounds {
        // What the trace should say about this round.
        let mut note = None;
        let ask = if round == 1 {
            request(&plan_prompt(harness.tasks), format!("Request:\n{text}"), PLAN_TOKENS, 0.2)
        } else {
            let head = format!("Request:\n{text}\n\nResults so far:");
            let tail = format!("\n\nIf these results already answer the request fully, reply {{\"done\": true, \"tasks\": []}}. Otherwise list only the tasks that fill the gaps, at most {}.", harness.tasks);
            let make = |shown: &[String]| request(&plan_prompt(harness.tasks), with_results(&head, &results, shown, &tail), PLAN_TOKENS, 0.2);
            let Some((shown, cut)) = fit(&results, UNCAPPED, make) else {
                rounds.push(json!({"round": round, "done": true, "note": "The results so far no longer fit in one request to a grid model, so the team combined them without planning more."}));
                break;
            };
            if !cut.is_empty() {
                note = Some(shortened("The lead planned this round from shortened results", &labels(&results, &cut)));
            }
            make(&shown)
        };
        let planned = match send(asker, &harness.lead, ask).await {
            Ok(planned) => planned,
            Err(error) if round == 1 => return Err(format!("The lead model could not plan: {error}")),
            // The results so far still make an answer.
            Err(error) => {
                rounds.push(json!({"round": round, "done": true, "note": format!("The lead could not plan another round, so the team combined the results it had. {error}")}));
                break;
            }
        };
        tally.add(&planned);
        let plan = parse_plan(&planned.text, usize::from(harness.tasks));
        let tasks = match plan {
            Some(plan) if plan.done && round > 1 => Vec::new(),
            Some(plan) if !plan.tasks.is_empty() => plan.tasks,
            // A first plan that cannot be read still answers: the whole request is one task. The
            // worker sees the request as context already, so the brief does not repeat it.
            _ if round == 1 => {
                note = Some("The lead's plan could not be read, so the request ran as one task.".to_owned());
                vec![Task { title: "Request".into(), brief: "Answer the whole request; no other worker has a part of it.".into() }]
            }
            _ => Vec::new(),
        };
        if tasks.is_empty() {
            let mut entry = json!({"round": round, "done": true, "planner": planned.computer});
            if let Some(note) = note {
                entry["note"] = json!(note);
            }
            rounds.push(entry);
            break;
        }
        let work = tasks
            .iter()
            .enumerate()
            .map(|(index, task)| {
                let model = harness.workers[(results.len() + index) % harness.workers.len()].clone();
                let user = format!("The team's request, for context:\n{text}\n\nYour task: {}\n{}", task.title, task.brief);
                (task.title.clone(), task.brief.clone(), model, request(WORKER_PROMPT, user, WORKER_TOKENS, 0.7))
            })
            .collect();
        let done = fan_out(asker, harness.computers, work).await;
        let mut entry = json!({"round": round, "planner": planned.computer, "tasks": done.iter().map(Done::trace).collect::<Vec<_>>()});
        if let Some(note) = note {
            entry["note"] = json!(note);
        }
        rounds.push(entry);
        let mut answered = 0;
        for item in done {
            match item.result {
                Ok(answer) => {
                    tally.add(&answer);
                    results.push((item.title, answer.text));
                    answered += 1;
                }
                Err(error) => failed.push((item.title, error)),
            }
        }
        if answered == 0 && results.is_empty() {
            trace["rounds"] = json!(rounds);
            return Err(format!("None of the workers answered. {}", failed.first().map(|(title, error)| format!("{title}: {error}")).unwrap_or_default()));
        }
    }
    trace["rounds"] = json!(rounds);
    let head = format!("Request:\n{text}\n\nWorkers' results:");
    let missing = if failed.is_empty() {
        String::new()
    } else {
        let tasks: Vec<String> = failed.iter().map(|(title, error)| format!("{title}: {}", clip(error, ERROR_LIMIT))).collect();
        format!("\n\nThese tasks got no result; cover them briefly yourself if you can: {}", clip(&tasks.join("; "), MISSING_LIMIT))
    };
    let combined = finish(asker, &harness.lead, &results, final_tokens, trace, "The lead combined shortened results", |shown, tokens| {
        request(COMBINE_PROMPT, with_results(&head, &results, shown, &missing), tokens, 0.3)
    })
    .await
    .map_err(|error| format!("The lead model could not combine the results: {error}"))?;
    tally.add(&combined);
    trace["final"] = json!({"model": harness.lead, "computer": combined.computer});
    Ok(combined.text)
}

async fn run_mixture<A: Ask>(harness: &Harness, asker: &A, messages: &[Value], final_tokens: u32, tally: &mut Tally, trace: &mut Value) -> Result<String, String> {
    let mut layers: Vec<Value> = Vec::new();
    // Each answer under the name the trace shows it by.
    let mut answers: Vec<(String, String)> = Vec::new();
    for layer in 1..=harness.rounds {
        let mut note = None;
        // From the second layer on, each worker improves on the previous layer's answers, shown
        // to fit one request. The temperatures all take the same room.
        let shown = if answers.is_empty() {
            None
        } else {
            let Some((shown, cut)) = fit(&answers, UNCAPPED, |shown| synthesis_request(shown, messages, WORKER_TOKENS, 0.9)) else { break };
            if !cut.is_empty() {
                note = Some(shortened("The workers improved on shortened answers", &labels(&answers, &cut)));
            }
            Some(shown)
        };
        let work = (0..usize::from(harness.tasks))
            .map(|index| {
                let model = harness.workers[index % harness.workers.len()].clone();
                // Different temperatures give the lead different answers to work with.
                let temperature = [0.7, 0.9, 0.5][index % 3];
                let request = match &shown {
                    Some(shown) => synthesis_request(shown, messages, WORKER_TOKENS, temperature),
                    None => json!({"messages": messages, "max_tokens": WORKER_TOKENS, "temperature": temperature, "stream": false}),
                };
                (format!("Answer {}", index + 1), String::new(), model, request)
            })
            .collect();
        let done = fan_out(asker, harness.computers, work).await;
        let mut entry = json!({"layer": layer, "answers": done.iter().map(Done::trace).collect::<Vec<_>>()});
        let first_error = done.iter().find_map(|item| item.result.as_ref().err().map(|error| format!("{}: {error}", item.title))).unwrap_or_default();
        let next: Vec<(String, String)> = done
            .into_iter()
            .filter_map(|item| {
                item.result.ok().map(|answer| {
                    tally.add(&answer);
                    (item.title, answer.text)
                })
            })
            .collect();
        if next.is_empty() && answers.is_empty() {
            layers.push(entry);
            trace["layers"] = json!(layers);
            return Err(format!("None of the workers answered. {first_error}").trim_end().to_owned());
        }
        if next.is_empty() {
            // The earlier layer's answers still make an answer.
            entry["note"] = json!(format!("No worker could improve on the earlier answers, so the lead wrote the answer from those. {first_error}").trim_end());
            layers.push(entry);
            break;
        }
        if let Some(note) = note {
            entry["note"] = json!(note);
        }
        layers.push(entry);
        answers = next;
    }
    trace["layers"] = json!(layers);
    let combined = finish(asker, &harness.lead, &answers, final_tokens, trace, "The lead wrote the answer from shortened answers", |shown, tokens| synthesis_request(shown, messages, tokens, 0.3))
        .await
        .map_err(|error| format!("The lead model could not write the answer: {error}"))?;
    tally.add(&combined);
    trace["final"] = json!({"model": harness.lead, "computer": combined.computer});
    Ok(combined.text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use std::time::Duration;

    /// What the model server answers any request it turns down with (model_server.py, `do_POST`).
    const REFUSED: &str = "Invalid model request. Check message roles, content, context length and generation settings.";

    /// A team that answers by role: the lead plans with `plan` and combines; workers name their task.
    struct Team {
        plan: Vec<String>,
        planned: AtomicUsize,
        running: AtomicUsize,
        most: AtomicUsize,
        calls: Mutex<Vec<(String, Value)>>,
        fail: Vec<&'static str>,
        /// Added to every worker's answer but those for the tasks in `short`.
        pad: String,
        short: Vec<&'static str>,
        /// Like a model's context window: longer requests are turned down as the server does.
        context: usize,
    }

    impl Team {
        fn new(plan: &[&str]) -> Team {
            Team {
                plan: plan.iter().map(|plan| plan.to_string()).collect(),
                planned: AtomicUsize::new(0),
                running: AtomicUsize::new(0),
                most: AtomicUsize::new(0),
                calls: Mutex::new(Vec::new()),
                fail: Vec::new(),
                pad: String::new(),
                short: Vec::new(),
                context: usize::MAX,
            }
        }
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    /// The characters in a request's messages.
    fn length(request: &Value) -> usize {
        request["messages"].as_array().unwrap().iter().map(|message| message["content"].as_str().unwrap_or_default().chars().count()).sum()
    }

    /// Whether the model server would take `request`, counted here apart from the harness, with the
    /// limits written as model_server.py writes them.
    fn the_server_takes(request: &Value) -> bool {
        let messages = request["messages"].as_array().unwrap();
        let tokens = request["max_tokens"].as_u64().unwrap();
        messages.len() <= 128 && length(request) + 2 * messages.len() <= 32_768 && serde_json::to_vec(request).unwrap().len() <= 65_536 && (1..=4096).contains(&tokens)
    }

    impl Ask for Team {
        fn ask<'a>(&'a self, model: &'a str, request: Value) -> BoxFuture<'a, Result<Answer, String>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push((model.to_owned(), request.clone()));
                if length(&request) > self.context {
                    return Err(REFUSED.to_owned());
                }
                let system = request["messages"][0]["content"].as_str().unwrap_or_default().to_owned();
                let user = request["messages"].as_array().unwrap().last().unwrap()["content"].as_str().unwrap_or_default().to_owned();
                let text = if system.contains("Reply with only a JSON object") {
                    let round = self.planned.fetch_add(1, Ordering::SeqCst);
                    self.plan.get(round).cloned().unwrap_or_else(|| r#"{"done": true, "tasks": []}"#.into())
                } else if system == WORKER_PROMPT {
                    let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
                    self.most.fetch_max(running, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    self.running.fetch_sub(1, Ordering::SeqCst);
                    let task = user.split("Your task: ").nth(1).unwrap_or_default().lines().next().unwrap_or_default().to_owned();
                    if self.fail.iter().any(|failing| task == *failing) {
                        return Err(format!("{task} timed out"));
                    }
                    format!("result of {task}{}", if self.short.contains(&task.as_str()) { "" } else { self.pad.as_str() })
                } else if system == COMBINE_PROMPT || system.starts_with("You are given several responses") && model == "acme/lead" {
                    format!("FINAL from {model}")
                } else {
                    let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
                    self.most.fetch_max(running, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    self.running.fetch_sub(1, Ordering::SeqCst);
                    format!("answer from {model} at {}{}", request["temperature"], self.pad)
                };
                Ok(Answer { text, computer: Some(format!("pc-{}", model.len())), prompt_tokens: 10, completion_tokens: 5 })
            })
        }
    }

    fn harness(strategy: Strategy, computers: u8, tasks: u8, rounds: u8) -> Harness {
        Harness::new("research", strategy, "acme/lead", &["acme/worker-a".into(), "acme/worker-bb".into()], computers, tasks, rounds).unwrap()
    }

    fn ask(text: &str) -> Vec<Value> {
        vec![json!({"role": "user", "content": text})]
    }

    #[tokio::test]
    async fn the_lead_splits_the_work_and_workers_share_the_computers_it_is_given() {
        let plan = r#"Here is the plan:
```json
{"tasks": [{"title": "Prices", "brief": "List prices."}, {"title": "Risks", "brief": "List risks."}, {"title": "Rivals", "brief": "Name rivals."}, {"title": "Costs", "brief": "Sum costs."}, {"title": "Hiring", "brief": "Plan hiring."}]}
```"#;
        let team = Team::new(&[plan]);
        let run = run(&harness(Strategy::Plan, 2, 8, 1), &team, &ask("Should we open a shop in Lyon?")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        assert_eq!(team.most.load(Ordering::SeqCst), 2, "never more requests in flight than computers");
        let calls = team.calls();
        let workers: Vec<&str> = calls.iter().filter(|(_, request)| request["messages"][0]["content"] == WORKER_PROMPT).map(|(model, _)| model.as_str()).collect();
        assert_eq!(workers.len(), 5);
        assert_eq!(workers.iter().filter(|model| **model == "acme/worker-a").count(), 3, "worker models take turns");
        // Each worker sees only its own brief; the lead sees every result.
        let combine = &calls.last().unwrap().1["messages"][1]["content"];
        for title in ["Prices", "Risks", "Rivals", "Costs", "Hiring"] {
            assert!(combine.as_str().unwrap().contains(&format!("### {title}\nresult of {title}")), "{title}");
        }
        let tasks = run.trace["rounds"][0]["tasks"].as_array().unwrap();
        assert_eq!(tasks.iter().map(|task| task["title"].as_str().unwrap()).collect::<Vec<_>>(), ["Prices", "Risks", "Rivals", "Costs", "Hiring"], "in the lead's order");
        assert_eq!(run.prompt_tokens, 70, "the plan, five tasks and the final answer");
        assert!(run.trace["computersUsed"].as_array().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn the_plan_never_exceeds_the_task_limit_and_a_simple_request_stays_whole() {
        let many = json!({"tasks": (1..=9).map(|n| json!({"title": format!("T{n}"), "brief": "x"})).collect::<Vec<_>>()}).to_string();
        let team = Team::new(&[&many]);
        let run = run(&harness(Strategy::Plan, 4, 3, 1), &team, &ask("Big job")).await.unwrap();
        assert_eq!(run.trace["rounds"][0]["tasks"].as_array().unwrap().len(), 3);
        // A lead that answers instead of planning still gets the request answered, as one task.
        let team = Team::new(&["Sure! Lyon is a fine city."]);
        let run = super::run(&harness(Strategy::Plan, 4, 3, 1), &team, &ask("Hi")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        assert_eq!(run.trace["rounds"][0]["tasks"][0]["title"], "Request");
        assert!(run.trace["rounds"][0]["note"].as_str().unwrap().contains("could not be read"));
    }

    #[tokio::test]
    async fn a_second_round_fills_gaps_only_when_the_lead_finds_some() {
        let first = r#"{"tasks": [{"title": "Draft", "brief": "Write a draft."}]}"#;
        let gaps = r#"{"tasks": [{"title": "Sources", "brief": "Find sources."}]}"#;
        let team = Team::new(&[first, gaps]);
        let run = run(&harness(Strategy::Plan, 2, 4, 3), &team, &ask("Write a report")).await.unwrap();
        let rounds = run.trace["rounds"].as_array().unwrap();
        assert_eq!(rounds.len(), 3, "two rounds of work, then the lead says done");
        assert_eq!(rounds[2]["done"], true);
        let replan = &team.calls()[2].1["messages"][1]["content"];
        assert!(replan.as_str().unwrap().contains("### Draft\nresult of Draft"), "the lead sees earlier results before planning again");
        let combine = team.calls().last().unwrap().1["messages"][1]["content"].as_str().unwrap().to_owned();
        assert!(combine.contains("result of Draft") && combine.contains("result of Sources"));
    }

    #[tokio::test]
    async fn failed_tasks_are_reported_and_the_answer_comes_from_the_rest() {
        let plan = r#"{"tasks": [{"title": "Good", "brief": "a"}, {"title": "Bad", "brief": "b"}]}"#;
        let mut team = Team::new(&[plan]);
        team.fail = vec!["Bad"];
        let run = run(&harness(Strategy::Plan, 2, 4, 1), &team, &ask("Do it")).await.unwrap();
        assert_eq!(run.trace["rounds"][0]["tasks"][1]["error"], "Bad timed out");
        let combine = team.calls().last().unwrap().1["messages"][1]["content"].as_str().unwrap().to_owned();
        assert!(combine.contains("got no result") && combine.contains("Bad: Bad timed out"));
        let mut team = Team::new(&[r#"{"tasks": [{"title": "Bad", "brief": "b"}]}"#]);
        team.fail = vec!["Bad"];
        assert!(super::run(&harness(Strategy::Plan, 2, 4, 1), &team, &ask("Do it")).await.unwrap_err().contains("None of the workers answered"));
    }

    #[tokio::test]
    async fn a_mixture_answers_in_parallel_then_refines_and_the_lead_synthesizes() {
        let team = Team::new(&[]);
        let run = run(&harness(Strategy::Mixture, 3, 3, 2), &team, &ask("Name a colour")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        assert_eq!(team.most.load(Ordering::SeqCst), 3);
        let calls = team.calls();
        assert_eq!(calls.len(), 7, "three answers, three refinements, one synthesis");
        assert_eq!(calls[0].1["messages"].as_array().unwrap().len(), 1, "the first layer answers the request as sent");
        let refine = calls[3].1["messages"][0]["content"].as_str().unwrap();
        assert!(refine.starts_with("You are given several responses") && refine.contains("1. answer from"), "the second layer sees the first layer's answers");
        assert_ne!(calls[0].1["temperature"], calls[1].1["temperature"], "answers differ in temperature");
        assert_eq!(run.trace["layers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn plans_are_read_from_messy_replies() {
        let fenced = "Sure.\n```json\n{\"tasks\": [\"Find the date\", {\"name\": \"Map\", \"instructions\": \"Draw it\"}, {\"title\": \"Empty\", \"brief\": \"  \"}]}\n```\nDone.";
        let plan = parse_plan(fenced, 8).unwrap();
        assert_eq!(plan.tasks, [Task { title: "Task 1".into(), brief: "Find the date".into() }, Task { title: "Map".into(), brief: "Draw it".into() }]);
        assert_eq!(parse_plan("{\"done\": true}", 8).unwrap(), Plan { tasks: Vec::new(), done: true });
        assert_eq!(parse_plan("no plan here {not json}", 8), None);
        assert_eq!(parse_plan("{\"a\": 1} then {\"tasks\": [\"x\"]}", 8).unwrap().tasks.len(), 1, "the first object with tasks wins");
    }

    #[test]
    fn the_request_reaches_the_team_as_text() {
        assert_eq!(request_text(&ask("Hello")).unwrap(), "Hello");
        let chat = vec![
            json!({"role": "system", "content": "Be brief."}),
            json!({"role": "user", "content": [{"type": "text", "text": "Hi"}]}),
            json!({"role": "assistant", "content": "Hello!"}),
            json!({"role": "user", "content": "And now?"}),
        ];
        assert_eq!(request_text(&chat).unwrap(), "Instructions: Be brief.\n\nUser: Hi\n\nAssistant: Hello!\n\nUser: And now?");
        assert!(request_text(&[json!({"role": "system", "content": "x"})]).is_err());
    }

    #[test]
    fn harness_choices_are_checked() {
        let workers = vec!["hf.co/Acme/Worker".to_owned(), "acme/worker".to_owned()];
        let made = Harness::new(" Swarm/Research ", Strategy::Plan, "hf.co/Acme/Lead", &workers, 5, 8, 2).unwrap();
        assert_eq!((made.name.as_str(), made.lead.as_str(), made.workers.as_slice()), ("research", "acme/lead", &["acme/worker".to_owned()][..]));
        assert_eq!(made.model(), "swarm/research");
        assert_eq!(made.models(), ["acme/lead", "acme/worker"]);
        for name in ["", "-x", "x-", "has space", "Ünï", &"a".repeat(41)] {
            assert!(Harness::new(name, Strategy::Plan, "acme/lead", &workers, 5, 8, 1).is_err(), "{name}");
        }
        assert!(Harness::new("r", Strategy::Plan, "swarm/other", &workers, 5, 8, 1).unwrap_err().contains("not other harnesses"));
        assert!(Harness::new("r", Strategy::Plan, "acme/lead", &[], 5, 8, 1).is_err());
        assert!(Harness::new("r", Strategy::Plan, "acme/lead", &workers, 0, 8, 1).is_err());
        assert!(Harness::new("r", Strategy::Plan, "acme/lead", &workers, 33, 8, 1).is_err());
        assert!(Harness::new("r", Strategy::Plan, "acme/lead", &workers, 5, 0, 1).is_err());
        assert!(Harness::new("r", Strategy::Plan, "acme/lead", &workers, 5, 8, 4).is_err());
        assert!(Harness::new("r", Strategy::Mixture, "acme/lead", &workers, 5, 8, 3).unwrap_err().contains("layers"), "a third layer over-corrects");
    }

    fn five_tasks() -> String {
        let tasks: Vec<Value> = ["Prices", "Risks", "Rivals", "Costs", "Hiring"].iter().map(|title| json!({"title": title, "brief": "Do it."})).collect();
        json!({ "tasks": tasks }).to_string()
    }

    #[tokio::test]
    async fn the_answer_never_asks_a_grid_model_for_more_tokens_than_it_writes() {
        let plan = r#"{"tasks": [{"title": "Prices", "brief": "List prices."}]}"#;
        let team = Team::new(&[plan]);
        let run = run_with(&harness(Strategy::Plan, 2, 4, 1), &team, &ask("Price it"), Some(32_768)).await.unwrap();
        let calls = team.calls();
        assert!(calls.iter().all(|(_, request)| the_server_takes(request)), "no request a grid model would refuse");
        assert_eq!(calls.last().unwrap().1["max_tokens"], 4096);
        assert!(run.trace["note"].as_str().unwrap().contains("capped at 4,096 tokens, the most a grid model writes in one reply; the request asked for 32,768."));
        // A smaller cap is the caller's to set; without one, the answer may be as long as a grid model writes.
        let team = Team::new(&[]);
        run_with(&harness(Strategy::Mixture, 2, 2, 1), &team, &ask("Price it"), Some(300)).await.unwrap();
        assert_eq!(team.calls().last().unwrap().1["max_tokens"], 300);
        let team = Team::new(&[plan]);
        let run = super::run(&harness(Strategy::Plan, 2, 4, 1), &team, &ask("Price it")).await.unwrap();
        assert_eq!(team.calls().last().unwrap().1["max_tokens"], 4096);
        assert!(run.trace.get("note").is_none(), "nothing to tell");
    }

    #[tokio::test]
    async fn long_results_are_cut_to_fit_one_request_and_the_trace_says_which() {
        let mut team = Team::new(&[&five_tasks()]);
        team.pad = "x".repeat(15_000);
        team.short = vec!["Costs"];
        let run = run(&harness(Strategy::Plan, 5, 5, 1), &team, &ask("Should we open a shop in Lyon?")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead", "the work done still makes an answer");
        let calls = team.calls();
        assert!(calls.iter().all(|(_, request)| the_server_takes(request)), "no request a grid model would refuse");
        let combine = &calls.last().unwrap().1;
        assert!(length(combine) > 30_000, "the room is used, not wasted: {}", length(combine));
        // Every result keeps its title and its place; the short one is whole and the long ones are cut alike.
        let text = combine["messages"][1]["content"].as_str().unwrap();
        let starts: Vec<usize> = ["Prices", "Risks", "Rivals", "Costs", "Hiring"].iter().map(|title| text.find(&format!("### {title}\nresult of {title}")).unwrap()).collect();
        assert!(starts.windows(2).all(|pair| pair[0] < pair[1]), "in the lead's order");
        assert!(text.contains("### Costs\nresult of Costs\n\n### Hiring"), "a short result is never cut for a long one");
        let cut: Vec<usize> = text.split("\n\n### ").skip(1).map(|part| part.split_once('\n').unwrap().1).filter(|body| body.ends_with(CUT)).map(|body| body.chars().count()).collect();
        assert_eq!(cut.len(), 4);
        assert!(cut.iter().all(|length| *length == cut[0]), "long results get equal shares: {cut:?}");
        let note = run.trace["note"].as_str().unwrap();
        assert_eq!(note, "The lead combined shortened results: Prices, Risks, Rivals and Hiring did not fit whole in one request to a grid model, so only the start of each was sent.");
    }

    #[tokio::test]
    async fn a_mixture_shows_long_answers_cut_alike_in_every_layer_and_says_so() {
        let mut team = Team::new(&[]);
        team.pad = "y".repeat(12_000);
        let run = run(&harness(Strategy::Mixture, 4, 4, 2), &team, &ask("Name a colour")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        let calls = team.calls();
        assert_eq!(calls.len(), 9, "four answers, four refinements, one synthesis");
        assert!(calls.iter().all(|(_, request)| the_server_takes(request)), "no request a grid model would refuse");
        let synthesis = calls.last().unwrap().1["messages"][0]["content"].as_str().unwrap();
        for number in 1..=4 {
            assert!(synthesis.contains(&format!("\n\n{number}. answer from")), "answer {number} keeps its place");
        }
        assert_eq!(synthesis.matches(CUT).count(), 4);
        assert!(run.trace["layers"][1]["note"].as_str().unwrap().starts_with("The workers improved on shortened answers: Answer 1, Answer 2, Answer 3 and Answer 4 did not fit whole"));
        assert!(run.trace["note"].as_str().unwrap().starts_with("The lead wrote the answer from shortened answers: Answer 1, Answer 2, Answer 3 and Answer 4 did not fit whole"));
    }

    #[tokio::test]
    async fn results_in_wide_characters_are_cut_to_the_bytes_a_grid_model_reads() {
        let plan = r#"{"tasks": [{"title": "Prices", "brief": "a"}, {"title": "Risks", "brief": "b"}, {"title": "Rivals", "brief": "c"}]}"#;
        let mut team = Team::new(&[plan]);
        // Three bytes a character: each result has fewer characters than a request holds, but
        // more bytes than a third of one.
        team.pad = "語".repeat(9_000);
        let run = run(&harness(Strategy::Plan, 3, 3, 1), &team, &ask("東京に店を開くべきか")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        let calls = team.calls();
        assert!(calls.iter().all(|(_, request)| the_server_takes(request)), "no request a grid model would refuse");
        let combine = &calls.last().unwrap().1;
        assert!(length(combine) < 25_000 && serde_json::to_vec(combine).unwrap().len() > 60_000, "bytes are what limit it");
        assert_eq!(combine["messages"][1]["content"].as_str().unwrap().matches(CUT).count(), 3);
    }

    #[tokio::test]
    async fn a_request_too_long_for_a_team_is_turned_down_before_any_work() {
        let team = Team::new(&[]);
        let error = run(&harness(Strategy::Plan, 2, 2, 1), &team, &ask(&"x".repeat(30_000))).await.unwrap_err();
        assert!(error.starts_with("This request is too long for a swarm: it is 30,000 characters, and a swarm takes at most 24,064 characters."), "{error}");
        assert!(error.ends_with("Shorten the request, or send it to one of the grid's models directly."), "{error}");
        // Wide characters run out of bytes first.
        let error = run(&harness(Strategy::Mixture, 2, 2, 1), &team, &ask(&"語".repeat(20_000))).await.unwrap_err();
        assert!(error.starts_with("This request is too long for a swarm: it is 59 KiB, and a swarm takes at most 47 KiB."), "{error}");
        // A mixture adds a message of its own to the conversation.
        let chat: Vec<Value> = (0..128).map(|index| json!({"role": if index % 2 == 0 { "user" } else { "assistant" }, "content": "Hi"})).collect();
        let error = run(&harness(Strategy::Mixture, 2, 2, 1), &team, &chat).await.unwrap_err();
        assert!(error.starts_with("This conversation has 128 messages, and a swarm takes at most 127"), "{error}");
        assert!(team.calls().is_empty(), "no computer did work that could not be combined");
        // A request that leaves the team its room runs.
        assert!(run(&harness(Strategy::Plan, 2, 2, 1), &team, &ask(&"x".repeat(24_000))).await.is_ok());
        assert!(team.calls().iter().all(|(_, request)| the_server_takes(request)));
    }

    #[tokio::test]
    async fn a_lead_that_turns_the_request_down_gets_a_smaller_one_before_the_call_fails() {
        // The lead's model holds 20,000 characters, and the results come to 40,000.
        let mut team = Team::new(&[&five_tasks()]);
        team.pad = "x".repeat(8_000);
        team.context = 20_000;
        let run = run(&harness(Strategy::Plan, 5, 5, 1), &team, &ask("Should we open a shop in Lyon?")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        let calls = team.calls();
        let finals: Vec<&Value> = calls.iter().map(|(_, request)| request).filter(|request| request["messages"][0]["content"] == COMBINE_PROMPT).collect();
        assert_eq!(finals.len(), 2, "one more request after the refusal");
        assert!(length(finals[1]) < length(finals[0]) / 2 + 1_000 && finals[1]["max_tokens"] == 2048);
        let note = run.trace["note"].as_str().unwrap();
        assert!(note.contains("acme/lead turned down the full request, most likely as too long for its context window, so it was asked again with half as much of the results and an answer of up to 2,048 tokens."), "{note}");
        assert!(note.contains("The lead combined shortened results: Prices, Risks, Rivals, Costs and Hiring did not fit whole"), "{note}");

        // A lead that turns the smaller one down too ends the call in words that say what to do.
        let mut team = Team::new(&[r#"{"tasks": [{"title": "Draft", "brief": "Write it."}]}"#]);
        team.pad = "x".repeat(4_000);
        team.context = 2_000;
        let error = super::run(&harness(Strategy::Plan, 2, 2, 1), &team, &ask("Write a report")).await.unwrap_err();
        assert_eq!(error, "The lead model could not combine the results: acme/lead could not take the request: with an answer of up to 2,048 tokens it is probably more than the model's context window holds. Choose a model with a larger context window, send a shorter request, or ask for a shorter answer.");
    }

    #[tokio::test]
    async fn a_lead_that_cannot_plan_again_still_combines_the_work_done() {
        let mut team = Team::new(&[r#"{"tasks": [{"title": "Draft", "brief": "Write a draft."}]}"#]);
        team.pad = "x".repeat(3_000);
        team.context = 3_000;
        let run = run(&harness(Strategy::Plan, 2, 4, 3), &team, &ask("Write a report")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        let rounds = run.trace["rounds"].as_array().unwrap();
        assert_eq!((rounds.len(), &rounds[1]["done"]), (2, &json!(true)));
        let note = rounds[1]["note"].as_str().unwrap();
        assert!(note.starts_with("The lead could not plan another round, so the team combined the results it had. acme/lead could not take the request"), "{note}");
    }

    #[tokio::test]
    async fn a_mixture_whose_second_layer_fails_answers_from_the_first() {
        let mut team = Team::new(&[]);
        team.pad = "z".repeat(1_000);
        team.context = 2_500;
        let run = run(&harness(Strategy::Mixture, 3, 3, 2), &team, &ask("Name a colour")).await.unwrap();
        assert_eq!(run.answer, "FINAL from acme/lead");
        assert_eq!(team.calls().len(), 8, "three answers, three refused refinements, two tries at the synthesis");
        let layers = run.trace["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        let note = layers[1]["note"].as_str().unwrap();
        assert!(note.starts_with("No worker could improve on the earlier answers, so the lead wrote the answer from those. Answer 1: acme/worker-a could not take the request"), "{note}");
    }

    #[tokio::test]
    async fn a_request_a_grid_model_would_refuse_is_never_sent_and_a_refusal_is_put_plainly() {
        let team = Team::new(&[]);
        let error = send(&team, "acme/lead", request("System", "x".repeat(32_768), 100, 0.3)).await.unwrap_err();
        assert!(error.starts_with("This request is too long for a grid model: it has 32,778 characters") && error.contains("so it was not sent"), "{error}");
        let error = send(&team, "acme/lead", request("System", "Hi".into(), 4_097, 0.3)).await.unwrap_err();
        assert_eq!(error, "A grid model writes 1 to 4,096 tokens in one answer, and this request asked for 4,097, so it was not sent.");
        assert!(team.calls().is_empty());
        // The largest request the server takes is sent.
        let largest = request("System", "x".repeat(32_768 - "System".len() - 4), 4_096, 0.3);
        assert!(the_server_takes(&largest));
        assert!(send(&team, "acme/lead", largest).await.is_ok());
        // The server's general refusal becomes words that say what to do; other errors stay as they are.
        let mut team = Team::new(&[]);
        team.context = 10;
        let error = send(&team, "acme/worker-a", request("System", "Hello there".into(), 2_048, 0.3)).await.unwrap_err();
        assert_eq!(error, "acme/worker-a could not take the request: with an answer of up to 2,048 tokens it is probably more than the model's context window holds. Choose a model with a larger context window, send a shorter request, or ask for a shorter answer.");
        assert_eq!(plain("acme/lead", 100, "The grid did not answer in time".into()), "The grid did not answer in time");
    }

    #[test]
    fn results_are_cut_alike_and_only_as_far_as_they_must_be() {
        let results = vec![("Short".to_owned(), "s".repeat(100)), ("Long".to_owned(), "l".repeat(30_000)), ("Longer".to_owned(), "m".repeat(40_000))];
        let make = |shown: &[String]| request("System", with_results("Request:\nGo", &results, shown, ""), 100, 0.3);
        let (shown, cut) = fit(&results, UNCAPPED, make).unwrap();
        assert_eq!(cut, [1, 2]);
        assert_eq!(shown[0], results[0].1, "a short result is never cut to make room for a long one");
        assert!(shown[1].ends_with(CUT) && shown[1].chars().count() == shown[2].chars().count(), "long results get equal shares");
        let built = make(&shown);
        assert!(the_server_takes(&built) && oversized(&built).is_none());
        assert!(length(&built) > CHARACTER_ROOM - 100, "the room is used, not wasted: {}", length(&built));
        // A cap on the results' room, as for a smaller request.
        let (capped, _) = fit(&results, (10_000, usize::MAX), make).unwrap();
        assert!(capped.iter().map(|text| text.chars().count()).sum::<usize>() <= 10_000);
        // Results that fit stay whole, and nothing fits when the request around them is too long already.
        let small = vec![("A".to_owned(), "a".repeat(10)), ("B".to_owned(), "b".repeat(20))];
        let whole = fit(&small, UNCAPPED, |shown| request("System", with_results("Go", &small, shown, ""), 100, 0.3)).unwrap();
        assert_eq!(whole, (vec!["a".repeat(10), "b".repeat(20)], vec![]));
        assert!(fit(&results, UNCAPPED, |shown| request("System", with_results(&"r".repeat(CHARACTER_ROOM), &results, shown, ""), 100, 0.3)).is_none());
    }

    #[test]
    fn requests_are_measured_as_the_model_server_and_serde_json_measure_them() {
        for text in ["plain", "a \"quote\" and a \\ slash", "new\nline\ttab\r\u{8}\u{c}", "\u{0}\u{1}\u{1f}\u{7f}", "é語😀"] {
            assert_eq!(json_bytes(text), serde_json::to_string(text).unwrap().len() - 2, "{text:?}");
        }
        // Each message counts two more for tool calls it has none of: `json.dumps([])` is `[]`.
        let messages = [json!({"role": "system", "content": "abc"}), json!({"role": "user", "content": [{"type": "text", "text": "de"}, {"type": "text", "text": "f"}]})];
        assert_eq!(server_characters(&messages), (3 + 2) + (4 + 2));
        // Tool calls count at least what Python writes for them.
        let calls = json!([{"id": "call_1", "type": "function", "function": {"name": "look", "arguments": "{\"q\": \"é\"}"}}]);
        let python = r#"[{"id": "call_1", "type": "function", "function": {"name": "look", "arguments": "{\"q\": \"\u00e9\"}"}}]"#;
        assert!(server_characters(&[json!({"role": "assistant", "content": null, "tool_calls": calls})]) >= python.chars().count());
        assert_eq!([grouped(7), grouped(4_096), grouped(1_234_567)], ["7", "4,096", "1,234,567"]);
    }
}
