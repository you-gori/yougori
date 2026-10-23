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
/// How much of each worker's answer reaches the lead, in characters.
const RESULT_LIMIT: usize = 12_000;
/// How much of all the workers' results together reaches the lead, in characters: a call must
/// stay well under the 1 MiB a computer reads a work offer with.
const COMBINE_LIMIT: usize = 400_000;
const BRIEF_LIMIT: usize = 4_000;
const PLAN_TOKENS: u32 = 1_200;
const WORKER_TOKENS: u32 = 2_048;
const FINAL_TOKENS: u32 = 4_096;

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
        prompt.push_str(&format!("\n\n{}. {}", index + 1, clip(answer)));
    }
    prompt
}

fn clip(text: &str) -> String {
    if text.chars().count() <= RESULT_LIMIT {
        return text.to_owned();
    }
    format!("{}… [cut]", text.chars().take(RESULT_LIMIT).collect::<String>())
}

fn request(system: &str, user: String, max_tokens: u32, temperature: f64) -> Value {
    json!({"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "max_tokens": max_tokens, "temperature": temperature, "stream": false})
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
        let result = asker.ask(&model, request).await;
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
    let mut tally = Tally::default();
    let mut trace = json!({"harness": harness.model(), "strategy": harness.strategy, "lead": harness.lead, "workers": harness.workers, "computers": harness.computers});
    let final_tokens = final_tokens.unwrap_or(FINAL_TOKENS);
    let answer = match harness.strategy {
        // A plan is written from the request's text alone; a request with images goes to every
        // model whole instead, so nothing the caller sent is left out.
        Strategy::Plan if has_attachments(messages) => {
            trace["note"] = json!("The request carries images or files, which a plan cannot split into tasks; the team answered it as a mixture, each model seeing the whole request.");
            run_mixture(harness, asker, messages, final_tokens, &mut tally, &mut trace).await?
        }
        Strategy::Plan => run_plan(harness, asker, &text, final_tokens, &mut tally, &mut trace).await?,
        Strategy::Mixture => run_mixture(harness, asker, messages, final_tokens, &mut tally, &mut trace).await?,
    };
    trace["computersUsed"] = json!(tally.computers);
    trace["seconds"] = json!((started.elapsed().as_secs_f64() * 10.0).round() / 10.0);
    Ok(Run { answer, trace, prompt_tokens: tally.prompt, completion_tokens: tally.completion })
}

/// Appends the workers' results to a request for the lead, each clipped, and all of them together
/// kept within `COMBINE_LIMIT` so the call stays small enough for a computer to receive.
fn append_results(ask: &mut String, results: &[(String, String)]) {
    if results.is_empty() {
        return;
    }
    let room = COMBINE_LIMIT.saturating_sub(ask.chars().count());
    let each = (room / results.len()).min(RESULT_LIMIT).max(200);
    for (title, result) in results {
        let body = if result.chars().count() <= each { result.clone() } else { format!("{}… [cut]", result.chars().take(each).collect::<String>()) };
        ask.push_str(&format!("\n\n### {title}\n{body}"));
    }
}

async fn run_plan<A: Ask>(harness: &Harness, asker: &A, text: &str, final_tokens: u32, tally: &mut Tally, trace: &mut Value) -> Result<String, String> {
    let mut rounds: Vec<Value> = Vec::new();
    let mut results: Vec<(String, String)> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for round in 1..=harness.rounds {
        let ask = if round == 1 {
            format!("Request:\n{text}")
        } else {
            let mut ask = format!("Request:\n{text}\n\nResults so far:");
            append_results(&mut ask, &results);
            ask.push_str(&format!("\n\nIf these results already answer the request fully, reply {{\"done\": true, \"tasks\": []}}. Otherwise list only the tasks that fill the gaps, at most {}.", harness.tasks));
            ask
        };
        let planned = asker.ask(&harness.lead, request(&plan_prompt(harness.tasks), ask, PLAN_TOKENS, 0.2)).await.map_err(|error| format!("The lead model could not plan: {error}"))?;
        tally.add(&planned);
        let plan = parse_plan(&planned.text, usize::from(harness.tasks));
        let mut note = None;
        let tasks = match plan {
            Some(plan) if plan.done && round > 1 => Vec::new(),
            Some(plan) if !plan.tasks.is_empty() => plan.tasks,
            // A first plan that cannot be read still answers: the whole request is one task.
            _ if round == 1 => {
                note = Some("The lead's plan could not be read, so the request ran as one task.");
                vec![Task { title: "Request".into(), brief: text.to_owned() }]
            }
            _ => Vec::new(),
        };
        if tasks.is_empty() {
            rounds.push(json!({"round": round, "done": true, "planner": planned.computer}));
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
                Err(error) => failed.push(format!("{}: {error}", item.title)),
            }
        }
        if answered == 0 && results.is_empty() {
            trace["rounds"] = json!(rounds);
            return Err(format!("None of the workers answered. {}", failed.first().map(String::as_str).unwrap_or_default()));
        }
    }
    trace["rounds"] = json!(rounds);
    let mut ask = format!("Request:\n{text}\n\nWorkers' results:");
    append_results(&mut ask, &results);
    if !failed.is_empty() {
        ask.push_str(&format!("\n\nThese tasks got no result; cover them briefly yourself if you can: {}", failed.join("; ")));
    }
    let combined = asker.ask(&harness.lead, request(COMBINE_PROMPT, ask, final_tokens, 0.3)).await.map_err(|error| format!("The lead model could not combine the results: {error}"))?;
    tally.add(&combined);
    trace["final"] = json!({"model": harness.lead, "computer": combined.computer});
    Ok(combined.text)
}

async fn run_mixture<A: Ask>(harness: &Harness, asker: &A, messages: &[Value], final_tokens: u32, tally: &mut Tally, trace: &mut Value) -> Result<String, String> {
    let mut layers: Vec<Value> = Vec::new();
    let mut answers: Vec<String> = Vec::new();
    for layer in 1..=harness.rounds {
        let work = (0..usize::from(harness.tasks))
            .map(|index| {
                let model = harness.workers[index % harness.workers.len()].clone();
                let mut chat: Vec<Value> = Vec::new();
                // From the second layer on, each worker improves on the previous layer's answers.
                if !answers.is_empty() {
                    chat.push(json!({"role": "system", "content": synthesis_prompt(&answers)}));
                }
                chat.extend(messages.iter().cloned());
                // Different temperatures give the lead different answers to work with.
                let temperature = [0.7, 0.9, 0.5][index % 3];
                (format!("Answer {}", index + 1), String::new(), model, json!({"messages": chat, "max_tokens": WORKER_TOKENS, "temperature": temperature, "stream": false}))
            })
            .collect();
        let done = fan_out(asker, harness.computers, work).await;
        layers.push(json!({"layer": layer, "answers": done.iter().map(Done::trace).collect::<Vec<_>>()}));
        let next: Vec<String> = done
            .into_iter()
            .filter_map(|item| item.result.ok())
            .map(|answer| {
                tally.add(&answer);
                answer.text
            })
            .collect();
        if next.is_empty() {
            trace["layers"] = json!(layers);
            return Err("None of the workers answered".into());
        }
        answers = next;
    }
    trace["layers"] = json!(layers);
    let mut chat = vec![json!({"role": "system", "content": synthesis_prompt(&answers)})];
    chat.extend(messages.iter().cloned());
    let combined = asker
        .ask(&harness.lead, json!({"messages": chat, "max_tokens": final_tokens, "temperature": 0.3, "stream": false}))
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

    /// A team that answers by role: the lead plans with `plan` and combines; workers name their task.
    struct Team {
        plan: Vec<String>,
        planned: AtomicUsize,
        running: AtomicUsize,
        most: AtomicUsize,
        calls: Mutex<Vec<(String, Value)>>,
        fail: Vec<&'static str>,
    }

    impl Team {
        fn new(plan: &[&str]) -> Team {
            Team { plan: plan.iter().map(|plan| plan.to_string()).collect(), planned: AtomicUsize::new(0), running: AtomicUsize::new(0), most: AtomicUsize::new(0), calls: Mutex::new(Vec::new()), fail: Vec::new() }
        }
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Ask for Team {
        fn ask<'a>(&'a self, model: &'a str, request: Value) -> BoxFuture<'a, Result<Answer, String>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push((model.to_owned(), request.clone()));
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
                    format!("result of {task}")
                } else if system == COMBINE_PROMPT || system.starts_with("You are given several responses") && model == "acme/lead" {
                    format!("FINAL from {model}")
                } else {
                    let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
                    self.most.fetch_max(running, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    self.running.fetch_sub(1, Ordering::SeqCst);
                    format!("answer from {model} at {}", request["temperature"])
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
}
