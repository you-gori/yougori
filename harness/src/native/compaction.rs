//! Keeping a conversation inside a small context window.
//!
//! A request may take the context window minus the output tokens and a margin. Before a call
//! would take more, old tool outputs are trimmed first (the newest are kept); when that is not
//! enough, the model summarises the older turns and the newest messages stay as they were. An
//! overflow reported by the server compacts harder; `/compact` summarises on request. If the
//! model cannot summarise, older messages are dropped with a short note instead, so the
//! conversation always fits.
use super::cancel::Cancel;
use super::conversation::{estimate, estimate_text, Conversation, Entry, Role};
use super::events::Events;
use super::llm::{CallError, Llm, Request};
use super::util;
use crate::protocol::{Event, Progress};
use serde_json::json;

pub const SUMMARY_PROMPT: &str = "You write the working notes that let a coding agent carry on after the older part of its \
conversation is removed. The agent will see only your notes and the newest messages.

Write the notes under these headings:
Requests: what the person asked for, keeping their exact words for requirements, names and values.
Done: what has been done so far: files changed and how, commands run and what they showed.
Facts: what was learned that still matters: paths, names, errors, decisions and their reasons.
Now: what was in progress at the end, and the next steps.

Be brief but exact: keep file paths, function names, numbers and error messages as they were. Leave out greetings and \
finished details that no longer matter. Never invent anything. Reply with the notes only.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The next call would not fit.
    Auto,
    /// The server said the last request was too long.
    Overflow,
    /// The person asked (`/compact`).
    Asked,
}

pub struct Plan {
    /// Tokens a request may take: context window - output - margin.
    pub budget: usize,
    /// The system prompt and tool definitions, in server tokens.
    pub fixed: usize,
    /// Server tokens per estimated token.
    pub ratio: f64,
    pub window: usize,
    pub max_output: usize,
    pub why: Why,
}

#[derive(Debug, Default, PartialEq)]
pub struct Done {
    pub trimmed: bool,
    /// The new head and the first message kept, when older messages were summarised.
    pub summary: Option<(String, i64)>,
    /// How many messages went into the summary.
    pub replaced: usize,
    /// Why the model's summary could not be used (older messages were dropped instead).
    pub fallback: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum Failure {
    Stopped,
    Failed(String),
}

/// Tokens kept free besides the output.
pub fn margin(window: usize) -> usize {
    (window / 32).max(512)
}

/// Tokens a request may take.
pub fn budget(window: usize, max_output: usize) -> usize {
    window.saturating_sub(max_output).saturating_sub(margin(window)).max(window / 4)
}

fn tokens(conv: &Conversation, plan: &Plan) -> usize {
    (estimate(&conv.wire(""), &[]) as f64 * plan.ratio).ceil() as usize + plan.fixed
}

fn entry_tokens(conv: &Conversation, entry: &Entry, ratio: f64) -> usize {
    let text = match entry.msg.role {
        Role::Tool => conv.tool_text(entry).len(),
        _ => entry.msg.text.len() + entry.msg.calls.iter().map(|c| c.arguments.len() + c.name.len() + 40).sum::<usize>(),
    };
    ((text as f64 / 3.6 + 8.0) * ratio).ceil() as usize
}

pub async fn compact(
    conv: &mut Conversation,
    plan: &Plan,
    llm: &Llm,
    model: &str,
    cancel: &Cancel,
    events: Option<&Events>,
) -> Result<Done, Failure> {
    let mut done = Done::default();
    if plan.why != Why::Asked {
        done.trimmed = trim(conv, plan);
        if plan.why == Why::Auto && tokens(conv, plan) <= plan.budget * 7 / 10 {
            return Ok(done);
        }
    }
    let keep = match plan.why {
        Why::Auto => plan.budget * 3 / 10,
        Why::Overflow => plan.budget / 5,
        Why::Asked => 0,
    };
    if let Some(at) = split(conv, keep, plan.ratio) {
        summarise_before(conv, at, plan, llm, model, cancel, events, &mut done).await?;
    }
    if tokens(conv, plan) > plan.budget {
        shrink(conv, plan);
    }
    if tokens(conv, plan) > plan.budget {
        return Err(Failure::Failed(
            "The newest messages alone do not fit the model's context window, even with long outputs cut.".into(),
        ));
    }
    Ok(done)
}

/// Trims tool outputs older than the newest ones (about 40% of the budget's worth), never those
/// of the latest step.
fn trim(conv: &mut Conversation, plan: &Plan) -> bool {
    let protect = plan.budget * 4 / 10;
    let latest_step = conv.entries.iter().rev().find(|e| e.msg.role == Role::Assistant).map(|e| e.seq).unwrap_or(i64::MAX);
    let mut used = 0usize;
    let mut cutoff = None;
    for entry in conv.entries.iter().rev() {
        if entry.seq < conv.trim_before {
            break;
        }
        if entry.msg.role != Role::Tool {
            continue;
        }
        used += entry_tokens(conv, entry, plan.ratio);
        if used > protect {
            cutoff = Some((entry.seq + 1).min(latest_step));
            break;
        }
    }
    match cutoff {
        Some(cutoff) if cutoff > conv.trim_before => {
            conv.trim_before = cutoff;
            true
        }
        _ => false,
    }
}

/// The first entry kept as it is: the newest entries within `keep` tokens, starting at a message
/// that is not a tool result (calls keep their results). None when nothing older is left.
fn split(conv: &Conversation, keep: usize, ratio: f64) -> Option<usize> {
    let mut used = 0usize;
    let mut at: Option<usize> = None;
    for (index, entry) in conv.entries.iter().enumerate().rev() {
        let size = entry_tokens(conv, entry, ratio);
        if at.is_some() && used + size > keep {
            break;
        }
        used += size;
        if entry.msg.role != Role::Tool {
            at = Some(index);
        }
    }
    at.filter(|index| *index > 0)
}

#[allow(clippy::too_many_arguments)]
async fn summarise_before(
    conv: &mut Conversation,
    at: usize,
    plan: &Plan,
    llm: &Llm,
    model: &str,
    cancel: &Cancel,
    events: Option<&Events>,
    done: &mut Done,
) -> Result<(), Failure> {
    let old: Vec<Entry> = conv.entries[..at].to_vec();
    let pieces = render(conv, &old);
    // Kept messages that start inside a turn need that turn's request beside the summary: the
    // newest request among the messages summarised now, or, when an earlier compaction of the
    // same turn summarised it already, the one kept then.
    let current = if conv.entries[at].msg.role == Role::User {
        None
    } else {
        old.iter().rev().find(|e| e.msg.role == Role::User).map(|e| e.msg.text.clone()).or_else(|| conv.request.clone())
    };
    let progress = util::new_id("compact");
    if let Some(events) = events {
        events.send(Event::Progress(Progress {
            id: progress.clone(),
            label: "Summarising older messages to make room".into(),
            ..Progress::default()
        }));
    }
    let result = summarise(conv.head.as_deref(), &pieces, plan, llm, model, cancel).await;
    if let Some(events) = events {
        events.send(Event::Progress(Progress {
            id: progress,
            label: "Summarised older messages".into(),
            finished: true,
            ..Progress::default()
        }));
    }
    let summary = match result {
        Ok(summary) => summary,
        Err(Failure::Stopped) => return Err(Failure::Stopped),
        Err(Failure::Failed(reason)) => {
            done.fallback = Some(reason);
            fallback(conv.head.as_deref(), &old)
        }
    };
    let mut head = format!("Summary of the conversation so far (older messages were removed to save room):\n\n{summary}");
    let current = current.map(|request| util::cut(&request, 4000).to_owned());
    if let Some(request) = &current {
        head.push_str(&format!("\n\nThe request being worked on now, in the person's words:\n{request}"));
    }
    let keep_from = conv.entries[at].seq;
    conv.entries.drain(..at);
    conv.head = Some(head.clone());
    conv.request = current;
    done.summary = Some((head, keep_from));
    done.replaced = at;
    Ok(())
}

fn head_tail(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    format!("{}\n[... cut ...]\n{}", util::cut(text, limit * 2 / 3), util::cut_tail(text, limit / 3))
}

/// The old messages as a transcript for the summary.
fn render(conv: &Conversation, entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| {
            let msg = &entry.msg;
            match msg.role {
                Role::User => Some(format!("PERSON: {}", head_tail(&msg.text, 6000))),
                Role::Assistant => {
                    let mut text = String::new();
                    if !msg.text.is_empty() {
                        text.push_str(&format!("ASSISTANT: {}", head_tail(&msg.text, 4000)));
                    }
                    for call in &msg.calls {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(&format!("ASSISTANT CALLED {} {}", call.name, util::one_line(&call.arguments, 400)));
                    }
                    (!text.is_empty()).then_some(text)
                }
                Role::Tool => Some(format!("RESULT: {}", head_tail(conv.tool_text(entry), 1500))),
            }
        })
        .collect()
}

/// The transcript summarised in chunks that fit, each folded into the summary before it.
async fn summarise(
    previous: Option<&str>,
    pieces: &[String],
    plan: &Plan,
    llm: &Llm,
    model: &str,
    cancel: &Cancel,
) -> Result<String, Failure> {
    let output = plan.max_output.clamp(256, 2048);
    let room = plan
        .window
        .saturating_sub(output)
        .saturating_sub(margin(plan.window))
        .saturating_sub(estimate_text(SUMMARY_PROMPT) + 200);
    // Characters per chunk, leaving space for the summary carried from the chunk before.
    let chars = ((room as f64 / plan.ratio.max(0.1)) * 3.6) as usize;
    let chunk_chars = chars.saturating_sub(output * 4).max(2000);
    let mut chunks: Vec<String> = Vec::new();
    let mut chunk = String::new();
    for piece in pieces {
        let piece = util::cut(piece, chunk_chars);
        if !chunk.is_empty() && chunk.len() + piece.len() + 2 > chunk_chars {
            chunks.push(std::mem::take(&mut chunk));
        }
        chunk.push_str(piece);
        chunk.push_str("\n\n");
    }
    if !chunk.trim().is_empty() {
        chunks.push(chunk);
    }
    let mut summary = previous.map(str::to_owned);
    for chunk in chunks {
        let mut text = String::new();
        if let Some(before) = &summary {
            text.push_str(&format!("Notes on what came before:\n{before}\n\nWhat happened next:\n"));
        }
        text.push_str(chunk.trim_end());
        summary = Some(ask(llm, model, &text, output, cancel).await?);
    }
    summary.ok_or_else(|| Failure::Failed("there was nothing to summarise".into()))
}

async fn ask(llm: &Llm, model: &str, transcript: &str, output: usize, cancel: &Cancel) -> Result<String, Failure> {
    let messages = vec![
        json!({ "role": "system", "content": SUMMARY_PROMPT }),
        json!({ "role": "user", "content": format!("{transcript}\n\nWrite the notes now.") }),
    ];
    let request = Request {
        model,
        messages: &messages,
        tools: &[],
        no_tools: false,
        max_tokens: output as u32,
        temperature: Some(0.2),
        top_p: None,
    };
    match llm.chat(&request, cancel, &mut |_| {}).await {
        Ok(reply) if !reply.text.trim().is_empty() => Ok(reply.text.trim().to_owned()),
        Ok(_) => Err(Failure::Failed("the model wrote an empty summary".into())),
        Err(CallError::Cancelled(_)) => Err(Failure::Stopped),
        Err(CallError::Overflow(message)) => Err(Failure::Failed(message)),
        Err(CallError::Failed { message, .. }) => Err(Failure::Failed(message)),
    }
}

/// When the model cannot summarise: what the person asked, so the work can go on.
fn fallback(previous: Option<&str>, old: &[Entry]) -> String {
    let mut text = String::from("Older messages were removed to make room; they could not be summarised.");
    if let Some(previous) = previous {
        text.push_str(&format!("\n\nNotes kept from before:\n{}", util::cut(previous, 6000)));
    }
    let asks: Vec<String> = old
        .iter()
        .filter(|e| e.msg.role == Role::User)
        .rev()
        .take(5)
        .map(|e| format!("- {}", util::one_line(&e.msg.text, 500)))
        .collect();
    if !asks.is_empty() {
        text.push_str("\n\nThe person's requests in them, newest first:\n");
        text.push_str(&asks.join("\n"));
    }
    text
}

/// Last resort: long tool outputs cut until the conversation fits.
fn shrink(conv: &mut Conversation, plan: &Plan) {
    for limit in [8000, 3000, 1000, 300] {
        for entry in conv.entries.iter_mut() {
            if entry.msg.role == Role::Tool && entry.msg.text.len() > limit {
                entry.msg.text = head_tail(&entry.msg.text, limit);
            }
        }
        if tokens(conv, plan) <= plan.budget {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::conversation::{Call, Msg, Shown, TRIMMED};
    use crate::native::testutil::{sse_body, FakeServer, Reply};
    use crate::protocol::{ToolKind, ToolStatus};

    fn shown() -> Shown {
        Shown { title: "t".into(), kind: ToolKind::Execute, status: ToolStatus::Completed, content: Vec::new(), locations: Vec::new() }
    }

    /// A long working session: requests, calls and big outputs.
    fn session(turns: usize, output: usize) -> Conversation {
        let mut conv = Conversation::default();
        for turn in 0..turns {
            conv.push(Msg::user(format!("request {turn}")));
            let call = Call { id: format!("c{turn}"), event: format!("e{turn}"), name: "bash".into(), arguments: "{\"command\":\"make\"}".into() };
            conv.push(Msg::assistant("m", String::new(), String::new(), vec![call]));
            conv.push(Msg::tool(&format!("c{turn}"), "o".repeat(output), shown()));
            conv.push(Msg::assistant("m", format!("done {turn}"), String::new(), Vec::new()));
        }
        conv
    }

    fn plan(why: Why) -> Plan {
        Plan { budget: budget(32768, 4096), fixed: 3000, ratio: 1.0, window: 32768, max_output: 4096, why }
    }

    fn llm(server: &FakeServer) -> Llm {
        let mut llm = Llm::new(&server.url, "k").unwrap();
        llm.retry.attempts = 1;
        llm
    }

    #[test]
    fn budgets_leave_room_for_the_reply() {
        assert_eq!(budget(32768, 4096), 32768 - 4096 - 1024);
        assert_eq!(budget(8192, 8192), 2048);
    }

    #[tokio::test]
    async fn old_outputs_are_trimmed_first() {
        let server = FakeServer::start(|_, _| Reply::empty(500)).await;
        // 10 turns with 6 KB outputs: about 17K tokens, over 70% of the budget only with outputs.
        let mut conv = session(12, 8000);
        let plan = plan(Why::Auto);
        assert!(tokens(&conv, &plan) > plan.budget, "{} <= {}", tokens(&conv, &plan), plan.budget);
        let done = compact(&mut conv, &plan, &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.trimmed && done.summary.is_none(), "{done:?}");
        assert!(tokens(&conv, &plan) <= plan.budget * 7 / 10);
        let wire = conv.wire("s");
        let trimmed = wire.iter().filter(|m| m["content"] == TRIMMED).count();
        assert!(trimmed >= 6, "{trimmed}");
        assert_ne!(wire[wire.len() - 2]["content"], TRIMMED, "the newest output stays");
        assert!(server.requests().is_empty(), "no model call was needed");
    }

    #[tokio::test]
    async fn older_turns_are_summarised_and_the_newest_kept() {
        let body = sse_body(&[json!({"choices": [{"delta": {"content": "Requests: fix the build."}, "finish_reason": "stop"}]})]);
        let server = FakeServer::start(move |_, _| Reply::sse(body.clone())).await;
        // Many turns of small messages: trimming cannot help.
        let mut conv = Conversation::default();
        for turn in 0..400 {
            conv.push(Msg::user(format!("request {turn}: {}", "please look at this ".repeat(8))));
            conv.push(Msg::assistant("m", format!("answer {turn}: {}", "here is what I found ".repeat(8)), String::new(), Vec::new()));
        }
        let plan = plan(Why::Auto);
        let done = compact(&mut conv, &plan, &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        let (head, keep_from) = done.summary.clone().unwrap();
        assert!(head.contains("Requests: fix the build."));
        assert_eq!(conv.head.as_deref(), Some(head.as_str()));
        assert_eq!(conv.entries.first().unwrap().seq, keep_from);
        assert!(conv.entries.last().unwrap().msg.text.starts_with("answer 399"));
        assert!(tokens(&conv, &plan) <= plan.budget);
        let sent = server.requests()[0].json();
        assert_eq!(sent["messages"][0]["content"], SUMMARY_PROMPT);
        assert!(sent["messages"][1]["content"].as_str().unwrap().contains("PERSON: request 0"));
        assert!(done.replaced > 0);
    }

    #[tokio::test]
    async fn a_summary_that_fails_drops_old_messages_with_a_note() {
        let server = FakeServer::start(|_, _| Reply::json(400, json!({"error": {"message": "bad template"}}))).await;
        let mut conv = Conversation::default();
        for turn in 0..400 {
            conv.push(Msg::user(format!("request {turn} {}", "x".repeat(150))));
            conv.push(Msg::assistant("m", "y".repeat(150), String::new(), Vec::new()));
        }
        let plan = plan(Why::Auto);
        let done = compact(&mut conv, &plan, &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.fallback.unwrap().contains("bad template"));
        let head = conv.head.unwrap();
        assert!(head.contains("could not be summarised") && head.contains("request "), "{head}");
    }

    #[tokio::test]
    async fn mid_turn_compaction_keeps_the_request_beside_the_summary() {
        let body = sse_body(&[json!({"choices": [{"delta": {"content": "Notes."}, "finish_reason": "stop"}]})]);
        let server = FakeServer::start(move |_, _| Reply::sse(body.clone())).await;
        let mut conv = Conversation::default();
        conv.push(Msg::user("Port the parser to the new API"));
        for step in 0..60 {
            let call = Call { id: format!("c{step}"), event: format!("e{step}"), name: "read".into(), arguments: "{}".into() };
            conv.push(Msg::assistant("m", format!("step {step} {}", "z".repeat(1200)), String::new(), vec![call]));
            conv.push(Msg::tool(&format!("c{step}"), "small".into(), shown()));
        }
        let done = compact(&mut conv, &plan(Why::Overflow), &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.summary.is_some());
        assert_eq!(conv.entries[0].msg.role, Role::Assistant);
        assert!(conv.head.unwrap().contains("in the person's words:\nPort the parser to the new API"));
    }

    #[tokio::test]
    async fn every_compaction_of_a_long_turn_keeps_the_request() {
        // The summariser never copies the request: only what is kept beside its notes survives.
        let body = sse_body(&[json!({"choices": [{"delta": {"content": "Notes: read files."}, "finish_reason": "stop"}]})]);
        let server = FakeServer::start(move |_, _| Reply::sse(body.clone())).await;
        let mut conv = Conversation::default();
        conv.push(Msg::user("Port the parser to the new API, keeping parse_v1 for old callers"));
        let mut step = 0;
        let mut steps = |conv: &mut Conversation, count: usize| {
            for _ in 0..count {
                let call = Call { id: format!("c{step}"), event: format!("e{step}"), name: "read".into(), arguments: "{}".into() };
                conv.push(Msg::assistant("m", format!("step {step} {}", "z".repeat(1200)), String::new(), vec![call]));
                conv.push(Msg::tool(&format!("c{step}"), "small".into(), shown()));
                step += 1;
            }
        };
        steps(&mut conv, 60);
        let overflow = plan(Why::Overflow);
        for round in 0..3 {
            let done = compact(&mut conv, &overflow, &llm(&server), "m", &Cancel::new(), None).await.unwrap();
            let (head, _) = done.summary.expect("summarised");
            assert!(head.contains("in the person's words:\nPort the parser to the new API, keeping parse_v1 for old callers"), "round {round}: {head}");
            assert_eq!(conv.request.as_deref(), Some("Port the parser to the new API, keeping parse_v1 for old callers"));
            assert_eq!(head.matches("in the person's words").count(), 1, "the request is kept once: {head}");
            steps(&mut conv, 60);
        }
        // A new turn's request replaces it, and a compaction that keeps that request's message
        // keeps nothing beside the summary.
        conv.push(Msg::user("Now add tests"));
        conv.push(Msg::assistant("m", "Which ones?".into(), String::new(), Vec::new()));
        let done = compact(&mut conv, &plan(Why::Asked), &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.summary.unwrap().0.contains("in the person's words:\nNow add tests"));
        // A request from an older turn is never carried on once newer requests are summarised.
        let mut later = Conversation { request: Some("an older request".into()), ..Conversation::default() };
        for turn in 0..400 {
            later.push(Msg::user(format!("request {turn}: {}", "please look at this ".repeat(8))));
            later.push(Msg::assistant("m", format!("answer {turn}"), String::new(), Vec::new()));
        }
        let done = compact(&mut later, &plan(Why::Auto), &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.summary.is_some());
        assert_ne!(later.request.as_deref(), Some("an older request"));
        if later.entries[0].msg.role == Role::User {
            assert_eq!(later.request, None, "the kept messages start with their own request");
        }
    }

    #[tokio::test]
    async fn asked_compaction_keeps_only_the_last_step() {
        let body = sse_body(&[json!({"choices": [{"delta": {"content": "Short notes."}, "finish_reason": "stop"}]})]);
        let server = FakeServer::start(move |_, _| Reply::sse(body.clone())).await;
        let mut conv = session(3, 100);
        let done = compact(&mut conv, &plan(Why::Asked), &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.summary.is_some());
        assert_eq!(conv.entries.len(), 1);
        assert_eq!(conv.entries[0].msg.text, "done 2");
        let mut tiny = Conversation::default();
        tiny.push(Msg::user("hi"));
        let done = compact(&mut tiny, &plan(Why::Asked), &llm(&server), "m", &Cancel::new(), None).await.unwrap();
        assert!(done.summary.is_none(), "nothing older to summarise");
    }
}
