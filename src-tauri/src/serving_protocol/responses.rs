//! OpenAI Responses stream assembly (S7 line 126; S9 line 167).
//!
//! Every event carries `type` and `sequence_number`. Numbers must rise by exactly one, so
//! a repeated number is a duplicate event and a skipped one a lost event. Output items
//! are declared by `response.output_item.added` in `output_index` order; a function call
//! streams `response.function_call_arguments.delta` text, closes it with
//! `response.function_call_arguments.done` (whose `arguments` must equal the deltas) and
//! ends with `response.output_item.done`. Only `response.completed` with every item done
//! completes the turn. Unknown event types are tolerated, as the API's versioning allows,
//! but they still take part in the sequence check.

use serde::Deserialize;
use serde_json::Value;

use super::dialect::Dialect;
use super::errors::{openai_error, ServiceError};
use super::sse::SseFrame;
use super::turn::{
    append_bounded, parse_event, resolve_terminal, violation, AssemblyLimits, CallBuilder,
    FinishReason, Flow, PendingToolCall, ProtocolViolation, StreamEnd, TurnOutcome, Usage,
    ViolationKind, WireFinish,
};

#[derive(Deserialize)]
struct ItemEvent {
    output_index: u32,
    item: WireItem,
}

#[derive(Deserialize)]
struct WireItem {
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
    call_id: Option<String>,
    name: Option<String>,
    arguments: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize)]
struct PartEvent {
    item_id: String,
    output_index: u32,
    content_index: u32,
    part: WirePart,
}

#[derive(Deserialize)]
struct WirePart {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct PartDelta {
    item_id: String,
    output_index: u32,
    content_index: u32,
    delta: String,
}

#[derive(Deserialize)]
struct TextDone {
    item_id: String,
    output_index: u32,
    content_index: u32,
    text: String,
}

#[derive(Deserialize)]
struct RefusalDone {
    item_id: String,
    output_index: u32,
    content_index: u32,
    refusal: String,
}

#[derive(Deserialize)]
struct ArgumentsDelta {
    item_id: String,
    output_index: u32,
    delta: String,
}

#[derive(Deserialize)]
struct ArgumentsDone {
    item_id: String,
    output_index: u32,
    arguments: String,
}

#[derive(Deserialize)]
struct ResponseEvent {
    response: WireResponse,
}

#[derive(Deserialize)]
struct WireResponse {
    status: Option<String>,
    output: Option<Vec<WireItem>>,
    usage: Option<WireUsage>,
    error: Option<Value>,
    incomplete_details: Option<IncompleteDetails>,
}

#[derive(Deserialize)]
struct IncompleteDetails {
    reason: Option<String>,
}

#[derive(Deserialize)]
struct WireUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    input_tokens_details: Option<InputDetails>,
}

#[derive(Deserialize)]
struct InputDetails {
    cached_tokens: Option<u64>,
}

impl WireUsage {
    fn usage(self) -> Usage {
        Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
            cached_input_tokens: self.input_tokens_details.and_then(|d| d.cached_tokens),
        }
    }
}

#[derive(Debug)]
struct Part {
    refusal: bool,
    text: String,
    done: bool,
}

#[derive(Debug)]
enum Body {
    Message(Vec<Part>),
    Reasoning,
    Call(CallBuilder),
}

#[derive(Debug)]
struct Item {
    id: String,
    body: Body,
    done: bool,
    incomplete: bool,
}

#[derive(Debug)]
enum State {
    Open,
    Completed,
    Incomplete(WireFinish),
    Failed(ServiceError),
    Violated(ProtocolViolation),
}

/// Assembles one OpenAI Responses stream (S7 line 126; S9 line 167).
#[derive(Debug)]
pub struct ResponsesAssembler {
    limits: AssemblyLimits,
    frames: usize,
    state: State,
    created: bool,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    items: Vec<Item>,
    usage: Option<Usage>,
    ignored_events: usize,
}

impl ResponsesAssembler {
    /// An assembler at the start of a stream.
    pub fn new(limits: AssemblyLimits) -> Self {
        Self {
            limits,
            frames: 0,
            state: State::Open,
            created: false,
            first_sequence: None,
            last_sequence: None,
            items: Vec::new(),
            usage: None,
            ignored_events: 0,
        }
    }

    /// Takes the next frame in arrival order.
    pub fn push(&mut self, frame: &SseFrame) -> Flow {
        let position = self.frames;
        self.frames = self.frames.saturating_add(1);
        match self.state {
            State::Open => {}
            State::Completed | State::Incomplete(_) => {
                self.state = State::Violated(violation(
                    ViolationKind::EventAfterTerminal,
                    position,
                    "an event after the response's terminal event",
                ));
                return Flow::Stop;
            }
            State::Failed(_) | State::Violated(_) => return Flow::Stop,
        }
        match self.apply(frame, position) {
            Ok(flow) => flow,
            Err(broken) => {
                self.state = State::Violated(broken);
                Flow::Stop
            }
        }
    }

    /// Event types outside this module's set, tolerated as the API's versioning allows.
    pub fn ignored_events(&self) -> usize {
        self.ignored_events
    }

    /// The calls declared so far; none is executable before the turn completes.
    pub fn pending_tool_calls(&self) -> Vec<PendingToolCall> {
        self.calls().map(CallBuilder::pending).collect()
    }

    /// Ends the stream and resolves its outcome.
    pub fn finish(self, end: StreamEnd) -> TurnOutcome {
        let dropped = self.pending_tool_calls();
        let last = self.frames.saturating_sub(1);
        match self.state {
            State::Violated(violation) => TurnOutcome::Violation { violation, dropped },
            State::Failed(error) => TurnOutcome::Failed { error, dropped },
            State::Incomplete(finish) => TurnOutcome::Truncated { finish, dropped },
            State::Completed => {
                let mut text = String::new();
                let mut refusal = String::new();
                let mut calls = Vec::new();
                for item in &self.items {
                    match &item.body {
                        Body::Message(parts) => {
                            for part in parts {
                                let target = if part.refusal {
                                    &mut refusal
                                } else {
                                    &mut text
                                };
                                target.push_str(&part.text);
                            }
                        }
                        Body::Reasoning => {}
                        Body::Call(call) => calls.push(call.clone()),
                    }
                }
                let reason = if calls.is_empty() {
                    FinishReason::Stop
                } else {
                    FinishReason::ToolCalls
                };
                let finish = WireFinish {
                    raw: "completed".to_owned(),
                    reason,
                };
                resolve_terminal(
                    Dialect::OpenAiResponses,
                    text,
                    refusal,
                    &calls,
                    finish,
                    self.usage,
                    last,
                )
            }
            State::Open => match end {
                StreamEnd::ClientCancel => TurnOutcome::Cancelled { dropped },
                StreamEnd::Eof => TurnOutcome::Disconnected {
                    after_finish: false,
                    dropped,
                },
            },
        }
    }

    fn calls(&self) -> impl Iterator<Item = &CallBuilder> {
        self.items.iter().filter_map(|item| match &item.body {
            Body::Call(call) => Some(call),
            _ => None,
        })
    }

    fn apply(&mut self, frame: &SseFrame, position: usize) -> Result<Flow, ProtocolViolation> {
        let value: Value = serde_json::from_str(&frame.data).map_err(|error| {
            violation(
                ViolationKind::MalformedFrame,
                position,
                format!("data is not JSON: {error}"),
            )
        })?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                violation(
                    ViolationKind::MalformedFrame,
                    position,
                    "an event without type",
                )
            })?
            .to_owned();
        if let Some(event) = &frame.event {
            if *event != kind {
                return Err(violation(
                    ViolationKind::EventNameMismatch,
                    position,
                    format!("event name {event:?} with type {kind:?}"),
                ));
            }
        }
        let sequence = value
            .get("sequence_number")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                violation(
                    ViolationKind::MalformedFrame,
                    position,
                    format!("{kind} without sequence_number"),
                )
            })?;
        self.check_sequence(sequence, position)?;
        match kind.as_str() {
            "error" => {
                self.state = State::Failed(openai_error(&value, None, true));
                return Ok(Flow::Stop);
            }
            "response.created" => {
                if self.created {
                    return Err(violation(
                        ViolationKind::DuplicateEvent,
                        position,
                        "response.created repeated",
                    ));
                }
                self.created = true;
            }
            _ if !self.created => {
                return Err(violation(
                    ViolationKind::UnexpectedEvent,
                    position,
                    format!("{kind} before response.created"),
                ))
            }
            "response.in_progress" | "response.queued" => {}
            "response.output_item.added" => {
                self.item_added(parse_event(value, position)?, position)?
            }
            "response.content_part.added" => {
                self.part_added(parse_event(value, position)?, position)?
            }
            "response.content_part.done" => {
                self.part_done(parse_event(value, position)?, position)?
            }
            "response.output_text.delta" => {
                self.part_delta(parse_event(value, position)?, false, position)?
            }
            "response.refusal.delta" => {
                self.part_delta(parse_event(value, position)?, true, position)?
            }
            "response.output_text.done" => {
                let done: TextDone = parse_event(value, position)?;
                let address = (done.item_id, done.output_index, done.content_index);
                self.part_text_done(address, &done.text, false, position)?;
            }
            "response.refusal.done" => {
                let done: RefusalDone = parse_event(value, position)?;
                let address = (done.item_id, done.output_index, done.content_index);
                self.part_text_done(address, &done.refusal, true, position)?;
            }
            "response.function_call_arguments.delta" => {
                self.arguments_delta(parse_event(value, position)?, position)?
            }
            "response.function_call_arguments.done" => {
                self.arguments_done(parse_event(value, position)?, position)?
            }
            "response.output_item.done" => {
                self.item_done(parse_event(value, position)?, position)?
            }
            "response.completed" => {
                self.completed(parse_event(value, position)?, position)?;
                return Ok(Flow::Stop);
            }
            "response.incomplete" => {
                self.incomplete(parse_event(value, position)?, position)?;
                return Ok(Flow::Stop);
            }
            "response.failed" => {
                let event: ResponseEvent = parse_event(value, position)?;
                let error = event.response.error.unwrap_or(Value::Null);
                self.state = State::Failed(openai_error(&error, None, true));
                return Ok(Flow::Stop);
            }
            _ => self.ignored_events = self.ignored_events.saturating_add(1),
        }
        Ok(Flow::Continue)
    }

    fn check_sequence(&mut self, sequence: u64, position: usize) -> Result<(), ProtocolViolation> {
        let (Some(first), Some(last)) = (self.first_sequence, self.last_sequence) else {
            self.first_sequence = Some(sequence);
            self.last_sequence = Some(sequence);
            return Ok(());
        };
        let expected = last.checked_add(1).ok_or_else(|| {
            violation(
                ViolationKind::LimitExceeded,
                position,
                "sequence_number overflow",
            )
        })?;
        if sequence == expected {
            self.last_sequence = Some(sequence);
            Ok(())
        } else if sequence > expected {
            Err(violation(
                ViolationKind::SequenceGap,
                position,
                format!("sequence_number {sequence} where {expected} was expected"),
            ))
        } else if sequence >= first {
            Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!("sequence_number {sequence} repeated"),
            ))
        } else {
            Err(violation(
                ViolationKind::OutOfOrderEvent,
                position,
                format!("sequence_number {sequence} precedes the stream's first, {first}"),
            ))
        }
    }

    fn item_added(&mut self, event: ItemEvent, position: usize) -> Result<(), ProtocolViolation> {
        let declared = self.items.len();
        let index = event.output_index as usize;
        if index < declared {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!("output item {index} added again"),
            ));
        }
        if index > declared {
            return Err(violation(
                ViolationKind::OutOfOrderIndex,
                position,
                format!("output_index {index} added before {declared}"),
            ));
        }
        let item = event.item;
        let id = item.id.filter(|id| !id.is_empty()).ok_or_else(|| {
            violation(
                ViolationKind::MalformedFrame,
                position,
                format!("output item {index} without an id"),
            )
        })?;
        if self.items.iter().any(|existing| existing.id == id) {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!("item id {id:?} added twice"),
            ));
        }
        let body = match item.kind.as_str() {
            "function_call" => {
                if self.calls().count() >= self.limits.max_tool_calls {
                    return Err(violation(
                        ViolationKind::LimitExceeded,
                        position,
                        format!("more than {} tool calls", self.limits.max_tool_calls),
                    ));
                }
                let call_id = item.call_id.filter(|id| !id.is_empty()).ok_or_else(|| {
                    violation(
                        ViolationKind::MissingToolCallHeader,
                        position,
                        format!("function call {index} without call_id"),
                    )
                })?;
                let name = item.name.filter(|name| !name.is_empty()).ok_or_else(|| {
                    violation(
                        ViolationKind::MissingToolCallHeader,
                        position,
                        format!("function call {index} without a name"),
                    )
                })?;
                if self.calls().any(|call| call.call_id == call_id) {
                    return Err(violation(
                        ViolationKind::DuplicateCallId,
                        position,
                        format!("call_id {call_id:?} used twice"),
                    ));
                }
                let mut call = CallBuilder::new(event.output_index, call_id, name);
                let initial = item.arguments.unwrap_or_default();
                append_bounded(
                    &mut call.arguments,
                    &initial,
                    self.limits.max_argument_bytes,
                    position,
                )?;
                Body::Call(call)
            }
            "message" => Body::Message(Vec::new()),
            "reasoning" => Body::Reasoning,
            other => {
                return Err(violation(
                    ViolationKind::UnsupportedContent,
                    position,
                    format!("output item type {other:?}"),
                ))
            }
        };
        self.items.push(Item {
            id,
            body,
            done: false,
            incomplete: false,
        });
        Ok(())
    }

    fn part_added(&mut self, event: PartEvent, position: usize) -> Result<(), ProtocolViolation> {
        let refusal = match event.part.kind.as_str() {
            "output_text" => false,
            "refusal" => true,
            other => {
                return Err(violation(
                    ViolationKind::UnsupportedContent,
                    position,
                    format!("content part type {other:?}"),
                ))
            }
        };
        let item = open_item(
            &mut self.items,
            event.output_index,
            &event.item_id,
            position,
        )?;
        let Body::Message(parts) = &mut item.body else {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                "a content part on an item that is not a message",
            ));
        };
        let declared = parts.len();
        let index = event.content_index as usize;
        if index < declared {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!("content part {index} added again"),
            ));
        }
        if index > declared {
            return Err(violation(
                ViolationKind::OutOfOrderIndex,
                position,
                format!("content_index {index} added before {declared}"),
            ));
        }
        parts.push(Part {
            refusal,
            text: String::new(),
            done: false,
        });
        Ok(())
    }

    fn part_delta(
        &mut self,
        event: PartDelta,
        refusal: bool,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        let max_text_bytes = self.limits.max_text_bytes;
        let address = (event.item_id, event.output_index, event.content_index);
        let part = open_part(&mut self.items, &address, refusal, false, position)?;
        append_bounded(&mut part.text, &event.delta, max_text_bytes, position)
    }

    fn part_text_done(
        &mut self,
        address: (String, u32, u32),
        text: &str,
        refusal: bool,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        let part = open_part(&mut self.items, &address, refusal, false, position)?;
        if part.text != text {
            return Err(violation(
                ViolationKind::ContentMismatch,
                position,
                format!(
                    "content part {} done text differs from its deltas",
                    address.2
                ),
            ));
        }
        Ok(())
    }

    fn part_done(&mut self, event: PartEvent, position: usize) -> Result<(), ProtocolViolation> {
        let refusal = event.part.kind == "refusal";
        let address = (event.item_id, event.output_index, event.content_index);
        let part = open_part(&mut self.items, &address, refusal, true, position)?;
        part.done = true;
        Ok(())
    }

    fn arguments_delta(
        &mut self,
        event: ArgumentsDelta,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        let max_argument_bytes = self.limits.max_argument_bytes;
        let call = open_call(
            &mut self.items,
            event.output_index,
            &event.item_id,
            position,
        )?;
        if call.arguments_closed {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("an arguments delta after call {} closed", call.index),
            ));
        }
        append_bounded(
            &mut call.arguments,
            &event.delta,
            max_argument_bytes,
            position,
        )
    }

    fn arguments_done(
        &mut self,
        event: ArgumentsDone,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        let call = open_call(
            &mut self.items,
            event.output_index,
            &event.item_id,
            position,
        )?;
        if call.arguments_closed {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!(
                    "function_call_arguments.done repeated for call {}",
                    call.index
                ),
            ));
        }
        if call.arguments != event.arguments {
            return Err(violation(
                ViolationKind::ContentMismatch,
                position,
                format!("call {} done arguments differ from its deltas", call.index),
            ));
        }
        call.arguments_closed = true;
        Ok(())
    }

    fn item_done(&mut self, event: ItemEvent, position: usize) -> Result<(), ProtocolViolation> {
        let index = event.output_index as usize;
        let item = self.items.get_mut(index).ok_or_else(|| {
            violation(
                ViolationKind::UnknownIndex,
                position,
                format!("output item {index} done but never added"),
            )
        })?;
        if item.done {
            return Err(violation(
                ViolationKind::DuplicateEvent,
                position,
                format!("output item {index} done twice"),
            ));
        }
        let wire = event.item;
        if wire.id.as_deref() != Some(item.id.as_str()) {
            return Err(violation(
                ViolationKind::UnknownIndex,
                position,
                format!("output item {index} done with another item's id"),
            ));
        }
        match &item.body {
            Body::Call(call) => {
                if wire.kind != "function_call"
                    || wire.call_id.as_deref() != Some(call.call_id.as_str())
                    || wire.name.as_deref() != Some(call.name.as_str())
                {
                    return Err(violation(
                        ViolationKind::ConflictingToolCallHeader,
                        position,
                        format!("call {index} done with another type, call_id or name"),
                    ));
                }
                if !call.arguments_closed {
                    return Err(violation(
                        ViolationKind::UnexpectedEvent,
                        position,
                        format!("call {index} done before function_call_arguments.done"),
                    ));
                }
                if wire.arguments.as_deref() != Some(call.arguments.as_str()) {
                    return Err(violation(
                        ViolationKind::ContentMismatch,
                        position,
                        format!("call {index} done item arguments differ from its deltas"),
                    ));
                }
                item.incomplete = wire.status.as_deref() != Some("completed");
            }
            Body::Message(parts) => {
                if wire.kind != "message" {
                    return Err(violation(
                        ViolationKind::UnexpectedEvent,
                        position,
                        format!("message item {index} done as {:?}", wire.kind),
                    ));
                }
                if parts.iter().any(|part| !part.done) {
                    return Err(violation(
                        ViolationKind::UnexpectedEvent,
                        position,
                        format!("message item {index} done with an open content part"),
                    ));
                }
                item.incomplete = wire.status.as_deref() == Some("incomplete");
            }
            Body::Reasoning => {
                if wire.kind != "reasoning" {
                    return Err(violation(
                        ViolationKind::UnexpectedEvent,
                        position,
                        format!("reasoning item {index} done as {:?}", wire.kind),
                    ));
                }
            }
        }
        item.done = true;
        Ok(())
    }

    fn completed(
        &mut self,
        event: ResponseEvent,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        let response = event.response;
        if response.status.as_deref() != Some("completed") {
            return Err(violation(
                ViolationKind::ConflictingFinishReason,
                position,
                format!("response.completed with status {:?}", response.status),
            ));
        }
        if let Some(open) = self.items.iter().position(|item| !item.done) {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("response.completed while output item {open} is open"),
            ));
        }
        if let Some(incomplete) = self.items.iter().position(|item| item.incomplete) {
            return Err(violation(
                ViolationKind::UnexpectedEvent,
                position,
                format!("response.completed with output item {incomplete} incomplete"),
            ));
        }
        let output = response.output.unwrap_or_default();
        if output.len() != self.items.len() {
            return Err(violation(
                ViolationKind::ContentMismatch,
                position,
                format!(
                    "response.output has {} items; the stream added {}",
                    output.len(),
                    self.items.len()
                ),
            ));
        }
        for (index, (wire, item)) in output.iter().zip(&self.items).enumerate() {
            let same = wire.id.as_deref() == Some(item.id.as_str())
                && match &item.body {
                    Body::Call(call) => {
                        wire.kind == "function_call"
                            && wire.call_id.as_deref() == Some(call.call_id.as_str())
                            && wire.name.as_deref() == Some(call.name.as_str())
                            && wire.arguments.as_deref() == Some(call.arguments.as_str())
                    }
                    Body::Message(_) => wire.kind == "message",
                    Body::Reasoning => wire.kind == "reasoning",
                };
            if !same {
                return Err(violation(
                    ViolationKind::ContentMismatch,
                    position,
                    format!("response.output[{index}] differs from the streamed item"),
                ));
            }
        }
        self.usage = response.usage.map(WireUsage::usage);
        self.state = State::Completed;
        Ok(())
    }

    fn incomplete(
        &mut self,
        event: ResponseEvent,
        position: usize,
    ) -> Result<(), ProtocolViolation> {
        let response = event.response;
        if response.status.as_deref() != Some("incomplete") {
            return Err(violation(
                ViolationKind::ConflictingFinishReason,
                position,
                format!("response.incomplete with status {:?}", response.status),
            ));
        }
        let reason = response
            .incomplete_details
            .and_then(|details| details.reason);
        let finish = match reason {
            Some(raw) => {
                let reason = match raw.as_str() {
                    "max_output_tokens" => FinishReason::Length,
                    "content_filter" => FinishReason::ContentFilter,
                    _ => FinishReason::Incomplete,
                };
                WireFinish { raw, reason }
            }
            None => WireFinish {
                raw: "incomplete".to_owned(),
                reason: FinishReason::Incomplete,
            },
        };
        self.usage = response.usage.map(WireUsage::usage);
        self.state = State::Incomplete(finish);
        Ok(())
    }
}

fn open_item<'a>(
    items: &'a mut [Item],
    output_index: u32,
    item_id: &str,
    position: usize,
) -> Result<&'a mut Item, ProtocolViolation> {
    let item = items.get_mut(output_index as usize).ok_or_else(|| {
        violation(
            ViolationKind::UnknownIndex,
            position,
            format!("output_index {output_index} was never added"),
        )
    })?;
    if item.id != item_id {
        return Err(violation(
            ViolationKind::UnknownIndex,
            position,
            format!("item_id {item_id:?} is not output item {output_index}"),
        ));
    }
    if item.done {
        return Err(violation(
            ViolationKind::UnexpectedEvent,
            position,
            format!("an event for output item {output_index} after it was done"),
        ));
    }
    Ok(item)
}

fn open_call<'a>(
    items: &'a mut [Item],
    output_index: u32,
    item_id: &str,
    position: usize,
) -> Result<&'a mut CallBuilder, ProtocolViolation> {
    match &mut open_item(items, output_index, item_id, position)?.body {
        Body::Call(call) => Ok(call),
        _ => Err(violation(
            ViolationKind::UnexpectedEvent,
            position,
            format!("function call arguments for output item {output_index}, not a call"),
        )),
    }
}

/// The open content part at `address`; `closing` says whether the event is the part's
/// own `content_part.done`, whose repetition is a duplicate event.
fn open_part<'a>(
    items: &'a mut [Item],
    address: &(String, u32, u32),
    refusal: bool,
    closing: bool,
    position: usize,
) -> Result<&'a mut Part, ProtocolViolation> {
    let (item_id, output_index, content_index) = address;
    let Body::Message(parts) = &mut open_item(items, *output_index, item_id, position)?.body else {
        return Err(violation(
            ViolationKind::UnexpectedEvent,
            position,
            format!("content for output item {output_index}, not a message"),
        ));
    };
    let part = parts.get_mut(*content_index as usize).ok_or_else(|| {
        violation(
            ViolationKind::UnknownIndex,
            position,
            format!("content_index {content_index} was never added"),
        )
    })?;
    if part.done {
        let kind = if closing {
            ViolationKind::DuplicateEvent
        } else {
            ViolationKind::UnexpectedEvent
        };
        return Err(violation(
            kind,
            position,
            format!("content part {content_index} after it was done"),
        ));
    }
    if part.refusal != refusal {
        return Err(violation(
            ViolationKind::UnexpectedEvent,
            position,
            format!("content part {content_index} addressed as the other part type"),
        ));
    }
    Ok(part)
}
