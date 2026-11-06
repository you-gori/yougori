//! The terminal command path of one boot (module docs in `mod.rs`; VM part §3.2 lines
//! 2059–2077, the terminal channel; §6.1–§6.3 lines 2284–2316; VM-P28 and VM-P29 lines
//! 2803–2804).
//!
//! A command is one terminal stream the host opens on the boot's link: the host sends
//! the caller's bounded input as `Data` within the credit the guest granted, then ends its
//! direction with `EndOfStream`; the guest answers with `Data` and ends with `Exit`, its
//! report of the exit code. The host keeps the guest's output up to the caller's limit,
//! counts and drops what comes beyond it and cancels the stream, credits the terminal
//! window back as it takes the bytes, and cancels the stream when the caller cancels or
//! the caller's time limit passes. A command also ends when the guest refuses or cancels
//! the stream, when the link or its terminal channel closes, and when the host closes the
//! boot's channels (a revocation among them); nothing it sent after that is taken.
//!
//! Everything the guest sends is the guest's: the output is [`GuestOutput`] and the exit
//! code is the guest's report ([`GuestReport`], source class `guest_report`), never a host
//! fact.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::sandbox::link::{
    CancelCause, Channel, ChannelCloseCause, CloseCause, ConsumeRefusal, GuestReport, GuestRequest,
    HostLink, HostMessage, LinkEvent, OpenRefusalCause, ReportBody, SendRefusal, StreamId,
    FIELD_OVERHEAD_BYTES,
};

use super::log::ClosureCause;

/// The most input one command may send: 1 MiB.
pub const MAX_COMMAND_INPUT_BYTES: usize = 1 << 20;
/// The highest output limit a caller may ask for: 16 MiB.
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 16 << 20;

/// What the caller asks of one command.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandRequest {
    pub image_entrypoint: bool,
    /// The bytes for the guest shell's standard input, sent and then ended; at most
    /// [`MAX_COMMAND_INPUT_BYTES`].
    pub input: Vec<u8>,
    /// The most guest output kept, from 1 to [`MAX_COMMAND_OUTPUT_BYTES`]; output beyond
    /// it is counted and dropped, and the stream is cancelled.
    pub max_output_bytes: usize,
    /// How long the command may run from its start on the host clock; when it passes,
    /// the stream is cancelled.
    pub time_limit: Duration,
    pub columns: u16,
    pub rows: u16,
}

impl fmt::Debug for CommandRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandRequest")
            .field("input_bytes", &self.input.len())
            .field("max_output_bytes", &self.max_output_bytes)
            .field("time_limit", &self.time_limit)
            .field("columns", &self.columns)
            .field("rows", &self.rows)
            .finish()
    }
}

/// Why a command could not be started or cancelled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "command_refusal", rename_all = "snake_case")]
pub enum CommandRefusal {
    InputTooLarge {
        input_bytes: usize,
        max_bytes: usize,
    },
    /// The output limit is zero or above [`MAX_COMMAND_OUTPUT_BYTES`].
    OutputLimit {
        max_output_bytes: usize,
        max_bytes: usize,
    },
    ZeroTimeLimit,
    /// Every even stream id has been used on this boot.
    StreamIdsExhausted,
    /// The link refused the open (its terminal stream quota, its queue, a closed channel).
    Send(SendRefusal),
    /// No running command has this stream.
    UnknownCommand {
        stream: StreamId,
    },
}

impl fmt::Display for CommandRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge {
                input_bytes,
                max_bytes,
            } => write!(
                f,
                "{input_bytes} bytes of input exceed the {max_bytes} a command may send"
            ),
            Self::OutputLimit {
                max_output_bytes,
                max_bytes,
            } => write!(
                f,
                "an output limit of {max_output_bytes} bytes is not between 1 and {max_bytes}"
            ),
            Self::ZeroTimeLimit => f.write_str("a command's time limit may not be zero"),
            Self::StreamIdsExhausted => f.write_str("every terminal stream id has been used"),
            Self::Send(refusal) => write!(f, "the link refused the open: {refusal}"),
            Self::UnknownCommand { stream } => write!(f, "no command runs on stream {stream}"),
        }
    }
}

impl std::error::Error for CommandRefusal {}

/// What a guest wrote on a command's stream: guest data, never a host fact (VM-P29). The
/// bytes kept stop at the caller's limit; the rest is counted.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestOutput {
    bytes: Vec<u8>,
    dropped_bytes: u64,
}

impl GuestOutput {
    /// The only source class guest output has (CORE-01).
    pub const SOURCE: SourceClass = SourceClass::GuestReport;

    /// The output kept, at most the caller's limit.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Output that arrived beyond the limit and was dropped.
    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    pub const fn source(&self) -> SourceClass {
        Self::SOURCE
    }
}

impl fmt::Debug for GuestOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestOutput")
            .field("bytes", &self.bytes.len())
            .field("dropped_bytes", &self.dropped_bytes)
            .finish()
    }
}

/// How a command ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandEnd {
    /// The guest reported the shell's exit; the report carries the code and is the
    /// guest's word.
    Exited { exit: GuestReport },
    /// The guest ended its direction without an exit report.
    EndedWithoutExit,
    /// The output passed the caller's limit; the host cancelled the stream.
    OutputLimitReached,
    /// The caller cancelled; the host cancelled the stream.
    Cancelled,
    /// The caller's time limit passed; the host cancelled the stream.
    TimeLimitPassed,
    /// The guest refused the open.
    OpenRefused { cause: OpenRefusalCause },
    /// The guest did not answer the open within the link's open timeout.
    OpenTimedOut,
    /// The guest cancelled the stream.
    GuestCancelled { cause: CancelCause },
    /// The link closed the terminal channel (the guest overran its window).
    TerminalClosed { cause: ChannelCloseCause },
    /// The link closed: the transport ended or failed, a violation, the guest's close,
    /// a timeout.
    LinkClosed { cause: CloseCause },
    /// The host closed the boot's channels: revoked, authority lost or shut down.
    HostClosed { cause: ClosureCause },
}

/// One finished command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub stream: StreamId,
    pub end: CommandEnd,
    pub output: GuestOutput,
    /// Input bytes the link took for the guest.
    pub input_sent_bytes: u64,
    /// On the host clock.
    pub started_at: MonotonicTime,
    pub ended_at: MonotonicTime,
    /// Why the link did not take the host's last frame for the stream (its cancel or end
    /// of stream), if it did not.
    pub unsent: Option<SendRefusal>,
}

impl CommandResult {
    /// The exit code the guest reported, if it reported one: the guest's word.
    pub fn exit_code(&self) -> Option<i32> {
        match &self.end {
            CommandEnd::Exited { exit } => match exit.body() {
                ReportBody::TerminalExit { code, .. } => Some(*code),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether the command ended because the sandbox was revoked.
    pub fn is_revoked(&self) -> bool {
        matches!(
            self.end,
            CommandEnd::HostClosed {
                cause: ClosureCause::Revoked
            }
        )
    }
}

/// What happened to a boot's commands in one delivery, disconnect or tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandEvent {
    /// The guest accepted the open.
    Opened {
        stream: StreamId,
    },
    /// All input reached the link and the host ended its direction.
    InputEnded {
        stream: StreamId,
        input_bytes: u64,
    },
    Ended(Box<CommandResult>),
}

impl CommandEvent {
    fn ended(result: CommandResult) -> Self {
        Self::Ended(Box::new(result))
    }
}

/// One running command.
struct Command {
    stream: StreamId,
    input: Vec<u8>,
    sent: usize,
    opened: bool,
    host_ended: bool,
    max_output: usize,
    output: Vec<u8>,
    dropped: u64,
    deadline: MonotonicTime,
    started_at: MonotonicTime,
}

impl Command {
    fn finish(
        self,
        end: CommandEnd,
        now: MonotonicTime,
        unsent: Option<SendRefusal>,
    ) -> CommandResult {
        CommandResult {
            stream: self.stream,
            end,
            output: GuestOutput {
                bytes: self.output,
                dropped_bytes: self.dropped,
            },
            input_sent_bytes: self.sent as u64,
            started_at: self.started_at,
            ended_at: now,
            unsent,
        }
    }
}

/// The commands of one boot's link (module docs).
pub(super) struct TerminalCommands {
    /// The next host stream id; `None` once every even id was used.
    next_stream: Option<u32>,
    running: BTreeMap<u32, Command>,
    /// Terminal bytes the host took from the link and has not credited back yet.
    owed_credit: u64,
    events: Vec<CommandEvent>,
}

impl fmt::Debug for TerminalCommands {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminalCommands")
            .field("running", &self.running.keys().collect::<Vec<_>>())
            .field("owed_credit", &self.owed_credit)
            .finish_non_exhaustive()
    }
}

impl TerminalCommands {
    pub(super) fn new() -> Self {
        Self {
            next_stream: Some(2),
            running: BTreeMap::new(),
            owed_credit: 0,
            events: Vec::new(),
        }
    }

    pub(super) fn running(&self) -> usize {
        self.running.len()
    }

    /// Opens a terminal stream on `link` for `request`; its input goes out once the guest
    /// accepted the open and granted credit.
    pub(super) fn start<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        request: CommandRequest,
        now: MonotonicTime,
    ) -> Result<StreamId, CommandRefusal> {
        if request.input.len() > MAX_COMMAND_INPUT_BYTES {
            return Err(CommandRefusal::InputTooLarge {
                input_bytes: request.input.len(),
                max_bytes: MAX_COMMAND_INPUT_BYTES,
            });
        }
        if request.max_output_bytes == 0 || request.max_output_bytes > MAX_COMMAND_OUTPUT_BYTES {
            return Err(CommandRefusal::OutputLimit {
                max_output_bytes: request.max_output_bytes,
                max_bytes: MAX_COMMAND_OUTPUT_BYTES,
            });
        }
        if request.time_limit.is_zero() {
            return Err(CommandRefusal::ZeroTimeLimit);
        }
        let stream = self
            .next_stream
            .and_then(StreamId::new)
            .ok_or(CommandRefusal::StreamIdsExhausted)?;
        link.send(if request.image_entrypoint {
            HostMessage::OpenImageEntrypoint { stream }
        } else {
            HostMessage::OpenTerminal {
                stream,
                columns: request.columns,
                rows: request.rows,
            }
        })
        .map_err(CommandRefusal::Send)?;
        self.next_stream = stream.get().checked_add(2);
        self.running.insert(
            stream.get(),
            Command {
                stream,
                input: request.input,
                sent: 0,
                opened: false,
                host_ended: false,
                max_output: request.max_output_bytes,
                output: Vec::new(),
                dropped: 0,
                deadline: now.saturating_add(request.time_limit),
                started_at: now,
            },
        );
        Ok(stream)
    }

    /// The caller cancels `stream`: the host cancels it on the link and the command ends
    /// with the output so far.
    pub(super) fn cancel<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        stream: StreamId,
        now: MonotonicTime,
    ) -> Result<CommandResult, CommandRefusal> {
        let command = self
            .running
            .remove(&stream.get())
            .ok_or(CommandRefusal::UnknownCommand { stream })?;
        let unsent = cancel_on(link, stream, CancelCause::Requested);
        Ok(command.finish(CommandEnd::Cancelled, now, unsent))
    }

    /// Ends every command whose time limit passed before `now`; the host cancels their
    /// streams.
    pub(super) fn expire<C: Clock>(&mut self, link: &mut HostLink<C>, now: MonotonicTime) {
        let expired: Vec<u32> = self
            .running
            .iter()
            .filter(|(_, command)| now > command.deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(command) = self.running.remove(&id) {
                let unsent = cancel_on(link, command.stream, CancelCause::TimedOut);
                self.events.push(CommandEvent::ended(command.finish(
                    CommandEnd::TimeLimitPassed,
                    now,
                    unsent,
                )));
            }
        }
    }

    /// Takes one of `link`'s events: a command's events are used here, and every other
    /// event is handed back. Terminal output is credited back to the guest whether a
    /// command holds the stream or not, so the channel's window never shrinks.
    pub(super) fn handle<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        event: LinkEvent,
        now: MonotonicTime,
    ) -> Option<LinkEvent> {
        match event {
            LinkEvent::Request(GuestRequest::Opened {
                channel: Channel::Terminal,
                stream,
            }) if self.running.contains_key(&stream.get()) => {
                if let Some(command) = self.running.get_mut(&stream.get()) {
                    command.opened = true;
                }
                self.events.push(CommandEvent::Opened { stream });
                None
            }
            LinkEvent::Request(GuestRequest::OpenRefused {
                channel: Channel::Terminal,
                stream,
                cause,
            }) if self.running.contains_key(&stream.get()) => {
                self.end(stream, CommandEnd::OpenRefused { cause }, now, None);
                None
            }
            LinkEvent::Request(GuestRequest::Data {
                channel: Channel::Terminal,
                stream,
                bytes,
            }) => {
                self.owed_credit = self.owed_credit.saturating_add(bytes.len() as u64);
                let Some(command) = self.running.get_mut(&stream.get()) else {
                    return Some(LinkEvent::Request(GuestRequest::Data {
                        channel: Channel::Terminal,
                        stream,
                        bytes,
                    }));
                };
                let room = command.max_output.saturating_sub(command.output.len());
                let keep = bytes.len().min(room);
                command
                    .output
                    .extend_from_slice(bytes.get(..keep).unwrap_or_default());
                let beyond = bytes.len().saturating_sub(keep);
                if beyond > 0 {
                    command.dropped = command.dropped.saturating_add(beyond as u64);
                    let unsent = cancel_on(link, stream, CancelCause::QuotaExceeded);
                    self.end(stream, CommandEnd::OutputLimitReached, now, unsent);
                }
                None
            }
            LinkEvent::Request(GuestRequest::EndOfStream {
                channel: Channel::Terminal,
                stream,
            }) if self.running.contains_key(&stream.get()) => {
                let unsent = self.end_host_direction(link, stream);
                self.end(stream, CommandEnd::EndedWithoutExit, now, unsent);
                None
            }
            LinkEvent::Request(GuestRequest::Cancel {
                channel: Channel::Terminal,
                stream,
                cause,
            }) if self.running.contains_key(&stream.get()) => {
                self.end(stream, CommandEnd::GuestCancelled { cause }, now, None);
                None
            }
            LinkEvent::Report(report) => {
                let exited = match report.body() {
                    ReportBody::TerminalExit { stream, .. }
                        if self.running.contains_key(&stream.get()) =>
                    {
                        Some(*stream)
                    }
                    _ => None,
                };
                match exited {
                    Some(stream) => {
                        let unsent = self.end_host_direction(link, stream);
                        self.end(stream, CommandEnd::Exited { exit: report }, now, unsent);
                        None
                    }
                    None => Some(LinkEvent::Report(report)),
                }
            }
            LinkEvent::StreamTimedOut {
                channel: Channel::Terminal,
                stream,
                ..
            } if self.running.contains_key(&stream.get()) => {
                self.end(stream, CommandEnd::OpenTimedOut, now, None);
                None
            }
            LinkEvent::ChannelClosed {
                channel: Channel::Terminal,
                cause,
            } => {
                self.owed_credit = 0;
                for result in self.end_all(CommandEnd::TerminalClosed { cause }, now) {
                    self.events.push(CommandEvent::ended(result));
                }
                Some(LinkEvent::ChannelClosed {
                    channel: Channel::Terminal,
                    cause,
                })
            }
            LinkEvent::Closed(cause) => {
                self.owed_credit = 0;
                for result in self.end_all(
                    CommandEnd::LinkClosed {
                        cause: cause.clone(),
                    },
                    now,
                ) {
                    self.events.push(CommandEvent::ended(result));
                }
                Some(LinkEvent::Closed(cause))
            }
            other => Some(other),
        }
    }

    /// Credits taken output back to the guest, then sends each opened command's input
    /// within the guest's credit and the terminal message bound, and ends the host's
    /// direction once all of it went out. What the link does not take now waits for the
    /// next pump.
    pub(super) fn pump<C: Clock>(&mut self, link: &mut HostLink<C>) {
        if self.owed_credit > 0 {
            let credit = u32::try_from(self.owed_credit).unwrap_or(u32::MAX);
            match link.consume(Channel::Terminal, credit) {
                Ok(()) => self.owed_credit -= u64::from(credit),
                Err(ConsumeRefusal::QueueFull { .. }) => {}
                Err(_) => self.owed_credit = 0,
            }
        }
        let chunk = usize::try_from(link.limits().terminal.max_message_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(FIELD_OVERHEAD_BYTES);
        for command in self.running.values_mut() {
            if !command.opened || command.host_ended {
                continue;
            }
            loop {
                let rest = command.input.get(command.sent..).unwrap_or_default();
                if rest.is_empty() {
                    if link
                        .send(HostMessage::EndOfStream {
                            channel: Channel::Terminal,
                            stream: command.stream,
                        })
                        .is_ok()
                    {
                        command.host_ended = true;
                        self.events.push(CommandEvent::InputEnded {
                            stream: command.stream,
                            input_bytes: command.sent as u64,
                        });
                    }
                    break;
                }
                let credit = usize::try_from(link.channel(Channel::Terminal).send_credit_bytes)
                    .unwrap_or(usize::MAX);
                let take = rest.len().min(chunk).min(credit);
                if take == 0 {
                    break;
                }
                let bytes = rest.get(..take).unwrap_or_default().to_vec();
                match link.send(HostMessage::Data {
                    channel: Channel::Terminal,
                    stream: command.stream,
                    bytes,
                }) {
                    Ok(()) => command.sent += take,
                    Err(_) => break,
                }
            }
        }
    }

    /// Ends every running command with `end`; the link is gone or about to be.
    pub(super) fn end_all(&mut self, end: CommandEnd, now: MonotonicTime) -> Vec<CommandResult> {
        std::mem::take(&mut self.running)
            .into_values()
            .map(|command| command.finish(end.clone(), now, None))
            .collect()
    }

    /// Ends every running command with `end` and reports each in the next delivery.
    pub(super) fn end_all_later(&mut self, end: CommandEnd, now: MonotonicTime) {
        for result in self.end_all(end, now) {
            self.events.push(CommandEvent::ended(result));
        }
    }

    pub(super) fn take_events(&mut self) -> Vec<CommandEvent> {
        std::mem::take(&mut self.events)
    }

    /// After the guest ended its direction: the host ends its own if it has not, which
    /// frees the stream; input not sent yet is dropped.
    fn end_host_direction<C: Clock>(
        &mut self,
        link: &mut HostLink<C>,
        stream: StreamId,
    ) -> Option<SendRefusal> {
        let ended = self
            .running
            .get(&stream.get())
            .is_some_and(|command| command.host_ended);
        if ended {
            return None;
        }
        link.send(HostMessage::EndOfStream {
            channel: Channel::Terminal,
            stream,
        })
        .err()
    }

    fn end(
        &mut self,
        stream: StreamId,
        end: CommandEnd,
        now: MonotonicTime,
        unsent: Option<SendRefusal>,
    ) {
        if let Some(command) = self.running.remove(&stream.get()) {
            self.events
                .push(CommandEvent::ended(command.finish(end, now, unsent)));
        }
    }
}

/// Cancels `stream` on `link`; the refusal, if the link did not take the cancel.
fn cancel_on<C: Clock>(
    link: &mut HostLink<C>,
    stream: StreamId,
    cause: CancelCause,
) -> Option<SendRefusal> {
    link.send(HostMessage::Cancel {
        channel: Channel::Terminal,
        stream,
        cause,
    })
    .err()
}
