//! Server-sent event framing shared by the three streamed dialects (S9 line 167:
//! parser/serializer conformance before optional translation).
//!
//! Decoding follows the HTML event-stream rules: lines end in CRLF, LF or CR; a blank
//! line dispatches the event; `:` starts a comment; `data` lines join with LF; a leading
//! byte-order mark is dropped. An event cut off by the end of the stream is discarded,
//! never dispatched, so a disconnect mid-event can only shorten a stream.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One dispatched server-sent event (S9 line 167).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseFrame {
    /// The `event:` name, if the frame carried one.
    pub event: Option<String>,
    /// The joined `data:` lines.
    pub data: String,
}

impl SseFrame {
    /// A frame with only data, as Chat Completions sends (S7 line 126).
    pub fn data(data: impl Into<String>) -> Self {
        Self {
            event: None,
            data: data.into(),
        }
    }

    /// A named frame, as Responses and Messages send (S7 line 126).
    pub fn named(event: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            event: Some(event.into()),
            data: data.into(),
        }
    }
}

/// Incremental decoder: feed text in any split and collect frames (S9 line 167).
#[derive(Clone, Debug, Default)]
pub struct SseDecoder {
    line: String,
    after_cr: bool,
    started: bool,
    event: Option<String>,
    data: String,
    has_data: bool,
}

/// What remained when the stream ended (S9 line 167).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SseTail {
    /// Whether an event had started but was not dispatched; it is discarded.
    pub discarded_partial_event: bool,
}

impl SseDecoder {
    /// A decoder at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes `chunk`, returning every frame it completes.
    pub fn push(&mut self, chunk: &str) -> Vec<SseFrame> {
        let mut frames = Vec::new();
        for character in chunk.chars() {
            if !self.started {
                self.started = true;
                if character == '\u{feff}' {
                    continue;
                }
            }
            if self.after_cr {
                self.after_cr = false;
                if character == '\n' {
                    continue;
                }
            }
            match character {
                '\r' => {
                    self.after_cr = true;
                    self.end_line(&mut frames);
                }
                '\n' => self.end_line(&mut frames),
                other => self.line.push(other),
            }
        }
        frames
    }

    /// Ends the stream; an undispatched event is discarded.
    pub fn finish(self) -> SseTail {
        SseTail {
            discarded_partial_event: !self.line.is_empty() || self.has_data || self.event.is_some(),
        }
    }

    fn end_line(&mut self, frames: &mut Vec<SseFrame>) {
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            self.dispatch(frames);
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line.as_str(), ""),
        };
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => {
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            _ => {}
        }
    }

    fn dispatch(&mut self, frames: &mut Vec<SseFrame>) {
        if !self.has_data {
            self.event = None;
            return;
        }
        let mut data = std::mem::take(&mut self.data);
        if data.ends_with('\n') {
            data.pop();
        }
        self.has_data = false;
        frames.push(SseFrame {
            event: self.event.take(),
            data,
        });
    }
}

/// Decodes a whole stream, returning its frames and its tail (S9 line 167).
pub fn decode_sse(text: &str) -> (Vec<SseFrame>, SseTail) {
    let mut decoder = SseDecoder::new();
    let frames = decoder.push(text);
    (frames, decoder.finish())
}

/// Why frames could not be written as an event stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SseEncodeError {
    /// An event name contains a line break.
    LineBreakInEventName { frame: usize },
    /// Data contains a carriage return, which the decoder would read as a line end.
    CarriageReturnInData { frame: usize },
}

impl fmt::Display for SseEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineBreakInEventName { frame } => {
                write!(f, "frame {frame}: the event name contains a line break")
            }
            Self::CarriageReturnInData { frame } => {
                write!(f, "frame {frame}: the data contains a carriage return")
            }
        }
    }
}

impl std::error::Error for SseEncodeError {}

/// Writes frames as an event stream that [`decode_sse`] reads back unchanged
/// (S9 line 167: serializer conformance).
pub fn encode_sse(frames: &[SseFrame]) -> Result<String, SseEncodeError> {
    let mut text = String::new();
    for (index, frame) in frames.iter().enumerate() {
        if let Some(event) = &frame.event {
            if event.contains(['\r', '\n']) {
                return Err(SseEncodeError::LineBreakInEventName { frame: index });
            }
            text.push_str("event: ");
            text.push_str(event);
            text.push('\n');
        }
        if frame.data.contains('\r') {
            return Err(SseEncodeError::CarriageReturnInData { frame: index });
        }
        for line in frame.data.split('\n') {
            text.push_str("data: ");
            text.push_str(line);
            text.push('\n');
        }
        text.push('\n');
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_names_comments_and_multiline_data() {
        let text = "\u{feff}: keep-alive\nevent: message_start\ndata: {\"a\":1}\n\n\
                    data: first\ndata: second\n\nevent: ping\n\n";
        let (frames, tail) = decode_sse(text);
        assert_eq!(
            frames,
            vec![
                SseFrame::named("message_start", "{\"a\":1}"),
                SseFrame::data("first\nsecond"),
            ]
        );
        // A named block without data dispatches nothing and leaves nothing behind.
        assert!(!tail.discarded_partial_event);
    }

    #[test]
    fn accepts_every_line_ending_and_any_split() {
        let text = "data: one\r\n\r\ndata: two\r\rdata:three\n\n";
        let expected = vec![
            SseFrame::data("one"),
            SseFrame::data("two"),
            SseFrame::data("three"),
        ];
        assert_eq!(decode_sse(text).0, expected);
        // Feed one character at a time: a CR and its LF may arrive in different chunks.
        let mut decoder = SseDecoder::new();
        let mut frames = Vec::new();
        for character in text.chars() {
            frames.extend(decoder.push(&character.to_string()));
        }
        assert_eq!(frames, expected);
        assert!(!decoder.finish().discarded_partial_event);
    }

    #[test]
    fn an_event_cut_off_by_the_end_is_discarded() {
        let (frames, tail) = decode_sse("data: {\"complete\":true}\n\ndata: {\"partial\":");
        assert_eq!(frames, vec![SseFrame::data("{\"complete\":true}")]);
        assert!(tail.discarded_partial_event);
        // Data lines without the dispatching blank line are discarded too.
        let (frames, tail) = decode_sse("data: {\"whole\":1}\n");
        assert!(frames.is_empty());
        assert!(tail.discarded_partial_event);
    }

    #[test]
    fn encoding_round_trips() {
        let frames = vec![
            SseFrame::named("content_block_delta", "{\"x\":\"a:b\"}"),
            SseFrame::data("line one\nline two"),
            SseFrame::data(""),
            SseFrame::data("[DONE]"),
        ];
        let text = encode_sse(&frames).unwrap();
        assert_eq!(
            decode_sse(&text),
            (
                frames,
                SseTail {
                    discarded_partial_event: false
                }
            )
        );
    }

    #[test]
    fn encoding_refuses_what_would_not_round_trip() {
        assert_eq!(
            encode_sse(&[SseFrame::named("a\nb", "{}")]),
            Err(SseEncodeError::LineBreakInEventName { frame: 0 })
        );
        assert_eq!(
            encode_sse(&[SseFrame::data("{}"), SseFrame::data("a\rb")]),
            Err(SseEncodeError::CarriageReturnInData { frame: 1 })
        );
    }
}
