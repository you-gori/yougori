//! Server-sent events, as the relay and MCP servers stream them.
//!
//! Lines may end in `\n` or `\r\n` and arrive split anywhere (inside a line, inside a UTF-8
//! character). A blank line ends an event; servers that leave the blank line out between two
//! complete JSON `data:` lines are tolerated.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field, `message` when absent.
    pub event: String,
    pub data: String,
}

#[derive(Default)]
pub struct SseParser {
    buf: Vec<u8>,
    event: String,
    data: String,
    has_data: bool,
}

impl SseParser {
    /// Feeds bytes; returns the events they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut start = 0;
        while let Some(offset) = self.buf[start..].iter().position(|&b| b == b'\n') {
            let end = start + offset;
            let mut line = &self.buf[start..end];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            let line = String::from_utf8_lossy(line).into_owned();
            self.line(&line, &mut out);
            start = end + 1;
        }
        self.buf.drain(..start);
        out
    }

    /// The stream ended: whatever is pending becomes a last event.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            let line = String::from_utf8_lossy(&rest);
            let line = line.trim_end_matches('\r').to_owned();
            self.line(&line, &mut out);
        }
        self.dispatch(&mut out);
        out
    }

    fn line(&mut self, line: &str, out: &mut Vec<SseEvent>) {
        if line.is_empty() {
            self.dispatch(out);
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.find(':') {
            Some(at) => {
                let value = &line[at + 1..];
                (&line[..at], value.strip_prefix(' ').unwrap_or(value))
            }
            None => (line, ""),
        };
        match field {
            "data" => {
                if self.has_data {
                    // A server that skips the blank line: a complete JSON value before this
                    // line is its own event.
                    if serde_json::from_str::<serde_json::Value>(&self.data).is_ok() {
                        self.dispatch(out);
                    } else {
                        self.data.push('\n');
                    }
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            "event" => self.event = value.to_owned(),
            _ => {}
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        if self.has_data {
            let event = if self.event.is_empty() { "message".to_owned() } else { std::mem::take(&mut self.event) };
            out.push(SseEvent { event, data: std::mem::take(&mut self.data) });
        }
        self.has_data = false;
        self.event.clear();
        self.data.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(events: &[SseEvent]) -> Vec<&str> {
        events.iter().map(|e| e.data.as_str()).collect()
    }

    #[test]
    fn events_split_anywhere_and_crlf() {
        let text = "data: {\"a\":1}\r\n\r\n: comment\n\nevent: error\ndata: {\"b\":\ndata: 2}\n\ndata: [DONE]\n\n";
        let mut parser = SseParser::default();
        let mut events = Vec::new();
        for byte in text.as_bytes().chunks(3) {
            events.extend(parser.push(byte));
        }
        events.extend(parser.finish());
        assert_eq!(data(&events), vec!["{\"a\":1}", "{\"b\":\n2}", "[DONE]"]);
        assert_eq!(events[1].event, "error");
        assert_eq!(events[0].event, "message");
    }

    #[test]
    fn utf8_split_across_chunks_survives() {
        let text = "data: {\"t\":\"h\u{e9}llo \u{4e16}\u{754c}\"}\n\n".as_bytes().to_vec();
        let mut parser = SseParser::default();
        let mut events = Vec::new();
        for byte in text.chunks(1) {
            events.extend(parser.push(byte));
        }
        assert_eq!(data(&events), vec!["{\"t\":\"h\u{e9}llo \u{4e16}\u{754c}\"}"]);
    }

    #[test]
    fn missing_blank_lines_between_json_lines_are_tolerated() {
        let mut parser = SseParser::default();
        let mut events = parser.push(b"data: {\"a\":1}\ndata: {\"a\":2}\n");
        events.extend(parser.finish());
        assert_eq!(data(&events), vec!["{\"a\":1}", "{\"a\":2}"]);
    }
}
