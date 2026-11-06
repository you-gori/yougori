//! The bounded HTTP/1.1 response reader: the upstream's answer to one forwarded request
//! (VM §4.3: "parse once with bounded, maintained libraries", "disable or re-authorize
//! redirects"; VM-W11: bounded parsers; VM-P10: redirects, upgrades and ambiguous framing
//! cannot bypass typed-operation policy).
//!
//! Bytes are fed incrementally. Every head, interim or final, is parsed once, when
//! complete, by `httparse` with a fixed array of [`MAX_HEADERS`] fields, and all heads of
//! one response together are limited to [`ReaderLimits::max_head_bytes`]. Before that,
//! the request reader's line scan refuses what `httparse` would accept silently: bare line
//! feeds, bare carriage returns, an empty line before a status line and obsolete line
//! folding; `httparse` itself refuses control characters other than tab. Only HTTP/1.1
//! and HTTP/1.0 are read, status codes outside 100..=599 are refused, and header values
//! must be UTF-8 text.
//!
//! `101 Switching Protocols` is refused: nothing switches protocols through the relay.
//! Other interim (1xx) responses are read and dropped, at most [`MAX_INTERIM_RESPONSES`].
//!
//! The final head's framing follows RFC 9112 §6.3. A response to HEAD and a `204` or
//! `304` response has no body, whatever its fields say. Otherwise `Transfer-Encoding:
//! chunked` is decoded by the request reader's strict chunked decoder (no extensions, no
//! trailers), a `Content-Length` body is read exactly, and only when neither field is
//! present does the body run until [`ResponseReader::end_of_input`]. The framing fields
//! are always judged, also when no body follows, by V02's one framing rule
//! (`request_framing`, applied to those fields alone), which refuses Content-Length
//! together with Transfer-Encoding, any other transfer coding, a repeated
//! Transfer-Encoding and a malformed length. Before it the reader refuses several
//! differing Content-Length values (identical repeats are one length) and
//! Transfer-Encoding in an HTTP/1.0 response (RFC 9112 §6.1), and it refuses more than one
//! `Location`, which would make a redirect ambiguous. Bytes after the end of the framed
//! body are refused, and a refusal is final.
//!
//! The result depends only on the bytes, never on how they were split into feeds.

use std::fmt;

use super::chunked::ChunkDecoder;
use super::reader::{scan_head, HeadSyntax, ReadProgress, ReadRefusal, ReaderLimits, MAX_HEADERS};
use crate::sandbox_contract::destinations::http::request_framing;
use crate::sandbox_contract::destinations::{
    BodyFraming, HttpMethod, HttpVersion, InspectedRequest, RequestRefusal,
};

/// The most interim (1xx) responses read and dropped before the final one.
pub const MAX_INTERIM_RESPONSES: usize = 8;

/// The HTTP version of the upstream's response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseVersion {
    Http10,
    Http11,
}

/// How the final response's body is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseFraming {
    /// No body (`BodyFraming::None`: a response to HEAD, `204` or `304`), a
    /// `Content-Length` body or a chunked body.
    Framed(BodyFraming),
    /// Neither `Content-Length` nor `Transfer-Encoding`: the body runs until the input ends.
    UntilClose,
}

/// Why the reader refused the upstream's response (VM §4.3; VM-P10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseReadRefusal {
    /// The heads, interim and final together, did not end within the limit.
    HeadTooLarge {
        limit: usize,
    },
    /// An empty line before a status line.
    EmptyLineBeforeStatus,
    /// A bare line feed, a bare carriage return or obsolete line folding, as the request
    /// reader's line scan refuses them.
    Line(ReadRefusal),
    /// The status line is not `HTTP-version SP 3DIGIT [SP reason]`.
    StatusLine,
    Syntax(HeadSyntax),
    TooManyHeaders {
        limit: usize,
    },
    /// A status code outside 100..=599.
    StatusOutOfRange {
        code: u16,
    },
    /// A header value that is not UTF-8 text.
    HeaderValueNotText {
        name: String,
    },
    /// `101 Switching Protocols`: nothing switches protocols through the relay.
    SwitchingProtocols,
    TooManyInterimResponses {
        limit: usize,
    },
    /// Transfer-Encoding in an HTTP/1.0 response, whose framing is then faulty.
    TransferEncodingInHttp10,
    /// Content-Length values that differ.
    DifferingContentLengths {
        values: Vec<String>,
    },
    /// V02's framing rule refused the framing fields.
    Framing(RequestRefusal),
    /// More than one `Location`.
    DuplicateLocation,
    /// A declared length (Content-Length or a chunk size) over the body limit.
    BodyTooLarge {
        limit: u64,
        length: u64,
    },
    /// A chunked body with its framing, or a body read until the input ends, ran past the
    /// body limit.
    BodyOverLimit {
        limit: u64,
    },
    /// The strict chunked decoder refused the body.
    Chunk(ReadRefusal),
    /// Bytes after the end of the response.
    TrailingBytes,
    /// The input ended before the response did.
    Truncated,
}

impl ResponseReadRefusal {
    fn from_scan(refusal: ReadRefusal) -> Self {
        match refusal {
            ReadRefusal::EmptyLineBeforeRequest => Self::EmptyLineBeforeStatus,
            other => Self::Line(other),
        }
    }

    fn from_chunk(refusal: ReadRefusal) -> Self {
        match refusal {
            ReadRefusal::BodyTooLarge { limit, length } => Self::BodyTooLarge { limit, length },
            other => Self::Chunk(other),
        }
    }
}

impl fmt::Display for ResponseReadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadTooLarge { limit } => {
                write!(f, "the response heads did not end within {limit} bytes")
            }
            Self::EmptyLineBeforeStatus => f.write_str("an empty line came before a status line"),
            Self::Line(refusal) | Self::Chunk(refusal) => fmt::Display::fmt(refusal, f),
            Self::StatusLine => f.write_str("the status line is malformed"),
            Self::Syntax(part) => match part {
                HeadSyntax::RequestLine => f.write_str("the status line is malformed"),
                HeadSyntax::Version => f.write_str("the HTTP version is malformed"),
                HeadSyntax::HeaderName => f.write_str("a header name is malformed"),
                HeadSyntax::HeaderValue => f.write_str("a header value is malformed"),
                HeadSyntax::LineEnding => f.write_str("a line ending is malformed"),
            },
            Self::TooManyHeaders { limit } => {
                write!(f, "a response head has more than {limit} header fields")
            }
            Self::StatusOutOfRange { code } => {
                write!(f, "status code {code} is outside 100..=599")
            }
            Self::HeaderValueNotText { name } => {
                write!(f, "the value of header {name:?} is not UTF-8 text")
            }
            Self::SwitchingProtocols => {
                f.write_str("101 Switching Protocols is refused; the relay switches no protocol")
            }
            Self::TooManyInterimResponses { limit } => {
                write!(f, "more than {limit} interim responses came first")
            }
            Self::TransferEncodingInHttp10 => {
                f.write_str("an HTTP/1.0 response may not carry Transfer-Encoding")
            }
            Self::DifferingContentLengths { values } => {
                write!(f, "the Content-Length values {values:?} differ")
            }
            Self::Framing(refusal) => fmt::Display::fmt(refusal, f),
            Self::DuplicateLocation => f.write_str("the response has more than one Location"),
            Self::BodyTooLarge { limit, length } => {
                write!(f, "a body of {length} bytes is over the {limit}-byte limit")
            }
            Self::BodyOverLimit { limit } => {
                write!(f, "the body ran past the {limit}-byte limit")
            }
            Self::TrailingBytes => f.write_str("bytes followed the end of the response"),
            Self::Truncated => f.write_str("the input ended before the response did"),
        }
    }
}

impl std::error::Error for ResponseReadRefusal {}

/// One complete response as the reader read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResponse {
    version: ResponseVersion,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    framing: ResponseFraming,
    content_length: Option<u64>,
    interim: Vec<u16>,
    body: Vec<u8>,
    wire_bytes: u64,
}

impl ReadResponse {
    pub const fn version(&self) -> ResponseVersion {
        self.version
    }

    /// The final status code, 200..=599 or an interim code never forwarded.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The reason phrase as `httparse` read it (empty when it had obsolete text).
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The final head's fields in received order, names as received.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub const fn framing(&self) -> ResponseFraming {
        self.framing
    }

    /// The declared Content-Length, also when no body followed (HEAD, `304`).
    pub const fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The status codes of the interim responses read and dropped, in order.
    pub fn interim(&self) -> &[u16] {
        &self.interim
    }

    /// The decoded body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The bytes the upstream sent: interim heads, the final head, the body and its
    /// chunk framing.
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}

/// Where a reader ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseOutcome {
    NeedMore,
    Complete(ReadResponse),
    Refused(ResponseReadRefusal),
}

/// One parsed head.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Head {
    version: ResponseVersion,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BodyDecoder {
    Length { remaining: u64 },
    Chunked(ChunkDecoder),
    UntilClose,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BodyRead {
    head: Head,
    framing: ResponseFraming,
    content_length: Option<u64>,
    interim: Vec<u16>,
    decoder: BodyDecoder,
    body: Vec<u8>,
    head_bytes: u64,
    body_wire: u64,
}

impl BodyRead {
    /// The most bytes the body may still bring, framing included.
    fn bound(&self, max_body_bytes: u64) -> u64 {
        match &self.decoder {
            BodyDecoder::Length { remaining } => *remaining,
            BodyDecoder::Chunked(_) | BodyDecoder::UntilClose => {
                max_body_bytes.saturating_sub(self.body_wire)
            }
        }
    }

    /// Consumes body bytes; returns how many and whether the body is complete.
    fn consume(
        &mut self,
        input: &[u8],
        max_body_bytes: u64,
    ) -> Result<(usize, bool), ResponseReadRefusal> {
        let (consumed, done) = match &mut self.decoder {
            BodyDecoder::Length { remaining } => {
                let take = usize::try_from(*remaining).map_or(input.len(), |r| r.min(input.len()));
                self.body
                    .extend_from_slice(input.get(..take).unwrap_or_default());
                *remaining = remaining.saturating_sub(byte_count(take));
                (take, *remaining == 0)
            }
            BodyDecoder::Chunked(decoder) => {
                // The framing counts against the limit too, so the decoder sees no more
                // than the room left.
                let room = max_body_bytes.saturating_sub(self.body_wire);
                let take = usize::try_from(room).map_or(input.len(), |r| r.min(input.len()));
                let (consumed, done) = decoder
                    .consume(
                        input.get(..take).unwrap_or_default(),
                        &mut self.body,
                        max_body_bytes,
                    )
                    .map_err(ResponseReadRefusal::from_chunk)?;
                if !done && take < input.len() {
                    return Err(ResponseReadRefusal::BodyOverLimit {
                        limit: max_body_bytes,
                    });
                }
                (consumed, done)
            }
            BodyDecoder::UntilClose => {
                if self.body_wire.saturating_add(byte_count(input.len())) > max_body_bytes {
                    return Err(ResponseReadRefusal::BodyOverLimit {
                        limit: max_body_bytes,
                    });
                }
                self.body.extend_from_slice(input);
                (input.len(), false)
            }
        };
        self.body_wire = self.body_wire.saturating_add(byte_count(consumed));
        Ok((consumed, done))
    }

    fn finish(self) -> ReadResponse {
        ReadResponse {
            version: self.head.version,
            status: self.head.status,
            reason: self.head.reason,
            headers: self.head.headers,
            framing: self.framing,
            content_length: self.content_length,
            interim: self.interim,
            body: self.body,
            wire_bytes: self.head_bytes.saturating_add(self.body_wire),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReaderState {
    Head {
        buffer: Vec<u8>,
        scanned: usize,
        interim: Vec<u16>,
        /// Bytes of the interim heads already read.
        earlier: usize,
    },
    Body(BodyRead),
    Complete(ReadResponse),
    Refused(ResponseReadRefusal),
}

/// Reads exactly one HTTP/1.1 (or HTTP/1.0) response to a request with a known method,
/// from bytes fed in any split (sans-IO).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseReader {
    limits: ReaderLimits,
    method: HttpMethod,
    state: ReaderState,
}

impl ResponseReader {
    /// A reader for the response to a `method` request; a response to HEAD has no body.
    pub fn new(limits: ReaderLimits, method: HttpMethod) -> Self {
        Self {
            limits,
            method,
            state: ReaderState::Head {
                buffer: Vec::new(),
                scanned: 0,
                interim: Vec::new(),
                earlier: 0,
            },
        }
    }

    pub const fn limits(&self) -> ReaderLimits {
        self.limits
    }

    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Feeds the next bytes from the upstream. After a refusal every feed returns that
    /// refusal; after the response is complete any further byte is refused.
    pub fn feed(&mut self, input: &[u8]) -> Result<ReadProgress, ResponseReadRefusal> {
        let result = self.advance(input);
        self.keep_refusal(result)
    }

    /// The upstream closed the connection: completes a body read until the end of the
    /// input, and refuses a response that has not ended.
    pub fn end_of_input(&mut self) -> Result<ReadProgress, ResponseReadRefusal> {
        let result = match &self.state {
            ReaderState::Refused(refusal) => Err(refusal.clone()),
            ReaderState::Complete(_) => Ok(ReadProgress::Complete),
            ReaderState::Body(body) if body.decoder == BodyDecoder::UntilClose => {
                self.complete();
                Ok(ReadProgress::Complete)
            }
            ReaderState::Head { .. } | ReaderState::Body(_) => Err(ResponseReadRefusal::Truncated),
        };
        self.keep_refusal(result)
    }

    /// Once the final head is read and until the body ends, the most bytes the body may
    /// still bring, framing included: the rest of a Content-Length, or what is left of
    /// the body limit for a chunked body or one read until the input ends.
    pub fn body_bound(&self) -> Option<u64> {
        match &self.state {
            ReaderState::Body(body) => Some(body.bound(self.limits.max_body_bytes())),
            ReaderState::Head { .. } | ReaderState::Complete(_) | ReaderState::Refused(_) => None,
        }
    }

    /// The response, the refusal, or that more bytes are needed.
    pub fn into_outcome(self) -> ResponseOutcome {
        match self.state {
            ReaderState::Head { .. } | ReaderState::Body(_) => ResponseOutcome::NeedMore,
            ReaderState::Complete(response) => ResponseOutcome::Complete(response),
            ReaderState::Refused(refusal) => ResponseOutcome::Refused(refusal),
        }
    }

    fn advance(&mut self, input: &[u8]) -> Result<ReadProgress, ResponseReadRefusal> {
        let rest = match &self.state {
            ReaderState::Refused(refusal) => return Err(refusal.clone()),
            ReaderState::Body(_) | ReaderState::Complete(_) => input,
            ReaderState::Head { .. } => match self.advance_head(input)? {
                None => return Ok(ReadProgress::NeedMore),
                Some(consumed) => input.get(consumed..).unwrap_or_default(),
            },
        };
        self.advance_body(rest)
    }

    fn keep_refusal<T>(
        &mut self,
        result: Result<T, ResponseReadRefusal>,
    ) -> Result<T, ResponseReadRefusal> {
        if let Err(refusal) = &result {
            self.state = ReaderState::Refused(refusal.clone());
        }
        result
    }

    /// Reads heads from `input`, dropping interim ones, until the final head ends or the
    /// input runs out; returns how many bytes of `input` the heads took once the final
    /// head ended, leaving the rest of `input` to the body.
    fn advance_head(&mut self, input: &[u8]) -> Result<Option<usize>, ResponseReadRefusal> {
        let limits = self.limits;
        let mut offset = 0;
        loop {
            let ReaderState::Head {
                buffer,
                scanned,
                interim,
                earlier,
            } = &mut self.state
            else {
                return Ok(Some(offset));
            };
            let rest = input.get(offset..).unwrap_or_default();
            let room = limits
                .max_head_bytes()
                .saturating_sub(earlier.saturating_add(buffer.len()));
            let take = room.min(rest.len());
            let before = buffer.len();
            buffer.extend_from_slice(rest.get(..take).unwrap_or_default());
            let Some(head_length) =
                scan_head(buffer, scanned).map_err(ResponseReadRefusal::from_scan)?
            else {
                if earlier.saturating_add(buffer.len()) >= limits.max_head_bytes() {
                    return Err(ResponseReadRefusal::HeadTooLarge {
                        limit: limits.max_head_bytes(),
                    });
                }
                return Ok(None);
            };
            // What follows the head in this feed is not part of it and is not kept.
            buffer.truncate(head_length);
            offset = offset.saturating_add(head_length.saturating_sub(before));
            let head = parse_head(buffer)?;
            if head.status < 200 {
                interim.push(head.status);
                if interim.len() > MAX_INTERIM_RESPONSES {
                    return Err(ResponseReadRefusal::TooManyInterimResponses {
                        limit: MAX_INTERIM_RESPONSES,
                    });
                }
                *earlier = earlier.saturating_add(head_length);
                buffer.clear();
                *scanned = 0;
                continue;
            }
            let (framing, content_length) = final_framing(&head, self.method, limits)?;
            let decoder = match framing {
                ResponseFraming::Framed(BodyFraming::None) => BodyDecoder::Length { remaining: 0 },
                ResponseFraming::Framed(BodyFraming::ContentLength(length)) => {
                    BodyDecoder::Length { remaining: length }
                }
                ResponseFraming::Framed(BodyFraming::Chunked) => {
                    BodyDecoder::Chunked(ChunkDecoder::new())
                }
                ResponseFraming::UntilClose => BodyDecoder::UntilClose,
            };
            let body = BodyRead {
                head,
                framing,
                content_length,
                interim: std::mem::take(interim),
                decoder,
                body: Vec::new(),
                head_bytes: byte_count(earlier.saturating_add(head_length)),
                body_wire: 0,
            };
            self.state = ReaderState::Body(body);
            return Ok(Some(offset));
        }
    }

    /// Feeds body bytes; completes the response when the body ends and refuses any byte
    /// after that end. An empty input still completes a body that needs no bytes.
    fn advance_body(&mut self, input: &[u8]) -> Result<ReadProgress, ResponseReadRefusal> {
        let max_body_bytes = self.limits.max_body_bytes();
        match &mut self.state {
            ReaderState::Refused(refusal) => Err(refusal.clone()),
            ReaderState::Complete(_) if input.is_empty() => Ok(ReadProgress::Complete),
            ReaderState::Complete(_) => Err(ResponseReadRefusal::TrailingBytes),
            ReaderState::Head { .. } => Ok(ReadProgress::NeedMore),
            ReaderState::Body(body) => {
                let (consumed, done) = body.consume(input, max_body_bytes)?;
                if !done {
                    return Ok(ReadProgress::NeedMore);
                }
                self.complete();
                if consumed < input.len() {
                    return Err(ResponseReadRefusal::TrailingBytes);
                }
                Ok(ReadProgress::Complete)
            }
        }
    }

    /// Turns a body in progress into the complete response.
    fn complete(&mut self) {
        // The placeholder is replaced at once by the complete response.
        if let ReaderState::Body(body) = std::mem::replace(
            &mut self.state,
            ReaderState::Refused(ResponseReadRefusal::Truncated),
        ) {
            self.state = ReaderState::Complete(body.finish());
        }
    }
}

fn byte_count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

fn syntax_refusal(error: httparse::Error) -> ResponseReadRefusal {
    match error {
        httparse::Error::HeaderName => ResponseReadRefusal::Syntax(HeadSyntax::HeaderName),
        httparse::Error::HeaderValue => ResponseReadRefusal::Syntax(HeadSyntax::HeaderValue),
        httparse::Error::NewLine => ResponseReadRefusal::Syntax(HeadSyntax::LineEnding),
        httparse::Error::Version => ResponseReadRefusal::Syntax(HeadSyntax::Version),
        httparse::Error::TooManyHeaders => {
            ResponseReadRefusal::TooManyHeaders { limit: MAX_HEADERS }
        }
        httparse::Error::Status | httparse::Error::Token => ResponseReadRefusal::StatusLine,
    }
}

/// Parses one complete head with `httparse` and checks its version and status.
fn parse_head(head: &[u8]) -> Result<Head, ResponseReadRefusal> {
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut fields);
    match parsed.parse(head).map_err(syntax_refusal)? {
        httparse::Status::Complete(length) if length == head.len() => {}
        // The scan found the empty line, so `httparse` must end exactly there; anything
        // else is a disagreement between the two, refused rather than resolved.
        _ => return Err(ResponseReadRefusal::Syntax(HeadSyntax::LineEnding)),
    }
    let (Some(version), Some(status), Some(reason)) = (parsed.version, parsed.code, parsed.reason)
    else {
        return Err(ResponseReadRefusal::StatusLine);
    };
    let version = match version {
        0 => ResponseVersion::Http10,
        1 => ResponseVersion::Http11,
        _ => return Err(ResponseReadRefusal::Syntax(HeadSyntax::Version)),
    };
    if !(100..=599).contains(&status) {
        return Err(ResponseReadRefusal::StatusOutOfRange { code: status });
    }
    if status == 101 {
        return Err(ResponseReadRefusal::SwitchingProtocols);
    }
    let mut headers = Vec::with_capacity(parsed.headers.len());
    for field in parsed.headers.iter() {
        let value = std::str::from_utf8(field.value).map_err(|_| {
            ResponseReadRefusal::HeaderValueNotText {
                name: field.name.to_ascii_lowercase(),
            }
        })?;
        headers.push((field.name.to_owned(), value.to_owned()));
    }
    Ok(Head {
        version,
        status,
        reason: reason.to_owned(),
        headers,
    })
}

/// The framing of a final head (RFC 9112 §6.3) and its declared Content-Length.
fn final_framing(
    head: &Head,
    method: HttpMethod,
    limits: ReaderLimits,
) -> Result<(ResponseFraming, Option<u64>), ResponseReadRefusal> {
    let mut lengths: Vec<&str> = Vec::new();
    let mut fields = Vec::new();
    let mut locations = 0usize;
    for (name, value) in &head.headers {
        if name.eq_ignore_ascii_case("content-length") {
            lengths.extend(value.split(',').map(|part| part.trim_matches([' ', '\t'])));
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            fields.push(("transfer-encoding".to_owned(), value.clone()));
        } else if name.eq_ignore_ascii_case("location") {
            locations = locations.saturating_add(1);
        }
    }
    if locations > 1 {
        return Err(ResponseReadRefusal::DuplicateLocation);
    }
    if head.version == ResponseVersion::Http10 && !fields.is_empty() {
        return Err(ResponseReadRefusal::TransferEncodingInHttp10);
    }
    if let Some(first) = lengths.first() {
        if lengths.iter().any(|length| length != first) {
            return Err(ResponseReadRefusal::DifferingContentLengths {
                values: lengths.iter().map(|length| (*length).to_owned()).collect(),
            });
        }
        fields.push(("content-length".to_owned(), (*first).to_owned()));
    }
    // V02's one framing rule, read for the framing fields alone: a POST may carry a body,
    // so only those fields decide.
    let declared = request_framing(&InspectedRequest {
        version: HttpVersion::Http11,
        method: HttpMethod::Post.as_str().to_owned(),
        target: "/".to_owned(),
        authority: None,
        scheme: None,
        protocol: None,
        headers: fields,
    })
    .map_err(ResponseReadRefusal::Framing)?;
    let content_length = match declared {
        BodyFraming::ContentLength(length) => Some(length),
        BodyFraming::None | BodyFraming::Chunked => None,
    };
    if method == HttpMethod::Head || head.status == 204 || head.status == 304 {
        return Ok((ResponseFraming::Framed(BodyFraming::None), content_length));
    }
    let framing = match declared {
        BodyFraming::None => ResponseFraming::UntilClose,
        BodyFraming::ContentLength(length) if length > limits.max_body_bytes() => {
            return Err(ResponseReadRefusal::BodyTooLarge {
                limit: limits.max_body_bytes(),
                length,
            })
        }
        framed => ResponseFraming::Framed(framed),
    };
    Ok((framing, content_length))
}

#[cfg(test)]
#[path = "tests/response.rs"]
mod tests;
