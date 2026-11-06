//! The bounded HTTP/1.1 request reader (VM §4.3: "parse once with bounded, maintained
//! libraries"; VM-W11: bounded parsers; VM-P10: ambiguous request framing cannot bypass
//! typed-operation policy).
//!
//! Bytes are fed incrementally. The head is limited to [`ReaderLimits::max_head_bytes`]
//! and parsed once, when complete, by `httparse` with a fixed array of [`MAX_HEADERS`]
//! fields. Before that, the reader refuses what `httparse` would accept silently and so
//! could not hand on exactly: bare line feeds (which `httparse` treats as line ends), bare
//! carriage returns, empty lines before the request line (which `httparse` skips) and
//! obsolete line folding. The parsed head becomes V02's [`InspectedRequest`] with nothing
//! dropped or merged: header fields stay in received order with their names as received,
//! duplicates stay duplicates for V02 to refuse, and the request target is the raw text.
//!
//! Once the head is complete, and before any body byte is kept, the reader refuses a
//! header whose name is an underscore spelling of a protected header
//! ([`UNDERSCORE_PROTECTED_HEADERS`], V02's credential and method-override headers, and
//! [`TARGET_OVERRIDE_HEADERS`]), since servers that read `_` as `-` would take it for the
//! real one; refuses the request-target overrides themselves, as V02 refuses method
//! overrides; and takes the framing from V02's one rule (`request_framing`), which also
//! refuses an unknown method, every duplicate header, connection-specific headers,
//! conflicting or malformed framing and a body on GET, HEAD or OPTIONS. An `Expect` other
//! than `100-continue` is refused; `100-continue` is reported
//! ([`RequestReader::expects_continue`]) so the transport can answer the guest itself.
//!
//! The body is read only as far as that framing says, within
//! [`ReaderLimits::max_body_bytes`]; chunked bodies go through a strict decoder (no
//! extensions, no trailers). Bytes after the end of the one request are refused, never
//! kept for a next request, and a refusal is final: every later feed returns it again.
//!
//! The result depends only on the bytes, never on how they were split into feeds.

use std::fmt;

use super::chunked::ChunkDecoder;
use crate::sandbox_contract::destinations::http::request_framing;
use crate::sandbox_contract::destinations::{
    BodyFraming, HttpVersion, InspectedRequest, RequestRefusal, METHOD_OVERRIDE_HEADERS,
    RESERVED_CREDENTIAL_HEADERS,
};

/// The fixed number of header fields handed to `httparse`; a head with more is refused.
pub const MAX_HEADERS: usize = 64;

/// The largest head limit a reader accepts.
pub const HEAD_LIMIT_CEILING: usize = 64 * 1024;

/// Headers some servers and frameworks obey in place of the request target; a guest may
/// never send them, as V02 refuses method overrides.
pub const TARGET_OVERRIDE_HEADERS: [&str; 2] = ["x-original-url", "x-rewrite-url"];

/// Framing, hop-by-hop, authority and expectation headers. A name that equals one of
/// these, V02's [`RESERVED_CREDENTIAL_HEADERS`] or [`METHOD_OVERRIDE_HEADERS`], or
/// [`TARGET_OVERRIDE_HEADERS`] once each `_` is read as `-` is refused: CGI-style servers
/// map both spellings to one variable, so the twin would bypass the check on the real one.
pub const UNDERSCORE_PROTECTED_HEADERS: [&str; 11] = [
    "content-length",
    "transfer-encoding",
    "host",
    "expect",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "http2-settings",
];

/// The one expectation a request may carry.
const CONTINUE: &str = "100-continue";

/// Why reader limits were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsError {
    /// The head limit is zero or above [`HEAD_LIMIT_CEILING`].
    HeadLimitOutOfRange { requested: usize, ceiling: usize },
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadLimitOutOfRange { requested, ceiling } => write!(
                f,
                "a head limit of {requested} bytes is outside 1..={ceiling}"
            ),
        }
    }
}

impl std::error::Error for LimitsError {}

/// The size limits of one reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReaderLimits {
    max_head_bytes: usize,
    max_body_bytes: u64,
}

impl ReaderLimits {
    /// Limits with a head of at most `max_head_bytes` (request line, fields and the empty
    /// line) and a decoded body of at most `max_body_bytes`.
    pub fn new(max_head_bytes: usize, max_body_bytes: u64) -> Result<Self, LimitsError> {
        if max_head_bytes == 0 || max_head_bytes > HEAD_LIMIT_CEILING {
            return Err(LimitsError::HeadLimitOutOfRange {
                requested: max_head_bytes,
                ceiling: HEAD_LIMIT_CEILING,
            });
        }
        Ok(Self {
            max_head_bytes,
            max_body_bytes,
        })
    }

    pub const fn max_head_bytes(&self) -> usize {
        self.max_head_bytes
    }

    pub const fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }

    /// The same limits with the body limit lowered to at most `cap`.
    pub fn with_body_cap(self, cap: u64) -> Self {
        Self {
            max_body_bytes: self.max_body_bytes.min(cap),
            ..self
        }
    }
}

/// Which part of the head `httparse` found malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeadSyntax {
    /// The method or the request target, or the single spaces between them.
    RequestLine,
    Version,
    HeaderName,
    HeaderValue,
    LineEnding,
}

impl HeadSyntax {
    const fn describe(self) -> &'static str {
        match self {
            Self::RequestLine => "the request line",
            Self::Version => "the HTTP version",
            Self::HeaderName => "a header name",
            Self::HeaderValue => "a header value",
            Self::LineEnding => "a line ending",
        }
    }
}

/// Why the reader refused the guest's bytes (VM §4.3; VM-P10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadRefusal {
    /// The head did not end within the limit.
    HeadTooLarge {
        limit: usize,
    },
    /// An empty line before the request line.
    EmptyLineBeforeRequest,
    /// A line feed without the carriage return before it.
    BareLineFeed,
    /// A carriage return without the line feed after it.
    BareCarriageReturn,
    /// A header line starting with a space or tab (obsolete line folding).
    ObsoleteLineFolding,
    Syntax(HeadSyntax),
    TooManyHeaders {
        limit: usize,
    },
    /// HTTP/1.0; only HTTP/1.1 is read.
    NotHttp11,
    /// A header value that is not UTF-8 text, which [`InspectedRequest`] cannot hold.
    HeaderValueNotText {
        name: String,
    },
    /// A header name that is an underscore spelling of a protected header.
    UnderscoreTwin {
        name: String,
    },
    /// A header that overrides the request target.
    TargetOverride {
        header: String,
    },
    /// An `Expect` other than `100-continue`.
    UnsupportedExpectation {
        value: String,
    },
    /// V02 refused the head while reading its framing, before any body byte was kept.
    Inspection(RequestRefusal),
    /// The declared or decoded body is over the limit.
    BodyTooLarge {
        limit: u64,
        length: u64,
    },
    /// A chunk size that is not 1 to 16 hexadecimal digits followed by CRLF.
    InvalidChunkSize,
    ChunkExtension,
    /// Chunk data, or the last chunk, not followed by CRLF.
    ChunkNotTerminated,
    /// A trailer field after the last chunk.
    Trailers,
    /// Bytes after the end of the request (pipelining).
    PipelinedBytes,
}

impl fmt::Display for ReadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadTooLarge { limit } => {
                write!(f, "the request head did not end within {limit} bytes")
            }
            Self::EmptyLineBeforeRequest => {
                f.write_str("an empty line came before the request line")
            }
            Self::BareLineFeed => f.write_str("a line feed is not preceded by a carriage return"),
            Self::BareCarriageReturn => {
                f.write_str("a carriage return is not followed by a line feed")
            }
            Self::ObsoleteLineFolding => {
                f.write_str("a header line starts with whitespace (obsolete line folding)")
            }
            Self::Syntax(part) => write!(f, "{} is malformed", part.describe()),
            Self::TooManyHeaders { limit } => {
                write!(f, "the request has more than {limit} header fields")
            }
            Self::NotHttp11 => f.write_str("only HTTP/1.1 requests are read"),
            Self::HeaderValueNotText { name } => {
                write!(f, "the value of header {name:?} is not UTF-8 text")
            }
            Self::UnderscoreTwin { name } => write!(
                f,
                "header {name:?} is an underscore spelling of a protected header"
            ),
            Self::TargetOverride { header } => {
                write!(f, "target override header {header:?} is refused")
            }
            Self::UnsupportedExpectation { value } => {
                write!(
                    f,
                    "Expect {value:?} is refused; only 100-continue is accepted"
                )
            }
            Self::Inspection(refusal) => fmt::Display::fmt(refusal, f),
            Self::BodyTooLarge { limit, length } => {
                write!(f, "a body of {length} bytes is over the {limit}-byte limit")
            }
            Self::InvalidChunkSize => {
                f.write_str("a chunk size is not 1 to 16 hex digits followed by CRLF")
            }
            Self::ChunkExtension => f.write_str("chunk extensions are refused"),
            Self::ChunkNotTerminated => f.write_str("chunk data is not followed by CRLF"),
            Self::Trailers => f.write_str("trailer fields are refused"),
            Self::PipelinedBytes => f.write_str("bytes followed the end of the request"),
        }
    }
}

impl std::error::Error for ReadRefusal {}

/// One complete request as the reader read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    request: InspectedRequest,
    framing: BodyFraming,
    expects_continue: bool,
    body: Vec<u8>,
    wire_bytes: u64,
}

impl ReadRequest {
    /// The parsed head, for V02.
    pub fn request(&self) -> &InspectedRequest {
        &self.request
    }

    /// The framing the reader followed, as V02's rule read it.
    pub const fn framing(&self) -> BodyFraming {
        self.framing
    }

    /// Whether the guest sent `Expect: 100-continue`. The expectation is never forwarded.
    pub const fn expects_continue(&self) -> bool {
        self.expects_continue
    }

    /// The decoded body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The bytes the guest sent for this request: head, framing and body.
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}

/// What one feed achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadProgress {
    NeedMore,
    Complete,
}

/// Where a reader ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    NeedMore,
    Complete(ReadRequest),
    Refused(ReadRefusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BodyDecoder {
    Length { remaining: u64 },
    Chunked(ChunkDecoder),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BodyRead {
    request: InspectedRequest,
    framing: BodyFraming,
    expects_continue: bool,
    decoder: BodyDecoder,
    body: Vec<u8>,
    wire_bytes: u64,
}

impl BodyRead {
    /// Consumes body bytes; returns how many and whether the body is complete.
    fn consume(&mut self, input: &[u8], max_body_bytes: u64) -> Result<(usize, bool), ReadRefusal> {
        let (consumed, done) = match &mut self.decoder {
            BodyDecoder::Length { remaining } => {
                let take = usize::try_from(*remaining).map_or(input.len(), |r| r.min(input.len()));
                self.body.extend_from_slice(&input[..take]);
                let taken = u64::try_from(take).map_err(|_| ReadRefusal::BodyTooLarge {
                    limit: max_body_bytes,
                    length: u64::MAX,
                })?;
                *remaining = remaining.saturating_sub(taken);
                (take, *remaining == 0)
            }
            BodyDecoder::Chunked(decoder) => {
                decoder.consume(input, &mut self.body, max_body_bytes)?
            }
        };
        let consumed_bytes = u64::try_from(consumed).unwrap_or(u64::MAX);
        self.wire_bytes = self.wire_bytes.saturating_add(consumed_bytes);
        Ok((consumed, done))
    }

    fn finish(self) -> ReadRequest {
        ReadRequest {
            request: self.request,
            framing: self.framing,
            expects_continue: self.expects_continue,
            body: self.body,
            wire_bytes: self.wire_bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReaderState {
    Head { buffer: Vec<u8>, scanned: usize },
    Body(BodyRead),
    Complete(ReadRequest),
    Refused(ReadRefusal),
}

/// Reads exactly one HTTP/1.1 request from bytes fed in any split (sans-IO).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestReader {
    limits: ReaderLimits,
    state: ReaderState,
}

impl RequestReader {
    pub fn new(limits: ReaderLimits) -> Self {
        Self {
            limits,
            state: ReaderState::Head {
                buffer: Vec::new(),
                scanned: 0,
            },
        }
    }

    pub const fn limits(&self) -> ReaderLimits {
        self.limits
    }

    /// Feeds the next bytes from the guest. After a refusal every feed returns that
    /// refusal; after the request is complete any further byte is refused as pipelining.
    pub fn feed(&mut self, input: &[u8]) -> Result<ReadProgress, ReadRefusal> {
        let result = self.advance(input);
        if let Err(refusal) = &result {
            self.state = ReaderState::Refused(refusal.clone());
        }
        result
    }

    /// True once the head is complete and accepted with `Expect: 100-continue`: the
    /// transport may then answer the guest `100 Continue` itself, since the relay reads the
    /// whole body before anything goes upstream.
    pub fn expects_continue(&self) -> bool {
        match &self.state {
            ReaderState::Body(body) => body.expects_continue,
            ReaderState::Complete(request) => request.expects_continue,
            ReaderState::Head { .. } | ReaderState::Refused(_) => false,
        }
    }

    /// The request, the refusal, or that more bytes are needed.
    pub fn into_outcome(self) -> ReadOutcome {
        match self.state {
            ReaderState::Head { .. } | ReaderState::Body(_) => ReadOutcome::NeedMore,
            ReaderState::Complete(request) => ReadOutcome::Complete(request),
            ReaderState::Refused(refusal) => ReadOutcome::Refused(refusal),
        }
    }

    fn advance(&mut self, input: &[u8]) -> Result<ReadProgress, ReadRefusal> {
        let limits = self.limits;
        match &mut self.state {
            ReaderState::Refused(refusal) => Err(refusal.clone()),
            ReaderState::Complete(_) if input.is_empty() => Ok(ReadProgress::Complete),
            ReaderState::Complete(_) => Err(ReadRefusal::PipelinedBytes),
            ReaderState::Body(_) => self.advance_body(&[input]),
            ReaderState::Head { buffer, scanned } => {
                let room = limits.max_head_bytes.saturating_sub(buffer.len());
                let take = room.min(input.len());
                buffer.extend_from_slice(&input[..take]);
                let Some(head_length) = scan_head(buffer, scanned)? else {
                    if buffer.len() >= limits.max_head_bytes {
                        return Err(ReadRefusal::HeadTooLarge {
                            limit: limits.max_head_bytes,
                        });
                    }
                    return Ok(ReadProgress::NeedMore);
                };
                let head = parse_head(&buffer[..head_length], limits)?;
                let buffered_body = buffer.split_off(head_length);
                let decoder = match head.framing {
                    BodyFraming::None => BodyDecoder::Length { remaining: 0 },
                    BodyFraming::ContentLength(length) => BodyDecoder::Length { remaining: length },
                    BodyFraming::Chunked => BodyDecoder::Chunked(ChunkDecoder::new()),
                };
                self.state = ReaderState::Body(BodyRead {
                    request: head.request,
                    framing: head.framing,
                    expects_continue: head.expects_continue,
                    decoder,
                    body: Vec::new(),
                    wire_bytes: u64::try_from(head_length).unwrap_or(u64::MAX),
                });
                self.advance_body(&[&buffered_body, &input[take..]])
            }
        }
    }

    /// Feeds `parts`, in order, to the body; completes the request when the body ends and
    /// refuses any byte after that end.
    fn advance_body(&mut self, parts: &[&[u8]]) -> Result<ReadProgress, ReadRefusal> {
        let max_body_bytes = self.limits.max_body_bytes;
        // An empty part still lets a body that needs no bytes complete.
        for part in std::iter::once(&[][..]).chain(parts.iter().copied()) {
            match &mut self.state {
                ReaderState::Body(body) => {
                    let (consumed, done) = body.consume(part, max_body_bytes)?;
                    if done {
                        // Moves the body out of the state; the placeholder is replaced at
                        // once by the complete request.
                        if let ReaderState::Body(body) = std::mem::replace(
                            &mut self.state,
                            ReaderState::Refused(ReadRefusal::PipelinedBytes),
                        ) {
                            self.state = ReaderState::Complete(body.finish());
                        }
                        if consumed < part.len() {
                            return Err(ReadRefusal::PipelinedBytes);
                        }
                    }
                }
                ReaderState::Complete(_) if part.is_empty() => {}
                ReaderState::Complete(_) => return Err(ReadRefusal::PipelinedBytes),
                ReaderState::Head { .. } | ReaderState::Refused(_) => {}
            }
        }
        Ok(match self.state {
            ReaderState::Complete(_) => ReadProgress::Complete,
            _ => ReadProgress::NeedMore,
        })
    }
}

/// Scans the buffered head from `*scanned` for line-ending faults, obsolete folding and
/// the empty line that ends the head; returns the head's length once it ended. A carriage
/// return at the end of the buffer waits for the next byte.
pub(super) fn scan_head(buffer: &[u8], scanned: &mut usize) -> Result<Option<usize>, ReadRefusal> {
    let mut index = *scanned;
    while index < buffer.len() {
        let byte = buffer[index];
        if index == 0 && byte == b'\r' {
            return Err(ReadRefusal::EmptyLineBeforeRequest);
        }
        let line_start = index >= 2 && &buffer[index - 2..index] == b"\r\n";
        if line_start && (byte == b' ' || byte == b'\t') {
            return Err(ReadRefusal::ObsoleteLineFolding);
        }
        match byte {
            b'\n' => {
                if index == 0 || buffer[index - 1] != b'\r' {
                    return Err(ReadRefusal::BareLineFeed);
                }
                if index >= 3 && &buffer[index - 3..index - 1] == b"\r\n" {
                    *scanned = index + 1;
                    return Ok(Some(index + 1));
                }
            }
            b'\r' => match buffer.get(index + 1) {
                None => break,
                Some(b'\n') => {}
                Some(_) => return Err(ReadRefusal::BareCarriageReturn),
            },
            _ => {}
        }
        index += 1;
    }
    *scanned = index;
    Ok(None)
}

fn syntax_refusal(error: httparse::Error) -> ReadRefusal {
    match error {
        httparse::Error::HeaderName => ReadRefusal::Syntax(HeadSyntax::HeaderName),
        httparse::Error::HeaderValue => ReadRefusal::Syntax(HeadSyntax::HeaderValue),
        httparse::Error::NewLine => ReadRefusal::Syntax(HeadSyntax::LineEnding),
        httparse::Error::Version => ReadRefusal::Syntax(HeadSyntax::Version),
        httparse::Error::TooManyHeaders => ReadRefusal::TooManyHeaders { limit: MAX_HEADERS },
        httparse::Error::Token | httparse::Error::Status => {
            ReadRefusal::Syntax(HeadSyntax::RequestLine)
        }
    }
}

/// A complete head that passed the reader's and V02's head checks.
struct AcceptedHead {
    request: InspectedRequest,
    framing: BodyFraming,
    expects_continue: bool,
}

/// Parses one complete head with `httparse`, checks it, and takes its framing from V02.
fn parse_head(head: &[u8], limits: ReaderLimits) -> Result<AcceptedHead, ReadRefusal> {
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut fields);
    match parsed.parse(head).map_err(syntax_refusal)? {
        httparse::Status::Complete(length) if length == head.len() => {}
        // The scan found the empty line, so `httparse` must end exactly there; anything
        // else is a disagreement between the two, refused rather than resolved.
        _ => return Err(ReadRefusal::Syntax(HeadSyntax::LineEnding)),
    }
    let (Some(method), Some(target), Some(version)) = (parsed.method, parsed.path, parsed.version)
    else {
        return Err(ReadRefusal::Syntax(HeadSyntax::RequestLine));
    };
    if version != 1 {
        return Err(ReadRefusal::NotHttp11);
    }
    let mut headers = Vec::with_capacity(parsed.headers.len());
    for field in parsed.headers.iter() {
        let value =
            std::str::from_utf8(field.value).map_err(|_| ReadRefusal::HeaderValueNotText {
                name: field.name.to_ascii_lowercase(),
            })?;
        check_name(field.name)?;
        headers.push((field.name.to_owned(), value.to_owned()));
    }
    let request = InspectedRequest {
        version: HttpVersion::Http11,
        method: method.to_owned(),
        target: target.to_owned(),
        authority: None,
        scheme: None,
        protocol: None,
        headers,
    };
    let framing = request_framing(&request).map_err(ReadRefusal::Inspection)?;
    // V02 refused duplicates, so there is at most one `Expect`.
    let expects_continue = match request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("expect"))
    {
        None => false,
        Some((_, value)) if value.eq_ignore_ascii_case(CONTINUE) => true,
        Some((_, value)) => {
            return Err(ReadRefusal::UnsupportedExpectation {
                value: value.clone(),
            })
        }
    };
    if let BodyFraming::ContentLength(length) = framing {
        if length > limits.max_body_bytes {
            return Err(ReadRefusal::BodyTooLarge {
                limit: limits.max_body_bytes,
                length,
            });
        }
    }
    Ok(AcceptedHead {
        request,
        framing,
        expects_continue,
    })
}

/// Refuses a request-target override and an underscore spelling of a protected header.
fn check_name(name: &str) -> Result<(), ReadRefusal> {
    if let Some(header) = TARGET_OVERRIDE_HEADERS
        .iter()
        .find(|header| name.eq_ignore_ascii_case(header))
    {
        return Err(ReadRefusal::TargetOverride {
            header: (*header).to_owned(),
        });
    }
    let mut protected = UNDERSCORE_PROTECTED_HEADERS
        .iter()
        .chain(&RESERVED_CREDENTIAL_HEADERS)
        .chain(&METHOD_OVERRIDE_HEADERS)
        .chain(&TARGET_OVERRIDE_HEADERS);
    if protected.any(|protected| is_underscore_twin(name, protected)) {
        return Err(ReadRefusal::UnderscoreTwin {
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// True when `name` has an underscore and equals the lowercase `protected` once each `_`
/// is read as `-`, ignoring ASCII case.
fn is_underscore_twin(name: &str, protected: &str) -> bool {
    name.contains('_')
        && name.len() == protected.len()
        && name.bytes().zip(protected.bytes()).all(|(byte, expected)| {
            let byte = if byte == b'_' {
                b'-'
            } else {
                byte.to_ascii_lowercase()
            };
            byte == expected
        })
}
