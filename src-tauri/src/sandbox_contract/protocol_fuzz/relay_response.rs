//! The relay's response reader under the fuzzer (M09B; VM §4.3, VM-W11, VM-P10; VM-W50):
//! `ResponseReader` on mutated upstream responses, read as the answer to a GET and to a
//! HEAD, fed whole, byte by byte and in random splits, with and without the end of the
//! input.
//!
//! Properties, for each method, beside no panic and the same result twice:
//!
//! - Split-independence: two random splits (with empty feeds), each with or without the
//!   end of the input, and byte-by-byte feeding with it for inputs up to 512 bytes, end
//!   exactly where the whole input ends.
//! - Finality: `feed` and `end_of_input` report what the outcome holds. After a refusal
//!   every feed and the end of the input return it again. After a complete response an
//!   empty feed and the end of the input stay complete, any byte is refused as trailing,
//!   and no body bound is left. The end of the input completes only a body read until it
//!   and refuses as truncated whatever else still needs more.
//! - Size limits: a complete response's heads, interim and final together, end within the
//!   head limit; it has at most [`MAX_HEADERS`] fields and [`MAX_INTERIM_RESPONSES`]
//!   interim responses; its body, and a chunked body's framing with it, is within the body
//!   limit. A refusal names the reader's own limits: a head-too-large refusal follows at
//!   least the head limit's bytes, a body-too-large refusal names a length over the body
//!   limit and a body-over-limit refusal follows more body bytes than it. A body still
//!   being read is never bounded above the body limit.
//! - Exactness: a complete response used every input byte; its status codes are the ones
//!   its status lines show, interim ones in 100..=199 but never 101 and the final one in
//!   200..=599; its version is its final status line's; its fields are that head's lines,
//!   in order and none merged, with at most one `Location`, one Content-Length value, and
//!   a Transfer-Encoding only as the lone framing field of an HTTP/1.1 response. Its
//!   framing is RFC 9112 §6.3's as decided here from those fields: no body for HEAD, `204`
//!   and `304`; a chunked body equal to what a separate strict decoder here makes of the
//!   bytes; exactly the Content-Length bytes; or every byte up to the end of the input,
//!   complete only once that end is signalled. Every strict prefix of a framed response
//!   needs more.
//! - HEAD: a response to HEAD never has a body. It is complete only with nothing after its
//!   final head and refused as trailing bytes otherwise, and wherever the heads decide the
//!   outcome (every refusal but a body's, trailing bytes and truncation), the HEAD and GET
//!   readings agree.

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{find, runs, variant, Encoding, Field, Grammar};
use super::rng::SplitMix64;
use crate::sandbox_contract::destinations::{BodyFraming, HttpMethod};
use crate::sandbox_contract::relay::{
    ReadProgress, ReadResponse, ReaderLimits, ResponseFraming, ResponseOutcome,
    ResponseReadRefusal, ResponseReader, ResponseVersion, HEAD_LIMIT_CEILING, MAX_HEADERS,
    MAX_INTERIM_RESPONSES,
};

/// Mutated responses per run.
const ITERATIONS: u64 = 40_000;
/// The reader's limits here: small, so mutated inputs reach both.
const HEAD_LIMIT: usize = 1_024;
const BODY_LIMIT: u64 = 1_024;

fn limits() -> ReaderLimits {
    ReaderLimits::new(HEAD_LIMIT, BODY_LIMIT).unwrap()
}

fn bytes_of(length: usize) -> u64 {
    u64::try_from(length).unwrap()
}

/// `status` as a status line, then `fields` (each ending in CRLF), the empty line and
/// `body`.
fn response(status: &str, fields: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{status}\r\n{fields}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        response(
            "HTTP/1.1 200 OK",
            "Content-Type: application/json\r\nContent-Length: 11\r\n",
            b"{\"a\":\"bc\"}x",
        ),
        response(
            "HTTP/1.1 200 OK",
            "Transfer-Encoding: chunked\r\n",
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        ),
        response(
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain\r\n",
            b"until the upstream closes",
        ),
        response("HTTP/1.0 200 OK", "Server: old\r\n", b"one-zero body"),
        response("HTTP/1.1 204 No Content", "Content-Length: 0\r\n", b""),
        response(
            "HTTP/1.1 304 Not Modified",
            "ETag: \"v1\"\r\nContent-Length: 1234\r\n",
            b"",
        ),
        [
            response("HTTP/1.1 100 Continue", "", b""),
            response(
                "HTTP/1.1 201 Created",
                "Location: /v1/jobs/7\r\nContent-Length: 2\r\n",
                b"{}",
            ),
        ]
        .concat(),
        [
            response(
                "HTTP/1.1 103 Early Hints",
                "Link: </s.css>; rel=preload\r\n",
                b"",
            ),
            response(
                "HTTP/1.1 200 OK",
                "Transfer-Encoding: chunked\r\n",
                b"00A\r\n0123456789\r\n0\r\n\r\n",
            ),
        ]
        .concat(),
        response(
            "HTTP/1.1 302 Found",
            "Location: https://api.example.com/v2\r\nContent-Length: 0\r\n",
            b"",
        ),
        response(
            "HTTP/1.1 404 Not Found",
            "Content-Length: 9\r\nConnection: close\r\n",
            b"not found",
        ),
        response("HTTP/1.1 200 OK", "Content-Length: 1234\r\n", b""),
        response(
            "HTTP/1.1 500 Internal Server Error",
            "Content-Length: 3, 3\r\n",
            b"err",
        ),
        response(
            "HTTP/1.1 200 OK",
            &format!("X-Pad: {}\r\nContent-Length: 0\r\n", "p".repeat(900)),
            b"",
        ),
    ]
}

/// Where the final head ends: past every interim head (a status code starting with 1)
/// and the head after them; `None` while a head has not ended.
fn final_head_end(input: &[u8]) -> Option<usize> {
    let mut start = 0;
    loop {
        let end = start + find(&input[start..], b"\r\n\r\n")? + 4;
        if input.get(start + 9) != Some(&b'1') {
            return Some(end);
        }
        start = end;
    }
}

/// The heads' decimal numbers and the hexadecimal chunk sizes that start body lines.
fn fields(input: &[u8]) -> Vec<Field> {
    let head_end = final_head_end(input).unwrap_or(input.len());
    let mut fields = runs(input, 0, head_end, u8::is_ascii_digit, Encoding::Decimal);
    let mut line = head_end;
    while line < input.len() {
        let digits = input[line..]
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        if digits > 0 {
            fields.push(Field {
                start: line,
                end: line + digits,
                encoding: Encoding::Hex,
            });
        }
        match find(&input[line..], b"\r\n") {
            Some(at) => line += at + 2,
            None => break,
        }
    }
    fields
}

fn grammar() -> Grammar {
    let tokens: [&[u8]; 26] = [
        b"\r\n",
        b"\n",
        b"\r",
        b" ",
        b"\t",
        b":",
        b";ext",
        b"\x00",
        b"\xff",
        b"Content-Length: 5\r\n",
        b"Content-Length: 5, 6\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Transfer-Encoding: gzip, chunked\r\n",
        b"Location: /next\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        b"HTTP/1.0 ",
        b"HTTP/1.1 204 No Content\r\n",
        b"HTTP/1.1 304 Not Modified\r\n",
        b"Connection: keep-alive\r\n",
        b"Upgrade: h2c\r\n",
        b"0\r\n\r\n",
        b"0\r\nX-Trailer: 1\r\n\r\n",
        b"FFFFFFFFFFFFFFFF",
        b" 999 ",
        b"HTTP/1.1 200 OK\r\n\r\n",
    ];
    Grammar {
        seeds: seeds(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![
            bytes_of(HEAD_LIMIT),
            BODY_LIMIT,
            bytes_of(MAX_HEADERS),
            bytes_of(MAX_INTERIM_RESPONSES),
            bytes_of(HEAD_LIMIT_CEILING),
            100,
            101,
            199,
            204,
            304,
            599,
            u64::MAX,
        ],
        fields,
        max_len: 2_600,
    }
}

/// Reads `pieces` fed in order into a fresh reader for `method`, then ends the input when
/// `close` is set.
fn read(method: HttpMethod, pieces: &[&[u8]], close: bool) -> ResponseOutcome {
    let mut reader = ResponseReader::new(limits(), method);
    for piece in pieces {
        let _ = reader.feed(piece);
    }
    if close {
        let _ = reader.end_of_input();
    }
    reader.into_outcome()
}

/// A separate strict chunked decoder for the test: sizes of 1 to 16 hex digits and CRLF,
/// data and CRLF, a zero chunk and CRLF, nothing after. `None` for anything else.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let digits = body
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        if !(1..=16).contains(&digits) || body.get(digits..digits + 2) != Some(b"\r\n") {
            return None;
        }
        let size = usize::from_str_radix(std::str::from_utf8(&body[..digits]).ok()?, 16).ok()?;
        body = &body[digits + 2..];
        if size == 0 {
            return (body == b"\r\n").then_some(decoded);
        }
        let data = body.get(..size)?;
        if body.get(size..size + 2) != Some(b"\r\n") {
            return None;
        }
        decoded.extend_from_slice(data);
        body = &body[size + 2..];
    }
}

/// A Content-Length value as V02 reads one: decimal digits without a leading zero.
fn content_length(text: &str) -> Result<u64, String> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'));
    if !canonical {
        return Err(format!("Content-Length {text:?} was read"));
    }
    text.parse()
        .map_err(|_| format!("Content-Length {text:?} was read"))
}

/// The values of the fields named `wanted`, ignoring case.
fn values<'a>(
    headers: &'a [(String, String)],
    wanted: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .iter()
        .filter(move |(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.as_str())
}

fn framing_label(framing: ResponseFraming) -> &'static str {
    match framing {
        ResponseFraming::Framed(BodyFraming::None) => "None",
        ResponseFraming::Framed(BodyFraming::ContentLength(_)) => "ContentLength",
        ResponseFraming::Framed(BodyFraming::Chunked) => "Chunked",
        ResponseFraming::UntilClose => "UntilClose",
    }
}

fn check_complete(
    input: &[u8],
    method: HttpMethod,
    response: &ReadResponse,
    open: &ResponseOutcome,
) -> Result<(), String> {
    ensure!(
        response.wire_bytes() == bytes_of(input.len()),
        "a complete response used {} of {} bytes",
        response.wire_bytes(),
        input.len()
    );
    let interim = response.interim();
    ensure!(
        interim.len() <= MAX_INTERIM_RESPONSES,
        "{} interim responses were read",
        interim.len()
    );
    ensure!(
        interim
            .iter()
            .all(|code| (100..200).contains(code) && *code != 101),
        "interim status codes {interim:?} were read"
    );
    ensure!(
        (200..=599).contains(&response.status()),
        "final status {} was read",
        response.status()
    );
    let mut starts = Vec::new();
    let mut end = 0;
    for _ in 0..=interim.len() {
        starts.push(end);
        end += find(&input[end..], b"\r\n\r\n")
            .ok_or_else(|| "a complete response without its head end".to_owned())?
            + 4;
    }
    ensure!(end <= HEAD_LIMIT, "{end} bytes of heads were read");
    for (start, code) in starts
        .iter()
        .zip(interim.iter().chain([&response.status()]))
    {
        let line = &input[*start..];
        ensure!(
            line.starts_with(b"HTTP/1.")
                && line.get(9..12) == Some(format!("{code:03}").as_bytes()),
            "status {code} is not the one its status line shows"
        );
    }
    let last = starts.last().copied().unwrap_or(0);
    let head = &input[last..end];
    let version = match head.get(..8) {
        Some(b"HTTP/1.0") => ResponseVersion::Http10,
        Some(b"HTTP/1.1") => ResponseVersion::Http11,
        _ => return Err("a complete response whose final head is not HTTP/1.0 or 1.1".to_owned()),
    };
    ensure!(
        response.version() == version,
        "version {:?} read from a {version:?} status line",
        response.version()
    );
    let headers = response.headers();
    ensure!(
        headers.len() <= MAX_HEADERS,
        "{} header fields were read",
        headers.len()
    );
    let lines = head.windows(2).filter(|pair| *pair == b"\r\n").count();
    ensure!(
        lines == headers.len() + 2,
        "{} header fields from {} head lines",
        headers.len(),
        lines.saturating_sub(2)
    );
    let mut at = find(head, b"\r\n").unwrap_or(0);
    for (name, _) in headers {
        let found = find(&head[at..], name.as_bytes())
            .ok_or_else(|| format!("header {name:?} is not in the head after the last one"))?;
        at += found + name.len();
    }
    ensure!(
        values(headers, "location").count() <= 1,
        "two Location fields were read"
    );
    let lengths: Vec<&str> = values(headers, "content-length")
        .flat_map(|value| value.split(',').map(|part| part.trim_matches([' ', '\t'])))
        .collect();
    ensure!(
        lengths.windows(2).all(|pair| pair[0] == pair[1]),
        "differing Content-Length values {lengths:?} were read"
    );
    let declared = lengths
        .first()
        .map(|length| content_length(length))
        .transpose()?;
    let encodings: Vec<&str> = values(headers, "transfer-encoding").collect();
    ensure!(
        encodings.is_empty()
            || (encodings.len() == 1
                && encodings[0].eq_ignore_ascii_case("chunked")
                && lengths.is_empty()
                && version == ResponseVersion::Http11),
        "Transfer-Encoding {encodings:?} was read beside {lengths:?} in {version:?}"
    );
    ensure!(
        response.content_length() == declared,
        "Content-Length {:?} reported for {declared:?}",
        response.content_length()
    );
    let body = &input[end..];
    let expected = if method == HttpMethod::Head || matches!(response.status(), 204 | 304) {
        ResponseFraming::Framed(BodyFraming::None)
    } else if !encodings.is_empty() {
        ResponseFraming::Framed(BodyFraming::Chunked)
    } else if let Some(length) = declared {
        ResponseFraming::Framed(BodyFraming::ContentLength(length))
    } else {
        ResponseFraming::UntilClose
    };
    ensure!(
        response.framing() == expected,
        "framing {:?}; RFC 9112 §6.3 gives {expected:?}",
        response.framing()
    );
    match expected {
        ResponseFraming::Framed(BodyFraming::None) => ensure!(
            body.is_empty() && response.body().is_empty(),
            "a {method:?} response without a body carried {} bytes",
            body.len()
        ),
        ResponseFraming::Framed(BodyFraming::ContentLength(length)) => ensure!(
            bytes_of(body.len()) == length && response.body() == body && length <= BODY_LIMIT,
            "a Content-Length {length} body of {} bytes",
            response.body().len()
        ),
        ResponseFraming::Framed(BodyFraming::Chunked) => ensure!(
            bytes_of(body.len()) <= BODY_LIMIT && dechunk(body).as_deref() == Some(response.body()),
            "the chunked body of {} bytes decodes otherwise here",
            body.len()
        ),
        ResponseFraming::UntilClose => ensure!(
            response.body() == body
                && bytes_of(body.len()) <= BODY_LIMIT
                && *open == ResponseOutcome::NeedMore,
            "a body read until the end of the input: {} of {} bytes, before that end {open:?}",
            response.body().len(),
            body.len()
        ),
    }
    if expected != ResponseFraming::UntilClose {
        let shorter = read(method, &[&input[..input.len() - 1]], false);
        ensure!(
            shorter == ResponseOutcome::NeedMore,
            "a strict prefix of a complete response gave {shorter:?}"
        );
    }
    Ok(())
}

fn check_refusal(input: &[u8], refusal: &ResponseReadRefusal) -> Result<(), String> {
    use ResponseReadRefusal as R;
    match refusal {
        R::HeadTooLarge { limit } => ensure!(
            *limit == HEAD_LIMIT && input.len() >= HEAD_LIMIT,
            "heads too large at {limit} after {} bytes",
            input.len()
        ),
        R::TooManyHeaders { limit } => {
            ensure!(*limit == MAX_HEADERS, "too many headers at {limit}")
        }
        R::TooManyInterimResponses { limit } => ensure!(
            *limit == MAX_INTERIM_RESPONSES,
            "too many interim responses at {limit}"
        ),
        R::StatusOutOfRange { code } => ensure!(
            !(100..=599).contains(code),
            "status {code} refused as out of range"
        ),
        R::BodyTooLarge { limit, length } => ensure!(
            *limit == BODY_LIMIT && length > limit,
            "a {length}-byte body refused at {limit}"
        ),
        R::BodyOverLimit { limit } => {
            let body = final_head_end(input).map_or(0, |end| input.len() - end);
            ensure!(
                *limit == BODY_LIMIT && bytes_of(body) > BODY_LIMIT,
                "a body of {body} bytes ran past {limit}"
            );
        }
        _ => {}
    }
    Ok(())
}

fn check_finality(
    input: &[u8],
    method: HttpMethod,
    open: &ResponseOutcome,
    closed: &ResponseOutcome,
) -> Result<(), String> {
    let mut reader = ResponseReader::new(limits(), method);
    let progress = reader.feed(input);
    match open {
        ResponseOutcome::Refused(refusal) => {
            let again = Err(refusal.clone());
            ensure!(
                progress == again,
                "feed returned {progress:?} for {refusal:?}"
            );
            ensure!(
                reader.feed(b"x") == again
                    && reader.feed(b"") == again
                    && reader.end_of_input() == again,
                "a refusal was not final"
            );
            ensure!(
                closed == open,
                "the end of the input turned {refusal:?} into {closed:?}"
            );
        }
        ResponseOutcome::Complete(_) => {
            ensure!(
                progress == Ok(ReadProgress::Complete),
                "feed returned {progress:?} for a complete response"
            );
            ensure!(
                reader.body_bound().is_none(),
                "a complete response still has a body bound"
            );
            ensure!(
                reader.clone().feed(b"x") == Err(ResponseReadRefusal::TrailingBytes),
                "a byte after a complete response was not refused"
            );
            ensure!(
                reader.clone().end_of_input() == Ok(ReadProgress::Complete),
                "the end of the input after a complete response"
            );
            ensure!(
                reader.feed(b"") == Ok(ReadProgress::Complete),
                "an empty feed after a complete response"
            );
            ensure!(
                closed == open,
                "the end of the input changed a complete response"
            );
        }
        ResponseOutcome::NeedMore => {
            ensure!(
                progress == Ok(ReadProgress::NeedMore),
                "feed returned {progress:?} for a response needing more"
            );
            if let Some(bound) = reader.body_bound() {
                ensure!(bound <= BODY_LIMIT, "a body bound of {bound} bytes");
            }
            let end = reader.end_of_input();
            match closed {
                ResponseOutcome::Complete(response) => {
                    ensure!(
                        end == Ok(ReadProgress::Complete)
                            && response.framing() == ResponseFraming::UntilClose,
                        "the end of the input completed a {:?} response",
                        response.framing()
                    );
                    ensure!(
                        reader.feed(b"x") == Err(ResponseReadRefusal::TrailingBytes),
                        "a byte after the end of the input was not refused"
                    );
                }
                ResponseOutcome::Refused(refusal) => ensure!(
                    *refusal == ResponseReadRefusal::Truncated && end == Err(refusal.clone()),
                    "the end of the input gave {end:?} and then {refusal:?}"
                ),
                ResponseOutcome::NeedMore => {
                    return Err("the end of the input left a response needing more".to_owned())
                }
            }
        }
    }
    Ok(())
}

/// Checks one method's reading of `input`; returns the outcome with the end of the input
/// signalled, and its label.
fn check_method(input: &[u8], method: HttpMethod) -> Result<(ResponseOutcome, String), String> {
    let open = read(method, &[input], false);
    let closed = read(method, &[input], true);
    ensure!(
        closed == read(method, &[input], true),
        "{method:?}: two readings of one input differ"
    );
    let mut rng = SplitMix64::for_input(input);
    for _ in 0..2 {
        let close = rng.one_in(2);
        let pieces = rng.split(input);
        let split = read(method, &pieces, close);
        let whole = if close { &closed } else { &open };
        ensure!(
            split == *whole,
            "{method:?} fed in {} pieces (end of input: {close}): {split:?}; whole: {whole:?}",
            pieces.len()
        );
    }
    if input.len() <= 512 {
        let bytewise: Vec<&[u8]> = input.chunks(1).collect();
        let split = read(method, &bytewise, true);
        ensure!(
            split == closed,
            "{method:?} byte by byte: {split:?}; whole: {closed:?}"
        );
    }
    check_finality(input, method, &open, &closed)?;
    let label = match &closed {
        ResponseOutcome::NeedMore => {
            return Err(format!(
                "{method:?}: a response needs more after the end of the input"
            ))
        }
        ResponseOutcome::Refused(refusal) => {
            check_refusal(input, refusal)?;
            format!("refused:{}", variant(&format!("{refusal:?}")))
        }
        ResponseOutcome::Complete(response) => {
            check_complete(input, method, response, &open)?;
            format!("complete:{}", framing_label(response.framing()))
        }
    };
    Ok((closed, label))
}

/// Whether the heads alone decided `outcome`: every refusal but a body's, trailing bytes
/// and truncation.
fn decided_by_heads(outcome: &ResponseOutcome) -> bool {
    use ResponseReadRefusal as R;
    matches!(
        outcome,
        ResponseOutcome::Refused(refusal) if !matches!(
            refusal,
            R::BodyTooLarge { .. } | R::BodyOverLimit { .. } | R::Chunk(_) | R::TrailingBytes | R::Truncated
        )
    )
}

/// The GET reading's label, then how the HEAD reading ended.
fn check(input: &[u8]) -> Verdict {
    let (get, label) = check_method(input, HttpMethod::Get)?;
    let (head, _) = check_method(input, HttpMethod::Head)?;
    if decided_by_heads(&get) || decided_by_heads(&head) {
        ensure!(get == head, "GET read {get:?} but HEAD read {head:?}");
    }
    let head_label = match &head {
        ResponseOutcome::Complete(_) => "head_complete",
        ResponseOutcome::Refused(ResponseReadRefusal::TrailingBytes) => "head_trailing",
        ResponseOutcome::Refused(_) => "head_refused",
        ResponseOutcome::NeedMore => "head_need_more",
    };
    Ok(format!("{label}:{head_label}"))
}

/// Responses that reach each refusal and the edges of acceptance, with the label of the
/// GET reading and how the HEAD reading ends.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "refused:Truncated:head_refused",
        input: b"",
    },
    Regression {
        expect: "complete:ContentLength:head_complete",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    },
    Regression {
        expect: "complete:ContentLength:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    },
    Regression {
        expect: "complete:ContentLength:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\nx",
    },
    Regression {
        expect: "complete:Chunked:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                 0000000000000005\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "complete:UntilClose:head_trailing",
        input: b"HTTP/1.1 200 OK\r\n\r\nuntil close",
    },
    Regression {
        expect: "complete:None:head_complete",
        input: b"HTTP/1.1 204 No Content\r\nContent-Length: 7\r\n\r\n",
    },
    Regression {
        expect: "complete:None:head_complete",
        input: b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
    },
    Regression {
        expect: "complete:ContentLength:head_complete",
        input: b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    },
    Regression {
        expect: "refused:SwitchingProtocols:head_refused",
        input: b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n",
    },
    Regression {
        expect: "refused:TooManyInterimResponses:head_refused",
        input: concat!(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )
        .as_bytes(),
    },
    Regression {
        expect: "refused:Line:head_refused",
        input: b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
    },
    Regression {
        expect: "refused:Line:head_refused",
        input: b"HTTP/1.1 200 OK\r\nX-A: b\r\n c\r\n\r\n",
    },
    Regression {
        expect: "refused:EmptyLineBeforeStatus:head_refused",
        input: b"\r\nHTTP/1.1 200 OK\r\n\r\n",
    },
    Regression {
        expect: "refused:Syntax:head_refused",
        input: b"HTTP/2.0 200 OK\r\n\r\n",
    },
    Regression {
        expect: "refused:StatusOutOfRange:head_refused",
        input: b"HTTP/1.1 600 Odd\r\n\r\n",
    },
    Regression {
        expect: "refused:StatusLine:head_refused",
        input: b"HTTP/1.1 2000 OK\r\n\r\n",
    },
    Regression {
        expect: "refused:HeaderValueNotText:head_refused",
        input: b"HTTP/1.1 200 OK\r\nX-Bin: \xff\r\n\r\n",
    },
    Regression {
        expect: "refused:TransferEncodingInHttp10:head_refused",
        input: b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:DifferingContentLengths:head_refused",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
    },
    Regression {
        expect: "refused:Framing:head_refused",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
    },
    Regression {
        expect: "refused:Framing:head_refused",
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
    },
    Regression {
        expect: "refused:Framing:head_refused",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 007\r\n\r\n1234567",
    },
    Regression {
        expect: "refused:DuplicateLocation:head_refused",
        input: b"HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
    },
    Regression {
        expect: "refused:BodyTooLarge:head_complete",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n",
    },
    Regression {
        expect: "refused:BodyTooLarge:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n",
    },
    Regression {
        expect: "refused:Chunk:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                 00000000000000005\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:Chunk:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:Chunk:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: 1\r\n\r\n",
    },
    Regression {
        expect: "refused:TrailingBytes:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab",
    },
    Regression {
        expect: "refused:Truncated:head_trailing",
        input: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel",
    },
];

#[test]
fn mutated_upstream_responses_read_the_same_in_every_split() {
    let run = Run {
        target: "relay::response",
        seed: 0x00E0_1A00_0000_0001,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "relay::response",
        &[
            "complete:None",
            "complete:ContentLength",
            "complete:Chunked",
            "complete:UntilClose",
            "refused:HeadTooLarge",
            "refused:Line",
            "refused:StatusLine",
            "refused:Syntax",
            "refused:Framing",
            "refused:BodyTooLarge",
            "refused:BodyOverLimit",
            "refused:Chunk",
            "refused:TrailingBytes",
            "refused:Truncated",
        ],
    );
    for head in [":head_complete", ":head_trailing", ":head_refused"] {
        let reached: u64 = report
            .outcomes
            .iter()
            .filter(|(label, _)| label.ends_with(head))
            .map(|(_, count)| *count)
            .sum();
        assert!(
            reached > 0,
            "relay::response: no HEAD reading ended as {head}; outcomes {:?}",
            report.outcomes
        );
    }
}

#[test]
fn response_size_limits_hold_at_their_boundaries() {
    let label = |input: &[u8]| check(input).unwrap();
    // Heads of exactly the limit, alone or after an interim head, are read; one byte more
    // is refused.
    let padded = |prefix: &[u8], length: usize| {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: ");
        let pad = length - bytes.len() - 4;
        bytes.extend(std::iter::repeat_n(b'p', pad));
        bytes.extend_from_slice(b"\r\n\r\n");
        bytes
    };
    for prefix in [&b""[..], b"HTTP/1.1 100 Continue\r\n\r\n"] {
        assert_eq!(
            label(&padded(prefix, HEAD_LIMIT)),
            "complete:ContentLength:head_complete"
        );
        assert_eq!(
            label(&padded(prefix, HEAD_LIMIT + 1)),
            "refused:HeadTooLarge:head_refused"
        );
    }
    let limit = usize::try_from(BODY_LIMIT).unwrap();
    // A Content-Length body of exactly the limit is read; one byte more is refused.
    for length in [limit, limit + 1] {
        let fixed = response(
            "HTTP/1.1 200 OK",
            &format!("Content-Length: {length}\r\n"),
            &vec![b'b'; length],
        );
        let expected = if length == limit {
            "complete:ContentLength:head_trailing"
        } else {
            "refused:BodyTooLarge:head_trailing"
        };
        assert_eq!(label(&fixed), expected);
    }
    // A chunked body whose framing ends exactly at the limit is read; one more byte of
    // framing runs over it, and a chunk over the limit is too large.
    let chunked = |size: usize| {
        let mut body = format!("{size:x}\r\n").into_bytes();
        body.extend(std::iter::repeat_n(b'c', size));
        body.extend_from_slice(b"\r\n0\r\n\r\n");
        response("HTTP/1.1 200 OK", "Transfer-Encoding: chunked\r\n", &body)
    };
    let fits = (1..limit)
        .rev()
        .find(|size| size + format!("{size:x}").len() + 9 == limit)
        .unwrap();
    assert_eq!(label(&chunked(fits)), "complete:Chunked:head_trailing");
    assert_eq!(
        label(&chunked(fits + 1)),
        "refused:BodyOverLimit:head_trailing"
    );
    assert_eq!(
        label(&chunked(limit + 1)),
        "refused:BodyTooLarge:head_trailing"
    );
    // A body read until the end of the input: the limit is read, one byte more runs over.
    for length in [limit, limit + 1] {
        let until = response("HTTP/1.1 200 OK", "", &vec![b'u'; length]);
        let expected = if length == limit {
            "complete:UntilClose:head_trailing"
        } else {
            "refused:BodyOverLimit:head_trailing"
        };
        assert_eq!(label(&until), expected);
    }
    // MAX_HEADERS fields are read; one more is refused.
    for count in [MAX_HEADERS, MAX_HEADERS + 1] {
        let fields: String = (0..count)
            .map(|index| format!("X-{index}: v\r\n"))
            .collect();
        let expected = if count == MAX_HEADERS {
            "complete:UntilClose:head_complete"
        } else {
            "refused:TooManyHeaders:head_refused"
        };
        assert_eq!(label(&response("HTTP/1.1 200 OK", &fields, b"")), expected);
    }
    // MAX_INTERIM_RESPONSES interim responses are dropped; one more is refused.
    for count in [MAX_INTERIM_RESPONSES, MAX_INTERIM_RESPONSES + 1] {
        let mut wire = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(count);
        wire.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let expected = if count == MAX_INTERIM_RESPONSES {
            "complete:ContentLength:head_complete"
        } else {
            "refused:TooManyInterimResponses:head_refused"
        };
        assert_eq!(label(&wire), expected);
    }
}
