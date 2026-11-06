//! The response reader alone: every framing case, interim responses, the refused forms,
//! each limit, and the same outcome for every split of the same bytes (VM §4.3;
//! VM-P10). Declared by `response.rs`, so the request side's `tests/mod.rs` is unchanged.

use crate::sandbox_contract::destinations::{BodyFraming, HttpMethod, RequestRefusal};
use crate::sandbox_contract::relay::{
    HeadSyntax, ReadProgress, ReadRefusal, ReadResponse, ReaderLimits, ResponseFraming,
    ResponseOutcome, ResponseReadRefusal, ResponseReader, ResponseVersion, MAX_HEADERS,
    MAX_INTERIM_RESPONSES,
};

fn limits() -> ReaderLimits {
    ReaderLimits::new(1_024, 4_096).unwrap()
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

/// A final `200 OK` head with `fields` (each ending in CRLF) and `body` after it.
fn ok(fields: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("HTTP/1.1 200 OK\r\n{fields}\r\n").into_bytes();
    wire.extend_from_slice(body);
    wire
}

/// Feeds `parts` in order with `limits`, then ends the input when `close` is set.
fn read_parts_with(
    limits: ReaderLimits,
    method: HttpMethod,
    parts: &[&[u8]],
    close: bool,
) -> ResponseOutcome {
    let mut reader = ResponseReader::new(limits, method);
    for part in parts {
        let _ = reader.feed(part);
    }
    if close {
        let _ = reader.end_of_input();
    }
    reader.into_outcome()
}

fn read_parts(method: HttpMethod, parts: &[&[u8]], close: bool) -> ResponseOutcome {
    read_parts_with(limits(), method, parts, close)
}

/// The response to a GET, read in one feed without an end of input.
fn read(wire: &[u8]) -> ResponseOutcome {
    read_parts(HttpMethod::Get, &[wire], false)
}

fn complete(outcome: ResponseOutcome) -> ReadResponse {
    match outcome {
        ResponseOutcome::Complete(response) => response,
        other => panic!("expected a complete response, got {other:?}"),
    }
}

fn read_ok(wire: &[u8]) -> ReadResponse {
    complete(read(wire))
}

fn refused_with(limits: ReaderLimits, wire: &[u8]) -> ResponseReadRefusal {
    match read_parts_with(limits, HttpMethod::Get, &[wire], false) {
        ResponseOutcome::Refused(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refused(wire: &[u8]) -> ResponseReadRefusal {
    refused_with(limits(), wire)
}

/// Feeds `wire` one byte at a time.
fn read_bytewise(method: HttpMethod, wire: &[u8], close: bool) -> ResponseOutcome {
    let parts: Vec<&[u8]> = wire.chunks(1).collect();
    read_parts(method, &parts, close)
}

#[test]
fn a_content_length_body_is_read_exactly_with_the_head_as_received() {
    let wire = ok(
        "Content-Type: application/json\r\nContent-Length: 13\r\nX-Trace: a\r\nx-trace: b\r\n",
        b"{\"model\":\"a\"}",
    );
    let response = read_ok(&wire);
    assert_eq!(response.version(), ResponseVersion::Http11);
    assert_eq!(response.status(), 200);
    assert_eq!(response.reason(), "OK");
    // Received order and names as received; duplicates stay duplicates.
    assert_eq!(
        response.headers(),
        &[
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Length".to_owned(), "13".to_owned()),
            ("X-Trace".to_owned(), "a".to_owned()),
            ("x-trace".to_owned(), "b".to_owned()),
        ]
    );
    assert_eq!(
        response.framing(),
        ResponseFraming::Framed(BodyFraming::ContentLength(13))
    );
    assert_eq!(response.content_length(), Some(13));
    assert_eq!(response.body(), b"{\"model\":\"a\"}");
    assert!(response.interim().is_empty());
    assert_eq!(response.wire_bytes(), length(&wire));
    let empty = read_ok(&ok("Content-Length: 0\r\n", b""));
    assert_eq!(
        empty.framing(),
        ResponseFraming::Framed(BodyFraming::ContentLength(0))
    );
    assert!(empty.body().is_empty());
}

#[test]
fn identical_content_length_repeats_are_one_length() {
    for fields in [
        "Content-Length: 2\r\nContent-Length: 2\r\n",
        "Content-Length: 2, 2\r\n",
    ] {
        let response = read_ok(&ok(fields, b"ok"));
        assert_eq!(response.content_length(), Some(2), "{fields}");
        assert_eq!(response.body(), b"ok");
    }
}

#[test]
fn a_chunked_body_is_decoded_by_the_strict_decoder_and_its_framing_counted() {
    let wire = ok(
        "Transfer-Encoding: chunked\r\n",
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    );
    let response = read_ok(&wire);
    assert_eq!(
        response.framing(),
        ResponseFraming::Framed(BodyFraming::Chunked)
    );
    assert_eq!(response.content_length(), None);
    assert_eq!(response.body(), b"hello world");
    assert_eq!(response.wire_bytes(), length(&wire));
    // `chunked` is a token, so its case does not matter (V02 agrees); hex digits may be
    // either case and have leading zeros.
    let response = read_ok(&ok(
        "Transfer-Encoding: Chunked\r\n",
        b"00A\r\n0123456789\r\n0\r\n\r\n",
    ));
    assert_eq!(response.body(), b"0123456789");
}

#[test]
fn chunk_faults_are_refused_rather_than_skipped() {
    for (body, expected) in [
        ("5;x=1\r\nhello\r\n0\r\n\r\n", ReadRefusal::ChunkExtension),
        ("5\r\nhello\r\n0\r\nX-Sum: 1\r\n\r\n", ReadRefusal::Trailers),
        ("g\r\n", ReadRefusal::InvalidChunkSize),
        ("5 \r\nhello\r\n", ReadRefusal::InvalidChunkSize),
        ("5\nhello\r\n", ReadRefusal::InvalidChunkSize),
        ("5\r\nhelloX", ReadRefusal::ChunkNotTerminated),
        ("0\r\n\rX", ReadRefusal::ChunkNotTerminated),
    ] {
        assert_eq!(
            refused(&ok("Transfer-Encoding: chunked\r\n", body.as_bytes())),
            ResponseReadRefusal::Chunk(expected),
            "{body:?}"
        );
    }
}

#[test]
fn a_body_without_framing_runs_until_the_end_of_input() {
    let wire = ok("Content-Type: text/plain\r\n", b"until close");
    let mut reader = ResponseReader::new(limits(), HttpMethod::Get);
    assert_eq!(reader.feed(&wire), Ok(ReadProgress::NeedMore));
    assert_eq!(reader.body_bound(), Some(4_096 - 11));
    assert_eq!(reader.feed(b" and more"), Ok(ReadProgress::NeedMore));
    assert_eq!(reader.end_of_input(), Ok(ReadProgress::Complete));
    assert_eq!(reader.end_of_input(), Ok(ReadProgress::Complete));
    let mut after = reader.clone();
    assert_eq!(after.feed(b"x"), Err(ResponseReadRefusal::TrailingBytes));
    let response = complete(reader.into_outcome());
    assert_eq!(response.framing(), ResponseFraming::UntilClose);
    assert_eq!(response.content_length(), None);
    assert_eq!(response.body(), b"until close and more");
    assert_eq!(response.wire_bytes(), length(&wire) + 9);
    // HTTP/1.0 responses are read too, and an empty body is a body.
    let old = complete(read_parts(
        HttpMethod::Get,
        &[b"HTTP/1.0 200 OK\r\n\r\nold"],
        true,
    ));
    assert_eq!(old.version(), ResponseVersion::Http10);
    assert_eq!(old.body(), b"old");
    let empty = complete(read_parts(HttpMethod::Get, &[&ok("", b"")], true));
    assert_eq!(empty.framing(), ResponseFraming::UntilClose);
    assert!(empty.body().is_empty());
}

#[test]
fn a_head_response_with_a_content_length_has_no_body() {
    let wire = ok(
        "Content-Length: 1234\r\nContent-Type: application/json\r\n",
        b"",
    );
    let mut reader = ResponseReader::new(limits(), HttpMethod::Head);
    // Complete at the end of the head, with no end of input.
    assert_eq!(reader.feed(&wire), Ok(ReadProgress::Complete));
    let response = complete(reader.into_outcome());
    assert_eq!(
        response.framing(),
        ResponseFraming::Framed(BodyFraming::None)
    );
    assert_eq!(response.content_length(), Some(1234));
    assert!(response.body().is_empty());
    assert_eq!(response.wire_bytes(), length(&wire));
    // A body after it is refused, in the same feed or a later one.
    let with_body = ok("Content-Length: 4\r\n", b"body");
    assert_eq!(
        read_parts(HttpMethod::Head, &[&with_body], false),
        ResponseOutcome::Refused(ResponseReadRefusal::TrailingBytes)
    );
    assert_eq!(
        read_parts(HttpMethod::Head, &[&wire, b"x"], false),
        ResponseOutcome::Refused(ResponseReadRefusal::TrailingBytes)
    );
    // The declared length is not a body, so the body limit does not apply; a chunked
    // HEAD response has no body either.
    for fields in [
        "Content-Length: 1000000000\r\n",
        "Transfer-Encoding: chunked\r\n",
    ] {
        let response = complete(read_parts(HttpMethod::Head, &[&ok(fields, b"")], false));
        assert!(response.body().is_empty(), "{fields}");
    }
}

#[test]
fn no_content_and_not_modified_responses_have_no_body() {
    for (wire, status, declared) in [
        (
            &b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"[..],
            204,
            Some(0),
        ),
        (b"HTTP/1.1 204 No Content\r\n\r\n", 204, None),
        (
            b"HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\nContent-Length: 99\r\n\r\n",
            304,
            Some(99),
        ),
    ] {
        let response = read_ok(wire);
        assert_eq!(response.status(), status);
        assert_eq!(
            response.framing(),
            ResponseFraming::Framed(BodyFraming::None)
        );
        assert_eq!(response.content_length(), declared);
        assert!(response.body().is_empty());
    }
    assert_eq!(
        refused(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 2\r\n\r\nok"),
        ResponseReadRefusal::TrailingBytes
    );
}

#[test]
fn interim_responses_are_read_and_dropped() {
    let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\
Link: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let response = read_ok(wire);
    assert_eq!(response.interim(), &[100, 103]);
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers(),
        &[("Content-Length".to_owned(), "2".to_owned())]
    );
    assert_eq!(response.body(), b"ok");
    // The interim heads were received, so they count.
    assert_eq!(response.wire_bytes(), length(wire));
    // An empty line between an interim head and the next status line is refused.
    assert_eq!(
        refused(b"HTTP/1.1 100 Continue\r\n\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"),
        ResponseReadRefusal::EmptyLineBeforeStatus
    );
}

#[test]
fn switching_protocols_is_refused() {
    assert_eq!(
        refused(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        ),
        ResponseReadRefusal::SwitchingProtocols
    );
    assert_eq!(
        refused(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Switching Protocols\r\n\r\n"),
        ResponseReadRefusal::SwitchingProtocols
    );
}

#[test]
fn smuggling_and_confusion_forms_are_refused() {
    let framing = ResponseReadRefusal::Framing;
    let cases: Vec<(Vec<u8>, ResponseReadRefusal)> = vec![
        (
            ok(
                "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
                b"0\r\n\r\n",
            ),
            framing(RequestRefusal::ConflictingFraming),
        ),
        (
            ok("Transfer-Encoding: gzip\r\n", b""),
            framing(RequestRefusal::UnsupportedTransferEncoding {
                value: "gzip".to_owned(),
            }),
        ),
        (
            ok("Transfer-Encoding: gzip, chunked\r\n", b""),
            framing(RequestRefusal::UnsupportedTransferEncoding {
                value: "gzip, chunked".to_owned(),
            }),
        ),
        (
            ok("Transfer-Encoding: chunked, chunked\r\n", b""),
            framing(RequestRefusal::UnsupportedTransferEncoding {
                value: "chunked, chunked".to_owned(),
            }),
        ),
        (
            ok(
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
                b"0\r\n\r\n",
            ),
            framing(RequestRefusal::DuplicateHeader {
                name: "transfer-encoding".to_owned(),
            }),
        ),
        (
            ok("Content-Length: 5\r\nContent-Length: 6\r\n", b"hello"),
            ResponseReadRefusal::DifferingContentLengths {
                values: vec!["5".to_owned(), "6".to_owned()],
            },
        ),
        (
            ok("Content-Length: 5, 6\r\n", b"hello"),
            ResponseReadRefusal::DifferingContentLengths {
                values: vec!["5".to_owned(), "6".to_owned()],
            },
        ),
        (
            ok("Content-Length: +5\r\n", b"hello"),
            framing(RequestRefusal::InvalidContentLength {
                value: "+5".to_owned(),
            }),
        ),
        (
            ok("Content-Length: 05\r\n", b"hello"),
            framing(RequestRefusal::InvalidContentLength {
                value: "05".to_owned(),
            }),
        ),
        (
            ok("Content-Length:\r\n", b""),
            framing(RequestRefusal::InvalidContentLength {
                value: String::new(),
            }),
        ),
        (
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
            ResponseReadRefusal::TransferEncodingInHttp10,
        ),
        (
            ok("X-Long: a\r\n b\r\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Line(ReadRefusal::ObsoleteLineFolding),
        ),
        (
            b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::Line(ReadRefusal::BareLineFeed),
        ),
        (
            ok("X-A: a\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Line(ReadRefusal::BareLineFeed),
        ),
        (
            ok("X-A: a\rb\r\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Line(ReadRefusal::BareCarriageReturn),
        ),
        (
            ok("X-A: a\0b\r\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Syntax(HeadSyntax::HeaderValue),
        ),
        (
            ok("X-A: a\x01b\r\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Syntax(HeadSyntax::HeaderValue),
        ),
        (
            ok("X-A: a\x7fb\r\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Syntax(HeadSyntax::HeaderValue),
        ),
        (
            ok("X-A : b\r\nContent-Length: 0\r\n", b""),
            ResponseReadRefusal::Syntax(HeadSyntax::HeaderName),
        ),
        (
            b"\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::EmptyLineBeforeStatus,
        ),
        (
            ok("Content-Length: 2\r\n", b"okEXTRA"),
            ResponseReadRefusal::TrailingBytes,
        ),
        (
            ok(
                "Transfer-Encoding: chunked\r\n",
                b"0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
            ),
            ResponseReadRefusal::TrailingBytes,
        ),
        (
            b"HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            ResponseReadRefusal::DuplicateLocation,
        ),
        (
            b"HTTP/1.1 200 OK\r\nX-A: caf\xe9\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::HeaderValueNotText {
                name: "x-a".to_owned(),
            },
        ),
        (
            b"HTTP/1.1 600 Odd\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::StatusOutOfRange { code: 600 },
        ),
        (
            b"HTTP/1.1 099 Low\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::StatusOutOfRange { code: 99 },
        ),
        (
            b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::Syntax(HeadSyntax::Version),
        ),
        (
            b"HTTP/1.2 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::Syntax(HeadSyntax::Version),
        ),
        (
            b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::StatusLine,
        ),
        (
            b"HTTP/1.1 200OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::StatusLine,
        ),
        (
            b"HTTP/1.1  200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ResponseReadRefusal::StatusLine,
        ),
    ];
    for (wire, expected) in cases {
        assert_eq!(
            refused(&wire),
            expected,
            "{}",
            String::from_utf8_lossy(&wire)
        );
    }
}

#[test]
fn reason_phrases_are_read_as_httparse_reads_them() {
    for (status_line, reason) in [
        (&b"HTTP/1.1 404 Not Found\r\n"[..], "Not Found"),
        (b"HTTP/1.1 200 \tOK\r\n", "\tOK"),
        (b"HTTP/1.1 200\r\n", ""),
        // Obsolete text makes `httparse` report an empty reason.
        (b"HTTP/1.1 200 caf\xe9\r\n", ""),
    ] {
        let mut wire = status_line.to_vec();
        wire.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        assert_eq!(read_ok(&wire).reason(), reason);
    }
}

#[test]
fn each_limit_is_enforced() {
    let small_head = ReaderLimits::new(64, 4_096).unwrap();
    // A head that does not end within the limit.
    assert_eq!(
        refused_with(
            small_head,
            &ok(&format!("X-Pad: {}\r\n", "a".repeat(64)), b"")
        ),
        ResponseReadRefusal::HeadTooLarge { limit: 64 }
    );
    // The limit holds for all heads together: each of these fits, both do not.
    let interim = b"HTTP/1.1 100 Continue\r\nX-Pad: aaaaaaaaaaaa\r\n\r\n";
    let last = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assert!(interim.len() < 64 && last.len() < 64);
    assert_eq!(
        refused_with(small_head, &[&interim[..], &last[..]].concat()),
        ResponseReadRefusal::HeadTooLarge { limit: 64 }
    );
    // A head of exactly the limit fits.
    let exact = ok(&format!("X-Pad: {}\r\n", "a".repeat(64 - 28)), b"");
    assert_eq!(exact.len(), 64);
    assert!(matches!(
        read_parts_with(small_head, HttpMethod::Get, &[&exact], true),
        ResponseOutcome::Complete(_)
    ));
    // The fixed header count.
    let fields = |count: usize| -> String {
        (0..count)
            .map(|index| format!("X-{index}: v\r\n"))
            .collect()
    };
    assert_eq!(
        refused(&ok(&fields(MAX_HEADERS + 1), b"")),
        ResponseReadRefusal::TooManyHeaders { limit: MAX_HEADERS }
    );
    assert!(matches!(
        read_parts(HttpMethod::Get, &[&ok(&fields(MAX_HEADERS), b"")], true),
        ResponseOutcome::Complete(_)
    ));
    // The body limit: a declared length, a chunk size, chunk framing, and a body read
    // until the end of the input.
    assert_eq!(
        refused(&ok("Content-Length: 4097\r\n", b"")),
        ResponseReadRefusal::BodyTooLarge {
            limit: 4_096,
            length: 4_097
        }
    );
    assert_eq!(
        refused(&ok("Transfer-Encoding: chunked\r\n", b"1001\r\n")),
        ResponseReadRefusal::BodyTooLarge {
            limit: 4_096,
            length: 4_097
        }
    );
    let small_body = ReaderLimits::new(1_024, 16).unwrap();
    let chunked = |body: &[u8]| ok("Transfer-Encoding: chunked\r\n", body);
    // Three decoded bytes, but 23 bytes with their framing.
    assert_eq!(
        refused_with(
            small_body,
            &chunked(b"1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n")
        ),
        ResponseReadRefusal::BodyOverLimit { limit: 16 }
    );
    let exact = complete(read_parts_with(
        small_body,
        HttpMethod::Get,
        &[&chunked(b"6\r\nhello!\r\n0\r\n\r\n")],
        false,
    ));
    assert_eq!(exact.body(), b"hello!");
    assert_eq!(
        read_parts_with(small_body, HttpMethod::Get, &[&ok("", &[b'x'; 17])], true),
        ResponseOutcome::Refused(ResponseReadRefusal::BodyOverLimit { limit: 16 })
    );
    let exact = complete(read_parts_with(
        small_body,
        HttpMethod::Get,
        &[&ok("", &[b'x'; 16])],
        true,
    ));
    assert_eq!(exact.body().len(), 16);
    // The interim count.
    let interim_heads =
        |count: usize| -> Vec<u8> { b"HTTP/1.1 100 Continue\r\n\r\n".repeat(count) };
    let mut allowed = interim_heads(MAX_INTERIM_RESPONSES);
    allowed.extend_from_slice(last);
    assert_eq!(read_ok(&allowed).interim().len(), MAX_INTERIM_RESPONSES);
    let mut too_many = interim_heads(MAX_INTERIM_RESPONSES + 1);
    too_many.extend_from_slice(last);
    assert_eq!(
        refused(&too_many),
        ResponseReadRefusal::TooManyInterimResponses {
            limit: MAX_INTERIM_RESPONSES
        }
    );
}

#[test]
fn a_response_that_has_not_ended_is_refused_at_the_end_of_input() {
    for wire in [
        &b""[..],
        b"HTTP/1.1 200 OK\r\nContent-Le",
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
    ] {
        assert_eq!(
            read_parts(HttpMethod::Get, &[wire], true),
            ResponseOutcome::Refused(ResponseReadRefusal::Truncated),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
    // Without the end of input they are only incomplete.
    assert_eq!(
        read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"),
        ResponseOutcome::NeedMore
    );
}

#[test]
fn a_refusal_is_final() {
    let mut reader = ResponseReader::new(limits(), HttpMethod::Get);
    assert_eq!(
        reader.feed(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
        Err(ResponseReadRefusal::SwitchingProtocols)
    );
    assert_eq!(
        reader.feed(&ok("Content-Length: 0\r\n", b"")),
        Err(ResponseReadRefusal::SwitchingProtocols)
    );
    assert_eq!(
        reader.end_of_input(),
        Err(ResponseReadRefusal::SwitchingProtocols)
    );
    assert_eq!(reader.body_bound(), None);
}

#[test]
fn the_body_bound_is_what_the_body_may_still_bring() {
    for (wire, method, bound) in [
        (ok("Content-Length: 5\r\n", b""), HttpMethod::Get, 5),
        (ok("Content-Length: 5\r\n", b"he"), HttpMethod::Get, 3),
        (
            ok("Transfer-Encoding: chunked\r\n", b""),
            HttpMethod::Get,
            4_096,
        ),
        (
            ok("Transfer-Encoding: chunked\r\n", b"2\r\nhe"),
            HttpMethod::Get,
            4_091,
        ),
        (ok("", b"abc"), HttpMethod::Get, 4_093),
    ] {
        let mut reader = ResponseReader::new(limits(), method);
        assert_eq!(reader.feed(&wire), Ok(ReadProgress::NeedMore));
        assert_eq!(
            reader.body_bound(),
            Some(bound),
            "{}",
            String::from_utf8_lossy(&wire)
        );
    }
    let mut reader = ResponseReader::new(limits(), HttpMethod::Get);
    assert_eq!(reader.body_bound(), None);
    assert_eq!(
        reader.feed(b"HTTP/1.1 200 OK\r\n"),
        Ok(ReadProgress::NeedMore)
    );
    assert_eq!(reader.body_bound(), None);
}

#[test]
fn the_same_bytes_give_the_same_outcome_in_every_split() {
    let cases: Vec<(HttpMethod, Vec<u8>, bool)> = vec![
        (
            HttpMethod::Get,
            ok(
                "Content-Type: text/plain\r\nContent-Length: 5\r\n",
                b"hello",
            ),
            false,
        ),
        (
            HttpMethod::Get,
            ok(
                "Transfer-Encoding: chunked\r\n",
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            ),
            false,
        ),
        (HttpMethod::Get, ok("", b"until close"), true),
        (HttpMethod::Head, ok("Content-Length: 1234\r\n", b""), false),
        (
            HttpMethod::Get,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n\
HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .to_vec(),
            false,
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec(),
            false,
        ),
        (
            HttpMethod::Get,
            ok("Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", b"ok"),
            false,
        ),
        (HttpMethod::Get, ok("X-A: a\r\n b\r\n", b""), false),
        (
            HttpMethod::Get,
            ok("Content-Length: 2\r\n", b"okEXTRA"),
            false,
        ),
        (
            HttpMethod::Get,
            ok("Transfer-Encoding: chunked\r\n", b"5;x\r\nhello\r\n"),
            false,
        ),
        (
            HttpMethod::Get,
            ok("Transfer-Encoding: chunked\r\n", &b"1\r\na\r\n".repeat(700)),
            false,
        ),
        (HttpMethod::Get, ok("", &[b'x'; 4_097]), true),
        (
            HttpMethod::Get,
            ok(&format!("X-Pad: {}\r\n", "a".repeat(1_100)), b""),
            false,
        ),
    ];
    for (method, wire, close) in cases {
        let whole = read_parts(method, &[&wire], close);
        assert_eq!(
            read_bytewise(method, &wire, close),
            whole,
            "{}",
            String::from_utf8_lossy(&wire)
        );
        for split in 0..=wire.len() {
            let (first, second) = wire.split_at(split);
            assert_eq!(
                read_parts(method, &[first, second], close),
                whole,
                "split at {split}: {}",
                String::from_utf8_lossy(&wire)
            );
        }
    }
}
