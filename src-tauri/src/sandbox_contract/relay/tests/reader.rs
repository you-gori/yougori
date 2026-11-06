//! The reader alone: what it hands to V02, smuggling forms, limits, pipelining, and the
//! same result for every split of the same bytes (VM §4.3; VM-P10).

use super::*;
use crate::sandbox_contract::destinations::{
    BodyFraming, HttpVersion, InspectedRequest, RequestRefusal,
};

/// A request with `fields` (each ending in CRLF) and `body` after the empty line.
fn request(method_and_target: &str, fields: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("{method_and_target} HTTP/1.1\r\nHost: api.example.com\r\n{fields}\r\n")
        .into_bytes();
    wire.extend_from_slice(body);
    wire
}

fn post(fields: &str, body: &[u8]) -> Vec<u8> {
    request("POST /v1/jobs", fields, body)
}

fn chunked(body: &str) -> Vec<u8> {
    post("Transfer-Encoding: chunked\r\n", body.as_bytes())
}

fn read_with(limits: ReaderLimits, wire: &[u8]) -> ReadOutcome {
    let mut reader = RequestReader::new(limits);
    let _ = reader.feed(wire);
    reader.into_outcome()
}

fn framing(refusal: RequestRefusal) -> ReadRefusal {
    ReadRefusal::Inspection(refusal)
}

#[test]
fn a_head_becomes_the_inspected_request_with_nothing_dropped_or_merged() {
    let wire = b"GET /v1/models?limit=5&after=a%2Fb HTTP/1.1\r\nHost: api.example.com\r\n\
X-Trace: one\r\nx-span: two\r\nACCEPT:   text/plain  \r\n\r\n";
    let read = read_ok(wire);
    assert_eq!(
        read.request(),
        &InspectedRequest {
            version: HttpVersion::Http11,
            method: "GET".to_owned(),
            target: "/v1/models?limit=5&after=a%2Fb".to_owned(),
            authority: None,
            scheme: None,
            protocol: None,
            // Received order and names as received. Only the optional whitespace around a
            // value, which is not part of it (RFC 9112 §5), is gone.
            headers: vec![
                ("Host".to_owned(), "api.example.com".to_owned()),
                ("X-Trace".to_owned(), "one".to_owned()),
                ("x-span".to_owned(), "two".to_owned()),
                ("ACCEPT".to_owned(), "text/plain".to_owned()),
            ],
        }
    );
    assert_eq!(read.framing(), BodyFraming::None);
    assert!(!read.expects_continue());
    assert!(read.body().is_empty());
    assert_eq!(read.wire_bytes(), u64::try_from(wire.len()).unwrap());
}

#[test]
fn duplicates_reach_v02_unmerged_and_are_refused_before_any_body_byte() {
    let mut reader = RequestReader::new(limits());
    // Only the head arrives; V02 refuses the duplicate in either spelling.
    assert_eq!(
        reader.feed(&post(
            "X-Trace: one\r\nx-trace: two\r\nContent-Length: 5\r\n",
            b""
        )),
        Err(framing(RequestRefusal::DuplicateHeader {
            name: "x-trace".to_owned()
        }))
    );
    // V02's other head faults are refused at the same point.
    for (fields, refusal) in [
        (
            "Upgrade: websocket\r\n",
            RequestRefusal::Upgrade {
                header: "Upgrade".to_owned(),
            },
        ),
        (
            "X-HTTP-Method-Override: DELETE\r\n",
            RequestRefusal::MethodOverride {
                header: "x-http-method-override".to_owned(),
            },
        ),
    ] {
        let mut reader = RequestReader::new(limits());
        let head = post(&format!("{fields}Content-Length: 5\r\n"), b"");
        assert_eq!(reader.feed(&head), Err(framing(refusal)), "{fields}");
    }
}

#[test]
fn connect_is_refused_by_v02_when_the_head_is_complete() {
    assert_eq!(
        read_refused(&request("CONNECT api.example.com:443", "", b"")),
        framing(RequestRefusal::UnknownMethod {
            method: "CONNECT".to_owned()
        })
    );
}

#[test]
fn absolute_form_and_asterisk_targets_stay_raw_for_v02() {
    for (line, method, target) in [
        (
            "GET http://evil.example/v1/models",
            "GET",
            "http://evil.example/v1/models",
        ),
        ("OPTIONS *", "OPTIONS", "*"),
        (
            "GET /v1/../admin;x=1?a=1&a=2",
            "GET",
            "/v1/../admin;x=1?a=1&a=2",
        ),
    ] {
        let read = read_ok(&request(line, "", b""));
        assert_eq!(read.request().method, method);
        assert_eq!(read.request().target, target);
    }
}

#[test]
fn content_length_bodies_are_read_exactly() {
    let wire = post("Content-Length: 11\r\n", b"hello world");
    let read = read_ok(&wire);
    assert_eq!(read.framing(), BodyFraming::ContentLength(11));
    assert_eq!(read.body(), b"hello world");
    assert_eq!(read.wire_bytes(), u64::try_from(wire.len()).unwrap());
    let empty = read_ok(&post("Content-Length: 0\r\n", b""));
    assert_eq!(empty.framing(), BodyFraming::ContentLength(0));
    assert!(empty.body().is_empty());
}

#[test]
fn chunked_bodies_are_decoded_strictly() {
    let wire = chunked("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    let read = read_ok(&wire);
    assert_eq!(read.framing(), BodyFraming::Chunked);
    assert_eq!(read.body(), b"hello world");
    assert_eq!(read.wire_bytes(), u64::try_from(wire.len()).unwrap());
    // Either case of hex digits and leading zeros are chunk sizes; `chunked` is a token,
    // so its case does not matter (V02 agrees).
    let read = read_ok(&post(
        "Transfer-Encoding: Chunked\r\n",
        b"00A\r\n0123456789\r\n0a\r\nabcdefghij\r\n000\r\n\r\n",
    ));
    assert_eq!(read.body(), b"0123456789abcdefghij");
    assert!(read_ok(&chunked("0\r\n\r\n")).body().is_empty());
}

#[test]
fn content_length_with_transfer_encoding_is_refused_in_either_order() {
    for fields in [
        "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
        "transfer-encoding: chunked\r\ncontent-length: 5\r\n",
        "Content-Length: 5\r\nTransfer-Encoding: identity\r\n",
    ] {
        assert_eq!(
            read_refused(&post(fields, b"0\r\n\r\n")),
            framing(RequestRefusal::ConflictingFraming),
            "{fields}"
        );
    }
}

#[test]
fn duplicate_framing_headers_are_refused() {
    for (fields, name) in [
        (
            "Content-Length: 5\r\nContent-Length: 5\r\n",
            "content-length",
        ),
        (
            "Content-Length: 5\r\ncontent-length: 6\r\n",
            "content-length",
        ),
        (
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "transfer-encoding",
        ),
    ] {
        assert_eq!(
            read_refused(&post(fields, b"hello")),
            framing(RequestRefusal::DuplicateHeader {
                name: name.to_owned()
            }),
            "{fields}"
        );
    }
}

#[test]
fn content_lengths_that_are_not_one_decimal_number_are_refused() {
    for value in [
        "5, 5",
        "+5",
        "-1",
        "0x10",
        "",
        "5 5",
        "18446744073709551616",
    ] {
        assert_eq!(
            read_refused(&post(&format!("Content-Length: {value}\r\n"), b"hello")),
            framing(RequestRefusal::InvalidContentLength {
                value: value.to_owned()
            }),
            "{value:?}"
        );
    }
}

#[test]
fn a_leading_zero_is_refused_by_v02s_framing_rule() {
    assert_eq!(
        read_refused(&post("Content-Length: 007\r\n", b"1234567")),
        framing(RequestRefusal::InvalidContentLength {
            value: "007".to_owned()
        })
    );
}

#[test]
fn expect_100_continue_is_reported_once_the_head_is_complete() {
    let head = post("Expect: 100-Continue\r\nContent-Length: 2\r\n", b"");
    let mut reader = RequestReader::new(limits());
    assert_eq!(
        reader.feed(&head[..head.len() - 1]),
        Ok(ReadProgress::NeedMore)
    );
    assert!(!reader.expects_continue());
    assert_eq!(
        reader.feed(&head[head.len() - 1..]),
        Ok(ReadProgress::NeedMore)
    );
    assert!(reader.expects_continue());
    assert_eq!(reader.feed(b"{}"), Ok(ReadProgress::Complete));
    assert!(reader.expects_continue());
    match reader.into_outcome() {
        ReadOutcome::Complete(read) => assert!(read.expects_continue()),
        other => panic!("expected a complete request, got {other:?}"),
    }
}

#[test]
fn other_expectations_are_refused() {
    for value in ["200-ok", "100-continue, foo", "", "100-continue-x"] {
        assert_eq!(
            read_refused(&post(
                &format!("Expect: {value}\r\nContent-Length: 2\r\n"),
                b"{}"
            )),
            ReadRefusal::UnsupportedExpectation {
                value: value.to_owned()
            },
            "{value:?}"
        );
    }
    assert_eq!(
        read_refused(&post(
            "Expect: 100-continue\r\nexpect: 100-continue\r\n",
            b""
        )),
        framing(RequestRefusal::DuplicateHeader {
            name: "expect".to_owned()
        })
    );
}

#[test]
fn underscore_twins_of_protected_headers_are_refused() {
    for name in [
        "Transfer_Encoding",
        "transfer_encoding",
        "Content_Length",
        "CONTENT_LENGTH",
        "Proxy_Authorization",
        "proxy_authorization",
        "Keep_Alive",
        "Proxy_Connection",
        "HTTP2_Settings",
        "X_HTTP_Method_Override",
        "X-Http_Method-Override",
        "X_Original_URL",
        "X_Rewrite_Url",
    ] {
        assert_eq!(
            read_refused(&post(&format!("{name}: 0\r\n"), b"")),
            ReadRefusal::UnderscoreTwin {
                name: name.to_owned()
            },
            "{name}"
        );
    }
    // Other names are ordinary headers. The real `Authorization` has no hyphen, so no
    // spelling with `_` is its twin; on a credentialed route V02 refuses it by name (the
    // step tests show that).
    for name in [
        "Authorization",
        "X_Custom_Header",
        "Transfer-Encoding_",
        "Authori_zation",
    ] {
        assert!(
            matches!(
                read_whole(&post(&format!("{name}: 0\r\n"), b"")),
                ReadOutcome::Complete(_)
            ),
            "{name}"
        );
    }
}

#[test]
fn target_override_headers_are_refused() {
    for (name, header) in [
        ("X-Original-URL", "x-original-url"),
        ("x-rewrite-url", "x-rewrite-url"),
    ] {
        assert_eq!(
            read_refused(&request(
                "GET /v1/models",
                &format!("{name}: /admin\r\n"),
                b""
            )),
            ReadRefusal::TargetOverride {
                header: header.to_owned()
            }
        );
    }
}

#[test]
fn transfer_encodings_other_than_chunked_are_refused() {
    for value in [
        "gzip, chunked",
        "chunked, gzip",
        "identity",
        "chunked, chunked",
        "xchunked",
    ] {
        assert_eq!(
            read_refused(&post(
                &format!("Transfer-Encoding: {value}\r\n"),
                b"0\r\n\r\n"
            )),
            framing(RequestRefusal::UnsupportedTransferEncoding {
                value: value.to_owned()
            }),
            "{value}"
        );
    }
}

#[test]
fn bare_line_feeds_and_carriage_returns_are_refused() {
    for wire in [
        &b"GET / HTTP/1.1\nHost: api.example.com\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nHost: api.example.com\n\r\n",
        b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\n",
        b"GET / HTTP/1.1\r\nHost: api.example.com\nContent-Length: 5\r\n\r\nhello",
    ] {
        assert_eq!(read_refused(wire), ReadRefusal::BareLineFeed);
    }
    assert_eq!(
        read_refused(b"GET / HTTP/1.1\r\nHost: api.example.com\rX-A: b\r\n\r\n"),
        ReadRefusal::BareCarriageReturn
    );
    assert_eq!(
        read_refused(b"\nGET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
        ReadRefusal::BareLineFeed
    );
}

#[test]
fn obsolete_line_folding_is_refused() {
    for wire in [
        &b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Long: a\r\n b\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Long: a\r\n\tb\r\n\r\n",
        b"GET / HTTP/1.1\r\n Host: api.example.com\r\n\r\n",
        b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\n 0\r\n\r\nx",
    ] {
        assert_eq!(read_refused(wire), ReadRefusal::ObsoleteLineFolding);
    }
}

#[test]
fn empty_lines_before_the_request_line_are_refused() {
    assert_eq!(
        read_refused(b"\r\nGET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
        ReadRefusal::EmptyLineBeforeRequest
    );
}

#[test]
fn only_http_1_1_is_read() {
    assert_eq!(
        read_refused(b"GET / HTTP/1.0\r\nHost: api.example.com\r\n\r\n"),
        ReadRefusal::NotHttp11
    );
    for version in ["HTTP/2.0", "HTTP/1.2", "http/1.1"] {
        assert_eq!(
            read_refused(format!("GET / {version}\r\nHost: api.example.com\r\n\r\n").as_bytes()),
            ReadRefusal::Syntax(HeadSyntax::Version),
            "{version}"
        );
    }
}

#[test]
fn malformed_heads_are_refused_by_httparse() {
    let cases: [(&[u8], HeadSyntax); 6] = [
        (
            b"GET / HTTP/1.1\r\nHost : api.example.com\r\n\r\n",
            HeadSyntax::HeaderName,
        ),
        (
            b"GET / HTTP/1.1\r\n:authority: api.example.com\r\n\r\n",
            HeadSyntax::HeaderName,
        ),
        (
            b"GET  / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            HeadSyntax::RequestLine,
        ),
        (
            b"G(T / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            HeadSyntax::RequestLine,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-A: a\x00b\r\n\r\n",
            HeadSyntax::HeaderValue,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-A: a\x7fb\r\n\r\n",
            HeadSyntax::HeaderValue,
        ),
    ];
    for (wire, part) in cases {
        assert_eq!(
            read_refused(wire),
            ReadRefusal::Syntax(part),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn header_values_must_be_utf8_text() {
    assert_eq!(
        read_refused(b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Bin: \xff\xfe\r\n\r\n"),
        ReadRefusal::HeaderValueNotText {
            name: "x-bin".to_owned()
        }
    );
    let read =
        read_ok("GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Name: café\r\n\r\n".as_bytes());
    assert_eq!(read.request().headers[1].1, "café");
}

#[test]
fn heads_over_the_limit_are_refused() {
    let limits = ReaderLimits::new(128, 1_024).unwrap();
    let base = "GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Pad: \r\n\r\n".len();
    let head = |pad: usize| {
        format!(
            "GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(pad)
        )
    };
    let exact = head(128 - base);
    assert_eq!(exact.len(), 128);
    assert!(matches!(
        read_with(limits, exact.as_bytes()),
        ReadOutcome::Complete(_)
    ));
    assert_eq!(
        read_with(limits, head(129 - base).as_bytes()),
        ReadOutcome::Refused(ReadRefusal::HeadTooLarge { limit: 128 })
    );
    // A head that never ends is refused at the limit, whatever follows.
    assert_eq!(
        read_with(limits, "a".repeat(10_000).as_bytes()),
        ReadOutcome::Refused(ReadRefusal::HeadTooLarge { limit: 128 })
    );
}

#[test]
fn heads_with_more_than_the_fixed_header_count_are_refused() {
    let fields = |count: usize| {
        (1..count)
            .map(|index| format!("X-Field-{index}: {index}\r\n"))
            .collect::<String>()
    };
    let read = read_ok(&request("GET /", &fields(MAX_HEADERS), b""));
    assert_eq!(read.request().headers.len(), MAX_HEADERS);
    assert_eq!(
        read_refused(&request("GET /", &fields(MAX_HEADERS + 1), b"")),
        ReadRefusal::TooManyHeaders { limit: MAX_HEADERS }
    );
}

#[test]
fn bodies_over_the_limit_are_refused_before_they_are_read() {
    let limits = ReaderLimits::new(4_096, 10).unwrap();
    let mut reader = RequestReader::new(limits);
    // Only the head arrives; the declared length alone is refused.
    assert_eq!(
        reader.feed(&post("Content-Length: 11\r\n", b"")),
        Err(ReadRefusal::BodyTooLarge {
            limit: 10,
            length: 11
        })
    );
    assert!(matches!(
        read_with(limits, &post("Content-Length: 10\r\n", b"0123456789")),
        ReadOutcome::Complete(_)
    ));
    // The second chunk size would pass the limit; its data is never read.
    let mut reader = RequestReader::new(limits);
    assert_eq!(
        reader.feed(&chunked("5\r\nhello\r\n6\r\n")),
        Err(ReadRefusal::BodyTooLarge {
            limit: 10,
            length: 11
        })
    );
    assert_eq!(
        read_with(limits, &chunked("ffffffffffffffff\r\n")),
        ReadOutcome::Refused(ReadRefusal::BodyTooLarge {
            limit: 10,
            length: u64::MAX
        })
    );
}

#[test]
fn invalid_chunk_sizes_are_refused() {
    for size in [
        "g",
        "",
        " 5",
        "5 ",
        "5\t",
        "-5",
        "+5",
        "0x5",
        "00000000000000005",
        "fffffffffffffffff",
    ] {
        assert_eq!(
            read_refused(&chunked(&format!("{size}\r\nhello\r\n0\r\n\r\n"))),
            ReadRefusal::InvalidChunkSize,
            "{size:?}"
        );
    }
    assert_eq!(
        read_refused(&chunked("5\nhello\r\n0\r\n\r\n")),
        ReadRefusal::InvalidChunkSize
    );
}

#[test]
fn chunk_extensions_are_refused() {
    for body in ["5;ext=1\r\nhello\r\n0\r\n\r\n", "0;last\r\n\r\n"] {
        assert_eq!(read_refused(&chunked(body)), ReadRefusal::ChunkExtension);
    }
}

#[test]
fn chunk_data_must_end_with_crlf() {
    for body in [
        "5\r\nhelloX\r\n0\r\n\r\n",
        "5\r\nhello\n0\r\n\r\n",
        "3\r\nhello\r\n0\r\n\r\n",
        "0\r\n\rX",
    ] {
        assert_eq!(
            read_refused(&chunked(body)),
            ReadRefusal::ChunkNotTerminated,
            "{body:?}"
        );
    }
}

#[test]
fn trailers_are_refused() {
    assert_eq!(
        read_refused(&chunked("5\r\nhello\r\n0\r\nX-Checksum: 1\r\n\r\n")),
        ReadRefusal::Trailers
    );
}

#[test]
fn pipelined_bytes_are_refused_not_carried_over() {
    let get = request("GET /v1/models", "", b"");
    let mut both = get.clone();
    both.extend_from_slice(&get);
    assert_eq!(read_refused(&both), ReadRefusal::PipelinedBytes);
    // The same bytes in two feeds: complete, then refused; the first request is gone.
    let mut reader = RequestReader::new(limits());
    assert_eq!(reader.feed(&get), Ok(ReadProgress::Complete));
    assert_eq!(reader.feed(b""), Ok(ReadProgress::Complete));
    assert_eq!(reader.feed(&get), Err(ReadRefusal::PipelinedBytes));
    assert_eq!(
        reader.into_outcome(),
        ReadOutcome::Refused(ReadRefusal::PipelinedBytes)
    );
    for wire in [
        post("Content-Length: 5\r\n", b"helloX"),
        post("Content-Length: 5\r\n", b"hello\r\n"),
        chunked("5\r\nhello\r\n0\r\n\r\n\r\n"),
        chunked("0\r\n\r\nGET / HTTP/1.1\r\n\r\n"),
    ] {
        assert_eq!(read_refused(&wire), ReadRefusal::PipelinedBytes);
    }
}

#[test]
fn a_refusal_is_final() {
    let mut reader = RequestReader::new(limits());
    assert_eq!(
        reader.feed(b"GET / HTTP/1.1\nHost"),
        Err(ReadRefusal::BareLineFeed)
    );
    assert_eq!(
        reader.feed(&request("GET /", "", b"")),
        Err(ReadRefusal::BareLineFeed)
    );
    assert_eq!(reader.feed(b""), Err(ReadRefusal::BareLineFeed));
    assert_eq!(
        reader.into_outcome(),
        ReadOutcome::Refused(ReadRefusal::BareLineFeed)
    );
}

#[test]
fn incomplete_requests_need_more() {
    let wire = post("Content-Length: 5\r\n", b"hello");
    for cut in [0, 10, wire.len() - 6, wire.len() - 1] {
        assert_eq!(read_whole(&wire[..cut]), ReadOutcome::NeedMore, "{cut}");
    }
    assert_eq!(
        read_whole(b"GET / HTTP/1.1\r\nHost: a\r\n\r"),
        ReadOutcome::NeedMore
    );
}

#[test]
fn limits_are_bounded() {
    assert_eq!(
        ReaderLimits::new(0, 1),
        Err(LimitsError::HeadLimitOutOfRange {
            requested: 0,
            ceiling: HEAD_LIMIT_CEILING
        })
    );
    assert!(ReaderLimits::new(HEAD_LIMIT_CEILING + 1, 1).is_err());
    let limits = ReaderLimits::new(HEAD_LIMIT_CEILING, 100).unwrap();
    assert_eq!(limits.with_body_cap(10).max_body_bytes(), 10);
    assert_eq!(limits.with_body_cap(1_000).max_body_bytes(), 100);
}

/// Every input above, valid or not.
fn corpus() -> Vec<Vec<u8>> {
    let mut corpus = vec![
        request("GET /v1/models?limit=5", "Accept: a\r\naccept: b\r\n", b""),
        request("CONNECT api.example.com:443", "", b""),
        post("Content-Length: 11\r\n", b"hello world"),
        post("Content-Length: 007\r\n", b"1234567"),
        chunked("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
        chunked("00A\r\n0123456789\r\n0\r\n\r\n"),
        post(
            "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
            b"0\r\n\r\n",
        ),
        post("Content-Length: 5\r\nContent-Length: 5\r\n", b"hello"),
        post("Content-Length: 5, 5\r\n", b"hello"),
        post("Transfer-Encoding: gzip, chunked\r\n", b"0\r\n\r\n"),
        b"GET / HTTP/1.1\r\nHost: api.example.com\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: api.example.com\rX-A: b\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Long: a\r\n b\r\n\r\n".to_vec(),
        b"\r\nGET / HTTP/1.1\r\n\r\n".to_vec(),
        b"GET / HTTP/1.0\r\nHost: api.example.com\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nHost : api.example.com\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\nX-Bin: \xff\r\n\r\n".to_vec(),
        chunked("5;ext\r\nhello\r\n0\r\n\r\n"),
        chunked("00000000000000005\r\nhello\r\n0\r\n\r\n"),
        chunked("3\r\nhello\r\n0\r\n\r\n"),
        chunked("5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n"),
        chunked("0\r\n\r\n\r\n"),
        post("Content-Length: 5\r\n", b"helloGET / HTTP/1.1\r\n\r\n"),
        post("Content-Length: 5\r\n", b"hel"),
        post("Expect: 100-continue\r\nContent-Length: 2\r\n", b"{}"),
        post("Expect: 200-ok\r\nContent-Length: 2\r\n", b"{}"),
        post("Transfer_Encoding: chunked\r\n", b"0\r\n\r\n"),
        request("GET /", "X-Original-URL: /admin\r\n", b""),
        request(
            "GET /",
            &"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".repeat(200),
            b"",
        ),
        request(
            "GET /",
            &(1..=MAX_HEADERS)
                .map(|index| format!("X-{index}: v\r\n"))
                .collect::<String>(),
            b"",
        ),
    ];
    let mut pipelined = request("GET /", "", b"");
    pipelined.extend_from_slice(&request("GET /", "", b""));
    corpus.push(pipelined);
    corpus
}

/// SplitMix64, the explicit seeded generator for the split property.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn read_in_parts(wire: &[u8], mut cut: impl FnMut(usize) -> usize) -> ReadOutcome {
    let mut reader = RequestReader::new(limits());
    let mut rest = wire;
    while !rest.is_empty() {
        let take = cut(rest.len()).clamp(1, rest.len());
        let _ = reader.feed(&rest[..take]);
        rest = &rest[take..];
    }
    reader.into_outcome()
}

#[test]
fn one_byte_at_a_time_and_every_split_give_the_same_result() {
    let mut random = SplitMix64(0x5eed_0001);
    for wire in corpus() {
        let whole = read_whole(&wire);
        let bytewise = read_in_parts(&wire, |_| 1);
        assert_eq!(whole, bytewise, "{}", String::from_utf8_lossy(&wire));
        for _ in 0..8 {
            let split = read_in_parts(&wire, |left| {
                usize::try_from(random.next() % u64::try_from(left).unwrap()).unwrap() + 1
            });
            assert_eq!(whole, split, "{}", String::from_utf8_lossy(&wire));
        }
    }
}

#[test]
fn a_valid_request_completes_exactly_at_its_last_byte() {
    for wire in [
        request("GET /v1/models", "", b""),
        post("Content-Length: 11\r\n", b"hello world"),
        chunked("5\r\nhello\r\n0\r\n\r\n"),
    ] {
        let mut reader = RequestReader::new(limits());
        for (index, byte) in wire.iter().enumerate() {
            let expected = if index + 1 == wire.len() {
                ReadProgress::Complete
            } else {
                ReadProgress::NeedMore
            };
            assert_eq!(reader.feed(&[*byte]), Ok(expected), "byte {index}");
        }
    }
}

fn read_parts(limits: ReaderLimits, parts: &[&[u8]]) -> ReadOutcome {
    let mut reader = RequestReader::new(limits);
    for part in parts {
        let _ = reader.feed(part);
    }
    reader.into_outcome()
}

/// The review's exhaustive probe: tight limits, so the head and body limits fall inside
/// the inputs, and every split into two (with an empty feed between) and three parts.
#[test]
fn every_two_and_three_way_split_gives_the_same_result() {
    let te = "POST /a HTTP/1.1\r\nHost: a.b.cc\r\nTransfer-Encoding: chunked\r\n\r\n";
    let limits = ReaderLimits::new(te.len(), 10).unwrap();
    let cl = "POST /a HTTP/1.1\r\nHost: a.b.cc\r\nContent-Length: ";
    let corpus: Vec<Vec<u8>> = vec![
        format!("{cl}10\r\n\r\n0123456789").into_bytes(),
        format!("{cl}10\r\n\r\n0123456789X").into_bytes(),
        format!("{cl}11\r\n\r\n0123456789X").into_bytes(),
        format!("{cl}0\r\n\r\n").into_bytes(),
        format!("{te}5\r\n01234\r\n5\r\n56789\r\n0\r\n\r\n").into_bytes(),
        format!("{te}5\r\n01234\r\n6\r\n56789X\r\n0\r\n\r\n").into_bytes(),
        format!("{te}000000000000000A\r\n0123456789\r\n0\r\n\r\n").into_bytes(),
        format!("{te}0\r\n\r\nX").into_bytes(),
        format!("{te}0\r\n\r").into_bytes(),
        // A head one byte over the limit, and one whose final CR is the last byte allowed.
        b"POST /a HTTP/1.1\r\nHost: a.b.cc\r\nTransfer-Encoding: chunkedd\r\n\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: a.b.cc\r\nTransfer-Encoding: chunked\r\n\rX".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: a.b.cc\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
    ];
    for wire in &corpus {
        let whole = read_parts(limits, &[wire]);
        for first in 0..=wire.len() {
            let two = read_parts(limits, &[&wire[..first], b"", &wire[first..]]);
            assert_eq!(whole, two, "split {first}");
            for second in first..=wire.len() {
                let three = read_parts(
                    limits,
                    &[&wire[..first], &wire[first..second], &wire[second..]],
                );
                assert_eq!(whole, three, "split {first} {second}");
            }
        }
    }
}

/// The review's fuzz probe: random concatenations of request fragments read whole, one
/// byte at a time and in two parts agree, and nothing panics.
#[test]
fn random_fragments_give_the_same_result_for_every_split() {
    let pieces: [&[u8]; 30] = [
        b"GET ",
        b"POST ",
        b"/v1/jobs",
        b" HTTP/1.1",
        b"\r\n",
        b"\n",
        b"\r",
        b"Host: api.example.com",
        b"Content-Length: 3",
        b"Transfer-Encoding: chunked",
        b" ",
        b"\t",
        b"0",
        b"3",
        b"abc",
        b"\r\n\r\n",
        b"0\r\n\r\n",
        b"3\r\nabc\r\n",
        b";x",
        b":",
        b"ffffffffffffffff",
        b"\xff",
        b"\xc3\xa9",
        b"\x00",
        b"Content-Length: 03",
        b"X: a",
        b"HTTP/1.0",
        b"#",
        b"Expect: 100-continue",
        b"Content_Length: 3",
    ];
    let limits = ReaderLimits::new(96, 8).unwrap();
    let mut random = SplitMix64(0x0909);
    let mut completes = 0;
    for _ in 0..40_000 {
        let mut wire = Vec::new();
        if random.next().is_multiple_of(2) {
            wire.extend_from_slice(b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\n");
        }
        for _ in 0..random.next() % 12 {
            let piece = usize::try_from(random.next() % 30).unwrap();
            wire.extend_from_slice(pieces[piece]);
        }
        let whole = read_parts(limits, &[&wire]);
        if matches!(whole, ReadOutcome::Complete(_)) {
            completes += 1;
        }
        let bytes: Vec<&[u8]> = wire.chunks(1).collect();
        let text = String::from_utf8_lossy(&wire);
        assert_eq!(whole, read_parts(limits, &bytes), "{text}");
        if !wire.is_empty() {
            let cut = usize::try_from(random.next() % u64::try_from(wire.len()).unwrap()).unwrap();
            assert_eq!(
                whole,
                read_parts(limits, &[&wire[..cut], &wire[cut..]]),
                "{text}"
            );
        }
    }
    // The fragments do form complete requests, so the comparison covers success too.
    assert!(completes > 0);
}
