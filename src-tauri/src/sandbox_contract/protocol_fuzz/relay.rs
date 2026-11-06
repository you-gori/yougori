//! The relay's request reader under the fuzzer (M09R; VM §4.3, VM-W11, VM-P10; VM-W50):
//! `RequestReader` on mutated guest requests, fed whole, byte by byte and in random
//! splits. The relay's response side is not a target.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - Split-independence: three random splits (with empty feeds), and byte-by-byte feeding
//!   for inputs up to 512 bytes, end exactly where the whole input ends.
//! - Finality: `feed` reports what the outcome holds; after a refusal every feed returns
//!   it again, and after a complete request an empty feed stays complete while any byte
//!   is refused as pipelining.
//! - Size limits: a complete request's head ends within the head limit, its body is
//!   within the body limit, it has at most [`MAX_HEADERS`] fields, and it used every input
//!   byte (`wire_bytes`); a head-too-large refusal has no head end within the limit, a
//!   body-too-large refusal names a length over the limit, and an incomplete input either
//!   holds a head end or is shorter than the limit.
//! - Exactness: a complete request's body is exactly what its framing says (the
//!   Content-Length bytes, or the chunked body decoded by a separate strict decoder here),
//!   its fields are the head's lines, in order and none merged, no field is a target
//!   override or an underscore twin of a protected header, `Expect` is `100-continue`
//!   when present and reported exactly then, and every strict prefix of it needs more.

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{find, runs, variant, Encoding, Field, Grammar};
use super::rng::SplitMix64;
use crate::sandbox_contract::destinations::{
    BodyFraming, METHOD_OVERRIDE_HEADERS, RESERVED_CREDENTIAL_HEADERS,
};
use crate::sandbox_contract::relay::{
    ReadOutcome, ReadProgress, ReadRefusal, ReadRequest, ReaderLimits, RequestReader,
    HEAD_LIMIT_CEILING, MAX_HEADERS, TARGET_OVERRIDE_HEADERS, UNDERSCORE_PROTECTED_HEADERS,
};

/// Mutated requests per run.
const ITERATIONS: u64 = 30_000;
/// The reader's limits here: small, so mutated inputs reach both.
const HEAD_LIMIT: usize = 1_024;
const BODY_LIMIT: u64 = 4_096;

fn limits() -> ReaderLimits {
    ReaderLimits::new(HEAD_LIMIT, BODY_LIMIT).unwrap()
}

fn bytes_of(length: usize) -> u64 {
    u64::try_from(length).unwrap()
}

/// `line` as an HTTP/1.1 request line with a Host field, then `fields` and `body`.
fn request(line: &str, fields: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes =
        format!("{line} HTTP/1.1\r\nHost: api.example.com\r\n{fields}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        request(
            "GET /v1/models?limit=5",
            "Accept: application/json\r\n",
            b"",
        ),
        request(
            "POST /v1/jobs",
            "Content-Length: 11\r\nContent-Type: application/json\r\n",
            b"{\"a\":\"bc\"}x",
        ),
        request(
            "PUT /v1/files/7",
            "Transfer-Encoding: chunked\r\n",
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        ),
        request(
            "POST /v1/jobs",
            "Expect: 100-continue\r\nContent-Length: 2\r\n",
            b"{}",
        ),
        request("HEAD /v1/models", "", b""),
        request("OPTIONS *", "", b""),
        request("DELETE /v1/files/7", "Content-Length: 0\r\n", b""),
        request(
            "GET http://api.example.com/v1/models",
            "Connection: close\r\n",
            b"",
        ),
        request(
            "POST /v1/jobs",
            "Transfer-Encoding: chunked\r\nTE: trailers\r\n",
            b"00A\r\n0123456789\r\n0\r\n\r\n",
        ),
        request("CONNECT api.example.com:443", "", b""),
        request("GET /", &format!("X-Pad: {}\r\n", "p".repeat(900)), b""),
    ]
}

/// The head's decimal numbers and the hexadecimal chunk sizes that start body lines.
fn fields(input: &[u8]) -> Vec<Field> {
    let head_end = find(input, b"\r\n\r\n").map_or(input.len(), |end| end + 4);
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
    let tokens: [&[u8]; 24] = [
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
        b"Transfer-Encoding: chunked\r\n",
        b"Transfer-Encoding: gzip, chunked\r\n",
        b"Content_Length: 1\r\n",
        b"Expect: 100-continue\r\n",
        b"Host: b\r\n",
        b"X-Original-URL: /admin\r\n",
        b"X-HTTP-Method-Override: DELETE\r\n",
        b"Connection: upgrade\r\n",
        b"Upgrade: h2c\r\n",
        b"Authorization: Bearer x\r\n",
        b"0\r\n\r\n",
        b"HTTP/1.0",
        b"GET / HTTP/1.1\r\n\r\n",
        b"FFFFFFFFFFFFFFFF",
    ];
    Grammar {
        seeds: seeds(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![
            bytes_of(HEAD_LIMIT),
            BODY_LIMIT,
            bytes_of(MAX_HEADERS),
            bytes_of(HEAD_LIMIT_CEILING),
            u64::MAX,
        ],
        fields,
        max_len: 2_500,
    }
}

/// Reads `pieces` fed in order into a fresh reader.
fn read(pieces: &[&[u8]]) -> ReadOutcome {
    let mut reader = RequestReader::new(limits());
    for piece in pieces {
        let _ = reader.feed(piece);
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

/// Whether `name` has an underscore and reads as a protected header with each `_` as `-`.
fn underscore_twin(name: &str) -> bool {
    let dashed = name.replace('_', "-").to_ascii_lowercase();
    name.contains('_')
        && UNDERSCORE_PROTECTED_HEADERS
            .iter()
            .chain(&RESERVED_CREDENTIAL_HEADERS)
            .chain(&METHOD_OVERRIDE_HEADERS)
            .chain(&TARGET_OVERRIDE_HEADERS)
            .any(|protected| dashed == *protected)
}

fn check_complete(input: &[u8], read: &ReadRequest) -> Result<(), String> {
    ensure!(
        read.wire_bytes() == bytes_of(input.len()),
        "a complete request used {} of {} bytes",
        read.wire_bytes(),
        input.len()
    );
    let head = find(input, b"\r\n\r\n")
        .map(|end| end + 4)
        .ok_or_else(|| "a complete request without a head end".to_owned())?;
    ensure!(head <= HEAD_LIMIT, "a {head}-byte head was read");
    let body = read.body();
    ensure!(
        bytes_of(body.len()) <= BODY_LIMIT,
        "a {}-byte body was read",
        body.len()
    );
    match read.framing() {
        BodyFraming::None => ensure!(
            body.is_empty() && head == input.len(),
            "a request without framing has a body"
        ),
        BodyFraming::ContentLength(length) => ensure!(
            bytes_of(body.len()) == length && &input[head..] == body,
            "a Content-Length {length} body of {} bytes",
            body.len()
        ),
        BodyFraming::Chunked => ensure!(
            dechunk(&input[head..]).as_deref() == Some(body),
            "the chunked body decodes otherwise here"
        ),
    }
    let request = read.request();
    ensure!(
        request.headers.len() <= MAX_HEADERS,
        "{} header fields",
        request.headers.len()
    );
    let lines = input[..head]
        .windows(2)
        .filter(|pair| *pair == b"\r\n")
        .count();
    ensure!(
        lines == request.headers.len() + 2,
        "{} header fields from {} head lines",
        request.headers.len(),
        lines - 2
    );
    ensure!(
        input.starts_with(format!("{} {} ", request.method, request.target).as_bytes()),
        "the request line is not the method and target as received"
    );
    let mut at = find(input, b"\r\n").unwrap_or(0);
    for (name, _) in &request.headers {
        let found = find(&input[at..head], name.as_bytes())
            .ok_or_else(|| format!("header {name:?} is not in the head after the last one"))?;
        at += found + name.len();
        ensure!(
            !TARGET_OVERRIDE_HEADERS
                .iter()
                .any(|header| name.eq_ignore_ascii_case(header)),
            "target override {name:?} was read"
        );
        ensure!(!underscore_twin(name), "underscore twin {name:?} was read");
    }
    let expect = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("expect"));
    let continues = expect.is_some_and(|(_, value)| value.eq_ignore_ascii_case("100-continue"));
    ensure!(
        expect.is_none() || continues,
        "Expect {expect:?} was accepted"
    );
    ensure!(
        read.expects_continue() == continues,
        "100-continue reported as {}",
        read.expects_continue()
    );
    let shorter = self::read(&[&input[..input.len() - 1]]);
    ensure!(
        shorter == ReadOutcome::NeedMore,
        "a strict prefix of a complete request gave {shorter:?}"
    );
    Ok(())
}

fn check_refusal(input: &[u8], refusal: &ReadRefusal) -> Result<(), String> {
    match refusal {
        ReadRefusal::HeadTooLarge { limit } => ensure!(
            *limit == HEAD_LIMIT
                && input.len() >= HEAD_LIMIT
                && find(&input[..HEAD_LIMIT], b"\r\n\r\n").is_none(),
            "head too large with a head end within {limit} bytes"
        ),
        ReadRefusal::BodyTooLarge { limit, length } => ensure!(
            *limit == BODY_LIMIT && length > limit,
            "a {length}-byte body refused at {limit}"
        ),
        ReadRefusal::TooManyHeaders { limit } => {
            ensure!(*limit == MAX_HEADERS, "too many headers at {limit}")
        }
        _ => {}
    }
    Ok(())
}

fn check(input: &[u8]) -> Verdict {
    let whole = read(&[input]);
    ensure!(whole == read(&[input]), "two readings of one input differ");
    let mut rng = SplitMix64::for_input(input);
    for _ in 0..3 {
        let pieces = rng.split(input);
        let split = read(&pieces);
        ensure!(
            split == whole,
            "fed in {} pieces: {split:?}; whole: {whole:?}",
            pieces.len()
        );
    }
    if input.len() <= 512 {
        let bytewise: Vec<&[u8]> = input.chunks(1).collect();
        let split = read(&bytewise);
        ensure!(split == whole, "byte by byte: {split:?}; whole: {whole:?}");
    }
    let mut reader = RequestReader::new(limits());
    let progress = reader.feed(input);
    match &whole {
        ReadOutcome::Refused(refusal) => {
            let again = Err(refusal.clone());
            ensure!(
                progress == again,
                "feed returned {progress:?} for {refusal:?}"
            );
            ensure!(
                reader.feed(b"x") == again && reader.feed(b"") == again,
                "a refusal was not final"
            );
            check_refusal(input, refusal)?;
            Ok(format!("refused:{}", variant(&format!("{refusal:?}"))))
        }
        ReadOutcome::NeedMore => {
            ensure!(
                progress == Ok(ReadProgress::NeedMore),
                "feed returned {progress:?} for an incomplete request"
            );
            ensure!(
                input.len() < HEAD_LIMIT || find(input, b"\r\n\r\n").is_some(),
                "an input of {} bytes without a head end needs more",
                input.len()
            );
            Ok("need_more".to_owned())
        }
        ReadOutcome::Complete(request) => {
            ensure!(
                progress == Ok(ReadProgress::Complete),
                "feed returned {progress:?} for a complete request"
            );
            ensure!(
                reader.clone().feed(b"x") == Err(ReadRefusal::PipelinedBytes),
                "a byte after a complete request was not refused"
            );
            ensure!(
                reader.feed(b"") == Ok(ReadProgress::Complete),
                "an empty feed after a complete request"
            );
            check_complete(input, request)?;
            Ok(format!(
                "complete:{}",
                variant(&format!("{:?}", request.framing()))
            ))
        }
    }
}

/// Requests that reach each refusal and the edges of acceptance.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "need_more",
        input: b"",
    },
    Regression {
        expect: "need_more",
        input: b"GET / HTTP/1.1\r\nHost: a\r\n\r",
    },
    Regression {
        expect: "complete:None",
        input: b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    },
    Regression {
        expect: "complete:Chunked",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 0000000000000005\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "complete:ContentLength",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
    },
    Regression {
        expect: "refused:BareLineFeed",
        input: b"GET / HTTP/1.1\nHost: a\r\n\r\n",
    },
    Regression {
        expect: "refused:BareCarriageReturn",
        input: b"GET / HTTP/1.1\rHost: a\r\n\r\n",
    },
    Regression {
        expect: "refused:ObsoleteLineFolding",
        input: b"GET / HTTP/1.1\r\nX-A: b\r\n c\r\n\r\n",
    },
    Regression {
        expect: "refused:EmptyLineBeforeRequest",
        input: b"\r\nGET / HTTP/1.1\r\n\r\n",
    },
    Regression {
        expect: "refused:NotHttp11",
        input: b"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
    },
    Regression {
        expect: "refused:Syntax",
        input: b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
    },
    Regression {
        expect: "refused:HeaderValueNotText",
        input: b"GET / HTTP/1.1\r\nX-Bin: \xff\r\n\r\n",
    },
    Regression {
        expect: "refused:UnderscoreTwin",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer_Encoding: chunked\r\n\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:TargetOverride",
        input: b"GET / HTTP/1.1\r\nHost: a\r\nX-Original-URL: /admin\r\n\r\n",
    },
    Regression {
        expect: "refused:UnsupportedExpectation",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nExpect: 200-ok\r\nContent-Length: 0\r\n\r\n",
    },
    Regression {
        expect: "refused:Inspection",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\
                 Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:Inspection",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 007\r\n\r\n1234567",
    },
    Regression {
        expect: "refused:Inspection",
        input: b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:BodyTooLarge",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4097\r\n\r\n",
    },
    Regression {
        expect: "refused:BodyTooLarge",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 FFFFFFFFFFFFFFFF\r\n",
    },
    Regression {
        expect: "refused:InvalidChunkSize",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 00000000000000005\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:ChunkExtension",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 5;x\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:ChunkNotTerminated",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 3\r\nhello\r\n0\r\n\r\n",
    },
    Regression {
        expect: "refused:Trailers",
        input: b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n\
                 0\r\nX-T: 1\r\n\r\n",
    },
    Regression {
        expect: "refused:PipelinedBytes",
        input: b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\n\r\n",
    },
];

#[test]
fn mutated_guest_requests_read_the_same_in_every_split() {
    let run = Run {
        target: "relay::reader",
        seed: 0x00E0_1E00_0000_0001,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "relay::reader",
        &[
            "complete:None",
            "complete:ContentLength",
            "complete:Chunked",
            "need_more",
            "refused:HeadTooLarge",
            "refused:BareLineFeed",
            "refused:BareCarriageReturn",
            "refused:Syntax",
            "refused:Inspection",
            "refused:BodyTooLarge",
            "refused:InvalidChunkSize",
            "refused:ChunkNotTerminated",
            "refused:PipelinedBytes",
        ],
    );
}

#[test]
fn reader_size_limits_hold_at_their_boundaries() {
    // A head of exactly the limit is read; one byte longer is refused.
    let head = |length: usize| {
        let mut bytes = b"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: ".to_vec();
        let pad = length - bytes.len() - 4;
        bytes.extend(std::iter::repeat_n(b'p', pad));
        bytes.extend_from_slice(b"\r\n\r\n");
        bytes
    };
    assert_eq!(check(&head(HEAD_LIMIT)).unwrap(), "complete:None");
    assert_eq!(
        check(&head(HEAD_LIMIT + 1)).unwrap(),
        "refused:HeadTooLarge"
    );
    // A body of exactly the limit is read, by length or chunked; one byte more is refused.
    let limit = usize::try_from(BODY_LIMIT).unwrap();
    for length in [limit, limit + 1] {
        let fixed = request(
            "POST /",
            &format!("Content-Length: {length}\r\n"),
            &vec![b'b'; length],
        );
        let mut body = format!("{length:x}\r\n").into_bytes();
        body.extend(std::iter::repeat_n(b'c', length));
        body.extend_from_slice(b"\r\n0\r\n\r\n");
        let chunked = request("POST /", "Transfer-Encoding: chunked\r\n", &body);
        let expect = |framing: &str| {
            if length == limit {
                format!("complete:{framing}")
            } else {
                "refused:BodyTooLarge".to_owned()
            }
        };
        assert_eq!(check(&fixed).unwrap(), expect("ContentLength"));
        assert_eq!(check(&chunked).unwrap(), expect("Chunked"));
    }
    // MAX_HEADERS fields are read; one more is refused.
    for extra in [MAX_HEADERS - 1, MAX_HEADERS] {
        let fields: String = (0..extra)
            .map(|index| format!("X-{index}: v\r\n"))
            .collect();
        let expect = if extra < MAX_HEADERS {
            "complete:None"
        } else {
            "refused:TooManyHeaders"
        };
        assert_eq!(check(&request("GET /", &fields, b"")).unwrap(), expect);
    }
}
