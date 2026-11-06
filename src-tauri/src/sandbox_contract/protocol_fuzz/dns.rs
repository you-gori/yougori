//! The DNS guard's wire layer under the fuzzer (M10D; VM-W08, VM §4.2 step 2; VM-W50):
//! `parse_query` on mutated guest messages and `encode_response` on every query it
//! accepts or refuses.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - Size limits: an accepted message is at most [`MAX_MESSAGE_BYTES`], its name at most
//!   [`MAX_WIRE_NAME_BYTES`] in wire form with labels of 1 to 63 bytes, and nothing follows
//!   the question; a message under the header length is refused as too short, a response
//!   as not a query and any other message over 512 bytes as too long, in that order.
//! - Exactness: an accepted query rebuilt from its parsed header and question is the input
//!   byte for byte (the AD bit, which the parser accepts and does not keep, aside).
//! - The second guard: a name the parser accepts but cannot write as text (a label holding
//!   a dot or a non-ASCII byte) is refused by `Question::name_text`, and every other name's
//!   text is its labels joined with dots.
//! - The encoder: the response to an accepted or refused query, for every response code,
//!   reads back with the query's id, opcode, RD and CD bits and the question echoed
//!   exactly; up to `answer_capacity` addresses of the asked family read back as written
//!   and one more is refused, as are answers with an error code, a TTL over the limit and
//!   addresses for a question that takes none; no response is accepted as a query, and
//!   none exceeds 512 bytes. Refusals without a header or of a response get no response.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{variant, Field, Grammar};
use super::rng::SplitMix64;
use crate::sandbox_contract::destinations::AddressFamily;
use crate::sandbox_contract::dns_guard::{
    answer_capacity, encode_response, parse_query, EncodeError, GuestQuery, QueryHeader,
    QueryProblem, QueryRefusal, Question, ResponseCode, CLASS_IN, HEADER_BYTES, MAX_MESSAGE_BYTES,
    MAX_TTL_SECONDS, MAX_WIRE_NAME_BYTES, TYPE_A, TYPE_AAAA,
};

/// Mutated messages per run.
const ITERATIONS: u64 = 80_000;

const RD: u8 = 0x01;
const AD: u8 = 0x20;
const CD: u8 = 0x10;

const CODES: [ResponseCode; 6] = [
    ResponseCode::NoError,
    ResponseCode::FormErr,
    ResponseCode::ServFail,
    ResponseCode::NxDomain,
    ResponseCode::NotImp,
    ResponseCode::Refused,
];

/// A message as a stub resolver writes it: `id`, the two flag bytes, one question of
/// `labels`, `qtype` and `qclass`, and no records.
fn query(id: u16, flags: [u8; 2], labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut message = id.to_be_bytes().to_vec();
    message.extend_from_slice(&flags);
    message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in labels {
        message.push(u8::try_from(label.len()).unwrap());
        message.extend_from_slice(label);
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&qclass.to_be_bytes());
    message
}

fn seeds() -> Vec<Vec<u8>> {
    let label63 = [b'a'; 63];
    let label61 = [b'b'; 61];
    let mut edns = query(0x5151, [RD, 0], &[b"pypi", b"org"], TYPE_A, CLASS_IN);
    edns[11] = 1;
    edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let mut response = query(0x6262, [0x81, 0x80], &[b"pypi", b"org"], TYPE_A, CLASS_IN);
    response[7] = 1;
    response.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 151, 101, 0, 223]);
    vec![
        query(0x1111, [RD, 0], &[b"pypi", b"org"], TYPE_A, CLASS_IN),
        query(
            0x2222,
            [RD, CD | AD],
            &[b"PyPI", b"Org"],
            TYPE_AAAA,
            CLASS_IN,
        ),
        query(0x3333, [0, 0], &[], TYPE_A, CLASS_IN),
        query(0x4444, [RD, 0], &[b"api", b"github", b"com"], 65, CLASS_IN),
        query(0x4545, [RD, 0], &[b"_sip", b"_tcp", b"corp"], 33, CLASS_IN),
        query(
            0x5555,
            [RD, 0],
            &[&label63, &label63, &label63, &label61],
            TYPE_A,
            CLASS_IN,
        ),
        query(0x5656, [RD, 0], &[b"api.example", b"com"], TYPE_A, CLASS_IN),
        query(
            0x5757,
            [RD, 0],
            &[b"caf\xc3\xa9", b"example"],
            TYPE_AAAA,
            CLASS_IN,
        ),
        query(0x5858, [RD, 0], &[b"version", b"bind"], 16, 3),
        edns,
        response,
    ]
}

/// The header counts, every label length byte and the type and class after a whole name.
fn fields(input: &[u8]) -> Vec<Field> {
    let mut fields = Vec::new();
    if input.len() < HEADER_BYTES {
        return fields;
    }
    for start in [4, 6, 8, 10] {
        fields.push(Field::binary(start, 2));
    }
    let mut offset = HEADER_BYTES;
    while let Some(&length) = input.get(offset) {
        fields.push(Field::binary(offset, 1));
        if length == 0 || length & 0xC0 != 0 {
            break;
        }
        offset += 1 + usize::from(length);
    }
    if input.get(offset) == Some(&0) && offset + 5 <= input.len() {
        fields.push(Field::binary(offset + 1, 2));
        fields.push(Field::binary(offset + 3, 2));
    }
    fields
}

fn grammar() -> Grammar {
    Grammar {
        seeds: seeds(),
        dictionary: vec![
            vec![0xC0, 0x0C],
            vec![0x00],
            vec![0x3F],
            vec![0x40],
            vec![0x80],
            vec![b'.'],
            vec![0, 1, 0, 1],
            vec![0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0],
        ],
        limits: vec![
            u64::try_from(MAX_MESSAGE_BYTES).unwrap(),
            u64::try_from(MAX_WIRE_NAME_BYTES).unwrap(),
            u64::try_from(HEADER_BYTES).unwrap(),
            63,
            u64::from(CLASS_IN),
            u64::from(TYPE_AAAA),
            41,
        ],
        fields,
        max_len: 600,
    }
}

/// A response as the test reads it back: header words, the echoed question and the
/// address records with their TTLs.
#[derive(Debug, PartialEq, Eq)]
struct Response {
    id: u16,
    flags: [u8; 2],
    question: Option<Vec<u8>>,
    answers: Vec<(IpAddr, u32)>,
}

/// Reads a response strictly: no authority or additional record, an uncompressed
/// question, every answer named by the pointer to the question, nothing after the last.
fn read_response(bytes: &[u8]) -> Result<Response, String> {
    ensure!(
        (HEADER_BYTES..=MAX_MESSAGE_BYTES).contains(&bytes.len()),
        "a response of {} bytes",
        bytes.len()
    );
    let word = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let (questions, answers, authorities, additional) = (word(4), word(6), word(8), word(10));
    ensure!(
        questions <= 1 && authorities == 0 && additional == 0,
        "response counts {questions} {authorities} {additional}"
    );
    let mut offset = HEADER_BYTES;
    let question = if questions == 1 {
        loop {
            let length = usize::from(
                *bytes
                    .get(offset)
                    .ok_or_else(|| "the echoed name is cut".to_owned())?,
            );
            ensure!(length <= 63, "an echoed label of {length} bytes");
            offset += 1 + length;
            if length == 0 {
                break;
            }
        }
        offset += 4;
        Some(
            bytes
                .get(HEADER_BYTES..offset)
                .ok_or_else(|| "the echoed question is cut".to_owned())?
                .to_vec(),
        )
    } else {
        None
    };
    let mut records = Vec::new();
    for _ in 0..answers {
        let record = bytes
            .get(offset..offset + 12)
            .ok_or_else(|| "an answer record is cut".to_owned())?;
        ensure!(
            record[..2] == [0xC0, 0x0C],
            "an answer not named by the question pointer"
        );
        let record_type = u16::from_be_bytes([record[2], record[3]]);
        let class = u16::from_be_bytes([record[4], record[5]]);
        let ttl = u32::from_be_bytes([record[6], record[7], record[8], record[9]]);
        let length = usize::from(u16::from_be_bytes([record[10], record[11]]));
        ensure!(class == CLASS_IN, "an answer of class {class}");
        let data = bytes
            .get(offset + 12..offset + 12 + length)
            .ok_or_else(|| "an answer's data is cut".to_owned())?;
        let address = match (record_type, data.len()) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap())),
            (TYPE_AAAA, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap())),
            other => return Err(format!("an answer of type and length {other:?}")),
        };
        records.push((address, ttl));
        offset += 12 + length;
    }
    ensure!(
        offset == bytes.len(),
        "{} bytes follow the answers",
        bytes.len() - offset
    );
    Ok(Response {
        id: word(0),
        flags: [bytes[2], bytes[3]],
        question,
        answers: records,
    })
}

/// Checks one encoded response against the query header, question, code and answers it
/// was written for.
fn check_response(
    bytes: &[u8],
    header: &QueryHeader,
    question: Option<&Question>,
    code: ResponseCode,
    answers: &[(IpAddr, u32)],
) -> Result<(), String> {
    let read = read_response(bytes)?;
    let rd = if header.recursion_desired() { RD } else { 0 };
    let cd = if header.checking_disabled() { CD } else { 0 };
    let expected = Response {
        id: header.id(),
        flags: [0x80 | (header.opcode() << 3) | rd, 0x80 | cd | code.code()],
        question: question.map(|question| question.wire().to_vec()),
        answers: answers.to_vec(),
    };
    ensure!(read == expected, "response {read:?}, expected {expected:?}");
    match parse_query(bytes) {
        Err(refusal) if refusal.problem() == QueryProblem::NotAQuery => Ok(()),
        other => Err(format!("a response parsed as a query: {other:?}")),
    }
}

/// The `index`th test address of `family`.
fn address(family: AddressFamily, index: usize) -> IpAddr {
    match family {
        AddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(index).unwrap())),
        AddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0x0DB8,
            0,
            0,
            0,
            0,
            0,
            u16::try_from(index).unwrap(),
        )),
    }
}

/// The encoder on an accepted query: every code without records, and address records up
/// to the capacity and one past it.
fn check_encoder(input: &[u8], query: &GuestQuery) -> Result<(), String> {
    let header = query.header();
    let question = query.question();
    for code in CODES {
        let bytes = encode_response(&header, Some(question), code, &[], 0)
            .map_err(|error| format!("no {code} response: {error}"))?;
        check_response(&bytes, &header, Some(question), code, &[])?;
    }
    let mut rng = SplitMix64::for_input(input);
    let ttl = *rng.pick(&[0, 1, 300, MAX_TTL_SECONDS]);
    let Some(family) = question.family() else {
        let one = [address(AddressFamily::Ipv4, 1)];
        let refused = encode_response(&header, Some(question), ResponseCode::NoError, &one, ttl);
        ensure!(
            matches!(refused, Err(EncodeError::QuestionTakesNoAddresses { .. })),
            "addresses for a question that takes none: {refused:?}"
        );
        return Ok(());
    };
    let capacity = answer_capacity(question);
    ensure!(
        capacity >= 1,
        "a {family:?} question with room for no answer"
    );
    let count = rng.between(1, capacity);
    let addresses: Vec<IpAddr> = (0..count).map(|index| address(family, index)).collect();
    let bytes = encode_response(
        &header,
        Some(question),
        ResponseCode::NoError,
        &addresses,
        ttl,
    )
    .map_err(|error| format!("{count} of {capacity} answers refused: {error}"))?;
    let expected: Vec<(IpAddr, u32)> = addresses.iter().map(|address| (*address, ttl)).collect();
    check_response(
        &bytes,
        &header,
        Some(question),
        ResponseCode::NoError,
        &expected,
    )?;
    let past: Vec<IpAddr> = (0..=capacity).map(|index| address(family, index)).collect();
    let refused = encode_response(&header, Some(question), ResponseCode::NoError, &past, ttl);
    ensure!(
        refused
            == Err(EncodeError::TooManyAnswers {
                count: capacity + 1,
                capacity
            }),
        "one answer past the capacity: {refused:?}"
    );
    let refused = encode_response(
        &header,
        Some(question),
        ResponseCode::Refused,
        &addresses,
        ttl,
    );
    ensure!(
        matches!(refused, Err(EncodeError::AnswersWithErrorCode { .. })),
        "answers with an error code: {refused:?}"
    );
    let refused = encode_response(
        &header,
        Some(question),
        ResponseCode::NoError,
        &addresses,
        MAX_TTL_SECONDS + 1,
    );
    ensure!(
        matches!(refused, Err(EncodeError::TtlTooLarge { .. })),
        "a TTL over the limit: {refused:?}"
    );
    let other = match family {
        AddressFamily::Ipv4 => address(AddressFamily::Ipv6, 1),
        AddressFamily::Ipv6 => address(AddressFamily::Ipv4, 1),
    };
    let refused = encode_response(
        &header,
        Some(question),
        ResponseCode::NoError,
        &[other],
        ttl,
    );
    ensure!(
        matches!(refused, Err(EncodeError::FamilyMismatch { .. })),
        "an address of the other family: {refused:?}"
    );
    Ok(())
}

fn check_accepted(input: &[u8], query: &GuestQuery) -> Verdict {
    let question = query.question();
    let header = query.header();
    ensure!(
        input.len() <= MAX_MESSAGE_BYTES,
        "a {}-byte message was accepted",
        input.len()
    );
    ensure!(
        HEADER_BYTES + question.wire().len() == input.len(),
        "bytes follow an accepted question"
    );
    ensure!(
        question.wire().len() - 4 <= MAX_WIRE_NAME_BYTES,
        "an accepted name of {} wire bytes",
        question.wire().len() - 4
    );
    let labels: Vec<&[u8]> = question.labels().collect();
    ensure!(
        labels.iter().all(|label| (1..=63).contains(&label.len())),
        "an accepted label outside 1..=63 bytes"
    );
    ensure!(
        question.class() == CLASS_IN,
        "class {} accepted",
        question.class()
    );
    let rd = if header.recursion_desired() { RD } else { 0 };
    let cd = if header.checking_disabled() { CD } else { 0 };
    let rebuilt = self::query(
        header.id(),
        [rd, cd],
        &labels,
        question.type_code(),
        question.class(),
    );
    let mut expected = input.to_vec();
    expected[3] &= !AD;
    ensure!(
        rebuilt == expected,
        "the parsed query rebuilds to {}",
        hex::encode(&rebuilt)
    );
    let unwritable = labels
        .iter()
        .any(|label| label.iter().any(|byte| *byte == b'.' || !byte.is_ascii()));
    let label = match question.name_text() {
        Ok(text) => {
            ensure!(
                !unwritable,
                "a name with a dot or non-ASCII label became {text:?}"
            );
            ensure!(
                text.as_bytes() == labels.join(&b'.').as_slice(),
                "the name text {text:?} is not the labels joined"
            );
            "accepted"
        }
        Err(_) if unwritable => "accepted:unwritable",
        Err(error) => return Err(format!("a writable name was refused: {error}")),
    };
    check_encoder(input, query)?;
    Ok(label.to_owned())
}

fn check_refused(input: &[u8], refusal: &QueryRefusal) -> Verdict {
    let problem = refusal.problem();
    if input.len() < HEADER_BYTES {
        ensure!(
            problem == QueryProblem::TooShort { bytes: input.len() } && refusal.header().is_none(),
            "a {}-byte message refused with {problem:?}",
            input.len()
        );
    } else {
        let id = u16::from_be_bytes([input[0], input[1]]);
        ensure!(
            refusal.header().map(QueryHeader::id) == Some(id),
            "the refusal keeps no header or another id"
        );
        if input[2] & 0x80 != 0 {
            ensure!(
                problem == QueryProblem::NotAQuery,
                "a response refused with {problem:?}"
            );
        } else if input.len() > MAX_MESSAGE_BYTES {
            ensure!(
                problem == QueryProblem::TooLong { bytes: input.len() },
                "a {}-byte query refused with {problem:?}",
                input.len()
            );
        }
    }
    if let Some(question) = refusal.question() {
        let wire = question.wire();
        ensure!(
            input.get(HEADER_BYTES..HEADER_BYTES + wire.len()) == Some(wire),
            "the refusal's question is not the bytes after the header"
        );
    }
    match (problem.response_code(), refusal.header()) {
        (None, _) => ensure!(
            matches!(
                problem,
                QueryProblem::TooShort { .. } | QueryProblem::NotAQuery
            ),
            "{problem:?} gets no response"
        ),
        (Some(code), Some(header)) => {
            let bytes = encode_response(&header, refusal.question(), code, &[], 0)
                .map_err(|error| format!("the {code} answer to {problem:?} failed: {error}"))?;
            check_response(&bytes, &header, refusal.question(), code, &[])?;
        }
        (Some(_), None) => return Err(format!("{problem:?} has a code but no header")),
    }
    Ok(format!("refused:{}", variant(&format!("{problem:?}"))))
}

fn check(input: &[u8]) -> Verdict {
    let first = parse_query(input);
    ensure!(
        first == parse_query(input),
        "two parses of one message differ"
    );
    match &first {
        Ok(query) => check_accepted(input, query),
        Err(refusal) => check_refused(input, refusal),
    }
}

/// Messages that reach each refusal, the edges of acceptance, and the guard's second check.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "refused:TooShort",
        input: b"",
    },
    Regression {
        expect: "refused:TooShort",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00",
    },
    Regression {
        expect: "refused:NotAQuery",
        input: b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00",
    },
    Regression {
        expect: "refused:UnsupportedOpcode",
        input: b"\x12\x34\x11\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:UnexpectedHeaderBits",
        input: b"\x12\x34\x03\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:UnexpectedHeaderBits",
        input: b"\x12\x34\x01\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:QuestionCount",
        input: b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    },
    Regression {
        expect: "refused:QuestionCount",
        input: b"\x12\x34\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:CompressedName",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:ReservedLabelType",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x40\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:ReservedLabelType",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x80\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:TruncatedQuestion",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04pypi\x03or",
    },
    Regression {
        expect: "refused:TruncatedQuestion",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04pypi\x00\x00\x01\x00",
    },
    Regression {
        expect: "refused:UnexpectedRecords",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "refused:AdditionalRecords",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x01\x00\x01\
                 \x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00",
    },
    Regression {
        expect: "refused:TrailingBytes",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00",
    },
    Regression {
        expect: "refused:UnsupportedClass",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\
                 \x00\x00\x10\x00\x03",
    },
    Regression {
        expect: "accepted",
        input: b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "accepted",
        input: b"\x12\x34\x01\x30\x00\x01\x00\x00\x00\x00\x00\x00\x04PyPI\x03org\
                 \x00\x00\x1c\x00\x01",
    },
    Regression {
        expect: "accepted:unwritable",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0bapi.example\x03com\
                 \x00\x00\x01\x00\x01",
    },
    Regression {
        expect: "accepted:unwritable",
        input: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\xc3\xa9\x00\x00\x01\x00\x01",
    },
];

#[test]
fn mutated_guest_queries_keep_every_parser_and_encoder_property() {
    let run = Run {
        target: "dns_guard",
        seed: 0x00E0_1D00_0000_0001,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(), check);
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "dns_guard",
        &[
            "accepted",
            "accepted:unwritable",
            "refused:TooShort",
            "refused:NotAQuery",
            "refused:TooLong",
            "refused:UnsupportedOpcode",
            "refused:UnexpectedHeaderBits",
            "refused:QuestionCount",
            "refused:CompressedName",
            "refused:ReservedLabelType",
            "refused:NameTooLong",
            "refused:TruncatedQuestion",
            "refused:UnexpectedRecords",
            "refused:AdditionalRecords",
            "refused:TrailingBytes",
            "refused:UnsupportedClass",
        ],
    );
}

#[test]
fn dns_size_limits_hold_at_their_boundaries() {
    let label63 = [b'a'; 63];
    let label61 = [b'b'; 61];
    let label62 = [b'c'; 62];
    // A name of exactly 255 wire bytes (3 * 64 + 62 + the root byte), then one of 256.
    let longest = query(
        1,
        [RD, 0],
        &[&label63, &label63, &label63, &label61],
        TYPE_A,
        CLASS_IN,
    );
    assert_eq!(longest.len(), HEADER_BYTES + MAX_WIRE_NAME_BYTES + 4);
    assert_eq!(check(&longest).unwrap(), "accepted");
    let over = query(
        1,
        [RD, 0],
        &[&label63, &label63, &label63, &label62],
        TYPE_A,
        CLASS_IN,
    );
    assert_eq!(
        parse_query(&over).unwrap_err().problem(),
        QueryProblem::NameTooLong { bytes: 256 }
    );
    assert_eq!(check(&over).unwrap(), "refused:NameTooLong");
    // 512 bytes is within the message limit (so the trailing bytes are what is refused);
    // 513 is over it.
    let mut padded = query(2, [RD, 0], &[b"pypi", b"org"], TYPE_A, CLASS_IN);
    padded.resize(MAX_MESSAGE_BYTES, 0);
    assert_eq!(check(&padded).unwrap(), "refused:TrailingBytes");
    padded.push(0);
    assert_eq!(check(&padded).unwrap(), "refused:TooLong");
    // A response over the limit is refused as a response, never answered.
    padded[2] |= 0x80;
    assert_eq!(check(&padded).unwrap(), "refused:NotAQuery");
}
