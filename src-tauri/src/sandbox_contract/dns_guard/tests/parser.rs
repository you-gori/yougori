//! The strict query parser: the accepted stub subset, and every refusal with the response
//! code it leads to.

use super::*;
use crate::sandbox_contract::destinations::{AddressFamily, GuestQueryType, NameError};

fn problem(message: &[u8]) -> QueryProblem {
    parse_query(message).unwrap_err().problem()
}

fn with_header_byte(mut message: Vec<u8>, index: usize, value: u8) -> Vec<u8> {
    message[index] = value;
    message
}

fn with_counts(mut message: Vec<u8>, counts: [u16; 4]) -> Vec<u8> {
    for (slot, count) in counts.iter().enumerate() {
        message[4 + 2 * slot..6 + 2 * slot].copy_from_slice(&count.to_be_bytes());
    }
    message
}

#[test]
fn a_stub_query_parses_into_its_header_and_question() {
    let message = query(0xA1B2, "Api.Example.com", TYPE_A);
    let parsed = parse_query(&message).unwrap();
    assert_eq!(parsed.header().id(), 0xA1B2);
    assert_eq!(parsed.header().opcode(), 0);
    assert!(parsed.header().recursion_desired());
    assert!(!parsed.header().checking_disabled());
    let question = parsed.question();
    assert_eq!(question.wire(), &message[HEADER_BYTES..]);
    assert_eq!(
        question.labels().collect::<Vec<_>>(),
        vec![&b"Api"[..], b"Example", b"com"]
    );
    assert_eq!(question.type_code(), TYPE_A);
    assert_eq!(question.query_type(), GuestQueryType::A);
    assert_eq!(question.class(), CLASS_IN);
    assert_eq!(question.family(), Some(AddressFamily::Ipv4));
    assert_eq!(question.name_text().unwrap(), "Api.Example.com");

    let aaaa = parse_query(&query(7, "api.example.com", TYPE_AAAA)).unwrap();
    assert_eq!(aaaa.question().family(), Some(AddressFamily::Ipv6));
    assert_eq!(aaaa.question().query_type(), GuestQueryType::Aaaa);
}

#[test]
fn rd_ad_and_cd_may_be_set_or_clear() {
    // glibc with `trust-ad` sets AD in queries (RFC 6840 §5.7); CD is copied back.
    for flags in [[0x00, 0x00], [RD, 0x20], [RD, 0x10], [0x00, 0x30]] {
        let mut message = query(1, "api.example.com", TYPE_A);
        message[2] = flags[0];
        message[3] = flags[1];
        let parsed = parse_query(&message).unwrap();
        assert_eq!(parsed.header().recursion_desired(), flags[0] & RD != 0);
        assert_eq!(parsed.header().checking_disabled(), flags[1] & 0x10 != 0);
    }
}

#[test]
fn short_messages_and_responses_are_dropped() {
    for length in 0..HEADER_BYTES {
        let refusal = parse_query(&vec![0; length]).unwrap_err();
        assert_eq!(refusal.problem(), QueryProblem::TooShort { bytes: length });
        assert_eq!(refusal.header(), None);
        assert_eq!(refusal.problem().response_code(), None);
    }
    let response = with_header_byte(query(1, "api.example.com", TYPE_A), 2, 0x80 | RD);
    let refusal = parse_query(&response).unwrap_err();
    assert_eq!(refusal.problem(), QueryProblem::NotAQuery);
    assert_eq!(refusal.problem().response_code(), None);
    // A response is dropped even when it is also too long.
    let mut long_response = response;
    long_response.resize(600, 0);
    assert_eq!(problem(&long_response), QueryProblem::NotAQuery);
}

#[test]
fn a_message_over_512_bytes_is_a_format_error() {
    let mut message = query(1, "api.example.com", TYPE_A);
    message.resize(MAX_MESSAGE_BYTES + 1, 0);
    let refusal = parse_query(&message).unwrap_err();
    assert_eq!(
        refusal.problem(),
        QueryProblem::TooLong {
            bytes: MAX_MESSAGE_BYTES + 1
        }
    );
    assert_eq!(refusal.question(), None);
    assert_eq!(
        refusal.problem().response_code(),
        Some(ResponseCode::FormErr)
    );
}

#[test]
fn other_opcodes_are_not_implemented() {
    // IQUERY 1, STATUS 2, NOTIFY 4, UPDATE 5, and the unassigned 15.
    for opcode in [1u8, 2, 4, 5, 15] {
        let message = with_header_byte(query(1, "api.example.com", TYPE_A), 2, opcode << 3);
        let refusal = parse_query(&message).unwrap_err();
        assert_eq!(
            refusal.problem(),
            QueryProblem::UnsupportedOpcode { opcode }
        );
        assert_eq!(refusal.header().unwrap().opcode(), opcode);
        assert_eq!(
            refusal.problem().response_code(),
            Some(ResponseCode::NotImp)
        );
    }
}

#[test]
fn header_bits_a_query_never_carries_are_format_errors() {
    // AA, TC in the third byte; RA, Z and every RCODE bit in the fourth.
    for (index, bit) in [
        (2, 0x04),
        (2, 0x02),
        (3, 0x80),
        (3, 0x40),
        (3, 0x01),
        (3, 0x08),
    ] {
        let mut message = query(1, "api.example.com", TYPE_A);
        message[index] |= bit;
        assert!(matches!(
            problem(&message),
            QueryProblem::UnexpectedHeaderBits { .. }
        ));
    }
}

#[test]
fn exactly_one_question_is_accepted() {
    let none = with_counts(query(1, "api.example.com", TYPE_A), [0, 0, 0, 0]);
    assert_eq!(problem(&none), QueryProblem::QuestionCount { count: 0 });
    let mut two = with_counts(query(1, "api.example.com", TYPE_A), [2, 0, 0, 0]);
    two.extend_from_slice(&question_bytes(&query(1, "evil.example.net", TYPE_A)));
    let refusal = parse_query(&two).unwrap_err();
    assert_eq!(refusal.problem(), QueryProblem::QuestionCount { count: 2 });
    assert_eq!(refusal.question(), None);
    assert_eq!(
        refusal.problem().response_code(),
        Some(ResponseCode::FormErr)
    );
}

#[test]
fn a_compressed_question_name_is_refused() {
    // A pointer to the header, to itself, and after one plain label.
    let mut to_header = query(1, "x.y", TYPE_A)[..HEADER_BYTES].to_vec();
    to_header.extend_from_slice(&[0xC0, 0x00, 0, 1, 0, 1]);
    assert_eq!(problem(&to_header), QueryProblem::CompressedName);
    let mut to_itself = query(1, "x.y", TYPE_A)[..HEADER_BYTES].to_vec();
    to_itself.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
    assert_eq!(problem(&to_itself), QueryProblem::CompressedName);
    let mut after_label = query(1, "x.y", TYPE_A)[..HEADER_BYTES].to_vec();
    after_label.extend_from_slice(&[3, b'a', b'p', b'i', 0xC0, 0x0C, 0, 1, 0, 1]);
    let refusal = parse_query(&after_label).unwrap_err();
    assert_eq!(refusal.problem(), QueryProblem::CompressedName);
    assert_eq!(refusal.question(), None);
}

#[test]
fn reserved_label_types_and_over_long_names_are_refused() {
    // A 64-byte label needs the length byte 0x40, a reserved label type.
    let long_label = vec![b'a'; 64];
    let mut message = query(1, "x.y", TYPE_A)[..HEADER_BYTES].to_vec();
    message.push(0x40);
    message.extend_from_slice(&long_label);
    message.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
    assert_eq!(
        problem(&message),
        QueryProblem::ReservedLabelType { byte: 0x40 }
    );
    let mut extended = query(1, "x.y", TYPE_A)[..HEADER_BYTES].to_vec();
    extended.extend_from_slice(&[0x81, 0, 0, 1, 0, 1]);
    assert_eq!(
        problem(&extended),
        QueryProblem::ReservedLabelType { byte: 0x81 }
    );

    // 63.63.63.61 is 253 text bytes and exactly 255 wire bytes: the longest name.
    let label63: &[u8] = &[b'a'; 63];
    let label61: &[u8] = &[b'b'; 61];
    let longest = query_labels(1, &[label63, label63, label63, label61], TYPE_A, CLASS_IN);
    let parsed = parse_query(&longest).unwrap();
    assert_eq!(parsed.question().wire().len(), MAX_WIRE_NAME_BYTES + 4);
    assert_eq!(parsed.question().name_text().unwrap().len(), 253);
    // One more byte is too long: four 63-byte labels need 257 bytes.
    let label62: &[u8] = &[b'b'; 62];
    let too_long = query_labels(1, &[label63, label63, label63, label62], TYPE_A, CLASS_IN);
    assert_eq!(problem(&too_long), QueryProblem::NameTooLong { bytes: 256 });
    let much_too_long = query_labels(1, &[label63; 4], TYPE_A, CLASS_IN);
    assert_eq!(
        problem(&much_too_long),
        QueryProblem::NameTooLong { bytes: 257 }
    );
    assert_eq!(
        QueryProblem::NameTooLong { bytes: 257 }.response_code(),
        Some(ResponseCode::FormErr)
    );
}

#[test]
fn records_in_a_query_are_refused_with_the_question_kept() {
    let base = query(1, "api.example.com", TYPE_A);
    for counts in [[1, 1, 0, 0], [1, 0, 1, 0]] {
        let refusal = parse_query(&with_counts(base.clone(), counts)).unwrap_err();
        assert!(matches!(
            refusal.problem(),
            QueryProblem::UnexpectedRecords { .. }
        ));
        assert_eq!(refusal.question().unwrap().wire(), &base[HEADER_BYTES..]);
    }
    // EDNS: an OPT record (root name, type 41, payload 1232, no options).
    let mut edns = with_counts(base.clone(), [1, 0, 0, 1]);
    edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let refusal = parse_query(&edns).unwrap_err();
    assert_eq!(
        refusal.problem(),
        QueryProblem::AdditionalRecords { count: 1 }
    );
    assert_eq!(refusal.question().unwrap().wire(), &base[HEADER_BYTES..]);
    assert_eq!(
        refusal.problem().response_code(),
        Some(ResponseCode::FormErr)
    );
}

#[test]
fn bytes_after_the_question_are_refused() {
    let mut message = query(1, "api.example.com", TYPE_A);
    message.push(0);
    let refusal = parse_query(&message).unwrap_err();
    assert_eq!(refusal.problem(), QueryProblem::TrailingBytes { bytes: 1 });
    assert!(refusal.question().is_some());
}

#[test]
fn a_truncated_question_is_refused() {
    let message = query(1, "api.example.com", TYPE_A);
    for length in HEADER_BYTES..message.len() {
        let refusal = parse_query(&message[..length]).unwrap_err();
        assert_eq!(refusal.problem(), QueryProblem::TruncatedQuestion);
        assert_eq!(refusal.question(), None);
    }
}

#[test]
fn only_class_in_is_implemented_and_every_type_is_left_to_v11() {
    // CH (version.bind probes), HS, NONE and ANY.
    for class in [3u16, 4, 254, 255] {
        let message = query_labels(1, &[b"api", b"example", b"com"], TYPE_A, class);
        let refusal = parse_query(&message).unwrap_err();
        assert_eq!(refusal.problem(), QueryProblem::UnsupportedClass { class });
        assert_eq!(refusal.question().unwrap().wire(), &message[HEADER_BYTES..]);
        assert_eq!(refusal.question().unwrap().family(), None);
        assert_eq!(
            refusal.problem().response_code(),
            Some(ResponseCode::NotImp)
        );
    }
    // Every type parses and is mapped to V02's guest query types; V11 decides.
    let types = [
        (TYPE_A, GuestQueryType::A),
        (TYPE_AAAA, GuestQueryType::Aaaa),
        (5u16, GuestQueryType::Other(5)),
        (12, GuestQueryType::Ptr),
        (15, GuestQueryType::Mx),
        (16, GuestQueryType::Txt),
        (33, GuestQueryType::Srv),
        (64, GuestQueryType::Svcb),
        (65, GuestQueryType::Https),
        (255, GuestQueryType::Any),
        (0, GuestQueryType::Other(0)),
    ];
    for (code, query_type) in types {
        let parsed = parse_query(&query(1, "api.example.com", code)).unwrap();
        assert_eq!(parsed.question().query_type(), query_type);
        let address_type = matches!(query_type, GuestQueryType::A | GuestQueryType::Aaaa);
        assert_eq!(parsed.question().family().is_some(), address_type);
    }
}

#[test]
fn the_wire_name_becomes_text_only_without_a_guess() {
    let text = |labels: &[&[u8]]| {
        parse_query(&query_labels(1, labels, TYPE_A, CLASS_IN))
            .unwrap()
            .question()
            .name_text()
    };
    // A dot inside a wire label would otherwise read as two labels.
    assert_eq!(
        text(&[b"api.example", b"com"]),
        Err(NameError::InvalidCharacter { character: '.' })
    );
    assert_eq!(
        text(&[b"api", b"example", b"com."]),
        Err(NameError::InvalidCharacter { character: '.' })
    );
    // Non-ASCII bytes, UTF-8 or not, have no text form without a guess.
    assert_eq!(
        text(&["bücher".as_bytes(), b"example", b"com"]),
        Err(NameError::NonAscii)
    );
    assert_eq!(
        text(&[&[0xFF, b'a'], b"example", b"com"]),
        Err(NameError::NonAscii)
    );
    // Everything else is passed on as received for V11 to judge: the root name, a single
    // label, other characters, IP-literal spellings and A-labels in any case.
    assert_eq!(text(&[]).unwrap(), "");
    assert_eq!(text(&[b"api"]).unwrap(), "api");
    assert_eq!(
        text(&[b"_dmarc", b"example", b"com"]).unwrap(),
        "_dmarc.example.com"
    );
    assert_eq!(
        text(&[b"a\0b", b"example", b"com"]).unwrap(),
        "a\0b.example.com"
    );
    assert_eq!(text(&[b"127", b"1"]).unwrap(), "127.1");
    assert_eq!(
        text(&[b"XN--BCHER-KVA", b"example", b"com"]).unwrap(),
        "XN--BCHER-KVA.example.com"
    );
}
