//! The strict response encoder: the id kept, the question echoed exactly, records only
//! where they belong, and the 512-byte limit.

use super::*;

fn parsed(message: &[u8]) -> GuestQuery {
    parse_query(message).unwrap()
}

#[test]
fn a_response_keeps_the_id_and_echoes_the_question_byte_for_byte() {
    let message = query(0xBEEF, "aPi.ExAmPlE.CoM", TYPE_A);
    let query = parsed(&message);
    let answers = [ip("93.184.216.34"), ip("93.184.216.35")];
    let response = encode_response(
        &query.header(),
        Some(query.question()),
        ResponseCode::NoError,
        &answers,
        60,
    )
    .unwrap();
    let decoded = decode(&response);
    assert_eq!(decoded.id, 0xBEEF);
    assert_eq!(decoded.code, ResponseCode::NoError);
    assert_eq!(decoded.question, question_bytes(&message));
    assert_eq!(decoded.answers, vec![(answers[0], 60), (answers[1], 60)]);
    // QR and the copied RD; RA; no AA, TC, Z, AD or CD.
    assert_eq!(decoded.flags, [0x80 | RD, 0x80]);
}

#[test]
fn rd_and_cd_are_copied_and_the_opcode_kept() {
    let mut message = query(9, "api.example.com", TYPE_AAAA);
    message[2] = 0x00;
    message[3] = 0x10;
    let query = parsed(&message);
    let answer = [ip("2606:2800:220:1:248:1893:25c8:1946")];
    let response = encode_response(
        &query.header(),
        Some(query.question()),
        ResponseCode::NoError,
        &answer,
        5,
    )
    .unwrap();
    let decoded = decode(&response);
    assert_eq!(decoded.flags, [0x80, 0x90]);
    assert_eq!(decoded.answers, vec![(answer[0], 5)]);

    // A NOTIMP for another opcode keeps that opcode and has no question.
    let mut notify = query_bytes_with_opcode(4);
    notify[0] = 0x12;
    let refusal = parse_query(&notify).unwrap_err();
    let response = encode_response(
        &refusal.header().unwrap(),
        None,
        ResponseCode::NotImp,
        &[],
        0,
    )
    .unwrap();
    assert_eq!(response.len(), HEADER_BYTES);
    assert_eq!(response[2], 0x80 | (4 << 3) | RD);
    assert_eq!(response[3], 0x80 | ResponseCode::NotImp.code());
    let decoded = decode(&response);
    assert_eq!(decoded.id, u16::from_be_bytes([0x12, notify[1]]));
    assert_eq!(decoded.question, Vec::<u8>::new());
}

fn query_bytes_with_opcode(opcode: u8) -> Vec<u8> {
    let mut message = query(0x0034, "api.example.com", TYPE_A);
    message[2] = (opcode << 3) | RD;
    message
}

#[test]
fn every_code_is_sent_with_the_question_and_no_record() {
    let message = query(77, "api.example.com", TYPE_A);
    let query = parsed(&message);
    for code in [
        ResponseCode::NoError,
        ResponseCode::FormErr,
        ResponseCode::ServFail,
        ResponseCode::NxDomain,
        ResponseCode::NotImp,
        ResponseCode::Refused,
    ] {
        let response =
            encode_response(&query.header(), Some(query.question()), code, &[], 0).unwrap();
        let decoded = decode(&response);
        assert_eq!(decoded.code, code);
        assert_eq!(ResponseCode::from_code(code.code()), Some(code));
        assert_eq!(decoded.id, 77);
        assert_eq!(decoded.question, question_bytes(&message));
        assert!(decoded.answers.is_empty());
    }
    assert_eq!(ResponseCode::from_code(6), None);
}

#[test]
fn records_are_refused_where_they_do_not_belong() {
    let message = query(1, "api.example.com", TYPE_A);
    let query = parsed(&message);
    let header = query.header();
    let question = Some(query.question());
    let v4 = [ip("93.184.216.34")];
    assert_eq!(
        encode_response(&header, question, ResponseCode::Refused, &v4, 60),
        Err(EncodeError::AnswersWithErrorCode {
            code: ResponseCode::Refused
        })
    );
    assert_eq!(
        encode_response(&header, None, ResponseCode::NoError, &v4, 60),
        Err(EncodeError::AnswersWithoutQuestion)
    );
    let v6 = ip("2606:2800:220:1:248:1893:25c8:1946");
    assert_eq!(
        encode_response(&header, question, ResponseCode::NoError, &[v4[0], v6], 60),
        Err(EncodeError::FamilyMismatch { address: v6 })
    );
    assert_eq!(
        encode_response(
            &header,
            question,
            ResponseCode::NoError,
            &v4,
            MAX_TTL_SECONDS + 1
        ),
        Err(EncodeError::TtlTooLarge {
            ttl_seconds: MAX_TTL_SECONDS + 1
        })
    );
    assert!(encode_response(
        &header,
        question,
        ResponseCode::NoError,
        &v4,
        MAX_TTL_SECONDS
    )
    .is_ok());

    // A question of another type takes no address record.
    let mx_message = super::query(1, "api.example.com", 15);
    let mx = parse_query(&mx_message).unwrap();
    assert_eq!(
        encode_response(
            &mx.header(),
            Some(mx.question()),
            ResponseCode::NoError,
            &v4,
            60
        ),
        Err(EncodeError::QuestionTakesNoAddresses {
            type_code: 15,
            class: CLASS_IN
        })
    );
}

#[test]
fn records_fill_at_most_512_bytes() {
    // The longest question: 255 name bytes plus type and class.
    let label63: &[u8] = &[b'a'; 63];
    let label61: &[u8] = &[b'b'; 61];
    for (qtype, record_bytes, sample) in [
        (TYPE_A, 16, ip("93.184.216.34")),
        (TYPE_AAAA, 28, ip("2606:2800:220:1:248:1893:25c8:1946")),
    ] {
        for message in [
            query(1, "api.example.com", qtype),
            query_labels(1, &[label63, label63, label63, label61], qtype, CLASS_IN),
        ] {
            let query = parsed(&message);
            let capacity = answer_capacity(query.question());
            let question_len = message.len() - HEADER_BYTES;
            assert_eq!(
                capacity,
                (MAX_MESSAGE_BYTES - HEADER_BYTES - question_len) / record_bytes
            );
            let full = vec![sample; capacity];
            let response = encode_response(
                &query.header(),
                Some(query.question()),
                ResponseCode::NoError,
                &full,
                1,
            )
            .unwrap();
            assert!(response.len() <= MAX_MESSAGE_BYTES);
            assert!(response.len() + record_bytes > MAX_MESSAGE_BYTES);
            assert_eq!(decode(&response).answers.len(), capacity);
            let over = vec![sample; capacity + 1];
            assert_eq!(
                encode_response(
                    &query.header(),
                    Some(query.question()),
                    ResponseCode::NoError,
                    &over,
                    1
                ),
                Err(EncodeError::TooManyAnswers {
                    count: capacity + 1,
                    capacity
                })
            );
        }
    }
    // The longest question still leaves room for 15 A or 8 AAAA records.
    let longest = parsed(&query_labels(
        1,
        &[label63, label63, label63, label61],
        TYPE_A,
        CLASS_IN,
    ));
    assert_eq!(answer_capacity(longest.question()), 15);
}
