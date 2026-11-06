//! The strict response encoder (RFC 1035 §4.1; VM-W08).
//!
//! A response keeps the query's transaction id, opcode, RD and CD bits, echoes the question
//! byte for byte, and carries address records only for a NOERROR answer to an A or AAAA
//! question, each of the asked family. Every answer record names the question through a
//! compression pointer to it, so the answer's owner name is exactly the asked spelling.
//! Nothing else is ever written: no authority or additional section, no OPT record, no AA,
//! TC or AD bit. A response that would break one of these rules, or exceed
//! [`MAX_MESSAGE_BYTES`], is refused with an [`EncodeError`] rather than adjusted.

use std::fmt;
use std::net::IpAddr;

use super::query::{
    QueryHeader, Question, CLASS_IN, HEADER_BYTES, MAX_MESSAGE_BYTES, TYPE_A, TYPE_AAAA,
};
use crate::sandbox_contract::destinations::AddressFamily;

/// The largest TTL a record may carry (RFC 2181 §8: a TTL is an unsigned 31-bit value).
pub const MAX_TTL_SECONDS: u32 = 0x7FFF_FFFF;

/// The compression pointer to the question name, which starts right after the header.
const POINTER_TO_QUESTION: [u8; 2] = [0xC0, 0x0C];

// Header bits the guard sets in the third and fourth bytes of a response.
const QR: u8 = 0x80;
const RD: u8 = 0x01;
const RA: u8 = 0x80;
const CD: u8 = 0x10;

/// A response code the guard sends (RFC 1035 §4.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResponseCode {
    /// The question was answered; with no answer record this is NODATA.
    NoError,
    /// The query was malformed under the strict subset.
    FormErr,
    /// The name was granted but no usable answer could be produced.
    ServFail,
    /// The allowed resolver reported that a granted name does not exist.
    NxDomain,
    /// The opcode, class or type is not implemented.
    NotImp,
    /// Refused by policy.
    Refused,
}

impl ResponseCode {
    /// The four-bit RCODE value.
    pub const fn code(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
        }
    }

    /// The code for an RCODE value the guard sends, or `None` for any other value.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::NoError),
            1 => Some(Self::FormErr),
            2 => Some(Self::ServFail),
            3 => Some(Self::NxDomain),
            4 => Some(Self::NotImp),
            5 => Some(Self::Refused),
            _ => None,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
        })
    }
}

/// Why the encoder refused to build a response.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EncodeError {
    /// Address records may only go with NOERROR.
    AnswersWithErrorCode { code: ResponseCode },
    /// Address records need the question they answer.
    AnswersWithoutQuestion,
    /// The question is not a class IN A or AAAA question, so it takes no address record.
    QuestionTakesNoAddresses { type_code: u16, class: u16 },
    /// An address of the other family than the question asked for.
    FamilyMismatch { address: IpAddr },
    /// A TTL above [`MAX_TTL_SECONDS`].
    TtlTooLarge { ttl_seconds: u32 },
    /// More records than fit in [`MAX_MESSAGE_BYTES`]; see [`answer_capacity`].
    TooManyAnswers { count: usize, capacity: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnswersWithErrorCode { code } => {
                write!(f, "a {code} response cannot carry address records")
            }
            Self::AnswersWithoutQuestion => {
                f.write_str("address records need the question they answer")
            }
            Self::QuestionTakesNoAddresses { type_code, class } => write!(
                f,
                "a question of type {type_code} and class {class} takes no address record"
            ),
            Self::FamilyMismatch { address } => {
                write!(f, "{address} is not of the family the question asked for")
            }
            Self::TtlTooLarge { ttl_seconds } => write!(
                f,
                "a TTL of {ttl_seconds} seconds exceeds the largest allowed, {MAX_TTL_SECONDS}"
            ),
            Self::TooManyAnswers { count, capacity } => write!(
                f,
                "{count} records do not fit in {MAX_MESSAGE_BYTES} bytes; at most {capacity} do"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

/// The size of one answer record of `family`: the name pointer, type, class, TTL, data
/// length and the address.
const fn record_bytes(family: AddressFamily) -> usize {
    match family {
        AddressFamily::Ipv4 => 2 + 2 + 2 + 4 + 2 + 4,
        AddressFamily::Ipv6 => 2 + 2 + 2 + 4 + 2 + 16,
    }
}

/// How many address records answering `question` fit in one response of at most
/// [`MAX_MESSAGE_BYTES`]; zero for a question that takes no address record.
pub fn answer_capacity(question: &Question) -> usize {
    match question.family() {
        Some(family) => {
            MAX_MESSAGE_BYTES
                .saturating_sub(HEADER_BYTES)
                .saturating_sub(question.wire().len())
                / record_bytes(family)
        }
        None => 0,
    }
}

/// Encodes a response to the query whose header is `header`.
///
/// `question` is echoed byte for byte when given; without it the response has no
/// question section (a query whose question did not parse). `answers` become A or AAAA
/// records with `ttl_seconds`, and are refused unless the code is NOERROR, the question is
/// a class IN A or AAAA question, every address is of its family, the TTL is at most
/// [`MAX_TTL_SECONDS`] and the records fit (see [`answer_capacity`]).
pub fn encode_response(
    header: &QueryHeader,
    question: Option<&Question>,
    code: ResponseCode,
    answers: &[IpAddr],
    ttl_seconds: u32,
) -> Result<Vec<u8>, EncodeError> {
    let mut records = Vec::new();
    if !answers.is_empty() {
        if code != ResponseCode::NoError {
            return Err(EncodeError::AnswersWithErrorCode { code });
        }
        let question = question.ok_or(EncodeError::AnswersWithoutQuestion)?;
        let family = question
            .family()
            .ok_or(EncodeError::QuestionTakesNoAddresses {
                type_code: question.type_code(),
                class: question.class(),
            })?;
        if ttl_seconds > MAX_TTL_SECONDS {
            return Err(EncodeError::TtlTooLarge { ttl_seconds });
        }
        let capacity = answer_capacity(question);
        if answers.len() > capacity {
            return Err(EncodeError::TooManyAnswers {
                count: answers.len(),
                capacity,
            });
        }
        for address in answers {
            records.extend_from_slice(&POINTER_TO_QUESTION);
            match (family, address) {
                (AddressFamily::Ipv4, IpAddr::V4(ipv4)) => {
                    records.extend_from_slice(&TYPE_A.to_be_bytes());
                    records.extend_from_slice(&CLASS_IN.to_be_bytes());
                    records.extend_from_slice(&ttl_seconds.to_be_bytes());
                    records.extend_from_slice(&4u16.to_be_bytes());
                    records.extend_from_slice(&ipv4.octets());
                }
                (AddressFamily::Ipv6, IpAddr::V6(ipv6)) => {
                    records.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                    records.extend_from_slice(&CLASS_IN.to_be_bytes());
                    records.extend_from_slice(&ttl_seconds.to_be_bytes());
                    records.extend_from_slice(&16u16.to_be_bytes());
                    records.extend_from_slice(&ipv6.octets());
                }
                _ => return Err(EncodeError::FamilyMismatch { address: *address }),
            }
        }
    }
    let answer_count = u16::try_from(answers.len()).map_err(|_| EncodeError::TooManyAnswers {
        count: answers.len(),
        capacity: question.map_or(0, answer_capacity),
    })?;
    let question_count: u16 = if question.is_some() { 1 } else { 0 };
    let question_wire = question.map_or(&[][..], Question::wire);
    let mut message = Vec::with_capacity(
        HEADER_BYTES
            .saturating_add(question_wire.len())
            .saturating_add(records.len()),
    );
    message.extend_from_slice(&header.id().to_be_bytes());
    let recursion = if header.recursion_desired() { RD } else { 0 };
    message.push(QR | ((header.opcode() & 0x0F) << 3) | recursion);
    let checking = if header.checking_disabled() { CD } else { 0 };
    message.push(RA | checking | code.code());
    message.extend_from_slice(&question_count.to_be_bytes());
    message.extend_from_slice(&answer_count.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(question_wire);
    message.extend_from_slice(&records);
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(EncodeError::TooManyAnswers {
            count: answers.len(),
            capacity: question.map_or(0, answer_capacity),
        });
    }
    Ok(message)
}
