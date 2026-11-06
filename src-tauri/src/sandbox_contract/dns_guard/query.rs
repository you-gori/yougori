//! The strict parser for the one DNS message a guest stub resolver sends (RFC 1035 §4.1;
//! VM-W08; VM §4.2 step 2: malformed names are rejected, never guessed).
//!
//! The accepted subset is what a stub sends over UDP and nothing more: one message of at
//! most [`MAX_MESSAGE_BYTES`], the standard query opcode, no AA, TC, RA or Z bit and a zero
//! RCODE (RD, AD and CD may be set), exactly one question, no answer, authority or
//! additional record, an uncompressed question name within [`MAX_WIRE_NAME_BYTES`] and
//! class IN. Every other message is refused with a [`QueryProblem`]; nothing is repaired
//! or skipped. The question type is not judged here: every type is mapped to V02's
//! [`GuestQueryType`] and V11's `HostNetwork::guest_dns` decides which it serves.
//!
//! EDNS is refused: a query carrying an OPT record gets FORMERR, which RFC 6891 §7 defines
//! as the answer of a responder without EDNS, and the requester retries without OPT. Not
//! implementing OPT keeps the response format fixed and every response within 512 bytes.

use std::fmt;

use super::response::ResponseCode;
use crate::sandbox_contract::destinations::{AddressFamily, GuestQueryType, NameError};

/// The largest message accepted or sent: the UDP limit without EDNS (RFC 1035 §2.3.4).
pub const MAX_MESSAGE_BYTES: usize = 512;

/// The size of the fixed DNS header (RFC 1035 §4.1.1).
pub const HEADER_BYTES: usize = 12;

/// The longest question name in wire form, length bytes and the root byte included
/// (RFC 1035 §2.3.4).
pub const MAX_WIRE_NAME_BYTES: usize = 255;

/// The class Internet, the only class answered.
pub const CLASS_IN: u16 = 1;

/// The type code of an A (IPv4 address) question.
pub const TYPE_A: u16 = 1;

/// The type code of an AAAA (IPv6 address) question (RFC 3596).
pub const TYPE_AAAA: u16 = 28;

/// The standard query opcode, the only one answered.
const OPCODE_QUERY: u8 = 0;

// Header bits in the third byte of the message.
const QR: u8 = 0x80;
const AA: u8 = 0x04;
const TC: u8 = 0x02;
const RD: u8 = 0x01;
// Header bits in the fourth byte of the message.
const RA: u8 = 0x80;
const Z: u8 = 0x40;
const CD: u8 = 0x10;
const RCODE: u8 = 0x0F;

/// The two top bits of a label length byte: `00` is a label, `11` a compression pointer,
/// `01` and `10` are reserved (RFC 1035 §4.1.4; RFC 6891 §5 deprecated their one use).
const LABEL_TYPE_BITS: u8 = 0xC0;
const COMPRESSION_POINTER: u8 = 0xC0;

/// Why the parser refused a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryProblem {
    /// Fewer than the 12 header bytes, so there is no transaction id to answer.
    TooShort { bytes: usize },
    /// The QR bit is set: the message is a response, which is never answered.
    NotAQuery,
    /// More than [`MAX_MESSAGE_BYTES`].
    TooLong { bytes: usize },
    /// An opcode other than the standard query, such as IQUERY, STATUS, NOTIFY or UPDATE.
    UnsupportedOpcode { opcode: u8 },
    /// A header bit or code no stub query carries: AA, TC, RA, Z or a nonzero RCODE. The
    /// value is the 16-bit flags field as received.
    UnexpectedHeaderBits { flags: u16 },
    /// Not exactly one question.
    QuestionCount { count: u16 },
    /// Answer or authority records in a query.
    UnexpectedRecords { answers: u16, authorities: u16 },
    /// Additional records, an EDNS OPT record included: EDNS is not implemented.
    AdditionalRecords { count: u16 },
    /// The question name uses a compression pointer.
    CompressedName,
    /// A label length byte with the reserved label type bits `01` or `10`; a label
    /// longer than 63 bytes cannot be written any other way.
    ReservedLabelType { byte: u8 },
    /// The question name exceeds [`MAX_WIRE_NAME_BYTES`] in wire form.
    NameTooLong { bytes: usize },
    /// The message ends inside the question.
    TruncatedQuestion,
    /// Bytes follow the question.
    TrailingBytes { bytes: usize },
    /// A class other than IN; V11's DNS decision has no class, so only IN reaches it.
    UnsupportedClass { class: u16 },
}

impl QueryProblem {
    /// The response code the guard answers with, or `None` when nothing is sent: a message
    /// without a full header has no id to answer, and a response is never answered, so two
    /// resolvers cannot loop. Malformed queries get FORMERR; a well-formed query of an
    /// opcode or class the guard does not implement gets NOTIMP, as V11 answers a type it
    /// does not serve.
    pub const fn response_code(&self) -> Option<ResponseCode> {
        match self {
            Self::TooShort { .. } | Self::NotAQuery => None,
            Self::UnsupportedOpcode { .. } | Self::UnsupportedClass { .. } => {
                Some(ResponseCode::NotImp)
            }
            Self::TooLong { .. }
            | Self::UnexpectedHeaderBits { .. }
            | Self::QuestionCount { .. }
            | Self::UnexpectedRecords { .. }
            | Self::AdditionalRecords { .. }
            | Self::CompressedName
            | Self::ReservedLabelType { .. }
            | Self::NameTooLong { .. }
            | Self::TruncatedQuestion
            | Self::TrailingBytes { .. } => Some(ResponseCode::FormErr),
        }
    }
}

impl fmt::Display for QueryProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { bytes } => write!(
                f,
                "the message is {bytes} bytes long, shorter than the {HEADER_BYTES}-byte header"
            ),
            Self::NotAQuery => f.write_str("the message is a response, not a query"),
            Self::TooLong { bytes } => write!(
                f,
                "the message is {bytes} bytes long; at most {MAX_MESSAGE_BYTES} are accepted"
            ),
            Self::UnsupportedOpcode { opcode } => {
                write!(f, "opcode {opcode} is not a standard query")
            }
            Self::UnexpectedHeaderBits { flags } => write!(
                f,
                "the header flags {flags:#06x} carry AA, TC, RA, Z or a response code"
            ),
            Self::QuestionCount { count } => {
                write!(
                    f,
                    "the query has {count} questions; exactly one is accepted"
                )
            }
            Self::UnexpectedRecords {
                answers,
                authorities,
            } => write!(
                f,
                "the query carries {answers} answer and {authorities} authority records"
            ),
            Self::AdditionalRecords { count } => write!(
                f,
                "the query carries {count} additional records; EDNS is not implemented"
            ),
            Self::CompressedName => f.write_str("the question name is compressed"),
            Self::ReservedLabelType { byte } => {
                write!(
                    f,
                    "the label length byte {byte:#04x} has reserved type bits"
                )
            }
            Self::NameTooLong { bytes } => write!(
                f,
                "the question name needs at least {bytes} bytes; at most \
                 {MAX_WIRE_NAME_BYTES} are allowed"
            ),
            Self::TruncatedQuestion => f.write_str("the message ends inside the question"),
            Self::TrailingBytes { bytes } => {
                write!(f, "{bytes} bytes follow the question")
            }
            Self::UnsupportedClass { class } => {
                write!(f, "class {class} is not answered; only IN is")
            }
        }
    }
}

impl std::error::Error for QueryProblem {}

/// The header fields of a query that a response keeps: the transaction id, the opcode, and
/// the RD and CD bits, which RFC 1035 §4.1.1 and RFC 4035 §3.2.2 copy into the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QueryHeader {
    id: u16,
    opcode: u8,
    recursion_desired: bool,
    checking_disabled: bool,
}

impl QueryHeader {
    /// The transaction id.
    pub const fn id(self) -> u16 {
        self.id
    }

    /// The four-bit opcode.
    pub const fn opcode(self) -> u8 {
        self.opcode
    }

    /// The RD bit.
    pub const fn recursion_desired(self) -> bool {
        self.recursion_desired
    }

    /// The CD bit.
    pub const fn checking_disabled(self) -> bool {
        self.checking_disabled
    }
}

/// One question exactly as received: its wire bytes, its labels, type and class.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    wire: Vec<u8>,
    labels: Vec<Vec<u8>>,
    type_code: u16,
    class: u16,
}

impl Question {
    /// The question's bytes as received (QNAME, QTYPE and QCLASS), letter case included, so
    /// a response echoes it exactly: resolvers match the echoed question against their
    /// query, and those that randomize letter case compare it byte for byte.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// The labels from left to right, as received.
    pub fn labels(&self) -> impl Iterator<Item = &[u8]> {
        self.labels.iter().map(Vec::as_slice)
    }

    /// The type code as received.
    pub const fn type_code(&self) -> u16 {
        self.type_code
    }

    /// The type under V02's guest query types.
    pub const fn query_type(&self) -> GuestQueryType {
        query_type(self.type_code)
    }

    /// The class code as received.
    pub const fn class(&self) -> u16 {
        self.class
    }

    /// The address family asked for: A is IPv4, AAAA is IPv6; `None` for every other type
    /// or a class other than IN.
    pub const fn family(&self) -> Option<AddressFamily> {
        if self.class != CLASS_IN {
            return None;
        }
        match self.type_code {
            TYPE_A => Some(AddressFamily::Ipv4),
            TYPE_AAAA => Some(AddressFamily::Ipv6),
            _ => None,
        }
    }

    /// The question name as text, labels joined with dots, letter case as received; the
    /// root name is the empty text.
    ///
    /// Only what the wire form adds is refused here: a label holding a dot, which joined
    /// would read as two labels (`api.example` + `com` must not become `api.example.com`),
    /// and a non-ASCII byte, which has no text form without a guess (V02 accepts
    /// internationalized names only as A-labels). Everything else, single labels, IP-literal
    /// spellings, invalid A-labels and other characters, is decided by V11 through V02's
    /// one destination parser.
    pub fn name_text(&self) -> Result<String, NameError> {
        let mut text = String::with_capacity(self.wire.len());
        for (index, label) in self.labels.iter().enumerate() {
            if index > 0 {
                text.push('.');
            }
            for &byte in label {
                if !byte.is_ascii() {
                    return Err(NameError::NonAscii);
                }
                if byte == b'.' {
                    return Err(NameError::InvalidCharacter { character: '.' });
                }
                text.push(char::from(byte));
            }
        }
        Ok(text)
    }
}

/// A query that passed the strict parser: one class IN question of any type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuestQuery {
    header: QueryHeader,
    question: Question,
}

impl GuestQuery {
    pub const fn header(&self) -> QueryHeader {
        self.header
    }

    pub fn question(&self) -> &Question {
        &self.question
    }
}

/// A refused message, with what a response may echo: the header when the message had one,
/// and the question when it parsed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QueryRefusal {
    problem: QueryProblem,
    header: Option<QueryHeader>,
    question: Option<Question>,
}

impl QueryRefusal {
    pub const fn problem(&self) -> QueryProblem {
        self.problem
    }

    /// The header, absent when the message was too short to hold one.
    pub const fn header(&self) -> Option<QueryHeader> {
        self.header
    }

    /// The question, present only when it parsed completely.
    pub fn question(&self) -> Option<&Question> {
        self.question.as_ref()
    }
}

impl fmt::Display for QueryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.problem, f)
    }
}

impl std::error::Error for QueryRefusal {}

/// Parses one guest DNS message under the strict subset of this module. It never panics:
/// every read is bounds-checked and every refusal is a [`QueryRefusal`].
pub fn parse_query(message: &[u8]) -> Result<GuestQuery, QueryRefusal> {
    let refuse = |problem, header, question| QueryRefusal {
        problem,
        header,
        question,
    };
    let Some(fixed) = message
        .get(..HEADER_BYTES)
        .and_then(|bytes| <[u8; HEADER_BYTES]>::try_from(bytes).ok())
    else {
        return Err(refuse(
            QueryProblem::TooShort {
                bytes: message.len(),
            },
            None,
            None,
        ));
    };
    let header = QueryHeader {
        id: u16::from_be_bytes([fixed[0], fixed[1]]),
        opcode: (fixed[2] >> 3) & 0x0F,
        recursion_desired: fixed[2] & RD != 0,
        checking_disabled: fixed[3] & CD != 0,
    };
    if fixed[2] & QR != 0 {
        return Err(refuse(QueryProblem::NotAQuery, Some(header), None));
    }
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(refuse(
            QueryProblem::TooLong {
                bytes: message.len(),
            },
            Some(header),
            None,
        ));
    }
    if header.opcode != OPCODE_QUERY {
        return Err(refuse(
            QueryProblem::UnsupportedOpcode {
                opcode: header.opcode,
            },
            Some(header),
            None,
        ));
    }
    if fixed[2] & (AA | TC) != 0 || fixed[3] & (RA | Z | RCODE) != 0 {
        return Err(refuse(
            QueryProblem::UnexpectedHeaderBits {
                flags: u16::from_be_bytes([fixed[2], fixed[3]]),
            },
            Some(header),
            None,
        ));
    }
    let questions = u16::from_be_bytes([fixed[4], fixed[5]]);
    let answers = u16::from_be_bytes([fixed[6], fixed[7]]);
    let authorities = u16::from_be_bytes([fixed[8], fixed[9]]);
    let additional = u16::from_be_bytes([fixed[10], fixed[11]]);
    if questions != 1 {
        return Err(refuse(
            QueryProblem::QuestionCount { count: questions },
            Some(header),
            None,
        ));
    }
    let question = match parse_question(message) {
        Ok(question) => question,
        Err(problem) => return Err(refuse(problem, Some(header), None)),
    };
    let end = HEADER_BYTES.saturating_add(question.wire.len());
    let problem = if answers != 0 || authorities != 0 {
        Some(QueryProblem::UnexpectedRecords {
            answers,
            authorities,
        })
    } else if additional != 0 {
        Some(QueryProblem::AdditionalRecords { count: additional })
    } else if message.len() > end {
        Some(QueryProblem::TrailingBytes {
            bytes: message.len().saturating_sub(end),
        })
    } else if question.class != CLASS_IN {
        Some(QueryProblem::UnsupportedClass {
            class: question.class,
        })
    } else {
        None
    };
    if let Some(problem) = problem {
        return Err(refuse(problem, Some(header), Some(question)));
    }
    Ok(GuestQuery { header, question })
}

/// Parses the question that starts right after the header.
fn parse_question(message: &[u8]) -> Result<Question, QueryProblem> {
    let mut labels = Vec::new();
    let mut offset = HEADER_BYTES;
    loop {
        let length_byte = *message.get(offset).ok_or(QueryProblem::TruncatedQuestion)?;
        match length_byte & LABEL_TYPE_BITS {
            0 => {}
            COMPRESSION_POINTER => return Err(QueryProblem::CompressedName),
            _ => return Err(QueryProblem::ReservedLabelType { byte: length_byte }),
        }
        if length_byte == 0 {
            offset = offset.saturating_add(1);
            break;
        }
        let start = offset.saturating_add(1);
        let end = start.saturating_add(usize::from(length_byte));
        // The name so far, plus the root byte that must still follow.
        let needed = end.saturating_sub(HEADER_BYTES).saturating_add(1);
        if needed > MAX_WIRE_NAME_BYTES {
            return Err(QueryProblem::NameTooLong { bytes: needed });
        }
        let label = message
            .get(start..end)
            .ok_or(QueryProblem::TruncatedQuestion)?;
        labels.push(label.to_vec());
        offset = end;
    }
    let fields_end = offset.saturating_add(4);
    let fields = message
        .get(offset..fields_end)
        .ok_or(QueryProblem::TruncatedQuestion)?;
    let (type_code, class) = match fields {
        [type_high, type_low, class_high, class_low] => (
            u16::from_be_bytes([*type_high, *type_low]),
            u16::from_be_bytes([*class_high, *class_low]),
        ),
        _ => return Err(QueryProblem::TruncatedQuestion),
    };
    let wire = message
        .get(HEADER_BYTES..fields_end)
        .ok_or(QueryProblem::TruncatedQuestion)?
        .to_vec();
    Ok(Question {
        wire,
        labels,
        type_code,
        class,
    })
}

/// Maps a type code to V02's guest query types.
const fn query_type(code: u16) -> GuestQueryType {
    match code {
        TYPE_A => GuestQueryType::A,
        TYPE_AAAA => GuestQueryType::Aaaa,
        12 => GuestQueryType::Ptr,
        15 => GuestQueryType::Mx,
        16 => GuestQueryType::Txt,
        33 => GuestQueryType::Srv,
        64 => GuestQueryType::Svcb,
        65 => GuestQueryType::Https,
        255 => GuestQueryType::Any,
        other => GuestQueryType::Other(other),
    }
}
