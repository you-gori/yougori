//! Payload fields: a flat tag-length-value list read by one linear pass with no recursion
//! and no nesting. A payload is a sequence of fields, each a one-byte tag in 1–16, a
//! two-byte big-endian length and that many value bytes. Every operation names its closed
//! field schema; a tag outside it, a repeated tag, a missing required tag, a value of the
//! wrong length or a value over its bound is refused with its typed reason (VM-P28
//! "recursion, duplicate fields"; VM-R58 line 2924 "typed bounded parsing").

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::foundation::ids::{validate_identifier, Digest, IdError};

/// The highest field tag; tags are 1 to this value.
pub const MAX_FIELD_TAG: u8 = 16;
/// Tag and length bytes of one field.
pub const FIELD_OVERHEAD_BYTES: usize = 3;
/// The longest text field, in bytes.
pub const MAX_TEXT_BYTES: usize = 256;
/// The longest value one field can carry (the length is two bytes).
pub const MAX_FIELD_VALUE_BYTES: usize = u16::MAX as usize;

/// Why a payload was refused by the field reader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "field_refusal", rename_all = "snake_case")]
pub enum FieldRefusal {
    /// Fewer than three bytes remain where a field header should start.
    TruncatedHeader {
        at_byte: usize,
    },
    /// A field declares more value bytes than remain.
    TruncatedValue {
        tag: u8,
        declared_bytes: usize,
        remaining_bytes: usize,
    },
    /// The tag is outside 1–16 or outside the operation's schema.
    UnknownField {
        tag: u8,
    },
    DuplicateField {
        tag: u8,
    },
    MissingField {
        tag: u8,
    },
    WrongLength {
        tag: u8,
        expected_bytes: usize,
        found_bytes: usize,
    },
    TooLong {
        tag: u8,
        max_bytes: usize,
        found_bytes: usize,
    },
    /// Not UTF-8, or it contains a control character.
    NotText {
        tag: u8,
    },
    /// Not an identifier of the shared ids.rs grammar: a path, a URL or free text.
    NotName {
        tag: u8,
        error: String,
    },
    /// A code outside its closed enumeration.
    InvalidValue {
        tag: u8,
        value: u64,
    },
}

impl FieldRefusal {
    /// The stable name used by the conformance corpus.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TruncatedHeader { .. } => "payload.truncated_header",
            Self::TruncatedValue { .. } => "payload.truncated_value",
            Self::UnknownField { .. } => "payload.unknown_field",
            Self::DuplicateField { .. } => "payload.duplicate_field",
            Self::MissingField { .. } => "payload.missing_field",
            Self::WrongLength { .. } => "payload.wrong_length",
            Self::TooLong { .. } => "payload.too_long",
            Self::NotText { .. } => "payload.not_text",
            Self::NotName { .. } => "payload.not_name",
            Self::InvalidValue { .. } => "payload.invalid_value",
        }
    }
}

impl fmt::Display for FieldRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { at_byte } => {
                write!(
                    f,
                    "the payload ends inside a field header at byte {at_byte}"
                )
            }
            Self::TruncatedValue {
                tag,
                declared_bytes,
                remaining_bytes,
            } => write!(
                f,
                "field {tag} declares {declared_bytes} bytes but {remaining_bytes} remain"
            ),
            Self::UnknownField { tag } => write!(f, "field {tag} is not part of the operation"),
            Self::DuplicateField { tag } => write!(f, "field {tag} appears twice"),
            Self::MissingField { tag } => write!(f, "required field {tag} is missing"),
            Self::WrongLength {
                tag,
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "field {tag} is {found_bytes} bytes, expected {expected_bytes}"
            ),
            Self::TooLong {
                tag,
                max_bytes,
                found_bytes,
            } => write!(
                f,
                "field {tag} is {found_bytes} bytes, more than {max_bytes}"
            ),
            Self::NotText { tag } => write!(f, "field {tag} is not plain text"),
            Self::NotName { tag, error } => write!(f, "field {tag} is not a name: {error}"),
            Self::InvalidValue { tag, value } => {
                write!(f, "field {tag} holds {value}, outside its enumeration")
            }
        }
    }
}

impl std::error::Error for FieldRefusal {}

/// Why a payload could not be encoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "encode_refusal", rename_all = "snake_case")]
pub enum EncodeRefusal {
    ValueTooLong {
        tag: u8,
        found_bytes: usize,
        max_bytes: usize,
    },
}

impl fmt::Display for EncodeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLong {
                tag,
                found_bytes,
                max_bytes,
            } => write!(
                f,
                "field {tag} is {found_bytes} bytes, more than the {max_bytes} a field holds"
            ),
        }
    }
}

impl std::error::Error for EncodeRefusal {}

/// A name carried on the link: the shared ids.rs identifier grammar narrowed to names
/// that start with a letter and contain no `:`, so it can never be a path (no separators,
/// never `..`), a URL, an address literal, a host:port or free text (§2.6 line 2004). A
/// name is resolved by the host's own contracts; it selects nothing by itself.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct LinkName(String);

impl LinkName {
    /// Accepts 1–128 letters, digits, '.', '_' or '-', starting with a letter.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        if let Some(colon) = value.chars().find(|character| *character == ':') {
            return Err(IdError::InvalidCharacter { character: colon });
        }
        if !value
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
        {
            return Err(IdError::InvalidStart);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LinkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkName({})", self.0)
    }
}

impl fmt::Display for LinkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LinkName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One entry of an operation's field schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSpec {
    pub tag: u8,
    pub required: bool,
}

impl FieldSpec {
    pub const fn required(tag: u8) -> Self {
        Self {
            tag,
            required: true,
        }
    }

    pub const fn optional(tag: u8) -> Self {
        Self {
            tag,
            required: false,
        }
    }
}

/// Writes a payload field by field.
#[derive(Clone, Debug, Default)]
pub struct FieldWriter {
    bytes: Vec<u8>,
}

impl FieldWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(self, tag: u8, value: u8) -> Self {
        self.fixed(tag, &[value])
    }

    pub fn u16(self, tag: u8, value: u16) -> Self {
        self.fixed(tag, &value.to_be_bytes())
    }

    pub fn u32(self, tag: u8, value: u32) -> Self {
        self.fixed(tag, &value.to_be_bytes())
    }

    pub fn u64(self, tag: u8, value: u64) -> Self {
        self.fixed(tag, &value.to_be_bytes())
    }

    pub fn i32(self, tag: u8, value: i32) -> Self {
        self.fixed(tag, &value.to_be_bytes())
    }

    pub fn digest(self, tag: u8, value: &Digest) -> Self {
        self.fixed(tag, value.as_bytes())
    }

    /// A variable-length value; refused above [`MAX_FIELD_VALUE_BYTES`].
    pub fn bytes(mut self, tag: u8, value: &[u8]) -> Result<Self, EncodeRefusal> {
        if value.len() > MAX_FIELD_VALUE_BYTES {
            return Err(EncodeRefusal::ValueTooLong {
                tag,
                found_bytes: value.len(),
                max_bytes: MAX_FIELD_VALUE_BYTES,
            });
        }
        self.push(tag, value);
        Ok(self)
    }

    pub fn text(self, tag: u8, value: &str) -> Result<Self, EncodeRefusal> {
        self.bytes(tag, value.as_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn fixed(mut self, tag: u8, value: &[u8]) -> Self {
        self.push(tag, value);
        self
    }

    fn push(&mut self, tag: u8, value: &[u8]) {
        let length = u16::try_from(value.len()).unwrap_or(u16::MAX);
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
    }
}

/// The fields of one payload, read against a schema. Borrows the payload; holds at most
/// one slice per tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields<'a> {
    values: [Option<&'a [u8]>; MAX_FIELD_TAG as usize],
}

impl<'a> Fields<'a> {
    /// One linear pass over `payload`. Refuses, in the order met, a truncated field
    /// header or value, a tag outside the schema, a repeated tag, and finally any required
    /// tag that is absent.
    pub fn parse(payload: &'a [u8], schema: &[FieldSpec]) -> Result<Self, FieldRefusal> {
        let mut values: [Option<&'a [u8]>; MAX_FIELD_TAG as usize] = [None; MAX_FIELD_TAG as usize];
        let mut cursor = 0usize;
        while cursor < payload.len() {
            let header = payload
                .get(cursor..cursor + FIELD_OVERHEAD_BYTES)
                .ok_or(FieldRefusal::TruncatedHeader { at_byte: cursor })?;
            let tag = header[0];
            let declared_bytes = usize::from(u16::from_be_bytes([header[1], header[2]]));
            cursor += FIELD_OVERHEAD_BYTES;
            let remaining_bytes = payload.len() - cursor;
            let value = payload.get(cursor..cursor + declared_bytes).ok_or(
                FieldRefusal::TruncatedValue {
                    tag,
                    declared_bytes,
                    remaining_bytes,
                },
            )?;
            cursor += declared_bytes;
            if tag == 0 || tag > MAX_FIELD_TAG || !schema.iter().any(|spec| spec.tag == tag) {
                return Err(FieldRefusal::UnknownField { tag });
            }
            let slot = &mut values[usize::from(tag - 1)];
            if slot.is_some() {
                return Err(FieldRefusal::DuplicateField { tag });
            }
            *slot = Some(value);
        }
        for spec in schema {
            if spec.required && spec.tag >= 1 && spec.tag <= MAX_FIELD_TAG {
                if values[usize::from(spec.tag - 1)].is_none() {
                    return Err(FieldRefusal::MissingField { tag: spec.tag });
                }
            }
        }
        Ok(Self { values })
    }

    fn raw(&self, tag: u8) -> Option<&'a [u8]> {
        if tag == 0 || tag > MAX_FIELD_TAG {
            return None;
        }
        self.values[usize::from(tag - 1)]
    }

    fn present(&self, tag: u8) -> Result<&'a [u8], FieldRefusal> {
        self.raw(tag).ok_or(FieldRefusal::MissingField { tag })
    }

    fn fixed<const N: usize>(&self, tag: u8) -> Result<[u8; N], FieldRefusal> {
        let value = self.present(tag)?;
        <[u8; N]>::try_from(value).map_err(|_| FieldRefusal::WrongLength {
            tag,
            expected_bytes: N,
            found_bytes: value.len(),
        })
    }

    pub fn u8(&self, tag: u8) -> Result<u8, FieldRefusal> {
        self.fixed::<1>(tag).map(|bytes| bytes[0])
    }

    pub fn u16(&self, tag: u8) -> Result<u16, FieldRefusal> {
        self.fixed::<2>(tag).map(u16::from_be_bytes)
    }

    pub fn u32(&self, tag: u8) -> Result<u32, FieldRefusal> {
        self.fixed::<4>(tag).map(u32::from_be_bytes)
    }

    pub fn u64(&self, tag: u8) -> Result<u64, FieldRefusal> {
        self.fixed::<8>(tag).map(u64::from_be_bytes)
    }

    pub fn i32(&self, tag: u8) -> Result<i32, FieldRefusal> {
        self.fixed::<4>(tag).map(i32::from_be_bytes)
    }

    pub fn digest(&self, tag: u8) -> Result<Digest, FieldRefusal> {
        self.fixed::<32>(tag).map(Digest::from_bytes)
    }

    pub fn optional_u64(&self, tag: u8) -> Result<Option<u64>, FieldRefusal> {
        match self.raw(tag) {
            None => Ok(None),
            Some(_) => self.u64(tag).map(Some),
        }
    }

    pub fn optional_u8(&self, tag: u8) -> Result<Option<u8>, FieldRefusal> {
        match self.raw(tag) {
            None => Ok(None),
            Some(_) => self.u8(tag).map(Some),
        }
    }

    pub fn optional_digest(&self, tag: u8) -> Result<Option<Digest>, FieldRefusal> {
        match self.raw(tag) {
            None => Ok(None),
            Some(_) => self.digest(tag).map(Some),
        }
    }

    /// Opaque bytes, at most `max_bytes` long.
    pub fn bytes(&self, tag: u8, max_bytes: usize) -> Result<&'a [u8], FieldRefusal> {
        let value = self.present(tag)?;
        if value.len() > max_bytes {
            return Err(FieldRefusal::TooLong {
                tag,
                max_bytes,
                found_bytes: value.len(),
            });
        }
        Ok(value)
    }

    /// UTF-8 text without control characters, at most `max_bytes` long.
    pub fn text(&self, tag: u8, max_bytes: usize) -> Result<String, FieldRefusal> {
        let value = self.bytes(tag, max_bytes)?;
        let text = std::str::from_utf8(value).map_err(|_| FieldRefusal::NotText { tag })?;
        if text.chars().any(char::is_control) {
            return Err(FieldRefusal::NotText { tag });
        }
        Ok(text.to_owned())
    }

    /// A [`LinkName`].
    pub fn name(&self, tag: u8) -> Result<LinkName, FieldRefusal> {
        let text = self.text(tag, MAX_TEXT_BYTES)?;
        LinkName::new(text).map_err(|error| FieldRefusal::NotName {
            tag,
            error: error.to_string(),
        })
    }

    /// A code of a closed enumeration, resolved by `from_code`.
    pub fn code<T>(&self, tag: u8, from_code: fn(u8) -> Option<T>) -> Result<T, FieldRefusal> {
        let value = self.u8(tag)?;
        from_code(value).ok_or(FieldRefusal::InvalidValue {
            tag,
            value: u64::from(value),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: [FieldSpec; 3] = [
        FieldSpec::required(1),
        FieldSpec::optional(2),
        FieldSpec::required(3),
    ];

    #[test]
    fn fields_round_trip_in_one_pass() {
        let payload = FieldWriter::new()
            .u64(1, 7)
            .text(2, "hello")
            .unwrap()
            .u8(3, 9)
            .finish();
        let fields = Fields::parse(&payload, &SCHEMA).unwrap();
        assert_eq!(fields.u64(1), Ok(7));
        assert_eq!(fields.text(2, 16), Ok("hello".to_owned()));
        assert_eq!(fields.u8(3), Ok(9));
        assert_eq!(fields.optional_u64(4), Ok(None));
    }

    #[test]
    fn every_malformation_has_its_own_refusal() {
        let good = FieldWriter::new().u64(1, 1).u8(3, 2).finish();
        assert!(Fields::parse(&good, &SCHEMA).is_ok());

        let mut duplicate = good.clone();
        duplicate.extend_from_slice(&FieldWriter::new().u64(1, 1).finish());
        assert_eq!(
            Fields::parse(&duplicate, &SCHEMA),
            Err(FieldRefusal::DuplicateField { tag: 1 })
        );

        let mut unknown = good.clone();
        unknown.extend_from_slice(&FieldWriter::new().u8(9, 1).finish());
        assert_eq!(
            Fields::parse(&unknown, &SCHEMA),
            Err(FieldRefusal::UnknownField { tag: 9 })
        );
        let zero_tag = [0u8, 0, 0];
        assert_eq!(
            Fields::parse(&zero_tag, &SCHEMA),
            Err(FieldRefusal::UnknownField { tag: 0 })
        );
        let high_tag = [17u8, 0, 0];
        assert_eq!(
            Fields::parse(&high_tag, &SCHEMA),
            Err(FieldRefusal::UnknownField { tag: 17 })
        );

        let missing = FieldWriter::new().u64(1, 1).finish();
        assert_eq!(
            Fields::parse(&missing, &SCHEMA),
            Err(FieldRefusal::MissingField { tag: 3 })
        );

        let truncated_header = [1u8, 0];
        assert_eq!(
            Fields::parse(&truncated_header, &SCHEMA),
            Err(FieldRefusal::TruncatedHeader { at_byte: 0 })
        );
        let truncated_value = [1u8, 0, 8, 1, 2, 3];
        assert_eq!(
            Fields::parse(&truncated_value, &SCHEMA),
            Err(FieldRefusal::TruncatedValue {
                tag: 1,
                declared_bytes: 8,
                remaining_bytes: 3
            })
        );

        let fields = Fields::parse(&good, &SCHEMA).unwrap();
        assert_eq!(
            fields.u32(1),
            Err(FieldRefusal::WrongLength {
                tag: 1,
                expected_bytes: 4,
                found_bytes: 8
            })
        );
        assert_eq!(
            fields.bytes(1, 4),
            Err(FieldRefusal::TooLong {
                tag: 1,
                max_bytes: 4,
                found_bytes: 8
            })
        );
        assert_eq!(fields.u8(2), Err(FieldRefusal::MissingField { tag: 2 }));
        assert_eq!(
            fields.code(3, |_| None::<u8>),
            Err(FieldRefusal::InvalidValue { tag: 3, value: 2 })
        );
    }

    #[test]
    fn text_and_names_are_checked() {
        let payload = FieldWriter::new()
            .bytes(1, &[0xff, 0xfe])
            .unwrap()
            .text(2, "tab\there")
            .unwrap()
            .text(3, "../etc")
            .unwrap()
            .finish();
        let fields = Fields::parse(&payload, &SCHEMA).unwrap();
        assert_eq!(fields.text(1, 16), Err(FieldRefusal::NotText { tag: 1 }));
        assert_eq!(fields.text(2, 16), Err(FieldRefusal::NotText { tag: 2 }));
        assert!(matches!(
            fields.name(3),
            Err(FieldRefusal::NotName { tag: 3, .. })
        ));
        assert!(LinkName::new("a/b").is_err());
        assert!(LinkName::new("..").is_err());
        assert!(LinkName::new("http://x").is_err());
        assert_eq!(
            LinkName::new("10.0.0.1:22"),
            Err(IdError::InvalidCharacter { character: ':' })
        );
        assert_eq!(LinkName::new("169.254.169.254"), Err(IdError::InvalidStart));
        assert_eq!(
            LinkName::new("host:22"),
            Err(IdError::InvalidCharacter { character: ':' })
        );
        assert_eq!(LinkName::new("_x"), Err(IdError::InvalidStart));
        assert_eq!(LinkName::new("dest-1").unwrap().as_str(), "dest-1");
        assert_eq!(
            LinkName::new("api.primary_v2").unwrap().as_str(),
            "api.primary_v2"
        );
        assert!(serde_json::from_str::<LinkName>("\"a b\"").is_err());
    }

    #[test]
    fn a_nested_payload_is_not_descended_into() {
        let inner = FieldWriter::new().u64(1, 1).u8(3, 2).finish();
        let mut nested = inner.clone();
        for _ in 0..1000 {
            nested = FieldWriter::new().bytes(2, &nested).unwrap().finish();
        }
        assert_eq!(
            Fields::parse(&nested, &SCHEMA),
            Err(FieldRefusal::MissingField { tag: 1 })
        );
        let mut writer = FieldWriter::new();
        for _ in 0..3 {
            writer = writer.u8(2, 1);
        }
        assert_eq!(
            Fields::parse(&writer.finish(), &SCHEMA),
            Err(FieldRefusal::DuplicateField { tag: 2 })
        );
    }

    #[test]
    fn the_writer_refuses_a_value_longer_than_a_field() {
        let long = vec![0u8; MAX_FIELD_VALUE_BYTES + 1];
        assert_eq!(
            FieldWriter::new().bytes(1, &long).err(),
            Some(EncodeRefusal::ValueTooLong {
                tag: 1,
                found_bytes: MAX_FIELD_VALUE_BYTES + 1,
                max_bytes: MAX_FIELD_VALUE_BYTES
            })
        );
    }
}
