//! Canonical parameter values (VM part §9.2 line 2344: "normalized parameters"; VM-P30:
//! canonical equivalents keep the digest, everything else changes it; VM-P28: duplicate
//! fields and malformed input stay bounded).
//!
//! Raw input is read strictly: a JSON object whose duplicate keys, floating-point numbers,
//! nulls and integers outside `i64` are refused rather than silently resolved, because two
//! readers that resolve them differently would approve one request and send another. An
//! operation contract then normalizes the raw values into [`Parameters`]: named
//! parameters are a sorted map, and a list whose order the contract declares meaningless
//! becomes a sorted set, so reordering either keeps the digest. Text is compared byte for
//! byte; no Unicode normalization is applied, so two spellings of one string are two
//! values and an approval of one never covers the other.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::foundation::ids::{Digest, DigestBuilder};

effect_name!(
    /// The name of one operation parameter, fixed by its operation contract.
    ParamName
);

/// Deepest nesting a raw parameter object may have, counting the top-level object.
pub const MAX_RAW_DEPTH: usize = 4;

/// A normalized parameter value (§9.2 line 2344).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalValue {
    Text(String),
    Integer(i64),
    Bool(bool),
    Digest(Digest),
    /// A list whose order carries meaning.
    List(Vec<CanonicalValue>),
    /// A list whose order carries no meaning, kept sorted.
    Set(BTreeSet<CanonicalValue>),
}

impl CanonicalValue {
    /// Writes the value into a digest with a type tag and, for collections, an item
    /// count, so no two values share an encoding.
    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::Text(text) => builder.str("text").str(text),
            Self::Integer(value) => builder.str("integer").bytes(&value.to_be_bytes()),
            Self::Bool(value) => builder.str("bool").bytes(&[u8::from(*value)]),
            Self::Digest(digest) => builder.str("digest").digest(digest),
            Self::List(items) => items
                .iter()
                .fold(builder.str("list").u64(len_u64(items.len())), |b, item| {
                    item.feed(b)
                }),
            Self::Set(items) => items
                .iter()
                .fold(builder.str("set").u64(len_u64(items.len())), |b, item| {
                    item.feed(b)
                }),
        }
    }
}

/// Normalized named parameters; the map order is the canonical order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Parameters(BTreeMap<ParamName, CanonicalValue>);

impl Parameters {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Sets `name`; insertion order never matters.
    pub fn with(mut self, name: ParamName, value: CanonicalValue) -> Self {
        self.0.insert(name, value);
        self
    }

    pub fn get(&self, name: &ParamName) -> Option<&CanonicalValue> {
        self.0.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ParamName, &CanonicalValue)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        self.0.iter().fold(
            builder.str("parameters").u64(len_u64(self.0.len())),
            |b, (name, value)| value.feed(b.str(name.as_str())),
        )
    }

    /// The bytes the parameters take in a request body: their canonical JSON.
    pub(super) fn encoded_bytes(&self) -> u64 {
        serde_json::to_vec(&self.0).map_or(u64::MAX, |bytes| len_u64(bytes.len()))
    }
}

/// A raw parameter value as read from a request, before its contract normalizes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawValue {
    Text(String),
    Integer(i64),
    Bool(bool),
    List(Vec<RawValue>),
    Map(BTreeMap<String, RawValue>),
}

impl RawValue {
    fn depth(&self) -> usize {
        match self {
            Self::Text(_) | Self::Integer(_) | Self::Bool(_) => 0,
            Self::List(items) => 1 + items.iter().map(Self::depth).max().unwrap_or(0),
            Self::Map(entries) => 1 + entries.values().map(Self::depth).max().unwrap_or(0),
        }
    }
}

/// Raw named parameters, as a guest or tool supplied them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawParameters(BTreeMap<String, RawValue>);

impl RawParameters {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn with(mut self, name: &str, value: RawValue) -> Self {
        self.0.insert(name.to_owned(), value);
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &RawValue)> {
        self.0.iter()
    }

    /// Reads a JSON object strictly: duplicate keys, floating-point numbers, nulls,
    /// integers outside `i64` and nesting deeper than [`MAX_RAW_DEPTH`] are refused.
    pub fn from_json(text: &str) -> Result<Self, CanonicalError> {
        let node: JsonNode = serde_json::from_str(text).map_err(|error| CanonicalError::Json {
            message: error.to_string(),
        })?;
        let value = node.into_raw("")?;
        if value.depth() > MAX_RAW_DEPTH {
            return Err(CanonicalError::TooDeep { max: MAX_RAW_DEPTH });
        }
        match value {
            RawValue::Map(entries) => Ok(Self(entries)),
            _ => Err(CanonicalError::NotAnObject),
        }
    }
}

/// Why raw input was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    Json {
        message: String,
    },
    NotAnObject,
    DuplicateKey {
        key: String,
    },
    /// Floating-point numbers have more than one textual form.
    Float {
        key: String,
    },
    IntegerOutOfRange {
        key: String,
    },
    /// Null is refused, so absent and null cannot mean different things to two readers.
    Null {
        key: String,
    },
    TooDeep {
        max: usize,
    },
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json { message } => write!(f, "the parameters are not valid JSON: {message}"),
            Self::NotAnObject => f.write_str("the parameters must be one JSON object"),
            Self::DuplicateKey { key } => write!(f, "the key {key:?} appears more than once"),
            Self::Float { key } => write!(
                f,
                "{key:?} is a floating-point number, which has no single canonical form"
            ),
            Self::IntegerOutOfRange { key } => {
                write!(f, "{key:?} is outside the signed 64-bit integer range")
            }
            Self::Null { key } => write!(f, "{key:?} is null; omit it instead"),
            Self::TooDeep { max } => write!(f, "the parameters nest deeper than {max} levels"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// JSON as parsed, keeping everything a strict reader must refuse so that the refusal
/// can be typed.
enum JsonNode {
    Null,
    Bool(bool),
    Integer(i64),
    OutOfRange,
    Float,
    Text(String),
    List(Vec<JsonNode>),
    Map(Vec<(String, JsonNode)>),
}

impl JsonNode {
    fn into_raw(self, key: &str) -> Result<RawValue, CanonicalError> {
        let key_name = || key.to_owned();
        match self {
            Self::Null => Err(CanonicalError::Null { key: key_name() }),
            Self::Bool(value) => Ok(RawValue::Bool(value)),
            Self::Integer(value) => Ok(RawValue::Integer(value)),
            Self::OutOfRange => Err(CanonicalError::IntegerOutOfRange { key: key_name() }),
            Self::Float => Err(CanonicalError::Float { key: key_name() }),
            Self::Text(text) => Ok(RawValue::Text(text)),
            Self::List(items) => items
                .into_iter()
                .map(|item| item.into_raw(key))
                .collect::<Result<Vec<_>, _>>()
                .map(RawValue::List),
            Self::Map(entries) => {
                let mut map = BTreeMap::new();
                for (name, value) in entries {
                    if map.contains_key(&name) {
                        return Err(CanonicalError::DuplicateKey { key: name });
                    }
                    let value = value.into_raw(&name)?;
                    map.insert(name, value);
                }
                Ok(RawValue::Map(map))
            }
        }
    }
}

impl<'de> Deserialize<'de> for JsonNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = JsonNode;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<JsonNode, E> {
        Ok(JsonNode::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<JsonNode, E> {
        Ok(JsonNode::Integer(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<JsonNode, E> {
        Ok(i64::try_from(value).map_or(JsonNode::OutOfRange, JsonNode::Integer))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<JsonNode, E> {
        Ok(JsonNode::Float)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<JsonNode, E> {
        Ok(JsonNode::Text(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<JsonNode, E> {
        Ok(JsonNode::Text(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<JsonNode, E> {
        Ok(JsonNode::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<JsonNode, E> {
        Ok(JsonNode::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonNode, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<JsonNode>()? {
            items.push(item);
        }
        Ok(JsonNode::List(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonNode, A::Error> {
        let mut entries = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, JsonNode>()? {
            entries.push((key, value));
        }
        Ok(JsonNode::Map(entries))
    }
}

pub(super) fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Writes a map whose keys are not strings as a list of `[key, value]` entries; reading
/// refuses a key that appears twice rather than keeping one of them.
pub(super) mod entries {
    use std::collections::BTreeMap;

    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, K, V>(map: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Serialize,
        V: Serialize,
    {
        let mut seq = serializer.serialize_seq(Some(map.len()))?;
        for entry in map {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        D: Deserializer<'de>,
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        let mut map = BTreeMap::new();
        for (key, value) in Vec::<(K, V)>::deserialize(deserializer)? {
            if map.insert(key, value).is_some() {
                return Err(serde::de::Error::custom("a map key appears twice"));
            }
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn name(text: &str) -> ParamName {
        ParamName::new(text).unwrap()
    }

    fn value_digest(parameters: &Parameters) -> Digest {
        parameters
            .feed(DigestBuilder::new("yougori/test/parameters/v1"))
            .finish()
    }

    #[test]
    fn named_parameters_and_sets_ignore_order_but_lists_do_not() {
        let a = Parameters::new()
            .with(name("title"), CanonicalValue::Text("fix".into()))
            .with(name("draft"), CanonicalValue::Bool(false));
        let b = Parameters::new()
            .with(name("draft"), CanonicalValue::Bool(false))
            .with(name("title"), CanonicalValue::Text("fix".into()));
        assert_eq!(value_digest(&a), value_digest(&b));

        let set = |items: &[&str]| {
            CanonicalValue::Set(
                items
                    .iter()
                    .map(|item| CanonicalValue::Text((*item).into()))
                    .collect(),
            )
        };
        let list = |items: &[&str]| {
            CanonicalValue::List(
                items
                    .iter()
                    .map(|item| CanonicalValue::Text((*item).into()))
                    .collect(),
            )
        };
        let with = |value| Parameters::new().with(name("labels"), value);
        assert_eq!(
            value_digest(&with(set(&["a", "b"]))),
            value_digest(&with(set(&["b", "a"])))
        );
        assert_ne!(
            value_digest(&with(list(&["a", "b"]))),
            value_digest(&with(list(&["b", "a"])))
        );
        assert_ne!(
            value_digest(&with(list(&["a", "b"]))),
            value_digest(&with(set(&["a", "b"])))
        );
    }

    #[test]
    fn value_encodings_never_collide() {
        let one = |value| value_digest(&Parameters::new().with(name("x"), value));
        let text = one(CanonicalValue::Text("1".into()));
        let integer = one(CanonicalValue::Integer(1));
        let boolean = one(CanonicalValue::Bool(true));
        let hash = one(CanonicalValue::Digest(digest("yougori/test/v1", &[b"1"])));
        let nested = one(CanonicalValue::List(vec![
            CanonicalValue::List(vec![CanonicalValue::Integer(1)]),
            CanonicalValue::Integer(2),
        ]));
        let flat = one(CanonicalValue::List(vec![CanonicalValue::List(vec![
            CanonicalValue::Integer(1),
            CanonicalValue::Integer(2),
        ])]));
        let all = [text, integer, boolean, hash, nested, flat];
        for (i, left) in all.iter().enumerate() {
            for right in &all[i + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn raw_json_is_read_strictly() {
        let parsed =
            RawParameters::from_json(r#"{"b": [1, 2], "a": "x", "c": true, "d": {"e": 3}}"#)
                .unwrap();
        let reordered =
            RawParameters::from_json(r#"{"d": {"e": 3}, "c": true, "a": "x", "b": [1, 2]}"#)
                .unwrap();
        assert_eq!(parsed, reordered);

        assert_eq!(
            RawParameters::from_json(r#"{"a": 1, "a": 2}"#),
            Err(CanonicalError::DuplicateKey { key: "a".into() })
        );
        assert_eq!(
            RawParameters::from_json(r#"{"x": {"a": 1, "a": 1}}"#),
            Err(CanonicalError::DuplicateKey { key: "a".into() })
        );
        assert_eq!(
            RawParameters::from_json(r#"{"price": 1.5}"#),
            Err(CanonicalError::Float {
                key: "price".into()
            })
        );
        assert_eq!(
            RawParameters::from_json(r#"{"n": 18446744073709551615}"#),
            Err(CanonicalError::IntegerOutOfRange { key: "n".into() })
        );
        assert_eq!(
            RawParameters::from_json(r#"{"n": null}"#),
            Err(CanonicalError::Null { key: "n".into() })
        );
        assert_eq!(
            RawParameters::from_json("[1]"),
            Err(CanonicalError::NotAnObject)
        );
        assert_eq!(
            RawParameters::from_json(r#"{"a": [[[[1]]]]}"#),
            Err(CanonicalError::TooDeep { max: MAX_RAW_DEPTH })
        );
        assert!(RawParameters::from_json(r#"{"a": [[[1]]]}"#).is_ok());
        assert!(matches!(
            RawParameters::from_json(r#"{"a": "#),
            Err(CanonicalError::Json { .. })
        ));
    }

    #[test]
    fn canonical_values_round_trip_and_refuse_unknown_shapes() {
        let parameters = Parameters::new()
            .with(name("n"), CanonicalValue::Integer(-3))
            .with(
                name("s"),
                CanonicalValue::Set(BTreeSet::from([CanonicalValue::Bool(true)])),
            );
        let json = serde_json::to_string(&parameters).unwrap();
        assert_eq!(
            serde_json::from_str::<Parameters>(&json).unwrap(),
            parameters
        );
        assert!(serde_json::from_str::<CanonicalValue>(r#"{"float": 1}"#).is_err());
        assert!(serde_json::from_str::<Parameters>(r#"{"bad name": {"bool": true}}"#).is_err());
    }
}
