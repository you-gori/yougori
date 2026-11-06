//! Strict tags for the tagged enums read back from JSON (S2 CORE-06 and every durable
//! record of docs/combined-gpu-memory-and-vm-sandbox-plan.md; the S06 open item "Stored
//! sequence ranges" of docs/combined-plan-leftover-tasks.md, from yougori-cc's E01Y
//! protocol fuzzing).
//!
//! serde reads the tag of an internally tagged enum (`#[serde(tag = "...")]`) or an
//! adjacently tagged one as a variant name only while it reads straight from JSON. Once
//! it has buffered the record, as it does for every field of another tagged enum, under
//! `flatten` and in untagged enums, it also takes an integer there as the variant's index,
//! so `{"entry":"volume","renewal":{"class":1}}` would read `renewal` as the second
//! class. Every tagged enum here that is read back therefore reads its record as a JSON
//! value first and refuses a tag that is not a string ([`check_tag`]) before the derived
//! code reads the record from that value ([`read_tagged`]).
//!
//! An enum that derives `Serialize` and `Deserialize` adopts this with two lines: the
//! attribute `#[serde(remote = "Self")]`, which turns the derived code into the inherent
//! functions `serialize` and `deserialize` and keeps every container, variant and field
//! attribute, and `strict_tag!(Name, "tag");` after it, which implements the serde traits
//! on them. The written form does not change, and nothing that was read before is refused
//! except a tag that is not a string, a record that is not a JSON object and a key that
//! appears twice in one object (see [`read_tagged`]). The twin-enum macros of the events,
//! evidence, product, report and profiles modules read through [`read_tagged`] too.

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Unexpected, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

#[cfg(test)]
mod tests;

/// Implements `Serialize` and `Deserialize` for a tagged enum that derives them with
/// `#[serde(remote = "Self")]` (see the module documentation).
///
/// - `strict_tag!(Name, "tag")`: writing forwards to the derived inherent `serialize`, so
///   the written form is unchanged; reading goes through [`read_tagged`] with the enum's
///   tag and then the derived inherent `deserialize`.
/// - `strict_tag!(Name<T, U>, "tag")`: the same for an enum with type parameters, each
///   bound by the trait it is written or read with.
/// - `strict_tag!(Name, "tag", deserialize)`: only `Deserialize`, for an enum that derives
///   only `Deserialize`.
///
/// `Name::deserialize(...)` written as a path names the derived inherent function, which
/// reads without the check; read through the trait (`<Name as Deserialize>::deserialize`
/// or `serde_json::from_*`) instead. A tag literal that differs from the enum's own
/// refuses every record as missing its tag.
macro_rules! strict_tag {
    ($name:ident $(<$($param:ident),+ $(,)?>)?, $tag:literal) => {
        impl$(<$($param: serde::Serialize),+>)? serde::Serialize for $name$(<$($param),+>)? {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                $name::serialize(self, serializer)
            }
        }

        $crate::foundation::strict_serde::strict_tag!(
            $name$(<$($param),+>)?, $tag, deserialize
        );
    };
    ($name:ident $(<$($param:ident),+ $(,)?>)?, $tag:literal, deserialize) => {
        impl<'de $($(, $param: serde::Deserialize<'de>)+)?> serde::Deserialize<'de>
            for $name$(<$($param),+>)?
        {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = $crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                $name::deserialize(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use strict_tag;

/// Declares an internally tagged enum whose every variant refuses unknown fields when
/// read, so a record cannot carry a field the schema does not name (S8 redaction).
/// Serde ignores fields after the tag of a unit variant, so reading goes through a twin
/// enum in which each unit variant is an empty struct variant; the written form is the
/// same. The twin reads through [`strict_tag!`], so a tag that is not a string is refused
/// even where serde buffers the record. One definition (U05 compactness: the events,
/// report and profiles modules each kept a copy); a module that declares its enums with
/// it in child files forwards to it with a three-line `macro_rules!` of the same name, so
/// the children keep the textual scope they had.
macro_rules! strict_tagged_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident (tag = $tag:literal, wire = $wire:ident, wire_name = $wire_name:literal) {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $field_type:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", from = $wire_name)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({
                    $(
                        $(#[$field_meta])*
                        $field: $field_type
                    ),*
                })?
            ),*
        }

        #[derive(serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
        #[serde(remote = "Self")]
        enum $wire {
            $(
                $variant {
                    $($(
                        $field: $field_type
                    ),*)?
                }
            ),*
        }

        crate::foundation::strict_serde::strict_tag!($wire, $tag, deserialize);

        impl From<$wire> for $name {
            fn from(wire: $wire) -> Self {
                match wire {
                    $(
                        $wire::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?,
                    )*
                }
            }
        }
    };
}

pub(crate) use strict_tagged_enum;

/// Refuses a record of an internally or adjacently tagged enum whose `tag` is missing or
/// is not a string, the one form serde itself would read as a variant index once the
/// record is buffered. A record that is not a JSON object is refused too.
///
/// The refusals are `invalid_type` (expected "a map") for a record that is not an object,
/// `invalid_type` (expected "a variant name") for a tag that is not a string, and
/// `missing_field` for a missing tag.
pub fn check_tag<E: de::Error>(value: &Value, tag: &'static str) -> Result<(), E> {
    let Value::Object(fields) = value else {
        return Err(E::invalid_type(unexpected(value), &"a map"));
    };
    match fields.get(tag) {
        Some(Value::String(_)) => Ok(()),
        Some(other) => Err(E::invalid_type(unexpected(other), &"a variant name")),
        None => Err(E::missing_field(tag)),
    }
}

/// Reads one record of a tagged enum as a JSON value and checks its `tag` ([`check_tag`]).
///
/// A key that appears twice in one object, at any depth of the record, is refused as a
/// duplicate field. Read straight from JSON, serde refuses a repeated tag or a repeated
/// field of a struct; a JSON value would instead keep only the last one, so a record with
/// a repeated tag or field would otherwise read where it was refused before. Numbers,
/// strings and nesting are kept exactly as the JSON reader delivers them.
pub fn read_tagged<'de, D: Deserializer<'de>>(
    deserializer: D,
    tag: &'static str,
) -> Result<Value, D::Error> {
    let value = UniqueKeys.deserialize(deserializer)?;
    check_tag::<D::Error>(&value, tag)?;
    Ok(value)
}

/// `value` as serde names an unexpected input.
fn unexpected(value: &Value) -> Unexpected<'_> {
    match value {
        Value::Null => Unexpected::Unit,
        Value::Bool(flag) => Unexpected::Bool(*flag),
        Value::Number(number) => number
            .as_u64()
            .map(Unexpected::Unsigned)
            .or_else(|| number.as_i64().map(Unexpected::Signed))
            .or_else(|| number.as_f64().map(Unexpected::Float))
            .unwrap_or(Unexpected::Other("number")),
        Value::String(text) => Unexpected::Str(text),
        Value::Array(_) => Unexpected::Seq,
        Value::Object(_) => Unexpected::Map,
    }
}

/// Reads any JSON value as `serde_json::Value` does, refusing a key repeated in one object.
#[derive(Clone, Copy)]
struct UniqueKeys;

impl<'de> DeserializeSeed<'de> for UniqueKeys {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueKeys {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.deserialize(deserializer)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(self)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut fields = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if fields.contains_key(&key) {
                return Err(de::Error::custom(format_args!("duplicate field `{key}`")));
            }
            let value = map.next_value_seed(self)?;
            fields.insert(key, value);
        }
        Ok(Value::Object(fields))
    }
}
