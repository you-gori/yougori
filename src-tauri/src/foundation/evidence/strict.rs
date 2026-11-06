//! Strict deserialization for internally tagged enums.
//!
//! serde accepts unknown fields beside the tag of a unit variant even under
//! `deny_unknown_fields`, and without that attribute it also accepts them beside struct
//! variants. Evidence, requirements and settings can arrive as untrusted JSON, so every
//! internally tagged enum here with unit or struct variants is defined through
//! `strict_evidence_enum!`: its deserializer reads each variant, unit variants included, as
//! a struct that refuses unknown fields. Serialization is unchanged.
//!
//! The record is read through `foundation::strict_serde::read_tagged` first, so a tag that
//! is not a string is refused even where serde buffers the record, as it does inside
//! another tagged enum, where it would read an integer tag as a variant index.

/// Defines an internally tagged, snake_case enum with unit and struct variants whose
/// deserialization refuses unknown fields for every variant and a tag that is not a string.
macro_rules! strict_evidence_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({ $($field:ident : $ty:ty),* $(,)? })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let value = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(value)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}
