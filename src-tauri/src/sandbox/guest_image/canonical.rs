//! The one byte form of a build record and of a feature manifest (VM-W05, line 2590:
//! "build records"; §8.3, line 2453: "verify signed artifact metadata before
//! execution").
//!
//! A document is JSON with object keys sorted by their bytes at every depth and no
//! insignificant whitespace, scalars and strings as `serde_json` writes them: the rule
//! of `sandbox::firecracker`'s canonical JSON, kept local so the guest image does not
//! depend on one backend. One document has one byte form, so its content key is its
//! identity and a signature over that key covers every field.
//!
//! Reading is strict and in this order: a size bound; the format version alone, so
//! another version is refused for its version and never reinterpreted; the typed
//! document, refusing unknown fields; then the bytes must be exactly the canonical form
//! of what was read. Reordered keys, whitespace, escapes that could be written plainly,
//! duplicate keys and unsorted lists are therefore refused rather than normalized.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The format version of build records and feature manifests this build reads and
/// writes. Another version is refused, never reinterpreted.
pub const GUEST_IMAGE_FORMAT: u64 = 1;

/// Why a document's bytes were refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum DocumentError {
    /// The document is larger than its bound.
    TooLarge { max_bytes: usize },
    /// The bytes are not such a document: bad JSON, an unknown or missing field, or a
    /// value its type refuses. Located, never quoted.
    Malformed { line: usize, column: usize },
    /// The document is in another format version.
    UnsupportedFormat { found: u64 },
    /// The bytes are a valid document but not its canonical form.
    NotCanonical,
    /// The document could not be written as JSON.
    Encoding { detail: String },
}

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => {
                write!(f, "the document is larger than {max_bytes} bytes")
            }
            Self::Malformed { line, column } => {
                write!(
                    f,
                    "the document is malformed at line {line}, column {column}"
                )
            }
            Self::UnsupportedFormat { found } => write!(
                f,
                "format {found} is not supported; this build reads format {GUEST_IMAGE_FORMAT}"
            ),
            Self::NotCanonical => f.write_str("the document is not in its canonical form"),
            Self::Encoding { detail } => write!(f, "the document could not be encoded: {detail}"),
        }
    }
}

impl std::error::Error for DocumentError {}

/// The canonical bytes of `value`.
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DocumentError> {
    let value = serde_json::to_value(value).map_err(|error| DocumentError::Encoding {
        detail: error.to_string(),
    })?;
    let mut out = String::new();
    write_value(&value, &mut out);
    Ok(out.into_bytes())
}

/// Reads `bytes` as a document of type `T` of at most `max_bytes`, in the order the
/// module documentation gives. The caller still checks the document's own rules and
/// that the bytes are its canonical form ([`require_canonical`]).
pub(super) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, DocumentError> {
    #[derive(Deserialize)]
    struct Versioned {
        format: u64,
    }
    if bytes.len() > max_bytes {
        return Err(DocumentError::TooLarge { max_bytes });
    }
    let malformed = |error: serde_json::Error| DocumentError::Malformed {
        line: error.line(),
        column: error.column(),
    };
    let Versioned { format } = serde_json::from_slice(bytes).map_err(malformed)?;
    if format != GUEST_IMAGE_FORMAT {
        return Err(DocumentError::UnsupportedFormat { found: format });
    }
    serde_json::from_slice(bytes).map_err(malformed)
}

/// Refuses `bytes` unless they are exactly `canonical`.
pub(super) fn require_canonical(bytes: &[u8], canonical: &[u8]) -> Result<(), DocumentError> {
    if bytes == canonical {
        Ok(())
    } else {
        Err(DocumentError::NotCanonical)
    }
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_value(item, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}
