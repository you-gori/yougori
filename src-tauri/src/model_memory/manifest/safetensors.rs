//! Bounded safetensors indexer (GPU part §3.3, plan line 510: "Its documented offsets are
//! relative to the data buffer, not the start of the file").
//!
//! Layout: an 8-byte little-endian header length N, N bytes of JSON starting with '{' and
//! padded with spaces, then the data buffer. Each tensor's `data_offsets` are relative to
//! the data buffer at byte 8 + N. The buffer must be indexed entirely, without holes or
//! overlaps, as the format requires. Duplicate keys and unknown fields are refused.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;

use serde::de::{Deserializer as _, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;

use super::groups::FileFormat;
use super::index::{
    read_exact, tensor_name, IndexError, IndexedFile, IndexedTensor, IndexerBounds,
};
use super::types::{tensor_bytes, ElementType, TensorDtype, TensorLayout};

/// Bytes of the little-endian header length that starts the file.
pub const SAFETENSORS_PREFIX_BYTES: u64 = 8;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTensor {
    dtype: String,
    shape: Vec<u64>,
    data_offsets: Vec<u64>,
}

#[derive(Default)]
struct RawHeader {
    tensors: Vec<(String, RawTensor)>,
    duplicate: Option<String>,
    duplicate_metadata: Option<String>,
    too_many: bool,
}

struct HeaderVisitor {
    max_tensors: u64,
}

impl<'de> Visitor<'de> for HeaderVisitor {
    type Value = RawHeader;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object of tensors")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawHeader, A::Error> {
        let mut header = RawHeader::default();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) && header.duplicate.is_none() {
                header.duplicate = Some(key.clone());
            }
            if key == "__metadata__" {
                let metadata: MetadataCheck = map.next_value()?;
                if header.duplicate_metadata.is_none() {
                    header.duplicate_metadata = metadata.duplicate;
                }
            } else if header.tensors.len() as u64 >= self.max_tensors {
                header.too_many = true;
                map.next_value::<IgnoredAny>()?;
            } else {
                let tensor: RawTensor = map.next_value()?;
                header.tensors.push((key, tensor));
            }
        }
        Ok(header)
    }
}

/// `__metadata__`: a map from strings to strings, each key once.
struct MetadataCheck {
    duplicate: Option<String>,
}

impl<'de> Deserialize<'de> for MetadataCheck {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MetadataVisitor)
    }
}

struct MetadataVisitor;

impl<'de> Visitor<'de> for MetadataVisitor {
    type Value = MetadataCheck;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object of strings")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MetadataCheck, A::Error> {
        let mut seen = BTreeSet::new();
        let mut duplicate = None;
        while let Some(key) = map.next_key::<String>()? {
            let _value: String = map.next_value()?;
            if !seen.insert(key.clone()) && duplicate.is_none() {
                duplicate = Some(key);
            }
        }
        Ok(MetadataCheck { duplicate })
    }
}

fn parse_header(json: &[u8], bounds: &IndexerBounds) -> Result<RawHeader, IndexError> {
    let malformed = |error: serde_json::Error| IndexError::MalformedHeader {
        reason: error.to_string(),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let header = (&mut deserializer)
        .deserialize_map(HeaderVisitor {
            max_tensors: bounds.max_tensors,
        })
        .map_err(malformed)?;
    deserializer.end().map_err(malformed)?;
    Ok(header)
}

/// The JSON inside the header: it must start with '{', and only spaces may follow the
/// closing '}'.
fn header_json(header: &[u8]) -> Result<&[u8], IndexError> {
    let end = header
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |last| last + 1);
    let json = header.get(..end).ok_or(IndexError::BadPadding)?;
    if json.first() != Some(&b'{') || json.last() != Some(&b'}') {
        return Err(IndexError::BadPadding);
    }
    Ok(json)
}

/// Indexes a safetensors file read from its first byte.
pub fn index_safetensors<R: Read>(
    reader: &mut R,
    file_length_bytes: u64,
    bounds: &IndexerBounds,
) -> Result<IndexedFile, IndexError> {
    bounds.check_within(&IndexerBounds::CEILING)?;
    if file_length_bytes < SAFETENSORS_PREFIX_BYTES {
        return Err(IndexError::Truncated);
    }
    let mut prefix = [0u8; 8];
    read_exact(reader, &mut prefix)?;
    let header_length_bytes = u64::from_le_bytes(prefix);
    let too_large = IndexError::HeaderTooLarge {
        length_bytes: header_length_bytes,
        max_bytes: bounds.max_header_bytes,
    };
    if header_length_bytes > bounds.max_header_bytes {
        return Err(too_large);
    }
    let data_start_bytes = SAFETENSORS_PREFIX_BYTES
        .checked_add(header_length_bytes)
        .ok_or(too_large)?;
    if data_start_bytes > file_length_bytes {
        return Err(IndexError::HeaderPastEnd {
            header_end_bytes: data_start_bytes,
            file_length_bytes,
        });
    }
    let header_len =
        usize::try_from(header_length_bytes).map_err(|_| IndexError::HeaderTooLarge {
            length_bytes: header_length_bytes,
            max_bytes: bounds.max_header_bytes,
        })?;
    let mut header = vec![0u8; header_len];
    read_exact(reader, &mut header)?;
    let raw = parse_header(header_json(&header)?, bounds)?;
    if let Some(name) = raw.duplicate {
        return Err(IndexError::DuplicateTensor { name });
    }
    if let Some(key) = raw.duplicate_metadata {
        return Err(IndexError::DuplicateMetadataKey { key });
    }
    if raw.too_many {
        return Err(IndexError::TooManyTensors {
            max: bounds.max_tensors,
        });
    }

    let buffer_bytes = file_length_bytes - data_start_bytes;
    let mut spans = Vec::with_capacity(raw.tensors.len());
    let mut tensors = Vec::with_capacity(raw.tensors.len());
    for (name, tensor) in raw.tensors {
        let dtype = ElementType::from_safetensors_name(&tensor.dtype).ok_or_else(|| {
            IndexError::UnknownDtype {
                dtype: tensor.dtype.clone(),
            }
        })?;
        let dimensions = tensor.shape.len() as u64;
        if dimensions > bounds.max_dimensions {
            return Err(IndexError::TooManyDimensions {
                found: dimensions,
                max: bounds.max_dimensions,
            });
        }
        let [begin, end] = <[u64; 2]>::try_from(tensor.data_offsets.as_slice()).map_err(|_| {
            IndexError::MalformedHeader {
                reason: format!("tensor {name:?} needs exactly two data offsets"),
            }
        })?;
        if end < begin {
            return Err(IndexError::OffsetsReversed { name });
        }
        if end > buffer_bytes {
            return Err(IndexError::OutOfBounds { name });
        }
        let expected_bytes = tensor_bytes(
            TensorDtype::Element(dtype),
            TensorLayout::RowMajor,
            &tensor.shape,
        )
        .map_err(|error| IndexError::Shape {
            name: name.clone(),
            error,
        })?;
        if end - begin != expected_bytes {
            return Err(IndexError::LengthMismatch {
                name,
                declared_bytes: end - begin,
                expected_bytes,
            });
        }
        spans.push((begin, end));
        tensors.push(IndexedTensor {
            name: tensor_name(name, bounds)?,
            dtype: TensorDtype::Element(dtype),
            shape: tensor.shape,
            layout: TensorLayout::RowMajor,
            offset_bytes: data_start_bytes + begin,
            true_length_bytes: expected_bytes,
        });
    }

    spans.sort_unstable();
    let mut covered_bytes = 0u64;
    for (begin, end) in spans {
        if begin > covered_bytes {
            return Err(IndexError::Hole {
                at_bytes: covered_bytes,
            });
        }
        if begin < covered_bytes {
            return Err(IndexError::Overlap { at_bytes: begin });
        }
        covered_bytes = end;
    }
    if covered_bytes != buffer_bytes {
        return Err(IndexError::Hole {
            at_bytes: covered_bytes,
        });
    }
    Ok(IndexedFile {
        format: FileFormat::Safetensors {
            header_length_bytes,
        },
        tensors,
    })
}
