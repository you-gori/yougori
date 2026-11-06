//! Bounded GGUF indexer (GPU part §3.3: header, metadata and tensor infos, with offsets
//! relative to the aligned data section).
//!
//! Layout (little-endian): magic `GGUF`, version (2 or 3), tensor count, metadata count,
//! the metadata key/value pairs, the tensor infos (name, dimensions innermost first, ggml
//! type, offset), padding to `general.alignment` (default 32), then the data section.
//! As ggml reads it, tensor data is contiguous in tensor-info order with each tensor
//! padded to the alignment. Every count and length is checked against the file length
//! and the bounds before it is read; nested arrays, removed or unknown types, duplicate
//! keys or names and big-endian files are refused.

use std::collections::BTreeSet;
use std::io::Read;

use crate::foundation::ids::DigestBuilder;

use super::digests::GGUF_METADATA_DOMAIN;
use super::groups::FileFormat;
use super::index::{
    read_exact, tensor_name, IndexError, IndexedFile, IndexedTensor, IndexerBounds,
};
use super::types::{element_count, tensor_bytes, ShapeError, TensorDtype, TensorLayout};

pub const GGUF_MAGIC: [u8; 4] = *b"GGUF";
/// Alignment of the data section and of each tensor when `general.alignment` is absent.
pub const GGUF_DEFAULT_ALIGNMENT_BYTES: u64 = 32;
/// ggml keeps tensor names in 64-byte buffers with a terminating NUL.
pub const GGUF_MAX_TENSOR_NAME_BYTES: u64 = 63;
/// ggml tensors have at most four dimensions.
pub const GGUF_MAX_DIMENSIONS: u64 = 4;
/// GGUF metadata keys are at most 65,535 bytes.
pub const GGUF_MAX_KEY_BYTES: u64 = 65_535;

const TYPE_UINT32: u32 = 4;
const TYPE_STRING: u32 = 8;
const TYPE_ARRAY: u32 = 9;

/// Bytes of a scalar metadata value type; `None` for strings, arrays and unknown types.
fn scalar_bytes(value_type: u32) -> Option<u64> {
    match value_type {
        0 | 1 | 7 => Some(1),
        2 | 3 => Some(2),
        4..=6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|padded| padded / alignment * alignment)
}

struct HeaderReader<'r, R> {
    reader: &'r mut R,
    consumed_bytes: u64,
    file_length_bytes: u64,
    max_header_bytes: u64,
    recording: Option<Vec<u8>>,
}

impl<R: Read> HeaderReader<'_, R> {
    /// Refuses a read of `len` bytes past the file or the header bound before it happens.
    fn reserve(&self, len: u64) -> Result<(), IndexError> {
        let end = self
            .consumed_bytes
            .checked_add(len)
            .ok_or(IndexError::Truncated)?;
        if end > self.file_length_bytes {
            return Err(IndexError::Truncated);
        }
        if end > self.max_header_bytes {
            return Err(IndexError::HeaderTooLarge {
                length_bytes: end,
                max_bytes: self.max_header_bytes,
            });
        }
        Ok(())
    }

    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), IndexError> {
        self.reserve(buffer.len() as u64)?;
        read_exact(self.reader, buffer)?;
        self.consumed_bytes += buffer.len() as u64;
        if let Some(recording) = &mut self.recording {
            recording.extend_from_slice(buffer);
        }
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], IndexError> {
        let mut buffer = [0u8; N];
        self.fill(&mut buffer)?;
        Ok(buffer)
    }

    fn u32(&mut self) -> Result<u32, IndexError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, IndexError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn bytes(&mut self, len: u64) -> Result<Vec<u8>, IndexError> {
        self.reserve(len)?;
        let len = usize::try_from(len).map_err(|_| IndexError::Truncated)?;
        let mut buffer = vec![0u8; len];
        self.fill(&mut buffer)?;
        Ok(buffer)
    }

    fn skip(&mut self, len: u64) -> Result<(), IndexError> {
        self.reserve(len)?;
        let mut chunk = [0u8; 4_096];
        let mut remaining = len;
        while remaining > 0 {
            let take = remaining.min(chunk.len() as u64) as usize;
            let part = chunk.get_mut(..take).ok_or(IndexError::Truncated)?;
            self.fill(part)?;
            remaining -= take as u64;
        }
        Ok(())
    }

    fn string_length(&mut self, max_bytes: u64) -> Result<u64, IndexError> {
        let found = self.u64()?;
        if found > max_bytes {
            return Err(IndexError::StringTooLong {
                found,
                max: max_bytes,
            });
        }
        Ok(found)
    }

    fn skip_value(&mut self, value_type: u32, bounds: &IndexerBounds) -> Result<(), IndexError> {
        if let Some(bytes) = scalar_bytes(value_type) {
            return self.skip(bytes);
        }
        match value_type {
            TYPE_STRING => {
                let len = self.string_length(bounds.max_string_bytes)?;
                self.skip(len)
            }
            TYPE_ARRAY => {
                let element_type = self.u32()?;
                if element_type == TYPE_ARRAY {
                    return Err(IndexError::NestedArray);
                }
                let count = self.u64()?;
                if count > bounds.max_array_elements {
                    return Err(IndexError::ArrayTooLong {
                        found: count,
                        max: bounds.max_array_elements,
                    });
                }
                if let Some(bytes) = scalar_bytes(element_type) {
                    return self.skip(count.checked_mul(bytes).ok_or(IndexError::Truncated)?);
                }
                if element_type != TYPE_STRING {
                    return Err(IndexError::InvalidValueType {
                        value_type: element_type,
                    });
                }
                self.reserve(count.checked_mul(8).ok_or(IndexError::Truncated)?)?;
                for _ in 0..count {
                    let len = self.string_length(bounds.max_string_bytes)?;
                    self.skip(len)?;
                }
                Ok(())
            }
            _ => Err(IndexError::InvalidValueType { value_type }),
        }
    }
}

/// One tensor info as read, before its data range is checked.
struct TensorInfo {
    name: String,
    shape: Vec<u64>,
    dtype: TensorDtype,
    offset_bytes: u64,
}

/// Indexes a GGUF file read from its first byte.
pub fn index_gguf<R: Read>(
    reader: &mut R,
    file_length_bytes: u64,
    bounds: &IndexerBounds,
) -> Result<IndexedFile, IndexError> {
    bounds.check_within(&IndexerBounds::CEILING)?;
    let mut r = HeaderReader {
        reader,
        consumed_bytes: 0,
        file_length_bytes,
        max_header_bytes: bounds.max_header_bytes,
        recording: None,
    };
    if r.array::<4>()? != GGUF_MAGIC {
        return Err(IndexError::BadMagic);
    }
    let version = r.u32()?;
    if !matches!(version, 2 | 3) {
        if matches!(version.swap_bytes(), 2 | 3) {
            return Err(IndexError::BigEndian);
        }
        return Err(IndexError::UnsupportedVersion { version });
    }
    let tensor_count = r.u64()?;
    if tensor_count > bounds.max_tensors {
        return Err(IndexError::TooManyTensors {
            max: bounds.max_tensors,
        });
    }
    let metadata_count = r.u64()?;
    if metadata_count > bounds.max_metadata_entries {
        return Err(IndexError::TooManyMetadataEntries {
            found: metadata_count,
            max: bounds.max_metadata_entries,
        });
    }

    r.recording = Some(Vec::new());
    let mut keys = BTreeSet::new();
    let mut alignment_bytes = GGUF_DEFAULT_ALIGNMENT_BYTES;
    for _ in 0..metadata_count {
        let len = r.string_length(GGUF_MAX_KEY_BYTES)?;
        let key = String::from_utf8(r.bytes(len)?).map_err(|_| IndexError::MalformedHeader {
            reason: "a metadata key is not UTF-8".to_owned(),
        })?;
        let value_type = r.u32()?;
        if key == "general.alignment" {
            if value_type != TYPE_UINT32 {
                return Err(IndexError::AlignmentType);
            }
            let alignment = u64::from(r.u32()?);
            if !alignment.is_power_of_two() {
                return Err(IndexError::InvalidAlignment { alignment });
            }
            alignment_bytes = alignment;
        } else {
            r.skip_value(value_type, bounds)?;
        }
        if !keys.insert(key.clone()) {
            return Err(IndexError::DuplicateMetadataKey { key });
        }
    }
    let metadata = r.recording.take().unwrap_or_default();
    let metadata_digest = DigestBuilder::new(GGUF_METADATA_DOMAIN)
        .u64(metadata_count)
        .bytes(&metadata)
        .finish();

    let max_name_bytes = GGUF_MAX_TENSOR_NAME_BYTES.min(bounds.max_name_bytes);
    let max_dimensions = GGUF_MAX_DIMENSIONS.min(bounds.max_dimensions);
    let mut names = BTreeSet::new();
    let mut infos = Vec::new();
    for _ in 0..tensor_count {
        let found_bytes = r.u64()?;
        if found_bytes > max_name_bytes {
            return Err(IndexError::NameTooLong {
                found_bytes,
                max_bytes: max_name_bytes,
            });
        }
        let name =
            String::from_utf8(r.bytes(found_bytes)?).map_err(|_| IndexError::MalformedHeader {
                reason: "a tensor name is not UTF-8".to_owned(),
            })?;
        if !names.insert(name.clone()) {
            return Err(IndexError::DuplicateTensor { name });
        }
        let dimensions = u64::from(r.u32()?);
        if dimensions > max_dimensions {
            return Err(IndexError::TooManyDimensions {
                found: dimensions,
                max: max_dimensions,
            });
        }
        let mut shape = Vec::new();
        for _ in 0..dimensions {
            shape.push(r.u64()?);
        }
        let elements = element_count(&shape).map_err(|error| IndexError::Shape {
            name: name.clone(),
            error,
        })?;
        let int64_max = i64::MAX as u64;
        if elements > int64_max || shape.iter().any(|dimension| *dimension > int64_max) {
            return Err(IndexError::Shape {
                name,
                error: ShapeError::Overflow,
            });
        }
        let type_id = r.u32()?;
        let dtype = TensorDtype::from_ggml_id(type_id)
            .ok_or(IndexError::UnsupportedGgmlType { id: type_id })?;
        let offset_bytes = r.u64()?;
        infos.push(TensorInfo {
            name,
            shape,
            dtype,
            offset_bytes,
        });
    }

    let data_offset_bytes =
        align_up(r.consumed_bytes, alignment_bytes).ok_or(IndexError::Truncated)?;
    let mut expected_bytes = 0u64;
    let mut tensors = Vec::with_capacity(infos.len());
    for info in infos {
        let true_length_bytes =
            tensor_bytes(info.dtype, TensorLayout::GgmlInnermostFirst, &info.shape).map_err(
                |error| IndexError::Shape {
                    name: info.name.clone(),
                    error,
                },
            )?;
        if info.offset_bytes != expected_bytes {
            return Err(IndexError::UnexpectedOffset {
                name: info.name,
                offset_bytes: info.offset_bytes,
                expected_bytes,
            });
        }
        let start_bytes = data_offset_bytes.checked_add(info.offset_bytes);
        let end_bytes = start_bytes.and_then(|start| start.checked_add(true_length_bytes));
        let padded_end = align_up(true_length_bytes, alignment_bytes)
            .and_then(|padded| expected_bytes.checked_add(padded));
        let (Some(start_bytes), Some(end_bytes), Some(padded_end)) =
            (start_bytes, end_bytes, padded_end)
        else {
            return Err(IndexError::OutOfBounds { name: info.name });
        };
        if end_bytes > file_length_bytes {
            return Err(IndexError::OutOfBounds { name: info.name });
        }
        expected_bytes = padded_end;
        tensors.push(IndexedTensor {
            name: tensor_name(info.name, bounds)?,
            dtype: info.dtype,
            shape: info.shape,
            layout: TensorLayout::GgmlInnermostFirst,
            offset_bytes: start_bytes,
            true_length_bytes,
        });
    }
    let data_end_bytes = data_offset_bytes
        .checked_add(expected_bytes)
        .ok_or(IndexError::Truncated)?;
    if file_length_bytes > data_end_bytes {
        return Err(IndexError::TrailingBytes {
            data_end_bytes,
            file_length_bytes,
        });
    }
    Ok(IndexedFile {
        format: FileFormat::Gguf {
            version,
            alignment_bytes,
            data_offset_bytes,
            metadata_digest,
        },
        tensors,
    })
}
