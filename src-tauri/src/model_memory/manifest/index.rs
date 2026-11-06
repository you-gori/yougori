//! Bounded sidecar indexers over existing weight files (GPU part §3.3: "Begin with a
//! sidecar index over existing safetensors/GGUF ... files"; GPU-W03: "bounded sidecar
//! parsing over existing artifacts before inventing a new container").
//!
//! An indexer reads only a file's header, sequentially, from a reader the caller opened.
//! Every length is checked against the file and the [`IndexerBounds`] before a buffer is
//! allocated for it, and malformed input is refused with a typed [`IndexError`].

use std::fmt;
use std::io::{self, Read};

use super::groups::{FileFormat, WeightFormat};
use super::types::{
    NameError, ShapeError, TensorDtype, TensorLayout, TensorName, MAX_TENSOR_NAME_BYTES,
};

/// Limits on what an indexer reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexerBounds {
    /// Largest header: the safetensors JSON, or GGUF metadata plus tensor infos.
    pub max_header_bytes: u64,
    pub max_tensors: u64,
    pub max_dimensions: u64,
    pub max_name_bytes: u64,
    pub max_metadata_entries: u64,
    pub max_array_elements: u64,
    pub max_string_bytes: u64,
}

impl IndexerBounds {
    /// The safetensors reference limit for headers (100,000,000 bytes) and limits sized
    /// for current checkpoints.
    pub const DEFAULT: Self = Self {
        max_header_bytes: 100_000_000,
        max_tensors: 1 << 20,
        max_dimensions: 16,
        max_name_bytes: 512,
        max_metadata_entries: 1 << 16,
        max_array_elements: 1 << 24,
        max_string_bytes: 1 << 24,
    };

    /// The largest bounds an indexer accepts. A gibibyte of header and counts no manifest
    /// can exceed keep every length an indexer adds far from overflow.
    pub const CEILING: Self = Self {
        max_header_bytes: 1 << 30,
        max_tensors: 1 << 22,
        max_dimensions: 64,
        max_name_bytes: MAX_TENSOR_NAME_BYTES as u64,
        max_metadata_entries: 1 << 20,
        max_array_elements: 1 << 30,
        max_string_bytes: 1 << 30,
    };

    /// Refuses a bound above `ceiling`.
    pub fn check_within(&self, ceiling: &Self) -> Result<(), IndexError> {
        let pairs: [(&'static str, u64, u64); 7] = [
            (
                "max_header_bytes",
                self.max_header_bytes,
                ceiling.max_header_bytes,
            ),
            ("max_tensors", self.max_tensors, ceiling.max_tensors),
            (
                "max_dimensions",
                self.max_dimensions,
                ceiling.max_dimensions,
            ),
            (
                "max_name_bytes",
                self.max_name_bytes,
                ceiling.max_name_bytes,
            ),
            (
                "max_metadata_entries",
                self.max_metadata_entries,
                ceiling.max_metadata_entries,
            ),
            (
                "max_array_elements",
                self.max_array_elements,
                ceiling.max_array_elements,
            ),
            (
                "max_string_bytes",
                self.max_string_bytes,
                ceiling.max_string_bytes,
            ),
        ];
        match pairs
            .into_iter()
            .find(|(_, declared, ceiling)| declared > ceiling)
        {
            Some((bound, declared, ceiling)) => Err(IndexError::BoundAboveCeiling {
                bound,
                declared,
                ceiling,
            }),
            None => Ok(()),
        }
    }
}

impl Default for IndexerBounds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One tensor found in a header. `offset_bytes` is from the start of the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedTensor {
    pub name: TensorName,
    pub dtype: TensorDtype,
    pub shape: Vec<u64>,
    pub layout: TensorLayout,
    pub offset_bytes: u64,
    pub true_length_bytes: u64,
}

/// What an indexer found in one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedFile {
    pub format: FileFormat,
    /// In header order.
    pub tensors: Vec<IndexedTensor>,
}

/// Why a header was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    /// A caller's bound is above [`IndexerBounds::CEILING`]; nothing was read.
    BoundAboveCeiling {
        bound: &'static str,
        declared: u64,
        ceiling: u64,
    },
    /// The file ends inside its header.
    Truncated,
    HeaderTooLarge {
        length_bytes: u64,
        max_bytes: u64,
    },
    /// The declared header extends past the end of the file.
    HeaderPastEnd {
        header_end_bytes: u64,
        file_length_bytes: u64,
    },
    MalformedHeader {
        reason: String,
    },
    /// A safetensors header must start with '{' and be padded only with spaces.
    BadPadding,
    DuplicateTensor {
        name: String,
    },
    DuplicateMetadataKey {
        key: String,
    },
    TooManyTensors {
        max: u64,
    },
    TooManyMetadataEntries {
        found: u64,
        max: u64,
    },
    TooManyDimensions {
        found: u64,
        max: u64,
    },
    InvalidName {
        error: NameError,
    },
    NameTooLong {
        found_bytes: u64,
        max_bytes: u64,
    },
    UnknownDtype {
        dtype: String,
    },
    UnsupportedGgmlType {
        id: u32,
    },
    Shape {
        name: String,
        error: ShapeError,
    },
    OffsetsReversed {
        name: String,
    },
    OutOfBounds {
        name: String,
    },
    LengthMismatch {
        name: String,
        declared_bytes: u64,
        expected_bytes: u64,
    },
    /// Bytes of the safetensors data buffer that no tensor indexes.
    Hole {
        at_bytes: u64,
    },
    Overlap {
        at_bytes: u64,
    },
    BadMagic,
    UnsupportedVersion {
        version: u32,
    },
    /// A GGUF file written big-endian; only little-endian is read.
    BigEndian,
    InvalidValueType {
        value_type: u32,
    },
    NestedArray,
    ArrayTooLong {
        found: u64,
        max: u64,
    },
    StringTooLong {
        found: u64,
        max: u64,
    },
    InvalidAlignment {
        alignment: u64,
    },
    /// `general.alignment` is not a u32.
    AlignmentType,
    /// GGUF tensor data must be contiguous in tensor-info order, each tensor padded to the
    /// alignment.
    UnexpectedOffset {
        name: String,
        offset_bytes: u64,
        expected_bytes: u64,
    },
    TrailingBytes {
        data_end_bytes: u64,
        file_length_bytes: u64,
    },
    Io {
        kind: io::ErrorKind,
    },
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundAboveCeiling {
                bound,
                declared,
                ceiling,
            } => write!(
                f,
                "indexer bound {bound} {declared} is above the ceiling {ceiling}"
            ),
            Self::Truncated => f.write_str("the file ends inside its header"),
            Self::HeaderTooLarge {
                length_bytes,
                max_bytes,
            } => write!(
                f,
                "the {length_bytes}-byte header exceeds the {max_bytes}-byte bound"
            ),
            Self::HeaderPastEnd {
                header_end_bytes,
                file_length_bytes,
            } => write!(
                f,
                "the header ends at byte {header_end_bytes}, past the {file_length_bytes}-byte \
                 file"
            ),
            Self::MalformedHeader { reason } => write!(f, "the header is malformed: {reason}"),
            Self::BadPadding => {
                f.write_str("the header must start with '{' and be padded only with spaces")
            }
            Self::DuplicateTensor { name } => write!(f, "tensor {name:?} appears twice"),
            Self::DuplicateMetadataKey { key } => write!(f, "metadata key {key:?} appears twice"),
            Self::TooManyTensors { max } => write!(f, "the header has more than {max} tensors"),
            Self::TooManyMetadataEntries { found, max } => {
                write!(f, "{found} metadata entries exceed the bound of {max}")
            }
            Self::TooManyDimensions { found, max } => {
                write!(f, "{found} dimensions exceed the bound of {max}")
            }
            Self::InvalidName { error } => write!(f, "a tensor name is invalid: {error}"),
            Self::NameTooLong {
                found_bytes,
                max_bytes,
            } => write!(
                f,
                "a {found_bytes}-byte name exceeds the bound of {max_bytes}"
            ),
            Self::UnknownDtype { dtype } => write!(f, "dtype {dtype:?} is not supported"),
            Self::UnsupportedGgmlType { id } => write!(f, "ggml type {id} is not supported"),
            Self::Shape { name, error } => write!(f, "tensor {name:?}: {error}"),
            Self::OffsetsReversed { name } => write!(f, "tensor {name:?} ends before it starts"),
            Self::OutOfBounds { name } => write!(f, "tensor {name:?} lies outside the file"),
            Self::LengthMismatch {
                name,
                declared_bytes,
                expected_bytes,
            } => write!(
                f,
                "tensor {name:?} spans {declared_bytes} bytes but its shape needs \
                 {expected_bytes}"
            ),
            Self::Hole { at_bytes } => write!(f, "data byte {at_bytes} belongs to no tensor"),
            Self::Overlap { at_bytes } => write!(f, "tensors overlap at data byte {at_bytes}"),
            Self::BadMagic => f.write_str("the file does not start with the GGUF magic"),
            Self::UnsupportedVersion { version } => {
                write!(f, "GGUF version {version} is not supported")
            }
            Self::BigEndian => f.write_str("big-endian GGUF files are not supported"),
            Self::InvalidValueType { value_type } => {
                write!(f, "metadata value type {value_type} is not valid")
            }
            Self::NestedArray => f.write_str("nested metadata arrays are not supported"),
            Self::ArrayTooLong { found, max } => {
                write!(f, "a {found}-element array exceeds the bound of {max}")
            }
            Self::StringTooLong { found, max } => {
                write!(f, "a {found}-byte string exceeds the bound of {max}")
            }
            Self::InvalidAlignment { alignment } => {
                write!(f, "alignment {alignment} is not a power of two")
            }
            Self::AlignmentType => f.write_str("general.alignment must be a u32"),
            Self::UnexpectedOffset {
                name,
                offset_bytes,
                expected_bytes,
            } => write!(
                f,
                "tensor {name:?} starts at data byte {offset_bytes}, expected {expected_bytes}"
            ),
            Self::TrailingBytes {
                data_end_bytes,
                file_length_bytes,
            } => write!(
                f,
                "the data ends at byte {data_end_bytes} but the file has {file_length_bytes}"
            ),
            Self::Io { kind } => write!(f, "reading the header failed: {kind}"),
        }
    }
}

impl std::error::Error for IndexError {}

/// Indexes a weights file of `format`. The reader is positioned at the start of the file
/// and `file_length_bytes` is the file's length.
pub fn index_weights<R: Read>(
    format: WeightFormat,
    reader: &mut R,
    file_length_bytes: u64,
    bounds: &IndexerBounds,
) -> Result<IndexedFile, IndexError> {
    match format {
        WeightFormat::Safetensors => {
            super::safetensors::index_safetensors(reader, file_length_bytes, bounds)
        }
        WeightFormat::Gguf => super::gguf::index_gguf(reader, file_length_bytes, bounds),
    }
}

pub(super) fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), IndexError> {
    reader
        .read_exact(buffer)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => IndexError::Truncated,
            kind => IndexError::Io { kind },
        })
}

/// Checks a tensor name read from a header against the bound and [`TensorName`] rules.
pub(super) fn tensor_name(name: String, bounds: &IndexerBounds) -> Result<TensorName, IndexError> {
    let found_bytes = name.len() as u64;
    if found_bytes > bounds.max_name_bytes {
        return Err(IndexError::NameTooLong {
            found_bytes,
            max_bytes: bounds.max_name_bytes,
        });
    }
    TensorName::new(name).map_err(|error| IndexError::InvalidName { error })
}
