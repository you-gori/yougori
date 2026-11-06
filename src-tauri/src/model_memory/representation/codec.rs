//! The existing lossless codec on real bytes (GPU §4.9 plan line 746, GPU-W08, GPU-T34 and
//! GPU-T35): zstd frames decoded only through a bounded sink, a strict frame-header check
//! before any decoding, and raw escape blocks where compression loses.
//!
//! The manifest (§3.3) already records, per extent, either raw storage or a zstd encoding
//! with its own digest. A raw escape block is therefore an extent stored raw beside encoded
//! ones; no second container format exists. [`prepare_file`] makes that choice per codec
//! block and returns builder inputs for the manifest.

use zstd::stream::raw::{DParameter, Decoder, InBuffer, Operation, OutBuffer};

use std::fmt;

use crate::foundation::ids::ContentKey;
use crate::foundation::report::{Measured, NotMeasuredReason};
use crate::model_memory::manifest::{
    BoundedOutput, Codec, CodecFormat, CodecVersion, DecodeError, EncodedDigest, EncodingInput,
    ExtentDecoder, ExtentInput, RelativePath, ZstdFrameParameters,
};

/// The zstd frame magic number, little-endian on the wire (RFC 8878 §3.1.1).
pub const ZSTD_MAGIC: u32 = 0xFD2F_B528;

/// The smallest window a zstd decoder accepts as a limit (`ZSTD_WINDOWLOG_ABSOLUTEMIN`).
pub const MIN_WINDOW_LOG: u32 = 10;

/// The largest window this module ever lets a decoder allocate: 2 GiB, zstd's 64-bit
/// maximum. Frames are further held to [`allowed_window_bytes`] of their output bound.
pub const MAX_WINDOW_LOG: u32 = 31;

/// Decoded bytes produced per decoder step; the only buffer besides zstd's own window.
pub const DECODE_CHUNK_BYTES: usize = 64 * 1024;

/// The default zstd level for prepared representations.
pub const DEFAULT_LEVEL: i32 = 3;

/// Why encoding or a standalone bounded decode failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The zstd encoder reported an error.
    Encode,
    /// A codec block size must be more than zero.
    ZeroBlockSize,
    /// A length does not fit this platform's address space.
    TooLarge {
        bytes: u64,
    },
    Decode(DecodeError),
    /// The frame decoded to fewer bytes than declared.
    DecodedLength {
        expected_bytes: u64,
        found_bytes: u64,
    },
}

impl From<DecodeError> for CodecError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode => f.write_str("the zstd encoder failed"),
            Self::ZeroBlockSize => f.write_str("a codec block size must be more than zero"),
            Self::TooLarge { bytes } => write!(f, "{bytes} bytes do not fit in memory here"),
            Self::Decode(error) => error.fmt(f),
            Self::DecodedLength {
                expected_bytes,
                found_bytes,
            } => write!(f, "decoded {found_bytes} bytes, expected {expected_bytes}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// The header of one zstd frame (RFC 8878 §3.1.1.1), read before any decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub header_bytes: usize,
    pub window_bytes: u64,
    pub content_bytes: Option<u64>,
    pub dictionary_id: Option<u32>,
    pub checksum: bool,
    pub single_segment: bool,
}

/// The largest window a frame bounded to `limit_bytes` may declare: the next power of two
/// at or above the bound, at least 1 KiB, at most 2 GiB. A window larger than the output
/// can never be referenced, so it only costs decoder memory (GPU-T35).
pub fn allowed_window_bytes(limit_bytes: u64) -> u64 {
    let floor = 1u64 << MIN_WINDOW_LOG;
    let ceiling = 1u64 << MAX_WINDOW_LOG;
    limit_bytes
        .max(floor)
        .checked_next_power_of_two()
        .map_or(ceiling, |window| window.min(ceiling))
}

fn little_endian(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

/// Reads and checks a frame header against the declared decoded length, before any
/// decoder allocates (GPU-T35: bounded rejection before out-of-range access).
///
/// Refused: anything but one standard zstd frame (skippable frames included), a reserved
/// bit, a truncated header, a window above [`allowed_window_bytes`] or a declared content
/// size above the bound ([`DecodeError::BoundExceeded`]), a content size below it, and a
/// dictionary id without a dictionary.
pub fn inspect_frame_header(
    encoded: &[u8],
    limit_bytes: u64,
    dictionary: Option<&[u8]>,
) -> Result<FrameHeader, DecodeError> {
    let magic = encoded.get(0..4).ok_or(DecodeError::Corrupt)?;
    if little_endian(magic) != u64::from(ZSTD_MAGIC) {
        return Err(DecodeError::Corrupt);
    }
    let descriptor = *encoded.get(4).ok_or(DecodeError::Corrupt)?;
    let content_flag = descriptor >> 6;
    let single_segment = descriptor & 0x20 != 0;
    if descriptor & 0x08 != 0 {
        return Err(DecodeError::Corrupt);
    }
    let checksum = descriptor & 0x04 != 0;
    let dictionary_flag = descriptor & 0x03;
    let mut position = 5usize;
    let mut window_bytes = 0u64;
    if !single_segment {
        let window = *encoded.get(position).ok_or(DecodeError::Corrupt)?;
        position += 1;
        let window_log = u32::from(window >> 3) + MIN_WINDOW_LOG;
        let base = 1u64 << window_log;
        window_bytes = base + (base / 8) * u64::from(window & 0x07);
    }
    let dictionary_bytes = match dictionary_flag {
        0 => 0usize,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dictionary_id = if dictionary_bytes == 0 {
        None
    } else {
        let field = encoded
            .get(position..position + dictionary_bytes)
            .ok_or(DecodeError::Corrupt)?;
        position += dictionary_bytes;
        u32::try_from(little_endian(field)).ok()
    };
    let content_field_bytes = match content_flag {
        0 if single_segment => 1usize,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let content_bytes = if content_field_bytes == 0 {
        None
    } else {
        let field = encoded
            .get(position..position + content_field_bytes)
            .ok_or(DecodeError::Corrupt)?;
        position += content_field_bytes;
        let value = little_endian(field);
        Some(if content_field_bytes == 2 {
            value + 256
        } else {
            value
        })
    };
    if single_segment {
        window_bytes = content_bytes.unwrap_or(0);
    }
    let bound = DecodeError::BoundExceeded { limit_bytes };
    if window_bytes > allowed_window_bytes(limit_bytes) {
        return Err(bound);
    }
    match content_bytes {
        Some(declared) if declared > limit_bytes => return Err(bound),
        Some(declared) if declared < limit_bytes => return Err(DecodeError::Corrupt),
        _ => {}
    }
    if dictionary_id.is_some_and(|id| id != 0) && dictionary.is_none() {
        return Err(DecodeError::DictionaryRequired);
    }
    Ok(FrameHeader {
        header_bytes: position,
        window_bytes,
        content_bytes,
        dictionary_id,
        checksum,
        single_segment,
    })
}

fn ceil_log2(value: u64) -> u32 {
    if value <= 1 {
        0
    } else {
        64 - (value - 1).leading_zeros()
    }
}

/// Decodes exactly one zstd frame, handing decoded bytes to `sink` in chunks of at most
/// [`DECODE_CHUNK_BYTES`]; returns the decoded length. The header is checked first, the
/// decoder's window is capped to it, more than `limit_bytes` of output is refused as soon
/// as it appears, and trailing bytes after the frame are refused.
pub fn decode_frame(
    encoded: &[u8],
    dictionary: Option<&[u8]>,
    limit_bytes: u64,
    mut sink: impl FnMut(&[u8]) -> Result<(), DecodeError>,
) -> Result<u64, DecodeError> {
    let header = inspect_frame_header(encoded, limit_bytes, dictionary)?;
    let window_log = ceil_log2(header.window_bytes).clamp(MIN_WINDOW_LOG, MAX_WINDOW_LOG);
    let mut decoder =
        Decoder::with_dictionary(dictionary.unwrap_or(&[])).map_err(|_| DecodeError::Corrupt)?;
    decoder
        .set_parameter(DParameter::WindowLogMax(window_log))
        .map_err(|_| DecodeError::Corrupt)?;
    let chunk_bytes = usize::try_from(limit_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(1)
        .clamp(1, DECODE_CHUNK_BYTES);
    let mut chunk = vec![0u8; chunk_bytes];
    let mut input = InBuffer::around(encoded);
    let mut decoded_bytes = 0u64;
    loop {
        let consumed_before = input.pos();
        let mut output = OutBuffer::around(&mut chunk[..]);
        let hint = decoder
            .run(&mut input, &mut output)
            .map_err(|_| DecodeError::Corrupt)?;
        let written = output.pos();
        let piece = chunk.get(..written).ok_or(DecodeError::Corrupt)?;
        decoded_bytes = decoded_bytes.saturating_add(written as u64);
        if decoded_bytes > limit_bytes {
            return Err(DecodeError::BoundExceeded { limit_bytes });
        }
        sink(piece)?;
        if hint == 0 {
            break;
        }
        if written == 0 && input.pos() == consumed_before {
            // No input left to make progress with: a truncated frame.
            return Err(DecodeError::Corrupt);
        }
    }
    if input.pos() != encoded.len() {
        return Err(DecodeError::Corrupt);
    }
    Ok(decoded_bytes)
}

/// Decodes one frame to exactly `true_length_bytes`. The buffer grows only as decoded
/// bytes arrive, so a lying length never allocates more than the frame produces.
pub fn decode_bounded(
    encoded: &[u8],
    dictionary: Option<&[u8]>,
    true_length_bytes: u64,
) -> Result<Vec<u8>, CodecError> {
    let mut decoded = Vec::new();
    decode_frame(encoded, dictionary, true_length_bytes, |piece| {
        decoded.extend_from_slice(piece);
        Ok(())
    })?;
    if decoded.len() as u64 != true_length_bytes {
        return Err(CodecError::DecodedLength {
            expected_bytes: true_length_bytes,
            found_bytes: decoded.len() as u64,
        });
    }
    Ok(decoded)
}

/// Encodes `bytes` as one zstd frame that records its content size, so the header check
/// can compare it with the declared length.
pub fn encode(bytes: &[u8], level: i32, dictionary: Option<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let mut compressor = match dictionary {
        Some(dictionary) => zstd::bulk::Compressor::with_dictionary(level, dictionary),
        None => zstd::bulk::Compressor::new(level),
    }
    .map_err(|_| CodecError::Encode)?;
    compressor.compress(bytes).map_err(|_| CodecError::Encode)
}

/// The zstd decoder the manifest's [`ExtentDecoder`] port expects (§3.3 decompression
/// bounds): it decodes RFC 8878 frames ([`CodecVersion::ZstdRfc8878`]), refuses a frame
/// whose header disagrees with the extent's declared dictionary id, checksum flag or
/// window bound (GPU-W08), and writes only through the [`BoundedOutput`] it is given.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZstdDecoder;

impl ExtentDecoder for ZstdDecoder {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &[CodecVersion::ZstdRfc8878]
    }

    fn decode(
        &self,
        format: &CodecFormat,
        encoded: &[u8],
        dictionary: Option<&[u8]>,
        output: &mut BoundedOutput,
    ) -> Result<(), DecodeError> {
        let CodecFormat::ZstdRfc8878(declared) = format;
        let limit_bytes = output
            .written_bytes()
            .saturating_add(output.remaining_bytes()) as u64;
        check_frame_parameters(
            &inspect_frame_header(encoded, limit_bytes, dictionary)?,
            declared,
        )?;
        decode_frame(encoded, dictionary, limit_bytes, |piece| {
            output.write(piece)
        })
        .map(|_| ())
    }
}

/// Refuses a frame whose header disagrees with the frame parameters its extent declares
/// (GPU-W08 codec versions): another dictionary id or checksum flag, or a window above
/// the declared bound.
pub fn check_frame_parameters(
    header: &FrameHeader,
    declared: &ZstdFrameParameters,
) -> Result<(), DecodeError> {
    if header.dictionary_id.unwrap_or(0) != declared.dictionary_id {
        return Err(DecodeError::FormatMismatch {
            field: "dictionary_id",
        });
    }
    if header.checksum != declared.content_checksum {
        return Err(DecodeError::FormatMismatch {
            field: "content_checksum",
        });
    }
    if header.window_bytes > declared.max_window_bytes {
        return Err(DecodeError::FormatMismatch {
            field: "max_window_bytes",
        });
    }
    Ok(())
}

/// The codec format [`prepare_file`] declares for blocks of `block_bytes` encoded by
/// [`encode`] without a dictionary: RFC 8878 frames without a dictionary id or content
/// checksum, whose window is at most [`allowed_window_bytes`] of the block size.
pub fn zstd_format(block_bytes: u64) -> CodecFormat {
    CodecFormat::ZstdRfc8878(ZstdFrameParameters {
        dictionary_id: 0,
        content_checksum: false,
        max_window_bytes: allowed_window_bytes(block_bytes),
    })
}

/// When a block is stored encoded rather than raw (GPU §4.9 line 744: some blocks "may
/// not compress enough to justify headers").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscapePolicy {
    pub level: i32,
    /// What one encoded block adds to the representation beyond its encoded bytes: its
    /// manifest entry (codec, location, encoded digest) and any per-block header.
    pub metadata_bytes_per_encoded_block: u64,
}

/// How one codec block is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockEncoding {
    /// A raw escape block: compression did not save more than its metadata.
    Raw,
    Zstd {
        encoded: Vec<u8>,
    },
}

/// Encodes a block and keeps the encoding only when the encoded bytes plus the block's
/// metadata are strictly fewer than the raw bytes; otherwise the block escapes raw.
pub fn choose_block(raw: &[u8], policy: &EscapePolicy) -> Result<BlockEncoding, CodecError> {
    let encoded = encode(raw, policy.level, None)?;
    let encoded_total =
        (encoded.len() as u64).saturating_add(policy.metadata_bytes_per_encoded_block);
    if encoded_total < raw.len() as u64 {
        Ok(BlockEncoding::Zstd { encoded })
    } else {
        Ok(BlockEncoding::Raw)
    }
}

/// One source file cut into codec blocks, each stored raw or encoded, as manifest
/// builder inputs (§3.3 extents; GPU-W08 "Select raw escape blocks when compression
/// loses").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFile {
    pub extents: Vec<ExtentInput>,
    /// The prepared file holding every encoded block, when any block is encoded.
    pub prepared: Option<(RelativePath, Vec<u8>)>,
    /// The codec block size g_c, set exactly when some block is encoded (the manifest
    /// refuses it otherwise).
    pub codec_block_bytes: Option<u64>,
    pub encoded_blocks: usize,
    pub escaped_blocks: usize,
}

/// Cuts `bytes` into blocks of `block_bytes` and stores each raw or zstd by
/// [`choose_block`]. Encoded blocks are laid out back to back in `prepared_path`.
pub fn prepare_file(
    file: &RelativePath,
    bytes: &[u8],
    block_bytes: u64,
    prepared_path: &RelativePath,
    policy: &EscapePolicy,
) -> Result<PreparedFile, CodecError> {
    let block =
        usize::try_from(block_bytes).map_err(|_| CodecError::TooLarge { bytes: block_bytes })?;
    if block == 0 {
        return Err(CodecError::ZeroBlockSize);
    }
    let format = zstd_format(block_bytes);
    let mut extents = Vec::new();
    let mut prepared = Vec::new();
    let mut encoded_blocks = 0usize;
    let mut escaped_blocks = 0usize;
    for (index, chunk) in bytes.chunks(block).enumerate() {
        let logical_offset_bytes = (index as u64).saturating_mul(block_bytes);
        let encoding = match choose_block(chunk, policy)? {
            BlockEncoding::Raw => {
                escaped_blocks += 1;
                EncodingInput::Raw
            }
            BlockEncoding::Zstd { encoded } => {
                encoded_blocks += 1;
                let input = EncodingInput::Encoded {
                    format,
                    dictionary: None,
                    prepared_file: prepared_path.clone(),
                    offset_bytes: prepared.len() as u64,
                    length_bytes: encoded.len() as u64,
                    digest: EncodedDigest::of(format, None, &encoded),
                };
                prepared.extend_from_slice(&encoded);
                input
            }
        };
        extents.push(ExtentInput {
            file: file.clone(),
            logical_offset_bytes,
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding,
        });
    }
    let any_encoded = encoded_blocks > 0;
    Ok(PreparedFile {
        extents,
        prepared: any_encoded.then(|| (prepared_path.clone(), prepared)),
        codec_block_bytes: any_encoded.then_some(block_bytes),
        encoded_blocks,
        escaped_blocks,
    })
}

/// One tensor class's ratio under the codec (GPU-W08: "Measure ratio and decode
/// throughput per tensor class, including quantized data").
#[derive(Clone, Debug, PartialEq)]
pub struct ClassProfile {
    pub class: String,
    pub raw_bytes: u64,
    pub encoded_bytes: u64,
    /// `encoded / raw`: the `r` of GPU §2.8, measured on the class's real bytes.
    pub compressed_fraction: f64,
    /// Decoder throughput needs a hardware measurement in an authorized environment, so
    /// it is never filled in here.
    pub decode_raw_bytes_per_second: Measured<f64>,
}

/// Encodes each class's sample bytes and reports its compressed fraction; throughput is
/// "not measured".
pub fn class_profiles(
    classes: &[(&str, &[u8])],
    level: i32,
) -> Result<Vec<ClassProfile>, CodecError> {
    classes
        .iter()
        .map(|(class, bytes)| {
            let encoded = encode(bytes, level, None)?;
            let raw_bytes = bytes.len() as u64;
            Ok(ClassProfile {
                class: (*class).to_string(),
                raw_bytes,
                encoded_bytes: encoded.len() as u64,
                compressed_fraction: if raw_bytes == 0 {
                    1.0
                } else {
                    encoded.len() as f64 / raw_bytes as f64
                },
                decode_raw_bytes_per_second: Measured::not_measured(
                    NotMeasuredReason::InstrumentUnavailable,
                ),
            })
        })
        .collect()
}
