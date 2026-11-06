//! Codec identity, codec versions and bounded decoding of encoded extents (GPU part §3.3:
//! codec and dictionary identity; decompression bounds; GPU-W08: "Include codec
//! versions/dictionaries and encoded/decoded identities in manifests").
//!
//! An encoded extent names a [`CodecFormat`]: its [`Codec`], the [`CodecVersion`] of the
//! codec's stream format and every frame parameter a decoder must agree on. The format is
//! bound into the extent's encoded digest, its extent-tree leaf and the canonical
//! manifest encoding, whose schema group lists every format before anything else is read,
//! so a reader refuses an unknown codec or version before it allocates. Raw extents have
//! no codec.
//!
//! No codec library is linked here. A decoder is supplied through [`ExtentDecoder`],
//! declares the versions it decodes, and can only write through a [`BoundedOutput`]
//! sized to the extent's declared true length, which validation has already held to the
//! manifest's per-extent bound, so a decompression bomb stops at the bound instead of
//! exhausting memory.

use std::fmt;

use crate::foundation::ids::DigestBuilder;

/// A codec of an encoded extent (§3.3 extents: codec). Raw extents have no codec: their
/// stored bytes are their decoded bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Codec {
    /// Zstandard (RFC 8878), with or without a dictionary.
    Zstd,
}

impl Codec {
    pub const ALL: [Self; 1] = [Self::Zstd];

    /// The stable tag hashed into encoded digests and extent-tree leaves.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
        }
    }

    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Zstd => 1,
        }
    }

    pub(super) fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|codec| codec.code() == code)
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One version of a codec's stream format (GPU-W08: codec versions). Each version belongs
/// to one codec. A reader knows only these and refuses any other, and a decoder decodes
/// only the versions it declares ([`ExtentDecoder::versions`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodecVersion {
    /// Zstandard frames as RFC 8878 §3.1.1 defines them: each extent is exactly one frame
    /// beginning with the magic number 0xFD2FB528, with no skippable frame and no byte
    /// after it. The frame header's dictionary id, checksum flag and window must agree
    /// with the extent's [`ZstdFrameParameters`].
    ZstdRfc8878,
}

impl CodecVersion {
    pub const ALL: [Self; 1] = [Self::ZstdRfc8878];

    /// The codec this version belongs to.
    pub const fn codec(self) -> Codec {
        match self {
            Self::ZstdRfc8878 => Codec::Zstd,
        }
    }

    /// The stable tag hashed, after the codec's tag, into encoded digests and leaves.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ZstdRfc8878 => "rfc8878",
        }
    }

    /// The version's number among its codec's versions in the canonical encoding.
    pub(super) const fn number(self) -> u16 {
        match self {
            Self::ZstdRfc8878 => 1,
        }
    }

    pub(super) fn from_number(codec: Codec, number: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|version| version.codec() == codec && version.number() == number)
    }
}

impl fmt::Display for CodecVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.codec().tag(), self.tag())
    }
}

/// The smallest window a zstd frame without the Single_Segment_flag declares: 1 KiB
/// (RFC 8878 §3.1.1.1.2, Window_Log at least 10).
pub const ZSTD_MIN_WINDOW_BYTES: u64 = 1 << 10;

/// The largest window bound a zstd format may declare for codec blocks of
/// `codec_block_bytes`: the next power of two at or above the block size, at least
/// [`ZSTD_MIN_WINDOW_BYTES`]. Every encoded extent is one block at most, so a larger
/// window could never be referenced and would only cost decoder memory (§3.3
/// decompression bounds, checked before any decoder allocates).
pub fn zstd_window_ceiling_bytes(codec_block_bytes: u64) -> u64 {
    codec_block_bytes
        .max(ZSTD_MIN_WINDOW_BYTES)
        .checked_next_power_of_two()
        .unwrap_or(u64::MAX)
}

/// The frame parameters every zstd frame of an extent carries and its decoder must agree
/// on (RFC 8878 §3.1.1.1, frame header). A decoder refuses a frame whose header differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZstdFrameParameters {
    /// The frame header's Dictionary_ID; 0 when the frame names no dictionary, which
    /// RFC 8878 treats like an absent field. A raw-content dictionary has no id, so an
    /// extent with a dictionary may still declare 0; a nonzero id needs one.
    pub dictionary_id: u32,
    /// Whether the frame ends with a Content_Checksum (the Content_Checksum_flag).
    pub content_checksum: bool,
    /// The largest Window_Size the frame may declare; a Single_Segment frame's window is
    /// its content size. At most [`zstd_window_ceiling_bytes`] of the codec block size.
    pub max_window_bytes: u64,
}

/// The codec format of an encoded extent: its codec, the codec's stream-format version
/// and the parameters a decoder must agree on (GPU-W08). It is bound into the extent's
/// [`EncodedDigest`](super::EncodedDigest), its extent-tree leaf and the canonical
/// encoding, so changing any part changes the manifest digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodecFormat {
    /// [`CodecVersion::ZstdRfc8878`] frames with these parameters.
    ZstdRfc8878(ZstdFrameParameters),
}

impl CodecFormat {
    pub const fn codec(&self) -> Codec {
        self.version().codec()
    }

    pub const fn version(&self) -> CodecVersion {
        match self {
            Self::ZstdRfc8878(_) => CodecVersion::ZstdRfc8878,
        }
    }

    /// Binds the codec tag, the version tag and every parameter, in that order.
    pub(super) fn bind(&self, builder: DigestBuilder) -> DigestBuilder {
        let builder = builder.str(self.codec().tag()).str(self.version().tag());
        match self {
            Self::ZstdRfc8878(frame) => builder
                .u64(frame.dictionary_id.into())
                .u64(frame.content_checksum.into())
                .u64(frame.max_window_bytes),
        }
    }
}

impl fmt::Display for CodecFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZstdRfc8878(frame) => write!(
                f,
                "{} (dictionary id {}, {}, window at most {} bytes)",
                self.version(),
                frame.dictionary_id,
                if frame.content_checksum {
                    "content checksum"
                } else {
                    "no content checksum"
                },
                frame.max_window_bytes
            ),
        }
    }
}

/// Why a decoder failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The decoder tried to write past the extent's declared true length.
    BoundExceeded { limit_bytes: u64 },
    /// The encoded bytes are not valid for the codec.
    Corrupt,
    /// The codec needs a dictionary and none was given.
    DictionaryRequired,
    /// The encoded bytes disagree with the extent's declared codec format, such as a
    /// frame with another dictionary id or checksum flag, or a window above the bound.
    FormatMismatch { field: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundExceeded { limit_bytes } => write!(
                f,
                "decoding would produce more than the declared {limit_bytes} bytes"
            ),
            Self::Corrupt => f.write_str("the encoded bytes are corrupt"),
            Self::DictionaryRequired => f.write_str("the codec needs its dictionary"),
            Self::FormatMismatch { field } => write!(
                f,
                "the encoded bytes disagree with their declared codec format ({field})"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decodes encoded extents of one codec. Implementations write decoded bytes only through
/// the [`BoundedOutput`] they are given.
pub trait ExtentDecoder {
    fn codec(&self) -> Codec;

    /// The versions of [`Self::codec`] this decoder decodes. Verification hands it only
    /// extents of these versions and refuses any other extent before allocating for it
    /// (GPU-W08). There is no default: every decoder states what it decodes.
    fn versions(&self) -> &[CodecVersion];

    /// Decodes `encoded`, the stored bytes of an extent declared as `format`, whose
    /// version is one of [`Self::versions`]. Bytes that disagree with `format` are
    /// refused with [`DecodeError::FormatMismatch`].
    fn decode(
        &self,
        format: &CodecFormat,
        encoded: &[u8],
        dictionary: Option<&[u8]>,
        output: &mut BoundedOutput,
    ) -> Result<(), DecodeError>;
}

/// Decoder output that refuses any byte past its limit (§3.3 decompression bounds).
#[derive(Debug)]
pub struct BoundedOutput {
    bytes: Vec<u8>,
    limit_bytes: usize,
}

impl BoundedOutput {
    /// Allocates `limit_bytes` up front. Only validated extents reach this, so the limit is
    /// already within the manifest's per-extent bound.
    pub(super) fn with_limit(limit_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit_bytes),
            limit_bytes,
        }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), DecodeError> {
        if data.len() > self.remaining_bytes() {
            return Err(DecodeError::BoundExceeded {
                limit_bytes: self.limit_bytes as u64,
            });
        }
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    pub fn written_bytes(&self) -> usize {
        self.bytes.len()
    }

    pub fn remaining_bytes(&self) -> usize {
        self.limit_bytes.saturating_sub(self.bytes.len())
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
