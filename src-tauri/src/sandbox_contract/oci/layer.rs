//! Layer reading over in-memory blobs (VM-W33 "malicious archive paths, links, metadata,
//! decompression bombs, corrupt layers"; VM-P37; VM-CP-30).
//!
//! A layer is decoded exactly as its media type says: plain tar, gzip (one member) or zstd
//! (one frame, with a bounded window). Compressed bytes are bounded before decoding;
//! expanded bytes, the expansion ratio against the compressed blob and the image-wide
//! budget are metered on every read, and each read asks the decoder for at most one byte
//! past the tightest limit, so decoding stops at the first limit and a bomb never fully
//! expands. Entry count and single-file size are checked from each header before its data
//! is read. Truncated, corrupt and trailing-garbage streams are refused with typed reasons,
//! and the expanded stream's sha256 must equal the config's diff_id.
//!
//! Every entry goes through V05: its name through [`ImageName::parse`] as it is read, and
//! the whole entry list through [`check_archive`] (names, collisions, links, hard links to
//! an earlier regular file of the same layer, devices, sizes and ratio). For a compressed
//! layer the share of compressed bytes each entry consumed is not observable, so each file
//! is declared to V05 with the whole blob's size, an upper bound; the stream meter enforces
//! the layer's ratio. This module adds only what is OCI-specific: setuid and setgid bits are
//! refused (the strict choice over stripping), and whiteout entries are classified and
//! checked here and applied by [`TreeBuilder`](super::TreeBuilder).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufRead, Read};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::archive::check_image_archive as check_archive;
use super::digest::{BlobReference, LayerCodec, MediaType, OciDigest, VerifiedBlob};
use super::limits::{detail, len_u64, ImportLimits};
use super::tar::{ByteSource, TarEntry, TarKind, TarReader, TarRefusal};
use crate::sandbox_contract::files::{
    ArchiveEntry, ArchiveEntryKind, ImageArchiveRefusal as ArchiveRefusal, ImageName, NameRefusal,
};

/// Why a layer's byte stream was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum StreamRefusal {
    /// The blob is not declared as a layer.
    NotALayer {
        media_type: MediaType,
    },
    CompressedTooLarge {
        size_bytes: u64,
        limit_bytes: u64,
    },
    ImageCompressedTooLarge {
        total_bytes: u64,
        limit_bytes: u64,
    },
    ExpandedTooLarge {
        expanded_bytes: u64,
        limit_bytes: u64,
    },
    ImageExpandedTooLarge {
        expanded_bytes: u64,
        limit_bytes: u64,
    },
    RatioExceeded {
        expanded_bytes: u64,
        compressed_bytes: u64,
        max_ratio: u64,
    },
    /// The compressed stream ended early.
    Truncated {
        codec: LayerCodec,
    },
    /// The decoder refused the stream (bad header, bad data, bad checksum, a window larger
    /// than allowed).
    Corrupt {
        codec: LayerCodec,
        detail: String,
    },
    /// Bytes after the one gzip member or zstd frame.
    TrailingData {
        codec: LayerCodec,
        trailing_bytes: u64,
    },
    /// The expanded stream is not the layer the config names.
    DiffIdMismatch {
        declared: OciDigest,
        found: OciDigest,
    },
}

impl fmt::Display for StreamRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotALayer { media_type } => write!(f, "{media_type} is not a layer"),
            Self::CompressedTooLarge {
                size_bytes,
                limit_bytes,
            } => write!(f, "a {size_bytes}-byte layer blob; at most {limit_bytes}"),
            Self::ImageCompressedTooLarge {
                total_bytes,
                limit_bytes,
            } => write!(
                f,
                "{total_bytes} compressed bytes in the image; at most {limit_bytes}"
            ),
            Self::ExpandedTooLarge {
                expanded_bytes,
                limit_bytes,
            } => write!(
                f,
                "the layer expanded past {limit_bytes} bytes ({expanded_bytes})"
            ),
            Self::ImageExpandedTooLarge {
                expanded_bytes,
                limit_bytes,
            } => write!(
                f,
                "the image expanded past its remaining {limit_bytes} bytes ({expanded_bytes})"
            ),
            Self::RatioExceeded {
                expanded_bytes,
                compressed_bytes,
                max_ratio,
            } => write!(
                f,
                "{compressed_bytes} compressed bytes expanded past {max_ratio}x ({expanded_bytes})"
            ),
            Self::Truncated { codec } => write!(f, "the {codec:?} stream is truncated"),
            Self::Corrupt { codec, detail } => {
                write!(f, "the {codec:?} stream is corrupt: {detail}")
            }
            Self::TrailingData {
                codec,
                trailing_bytes,
            } => write!(f, "{trailing_bytes} bytes after the {codec:?} stream"),
            Self::DiffIdMismatch { declared, found } => {
                write!(
                    f,
                    "the layer expands to {found}, not the diff_id {declared}"
                )
            }
        }
    }
}

/// Why a whiteout entry was refused (OCI whiteouts; VM-W33).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum WhiteoutRefusal {
    /// A `.wh.` name that is not a regular file.
    NotRegularFile { index: usize, name: ImageName },
    /// Whiteouts are empty files.
    NotEmpty {
        index: usize,
        name: ImageName,
        size_bytes: u64,
    },
    /// `.wh..wh.` is reserved; only `.wh..wh..opq` is defined.
    ReservedName { index: usize, name: ImageName },
    /// The hidden name is empty or refused by V05.
    UnsafeTarget {
        index: usize,
        name: ImageName,
        refusal: NameRefusal,
    },
    /// The hidden name is not in the whiteout's own directory.
    OutsideDirectory { index: usize, name: ImageName },
    /// A whiteout hides something its own layer adds: whiteouts apply only to lower
    /// layers.
    HidesSameLayer {
        index: usize,
        name: ImageName,
        hidden: ImageName,
    },
}

impl fmt::Display for WhiteoutRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegularFile { index, name } => {
                write!(
                    f,
                    "entry {index} ({name}) is a whiteout name but not a file"
                )
            }
            Self::NotEmpty {
                index,
                name,
                size_bytes,
            } => write!(f, "whiteout {index} ({name}) has {size_bytes} bytes"),
            Self::ReservedName { index, name } => {
                write!(
                    f,
                    "entry {index} ({name}) uses the reserved .wh..wh. prefix"
                )
            }
            Self::UnsafeTarget {
                index,
                name,
                refusal,
            } => write!(
                f,
                "whiteout {index} ({name}) hides an unsafe name: {refusal}"
            ),
            Self::OutsideDirectory { index, name } => {
                write!(f, "whiteout {index} ({name}) reaches outside its directory")
            }
            Self::HidesSameLayer {
                index,
                name,
                hidden,
            } => write!(
                f,
                "whiteout {index} ({name}) hides {hidden} from its own layer"
            ),
        }
    }
}

/// Why a layer was refused (VM-P37).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LayerRefusal {
    Stream {
        refusal: StreamRefusal,
    },
    Tar {
        refusal: TarRefusal,
    },
    /// V05's archive checks.
    Archive {
        refusal: ArchiveRefusal,
    },
    TooManyEntries {
        entries: usize,
        limit: usize,
    },
    ImageTooManyEntries {
        entries: usize,
        limit: usize,
    },
    /// Setuid and setgid bits are refused rather than stripped.
    SetuidOrSetgid {
        index: usize,
        name: ImageName,
        mode: u32,
    },
    Whiteout {
        refusal: WhiteoutRefusal,
    },
}

impl fmt::Display for LayerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream { refusal } => refusal.fmt(f),
            Self::Tar { refusal } => refusal.fmt(f),
            Self::Archive { refusal } => refusal.fmt(f),
            Self::TooManyEntries { entries, limit } => {
                write!(f, "more than {limit} entries in the layer ({entries})")
            }
            Self::ImageTooManyEntries { entries, limit } => write!(
                f,
                "more than the image's remaining {limit} entries ({entries})"
            ),
            Self::SetuidOrSetgid { index, name, mode } => {
                write!(
                    f,
                    "entry {index} ({name}) has mode {mode:o} with setuid or setgid"
                )
            }
            Self::Whiteout { refusal } => refusal.fmt(f),
        }
    }
}

impl std::error::Error for LayerRefusal {}

fn stream(refusal: StreamRefusal) -> LayerRefusal {
    LayerRefusal::Stream { refusal }
}

/// What one entry of a layer is, after V05 and the whiteout checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LayerEntryKind {
    Directory,
    File {
        size_bytes: u64,
        sha256: OciDigest,
        /// Where the data starts in the layer's expanded tar stream.
        data_offset_bytes: u64,
    },
    Symlink {
        target: String,
    },
    /// A second name for an earlier regular file of the same layer.
    HardLink {
        target: ImageName,
    },
    /// Hides `target` from the layers below.
    Whiteout {
        target: ImageName,
    },
    /// Hides everything below in `directory` (the root when `None`).
    OpaqueWhiteout {
        directory: Option<ImageName>,
    },
}

/// One checked entry of a layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayerEntry {
    pub index: usize,
    pub name: ImageName,
    pub kind: LayerEntryKind,
    /// Permission bits; setuid and setgid never appear.
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    /// Allowlisted `user.*` extended attributes.
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

/// A layer that passed every check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayerReport {
    pub reference: BlobReference,
    pub diff_id: OciDigest,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub entries: Vec<LayerEntry>,
}

/// What the rest of an image may still use: compressed and expanded bytes and entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ImageBudget {
    pub remaining_compressed_bytes: u64,
    pub remaining_expanded_bytes: u64,
    pub remaining_entries: usize,
}

impl ImageBudget {
    /// The whole image's budget under `limits`.
    pub fn new(limits: &ImportLimits) -> Self {
        Self {
            remaining_compressed_bytes: limits.max_image_compressed_bytes,
            remaining_expanded_bytes: limits.max_image_expanded_bytes,
            remaining_entries: limits.max_image_entries,
        }
    }
}

/// A [`BufRead`] over a slice that remembers how much the decoder consumed.
struct CountingSlice<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl CountingSlice<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn rest(&self) -> &[u8] {
        self.bytes.get(self.position..).unwrap_or(&[])
    }
}

impl Read for CountingSlice<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let rest = self.rest();
        let count = rest.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..count), rest.get(..count)) {
            target.copy_from_slice(source);
        }
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for CountingSlice<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(self.rest())
    }

    fn consume(&mut self, amount: usize) {
        self.position = self.position.saturating_add(amount).min(self.bytes.len());
    }
}

enum Decoder<'a> {
    Plain(CountingSlice<'a>),
    Gzip(Box<flate2::bufread::GzDecoder<CountingSlice<'a>>>),
    Zstd(Box<zstd::stream::read::Decoder<'static, CountingSlice<'a>>>),
}

/// The metered, hashed expanded stream of one layer.
struct MeteredStream<'a> {
    decoder: Decoder<'a>,
    codec: LayerCodec,
    compressed_bytes: u64,
    expanded_bytes: u64,
    layer_limit_bytes: u64,
    ratio_limit_bytes: u64,
    image_limit_bytes: u64,
    max_ratio: u64,
    hasher: Sha256,
}

impl<'a> MeteredStream<'a> {
    fn new(
        bytes: &'a [u8],
        codec: LayerCodec,
        limits: &ImportLimits,
        image_limit_bytes: u64,
    ) -> Result<Self, LayerRefusal> {
        let slice = CountingSlice { bytes, position: 0 };
        let corrupt = |error: io::Error| {
            stream(StreamRefusal::Corrupt {
                codec,
                detail: detail(error),
            })
        };
        let decoder = match codec {
            LayerCodec::Uncompressed => Decoder::Plain(slice),
            LayerCodec::Gzip => Decoder::Gzip(Box::new(flate2::bufread::GzDecoder::new(slice))),
            LayerCodec::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(slice)
                    .map_err(corrupt)?
                    .single_frame();
                decoder
                    .window_log_max(limits.max_zstd_window_log)
                    .map_err(corrupt)?;
                Decoder::Zstd(Box::new(decoder))
            }
        };
        let compressed_bytes = len_u64(bytes.len());
        Ok(Self {
            decoder,
            codec,
            compressed_bytes,
            expanded_bytes: 0,
            layer_limit_bytes: limits.max_layer_expanded_bytes,
            ratio_limit_bytes: compressed_bytes.saturating_mul(limits.max_ratio),
            image_limit_bytes,
            max_ratio: limits.max_ratio,
            hasher: Sha256::new(),
        })
    }

    fn exceeded(&self) -> Option<StreamRefusal> {
        let expanded_bytes = self.expanded_bytes;
        [
            self.layer_limit_bytes,
            self.ratio_limit_bytes,
            self.image_limit_bytes,
        ]
        .into_iter()
        .enumerate()
        .filter(|(_, limit)| expanded_bytes > *limit)
        .min_by_key(|(_, limit)| *limit)
        .map(|(which, limit_bytes)| match which {
            0 => StreamRefusal::ExpandedTooLarge {
                expanded_bytes,
                limit_bytes,
            },
            1 => StreamRefusal::RatioExceeded {
                expanded_bytes,
                compressed_bytes: self.compressed_bytes,
                max_ratio: self.max_ratio,
            },
            _ => StreamRefusal::ImageExpandedTooLarge {
                expanded_bytes,
                limit_bytes,
            },
        })
    }

    /// Checks that the decoder consumed the whole blob and returns the expanded size and
    /// its sha256 digest.
    fn finish(self) -> Result<(u64, OciDigest), LayerRefusal> {
        let trailing = match self.decoder {
            Decoder::Plain(slice) => slice.remaining(),
            Decoder::Gzip(decoder) => decoder.into_inner().remaining(),
            Decoder::Zstd(decoder) => decoder.finish().remaining(),
        };
        if trailing > 0 {
            return Err(stream(StreamRefusal::TrailingData {
                codec: self.codec,
                trailing_bytes: len_u64(trailing),
            }));
        }
        Ok((self.expanded_bytes, OciDigest::from_hasher(self.hasher)))
    }
}

impl ByteSource for MeteredStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, LayerRefusal> {
        let ceiling = self
            .layer_limit_bytes
            .min(self.ratio_limit_bytes)
            .min(self.image_limit_bytes);
        let allowance = ceiling
            .saturating_sub(self.expanded_bytes)
            .saturating_add(1);
        let want = usize::try_from(allowance)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let target = buffer.get_mut(..want).unwrap_or(&mut []);
        let result = match &mut self.decoder {
            Decoder::Plain(slice) => slice.read(target),
            Decoder::Gzip(decoder) => decoder.read(target),
            Decoder::Zstd(decoder) => decoder.read(target),
        };
        let codec = self.codec;
        let read = result.map_err(|error| {
            stream(if error.kind() == io::ErrorKind::UnexpectedEof {
                StreamRefusal::Truncated { codec }
            } else {
                StreamRefusal::Corrupt {
                    codec,
                    detail: detail(error),
                }
            })
        })?;
        self.expanded_bytes = self.expanded_bytes.saturating_add(len_u64(read));
        if let Some(refusal) = self.exceeded() {
            return Err(stream(refusal));
        }
        self.hasher.update(target.get(..read).unwrap_or(&[]));
        Ok(read)
    }
}

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const RESERVED_WHITEOUT_PREFIX: &str = ".wh..wh.";

/// Classifies a `.wh.` entry; `None` for every other name.
fn classify_whiteout(
    entry: &TarEntry,
    name: &ImageName,
) -> Result<Option<LayerEntryKind>, WhiteoutRefusal> {
    let index = entry.index;
    let file_name = name.file_name();
    let Some(hidden) = file_name.strip_prefix(WHITEOUT_PREFIX) else {
        return Ok(None);
    };
    if entry.kind != TarKind::Regular {
        return Err(WhiteoutRefusal::NotRegularFile {
            index,
            name: name.clone(),
        });
    }
    if entry.size_bytes != 0 {
        return Err(WhiteoutRefusal::NotEmpty {
            index,
            name: name.clone(),
            size_bytes: entry.size_bytes,
        });
    }
    if file_name == OPAQUE_WHITEOUT {
        return Ok(Some(LayerEntryKind::OpaqueWhiteout {
            directory: name.parent(),
        }));
    }
    if file_name.starts_with(RESERVED_WHITEOUT_PREFIX) {
        return Err(WhiteoutRefusal::ReservedName {
            index,
            name: name.clone(),
        });
    }
    if hidden.is_empty() {
        return Err(WhiteoutRefusal::UnsafeTarget {
            index,
            name: name.clone(),
            refusal: NameRefusal::Empty,
        });
    }
    let text = match name.parent() {
        Some(parent) => format!("{parent}/{hidden}"),
        None => hidden.to_owned(),
    };
    let target = ImageName::parse(&text).map_err(|refusal| WhiteoutRefusal::UnsafeTarget {
        index,
        name: name.clone(),
        refusal,
    })?;
    if target.parent() != name.parent() {
        return Err(WhiteoutRefusal::OutsideDirectory {
            index,
            name: name.clone(),
        });
    }
    Ok(Some(LayerEntryKind::Whiteout { target }))
}

/// Whether `folded` or anything beneath it is in `present`.
fn covers(present: &BTreeSet<String>, folded: &str) -> bool {
    let below = format!("{folded}/");
    present.contains(folded)
        || present
            .range(below.clone()..)
            .next()
            .is_some_and(|name| name.starts_with(&below))
}

/// Reads one verified layer blob against its config diff_id, within `limits` and what is
/// left of the image's `budget`, which is charged only when the layer passes (VM-W33,
/// VM-P37).
pub fn read_layer(
    blob: &VerifiedBlob,
    diff_id: &OciDigest,
    limits: &ImportLimits,
    budget: &mut ImageBudget,
) -> Result<LayerReport, LayerRefusal> {
    let media_type = blob.reference().media_type;
    let codec = media_type
        .layer_codec()
        .ok_or_else(|| stream(StreamRefusal::NotALayer { media_type }))?;
    let compressed_bytes = len_u64(blob.bytes().len());
    if compressed_bytes > limits.max_layer_compressed_bytes {
        return Err(stream(StreamRefusal::CompressedTooLarge {
            size_bytes: compressed_bytes,
            limit_bytes: limits.max_layer_compressed_bytes,
        }));
    }
    if compressed_bytes > budget.remaining_compressed_bytes {
        return Err(stream(StreamRefusal::ImageCompressedTooLarge {
            total_bytes: compressed_bytes,
            limit_bytes: budget.remaining_compressed_bytes,
        }));
    }
    let mut metered =
        MeteredStream::new(blob.bytes(), codec, limits, budget.remaining_expanded_bytes)?;
    let mut archive = Vec::new();
    let mut read = Vec::new();
    {
        let mut reader = TarReader::new(&mut metered, limits);
        while let Some(entry) = reader.next_entry()? {
            let index = entry.index;
            if index >= limits.max_entries_per_layer {
                return Err(LayerRefusal::TooManyEntries {
                    entries: index.saturating_add(1),
                    limit: limits.max_entries_per_layer,
                });
            }
            if index >= budget.remaining_entries {
                return Err(LayerRefusal::ImageTooManyEntries {
                    entries: index.saturating_add(1),
                    limit: budget.remaining_entries,
                });
            }
            let raw = match entry.kind {
                TarKind::Directory => entry.name.strip_suffix('/').unwrap_or(&entry.name),
                _ => entry.name.as_str(),
            };
            let name = ImageName::parse(raw).map_err(|refusal| LayerRefusal::Archive {
                refusal: ArchiveRefusal::UnsafeName { index, refusal },
            })?;
            let archive_kind = match entry.kind {
                TarKind::Regular => ArchiveEntryKind::File {
                    uncompressed_bytes: entry.size_bytes,
                    compressed_bytes: match codec {
                        LayerCodec::Uncompressed => entry.size_bytes,
                        LayerCodec::Gzip | LayerCodec::Zstd => compressed_bytes,
                    },
                },
                TarKind::Directory => ArchiveEntryKind::Directory,
                TarKind::Symlink => ArchiveEntryKind::Symlink {
                    target: entry.link_target.clone().unwrap_or_default(),
                },
                TarKind::HardLink => ArchiveEntryKind::HardLink {
                    target: entry.link_target.clone().unwrap_or_default(),
                },
                TarKind::CharacterDevice | TarKind::BlockDevice | TarKind::Fifo => {
                    return Err(LayerRefusal::Archive {
                        refusal: ArchiveRefusal::DeviceEntry { index, name },
                    })
                }
            };
            if entry.mode & 0o6000 != 0 {
                return Err(LayerRefusal::SetuidOrSetgid {
                    index,
                    name,
                    mode: entry.mode,
                });
            }
            if entry.kind == TarKind::Regular && entry.size_bytes > limits.max_file_bytes {
                return Err(LayerRefusal::Archive {
                    refusal: ArchiveRefusal::EntryTooLarge {
                        index,
                        uncompressed_bytes: entry.size_bytes,
                        limit: limits.max_file_bytes,
                    },
                });
            }
            let data = match entry.kind {
                TarKind::Regular => Some(reader.entry_data()?),
                _ => None,
            };
            archive.push(ArchiveEntry {
                name: entry.name.clone(),
                kind: archive_kind,
            });
            read.push((entry, name, data));
        }
    }
    let (expanded_bytes, found) = metered.finish()?;
    if found != *diff_id {
        return Err(stream(StreamRefusal::DiffIdMismatch {
            declared: *diff_id,
            found,
        }));
    }
    check_archive(&archive, &limits.layer_archive_limits())
        .map_err(|refusal| LayerRefusal::Archive { refusal })?;

    let mut entries = Vec::with_capacity(read.len());
    for (entry, name, data) in read {
        let whiteout = classify_whiteout(&entry, &name)
            .map_err(|refusal| LayerRefusal::Whiteout { refusal })?;
        let kind = match (whiteout, entry.kind, data) {
            (Some(kind), _, _) => kind,
            (None, TarKind::Regular, Some((sha256, data_offset_bytes))) => LayerEntryKind::File {
                size_bytes: entry.size_bytes,
                sha256,
                data_offset_bytes,
            },
            (None, TarKind::Directory, _) => LayerEntryKind::Directory,
            (None, TarKind::Symlink, _) => LayerEntryKind::Symlink {
                target: entry.link_target.clone().unwrap_or_default(),
            },
            (None, TarKind::HardLink, _) => {
                let text = entry.link_target.clone().unwrap_or_default();
                let target = ImageName::parse(&text).map_err(|_| LayerRefusal::Archive {
                    refusal: ArchiveRefusal::HardLinkTarget {
                        index: entry.index,
                        name: name.clone(),
                    },
                })?;
                LayerEntryKind::HardLink { target }
            }
            (None, _, _) => {
                return Err(LayerRefusal::Archive {
                    refusal: ArchiveRefusal::ExtractionUnknownEntry { index: entry.index },
                })
            }
        };
        entries.push(LayerEntry {
            index: entry.index,
            name,
            kind,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            xattrs: entry.xattrs,
        });
    }

    let present: BTreeSet<String> = entries
        .iter()
        .filter(|entry| {
            !matches!(
                entry.kind,
                LayerEntryKind::Whiteout { .. } | LayerEntryKind::OpaqueWhiteout { .. }
            )
        })
        .map(|entry| entry.name.folded())
        .collect();
    for entry in &entries {
        if let LayerEntryKind::Whiteout { target } = &entry.kind {
            if covers(&present, &target.folded()) {
                return Err(LayerRefusal::Whiteout {
                    refusal: WhiteoutRefusal::HidesSameLayer {
                        index: entry.index,
                        name: entry.name.clone(),
                        hidden: target.clone(),
                    },
                });
            }
        }
    }

    budget.remaining_compressed_bytes = budget
        .remaining_compressed_bytes
        .saturating_sub(compressed_bytes);
    budget.remaining_expanded_bytes = budget
        .remaining_expanded_bytes
        .saturating_sub(expanded_bytes);
    budget.remaining_entries = budget.remaining_entries.saturating_sub(entries.len());
    Ok(LayerReport {
        reference: *blob.reference(),
        diff_id: found,
        compressed_bytes,
        expanded_bytes,
        entries,
    })
}
