//! Content identity (S2 CORE-02 "scoped content identity"; GPU part §3.3, lines 529–531).
//!
//! An object's bytes are named by the shared [`ContentKey`] of `ids`: a domain-separated
//! digest of the true length and the bytes (line 529), the same identity transfer and
//! manifests use. It establishes equality and nothing else (S3.3). An object is made of
//! extents, each with its own digest, and the import manifest binds every extent's
//! offset, length and order to that digest. A manifest is validated for bounds, overflow,
//! gaps and overlaps before anything is allocated for it (line 531).

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{
    digest, ContentHasher, ContentKey, ContentLengthError, Digest, DigestBuilder,
};

/// Domain of [`ExtentDigest`]; distinct from [`ContentKey::DOMAIN`], so an extent digest
/// is never mistaken for an object's content key.
pub const EXTENT_DOMAIN: &str = "yougori/catalog/extent/v1";
/// Domain of [`ImportManifest::digest`].
pub const MANIFEST_DOMAIN: &str = "yougori/catalog/manifest/v1";

digest_type!(
    /// The digest of one extent's bytes (CORE-02 "resumable verified data"): the `ids`
    /// digest of the bytes as one part under [`EXTENT_DOMAIN`], the shape of a
    /// [`ContentKey`] under its own domain, so the part's length prefix is the extent's
    /// true length.
    ExtentDigest
);

impl ExtentDigest {
    /// The digest of one extent's `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(digest(EXTENT_DOMAIN, &[bytes]))
    }

    /// Wraps a digest computed elsewhere, such as one read from a publisher's declaration.
    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
}

/// One extent of an object: where it lies and the digest of its bytes (line 525,
/// "logical offsets, lengths ... decoded digests").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtentEntry {
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub digest: ExtentDigest,
}

/// Bounds a manifest must satisfy before anything is allocated for it (line 531).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestLimits {
    pub max_object_bytes: u64,
    pub max_extent_bytes: u64,
    pub max_extents: u32,
}

/// Why a manifest was rejected (line 531: overflow, overlapping ranges, missing data and
/// bounds are validated before allocating).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ManifestError {
    ObjectTooLarge {
        true_length_bytes: u64,
        max_object_bytes: u64,
    },
    TooManyExtents {
        extents: u64,
        max_extents: u32,
    },
    EmptyExtent {
        extent: u32,
    },
    ExtentTooLarge {
        extent: u32,
        length_bytes: u64,
        max_extent_bytes: u64,
    },
    /// The extent starts after the previous one ends: bytes in between are missing.
    Gap {
        extent: u32,
        expected_offset_bytes: u64,
        found_offset_bytes: u64,
    },
    /// The extent starts before the previous one ends, or out of order.
    Overlap {
        extent: u32,
        expected_offset_bytes: u64,
        found_offset_bytes: u64,
    },
    /// Offset plus length overflows.
    Overflow {
        extent: u32,
    },
    /// The extents cover a different length than the declared true length.
    LengthMismatch {
        covered_bytes: u64,
        true_length_bytes: u64,
    },
}

crate::foundation::strict_serde::strict_tag!(ManifestError, "error");

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectTooLarge {
                true_length_bytes,
                max_object_bytes,
            } => write!(
                f,
                "the manifest declares {true_length_bytes} bytes; the limit is {max_object_bytes}"
            ),
            Self::TooManyExtents {
                extents,
                max_extents,
            } => write!(
                f,
                "the manifest lists {extents} extents; the limit is {max_extents}"
            ),
            Self::EmptyExtent { extent } => write!(f, "extent {extent} is empty"),
            Self::ExtentTooLarge {
                extent,
                length_bytes,
                max_extent_bytes,
            } => write!(
                f,
                "extent {extent} is {length_bytes} bytes; the limit is {max_extent_bytes}"
            ),
            Self::Gap {
                extent,
                expected_offset_bytes,
                found_offset_bytes,
            } => write!(
                f,
                "extent {extent} starts at {found_offset_bytes}, leaving bytes from \
                 {expected_offset_bytes} undeclared"
            ),
            Self::Overlap {
                extent,
                expected_offset_bytes,
                found_offset_bytes,
            } => write!(
                f,
                "extent {extent} starts at {found_offset_bytes}, overlapping bytes before \
                 {expected_offset_bytes}"
            ),
            Self::Overflow { extent } => write!(f, "extent {extent} overflows the offset range"),
            Self::LengthMismatch {
                covered_bytes,
                true_length_bytes,
            } => write!(
                f,
                "the extents cover {covered_bytes} bytes, but the true length is \
                 {true_length_bytes}"
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

/// What a source declares about an object before any byte is fetched: the true length,
/// the content key and the extent table (GPU part §3.3; CORE-02).
///
/// The extents must tile `[0, true length)` in order. Each extent digest is what makes
/// partial data verifiable, so an interrupted import resumes from verified extents only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportManifest {
    pub true_length_bytes: u64,
    pub content_key: ContentKey,
    pub extents: Vec<ExtentEntry>,
}

impl ImportManifest {
    /// Describes `bytes` already in memory, in extents of `extent_length_bytes` (the last
    /// may be shorter).
    pub fn describe(bytes: &[u8], extent_length_bytes: NonZeroU64) -> Self {
        let chunk = usize::try_from(extent_length_bytes.get()).unwrap_or(usize::MAX);
        let mut offset_bytes = 0u64;
        let extents = bytes
            .chunks(chunk)
            .map(|piece| {
                let entry = ExtentEntry {
                    offset_bytes,
                    length_bytes: piece.len() as u64,
                    digest: ExtentDigest::of(piece),
                };
                offset_bytes = offset_bytes.saturating_add(piece.len() as u64);
                entry
            })
            .collect();
        Self {
            true_length_bytes: bytes.len() as u64,
            content_key: ContentKey::of(bytes),
            extents,
        }
    }

    /// Checks bounds, overflow, gaps, overlaps and coverage (line 531). Nothing is
    /// allocated or fetched for a manifest that fails.
    pub fn validate(&self, limits: &ManifestLimits) -> Result<(), ManifestError> {
        if self.true_length_bytes > limits.max_object_bytes {
            return Err(ManifestError::ObjectTooLarge {
                true_length_bytes: self.true_length_bytes,
                max_object_bytes: limits.max_object_bytes,
            });
        }
        if self.extents.len() as u64 > u64::from(limits.max_extents) {
            return Err(ManifestError::TooManyExtents {
                extents: self.extents.len() as u64,
                max_extents: limits.max_extents,
            });
        }
        let mut expected_offset_bytes = 0u64;
        for (position, extent) in self.extents.iter().enumerate() {
            let index = u32::try_from(position).unwrap_or(u32::MAX);
            if extent.length_bytes == 0 {
                return Err(ManifestError::EmptyExtent { extent: index });
            }
            if extent.length_bytes > limits.max_extent_bytes {
                return Err(ManifestError::ExtentTooLarge {
                    extent: index,
                    length_bytes: extent.length_bytes,
                    max_extent_bytes: limits.max_extent_bytes,
                });
            }
            if extent.offset_bytes < expected_offset_bytes {
                return Err(ManifestError::Overlap {
                    extent: index,
                    expected_offset_bytes,
                    found_offset_bytes: extent.offset_bytes,
                });
            }
            if extent.offset_bytes > expected_offset_bytes {
                return Err(ManifestError::Gap {
                    extent: index,
                    expected_offset_bytes,
                    found_offset_bytes: extent.offset_bytes,
                });
            }
            expected_offset_bytes = extent
                .offset_bytes
                .checked_add(extent.length_bytes)
                .ok_or(ManifestError::Overflow { extent: index })?;
        }
        if expected_offset_bytes != self.true_length_bytes {
            return Err(ManifestError::LengthMismatch {
                covered_bytes: expected_offset_bytes,
                true_length_bytes: self.true_length_bytes,
            });
        }
        Ok(())
    }

    /// The canonical digest of the whole declaration; it binds the true length, the
    /// content key and every extent's offset, length and digest in order (line 529).
    pub fn digest(&self) -> Digest {
        self.extents
            .iter()
            .fold(
                DigestBuilder::new(MANIFEST_DOMAIN)
                    .u64(self.true_length_bytes)
                    .digest(self.content_key.digest())
                    .u64(self.extents.len() as u64),
                |builder, extent| {
                    builder
                        .u64(extent.offset_bytes)
                        .u64(extent.length_bytes)
                        .digest(&extent.digest.digest())
                },
            )
            .finish()
    }

    /// How many extents the manifest declares.
    pub fn extent_count(&self) -> u32 {
        u32::try_from(self.extents.len()).unwrap_or(u32::MAX)
    }
}

/// Builds an [`ImportManifest`] while the bytes stream past, for an importer that
/// produces an object (a prepared representation) instead of receiving a declaration.
/// It holds at most one extent in memory.
pub struct ManifestBuilder {
    true_length_bytes: u64,
    extent_length_bytes: u64,
    content: ContentHasher,
    current: Vec<u8>,
    extents: Vec<ExtentEntry>,
    next_offset_bytes: u64,
}

impl ManifestBuilder {
    /// Starts a manifest for `true_length_bytes` in extents of `extent_length_bytes` (the
    /// last may be shorter).
    pub fn new(true_length_bytes: u64, extent_length_bytes: NonZeroU64) -> Self {
        Self {
            true_length_bytes,
            extent_length_bytes: extent_length_bytes.get(),
            content: ContentHasher::new(true_length_bytes),
            current: Vec::new(),
            extents: Vec::new(),
            next_offset_bytes: 0,
        }
    }

    /// Adds the next bytes; refuses any beyond the declared true length.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), ContentLengthError> {
        self.content.update(bytes)?;
        let mut rest = bytes;
        while !rest.is_empty() {
            let extent_bytes = self
                .true_length_bytes
                .saturating_sub(self.next_offset_bytes)
                .min(self.extent_length_bytes);
            let room = usize::try_from(extent_bytes)
                .unwrap_or(usize::MAX)
                .saturating_sub(self.current.len());
            let Some((head, tail)) = rest
                .split_at_checked(room.min(rest.len()))
                .filter(|(head, _)| !head.is_empty())
            else {
                // The content hasher already refuses bytes past the true length.
                return Err(ContentLengthError {
                    declared: self.true_length_bytes,
                    seen: self
                        .next_offset_bytes
                        .saturating_add(self.current.len() as u64)
                        .saturating_add(rest.len() as u64),
                });
            };
            self.current.extend_from_slice(head);
            rest = tail;
            if self.current.len() as u64 == extent_bytes {
                self.extents.push(ExtentEntry {
                    offset_bytes: self.next_offset_bytes,
                    length_bytes: extent_bytes,
                    digest: ExtentDigest::of(&self.current),
                });
                self.next_offset_bytes = self.next_offset_bytes.saturating_add(extent_bytes);
                self.current.clear();
            }
        }
        Ok(())
    }

    /// The manifest; refuses if fewer bytes than the declared true length arrived.
    pub fn finish(self) -> Result<ImportManifest, ContentLengthError> {
        let content_key = self.content.finish()?;
        Ok(ImportManifest {
            true_length_bytes: self.true_length_bytes,
            content_key,
            extents: self.extents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ManifestLimits {
        ManifestLimits {
            max_object_bytes: 1 << 20,
            max_extent_bytes: 16,
            max_extents: 64,
        }
    }

    fn extent_size(bytes: u64) -> NonZeroU64 {
        NonZeroU64::new(bytes).unwrap()
    }

    #[test]
    fn extent_digests_share_the_content_encoding_under_their_own_domain() {
        for bytes in [&b""[..], b"a", b"weights", &[7u8; 1000][..]] {
            assert_eq!(
                ExtentDigest::of(bytes).digest(),
                digest(EXTENT_DOMAIN, &[bytes])
            );
            assert_eq!(
                *ContentKey::of(bytes).digest(),
                digest(ContentKey::DOMAIN, &[bytes])
            );
            // An extent digest never passes for an object's content key.
            assert_ne!(
                ExtentDigest::of(bytes).digest(),
                *ContentKey::of(bytes).digest()
            );
        }
        assert_ne!(ExtentDigest::of(b"ab"), ExtentDigest::of(b"ab\0"));
        assert_ne!(ExtentDigest::of(b""), ExtentDigest::of(b"\0"));
    }

    #[test]
    fn a_described_manifest_tiles_the_object_and_validates() {
        let bytes: Vec<u8> = (0..=40u8).collect();
        let manifest = ImportManifest::describe(&bytes, extent_size(16));
        assert_eq!(manifest.true_length_bytes, 41);
        assert_eq!(
            manifest
                .extents
                .iter()
                .map(|extent| (extent.offset_bytes, extent.length_bytes))
                .collect::<Vec<_>>(),
            [(0, 16), (16, 16), (32, 9)]
        );
        assert_eq!(manifest.extents[2].digest, ExtentDigest::of(&bytes[32..]));
        assert_eq!(manifest.content_key, ContentKey::of(&bytes));
        assert_eq!(manifest.validate(&limits()), Ok(()));

        let empty = ImportManifest::describe(b"", extent_size(16));
        assert!(empty.extents.is_empty());
        assert_eq!(empty.validate(&limits()), Ok(()));
    }

    #[test]
    fn the_streaming_builder_matches_describe_for_any_chunking() {
        let bytes: Vec<u8> = (0..100u8).collect();
        let expected = ImportManifest::describe(&bytes, extent_size(16));
        for chunk in [1, 5, 16, 17, 100] {
            let mut builder = ManifestBuilder::new(100, extent_size(16));
            for piece in bytes.chunks(chunk) {
                builder.update(piece).unwrap();
            }
            assert_eq!(builder.finish().unwrap(), expected, "chunk {chunk}");
        }
        let mut short = ManifestBuilder::new(100, extent_size(16));
        short.update(&bytes[..99]).unwrap();
        assert_eq!(
            short.finish(),
            Err(ContentLengthError {
                declared: 100,
                seen: 99
            })
        );
        let mut long = ManifestBuilder::new(10, extent_size(16));
        assert_eq!(
            long.update(&bytes[..11]),
            Err(ContentLengthError {
                declared: 10,
                seen: 11
            })
        );
    }

    #[test]
    fn every_corrupt_manifest_is_rejected_before_allocation() {
        let bytes: Vec<u8> = (0..48u8).collect();
        let good = ImportManifest::describe(&bytes, extent_size(16));
        let reject = |change: &dyn Fn(&mut ImportManifest)| {
            let mut manifest = good.clone();
            change(&mut manifest);
            manifest.validate(&limits()).unwrap_err()
        };

        assert_eq!(
            reject(&|m| m.extents[1].offset_bytes = 8),
            ManifestError::Overlap {
                extent: 1,
                expected_offset_bytes: 16,
                found_offset_bytes: 8
            }
        );
        assert_eq!(
            reject(&|m| m.extents[1].offset_bytes = 20),
            ManifestError::Gap {
                extent: 1,
                expected_offset_bytes: 16,
                found_offset_bytes: 20
            }
        );
        assert_eq!(
            reject(&|m| m.extents.swap(0, 1)),
            ManifestError::Gap {
                extent: 0,
                expected_offset_bytes: 0,
                found_offset_bytes: 16
            }
        );
        assert_eq!(
            reject(&|m| {
                m.extents.pop();
            }),
            ManifestError::LengthMismatch {
                covered_bytes: 32,
                true_length_bytes: 48
            }
        );
        assert_eq!(
            reject(&|m| m.true_length_bytes = 47),
            ManifestError::LengthMismatch {
                covered_bytes: 48,
                true_length_bytes: 47
            }
        );
        assert_eq!(
            reject(&|m| m.extents[0].length_bytes = 0),
            ManifestError::EmptyExtent { extent: 0 }
        );
        assert_eq!(
            reject(&|m| m.extents[0].length_bytes = 17),
            ManifestError::ExtentTooLarge {
                extent: 0,
                length_bytes: 17,
                max_extent_bytes: 16
            }
        );
        assert_eq!(
            reject(&|m| m.true_length_bytes = (1 << 20) + 1),
            ManifestError::ObjectTooLarge {
                true_length_bytes: (1 << 20) + 1,
                max_object_bytes: 1 << 20
            }
        );
        assert_eq!(
            reject(&|m| m.extents = vec![m.extents[0]; 65]),
            ManifestError::TooManyExtents {
                extents: 65,
                max_extents: 64
            }
        );

        let overflow = ImportManifest {
            true_length_bytes: u64::MAX,
            content_key: good.content_key,
            extents: vec![
                ExtentEntry {
                    offset_bytes: 0,
                    length_bytes: u64::MAX - 1,
                    digest: good.extents[0].digest,
                },
                ExtentEntry {
                    offset_bytes: u64::MAX - 1,
                    length_bytes: 2,
                    digest: good.extents[0].digest,
                },
            ],
        };
        let unbounded = ManifestLimits {
            max_object_bytes: u64::MAX,
            max_extent_bytes: u64::MAX,
            max_extents: 2,
        };
        assert_eq!(
            overflow.validate(&unbounded),
            Err(ManifestError::Overflow { extent: 1 })
        );
    }

    #[test]
    fn the_manifest_digest_binds_offsets_order_and_digests() {
        let bytes: Vec<u8> = (0..48u8).collect();
        let manifest = ImportManifest::describe(&bytes, extent_size(16));
        let base = manifest.digest();
        assert_eq!(base, manifest.clone().digest());

        let mut swapped = manifest.clone();
        swapped.extents.swap(1, 2);
        assert_ne!(swapped.digest(), base);

        let mut moved = manifest.clone();
        moved.extents[2].offset_bytes += 1;
        assert_ne!(moved.digest(), base);

        let mut other = manifest.clone();
        other.extents[0].digest = ExtentDigest::of(b"other");
        assert_ne!(other.digest(), base);

        let mut key = manifest;
        key.content_key = ContentKey::of(b"other");
        assert_ne!(key.digest(), base);
    }
}
