//! Published object envelopes (§5.3 "a trusted import pipeline can publish
//! content-addressed read-only OCI layer ... images"; S2 CORE-02 scoped content identity).
//!
//! Each catalog object is a prefix followed by a body. The prefix is an 8-byte magic, a
//! 4-byte big-endian header length and a canonical JSON header that names what the body
//! is: for a layer, the OCI descriptor (media type, digest, size) and diff_id, with the
//! verified blob as the body; for a tree, the manifest, config, layer digests and
//! diff_ids, with the tree index as the body. The prefix is always the object's first
//! extent on its own, so a trust claim can carry the prefix and the extent table and the
//! verifier can bind them to the exact content key being imported without the body.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::digest::{BlobReference, OciDigest, VerifiedBlob};
use super::limits::{detail, len_u64};
use super::tree::TreeIndex;
use crate::foundation::catalog::{ExtentDigest, ExtentEntry, ImportManifest};
use crate::foundation::ids::ContentKey;

/// Magic of a layer envelope.
pub const LAYER_MAGIC: [u8; 8] = *b"YGOCIL01";
/// Magic of a tree envelope.
pub const TREE_MAGIC: [u8; 8] = *b"YGOCIT01";
/// Largest envelope header.
pub(crate) const MAX_HEADER_BYTES: usize = 1 << 20;
/// Magic and header length.
pub(crate) const FIXED_PREFIX_BYTES: usize = 12;

/// What an envelope holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    Layer,
    Tree,
}

/// Why an envelope prefix was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum EnvelopeRefusal {
    TooShort,
    UnknownMagic,
    HeaderTooLarge { bytes: usize, limit: usize },
    Malformed { detail: String },
}

impl fmt::Display for EnvelopeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("the envelope is shorter than its prefix"),
            Self::UnknownMagic => f.write_str("the envelope magic is unknown"),
            Self::HeaderTooLarge { bytes, limit } => {
                write!(f, "a {bytes}-byte envelope header; at most {limit}")
            }
            Self::Malformed { detail } => write!(f, "malformed envelope header: {detail}"),
        }
    }
}

impl std::error::Error for EnvelopeRefusal {}

/// The header of a layer envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayerHeader {
    pub layer: BlobReference,
    pub diff_id: OciDigest,
}

/// The header of a tree envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TreeHeader {
    pub manifest: OciDigest,
    pub config: OciDigest,
    pub layers: Vec<OciDigest>,
    pub diff_ids: Vec<OciDigest>,
}

/// A parsed envelope header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeHeader {
    Layer(LayerHeader),
    Tree(TreeHeader),
}

/// An envelope in memory: its bytes and where the prefix ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Envelope {
    pub bytes: Vec<u8>,
    pub prefix_bytes: usize,
}

fn malformed(error: impl fmt::Display) -> EnvelopeRefusal {
    EnvelopeRefusal::Malformed {
        detail: detail(error),
    }
}

fn build(
    magic: [u8; 8],
    header: &impl Serialize,
    body: &[u8],
) -> Result<Envelope, EnvelopeRefusal> {
    let header = serde_json::to_vec(header).map_err(malformed)?;
    if header.len() > MAX_HEADER_BYTES {
        return Err(EnvelopeRefusal::HeaderTooLarge {
            bytes: header.len(),
            limit: MAX_HEADER_BYTES,
        });
    }
    let length = u32::try_from(header.len()).map_err(malformed)?;
    let mut bytes = Vec::with_capacity(
        FIXED_PREFIX_BYTES
            .saturating_add(header.len())
            .saturating_add(body.len()),
    );
    bytes.extend_from_slice(&magic);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&header);
    let prefix_bytes = bytes.len();
    bytes.extend_from_slice(body);
    Ok(Envelope {
        bytes,
        prefix_bytes,
    })
}

/// The envelope of one verified layer blob.
pub(crate) fn layer_envelope(
    blob: &VerifiedBlob,
    diff_id: OciDigest,
) -> Result<Envelope, EnvelopeRefusal> {
    build(
        LAYER_MAGIC,
        &LayerHeader {
            layer: *blob.reference(),
            diff_id,
        },
        blob.bytes(),
    )
}

/// The envelope of an image's tree index.
pub(crate) fn tree_envelope(
    header: &TreeHeader,
    tree: &TreeIndex,
) -> Result<Envelope, EnvelopeRefusal> {
    let body = tree.body_bytes().map_err(malformed)?;
    build(TREE_MAGIC, header, &body)
}

/// The magic and header length at the start of `fixed`; the length is bounded.
pub(crate) fn parse_fixed(fixed: &[u8]) -> Result<(EnvelopeKind, usize), EnvelopeRefusal> {
    let magic = fixed.get(..8).ok_or(EnvelopeRefusal::TooShort)?;
    let kind = if magic == LAYER_MAGIC {
        EnvelopeKind::Layer
    } else if magic == TREE_MAGIC {
        EnvelopeKind::Tree
    } else {
        return Err(EnvelopeRefusal::UnknownMagic);
    };
    let length: [u8; 4] = fixed
        .get(8..FIXED_PREFIX_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(EnvelopeRefusal::TooShort)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(malformed)?;
    if length > MAX_HEADER_BYTES {
        return Err(EnvelopeRefusal::HeaderTooLarge {
            bytes: length,
            limit: MAX_HEADER_BYTES,
        });
    }
    Ok((kind, length))
}

/// Parses a header of `kind` from its JSON bytes.
pub(crate) fn parse_header(
    kind: EnvelopeKind,
    header: &[u8],
) -> Result<EnvelopeHeader, EnvelopeRefusal> {
    match kind {
        EnvelopeKind::Layer => serde_json::from_slice(header)
            .map(EnvelopeHeader::Layer)
            .map_err(malformed),
        EnvelopeKind::Tree => serde_json::from_slice(header)
            .map(EnvelopeHeader::Tree)
            .map_err(malformed),
    }
}

/// Parses `prefix`, which must be exactly one envelope prefix.
pub(crate) fn parse_prefix(prefix: &[u8]) -> Result<EnvelopeHeader, EnvelopeRefusal> {
    let (kind, length) = parse_fixed(prefix)?;
    let header = prefix
        .get(FIXED_PREFIX_BYTES..)
        .filter(|header| header.len() == length)
        .ok_or_else(|| malformed("the prefix length differs from its header length"))?;
    parse_header(kind, header)
}

impl Envelope {
    pub(crate) fn prefix(&self) -> &[u8] {
        self.bytes.get(..self.prefix_bytes).unwrap_or(&[])
    }

    /// The catalog declaration: the prefix as extent 0, then the body in extents of
    /// `extent_bytes` (the last may be shorter).
    pub(crate) fn import_manifest(&self, extent_bytes: u64) -> ImportManifest {
        let chunk = usize::try_from(extent_bytes.max(1)).unwrap_or(usize::MAX);
        let prefix = self.prefix();
        let mut extents = vec![ExtentEntry {
            offset_bytes: 0,
            length_bytes: len_u64(prefix.len()),
            digest: ExtentDigest::of(prefix),
        }];
        let mut offset_bytes = len_u64(prefix.len());
        let body = self.bytes.get(self.prefix_bytes..).unwrap_or(&[]);
        for piece in body.chunks(chunk) {
            extents.push(ExtentEntry {
                offset_bytes,
                length_bytes: len_u64(piece.len()),
                digest: ExtentDigest::of(piece),
            });
            offset_bytes = offset_bytes.saturating_add(len_u64(piece.len()));
        }
        ImportManifest {
            true_length_bytes: len_u64(self.bytes.len()),
            content_key: ContentKey::of(&self.bytes),
            extents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::catalog::ManifestLimits;
    use crate::sandbox_contract::oci::digest::MediaType;

    fn blob(bytes: &[u8]) -> VerifiedBlob {
        VerifiedBlob::verify(
            BlobReference {
                media_type: MediaType::LayerTar,
                digest: OciDigest::of(bytes),
                size_bytes: bytes.len() as u64,
            },
            bytes.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn the_prefix_is_extent_zero_and_the_body_follows() {
        let body = vec![7u8; 2500];
        let envelope = layer_envelope(&blob(&body), OciDigest::of(b"diff")).unwrap();
        let manifest = envelope.import_manifest(1000);
        manifest
            .validate(&ManifestLimits {
                max_object_bytes: 1 << 20,
                max_extent_bytes: 1 << 20,
                max_extents: 16,
            })
            .unwrap();
        assert_eq!(manifest.extents.len(), 4);
        assert_eq!(
            manifest.extents[0].length_bytes,
            envelope.prefix_bytes as u64
        );
        assert_eq!(
            manifest.extents[0].digest,
            ExtentDigest::of(envelope.prefix())
        );
        assert_eq!(manifest.extents[3].length_bytes, 500);
        assert_eq!(manifest.content_key, ContentKey::of(&envelope.bytes));
        assert_eq!(
            envelope.bytes.get(envelope.prefix_bytes..).unwrap(),
            &body[..]
        );
        match parse_prefix(envelope.prefix()).unwrap() {
            EnvelopeHeader::Layer(header) => {
                assert_eq!(header.layer.digest, OciDigest::of(&body));
                assert_eq!(header.diff_id, OciDigest::of(b"diff"));
            }
            EnvelopeHeader::Tree(_) => panic!("a layer envelope parsed as a tree"),
        }
    }

    #[test]
    fn malformed_prefixes_are_refused() {
        let envelope = layer_envelope(&blob(b"x"), OciDigest::of(b"d")).unwrap();
        assert_eq!(parse_prefix(b"YGOCIL0"), Err(EnvelopeRefusal::TooShort));
        let mut wrong = envelope.prefix().to_vec();
        wrong[7] = b'9';
        assert_eq!(parse_prefix(&wrong), Err(EnvelopeRefusal::UnknownMagic));
        let mut long = envelope.prefix().to_vec();
        long[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            parse_prefix(&long),
            Err(EnvelopeRefusal::HeaderTooLarge { .. })
        ));
        let mut extra = envelope.prefix().to_vec();
        extra.push(b' ');
        assert!(matches!(
            parse_prefix(&extra),
            Err(EnvelopeRefusal::Malformed { .. })
        ));
        // A layer header read as a tree header is refused, not reinterpreted.
        let mut as_tree = envelope.prefix().to_vec();
        as_tree[..8].copy_from_slice(&TREE_MAGIC);
        assert!(matches!(
            parse_prefix(&as_tree),
            Err(EnvelopeRefusal::Malformed { .. })
        ));
    }
}
