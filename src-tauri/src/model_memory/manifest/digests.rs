//! Domain-separated digests of the sidecar manifest (GPU part §3.3: "Use domain-separated
//! hashes and canonical encodings"). Each domain names one fixed field layout and is
//! hashed through [`DigestBuilder`].

use std::fmt;

use crate::foundation::ids::{Digest, DigestBuilder};

use super::codec::CodecFormat;

/// The content key of a byte string (§3.3: "decoded content keys hash a domain tag, true
/// length and decoded bytes"). It is the shared content identity of `foundation::ids`, used
/// both for every decoded integrity extent and for every whole source file, so decoded keys
/// match the catalog's and transfers', and a source file's key is the content key the
/// catalog names that file's object by and the identity layers bind (T05, T07). The same
/// decoded bytes have the same key under every encoding, which lets representations be
/// reused without confusing representation and content.
pub use crate::foundation::ids::ContentKey;

/// Domain of [`ManifestDigest`]: the canonical manifest body.
pub const MANIFEST_DOMAIN: &str = "yougori/model-memory/manifest/v1";
/// Domain of [`EncodedDigest`]: codec, codec version, the version's frame parameters,
/// dictionary, encoded length, encoded bytes. Version 2 added the codec version and its
/// parameters (GPU-W08).
pub const ENCODED_DOMAIN: &str = "yougori/model-memory/manifest/encoded/v2";
/// Domain of [`DictionaryId`]: dictionary length, then its bytes.
pub const DICTIONARY_DOMAIN: &str = "yougori/model-memory/manifest/dictionary/v1";
/// Domain of a local source's content-derived revision: the file listing.
pub const SOURCE_LISTING_DOMAIN: &str = "yougori/model-memory/manifest/source-listing/v1";
/// Domain of the semantics group's configuration digest.
pub const CONFIGURATION_DOMAIN: &str = "yougori/model-memory/manifest/configuration/v1";
/// Domain of the semantics group's tokenizer digest.
pub const TOKENIZER_DOMAIN: &str = "yougori/model-memory/manifest/tokenizer/v1";
/// Domain of a GGUF file's metadata section digest.
pub const GGUF_METADATA_DOMAIN: &str = "yougori/model-memory/manifest/gguf-metadata/v1";
/// Domain of one extent-tree leaf: offset, true length, content key and encoding, an
/// encoding with its codec format. Version 2 added the codec version and its parameters.
pub const EXTENT_LEAF_DOMAIN: &str = "yougori/model-memory/manifest/extent-leaf/v2";
/// Domain of an extent-tree interior node.
pub const TREE_NODE_DOMAIN: &str = "yougori/model-memory/manifest/tree-node/v1";
/// Domain of the root of a tree with no leaves.
pub const TREE_EMPTY_DOMAIN: &str = "yougori/model-memory/manifest/tree-empty/v1";
/// Domain of the artifact's decoded content identity, independent of encodings.
pub const DECODED_CONTENT_DOMAIN: &str = "yougori/model-memory/manifest/decoded-content/v1";

/// Digest of an encoded representation of one extent, binding its codec format (codec,
/// codec version and frame parameters) and dictionary identity (§3.3: "Encoded
/// representations have their own digest plus codec/dictionary identity"; GPU-W08), so
/// the same stored bytes declared under another version or parameters have another
/// identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncodedDigest(Digest);

impl EncodedDigest {
    pub fn of(format: CodecFormat, dictionary: Option<DictionaryId>, encoded: &[u8]) -> Self {
        let builder = format.bind(DigestBuilder::new(ENCODED_DOMAIN));
        let builder = match dictionary {
            None => builder.str("no-dictionary"),
            Some(dictionary) => builder.str("dictionary").digest(&dictionary.digest()),
        };
        Self(builder.u64(encoded.len() as u64).bytes(encoded).finish())
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> Digest {
        self.0
    }
}

/// Identity of a compression dictionary: the digest of its bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DictionaryId(Digest);

impl DictionaryId {
    pub fn of(dictionary: &[u8]) -> Self {
        Self(
            DigestBuilder::new(DICTIONARY_DOMAIN)
                .u64(dictionary.len() as u64)
                .bytes(dictionary)
                .finish(),
        )
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> Digest {
        self.0
    }
}

/// Digest of a canonical manifest body (§3.3 integrity: manifest digest). It binds every
/// field group, so a changed shape, offset or codec changes it even when the payload is
/// identical. The artifact identity of §3.2 layer 4 is built from it by the identity
/// layers (T07, `ArtifactIdentity::from_manifest_digest`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestDigest(Digest);

impl ManifestDigest {
    pub(super) fn of_body(body: &[u8]) -> Self {
        Self(DigestBuilder::new(MANIFEST_DOMAIN).bytes(body).finish())
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> Digest {
        self.0
    }
}

macro_rules! hex_formatting {
    ($($name:ident),*) => {
        $(
            impl fmt::Debug for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "{}({})", stringify!($name), self.0.to_hex())
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(&self.0.to_hex())
                }
            }
        )*
    };
}

hex_formatting!(EncodedDigest, DictionaryId, ManifestDigest);
