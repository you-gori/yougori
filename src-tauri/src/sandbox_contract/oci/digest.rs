//! OCI content digests, media types and verified blobs (§5.3 "a digest proves content
//! identity, not publisher trust"; §8.3 line 2278 "bind the exact opened artifact to the
//! verified identity").

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::limits::{bounded_text, len_u64};

/// A sha256 OCI content digest, `sha256:` and 64 lowercase hex digits. It names bytes and
/// says nothing about who published them (§5.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OciDigest([u8; 32]);

/// Why a digest string was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum DigestRefusal {
    /// Only sha256 is accepted.
    UnsupportedAlgorithm { algorithm: String },
    /// Not 64 lowercase hex digits after `sha256:`.
    Malformed,
}

impl fmt::Display for DigestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(f, "digest algorithm {algorithm:?} is not sha256")
            }
            Self::Malformed => f.write_str("the digest is not sha256 and 64 lowercase hex digits"),
        }
    }
}

impl std::error::Error for DigestRefusal {}

impl OciDigest {
    /// The sha256 digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Wraps a finished sha256 state.
    pub(crate) fn from_hasher(hasher: Sha256) -> Self {
        Self(hasher.finalize().into())
    }

    /// Parses `sha256:<64 lowercase hex>`; every other algorithm and spelling is refused.
    pub fn parse(text: &str) -> Result<Self, DigestRefusal> {
        let Some((algorithm, encoded)) = text.split_once(':') else {
            return Err(DigestRefusal::Malformed);
        };
        if algorithm != "sha256" {
            return Err(DigestRefusal::UnsupportedAlgorithm {
                algorithm: bounded_text(algorithm, 32),
            });
        }
        let lowercase_hex = encoded.len() == 64
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !lowercase_hex {
            return Err(DigestRefusal::Malformed);
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(encoded, &mut bytes).map_err(|_| DigestRefusal::Malformed)?;
        Ok(Self(bytes))
    }

    /// The 32 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for OciDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for OciDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OciDigest({self})")
    }
}

impl Serialize for OciDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OciDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// How a layer's tar stream is stored, as its media type says; never sniffed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerCodec {
    Uncompressed,
    Gzip,
    Zstd,
}

/// The OCI and Docker schema-2 image media types this importer accepts (VM-W33).
/// Artifact types, schema 1, empty descriptors and foreign layers are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MediaType {
    ImageIndex,
    ImageManifest,
    ImageConfig,
    LayerTar,
    LayerTarGzip,
    LayerTarZstd,
    DockerIndex,
    DockerManifest,
    DockerConfig,
    DockerLayerGzip,
}

impl MediaType {
    /// Every accepted media type.
    pub const ALL: [Self; 10] = [
        Self::ImageIndex,
        Self::ImageManifest,
        Self::ImageConfig,
        Self::LayerTar,
        Self::LayerTarGzip,
        Self::LayerTarZstd,
        Self::DockerIndex,
        Self::DockerManifest,
        Self::DockerConfig,
        Self::DockerLayerGzip,
    ];

    /// The registered media type string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DockerIndex => "application/vnd.docker.distribution.manifest.list.v2+json",
            Self::DockerManifest => "application/vnd.docker.distribution.manifest.v2+json",
            Self::DockerConfig => "application/vnd.docker.container.image.v1+json",
            Self::DockerLayerGzip => "application/vnd.docker.image.rootfs.diff.tar.gzip",
            Self::ImageIndex => "application/vnd.oci.image.index.v1+json",
            Self::ImageManifest => "application/vnd.oci.image.manifest.v1+json",
            Self::ImageConfig => "application/vnd.oci.image.config.v1+json",
            Self::LayerTar => "application/vnd.oci.image.layer.v1.tar",
            Self::LayerTarGzip => "application/vnd.oci.image.layer.v1.tar+gzip",
            Self::LayerTarZstd => "application/vnd.oci.image.layer.v1.tar+zstd",
        }
    }

    /// The accepted media type spelled exactly `text`, if any.
    pub fn from_exact(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|media| media.as_str() == text)
    }

    /// Whether `text` is one of the deprecated non-distributable ("foreign") layer types.
    pub fn is_non_distributable(text: &str) -> bool {
        text.starts_with("application/vnd.oci.image.layer.nondistributable.v1.tar")
            || text.starts_with("application/vnd.docker.image.rootfs.foreign.diff.tar")
    }

    pub const fn is_index(self) -> bool {
        matches!(self, Self::ImageIndex | Self::DockerIndex)
    }
    pub const fn is_manifest(self) -> bool {
        matches!(self, Self::ImageManifest | Self::DockerManifest)
    }
    pub const fn is_config(self) -> bool {
        matches!(self, Self::ImageConfig | Self::DockerConfig)
    }

    /// The layer's codec; `None` for documents.
    pub const fn layer_codec(self) -> Option<LayerCodec> {
        match self {
            Self::LayerTar => Some(LayerCodec::Uncompressed),
            Self::LayerTarGzip | Self::DockerLayerGzip => Some(LayerCodec::Gzip),
            Self::LayerTarZstd => Some(LayerCodec::Zstd),
            _ => None,
        }
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for MediaType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MediaType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_exact(&text).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown media type {:?}", bounded_text(&text, 128)))
        })
    }
}

/// What a blob is expected to be: the media type, digest and size its parent declared,
/// or the pinned root reference a caller supplies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReference {
    pub media_type: MediaType,
    pub digest: OciDigest,
    pub size_bytes: u64,
}

/// Why fetched bytes are not the declared blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum BlobRefusal {
    /// The declared size is above the limit for its kind; nothing was fetched.
    DeclaredTooLarge { size_bytes: u64, limit_bytes: u64 },
    SizeMismatch {
        declared_bytes: u64,
        found_bytes: u64,
    },
    DigestMismatch {
        declared: OciDigest,
        found: OciDigest,
    },
}

impl fmt::Display for BlobRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeclaredTooLarge {
                size_bytes,
                limit_bytes,
            } => write!(f, "declared {size_bytes} bytes; at most {limit_bytes}"),
            Self::SizeMismatch {
                declared_bytes,
                found_bytes,
            } => write!(f, "declared {declared_bytes} bytes; found {found_bytes}"),
            Self::DigestMismatch { declared, found } => {
                write!(f, "declared {declared}; the bytes hash to {found}")
            }
        }
    }
}

impl std::error::Error for BlobRefusal {}

/// Bytes whose sha256 digest and size matched their reference when this value was made
/// (§8.3 line 2278). Every parser here reads a `VerifiedBlob`, so what is parsed is
/// exactly what was hashed: there is no second read that could return other bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedBlob {
    reference: BlobReference,
    bytes: Vec<u8>,
}

impl VerifiedBlob {
    /// Checks `bytes` against `reference`: the size first, then the sha256 digest.
    pub fn verify(reference: BlobReference, bytes: Vec<u8>) -> Result<Self, BlobRefusal> {
        let found_bytes = len_u64(bytes.len());
        if found_bytes != reference.size_bytes {
            return Err(BlobRefusal::SizeMismatch {
                declared_bytes: reference.size_bytes,
                found_bytes,
            });
        }
        let found = OciDigest::of(&bytes);
        if found != reference.digest {
            return Err(BlobRefusal::DigestMismatch {
                declared: reference.digest,
                found,
            });
        }
        Ok(Self { reference, bytes })
    }

    /// The reference the bytes were verified against.
    pub fn reference(&self) -> &BlobReference {
        &self.reference
    }

    /// The verified bytes, the only ones any parser here reads.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for VerifiedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedBlob")
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_sha256_lowercase_only() {
        let digest = OciDigest::of(b"abc");
        assert_eq!(
            digest.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(OciDigest::parse(&digest.to_string()), Ok(digest));
        let upper = digest
            .to_string()
            .to_uppercase()
            .replace("SHA256", "sha256");
        assert_eq!(OciDigest::parse(&upper), Err(DigestRefusal::Malformed));
        assert_eq!(
            OciDigest::parse(&format!("sha512:{}", "a".repeat(128))),
            Err(DigestRefusal::UnsupportedAlgorithm {
                algorithm: "sha512".into()
            })
        );
        for bad in ["", "sha256", "sha256:", "sha256:abc", "sha256:+zz"] {
            assert_eq!(
                OciDigest::parse(bad),
                Err(DigestRefusal::Malformed),
                "{bad}"
            );
        }
        assert!(serde_json::from_str::<OciDigest>("\"md5:abc\"").is_err());
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(serde_json::from_str::<OciDigest>(&json).unwrap(), digest);
    }

    #[test]
    fn media_types_are_exact_and_never_sniffed() {
        for media in MediaType::ALL {
            assert_eq!(MediaType::from_exact(media.as_str()), Some(media));
        }
        for text in [
            "application/vnd.docker.distribution.manifest.v1+json",
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            "application/vnd.oci.empty.v1+json",
            "application/vnd.oci.image.layer.v1.tar+bzip2",
            "application/vnd.oci.image.layer.v1.tar+gzip ",
            "APPLICATION/VND.OCI.IMAGE.LAYER.V1.TAR",
        ] {
            assert_eq!(MediaType::from_exact(text), None, "{text}");
        }
        assert!(MediaType::is_non_distributable(
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
        ));
        assert_eq!(
            MediaType::LayerTarZstd.layer_codec(),
            Some(LayerCodec::Zstd)
        );
        assert_eq!(MediaType::ImageConfig.layer_codec(), None);
    }

    #[test]
    fn a_blob_must_match_its_size_and_digest() {
        let reference = BlobReference {
            media_type: MediaType::ImageConfig,
            digest: OciDigest::of(b"{}"),
            size_bytes: 2,
        };
        let blob = VerifiedBlob::verify(reference, b"{}".to_vec()).unwrap();
        assert_eq!(blob.bytes(), b"{}");
        assert_eq!(
            VerifiedBlob::verify(reference, b"{} ".to_vec()),
            Err(BlobRefusal::SizeMismatch {
                declared_bytes: 2,
                found_bytes: 3
            })
        );
        assert_eq!(
            VerifiedBlob::verify(reference, b"[]".to_vec()),
            Err(BlobRefusal::DigestMismatch {
                declared: reference.digest,
                found: OciDigest::of(b"[]")
            })
        );
    }
}
