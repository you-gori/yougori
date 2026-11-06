//! Strict OCI image index and image manifest parsing (VM-W33; §5.3 "verify image identity,
//! provenance and layout; prohibit undeclared backing files").
//!
//! Only schema version 2 with OCI or Docker image media types is accepted. Every document's `mediaType`
//! must be present and equal the media type its parent descriptor declared, so a manifest
//! can never be read as an index or the other way round. Unknown fields and duplicate keys
//! are refused (the OCI specification asks readers to ignore unknown fields; this is the
//! strict reading). Descriptors with `urls` name backing files outside the image and are
//! refused, as are non-distributable layers, embedded `data`, `artifactType` and
//! `subject`. A platform is chosen from an index by exact equality of every platform
//! field and never falls back to another platform.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::digest::{BlobReference, DigestRefusal, MediaType, OciDigest, VerifiedBlob};
use super::limits::{bounded_text, detail, len_u64, ImportLimits};

/// Where in a document a descriptor sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum DescriptorAt {
    Manifest { index: usize },
    Config,
    Layer { index: usize },
}

/// Why annotations or labels were refused (bounded metadata).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum AnnotationRefusal {
    TooMany {
        count: usize,
        limit: usize,
    },
    KeyTooLong {
        bytes: usize,
        limit: usize,
    },
    ValueTooLong {
        key: String,
        bytes: usize,
        limit: usize,
    },
    TotalTooLarge {
        bytes: usize,
        limit: usize,
    },
}

impl fmt::Display for AnnotationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany { count, limit } => write!(f, "{count} entries; at most {limit}"),
            Self::KeyTooLong { bytes, limit } => write!(f, "a {bytes}-byte key; at most {limit}"),
            Self::ValueTooLong { key, bytes, limit } => {
                write!(f, "{key:?} has a {bytes}-byte value; at most {limit}")
            }
            Self::TotalTooLarge { bytes, limit } => write!(f, "{bytes} bytes; at most {limit}"),
        }
    }
}

/// Why an index or manifest was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DocumentRefusal {
    TooLarge {
        size_bytes: u64,
        limit_bytes: u64,
    },
    /// Not JSON of the expected shape: a syntax error, a missing or unknown field, a
    /// duplicate key or a wrong type.
    Malformed {
        detail: String,
    },
    SchemaVersion {
        found: i64,
    },
    /// The document has no `mediaType`.
    MissingMediaType,
    /// The document's `mediaType` differs from what its parent declared.
    MediaTypeMismatch {
        declared: MediaType,
        found: String,
    },
    UnknownMediaType {
        at: DescriptorAt,
        media_type: String,
    },
    /// A known media type in the wrong position, such as a layer type as the config.
    UnexpectedMediaType {
        at: DescriptorAt,
        media_type: MediaType,
    },
    NonDistributableLayer {
        at: DescriptorAt,
    },
    /// The descriptor names backing files by URL (§5.3).
    ForeignUrls {
        at: DescriptorAt,
    },
    EmbeddedData {
        at: DescriptorAt,
    },
    /// An artifact, not an image.
    ArtifactType,
    Subject,
    NegativeSize {
        at: DescriptorAt,
    },
    Digest {
        at: DescriptorAt,
        refusal: DigestRefusal,
    },
    Annotations {
        refusal: AnnotationRefusal,
    },
    /// A platform on a descriptor other than an index entry.
    UnexpectedPlatform {
        at: DescriptorAt,
    },
    PlatformFieldTooLong {
        at: DescriptorAt,
        bytes: usize,
        limit: usize,
    },
    TooManyManifests {
        count: usize,
        limit: usize,
    },
    TooManyLayers {
        count: usize,
        limit: usize,
    },
    NoLayers,
    /// An index inside an index.
    NestedIndex {
        at: DescriptorAt,
    },
    NoMatchingPlatform {
        wanted: Platform,
    },
    AmbiguousPlatform {
        wanted: Platform,
        matches: usize,
    },
}

impl fmt::Display for DocumentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                size_bytes,
                limit_bytes,
            } => write!(f, "a {size_bytes}-byte document; at most {limit_bytes}"),
            Self::Malformed { detail } => write!(f, "malformed document: {detail}"),
            Self::SchemaVersion { found } => write!(f, "schema version {found}; only 2"),
            Self::MissingMediaType => f.write_str("the document has no mediaType"),
            Self::MediaTypeMismatch { declared, found } => {
                write!(f, "declared {declared}; the document says {found:?}")
            }
            Self::UnknownMediaType { at, media_type } => {
                write!(f, "{at:?}: unknown media type {media_type:?}")
            }
            Self::UnexpectedMediaType { at, media_type } => {
                write!(f, "{at:?}: {media_type} is not allowed here")
            }
            Self::NonDistributableLayer { at } => {
                write!(f, "{at:?}: non-distributable layers are refused")
            }
            Self::ForeignUrls { at } => {
                write!(
                    f,
                    "{at:?}: descriptors naming backing files by URL are refused"
                )
            }
            Self::EmbeddedData { at } => write!(f, "{at:?}: embedded data is refused"),
            Self::ArtifactType => f.write_str("artifact manifests are not images"),
            Self::Subject => f.write_str("manifests with a subject are not images"),
            Self::NegativeSize { at } => write!(f, "{at:?}: negative size"),
            Self::Digest { at, refusal } => write!(f, "{at:?}: {refusal}"),
            Self::Annotations { refusal } => write!(f, "annotations: {refusal}"),
            Self::UnexpectedPlatform { at } => write!(f, "{at:?}: a platform is not allowed here"),
            Self::PlatformFieldTooLong { at, bytes, limit } => {
                write!(f, "{at:?}: a {bytes}-byte platform field; at most {limit}")
            }
            Self::TooManyManifests { count, limit } => {
                write!(f, "{count} manifests; at most {limit}")
            }
            Self::TooManyLayers { count, limit } => write!(f, "{count} layers; at most {limit}"),
            Self::NoLayers => f.write_str("the manifest has no layers"),
            Self::NestedIndex { at } => write!(f, "{at:?}: nested indexes are refused"),
            Self::NoMatchingPlatform { wanted } => {
                write!(f, "no manifest for exactly {wanted}")
            }
            Self::AmbiguousPlatform { wanted, matches } => {
                write!(
                    f,
                    "{matches} manifests for {wanted}; exactly one is required"
                )
            }
        }
    }
}

impl std::error::Error for DocumentRefusal {}

/// A JSON object of string values whose duplicate keys are refused instead of the last one
/// silently winning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StrictMap<V>(pub(crate) BTreeMap<String, V>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for StrictMap<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor<V>(PhantomData<V>);

        impl<'de, V: Deserialize<'de>> Visitor<'de> for StrictVisitor<V> {
            type Value = StrictMap<V>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object without duplicate keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, V>()? {
                    if map.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate key {:?}",
                            bounded_text(&key, 64)
                        )));
                    }
                    map.insert(key, value);
                }
                Ok(StrictMap(map))
            }
        }

        deserializer.deserialize_map(StrictVisitor(PhantomData))
    }
}

/// Records whether a field was present at all, `null` included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Present(pub(crate) bool);

impl<'de> Deserialize<'de> for Present {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

/// Bounded string annotations (or labels).
pub type Annotations = BTreeMap<String, String>;

/// Checks `map` against the annotation bounds.
pub(crate) fn check_annotations(
    map: &BTreeMap<String, String>,
    limits: &ImportLimits,
) -> Result<(), AnnotationRefusal> {
    if map.len() > limits.max_annotations {
        return Err(AnnotationRefusal::TooMany {
            count: map.len(),
            limit: limits.max_annotations,
        });
    }
    let mut total = 0usize;
    for (key, value) in map {
        if key.len() > limits.max_annotation_key_bytes {
            return Err(AnnotationRefusal::KeyTooLong {
                bytes: key.len(),
                limit: limits.max_annotation_key_bytes,
            });
        }
        if value.len() > limits.max_annotation_value_bytes {
            return Err(AnnotationRefusal::ValueTooLong {
                key: bounded_text(key, 64),
                bytes: value.len(),
                limit: limits.max_annotation_value_bytes,
            });
        }
        total = total.saturating_add(key.len()).saturating_add(value.len());
        if total > limits.max_annotation_total_bytes {
            return Err(AnnotationRefusal::TotalTooLarge {
                bytes: total,
                limit: limits.max_annotation_total_bytes,
            });
        }
    }
    Ok(())
}

/// The platform an image runs on. Selection compares every field exactly: a request for
/// `linux/arm64` without a variant never matches `linux/arm64/v8`, and nothing falls back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
    #[serde(rename = "os.features", default, skip_serializing_if = "Vec::is_empty")]
    pub os_features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

impl Platform {
    /// `os/architecture` with no variant, version or features.
    pub fn new(os: &str, architecture: &str) -> Self {
        Self {
            os: os.to_owned(),
            architecture: architecture.to_owned(),
            variant: None,
            os_version: None,
            os_features: Vec::new(),
            features: Vec::new(),
        }
    }

    /// The same platform with `variant`.
    pub fn with_variant(mut self, variant: &str) -> Self {
        self.variant = Some(variant.to_owned());
        self
    }

    pub(crate) fn check(
        &self,
        at: DescriptorAt,
        limits: &ImportLimits,
    ) -> Result<(), DocumentRefusal> {
        let fields = [&self.os, &self.architecture]
            .into_iter()
            .chain(self.variant.as_ref())
            .chain(self.os_version.as_ref())
            .chain(self.os_features.iter())
            .chain(self.features.iter());
        let mut count = 0usize;
        for field in fields {
            count = count.saturating_add(1);
            if field.len() > limits.max_platform_field_bytes {
                return Err(DocumentRefusal::PlatformFieldTooLong {
                    at,
                    bytes: field.len(),
                    limit: limits.max_platform_field_bytes,
                });
            }
        }
        if count > limits.max_annotations {
            return Err(DocumentRefusal::Annotations {
                refusal: AnnotationRefusal::TooMany {
                    count,
                    limit: limits.max_annotations,
                },
            });
        }
        Ok(())
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(f, "/{variant}")?;
        }
        if let Some(version) = &self.os_version {
            write!(f, " ({version})")?;
        }
        Ok(())
    }
}

/// A checked descriptor: an accepted media type, a sha256 digest, a non-negative size and
/// bounded annotations; `platform` only on index entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    pub media_type: MediaType,
    pub digest: OciDigest,
    pub size_bytes: u64,
    pub annotations: Annotations,
    pub platform: Option<Platform>,
}

impl Descriptor {
    /// What the referenced blob must be.
    pub fn reference(&self) -> BlobReference {
        BlobReference {
            media_type: self.media_type,
            digest: self.digest,
            size_bytes: self.size_bytes,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawDescriptor {
    media_type: String,
    digest: String,
    size: i64,
    #[serde(default)]
    urls: Present,
    #[serde(default)]
    annotations: Option<StrictMap<String>>,
    #[serde(default)]
    data: Present,
    #[serde(default)]
    artifact_type: Present,
    #[serde(default)]
    platform: Option<Platform>,
}

impl RawDescriptor {
    fn check(self, at: DescriptorAt, limits: &ImportLimits) -> Result<Descriptor, DocumentRefusal> {
        let media_type = match MediaType::from_exact(&self.media_type) {
            Some(media_type) => media_type,
            None if MediaType::is_non_distributable(&self.media_type) => {
                return Err(DocumentRefusal::NonDistributableLayer { at })
            }
            None => {
                return Err(DocumentRefusal::UnknownMediaType {
                    at,
                    media_type: bounded_text(&self.media_type, 128),
                })
            }
        };
        if self.urls.0 {
            return Err(DocumentRefusal::ForeignUrls { at });
        }
        if self.data.0 {
            return Err(DocumentRefusal::EmbeddedData { at });
        }
        if self.artifact_type.0 {
            return Err(DocumentRefusal::ArtifactType);
        }
        let digest = OciDigest::parse(&self.digest)
            .map_err(|refusal| DocumentRefusal::Digest { at, refusal })?;
        let size_bytes =
            u64::try_from(self.size).map_err(|_| DocumentRefusal::NegativeSize { at })?;
        let annotations = self.annotations.map(|map| map.0).unwrap_or_default();
        check_annotations(&annotations, limits)
            .map_err(|refusal| DocumentRefusal::Annotations { refusal })?;
        let platform = match (at, self.platform) {
            (_, None) => None,
            (DescriptorAt::Manifest { .. }, Some(platform)) => {
                platform.check(at, limits)?;
                Some(platform)
            }
            (_, Some(_)) => return Err(DocumentRefusal::UnexpectedPlatform { at }),
        };
        Ok(Descriptor {
            media_type,
            digest,
            size_bytes,
            annotations,
            platform,
        })
    }
}

/// A checked image index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImageIndex {
    pub manifests: Vec<Descriptor>,
    pub annotations: Annotations,
}

/// A checked image manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImageManifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    pub annotations: Annotations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawIndex {
    schema_version: i64,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    artifact_type: Present,
    manifests: Vec<RawDescriptor>,
    #[serde(default)]
    subject: Present,
    #[serde(default)]
    annotations: Option<StrictMap<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawManifest {
    schema_version: i64,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    artifact_type: Present,
    config: RawDescriptor,
    layers: Vec<RawDescriptor>,
    #[serde(default)]
    subject: Present,
    #[serde(default)]
    annotations: Option<StrictMap<String>>,
}

/// Parses `bytes` as JSON within the document size bound.
pub(crate) fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    limits: &ImportLimits,
) -> Result<T, DocumentRefusal> {
    let size_bytes = len_u64(bytes.len());
    if size_bytes > limits.max_document_bytes {
        return Err(DocumentRefusal::TooLarge {
            size_bytes,
            limit_bytes: limits.max_document_bytes,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| DocumentRefusal::Malformed {
        detail: detail(error),
    })
}

fn check_header(
    declared: MediaType,
    schema_version: i64,
    media_type: Option<&str>,
    artifact_type: Present,
    subject: Present,
) -> Result<(), DocumentRefusal> {
    if schema_version != 2 {
        return Err(DocumentRefusal::SchemaVersion {
            found: schema_version,
        });
    }
    let found = media_type.ok_or(DocumentRefusal::MissingMediaType)?;
    if found != declared.as_str() {
        return Err(DocumentRefusal::MediaTypeMismatch {
            declared,
            found: bounded_text(found, 128),
        });
    }
    if artifact_type.0 {
        return Err(DocumentRefusal::ArtifactType);
    }
    if subject.0 {
        return Err(DocumentRefusal::Subject);
    }
    Ok(())
}

/// Parses a verified blob declared as an image index (VM-W33).
pub fn parse_index(
    blob: &VerifiedBlob,
    limits: &ImportLimits,
) -> Result<ImageIndex, DocumentRefusal> {
    let declared = blob.reference().media_type;
    if !declared.is_index() {
        return Err(DocumentRefusal::MediaTypeMismatch {
            declared,
            found: MediaType::ImageIndex.as_str().to_owned(),
        });
    }
    let raw: RawIndex = parse_json(blob.bytes(), limits)?;
    check_header(
        declared,
        raw.schema_version,
        raw.media_type.as_deref(),
        raw.artifact_type,
        raw.subject,
    )?;
    if raw.manifests.len() > limits.max_index_manifests {
        return Err(DocumentRefusal::TooManyManifests {
            count: raw.manifests.len(),
            limit: limits.max_index_manifests,
        });
    }
    let annotations = raw.annotations.map(|map| map.0).unwrap_or_default();
    check_annotations(&annotations, limits)
        .map_err(|refusal| DocumentRefusal::Annotations { refusal })?;
    let mut manifests = Vec::with_capacity(raw.manifests.len());
    for (index, raw) in raw.manifests.into_iter().enumerate() {
        let at = DescriptorAt::Manifest { index };
        let descriptor = raw.check(at, limits)?;
        match descriptor.media_type {
            MediaType::ImageManifest | MediaType::DockerManifest => {}
            MediaType::ImageIndex | MediaType::DockerIndex => {
                return Err(DocumentRefusal::NestedIndex { at })
            }
            media_type => return Err(DocumentRefusal::UnexpectedMediaType { at, media_type }),
        }
        manifests.push(descriptor);
    }
    Ok(ImageIndex {
        manifests,
        annotations,
    })
}

/// Parses a verified blob declared as an image manifest (VM-W33).
pub fn parse_manifest(
    blob: &VerifiedBlob,
    limits: &ImportLimits,
) -> Result<ImageManifest, DocumentRefusal> {
    let declared = blob.reference().media_type;
    if !declared.is_manifest() {
        return Err(DocumentRefusal::MediaTypeMismatch {
            declared,
            found: MediaType::ImageManifest.as_str().to_owned(),
        });
    }
    let raw: RawManifest = parse_json(blob.bytes(), limits)?;
    check_header(
        declared,
        raw.schema_version,
        raw.media_type.as_deref(),
        raw.artifact_type,
        raw.subject,
    )?;
    if raw.layers.is_empty() {
        return Err(DocumentRefusal::NoLayers);
    }
    if raw.layers.len() > limits.max_layers {
        return Err(DocumentRefusal::TooManyLayers {
            count: raw.layers.len(),
            limit: limits.max_layers,
        });
    }
    let annotations = raw.annotations.map(|map| map.0).unwrap_or_default();
    check_annotations(&annotations, limits)
        .map_err(|refusal| DocumentRefusal::Annotations { refusal })?;
    let config = raw.config.check(DescriptorAt::Config, limits)?;
    if !config.media_type.is_config() {
        return Err(DocumentRefusal::UnexpectedMediaType {
            at: DescriptorAt::Config,
            media_type: config.media_type,
        });
    }
    let mut layers = Vec::with_capacity(raw.layers.len());
    for (index, raw) in raw.layers.into_iter().enumerate() {
        let at = DescriptorAt::Layer { index };
        let descriptor = raw.check(at, limits)?;
        if descriptor.media_type.layer_codec().is_none() {
            return Err(DocumentRefusal::UnexpectedMediaType {
                at,
                media_type: descriptor.media_type,
            });
        }
        layers.push(descriptor);
    }
    Ok(ImageManifest {
        config,
        layers,
        annotations,
    })
}

/// The one manifest of `index` whose platform equals `wanted` in every field. No match, or
/// more than one, is refused; there is no fallback to a compatible platform.
pub fn select_platform<'a>(
    index: &'a ImageIndex,
    wanted: &Platform,
) -> Result<&'a Descriptor, DocumentRefusal> {
    let mut matches = index
        .manifests
        .iter()
        .filter(|descriptor| descriptor.platform.as_ref() == Some(wanted));
    let first = matches
        .next()
        .ok_or_else(|| DocumentRefusal::NoMatchingPlatform {
            wanted: wanted.clone(),
        })?;
    let others = matches.count();
    if others > 0 {
        return Err(DocumentRefusal::AmbiguousPlatform {
            wanted: wanted.clone(),
            matches: others.saturating_add(1),
        });
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn blob(media_type: MediaType, value: &serde_json::Value) -> VerifiedBlob {
        let bytes = serde_json::to_vec(value).unwrap();
        VerifiedBlob::verify(
            BlobReference {
                media_type,
                digest: OciDigest::of(&bytes),
                size_bytes: bytes.len() as u64,
            },
            bytes,
        )
        .unwrap()
    }

    fn raw_blob(media_type: MediaType, text: &str) -> VerifiedBlob {
        let bytes = text.as_bytes().to_vec();
        VerifiedBlob::verify(
            BlobReference {
                media_type,
                digest: OciDigest::of(&bytes),
                size_bytes: bytes.len() as u64,
            },
            bytes,
        )
        .unwrap()
    }

    fn digest(seed: &str) -> String {
        OciDigest::of(seed.as_bytes()).to_string()
    }

    fn layer(seed: &str) -> serde_json::Value {
        json!({"mediaType": MediaType::LayerTarGzip.as_str(), "digest": digest(seed), "size": 10})
    }

    fn manifest_json() -> serde_json::Value {
        json!({
            "schemaVersion": 2,
            "mediaType": MediaType::ImageManifest.as_str(),
            "config": {"mediaType": MediaType::ImageConfig.as_str(), "digest": digest("c"), "size": 5},
            "layers": [layer("a"), layer("b")],
            "annotations": {"org.opencontainers.image.title": "demo"}
        })
    }

    fn limits() -> ImportLimits {
        ImportLimits::default()
    }

    fn manifest_with(
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> Result<ImageManifest, DocumentRefusal> {
        let mut value = manifest_json();
        edit(&mut value);
        parse_manifest(&blob(MediaType::ImageManifest, &value), &limits())
    }

    #[test]
    fn docker_schema_two_uses_exact_descriptors_and_refuses_foreign_layers() {
        let mut value = manifest_json();
        value["mediaType"] = json!(MediaType::DockerManifest.as_str());
        value["config"]["mediaType"] = json!(MediaType::DockerConfig.as_str());
        value["layers"][0]["mediaType"] = json!(MediaType::DockerLayerGzip.as_str());
        let manifest = parse_manifest(&blob(MediaType::DockerManifest, &value), &limits()).unwrap();
        assert_eq!(
            manifest.layers[0].media_type.layer_codec(),
            Some(super::super::LayerCodec::Gzip)
        );
        assert!(parse_manifest(&blob(MediaType::ImageManifest, &value), &limits()).is_err());
        value["layers"][0]["mediaType"] =
            json!("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip");
        assert!(matches!(
            parse_manifest(&blob(MediaType::DockerManifest, &value), &limits()),
            Err(DocumentRefusal::NonDistributableLayer { .. })
        ));
    }

    #[test]
    fn a_plain_manifest_parses() {
        let manifest = manifest_with(|_| {}).unwrap();
        assert_eq!(manifest.layers.len(), 2);
        assert_eq!(manifest.config.media_type, MediaType::ImageConfig);
        assert_eq!(manifest.config.size_bytes, 5);
        assert_eq!(manifest.annotations.len(), 1);
    }

    #[test]
    fn only_schema_version_2_with_a_matching_media_type_is_accepted() {
        assert_eq!(
            manifest_with(|v| v["schemaVersion"] = json!(1)),
            Err(DocumentRefusal::SchemaVersion { found: 1 })
        );
        assert_eq!(
            manifest_with(|v| {
                v.as_object_mut().unwrap().remove("mediaType");
            }),
            Err(DocumentRefusal::MissingMediaType)
        );
        assert_eq!(
            manifest_with(|v| v["mediaType"] = json!(MediaType::ImageIndex.as_str())),
            Err(DocumentRefusal::MediaTypeMismatch {
                declared: MediaType::ImageManifest,
                found: MediaType::ImageIndex.as_str().into()
            })
        );
        // A manifest blob declared as an index is never read as one.
        let manifest_bytes = blob(MediaType::ImageManifest, &manifest_json());
        let as_index = VerifiedBlob::verify(
            BlobReference {
                media_type: MediaType::ImageIndex,
                ..*manifest_bytes.reference()
            },
            manifest_bytes.bytes().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            parse_index(&as_index, &limits()),
            Err(DocumentRefusal::Malformed { .. })
        ));
        assert!(matches!(
            parse_manifest(&as_index, &limits()),
            Err(DocumentRefusal::MediaTypeMismatch { .. })
        ));
    }

    #[test]
    fn unknown_fields_and_duplicate_keys_are_refused() {
        assert!(matches!(
            manifest_with(|v| v["extra"] = json!(true)),
            Err(DocumentRefusal::Malformed { .. })
        ));
        assert!(matches!(
            manifest_with(|v| v["layers"][0]["extra"] = json!(1)),
            Err(DocumentRefusal::Malformed { .. })
        ));
        let duplicate_annotation = format!(
            r#"{{"schemaVersion":2,"mediaType":"{}","config":{{"mediaType":"{}","digest":"{}","size":5}},"layers":[{{"mediaType":"{}","digest":"{}","size":1}}],"annotations":{{"a":"1","a":"2"}}}}"#,
            MediaType::ImageManifest.as_str(),
            MediaType::ImageConfig.as_str(),
            digest("c"),
            MediaType::LayerTar.as_str(),
            digest("a")
        );
        assert!(matches!(
            parse_manifest(&raw_blob(MediaType::ImageManifest, &duplicate_annotation), &limits()),
            Err(DocumentRefusal::Malformed { detail }) if detail.contains("duplicate key")
        ));
        let duplicate_field = duplicate_annotation
            .replace(r#""annotations":{"a":"1","a":"2"}"#, r#""schemaVersion":2"#);
        assert!(matches!(
            parse_manifest(&raw_blob(MediaType::ImageManifest, &duplicate_field), &limits()),
            Err(DocumentRefusal::Malformed { detail }) if detail.contains("duplicate field")
        ));
    }

    #[test]
    fn foreign_layers_and_undeclared_backing_files_are_refused() {
        let at = DescriptorAt::Layer { index: 0 };
        assert_eq!(
            manifest_with(|v| v["layers"][0]["urls"] = json!(["https://example.com/l.tgz"])),
            Err(DocumentRefusal::ForeignUrls { at })
        );
        assert_eq!(
            manifest_with(|v| v["layers"][0]["urls"] = json!(null)),
            Err(DocumentRefusal::ForeignUrls { at })
        );
        assert_eq!(
            manifest_with(|v| v["layers"][0]["mediaType"] =
                json!("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip")),
            Err(DocumentRefusal::NonDistributableLayer { at })
        );
        assert_eq!(
            manifest_with(|v| v["layers"][0]["data"] = json!("aGk=")),
            Err(DocumentRefusal::EmbeddedData { at })
        );
        assert_eq!(
            manifest_with(|v| v["artifactType"] = json!("application/x")),
            Err(DocumentRefusal::ArtifactType)
        );
        assert_eq!(
            manifest_with(|v| v["subject"] = layer("s")),
            Err(DocumentRefusal::Subject)
        );
    }

    #[test]
    fn unknown_and_misplaced_media_types_are_refused() {
        assert_eq!(
            manifest_with(|v| v["layers"][1]["mediaType"] =
                json!("application/vnd.oci.image.layer.v1.tar+bzip2")),
            Err(DocumentRefusal::UnknownMediaType {
                at: DescriptorAt::Layer { index: 1 },
                media_type: "application/vnd.oci.image.layer.v1.tar+bzip2".into()
            })
        );
        assert_eq!(
            manifest_with(|v| v["config"]["mediaType"] = json!(MediaType::LayerTar.as_str())),
            Err(DocumentRefusal::UnexpectedMediaType {
                at: DescriptorAt::Config,
                media_type: MediaType::LayerTar
            })
        );
        assert_eq!(
            manifest_with(|v| v["layers"][0]["mediaType"] = json!(MediaType::ImageConfig.as_str())),
            Err(DocumentRefusal::UnexpectedMediaType {
                at: DescriptorAt::Layer { index: 0 },
                media_type: MediaType::ImageConfig
            })
        );
    }

    #[test]
    fn descriptor_fields_are_checked() {
        assert_eq!(
            manifest_with(|v| v["layers"][0]["size"] = json!(-1)),
            Err(DocumentRefusal::NegativeSize {
                at: DescriptorAt::Layer { index: 0 }
            })
        );
        assert_eq!(
            manifest_with(|v| v["layers"][0]["digest"] = json!("sha512:00")),
            Err(DocumentRefusal::Digest {
                at: DescriptorAt::Layer { index: 0 },
                refusal: DigestRefusal::UnsupportedAlgorithm {
                    algorithm: "sha512".into()
                }
            })
        );
        assert_eq!(
            manifest_with(
                |v| v["layers"][0]["platform"] = json!({"os": "linux", "architecture": "amd64"})
            ),
            Err(DocumentRefusal::UnexpectedPlatform {
                at: DescriptorAt::Layer { index: 0 }
            })
        );
        assert_eq!(
            manifest_with(|v| v["layers"] = json!([])),
            Err(DocumentRefusal::NoLayers)
        );
        let many: Vec<_> = (0..129).map(|i| layer(&i.to_string())).collect();
        assert_eq!(
            manifest_with(|v| v["layers"] = json!(many)),
            Err(DocumentRefusal::TooManyLayers {
                count: 129,
                limit: 128
            })
        );
    }

    #[test]
    fn annotations_are_bounded() {
        let tight = ImportLimits {
            max_annotations: 2,
            max_annotation_key_bytes: 8,
            max_annotation_value_bytes: 8,
            max_annotation_total_bytes: 20,
            ..limits()
        };
        let parse = |annotations: serde_json::Value| {
            let mut value = manifest_json();
            value["annotations"] = annotations;
            parse_manifest(&blob(MediaType::ImageManifest, &value), &tight)
        };
        assert!(parse(json!({"a": "1", "b": "2"})).is_ok());
        assert_eq!(
            parse(json!({"a": "1", "b": "2", "c": "3"})),
            Err(DocumentRefusal::Annotations {
                refusal: AnnotationRefusal::TooMany { count: 3, limit: 2 }
            })
        );
        assert_eq!(
            parse(json!({"123456789": "1"})),
            Err(DocumentRefusal::Annotations {
                refusal: AnnotationRefusal::KeyTooLong { bytes: 9, limit: 8 }
            })
        );
        assert_eq!(
            parse(json!({"k": "123456789"})),
            Err(DocumentRefusal::Annotations {
                refusal: AnnotationRefusal::ValueTooLong {
                    key: "k".into(),
                    bytes: 9,
                    limit: 8
                }
            })
        );
        assert_eq!(
            parse(json!({"aaaaaaaa": "bbbbbbbb", "cc": "dddddd"})),
            Err(DocumentRefusal::Annotations {
                refusal: AnnotationRefusal::TotalTooLarge {
                    bytes: 24,
                    limit: 20
                }
            })
        );
        let big = ImportLimits {
            max_document_bytes: 10,
            ..limits()
        };
        assert!(matches!(
            parse_manifest(&blob(MediaType::ImageManifest, &manifest_json()), &big),
            Err(DocumentRefusal::TooLarge {
                limit_bytes: 10,
                ..
            })
        ));
    }

    fn index_json(platforms: &[serde_json::Value]) -> serde_json::Value {
        let manifests: Vec<_> = platforms
            .iter()
            .enumerate()
            .map(|(i, platform)| {
                json!({
                    "mediaType": MediaType::ImageManifest.as_str(),
                    "digest": digest(&format!("m{i}")),
                    "size": 100,
                    "platform": platform
                })
            })
            .collect();
        json!({"schemaVersion": 2, "mediaType": MediaType::ImageIndex.as_str(), "manifests": manifests})
    }

    #[test]
    fn platform_selection_is_exact_and_never_falls_back() {
        let index = parse_index(
            &blob(
                MediaType::ImageIndex,
                &index_json(&[
                    json!({"os": "linux", "architecture": "amd64"}),
                    json!({"os": "linux", "architecture": "arm64", "variant": "v8"}),
                    json!({"os": "windows", "architecture": "amd64", "os.version": "10.0.20348.1"}),
                ]),
            ),
            &limits(),
        )
        .unwrap();
        assert_eq!(
            select_platform(&index, &Platform::new("linux", "amd64"))
                .unwrap()
                .digest
                .to_string(),
            digest("m0")
        );
        assert_eq!(
            select_platform(&index, &Platform::new("linux", "arm64").with_variant("v8"))
                .unwrap()
                .digest
                .to_string(),
            digest("m1")
        );
        // No variant requested: the v8 entry is not "close enough".
        assert_eq!(
            select_platform(&index, &Platform::new("linux", "arm64")),
            Err(DocumentRefusal::NoMatchingPlatform {
                wanted: Platform::new("linux", "arm64")
            })
        );
        // A Windows entry with an os.version is not matched without it.
        assert!(select_platform(&index, &Platform::new("windows", "amd64")).is_err());
        assert!(select_platform(&index, &Platform::new("linux", "386")).is_err());
        let twice = parse_index(
            &blob(
                MediaType::ImageIndex,
                &index_json(&[
                    json!({"os": "linux", "architecture": "amd64"}),
                    json!({"os": "linux", "architecture": "amd64"}),
                ]),
            ),
            &limits(),
        )
        .unwrap();
        assert_eq!(
            select_platform(&twice, &Platform::new("linux", "amd64")),
            Err(DocumentRefusal::AmbiguousPlatform {
                wanted: Platform::new("linux", "amd64"),
                matches: 2
            })
        );
    }

    #[test]
    fn index_entries_are_checked() {
        let mut nested = index_json(&[json!({"os": "linux", "architecture": "amd64"})]);
        nested["manifests"][0]["mediaType"] = json!(MediaType::ImageIndex.as_str());
        assert_eq!(
            parse_index(&blob(MediaType::ImageIndex, &nested), &limits()),
            Err(DocumentRefusal::NestedIndex {
                at: DescriptorAt::Manifest { index: 0 }
            })
        );
        let mut unknown_platform_field =
            index_json(&[json!({"os": "linux", "architecture": "amd64"})]);
        unknown_platform_field["manifests"][0]["platform"]["cpu"] = json!("fast");
        assert!(matches!(
            parse_index(
                &blob(MediaType::ImageIndex, &unknown_platform_field),
                &limits()
            ),
            Err(DocumentRefusal::Malformed { .. })
        ));
        let long = index_json(&[json!({"os": "linux", "architecture": "a".repeat(129)})]);
        assert_eq!(
            parse_index(&blob(MediaType::ImageIndex, &long), &limits()),
            Err(DocumentRefusal::PlatformFieldTooLong {
                at: DescriptorAt::Manifest { index: 0 },
                bytes: 129,
                limit: 128
            })
        );
        let platforms: Vec<_> = (0..257)
            .map(|_| json!({"os": "linux", "architecture": "amd64"}))
            .collect();
        assert_eq!(
            parse_index(
                &blob(MediaType::ImageIndex, &index_json(&platforms)),
                &limits()
            ),
            Err(DocumentRefusal::TooManyManifests {
                count: 257,
                limit: 256
            })
        );
    }
}
