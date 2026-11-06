//! The catalog verifier for [`ArtifactClass::OciLayer`] (S2 CORE-02 specialized importers;
//! INT-09; §5.3 "a digest proves content identity, not publisher trust"; §8.3 line 2278).
//!
//! Trust is decided by the catalog: its [`TrustPolicy`](crate::foundation::catalog::TrustPolicy)
//! names the publishers trusted for the class, and this verifier authenticates a claim.
//! An attestation carries the publisher's signature over the image manifest digest, the
//! manifest and config bytes, the object's envelope prefix and its extent table.
//! [`OciVerifier::authenticate`] accepts it only when:
//!
//! - the extent table is the one being imported (its digest equals the catalog's
//!   declaration digest, which binds the content key and length) and its first extent is
//!   exactly the attested prefix;
//! - the signature verifies for the claimed publisher through [`PublisherSignatures`];
//! - the config is the manifest's config; and
//! - the prefix names that manifest's layer (descriptor and diff_id) or its whole layer
//!   list (for a tree).
//!
//! A forged claim fails one of these: a publisher whose key did not sign the manifest, or
//! a valid signature attached to different content. [`OciVerifier::validate`] needs no
//! claim: it re-reads the committed envelope, re-verifies the blob's sha256 and re-runs the
//! layer or tree checks, so a later re-verification by the catalog keeps working.
//!
//! [`PublisherSignatures`] is a port. Tier 0 has no signature library; real verification
//! of publisher keys, with rotation and revocation (§8.3), is runtime work.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::config::config_diff_ids;
use super::digest::{BlobReference, MediaType, OciDigest, VerifiedBlob};
use super::document::parse_manifest;
use super::envelope::{
    parse_fixed, parse_header, parse_prefix, EnvelopeHeader, EnvelopeKind, FIXED_PREFIX_BYTES,
};
use super::layer::{read_layer, ImageBudget};
use super::limits::{detail, len_u64, ImportLimits, LimitsProblem};
use super::tree::TreeIndex;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, ContentDescriptor, ExtentDigest, ImportManifest, ObjectBytes,
    PublisherId, VerifierRejection,
};
use crate::foundation::ids::{Digest, DigestBuilder};

/// Domain of [`manifest_statement`].
pub const STATEMENT_DOMAIN: &str = "yougori/oci/manifest-statement/v1";

/// What a publisher signs: a domain-separated digest naming one image manifest digest.
pub fn manifest_statement(manifest: &OciDigest) -> Digest {
    DigestBuilder::new(STATEMENT_DOMAIN)
        .bytes(manifest.as_bytes())
        .finish()
}

/// Why a publisher signature was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureRefusal {
    /// No key is known for the publisher.
    UnknownPublisher,
    /// The signature does not verify under the publisher's key.
    BadSignature,
}

impl fmt::Display for SignatureRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPublisher => f.write_str("no key is known for the publisher"),
            Self::BadSignature => f.write_str("the signature does not verify"),
        }
    }
}

impl std::error::Error for SignatureRefusal {}

/// Verifies a publisher's signature over a statement (§8.3). A port: the runtime supplies
/// the key store and algorithm; tests use a keyed-digest fake. Accepting a signature here
/// is authenticity only; whether the publisher is trusted is the catalog policy's call.
pub trait PublisherSignatures: Send + Sync {
    /// Whether `signature` is `publisher`'s signature over `statement`.
    fn verify(
        &self,
        publisher: &PublisherId,
        statement: &Digest,
        signature: &[u8],
    ) -> Result<(), SignatureRefusal>;
}

/// Domain tag in the attestation wire format.
const ATTESTATION_FORMAT: &str = "yougori.oci.attestation.v1";

/// A publisher claim about one catalog object of an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciAttestation {
    /// The image manifest bytes; their sha256 is the signed manifest digest.
    pub manifest: Vec<u8>,
    /// The image config bytes, which the manifest names.
    pub config: Vec<u8>,
    /// The publisher's signature over [`manifest_statement`].
    pub signature: Vec<u8>,
    /// The object's envelope prefix, its first extent.
    pub prefix: Vec<u8>,
    /// The object's whole catalog declaration.
    pub import_manifest: ImportManifest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAttestation {
    format: String,
    manifest: String,
    config: String,
    signature: String,
    prefix: String,
    import_manifest: ImportManifest,
}

fn wrong_format(text: impl fmt::Display) -> VerifierRejection {
    VerifierRejection::WrongFormat {
        detail: detail(text),
    }
}

fn corrupt(text: impl fmt::Display) -> VerifierRejection {
    VerifierRejection::CorruptStructure {
        detail: detail(text),
    }
}

impl OciAttestation {
    /// The wire form carried in a catalog trust claim.
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireAttestation {
            format: ATTESTATION_FORMAT.to_owned(),
            manifest: hex::encode(&self.manifest),
            config: hex::encode(&self.config),
            signature: hex::encode(&self.signature),
            prefix: hex::encode(&self.prefix),
            import_manifest: self.import_manifest.clone(),
        };
        serde_json::to_vec(&wire).unwrap_or_default()
    }

    /// Parses the wire form within `limit_bytes`.
    pub fn decode(bytes: &[u8], limit_bytes: u64) -> Result<Self, VerifierRejection> {
        if len_u64(bytes.len()) > limit_bytes {
            return Err(wrong_format(format!(
                "a {}-byte attestation; at most {limit_bytes}",
                bytes.len()
            )));
        }
        let wire: WireAttestation = serde_json::from_slice(bytes).map_err(wrong_format)?;
        if wire.format != ATTESTATION_FORMAT {
            return Err(wrong_format("unknown attestation format"));
        }
        let decode = |text: &str| hex::decode(text).map_err(wrong_format);
        Ok(Self {
            manifest: decode(&wire.manifest)?,
            config: decode(&wire.config)?,
            signature: decode(&wire.signature)?,
            prefix: decode(&wire.prefix)?,
            import_manifest: wire.import_manifest,
        })
    }
}

/// Checks a publisher's signature over the manifest digest of `manifest`; for the
/// importer's early refusal and for [`OciVerifier::authenticate`].
pub(crate) fn check_signature(
    signatures: &dyn PublisherSignatures,
    publisher: &PublisherId,
    manifest: &OciDigest,
    signature: &[u8],
) -> Result<(), SignatureRefusal> {
    signatures.verify(publisher, &manifest_statement(manifest), signature)
}

/// The catalog verifier of [`ArtifactClass::OciLayer`] objects.
#[derive(Clone)]
pub struct OciVerifier {
    signatures: Arc<dyn PublisherSignatures>,
    limits: ImportLimits,
    /// Whether a layer envelope's tar stream is read here, or only its blob's digest and
    /// size checked ([`Self::without_host_layer_parsing`]).
    parse_layers: bool,
}

impl fmt::Debug for OciVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OciVerifier")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl OciVerifier {
    /// A verifier under `limits`, which must be enforceable, checking signatures through
    /// `signatures`.
    pub fn new(
        signatures: Arc<dyn PublisherSignatures>,
        limits: ImportLimits,
    ) -> Result<Self, LimitsProblem> {
        limits.validate()?;
        Ok(Self {
            signatures,
            limits,
            parse_layers: true,
        })
    }

    /// For limits that already passed [`ImportLimits::validate`].
    pub(crate) fn with_checked_limits(
        signatures: Arc<dyn PublisherSignatures>,
        limits: ImportLimits,
    ) -> Self {
        Self {
            signatures,
            limits,
            parse_layers: true,
        }
    }

    /// The same verifier, checking a layer envelope by its blob's digest and size only: the
    /// tar stream is never parsed on the host (§5.2; the engine's importer reads layers inside
    /// a VM, and consumers check every byte as they materialize them).
    pub fn without_host_layer_parsing(mut self) -> Self {
        self.parse_layers = false;
        self
    }

    fn read(
        bytes: &mut ObjectBytes,
        offset_bytes: u64,
        length: usize,
    ) -> Result<Vec<u8>, VerifierRejection> {
        let mut buffer = vec![0u8; length];
        bytes
            .read_exact_at(offset_bytes, &mut buffer)
            .map_err(|error| VerifierRejection::Unreadable {
                detail: detail(error),
            })?;
        Ok(buffer)
    }
}

impl ArtifactVerifier for OciVerifier {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::OciLayer
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        let attestation = OciAttestation::decode(attestation, self.limits.max_attestation_bytes)?;
        let declared = &attestation.import_manifest;
        let bound = content.class == ArtifactClass::OciLayer
            && declared.digest() == content.manifest_digest
            && declared.content_key == content.content_key
            && declared.true_length_bytes == content.length_bytes;
        if !bound {
            return Err(VerifierRejection::AttestationInvalid);
        }
        let first_is_prefix = declared.extents.first().is_some_and(|first| {
            first.offset_bytes == 0
                && first.length_bytes == len_u64(attestation.prefix.len())
                && first.digest == ExtentDigest::of(&attestation.prefix)
        });
        if !first_is_prefix {
            return Err(VerifierRejection::AttestationInvalid);
        }
        let header = parse_prefix(&attestation.prefix).map_err(corrupt)?;
        let manifest_digest = OciDigest::of(&attestation.manifest);
        check_signature(
            self.signatures.as_ref(),
            publisher,
            &manifest_digest,
            &attestation.signature,
        )
        .map_err(|_| VerifierRejection::AttestationInvalid)?;
        let manifest_blob = VerifiedBlob::verify(
            BlobReference {
                media_type: MediaType::ImageManifest,
                digest: manifest_digest,
                size_bytes: len_u64(attestation.manifest.len()),
            },
            attestation.manifest,
        )
        .map_err(corrupt)?;
        let manifest = parse_manifest(&manifest_blob, &self.limits).map_err(corrupt)?;
        let config = VerifiedBlob::verify(manifest.config.reference(), attestation.config)
            .map_err(|_| VerifierRejection::AttestationInvalid)?;
        let diff_ids =
            config_diff_ids(&config, manifest.layers.len(), &self.limits).map_err(corrupt)?;
        let names_it = match header {
            EnvelopeHeader::Layer(header) => {
                manifest
                    .layers
                    .iter()
                    .zip(&diff_ids)
                    .any(|(layer, diff_id)| {
                        layer.reference() == header.layer && *diff_id == header.diff_id
                    })
            }
            EnvelopeHeader::Tree(header) => {
                header.manifest == manifest_digest
                    && header.config == manifest.config.digest
                    && header
                        .layers
                        .iter()
                        .eq(manifest.layers.iter().map(|layer| &layer.digest))
                    && header.diff_ids == diff_ids
            }
        };
        if !names_it {
            return Err(VerifierRejection::AttestationInvalid);
        }
        Ok(())
    }

    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        if content.class != ArtifactClass::OciLayer {
            return Err(wrong_format("not an OCI object"));
        }
        let length_bytes = bytes.length_bytes();
        let fixed = Self::read(bytes, 0, FIXED_PREFIX_BYTES)?;
        let (kind, header_length) = parse_fixed(&fixed).map_err(wrong_format)?;
        let header_offset = len_u64(FIXED_PREFIX_BYTES);
        let header_bytes = Self::read(bytes, header_offset, header_length)?;
        let header = parse_header(kind, &header_bytes).map_err(corrupt)?;
        let body_offset = header_offset.saturating_add(len_u64(header_length));
        let body_length = length_bytes
            .checked_sub(body_offset)
            .ok_or_else(|| corrupt("the envelope is shorter than its prefix"))?;
        let limit = match kind {
            EnvelopeKind::Layer => self.limits.max_layer_compressed_bytes,
            EnvelopeKind::Tree => self.limits.max_tree_object_bytes,
        };
        if body_length > limit {
            return Err(corrupt(format!(
                "a {body_length}-byte body; at most {limit}"
            )));
        }
        let body_length = usize::try_from(body_length).map_err(corrupt)?;
        let body = Self::read(bytes, body_offset, body_length)?;
        match header {
            EnvelopeHeader::Layer(header) => {
                let blob = VerifiedBlob::verify(header.layer, body).map_err(corrupt)?;
                if self.parse_layers {
                    let mut budget = ImageBudget::new(&self.limits);
                    read_layer(&blob, &header.diff_id, &self.limits, &mut budget)
                        .map_err(corrupt)?;
                }
            }
            EnvelopeHeader::Tree(header) => {
                if header.layers.len() != header.diff_ids.len() {
                    return Err(corrupt(
                        "the tree header's layers and diff_ids differ in number",
                    ));
                }
                let layers = u32::try_from(header.layers.len()).map_err(corrupt)?;
                TreeIndex::from_body(&body, layers, &self.limits).map_err(corrupt)?;
            }
        }
        Ok(())
    }
}
