//! OCI layers: layer and config blobs admitted only through V10's import, against an
//! image manifest signed under V10's own statement and checked through the trust roots
//! (VM-W48, line 2671; VM-W33, line 2649; §5.3: "a digest proves content identity, not
//! publisher trust"; V10's `sandbox_contract::oci`; M18's
//! `trust_adapter::TrustRootSignatures`).
//!
//! **Local, not signed.** V10's publisher signs `oci::manifest_statement` (domain
//! `yougori/oci/manifest-statement/v1`): the image manifest's digest, with no publisher
//! identity and no class, once for the whole image. The catalog's statement bindings
//! sign one object each, its content key (`StatementBinding::Content`) or its declaration
//! (`StatementBinding::Manifest`), with the publisher and the class, and the objects V10
//! publishes are envelopes (a header and a layer blob, or a tree index) whose content
//! keys the publisher never sees. A binding would need a second OCI statement per
//! object, so the class is registered as `OfferedClass::Local` with V10's own
//! [`OciVerifier`](crate::sandbox_contract::oci::OciVerifier) from
//! [`OciImporter::verifier`], whose signature port is
//! [`TrustRootSignatures`](crate::sandbox_contract::trust_adapter::TrustRootSignatures)
//! (the trust roots' `oci_layer` keys, their windows and revocations), with the trust
//! roots as its policy source (`OfferedClass::LocalWithPolicy`,
//! [`roots_policy`](super::roots_policy)).
//!
//! **Pins** ([`import_pinned`]). V10's request already names its root by digest and
//! size, verifies every blob against its descriptor before parsing it, and refuses a
//! checksum as trust; this entry adds the pins of `sandbox::trust::provenance` (VM-W48's
//! typed OCI provenance) before and during the fetch:
//!
//! - the reference must be the digest of the pinned root: a mutable tag is refused before
//!   anything is fetched, and so is a digest that names another root;
//! - every blob the registry serves is checked with `Provenance::check_pins`: bytes
//!   served by another host than the pinned registry (a redirect) are refused before
//!   V10 reads them; bytes that differ from the pinned digest are refused by V10.
//!
//! Either way nothing is published, so a redirect or a tag cannot change what is
//! admitted. Objects stay per scope: importing the same digests into another scope makes
//! that scope's own objects under its own claim, and never serves the first scope's.

use std::fmt;

use crate::foundation::catalog::Catalog;
use crate::foundation::ids::{ContentKey, Digest};
use crate::sandbox::trust::{
    OciProvenance, OciReference, Provenance, ProvenanceRefusal, RegistryHost, RepositoryPath,
};
use crate::sandbox_contract::oci::{
    BlobSource, BlobSourceError, ImportedImage, OciDigest, OciImportError, OciImportRequest,
    OciImporter,
};

/// Where an image is pinned, as its caller declares it before anything is fetched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImagePin {
    /// The registry the image is pinned to.
    pub registry: RegistryHost,
    pub repository: RepositoryPath,
    /// The digest of the pinned root (an image index or manifest); a tag is refused.
    pub reference: OciReference,
}

impl ImagePin {
    /// The typed provenance (`sandbox::trust::Provenance::Oci`) of bytes with content key
    /// `content` that `served_by` delivered under this pin.
    pub fn provenance(&self, served_by: RegistryHost, content: ContentKey) -> OciProvenance {
        OciProvenance {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            reference: self.reference.clone(),
            served_by,
            layer: content,
        }
    }
}

/// One blob as a registry served it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedBlob {
    pub bytes: Vec<u8>,
    /// The host that finally served the bytes, after any redirect, as the fetch layer
    /// observed it.
    pub served_by: RegistryHost,
}

/// A registry the importer fetches blobs from by digest. A port: the runtime supplies the
/// transport. An implementation must not return more than `max_bytes`; the importer checks
/// the length and digest of whatever it returns.
pub trait RegistrySource {
    fn fetch(
        &mut self,
        repository: &RepositoryPath,
        digest: &OciDigest,
        max_bytes: u64,
    ) -> Result<ServedBlob, BlobSourceError>;
}

/// Why a pinned import was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinnedImportError {
    /// The pins refused the image: a mutable tag before anything was fetched, or bytes
    /// served by another host than the pinned registry. Nothing was published.
    Provenance { refusal: ProvenanceRefusal },
    /// The reference is a digest, but not the digest of the request's pinned root.
    /// Nothing was fetched.
    ReferenceNotRoot { reference: Digest, root: OciDigest },
    /// V10's import refused or failed (a blob that is not its pinned digest, a refused
    /// signature or publisher, a layer, the catalog). As V10 documents, only a catalog
    /// failure after the first object can leave earlier layers published.
    Import { error: Box<OciImportError> },
}

impl fmt::Display for PinnedImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provenance { refusal } => refusal.fmt(f),
            Self::ReferenceNotRoot { reference, root } => write!(
                f,
                "the reference names {reference}, not the pinned root {root}"
            ),
            Self::Import { error } => error.fmt(f),
        }
    }
}

impl std::error::Error for PinnedImportError {}

/// V10's blob source over a registry, checking each served blob's pins first.
struct PinnedBlobs<'a> {
    pin: &'a ImagePin,
    registry: &'a mut dyn RegistrySource,
    /// The first pin refusal, kept so the import's error can name it.
    refusal: Option<ProvenanceRefusal>,
}

impl BlobSource for PinnedBlobs<'_> {
    fn read_blob(
        &mut self,
        digest: &OciDigest,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BlobSourceError> {
        let served = self
            .registry
            .fetch(&self.pin.repository, digest, max_bytes)?;
        let provenance = Provenance::Oci(
            self.pin
                .provenance(served.served_by, ContentKey::of(&served.bytes)),
        );
        if let Err(refusal) = provenance.check_pins() {
            let detail = refusal.to_string();
            self.refusal.get_or_insert(refusal);
            return Err(BlobSourceError { detail });
        }
        Ok(served.bytes)
    }
}

/// Imports the image `request` pins into `catalog` through V10's `importer`, fetching
/// from `registry` under `pin`. See the module documentation.
pub fn import_pinned(
    importer: &OciImporter,
    catalog: &mut Catalog,
    registry: &mut dyn RegistrySource,
    pin: &ImagePin,
    request: &OciImportRequest,
) -> Result<ImportedImage, PinnedImportError> {
    match &pin.reference {
        OciReference::Tag { tag } => {
            return Err(PinnedImportError::Provenance {
                refusal: ProvenanceRefusal::MutableTag { tag: tag.clone() },
            })
        }
        OciReference::Digest { manifest }
            if manifest.as_bytes() == request.root.digest.as_bytes() => {}
        OciReference::Digest { manifest } => {
            return Err(PinnedImportError::ReferenceNotRoot {
                reference: *manifest,
                root: request.root.digest,
            })
        }
    }
    let mut blobs = PinnedBlobs {
        pin,
        registry,
        refusal: None,
    };
    let imported = importer.import(catalog, &mut blobs, request);
    imported.map_err(|error| match blobs.refusal.take() {
        Some(refusal) => PinnedImportError::Provenance { refusal },
        None => PinnedImportError::Import {
            error: Box::new(error),
        },
    })
}
