//! OCI layers through V10's import against a real catalog service: an image signed by
//! the trust roots' OCI key is admitted; wrong signatures, wrong-class and revoked keys,
//! a mutable tag, a registry redirect, a substituted manifest, another scope and a
//! corrupted local object are refused, and nothing refused is published or readable
//! (VM-W48, line 2671).

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::json;

use super::tests::{
    execution, keys, keys_revoking, operation, pair, publisher, tenant, Fixture, GUEST, OCI,
    REVOKED, ROGUE,
};
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, IntegrityFailure, ObjectStatus, ReadError, ReadRefusal, Scope, TrustBasis,
    VerifyError,
};
use crate::foundation::ids::Digest;
use crate::sandbox::trust::{
    admit_cache_hit, admit_execution, identify, Attestation, CacheHit, ExecutionPermission,
    HexBytes, OciReference, Provenance, ProvenanceRecord, ProvenanceRefusal, RegistryHost,
    RepositoryPath,
};
use crate::sandbox_contract::files::InspectionMethod;
use crate::sandbox_contract::oci::{
    manifest_statement, BlobAt, BlobReference, BlobSourceError, MediaType, OciDigest,
    OciImportError, OciImportRequest, OciTrust, Platform, SignatureRefusal,
};

pub(super) const REGISTRY: &str = "registry.example";
pub(super) const REPOSITORY: &str = "library/app";

/// An image in blobs: one uncompressed layer holding `app/main`.
pub(super) struct ImageFx {
    pub blobs: BTreeMap<OciDigest, Vec<u8>>,
    pub root: BlobReference,
    pub manifest_bytes: Vec<u8>,
}

fn header(kind: tar::EntryType, size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1_700_000_000);
    header
}

fn layer_tar(main: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut dir = header(tar::EntryType::Directory, 0, 0o755);
    builder.append_data(&mut dir, "app", &[][..]).unwrap();
    let mut file = header(tar::EntryType::Regular, main.len() as u64, 0o644);
    builder.append_data(&mut file, "app/main", main).unwrap();
    builder.into_inner().unwrap()
}

fn blob(
    blobs: &mut BTreeMap<OciDigest, Vec<u8>>,
    media_type: MediaType,
    bytes: Vec<u8>,
) -> BlobReference {
    let digest = OciDigest::of(&bytes);
    let size_bytes = bytes.len() as u64;
    blobs.insert(digest, bytes);
    BlobReference {
        media_type,
        digest,
        size_bytes,
    }
}

fn descriptor(reference: &BlobReference) -> serde_json::Value {
    json!({
        "mediaType": reference.media_type.as_str(),
        "digest": reference.digest.to_string(),
        "size": reference.size_bytes,
    })
}

/// An image whose one layer holds `app/main` with `main`.
pub(super) fn image(main: &[u8]) -> ImageFx {
    let mut blobs = BTreeMap::new();
    let tar = layer_tar(main);
    let diff_id = OciDigest::of(&tar);
    let layer = blob(&mut blobs, MediaType::LayerTar, tar);
    let config = json!({
        "created": "2026-10-01T12:00:00Z",
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": ["PATH=/usr/bin"], "Cmd": ["/app/main"]},
        "rootfs": {"type": "layers", "diff_ids": [diff_id.to_string()]},
    });
    let config = blob(
        &mut blobs,
        MediaType::ImageConfig,
        serde_json::to_vec(&config).unwrap(),
    );
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MediaType::ImageManifest.as_str(),
        "config": descriptor(&config),
        "layers": [descriptor(&layer)],
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let root = blob(&mut blobs, MediaType::ImageManifest, manifest_bytes.clone());
    ImageFx {
        blobs,
        root,
        manifest_bytes,
    }
}

pub(super) fn host(name: &str) -> RegistryHost {
    RegistryHost::new(name).unwrap()
}

/// A registry serving blobs by digest, as the host `served_by` after any redirect.
pub(super) struct Registry {
    pub blobs: BTreeMap<OciDigest, Vec<u8>>,
    pub served_by: RegistryHost,
    pub fetched: Vec<OciDigest>,
}

impl Registry {
    pub(super) fn serving(fx: &ImageFx) -> Self {
        Self {
            blobs: fx.blobs.clone(),
            served_by: host(REGISTRY),
            fetched: Vec::new(),
        }
    }
}

impl RegistrySource for Registry {
    fn fetch(
        &mut self,
        repository: &RepositoryPath,
        digest: &OciDigest,
        max_bytes: u64,
    ) -> Result<ServedBlob, BlobSourceError> {
        assert_eq!(repository.as_str(), REPOSITORY);
        self.fetched.push(*digest);
        let bytes = self.blobs.get(digest).ok_or_else(|| BlobSourceError {
            detail: format!("no blob {digest}"),
        })?;
        let length = bytes.len().min(max_bytes as usize);
        Ok(ServedBlob {
            bytes: bytes[..length].to_vec(),
            served_by: self.served_by.clone(),
        })
    }
}

/// `seed`'s signature over V10's statement about the image's manifest.
pub(super) fn signed_trust(fx: &ImageFx, seed: u8) -> OciTrust {
    let statement = manifest_statement(&OciDigest::of(&fx.manifest_bytes));
    OciTrust::Publisher {
        publisher: publisher(seed),
        signature: pair(seed).sign(statement.as_bytes()).as_ref().to_vec(),
    }
}

/// The pin of `fx`'s root on the test registry.
pub(super) fn pin_of(fx: &ImageFx) -> ImagePin {
    ImagePin {
        registry: host(REGISTRY),
        repository: RepositoryPath::new(REPOSITORY).unwrap(),
        reference: OciReference::Digest {
            manifest: Digest::from_bytes(*fx.root.digest.as_bytes()),
        },
    }
}

/// The pin and V10 request importing `fx` into `scope`, signed by `seed`.
pub(super) fn publish_request(
    fx: &ImageFx,
    scope: Scope,
    seed: u8,
) -> (ImagePin, OciImportRequest) {
    let request = OciImportRequest {
        operation: operation(),
        importer: execution("oci-importer"),
        scope,
        root: fx.root,
        platform: Platform::new("linux", "amd64"),
        trust: signed_trust(fx, seed),
        inspection: InspectionMethod::SeparateVm,
    };
    (pin_of(fx), request)
}

/// The typed provenance record of one published object of `fx`.
fn record(fx: &ImageFx, content: crate::foundation::ids::ContentKey) -> ProvenanceRecord {
    ProvenanceRecord {
        provenance: Provenance::Oci(pin_of(fx).provenance(host(REGISTRY), content)),
        attestation: Attestation {
            publisher: publisher(OCI),
            attestation: HexBytes::new(Vec::new()),
        },
    }
}

fn import(
    opened: &super::tests::Opened,
    registry: &mut Registry,
    pin: &ImagePin,
    request: &OciImportRequest,
) -> Result<crate::sandbox_contract::oci::ImportedImage, PinnedImportError> {
    import_pinned(
        opened.classes.oci(),
        &mut opened.service.catalog(),
        registry,
        pin,
        request,
    )
}

#[test]
fn an_image_signed_by_the_oci_key_is_admitted_through_v10() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"#!/bin/sh\necho hi\n");
    let mut registry = Registry::serving(&fx);
    let a = tenant("a");
    let (pin, request) = publish_request(&fx, a.clone(), OCI);
    let imported = import(&opened, &mut registry, &pin, &request).unwrap();
    assert_eq!(imported.layers.len(), 1);
    assert!(!imported.layers[0].cache_hit && !imported.tree.cache_hit);
    // Every blob came from the pinned registry by digest: manifest, config, layer.
    assert_eq!(registry.fetched.len(), 3);
    assert_eq!(registry.fetched[0], fx.root.digest);

    let catalog = opened.service.catalog();
    for object in [imported.layers[0].object, imported.tree.object] {
        assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
        let metadata = catalog.private_metadata(&a, object).unwrap();
        assert_eq!(metadata.class, ArtifactClass::OciLayer);
        assert_eq!(
            metadata.trust,
            TrustBasis::Publisher {
                publisher: publisher(OCI)
            }
        );
        // Identified through its typed provenance and the catalog's own policy; execution
        // still needs a permission for this exact object.
        let identity = identify(&catalog, &a, &record(&fx, metadata.content_key)).unwrap();
        assert_eq!(identity.object(), object);
        let permission = ExecutionPermission {
            scope: a.clone(),
            execution: execution("sandbox-1"),
            object,
        };
        assert!(admit_execution(&catalog, &identity, &permission).is_ok());
    }
}

#[test]
fn wrong_signatures_and_wrong_class_or_revoked_keys_admit_no_layer() {
    use crate::sandbox_contract::oci::ProvenanceRefusal as V10Refusal;

    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"payload");
    let a = tenant("a");
    let genuine = match signed_trust(&fx, OCI) {
        OciTrust::Publisher { signature, .. } => signature,
        other => panic!("{other:?}"),
    };
    let mut flipped = genuine.clone();
    flipped[9] ^= 0x01;
    let raw_digest = pair(OCI)
        .sign(OciDigest::of(&fx.manifest_bytes).as_bytes())
        .as_ref()
        .to_vec();
    let by = |seed: u8, signature: Vec<u8>| OciTrust::Publisher {
        publisher: publisher(seed),
        signature,
    };
    let bad_signature = V10Refusal::SignatureRejected {
        refusal: SignatureRefusal::BadSignature,
    };
    let not_trusted = |seed: u8| V10Refusal::PublisherNotTrusted {
        publisher: publisher(seed),
    };
    let cases = [
        // A damaged signature, another key's signature, and the key's signature over the
        // raw digest instead of V10's statement.
        (by(OCI, flipped), bad_signature.clone()),
        (by(OCI, signed_of(&fx, ROGUE)), bad_signature.clone()),
        (by(OCI, raw_digest), bad_signature),
        // A key in no trust-root file, a guest image key and a revoked key.
        (signed_trust(&fx, ROGUE), not_trusted(ROGUE)),
        (signed_trust(&fx, GUEST), not_trusted(GUEST)),
        (signed_trust(&fx, REVOKED), not_trusted(REVOKED)),
        // A digest is never trust.
        (OciTrust::ChecksumOnly, V10Refusal::ChecksumIsNotTrust),
    ];
    for (trust_claim, expected) in cases {
        let (pin, mut request) = publish_request(&fx, a.clone(), OCI);
        request.trust = trust_claim;
        let mut registry = Registry::serving(&fx);
        assert_eq!(
            import(&opened, &mut registry, &pin, &request),
            Err(PinnedImportError::Import {
                error: Box::new(OciImportError::Provenance { refusal: expected })
            })
        );
    }
    // Nothing of the image is published in the scope, so nothing of it is readable there.
    assert!(opened.service.catalog().objects(&a).is_empty());
}

fn signed_of(fx: &ImageFx, seed: u8) -> Vec<u8> {
    match signed_trust(fx, seed) {
        OciTrust::Publisher { signature, .. } => signature,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_mutable_tag_or_another_digest_is_refused_before_anything_is_fetched() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"payload");
    let a = tenant("a");
    let (mut pin, request) = publish_request(&fx, a.clone(), OCI);
    let mut registry = Registry::serving(&fx);

    pin.reference = OciReference::Tag {
        tag: "latest".to_owned(),
    };
    assert_eq!(
        import(&opened, &mut registry, &pin, &request),
        Err(PinnedImportError::Provenance {
            refusal: ProvenanceRefusal::MutableTag {
                tag: "latest".to_owned()
            }
        })
    );
    let other = image(b"another payload");
    pin.reference = pin_of(&other).reference;
    assert_eq!(
        import(&opened, &mut registry, &pin, &request),
        Err(PinnedImportError::ReferenceNotRoot {
            reference: Digest::from_bytes(*other.root.digest.as_bytes()),
            root: fx.root.digest,
        })
    );
    assert!(registry.fetched.is_empty());
    assert!(opened.service.catalog().objects(&a).is_empty());
}

#[test]
fn a_registry_redirect_cannot_change_what_is_admitted() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"payload");
    let a = tenant("a");
    let (pin, request) = publish_request(&fx, a.clone(), OCI);

    // The right bytes, served by a host the image is not pinned to.
    let mut redirected = Registry::serving(&fx);
    redirected.served_by = host("mirror.other.example");
    assert_eq!(
        import(&opened, &mut redirected, &pin, &request),
        Err(PinnedImportError::Provenance {
            refusal: ProvenanceRefusal::RegistryRedirect {
                pinned: host(REGISTRY),
                served_by: host("mirror.other.example"),
            }
        })
    );
    assert_eq!(redirected.fetched, vec![fx.root.digest]);

    // The pinned registry serving another image's manifest, validly signed by the same
    // publisher, under the pinned digest.
    let other = image(b"another payload");
    let mut substituted = Registry::serving(&fx);
    substituted.blobs.extend(other.blobs.clone());
    substituted
        .blobs
        .insert(fx.root.digest, other.manifest_bytes.clone());
    let refused = import(&opened, &mut substituted, &pin, &request).unwrap_err();
    assert!(
        matches!(
            &refused,
            PinnedImportError::Import { error }
                if matches!(**error, OciImportError::Blob { at: BlobAt::Root, .. })
        ),
        "{refused:?}"
    );
    assert!(opened.service.catalog().objects(&a).is_empty());

    // The pinned registry serving the pinned bytes admits exactly the pinned image.
    let mut genuine = Registry::serving(&fx);
    let imported = import(&opened, &mut genuine, &pin, &request).unwrap();
    assert_eq!(imported.manifest, OciDigest::of(&fx.manifest_bytes));
    assert_eq!(opened.service.catalog().objects(&a).len(), 2);
}

#[test]
fn an_image_in_one_scope_is_never_served_to_another() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"payload");
    let (a, b) = (tenant("a"), tenant("b"));
    let (pin, request) = publish_request(&fx, a.clone(), OCI);
    let first = import(&opened, &mut Registry::serving(&fx), &pin, &request).unwrap();
    let tree = first.tree.object;

    {
        let mut catalog = opened.service.catalog();
        let content = catalog.private_metadata(&a, tree).unwrap().content_key;
        let reader = execution("sandbox-b");
        assert_eq!(
            catalog.acquire_lease(&b, &reader, tree, Duration::from_secs(60)),
            Err(ReadRefusal::NotGranted { object: tree })
        );
        assert_eq!(
            catalog.object_view(&b, &reader, tree),
            Err(ReadRefusal::NotGranted { object: tree })
        );
        assert!(catalog.private_metadata(&b, tree).is_err());
        // Equal bytes are not permission: b's identity names b's own object, absent.
        assert!(matches!(
            identify(&catalog, &b, &record(&fx, content)),
            Err(ProvenanceRefusal::NotInCatalog { object }) if object != tree
        ));
        let hit = CacheHit {
            owner: a.clone(),
            class: ArtifactClass::OciLayer,
            content,
        };
        assert_eq!(
            admit_cache_hit(&b, &hit),
            Err(ProvenanceRefusal::CrossUserCacheReuse {
                owner: a.clone(),
                requester: b.clone(),
            })
        );
    }

    // b's own import makes b's own objects under its own claim, fetched again.
    let (pin_b, request_b) = publish_request(&fx, b.clone(), OCI);
    let mut registry = Registry::serving(&fx);
    let second = import(&opened, &mut registry, &pin_b, &request_b).unwrap();
    assert_eq!(registry.fetched.len(), 3);
    assert!(!second.tree.cache_hit && !second.layers[0].cache_hit);
    assert_ne!(second.tree.object, tree);
    assert_ne!(second.layers[0].object, first.layers[0].object);
    assert_eq!(opened.service.catalog().objects(&b).len(), 2);
    // a's own repeat import is a cache hit in a's scope, its claim checked again.
    let again = import(&opened, &mut Registry::serving(&fx), &pin, &request).unwrap();
    assert!(again.tree.cache_hit && again.layers[0].cache_hit);
    assert_eq!(again.tree.object, tree);
}

#[test]
fn revoking_the_oci_key_quarantines_what_it_admitted() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"payload");
    let a = tenant("a");
    let (pin, request) = publish_request(&fx, a.clone(), OCI);
    let imported = import(&opened, &mut Registry::serving(&fx), &pin, &request).unwrap();
    let mut objects = vec![imported.layers[0].object, imported.tree.object];
    objects.sort();

    let applied = fixture.reload(&opened, &mut trust, keys_revoking("oci-publisher"));
    let oci = applied
        .iter()
        .find(|applied| applied.class == ArtifactClass::OciLayer)
        .unwrap();
    let mut quarantined = oci.quarantined.clone();
    quarantined.sort();
    assert_eq!(quarantined, objects);
    for other in applied
        .iter()
        .filter(|applied| applied.class != ArtifactClass::OciLayer)
    {
        assert!(other.quarantined.is_empty());
    }
    {
        let mut catalog = opened.service.catalog();
        for object in &objects {
            assert!(matches!(
                catalog.status(&a, *object),
                ObjectStatus::Quarantined {
                    reason: IntegrityFailure::TrustWithdrawn { .. }
                }
            ));
            assert_eq!(
                catalog.acquire_lease(
                    &a,
                    &execution("sandbox-1"),
                    *object,
                    Duration::from_secs(60)
                ),
                Err(ReadRefusal::Quarantined { object: *object })
            );
        }
    }
    // The revoked key admits nothing new either.
    let other = image(b"after the revocation");
    let (pin, request) = publish_request(&other, a.clone(), OCI);
    assert!(matches!(
        import(&opened, &mut Registry::serving(&other), &pin, &request),
        Err(PinnedImportError::Import { error })
            if matches!(*error, OciImportError::Provenance { .. })
    ));
    assert_eq!(opened.service.catalog().objects(&a).len(), 2);
}

#[test]
fn a_corrupted_layer_is_refused_when_read_back_and_never_executed() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let fx = image(b"payload to be damaged on disk");
    let a = tenant("a");
    let (pin, request) = publish_request(&fx, a.clone(), OCI);
    let imported = import(&opened, &mut Registry::serving(&fx), &pin, &request).unwrap();
    let layer = imported.layers[0].object;
    let reader = execution("sandbox-1");

    let mut catalog = opened.service.catalog();
    let content = catalog.private_metadata(&a, layer).unwrap().content_key;
    let identity = identify(&catalog, &a, &record(&fx, content)).unwrap();
    let lease = catalog
        .acquire_lease(&a, &reader, layer, Duration::from_secs(60))
        .unwrap();
    let mut handle = catalog.open_read(&a, &reader, lease).unwrap();
    let length = handle.length_bytes();
    fixture.corrupt(layer, length - 5);

    // Read back, the changed extent fails its digest; verification quarantines the
    // object and revokes its lease; the execution gate then refuses it.
    assert!(matches!(
        handle.read_all(),
        Err(ReadError::ExtentCorrupt { .. })
    ));
    assert!(matches!(
        catalog.verify_object(&a, layer),
        Err(VerifyError::Quarantined {
            reason: IntegrityFailure::ExtentCorrupt { .. }
        })
    ));
    assert_eq!(handle.read_all(), Err(ReadError::LeaseRevoked));
    assert_eq!(
        catalog.acquire_lease(&a, &reader, layer, Duration::from_secs(60)),
        Err(ReadRefusal::Quarantined { object: layer })
    );
    assert!(matches!(
        identify(&catalog, &a, &record(&fx, content)),
        Err(ProvenanceRefusal::Quarantined { object, .. }) if object == layer
    ));
    let permission = ExecutionPermission {
        scope: a.clone(),
        execution: reader,
        object: layer,
    };
    assert_eq!(
        admit_execution(&catalog, &identity, &permission),
        Err(ProvenanceRefusal::CatalogRefused {
            refusal: ReadRefusal::Quarantined { object: layer }
        })
    );
}
