//! Boundary 1 over the committed modules (T05, P01): what the store's importer publishes
//! reads back as a verified representation, inside the request's partition only, named as
//! the catalog, the transfer executor (P03) and the coordinator name it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::committed::*;
use super::support::*;
use crate::foundation::catalog::{ArtifactClass, ObjectId, Scope};
use crate::foundation::coordination::{validate_model_cache, CacheDefect, ModelCacheManifest};
use crate::foundation::evidence::ArtifactVerification;
use crate::foundation::ids::{
    digest, ContentKey, ExecutionCategory, ManualClock, MonotonicTime, TenantId, TrustScope,
};
use crate::model_memory::boundaries::*;
use crate::model_memory::executor::{
    CatalogPort, CatalogRefusal as ManifestRefusal, ResolveRequest, StoredForm,
};
use crate::model_memory::identity::ArtifactIdentity;
use crate::model_memory::manifest as mf;

fn new_clock() -> Clocked {
    Arc::new(ManualClock::new(MonotonicTime::ZERO))
}

#[test]
fn an_imported_model_reads_back_as_its_verified_representation() {
    let clock = new_clock();
    let (_dir, mut store) = open_store(&clock);
    let folder = ModelFolder::small();
    let artifact = import_model(&mut store, &folder);
    let representation = store
        .representation(&artifact, &SecurityPartition::new(scope()))
        .unwrap();
    assert_eq!(representation.artifact(), artifact);
    assert_eq!(representation.scope(), scope());
    // A sidecar records the source and its revision; the licence is bound into the
    // source identity the import was keyed by.
    assert_eq!(representation.provenance().license, None);

    // Every extent is named by the content key of its own bytes, stored at its offset in
    // a source file named by the content key of the whole file, and the extents of the
    // weights file tile it exactly.
    let files: BTreeMap<ContentKey, &Vec<u8>> = folder
        .files
        .values()
        .map(|bytes| (ContentKey::of(bytes), bytes))
        .collect();
    let weights = ContentKey::of(folder.weights());
    let mut covered: BTreeMap<ContentKey, u64> = BTreeMap::new();
    for descriptor in representation.extents() {
        let stored = descriptor.stored.unwrap();
        let bytes = files[&stored.representation];
        let start = stored.offset_bytes as usize;
        let end = start + descriptor.length_bytes as usize;
        assert_eq!(descriptor.digest, ContentKey::of(&bytes[start..end]));
        assert!(descriptor.length_bytes <= EXTENT_BYTES);
        assert_eq!(stored.index, u64::from(descriptor.extent.get()));
        *covered.entry(stored.representation).or_default() += descriptor.length_bytes;
    }
    assert_eq!(covered[&weights], folder.weights().len() as u64);

    // The artifact is the sidecar the importer published over the originals: one catalog
    // object each, named by the catalog's own object identities.
    let sidecar = representation.extents()[0].stored.unwrap().artifact;
    let mut objects: BTreeSet<ObjectId> = files
        .keys()
        .map(|key| ObjectId::new(&owner_scope(), ArtifactClass::ModelWeights, *key))
        .collect();
    objects.insert(ObjectId::new(
        &owner_scope(),
        ArtifactClass::ModelSidecar,
        sidecar,
    ));
    assert_eq!(representation.objects(), &objects);
    let published: BTreeSet<ObjectId> = store
        .importer()
        .catalog()
        .catalog()
        .objects(&owner_scope())
        .into_iter()
        .collect();
    assert_eq!(published, objects);

    // Its verified artifacts are named as the catalog's own verification names them, and
    // the coordinator's model-cache check accepts them for the tenant's content.
    let verification = store
        .importer()
        .catalog()
        .catalog()
        .artifact_verification(&owner_scope(), &owner(), objects.iter().copied())
        .unwrap();
    assert_eq!(
        verification,
        ArtifactVerification::Verified {
            artifacts: representation.verified_artifacts()
        }
    );
    let cache = ModelCacheManifest {
        tenant: tenant(),
        artifacts: BTreeSet::from([sidecar, weights]),
    };
    assert_eq!(
        validate_model_cache(&cache, &tenant(), &verification),
        Ok(())
    );
    // The tenant's objects never stand for another tenant's equal content (S3.3).
    let other = TenantId::new("tenant-b").unwrap();
    let foreign = ModelCacheManifest {
        tenant: other.clone(),
        artifacts: cache.artifacts.clone(),
    };
    assert!(matches!(
        validate_model_cache(&foreign, &other, &verification),
        Err(defects) if defects.iter().any(|defect| matches!(
            defect,
            CacheDefect::UnverifiedArtifacts { .. }
        ))
    ));

    // A repeated import publishes nothing new and names the same artifact.
    let key = derived_key(&store, &folder, &owner_scope());
    let again = store
        .import(ModelImport {
            request: import_request(&folder, &owner_scope(), key),
            source: &folder.source(),
            cancel: mf::CancellationToken::new(),
        })
        .unwrap();
    assert_eq!(again, artifact);
    let after: BTreeSet<ObjectId> = store
        .importer()
        .catalog()
        .catalog()
        .objects(&owner_scope())
        .into_iter()
        .collect();
    assert_eq!(after, objects);
}

#[test]
fn the_store_reads_only_inside_the_partition_and_imports_only_into_its_scopes() {
    let clock = new_clock();
    let (_dir, mut store) = open_store(&clock);
    let folder = ModelFolder::small();
    let artifact = import_model(&mut store, &folder);

    // Another sandbox's partition holds no grant for this sandbox's scope (S3.3, S3.6),
    // unless the security layer granted it one.
    let elsewhere = SecurityPartition::new(TrustScope::named(
        ExecutionCategory::VmSandbox,
        "tenant-b/sandbox",
    ));
    assert_eq!(
        store.representation(&artifact, &elsewhere),
        Err(CatalogRefusal::OutsidePartition { artifact })
    );
    assert!(store
        .representation(&artifact, &elsewhere.with_read_grant(scope()))
        .is_ok());

    // An artifact never published is unknown.
    let unknown =
        ArtifactIdentity::from_manifest_digest(&digest("yougori/test/manifest/v1", &[b"none"]));
    assert_eq!(
        store.representation(&unknown, &SecurityPartition::new(scope())),
        Err(CatalogRefusal::UnknownArtifact { artifact: unknown })
    );

    // The store publishes only into scopes it reads, so nothing it imports is lost to it;
    // the refusal comes before anything is read.
    let other = Scope::tenant(TenantId::new("tenant-b").unwrap());
    let key = derived_key(&store, &folder, &owner_scope());
    let refused = store.import(ModelImport {
        request: import_request(&folder, &other, key),
        source: &folder.source(),
        cancel: mf::CancellationToken::new(),
    });
    assert!(
        matches!(refused, Err(ImportRefusal::Rejected { .. })),
        "{refused:?}"
    );
    assert!(store
        .importer()
        .catalog()
        .catalog()
        .objects(&other)
        .is_empty());
}

#[test]
fn p03_resolves_the_same_sidecar_by_content_key_for_its_tenant_only() {
    let clock = new_clock();
    let (_dir, mut store) = open_store(&clock);
    let folder = ModelFolder::small();
    let artifact = import_model(&mut store, &folder);
    let representation = store
        .representation(&artifact, &SecurityPartition::new(scope()))
        .unwrap();
    let manifests = StoreManifests::new(Arc::new(store), vec![local_candidate()]);
    let weights = ContentKey::of(folder.weights());
    let sidecar = representation.extents()[0].stored.unwrap().artifact;
    let request = ResolveRequest {
        execution: owner(),
        tenant: tenant(),
        artifact: sidecar,
        representation: weights,
    };
    let resolved = manifests.resolve(&request).unwrap();
    assert_eq!(
        (
            resolved.manifest,
            resolved.artifact,
            resolved.representation
        ),
        (sidecar, sidecar, weights)
    );
    assert_eq!(resolved.object_length_bytes, folder.weights().len() as u64);
    assert_eq!(resolved.sources, vec![local_candidate()]);

    // Its extents are the representation's extents of that file: the same indices,
    // content keys, offsets and lengths, stored raw in place.
    let expected: Vec<(u64, ContentKey, u64, u64)> = representation
        .extents()
        .iter()
        .filter_map(|descriptor| {
            descriptor
                .stored
                .filter(|stored| stored.representation == weights)
                .map(|stored| {
                    (
                        stored.index,
                        descriptor.digest,
                        stored.offset_bytes,
                        descriptor.length_bytes,
                    )
                })
        })
        .collect();
    let got: Vec<(u64, ContentKey, u64, u64)> = resolved
        .extents
        .iter()
        .map(|extent| {
            (
                extent.index,
                extent.decoded_key,
                extent.decoded_offset_bytes,
                extent.decoded_length_bytes,
            )
        })
        .collect();
    assert_eq!(got, expected);
    assert!(resolved.extents.iter().all(|extent| {
        extent.stored == StoredForm::Raw
            && extent.stored_offset_bytes == extent.decoded_offset_bytes
            && extent.stored_length_bytes == extent.decoded_length_bytes
    }));

    // Another tenant finds nothing, and neither does a stored object the sidecar does
    // not index.
    let foreign = ResolveRequest {
        tenant: TenantId::new("tenant-b").unwrap(),
        ..request.clone()
    };
    assert_eq!(manifests.resolve(&foreign), Err(ManifestRefusal::NotFound));
    let unindexed = ResolveRequest {
        representation: ContentKey::of(b"another file"),
        ..request
    };
    assert_eq!(
        manifests.resolve(&unindexed),
        Err(ManifestRefusal::NotFound)
    );
}
