//! VM-N4 tests (VM part §9.4, lines 2385–2395; §5.3–§5.4; VM-P45; VM-W57): manifests
//! compiled before private inputs, approved object IDs only, one scope for hits and
//! misses, offline prefetch, the lazy metadata channel, private-derived manifests and
//! manifest updates.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use super::fakes::*;
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, Catalog, ImportManifest, ImportRefusal, ImportRequest, ImportStart, ObjectId,
    ObjectMetadata, ObjectRole, ObjectStatus, ReadRefusal, Scope, SourceIdentity, TrustClaim,
    TrustRefusal, Uninterrupted,
};
use crate::foundation::ids::{Clock, ExecutionId, ManualClock, OperationId};
use crate::foundation::transfer::GeneralReleaseBudget;

const CLASS: ArtifactClass = ArtifactClass::DependencyPackage;

struct Setup {
    _dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    catalog: Catalog,
    registry: FakeRegistry,
    fetch: FetchService,
    locks: Vec<LockEntry>,
    fetch_scope: Scope,
    compute_scope: Scope,
    compute: ExecutionId,
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let fetch_scope = scope("acme-fetch");
    let compute_scope = scope("acme");
    let catalog = open_catalog(
        dir.path(),
        Arc::clone(&clock),
        &[
            fetch_scope.clone(),
            compute_scope.clone(),
            scope("globex"),
            scope("globex-fetch"),
        ],
        &[publisher("registry-signer")],
    );
    let mut registry = FakeRegistry::default();
    let locks = vec![
        registry.publish(
            "npm",
            "left-pad",
            "1.3.0",
            CLASS,
            &package_bytes(1, 10_000),
            publisher("registry-signer"),
        ),
        registry.publish(
            "npm",
            "@acme/util",
            "2.0.1",
            CLASS,
            &package_bytes(2, 3_000),
            publisher("registry-signer"),
        ),
        registry.publish(
            "pypi",
            "requests",
            "2.32.3",
            CLASS,
            &package_bytes(3, 9_000),
            publisher("registry-signer"),
        ),
    ];
    Setup {
        _dir: dir,
        clock,
        catalog,
        registry,
        fetch: FetchService::new(
            fetch_scope.clone(),
            execution("fetch-service"),
            OperationId::new("op-fetch").unwrap(),
        ),
        locks,
        fetch_scope,
        compute_scope,
        compute: execution("compute-vm"),
    }
}

impl Setup {
    fn draft(&self, origin: ManifestOrigin) -> ManifestDraft {
        ManifestDraft::new(
            self.fetch_scope.clone(),
            self.compute_scope.clone(),
            self.compute.clone(),
            origin,
            self.locks.clone(),
        )
        .unwrap()
    }

    fn manifest(&mut self) -> DependencyManifest {
        let draft = self.draft(ManifestOrigin::PublicLockfile);
        ManifestCompiler
            .compile(
                &draft,
                &mut self.registry,
                PrivateExposure::BeforePrivateInputs,
                None,
                &mut GeneralReleaseBudget::vm_d12_default(),
            )
            .unwrap()
    }

    fn service(&mut self, mode: FetchMode) -> ContentService {
        let manifest = self.manifest();
        let clock: Arc<dyn Clock> = self.clock.clone();
        ContentService::new(manifest, mode, Duration::from_secs(60), clock)
    }
}

fn nth_object(service: &ContentService, index: usize) -> ObjectId {
    *service.manifest().entries().keys().nth(index).unwrap()
}

fn lazy() -> FetchMode {
    FetchMode::Lazy {
        metadata_channel: operator(),
    }
}

#[test]
fn the_manifest_is_compiled_before_private_inputs_enter() {
    let mut setup = setup();
    let manifest = setup.manifest();
    assert_eq!(manifest.entries().len(), 3);
    assert_eq!(manifest.version(), 1);
    for (object, entry) in manifest.entries() {
        // Approved IDs are catalog identities in the fetch scope.
        assert_eq!(
            *object,
            ObjectId::new(&setup.fetch_scope, CLASS, entry.content_key)
        );
    }
    assert_eq!(setup.registry.resolves, 3);
    // Compiling once private inputs entered could carry private data (§5.4, VM-P45).
    let draft = setup.draft(ManifestOrigin::PublicLockfile);
    let before = setup.registry.network_calls();
    assert_eq!(
        ManifestCompiler
            .compile(
                &draft,
                &mut setup.registry,
                PrivateExposure::PrivateInputsEntered,
                None,
                &mut GeneralReleaseBudget::vm_d12_default(),
            )
            .unwrap_err(),
        ManifestRefusal::PotentialExfiltration
    );
    assert_eq!(setup.registry.network_calls(), before);
    // The fetch service and the compute VM never share a scope.
    assert_eq!(
        ManifestDraft::new(
            setup.compute_scope.clone(),
            setup.compute_scope.clone(),
            setup.compute.clone(),
            ManifestOrigin::PublicLockfile,
            Vec::new(),
        )
        .unwrap_err(),
        ManifestRefusal::SameScope
    );
    // A lockfile pin the registry resolves differently is refused.
    setup
        .registry
        .artifact_mut("npm", "left-pad", "1.3.0")
        .resolve_to = Some(crate::foundation::ids::ContentKey::of(b"something else"));
    let draft = setup.draft(ManifestOrigin::PublicLockfile);
    assert!(matches!(
        ManifestCompiler.compile(
            &draft,
            &mut setup.registry,
            PrivateExposure::BeforePrivateInputs,
            None,
            &mut GeneralReleaseBudget::vm_d12_default(),
        ),
        Err(ManifestRefusal::LockMismatch { .. })
    ));
    // Every approved object, and nothing else, is in the CORE-05 transfer scope.
    let scope = manifest.transfer_scope().unwrap();
    assert_eq!(scope.objects().len(), 3);
    assert_eq!(scope.total_bytes(), 10_000 + 3_000 + 9_000);
}

#[test]
fn only_approved_object_ids_are_answered() {
    let mut setup = setup();
    let mut service = setup.service(lazy());
    let calls = setup.registry.network_calls();
    let approved = nth_object(&service, 0);
    for request in [
        ContentRequest::Url {
            url: "https://evil.example/?d=secret".to_string(),
        },
        ContentRequest::PackageName {
            name: "secret-encoded-name".to_string(),
            version: None,
        },
        ContentRequest::Query {
            query: "name~=a*".to_string(),
        },
        ContentRequest::Redirect {
            object: approved,
            location: "https://evil.example/".to_string(),
        },
    ] {
        let kind = request.kind();
        assert_eq!(
            service
                .serve_lazy(
                    &mut setup.catalog,
                    &setup.fetch,
                    &mut setup.registry,
                    &request
                )
                .unwrap_err(),
            ContentRefusal::NotAnObjectRequest { kind }
        );
    }
    // An unapproved object ID is refused locally.
    let unapproved = ObjectId::new(
        &setup.fetch_scope,
        CLASS,
        crate::foundation::ids::ContentKey::of(b"x"),
    );
    assert_eq!(
        service
            .serve_lazy(
                &mut setup.catalog,
                &setup.fetch,
                &mut setup.registry,
                &ContentRequest::Object { object: unapproved },
            )
            .unwrap_err(),
        ContentRefusal::NotInManifest { object: unapproved }
    );
    assert_eq!(
        setup.registry.network_calls(),
        calls,
        "nothing left the host"
    );
    // The wire form is read strictly.
    let hex = approved.to_string();
    let good = format!(r#"{{"request":"object","object":"{hex}"}}"#);
    assert_eq!(
        ContentRequest::from_wire(good.as_bytes()).unwrap(),
        ContentRequest::Object { object: approved }
    );
    for bad in [
        format!(r#"{{"request":"object","object":"{hex}","hint":"x"}}"#),
        r#"{"request":"download","url":"https://x"}"#.to_string(),
        "https://evil.example/pkg".to_string(),
    ] {
        assert_eq!(
            ContentRequest::from_wire(bad.as_bytes()).unwrap_err(),
            ContentRefusal::Malformed,
            "{bad}"
        );
    }
    assert!(matches!(
        ContentRequest::from_wire(&vec![b' '; MAX_REQUEST_BYTES + 1]),
        Err(ContentRefusal::TooLarge { .. })
    ));
    // A registry redirect is never followed.
    setup
        .registry
        .artifact_mut("npm", "left-pad", "1.3.0")
        .redirect = Some("https://mirror.example/left-pad".to_string());
    let left_pad = service
        .manifest()
        .entries()
        .values()
        .find(|entry| entry.length_bytes == 10_000)
        .unwrap()
        .object;
    assert!(matches!(
        service.serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &ContentRequest::Object { object: left_pad },
        ),
        Err(ContentRefusal::Fetch(FetchRefusal::Redirect { .. }))
    ));
    assert_eq!(
        setup.catalog.status(&setup.fetch_scope, left_pad),
        ObjectStatus::Absent
    );
}

#[test]
fn a_late_package_name_after_private_reads_is_refused_as_exfiltration() {
    let mut setup = setup();
    let mut service = setup.service(lazy());
    service.private_inputs_entered(&setup.catalog).unwrap();
    let calls = setup.registry.network_calls();
    for request in [
        ContentRequest::PackageName {
            name: "acme-internal-codename".to_string(),
            version: Some("1.0.0".to_string()),
        },
        ContentRequest::Url {
            url: "https://registry.example/acme-internal-codename".to_string(),
        },
        ContentRequest::Query {
            query: "acme".to_string(),
        },
    ] {
        let kind = request.kind();
        let refusal = service
            .serve_lazy(
                &mut setup.catalog,
                &setup.fetch,
                &mut setup.registry,
                &request,
            )
            .unwrap_err();
        assert_eq!(refusal, ContentRefusal::PotentialExfiltration { kind });
        assert!(refusal.to_string().contains("nothing was sent"));
    }
    // A late object lookup outside the manifest is refused locally too (VM-P45).
    let late = ObjectId::new(
        &setup.fetch_scope,
        CLASS,
        crate::foundation::ids::ContentKey::of(b"late"),
    );
    assert!(matches!(
        service.serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &ContentRequest::Object { object: late },
        ),
        Err(ContentRefusal::NotInManifest { .. })
    ));
    assert_eq!(setup.registry.network_calls(), calls);
}

#[test]
fn cache_hits_and_misses_enforce_the_same_scope() {
    let mut setup = setup();
    let mut acme = setup.service(lazy());
    let first = nth_object(&acme, 0);
    let request = ContentRequest::Object { object: first };
    let miss = acme
        .serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &request,
        )
        .unwrap();
    assert_eq!(miss.cache, CacheResult::Miss);
    let calls = setup.registry.network_calls();
    let hit = acme
        .serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &request,
        )
        .unwrap();
    assert_eq!(hit.cache, CacheResult::Hit);
    assert_eq!(hit.bytes, miss.bytes);
    assert_eq!(
        setup.registry.network_calls(),
        calls,
        "a hit makes no registry call"
    );
    // Each read's grant is revoked when it ends: the compute VM holds no standing access.
    assert!(matches!(
        setup.catalog.acquire_lease(
            &setup.compute_scope,
            &setup.compute,
            first,
            Duration::from_secs(1)
        ),
        Err(ReadRefusal::NotGranted { .. })
    ));
    // Another tenant with the same content gets its own objects: equal bytes are not
    // permission, and acme's cached object is refused to it before and after caching.
    let globex_fetch = FetchService::new(
        scope("globex-fetch"),
        execution("globex-fetch-service"),
        OperationId::new("op-globex").unwrap(),
    );
    let draft = ManifestDraft::new(
        scope("globex-fetch"),
        scope("globex"),
        execution("globex-vm"),
        ManifestOrigin::PublicLockfile,
        setup.locks.clone(),
    )
    .unwrap();
    let globex_manifest = ManifestCompiler
        .compile(
            &draft,
            &mut setup.registry,
            PrivateExposure::BeforePrivateInputs,
            None,
            &mut GeneralReleaseBudget::vm_d12_default(),
        )
        .unwrap();
    assert!(globex_manifest.entry(&first).is_none());
    let clock: Arc<dyn Clock> = setup.clock.clone();
    let mut globex = ContentService::new(globex_manifest, lazy(), Duration::from_secs(60), clock);
    assert_eq!(
        globex
            .serve_lazy(
                &mut setup.catalog,
                &globex_fetch,
                &mut setup.registry,
                &request
            )
            .unwrap_err(),
        ContentRefusal::NotInManifest { object: first }
    );
    // Globex's own object for the same package as acme's: object identities bind the
    // scope, so the manifests' orders differ and only the content key matches.
    let content = acme.manifest().entry(&first).unwrap().content_key;
    let own = globex
        .manifest()
        .entries()
        .values()
        .find(|entry| entry.content_key == content)
        .map(|entry| entry.object)
        .unwrap();
    let served = globex
        .serve_lazy(
            &mut setup.catalog,
            &globex_fetch,
            &mut setup.registry,
            &ContentRequest::Object { object: own },
        )
        .unwrap();
    assert_eq!(
        served.cache,
        CacheResult::Miss,
        "acme's cache is not globex's"
    );
    assert_eq!(served.bytes, miss.bytes);
    assert!(matches!(
        setup.catalog.acquire_lease(
            &scope("globex"),
            &execution("globex-vm"),
            first,
            Duration::from_secs(1)
        ),
        Err(ReadRefusal::NotGranted { .. })
    ));
    // The fetch service refuses a manifest of another fetch scope.
    assert_eq!(
        setup
            .fetch
            .ensure(
                &mut setup.catalog,
                globex.manifest(),
                own,
                &mut setup.registry
            )
            .unwrap_err(),
        FetchRefusal::WrongScope
    );
}

#[test]
fn strict_private_mode_prefetches_and_then_serves_offline() {
    let mut setup = setup();
    let mut service = setup.service(FetchMode::StrictPrivate);
    // Private inputs may not enter before the whole manifest is prefetched.
    assert!(matches!(
        service.private_inputs_entered(&setup.catalog),
        Err(ContentRefusal::NotPrefetched { .. })
    ));
    let report = service
        .prefetch(&mut setup.catalog, &setup.fetch, &mut setup.registry)
        .unwrap();
    assert_eq!(
        report,
        PrefetchReport {
            objects: 3,
            fetched: 3,
            already_cached: 0,
        }
    );
    service.private_inputs_entered(&setup.catalog).unwrap();
    let calls = setup.registry.network_calls();
    for index in 0..3 {
        let object = nth_object(&service, index);
        let served = service
            .serve_offline(&mut setup.catalog, &ContentRequest::Object { object })
            .unwrap();
        assert_eq!(served.cache, CacheResult::Hit);
        let entry = service.manifest().entry(&object).unwrap();
        assert_eq!(
            crate::foundation::ids::ContentKey::of(&served.bytes),
            entry.content_key
        );
    }
    assert_eq!(
        setup.registry.network_calls(),
        calls,
        "no network activity after prefetch"
    );
    assert_eq!(
        service.channel(),
        ChannelClassification::NoNetworkAfterPrefetch
    );
    assert!(service.observations().is_empty());
    // A strict service never fetches lazily, and never prefetches late.
    let object = nth_object(&service, 0);
    assert_eq!(
        service
            .serve_lazy(
                &mut setup.catalog,
                &setup.fetch,
                &mut setup.registry,
                &ContentRequest::Object { object },
            )
            .unwrap_err(),
        ContentRefusal::WrongMode
    );
    assert_eq!(
        service
            .prefetch(&mut setup.catalog, &setup.fetch, &mut setup.registry)
            .unwrap_err(),
        FetchRefusal::PrefetchAfterPrivateInputs
    );
    // Offline serving of something never prefetched is refused, not fetched.
    let mut fresh = setup.service(FetchMode::StrictPrivate);
    let mut other = setup_other_catalog(&setup);
    let object = nth_object(&fresh, 0);
    assert_eq!(
        fresh
            .serve_offline(&mut other.1, &ContentRequest::Object { object })
            .unwrap_err(),
        ContentRefusal::NotPrefetched { object }
    );
}

/// A second, empty catalog with the same configuration.
fn setup_other_catalog(setup: &Setup) -> (tempfile::TempDir, Catalog) {
    let dir = tempfile::tempdir().unwrap();
    let catalog = open_catalog(
        dir.path(),
        Arc::clone(&setup.clock),
        &[setup.fetch_scope.clone(), setup.compute_scope.clone()],
        &[publisher("registry-signer")],
    );
    (dir, catalog)
}

#[test]
fn lazy_fetches_are_a_permitted_metadata_channel_not_noninterference() {
    let mut setup = setup();
    let mut service = setup.service(lazy());
    let first = nth_object(&service, 0);
    let second = nth_object(&service, 1);
    service
        .serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &ContentRequest::Object { object: first },
        )
        .unwrap();
    setup.clock.advance(Duration::from_secs(5));
    service
        .serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &ContentRequest::Object { object: second },
        )
        .unwrap();
    service
        .serve_lazy(
            &mut setup.catalog,
            &setup.fetch,
            &mut setup.registry,
            &ContentRequest::Object { object: first },
        )
        .unwrap();
    // Two misses are observable, with their selection and timing; the hit is local.
    let observed: Vec<ObjectId> = service.observations().iter().map(|o| o.object).collect();
    assert_eq!(observed, vec![first, second]);
    let gap = service.observations()[1]
        .at
        .saturating_duration_since(service.observations()[0].at);
    assert_eq!(gap, Duration::from_secs(5));
    let ChannelClassification::PermittedMetadataChannel {
        reveals,
        remote_fetches,
        approval,
    } = service.channel()
    else {
        panic!("lazy mode is a metadata channel");
    };
    assert_eq!(
        reveals,
        BTreeSet::from([
            MetadataLeak::ObjectSelection,
            MetadataLeak::Timing,
            MetadataLeak::CacheMisses,
        ])
    );
    assert_eq!(remote_fetches, 2);
    assert!(approval.is_operator());
}

#[test]
fn a_private_derived_manifest_is_a_metadata_release_that_needs_authorization() {
    let mut setup = setup();
    let origin = ManifestOrigin::DerivedFromPrivate {
        source: tag("private-repo"),
    };
    let draft = setup.draft(origin.clone());
    // Names, versions, a 32-byte route and 8 bytes of framing per field are counted.
    let expected: u64 = setup
        .locks
        .iter()
        .map(|lock| lock.name.as_str().len() as u64 + lock.version.len() as u64 + 32 + 24)
        .sum();
    assert_eq!(draft.metadata_bytes(), expected);
    assert_eq!(expected, (8 + 5 + 56) + (10 + 5 + 56) + (8 + 6 + 56));
    let mut budget = GeneralReleaseBudget::vm_d12_default();
    let calls = setup.registry.network_calls();
    assert_eq!(
        ManifestCompiler
            .compile(
                &draft,
                &mut setup.registry,
                PrivateExposure::BeforePrivateInputs,
                None,
                &mut budget
            )
            .unwrap_err(),
        ManifestRefusal::MetadataReleaseNotAuthorized {
            draft: draft.digest(),
            metadata_bytes: expected,
        }
    );
    // An authorization of another draft does not transfer.
    let other = ManifestDraft::new(
        setup.fetch_scope.clone(),
        setup.compute_scope.clone(),
        setup.compute.clone(),
        origin,
        setup.locks[..1].to_vec(),
    )
    .unwrap();
    let wrong = MetadataReleaseAuthorization::new(&other, operator());
    assert!(matches!(
        ManifestCompiler.compile(
            &draft,
            &mut setup.registry,
            PrivateExposure::BeforePrivateInputs,
            Some(&wrong),
            &mut budget,
        ),
        Err(ManifestRefusal::AuthorizationForOtherManifest { .. })
    ));
    assert_eq!(
        setup.registry.network_calls(),
        calls,
        "no name left before authorization"
    );
    assert_eq!(budget.released_bytes(), 0);
    // A release budget too small refuses before contacting the registry.
    let authorization = MetadataReleaseAuthorization::new(&draft, operator());
    let mut tiny = GeneralReleaseBudget::with_limit(expected - 1);
    assert!(matches!(
        ManifestCompiler.compile(
            &draft,
            &mut setup.registry,
            PrivateExposure::BeforePrivateInputs,
            Some(&authorization),
            &mut tiny,
        ),
        Err(ManifestRefusal::ReleaseBudget { .. })
    ));
    assert_eq!(setup.registry.network_calls(), calls);
    let manifest = ManifestCompiler
        .compile(
            &draft,
            &mut setup.registry,
            PrivateExposure::BeforePrivateInputs,
            Some(&authorization),
            &mut budget,
        )
        .unwrap();
    assert_eq!(budget.released_bytes(), expected);
    assert_eq!(manifest.entries().len(), 3);
}

#[test]
fn dynamic_dependencies_need_a_manifest_update_decision() {
    let mut setup = setup();
    let manifest = setup.manifest();
    let addition = setup.registry.publish(
        "npm",
        "plugin-x",
        "0.1.0",
        CLASS,
        &package_bytes(9, 2_000),
        publisher("registry-signer"),
    );
    let update = ManifestUpdate::new(
        &manifest,
        vec![addition.clone()],
        PrivateExposure::PrivateInputsEntered,
    )
    .unwrap();
    let mut budget = GeneralReleaseBudget::vm_d12_default();
    // No decision: registry access is not reopened (line 2395).
    assert_eq!(
        ManifestCompiler
            .apply_update(&manifest, &update, None, &mut setup.registry, &mut budget)
            .unwrap_err(),
        ManifestRefusal::UpdateNeedsDecision
    );
    let other = ManifestUpdate::new(
        &manifest,
        vec![addition.clone()],
        PrivateExposure::BeforePrivateInputs,
    )
    .unwrap();
    assert_eq!(
        ManifestCompiler
            .apply_update(
                &manifest,
                &update,
                Some(&UpdateApproval::new(&other, operator())),
                &mut setup.registry,
                &mut budget,
            )
            .unwrap_err(),
        ManifestRefusal::ApprovalForOtherUpdate
    );
    let approval = UpdateApproval::new(&update, operator());
    let next = ManifestCompiler
        .apply_update(
            &manifest,
            &update,
            Some(&approval),
            &mut setup.registry,
            &mut budget,
        )
        .unwrap();
    assert_eq!(next.version(), 2);
    assert_eq!(next.entries().len(), 4);
    assert_ne!(next.digest(), manifest.digest());
    // Names asked for after private inputs entered were charged as a metadata release.
    assert_eq!(budget.released_bytes(), update.metadata_bytes());
    // The same update cannot be applied to the newer manifest, and duplicates are refused.
    assert_eq!(
        ManifestCompiler
            .apply_update(
                &next,
                &update,
                Some(&approval),
                &mut setup.registry,
                &mut budget
            )
            .unwrap_err(),
        ManifestRefusal::UpdateForOtherManifest
    );
    assert!(matches!(
        ManifestUpdate::new(&next, vec![addition], PrivateExposure::BeforePrivateInputs),
        Err(ManifestRefusal::DuplicateEntry { .. })
    ));
}

#[test]
fn fetching_verifies_hashes_and_publisher_trust() {
    // Corrupted deliveries never publish, and a later request is still a miss.
    let mut setup = setup();
    let manifest = setup.manifest();
    let left_pad = manifest
        .entries()
        .values()
        .find(|entry| entry.length_bytes == 10_000)
        .unwrap()
        .object;
    setup
        .registry
        .artifact_mut("npm", "left-pad", "1.3.0")
        .corrupt = true;
    let refusal = setup
        .fetch
        .ensure(&mut setup.catalog, &manifest, left_pad, &mut setup.registry)
        .unwrap_err();
    assert!(
        matches!(
            refusal,
            FetchRefusal::ImportIncomplete { .. } | FetchRefusal::ImportFailed { .. }
        ),
        "{refusal:?}"
    );
    assert_eq!(
        setup.catalog.status(&setup.fetch_scope, left_pad),
        ObjectStatus::Absent
    );
    setup
        .registry
        .artifact_mut("npm", "left-pad", "1.3.0")
        .corrupt = false;
    assert_eq!(
        setup
            .fetch
            .ensure(&mut setup.catalog, &manifest, left_pad, &mut setup.registry)
            .unwrap()
            .cache,
        CacheResult::Miss
    );
    // A publisher the class policy does not trust is refused by the catalog.
    let rogue = setup.registry.publish(
        "npm",
        "typosquat",
        "9.9.9",
        CLASS,
        &package_bytes(7, 1_000),
        publisher("rogue"),
    );
    let draft = ManifestDraft::new(
        setup.fetch_scope.clone(),
        setup.compute_scope.clone(),
        setup.compute.clone(),
        ManifestOrigin::PublicLockfile,
        vec![rogue],
    )
    .unwrap();
    let rogue_manifest = ManifestCompiler
        .compile(
            &draft,
            &mut setup.registry,
            PrivateExposure::BeforePrivateInputs,
            None,
            &mut GeneralReleaseBudget::vm_d12_default(),
        )
        .unwrap();
    let rogue_object = *rogue_manifest.entries().keys().next().unwrap();
    assert!(matches!(
        setup.fetch.ensure(
            &mut setup.catalog,
            &rogue_manifest,
            rogue_object,
            &mut setup.registry
        ),
        Err(FetchRefusal::Import {
            refusal: ImportRefusal::Trust {
                refusal: TrustRefusal::PublisherNotTrusted { .. }
            },
            ..
        })
    ));
    // A declaration whose publisher changed after approval is refused before import.
    setup
        .registry
        .artifact_mut("pypi", "requests", "2.32.3")
        .publisher = publisher("registry-signer-2");
    let requests = manifest
        .entries()
        .values()
        .find(|entry| entry.length_bytes == 9_000)
        .unwrap()
        .object;
    assert_eq!(
        setup
            .fetch
            .ensure(&mut setup.catalog, &manifest, requests, &mut setup.registry)
            .unwrap_err(),
        FetchRefusal::PinMismatch { object: requests }
    );
}

#[test]
fn the_fetch_service_cannot_read_private_project_content() {
    let mut setup = setup();
    // The compute VM's private project, imported into its own scope.
    let bytes = package_bytes(42, 5_000);
    let request = ImportRequest {
        operation: OperationId::new("op-import").unwrap(),
        execution: setup.compute.clone(),
        scope: setup.compute_scope.clone(),
        class: ArtifactClass::DocumentManifest,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(&bytes, NonZeroU64::new(EXTENT_BYTES).unwrap()),
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let identity = SourceIdentity::describe("project", "acme-app");
    let ImportStart::Started(ticket) = setup.catalog.begin_import(request, identity).unwrap()
    else {
        panic!("expected a new import");
    };
    let mut source = MemorySource { identity, bytes };
    setup
        .catalog
        .drive_import(&ticket, &mut source, &mut Uninterrupted)
        .unwrap();
    let private = setup
        .catalog
        .find(
            &setup.compute_scope,
            ArtifactClass::DocumentManifest,
            crate::foundation::ids::ContentKey::of(&source.bytes),
        )
        .unwrap();
    // The fetch service's identity holds no grant on the compute scope.
    assert!(matches!(
        setup.catalog.acquire_lease(
            setup.fetch.scope(),
            setup.fetch.execution(),
            private,
            Duration::from_secs(1),
        ),
        Err(ReadRefusal::NotGranted { .. })
    ));
    // And it fetches only manifest objects.
    let manifest = setup.manifest();
    assert_eq!(
        setup
            .fetch
            .ensure(&mut setup.catalog, &manifest, private, &mut setup.registry)
            .unwrap_err(),
        FetchRefusal::NotInManifest { object: private }
    );
}
