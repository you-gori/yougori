//! Tests for the engine glue: the settings, the method's states and actions, the classes
//! the engine registers, and the model-file import entry over a real catalog in a
//! temporary directory, with a listing-keyed identity port in place of the identity
//! layers.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ImportManifest, ImportRefusal, ImportRequest as ObjectImport, ImportSource,
    ImportStart, ImportStatus, ObjectId, ObjectMetadata, ObjectRole, ObjectStatus, QuotaRefusal,
    Scope, TrustClaim, Uninterrupted,
};
use crate::foundation::catalog_service::{CatalogLocation, CatalogService, GcOutcome};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{
    ContentKey, Digest, DigestBuilder, ExecutionId, ManualClock, MonotonicTime, OperationId,
};
use crate::foundation::signing::{
    content_statement, Ed25519PublicKey, TrustCalendar, TrustRootLocation, TrustRootService,
};
use crate::model_memory::manifest::{
    listing_digest, ArtifactDescription, ArtifactIdentity, CancellationToken, CatalogContext,
    Distribution, ElementType, ExecutionAbi, ExecutionIdentity, FileRole, HardwareRestriction,
    IdentityError, ImportKey, ImportLimits, ImportRequest, ListedFile, ManifestBounds,
    ManifestDigest, ModelIdentities, Quantization, ReadBackChannel, RelativePath, SourceError,
    SourceIdentity, SourceListing, SourceOrigin, StateGroup, Token, ValidatedManifest,
    VersionedName, WeightFormat,
};

struct FixedCalendar;

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        "2026-10-29T12:00:00Z".parse().unwrap()
    }
}

fn untrusted() -> TrustRootService {
    TrustRootService::open(
        TrustRootLocation::from_setting("YOUGORI_TEST_GLUE_TRUST_ROOTS", None),
        Arc::new(FixedCalendar),
    )
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)))
}

fn owner() -> Scope {
    owner_scope().unwrap()
}

#[test]
fn the_settings_name_an_absolute_directory_and_a_whole_number_of_bytes() {
    let none = Settings::from_values(None, None);
    assert_eq!(
        none.location,
        CatalogLocation::NotConfigured {
            setting: CATALOG_ROOT_SETTING
        }
    );
    assert_eq!(none.quota, QuotaSetting::NotConfigured);
    let dir = tempfile::tempdir().unwrap();
    let configured = Settings::from_values(
        Some(dir.path().as_os_str()),
        Some(std::ffi::OsStr::new(" 1073741824 ")),
    );
    assert_eq!(
        configured.location,
        CatalogLocation::Directory {
            setting: CATALOG_ROOT_SETTING,
            path: dir.path().to_path_buf()
        }
    );
    assert_eq!(configured.quota, QuotaSetting::Bytes(1 << 30));
    assert_eq!(
        QuotaSetting::from_setting(Some(std::ffi::OsStr::new("10GB"))),
        QuotaSetting::Invalid {
            value: "10GB".to_owned()
        }
    );
    assert_eq!(
        QuotaSetting::from_setting(Some(std::ffi::OsStr::new(""))),
        QuotaSetting::NotConfigured
    );
    assert!(matches!(
        Settings::from_values(Some(std::ffi::OsStr::new("catalog")), None).location,
        CatalogLocation::Invalid { .. }
    ));
}

#[test]
fn without_a_location_the_catalog_is_not_opened_and_says_how_to_open_it() {
    let mut trust = untrusted();
    let catalog = open(
        &Settings::from_values(None, None),
        &mut trust,
        clock(),
        Arc::new(FixedCalendar),
    );
    let status = respond(&catalog, None).unwrap();
    assert_eq!(status["state"], "not_opened");
    assert_eq!(status["setting"], CATALOG_ROOT_SETTING);
    assert!(status["remedy"]
        .as_str()
        .unwrap()
        .contains(CATALOG_ROOT_SETTING));
    assert_eq!(status["quota"]["state"], "not_configured");
    let gc = respond(&catalog, Some("gc")).unwrap();
    assert_eq!(gc["gc"]["outcome"], "not_opened");
    let error = respond(&catalog, Some("delete_everything")).unwrap_err();
    assert!(error.contains("Use status or gc"), "{error}");
    let refused = match &catalog {
        EngineCatalog::NotOpened { .. } => ModelFileRefusal::NotOpened {
            detail: not_open_detail(&catalog),
        },
        _ => panic!("opened"),
    };
    assert!(refused.to_string().contains(CATALOG_ROOT_SETTING));
}

#[test]
fn the_engine_registers_model_files_sidecars_and_helpers_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("catalog");
    let mut trust = untrusted();
    let catalog = open(
        &Settings::from_values(Some(root.as_os_str()), Some(std::ffi::OsStr::new("4096"))),
        &mut trust,
        clock(),
        Arc::new(FixedCalendar),
    );
    let status = respond(&catalog, Some("status")).unwrap();
    assert_eq!(status["state"], "open");
    assert_eq!(status["root"], root.display().to_string());
    let class = |tag: &str| -> Value {
        status["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|class| class["class"] == tag)
            .cloned()
            .unwrap()
    };
    assert_eq!(class("model_weights")["verifier"], "user_selected_only");
    assert_eq!(class("model_weights")["accepts_user_selected"], true);
    assert_eq!(
        class("model_weights")["publishers"]["refusal"],
        "no_trust_roots"
    );
    assert_eq!(class("model_sidecar")["verifier"], "local");
    assert_eq!(class("model_sidecar")["accepts_user_selected"], true);
    assert_eq!(class("model_helper")["verifier"], "refused");
    assert_eq!(
        class("model_helper")["refusal"]["refusal"],
        "no_trust_roots"
    );
    assert_eq!(class("oci_layer")["verifier"], "local");
    assert_eq!(class("oci_layer")["accepts_user_selected"], true);
    for tag in [
        "guest_image",
        "document_manifest",
        "runtime_update",
        "dependency_package",
    ] {
        assert_eq!(class(tag)["verifier"], "not_offered", "{tag}");
    }
    // The budget applies to the host's scope and the owner's.
    let scopes = status["catalog"]["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes
        .iter()
        .all(|scope| scope["quota"]["limit_bytes"] == 4096));
    assert_eq!(status["quota"]["state"], "configured");
    assert_eq!(status["recovery"]["published"], 0);

    let gc = respond(&catalog, Some("gc")).unwrap();
    assert_eq!(gc["gc"]["outcome"], "collected");
    assert_eq!(gc["status"]["last_gc"]["outcome"], "collected");

    // A root that cannot be a directory is refused and reported with a remedy.
    let file = dir.path().join("not-a-directory");
    fs::write(&file, b"x").unwrap();
    let refused = open(
        &Settings::from_values(Some(file.as_os_str()), None),
        &mut trust,
        clock(),
        Arc::new(FixedCalendar),
    );
    let status = respond(&refused, None).unwrap();
    assert_eq!(status["state"], "refused");
    assert_eq!(status["refusal"]["refusal"], "storage");
    assert!(status["remedy"]
        .as_str()
        .unwrap()
        .contains(CATALOG_ROOT_SETTING));
}

#[test]
fn classes_with_keys_in_the_trust_roots_get_the_signed_verifier() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let dir = tempfile::tempdir().unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let public =
        crate::foundation::signing::Ed25519PublicKey::from_bytes(pair.public_key().as_ref())
            .unwrap();
    let roots = dir.path().join("trust-roots.json");
    fs::write(
        &roots,
        json!({
            "format": 1,
            "keys": [{
                "id": "owner-release",
                "algorithm": "ed25519",
                "public_key": public.to_hex(),
                "classes": ["model_helper", "model_weights"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2028-01-01T00:00:00Z",
            }],
        })
        .to_string(),
    )
    .unwrap();
    let mut trust = TrustRootService::open(
        TrustRootLocation::from_setting("YOUGORI_TEST_GLUE_TRUST_ROOTS", Some(roots.as_os_str())),
        Arc::new(FixedCalendar),
    );
    let root = dir.path().join("catalog");
    let catalog = open(
        &Settings::from_values(Some(root.as_os_str()), Some(std::ffi::OsStr::new("4096"))),
        &mut trust,
        clock(),
        Arc::new(FixedCalendar),
    );
    let status = respond(&catalog, None).unwrap();
    let class = |tag: &str| -> Value {
        status["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|class| class["class"] == tag)
            .cloned()
            .unwrap()
    };
    assert_eq!(class("model_helper")["verifier"], "signed");
    assert_eq!(class("model_helper")["accepts_user_selected"], false);
    // Model files take the owner's key and still the owner's own originals.
    assert_eq!(class("model_weights")["verifier"], "signed");
    assert_eq!(class("model_weights")["accepts_user_selected"], true);
    // With trust roots in force, M18F's classes get their own verifiers and policies.
    for tag in ["oci_layer", "guest_image", "runtime_update"] {
        assert_eq!(class(tag)["verifier"], "local", "{tag}");
        assert_eq!(class(tag)["policy"], true, "{tag}");
        assert_eq!(
            class(tag)["accepts_user_selected"],
            tag == "oci_layer",
            "{tag}"
        );
    }
    for tag in ["document_manifest", "dependency_package"] {
        assert_eq!(class(tag)["verifier"], "not_offered", "{tag}");
    }
    // The trust-root service's own status shows the verifiers the catalog registered.
    let trusted = serde_json::to_value(trust.status()).unwrap();
    let helper = trusted["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|class| class["class"] == "model_helper")
        .cloned()
        .unwrap();
    assert_eq!(helper["trust"]["verifier_registered"], true);
}

#[test]
fn the_method_answers_whatever_this_computer_configures_and_a_reload_reaches_no_closed_catalog() {
    // Whatever the variables say on this computer, the method answers with a state and
    // refuses unknown actions; a reload never opens the catalog.
    let status = dispatch(None).unwrap();
    assert!(status["state"].is_string(), "{status}");
    assert!(dispatch(Some("unknown".to_owned())).is_err());
    let reloaded = crate::trust_roots::dispatch(Some("reload".to_owned())).unwrap();
    assert!(reloaded.get("catalog").is_some(), "{reloaded}");
    if status["state"] != "open" {
        assert!(reloaded["catalog"].is_null());
        assert_eq!(on_trust_roots_reloaded(&untrusted()), None);
    }
}

#[test]
fn integrity_extents_tile_the_file_and_keep_the_true_length_of_the_last() {
    use crate::model_memory::manifest::{ExtentPlanError, ExtentPlanner, ExtentSpan};
    assert_eq!(
        TiledExtents.integrity_extents(10, 4),
        Ok(vec![
            ExtentSpan {
                offset_bytes: 0,
                true_length_bytes: 4
            },
            ExtentSpan {
                offset_bytes: 4,
                true_length_bytes: 4
            },
            ExtentSpan {
                offset_bytes: 8,
                true_length_bytes: 2
            },
        ])
    );
    assert_eq!(TiledExtents.integrity_extents(0, 4), Ok(Vec::new()));
    assert_eq!(
        TiledExtents.integrity_extents(10, 0),
        Err(ExtentPlanError::Refused)
    );
}

// ---- The model-file import entry -------------------------------------------------------

/// Identities keyed by the listing alone, so a test can key its request up front.
struct ListingIdentities;

const IDENTITY_DOMAIN: &str = "yougori/test/catalog-glue/identity/v1";

fn source_for(listing: &SourceListing) -> SourceIdentity {
    let files = listing.sorted_files();
    SourceIdentity(
        DigestBuilder::new(IDENTITY_DOMAIN)
            .str("source")
            .digest(&listing_digest(
                files
                    .iter()
                    .map(|file| (&file.path, file.length_bytes, file.content)),
            ))
            .finish(),
    )
}

fn execution_for(source: &SourceIdentity) -> ExecutionIdentity {
    ExecutionIdentity(
        DigestBuilder::new(IDENTITY_DOMAIN)
            .str("execution")
            .digest(&source.0)
            .finish(),
    )
}

impl ModelIdentities for ListingIdentities {
    type Context = ();

    fn source_identity(
        &self,
        listing: &SourceListing,
        _configuration: &Digest,
        _context: &(),
    ) -> Result<SourceIdentity, IdentityError> {
        Ok(source_for(listing))
    }

    fn execution_identity(
        &self,
        source: &SourceIdentity,
        _manifest: &ValidatedManifest,
        _context: &(),
    ) -> Result<ExecutionIdentity, IdentityError> {
        Ok(execution_for(source))
    }

    fn artifact_identity(&self, manifest: &ManifestDigest) -> ArtifactIdentity {
        ArtifactIdentity(
            DigestBuilder::new(IDENTITY_DOMAIN)
                .str("artifact")
                .digest(&manifest.digest())
                .finish(),
        )
    }
}

type TestModels = ModelFiles<ListingIdentities, TiledExtents>;

/// A safetensors file holding `tensors` (name, dtype, shape, bytes) in order.
fn safetensors(tensors: &[(&str, ElementType, &[u64], &[u8])]) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    header.insert("__metadata__".to_owned(), json!({ "format": "pt" }));
    let mut data = Vec::new();
    for (tensor, dtype, shape, bytes) in tensors {
        let begin = data.len();
        data.extend_from_slice(bytes);
        header.insert(
            (*tensor).to_owned(),
            json!({
                "dtype": dtype.safetensors_name(),
                "shape": shape,
                "data_offsets": [begin, data.len()],
            }),
        );
    }
    let mut header = serde_json::to_vec(&header).unwrap();
    while !header.len().is_multiple_of(8) {
        header.push(b' ');
    }
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&data);
    file
}

fn token(text: &str) -> Token {
    Token::new(text).unwrap()
}

fn description() -> ArtifactDescription {
    ArtifactDescription {
        bounds: ManifestBounds::DEFAULT,
        compute_dtype: ElementType::Bf16,
        quantization: Quantization::None,
        adapters: Vec::new(),
        execution_abi: ExecutionAbi {
            runner: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            architecture_adapter: VersionedName {
                name: token("LlamaForCausalLM"),
                version: token("1"),
            },
            layout: token("original"),
            kernels: Vec::new(),
            hardware: HardwareRestriction::Unrestricted,
        },
        distribution: Distribution::SINGLE,
        integrity_extent_bytes: 16,
    }
}

const WEIGHTS: FileRole = FileRole::Weights {
    format: WeightFormat::Safetensors,
    rank: None,
};

/// The owner's model folder: configuration, tokenizer and one safetensors file.
struct ModelFolder {
    dir: tempfile::TempDir,
    files: Vec<(&'static str, Vec<u8>, FileRole)>,
}

impl ModelFolder {
    fn new(seed: u8) -> Self {
        let embed: Vec<u8> = (0..16u8)
            .flat_map(|value| f32::from(value.wrapping_add(seed)).to_le_bytes())
            .collect();
        let norm: Vec<u8> = (0..8u8).map(|value| value ^ seed).collect();
        let files = vec![
            (
                "config.json",
                format!(r#"{{"architectures":["LlamaForCausalLM"],"seed":{seed}}}"#).into_bytes(),
                FileRole::Configuration,
            ),
            (
                "tokenizer.json",
                br#"{"model":{"type":"BPE","vocab":{}}}"#.to_vec(),
                FileRole::Tokenizer,
            ),
            (
                "model.safetensors",
                safetensors(&[
                    (
                        "model.embed_tokens.weight",
                        ElementType::F32,
                        &[4, 4],
                        &embed,
                    ),
                    ("model.norm.weight", ElementType::Bf16, &[4], &norm),
                ]),
                WEIGHTS,
            ),
        ];
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes, _) in &files {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        Self { dir, files }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn listing(&self) -> SourceListing {
        let files: Vec<ListedFile> = self
            .files
            .iter()
            .map(|(name, bytes, role)| ListedFile {
                path: RelativePath::new(*name).unwrap(),
                length_bytes: bytes.len() as u64,
                content: ContentKey::of(bytes),
                role: *role,
            })
            .collect();
        SourceListing {
            origin: SourceOrigin::LocalFolder,
            revision: SourceListing::content_revision(&files),
            files,
        }
    }

    fn import(&self) -> ModelFileImport<()> {
        let listing = self.listing();
        let source = source_for(&listing);
        ModelFileImport {
            folder: self.dir.path().to_path_buf(),
            request: ImportRequest {
                key: ImportKey {
                    source,
                    execution: execution_for(&source),
                },
                listing,
                description: description(),
                state: StateGroup::default(),
                aliases: Vec::new(),
                owners: Vec::new(),
                identity: (),
                catalog: CatalogContext {
                    scope: owner(),
                    execution: ExecutionId::new("exe-model-runner").unwrap(),
                    operation: OperationId::new("op-model-import").unwrap(),
                    trust: TrustClaim::UserSelected,
                    dependencies: BTreeMap::new(),
                },
            },
            lease: Duration::from_secs(600),
            declared: BTreeMap::new(),
            claims: BTreeMap::new(),
        }
    }

    /// Every file's bytes and modification time, to show the folder is untouched.
    fn snapshot(&self) -> Vec<(Vec<u8>, std::time::SystemTime)> {
        self.files
            .iter()
            .map(|(name, _, _)| {
                let path = self.path(name);
                (
                    fs::read(&path).unwrap(),
                    fs::metadata(&path).unwrap().modified().unwrap(),
                )
            })
            .collect()
    }
}

/// The engine's catalog composition with the listing-keyed identities.
struct Engine {
    _dir: tempfile::TempDir,
    root: PathBuf,
    service: CatalogService,
    models: Arc<TestModels>,
}

fn engine_with_quota(quota_bytes: u64) -> Engine {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("catalog");
    let limits = ImportLimits::DEFAULT;
    let read_back = ReadBackChannel::new();
    let (service, models) = CatalogService::open(
        &root,
        engine_config(&QuotaSetting::Bytes(quota_bytes)),
        engine_classes(&read_back, &limits),
        &mut untrusted(),
        clock(),
        Arc::new(FixedCalendar),
        |catalog| ModelFiles::new(catalog, read_back, ListingIdentities, TiledExtents, limits),
    )
    .unwrap();
    Engine {
        _dir: dir,
        root,
        service,
        models,
    }
}

fn data_path(root: &Path, object: ObjectId) -> PathBuf {
    root.join("objects").join(object.to_string()).join("data")
}

#[test]
fn a_model_folder_is_published_as_read_only_originals_and_a_sidecar_under_leases() {
    let engine = engine_with_quota(1 << 20);
    let folder = ModelFolder::new(1);
    let before = folder.snapshot();
    let request = folder.import();

    let imported = engine
        .models
        .import(&request, &CancellationToken::new())
        .unwrap();
    assert!(!imported.reused);
    assert_eq!(imported.scope, owner());
    assert_eq!(
        imported
            .originals
            .iter()
            .map(|original| (original.path.as_str(), original.copied))
            .collect::<Vec<_>>(),
        vec![
            ("config.json", true),
            ("model.safetensors", true),
            ("tokenizer.json", true),
        ]
    );
    // One lease per object, the sidecar's first, each live for the importing execution.
    assert_eq!(imported.leases.len(), 4);
    assert_eq!(imported.leases[0].object, imported.sidecar);
    {
        let catalog = engine.service.catalog();
        for held in &imported.leases {
            assert_eq!(
                catalog
                    .lease_object(&imported.scope, &imported.execution, held.lease)
                    .unwrap()
                    .0,
                held.object
            );
        }
        assert_eq!(
            catalog.status(&owner(), imported.sidecar),
            ObjectStatus::Published
        );
        // Every original is the owner's published copy, keyed by its content.
        for (original, (_, bytes, _)) in imported.originals.iter().zip({
            let mut files = folder.files.clone();
            files.sort_by_key(|file| file.0);
            files
        }) {
            assert_eq!(
                original.object,
                ObjectId::new(
                    &owner(),
                    ArtifactClass::ModelWeights,
                    ContentKey::of(&bytes)
                )
            );
            let path = data_path(&engine.root, original.object);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(fs::metadata(&path).unwrap().permissions().readonly());
        }
    }
    // The owner's folder is exactly as it was.
    assert_eq!(folder.snapshot(), before);

    let status = engine.service.status();
    let scope = status
        .catalog
        .scopes
        .iter()
        .find(|scope| scope.scope == owner())
        .unwrap();
    let total: u64 = folder
        .files
        .iter()
        .map(|(_, bytes, _)| bytes.len() as u64)
        .sum();
    let weights = scope
        .classes
        .iter()
        .find(|class| class.class == ArtifactClass::ModelWeights)
        .unwrap();
    assert_eq!(
        (weights.published.objects, weights.published.bytes),
        (3, total)
    );
    assert_eq!(weights.originals.objects, 3);
    let sidecars = scope
        .classes
        .iter()
        .find(|class| class.class == ArtifactClass::ModelSidecar)
        .unwrap();
    assert_eq!(
        (sidecars.published.objects, sidecars.originals.objects),
        (1, 0)
    );
    assert_eq!(scope.leased_objects, 4);
    let charged = scope.quota.charged_bytes;

    // A repeated import copies and indexes nothing again; storage does not grow.
    let again = engine
        .models
        .import(&request, &CancellationToken::new())
        .unwrap();
    assert!(again.reused);
    assert!(again.originals.iter().all(|original| !original.copied));
    assert_eq!(again.sidecar, imported.sidecar);
    let status = engine.service.status();
    let scope = status
        .catalog
        .scopes
        .iter()
        .find(|scope| scope.scope == owner())
        .unwrap();
    assert_eq!(scope.quota.charged_bytes, charged);

    // Garbage collection removes nothing a lease or the model's root holds.
    let record = engine.service.collect_garbage();
    assert!(
        matches!(&record.outcome, GcOutcome::Collected { removed, .. } if removed.is_empty()),
        "{record:?}"
    );
    engine.models.release(&imported).unwrap();
    engine.models.release(&again).unwrap();
    assert!(engine.models.release(&again).is_err(), "released twice");
    assert_eq!(engine.service.status().catalog.live_leases, 0);
    // Nothing the catalog did touched the owner's folder.
    assert_eq!(folder.snapshot(), before);
}

#[test]
fn a_file_that_does_not_match_its_listing_publishes_nothing() {
    let engine = engine_with_quota(1 << 20);
    let folder = ModelFolder::new(2);
    let request = folder.import();
    // The weights change after they were listed: same length, other bytes.
    let path = folder.path("model.safetensors");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        engine.models.import(&request, &CancellationToken::new()),
        Err(ModelFileRefusal::Source(SourceError::DigestMismatch {
            path: RelativePath::new("model.safetensors").unwrap()
        }))
    );
    // A missing file is refused the same way, before anything is published.
    bytes[last] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
    fs::remove_file(folder.path("tokenizer.json")).unwrap();
    assert_eq!(
        engine
            .models
            .import(&folder.import(), &CancellationToken::new()),
        Err(ModelFileRefusal::Source(SourceError::MissingFile {
            path: RelativePath::new("tokenizer.json").unwrap()
        }))
    );
    let status = engine.service.status();
    assert!(status
        .catalog
        .scopes
        .iter()
        .all(|scope| scope.classes.is_empty()));
    assert_eq!(status.catalog.live_leases, 0);
}

#[test]
fn a_model_over_the_owner_budget_is_refused_with_the_catalog_reason() {
    let engine = engine_with_quota(64);
    let folder = ModelFolder::new(3);
    let refused = engine
        .models
        .import(&folder.import(), &CancellationToken::new())
        .unwrap_err();
    let ModelFileRefusal::Admission { path, refusal } = &refused else {
        panic!("{refused:?}");
    };
    // config.json fits; the weights do not, and nothing is evicted for them.
    assert_eq!(path.as_str(), "model.safetensors");
    assert!(
        matches!(
            refusal.as_ref(),
            ImportRefusal::Quota {
                refusal: QuotaRefusal::Exceeded {
                    limit_bytes: 64,
                    evictable_bytes: 0,
                    ..
                }
            }
        ),
        "{refusal:?}"
    );
    assert!(refused.to_string().contains("model.safetensors"));
    assert_eq!(engine.service.status().catalog.live_leases, 0);
}

#[test]
fn a_cancelled_model_import_publishes_nothing() {
    let engine = engine_with_quota(1 << 20);
    let folder = ModelFolder::new(4);
    let request = folder.import();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        engine.models.import(&request, &cancel),
        Err(ModelFileRefusal::Cancelled { path: None })
    );
    let status = engine.service.status();
    assert!(status
        .catalog
        .scopes
        .iter()
        .all(|scope| scope.classes.is_empty()));
    // Nothing was staged either, so the retry copies everything once.
    assert_eq!(status.catalog.staging.objects, 0);
    let imported = engine
        .models
        .import(&request, &CancellationToken::new())
        .unwrap();
    assert!(imported.originals.iter().all(|original| original.copied));
    assert_eq!(imported.leases.len(), 4);
}

// ---- Model views -------------------------------------------------------------------------

/// The engine's catalog in a temporary root, with the registry its views are held in and
/// the listing-keyed identity port the engine uses.
struct ViewEngine {
    dir: tempfile::TempDir,
    root: PathBuf,
    views: ViewRegistry,
    catalog: Option<EngineCatalog>,
}

impl ViewEngine {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("catalog");
        let views = ViewRegistry::new();
        let catalog = open_with_views(
            &Settings::from_values(
                Some(root.as_os_str()),
                Some(std::ffi::OsStr::new("1048576")),
            ),
            &mut untrusted(),
            clock(),
            Arc::new(FixedCalendar),
            &views,
        );
        Self {
            dir,
            root,
            views,
            catalog: Some(catalog),
        }
    }

    fn catalog(&self) -> &EngineCatalog {
        self.catalog.as_ref().unwrap()
    }

    fn service(&self) -> &CatalogService {
        match self.catalog() {
            EngineCatalog::Open { service, .. } => service,
            _ => panic!("not open"),
        }
    }

    /// Drops the catalog, as a restart would, and opens the root again without the engine's
    /// sweep, as the foundation's recovery alone would.
    fn reopen_without_sweep(&mut self) {
        self.catalog = None;
        self.views = ViewRegistry::new();
        self.catalog = Some(open(
            &Settings::from_values(
                Some(self.root.as_os_str()),
                Some(std::ffi::OsStr::new("1048576")),
            ),
            &mut untrusted(),
            clock(),
            Arc::new(FixedCalendar),
        ));
    }

    fn import(&self, folder: &ModelFolder) -> ImportedModel {
        import_model(
            self.catalog(),
            &folder_import(folder),
            &CancellationToken::new(),
        )
        .unwrap()
    }

    fn view_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = fs::read_dir(self.root.join(VIEWS_DIR))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        dirs.sort();
        dirs
    }
}

impl Drop for ViewEngine {
    fn drop(&mut self) {
        self.catalog = None;
        make_tree_writable(self.dir.path());
    }
}

// ---------------------------------------------------------------- publication and reload

/// A structure check that accepts every object, for the publication schedules below.
struct AcceptAll;

impl crate::foundation::signing::StructureValidator for AcceptAll {
    fn validate(
        &self,
        _content: &crate::foundation::catalog::ContentDescriptor,
        _bytes: &mut crate::foundation::catalog::ObjectBytes,
    ) -> Result<(), crate::foundation::catalog::VerifierRejection> {
        Ok(())
    }
}

/// Bytes in memory as an import source.
struct MemorySource {
    identity: crate::foundation::catalog::SourceIdentity,
    bytes: Vec<u8>,
}

impl MemorySource {
    fn new(bytes: &[u8]) -> Self {
        Self {
            identity: crate::foundation::catalog::SourceIdentity::describe(
                "test",
                &ContentKey::of(bytes).to_string(),
            ),
            bytes: bytes.to_vec(),
        }
    }
}

impl crate::foundation::catalog::ImportSource for MemorySource {
    fn identity(&self) -> crate::foundation::catalog::SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, crate::foundation::catalog::SourceError> {
        Ok(u64::try_from(self.bytes.len()).unwrap())
    }

    fn read_at(
        &mut self,
        offset_bytes: u64,
        buffer: &mut [u8],
    ) -> Result<usize, crate::foundation::catalog::SourceError> {
        let start = usize::try_from(offset_bytes).unwrap().min(self.bytes.len());
        let available = &self.bytes[start..];
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// The publication schedules' signing key (`seed` bytes) and its publisher identity.
fn release_pair(seed: u8) -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn release_public(seed: u8) -> crate::foundation::signing::Ed25519PublicKey {
    use ring::signature::KeyPair;
    crate::foundation::signing::Ed25519PublicKey::from_bytes(
        release_pair(seed).public_key().as_ref(),
    )
    .unwrap()
}

/// A trust-root document listing the release key for runtime updates, revoked or not.
fn release_roots(seed: u8, revoked: bool) -> String {
    let mut key = json!({
        "id": "release-2026",
        "algorithm": "ed25519",
        "public_key": release_public(seed).to_hex(),
        "classes": ["runtime_update"],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2028-01-01T00:00:00Z",
    });
    if revoked {
        key["revoked"] = json!({ "reason": "key-compromise" });
    }
    json!({ "format": 1, "keys": [key] }).to_string()
}

/// `seed`'s signed claim for `bytes` as a runtime update, and the bytes as a source.
fn signed_update(
    seed: u8,
    bytes: &[u8],
) -> (crate::foundation::catalog::ImportRequest, MemorySource) {
    use std::num::NonZeroU64;
    let class = ArtifactClass::RuntimeUpdate;
    let manifest =
        crate::foundation::catalog::ImportManifest::describe(bytes, NonZeroU64::new(8).unwrap());
    let publisher = release_public(seed).publisher_id();
    let statement = crate::foundation::signing::content_statement(
        &publisher,
        class,
        &manifest.content_key,
        manifest.true_length_bytes,
    );
    let attestation = release_pair(seed)
        .sign(statement.as_bytes())
        .as_ref()
        .to_vec();
    let request = crate::foundation::catalog::ImportRequest {
        operation: OperationId::new(format!("op-update-{}", bytes.len())).unwrap(),
        execution: ExecutionId::new("exe-release").unwrap(),
        scope: Scope::Host,
        class,
        role: crate::foundation::catalog::ObjectRole::Original,
        manifest,
        trust: TrustClaim::Publisher {
            publisher,
            attestation,
        },
        depends_on: std::collections::BTreeSet::new(),
        metadata: crate::foundation::catalog::ObjectMetadata::new(),
    };
    (request, MemorySource::new(bytes))
}

/// Opens the engine's catalog shape at `root` through `trust`: the engine's own classes
/// and, beside them, the runtime update class checked by `AcceptAll`. The schedules below
/// exercise the publication protocol with this production composition, not the update
/// class's real structure check.
fn open_for_updates(root: &Path, trust: &mut TrustRootService) -> EngineCatalog {
    let limits = ImportLimits::DEFAULT;
    let read_back = ReadBackChannel::new();
    let mut offered = engine_classes(&read_back, &limits);
    offered.push(crate::foundation::catalog_service::OfferedClass::Signed(
        crate::foundation::signing::ClassVerification {
            class: ArtifactClass::RuntimeUpdate,
            binding: crate::foundation::signing::StatementBinding::Content,
            structure: Box::new(AcceptAll),
        },
    ));
    let quota = QuotaSetting::Bytes(1 << 16);
    let (service, models) = CatalogService::open(
        root,
        engine_config(&quota),
        offered,
        trust,
        clock(),
        Arc::new(FixedCalendar),
        |catalog| ModelFiles::new(catalog, read_back, FolderIdentities, TiledExtents, limits),
    )
    .unwrap();
    EngineCatalog::Open {
        service: Box::new(service),
        models,
        policy: None,
        quota,
    }
}

fn open_service(catalog: &EngineCatalog) -> &CatalogService {
    match catalog {
        EngineCatalog::Open { service, .. } => service,
        _ => panic!("the catalog opened"),
    }
}

/// Committed files are read-only; make them writable so the temporary root goes.
#[allow(clippy::permissions_set_readonly_false)]
fn make_tree_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_tree_writable(&entry.path());
        }
    }
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

/// `folder`'s import keyed as the engine keys it, for a fresh execution.
fn folder_import(folder: &ModelFolder) -> ModelFileImport<()> {
    let listing = folder.listing();
    let description = description();
    ModelFileImport {
        folder: folder.dir.path().to_path_buf(),
        request: ImportRequest {
            key: FolderIdentities::import_key(&listing, &description),
            listing,
            description,
            state: StateGroup::default(),
            aliases: Vec::new(),
            owners: Vec::new(),
            identity: (),
            catalog: CatalogContext {
                scope: owner(),
                execution: ExecutionId::generate(),
                operation: OperationId::new("op-model-run").unwrap(),
                trust: TrustClaim::UserSelected,
                dependencies: BTreeMap::new(),
            },
        },
        lease: Duration::from_secs(600),
        declared: BTreeMap::new(),
        claims: BTreeMap::new(),
    }
}

#[test]
fn the_folder_identity_port_keys_an_import_before_it_reads_and_the_importer_agrees() {
    let engine = ViewEngine::new();
    let folder = ModelFolder::new(11);
    // The importer derives the same identities the runner keyed the request by: a
    // mismatch would refuse the import.
    let imported = engine.import(&folder);
    assert!(!imported.reused);
    assert_eq!(
        imported.artifact.key,
        FolderIdentities::import_key(&folder.listing(), &description())
    );
    // Another folder's bytes are another source; another description is another execution.
    let other = ModelFolder::new(12);
    let key = FolderIdentities::import_key(&other.listing(), &description());
    assert_ne!(key.source, imported.artifact.key.source);
    let mut quantized = description();
    quantized.quantization = Quantization::Method {
        method: token("gguf"),
        parameters: vec![(token("type"), token("Q4_K_M"))],
    };
    let key = FolderIdentities::import_key(&folder.listing(), &quantized);
    assert_eq!(key.source, imported.artifact.key.source);
    assert_ne!(key.execution, imported.artifact.key.execution);
}

#[test]
fn cancelled_view_copy_releases_imported_leases_and_preserves_originals() {
    let engine = ViewEngine::new();
    let folder = ModelFolder::new(13);
    let before = folder.snapshot();
    let imported = engine.import(&folder);
    let execution = imported.execution.clone();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(hold_model_view_cancellable(engine.catalog(), &engine.views, imported, &cancel).is_err());
    assert!(engine.views.view(&execution).is_none());
    assert!(engine.view_dirs().is_empty());
    let status = respond_with_views(engine.catalog(), &engine.views, None).unwrap();
    assert_eq!(status["catalog"]["live_leases"], 0);
    assert_eq!(folder.snapshot(), before);
    let retry = engine.import(&folder);
    assert!(hold_model_view(engine.catalog(), &engine.views, retry).is_ok());
}

#[test]
fn a_held_view_copies_the_published_originals_read_only_and_release_removes_it() {
    let engine = ViewEngine::new();
    let folder = ModelFolder::new(13);
    let before = folder.snapshot();
    let imported = engine.import(&folder);
    let execution = imported.execution.clone();
    let sidecar = imported.sidecar;
    let originals = imported.originals.clone();

    let view = hold_model_view(engine.catalog(), &engine.views, imported).unwrap();
    assert_eq!(view.execution, execution);
    assert_eq!(view.sidecar, sidecar);
    assert_eq!(
        view.path,
        engine.root.join(VIEWS_DIR).join(execution.as_str())
    );
    assert_eq!(view.files, 3);
    assert_eq!(
        view.bytes,
        folder
            .files
            .iter()
            .map(|(_, bytes, _)| bytes.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(engine.views.view(&execution), Some(view.clone()));
    for original in &originals {
        let link = view.path.join(original.path.as_str());
        let data = data_path(&engine.root, original.object);
        assert_eq!(fs::read(&link).unwrap(), fs::read(&data).unwrap());
        assert!(fs::metadata(&link).unwrap().permissions().readonly());
        assert!(
            fs::OpenOptions::new().write(true).open(&link).is_err(),
            "the view is writable"
        );
    }
    // The status shows the view beside the leases.
    let status = respond_with_views(engine.catalog(), &engine.views, None).unwrap();
    assert_eq!(status["views"]["count"], 1);
    assert_eq!(status["views"]["held"][0]["execution"], execution.as_str());
    assert_eq!(status["views"]["held"][0]["model"], sidecar.to_string());
    assert_eq!(status["views"]["held"][0]["files"], 3);
    assert_eq!(status["views"]["held"][0]["leases"], 4);
    assert_eq!(status["catalog"]["live_leases"], 4);
    // The collector leaves the view, its links and the leased objects alone.
    let record = engine.service().collect_garbage();
    assert!(matches!(&record.outcome, GcOutcome::Collected { removed, .. } if removed.is_empty()));
    assert_eq!(engine.view_dirs(), vec![view.path.clone()]);
    assert_eq!(fs::read_dir(&view.path).unwrap().count(), 3);

    // Release: the leases end, the view goes, the published copies stay read-only.
    let swept = release_model_view(engine.catalog(), &engine.views, &execution).unwrap();
    assert_eq!(swept.kept, 0);
    assert!(!view.path.exists());
    assert_eq!(engine.views.view(&execution), None);
    let status = respond_with_views(engine.catalog(), &engine.views, None).unwrap();
    assert_eq!(status["catalog"]["live_leases"], 0);
    assert_eq!(status["views"]["count"], 0);
    for original in &originals {
        let data = data_path(&engine.root, original.object);
        assert!(
            fs::metadata(&data).unwrap().permissions().readonly(),
            "{}",
            original.path
        );
        assert_eq!(
            engine.service().catalog().status(&owner(), original.object),
            ObjectStatus::Published
        );
    }
    assert_eq!(folder.snapshot(), before);
}

#[test]
fn opening_the_catalog_removes_views_without_a_live_lease_and_quarantines_nothing() {
    let mut engine = ViewEngine::new();
    let folder = ModelFolder::new(14);
    let imported = engine.import(&folder);
    let execution = imported.execution.clone();
    let view = hold_model_view(engine.catalog(), &engine.views, imported).unwrap();
    // Something else left under views/ is the engine's too.
    let stale = engine.root.join(VIEWS_DIR).join("exe-stale");
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("left-over"), b"x").unwrap();
    // A sweep while the execution holds live leases keeps its view and removes the stale one.
    let swept = sweep_stale_views(engine.catalog(), &engine.views).unwrap();
    assert_eq!(
        (swept.kept, swept.removed.clone()),
        (1, vec!["exe-stale".to_owned()])
    );
    assert_eq!(engine.view_dirs(), vec![view.path.clone()]);
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("left-over"), b"x").unwrap();

    // The catalog's own recovery leaves views/ alone...
    engine.reopen_without_sweep();
    let mut left = vec![stale.clone(), view.path.clone()];
    left.sort();
    assert_eq!(engine.view_dirs(), left);
    let status = respond_with_views(engine.catalog(), &engine.views, None).unwrap();
    assert_eq!(
        status["recovery"]["quarantined"].as_array().unwrap().len(),
        0
    );
    assert_eq!(status["recovery"]["published"], 4);
    assert_eq!(status["recovery"]["temporaries_removed"], 0);
    // ...and so does the collector.
    let record = engine.service().collect_garbage();
    assert!(matches!(&record.outcome, GcOutcome::Collected { removed, .. } if removed.is_empty()));
    assert_eq!(engine.view_dirs(), left);
    // The engine's sweep on open removes every view, since no lease survived the reopen,
    // and quarantines nothing.
    let swept = sweep_stale_views(engine.catalog(), &engine.views).unwrap();
    assert_eq!(swept.kept, 0);
    assert_eq!(swept.removed.len(), 2);
    assert!(swept.failures.is_empty(), "{:?}", swept.failures);
    assert!(engine.view_dirs().is_empty());
    assert!(engine.root.join(VIEWS_DIR).is_dir());
    let status = respond_with_views(engine.catalog(), &engine.views, None).unwrap();
    assert_eq!(
        status["recovery"]["quarantined"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        status["views"]["last_sweep"]["removed"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Classes are in class order: the three weights originals, then the one sidecar.
    assert_eq!(
        status["catalog"]["scopes"][1]["classes"][0]["published"]["objects"],
        3
    );
    assert_eq!(
        status["catalog"]["scopes"][1]["classes"][1]["published"]["objects"],
        1
    );

    // Before the next start the execution leases its model again and the view is copied again.
    let originals: Vec<(RelativePath, ObjectId)> = folder
        .listing()
        .files
        .iter()
        .map(|file| {
            (
                file.path.clone(),
                ObjectId::new(&owner(), ArtifactClass::ModelWeights, file.content),
            )
        })
        .collect();
    let copied = refresh_model_view(
        engine.catalog(),
        &engine.views,
        &owner(),
        &execution,
        view.sidecar,
        originals.clone(),
        Duration::from_secs(600),
    )
    .unwrap();
    assert_eq!((copied.path, copied.files), (view.path.clone(), 3));
    assert_eq!(
        respond_with_views(engine.catalog(), &engine.views, None).unwrap()["catalog"]
            ["live_leases"],
        4
    );
    // Refreshing again renews the held leases and links nothing twice.
    let again = refresh_model_view(
        engine.catalog(),
        &engine.views,
        &owner(),
        &execution,
        view.sidecar,
        originals,
        Duration::from_secs(600),
    )
    .unwrap();
    assert_eq!(again.files, 3);
    assert_eq!(
        respond_with_views(engine.catalog(), &engine.views, None).unwrap()["catalog"]
            ["live_leases"],
        4
    );
    // A model the catalog does not hold cannot be leased, and nothing stays held for it.
    let missing = ObjectId::new(
        &owner(),
        ArtifactClass::ModelWeights,
        ContentKey::of(b"never published"),
    );
    let refused = refresh_model_view(
        engine.catalog(),
        &engine.views,
        &owner(),
        &ExecutionId::generate(),
        view.sidecar,
        vec![(RelativePath::new("missing.bin").unwrap(), missing)],
        Duration::from_secs(600),
    )
    .unwrap_err();
    assert!(
        matches!(refused, ViewRefusal::Lease { object, .. } if object == missing),
        "{refused:?}"
    );
    assert_eq!(
        respond_with_views(engine.catalog(), &engine.views, None).unwrap()["views"]["count"],
        1
    );
}

/// Review finding R4 on the production seam: a signed update is published under the
/// release key before the engine's catalog is first opened; a reload then revokes the key,
/// either during the catalog's open (between the open and the publication, where the old
/// initializer had dropped the trust lock) or after it. Either way the reload must reach
/// the catalog: the cached object is quarantined and can no longer be leased, and a new
/// import under the key is refused.
fn publication_schedule(reload_during_publication: bool) {
    use std::sync::mpsc;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("catalog");
    let roots = dir.path().join("trust-roots.json");
    fs::write(&roots, release_roots(1, false)).unwrap();
    let location =
        TrustRootLocation::from_setting("YOUGORI_TEST_GLUE_TRUST_ROOTS", Some(roots.as_os_str()));
    let bytes = b"runtime update persisted before the engine's first catalog access";
    let object = {
        let mut trust = TrustRootService::open(location.clone(), Arc::new(FixedCalendar));
        let seeded = open_for_updates(&root, &mut trust);
        let (request, mut source) = signed_update(1, bytes);
        let mut catalog = open_service(&seeded).catalog();
        let identity = crate::foundation::catalog::ImportSource::identity(&source);
        let ticket = match catalog.begin_import(request, identity).unwrap() {
            crate::foundation::catalog::ImportStart::Started(ticket) => ticket,
            other => panic!("expected a new import, got {other:?}"),
        };
        match catalog
            .drive_import(
                &ticket,
                &mut source,
                &mut crate::foundation::catalog::Uninterrupted,
            )
            .unwrap()
        {
            crate::foundation::catalog::ImportStatus::Published { object, .. } => object,
            other => panic!("expected publication, got {other:?}"),
        }
    };

    let trust = Mutex::new(TrustRootService::open(location, Arc::new(FixedCalendar)));
    let cell: OnceLock<EngineCatalog> = OnceLock::new();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let (reloaded_tx, reloaded_rx) = mpsc::channel();
    // The owner revokes the key: the next reload puts the revocation in force.
    fs::write(&roots, release_roots(1, true)).unwrap();
    let reload = |trust: &Mutex<TrustRootService>, cell: &OnceLock<EngineCatalog>| {
        let mut service = trust.lock().unwrap();
        let outcome = service.reload();
        assert!(
            matches!(
                outcome,
                crate::foundation::signing::ReloadOutcome::Applied { .. }
            ),
            "{outcome:?}"
        );
        reload_reaches(cell, &service)
    };
    let quarantined = |applied: &TrustApplied| {
        applied.classes.iter().any(|class| {
            class.class == ArtifactClass::RuntimeUpdate && class.quarantined == [object]
        })
    };
    std::thread::scope(|scope| {
        let root = root.clone();
        let (trust, cell) = (&trust, &cell);
        let opening = scope.spawn(move || {
            publish(cell, trust, |service| {
                let catalog = open_for_updates(&root, service);
                // The old initializer had released the trust lock here, before the
                // publication; a reload must now wait for the publication instead.
                ready_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                catalog
            });
        });
        ready_rx.recv().unwrap();
        assert!(
            cell.get().is_none(),
            "nothing is published while the open runs"
        );
        if reload_during_publication {
            scope.spawn(move || reloaded_tx.send(reload(trust, cell)).unwrap());
            // The reload cannot run between the open and the publication.
            assert!(
                reloaded_rx
                    .recv_timeout(Duration::from_millis(300))
                    .is_err(),
                "the reload ran before the catalog was published"
            );
            resume_tx.send(()).unwrap();
            opening.join().unwrap();
            let applied = reloaded_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("the reload completes once the catalog is published")
                .expect("the reload reaches the published catalog");
            assert!(quarantined(&applied), "{applied:?}");
        } else {
            resume_tx.send(()).unwrap();
            opening.join().unwrap();
            let applied = reload(trust, cell).expect("the reload reaches the published catalog");
            assert!(quarantined(&applied), "{applied:?}");
        }
    });

    // Both schedules refuse new content under the revoked key and the cached object.
    let service = open_service(cell.get().unwrap());
    let mut catalog = service.catalog();
    let fresh = b"different runtime bytes after the revocation";
    let (request, source) = signed_update(1, fresh);
    assert!(matches!(
        catalog.begin_import(request, source.identity),
        Err(ImportRefusal::Trust { .. })
    ));
    assert!(matches!(
        catalog.status(&Scope::Host, object),
        ObjectStatus::Quarantined { .. }
    ));
    let lease = catalog.acquire_lease(
        &Scope::Host,
        &ExecutionId::new("exe-reader").unwrap(),
        object,
        Duration::from_secs(30),
    );
    assert!(
        lease.is_err(),
        "a completed key revocation must also refuse the cached object; got {lease:?}"
    );
    drop(catalog);
    make_tree_writable(dir.path());
}

#[test]
fn a_trust_reload_during_the_catalogs_publication_waits_and_then_reaches_it() {
    publication_schedule(true);
}

#[test]
fn a_trust_reload_after_the_catalogs_publication_reaches_it() {
    publication_schedule(false);
}

#[test]
fn a_published_catalog_is_returned_without_the_trust_lock_and_opens_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("catalog");
    let trust = Mutex::new(untrusted());
    let cell: OnceLock<EngineCatalog> = OnceLock::new();
    let opens = AtomicUsize::new(0);
    let first = publish(&cell, &trust, |service| {
        opens.fetch_add(1, Ordering::SeqCst);
        open_for_updates(&root, service)
    }) as *const EngineCatalog;
    // While another holder has the trust service, the published catalog is still
    // returned: the fast path takes no lock and opens nothing again.
    let held = trust.lock().unwrap();
    let again = publish(&cell, &trust, |service| {
        opens.fetch_add(1, Ordering::SeqCst);
        open_for_updates(&root, service)
    });
    assert!(std::ptr::eq(first, again));
    drop(held);
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    // A reload reaches no unpublished catalog, and reaches a published one.
    let empty: OnceLock<EngineCatalog> = OnceLock::new();
    assert!(reload_reaches(&empty, &trust.lock().unwrap()).is_none());
    assert!(reload_reaches(&cell, &trust.lock().unwrap()).is_some());
    make_tree_writable(dir.path());
}

#[test]
fn the_default_root_lives_under_the_data_folder_when_its_volume_has_room_and_the_owner_said_nothing(
) {
    let data = std::env::temp_dir().join("yougori-catalog-default-test");
    let data = data.as_path();
    let gib = 1u64 << 30;
    // Unset, with room: the default root and the default budget.
    let (settings, policy) = Settings::with_defaults(None, None, Some(data), Some(100 * gib));
    assert!(
        matches!(&settings.location, CatalogLocation::Directory { setting, path } if *setting == DEFAULT_ROOT_SETTING && *path == data.join(DEFAULT_ROOT_FOLDER)),
        "{:?}",
        settings.location
    );
    assert_eq!(settings.quota, QuotaSetting::Bytes(DEFAULT_QUOTA_BYTES));
    assert_eq!(
        policy,
        DefaultPolicy::Taken {
            root: data.join(DEFAULT_ROOT_FOLDER),
            free_bytes: 100 * gib
        }
    );
    // An explicit budget stays with the default root.
    let (settings, _) = Settings::with_defaults(
        None,
        Some(std::ffi::OsStr::new("1048576")),
        Some(data),
        Some(100 * gib),
    );
    assert_eq!(settings.quota, QuotaSetting::Bytes(1048576));
    // Too little room: not configured, with the free bytes seen.
    let (settings, policy) = Settings::with_defaults(None, None, Some(data), Some(10 * gib));
    assert!(matches!(
        settings.location,
        CatalogLocation::NotConfigured { .. }
    ));
    assert_eq!(
        policy,
        DefaultPolicy::TooLittleFree {
            free_bytes: 10 * gib
        }
    );
    // No data folder: not configured.
    let (_, policy) = Settings::with_defaults(None, None, None, None);
    assert_eq!(policy, DefaultPolicy::NoDataFolder);
    // The owner's explicit root is the owner's word, budget or not.
    let explicit = std::env::temp_dir().join("yougori-catalog-explicit-test");
    let (settings, policy) = Settings::with_defaults(
        Some(explicit.as_os_str()),
        None,
        Some(data),
        Some(100 * gib),
    );
    assert!(matches!(
        settings.location,
        CatalogLocation::Directory {
            setting: CATALOG_ROOT_SETTING,
            ..
        }
    ));
    assert_eq!(settings.quota, QuotaSetting::NotConfigured);
    assert_eq!(policy, DefaultPolicy::Configured);
    // The owner turned it off.
    let (settings, policy) = Settings::with_defaults(
        Some(std::ffi::OsStr::new(" OFF ")),
        None,
        Some(data),
        Some(100 * gib),
    );
    assert!(matches!(
        settings.location,
        CatalogLocation::NotConfigured { .. }
    ));
    assert_eq!(policy, DefaultPolicy::Off);
}

#[test]
fn a_running_environments_view_and_leases_survive_a_restart_and_the_rest_is_swept() {
    let mut engine = ViewEngine::new();
    let folder = ModelFolder::new(15);
    let imported = engine.import(&folder);
    let execution = imported.execution.clone();
    let sidecar = imported.sidecar;
    let originals = imported.originals.clone();
    let view = hold_model_view(engine.catalog(), &engine.views, imported).unwrap();
    let kept_file = view.path.join(originals[0].path.as_str());
    let before = fs::metadata(&kept_file).unwrap().modified().unwrap();
    // Another execution's view, whose environment is not running after the restart.
    let other = engine.import(&ModelFolder::new(16));
    let other_view = hold_model_view(engine.catalog(), &engine.views, other).unwrap();
    // A restart: the catalog reopens without a sweep, no lease survives.
    engine.reopen_without_sweep();
    assert_eq!(engine.view_dirs().len(), 2);
    // The engine's start restores the running environment's model and sweeps the other.
    let running = RunningModel {
        environment: "env-running".to_owned(),
        execution: execution.clone(),
        sidecar,
        originals: originals
            .iter()
            .map(|original| (original.path.clone(), original.object))
            .collect(),
    };
    let restored = restore_views(
        engine.catalog(),
        &engine.views,
        &owner(),
        &[running],
        Duration::from_secs(3600),
    )
    .unwrap();
    assert_eq!(restored.restored, vec!["env-running".to_owned()]);
    assert!(restored.failures.is_empty(), "{:?}", restored.failures);
    assert_eq!(restored.swept.kept, 1);
    assert_eq!(
        restored.swept.removed,
        vec![other_view.execution.to_string()]
    );
    assert_eq!(engine.view_dirs(), vec![view.path.clone()]);
    // The view's files were there and stayed: nothing was copied again.
    assert_eq!(
        fs::metadata(&kept_file).unwrap().modified().unwrap(),
        before
    );
    assert_eq!(fs::read_dir(&view.path).unwrap().count(), 3);
    // The leases are live again and the status says what the start did.
    let status = respond_with_views(engine.catalog(), &engine.views, None).unwrap();
    assert_eq!(status["views"]["count"], 1);
    assert_eq!(status["catalog"]["live_leases"], 4);
    assert_eq!(
        status["views"]["last_restore"]["restored"][0],
        "env-running"
    );
    assert_eq!(
        status["views"]["last_restore"]["swept"]["removed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A model whose objects are gone cannot be restored; it is reported and its view swept.
    engine.reopen_without_sweep();
    let missing = RunningModel {
        environment: "env-missing".to_owned(),
        execution: ExecutionId::new("exe-missing").unwrap(),
        sidecar: ObjectId::new(
            &owner(),
            ArtifactClass::ModelSidecar,
            crate::foundation::ids::ContentKey::of(b"nothing"),
        ),
        originals: Vec::new(),
    };
    let restored = restore_views(
        engine.catalog(),
        &engine.views,
        &owner(),
        &[missing],
        Duration::from_secs(3600),
    )
    .unwrap();
    assert!(restored.restored.is_empty());
    assert_eq!(restored.failures.len(), 1);
    assert!(engine.view_dirs().is_empty());
}

// Delivery 2 (G04/S02): declarations before the import, publisher claims, bounded eviction
// and single flight across requests.

/// Publishes `bytes` as a prepared representation derived from the owner's `from`,
/// through the catalog directly (as a converter would), and returns its object.
fn publish_prepared(engine: &Engine, bytes: &[u8], from: ObjectId) -> ObjectId {
    let mut catalog = engine.service.catalog();
    let mut source = MemorySource::new(bytes);
    let request = ObjectImport {
        operation: OperationId::new("op-prepare").unwrap(),
        execution: ExecutionId::new("exe-prepare").unwrap(),
        scope: owner(),
        class: ArtifactClass::ModelWeights,
        role: ObjectRole::Prepared {
            derived_from: [from].into_iter().collect(),
        },
        manifest: ImportManifest::describe(bytes, ORIGINAL_EXTENT_BYTES),
        trust: TrustClaim::UserSelected,
        depends_on: std::collections::BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ImportStart::Started(ticket) = catalog.begin_import(request, source.identity()).unwrap()
    else {
        panic!("the prepared representation did not start")
    };
    let status = catalog
        .drive_import(&ticket, &mut source, &mut Uninterrupted)
        .unwrap();
    let ImportStatus::Published { object, .. } = status else {
        panic!("{status:?}")
    };
    catalog.cancel_import(ticket);
    object
}

/// The bytes of `folder`'s files that an import after `held` (another folder's files,
/// published already) copies: the files whose bytes `held` does not hold.
fn fresh_bytes(folder: &ModelFolder, held: &ModelFolder) -> u64 {
    folder
        .files
        .iter()
        .filter(|(_, bytes, _)| !held.files.iter().any(|(_, other, _)| other == bytes))
        .map(|(_, bytes, _)| bytes.len() as u64)
        .sum()
}

#[test]
fn a_model_over_budget_evicts_idle_prepared_representations_as_far_as_needed_and_keeps_every_original(
) {
    let a = ModelFolder::new(21);
    let b = ModelFolder::new(22);
    let prepared_bytes = vec![0x5au8; 65_536];
    // Measured once: what A and a prepared representation charge the owner's budget.
    let measure = engine_with_quota(1 << 30);
    let imported_a = measure
        .models
        .import(&a.import(), &CancellationToken::new())
        .unwrap();
    publish_prepared(&measure, &prepared_bytes, imported_a.originals[0].object);
    let charged = measure
        .service
        .catalog()
        .quota_usage(&owner())
        .charged_bytes();
    drop(measure);

    // A budget that takes A, the prepared representation and B's originals less one byte:
    // B's last original is one byte over, and the import evicts to make room.
    let engine = engine_with_quota(charged + fresh_bytes(&b, &a) - 1);
    let imported_a = engine
        .models
        .import(&a.import(), &CancellationToken::new())
        .unwrap();
    let prepared = publish_prepared(&engine, &prepared_bytes, imported_a.originals[0].object);
    assert_eq!(
        engine
            .service
            .catalog()
            .quota_usage(&owner())
            .charged_bytes(),
        charged
    );
    let imported_b = engine
        .models
        .import(&b.import(), &CancellationToken::new())
        .unwrap();
    // One eviction, of exactly the prepared representation; every object of A stays.
    assert_eq!(imported_b.evictions.len(), 1, "{:?}", imported_b.evictions);
    assert_eq!(imported_b.evictions[0].evicted, vec![prepared]);
    assert_eq!(imported_b.evictions[0].freed_bytes, 65_536);
    assert!(imported_b.originals.iter().any(|original| original.copied));
    let catalog = engine.service.catalog();
    assert_eq!(catalog.status(&owner(), prepared), ObjectStatus::Absent);
    for original in &imported_a.originals {
        assert_eq!(
            catalog.status(&owner(), original.object),
            ObjectStatus::Published,
            "{}",
            original.path
        );
    }
    assert_eq!(
        catalog.status(&owner(), imported_a.sidecar),
        ObjectStatus::Published
    );
    drop(catalog);

    // With nothing evictable the same shortfall is the catalog's refusal, as before, and
    // A's originals are never candidates.
    let bare = engine_with_quota(charged - 65_536 + fresh_bytes(&b, &a) - 1);
    bare.models
        .import(&a.import(), &CancellationToken::new())
        .unwrap();
    let refused = bare
        .models
        .import(&b.import(), &CancellationToken::new())
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            ModelFileRefusal::Admission { refusal, .. }
                if matches!(refusal.as_ref(), ImportRefusal::Quota { refusal: QuotaRefusal::Exceeded { evictable_bytes: 0, .. } })
        ),
        "{refused:?}"
    );
}

#[test]
fn a_sidecar_the_budget_cannot_take_evicts_idle_prepared_representations_and_never_an_original() {
    let a = ModelFolder::new(31);
    let b = ModelFolder::new(32);
    let prepared_bytes = vec![0x6bu8; 65_536];
    // Measured once: what A with a prepared representation charges, and then B whole.
    let measure = engine_with_quota(1 << 30);
    let imported_a = measure
        .models
        .import(&a.import(), &CancellationToken::new())
        .unwrap();
    publish_prepared(&measure, &prepared_bytes, imported_a.originals[0].object);
    let before_b = measure
        .service
        .catalog()
        .quota_usage(&owner())
        .charged_bytes();
    measure
        .models
        .import(&b.import(), &CancellationToken::new())
        .unwrap();
    let with_b = measure
        .service
        .catalog()
        .quota_usage(&owner())
        .charged_bytes();
    let sidecar_b = with_b - before_b - fresh_bytes(&b, &a);
    assert!(sidecar_b > 0 && sidecar_b < 65_536, "{sidecar_b}");
    drop(measure);

    // A budget one byte short of B's sidecar: B's originals fit, its sidecar evicts the idle
    // prepared representation and is published; every original stays.
    let engine = engine_with_quota(with_b - 1);
    let imported_a = engine
        .models
        .import(&a.import(), &CancellationToken::new())
        .unwrap();
    let prepared = publish_prepared(&engine, &prepared_bytes, imported_a.originals[0].object);
    let imported_b = engine
        .models
        .import(&b.import(), &CancellationToken::new())
        .unwrap();
    assert_eq!(imported_b.evictions.len(), 1, "{:?}", imported_b.evictions);
    assert_eq!(imported_b.evictions[0].evicted, vec![prepared]);
    let catalog = engine.service.catalog();
    assert_eq!(catalog.status(&owner(), prepared), ObjectStatus::Absent);
    assert_eq!(
        catalog.status(&owner(), imported_b.sidecar),
        ObjectStatus::Published
    );
    for original in imported_a.originals.iter().chain(&imported_b.originals) {
        assert_eq!(
            catalog.status(&owner(), original.object),
            ObjectStatus::Published,
            "{}",
            original.path
        );
    }
    drop(catalog);

    // With nothing evictable, the sidecar's shortfall refuses the import, as before.
    let bare = engine_with_quota(with_b - 65_536 - 1);
    bare.models
        .import(&a.import(), &CancellationToken::new())
        .unwrap();
    let refused = bare
        .models
        .import(&b.import(), &CancellationToken::new())
        .unwrap_err();
    assert!(
        matches!(refused, ModelFileRefusal::Sidecar(_)),
        "{refused:?}"
    );
}

#[test]
fn two_concurrent_requests_of_one_folder_publish_it_once_and_both_hold_leases() {
    let engine = engine_with_quota(1 << 30);
    let folder = ModelFolder::new(23);
    let request = || {
        let mut request = folder.import();
        request.request.catalog.execution = ExecutionId::generate();
        request
    };
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| engine.models.import(&request(), &CancellationToken::new()));
        let second = scope.spawn(|| engine.models.import(&request(), &CancellationToken::new()));
        (first.join().unwrap(), second.join().unwrap())
    });
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_eq!(first.sidecar, second.sidecar);
    assert_eq!(
        first
            .originals
            .iter()
            .map(|original| original.object)
            .collect::<Vec<_>>(),
        second
            .originals
            .iter()
            .map(|original| original.object)
            .collect::<Vec<_>>()
    );
    // Each file was copied by exactly one request, and the sidecar indexed once: the
    // other request took the published result.
    for (one, other) in first.originals.iter().zip(&second.originals) {
        assert_ne!(one.copied, other.copied, "{}", one.path);
    }
    assert_ne!(first.reused, second.reused);
    assert_eq!(engine.service.catalog().objects(&owner()).len(), 4);
    // Both executions hold their leases: the sidecar and three originals each.
    assert_eq!(engine.service.status().catalog.live_leases, 8);
}

#[test]
fn a_declaration_made_before_the_import_stands_in_for_its_verifying_read_when_it_matches_the_listing(
) {
    let engine = engine_with_quota(1 << 30);
    let declare = |folder: &ModelFolder| -> BTreeMap<RelativePath, ImportManifest> {
        folder
            .files
            .iter()
            .map(|(name, bytes, _)| {
                (
                    RelativePath::new(*name).unwrap(),
                    ImportManifest::describe(bytes, ORIGINAL_EXTENT_BYTES),
                )
            })
            .collect()
    };
    // Matching declarations: the import proceeds on them.
    let folder = ModelFolder::new(24);
    let mut request = folder.import();
    request.declared = declare(&folder);
    let imported = engine
        .models
        .import(&request, &CancellationToken::new())
        .unwrap();
    assert!(imported.originals.iter().all(|original| original.copied));

    // A declaration with the listing's key and length but another extent digest is taken
    // as the caller's word, and the copy's own verification fails on it: proof that the
    // import read nothing again before the copy. Nothing of the file is published.
    let other = ModelFolder::new(25);
    let weights = RelativePath::new("model.safetensors").unwrap();
    let config = RelativePath::new("config.json").unwrap();
    let mut declared = declare(&other);
    let foreign = declared[&config].extents[0].digest.clone();
    declared.get_mut(&weights).unwrap().extents[0].digest = foreign;
    let mut request = other.import();
    request.declared = declared;
    let refused = engine
        .models
        .import(&request, &CancellationToken::new())
        .unwrap_err();
    assert!(
        matches!(&refused, ModelFileRefusal::Interrupted { path, failure: Some(_) } if *path == weights),
        "{refused:?}"
    );
    let content = other
        .listing()
        .files
        .iter()
        .find(|file| file.path == weights)
        .unwrap()
        .content;
    assert!(engine
        .service
        .catalog()
        .find(&owner(), ArtifactClass::ModelWeights, content)
        .is_none());

    // A declaration for other content is ignored: the file is read and imported as before.
    let mut declared = declare(&other);
    declared.insert(
        weights.clone(),
        ImportManifest::describe(b"not these bytes", ORIGINAL_EXTENT_BYTES),
    );
    let mut request = other.import();
    request.declared = declared;
    let imported = engine
        .models
        .import(&request, &CancellationToken::new())
        .unwrap();
    assert!(
        imported
            .originals
            .iter()
            .find(|original| original.path == weights)
            .unwrap()
            .copied
    );
}

#[test]
fn a_file_with_a_publisher_claim_is_admitted_under_that_key_and_a_wrong_signature_publishes_it_not()
{
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let dir = tempfile::tempdir().unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let public = Ed25519PublicKey::from_bytes(pair.public_key().as_ref()).unwrap();
    let roots = dir.path().join("trust-roots.json");
    fs::write(
        &roots,
        json!({
            "format": 1,
            "keys": [{
                "id": "weights-publisher",
                "algorithm": "ed25519",
                "public_key": public.to_hex(),
                "classes": ["model_weights"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2028-01-01T00:00:00Z",
            }],
        })
        .to_string(),
    )
    .unwrap();
    let mut trust = TrustRootService::open(
        TrustRootLocation::from_setting("YOUGORI_TEST_GLUE_CLAIM_ROOTS", Some(roots.as_os_str())),
        Arc::new(FixedCalendar),
    );
    let limits = ImportLimits::DEFAULT;
    let read_back = ReadBackChannel::new();
    let (service, models) = CatalogService::open(
        &dir.path().join("catalog"),
        engine_config(&QuotaSetting::Bytes(1 << 30)),
        engine_classes(&read_back, &limits),
        &mut trust,
        clock(),
        Arc::new(FixedCalendar),
        |catalog| ModelFiles::new(catalog, read_back, ListingIdentities, TiledExtents, limits),
    )
    .unwrap();
    let folder = ModelFolder::new(26);
    let weights = RelativePath::new("model.safetensors").unwrap();
    let bytes = &folder
        .files
        .iter()
        .find(|(name, _, _)| *name == "model.safetensors")
        .unwrap()
        .1;
    let publisher = public.publisher_id();
    let statement = content_statement(
        &publisher,
        ArtifactClass::ModelWeights,
        &ContentKey::of(bytes),
        bytes.len() as u64,
    );
    let claim = |attestation: Vec<u8>| PublisherClaim {
        publisher,
        attestation,
    };

    // Another key's signature over the same statement: refused at admission, nothing of
    // the file published, no lease left.
    let other = Ed25519KeyPair::from_seed_unchecked(&[10; 32]).unwrap();
    let mut request = folder.import();
    request.claims.insert(
        weights.clone(),
        claim(other.sign(statement.as_bytes()).as_ref().to_vec()),
    );
    let refused = models
        .import(&request, &CancellationToken::new())
        .unwrap_err();
    assert!(
        matches!(
            &refused,
            ModelFileRefusal::Admission { path, refusal }
                if *path == weights && matches!(refusal.as_ref(), ImportRefusal::Trust { .. })
        ),
        "{refused:?}"
    );
    assert!(service
        .catalog()
        .find(&owner(), ArtifactClass::ModelWeights, ContentKey::of(bytes))
        .is_none());
    assert_eq!(service.status().catalog.live_leases, 0);

    // The publisher's own signature: admitted under its key.
    let mut request = folder.import();
    request.claims.insert(
        weights.clone(),
        claim(pair.sign(statement.as_bytes()).as_ref().to_vec()),
    );
    let imported = models.import(&request, &CancellationToken::new()).unwrap();
    assert!(
        imported
            .originals
            .iter()
            .find(|original| original.path == weights)
            .unwrap()
            .copied
    );
    assert_eq!(service.status().catalog.live_leases, 4);
}
