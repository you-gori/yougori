//! The importer protocol over fake ports, with model folders in temporary directories and
//! an in-memory source that counts its reads.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::{mpsc, Arc};

use super::super::*;
use super::fakes::{
    CancellingExtents, CountingSource, FakeCatalog, FakeIdentities, FixedExtents, Gate, Misreport,
    OverlappingExtents,
};
use super::{
    description, f32_bytes, name, path, pattern, safetensors_bytes, small_model, tensor_parallel,
    token, GgufFile, ModelFixture, GGUF_WEIGHTS, SAFETENSORS_WEIGHTS,
};
use crate::foundation::ids::digest;

/// Integrity-extent size of these imports, small so every file has several extents.
const G: u64 = 16;

const PROTOCOL: [&str; 6] = [
    "published",
    "begin_staging",
    "write_staged",
    "read_staged",
    "commit",
    "publish",
];

fn new_importer() -> Importer<FakeCatalog, FakeIdentities, FixedExtents> {
    importer_with(ImportLimits::DEFAULT)
}

fn importer_with(limits: ImportLimits) -> Importer<FakeCatalog, FakeIdentities, FixedExtents> {
    Importer::new(FakeCatalog::default(), FakeIdentities, FixedExtents, limits)
}

fn run<E: ExtentPlanner>(
    importer: &Importer<FakeCatalog, FakeIdentities, E>,
    request: &ImportRequest,
    source: &dyn SourceFiles,
) -> Result<ImportOutcome, ImportError> {
    importer.import(request, source, &CancellationToken::new())
}

/// Keys a request again after its listing or description changed.
fn rekey(request: &mut ImportRequest) {
    let source = FakeIdentities::source_for(&request.listing);
    request.key = ImportKey {
        source,
        execution: FakeIdentities::execution_for(
            &source,
            &request.description.execution_abi,
            &request.description.distribution,
        ),
    };
}

/// Every file under `root` with its bytes.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                files.insert(relative, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

/// The manifest staged by an import that published.
fn staged_manifest(
    importer: &Importer<FakeCatalog, FakeIdentities, impl ExtentPlanner>,
) -> ValidatedManifest {
    let state = importer.catalog().state();
    let staged = state.staged.values().last().unwrap();
    ValidatedManifest::from_sidecar_bytes(&staged.bytes).unwrap()
}

/// Nothing is visible, and the one temporary area, if opened, was discarded.
fn assert_nothing_published(catalog: &FakeCatalog, staged: bool) {
    let state = catalog.state();
    assert!(state.published.is_empty());
    assert!(!state.calls.contains(&"publish"));
    assert!(state.staged.is_empty());
    assert_eq!(state.discarded.len(), usize::from(staged));
}

#[test]
fn an_import_publishes_a_verified_sidecar_over_the_original_files() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = new_importer();
    let before = snapshot(model.root());

    let Ok(ImportOutcome::Published(published)) = run(&importer, &request, &model.source()) else {
        panic!("the import did not publish");
    };
    assert_eq!(published.key, request.key);
    {
        let state = importer.catalog().state();
        assert_eq!(state.calls, PROTOCOL);
        assert!(state.discarded.is_empty());
        let staged = state.staged.values().next().unwrap();
        assert_eq!(
            staged.reserved_bytes,
            ImportLimits::DEFAULT.max_sidecar_bytes
        );
        assert!(staged.committed);
        assert_eq!(staged.record, Some(published));
    }
    let manifest = staged_manifest(&importer);
    assert_eq!(manifest.digest(), published.manifest);
    assert_eq!(
        published.artifact,
        FakeIdentities::artifact_for(&manifest.digest())
    );
    assert!(!importer.in_flight(&request.key));

    let m = manifest.manifest();
    let paths: Vec<&str> = m
        .provenance
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["config.json", "model.safetensors", "tokenizer.json"]
    );
    assert_eq!(m.provenance.revision, model.listing.revision);
    assert_eq!(m.provenance.converter, sidecar_converter().unwrap());
    assert!(matches!(
        m.provenance.files[1].format,
        FileFormat::Safetensors { .. }
    ));
    assert_eq!(m.provenance.files[0].format, FileFormat::Opaque);
    for file in &m.provenance.files {
        assert_eq!(
            file.content,
            ContentKey::of(&model.files[file.path.as_str()])
        );
    }

    let weights = &model.files["model.safetensors"];
    let embed = manifest.tensor("model.embed_tokens.weight").unwrap();
    let expected: Vec<f32> = (0..16).map(|value| value as f32).collect();
    assert_eq!(
        &weights[embed.offset_bytes as usize..][..embed.true_length_bytes as usize],
        &f32_bytes(&expected)[..]
    );
    let norm = manifest.tensor("model.norm.weight").unwrap();
    assert_eq!(norm.dtype, TensorDtype::Element(ElementType::Bf16));
    assert_eq!(
        &weights[norm.offset_bytes as usize..][..8],
        &pattern(8, 7)[..]
    );

    for (index, extent) in m.extents.extents.iter().enumerate() {
        let file = &model.files[m.provenance.files[extent.file.index()].path.as_str()];
        let bytes =
            &file[extent.logical_offset_bytes as usize..][..extent.true_length_bytes as usize];
        assert_eq!(
            manifest.verify_extent(index, bytes, None, &[]).unwrap(),
            bytes
        );
        assert!(extent.true_length_bytes <= G);
        let proof = manifest.extent_proof(index).unwrap();
        assert!(proof.verify(&manifest.extent_root(extent.file).unwrap(), extent));
    }

    // A sidecar: the originals are referenced, never copied, converted or changed.
    assert!(m.extents.prepared_files.is_empty());
    assert!(m
        .extents
        .extents
        .iter()
        .all(|extent| extent.encoding == ExtentEncoding::Raw));
    assert_eq!(
        m.lifecycle.storage,
        StorageAccounting {
            referenced_source_bytes: model.files.values().map(|bytes| bytes.len() as u64).sum(),
            owned_representation_bytes: 0,
        }
    );
    assert_eq!(
        m.lifecycle.migration,
        MigrationRequirement::ReindexFromSources
    );
    assert_eq!(snapshot(model.root()), before);
}

#[test]
fn each_source_file_is_read_once_and_the_staged_sidecar_read_back_once() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = new_importer();
    let source = CountingSource::new(&model.files);
    assert!(matches!(
        run(&importer, &request, &source),
        Ok(ImportOutcome::Published(_))
    ));
    for (file, bytes) in &model.files {
        assert_eq!(source.opens(file), 1, "{file} was opened once");
        assert_eq!(
            source.bytes_read(file),
            bytes.len() as u64,
            "{file} was read in one full pass"
        );
    }
    let state = importer.catalog().state();
    let read_backs = state
        .calls
        .iter()
        .filter(|call| **call == "read_staged")
        .count();
    assert_eq!(read_backs, 1);
    assert_eq!(state.calls, PROTOCOL);
}

#[test]
fn a_source_that_delivers_other_bytes_than_it_reports_is_refused() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    for misreport in [Misreport::Longer, Misreport::Shorter] {
        let importer = new_importer();
        let source = CountingSource::new(&model.files).misreport("tokenizer.json", misreport);
        assert_eq!(
            run(&importer, &request, &source),
            Err(ImportError::Source(SourceError::Changed {
                path: path("tokenizer.json")
            })),
            "{misreport:?}"
        );
        assert_nothing_published(importer.catalog(), false);
    }
}

#[test]
fn a_cancelled_import_publishes_nothing() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));

    let importer = new_importer();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        importer.import(&request, &model.source(), &cancel),
        Err(ImportError::Cancelled {
            step: ImportStep::VerifySource
        })
    );
    assert_nothing_published(importer.catalog(), false);
    assert!(!importer.in_flight(&request.key));

    for (call, step) in [
        ("published", ImportStep::VerifySource),
        ("begin_staging", ImportStep::Index),
        ("write_staged", ImportStep::ReadBack),
        ("read_staged", ImportStep::Commit),
        ("commit", ImportStep::Publish),
    ] {
        let importer = new_importer();
        let cancel = CancellationToken::new();
        importer.catalog().cancel_on(call, &cancel);
        assert_eq!(
            importer.import(&request, &model.source(), &cancel),
            Err(ImportError::Cancelled { step }),
            "cancelled at {call}"
        );
        assert_nothing_published(importer.catalog(), call != "published");
        assert!(!importer.in_flight(&request.key));
    }

    // Cancelled while files are read: the planner cancels when the second file starts.
    let cancel = CancellationToken::new();
    let importer = Importer::new(
        FakeCatalog::default(),
        FakeIdentities,
        CancellingExtents {
            token: cancel.clone(),
            cancel_on_call: 2,
            calls: AtomicUsize::new(0),
        },
        ImportLimits::DEFAULT,
    );
    assert_eq!(
        importer.import(&request, &model.source(), &cancel),
        Err(ImportError::Cancelled {
            step: ImportStep::VerifySource
        })
    );
    assert_nothing_published(importer.catalog(), false);
    // The cancelled import released its flight, so a new attempt runs to the end.
    assert!(matches!(
        run(&importer, &request, &model.source()),
        Ok(ImportOutcome::Published(_))
    ));
}

#[test]
fn imports_are_single_flight_per_source_and_execution_identity() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = Arc::new(new_importer());
    let (entered, entered_signal) = mpsc::channel();
    let (release_signal, release) = mpsc::channel();
    importer
        .catalog()
        .hold_next_staging(Gate { entered, release });
    let first = {
        let importer = Arc::clone(&importer);
        let request = request.clone();
        let source = model.source();
        std::thread::spawn(move || run(&importer, &request, &source))
    };
    entered_signal.recv().unwrap();
    assert!(importer.in_flight(&request.key));
    assert_eq!(
        run(&importer, &request, &model.source()),
        Err(ImportError::InFlight { key: request.key })
    );

    // Another execution identity of the same source is another flight.
    let mut processed = description(Distribution::SINGLE, G);
    processed.execution_abi.layout = token("processed-v2");
    let processed = model.request(processed);
    assert_eq!(processed.key.source, request.key.source);
    assert_ne!(processed.key.execution, request.key.execution);
    assert!(matches!(
        run(&importer, &processed, &model.source()),
        Ok(ImportOutcome::Published(_))
    ));

    release_signal.send(()).unwrap();
    assert!(matches!(
        first.join().unwrap(),
        Ok(ImportOutcome::Published(published)) if published.key == request.key
    ));
    assert!(!importer.in_flight(&request.key));
    assert_eq!(importer.catalog().state().published.len(), 2);
}

#[test]
fn a_repeated_import_reuses_the_published_artifact() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = new_importer();
    let Ok(ImportOutcome::Published(first)) = run(&importer, &request, &model.source()) else {
        panic!("the first import did not publish");
    };
    let source = CountingSource::new(&model.files);
    assert_eq!(
        run(&importer, &request, &source),
        Ok(ImportOutcome::AlreadyPublished(first))
    );
    assert_eq!(source.opens("model.safetensors"), 0, "nothing was read");
    let state = importer.catalog().state();
    assert_eq!(state.next_staging, 1, "nothing was staged twice");
    assert_eq!(state.calls[PROTOCOL.len()..], ["published"]);
}

#[test]
fn missing_or_changed_source_files_are_refused_before_staging() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let tokenizer = model.root().join("tokenizer.json");
    let original = model.files["tokenizer.json"].clone();
    let refused = |expected: SourceError| {
        let importer = new_importer();
        assert_eq!(
            run(&importer, &request, &model.source()),
            Err(ImportError::Source(expected))
        );
        assert_eq!(importer.catalog().state().calls, ["published"]);
    };

    std::fs::remove_file(&tokenizer).unwrap();
    refused(SourceError::MissingFile {
        path: path("tokenizer.json"),
    });
    let mut changed = original.clone();
    changed[3] ^= 1;
    std::fs::write(&tokenizer, &changed).unwrap();
    refused(SourceError::DigestMismatch {
        path: path("tokenizer.json"),
    });
    std::fs::write(&tokenizer, [&original[..], b" "].concat()).unwrap();
    refused(SourceError::LengthMismatch {
        path: path("tokenizer.json"),
        listed_bytes: original.len() as u64,
        found_bytes: original.len() as u64 + 1,
    });
    std::fs::remove_file(&tokenizer).unwrap();
    std::fs::create_dir(&tokenizer).unwrap();
    refused(SourceError::NotARegularFile {
        path: path("tokenizer.json"),
    });
}

#[test]
fn a_source_changed_after_its_pass_is_caught_when_its_extents_are_used() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = new_importer();
    let weights = model.root().join("model.safetensors");
    let mut changed = model.files["model.safetensors"].clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let written = changed.clone();
    importer.catalog().on("write_staged", move || {
        std::fs::write(&weights, &written).unwrap()
    });
    // The sources were verified and indexed in their one pass; nothing rereads them.
    assert!(matches!(
        run(&importer, &request, &model.source()),
        Ok(ImportOutcome::Published(_))
    ));
    // The published manifest describes the verified bytes, so the changed bytes fail
    // verification where they are read.
    let manifest = staged_manifest(&importer);
    let m = manifest.manifest();
    let (index, extent) = m
        .extents
        .extents
        .iter()
        .enumerate()
        .rfind(|(_, extent)| extent.file == SourceFileId(1))
        .unwrap();
    let start = extent.logical_offset_bytes as usize;
    let bytes = &changed[start..start + extent.true_length_bytes as usize];
    assert_eq!(
        manifest.verify_extent(index, bytes, None, &[]),
        Err(ExtentError::ContentKeyMismatch)
    );
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[test]
fn a_symlinked_source_file_is_refused() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.json");
    std::fs::write(&secret, b"{}").unwrap();
    let model = small_model();
    let link = model.root().join("extra.json");
    if symlink(&secret, &link).is_err() {
        // Creating symlinks needs a privilege this machine may not grant; the refusal
        // of non-regular files is covered by the directory case.
        return;
    }
    let mut request = model.request(description(Distribution::SINGLE, G));
    request
        .listing
        .files
        .push(super::listed_file("extra.json", b"{}", FileRole::Other));
    request.listing.revision = SourceListing::content_revision(&request.listing.files);
    rekey(&mut request);
    assert_eq!(
        run(&new_importer(), &request, &model.source()),
        Err(ImportError::Source(SourceError::NotARegularFile {
            path: path("extra.json")
        }))
    );
}

#[test]
fn identity_mismatches_are_refused() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let other = digest("yougori/test/other/v1", &[b"x"]);

    let mut wrong_source = request.clone();
    wrong_source.key.source = SourceIdentity(other);
    let importer = new_importer();
    assert_eq!(
        run(&importer, &wrong_source, &model.source()),
        Err(ImportError::SourceIdentityMismatch {
            expected: SourceIdentity(other),
            found: request.key.source,
        })
    );
    assert_nothing_published(importer.catalog(), false);

    let mut wrong_execution = request.clone();
    wrong_execution.key.execution = ExecutionIdentity(other);
    let importer = new_importer();
    assert_eq!(
        run(&importer, &wrong_execution, &model.source()),
        Err(ImportError::ExecutionIdentityMismatch {
            expected: ExecutionIdentity(other),
            found: request.key.execution,
        })
    );
    assert_nothing_published(importer.catalog(), true);
}

#[test]
fn a_read_back_that_differs_from_what_was_staged_is_refused() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = new_importer();
    importer.catalog().state().corrupt_read_back = true;
    assert_eq!(
        run(&importer, &request, &model.source()),
        Err(ImportError::ReadBackMismatch)
    );
    assert_nothing_published(importer.catalog(), true);
}

#[test]
fn source_verification_is_bounded() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let total: u64 = model.files.values().map(|bytes| bytes.len() as u64).sum();
    let limited = |limits: ImportLimits, expected: SourceError| {
        let importer = importer_with(limits);
        assert_eq!(
            run(&importer, &request, &model.source()),
            Err(ImportError::Source(expected))
        );
        assert_nothing_published(importer.catalog(), false);
    };
    limited(
        ImportLimits {
            max_source_files: 2,
            ..ImportLimits::DEFAULT
        },
        SourceError::TooManyFiles { count: 3, max: 2 },
    );
    limited(
        ImportLimits {
            max_source_bytes: total - 1,
            ..ImportLimits::DEFAULT
        },
        SourceError::TooManyBytes {
            max_bytes: total - 1,
        },
    );

    let mut twins = request.clone();
    twins
        .listing
        .files
        .push(super::listed_file("CONFIG.json", b"{}", FileRole::Other));
    rekey(&mut twins);
    assert_eq!(
        run(&new_importer(), &twins, &model.source()),
        Err(ImportError::Source(SourceError::DuplicateFile {
            path: path("CONFIG.json")
        }))
    );

    let mut wrong_revision = request.clone();
    wrong_revision.listing.revision =
        SourceRevision::ContentListing(digest("yougori/test/other/v1", &[b"x"]));
    rekey(&mut wrong_revision);
    assert_eq!(
        run(&new_importer(), &wrong_revision, &model.source()),
        Err(ImportError::Source(SourceError::RevisionMismatch))
    );

    let commit = GitCommit::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap();
    let mut committed = request.clone();
    committed.listing.origin = SourceOrigin::HuggingFace {
        repository: token("example/tiny-llama"),
    };
    committed.listing.revision = SourceRevision::GitCommit(commit);
    rekey(&mut committed);
    assert!(matches!(
        run(&new_importer(), &committed, &model.source()),
        Ok(ImportOutcome::Published(_))
    ));
}

#[test]
fn an_invalid_extent_plan_is_refused_before_staging() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));
    let importer = Importer::new(
        FakeCatalog::default(),
        FakeIdentities,
        OverlappingExtents,
        ImportLimits::DEFAULT,
    );
    let config_bytes = model.files["config.json"].len() as u64;
    assert_eq!(
        run(&importer, &request, &model.source()),
        Err(ImportError::Extents(ExtentPlanError::InvalidPlan {
            offset_bytes: config_bytes
        }))
    );
    assert_nothing_published(importer.catalog(), false);
}

fn rank_files() -> Vec<(String, Vec<u8>)> {
    (0..2u8)
        .map(|rank| {
            let shard = pattern(32, rank * 50);
            (
                format!("model-rank-{rank}-part-0.safetensors"),
                safetensors_bytes(&[(
                    &format!("layers.{rank}.q_proj.weight"),
                    ElementType::Bf16,
                    &[4, 4],
                    &shard,
                )]),
            )
        })
        .collect()
}

#[test]
fn processed_rank_files_import_with_rank_coverage() {
    let config = br#"{"architectures":["LlamaForCausalLM"]}"#.to_vec();
    let rank_role = |rank| FileRole::Weights {
        format: WeightFormat::Safetensors,
        rank: Some(rank),
    };
    let shards = rank_files();
    let model = ModelFixture::new(&[
        ("config.json", config.clone(), FileRole::Configuration),
        (&shards[0].0, shards[0].1.clone(), rank_role(0)),
        (&shards[1].0, shards[1].1.clone(), rank_role(1)),
    ]);
    let layout = tensor_parallel(2);
    let request = model.request(description(layout, G));
    let importer = new_importer();
    assert!(matches!(
        run(&importer, &request, &model.source()),
        Ok(ImportOutcome::Published(_))
    ));
    let manifest = staged_manifest(&importer);
    for rank in 0..2u32 {
        let plan = manifest.rank_plan(&layout, rank).unwrap();
        assert_eq!(
            plan.tensors,
            vec![name(&format!("layers.{rank}.q_proj.weight"))]
        );
        assert_eq!(plan.tensor_bytes, 32);
    }
    assert!(matches!(
        manifest.rank_plan(&Distribution::SINGLE, 0),
        Err(RankRefusal::LayoutMismatch { .. })
    ));

    // Without rank 1's file the artifact does not cover its layout.
    let partial = ModelFixture::new(&[
        ("config.json", config, FileRole::Configuration),
        (&shards[0].0, shards[0].1.clone(), rank_role(0)),
    ]);
    let importer = new_importer();
    assert_eq!(
        run(
            &importer,
            &partial.request(description(layout, G)),
            &partial.source()
        ),
        Err(ImportError::Manifest(ManifestError::MissingRank {
            rank: 1
        }))
    );
    assert_nothing_published(importer.catalog(), true);
}

#[test]
fn a_gguf_model_is_configured_by_its_metadata() {
    let gguf = |architecture: &str| {
        GgufFile::new()
            .kv_string("general.architecture", architecture)
            .kv_strings("tokenizer.ggml.tokens", &["<s>", "a"])
            .tensor("token_embd.weight", &[32, 2], 8, pattern(68, 3))
            .bytes()
    };
    let import = |architecture: &str| {
        let model = ModelFixture::new(&[("model.gguf", gguf(architecture), GGUF_WEIGHTS)]);
        let importer = new_importer();
        assert!(matches!(
            run(
                &importer,
                &model.request(description(Distribution::SINGLE, G)),
                &model.source()
            ),
            Ok(ImportOutcome::Published(_))
        ));
        staged_manifest(&importer)
    };
    let llama = import("llama");
    let tensor = llama.tensor("token_embd.weight").unwrap();
    assert_eq!(tensor.dtype, TensorDtype::Ggml(GgmlType::Q8_0));
    assert_eq!(tensor.true_length_bytes, 68);
    assert!(matches!(
        llama.manifest().provenance.files[0].format,
        FileFormat::Gguf {
            version: 3,
            alignment_bytes: 32,
            ..
        }
    ));
    let qwen = import("qwen2");
    assert_ne!(
        llama.manifest().semantics.configuration_digest,
        qwen.manifest().semantics.configuration_digest
    );
    assert_ne!(
        llama.manifest().semantics.tokenizer_digest,
        qwen.manifest().semantics.tokenizer_digest
    );
}

#[test]
fn a_model_without_configuration_is_refused_before_staging() {
    let weights = safetensors_bytes(&[("w", ElementType::U8, &[4], &[1, 2, 3, 4])]);
    let model = ModelFixture::new(&[("model.safetensors", weights, SAFETENSORS_WEIGHTS)]);
    let importer = new_importer();
    assert_eq!(
        run(
            &importer,
            &model.request(description(Distribution::SINGLE, G)),
            &model.source()
        ),
        Err(ImportError::Manifest(ManifestError::MissingConfiguration))
    );
    assert_nothing_published(importer.catalog(), false);
}

#[test]
fn the_request_supplies_ownership_aliases_and_state() {
    let model = small_model();
    let mut request = model.request(description(Distribution::SINGLE, G));
    request.aliases = vec![TensorAlias {
        name: name("lm_head.weight"),
        target: name("model.embed_tokens.weight"),
    }];
    request.state.persistent_buffers = vec![name("model.norm.weight")];
    request.state.rematerialized_buffers = vec![RematerializedBuffer {
        name: name("rotary_emb.inv_freq"),
        dtype: TensorDtype::Element(ElementType::F32),
        shape: vec![2],
        reconstruction: VersionedName {
            name: token("rotary-embedding"),
            version: token("1"),
        },
    }];
    let importer = new_importer();
    assert!(matches!(
        run(&importer, &request, &model.source()),
        Ok(ImportOutcome::Published(_))
    ));
    let manifest = staged_manifest(&importer);
    assert_eq!(
        manifest.tensor("lm_head.weight").unwrap().name,
        name("model.embed_tokens.weight")
    );
    assert_eq!(manifest.manifest().state, request.state);

    let mut unknown_owner = request.clone();
    unknown_owner.owners = vec![(name("missing"), TensorOwner::Rank(0))];
    let importer = new_importer();
    assert_eq!(
        run(&importer, &unknown_owner, &model.source()),
        Err(ImportError::Manifest(ManifestError::MissingTensor {
            name: name("missing")
        }))
    );
    assert_nothing_published(importer.catalog(), true);
}

#[test]
fn malformed_weights_and_duplicate_tensors_are_refused() {
    let config = br#"{"architectures":["LlamaForCausalLM"]}"#.to_vec();
    let broken = ModelFixture::new(&[
        ("config.json", config.clone(), FileRole::Configuration),
        (
            "model.safetensors",
            b"not a safetensors file".to_vec(),
            SAFETENSORS_WEIGHTS,
        ),
    ]);
    let importer = new_importer();
    assert!(matches!(
        run(
            &importer,
            &broken.request(description(Distribution::SINGLE, G)),
            &broken.source()
        ),
        Err(ImportError::Index {
            error: IndexError::HeaderTooLarge { .. },
            ..
        })
    ));
    assert_nothing_published(importer.catalog(), false);

    let shard =
        |seed| safetensors_bytes(&[("shared.weight", ElementType::U8, &[4], &pattern(4, seed))]);
    let twins = ModelFixture::new(&[
        ("config.json", config, FileRole::Configuration),
        ("a.safetensors", shard(1), SAFETENSORS_WEIGHTS),
        ("b.safetensors", shard(2), SAFETENSORS_WEIGHTS),
    ]);
    let importer = new_importer();
    assert_eq!(
        run(
            &importer,
            &twins.request(description(Distribution::SINGLE, G)),
            &twins.source()
        ),
        Err(ImportError::Manifest(ManifestError::DuplicateName {
            name: "shared.weight".to_owned()
        }))
    );
    assert_nothing_published(importer.catalog(), true);
}

#[test]
fn catalog_failures_publish_nothing() {
    let model = small_model();
    let request = model.request(description(Distribution::SINGLE, G));

    let importer = new_importer();
    importer.catalog().state().refuse_reservation = true;
    assert_eq!(
        run(&importer, &request, &model.source()),
        Err(ImportError::Catalog {
            step: ImportStep::StageRepresentation,
            error: CatalogError::ReservationRefused {
                requested_bytes: ImportLimits::DEFAULT.max_sidecar_bytes
            }
        })
    );
    assert_nothing_published(importer.catalog(), false);

    let importer = importer_with(ImportLimits {
        max_sidecar_bytes: 64,
        ..ImportLimits::DEFAULT
    });
    assert!(matches!(
        run(&importer, &request, &model.source()),
        Err(ImportError::SidecarTooLarge { max_bytes: 64, .. })
    ));
    assert_nothing_published(importer.catalog(), true);

    let mut wrong_execution = request.clone();
    wrong_execution.key.execution = ExecutionIdentity(digest("yougori/test/other/v1", &[b"x"]));
    let importer = new_importer();
    importer.catalog().state().fail_discard = true;
    let error = run(&importer, &wrong_execution, &model.source()).unwrap_err();
    assert!(matches!(
        &error,
        ImportError::CleanupFailed { original, cleanup: CatalogError::Storage { .. } }
            if matches!(**original, ImportError::ExecutionIdentityMismatch { .. })
    ));
    let state = importer.catalog().state();
    assert!(state.published.is_empty());
    assert!(!state.calls.contains(&"publish"));
}
