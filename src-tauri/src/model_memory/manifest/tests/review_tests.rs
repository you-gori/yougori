//! The independent review's proofs (R1-c) as refusal tests: execution identities bind
//! the exact quantization and the kernel list, bounds above their ceilings are refused
//! before anything is read, and seeded fuzzing never makes an indexer or the sidecar
//! decoder panic.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::super::*;
use super::adapter_tests::{layer_context, layered_identities};
use super::fakes::{CountingSource, FakeCatalog, FakeIdentities, FixedExtents};
use super::{description, small_model, token};
use crate::foundation::evidence::{Backend, BackendRelease, BackendVersion};
use crate::foundation::ids::{digest, DigestBuilder};
use crate::model_memory::identity as layers;

/// Integrity-extent size of these imports.
const G: u64 = 16;

/// A sidecar over one configuration file, quantized with gptq `parameters` and built for
/// `kernels`: the review's two artifacts differ only in these.
fn quantized_manifest(parameters: &[(&str, &str)], kernels: &[&str]) -> ValidatedManifest {
    let config = b"{\"hidden\":1}";
    let path = RelativePath::new("config.json").unwrap();
    let description = ArtifactDescription {
        bounds: ManifestBounds::DEFAULT,
        compute_dtype: ElementType::Bf16,
        quantization: Quantization::Method {
            method: token("gptq"),
            parameters: parameters
                .iter()
                .map(|(key, value)| (token(key), token(value)))
                .collect(),
        },
        adapters: Vec::new(),
        execution_abi: ExecutionAbi {
            runner: BackendRelease {
                backend: Backend::Vllm,
                version: BackendVersion::new("0.31.0").unwrap(),
            },
            architecture_adapter: VersionedName {
                name: token("llama"),
                version: token("1"),
            },
            layout: token("original"),
            kernels: kernels.iter().map(|kernel| token(kernel)).collect(),
            hardware: HardwareRestriction::Unrestricted,
        },
        distribution: Distribution::SINGLE,
        integrity_extent_bytes: 1 << 20,
    };
    let mut builder = ManifestBuilder::new(
        SourceOrigin::LocalFolder,
        sidecar_converter().unwrap(),
        description,
    );
    builder
        .add_source_file(SourceFileInput {
            path: path.clone(),
            length_bytes: config.len() as u64,
            content: ContentKey::of(config),
            role: FileRole::Configuration,
            format: FileFormat::Opaque,
        })
        .unwrap();
    builder.add_extent(ExtentInput {
        file: path,
        logical_offset_bytes: 0,
        true_length_bytes: config.len() as u64,
        content_key: ContentKey::of(config),
        encoding: EncodingInput::Raw,
    });
    builder.finish().unwrap()
}

/// A gptq scheme with `bits` and `group` whose parameters digest is the one of
/// `quantization`.
fn gptq(quantization: &Quantization, bits: u8, group: Option<u32>) -> layers::Quantization {
    layers::Quantization::Scheme(
        layers::QuantizationScheme::new(
            layers::VersionedName::new("gptq", "1").unwrap(),
            bits,
            group,
            quantization_parameters_digest(quantization).unwrap(),
        )
        .unwrap(),
    )
}

/// Identity inputs that state `manifest`'s exact quantization.
fn context_for(manifest: &ValidatedManifest, bits: u8, group: Option<u32>) -> LayerContext {
    LayerContext {
        quantization: gptq(&manifest.manifest().semantics.quantization, bits, group),
        ..layer_context()
    }
}

fn source_of(manifest: &ValidatedManifest, context: &LayerContext) -> SourceIdentity {
    let source = IdentityLayers::manifest_source_spec(manifest.manifest(), context)
        .unwrap()
        .identity()
        .unwrap();
    SourceIdentity(*source.digest())
}

#[test]
fn quantization_parameters_and_kernels_never_share_an_execution_identity() {
    let a = quantized_manifest(&[("group_size", "128")], &["marlin_gemm"]);
    let b = quantized_manifest(
        &[("desc_act", "true"), ("group_size", "32")],
        &["exllama_v2_gemm"],
    );
    assert_ne!(a.digest(), b.digest(), "the artifacts differ");
    let context_a = context_for(&a, 4, Some(128));
    let source = source_of(&a, &context_a);
    assert_eq!(source, source_of(&b, &context_a), "over the same files");
    let execution_a = IdentityLayers
        .execution_identity(&source, &a, &context_a)
        .unwrap();

    // The review's collision: b under a's identity inputs is refused, never given a's
    // execution identity and so never a's import key.
    assert_eq!(
        IdentityLayers.execution_identity(&source, &b, &context_a),
        Err(IdentityError::Inconsistent {
            field: "quantization parameters"
        })
    );
    // Under its own inputs b has its own execution identity and import key.
    let execution_b = IdentityLayers
        .execution_identity(&source, &b, &context_for(&b, 4, Some(32)))
        .unwrap();
    assert_ne!(execution_a, execution_b);
    assert_ne!(
        ImportKey {
            source,
            execution: execution_a
        },
        ImportKey {
            source,
            execution: execution_b
        }
    );

    // The kernel list alone separates two executions: the kernel layout is derived from
    // the manifest, never taken from the caller.
    let c = quantized_manifest(&[("group_size", "128")], &["exllama_v2_gemm"]);
    let execution_c = IdentityLayers
        .execution_identity(&source, &c, &context_a)
        .unwrap();
    assert_ne!(execution_c, execution_a);
    let kernels =
        |manifest: &ValidatedManifest| kernel_layout(&manifest.manifest().execution_abi).unwrap();
    assert_ne!(kernels(&a), kernels(&c));
    assert_eq!(kernels(&a).name.as_str(), KERNEL_SET_NAME);
    assert_eq!(
        kernels(&quantized_manifest(&[], &["b", "a"])),
        kernels(&quantized_manifest(&[], &["a", "b"]))
    );
}

#[test]
fn a_scheme_that_disagrees_with_the_manifest_is_refused() {
    let manifest = quantized_manifest(&[("bits", "4"), ("group_size", "128")], &[]);
    let source = source_of(&manifest, &context_for(&manifest, 4, Some(128)));
    let identity =
        |context: &LayerContext| IdentityLayers.execution_identity(&source, &manifest, context);
    let inconsistent = |field| Err(IdentityError::Inconsistent { field });
    assert!(identity(&context_for(&manifest, 4, Some(128))).is_ok());
    assert_eq!(
        identity(&context_for(&manifest, 8, Some(128))),
        inconsistent("quantization bits")
    );
    assert_eq!(
        identity(&context_for(&manifest, 4, Some(64))),
        inconsistent("quantization group size")
    );
    assert_eq!(
        identity(&context_for(&manifest, 4, None)),
        inconsistent("quantization group size")
    );
    let exact =
        quantization_parameters_digest(&manifest.manifest().semantics.quantization).unwrap();
    let scheme = |method: &str, parameters| LayerContext {
        quantization: layers::Quantization::Scheme(
            layers::QuantizationScheme::new(
                layers::VersionedName::new(method, "1").unwrap(),
                4,
                Some(128),
                parameters,
            )
            .unwrap(),
        ),
        ..layer_context()
    };
    assert_eq!(
        identity(&scheme("awq", exact)),
        inconsistent("quantization method")
    );
    assert_eq!(
        identity(&scheme(
            "gptq",
            digest("yougori/test/other-parameters/v1", &[b"x"])
        )),
        inconsistent("quantization parameters")
    );
    assert_eq!(identity(&layer_context()), inconsistent("quantization"));

    // A parameter that is not a plain integer, such as gptq's per-channel group size of
    // -1, is bound by the parameters digest alone.
    let per_channel = quantized_manifest(&[("group_size", "-1")], &[]);
    assert!(IdentityLayers
        .execution_identity(&source, &per_channel, &context_for(&per_channel, 4, None))
        .is_ok());

    // The digest is the exact parameter set, in any order, and nothing when unquantized.
    let method = |parameters: &[(&str, &str)]| Quantization::Method {
        method: token("gptq"),
        parameters: parameters
            .iter()
            .map(|(key, value)| (token(key), token(value)))
            .collect(),
    };
    assert_eq!(
        quantization_parameters_digest(&method(&[("b", "4"), ("a", "1")])),
        quantization_parameters_digest(&method(&[("a", "1"), ("b", "4")]))
    );
    assert_ne!(
        quantization_parameters_digest(&method(&[("a", "1")])),
        quantization_parameters_digest(&method(&[("a", "2")]))
    );
    assert_eq!(quantization_parameters_digest(&Quantization::None), None);
}

#[test]
fn an_import_for_other_quantization_is_never_answered_with_the_first_artifact() {
    let model = small_model();
    let importer = Importer::new(
        FakeCatalog::default(),
        IdentityLayers,
        FixedExtents,
        ImportLimits::DEFAULT,
    );
    let request_for = |parameters: &[(&str, &str)], kernels: &[&str], group: Option<u32>| {
        let mut description = description(Distribution::SINGLE, G);
        description.quantization = Quantization::Method {
            method: token("gptq"),
            parameters: parameters
                .iter()
                .map(|(key, value)| (token(key), token(value)))
                .collect(),
        };
        description.execution_abi.kernels = kernels.iter().map(|kernel| token(kernel)).collect();
        let context = LayerContext {
            quantization: gptq(&description.quantization, 4, group),
            ..layer_context()
        };
        let (source, execution) = layered_identities(&model, &context, &description.execution_abi);
        let mut request = model.request_with(description, context, ());
        request.key = IdentityLayers::import_key(&source, &execution);
        request
    };
    let first = request_for(&[("group_size", "128")], &["marlin_gemm"], Some(128));
    let second = request_for(
        &[("desc_act", "true"), ("group_size", "32")],
        &["exllama_v2_gemm"],
        Some(32),
    );
    assert_ne!(first.key, second.key);
    let run = |request: &ImportRequest<LayerContext>| {
        importer.import(request, &model.source(), &CancellationToken::new())
    };
    let Ok(ImportOutcome::Published(a)) = run(&first) else {
        panic!("the first import did not publish");
    };
    let outcome = run(&second);
    let Ok(ImportOutcome::Published(b)) = outcome else {
        panic!("the second import was answered with {outcome:?}");
    };
    assert_ne!(a.manifest, b.manifest);
    assert_eq!(run(&first), Ok(ImportOutcome::AlreadyPublished(a)));

    // The second artifact under the first's quantization inputs is refused at its index.
    let mut mixed = second.clone();
    mixed.identity = first.identity.clone();
    let (source, execution) =
        layered_identities(&model, &mixed.identity, &mixed.description.execution_abi);
    mixed.key = IdentityLayers::import_key(&source, &execution);
    assert_eq!(
        run(&mixed),
        Err(ImportError::Identity(IdentityError::Inconsistent {
            field: "quantization parameters"
        }))
    );
    assert_eq!(importer.catalog().state().published.len(), 2);
}

#[test]
fn bounds_above_their_ceilings_are_refused_before_anything_is_read() {
    // The review's hostile prefix: a header length of u64::MAX under a u64::MAX bound.
    let mut file = u64::MAX.to_le_bytes().to_vec();
    file.extend_from_slice(b"{}      ");
    let length = file.len() as u64;
    let wide = IndexerBounds {
        max_header_bytes: u64::MAX,
        ..IndexerBounds::DEFAULT
    };
    let above = IndexError::BoundAboveCeiling {
        bound: "max_header_bytes",
        declared: u64::MAX,
        ceiling: IndexerBounds::CEILING.max_header_bytes,
    };
    assert_eq!(
        index_safetensors(&mut &file[..], length, &wide),
        Err(above.clone())
    );
    assert_eq!(index_gguf(&mut &file[..], length, &wide), Err(above));
    // Under the ceiling the same prefix is too large, with no overflow on the way.
    assert_eq!(
        index_safetensors(&mut &file[..], length, &IndexerBounds::CEILING),
        Err(IndexError::HeaderTooLarge {
            length_bytes: u64::MAX,
            max_bytes: IndexerBounds::CEILING.max_header_bytes
        })
    );
    for (bound, bounds) in [
        (
            "max_tensors",
            IndexerBounds {
                max_tensors: u64::MAX,
                ..IndexerBounds::DEFAULT
            },
        ),
        (
            "max_dimensions",
            IndexerBounds {
                max_dimensions: u64::MAX,
                ..IndexerBounds::DEFAULT
            },
        ),
        (
            "max_name_bytes",
            IndexerBounds {
                max_name_bytes: u64::MAX,
                ..IndexerBounds::DEFAULT
            },
        ),
        (
            "max_metadata_entries",
            IndexerBounds {
                max_metadata_entries: u64::MAX,
                ..IndexerBounds::DEFAULT
            },
        ),
        (
            "max_array_elements",
            IndexerBounds {
                max_array_elements: u64::MAX,
                ..IndexerBounds::DEFAULT
            },
        ),
        (
            "max_string_bytes",
            IndexerBounds {
                max_string_bytes: u64::MAX,
                ..IndexerBounds::DEFAULT
            },
        ),
    ] {
        assert!(
            matches!(
                index_gguf(&mut &file[..], length, &bounds),
                Err(IndexError::BoundAboveCeiling { bound: found, .. }) if found == bound
            ),
            "{bound}"
        );
    }
    assert_eq!(
        IndexerBounds::DEFAULT.check_within(&IndexerBounds::CEILING),
        Ok(())
    );

    // An importer whose limits exceed their ceilings opens nothing and stages nothing.
    let model = small_model();
    for (limit, limits) in [
        (
            "max_source_files",
            ImportLimits {
                max_source_files: u64::MAX,
                ..ImportLimits::DEFAULT
            },
        ),
        (
            "max_source_bytes",
            ImportLimits {
                max_source_bytes: u64::MAX,
                ..ImportLimits::DEFAULT
            },
        ),
        (
            "max_sidecar_bytes",
            ImportLimits {
                max_sidecar_bytes: u64::MAX,
                ..ImportLimits::DEFAULT
            },
        ),
        (
            "read_chunk_bytes",
            ImportLimits {
                read_chunk_bytes: usize::MAX,
                ..ImportLimits::DEFAULT
            },
        ),
        (
            "indexer.max_header_bytes",
            ImportLimits {
                indexer: wide,
                ..ImportLimits::DEFAULT
            },
        ),
    ] {
        let importer = Importer::new(FakeCatalog::default(), FakeIdentities, FixedExtents, limits);
        let source = CountingSource::new(&model.files);
        let outcome = importer.import(
            &model.request(description(Distribution::SINGLE, G)),
            &source,
            &CancellationToken::new(),
        );
        assert!(
            matches!(
                outcome,
                Err(ImportError::LimitAboveCeiling { limit: found, .. }) if found == limit
            ),
            "{limit}: {outcome:?}"
        );
        assert_eq!(source.opens("model.safetensors"), 0);
        assert!(importer.catalog().state().calls.is_empty());
    }
    assert_eq!(
        ImportLimits::DEFAULT.check_within(&ImportLimits::CEILING),
        Ok(())
    );
}

/// The review's seeded generator; tests draw randomness only from it.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }
}

/// Up to four edits: a byte, a little-endian u64 or u32 at a hostile value, a cut or a
/// tail of noise.
fn mutate(base: &[u8], rng: &mut XorShift) -> Vec<u8> {
    let mut out = base.to_vec();
    let edits = 1 + rng.below(4);
    for _ in 0..edits {
        match rng.below(6) {
            0 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = rng.next() as u8;
            }
            1 if out.len() >= 8 => {
                let i = rng.below(out.len() - 7);
                let v: u64 = match rng.below(6) {
                    0 => u64::MAX,
                    1 => 1 << 63,
                    2 => u64::MAX - 7,
                    3 => rng.next() % 1_000_000,
                    4 => 0,
                    _ => rng.next(),
                };
                out[i..i + 8].copy_from_slice(&v.to_le_bytes());
            }
            2 => {
                let cut = rng.below(out.len() + 1);
                out.truncate(cut);
            }
            3 => {
                let extra = rng.below(64);
                for _ in 0..extra {
                    out.push(rng.next() as u8);
                }
            }
            4 if out.len() >= 4 => {
                let i = rng.below(out.len() - 3);
                let v: u32 = match rng.below(4) {
                    0 => u32::MAX,
                    1 => 1 << 31,
                    2 => (rng.next() % 64) as u32,
                    _ => rng.next() as u32,
                };
                out[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            _ => {}
        }
    }
    out
}

fn safetensors_base() -> Vec<u8> {
    let mut header = br#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"__metadata__":{"k":"v"},"b":{"dtype":"BF16","shape":[2,2],"data_offsets":[8,16]}}"#.to_vec();
    while !header.len().is_multiple_of(8) {
        header.push(b' ');
    }
    let mut file = (header.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&header);
    file.extend_from_slice(&[0u8; 16]);
    file
}

fn gguf_base() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(b"GGUF");
    f.extend_from_slice(&3u32.to_le_bytes());
    f.extend_from_slice(&2u64.to_le_bytes());
    f.extend_from_slice(&3u64.to_le_bytes());
    let key = |f: &mut Vec<u8>, k: &str| {
        f.extend_from_slice(&(k.len() as u64).to_le_bytes());
        f.extend_from_slice(k.as_bytes());
    };
    key(&mut f, "general.alignment");
    f.extend_from_slice(&4u32.to_le_bytes());
    f.extend_from_slice(&32u32.to_le_bytes());
    key(&mut f, "general.name");
    f.extend_from_slice(&8u32.to_le_bytes());
    f.extend_from_slice(&4u64.to_le_bytes());
    f.extend_from_slice(b"test");
    key(&mut f, "tokenizer.ggml.tokens");
    f.extend_from_slice(&9u32.to_le_bytes());
    f.extend_from_slice(&8u32.to_le_bytes());
    f.extend_from_slice(&2u64.to_le_bytes());
    for t in ["a", "bb"] {
        f.extend_from_slice(&(t.len() as u64).to_le_bytes());
        f.extend_from_slice(t.as_bytes());
    }
    // F32 [8].
    f.extend_from_slice(&1u64.to_le_bytes());
    f.extend_from_slice(b"t");
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&8u64.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&0u64.to_le_bytes());
    // Q4_0 [32, 2].
    f.extend_from_slice(&1u64.to_le_bytes());
    f.extend_from_slice(b"q");
    f.extend_from_slice(&2u32.to_le_bytes());
    f.extend_from_slice(&32u64.to_le_bytes());
    f.extend_from_slice(&2u64.to_le_bytes());
    f.extend_from_slice(&2u32.to_le_bytes());
    f.extend_from_slice(&32u64.to_le_bytes());
    while !f.len().is_multiple_of(32) {
        f.push(0);
    }
    f.extend_from_slice(&[0u8; 32]);
    f.extend_from_slice(&[0u8; 36]);
    f
}

#[test]
fn the_fuzzing_bases_index() {
    let st = safetensors_base();
    let indexed = index_safetensors(&mut &st[..], st.len() as u64, &IndexerBounds::DEFAULT);
    assert!(indexed.is_ok(), "{indexed:?}");
    let g = gguf_base();
    let indexed = index_gguf(&mut &g[..], g.len() as u64, &IndexerBounds::DEFAULT);
    assert!(indexed.is_ok(), "{indexed:?}");
}

#[test]
fn seeded_fuzzing_never_makes_an_indexer_panic() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let st = safetensors_base();
    let g = gguf_base();
    for round in 0..60_000u32 {
        let (base, is_gguf) = if round % 2 == 0 {
            (&st, false)
        } else {
            (&g, true)
        };
        let file = mutate(base, &mut rng);
        let declared = match rng.below(8) {
            0 => file.len() as u64 + rng.below(100) as u64,
            1 => (file.len() as u64).saturating_sub(rng.below(16) as u64),
            _ => file.len() as u64,
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            if is_gguf {
                index_gguf(&mut &file[..], declared, &IndexerBounds::DEFAULT).is_ok()
            } else {
                index_safetensors(&mut &file[..], declared, &IndexerBounds::DEFAULT).is_ok()
            }
        }));
        assert!(
            outcome.is_ok(),
            "indexer panicked on round {round}: {:02x?}",
            &file[..file.len().min(200)]
        );
    }
}

#[test]
fn seeded_fuzzing_never_makes_the_sidecar_decoder_panic() {
    let sidecar = quantized_manifest(&[("group_size", "128")], &["k"]).sidecar_bytes();
    let body = &sidecar[..sidecar.len() - SIDECAR_DIGEST_BYTES];
    let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
    for round in 0..40_000u32 {
        let mut mutated = mutate(body, &mut rng);
        if rng.below(3) == 0 && mutated.len() >= 8 {
            let i = rng.below(mutated.len() - 7);
            let v: u64 = [u64::MAX, 1 << 26, 1 << 40, 0, 4096][rng.below(5)];
            mutated[i..i + 8].copy_from_slice(&v.to_be_bytes());
        }
        let trailer = DigestBuilder::new(MANIFEST_DOMAIN).bytes(&mutated).finish();
        let mut sidecar = mutated;
        sidecar.extend_from_slice(trailer.as_bytes());
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            ValidatedManifest::from_sidecar_bytes(&sidecar).is_ok()
        }));
        assert!(outcome.is_ok(), "decoder panicked on round {round}");
    }
}
