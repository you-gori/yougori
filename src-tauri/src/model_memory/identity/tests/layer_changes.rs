//! §3.2: each layer changes when any of its inputs changes, and only then. Equal inputs
//! give equal identities, order carries no meaning in sets, and names or sizes never
//! stand in for content (line 504).

use std::collections::BTreeSet;

use crate::foundation::ids::{
    AuthorizationEpoch, ContentKey, Digest, ExecutionCategory, GpuAllocationGeneration,
    ModelActivationGeneration,
};

use super::super::*;
use super::support::*;

/// Every variant differs from the base and from every other variant, and rebuilding any
/// of them gives the same digest again.
fn check_layer<S: Clone>(base: &S, variants: &[(&str, S)], identity: impl Fn(&S) -> Digest) {
    let base_digest = identity(base);
    assert_eq!(identity(&base.clone()), base_digest);
    let mut cases = vec![("base", base_digest)];
    for (name, spec) in variants {
        let digest = identity(spec);
        assert_eq!(
            identity(&spec.clone()),
            digest,
            "{name} is not deterministic"
        );
        cases.push((name, digest));
    }
    assert_all_distinct(&cases);
}

fn with_file(spec: &SourceSpec, index: usize, change: impl FnOnce(&mut SourceFile)) -> SourceSpec {
    let mut spec = spec.clone();
    change(&mut spec.files[index]);
    spec
}

fn repository(host: &str, repository: &str) -> SourceLocation {
    SourceLocation::Repository {
        host: label(host),
        repository: label(repository),
    }
}

#[test]
fn source_identity_changes_with_every_input_and_only_then() {
    let base = source_spec();
    let mut added = base.clone();
    added.files.push(file("README.md", 10, "readme"));
    let mut removed = base.clone();
    removed.files.pop();
    let variants = [
        (
            "host",
            SourceSpec {
                location: repository("hf-mirror.example", "example-org/example-8b"),
                ..base.clone()
            },
        ),
        (
            "repository",
            SourceSpec {
                location: repository("huggingface.co", "example-org/example-8b-v2"),
                ..base.clone()
            },
        ),
        (
            "local location",
            SourceSpec {
                location: SourceLocation::Local {
                    name: label("example-org/example-8b"),
                },
                ..base.clone()
            },
        ),
        (
            "revision",
            SourceSpec {
                revision: ImmutableRevision::Commit(CommitId::new(OTHER_COMMIT).unwrap()),
                ..base.clone()
            },
        ),
        (
            "file path",
            with_file(&base, 0, |file| {
                file.path = RelativePath::new("configs/config.json").unwrap()
            }),
        ),
        (
            "file length",
            with_file(&base, 1, |file| file.length_bytes += 1),
        ),
        (
            "file content",
            with_file(&base, 2, |file| {
                file.content = ContentKey::of(b"other-shard")
            }),
        ),
        ("file added", added),
        ("file removed", removed),
        (
            "configuration",
            SourceSpec {
                configuration: d("other-configuration"),
                ..base.clone()
            },
        ),
        (
            "published dtype",
            SourceSpec {
                published_dtype: Dtype::Float32,
                ..base.clone()
            },
        ),
        (
            "license",
            SourceSpec {
                license: label("mit"),
                ..base.clone()
            },
        ),
        (
            "provenance",
            SourceSpec {
                provenance: Some(d("other-attestation")),
                ..base.clone()
            },
        ),
        (
            "no provenance",
            SourceSpec {
                provenance: None,
                ..base.clone()
            },
        ),
    ];
    check_layer(&base, &variants, |spec| *spec.identity().unwrap().digest());
}

#[test]
fn file_order_carries_no_meaning() {
    let identity = source();
    let mut random = SplitMix64::new(0x7007);
    for _ in 0..64 {
        let mut spec = source_spec();
        random.shuffle(&mut spec.files);
        assert_eq!(spec.identity().unwrap(), identity);
    }
}

#[test]
fn same_name_and_size_with_different_content_never_share_an_identity() {
    let original = source_spec();
    // Same repository name, same paths, same lengths: only the bytes of one shard differ.
    let altered = with_file(&original, 1, |file| {
        file.content = ContentKey::of(b"tampered-shard")
    });
    assert_eq!(original.location, altered.location);
    assert_eq!(original.total_length_bytes(), altered.total_length_bytes());
    let paths = |spec: &SourceSpec| {
        spec.files
            .iter()
            .map(|file| (file.path.clone(), file.length_bytes))
            .collect::<Vec<_>>()
    };
    assert_eq!(paths(&original), paths(&altered));

    let altered_source = altered.identity().unwrap();
    assert_ne!(altered_source, source());

    // The difference carries through every layer built on the source.
    let altered_logical = LogicalModelSpec {
        source: altered_source,
        ..logical_spec()
    }
    .identity();
    assert_ne!(altered_logical, logical());
    let altered_execution = ExecutionSpec {
        logical: altered_logical,
        ..execution_spec()
    }
    .identity()
    .unwrap();
    assert_ne!(altered_execution, execution());

    // Bytes moved between two files keep every name and the total size, and still differ.
    let moved = {
        let mut spec = with_file(&original, 1, |file| file.length_bytes -= 1_000);
        spec.files[2].length_bytes += 1_000;
        spec
    };
    assert_eq!(moved.total_length_bytes(), original.total_length_bytes());
    assert_ne!(moved.identity().unwrap(), source());
}

#[test]
fn logical_identity_changes_with_every_input_and_only_then() {
    let base = logical_spec();
    let scheme = |method: (&str, &str), bits: u8, group: Option<u32>, parameters: &str| {
        Quantization::Scheme(
            QuantizationScheme::new(versioned(method.0, method.1), bits, group, d(parameters))
                .unwrap(),
        )
    };
    let merged_recipe = |adapters: Vec<MergedAdapter>| {
        AdapterRecipe::Merged(MergedAdapters::new(adapters).unwrap())
    };
    let other_procedure = MergedAdapter {
        procedure: versioned("peft-merge-bf16", "0.13"),
        ..merged("org/a", 1.0)
    };
    let variants = [
        (
            "source",
            LogicalModelSpec {
                source: SourceSpec {
                    revision: ImmutableRevision::Commit(CommitId::new(OTHER_COMMIT).unwrap()),
                    ..source_spec()
                }
                .identity()
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "dtype",
            LogicalModelSpec {
                dtype: Dtype::Float16,
                ..base.clone()
            },
        ),
        (
            "quantization",
            LogicalModelSpec {
                quantization: Quantization::Scheme(awq()),
                ..base.clone()
            },
        ),
        (
            "quantization method",
            LogicalModelSpec {
                quantization: scheme(("gptq", "0.2"), 4, Some(128), "awq-scales"),
                ..base.clone()
            },
        ),
        (
            "quantization method version",
            LogicalModelSpec {
                quantization: scheme(("awq", "0.3"), 4, Some(128), "awq-scales"),
                ..base.clone()
            },
        ),
        (
            "quantization bits",
            LogicalModelSpec {
                quantization: scheme(("awq", "0.2"), 8, Some(128), "awq-scales"),
                ..base.clone()
            },
        ),
        (
            "quantization group",
            LogicalModelSpec {
                quantization: scheme(("awq", "0.2"), 4, Some(64), "awq-scales"),
                ..base.clone()
            },
        ),
        (
            "quantization without groups",
            LogicalModelSpec {
                quantization: scheme(("awq", "0.2"), 4, None, "awq-scales"),
                ..base.clone()
            },
        ),
        (
            "quantization parameters",
            LogicalModelSpec {
                quantization: scheme(("awq", "0.2"), 4, Some(128), "other-scales"),
                ..base.clone()
            },
        ),
        (
            "tokenizer",
            LogicalModelSpec {
                tokenizer: d("other-tokenizer"),
                ..base.clone()
            },
        ),
        (
            "generation configuration",
            LogicalModelSpec {
                generation_config: d("other-generation-config"),
                ..base.clone()
            },
        ),
        (
            "merged adapter",
            LogicalModelSpec {
                adapters: merged_recipe(vec![merged("org/a", 1.0)]),
                ..base.clone()
            },
        ),
        (
            "merge scale",
            LogicalModelSpec {
                adapters: merged_recipe(vec![merged("org/a", 0.5)]),
                ..base.clone()
            },
        ),
        (
            "merge procedure",
            LogicalModelSpec {
                adapters: merged_recipe(vec![other_procedure]),
                ..base.clone()
            },
        ),
        (
            "merged a then b",
            LogicalModelSpec {
                adapters: merged_recipe(vec![merged("org/a", 1.0), merged("org/b", 1.0)]),
                ..base.clone()
            },
        ),
        (
            "merged b then a",
            LogicalModelSpec {
                adapters: merged_recipe(vec![merged("org/b", 1.0), merged("org/a", 1.0)]),
                ..base.clone()
            },
        ),
        (
            "remote code",
            LogicalModelSpec {
                code_policy: CodePolicy::PinnedRemoteCode {
                    code: d("modeling.py"),
                },
                ..base.clone()
            },
        ),
        (
            "other remote code",
            LogicalModelSpec {
                code_policy: CodePolicy::PinnedRemoteCode {
                    code: d("modeling-v2.py"),
                },
                ..base.clone()
            },
        ),
    ];
    check_layer(&base, &variants, |spec| *spec.identity().digest());
}

#[test]
fn execution_identity_changes_with_every_input_and_only_then() {
    let base = execution_spec();
    let topology = |tp, pp, ep| RankTopology::new(tp, pp, ep).unwrap();
    let variants = [
        (
            "logical",
            ExecutionSpec {
                logical: LogicalModelSpec {
                    dtype: Dtype::Float16,
                    ..logical_spec()
                }
                .identity(),
                ..base.clone()
            },
        ),
        (
            "runner",
            ExecutionSpec {
                runner: versioned("sglang", "0.29.0"),
                ..base.clone()
            },
        ),
        (
            "runner version",
            ExecutionSpec {
                runner: versioned("vllm", "0.31.0"),
                ..base.clone()
            },
        ),
        (
            "architecture adapter",
            ExecutionSpec {
                architecture_adapter: versioned("llama", "2"),
                ..base.clone()
            },
        ),
        (
            "kernel layout",
            ExecutionSpec {
                kernel_layout: versioned("flash-attn", "3.0.0"),
                ..base.clone()
            },
        ),
        (
            "gpu architecture",
            ExecutionSpec {
                gpu_architectures: BTreeSet::from([label("sm_120")]),
                ..base.clone()
            },
        ),
        (
            "added gpu architecture",
            ExecutionSpec {
                gpu_architectures: BTreeSet::from([label("sm_90a"), label("sm_120")]),
                ..base.clone()
            },
        ),
        (
            "tensor parallel",
            ExecutionSpec {
                topology: topology(2, 1, 1),
                ..base.clone()
            },
        ),
        (
            "pipeline parallel",
            ExecutionSpec {
                topology: topology(1, 2, 1),
                ..base.clone()
            },
        ),
        (
            "expert parallel",
            ExecutionSpec {
                topology: topology(1, 1, 2),
                ..base.clone()
            },
        ),
        (
            "processed weights",
            ExecutionSpec {
                processed_weights: versioned("vllm-marlin", "1"),
                ..base.clone()
            },
        ),
        (
            "compiled",
            ExecutionSpec {
                compile: CompileConfiguration::Compiled {
                    configuration: d("torch-compile"),
                },
                ..base.clone()
            },
        ),
        (
            "compile configuration",
            ExecutionSpec {
                compile: CompileConfiguration::Compiled {
                    configuration: d("torch-compile-max-autotune"),
                },
                ..base.clone()
            },
        ),
    ];
    check_layer(&base, &variants, |spec| *spec.identity().unwrap().digest());

    let mut reversed = BTreeSet::new();
    reversed.insert(label("sm_120"));
    reversed.insert(label("sm_90a"));
    let reordered = ExecutionSpec {
        gpu_architectures: reversed,
        ..base.clone()
    };
    let forward = ExecutionSpec {
        gpu_architectures: BTreeSet::from([label("sm_90a"), label("sm_120")]),
        ..base
    };
    assert_eq!(reordered.identity(), forward.identity());
}

#[test]
fn artifact_identity_changes_with_the_manifest_digest_and_only_then() {
    assert_eq!(
        ArtifactIdentity::from_manifest_digest(&d("manifest")),
        artifact()
    );
    assert_ne!(
        ArtifactIdentity::from_manifest_digest(&d("other-manifest")),
        artifact()
    );
}

#[test]
fn placement_identity_changes_with_every_input_and_only_then() {
    let base = placement_spec();
    let epoch = |value| Some(AuthorizationEpoch::new(value));
    let leases = |ids: &[u64]| ids.iter().map(|id| lease(*id)).collect();
    let variants = [
        (
            "artifact",
            PlacementSpec {
                artifact: ArtifactIdentity::from_manifest_digest(&d("other-manifest")),
                ..base.clone()
            },
        ),
        (
            "execution",
            PlacementSpec {
                execution: ExecutionSpec {
                    runner: versioned("vllm", "0.31.0"),
                    ..execution_spec()
                }
                .identity()
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "machine",
            PlacementSpec {
                device: gpu("host-b", "GPU-0"),
                ..base.clone()
            },
        ),
        (
            "device",
            PlacementSpec {
                device: gpu("host-a", "GPU-1"),
                ..base.clone()
            },
        ),
        (
            "owner",
            PlacementSpec {
                owner: tenant("tenant-b"),
                ..base.clone()
            },
        ),
        (
            "parent execution",
            PlacementSpec {
                authority: vm_binding("exe-other-parent", 3),
                ..base.clone()
            },
        ),
        (
            "authorization epoch",
            PlacementSpec {
                authority: vm_binding("exe-parent", 4),
                ..base.clone()
            },
        ),
        (
            "runtime category",
            PlacementSpec {
                authority: AuthorityBinding::new(
                    exe("exe-parent"),
                    ExecutionCategory::SharedKernelGpuRuntime,
                    epoch(3),
                )
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "labelled runtime without epoch",
            PlacementSpec {
                authority: AuthorityBinding::new(
                    exe("exe-parent"),
                    ExecutionCategory::SharedKernelGpuRuntime,
                    None,
                )
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "activation",
            PlacementSpec {
                activation: ModelActivationGeneration::new(6),
                ..base.clone()
            },
        ),
        (
            "allocation",
            PlacementSpec {
                allocation: GpuAllocationGeneration::new(10),
                ..base.clone()
            },
        ),
        (
            "lease added",
            PlacementSpec {
                leases: leases(&[1, 2, 3]),
                ..base.clone()
            },
        ),
        (
            "lease removed",
            PlacementSpec {
                leases: leases(&[1]),
                ..base.clone()
            },
        ),
        (
            "lease replaced",
            PlacementSpec {
                leases: leases(&[1, 9]),
                ..base.clone()
            },
        ),
        (
            "no leases",
            PlacementSpec {
                leases: BTreeSet::new(),
                ..base.clone()
            },
        ),
    ];
    check_layer(&base, &variants, |spec| *spec.identity().digest());
}

#[test]
fn session_identity_changes_with_every_input_and_only_then() {
    let base = session_spec();
    let kv = |dtype, quantization, block_tokens, layout: (&str, &str)| {
        KvRepresentation::new(
            dtype,
            quantization,
            block_tokens,
            versioned(layout.0, layout.1),
        )
        .unwrap()
    };
    let fp8 = QuantizationScheme::new(versioned("fp8-kv", "1"), 8, None, d("kv-scales")).unwrap();
    let variants = [
        (
            "execution",
            SessionSpec {
                execution: ExecutionSpec {
                    kernel_layout: versioned("flash-attn", "3.0.0"),
                    ..execution_spec()
                }
                .identity()
                .unwrap(),
                ..base.clone()
            },
        ),
        (
            "token prefix",
            SessionSpec {
                state: TokenState::Prefix(TokenPrefix::from_token_ids(&[128_000, 9906, 11, 1918])),
                ..base.clone()
            },
        ),
        (
            "longer prefix",
            SessionSpec {
                state: TokenState::Prefix(TokenPrefix::from_token_ids(&[
                    128_000, 9906, 11, 1917, 30,
                ])),
                ..base.clone()
            },
        ),
        (
            "recurrent state",
            SessionSpec {
                state: TokenState::Recurrent {
                    state: d("ssm-state"),
                    tokens_consumed: 4,
                },
                ..base.clone()
            },
        ),
        (
            "recurrent tokens",
            SessionSpec {
                state: TokenState::Recurrent {
                    state: d("ssm-state"),
                    tokens_consumed: 5,
                },
                ..base.clone()
            },
        ),
        (
            "no adapter",
            SessionSpec {
                adapter: None,
                ..base.clone()
            },
        ),
        (
            "other adapter",
            SessionSpec {
                adapter: Some(adapter("org/other-lora")),
                ..base.clone()
            },
        ),
        (
            "positional scheme",
            SessionSpec {
                positional_encoding: PositionalEncoding {
                    scheme: versioned("rope", "2"),
                    ..rope()
                },
                ..base.clone()
            },
        ),
        (
            "positional parameters",
            SessionSpec {
                positional_encoding: PositionalEncoding {
                    parameters: d("rope-yarn-factor-4"),
                    ..rope()
                },
                ..base.clone()
            },
        ),
        (
            "kv dtype",
            SessionSpec {
                kv: kv(Dtype::Float8E4M3, Quantization::None, 16, ("paged", "1")),
                ..base.clone()
            },
        ),
        (
            "kv quantization",
            SessionSpec {
                kv: kv(
                    Dtype::BFloat16,
                    Quantization::Scheme(fp8),
                    16,
                    ("paged", "1"),
                ),
                ..base.clone()
            },
        ),
        (
            "kv block",
            SessionSpec {
                kv: kv(Dtype::BFloat16, Quantization::None, 32, ("paged", "1")),
                ..base.clone()
            },
        ),
        (
            "kv layout",
            SessionSpec {
                kv: kv(Dtype::BFloat16, Quantization::None, 16, ("paged", "2")),
                ..base.clone()
            },
        ),
        (
            "tenant",
            SessionSpec {
                tenant: tenant("tenant-b"),
                ..base.clone()
            },
        ),
        (
            "parent execution",
            SessionSpec {
                authority: vm_binding("exe-other-session", 3),
                ..base.clone()
            },
        ),
        (
            "authorization epoch",
            SessionSpec {
                authority: vm_binding("exe-session", 4),
                ..base.clone()
            },
        ),
    ];
    check_layer(&base, &variants, |spec| *spec.identity().digest());
}

#[test]
fn adapter_identity_changes_with_every_input_and_only_then() {
    let base = adapter_spec("org/support-lora");
    let variants = [
        (
            "source",
            AdapterSpec {
                source: adapter_source("org/other-lora"),
                ..base.clone()
            },
        ),
        (
            "method",
            AdapterSpec {
                method: versioned("dora", "1"),
                ..base.clone()
            },
        ),
        (
            "method version",
            AdapterSpec {
                method: versioned("lora", "2"),
                ..base.clone()
            },
        ),
        (
            "dtype",
            AdapterSpec {
                dtype: Dtype::Float16,
                ..base.clone()
            },
        ),
    ];
    check_layer(&base, &variants, |spec| *spec.identity().digest());
}

#[test]
fn token_order_and_count_are_part_of_a_prefix() {
    let forward = TokenPrefix::from_token_ids(&[1, 2, 3]);
    assert_eq!(forward, TokenPrefix::from_token_ids(&[1, 2, 3]));
    assert_eq!(forward.token_count(), 3);
    assert_ne!(forward, TokenPrefix::from_token_ids(&[3, 2, 1]));
    assert_ne!(forward, TokenPrefix::from_token_ids(&[1, 2]));
    assert_ne!(
        TokenPrefix::from_token_ids(&[]),
        TokenPrefix::from_token_ids(&[0])
    );
}
