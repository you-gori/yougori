//! Typed fields refuse inputs without one canonical form (§3.2), and every refusal can be
//! displayed.

use std::collections::BTreeSet;

use super::super::*;
use super::support::*;

#[test]
fn labels_have_one_canonical_form() {
    assert_eq!(Label::new(""), Err(IdentityError::EmptyLabel));
    assert_eq!(
        Label::new("x".repeat(MAX_LABEL_BYTES + 1)),
        Err(IdentityError::LabelTooLong {
            max_bytes: MAX_LABEL_BYTES
        })
    );
    assert!(Label::new("x".repeat(MAX_LABEL_BYTES)).is_ok());
    assert_eq!(
        Label::new("vllm\n"),
        Err(IdentityError::LabelControlCharacter)
    );
    for padded in [" vllm", "vllm ", "\u{a0}vllm"] {
        assert_eq!(
            Label::new(padded),
            Err(IdentityError::LabelSurroundingWhitespace),
            "{padded:?}"
        );
    }
    assert_eq!(label("org/model 8B").as_str(), "org/model 8B");
}

#[test]
fn source_paths_are_canonical_and_relative() {
    let problem = |path: &str| match RelativePath::new(path) {
        Err(IdentityError::InvalidPath { problem }) => Some(problem),
        Ok(_) => None,
        Err(other) => panic!("unexpected {other:?}"),
    };
    assert_eq!(problem(""), Some(PathProblem::Empty));
    assert_eq!(
        problem(&"a".repeat(MAX_PATH_BYTES + 1)),
        Some(PathProblem::TooLong)
    );
    assert_eq!(problem("a\tb"), Some(PathProblem::ControlCharacter));
    assert_eq!(
        problem("dir\\model.safetensors"),
        Some(PathProblem::Backslash)
    );
    assert_eq!(problem("C:/model.safetensors"), Some(PathProblem::Colon));
    assert_eq!(problem("/model.safetensors"), Some(PathProblem::Absolute));
    assert_eq!(
        problem("dir//model.safetensors"),
        Some(PathProblem::EmptySegment)
    );
    assert_eq!(problem("dir/"), Some(PathProblem::EmptySegment));
    assert_eq!(
        problem("./model.safetensors"),
        Some(PathProblem::DotSegment)
    );
    assert_eq!(
        problem("dir/../model.safetensors"),
        Some(PathProblem::DotSegment)
    );
    assert_eq!(problem("onnx/model.onnx_data"), None);
}

#[test]
fn a_revision_must_be_an_immutable_commit() {
    for mutable in [
        "main",
        "v1.0",
        "refs/heads/main",
        "0123456",
        &COMMIT[..39],
        &format!("{COMMIT}0"),
        &"g".repeat(40),
    ] {
        assert_eq!(
            CommitId::new(mutable),
            Err(IdentityError::NotAnImmutableRevision),
            "{mutable}"
        );
    }
    assert_eq!(
        CommitId::new(&COMMIT.to_uppercase()),
        CommitId::new(COMMIT),
        "hexadecimal case is not part of the revision"
    );
    assert!(
        CommitId::new(&"a".repeat(64)).is_ok(),
        "SHA-256 repositories"
    );

    let floating = SourceSpec {
        revision: ImmutableRevision::FileDigests,
        ..source_spec()
    };
    assert_eq!(
        floating.identity(),
        Err(IdentityError::RepositoryNeedsCommit)
    );
    let local = SourceSpec {
        location: SourceLocation::Local {
            name: label("my-model"),
        },
        revision: ImmutableRevision::FileDigests,
        ..source_spec()
    };
    assert!(local.identity().is_ok());
}

#[test]
fn a_source_lists_each_file_once() {
    let empty = SourceSpec {
        files: Vec::new(),
        ..source_spec()
    };
    assert_eq!(empty.identity(), Err(IdentityError::NoSourceFiles));
    let mut duplicated = source_spec();
    duplicated
        .files
        .push(file("tokenizer.json", 9_000_000, "tokenizer-copy"));
    assert_eq!(
        duplicated.identity(),
        Err(IdentityError::DuplicateSourceFile {
            path: "tokenizer.json".to_owned()
        })
    );
    let overflowing = SourceSpec {
        files: vec![file("a", u64::MAX, "a"), file("b", 1, "b")],
        ..source_spec()
    };
    assert_eq!(overflowing.total_length_bytes(), None);
    assert!(
        overflowing.identity().is_ok(),
        "sizes are not summed into an identity"
    );
}

#[test]
fn execution_inputs_are_checked() {
    let no_architecture = ExecutionSpec {
        gpu_architectures: BTreeSet::new(),
        ..execution_spec()
    };
    assert_eq!(
        no_architecture.identity(),
        Err(IdentityError::NoGpuArchitecture)
    );
    for (sizes, dimension) in [
        ((0, 1, 1), "tensor_parallel_size"),
        ((1, 0, 1), "pipeline_parallel_size"),
        ((1, 1, 0), "expert_parallel_size"),
    ] {
        assert_eq!(
            RankTopology::new(sizes.0, sizes.1, sizes.2),
            Err(IdentityError::ZeroParallelism { dimension })
        );
    }
    let topology = RankTopology::new(4, 2, 8).unwrap();
    assert_eq!(
        (
            topology.tensor_parallel_size(),
            topology.pipeline_parallel_size(),
            topology.expert_parallel_size()
        ),
        (4, 2, 8)
    );
}

#[test]
fn quantization_and_kv_inputs_are_checked() {
    for bits in [0, 17] {
        assert_eq!(
            QuantizationScheme::new(versioned("awq", "0.2"), bits, None, d("p")),
            Err(IdentityError::QuantizationBits { bits })
        );
    }
    assert_eq!(
        QuantizationScheme::new(versioned("awq", "0.2"), 4, Some(0), d("p")),
        Err(IdentityError::ZeroGroupSize)
    );
    let scheme = awq();
    assert_eq!(scheme.method(), &versioned("awq", "0.2"));
    assert_eq!((scheme.weight_bits(), scheme.group_size()), (4, Some(128)));
    assert_eq!(scheme.parameters(), &d("awq-scales"));
    assert_eq!(
        KvRepresentation::new(
            Dtype::BFloat16,
            Quantization::None,
            0,
            versioned("paged", "1")
        ),
        Err(IdentityError::ZeroBlockTokens)
    );
    let tags: BTreeSet<&str> = Dtype::ALL.iter().map(|dtype| dtype.tag()).collect();
    assert_eq!(tags.len(), Dtype::ALL.len(), "each dtype has its own tag");
}

#[test]
fn every_refusal_explains_itself() {
    let messages = [
        IdentityError::EmptyLabel.to_string(),
        IdentityError::InvalidPath {
            problem: PathProblem::DotSegment,
        }
        .to_string(),
        IdentityError::NotAnImmutableRevision.to_string(),
        IdentityError::MissingAuthorizationEpoch.to_string(),
        IdentityError::GenerationNotAfter {
            field: "model activation",
            current: 5,
            proposed: 4,
        }
        .to_string(),
        LoraRefusal::SubtractionIsNotExactUndo {
            load_instead: logical(),
        }
        .to_string(),
        GraphReuseRefusal::Mismatch {
            differences: vec![GraphDifference::Execution],
        }
        .to_string(),
        KvReuseRefusal::BackendDoesNotEnforceScope.to_string(),
        SharingRefusal::CrossVmDeviceMemory.to_string(),
        GrantRefusal::Missing.to_string(),
        AdvertisementRefusal::Incompatible.to_string(),
        FidelityRefusal::MemorySettingApproximates {
            technique: Technique::Quantization,
        }
        .to_string(),
    ];
    for message in &messages {
        assert!(!message.is_empty());
    }
    assert!(messages[5].contains(&logical().to_string()));
    assert!(messages[11].contains("not a memory setting"));
}
