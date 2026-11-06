//! §1.3: lossless representation, exact reuse and approximate inference are separate;
//! approximations need explicit configuration and accuracy evaluation; a memory setting
//! can never change the fidelity category.

use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::ids::ContentKey;

use super::super::*;
use super::support::*;

fn evaluation(name: &str) -> AccuracyEvaluation {
    AccuracyEvaluation { report: d(name) }
}

fn approximate_with(approximation: Approximation) -> FidelityConfiguration {
    FidelityConfiguration::approximate_inference(BTreeMap::from([(
        approximation,
        evaluation("evaluation-report"),
    )]))
    .unwrap()
}

fn configurations() -> Vec<FidelityConfiguration> {
    vec![
        FidelityConfiguration::lossless_representation(),
        FidelityConfiguration::exact_reuse(),
        approximate_with(Approximation::Quantization(awq())),
    ]
}

fn memory(techniques: &[Technique]) -> MemorySettings {
    MemorySettings {
        techniques: techniques.iter().copied().collect(),
        ..MemorySettings::default()
    }
}

#[test]
fn the_three_categories_are_separate() {
    let mut by_category: BTreeMap<FidelityCategory, BTreeSet<Technique>> = BTreeMap::new();
    for technique in Technique::ALL {
        by_category
            .entry(technique.category())
            .or_default()
            .insert(technique);
    }
    assert_eq!(by_category.len(), 3);
    for (category, count) in [
        (FidelityCategory::LosslessRepresentation, 4),
        (FidelityCategory::ExactReuse, 5),
        (FidelityCategory::ApproximateInference, 4),
    ] {
        assert_eq!(by_category[&category].len(), count, "{category}");
    }
    // Shared-subgraph reuse (line 894) is exact reuse, never an approximation.
    assert_eq!(
        Technique::SharedSubgraphReuse.category(),
        FidelityCategory::ExactReuse
    );
    assert_eq!(
        FidelityConfiguration::lossless_representation()
            .resolve(&memory(&[Technique::SharedSubgraphReuse])),
        Err(FidelityRefusal::MemorySettingExceedsCategory {
            technique: Technique::SharedSubgraphReuse,
            configured: FidelityCategory::LosslessRepresentation,
        })
    );
    // The four §1.3 approximations are approximate inference and nothing else is.
    assert_eq!(
        by_category[&FidelityCategory::ApproximateInference],
        BTreeSet::from([
            Technique::Quantization,
            Technique::AlternateModel,
            Technique::SparseApproximation,
            Technique::ChangedContextSemantics,
        ])
    );
    for (approximation, technique) in [
        (Approximation::Quantization(awq()), Technique::Quantization),
        (
            Approximation::AlternateModel(logical()),
            Technique::AlternateModel,
        ),
        (
            Approximation::SparseApproximation(versioned("top-k-attention", "1")),
            Technique::SparseApproximation,
        ),
        (
            Approximation::ChangedContextSemantics(versioned("sliding-window", "1")),
            Technique::ChangedContextSemantics,
        ),
        (
            Approximation::PrecisionReduction {
                from: Dtype::Float32,
                to: Dtype::BFloat16,
            },
            Technique::Quantization,
        ),
    ] {
        assert_eq!(approximation.technique(), technique);
    }
    let labels: BTreeSet<String> = FidelityCategory::ALL
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(labels.len(), 3);
}

#[test]
fn a_memory_setting_cannot_change_the_fidelity_category() {
    let mut random = SplitMix64::new(1336);
    for configuration in configurations() {
        let allowed: Vec<Technique> = Technique::ALL
            .into_iter()
            .filter(|technique| technique.category() <= configuration.category())
            .filter(|technique| technique.category() != FidelityCategory::ApproximateInference)
            .collect();
        for _ in 0..200 {
            let settings = MemorySettings {
                gpu_memory_target_bytes: random.next_u64(),
                kv_cache_bytes: random.next_u64(),
                pinned_host_bytes: random.next_u64(),
                disk_quota_bytes: random.next_u64(),
                techniques: allowed
                    .iter()
                    .copied()
                    .filter(|_| random.below(2) == 1)
                    .collect(),
            };
            assert_eq!(
                configuration.resolve(&settings),
                Ok(configuration.category()),
                "{settings:?}"
            );
        }
    }
}

#[test]
fn a_memory_setting_cannot_add_an_approximation() {
    for configuration in configurations() {
        for technique in Technique::ALL
            .into_iter()
            .filter(|technique| technique.category() == FidelityCategory::ApproximateInference)
        {
            // Even when the configuration itself allows that approximation.
            assert_eq!(
                configuration.resolve(&memory(&[Technique::TierOffload, technique])),
                Err(FidelityRefusal::MemorySettingApproximates { technique }),
                "{:?} {technique:?}",
                configuration.category()
            );
        }
    }
}

#[test]
fn a_memory_setting_cannot_widen_lossless_representation_to_reuse() {
    let lossless = FidelityConfiguration::lossless_representation();
    for technique in Technique::ALL
        .into_iter()
        .filter(|technique| technique.category() == FidelityCategory::ExactReuse)
    {
        assert_eq!(
            lossless.resolve(&memory(&[technique])),
            Err(FidelityRefusal::MemorySettingExceedsCategory {
                technique,
                configured: FidelityCategory::LosslessRepresentation,
            })
        );
        assert_eq!(
            FidelityConfiguration::exact_reuse().resolve(&memory(&[technique])),
            Ok(FidelityCategory::ExactReuse)
        );
    }
    // An approximation is reported before a category overreach.
    assert_eq!(
        lossless.resolve(&memory(&[
            Technique::PrefixKvReuse,
            Technique::ChangedContextSemantics
        ])),
        Err(FidelityRefusal::MemorySettingApproximates {
            technique: Technique::ChangedContextSemantics
        })
    );
}

#[test]
fn values_of_eight_bits_or_fewer_count_as_quantized() {
    let narrow: Vec<Dtype> = Dtype::ALL
        .into_iter()
        .filter(|dtype| dtype.bits() <= 8)
        .collect();
    assert_eq!(narrow.len(), 6);
    for dtype in narrow {
        let cast = LogicalModelSpec {
            dtype,
            ..logical_spec()
        };
        let kv =
            KvRepresentation::new(dtype, Quantization::None, 16, versioned("paged", "1")).unwrap();
        for configuration in configurations() {
            assert_eq!(
                configuration.check_logical_model(&source_spec(), &cast),
                Err(FidelityRefusal::NarrowDtypeWithoutScheme { dtype })
            );
            assert_eq!(
                configuration.check_kv_representation(&logical_spec(), &kv),
                Err(FidelityRefusal::NarrowDtypeWithoutScheme { dtype })
            );
        }
        // Named exactly and configured explicitly, the same dtype is accepted.
        let scheme =
            QuantizationScheme::new(versioned("cast", "1"), dtype.bits(), None, d("scales"))
                .unwrap();
        let quantized = LogicalModelSpec {
            quantization: Quantization::Scheme(scheme.clone()),
            ..cast
        };
        assert_eq!(
            approximate_with(Approximation::Quantization(scheme))
                .check_logical_model(&source_spec(), &quantized),
            Ok(())
        );
    }
}

#[test]
fn approximations_need_explicit_configuration_and_evaluation() {
    assert_eq!(
        FidelityConfiguration::approximate_inference(BTreeMap::new()),
        Err(FidelityRefusal::NoApproximationListed)
    );
    let quantization = Approximation::Quantization(awq());
    for configuration in [
        FidelityConfiguration::lossless_representation(),
        FidelityConfiguration::exact_reuse(),
    ] {
        assert_eq!(
            configuration.require(&quantization),
            Err(FidelityRefusal::NotExplicitlyConfigured {
                approximation: quantization.clone()
            })
        );
    }
    let configured = approximate_with(quantization.clone());
    assert_eq!(
        configured.category(),
        FidelityCategory::ApproximateInference
    );
    assert_eq!(
        configured.require(&quantization),
        Ok(&evaluation("evaluation-report"))
    );
    // An evaluation covers exactly the configured approximation.
    let other_bits = Approximation::Quantization(
        QuantizationScheme::new(versioned("awq", "0.2"), 3, Some(128), d("awq-scales")).unwrap(),
    );
    assert_eq!(
        configured.require(&other_bits),
        Err(FidelityRefusal::NotExplicitlyConfigured {
            approximation: other_bits
        })
    );
    let sparse = Approximation::SparseApproximation(versioned("top-k-attention", "1"));
    assert!(configured.require(&sparse).is_err());
    assert!(approximate_with(sparse.clone()).require(&sparse).is_ok());
}

#[test]
fn quantized_weights_and_kv_need_explicit_configuration() {
    let quantized = LogicalModelSpec {
        quantization: Quantization::Scheme(awq()),
        ..logical_spec()
    };
    let refusal = Err(FidelityRefusal::NotExplicitlyConfigured {
        approximation: Approximation::Quantization(awq()),
    });
    assert_eq!(
        FidelityConfiguration::exact_reuse().check_logical_model(&source_spec(), &quantized),
        refusal
    );
    assert_eq!(
        approximate_with(Approximation::Quantization(awq()))
            .check_logical_model(&source_spec(), &quantized),
        Ok(())
    );
    for configuration in configurations() {
        assert_eq!(
            configuration.check_logical_model(&source_spec(), &logical_spec()),
            Ok(())
        );
        assert_eq!(
            configuration.check_kv_representation(&logical_spec(), &kv_representation()),
            Ok(())
        );
    }

    let fp8 = QuantizationScheme::new(versioned("fp8-kv", "1"), 8, None, d("kv-scales")).unwrap();
    let fp8_kv = KvRepresentation::new(
        Dtype::Float8E4M3,
        Quantization::Scheme(fp8.clone()),
        16,
        versioned("paged", "1"),
    )
    .unwrap();
    assert_eq!(
        FidelityConfiguration::exact_reuse().check_kv_representation(&logical_spec(), &fp8_kv),
        Err(FidelityRefusal::NotExplicitlyConfigured {
            approximation: Approximation::Quantization(fp8.clone())
        })
    );
    assert_eq!(
        approximate_with(Approximation::Quantization(awq()))
            .check_kv_representation(&logical_spec(), &fp8_kv),
        Err(FidelityRefusal::NotExplicitlyConfigured {
            approximation: Approximation::Quantization(fp8.clone())
        }),
        "weight quantization does not cover KV quantization"
    );
    assert_eq!(
        approximate_with(Approximation::Quantization(fp8))
            .check_kv_representation(&logical_spec(), &fp8_kv),
        Ok(())
    );
}

#[test]
fn an_alternate_model_needs_explicit_configuration() {
    let requested = logical();
    // Same repository name and file sizes, different weights.
    let other_source = SourceSpec {
        files: source_spec()
            .files
            .into_iter()
            .map(|file| SourceFile {
                content: ContentKey::of(format!("distilled/{}", file.path.as_str()).as_bytes()),
                ..file
            })
            .collect(),
        ..source_spec()
    }
    .identity()
    .unwrap();
    let served = LogicalModelSpec {
        source: other_source,
        ..logical_spec()
    }
    .identity();
    let exact = FidelityConfiguration::exact_reuse();
    assert_eq!(exact.check_served_model(&requested, &requested), Ok(()));
    assert_eq!(
        exact.check_served_model(&requested, &served),
        Err(FidelityRefusal::NotExplicitlyConfigured {
            approximation: Approximation::AlternateModel(served)
        })
    );
    assert_eq!(
        approximate_with(Approximation::AlternateModel(served))
            .check_served_model(&requested, &served),
        Ok(())
    );
}

/// A source published in `published` and a logical model of it computing in `computed`.
fn published_as(published: Dtype, computed: Dtype) -> (SourceSpec, LogicalModelSpec) {
    let source = SourceSpec {
        published_dtype: published,
        ..source_spec()
    };
    let logical = LogicalModelSpec {
        source: source.identity().unwrap(),
        dtype: computed,
        ..logical_spec()
    };
    (source, logical)
}

#[test]
fn precision_reduction_needs_explicit_configuration() {
    let (source, logical) = published_as(Dtype::Float32, Dtype::BFloat16);
    let reduction = Approximation::PrecisionReduction {
        from: Dtype::Float32,
        to: Dtype::BFloat16,
    };
    for configuration in [
        FidelityConfiguration::lossless_representation(),
        FidelityConfiguration::exact_reuse(),
        approximate_with(Approximation::PrecisionReduction {
            from: Dtype::Float32,
            to: Dtype::Float16,
        }),
    ] {
        assert_eq!(
            configuration.check_logical_model(&source, &logical),
            Err(FidelityRefusal::NotExplicitlyConfigured {
                approximation: reduction.clone()
            })
        );
    }
    assert_eq!(
        approximate_with(reduction).check_logical_model(&source, &logical),
        Ok(())
    );
    // A memory setting cannot ask for it either: it is quantization.
    assert_eq!(
        FidelityConfiguration::exact_reuse().resolve(&memory(&[Technique::Quantization])),
        Err(FidelityRefusal::MemorySettingApproximates {
            technique: Technique::Quantization
        })
    );
}

#[test]
fn only_an_exact_widening_needs_no_configuration() {
    let mut exact_pairs = Vec::new();
    for from in Dtype::ALL {
        for to in Dtype::ALL {
            if from.widens_exactly_to(to) {
                exact_pairs.push((from, to));
            }
        }
    }
    assert_eq!(
        exact_pairs,
        vec![
            (Dtype::Float32, Dtype::Float64),
            (Dtype::Float16, Dtype::Float64),
            (Dtype::Float16, Dtype::Float32),
            (Dtype::BFloat16, Dtype::Float64),
            (Dtype::BFloat16, Dtype::Float32),
        ]
    );
    for (from, to) in exact_pairs {
        let (source, logical) = published_as(from, to);
        assert_eq!(
            FidelityConfiguration::lossless_representation().check_logical_model(&source, &logical),
            Ok(()),
            "{from:?} to {to:?}"
        );
    }

    for (from, to) in [
        (Dtype::BFloat16, Dtype::Float16),
        (Dtype::Float16, Dtype::BFloat16),
        (Dtype::Float32, Dtype::Float16),
        (Dtype::Float64, Dtype::Float32),
        (Dtype::Int8, Dtype::Float16),
        (Dtype::UInt8, Dtype::BFloat16),
        (Dtype::Int4, Dtype::Float32),
        (Dtype::Float8E4M3, Dtype::BFloat16),
    ] {
        let (source, logical) = published_as(from, to);
        assert_eq!(
            FidelityConfiguration::exact_reuse().check_logical_model(&source, &logical),
            Err(FidelityRefusal::NotExplicitlyConfigured {
                approximation: Approximation::PrecisionReduction { from, to }
            }),
            "{from:?} to {to:?}"
        );
    }
}

#[test]
fn the_check_uses_the_logical_models_own_source() {
    // The weights are published in F32 and served in BF16. Claiming a BF16 source to make
    // that look like no conversion gives another source identity, and is refused.
    let (published, logical) = published_as(Dtype::Float32, Dtype::BFloat16);
    let claimed = source_spec();
    assert_eq!(
        FidelityConfiguration::exact_reuse().check_logical_model(&claimed, &logical),
        Err(FidelityRefusal::SourceMismatch {
            logical_source: published.identity().unwrap(),
            given_source: claimed.identity().unwrap(),
        })
    );
    let invalid = SourceSpec {
        files: Vec::new(),
        ..published
    };
    assert_eq!(
        FidelityConfiguration::exact_reuse().check_logical_model(&invalid, &logical),
        Err(FidelityRefusal::InvalidSource(IdentityError::NoSourceFiles))
    );
}

#[test]
fn kv_precision_follows_the_model_dtype() {
    let model = logical_spec();
    assert_eq!(model.dtype, Dtype::BFloat16);
    let kv = |dtype| {
        KvRepresentation::new(dtype, Quantization::None, 16, versioned("paged", "1")).unwrap()
    };

    // A BF16 model with F16 KV is refused unless that exact reduction is configured.
    let reduction = Approximation::PrecisionReduction {
        from: Dtype::BFloat16,
        to: Dtype::Float16,
    };
    for configuration in [
        FidelityConfiguration::lossless_representation(),
        FidelityConfiguration::exact_reuse(),
        approximate_with(Approximation::PrecisionReduction {
            from: Dtype::Float32,
            to: Dtype::Float16,
        }),
    ] {
        assert_eq!(
            configuration.check_kv_representation(&model, &kv(Dtype::Float16)),
            Err(FidelityRefusal::NotExplicitlyConfigured {
                approximation: reduction.clone()
            })
        );
    }
    assert_eq!(
        approximate_with(reduction).check_kv_representation(&model, &kv(Dtype::Float16)),
        Ok(())
    );

    // The model's own dtype and exact widenings of it need no configuration.
    for dtype in [Dtype::BFloat16, Dtype::Float32, Dtype::Float64] {
        assert_eq!(
            FidelityConfiguration::lossless_representation()
                .check_kv_representation(&model, &kv(dtype)),
            Ok(()),
            "{dtype:?}"
        );
    }

    // An F32 model with BF16 KV is a reduction too.
    let f32_model = LogicalModelSpec {
        dtype: Dtype::Float32,
        ..logical_spec()
    };
    assert_eq!(
        FidelityConfiguration::exact_reuse()
            .check_kv_representation(&f32_model, &kv(Dtype::BFloat16)),
        Err(FidelityRefusal::NotExplicitlyConfigured {
            approximation: Approximation::PrecisionReduction {
                from: Dtype::Float32,
                to: Dtype::BFloat16,
            }
        })
    );

    // FP8 KV without its scheme is refused under every configuration.
    for configuration in configurations() {
        assert_eq!(
            configuration.check_kv_representation(&model, &kv(Dtype::Float8E4M3)),
            Err(FidelityRefusal::NarrowDtypeWithoutScheme {
                dtype: Dtype::Float8E4M3
            })
        );
    }
}
