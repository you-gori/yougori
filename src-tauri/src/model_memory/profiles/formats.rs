//! KV cache representations (S13 lines 248 and 250; GPU §1.3).
//!
//! Fidelity comes from the model identity layers (T07): a KV representation is a lossless
//! representation only where a configuration without approximations accepts it for the
//! model it caches, and anything else needs its exact quantization scheme or precision
//! reduction configured with an accuracy evaluation (§1.3). On top of that, line 248
//! requires per-model support, numerical behaviour, cache format and rollback to be
//! checked for the exact model on the exact engine, per-model support first, before any
//! reduced-precision KV is used: one architecture's FP4 KV is no generic switch for
//! another checkpoint.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::settings::EngineRef;
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::model_memory::identity::{
    FidelityCategory, FidelityConfiguration, FidelityRefusal, KvRepresentation,
    LogicalModelIdentity, LogicalModelSpec, Quantization,
};

/// One check line 248 requires before a reduced-precision KV representation is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvCheck {
    /// The model supports the representation at all.
    PerModelSupport,
    /// Numerical behaviour against the model's own dtype.
    NumericalBehavior,
    /// The cache layout and its size per token.
    CacheFormat,
    /// Returning to the lossless representation works.
    Rollback,
}

impl KvCheck {
    /// The order the checks are read in: per-model support comes first (line 248).
    pub const ORDER: [Self; 4] = [
        Self::PerModelSupport,
        Self::NumericalBehavior,
        Self::CacheFormat,
        Self::Rollback,
    ];
}

impl fmt::Display for KvCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PerModelSupport => "per-model support",
            Self::NumericalBehavior => "numerical behaviour",
            Self::CacheFormat => "cache format",
            Self::Rollback => "rollback",
        })
    }
}

strict_tagged_enum! {
/// The outcome of one check, with the CORE-08 raw report it rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckResult (tag = "outcome", wire = CheckResultWire, wire_name = "CheckResultWire") {
    Passed { report: Digest },
    Failed { report: Digest },
    /// Not checked, which never passes.
    NotChecked,
}
}

/// The line 248 checks of one KV representation for one exact logical model on one
/// pinned engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvFormatQualification {
    pub model: LogicalModelIdentity,
    pub engine: EngineRef,
    pub kv: KvRepresentation,
    pub per_model_support: CheckResult,
    pub numerical_behavior: CheckResult,
    pub cache_format: CheckResult,
    pub rollback: CheckResult,
}

impl KvFormatQualification {
    pub fn result(&self, check: KvCheck) -> CheckResult {
        match check {
            KvCheck::PerModelSupport => self.per_model_support,
            KvCheck::NumericalBehavior => self.numerical_behavior,
            KvCheck::CacheFormat => self.cache_format,
            KvCheck::Rollback => self.rollback,
        }
    }

    fn first_unpassed(&self) -> Option<(KvCheck, CheckResult)> {
        KvCheck::ORDER
            .into_iter()
            .map(|check| (check, self.result(check)))
            .find(|(_, result)| !matches!(result, CheckResult::Passed { .. }))
    }
}

/// Why a KV representation was not admitted. The refused representation is boxed to keep
/// the refusal small.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvFormatRefusal {
    /// The request's fidelity configuration does not allow it (T07, §1.3): a lossy
    /// representation needs its exact approximation configured with an accuracy
    /// evaluation.
    Fidelity { refusal: FidelityRefusal },
    /// No qualification exists for this exact model on this exact engine (line 248).
    NotQualified { kv: Box<KvRepresentation> },
    /// The first check, in [`KvCheck::ORDER`], that did not pass.
    CheckNotPassed {
        kv: Box<KvRepresentation>,
        check: KvCheck,
        result: CheckResult,
    },
}

impl fmt::Display for KvFormatRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fidelity { refusal } => write!(f, "{refusal}"),
            Self::NotQualified { kv } => write!(
                f,
                "{} KV has not been checked for this model on this engine; per-model support, \
                 numerical behaviour, cache format and rollback come first",
                kv.dtype().tag()
            ),
            Self::CheckNotPassed {
                kv,
                check,
                result: CheckResult::Failed { .. },
            } => write!(
                f,
                "{} KV cannot be used for this model: its {check} check failed",
                kv.dtype().tag()
            ),
            Self::CheckNotPassed { kv, check, .. } => write!(
                f,
                "{} KV cannot be used for this model: {check} has not been checked",
                kv.dtype().tag()
            ),
        }
    }
}

impl std::error::Error for KvFormatRefusal {}

/// The fidelity category of caching `logical`'s KV as `kv`: a lossless representation
/// where a configuration without approximations accepts it (the model's own dtype or an
/// exact widening, unquantized), approximate inference otherwise (T07, §1.3; line 250).
pub fn kv_fidelity(logical: &LogicalModelSpec, kv: &KvRepresentation) -> FidelityCategory {
    if FidelityConfiguration::lossless_representation()
        .check_kv_representation(logical, kv)
        .is_ok()
    {
        FidelityCategory::LosslessRepresentation
    } else {
        FidelityCategory::ApproximateInference
    }
}

/// Requires the line 248 checks for `kv` on exactly `model` and `engine`: every
/// qualification for that combination must have passed all four, per-model support first,
/// and contradicting qualifications refuse.
pub fn check_kv_qualification(
    model: &LogicalModelIdentity,
    engine: &EngineRef,
    kv: &KvRepresentation,
    qualifications: &[KvFormatQualification],
) -> Result<(), KvFormatRefusal> {
    let mut matching = qualifications.iter().filter(|qualification| {
        qualification.model == *model && qualification.engine == *engine && qualification.kv == *kv
    });
    let first = matching
        .next()
        .ok_or_else(|| KvFormatRefusal::NotQualified {
            kv: Box::new(kv.clone()),
        })?;
    for qualification in std::iter::once(first).chain(matching) {
        if let Some((check, result)) = qualification.first_unpassed() {
            return Err(KvFormatRefusal::CheckNotPassed {
                kv: Box::new(kv.clone()),
                check,
                result,
            });
        }
    }
    Ok(())
}

/// Admits `kv` for `logical` on `engine` under the request's `fidelity` and returns its
/// category. T07's check comes first: a KV of 8 bits or fewer, FP4 included, needs its
/// exact quantization scheme configured, and any other lossy representation its precision
/// reduction. A representation that is not lossless then also needs its line 248
/// qualification.
pub fn admit_kv_representation(
    fidelity: &FidelityConfiguration,
    logical: &LogicalModelSpec,
    engine: &EngineRef,
    kv: &KvRepresentation,
    qualifications: &[KvFormatQualification],
) -> Result<FidelityCategory, KvFormatRefusal> {
    fidelity
        .check_kv_representation(logical, kv)
        .map_err(|refusal| KvFormatRefusal::Fidelity { refusal })?;
    let category = kv_fidelity(logical, kv);
    if category != FidelityCategory::LosslessRepresentation {
        check_kv_qualification(&logical.identity(), engine, kv, qualifications)?;
    }
    Ok(category)
}

/// Hashes every field of a KV representation into an identity.
pub(super) fn feed_kv(builder: DigestBuilder, kv: &KvRepresentation) -> DigestBuilder {
    let builder = builder.str(kv.dtype().tag());
    let builder = match kv.quantization() {
        Quantization::None => builder.str("unquantized"),
        Quantization::Scheme(scheme) => {
            let builder = builder
                .str("scheme")
                .str(scheme.method().name.as_str())
                .str(scheme.method().version.as_str())
                .u64(u64::from(scheme.weight_bits()));
            match scheme.group_size() {
                Some(size) => builder.str("group").u64(u64::from(size)),
                None => builder.str("no_group"),
            }
            .digest(scheme.parameters())
        }
    };
    builder
        .u64(u64::from(kv.block_tokens()))
        .str(kv.layout().name.as_str())
        .str(kv.layout().version.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::model_memory::identity::{
        AccuracyEvaluation, Approximation, Dtype, FidelityConfiguration,
    };
    use crate::model_memory::profiles::testkit::{
        allowing, d, engine, fp4_kv, fp8_kv, kv, logical, logical_spec, lossless, model_kv,
        qualification,
    };

    #[test]
    fn the_models_own_dtype_is_a_lossless_representation() {
        assert_eq!(
            admit_kv_representation(&lossless(), &logical_spec(), &engine(), &model_kv(), &[]),
            Ok(FidelityCategory::LosslessRepresentation)
        );
        // F32 widens BF16 exactly; F16 does not.
        let widened = kv(Dtype::Float32, Quantization::None);
        assert_eq!(
            kv_fidelity(&logical_spec(), &widened),
            FidelityCategory::LosslessRepresentation
        );
        assert_eq!(
            kv_fidelity(&logical_spec(), &kv(Dtype::Float16, Quantization::None)),
            FidelityCategory::ApproximateInference
        );
        for lossy in [fp8_kv(), fp4_kv()] {
            assert_eq!(
                kv_fidelity(&logical_spec(), &lossy),
                FidelityCategory::ApproximateInference
            );
        }
    }

    #[test]
    fn lossy_kv_needs_its_approximation_configured() {
        let Quantization::Scheme(scheme) = fp8_kv().quantization().clone() else {
            panic!("FP8 KV carries its scheme");
        };
        assert_eq!(
            admit_kv_representation(&lossless(), &logical_spec(), &engine(), &fp8_kv(), &[]),
            Err(KvFormatRefusal::Fidelity {
                refusal: FidelityRefusal::NotExplicitlyConfigured {
                    approximation: Approximation::Quantization(scheme)
                }
            })
        );
        // Eight bits or fewer without a scheme is refused by T07 whatever is configured.
        let unscaled = kv(Dtype::Float4E2M1, Quantization::None);
        assert_eq!(
            admit_kv_representation(
                &allowing(&fp4_kv()),
                &logical_spec(),
                &engine(),
                &unscaled,
                &[]
            ),
            Err(KvFormatRefusal::Fidelity {
                refusal: FidelityRefusal::NarrowDtypeWithoutScheme {
                    dtype: Dtype::Float4E2M1
                }
            })
        );
    }

    #[test]
    fn fp4_kv_is_refused_without_per_model_support() {
        let fidelity = allowing(&fp4_kv());
        let admit = |qualifications: &[KvFormatQualification]| {
            admit_kv_representation(
                &fidelity,
                &logical_spec(),
                &engine(),
                &fp4_kv(),
                qualifications,
            )
        };
        // Configured and evaluated under T07, but never qualified for this model.
        assert_eq!(
            admit(&[]),
            Err(KvFormatRefusal::NotQualified {
                kv: Box::new(fp4_kv())
            })
        );
        // Everything else passed, but per-model support was never checked.
        let mut unsupported = qualification(fp4_kv());
        unsupported.per_model_support = CheckResult::NotChecked;
        assert_eq!(
            admit(&[unsupported]),
            Err(KvFormatRefusal::CheckNotPassed {
                kv: Box::new(fp4_kv()),
                check: KvCheck::PerModelSupport,
                result: CheckResult::NotChecked,
            })
        );
        // Per-model support is reported first even when nothing else was checked.
        let nothing = KvFormatQualification {
            per_model_support: CheckResult::Failed { report: d("fp4") },
            numerical_behavior: CheckResult::NotChecked,
            cache_format: CheckResult::NotChecked,
            rollback: CheckResult::NotChecked,
            ..qualification(fp4_kv())
        };
        assert_eq!(
            admit(&[nothing]),
            Err(KvFormatRefusal::CheckNotPassed {
                kv: Box::new(fp4_kv()),
                check: KvCheck::PerModelSupport,
                result: CheckResult::Failed { report: d("fp4") },
            })
        );
        assert_eq!(
            admit(&[qualification(fp4_kv())]),
            Ok(FidelityCategory::ApproximateInference)
        );
    }

    #[test]
    fn fp4_support_for_another_model_or_engine_does_not_carry_over() {
        let mut other_model = qualification(fp4_kv());
        other_model.model = crate::model_memory::identity::LogicalModelSpec {
            tokenizer: d("other tokenizer"),
            ..logical_spec()
        }
        .identity();
        assert_ne!(other_model.model, logical());
        let mut other_engine = qualification(fp4_kv());
        other_engine.engine.image = d("upgraded image");
        let fp8_only = qualification(fp8_kv());
        assert_eq!(
            admit_kv_representation(
                &allowing(&fp4_kv()),
                &logical_spec(),
                &engine(),
                &fp4_kv(),
                &[other_model, other_engine, fp8_only]
            ),
            Err(KvFormatRefusal::NotQualified {
                kv: Box::new(fp4_kv())
            })
        );
    }

    #[test]
    fn every_line_248_check_must_pass() {
        let fidelity = allowing(&fp8_kv());
        for check in KvCheck::ORDER {
            let mut missing = qualification(fp8_kv());
            match check {
                KvCheck::PerModelSupport => missing.per_model_support = CheckResult::NotChecked,
                KvCheck::NumericalBehavior => missing.numerical_behavior = CheckResult::NotChecked,
                KvCheck::CacheFormat => missing.cache_format = CheckResult::NotChecked,
                KvCheck::Rollback => missing.rollback = CheckResult::NotChecked,
            }
            assert_eq!(
                admit_kv_representation(
                    &fidelity,
                    &logical_spec(),
                    &engine(),
                    &fp8_kv(),
                    &[missing]
                ),
                Err(KvFormatRefusal::CheckNotPassed {
                    kv: Box::new(fp8_kv()),
                    check,
                    result: CheckResult::NotChecked,
                }),
                "{check:?}"
            );
        }
    }

    #[test]
    fn contradicting_qualifications_refuse() {
        let mut failed = qualification(fp8_kv());
        failed.numerical_behavior = CheckResult::Failed { report: d("drift") };
        assert_eq!(
            admit_kv_representation(
                &allowing(&fp8_kv()),
                &logical_spec(),
                &engine(),
                &fp8_kv(),
                &[qualification(fp8_kv()), failed]
            ),
            Err(KvFormatRefusal::CheckNotPassed {
                kv: Box::new(fp8_kv()),
                check: KvCheck::NumericalBehavior,
                result: CheckResult::Failed { report: d("drift") },
            })
        );
    }

    #[test]
    fn a_precision_reduction_is_lossy_too() {
        let half = kv(Dtype::Float16, Quantization::None);
        let reduction = Approximation::PrecisionReduction {
            from: Dtype::BFloat16,
            to: Dtype::Float16,
        };
        assert_eq!(
            admit_kv_representation(&lossless(), &logical_spec(), &engine(), &half, &[]),
            Err(KvFormatRefusal::Fidelity {
                refusal: FidelityRefusal::NotExplicitlyConfigured {
                    approximation: reduction.clone()
                }
            })
        );
        let configured = FidelityConfiguration::approximate_inference(BTreeMap::from([(
            reduction,
            AccuracyEvaluation {
                report: d("f16 accuracy"),
            },
        )]))
        .unwrap();
        assert_eq!(
            admit_kv_representation(&configured, &logical_spec(), &engine(), &half, &[]),
            Err(KvFormatRefusal::NotQualified {
                kv: Box::new(half.clone())
            })
        );
        assert_eq!(
            admit_kv_representation(
                &configured,
                &logical_spec(),
                &engine(),
                &half,
                &[qualification(half.clone())]
            ),
            Ok(FidelityCategory::ApproximateInference)
        );
    }

    #[test]
    fn check_results_refuse_unknown_fields() {
        assert_eq!(
            serde_json::from_str::<CheckResult>(r#"{"outcome":"not_checked"}"#).unwrap(),
            CheckResult::NotChecked
        );
        assert!(
            serde_json::from_str::<CheckResult>(r#"{"outcome":"not_checked","report":"00"}"#)
                .is_err()
        );
        assert_eq!(
            serde_json::to_string(&CheckResult::NotChecked).unwrap(),
            r#"{"outcome":"not_checked"}"#
        );
    }

    #[test]
    fn refusals_explain_themselves() {
        let text = KvFormatRefusal::CheckNotPassed {
            kv: Box::new(fp4_kv()),
            check: KvCheck::PerModelSupport,
            result: CheckResult::NotChecked,
        }
        .to_string();
        assert_eq!(
            text,
            "f4e2m1 KV cannot be used for this model: per-model support has not been checked"
        );
        assert!(KvFormatRefusal::NotQualified {
            kv: Box::new(fp8_kv())
        }
        .to_string()
        .contains("per-model support"));
    }
}
