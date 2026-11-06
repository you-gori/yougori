//! Fidelity categories (§1.3: "Lossless representation, exact reuse and approximate
//! inference are separate categories. Quantization, alternate models, sparse
//! approximation or changed context semantics need explicit configuration and accuracy
//! evaluation. They cannot hide under a memory setting").
//!
//! A [`FidelityConfiguration`] fixes the category explicitly, and every approximation it
//! allows names its accuracy evaluation. [`MemorySettings`] carry budgets and the
//! representation or reuse techniques memory management may use. They never add an
//! approximation and never move the configured category.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::Digest;

use super::error::IdentityError;
use super::fields::{Dtype, KvRepresentation, Quantization, QuantizationScheme, VersionedName};
use super::layers::{LogicalModelIdentity, LogicalModelSpec, SourceIdentity, SourceSpec};

/// The three separate categories of §1.3, in the order of what a configuration allows:
/// each allows the techniques of the categories before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FidelityCategory {
    /// The same values in another encoding, layout or tier.
    LosslessRepresentation,
    /// State computed earlier under a matching identity, used again.
    ExactReuse,
    /// Results may differ from the reference model.
    ApproximateInference,
}

impl FidelityCategory {
    pub const ALL: [Self; 3] = [
        Self::LosslessRepresentation,
        Self::ExactReuse,
        Self::ApproximateInference,
    ];
}

impl fmt::Display for FidelityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LosslessRepresentation => "lossless representation",
            Self::ExactReuse => "exact reuse",
            Self::ApproximateInference => "approximate inference",
        })
    }
}

/// A technique and the one category it belongs to (§1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Technique {
    LosslessCompression,
    LayoutConversion,
    /// Exact bytes moved to host memory or disk.
    TierOffload,
    /// A clean GPU copy dropped because a verified reconstructible copy exists.
    DropReconstructibleCopy,
    PrefixKvReuse,
    /// KV restored from host memory or disk under its scope key (FAST-03).
    KvTierRestore,
    CudaGraphReuse,
    CompiledStateReuse,
    /// Exact intermediate state of a shared subgraph, computed once for variants that
    /// provably share it (GPU §4.16, line 894).
    SharedSubgraphReuse,
    Quantization,
    AlternateModel,
    SparseApproximation,
    ChangedContextSemantics,
}

impl Technique {
    pub const ALL: [Self; 13] = [
        Self::LosslessCompression,
        Self::LayoutConversion,
        Self::TierOffload,
        Self::DropReconstructibleCopy,
        Self::PrefixKvReuse,
        Self::KvTierRestore,
        Self::CudaGraphReuse,
        Self::CompiledStateReuse,
        Self::SharedSubgraphReuse,
        Self::Quantization,
        Self::AlternateModel,
        Self::SparseApproximation,
        Self::ChangedContextSemantics,
    ];

    /// The one category this technique belongs to (§1.3).
    pub const fn category(self) -> FidelityCategory {
        match self {
            Self::LosslessCompression
            | Self::LayoutConversion
            | Self::TierOffload
            | Self::DropReconstructibleCopy => FidelityCategory::LosslessRepresentation,
            Self::PrefixKvReuse
            | Self::KvTierRestore
            | Self::CudaGraphReuse
            | Self::CompiledStateReuse
            | Self::SharedSubgraphReuse => FidelityCategory::ExactReuse,
            Self::Quantization
            | Self::AlternateModel
            | Self::SparseApproximation
            | Self::ChangedContextSemantics => FidelityCategory::ApproximateInference,
        }
    }
}

/// One explicitly configured approximation, exact enough that its accuracy evaluation
/// applies to it alone (§1.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Approximation {
    Quantization(QuantizationScheme),
    /// A conversion that is not an exact widening: weights computed in another dtype than
    /// the published one, or KV stored in another dtype than the model's, such as F32 to
    /// BF16, BF16 to F16 or any integer conversion. Quantization without a scheme.
    PrecisionReduction {
        from: Dtype,
        to: Dtype,
    },
    /// Another model served in place of the requested one.
    AlternateModel(LogicalModelIdentity),
    SparseApproximation(VersionedName),
    ChangedContextSemantics(VersionedName),
}

impl Approximation {
    /// The technique this approximation is an instance of.
    pub fn technique(&self) -> Technique {
        match self {
            Self::Quantization(_) | Self::PrecisionReduction { .. } => Technique::Quantization,
            Self::AlternateModel(_) => Technique::AlternateModel,
            Self::SparseApproximation(_) => Technique::SparseApproximation,
            Self::ChangedContextSemantics(_) => Technique::ChangedContextSemantics,
        }
    }
}

/// The accuracy evaluation an approximation needs (§1.3): the digest of its report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccuracyEvaluation {
    pub report: Digest,
}

/// The explicitly configured fidelity of a serving configuration (§1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidelityConfiguration {
    category: FidelityCategory,
    approximations: BTreeMap<Approximation, AccuracyEvaluation>,
}

/// Memory budgets and the techniques memory management may use (§1.3 "memory
/// setting"). Budgets have no part in fidelity; techniques must stay within the
/// configured category and never approximate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemorySettings {
    pub gpu_memory_target_bytes: u64,
    pub kv_cache_bytes: u64,
    pub pinned_host_bytes: u64,
    pub disk_quota_bytes: u64,
    pub techniques: BTreeSet<Technique>,
}

/// Why a fidelity configuration or its use was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FidelityRefusal {
    /// An approximate-inference configuration must name what it approximates.
    NoApproximationListed,
    /// A memory setting tried to add an approximation (§1.3).
    MemorySettingApproximates { technique: Technique },
    /// A memory setting tried to use a technique beyond the configured category.
    MemorySettingExceedsCategory {
        technique: Technique,
        configured: FidelityCategory,
    },
    /// An approximation is in use without explicit configuration and evaluation.
    NotExplicitlyConfigured { approximation: Approximation },
    /// Values of 8 bits or fewer are quantized; they need an exact scheme to configure.
    NarrowDtypeWithoutScheme { dtype: Dtype },
    /// The source spec given for a check has no identity.
    InvalidSource(IdentityError),
    /// The source spec given for a check is not the logical model's source.
    SourceMismatch {
        logical_source: SourceIdentity,
        given_source: SourceIdentity,
    },
}

impl fmt::Display for FidelityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoApproximationListed => {
                f.write_str("an approximate-inference configuration lists no approximation")
            }
            Self::MemorySettingApproximates { technique } => write!(
                f,
                "{technique:?} is an approximation; it needs explicit configuration, not a memory setting"
            ),
            Self::MemorySettingExceedsCategory {
                technique,
                configured,
            } => write!(
                f,
                "{technique:?} is {}; the configuration allows only {configured}",
                technique.category()
            ),
            Self::NotExplicitlyConfigured { approximation } => write!(
                f,
                "{:?} needs explicit configuration and an accuracy evaluation",
                approximation.technique()
            ),
            Self::NarrowDtypeWithoutScheme { dtype } => write!(
                f,
                "{} values are quantized; name the exact quantization scheme",
                dtype.tag()
            ),
            Self::InvalidSource(error) => write!(f, "the source spec is invalid: {error}"),
            Self::SourceMismatch {
                logical_source,
                given_source,
            } => write!(
                f,
                "the logical model's source is {logical_source}, not the given {given_source}"
            ),
        }
    }
}

impl std::error::Error for FidelityRefusal {}

impl FidelityConfiguration {
    /// Only lossless representation changes.
    pub fn lossless_representation() -> Self {
        Self {
            category: FidelityCategory::LosslessRepresentation,
            approximations: BTreeMap::new(),
        }
    }

    /// Lossless representation changes and exact reuse.
    pub fn exact_reuse() -> Self {
        Self {
            category: FidelityCategory::ExactReuse,
            approximations: BTreeMap::new(),
        }
    }

    /// Approximate inference limited to the listed approximations, each with its
    /// accuracy evaluation. At least one.
    pub fn approximate_inference(
        approximations: BTreeMap<Approximation, AccuracyEvaluation>,
    ) -> Result<Self, FidelityRefusal> {
        if approximations.is_empty() {
            return Err(FidelityRefusal::NoApproximationListed);
        }
        Ok(Self {
            category: FidelityCategory::ApproximateInference,
            approximations,
        })
    }

    /// The configured category, which no memory setting changes.
    pub fn category(&self) -> FidelityCategory {
        self.category
    }

    /// The configured approximations with their accuracy evaluations.
    pub fn approximations(&self) -> &BTreeMap<Approximation, AccuracyEvaluation> {
        &self.approximations
    }

    /// The category in effect under `memory`: always the configured one. A memory
    /// setting that would approximate or exceed the category is refused rather than
    /// allowed to change it (§1.3).
    pub fn resolve(&self, memory: &MemorySettings) -> Result<FidelityCategory, FidelityRefusal> {
        let mut techniques = memory.techniques.iter().copied();
        if let Some(technique) = techniques
            .clone()
            .find(|technique| technique.category() == FidelityCategory::ApproximateInference)
        {
            return Err(FidelityRefusal::MemorySettingApproximates { technique });
        }
        if let Some(technique) = techniques.find(|technique| technique.category() > self.category) {
            return Err(FidelityRefusal::MemorySettingExceedsCategory {
                technique,
                configured: self.category,
            });
        }
        Ok(self.category)
    }

    /// The accuracy evaluation of an explicitly configured approximation.
    pub fn require(
        &self,
        approximation: &Approximation,
    ) -> Result<&AccuracyEvaluation, FidelityRefusal> {
        self.approximations.get(approximation).ok_or_else(|| {
            FidelityRefusal::NotExplicitlyConfigured {
                approximation: approximation.clone(),
            }
        })
    }

    /// Checks a logical model against its own source (§1.3). Quantized weights need their
    /// exact scheme configured explicitly, and weights of 8 bits or fewer count as
    /// quantized. A dtype of 16 bits or more other than the published one needs a
    /// configured [`Approximation::PrecisionReduction`] unless it widens exactly.
    pub fn check_logical_model(
        &self,
        source: &SourceSpec,
        logical: &LogicalModelSpec,
    ) -> Result<(), FidelityRefusal> {
        let given_source = source.identity().map_err(FidelityRefusal::InvalidSource)?;
        if logical.source != given_source {
            return Err(FidelityRefusal::SourceMismatch {
                logical_source: logical.source,
                given_source,
            });
        }
        self.check_quantization(logical.dtype, &logical.quantization)?;
        self.check_precision(source.published_dtype, logical.dtype)
    }

    /// Checks a KV representation against the model it caches (§1.3). A quantized KV
    /// representation needs its exact scheme configured explicitly, and KV entries of 8
    /// bits or fewer count as quantized. A KV dtype of 16 bits or more other than the
    /// model's dtype needs a configured [`Approximation::PrecisionReduction`] unless it
    /// widens exactly.
    pub fn check_kv_representation(
        &self,
        logical: &LogicalModelSpec,
        kv: &KvRepresentation,
    ) -> Result<(), FidelityRefusal> {
        self.check_quantization(kv.dtype(), kv.quantization())?;
        self.check_precision(logical.dtype, kv.dtype())
    }

    /// Serving another model than the one requested needs that alternate configured
    /// explicitly; identities decide, never names.
    pub fn check_served_model(
        &self,
        requested: &LogicalModelIdentity,
        served: &LogicalModelIdentity,
    ) -> Result<(), FidelityRefusal> {
        if requested == served {
            return Ok(());
        }
        self.require(&Approximation::AlternateModel(*served))
            .map(|_| ())
    }

    /// Converting `from` to `to` needs a configured precision reduction unless `to` is
    /// the same or an exact widening. A `to` of 8 bits or fewer is covered by its
    /// quantization scheme, which `check_quantization` requires.
    fn check_precision(&self, from: Dtype, to: Dtype) -> Result<(), FidelityRefusal> {
        if to.bits() <= 8 || from == to || from.widens_exactly_to(to) {
            return Ok(());
        }
        self.require(&Approximation::PrecisionReduction { from, to })
            .map(|_| ())
    }

    fn check_quantization(
        &self,
        dtype: Dtype,
        quantization: &Quantization,
    ) -> Result<(), FidelityRefusal> {
        match quantization {
            Quantization::None if dtype.bits() <= 8 => {
                Err(FidelityRefusal::NarrowDtypeWithoutScheme { dtype })
            }
            Quantization::None => Ok(()),
            Quantization::Scheme(scheme) => self
                .require(&Approximation::Quantization(scheme.clone()))
                .map(|_| ()),
        }
    }
}
