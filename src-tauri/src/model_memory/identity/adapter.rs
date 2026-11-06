//! Adapters (§3.2 items 2 and 6) and the LoRA rule of §1.1, line 308.
//!
//! LoRA keeps an immutable base with unmerged adapters, or gives a merged variant its
//! own identity. Floating-point subtraction is not a bit-exact undo, so a merged variant
//! is never turned back into a model without that adapter by subtracting it; the target
//! is loaded from its own immutable artifact instead.

use std::fmt;

use super::encoding::{identity_type, Encode, Encoding, ADAPTER_DOMAIN};
use super::error::IdentityError;
use super::fields::{Dtype, VersionedName};
use super::layers::{LogicalModelIdentity, LogicalModelSpec, SourceIdentity};

identity_type!(
    /// An adapter's own identity: its source, method and dtype (§3.2 items 2 and 6).
    /// Built only by [`AdapterSpec::identity`].
    AdapterIdentity
);

/// The typed inputs of an [`AdapterIdentity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterSpec {
    /// The adapter's own source. Its configuration digest covers rank, alpha and target
    /// modules.
    pub source: SourceIdentity,
    /// The adapter method and its version, such as LoRA.
    pub method: VersionedName,
    pub dtype: Dtype,
}

impl AdapterSpec {
    /// The adapter's identity, under its own domain.
    pub fn identity(&self) -> AdapterIdentity {
        AdapterIdentity(self.canonical().finish(ADAPTER_DOMAIN))
    }

    pub(crate) fn canonical(&self) -> Encoding {
        let mut out = Encoding::new();
        out.item(&self.source).item(&self.method).item(&self.dtype);
        out
    }
}

/// The exact scale an adapter is merged with, kept as its IEEE 754 bits (§1.1, line
/// 308). Finite and not zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MergeScale {
    bits: u64,
}

impl MergeScale {
    /// Refuses zero, NaN and infinite scales.
    pub fn new(scale: f64) -> Result<Self, IdentityError> {
        if !scale.is_finite() || scale == 0.0 {
            return Err(IdentityError::InvalidMergeScale);
        }
        Ok(Self {
            bits: scale.to_bits(),
        })
    }

    pub fn get(self) -> f64 {
        f64::from_bits(self.bits)
    }
}

/// One adapter merged into the weights: which adapter, at what scale and by which merge
/// procedure (§3.2 item 2 "adapter recipe"). Rounding depends on the procedure, so it is
/// part of the identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MergedAdapter {
    pub adapter: AdapterIdentity,
    pub scale: MergeScale,
    pub procedure: VersionedName,
}

impl Encode for MergedAdapter {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.adapter)
            .u64(self.scale.bits)
            .item(&self.procedure);
    }
}

/// The adapters merged into a variant, in merge order: floating-point addition is not
/// associative, so the order is part of the identity. At least one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MergedAdapters(Vec<MergedAdapter>);

impl MergedAdapters {
    /// Adapters in merge order. Refuses an empty list.
    pub fn new(adapters: Vec<MergedAdapter>) -> Result<Self, IdentityError> {
        if adapters.is_empty() {
            return Err(IdentityError::NoMergedAdapters);
        }
        Ok(Self(adapters))
    }

    pub fn adapters(&self) -> &[MergedAdapter] {
        &self.0
    }

    pub(crate) fn single(adapter: MergedAdapter) -> Self {
        Self(vec![adapter])
    }

    pub(crate) fn then(&self, adapter: MergedAdapter) -> Self {
        let mut adapters = self.0.clone();
        adapters.push(adapter);
        Self(adapters)
    }
}

impl Encode for MergedAdapters {
    fn encode(&self, out: &mut Encoding) {
        out.list(&self.0);
    }
}

/// Which adapters a logical model has merged into its weights (§3.2 item 2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AdapterRecipe {
    /// The base weights as published; unmerged adapters attach per session.
    None,
    /// A separate merged variant with its own identity (§1.1, line 308).
    Merged(MergedAdapters),
}

impl Encode for AdapterRecipe {
    fn encode(&self, out: &mut Encoding) {
        match self {
            Self::None => {
                out.tag("none");
            }
            Self::Merged(merged) => {
                out.tag("merged").item(merged);
            }
        }
    }
}

/// A model as a session runs it: a logical model and at most one unmerged adapter
/// (§1.1, line 308; §3.2 item 6 "adapter").
///
/// An unmerged adapter never touches the base weights, so detaching it is exact. Merging
/// gives a separate variant; subtracting a merged adapter is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptedModel {
    pub logical: LogicalModelSpec,
    pub unmerged: Option<AdapterIdentity>,
}

/// A proposed change to the adapters of an [`AdaptedModel`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterChange {
    AttachUnmerged(AdapterIdentity),
    DetachUnmerged,
    /// Make a merged variant with its own identity.
    Merge(MergedAdapter),
    /// Subtract a merged adapter from merged weights. Always refused, because
    /// floating-point subtraction is not a bit-exact undo (§1.1, line 308).
    SubtractMerged(AdapterIdentity),
}

/// Why an [`AdapterChange`] was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoraRefusal {
    /// Only one unmerged adapter is attached at a time; detach it first.
    AlreadyAttached {
        attached: AdapterIdentity,
    },
    NothingAttached,
    NotMerged {
        adapter: AdapterIdentity,
    },
    /// Merge-then-subtract is not an exact undo. Load `load_instead` from its own
    /// immutable artifact: the variant without that adapter, or the base itself.
    SubtractionIsNotExactUndo {
        load_instead: LogicalModelIdentity,
    },
}

impl fmt::Display for LoraRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyAttached { attached } => {
                write!(f, "unmerged adapter {attached} is already attached")
            }
            Self::NothingAttached => f.write_str("no unmerged adapter is attached"),
            Self::NotMerged { adapter } => write!(f, "adapter {adapter} is not merged"),
            Self::SubtractionIsNotExactUndo { load_instead } => write!(
                f,
                "subtracting a merged adapter is not a bit-exact undo; load {load_instead} from its own artifact"
            ),
        }
    }
}

impl std::error::Error for LoraRefusal {}

impl AdaptedModel {
    /// A logical model with no unmerged adapter attached.
    pub fn base(logical: LogicalModelSpec) -> Self {
        Self {
            logical,
            unmerged: None,
        }
    }

    /// Applies `change`, returning the new model; `self` is never modified.
    pub fn apply(&self, change: &AdapterChange) -> Result<Self, LoraRefusal> {
        match change {
            AdapterChange::AttachUnmerged(adapter) => match self.unmerged {
                Some(attached) => Err(LoraRefusal::AlreadyAttached { attached }),
                None => Ok(Self {
                    logical: self.logical.clone(),
                    unmerged: Some(*adapter),
                }),
            },
            AdapterChange::DetachUnmerged => match self.unmerged {
                None => Err(LoraRefusal::NothingAttached),
                Some(_) => Ok(Self {
                    logical: self.logical.clone(),
                    unmerged: None,
                }),
            },
            AdapterChange::Merge(adapter) => Ok(Self {
                logical: self.logical.with_merged(adapter.clone()),
                unmerged: self.unmerged,
            }),
            AdapterChange::SubtractMerged(adapter) => Err(self.refuse_subtraction(adapter)),
        }
    }

    fn refuse_subtraction(&self, adapter: &AdapterIdentity) -> LoraRefusal {
        let AdapterRecipe::Merged(merged) = &self.logical.adapters else {
            return LoraRefusal::NotMerged { adapter: *adapter };
        };
        let Some(index) = merged
            .adapters()
            .iter()
            .rposition(|entry| entry.adapter == *adapter)
        else {
            return LoraRefusal::NotMerged { adapter: *adapter };
        };
        let remaining = merged
            .adapters()
            .iter()
            .enumerate()
            .filter(|(position, _)| *position != index)
            .map(|(_, entry)| entry.clone())
            .collect();
        let adapters = match MergedAdapters::new(remaining) {
            Ok(merged) => AdapterRecipe::Merged(merged),
            Err(_) => AdapterRecipe::None,
        };
        let target = LogicalModelSpec {
            adapters,
            ..self.logical.clone()
        };
        LoraRefusal::SubtractionIsNotExactUndo {
            load_instead: target.identity(),
        }
    }
}
