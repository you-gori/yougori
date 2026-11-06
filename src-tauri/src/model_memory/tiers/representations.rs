//! Representations and their space budget across tiers (GPU §3.4 lines 548–550).
//!
//! A model's representations are its original, a raw prepared form, a compressed
//! prepared form and a host copy, held in local storage or host RAM. Keeping all of them
//! routinely multiplies space, so without an explicit space budget a model keeps one
//! representation; with one, everything the store holds fits within it. A derived
//! representation is admitted only when its forecast satisfies the catalog's
//! [`ImportAmortization`] (line 550) and is kept only while its measured reuse does
//! (line 548). When room is needed, derived representations leave in order of measured
//! reuse value per retained byte, least first, and only when what they are worth together
//! is less than what the newcomer is worth.
//!
//! The store plans; it deletes nothing. A planned eviction in local storage is carried
//! out by the catalog's cache eviction (through
//! [`LocalStorageTier::evict_cache`](super::local::LocalStorageTier::evict_cache)), which
//! itself refuses an original, a leased object or a dependency (line 552); one in host
//! RAM by the pinned or reclaimable tier. In local storage only derived representations
//! that the pool's catalog lists among its eviction candidates now are planned, so an
//! original is never planned, whether the store or the catalog is asked. Each tier's own
//! accounting applies on top of this budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::amortization::ReuseRecord;
use super::object::ObjectRef;
use super::Tier;
use crate::foundation::catalog::{AmortizationError, Catalog, ImportAmortization, ObjectId, Scope};
use crate::foundation::ids::{Clock, Digest};
use crate::model_memory::identity::LogicalModelIdentity;
use crate::model_memory::math::{positive, InputError};

/// One model within the scope that owns it. Its representations are objects of the same
/// scope (lines 546–548).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelKey {
    pub scope: Scope,
    /// The digest of the model's logical identity (T07, §3.2 item 2).
    pub model: Digest,
}

impl ModelKey {
    /// The model with this logical identity, in `scope`.
    pub fn logical(scope: Scope, identity: &LogicalModelIdentity) -> Self {
        Self {
            scope,
            model: *identity.digest(),
        }
    }
}

impl fmt::Display for ModelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model {} of {}", self.model, self.scope)
    }
}

/// The representations of line 548.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationKind {
    /// The user's model as imported; never evicted (line 552).
    Original,
    RawPrepared,
    CompressedPrepared,
    HostCopy,
}

impl RepresentationKind {
    pub const ALL: [Self; 4] = [
        Self::Original,
        Self::RawPrepared,
        Self::CompressedPrepared,
        Self::HostCopy,
    ];

    /// The derived kind, or `None` for the original.
    pub const fn derived(self) -> Option<DerivedKind> {
        match self {
            Self::Original => None,
            Self::RawPrepared => Some(DerivedKind::RawPrepared),
            Self::CompressedPrepared => Some(DerivedKind::CompressedPrepared),
            Self::HostCopy => Some(DerivedKind::HostCopy),
        }
    }

    /// The tiers that may hold this kind (table lines 540–542): originals and prepared
    /// artifacts in local storage, host copies in pinned or reclaimable host RAM.
    pub const fn tiers(self) -> &'static [Tier] {
        match self {
            Self::Original | Self::RawPrepared | Self::CompressedPrepared => &[Tier::LocalStorage],
            Self::HostCopy => &[Tier::PinnedHost, Tier::ReclaimableHost],
        }
    }
}

/// A representation derived from the original: the only kinds an eviction can name
/// (line 552).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedKind {
    RawPrepared,
    CompressedPrepared,
    HostCopy,
}

impl DerivedKind {
    pub const fn kind(self) -> RepresentationKind {
        match self {
            Self::RawPrepared => RepresentationKind::RawPrepared,
            Self::CompressedPrepared => RepresentationKind::CompressedPrepared,
            Self::HostCopy => RepresentationKind::HostCopy,
        }
    }
}

/// The explicit space budget of line 548.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "budget", rename_all = "snake_case")]
pub enum SpaceBudget {
    /// No explicit budget: each model keeps one representation.
    Unset,
    /// Everything the store holds fits within `max_bytes`.
    Explicit { max_bytes: u64 },
}

/// A representation offered to the store.
#[derive(Clone, Debug, PartialEq)]
pub enum RepresentationProposal {
    /// The model's original, kept in local storage; it need not amortize.
    Original {
        model: ModelKey,
        object: ObjectRef,
        bytes: u64,
    },
    /// A derived representation and the forecast it must amortize (line 550).
    Derived {
        model: ModelKey,
        object: ObjectRef,
        kind: DerivedKind,
        tier: Tier,
        bytes: u64,
        forecast: ImportAmortization,
    },
}

impl RepresentationProposal {
    pub fn model(&self) -> &ModelKey {
        match self {
            Self::Original { model, .. } | Self::Derived { model, .. } => model,
        }
    }

    pub fn object(&self) -> &ObjectRef {
        match self {
            Self::Original { object, .. } | Self::Derived { object, .. } => object,
        }
    }

    pub fn kind(&self) -> RepresentationKind {
        match self {
            Self::Original { .. } => RepresentationKind::Original,
            Self::Derived { kind, .. } => kind.kind(),
        }
    }

    pub fn tier(&self) -> Tier {
        match self {
            Self::Original { .. } => Tier::LocalStorage,
            Self::Derived { tier, .. } => *tier,
        }
    }

    pub fn bytes(&self) -> u64 {
        match self {
            Self::Original { bytes, .. } | Self::Derived { bytes, .. } => *bytes,
        }
    }
}

/// A representation the store holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRepresentation {
    pub model: ModelKey,
    pub kind: RepresentationKind,
    pub object: ObjectRef,
    pub tier: Tier,
    pub bytes: u64,
}

/// One derived representation to evict, and the tier that carries it out: the catalog's
/// cache eviction for local storage, the pinned or reclaimable tier for a host copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedEviction {
    pub model: ModelKey,
    pub object: ObjectRef,
    pub kind: DerivedKind,
    pub tier: Tier,
    pub bytes: u64,
}

/// What [`RepresentationStore::enforce_budget`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetEnforcement {
    /// Evictions to carry out, least measured value per byte first.
    pub evictions: Vec<PlannedEviction>,
    /// Bytes still over the budget afterwards: held by originals and by representations
    /// the catalog would not evict now. Originals are never evicted to meet it.
    pub unmet_bytes: u64,
}

/// Why a representation was refused or could not be made room for (lines 548–550).
#[derive(Clone, Debug, PartialEq)]
pub enum RepresentationRefusal {
    Input(InputError),
    Amortization(AmortizationError),
    ZeroBytes,
    /// A representation is an object of its model's scope.
    ScopeMismatch {
        model: Scope,
        object: Scope,
    },
    /// The kind may not live in that tier.
    WrongTier {
        kind: RepresentationKind,
        tier: Tier,
    },
    /// The model already holds this kind.
    AlreadyHeld {
        kind: RepresentationKind,
    },
    /// The object is already held as another representation; it is not a second one.
    SameObjectAsHeld {
        kind: RepresentationKind,
    },
    /// The forecast does not satisfy line 550.
    DoesNotAmortize {
        expected_saving_seconds: f64,
        total_cost_seconds: f64,
    },
    /// Without an explicit space budget a model keeps one representation (line 548).
    NoExplicitBudget {
        held: RepresentationKind,
    },
    /// The budget cannot be unset while a model holds more than one representation.
    SeveralRepresentationsHeld {
        model: ModelKey,
    },
    /// The representation does not fit the explicit budget.
    OverBudget {
        max_bytes: u64,
        held_bytes: u64,
        requested_bytes: u64,
    },
    /// Evicting everything the catalog would evict still leaves too little room.
    NoRoom {
        needed_bytes: u64,
        evictable_bytes: u64,
    },
    /// The representations that would leave are worth at least as much, by measured
    /// reuse, as the newcomer is forecast to be.
    DisplacementNotWorthIt {
        displaced_value_seconds: f64,
        newcomer_value_seconds: f64,
    },
    /// The store holds no such representation.
    NotHeld {
        model: ModelKey,
        kind: RepresentationKind,
    },
    /// A byte total does not fit in 64 bits.
    Overflow,
}

impl From<InputError> for RepresentationRefusal {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<AmortizationError> for RepresentationRefusal {
    fn from(error: AmortizationError) -> Self {
        Self::Amortization(error)
    }
}

impl fmt::Display for RepresentationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Amortization(error) => error.fmt(f),
            Self::ZeroBytes => f.write_str("a representation has at least one byte"),
            Self::ScopeMismatch { model, object } => write!(
                f,
                "a representation of a model of {model} is an object of the same scope, not \
                 of {object}"
            ),
            Self::WrongTier { kind, tier } => write!(f, "{kind:?} may not live in {tier}"),
            Self::AlreadyHeld { kind } => write!(f, "the model already holds {kind:?}"),
            Self::SameObjectAsHeld { kind } => {
                write!(f, "this object is already held as {kind:?}")
            }
            Self::DoesNotAmortize {
                expected_saving_seconds,
                total_cost_seconds,
            } => write!(
                f,
                "expected uses times saving ({expected_saving_seconds} s) does not exceed \
                 preparation cost plus retention penalty ({total_cost_seconds} s)"
            ),
            Self::NoExplicitBudget { held } => write!(
                f,
                "the model already holds {held:?}; another representation needs an explicit \
                 space budget"
            ),
            Self::SeveralRepresentationsHeld { model } => write!(
                f,
                "{model} holds more than one representation, so the budget cannot be unset"
            ),
            Self::OverBudget {
                max_bytes,
                held_bytes,
                requested_bytes,
            } => write!(
                f,
                "{requested_bytes} more bytes do not fit: {held_bytes} of {max_bytes} are held"
            ),
            Self::NoRoom {
                needed_bytes,
                evictable_bytes,
            } => write!(
                f,
                "{needed_bytes} bytes are needed but only {evictable_bytes} may be evicted; \
                 originals are never evicted"
            ),
            Self::DisplacementNotWorthIt {
                displaced_value_seconds,
                newcomer_value_seconds,
            } => write!(
                f,
                "the representations that would leave are worth {displaced_value_seconds} s, \
                 not less than the newcomer's {newcomer_value_seconds} s"
            ),
            Self::NotHeld { model, kind } => write!(f, "{model} holds no {kind:?}"),
            Self::Overflow => f.write_str("a byte total does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for RepresentationRefusal {}

/// Benefit minus cost: what a representation is worth over the horizon.
fn net_seconds(terms: &ImportAmortization) -> Result<f64, AmortizationError> {
    Ok(terms.expected_saving_seconds()? - terms.total_cost_seconds()?)
}

#[derive(Clone, Debug, PartialEq)]
struct Held {
    object: ObjectRef,
    tier: Tier,
    bytes: u64,
    preparation_cost_seconds: f64,
    retention_penalty_seconds: f64,
    reuse: ReuseRecord,
}

type Slot = (ModelKey, RepresentationKind);

struct Candidate {
    model: ModelKey,
    kind: DerivedKind,
    object: ObjectRef,
    tier: Tier,
    bytes: u64,
    measured: ImportAmortization,
    /// Measured expected saving minus preparation cost and retention penalty.
    value_seconds: f64,
}

/// Representations under one space budget (GPU §3.4 lines 548–550): one store per pool,
/// whose catalog it consults for local storage, with that pool's host copies.
#[derive(Clone, Debug, PartialEq)]
pub struct RepresentationStore {
    budget: SpaceBudget,
    horizon_seconds: f64,
    held: BTreeMap<Slot, Held>,
    held_bytes: u64,
}

impl RepresentationStore {
    /// `horizon_seconds` is the horizon over which expected uses and retention penalties
    /// are stated, for forecasts and measurements alike.
    pub fn new(budget: SpaceBudget, horizon_seconds: f64) -> Result<Self, RepresentationRefusal> {
        Ok(Self {
            budget,
            horizon_seconds: positive("horizon_seconds", horizon_seconds)?,
            held: BTreeMap::new(),
            held_bytes: 0,
        })
    }

    pub fn budget(&self) -> SpaceBudget {
        self.budget
    }

    pub fn horizon_seconds(&self) -> f64 {
        self.horizon_seconds
    }

    /// Changes the budget. A smaller explicit budget is met by
    /// [`RepresentationStore::enforce_budget`]; unsetting it is refused while any model
    /// holds more than one representation.
    pub fn set_budget(&mut self, budget: SpaceBudget) -> Result<(), RepresentationRefusal> {
        if budget == SpaceBudget::Unset {
            let mut seen = BTreeSet::new();
            for (model, _) in self.held.keys() {
                if !seen.insert(model) {
                    return Err(RepresentationRefusal::SeveralRepresentationsHeld {
                        model: model.clone(),
                    });
                }
            }
        }
        self.budget = budget;
        Ok(())
    }

    /// Bytes of every representation held, each counted once.
    pub fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// Every representation held, in model and kind order.
    pub fn representations(&self) -> Vec<HeldRepresentation> {
        self.held
            .iter()
            .map(|((model, kind), held)| HeldRepresentation {
                model: model.clone(),
                kind: *kind,
                object: held.object.clone(),
                tier: held.tier,
                bytes: held.bytes,
            })
            .collect()
    }

    /// The representations of one model.
    pub fn representations_of(&self, model: &ModelKey) -> Vec<HeldRepresentation> {
        self.representations()
            .into_iter()
            .filter(|held| held.model == *model)
            .collect()
    }

    /// Admits a representation that fits as things stand; it never evicts. Use
    /// [`RepresentationStore::plan_room`] to find evictions that would make it fit.
    pub fn admit(
        &mut self,
        proposal: RepresentationProposal,
        clock: &dyn Clock,
    ) -> Result<(), RepresentationRefusal> {
        self.validate(&proposal)?;
        let bytes = proposal.bytes();
        let total = self
            .held_bytes
            .checked_add(bytes)
            .ok_or(RepresentationRefusal::Overflow)?;
        match self.budget {
            SpaceBudget::Unset => {
                if let Some(held) = self.kinds_of(proposal.model()).first() {
                    return Err(RepresentationRefusal::NoExplicitBudget { held: *held });
                }
            }
            SpaceBudget::Explicit { max_bytes } => {
                if total > max_bytes {
                    return Err(RepresentationRefusal::OverBudget {
                        max_bytes,
                        held_bytes: self.held_bytes,
                        requested_bytes: bytes,
                    });
                }
            }
        }
        let (slot, held) = match proposal {
            RepresentationProposal::Original {
                model,
                object,
                bytes,
            } => (
                (model, RepresentationKind::Original),
                Held {
                    object,
                    tier: Tier::LocalStorage,
                    bytes,
                    preparation_cost_seconds: 0.0,
                    retention_penalty_seconds: 0.0,
                    reuse: ReuseRecord::new(clock),
                },
            ),
            RepresentationProposal::Derived {
                model,
                object,
                kind,
                tier,
                bytes,
                forecast,
            } => (
                (model, kind.kind()),
                Held {
                    object,
                    tier,
                    bytes,
                    preparation_cost_seconds: forecast.preparation_cost_seconds,
                    retention_penalty_seconds: forecast.retention_penalty_seconds,
                    reuse: ReuseRecord::new(clock),
                },
            ),
        };
        self.held.insert(slot, held);
        self.held_bytes = total;
        Ok(())
    }

    /// Records one measured use of a held representation and the saving measured for it.
    pub fn record_use(
        &mut self,
        model: &ModelKey,
        kind: RepresentationKind,
        saved_seconds: f64,
        clock: &dyn Clock,
    ) -> Result<(), RepresentationRefusal> {
        let held = self.held.get_mut(&(model.clone(), kind)).ok_or_else(|| {
            RepresentationRefusal::NotHeld {
                model: model.clone(),
                kind,
            }
        })?;
        held.reuse.record_use(saved_seconds, clock)?;
        Ok(())
    }

    /// The keep side of line 550 for a held derived representation: measured expected
    /// uses and saving against its preparation cost and retention penalty.
    pub fn measured_amortization(
        &self,
        model: &ModelKey,
        kind: DerivedKind,
        clock: &dyn Clock,
    ) -> Result<ImportAmortization, RepresentationRefusal> {
        let held = self
            .held
            .get(&(model.clone(), kind.kind()))
            .ok_or_else(|| RepresentationRefusal::NotHeld {
                model: model.clone(),
                kind: kind.kind(),
            })?;
        self.measured(held, clock)
    }

    /// Evictions that would let `proposal` fit, least measured value per retained byte
    /// first (line 548).
    ///
    /// Only derived representations are candidates, and in local storage only those the
    /// catalog would evict now; originals never are. For a derived newcomer the evicted
    /// representations must together be worth less, by measured reuse, than the
    /// newcomer's forecast; an original newcomer outranks every cache entry. Nothing is
    /// evicted here.
    pub fn plan_room(
        &self,
        proposal: &RepresentationProposal,
        catalog: &Catalog,
        clock: &dyn Clock,
    ) -> Result<Vec<PlannedEviction>, RepresentationRefusal> {
        self.validate(proposal)?;
        let max_bytes = match self.budget {
            SpaceBudget::Explicit { max_bytes } => max_bytes,
            SpaceBudget::Unset => {
                return match self.kinds_of(proposal.model()).first() {
                    Some(held) => Err(RepresentationRefusal::NoExplicitBudget { held: *held }),
                    None => Ok(Vec::new()),
                };
            }
        };
        let total = self
            .held_bytes
            .checked_add(proposal.bytes())
            .ok_or(RepresentationRefusal::Overflow)?;
        if total <= max_bytes {
            return Ok(Vec::new());
        }
        let needed_bytes = total - max_bytes;
        let candidates = self.candidates(catalog, clock)?;
        let mut freed_bytes = 0u64;
        let mut displaced_value_seconds = 0.0;
        let mut chosen = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            if freed_bytes >= needed_bytes {
                break;
            }
            freed_bytes = freed_bytes.saturating_add(candidate.bytes);
            displaced_value_seconds += candidate.value_seconds.max(0.0);
            chosen.push(index);
        }
        if freed_bytes < needed_bytes {
            return Err(RepresentationRefusal::NoRoom {
                needed_bytes,
                evictable_bytes: freed_bytes,
            });
        }
        if let RepresentationProposal::Derived { forecast, .. } = proposal {
            let newcomer_value_seconds = net_seconds(forecast)?;
            if displaced_value_seconds >= newcomer_value_seconds {
                return Err(RepresentationRefusal::DisplacementNotWorthIt {
                    displaced_value_seconds,
                    newcomer_value_seconds,
                });
            }
        }
        Ok(chosen
            .into_iter()
            .map(|index| planned(&candidates[index]))
            .collect())
    }

    /// Derived representations, evictable now, whose measured reuse no longer satisfies
    /// line 550: "prepare or keep a representation only when" it amortizes.
    pub fn review(
        &self,
        catalog: &Catalog,
        clock: &dyn Clock,
    ) -> Result<Vec<PlannedEviction>, RepresentationRefusal> {
        let mut evictions = Vec::new();
        for candidate in self.candidates(catalog, clock)? {
            if !candidate.measured.amortizes()? {
                evictions.push(planned(&candidate));
            }
        }
        Ok(evictions)
    }

    /// Evictions that bring the store within an explicit budget, least measured value per
    /// retained byte first. What originals and representations the catalog would not
    /// evict now still hold beyond it is reported as unmet, never evicted.
    pub fn enforce_budget(
        &self,
        catalog: &Catalog,
        clock: &dyn Clock,
    ) -> Result<BudgetEnforcement, RepresentationRefusal> {
        let SpaceBudget::Explicit { max_bytes } = self.budget else {
            return Ok(BudgetEnforcement {
                evictions: Vec::new(),
                unmet_bytes: 0,
            });
        };
        let mut over_bytes = self.held_bytes.saturating_sub(max_bytes);
        if over_bytes == 0 {
            return Ok(BudgetEnforcement {
                evictions: Vec::new(),
                unmet_bytes: 0,
            });
        }
        let mut evictions = Vec::new();
        for candidate in self.candidates(catalog, clock)? {
            if over_bytes == 0 {
                break;
            }
            over_bytes = over_bytes.saturating_sub(candidate.bytes);
            evictions.push(planned(&candidate));
        }
        Ok(BudgetEnforcement {
            evictions,
            unmet_bytes: over_bytes,
        })
    }

    /// Removes a representation after its eviction was carried out; returns its bytes.
    pub fn forget(&mut self, eviction: &PlannedEviction) -> Result<u64, RepresentationRefusal> {
        let slot = (eviction.model.clone(), eviction.kind.kind());
        match self.held.get(&slot) {
            Some(held) if held.object == eviction.object => {}
            _ => {
                return Err(RepresentationRefusal::NotHeld {
                    model: slot.0,
                    kind: slot.1,
                })
            }
        }
        let bytes = self.held.remove(&slot).map_or(0, |held| held.bytes);
        self.held_bytes = self.held_bytes.saturating_sub(bytes);
        Ok(bytes)
    }

    /// Removes every representation of a model after its owner's local model deletion;
    /// returns the bytes released from this budget.
    pub fn forget_model(&mut self, model: &ModelKey) -> u64 {
        let slots: Vec<Slot> = self
            .held
            .keys()
            .filter(|(held_model, _)| held_model == model)
            .cloned()
            .collect();
        let mut released_bytes = 0u64;
        for slot in slots {
            if let Some(held) = self.held.remove(&slot) {
                released_bytes = released_bytes.saturating_add(held.bytes);
            }
        }
        self.held_bytes = self.held_bytes.saturating_sub(released_bytes);
        released_bytes
    }

    fn validate(&self, proposal: &RepresentationProposal) -> Result<(), RepresentationRefusal> {
        let model = proposal.model();
        let object = proposal.object();
        let kind = proposal.kind();
        if proposal.bytes() == 0 {
            return Err(RepresentationRefusal::ZeroBytes);
        }
        if object.scope != model.scope {
            return Err(RepresentationRefusal::ScopeMismatch {
                model: model.scope.clone(),
                object: object.scope.clone(),
            });
        }
        if !kind.tiers().contains(&proposal.tier()) {
            return Err(RepresentationRefusal::WrongTier {
                kind,
                tier: proposal.tier(),
            });
        }
        if self.held.contains_key(&(model.clone(), kind)) {
            return Err(RepresentationRefusal::AlreadyHeld { kind });
        }
        if let Some(((_, held_kind), _)) = self.held.iter().find(|(_, held)| held.object == *object)
        {
            return Err(RepresentationRefusal::SameObjectAsHeld { kind: *held_kind });
        }
        if let RepresentationProposal::Derived { forecast, .. } = proposal {
            if !forecast.amortizes()? {
                return Err(RepresentationRefusal::DoesNotAmortize {
                    expected_saving_seconds: forecast.expected_saving_seconds()?,
                    total_cost_seconds: forecast.total_cost_seconds()?,
                });
            }
        }
        Ok(())
    }

    fn kinds_of(&self, model: &ModelKey) -> Vec<RepresentationKind> {
        self.held
            .keys()
            .filter(|(held_model, _)| held_model == model)
            .map(|(_, kind)| *kind)
            .collect()
    }

    fn measured(
        &self,
        held: &Held,
        clock: &dyn Clock,
    ) -> Result<ImportAmortization, RepresentationRefusal> {
        let measured = held.reuse.measured(self.horizon_seconds, clock)?;
        Ok(measured.amortization(
            held.preparation_cost_seconds,
            held.retention_penalty_seconds,
        ))
    }

    /// Derived representations that may be evicted now, least measured value per
    /// retained byte first, ties by object identity: in local storage only what the
    /// catalog would evict.
    fn candidates(
        &self,
        catalog: &Catalog,
        clock: &dyn Clock,
    ) -> Result<Vec<Candidate>, RepresentationRefusal> {
        let mut evictable: BTreeMap<&Scope, BTreeSet<ObjectId>> = BTreeMap::new();
        let mut candidates = Vec::new();
        for ((model, kind), held) in &self.held {
            let Some(kind) = kind.derived() else {
                continue;
            };
            if held.tier == Tier::LocalStorage {
                let scope = &held.object.scope;
                let in_scope = evictable.entry(scope).or_insert_with(|| {
                    catalog
                        .eviction_candidates(scope)
                        .into_iter()
                        .map(|candidate| candidate.object)
                        .collect()
                });
                if !in_scope.contains(&held.object.id()) {
                    continue;
                }
            }
            let measured = self.measured(held, clock)?;
            candidates.push(Candidate {
                model: model.clone(),
                kind,
                object: held.object.clone(),
                tier: held.tier,
                bytes: held.bytes,
                value_seconds: net_seconds(&measured)?,
                measured,
            });
        }
        candidates.sort_by(|left, right| {
            let per_byte = |candidate: &Candidate| candidate.value_seconds / candidate.bytes as f64;
            per_byte(left)
                .total_cmp(&per_byte(right))
                .then_with(|| left.object.id().cmp(&right.object.id()))
        });
        Ok(candidates)
    }
}

fn planned(candidate: &Candidate) -> PlannedEviction {
    PlannedEviction {
        model: candidate.model.clone(),
        object: candidate.object.clone(),
        kind: candidate.kind,
        tier: candidate.tier,
        bytes: candidate.bytes,
    }
}

#[cfg(test)]
mod tests;
