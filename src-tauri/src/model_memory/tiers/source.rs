//! Choosing where bytes come from across tiers (GPU §3.4; §1.1 line 312: "Select by
//! completion time, authorization and interference"; a congested donor may lose to NVMe).
//!
//! Tiers make [`SourceOffer`]s only for objects they can supply now, after their own
//! checks: a peer's expiry, scopes, donor budget and topology; a remote's access and
//! egress policy; a host estimate's freshness; a pool's selection and presence and the
//! catalog's publication; and, for memory a runtime holds (GPU, pinned or host copies), the
//! requester's tenant and trust scope. Each offer records the consumer it was checked
//! for. The chooser then excludes offers checked for another consumer, offers of other
//! content, offers of objects the requester may not read (its own scope's, or another's
//! only under a grant in the CORE-02 catalog for exactly that object and execution: equal
//! content is not permission) and offers whose budget cannot cover the request, and hands
//! the rest to [`MultiSourceLoad`] (T03). The planner assigns bytes by predicted
//! completion, counting startup, shared cuts once and each source's interference cost. No
//! tier is preferred for what it is.

use std::collections::BTreeMap;
use std::fmt;

use super::gpu::GpuRefusal;
use super::host::HostRefusal;
use super::local::LocalRefusal;
use super::object::{Consumer, ObjectRef};
use super::peer::PeerRefusal;
use super::pinned::PinnedRefusal;
use super::remote::RemoteRefusal;
use super::{checked_sum, Tier};
use crate::foundation::catalog::{Catalog, ObjectId};
use crate::foundation::ids::ContentKey;
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::sources::{
    CutSpec, MultiSourceLoad, SourceAuthorization, SourceSpec, SourcesError, StealPolicy,
};
use crate::model_memory::math::{CutId, SourceId};

/// How bytes travel from one source to the consumer (GPU §2.5 inputs).
#[derive(Clone, Debug, PartialEq)]
pub struct SourcePath {
    /// Time before the first byte: connection, handshake, open or seek.
    pub startup_seconds: f64,
    /// Measured usable directional bandwidth now; the planner refuses advertised figures.
    pub bandwidth: BandwidthRating,
    /// Shared links and storage cuts the bytes cross (topology); each must be declared
    /// in the request with its measured capacity.
    pub cuts: Vec<CutId>,
    /// Most batches in flight from this source at once.
    pub max_in_flight: u32,
    /// Seconds of the objective per byte read here, such as slowing a donor's own
    /// serving.
    pub interference_seconds_per_byte: f64,
}

/// One tier's offer to supply an object to one consumer. Only the tiers make them, after
/// their checks, which may depend on that consumer (S3.3), so the offer is planned for no
/// other.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceOffer {
    tier: Tier,
    source: SourceId,
    object: ObjectRef,
    requester: Consumer,
    path: SourcePath,
    covers_bytes: u64,
}

impl SourceOffer {
    pub(super) fn new(
        tier: Tier,
        source: SourceId,
        object: ObjectRef,
        requester: &Consumer,
        path: SourcePath,
        covers_bytes: u64,
    ) -> Self {
        Self {
            tier,
            source,
            object,
            requester: requester.clone(),
            path,
            covers_bytes,
        }
    }

    /// The consumer the tier checked the offer for.
    pub fn requester(&self) -> &Consumer {
        &self.requester
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn source(&self) -> &SourceId {
        &self.source
    }

    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    pub fn path(&self) -> &SourcePath {
        &self.path
    }

    /// Bytes the source can supply within its own budgets, such as a donor budget or an
    /// egress budget.
    pub fn covers_bytes(&self) -> u64 {
        self.covers_bytes
    }
}

/// A tier's own refusal to offer.
#[derive(Clone, Debug, PartialEq)]
pub enum TierRefusal {
    Gpu(GpuRefusal),
    Pinned(PinnedRefusal),
    Host(HostRefusal),
    Local(LocalRefusal),
    Peer(PeerRefusal),
    Remote(RemoteRefusal),
}

impl fmt::Display for TierRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gpu(refusal) => refusal.fmt(f),
            Self::Pinned(refusal) => refusal.fmt(f),
            Self::Host(refusal) => refusal.fmt(f),
            Self::Local(refusal) => refusal.fmt(f),
            Self::Peer(refusal) => refusal.fmt(f),
            Self::Remote(refusal) => refusal.fmt(f),
        }
    }
}

/// A tier's refusal to offer one source.
#[derive(Clone, Debug, PartialEq)]
pub struct OfferRefusal {
    pub source: SourceId,
    pub tier: Tier,
    pub reason: TierRefusal,
}

impl OfferRefusal {
    pub(super) fn new(source: &SourceId, tier: Tier, reason: TierRefusal) -> Self {
        Self {
            source: source.clone(),
            tier,
            reason,
        }
    }
}

impl fmt::Display for OfferRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.source, self.tier, self.reason)
    }
}

impl std::error::Error for OfferRefusal {}

/// The bytes a requester needs, and how to plan them (GPU §2.5).
#[derive(Clone, Debug, PartialEq)]
pub struct SourceRequest {
    /// The consumer the bytes are for; it must be authorized to read every source.
    pub requester: Consumer,
    /// The content key needed.
    pub content: ContentKey,
    /// What remains to load, in batches.
    pub batches_bytes: Vec<u64>,
    /// Every shared cut the offers cross, with its measured capacity.
    pub cuts: Vec<CutSpec>,
    pub policy: StealPolicy,
}

/// Why an offer took no part in the plan.
#[derive(Clone, Debug, PartialEq)]
pub enum ExclusionReason {
    /// The tier refused to offer.
    Refused(TierRefusal),
    /// The tier checked the offer for another consumer, such as the same tenant's runner in
    /// another trust scope; memory never crosses a VM boundary (S3.3).
    OfferedToAnother { offered_to: Box<Consumer> },
    /// The offer is for other content.
    DifferentContent { offered: ContentKey },
    /// The object is outside the requester's scope and no grant names exactly it.
    OutsideScope { object: ObjectId },
    /// The source's budget cannot cover every byte the planner might assign it.
    CannotCover {
        covers_bytes: u64,
        needed_bytes: u64,
    },
}

impl fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => refusal.fmt(f),
            Self::OfferedToAnother { offered_to } => write!(
                f,
                "it was offered to {} and is planned for no other consumer",
                offered_to.execution
            ),
            Self::DifferentContent { offered } => write!(f, "it offers other content, {offered}"),
            Self::OutsideScope { object } => write!(
                f,
                "object {object} is outside the requester's scope and no grant names it; \
                 equal content is not permission"
            ),
            Self::CannotCover {
                covers_bytes,
                needed_bytes,
            } => write!(
                f,
                "it can supply {covers_bytes} bytes within its budget, not {needed_bytes}"
            ),
        }
    }
}

/// One source left out of the plan, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct ExcludedSource {
    pub source: SourceId,
    pub tier: Tier,
    pub reason: ExclusionReason,
}

/// Why no plan was made.
#[derive(Clone, Debug, PartialEq)]
pub enum SourceChoiceError {
    /// The batches add up to more than 64 bits.
    Overflow,
    /// Every offer was excluded.
    NoEligibleSource { excluded: Vec<ExcludedSource> },
    /// The planner refused the inputs (T03).
    Planner(SourcesError),
}

impl fmt::Display for SourceChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("the batches do not fit in 64 bits"),
            Self::NoEligibleSource { excluded } => {
                write!(
                    f,
                    "no eligible source: {} offers were excluded",
                    excluded.len()
                )
            }
            Self::Planner(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SourceChoiceError {}

/// The plan across tiers, and every offer left out of it with its reason.
#[derive(Clone, Debug)]
pub struct SourceChoice {
    load: MultiSourceLoad,
    offers: BTreeMap<SourceId, (Tier, ObjectRef)>,
    excluded: Vec<ExcludedSource>,
    batches_bytes: Vec<u64>,
}

impl SourceChoice {
    /// The T03 plan; dispatch, completion and work stealing continue on it.
    pub fn load(&self) -> &MultiSourceLoad {
        &self.load
    }

    pub fn load_mut(&mut self) -> &mut MultiSourceLoad {
        &mut self.load
    }

    pub fn excluded(&self) -> &[ExcludedSource] {
        &self.excluded
    }

    /// The tier of a planned source.
    pub fn tier_of(&self, source: &SourceId) -> Option<Tier> {
        self.offers.get(source).map(|(tier, _)| *tier)
    }

    /// The object a planned source supplies.
    pub fn object_of(&self, source: &SourceId) -> Option<&ObjectRef> {
        self.offers.get(source).map(|(_, object)| object)
    }

    /// Bytes currently assigned to a source, to charge against its donor or egress
    /// budget once served.
    pub fn assigned_bytes(&self, source: &SourceId) -> u64 {
        self.load
            .batches_of(source)
            .iter()
            .filter_map(|batch| self.batches_bytes.get(*batch))
            .fold(0u64, |total, bytes| total.saturating_add(*bytes))
    }

    /// Predicted seconds until every batch is done.
    pub fn predicted_completion_seconds(&self) -> f64 {
        self.load.predicted_completion_seconds()
    }
}

/// Chooses sources for `request` among the tiers' offers (line 312).
///
/// Excluded: tier refusals, offers a tier checked for another consumer, offers of other
/// content, offers of objects outside the requester's scope that no catalog grant names,
/// and offers that cannot cover every requested byte, since the planner may assign all of
/// them to one source. The remaining offers are planned by [`MultiSourceLoad`] as
/// authorized sources.
pub fn choose_source(
    request: &SourceRequest,
    offers: Vec<Result<SourceOffer, OfferRefusal>>,
    catalog: &Catalog,
) -> Result<SourceChoice, SourceChoiceError> {
    let needed_bytes =
        checked_sum(request.batches_bytes.iter().copied()).ok_or(SourceChoiceError::Overflow)?;
    let mut excluded = Vec::new();
    let mut eligible = Vec::new();
    for offer in offers {
        let offer = match offer {
            Ok(offer) => offer,
            Err(refusal) => {
                excluded.push(ExcludedSource {
                    source: refusal.source,
                    tier: refusal.tier,
                    reason: ExclusionReason::Refused(refusal.reason),
                });
                continue;
            }
        };
        let reason = if offer.requester != request.requester {
            Some(ExclusionReason::OfferedToAnother {
                offered_to: Box::new(offer.requester.clone()),
            })
        } else if offer.object.content != request.content {
            Some(ExclusionReason::DifferentContent {
                offered: offer.object.content,
            })
        } else if offer.object.scope != request.requester.scope()
            && !may_read(catalog, &request.requester, offer.object.id())
        {
            Some(ExclusionReason::OutsideScope {
                object: offer.object.id(),
            })
        } else if offer.covers_bytes < needed_bytes {
            Some(ExclusionReason::CannotCover {
                covers_bytes: offer.covers_bytes,
                needed_bytes,
            })
        } else {
            None
        };
        match reason {
            Some(reason) => excluded.push(ExcludedSource {
                source: offer.source,
                tier: offer.tier,
                reason,
            }),
            None => eligible.push(offer),
        }
    }
    if eligible.is_empty() {
        return Err(SourceChoiceError::NoEligibleSource { excluded });
    }
    let specs = eligible
        .iter()
        .map(|offer| SourceSpec {
            id: offer.source.clone(),
            authorization: SourceAuthorization::Authorized,
            startup_seconds: offer.path.startup_seconds,
            bandwidth: offer.path.bandwidth,
            cuts: offer.path.cuts.clone(),
            max_in_flight: offer.path.max_in_flight,
            interference_seconds_per_byte: offer.path.interference_seconds_per_byte,
        })
        .collect();
    let load = MultiSourceLoad::plan(
        specs,
        request.cuts.clone(),
        &request.batches_bytes,
        request.policy,
    )
    .map_err(SourceChoiceError::Planner)?;
    let offers = eligible
        .into_iter()
        .map(|offer| (offer.source, (offer.tier, offer.object)))
        .collect();
    Ok(SourceChoice {
        load,
        offers,
        excluded,
        batches_bytes: request.batches_bytes.clone(),
    })
}

/// Whether `reader` may read another scope's `object` now: only under a live catalog
/// grant for exactly that object and execution (S3.3, INT-05).
fn may_read(catalog: &Catalog, reader: &Consumer, object: ObjectId) -> bool {
    catalog
        .object_view(&reader.scope(), &reader.execution, object)
        .is_ok()
}

#[cfg(test)]
mod tests;
