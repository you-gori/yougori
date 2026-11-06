//! Retention as size-constrained caching with shared prerequisites (GPU §2.7; §1.1,
//! line 304: dependency-aware retention with session leases and marginal shared costs).
//!
//! [`ResidencyCache`] models the objects one device retains: immutable base weights,
//! adapters, merged variants and graph pools, and mutable session KV. It holds every
//! invariant itself, so no policy can break one:
//!
//! - an object is resident only with all of its prerequisites, and each object's bytes
//!   count once however many dependents share it;
//! - pinned objects, objects under an unexpired [`SessionLease`], objects the current
//!   request needs, objects the [clean-eviction rule](super::eviction) retains, and every
//!   prerequisite of these are never evicted;
//! - only an object without resident dependents is evicted, so no dependent is orphaned;
//!   the one exception is a graph pool, which never keeps its weights node resident and
//!   is evicted with the node, before it ([`ObjectKind::GraphPool`]);
//! - a request either gets every object it needs or is refused before anything is
//!   evicted;
//! - an evicted object is dropped clean, dropped for recapture, or written back first
//!   (line 307).
//!
//! A [`RetentionPolicy`] only ranks the legal victims. [`Lru`] and [`CostPerByte`] are the
//! §2.7 baselines, [`MarginalSavedLatency`] ranks by saved latency per retained byte, and
//! [`GreedyDualSize`] is Landlord with shared bases charged once.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{
    AuthorizationEpoch, Clock, DigestBuilder, ExecutionId, MonotonicTime,
};

use super::eviction::{
    eviction_action, Content, ContentState, CopyTier, EvictionAction, GpuCopy, ReconstructibleCopy,
    Verification, WriteBack,
};
use super::{add_bytes, check_name, check_seconds, InputError};

/// Digest domain of the marker session KV takes after each request that changes it; the
/// new marker makes older verified copies of the session stop matching.
const NEXT_SESSION_STATE: &str = "yougori/model-memory/residency/session-state/v1";

/// What a retained object is (GPU §2.7; §1.1, lines 304, 307 and 308; §3.9, lines 632
/// and 634). The kinds fix what an object may depend on, what may depend on it, and how
/// it leaves the device; [`ResidencyCache::new`] refuses a catalog that breaks a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ObjectKind {
    /// Immutable model weights, typically shared by adapters and sessions.
    BaseWeights,
    /// Immutable adapter weights on top of a base.
    Adapter,
    /// Immutable weights of its own, materialized from a base and an adapter under a
    /// merge proof and named by the merged identity's content key (§1.1, line 308; §3.9,
    /// line 634). A request never changes it. It is a base to the sessions that use it:
    /// a shared prerequisite charged once (line 304). It has no prerequisites: it never
    /// keeps the base it was merged from resident and is never charged to it. The merge
    /// recipe is no copy: without a verified copy of its own bytes it is written back or
    /// retained, exactly as base weights are (line 307).
    MergedVariant,
    /// Graphs captured by one process over one weights node, a base or a merged variant,
    /// under one runtime configuration (§2.7; §1.1, line 309). Immutable, with exactly
    /// one prerequisite, its weights node, and the relation runs the other way: the pool
    /// never keeps the node resident, the node is evicted with its pools resident and
    /// they go first, and a pool never stays without its node. Nothing depends on a pool
    /// and no session lease holds one. No tier outside the GPU holds graph resources
    /// (§3.4), so a pool has no copies: a clean pool is dropped for recapture, and its
    /// reload cost is the capture latency.
    GraphPool,
    /// One session's KV, which every request to the session changes.
    SessionKv,
}

impl ObjectKind {
    /// Whether a request for the object changes its bytes; weights, adapters, merged
    /// variants and graph pools are immutable (§3.4).
    pub const fn mutates_on_use(self) -> bool {
        matches!(self, Self::SessionKv)
    }

    /// Whether `content` names what this kind holds: a content key for weights, adapters
    /// and merged variants, a session-state marker for session KV, a capture key for a
    /// graph pool.
    pub const fn holds(self, content: &Content) -> bool {
        matches!(
            (self, content),
            (
                Self::BaseWeights | Self::Adapter | Self::MergedVariant,
                Content::Immutable(_)
            ) | (Self::SessionKv, Content::SessionState(_))
                | (Self::GraphPool, Content::GraphPool { .. })
        )
    }

    /// Whether the object is a weights node: what a session runs on and a graph pool is
    /// captured over (a base or a merged variant).
    pub const fn is_weights(self) -> bool {
        matches!(self, Self::BaseWeights | Self::MergedVariant)
    }

    /// Whether the object keeps its prerequisites resident while it is resident. A graph
    /// pool does not: it goes with its weights node instead.
    pub const fn keeps_prerequisites_resident(self) -> bool {
        !matches!(self, Self::GraphPool)
    }

    /// Whether the object is rebuilt by capturing it again over its weights node rather
    /// than from a copy, so that it never has copies and is never written back (§3.4).
    pub const fn recaptured(self) -> bool {
        matches!(self, Self::GraphPool)
    }
}

/// One object the cache may hold.
#[derive(Clone, Debug, PartialEq)]
pub struct CachedObject {
    pub key: String,
    pub kind: ObjectKind,
    /// More than zero.
    pub bytes: u64,
    /// Latency to make the object resident again after eviction: the policies' cost.
    pub reload_seconds: f64,
    /// Objects that must be resident whenever this one is, such as a session's base. The
    /// kinds restrict them ([`ObjectKind`]): a merged variant lists none, a graph pool
    /// lists exactly its weights node, and nothing lists a graph pool.
    pub prerequisites: Vec<String>,
    /// What the object's GPU bytes hold when loaded: the content key of weights, an
    /// adapter or a merged variant, a session's state marker, or a graph pool's capture
    /// key, which must name its weights node's content. It must match the kind.
    pub content: Content,
    /// Copies outside the GPU when the cache starts; none for a graph pool.
    pub copies: Vec<ReconstructibleCopy>,
}

/// A cache's capacity and catalog.
#[derive(Clone, Debug, PartialEq)]
pub struct CacheConfig {
    /// The device budget granted to this policy client by the CORE-03 ledger (§3.1,
    /// line 491); the cache never grows it.
    pub capacity_bytes: u64,
    pub objects: Vec<CachedObject>,
    /// Where dirty or unverified objects are written back, and verified, on eviction. It
    /// must guarantee availability; `None` retains such objects instead (line 307).
    pub write_back_tier: Option<CopyTier>,
}

/// Protection of one object, and through it its prerequisites, until the lease expires,
/// is released or its authorization epoch is revoked (§1.1, line 304).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLease {
    /// The parent execution the lease belongs to (S3.1).
    pub execution: ExecutionId,
    /// The VM authorization epoch the lease is bound to where one applies (S3.1); `None`
    /// only for a runtime without one.
    pub authorization_epoch: Option<AuthorizationEpoch>,
    pub object: String,
    pub expires_at: MonotonicTime,
}

/// A resident object as a policy sees it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ObjectView<'a> {
    pub key: &'a str,
    pub kind: ObjectKind,
    pub bytes: u64,
    pub reload_seconds: f64,
    /// The request step that last needed the object.
    pub last_use_step: u64,
    /// How many requests needed the object, directly or as a prerequisite.
    pub use_count: u64,
    /// Never evicted now: pinned, leased, needed by the current request, retained by the
    /// clean-eviction rule, or a prerequisite of one of these.
    pub protected: bool,
    /// A legal victim now: unprotected and with no resident dependent other than its
    /// graph pools, which are evicted with it.
    pub evictable: bool,
}

/// Ranks eviction victims (GPU §2.7). The cache enforces every invariant; naming an object
/// that is not evictable is refused with [`CacheError::PolicyChoseIneligible`].
pub trait RetentionPolicy {
    fn name(&self) -> &str;

    /// After a request, once for every object it needed, prerequisites first.
    fn on_use(&mut self, object: &ObjectView<'_>, step: u64);

    /// After an object leaves the device.
    fn on_evict(&mut self, key: &str);

    /// The index in `residents` of the next victim. `residents` lists every resident
    /// object in key order, and at least one of them is evictable.
    fn choose_victim(&mut self, residents: &[ObjectView<'_>], step: u64) -> Option<usize>;
}

impl<P: RetentionPolicy + ?Sized> RetentionPolicy for Box<P> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn on_use(&mut self, object: &ObjectView<'_>, step: u64) {
        (**self).on_use(object, step);
    }

    fn on_evict(&mut self, key: &str) {
        (**self).on_evict(key);
    }

    fn choose_victim(&mut self, residents: &[ObjectView<'_>], step: u64) -> Option<usize> {
        (**self).choose_victim(residents, step)
    }
}

/// The built-in policies' tie-break: older last use first, then key order.
fn older(a: &ObjectView<'_>, b: &ObjectView<'_>) -> Ordering {
    a.last_use_step
        .cmp(&b.last_use_step)
        .then_with(|| a.key.cmp(b.key))
}

/// The evictable object with the lowest score, ties broken by [`older`].
fn lowest(residents: &[ObjectView<'_>], score: impl Fn(&ObjectView<'_>) -> f64) -> Option<usize> {
    residents
        .iter()
        .enumerate()
        .filter(|(_, view)| view.evictable)
        .map(|(index, view)| (index, view, score(view)))
        .min_by(|(_, a, a_score), (_, b, b_score)| {
            a_score.total_cmp(b_score).then_with(|| older(a, b))
        })
        .map(|(index, _, _)| index)
}

/// Least recently used: the §2.7 recency baseline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lru;

impl RetentionPolicy for Lru {
    fn name(&self) -> &str {
        "lru"
    }

    fn on_use(&mut self, _object: &ObjectView<'_>, _step: u64) {}

    fn on_evict(&mut self, _key: &str) {}

    fn choose_victim(&mut self, residents: &[ObjectView<'_>], _step: u64) -> Option<usize> {
        residents
            .iter()
            .enumerate()
            .filter(|(_, view)| view.evictable)
            .min_by(|(_, a), (_, b)| older(a, b))
            .map(|(index, _)| index)
    }
}

/// Evicts the object cheapest to reload per byte it frees: `reload_seconds / bytes`, the
/// §2.7 cost baseline. It ignores recency and frequency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostPerByte;

impl RetentionPolicy for CostPerByte {
    fn name(&self) -> &str {
        "cost-per-byte"
    }

    fn on_use(&mut self, _object: &ObjectView<'_>, _step: u64) {}

    fn on_evict(&mut self, _key: &str) {}

    fn choose_victim(&mut self, residents: &[ObjectView<'_>], _step: u64) -> Option<usize> {
        lowest(residents, |view| view.reload_seconds / view.bytes as f64)
    }
}

/// Evicts the object that saves the least latency per byte it keeps resident (GPU §2.7):
/// `expected uses × reload_seconds / bytes`.
///
/// Expected uses are an exponentially decayed count of the requests that needed the
/// object, halving every `half_life_steps` requests. A shared base is credited with every
/// dependent's requests and charged for its own bytes once; a dependent is charged only
/// its marginal bytes, because its base stays resident for others (line 304).
#[derive(Clone, Debug, PartialEq)]
pub struct MarginalSavedLatency {
    half_life_steps: u64,
    history: BTreeMap<String, DecayedCount>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct DecayedCount {
    value: f64,
    at_step: u64,
}

impl DecayedCount {
    fn at(self, step: u64, half_life_steps: u64) -> f64 {
        let elapsed = step.saturating_sub(self.at_step) as f64;
        self.value * (-elapsed / half_life_steps as f64).exp2()
    }
}

impl MarginalSavedLatency {
    pub fn new(half_life_steps: u64) -> Result<Self, InputError> {
        if half_life_steps == 0 {
            return Err(InputError::NotPositive {
                field: "half-life steps",
            });
        }
        Ok(Self {
            half_life_steps,
            history: BTreeMap::new(),
        })
    }

    /// The decayed number of requests that needed `key`, as of `step`.
    pub fn expected_uses(&self, key: &str, step: u64) -> f64 {
        self.history
            .get(key)
            .map_or(0.0, |count| count.at(step, self.half_life_steps))
    }

    /// Saved seconds per retained byte.
    pub fn saved_seconds_per_byte(&self, object: &ObjectView<'_>, step: u64) -> f64 {
        self.expected_uses(object.key, step) * object.reload_seconds / object.bytes as f64
    }
}

impl RetentionPolicy for MarginalSavedLatency {
    fn name(&self) -> &str {
        "marginal-saved-latency"
    }

    fn on_use(&mut self, object: &ObjectView<'_>, step: u64) {
        let value = self.expected_uses(object.key, step) + 1.0;
        self.history.insert(
            object.key.to_string(),
            DecayedCount {
                value,
                at_step: step,
            },
        );
    }

    fn on_evict(&mut self, _key: &str) {}

    fn choose_victim(&mut self, residents: &[ObjectView<'_>], step: u64) -> Option<usize> {
        lowest(residents, |view| self.saved_seconds_per_byte(view, step))
    }
}

/// GreedyDual-Size in Landlord form (GPU §2.7), with shared bases charged once.
///
/// Every resident object holds a credit of at most its reload seconds, reset to that cost
/// whenever a request needs it, including as a prerequisite, so each dependent's request
/// refreshes its shared base. To evict, the policy takes the smallest credit per byte Δ
/// among the legal victims and charges every unprotected resident object rent of
/// Δ × its own bytes, once: a base shared by many dependents pays for its bytes once,
/// never once per dependent. The victim's credit is then zero.
///
/// The classical competitive guarantee of Landlord/GreedyDual-Size (Young 2002) does not
/// automatically survive varying costs, shared bases, pinned objects, session leases,
/// eviction write-backs, prediction or prefetch (line 448). None is claimed here;
/// [`landlord_guarantee`](super::simulator::landlord_guarantee) lists which of these a
/// setting uses.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GreedyDualSize {
    credits: BTreeMap<String, f64>,
}

impl GreedyDualSize {
    pub fn new() -> Self {
        Self::default()
    }

    /// A resident object's remaining credit, in seconds.
    pub fn credit(&self, key: &str) -> Option<f64> {
        self.credits.get(key).copied()
    }

    fn credit_per_byte(&self, view: &ObjectView<'_>) -> f64 {
        self.credits.get(view.key).copied().unwrap_or(0.0) / view.bytes as f64
    }
}

impl RetentionPolicy for GreedyDualSize {
    fn name(&self) -> &str {
        "greedy-dual-size"
    }

    fn on_use(&mut self, object: &ObjectView<'_>, _step: u64) {
        self.credits
            .insert(object.key.to_string(), object.reload_seconds);
    }

    fn on_evict(&mut self, key: &str) {
        self.credits.remove(key);
    }

    fn choose_victim(&mut self, residents: &[ObjectView<'_>], _step: u64) -> Option<usize> {
        let victim = lowest(residents, |view| self.credit_per_byte(view))?;
        let rent_per_byte = residents
            .get(victim)
            .map(|view| self.credit_per_byte(view))?;
        for view in residents.iter().filter(|view| !view.protected) {
            if let Some(credit) = self.credits.get_mut(view.key) {
                *credit = (*credit - rent_per_byte * view.bytes as f64).max(0.0);
            }
        }
        if let Some(view) = residents.get(victim) {
            self.credits.insert(view.key.to_string(), 0.0);
        }
        Some(victim)
    }
}

/// One evicted object and how it left the device.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Eviction {
    pub object: String,
    pub action: EvictionAction,
}

/// What one request did.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AccessOutcome {
    /// Every needed object was already resident.
    pub hit: bool,
    /// Reload seconds of the needed objects that were already resident.
    pub saved_seconds: f64,
    /// Reload seconds of the needed objects that had to be loaded.
    pub paid_seconds: f64,
    /// The objects loaded, prerequisites first.
    pub loaded: Vec<String>,
    /// Host-to-device bytes.
    pub loaded_bytes: u64,
    pub evictions: Vec<Eviction>,
    /// Device-to-host bytes of the write-backs among the evictions.
    pub written_back_bytes: u64,
}

/// Why the cache refused an operation.
#[derive(Clone, Debug, PartialEq)]
pub enum CacheError {
    Input(InputError),
    /// The write-back tier does not guarantee availability, so a written-back copy would
    /// not be reconstructible (line 307).
    WriteBackTierNotGuaranteed {
        tier: CopyTier,
    },
    /// The object's content does not match its kind: weights, adapters and merged
    /// variants are immutable content named by a content key, session KV is a state
    /// named by a marker, a graph pool is named by its capture key.
    WrongContentKind {
        object: String,
    },
    /// A prerequisite the kinds forbid ([`ObjectKind`]): a merged variant keeps nothing
    /// resident, least of all the base it was merged from (line 308); a graph pool
    /// depends only on a weights node; and nothing depends on a graph pool.
    ForbiddenPrerequisite {
        object: String,
        prerequisite: String,
    },
    /// A graph pool is captured over exactly one weights node; this one lists `count`
    /// prerequisites.
    GraphPoolPrerequisites {
        object: String,
        count: usize,
    },
    /// The graph pool's capture key names other weights than its prerequisite holds.
    GraphPoolForOtherWeights {
        object: String,
        prerequisite: String,
    },
    /// A graph pool lists a copy outside the GPU, which no tier holds (§3.4).
    GraphPoolCopy {
        object: String,
    },
    /// A session lease never holds a graph pool, which belongs to a process, not a
    /// session.
    LeaseOnGraphPool {
        object: String,
    },
    /// The clock reads earlier than a previous operation did.
    TimeWentBack {
        last: MonotonicTime,
        now: MonotonicTime,
    },
    /// A lease that has already expired protects nothing.
    LeaseAlreadyExpired {
        object: String,
    },
    /// The lease is bound to a revoked authorization epoch, which is never honoured again
    /// (S3.1).
    RevokedAuthorization {
        object: String,
        epoch: AuthorizationEpoch,
    },
    /// Pinned, leased and retained objects leave too little room; nothing was evicted.
    NoRoom {
        object: String,
        needed_bytes: u64,
        free_bytes: u64,
        freeable_bytes: u64,
    },
    /// The policy named no victim although one was required.
    PolicyChoseNothing {
        policy: String,
    },
    /// The policy named an object that may not be evicted now, or none that exists.
    PolicyChoseIneligible {
        policy: String,
        object: Option<String>,
    },
    /// The clean-eviction rule keeps this object on the device (line 307).
    MustRetain {
        object: String,
    },
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::WriteBackTierNotGuaranteed { tier } => write!(
                f,
                "a write-back to {tier:?} would not leave a reconstructible copy"
            ),
            Self::WrongContentKind { object } => write!(
                f,
                "{object}: weights need a content key, session KV a state marker, a graph \
                 pool a capture key"
            ),
            Self::ForbiddenPrerequisite {
                object,
                prerequisite,
            } => write!(f, "{object} may not depend on {prerequisite}"),
            Self::GraphPoolPrerequisites { object, count } => write!(
                f,
                "graph pool {object} lists {count} prerequisites; it is captured over \
                 exactly one weights node"
            ),
            Self::GraphPoolForOtherWeights {
                object,
                prerequisite,
            } => write!(
                f,
                "graph pool {object} was captured over other weights than {prerequisite}"
            ),
            Self::GraphPoolCopy { object } => {
                write!(
                    f,
                    "graph pool {object} lists a copy; no tier holds graph resources"
                )
            }
            Self::LeaseOnGraphPool { object } => {
                write!(f, "a session lease cannot hold graph pool {object}")
            }
            Self::TimeWentBack { last, now } => write!(
                f,
                "the clock went back from {} ns to {} ns",
                last.as_nanos(),
                now.as_nanos()
            ),
            Self::LeaseAlreadyExpired { object } => {
                write!(f, "the lease on {object} has already expired")
            }
            Self::RevokedAuthorization { object, epoch } => write!(
                f,
                "the lease on {object} is bound to revoked authorization epoch {epoch}"
            ),
            Self::NoRoom {
                object,
                needed_bytes,
                free_bytes,
                freeable_bytes,
            } => write!(
                f,
                "{object} needs {needed_bytes} bytes; {free_bytes} are free and \
                 {freeable_bytes} more may be evicted"
            ),
            Self::PolicyChoseNothing { policy } => {
                write!(f, "policy {policy} chose no victim")
            }
            Self::PolicyChoseIneligible { policy, object } => {
                write!(
                    f,
                    "policy {policy} chose {object:?}, which may not be evicted"
                )
            }
            Self::MustRetain { object } => {
                write!(
                    f,
                    "{object} is dirty or unverified and cannot be written back"
                )
            }
        }
    }
}

impl std::error::Error for CacheError {}

impl From<InputError> for CacheError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

#[derive(Clone, Debug)]
struct Entry {
    kind: ObjectKind,
    bytes: u64,
    reload_seconds: f64,
    prerequisites: Vec<String>,
    content: Content,
    state: ContentState,
    copies: Vec<ReconstructibleCopy>,
    resident: bool,
    pinned: bool,
    last_use_step: u64,
    use_count: u64,
}

impl Entry {
    fn gpu_copy(&self) -> GpuCopy {
        GpuCopy {
            content: self.content,
            state: self.state,
            bytes: self.bytes,
        }
    }
}

/// The retained objects of one device under one policy (GPU §2.7; §1.1, lines 304 and
/// 307). It holds no global state: every capacity comes from its [`CacheConfig`].
#[derive(Clone, Debug)]
pub struct ResidencyCache<P> {
    capacity_bytes: u64,
    resident_bytes: u64,
    entries: BTreeMap<String, Entry>,
    leases: Vec<SessionLease>,
    /// Leases bound to an epoch older than this are void.
    revoked_before: Option<AuthorizationEpoch>,
    write_back_tier: Option<CopyTier>,
    policy: P,
    step: u64,
    last_seen: MonotonicTime,
}

impl<P: RetentionPolicy> ResidencyCache<P> {
    /// An empty cache; nothing is resident yet.
    pub fn new(config: &CacheConfig, policy: P) -> Result<Self, CacheError> {
        if config.capacity_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "cache capacity",
            }
            .into());
        }
        if let Some(tier) = config.write_back_tier {
            if !tier.guarantees_availability() {
                return Err(CacheError::WriteBackTierNotGuaranteed { tier });
            }
        }
        let mut entries = BTreeMap::new();
        for object in &config.objects {
            check_name("object key", &object.key)?;
            if object.bytes == 0 {
                return Err(InputError::NotPositive {
                    field: "object bytes",
                }
                .into());
            }
            check_seconds("reload seconds", object.reload_seconds)?;
            if !object.kind.holds(&object.content) {
                return Err(CacheError::WrongContentKind {
                    object: object.key.clone(),
                });
            }
            let mut listed = BTreeSet::new();
            for prerequisite in &object.prerequisites {
                if !listed.insert(prerequisite.as_str()) {
                    return Err(InputError::Duplicate {
                        field: "prerequisite",
                        name: prerequisite.clone(),
                    }
                    .into());
                }
            }
            let entry = Entry {
                kind: object.kind,
                bytes: object.bytes,
                reload_seconds: object.reload_seconds,
                prerequisites: object.prerequisites.clone(),
                content: object.content,
                state: ContentState::Clean,
                copies: object.copies.clone(),
                resident: false,
                pinned: false,
                last_use_step: 0,
                use_count: 0,
            };
            if entries.insert(object.key.clone(), entry).is_some() {
                return Err(InputError::Duplicate {
                    field: "object key",
                    name: object.key.clone(),
                }
                .into());
            }
        }
        check_prerequisites(&entries)?;
        check_kinds(&entries)?;
        Ok(Self {
            capacity_bytes: config.capacity_bytes,
            resident_bytes: 0,
            entries,
            leases: Vec::new(),
            revoked_before: None,
            write_back_tier: config.write_back_tier,
            policy,
            step: 0,
            last_seen: MonotonicTime::ZERO,
        })
    }

    pub fn policy(&self) -> &P {
        &self.policy
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Bytes of resident objects, each counted once.
    pub fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    pub fn free_bytes(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.resident_bytes)
    }

    pub fn is_resident(&self, key: &str) -> bool {
        self.entries.get(key).is_some_and(|entry| entry.resident)
    }

    /// Resident objects in key order.
    pub fn resident_objects(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.resident)
            .map(|(key, _)| key.as_str())
            .collect()
    }

    pub fn content_state(&self, key: &str) -> Option<ContentState> {
        self.entries.get(key).map(|entry| entry.state)
    }

    /// The copies outside the GPU, including verified write-backs.
    pub fn copies(&self, key: &str) -> Option<&[ReconstructibleCopy]> {
        self.entries.get(key).map(|entry| entry.copies.as_slice())
    }

    /// Never evict `key` (or its prerequisites) while it is resident.
    pub fn pin(&mut self, key: &str) -> Result<(), CacheError> {
        self.entry_mut(key)?.pinned = true;
        Ok(())
    }

    pub fn unpin(&mut self, key: &str) -> Result<(), CacheError> {
        self.entry_mut(key)?.pinned = false;
        Ok(())
    }

    /// Protects the leased object and its prerequisites until the lease expires on
    /// `clock`, is released or its epoch is revoked; a hit never renews it. A graph pool
    /// is never leased ([`ObjectKind::GraphPool`]).
    pub fn grant_lease(
        &mut self,
        lease: SessionLease,
        clock: &dyn Clock,
    ) -> Result<(), CacheError> {
        let now = self.observe(clock)?;
        match self.entries.get(&lease.object) {
            None => {
                return Err(InputError::Unknown {
                    field: "leased object",
                    name: lease.object,
                }
                .into());
            }
            Some(entry) if entry.kind == ObjectKind::GraphPool => {
                return Err(CacheError::LeaseOnGraphPool {
                    object: lease.object,
                });
            }
            Some(_) => {}
        }
        if let Some(epoch) = lease.authorization_epoch {
            if self.is_revoked(epoch) {
                return Err(CacheError::RevokedAuthorization {
                    object: lease.object,
                    epoch,
                });
            }
        }
        if lease.expires_at <= now {
            return Err(CacheError::LeaseAlreadyExpired {
                object: lease.object,
            });
        }
        self.leases.push(lease);
        Ok(())
    }

    /// Ends `execution`'s leases on `object`; returns whether there were any.
    pub fn release_lease(&mut self, execution: &ExecutionId, object: &str) -> bool {
        let before = self.leases.len();
        self.leases
            .retain(|lease| !(lease.execution == *execution && lease.object == object));
        self.leases.len() != before
    }

    /// Voids every lease bound to an authorization epoch older than `current`, now and
    /// for any later grant (S3.1: nothing bound to an older epoch is honoured again).
    /// Revocation never moves back to an older epoch.
    pub fn revoke_authorization_before(&mut self, current: AuthorizationEpoch) {
        let floor = self
            .revoked_before
            .map_or(current, |floor| floor.max(current));
        self.revoked_before = Some(floor);
        self.leases
            .retain(|lease| lease.authorization_epoch.is_none_or(|epoch| epoch >= floor));
    }

    fn is_revoked(&self, epoch: AuthorizationEpoch) -> bool {
        self.revoked_before.is_some_and(|floor| epoch < floor)
    }

    /// Serves one request for `key`: loads whatever it and its prerequisites lack,
    /// evicting legal victims chosen by the policy, or refuses with
    /// [`CacheError::NoRoom`] before evicting anything. A victim's graph pools are
    /// evicted with it, before it, since a pool never stays without its weights node.
    pub fn access(&mut self, key: &str, clock: &dyn Clock) -> Result<AccessOutcome, CacheError> {
        let now = self.observe(clock)?;
        if !self.entries.contains_key(key) {
            return Err(InputError::Unknown {
                field: "object",
                name: key.to_string(),
            }
            .into());
        }
        let step = self.step.checked_add(1).ok_or(InputError::Overflow {
            field: "request steps",
        })?;
        let order = self.need_order(key);
        let need: BTreeSet<String> = order.iter().cloned().collect();

        let mut missing_bytes = 0u64;
        let mut saved_seconds = 0.0;
        let mut paid_seconds = 0.0;
        for name in &order {
            if let Some(entry) = self.entries.get(name) {
                if entry.resident {
                    saved_seconds += entry.reload_seconds;
                } else {
                    missing_bytes = add_bytes("missing bytes", missing_bytes, entry.bytes)?;
                    paid_seconds += entry.reload_seconds;
                }
            }
        }

        let mut evictions = Vec::new();
        let mut written_back_bytes = 0u64;
        if self.free_bytes() < missing_bytes {
            let protected = self.protected(&need, now);
            let freeable_bytes = self
                .entries
                .iter()
                .filter(|(name, entry)| entry.resident && !protected.contains(*name))
                .try_fold(0u64, |total, (_, entry)| {
                    add_bytes("freeable bytes", total, entry.bytes)
                })?;
            if self.free_bytes().saturating_add(freeable_bytes) < missing_bytes {
                return Err(CacheError::NoRoom {
                    object: key.to_string(),
                    needed_bytes: missing_bytes,
                    free_bytes: self.free_bytes(),
                    freeable_bytes,
                });
            }
            while self.free_bytes() < missing_bytes {
                let victim = {
                    let residents = views(&self.entries, &protected);
                    let choice = self.policy.choose_victim(&residents, step);
                    match choice.map(|index| residents.get(index)) {
                        None => {
                            return Err(CacheError::PolicyChoseNothing {
                                policy: self.policy.name().to_string(),
                            })
                        }
                        Some(Some(view)) if view.evictable => view.key.to_string(),
                        Some(other) => {
                            return Err(CacheError::PolicyChoseIneligible {
                                policy: self.policy.name().to_string(),
                                object: other.map(|view| view.key.to_string()),
                            })
                        }
                    }
                };
                // A protected pool protects its node, so a victim's pools are never
                // protected.
                for pool in self.resident_pools_of(&victim) {
                    let eviction = self.evict(&pool)?;
                    written_back_bytes = add_bytes(
                        "written-back bytes",
                        written_back_bytes,
                        eviction.action.d2h_bytes(),
                    )?;
                    evictions.push(eviction);
                }
                let eviction = self.evict(&victim)?;
                written_back_bytes = add_bytes(
                    "written-back bytes",
                    written_back_bytes,
                    eviction.action.d2h_bytes(),
                )?;
                evictions.push(eviction);
            }
        }

        // Fits by the loop above: resident + missing <= capacity.
        let mut loaded = Vec::new();
        for name in &order {
            if let Some(entry) = self.entries.get_mut(name) {
                if !entry.resident {
                    entry.resident = true;
                    entry.state = ContentState::Clean;
                    self.resident_bytes = self.resident_bytes.saturating_add(entry.bytes);
                    loaded.push(name.clone());
                }
            }
        }

        for name in &order {
            let Some(entry) = self.entries.get_mut(name) else {
                continue;
            };
            entry.use_count = entry.use_count.saturating_add(1);
            entry.last_use_step = step;
            if name == key && entry.kind.mutates_on_use() {
                if let Content::SessionState(marker) = entry.content {
                    entry.content = Content::SessionState(
                        DigestBuilder::new(NEXT_SESSION_STATE)
                            .digest(&marker)
                            .finish(),
                    );
                }
                entry.state = ContentState::Dirty;
            }
            let view = ObjectView {
                key: name,
                kind: entry.kind,
                bytes: entry.bytes,
                reload_seconds: entry.reload_seconds,
                last_use_step: entry.last_use_step,
                use_count: entry.use_count,
                protected: true,
                evictable: false,
            };
            self.policy.on_use(&view, step);
        }
        self.step = step;

        Ok(AccessOutcome {
            hit: loaded.is_empty(),
            saved_seconds,
            paid_seconds,
            loaded,
            loaded_bytes: missing_bytes,
            evictions,
            written_back_bytes,
        })
    }

    fn entry_mut(&mut self, key: &str) -> Result<&mut Entry, CacheError> {
        self.entries.get_mut(key).ok_or_else(|| {
            InputError::Unknown {
                field: "object",
                name: key.to_string(),
            }
            .into()
        })
    }

    fn observe(&mut self, clock: &dyn Clock) -> Result<MonotonicTime, CacheError> {
        let now = clock.now();
        if now < self.last_seen {
            return Err(CacheError::TimeWentBack {
                last: self.last_seen,
                now,
            });
        }
        self.last_seen = now;
        self.leases.retain(|lease| lease.expires_at > now);
        Ok(now)
    }

    fn write_back(&self) -> WriteBack {
        if self.write_back_tier.is_some() {
            WriteBack::Available
        } else {
            WriteBack::Unavailable
        }
    }

    /// Resident objects that go with `key` rather than keeping it resident: its graph
    /// pools, in key order.
    fn resident_pools_of(&self, key: &str) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| {
                entry.resident
                    && !entry.kind.keeps_prerequisites_resident()
                    && entry
                        .prerequisites
                        .iter()
                        .any(|prerequisite| prerequisite == key)
            })
            .map(|(pool, _)| pool.clone())
            .collect()
    }

    /// `key` and its prerequisites, transitively, prerequisites first.
    fn need_order(&self, key: &str) -> Vec<String> {
        let mut order = Vec::new();
        let mut done: BTreeSet<&str> = BTreeSet::new();
        let mut stack: Vec<(&str, bool)> = vec![(key, false)];
        while let Some((name, expanded)) = stack.pop() {
            if done.contains(name) {
                continue;
            }
            if expanded {
                done.insert(name);
                order.push(name.to_string());
                continue;
            }
            stack.push((name, true));
            if let Some(entry) = self.entries.get(name) {
                for prerequisite in entry.prerequisites.iter().rev() {
                    if !done.contains(prerequisite.as_str()) {
                        stack.push((prerequisite, false));
                    }
                }
            }
        }
        order
    }

    /// Objects that may not be evicted now, with every prerequisite of each.
    fn protected(&self, need: &BTreeSet<String>, now: MonotonicTime) -> BTreeSet<String> {
        let write_back = self.write_back();
        let mut stack: Vec<&str> = Vec::new();
        for (key, entry) in &self.entries {
            let leased = self
                .leases
                .iter()
                .any(|lease| lease.object == *key && lease.expires_at > now);
            let retained = matches!(
                eviction_action(&entry.gpu_copy(), &entry.copies, write_back),
                EvictionAction::Retain { .. }
            );
            if need.contains(key) || (entry.resident && (entry.pinned || leased || retained)) {
                stack.push(key);
            }
        }
        let mut protected = BTreeSet::new();
        while let Some(key) = stack.pop() {
            if protected.insert(key.to_string()) {
                if let Some(entry) = self.entries.get(key) {
                    stack.extend(entry.prerequisites.iter().map(String::as_str));
                }
            }
        }
        protected
    }

    fn evict(&mut self, key: &str) -> Result<Eviction, CacheError> {
        let write_back = self.write_back();
        let tier = self.write_back_tier;
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| InputError::Unknown {
                field: "object",
                name: key.to_string(),
            })?;
        let action = eviction_action(&entry.gpu_copy(), &entry.copies, write_back);
        match (action, tier) {
            (EvictionAction::DropClean { .. } | EvictionAction::Recapture, _) => {}
            (EvictionAction::WriteBackThenDrop { .. }, Some(tier)) => {
                // The written-back copy replaces this tier's older copy once verified.
                let content = entry.content;
                entry.copies.retain(|copy| copy.tier != tier);
                entry.copies.push(ReconstructibleCopy {
                    tier,
                    verification: Verification::Verified { content },
                });
                entry.state = ContentState::Clean;
            }
            (EvictionAction::WriteBackThenDrop { .. }, None)
            | (EvictionAction::Retain { .. }, _) => {
                return Err(CacheError::MustRetain {
                    object: key.to_string(),
                })
            }
        }
        entry.resident = false;
        self.resident_bytes = self.resident_bytes.saturating_sub(entry.bytes);
        self.policy.on_evict(key);
        Ok(Eviction {
            object: key.to_string(),
            action,
        })
    }
}

/// Every resident object as a policy sees it, in key order. A resident dependent holds
/// its prerequisites, except a graph pool, which goes with its weights node.
fn views<'a>(
    entries: &'a BTreeMap<String, Entry>,
    protected: &BTreeSet<String>,
) -> Vec<ObjectView<'a>> {
    let held: BTreeSet<&str> = entries
        .values()
        .filter(|entry| entry.resident && entry.kind.keeps_prerequisites_resident())
        .flat_map(|entry| entry.prerequisites.iter().map(String::as_str))
        .collect();
    entries
        .iter()
        .filter(|(_, entry)| entry.resident)
        .map(|(key, entry)| {
            let protected = protected.contains(key);
            ObjectView {
                key,
                kind: entry.kind,
                bytes: entry.bytes,
                reload_seconds: entry.reload_seconds,
                last_use_step: entry.last_use_step,
                use_count: entry.use_count,
                protected,
                evictable: !protected && !held.contains(key.as_str()),
            }
        })
        .collect()
}

/// Every prerequisite is declared and none is reached from itself.
fn check_prerequisites(entries: &BTreeMap<String, Entry>) -> Result<(), InputError> {
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (key, entry) in entries {
        for prerequisite in &entry.prerequisites {
            if !entries.contains_key(prerequisite) {
                return Err(InputError::Unknown {
                    field: "prerequisite",
                    name: prerequisite.clone(),
                });
            }
            dependents
                .entry(prerequisite.as_str())
                .or_default()
                .push(key.as_str());
        }
    }
    let mut waiting: BTreeMap<&str, usize> = entries
        .iter()
        .map(|(key, entry)| (key.as_str(), entry.prerequisites.len()))
        .collect();
    let mut ready: Vec<&str> = waiting
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(key, _)| *key)
        .collect();
    let mut placed = 0usize;
    while let Some(key) = ready.pop() {
        placed = placed.saturating_add(1);
        for &dependent in dependents.get(key).map(Vec::as_slice).unwrap_or_default() {
            if let Some(count) = waiting.get_mut(dependent) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push(dependent);
                }
            }
        }
    }
    if placed < entries.len() {
        let name = waiting
            .iter()
            .find(|(_, count)| **count > 0)
            .map(|(key, _)| key.to_string())
            .unwrap_or_default();
        return Err(InputError::Cycle {
            field: "prerequisites",
            name,
        });
    }
    Ok(())
}

/// The prerequisite and copy rules of the kinds ([`ObjectKind`]), checked once every
/// prerequisite is known to exist.
fn check_kinds(entries: &BTreeMap<String, Entry>) -> Result<(), CacheError> {
    for (key, entry) in entries {
        for prerequisite in &entry.prerequisites {
            let Some(target) = entries.get(prerequisite) else {
                continue;
            };
            let allowed = match entry.kind {
                ObjectKind::MergedVariant => false,
                ObjectKind::GraphPool => target.kind.is_weights(),
                ObjectKind::BaseWeights | ObjectKind::Adapter | ObjectKind::SessionKv => {
                    target.kind != ObjectKind::GraphPool
                }
            };
            if !allowed {
                return Err(CacheError::ForbiddenPrerequisite {
                    object: key.clone(),
                    prerequisite: prerequisite.clone(),
                });
            }
        }
        if entry.kind != ObjectKind::GraphPool {
            continue;
        }
        let [weights] = entry.prerequisites.as_slice() else {
            return Err(CacheError::GraphPoolPrerequisites {
                object: key.clone(),
                count: entry.prerequisites.len(),
            });
        };
        let captured_over = match entry.content {
            Content::GraphPool { weights, .. } => Some(weights),
            Content::Immutable(_) | Content::SessionState(_) => None,
        };
        let held = match entries.get(weights).map(|target| target.content) {
            Some(Content::Immutable(content)) => Some(content),
            _ => None,
        };
        if captured_over != held {
            return Err(CacheError::GraphPoolForOtherWeights {
                object: key.clone(),
                prerequisite: weights.clone(),
            });
        }
        if !entry.copies.is_empty() {
            return Err(CacheError::GraphPoolCopy {
                object: key.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ContentKey, ManualClock};
    use crate::model_memory::residency::eviction::NotDroppable;
    use crate::model_memory::residency::test_support::{at, GIB};
    use std::time::Duration;

    const SESSION: &str = "yougori/test/residency/session/v1";
    const EXECUTION_KEY: &str = "yougori/test/residency/execution-key/v1";

    /// Sizes are whole GiB so every credit and ratio below is exact in binary. Weights and
    /// adapters are keyed by their name's bytes and start with a verified local copy; a
    /// session starts with no copy.
    fn object(
        key: &str,
        kind: ObjectKind,
        gib: u64,
        reload_seconds: f64,
        prerequisites: &[&str],
    ) -> CachedObject {
        let (content, copies) = if kind.mutates_on_use() {
            (
                Content::SessionState(digest(SESSION, &[key.as_bytes()])),
                Vec::new(),
            )
        } else {
            let content = Content::Immutable(ContentKey::of(key.as_bytes()));
            let copy = ReconstructibleCopy {
                tier: CopyTier::LocalStorage,
                verification: Verification::Verified { content },
            };
            (content, vec![copy])
        };
        CachedObject {
            key: key.to_string(),
            kind,
            bytes: gib * GIB,
            reload_seconds,
            prerequisites: prerequisites.iter().map(|key| key.to_string()).collect(),
            content,
            copies,
        }
    }

    fn base(key: &str, gib: u64, reload_seconds: f64) -> CachedObject {
        object(key, ObjectKind::BaseWeights, gib, reload_seconds, &[])
    }

    fn adapter(key: &str, gib: u64, reload_seconds: f64, of: &str) -> CachedObject {
        object(key, ObjectKind::Adapter, gib, reload_seconds, &[of])
    }

    fn session(key: &str, gib: u64, reload_seconds: f64, of: &str) -> CachedObject {
        object(key, ObjectKind::SessionKv, gib, reload_seconds, &[of])
    }

    /// A merged variant with no copy outside the GPU: the merge recipe is no copy.
    fn variant(key: &str, gib: u64, reload_seconds: f64) -> CachedObject {
        CachedObject {
            copies: Vec::new(),
            ..object(key, ObjectKind::MergedVariant, gib, reload_seconds, &[])
        }
    }

    /// A graph pool captured over the weights `of`, under a configuration named by the
    /// pool's key.
    fn pool(key: &str, gib: u64, reload_seconds: f64, of: &str) -> CachedObject {
        CachedObject {
            key: key.to_string(),
            kind: ObjectKind::GraphPool,
            bytes: gib * GIB,
            reload_seconds,
            prerequisites: vec![of.to_string()],
            content: Content::GraphPool {
                weights: ContentKey::of(of.as_bytes()),
                execution_key: digest(EXECUTION_KEY, &[key.as_bytes()]),
            },
            copies: Vec::new(),
        }
    }

    fn config(capacity_gib: u64, objects: Vec<CachedObject>) -> CacheConfig {
        CacheConfig {
            capacity_bytes: capacity_gib * GIB,
            objects,
            write_back_tier: Some(CopyTier::PinnedHost),
        }
    }

    fn run<P: RetentionPolicy>(
        cache: &mut ResidencyCache<P>,
        clock: &ManualClock,
        keys: &[&str],
    ) -> Vec<AccessOutcome> {
        keys.iter()
            .map(|key| {
                clock.advance(Duration::from_secs(1));
                cache.access(key, clock).unwrap()
            })
            .collect()
    }

    fn evicted(outcomes: &[AccessOutcome]) -> Vec<&str> {
        outcomes
            .iter()
            .flat_map(|outcome| {
                outcome
                    .evictions
                    .iter()
                    .map(|eviction| eviction.object.as_str())
            })
            .collect()
    }

    fn policies() -> Vec<Box<dyn RetentionPolicy>> {
        vec![
            Box::new(Lru),
            Box::new(CostPerByte),
            Box::new(MarginalSavedLatency::new(8).unwrap()),
            Box::new(GreedyDualSize::new()),
        ]
    }

    #[test]
    fn a_shared_base_counts_once_however_many_dependents_it_has() {
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(
            &config(
                16,
                vec![
                    base("b", 8, 8.0),
                    adapter("a1", 1, 2.0, "b"),
                    adapter("a2", 1, 2.0, "b"),
                    adapter("a3", 1, 2.0, "b"),
                    base("x", 4, 1.0),
                ],
            ),
            Lru,
        )
        .unwrap();
        let outcomes = run(&mut cache, &clock, &["a1", "a2", "a3", "x"]);
        assert_eq!(outcomes[0].loaded, vec!["b", "a1"]);
        assert_eq!(outcomes[0].loaded_bytes, 9 * GIB);
        assert_eq!(outcomes[0].paid_seconds, 10.0);
        assert!(!outcomes[1].hit);
        assert_eq!(outcomes[1].loaded, vec!["a2"]);
        assert_eq!(outcomes[1].saved_seconds, 8.0);
        // 8 + 3 × 1 + 4 = 15 GiB: the base is counted once, not once per adapter.
        assert_eq!(cache.resident_bytes(), 15 * GIB);
        assert!(evicted(&outcomes).is_empty());
        let hit = run(&mut cache, &clock, &["a1"]);
        assert!(hit[0].hit);
        assert_eq!(hit[0].saved_seconds, 10.0);
    }

    #[test]
    fn greedy_dual_size_charges_a_shared_base_once() {
        let objects = vec![
            base("b", 8, 8.0),
            adapter("a1", 1, 2.0, "b"),
            adapter("a2", 1, 2.0, "b"),
            adapter("a3", 1, 2.0, "b"),
            base("x", 4, 1.0),
            base("y", 4, 1.0),
        ];
        for dependents in [vec!["a1"], vec!["a1", "a2", "a3"]] {
            let clock = ManualClock::default();
            let mut cache =
                ResidencyCache::new(&config(16, objects.clone()), GreedyDualSize::new()).unwrap();
            run(&mut cache, &clock, &dependents);
            run(&mut cache, &clock, &["x"]);
            assert_eq!(cache.policy().credit("b"), Some(8.0));
            // Loading y evicts x: Δ = 1 s / 4 GiB, so the base pays 0.25 s/GiB × 8 GiB
            // = 2 s once, whether it has one dependent or three.
            let outcome = run(&mut cache, &clock, &["y"]);
            assert_eq!(evicted(&outcome), vec!["x"]);
            assert_eq!(cache.policy().credit("b"), Some(6.0));
            assert_eq!(cache.policy().credit("a1"), Some(1.75));
            assert_eq!(cache.policy().credit("x"), None);
            assert_eq!(cache.policy().credit("y"), Some(1.0));
            assert_eq!(
                cache.resident_bytes(),
                (8 + dependents.len() as u64 + 4) * GIB
            );
        }
    }

    #[test]
    fn greedy_dual_size_keeps_a_frequently_reused_base() {
        // r and b are equal in size and cost; only b is reused, through session s1.
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(
            &config(
                17,
                vec![
                    base("r", 8, 8.0),
                    base("b", 8, 8.0),
                    session("s1", 1, 0.25, "b"),
                    base("y", 1, 0.25),
                    base("x", 8, 4.0),
                ],
            ),
            GreedyDualSize::new(),
        )
        .unwrap();
        run(&mut cache, &clock, &["r", "s1", "y"]);
        // Loading y charged rent: r and b both fell from 8 to 6 s.
        assert_eq!(cache.policy().credit("r"), Some(6.0));
        run(&mut cache, &clock, &["s1"]);
        // The session's request refreshed its base; nothing refreshed r.
        assert_eq!(cache.policy().credit("b"), Some(8.0));
        assert_eq!(cache.policy().credit("r"), Some(4.0));
        let outcome = run(&mut cache, &clock, &["x"]);
        assert_eq!(evicted(&outcome), vec!["s1", "r"]);
        assert!(cache.is_resident("b"));
        assert_eq!(cache.policy().credit("b"), Some(4.0));
    }

    #[test]
    fn pinned_objects_are_never_evicted() {
        for policy in policies() {
            let name = policy.name().to_string();
            let clock = ManualClock::default();
            let mut cache = ResidencyCache::new(
                &config(
                    12,
                    vec![base("p", 4, 1.0), base("q", 4, 16.0), base("z", 8, 16.0)],
                ),
                policy,
            )
            .unwrap();
            cache.pin("p").unwrap();
            // p is the cheapest per byte and the least recent, yet it stays.
            let outcomes = run(&mut cache, &clock, &["p", "q", "z", "q", "z"]);
            assert!(!evicted(&outcomes).contains(&"p"), "{name}");
            assert!(cache.is_resident("p"), "{name}");

            // With everything else pinned too, a request that needs more room is refused
            // before anything is evicted.
            cache.pin("z").unwrap();
            let before = cache.resident_objects().join(",");
            clock.advance(Duration::from_secs(1));
            assert_eq!(
                cache.access("q", &clock),
                Err(CacheError::NoRoom {
                    object: "q".to_string(),
                    needed_bytes: 4 * GIB,
                    free_bytes: 0,
                    freeable_bytes: 0,
                }),
                "{name}"
            );
            assert_eq!(cache.resident_objects().join(","), before, "{name}");
        }
    }

    /// x needs 9 of 12 GiB, so it fits only once both the session and its base are gone.
    fn leased_cache<P: RetentionPolicy>(policy: P) -> ResidencyCache<P> {
        ResidencyCache::new(
            &config(
                12,
                vec![
                    base("b", 4, 4.0),
                    session("s", 1, 1.0, "b"),
                    base("x", 9, 1.0),
                ],
            ),
            policy,
        )
        .unwrap()
    }

    #[test]
    fn leased_sessions_and_their_bases_are_never_evicted() {
        for policy in policies() {
            let name = policy.name().to_string();
            let clock = ManualClock::default();
            let mut cache = leased_cache(policy);
            cache.access("s", &clock).unwrap();
            let execution = ExecutionId::new("exe-1").unwrap();
            cache
                .grant_lease(
                    SessionLease {
                        execution: execution.clone(),
                        authorization_epoch: Some(AuthorizationEpoch::FIRST),
                        object: "s".to_string(),
                        expires_at: at(100),
                    },
                    &clock,
                )
                .unwrap();
            clock.advance_to(at(10));
            assert!(
                matches!(
                    cache.access("x", &clock),
                    Err(CacheError::NoRoom {
                        freeable_bytes: 0,
                        ..
                    })
                ),
                "{name}"
            );
            assert!(cache.is_resident("s") && cache.is_resident("b"), "{name}");
            // Hits do not renew the lease; once it expires, both may go.
            cache.access("s", &clock).unwrap();
            clock.advance_to(at(150));
            let outcome = cache.access("x", &clock).unwrap();
            assert_eq!(
                outcome
                    .evictions
                    .iter()
                    .map(|eviction| eviction.object.as_str())
                    .collect::<Vec<_>>(),
                vec!["s", "b"],
                "{name}"
            );
            assert!(!cache.release_lease(&execution, "s"), "{name}");
        }
    }

    #[test]
    fn a_released_lease_protects_nothing() {
        let clock = ManualClock::default();
        let mut cache = leased_cache(Lru);
        cache.access("s", &clock).unwrap();
        let execution = ExecutionId::new("exe-1").unwrap();
        let lease = SessionLease {
            execution: execution.clone(),
            authorization_epoch: None,
            object: "s".to_string(),
            expires_at: at(100),
        };
        cache.grant_lease(lease.clone(), &clock).unwrap();
        assert!(!cache.release_lease(&ExecutionId::new("exe-2").unwrap(), "s"));
        assert!(cache.release_lease(&execution, "s"));
        assert!(cache.access("x", &clock).is_ok());
        assert!(!cache.is_resident("s"));

        clock.advance_to(at(200));
        assert_eq!(
            cache.grant_lease(lease.clone(), &clock),
            Err(CacheError::LeaseAlreadyExpired {
                object: "s".to_string()
            })
        );
        assert!(matches!(
            cache.grant_lease(
                SessionLease {
                    object: "nothing".to_string(),
                    expires_at: at(300),
                    ..lease
                },
                &clock
            ),
            Err(CacheError::Input(InputError::Unknown { .. }))
        ));
    }

    #[test]
    fn a_revoked_authorization_epoch_is_never_honoured_again() {
        let clock = ManualClock::default();
        let mut cache = leased_cache(GreedyDualSize::new());
        cache.access("s", &clock).unwrap();
        let lease = |epoch| SessionLease {
            execution: ExecutionId::new("exe-1").unwrap(),
            authorization_epoch: Some(AuthorizationEpoch::new(epoch)),
            object: "s".to_string(),
            expires_at: at(100),
        };
        cache.grant_lease(lease(1), &clock).unwrap();
        assert!(matches!(
            cache.access("x", &clock),
            Err(CacheError::NoRoom { .. })
        ));

        cache.revoke_authorization_before(AuthorizationEpoch::new(2));
        // An older floor never lowers the revocation.
        cache.revoke_authorization_before(AuthorizationEpoch::FIRST);
        assert_eq!(
            cache.grant_lease(lease(1), &clock),
            Err(CacheError::RevokedAuthorization {
                object: "s".to_string(),
                epoch: AuthorizationEpoch::FIRST,
            })
        );
        // The revoked lease no longer protects the session or its base.
        let outcome = cache.access("x", &clock).unwrap();
        assert_eq!(outcome.evictions.len(), 2);
        // A lease under the current epoch is honoured.
        assert!(cache.grant_lease(lease(2), &clock).is_ok());
    }

    /// Always names one object, legal or not.
    struct Rogue(&'static str);

    impl RetentionPolicy for Rogue {
        fn name(&self) -> &str {
            "rogue"
        }

        fn on_use(&mut self, _object: &ObjectView<'_>, _step: u64) {}

        fn on_evict(&mut self, _key: &str) {}

        fn choose_victim(&mut self, residents: &[ObjectView<'_>], _step: u64) -> Option<usize> {
            match self.0 {
                "nothing" => None,
                "out of range" => Some(residents.len()),
                key => residents.iter().position(|view| view.key == key),
            }
        }
    }

    #[test]
    fn no_policy_can_evict_a_protected_object() {
        let objects = vec![
            base("b", 4, 4.0),
            adapter("a", 1, 1.0, "b"),
            base("p", 4, 1.0),
            base("x", 4, 1.0),
        ];
        // p is pinned, b still has its adapter, x is the object being loaded.
        let cases = [("p", Some("p")), ("b", Some("b")), ("out of range", None)];
        for (target, named) in cases {
            let clock = ManualClock::default();
            let mut cache =
                ResidencyCache::new(&config(9, objects.clone()), Rogue(target)).unwrap();
            cache.pin("p").unwrap();
            run(&mut cache, &clock, &["a", "p"]);
            // x needs 4 GiB with none free: only a is a legal victim, and b only after it.
            clock.advance(Duration::from_secs(1));
            assert_eq!(
                cache.access("x", &clock),
                Err(CacheError::PolicyChoseIneligible {
                    policy: "rogue".to_string(),
                    object: named.map(str::to_string),
                })
            );
            assert!(cache.is_resident("p") && cache.is_resident("b") && cache.is_resident("a"));
        }
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(9, objects), Rogue("nothing")).unwrap();
        run(&mut cache, &clock, &["a", "p"]);
        assert_eq!(
            cache.access("x", &clock),
            Err(CacheError::PolicyChoseNothing {
                policy: "rogue".to_string()
            })
        );
    }

    #[test]
    fn an_object_larger_than_the_cache_is_refused() {
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(4, vec![base("big", 8, 1.0)]), Lru).unwrap();
        assert_eq!(
            cache.access("big", &clock),
            Err(CacheError::NoRoom {
                object: "big".to_string(),
                needed_bytes: 8 * GIB,
                free_bytes: 4 * GIB,
                freeable_bytes: 0,
            })
        );
        assert_eq!(cache.resident_bytes(), 0);
    }

    #[test]
    fn dirty_session_state_is_written_back_before_it_leaves() {
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(
            &config(
                10,
                vec![
                    base("b", 4, 4.0),
                    session("s", 1, 2.0, "b"),
                    base("x", 6, 1.0),
                ],
            ),
            Lru,
        )
        .unwrap();
        let outcomes = run(&mut cache, &clock, &["s", "x"]);
        assert_eq!(cache.content_state("s"), Some(ContentState::Clean));
        assert_eq!(
            outcomes[1].evictions,
            vec![Eviction {
                object: "s".to_string(),
                action: EvictionAction::WriteBackThenDrop {
                    d2h_bytes: GIB,
                    because: NotDroppable::Dirty,
                },
            }]
        );
        assert_eq!(outcomes[1].written_back_bytes, GIB);
        let first_copy = cache.copies("s").unwrap().to_vec();
        assert_eq!(first_copy.len(), 1);
        assert_eq!(first_copy[0].tier, CopyTier::PinnedHost);

        // Used again, the session changes, so its earlier copy no longer reconstructs it
        // and the next eviction writes back again; the base drops clean.
        let outcomes = run(&mut cache, &clock, &["s", "x"]);
        assert_eq!(cache.content_state("s"), Some(ContentState::Clean));
        assert_eq!(outcomes[0].evictions.len(), 1);
        assert_eq!(outcomes[0].evictions[0].object, "x");
        assert_eq!(
            outcomes[0].evictions[0].action,
            EvictionAction::DropClean {
                source: CopyTier::LocalStorage
            }
        );
        assert_eq!(outcomes[1].written_back_bytes, GIB);
        let second_copy = cache.copies("s").unwrap();
        assert_eq!(second_copy.len(), 1);
        assert_ne!(second_copy[0], first_copy[0]);
    }

    #[test]
    fn without_a_write_back_path_dirty_state_is_retained() {
        let clock = ManualClock::default();
        let mut retaining = config(
            10,
            vec![
                base("b", 4, 4.0),
                session("s", 1, 2.0, "b"),
                base("x", 6, 1.0),
            ],
        );
        retaining.write_back_tier = None;
        let mut cache = ResidencyCache::new(&retaining, Lru).unwrap();
        run(&mut cache, &clock, &["s"]);
        assert_eq!(cache.content_state("s"), Some(ContentState::Dirty));
        // Making room for x would drop the dirty session: refused instead.
        assert!(matches!(
            cache.access("x", &clock),
            Err(CacheError::NoRoom {
                freeable_bytes: 0,
                ..
            })
        ));
        assert!(cache.is_resident("s"));
    }

    #[test]
    fn an_unverified_base_is_written_back_once_then_dropped_clean() {
        let clock = ManualClock::default();
        let mut unverified = base("u", 4, 4.0);
        unverified.copies = vec![ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Unverified,
        }];
        let mut cache = ResidencyCache::new(
            &config(8, vec![unverified, base("v", 4, 1.0), base("w", 4, 1.0)]),
            Lru,
        )
        .unwrap();
        let outcomes = run(&mut cache, &clock, &["u", "v", "w", "u", "v", "w"]);
        let actions: Vec<(&str, EvictionAction)> = outcomes
            .iter()
            .flat_map(|outcome| {
                outcome
                    .evictions
                    .iter()
                    .map(|eviction| (eviction.object.as_str(), eviction.action))
            })
            .collect();
        assert_eq!(
            actions,
            vec![
                (
                    "u",
                    EvictionAction::WriteBackThenDrop {
                        d2h_bytes: 4 * GIB,
                        because: NotDroppable::NoVerifiedCopy,
                    }
                ),
                (
                    "v",
                    EvictionAction::DropClean {
                        source: CopyTier::LocalStorage
                    }
                ),
                (
                    "w",
                    EvictionAction::DropClean {
                        source: CopyTier::LocalStorage
                    }
                ),
                (
                    "u",
                    EvictionAction::DropClean {
                        source: CopyTier::PinnedHost
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_write_back_must_leave_a_reconstructible_copy() {
        let mut reclaimable = config(8, vec![base("u", 4, 4.0)]);
        reclaimable.write_back_tier = Some(CopyTier::ReclaimableHost);
        assert!(matches!(
            ResidencyCache::new(&reclaimable, Lru),
            Err(CacheError::WriteBackTierNotGuaranteed {
                tier: CopyTier::ReclaimableHost
            })
        ));
    }

    #[test]
    fn marginal_saved_latency_keeps_what_requests_reuse() {
        // r is the most expensive per byte but was used once; adapter a is used often.
        let objects = vec![
            base("b", 8, 4.0),
            adapter("a", 1, 0.5, "b"),
            base("r", 4, 4.0),
            base("n", 4, 1.0),
        ];
        let trace = ["r", "a", "a", "a", "a", "n", "a"];

        let clock = ManualClock::default();
        let mut marginal = ResidencyCache::new(
            &config(13, objects.clone()),
            MarginalSavedLatency::new(8).unwrap(),
        )
        .unwrap();
        let outcomes = run(&mut marginal, &clock, &trace);
        assert_eq!(evicted(&outcomes), vec!["r"]);
        assert!(outcomes[6].hit);
        // Every adapter request is a use of its base too.
        assert_eq!(
            marginal.policy().expected_uses("b", 7),
            marginal.policy().expected_uses("a", 7)
        );
        // Uses at steps 2, 3, 4, 5 and 7, each halved every 8 steps: Σ 2^(−age/8).
        let closed_form: f64 = [5.0f64, 4.0, 3.0, 2.0, 0.0]
            .iter()
            .map(|age| (-age / 8.0).exp2())
            .sum();
        assert!((marginal.policy().expected_uses("b", 7) - closed_form).abs() < 1e-12);

        let clock = ManualClock::default();
        let mut cheapest = ResidencyCache::new(&config(13, objects), CostPerByte).unwrap();
        let outcomes = run(&mut cheapest, &clock, &trace);
        // Cost per byte drops the reused adapter and its base, then misses on them.
        assert_eq!(evicted(&outcomes), vec!["a", "b", "n"]);
        assert!(!outcomes[6].hit);
    }

    #[test]
    fn the_decayed_count_halves_every_half_life() {
        let mut policy = MarginalSavedLatency::new(4).unwrap();
        let view = ObjectView {
            key: "k",
            kind: ObjectKind::BaseWeights,
            bytes: 2,
            reload_seconds: 3.0,
            last_use_step: 1,
            use_count: 1,
            protected: false,
            evictable: true,
        };
        policy.on_use(&view, 1);
        assert_eq!(policy.expected_uses("k", 1), 1.0);
        assert_eq!(policy.expected_uses("k", 5), 0.5);
        assert_eq!(policy.expected_uses("k", 9), 0.25);
        // 0.25 uses × 3 s / 2 bytes.
        assert_eq!(policy.saved_seconds_per_byte(&view, 9), 0.375);
        assert_eq!(policy.expected_uses("other", 9), 0.0);
        assert_eq!(
            MarginalSavedLatency::new(0),
            Err(InputError::NotPositive {
                field: "half-life steps"
            })
        );
    }

    #[test]
    fn the_catalog_is_validated() {
        let check =
            |objects: Vec<CachedObject>| ResidencyCache::new(&config(8, objects), Lru).map(|_| ());
        assert!(matches!(
            check(vec![base("a", 1, 1.0), base("a", 1, 1.0)]),
            Err(CacheError::Input(InputError::Duplicate { .. }))
        ));
        // Weights named by a session marker, or a session named by a content key, are
        // refused: the two identities never mix.
        let marker = Content::SessionState(digest(SESSION, &[b"w"]));
        assert_eq!(
            check(vec![CachedObject {
                content: marker,
                ..base("w", 1, 1.0)
            }]),
            Err(CacheError::WrongContentKind {
                object: "w".to_string()
            })
        );
        assert_eq!(
            check(vec![
                base("b", 1, 1.0),
                CachedObject {
                    content: Content::Immutable(ContentKey::of(b"s")),
                    ..session("s", 1, 1.0, "b")
                }
            ]),
            Err(CacheError::WrongContentKind {
                object: "s".to_string()
            })
        );
        assert!(matches!(
            check(vec![adapter("a", 1, 1.0, "missing")]),
            Err(CacheError::Input(InputError::Unknown { .. }))
        ));
        assert!(matches!(
            check(vec![adapter("a", 1, 1.0, "a")]),
            Err(CacheError::Input(InputError::Cycle { .. }))
        ));
        assert!(matches!(
            check(vec![adapter("a", 1, 1.0, "b"), adapter("b", 1, 1.0, "a")]),
            Err(CacheError::Input(InputError::Cycle { .. }))
        ));
        assert!(matches!(
            check(vec![
                object("a", ObjectKind::Adapter, 1, 1.0, &["b", "b"]),
                base("b", 1, 1.0)
            ]),
            Err(CacheError::Input(InputError::Duplicate { .. }))
        ));
        assert!(matches!(
            check(vec![base("a", 0, 1.0)]),
            Err(CacheError::Input(InputError::NotPositive { .. }))
        ));
        assert!(matches!(
            check(vec![base("a", 1, f64::NAN)]),
            Err(CacheError::Input(InputError::NotFinite { .. }))
        ));
        assert!(matches!(
            check(vec![base("", 1, 1.0)]),
            Err(CacheError::Input(InputError::EmptyName { .. }))
        ));
        assert!(matches!(
            ResidencyCache::new(&config(0, Vec::new()), Lru),
            Err(CacheError::Input(InputError::NotPositive { .. }))
        ));
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(8, vec![base("a", 1, 1.0)]), Lru).unwrap();
        assert!(matches!(
            cache.access("missing", &clock),
            Err(CacheError::Input(InputError::Unknown { .. }))
        ));
        assert!(cache.pin("missing").is_err());
        assert!(cache.unpin("a").is_ok());
    }

    #[test]
    fn a_merged_variant_is_a_base_to_its_sessions_and_never_keeps_its_source_base() {
        // The base is the oldest, the cheapest per byte and the lowest in credit, so
        // every policy takes it; the variant merged from it stays for its sessions.
        let objects = vec![
            base("b", 8, 0.5),
            variant("m", 8, 4.0),
            session("s1", 1, 2.0, "m"),
            session("s2", 1, 2.0, "m"),
            session("s3", 1, 2.0, "m"),
            base("x", 4, 1.0),
        ];
        for policy in policies() {
            let name = policy.name().to_string();
            let clock = ManualClock::default();
            let mut cache = ResidencyCache::new(&config(20, objects.clone()), policy).unwrap();
            run(&mut cache, &clock, &["b"]);
            let outcomes = run(&mut cache, &clock, &["s1", "s2", "s3"]);
            // The variant is loaded once for its first session and charged once.
            assert_eq!(outcomes[0].loaded, vec!["m", "s1"], "{name}");
            assert_eq!(outcomes[1].loaded, vec!["s2"], "{name}");
            assert_eq!(outcomes[1].saved_seconds, 4.0, "{name}");
            assert_eq!(cache.resident_bytes(), 19 * GIB, "{name}");

            let outcome = run(&mut cache, &clock, &["x"]);
            assert_eq!(evicted(&outcome), vec!["b"], "{name}");
            assert!(cache.is_resident("m") && !cache.is_resident("b"), "{name}");
        }

        // Structurally: the base is a legal victim while the variant and its session
        // are resident, and the variant is not while its session is.
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(20, objects.clone()), Rogue("b")).unwrap();
        run(&mut cache, &clock, &["b", "s1"]);
        cache.pin("s1").unwrap();
        let outcome = run(&mut cache, &clock, &["x"]);
        assert_eq!(evicted(&outcome), vec!["b"]);
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(20, objects), Rogue("m")).unwrap();
        run(&mut cache, &clock, &["b", "s1"]);
        assert_eq!(
            cache.access("x", &clock),
            Err(CacheError::PolicyChoseIneligible {
                policy: "rogue".to_string(),
                object: Some("m".to_string()),
            })
        );
    }

    #[test]
    fn greedy_dual_size_charges_a_merged_variant_once() {
        let objects = vec![
            variant("m", 8, 8.0),
            session("s1", 1, 2.0, "m"),
            session("s2", 1, 2.0, "m"),
            session("s3", 1, 2.0, "m"),
            base("x", 4, 1.0),
            base("y", 4, 1.0),
        ];
        for sessions in [vec!["s1"], vec!["s1", "s2", "s3"]] {
            let clock = ManualClock::default();
            let mut cache =
                ResidencyCache::new(&config(16, objects.clone()), GreedyDualSize::new()).unwrap();
            run(&mut cache, &clock, &sessions);
            run(&mut cache, &clock, &["x"]);
            assert_eq!(cache.policy().credit("m"), Some(8.0));
            // Loading y evicts x: Δ = 1 s / 4 GiB, so the variant pays 2 s once, whether
            // one session or three use it.
            let outcome = run(&mut cache, &clock, &["y"]);
            assert_eq!(evicted(&outcome), vec!["x"]);
            assert_eq!(cache.policy().credit("m"), Some(6.0));
            assert_eq!(cache.policy().credit("s1"), Some(1.75));
            assert_eq!(
                cache.resident_bytes(),
                (8 + sessions.len() as u64 + 4) * GIB
            );
        }
    }

    #[test]
    fn a_merged_variant_without_a_verified_copy_is_written_back_or_retained_never_dropped() {
        // The variant has no copy of its own bytes; a verified copy of the base it was
        // merged from is other content, and the merge recipe is no copy.
        let mut from_base = variant("m", 8, 4.0);
        from_base.copies = vec![ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Verified {
                content: Content::Immutable(ContentKey::of(b"b")),
            },
        }];
        let objects = vec![from_base, base("x", 8, 1.0)];

        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(8, objects.clone()), Lru).unwrap();
        let outcomes = run(&mut cache, &clock, &["m", "x"]);
        assert_eq!(
            outcomes[1].evictions,
            vec![Eviction {
                object: "m".to_string(),
                action: EvictionAction::WriteBackThenDrop {
                    d2h_bytes: 8 * GIB,
                    because: NotDroppable::NoVerifiedCopy,
                },
            }]
        );
        assert_eq!(outcomes[1].written_back_bytes, 8 * GIB);
        // The written-back copy of its own bytes is what lets it drop clean afterwards.
        let outcomes = run(&mut cache, &clock, &["m", "x"]);
        assert_eq!(
            outcomes[1].evictions[0].action,
            EvictionAction::DropClean {
                source: CopyTier::PinnedHost
            }
        );

        let clock = ManualClock::default();
        let mut retaining = config(8, objects);
        retaining.write_back_tier = None;
        let mut cache = ResidencyCache::new(&retaining, Lru).unwrap();
        run(&mut cache, &clock, &["m"]);
        assert!(matches!(
            cache.access("x", &clock),
            Err(CacheError::NoRoom {
                freeable_bytes: 0,
                ..
            })
        ));
        assert!(cache.is_resident("m"));
    }

    #[test]
    fn a_merged_variant_keeps_nothing_resident() {
        let check =
            |objects: Vec<CachedObject>| ResidencyCache::new(&config(8, objects), Lru).map(|_| ());
        for prerequisite in ["b", "a"] {
            assert_eq!(
                check(vec![
                    base("b", 1, 1.0),
                    adapter("a", 1, 1.0, "b"),
                    CachedObject {
                        prerequisites: vec![prerequisite.to_string()],
                        ..variant("m", 1, 1.0)
                    },
                ]),
                Err(CacheError::ForbiddenPrerequisite {
                    object: "m".to_string(),
                    prerequisite: prerequisite.to_string(),
                })
            );
        }
    }

    #[test]
    fn a_graph_pool_is_evicted_before_its_weights_node_and_goes_with_it() {
        for policy in policies() {
            let name = policy.name().to_string();
            let clock = ManualClock::default();
            let mut cache = ResidencyCache::new(
                &config(
                    9,
                    vec![
                        base("b", 8, 8.0),
                        pool("b-graphs", 1, 1.0, "b"),
                        base("z", 9, 1.0),
                    ],
                ),
                policy,
            )
            .unwrap();
            let outcome = run(&mut cache, &clock, &["b-graphs"]);
            assert_eq!(outcome[0].loaded, vec!["b", "b-graphs"], "{name}");
            // z needs the whole device: the pool goes first, for recapture, then its node.
            let outcome = run(&mut cache, &clock, &["z"]);
            assert_eq!(
                outcome[0].evictions,
                vec![
                    Eviction {
                        object: "b-graphs".to_string(),
                        action: EvictionAction::Recapture,
                    },
                    Eviction {
                        object: "b".to_string(),
                        action: EvictionAction::DropClean {
                            source: CopyTier::LocalStorage
                        },
                    },
                ],
                "{name}"
            );
            assert_eq!(outcome[0].written_back_bytes, 0, "{name}");
            assert!(!cache.is_resident("b-graphs"), "{name}");
        }
    }

    #[test]
    fn a_graph_pool_never_keeps_its_weights_node_resident() {
        // Under GreedyDual-Size the pool holds 4 s/GiB of credit, the base 0.25 s/GiB and
        // y 0.5 s/GiB: the base is the cheapest legal victim although its pool is
        // resident, and the pool goes with it.
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(
            &config(
                11,
                vec![
                    base("b", 8, 2.0),
                    pool("b-graphs", 1, 4.0, "b"),
                    base("y", 2, 1.0),
                    base("z", 8, 1.0),
                ],
            ),
            GreedyDualSize::new(),
        )
        .unwrap();
        run(&mut cache, &clock, &["b-graphs", "y"]);
        let outcome = run(&mut cache, &clock, &["z"]);
        assert_eq!(evicted(&outcome), vec!["b-graphs", "b"]);
        assert!(cache.is_resident("y"));

        // A rogue policy naming the node while its pool is resident is within its rights;
        // naming the node while a session depends on it is not.
        let objects = vec![
            base("b", 4, 1.0),
            pool("b-graphs", 1, 1.0, "b"),
            session("s", 1, 1.0, "b"),
            base("x", 4, 1.0),
        ];
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(6, objects.clone()), Rogue("b")).unwrap();
        run(&mut cache, &clock, &["b-graphs"]);
        let outcome = run(&mut cache, &clock, &["x"]);
        assert_eq!(evicted(&outcome), vec!["b-graphs", "b"]);
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(6, objects), Rogue("b")).unwrap();
        run(&mut cache, &clock, &["b-graphs", "s"]);
        assert_eq!(
            cache.access("x", &clock),
            Err(CacheError::PolicyChoseIneligible {
                policy: "rogue".to_string(),
                object: Some("b".to_string()),
            })
        );
        assert!(cache.is_resident("b-graphs"));
    }

    #[test]
    fn a_graph_pool_is_dropped_for_recapture_never_written_back() {
        // Neither the pool nor its node has a copy and there is no write-back path: the
        // node is retained, and the pool still goes, for recapture, with no bytes moved.
        let mut uncopied = base("b", 4, 4.0);
        uncopied.copies.clear();
        let mut retaining = config(
            6,
            vec![uncopied, pool("b-graphs", 1, 1.0, "b"), base("x", 2, 1.0)],
        );
        retaining.write_back_tier = None;
        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&retaining, Lru).unwrap();
        run(&mut cache, &clock, &["b-graphs"]);
        let outcome = run(&mut cache, &clock, &["x"]);
        assert_eq!(
            outcome[0].evictions,
            vec![Eviction {
                object: "b-graphs".to_string(),
                action: EvictionAction::Recapture,
            }]
        );
        assert_eq!(outcome[0].written_back_bytes, 0);
        assert!(cache.is_resident("b") && !cache.is_resident("b-graphs"));
        assert!(cache.copies("b-graphs").unwrap().is_empty());

        // The pool's bytes are the only ones that may go: a request needing the retained
        // node's bytes too is refused, and the pool stays with its node.
        let mut more = retaining.clone();
        more.objects.push(base("w", 3, 1.0));
        let mut cache = ResidencyCache::new(&more, Lru).unwrap();
        run(&mut cache, &clock, &["b-graphs"]);
        assert_eq!(
            cache.access("w", &clock),
            Err(CacheError::NoRoom {
                object: "w".to_string(),
                needed_bytes: 3 * GIB,
                free_bytes: GIB,
                freeable_bytes: GIB,
            })
        );
        assert!(cache.is_resident("b") && cache.is_resident("b-graphs"));
    }

    #[test]
    fn a_graph_pool_is_captured_over_exactly_one_weights_node() {
        let check =
            |objects: Vec<CachedObject>| ResidencyCache::new(&config(8, objects), Lru).map(|_| ());
        let with = |prerequisites: &[&str]| CachedObject {
            prerequisites: prerequisites.iter().map(|key| key.to_string()).collect(),
            ..pool("p", 1, 1.0, "b")
        };
        let catalog = || {
            vec![
                base("b", 1, 1.0),
                base("c", 1, 1.0),
                adapter("a", 1, 1.0, "b"),
                variant("m", 1, 1.0),
                session("s", 1, 1.0, "b"),
            ]
        };
        for (prerequisites, count) in [(vec![], 0), (vec!["b", "c"], 2)] {
            let mut objects = catalog();
            objects.push(with(&prerequisites));
            assert_eq!(
                check(objects),
                Err(CacheError::GraphPoolPrerequisites {
                    object: "p".to_string(),
                    count,
                })
            );
        }
        for prerequisite in ["a", "s"] {
            let mut objects = catalog();
            objects.push(with(&[prerequisite]));
            assert_eq!(
                check(objects),
                Err(CacheError::ForbiddenPrerequisite {
                    object: "p".to_string(),
                    prerequisite: prerequisite.to_string(),
                })
            );
        }
        // Over a merged variant is fine, with a capture key naming that variant.
        let mut objects = catalog();
        objects.push(pool("p", 1, 1.0, "m"));
        assert_eq!(check(objects), Ok(()));
        // The capture key must name the weights the pool depends on.
        let mut objects = catalog();
        objects.push(CachedObject {
            prerequisites: vec!["c".to_string()],
            ..pool("p", 1, 1.0, "b")
        });
        assert_eq!(
            check(objects),
            Err(CacheError::GraphPoolForOtherWeights {
                object: "p".to_string(),
                prerequisite: "c".to_string(),
            })
        );
        // No tier holds graph resources, so a pool lists no copy.
        let mut objects = catalog();
        let mut copied = pool("p", 1, 1.0, "b");
        copied.copies = vec![ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Verified {
                content: copied.content,
            },
        }];
        objects.push(copied);
        assert_eq!(
            check(objects),
            Err(CacheError::GraphPoolCopy {
                object: "p".to_string()
            })
        );
        // A pool's content is a capture key, and only a pool holds one.
        let mut objects = catalog();
        objects.push(CachedObject {
            content: Content::Immutable(ContentKey::of(b"p")),
            ..pool("p", 1, 1.0, "b")
        });
        assert_eq!(
            check(objects),
            Err(CacheError::WrongContentKind {
                object: "p".to_string()
            })
        );
        assert_eq!(
            check(vec![CachedObject {
                content: pool("p", 1, 1.0, "b").content,
                ..base("b", 1, 1.0)
            }]),
            Err(CacheError::WrongContentKind {
                object: "b".to_string()
            })
        );
        assert_eq!(
            check(vec![CachedObject {
                content: pool("p", 1, 1.0, "b").content,
                ..variant("m", 1, 1.0)
            }]),
            Err(CacheError::WrongContentKind {
                object: "m".to_string()
            })
        );
    }

    #[test]
    fn nothing_depends_on_a_graph_pool_and_no_lease_holds_one() {
        let check =
            |objects: Vec<CachedObject>| ResidencyCache::new(&config(8, objects), Lru).map(|_| ());
        let catalog = || vec![base("b", 1, 1.0), pool("p", 1, 1.0, "b")];
        for dependent in [
            session("s", 1, 1.0, "p"),
            object("a", ObjectKind::Adapter, 1, 1.0, &["p"]),
            pool("q", 1, 1.0, "p"),
        ] {
            let name = dependent.key.clone();
            let mut objects = catalog();
            objects.push(dependent);
            assert_eq!(
                check(objects),
                Err(CacheError::ForbiddenPrerequisite {
                    object: name,
                    prerequisite: "p".to_string(),
                })
            );
        }

        let clock = ManualClock::default();
        let mut cache = ResidencyCache::new(&config(8, catalog()), Lru).unwrap();
        run(&mut cache, &clock, &["p"]);
        assert_eq!(
            cache.grant_lease(
                SessionLease {
                    execution: ExecutionId::new("exe-1").unwrap(),
                    authorization_epoch: None,
                    object: "p".to_string(),
                    expires_at: at(100),
                },
                &clock
            ),
            Err(CacheError::LeaseOnGraphPool {
                object: "p".to_string()
            })
        );
        // Pinning a pool is an explicit choice, and it protects the node under it.
        cache.pin("p").unwrap();
        let mut more = config(8, catalog());
        more.objects.push(base("x", 8, 1.0));
        let mut cache = ResidencyCache::new(&more, Lru).unwrap();
        run(&mut cache, &clock, &["p"]);
        cache.pin("p").unwrap();
        assert!(matches!(
            cache.access("x", &clock),
            Err(CacheError::NoRoom {
                freeable_bytes: 0,
                ..
            })
        ));
    }

    #[test]
    fn time_never_goes_back() {
        let mut cache = ResidencyCache::new(&config(8, vec![base("a", 1, 1.0)]), Lru).unwrap();
        cache.access("a", &ManualClock::new(at(100))).unwrap();
        assert_eq!(
            cache.access("a", &ManualClock::new(at(50))),
            Err(CacheError::TimeWentBack {
                last: at(100),
                now: at(50)
            })
        );
    }
}
