//! Seeded synthetic request traces for the replay evaluator (GPU-W06 acceptance, line
//! 1249: "mixed and adversarial traces ... Do not accept only alternating A/B results";
//! §4.14's first prototype, line 1006: adversarial and shared-base workloads; GPU-T37).
//!
//! A [`ReplayTrace`] is a catalog of objects (standalone models, and optionally one
//! shared base with adapters on it), the targets the workload declares it may request
//! (the declared-intent gate a predictor ranks within), the budget every policy replays
//! it under, how requests arrive, and the requests. Each request names its target, the
//! gap before it and the part of that gap the workload declares in advance (§4.1: a
//! request never arrives before its declared earliest time); preparation for a request
//! must finish within its declared gap.
//!
//! Requests arrive in one of two ways ([`ArrivalMode`]). In a closed loop, as in §4.1
//! ("prepare the next model while the current tool runs"), the gap runs from the moment
//! the previous request was served: a tool or a person works in between. In an open
//! loop the gap runs from the previous request's arrival whether or not it was served, so
//! requests queue behind slow loads.
//!
//! The patterns:
//!
//! - [`TraceKind::Alternating`]: two models that do not fit together, A B A B (closed).
//! - [`TraceKind::Scan`]: a cycle over more models than fit, LRU's worst case (closed).
//! - [`TraceKind::Bursty`]: bursts of one model with short gaps, long idle gaps between
//!   bursts, the next burst's model following a usual successor or not (open).
//! - [`TraceKind::Mixed`]: models and adapters on a shared base, a Markov chain with a
//!   usual successor, repeats and uniform noise (closed).
//! - [`TraceKind::AdversarialToMarkov`]: each next target is drawn among those a
//!   [`MarkovPredictor`] with the trace's configuration, fed the same history, does not
//!   rank first, so its top forecast is never right (closed).
//!
//! Randomness comes only from [`SeededRng`]; the same specification and seed always give
//! the same trace.

use std::collections::BTreeSet;
use std::time::Duration;

use super::markov::{MarkovConfig, MarkovPredictor};
use super::replay::ReplayBudget;
use super::{PredictionError, Predictor};
use crate::foundation::ids::ContentKey;
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};
use crate::model_memory::residency::retention::{CacheConfig, CachedObject, ObjectKind};

const GB: u64 = 1_000_000_000;
const HALF_GB: u64 = GB / 2;
const PPM: u64 = 1_000_000;

/// A request pattern (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceKind {
    Alternating,
    Scan,
    Bursty,
    Mixed,
    AdversarialToMarkov,
}

impl TraceKind {
    pub const ALL: [Self; 5] = [
        Self::Alternating,
        Self::Scan,
        Self::Bursty,
        Self::Mixed,
        Self::AdversarialToMarkov,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Alternating => "alternating",
            Self::Scan => "scan",
            Self::Bursty => "bursty",
            Self::Mixed => "mixed",
            Self::AdversarialToMarkov => "adversarial-to-markov",
        }
    }
}

/// When a request arrives (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrivalMode {
    /// The gap runs from the previous request's arrival; requests may queue.
    Open,
    /// The gap runs from the moment the previous request was served.
    Closed,
}

/// One object of a trace's catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogObject {
    pub key: String,
    /// [`ObjectKind::BaseWeights`] or [`ObjectKind::Adapter`]: immutable, with a verified
    /// local copy, so eviction drops it clean.
    pub kind: ObjectKind,
    pub bytes: u64,
    /// The time to load it on the replay clock; more than zero.
    pub load_nanos: u64,
    /// Objects resident whenever it is, such as an adapter's base.
    pub prerequisites: Vec<String>,
}

/// One request of a trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceRequest {
    /// A declared target: a catalog object, needed with its prerequisites.
    pub target: String,
    /// The gap before this request ([`ArrivalMode`]); the first request's runs from time
    /// zero.
    pub gap: Duration,
    /// The part of `gap` the workload declares in advance: preparation for this request
    /// must finish within it. At most `gap`.
    pub declared_gap: Duration,
}

/// A replayable trace (see the module documentation).
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayTrace {
    pub kind: TraceKind,
    pub seed: u64,
    pub arrivals: ArrivalMode,
    pub catalog: Vec<CatalogObject>,
    /// The targets the workload declares; a predictor ranks only these.
    pub declared: Vec<String>,
    /// The budget every policy replays this trace under.
    pub budget: ReplayBudget,
    pub requests: Vec<TraceRequest>,
}

impl ReplayTrace {
    /// Checks the trace: unique catalog keys of base weights or adapters with positive
    /// bytes and loads, known and acyclic prerequisites; declared targets in the catalog;
    /// requests for declared targets whose declared gap is at most their gap; every
    /// request's closure within the capacity. [`CacheConfig`] checks the rest.
    pub fn check(&self) -> Result<(), PredictionError> {
        let invalid = |field, reason| Err(PredictionError::InvalidConfig { field, reason });
        let mut keys = BTreeSet::new();
        for object in &self.catalog {
            if !keys.insert(object.key.as_str()) {
                return Err(PredictionError::DuplicateObject {
                    key: object.key.clone(),
                });
            }
            if !matches!(object.kind, ObjectKind::BaseWeights | ObjectKind::Adapter) {
                return invalid("catalog.kind", "base weights or adapters only");
            }
            if object.bytes == 0 || object.load_nanos == 0 {
                return invalid("catalog", "bytes and load time more than zero");
            }
        }
        for object in &self.catalog {
            self.closure(&object.key)?;
        }
        for target in &self.declared {
            if !keys.contains(target.as_str()) {
                return Err(PredictionError::UnknownObject {
                    key: target.clone(),
                });
            }
        }
        if self.budget.capacity_bytes == 0 {
            return invalid("budget.capacity_bytes", "more than zero");
        }
        for request in &self.requests {
            if !self.declared.contains(&request.target) {
                return invalid("requests", "a request for an undeclared target");
            }
            if request.declared_gap > request.gap {
                return invalid("requests", "a declared gap longer than the gap");
            }
            let bytes = self.closure_bytes(&request.target)?;
            if bytes > self.budget.capacity_bytes {
                return Err(PredictionError::DoesNotFit {
                    key: request.target.clone(),
                    bytes,
                    capacity: self.budget.capacity_bytes,
                });
            }
        }
        Ok(())
    }

    /// The catalog object `key`.
    pub fn object(&self, key: &str) -> Option<&CatalogObject> {
        self.catalog.iter().find(|object| object.key == key)
    }

    /// `key` and its prerequisites, transitively, prerequisites first. Refuses an unknown
    /// object or a prerequisite cycle.
    pub fn closure(&self, key: &str) -> Result<Vec<String>, PredictionError> {
        let mut order: Vec<String> = Vec::new();
        let mut path: Vec<String> = Vec::new();
        self.visit(key, &mut path, &mut order)?;
        Ok(order)
    }

    fn visit(
        &self,
        key: &str,
        path: &mut Vec<String>,
        order: &mut Vec<String>,
    ) -> Result<(), PredictionError> {
        if order.iter().any(|done| done == key) {
            return Ok(());
        }
        if path.iter().any(|open| open == key) {
            return Err(PredictionError::InvalidConfig {
                field: "catalog.prerequisites",
                reason: "a prerequisite cycle",
            });
        }
        let object = self
            .object(key)
            .ok_or_else(|| PredictionError::UnknownObject {
                key: key.to_string(),
            })?;
        path.push(key.to_string());
        for prerequisite in &object.prerequisites {
            self.visit(prerequisite, path, order)?;
        }
        path.pop();
        order.push(key.to_string());
        Ok(())
    }

    /// Bytes of `key` with its prerequisites, each once.
    pub fn closure_bytes(&self, key: &str) -> Result<u64, PredictionError> {
        self.closure(key)?.iter().try_fold(0u64, |total, name| {
            let bytes = self.object(name).map_or(0, |object| object.bytes);
            total
                .checked_add(bytes)
                .ok_or(PredictionError::Overflow { field: "bytes" })
        })
    }

    /// The residency cache's configuration: the budget's capacity and the catalog, each
    /// object with a verified local-storage copy so that eviction drops it clean. Reload
    /// seconds are the load times, which the reload-cost baselines rank by.
    pub fn cache_config(&self) -> CacheConfig {
        CacheConfig {
            capacity_bytes: self.budget.capacity_bytes,
            objects: self
                .catalog
                .iter()
                .map(|object| {
                    let content = Content::Immutable(ContentKey::of(object.key.as_bytes()));
                    CachedObject {
                        key: object.key.clone(),
                        kind: object.kind,
                        bytes: object.bytes,
                        reload_seconds: Duration::from_nanos(object.load_nanos).as_secs_f64(),
                        prerequisites: object.prerequisites.clone(),
                        content,
                        copies: vec![ReconstructibleCopy {
                            tier: CopyTier::LocalStorage,
                            verification: Verification::Verified { content },
                        }],
                    }
                })
                .collect(),
            write_back_tier: None,
        }
    }
}

/// How a trace is generated. [`TraceSpec::standard`] and [`TraceSpec::tiny`] give the
/// evaluation's fixed specifications.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TraceSpec {
    pub kind: TraceKind,
    pub arrivals: ArrivalMode,
    pub requests: usize,
    /// Standalone models `model-<i>`, at least two.
    pub models: usize,
    /// Model sizes, drawn in half-gigabyte steps between these.
    pub min_model_bytes: u64,
    pub max_model_bytes: u64,
    /// Adapters `adapter-<i>` on one shared `base`; zero for none.
    pub adapters: usize,
    pub base_bytes: u64,
    pub adapter_bytes: u64,
    /// Load time per gigabyte on the replay clock.
    pub load_nanos_per_gb: u64,
    /// Each object's fixed setup time on top (engine start, graph capture), drawn between
    /// these, so reload cost is not proportional to bytes.
    pub min_setup: Duration,
    pub max_setup: Duration,
    /// Gaps before requests (before a burst's first request for bursty traces); the
    /// declared gap is the minimum.
    pub min_gap: Duration,
    pub max_gap: Duration,
    /// Bursty only: burst lengths and the gaps inside a burst.
    pub min_burst: usize,
    pub max_burst: usize,
    pub min_burst_gap: Duration,
    pub max_burst_gap: Duration,
    /// Bursty and mixed: parts per million of next targets that are the current one's
    /// usual successor.
    pub usual_successor_ppm: u32,
    /// Mixed: parts per million of requests that repeat the current target.
    pub repeat_ppm: u32,
    /// Adversarial: the Markov predictor the trace is built against.
    pub adversary: MarkovConfig,
    pub budget: ReplayBudget,
}

/// The Markov configuration the standard specifications attack, and the evaluation's
/// Markov predictor.
pub const STANDARD_MARKOV: MarkovConfig = MarkovConfig {
    max_states: 64,
    max_successors: 16,
    halve_at: 64,
    prior: 0.5,
};

impl TraceSpec {
    /// The evaluation's specification of `kind`: 200 requests over 4–8 GB models loaded
    /// at 1 GB/s after a 0.5–3 s setup, gaps of 12–30 s (6–30 s for mixed traces; 15–40 s
    /// between bursts and 0.2–1 s inside them), budgets that hold some but not all of the
    /// targets, and up to one model's bytes prepared per gap.
    pub fn standard(kind: TraceKind) -> Self {
        let base = Self {
            kind,
            arrivals: ArrivalMode::Closed,
            requests: 200,
            models: 5,
            min_model_bytes: 4 * GB,
            max_model_bytes: 8 * GB,
            adapters: 0,
            base_bytes: 6 * GB,
            adapter_bytes: HALF_GB,
            load_nanos_per_gb: 1_000_000_000,
            min_setup: Duration::from_millis(500),
            max_setup: Duration::from_secs(3),
            min_gap: Duration::from_secs(12),
            max_gap: Duration::from_secs(30),
            min_burst: 3,
            max_burst: 8,
            min_burst_gap: Duration::from_millis(200),
            max_burst_gap: Duration::from_millis(1_000),
            usual_successor_ppm: 700_000,
            repeat_ppm: 0,
            adversary: STANDARD_MARKOV,
            budget: ReplayBudget {
                capacity_bytes: 16 * GB,
                max_prepared_bytes_per_gap: 8 * GB,
            },
        };
        match kind {
            TraceKind::Alternating => Self {
                models: 2,
                min_model_bytes: 6 * GB,
                max_model_bytes: 8 * GB,
                budget: ReplayBudget {
                    capacity_bytes: 9 * GB,
                    ..base.budget
                },
                ..base
            },
            TraceKind::Scan => Self {
                max_model_bytes: 6 * GB,
                budget: ReplayBudget {
                    capacity_bytes: 20 * GB,
                    ..base.budget
                },
                ..base
            },
            TraceKind::Bursty => Self {
                arrivals: ArrivalMode::Open,
                min_gap: Duration::from_secs(15),
                max_gap: Duration::from_secs(40),
                ..base
            },
            TraceKind::AdversarialToMarkov => base,
            TraceKind::Mixed => Self {
                models: 4,
                adapters: 3,
                min_gap: Duration::from_secs(6),
                usual_successor_ppm: 600_000,
                repeat_ppm: 150_000,
                ..base
            },
        }
    }

    /// A tiny specification of `kind` for the exhaustive optimum: at most five objects
    /// and twelve requests, gaps that sometimes leave no time to prepare.
    pub fn tiny(kind: TraceKind) -> Self {
        let standard = Self::standard(kind);
        let base = Self {
            requests: 12,
            models: 3,
            min_model_bytes: 2 * GB,
            max_model_bytes: 3 * GB,
            base_bytes: 2 * GB,
            min_setup: Duration::from_millis(200),
            max_setup: Duration::from_secs(1),
            min_gap: Duration::from_millis(1_500),
            max_gap: Duration::from_secs(4),
            min_burst: 2,
            max_burst: 4,
            budget: ReplayBudget {
                capacity_bytes: 5 * GB,
                max_prepared_bytes_per_gap: 3 * GB,
            },
            ..standard
        };
        match kind {
            TraceKind::Alternating => Self {
                requests: 10,
                models: 2,
                budget: ReplayBudget {
                    capacity_bytes: 3 * GB,
                    ..base.budget
                },
                ..base
            },
            TraceKind::Bursty => Self {
                min_gap: Duration::from_secs(3),
                max_gap: Duration::from_secs(8),
                ..base
            },
            TraceKind::Mixed => Self {
                models: 2,
                adapters: 2,
                ..base
            },
            TraceKind::Scan | TraceKind::AdversarialToMarkov => base,
        }
    }

    /// Generates the trace of this specification from `seed`.
    pub fn generate(&self, seed: u64) -> Result<ReplayTrace, PredictionError> {
        let invalid = |field, reason| Err(PredictionError::InvalidConfig { field, reason });
        if self.models < 2 || self.models > 64 {
            return invalid("models", "between 2 and 64");
        }
        if self.adapters > 64 {
            return invalid("adapters", "at most 64");
        }
        if self.kind != TraceKind::Alternating && self.models + self.adapters < 3 {
            return invalid("models", "at least three targets unless alternating");
        }
        if self.min_model_bytes == 0 || self.min_model_bytes > self.max_model_bytes {
            return invalid(
                "min_model_bytes",
                "more than zero and at most max_model_bytes",
            );
        }
        if self.adapters > 0 && (self.base_bytes == 0 || self.adapter_bytes == 0) {
            return invalid("base_bytes", "a shared base and its adapters need bytes");
        }
        if self.load_nanos_per_gb == 0 {
            return invalid("load_nanos_per_gb", "more than zero");
        }
        if self.min_setup > self.max_setup {
            return invalid("min_setup", "at most max_setup");
        }
        if self.min_gap.is_zero() || self.min_gap > self.max_gap {
            return invalid("min_gap", "more than zero and at most max_gap");
        }
        if self.kind == TraceKind::Bursty
            && (self.min_burst == 0
                || self.min_burst > self.max_burst
                || self.min_burst_gap.is_zero()
                || self.min_burst_gap > self.max_burst_gap)
        {
            return invalid(
                "min_burst",
                "positive bursts and burst gaps, each minimum at most its maximum",
            );
        }
        if u64::from(self.usual_successor_ppm) + u64::from(self.repeat_ppm) > PPM {
            return invalid("usual_successor_ppm", "with repeat_ppm at most 1000000");
        }
        let mut rng = SeededRng::new(seed);
        let mut sizes = rng.fork();
        let mut catalog = Vec::new();
        let mut declared = Vec::new();
        let steps = (self.max_model_bytes - self.min_model_bytes) / HALF_GB;
        for index in 0..self.models {
            let bytes = self.min_model_bytes + sizes.below(steps + 1) * HALF_GB;
            let key = format!("model-{index}");
            catalog.push(CatalogObject {
                key: key.clone(),
                kind: ObjectKind::BaseWeights,
                bytes,
                load_nanos: self.load_nanos(bytes, &mut sizes)?,
                prerequisites: Vec::new(),
            });
            declared.push(key);
        }
        if self.adapters > 0 {
            catalog.push(CatalogObject {
                key: "base".to_string(),
                kind: ObjectKind::BaseWeights,
                bytes: self.base_bytes,
                load_nanos: self.load_nanos(self.base_bytes, &mut sizes)?,
                prerequisites: Vec::new(),
            });
            for index in 0..self.adapters {
                let key = format!("adapter-{index}");
                catalog.push(CatalogObject {
                    key: key.clone(),
                    kind: ObjectKind::Adapter,
                    bytes: self.adapter_bytes,
                    load_nanos: self.load_nanos(self.adapter_bytes, &mut sizes)?,
                    prerequisites: vec!["base".to_string()],
                });
                declared.push(key);
            }
        }
        let mut targets = rng.fork();
        let mut gaps = rng.fork();
        let requests = self.requests(&declared, &mut targets, &mut gaps)?;
        let trace = ReplayTrace {
            kind: self.kind,
            seed,
            arrivals: self.arrivals,
            catalog,
            declared,
            budget: self.budget,
            requests,
        };
        trace.check()?;
        Ok(trace)
    }

    /// The setup time drawn from `rng` plus `bytes` at the load rate.
    fn load_nanos(&self, bytes: u64, rng: &mut SeededRng) -> Result<u64, PredictionError> {
        let (setup, _) = Self::gap(rng, false, self.min_setup, self.max_setup);
        let transfer = u128::from(bytes) * u128::from(self.load_nanos_per_gb) / u128::from(GB);
        u64::try_from((transfer + setup.as_nanos()).max(1))
            .map_err(|_| PredictionError::Overflow { field: "load time" })
    }

    /// A gap uniform in `[low, high]`, declared as `low`; the first request's gap is zero.
    fn gap(
        rng: &mut SeededRng,
        first: bool,
        low: Duration,
        high: Duration,
    ) -> (Duration, Duration) {
        if first {
            return (Duration::ZERO, Duration::ZERO);
        }
        let low_nanos = u64::try_from(low.as_nanos()).unwrap_or(u64::MAX);
        let high_nanos = u64::try_from(high.as_nanos()).unwrap_or(u64::MAX);
        let span = high_nanos.saturating_sub(low_nanos);
        let gap = Duration::from_nanos(low_nanos.saturating_add(rng.below(span.saturating_add(1))));
        (gap, low)
    }

    /// The next target after `current` on a chain with `repeat_ppm` repeats, a usual
    /// successor (the next declared target) and uniform noise over the others.
    fn chain_step(
        &self,
        declared: &[String],
        current: usize,
        repeat_ppm: u32,
        rng: &mut SeededRng,
    ) -> Result<usize, PredictionError> {
        let draw = rng.below(PPM);
        let repeat = u64::from(repeat_ppm);
        let usual = u64::from(self.usual_successor_ppm);
        if draw < repeat {
            return Ok(current);
        }
        if draw < repeat + usual {
            return Ok((current + 1) % declared.len());
        }
        let others: Vec<usize> = (0..declared.len()).filter(|at| *at != current).collect();
        pick(&others, rng).copied()
    }

    /// The requests of the trace, in order.
    fn requests(
        &self,
        declared: &[String],
        targets: &mut SeededRng,
        gaps: &mut SeededRng,
    ) -> Result<Vec<TraceRequest>, PredictionError> {
        let name = |at: usize| -> Result<String, PredictionError> {
            declared
                .get(at)
                .cloned()
                .ok_or(PredictionError::InvalidConfig {
                    field: "declared",
                    reason: "a target index out of range",
                })
        };
        let mut out: Vec<TraceRequest> = Vec::with_capacity(self.requests);
        let push = |out: &mut Vec<TraceRequest>,
                    target: String,
                    (gap, declared_gap): (Duration, Duration)| {
            out.push(TraceRequest {
                target,
                gap,
                declared_gap,
            });
        };
        match self.kind {
            TraceKind::Alternating | TraceKind::Scan => {
                let cycle = if self.kind == TraceKind::Alternating {
                    2
                } else {
                    declared.len()
                };
                for index in 0..self.requests {
                    let gap = Self::gap(gaps, index == 0, self.min_gap, self.max_gap);
                    push(&mut out, name(index % cycle)?, gap);
                }
            }
            TraceKind::Mixed => {
                let mut current = 0usize;
                for index in 0..self.requests {
                    let gap = Self::gap(gaps, index == 0, self.min_gap, self.max_gap);
                    push(&mut out, name(current)?, gap);
                    current = self.chain_step(declared, current, self.repeat_ppm, targets)?;
                }
            }
            TraceKind::Bursty => {
                let mut current = 0usize;
                while out.len() < self.requests {
                    let span = u64::try_from(self.max_burst - self.min_burst).unwrap_or(0);
                    let length =
                        self.min_burst + usize::try_from(targets.below(span + 1)).unwrap_or(0);
                    for position in 0..length {
                        if out.len() == self.requests {
                            break;
                        }
                        let gap = if position == 0 {
                            Self::gap(gaps, out.is_empty(), self.min_gap, self.max_gap)
                        } else {
                            Self::gap(gaps, false, self.min_burst_gap, self.max_burst_gap)
                        };
                        push(&mut out, name(current)?, gap);
                    }
                    // The next burst is always another model.
                    current = self.chain_step(declared, current, 0, targets)?;
                }
            }
            TraceKind::AdversarialToMarkov => {
                let mut markov = MarkovPredictor::new(self.adversary)?;
                for index in 0..self.requests {
                    let next = adversarial_next(&markov, declared, targets)?;
                    markov.observe(&next);
                    let gap = Self::gap(gaps, index == 0, self.min_gap, self.max_gap);
                    push(&mut out, next, gap);
                }
            }
        }
        Ok(out)
    }
}

/// One of `choices`, uniformly.
fn pick<'a, T>(choices: &'a [T], rng: &mut SeededRng) -> Result<&'a T, PredictionError> {
    let count = u64::try_from(choices.len()).unwrap_or(0);
    let at = usize::try_from(rng.below(count))
        .map_err(|_| PredictionError::Overflow { field: "choice" })?;
    choices.get(at).ok_or(PredictionError::InvalidConfig {
        field: "declared",
        reason: "nothing to choose from",
    })
}

/// A next target that `markov` does not rank first among `declared` (ties broken in
/// declared order, as [`GuardedPredictor::rank`](super::GuardedPredictor::rank) breaks
/// them), drawn uniformly among the others. Before any history every target is allowed.
pub fn adversarial_next(
    markov: &MarkovPredictor<String>,
    declared: &[String],
    rng: &mut SeededRng,
) -> Result<String, PredictionError> {
    let top = markov.previous().and_then(|_| {
        markov
            .forecast(declared)
            .iter()
            .enumerate()
            .max_by(|(a_at, a), (b_at, b)| {
                a.probability.total_cmp(&b.probability).then(b_at.cmp(a_at))
            })
            .map(|(at, _)| at)
    });
    let allowed: Vec<&String> = declared
        .iter()
        .enumerate()
        .filter(|(at, _)| Some(*at) != top)
        .map(|(_, target)| target)
        .collect();
    pick(&allowed, rng).map(|target| (*target).clone())
}
