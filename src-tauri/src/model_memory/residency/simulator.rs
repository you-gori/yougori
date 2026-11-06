//! A deterministic trace simulator that compares retention policies by hit rate, saved
//! latency and bytes moved (GPU §2.7).
//!
//! Time comes only from a [`ManualClock`] driven by the trace's timestamps, and
//! randomness only from the seeded [`SplitMix64`] that [`generate_trace`] uses, so the
//! same inputs always give the same reports.

use std::time::Duration;

use serde::Serialize;

use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, ExecutionId, ManualClock, MonotonicTime,
};

use super::eviction::{Content, CopyTier, EvictionAction, ReconstructibleCopy, Verification};
use super::retention::{
    AccessOutcome, CacheConfig, CacheError, CachedObject, ObjectKind, ResidencyCache,
    RetentionPolicy, SessionLease,
};
use super::{add_bytes, check_seconds, InputError};

/// Digest domain of the initial state marker of generated sessions.
const SIMULATED_SESSION: &str = "yougori/model-memory/residency/simulated-session/v1";

/// Integer Zipf weights are this divided by the rank, so every rank keeps a weight.
const ZIPF_SCALE: u64 = 1 << 20;

/// The most objects [`generate_trace`] creates.
pub const MAX_GENERATED_OBJECTS: u64 = 1 << 16;

/// One step of a trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceEvent {
    /// A request needing `object` and its prerequisites.
    Request {
        object: String,
    },
    Lease(SessionLease),
    Release {
        execution: ExecutionId,
        object: String,
    },
    Pin {
        object: String,
    },
    Unpin {
        object: String,
    },
    /// Voids leases bound to an authorization epoch older than `before` (S3.1).
    RevokeAuthorization {
        before: AuthorizationEpoch,
    },
}

/// A trace event at a time on the trace's clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedEvent {
    pub at: MonotonicTime,
    pub event: TraceEvent,
}

/// One policy's results over one trace.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct SimulationReport {
    pub policy: String,
    pub requests: u64,
    /// Requests whose every needed object was resident.
    pub hits: u64,
    /// Requests refused because pinned, leased or retained objects left no room.
    pub refused: u64,
    /// Reload seconds avoided because needed objects were resident.
    pub saved_seconds: f64,
    /// Reload seconds spent loading needed objects.
    pub paid_seconds: f64,
    /// Host-to-device bytes.
    pub loaded_bytes: u64,
    /// Device-to-host bytes written back on eviction (line 307).
    pub written_back_bytes: u64,
    pub evictions: u64,
    /// Evictions that dropped a clean copy with no device-to-host bytes.
    pub clean_drops: u64,
    /// Evictions that dropped a graph pool for recapture, with no device-to-host bytes.
    pub recaptures: u64,
}

impl SimulationReport {
    /// Hits over every request, refused ones included; `None` without requests.
    pub fn hit_rate(&self) -> Option<f64> {
        (self.requests > 0).then(|| self.hits as f64 / self.requests as f64)
    }

    /// Loaded plus written-back bytes; `None` if the sum overflows.
    pub fn bytes_moved(&self) -> Option<u64> {
        self.loaded_bytes.checked_add(self.written_back_bytes)
    }

    fn record(&mut self, outcome: &AccessOutcome) -> Result<(), InputError> {
        if outcome.hit {
            self.hits = self.hits.saturating_add(1);
        }
        self.saved_seconds += outcome.saved_seconds;
        self.paid_seconds += outcome.paid_seconds;
        self.loaded_bytes = add_bytes("loaded bytes", self.loaded_bytes, outcome.loaded_bytes)?;
        self.written_back_bytes = add_bytes(
            "written-back bytes",
            self.written_back_bytes,
            outcome.written_back_bytes,
        )?;
        for eviction in &outcome.evictions {
            self.evictions = self.evictions.saturating_add(1);
            if matches!(eviction.action, EvictionAction::DropClean { .. }) {
                self.clean_drops = self.clean_drops.saturating_add(1);
            }
            if matches!(eviction.action, EvictionAction::Recapture) {
                self.recaptures = self.recaptures.saturating_add(1);
            }
        }
        Ok(())
    }
}

/// Replays `trace` against a fresh cache under `policy`. A request the cache refuses for
/// lack of room counts as refused; any other refusal stops the run.
pub fn simulate<P: RetentionPolicy>(
    config: &CacheConfig,
    policy: P,
    trace: &[TimedEvent],
) -> Result<SimulationReport, CacheError> {
    let mut cache = ResidencyCache::new(config, policy)?;
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut report = SimulationReport {
        policy: cache.policy().name().to_string(),
        ..SimulationReport::default()
    };
    let mut previous = MonotonicTime::ZERO;
    for timed in trace {
        if timed.at < previous {
            return Err(CacheError::TimeWentBack {
                last: previous,
                now: timed.at,
            });
        }
        previous = timed.at;
        clock.advance_to(timed.at);
        match &timed.event {
            TraceEvent::Request { object } => {
                report.requests = report.requests.saturating_add(1);
                match cache.access(object, &clock) {
                    Ok(outcome) => report.record(&outcome)?,
                    Err(CacheError::NoRoom { .. }) => {
                        report.refused = report.refused.saturating_add(1);
                    }
                    Err(error) => return Err(error),
                }
            }
            TraceEvent::Lease(lease) => cache.grant_lease(lease.clone(), &clock)?,
            TraceEvent::Release { execution, object } => {
                cache.release_lease(execution, object);
            }
            TraceEvent::Pin { object } => cache.pin(object)?,
            TraceEvent::Unpin { object } => cache.unpin(object)?,
            TraceEvent::RevokeAuthorization { before } => {
                cache.revoke_authorization_before(*before);
            }
        }
    }
    Ok(report)
}

/// Runs every policy over the same trace and capacity, in the order given.
pub fn compare(
    config: &CacheConfig,
    policies: Vec<Box<dyn RetentionPolicy>>,
    trace: &[TimedEvent],
) -> Result<Vec<SimulationReport>, CacheError> {
    policies
        .into_iter()
        .map(|policy| simulate(config, policy, trace))
        .collect()
}

/// SplitMix64 (Steele, Lea and Flood 2014): the only source of randomness here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// Uniform in `0..bound`, without modulo bias; `None` when `bound` is zero.
    pub fn below(&mut self, bound: u64) -> Option<u64> {
        if bound == 0 {
            return None;
        }
        // Rejecting the 2^64 mod bound lowest values leaves a whole number of ranges.
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let value = self.next_u64();
            if value >= threshold {
                return Some(value % bound);
            }
        }
    }
}

/// A synthetic workload: bases with Zipf popularity, each with sessions chosen uniformly.
#[derive(Clone, Debug, PartialEq)]
pub struct TraceSpec {
    pub bases: u64,
    pub sessions_per_base: u64,
    pub base_bytes: u64,
    pub base_reload_seconds: f64,
    pub session_bytes: u64,
    pub session_reload_seconds: f64,
    pub requests: u64,
    pub spacing: Duration,
    pub capacity_bytes: u64,
}

/// Builds a cache configuration and a request trace from `spec`, deterministically for
/// each `seed`. Bases are `base-<i>` with a verified local-storage copy; sessions are
/// `session-<i>-<j>` session KV on base `i`, written back to pinned host RAM on eviction.
/// Base `i` is requested with weight proportional to 1/(i + 1).
pub fn generate_trace(
    spec: &TraceSpec,
    seed: u64,
) -> Result<(CacheConfig, Vec<TimedEvent>), InputError> {
    for (field, value) in [
        ("bases", spec.bases),
        ("sessions per base", spec.sessions_per_base),
        ("base bytes", spec.base_bytes),
        ("session bytes", spec.session_bytes),
        ("cache capacity", spec.capacity_bytes),
    ] {
        if value == 0 {
            return Err(InputError::NotPositive { field });
        }
    }
    check_seconds("base reload seconds", spec.base_reload_seconds)?;
    check_seconds("session reload seconds", spec.session_reload_seconds)?;
    let objects_count = spec
        .sessions_per_base
        .checked_add(1)
        .and_then(|per_base| per_base.checked_mul(spec.bases))
        .filter(|count| *count <= MAX_GENERATED_OBJECTS)
        .ok_or(InputError::OutOfRange {
            field: "generated objects",
        })?;
    let spacing_nanos =
        u64::try_from(spec.spacing.as_nanos()).map_err(|_| InputError::Overflow {
            field: "trace spacing",
        })?;

    let mut objects = Vec::with_capacity(usize::try_from(objects_count).unwrap_or_default());
    for base in 0..spec.bases {
        let key = format!("base-{base}");
        // A simulated base's bytes are its name.
        let content = Content::Immutable(ContentKey::of(key.as_bytes()));
        objects.push(CachedObject {
            key: key.clone(),
            kind: ObjectKind::BaseWeights,
            bytes: spec.base_bytes,
            reload_seconds: spec.base_reload_seconds,
            prerequisites: Vec::new(),
            content,
            copies: vec![ReconstructibleCopy {
                tier: CopyTier::LocalStorage,
                verification: Verification::Verified { content },
            }],
        });
        for session in 0..spec.sessions_per_base {
            let session_key = format!("session-{base}-{session}");
            objects.push(CachedObject {
                content: Content::SessionState(digest(
                    SIMULATED_SESSION,
                    &[session_key.as_bytes()],
                )),
                key: session_key,
                kind: ObjectKind::SessionKv,
                bytes: spec.session_bytes,
                reload_seconds: spec.session_reload_seconds,
                prerequisites: vec![key.clone()],
                copies: Vec::new(),
            });
        }
    }

    let weights: Vec<u64> = (0..spec.bases)
        .map(|base| ZIPF_SCALE / base.saturating_add(1))
        .collect();
    let total_weight = weights.iter().try_fold(0u64, |total, weight| {
        add_bytes("Zipf weights", total, *weight)
    })?;
    let mut random = SplitMix64::new(seed);
    let mut trace = Vec::new();
    for request in 0..spec.requests {
        let draw = random.below(total_weight).ok_or(InputError::NotPositive {
            field: "Zipf weights",
        })?;
        let base = pick(&weights, draw);
        let session = random
            .below(spec.sessions_per_base)
            .ok_or(InputError::NotPositive {
                field: "sessions per base",
            })?;
        let at = request
            .checked_mul(spacing_nanos)
            .map(MonotonicTime::from_nanos)
            .ok_or(InputError::Overflow {
                field: "trace time",
            })?;
        trace.push(TimedEvent {
            at,
            event: TraceEvent::Request {
                object: format!("session-{base}-{session}"),
            },
        });
    }
    let config = CacheConfig {
        capacity_bytes: spec.capacity_bytes,
        objects,
        write_back_tier: Some(CopyTier::PinnedHost),
    };
    Ok((config, trace))
}

/// The index whose cumulative weight range holds `draw`.
fn pick(weights: &[u64], draw: u64) -> usize {
    let mut remaining = draw;
    for (index, weight) in weights.iter().enumerate() {
        if remaining < *weight {
            return index;
        }
        remaining -= weight;
    }
    weights.len().saturating_sub(1)
}

/// A way a setting departs from the classical file-caching model of Landlord (line 448).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum LandlordExtension {
    /// Objects depend on shared bases.
    SharedPrerequisites,
    /// Objects are pinned.
    PinnedObjects,
    /// Objects are protected by session leases.
    SessionLeases,
    /// Evicting some objects costs a write-back, or keeps them when none is possible.
    EvictionWriteBack,
}

/// Whether the classical Landlord/GreedyDual-Size competitive guarantee may be quoted for
/// a setting (line 448).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ClassicalGuarantee {
    /// Independent objects with fixed costs, nothing pinned or leased, free evictions and
    /// loading on demand only: the setting of the published bound (Young 2002).
    ClassicalSetting,
    /// The setting extends the classical one, so the bound is not claimed and only
    /// measurement speaks.
    NotClaimed { extensions: Vec<LandlordExtension> },
}

/// Classifies a configuration and trace for [`ClassicalGuarantee`] (line 448). This
/// simulator keeps costs fixed and loads only on demand, so varying costs, prediction and
/// prefetch, which would also void the guarantee, never arise here.
pub fn landlord_guarantee(config: &CacheConfig, trace: &[TimedEvent]) -> ClassicalGuarantee {
    let mut extensions = Vec::new();
    if config
        .objects
        .iter()
        .any(|object| !object.prerequisites.is_empty())
    {
        extensions.push(LandlordExtension::SharedPrerequisites);
    }
    if trace
        .iter()
        .any(|timed| matches!(timed.event, TraceEvent::Pin { .. }))
    {
        extensions.push(LandlordExtension::PinnedObjects);
    }
    if trace
        .iter()
        .any(|timed| matches!(timed.event, TraceEvent::Lease(_)))
    {
        extensions.push(LandlordExtension::SessionLeases);
    }
    // A graph pool is dropped for recapture, never written back.
    if config.objects.iter().any(|object| {
        object.kind.mutates_on_use()
            || (!object.kind.recaptured()
                && !object
                    .copies
                    .iter()
                    .any(|copy| copy.reconstructs(&object.content)))
    }) {
        extensions.push(LandlordExtension::EvictionWriteBack);
    }
    if extensions.is_empty() {
        ClassicalGuarantee::ClassicalSetting
    } else {
        ClassicalGuarantee::NotClaimed { extensions }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::residency::retention::{
        CostPerByte, GreedyDualSize, Lru, MarginalSavedLatency,
    };
    use crate::model_memory::residency::test_support::{at, GIB};

    fn independent(key: &str, gib: u64, reload_seconds: f64) -> CachedObject {
        let content = Content::Immutable(ContentKey::of(key.as_bytes()));
        CachedObject {
            key: key.to_string(),
            kind: ObjectKind::BaseWeights,
            bytes: gib * GIB,
            reload_seconds,
            prerequisites: Vec::new(),
            content,
            copies: vec![ReconstructibleCopy {
                tier: CopyTier::LocalStorage,
                verification: Verification::Verified { content },
            }],
        }
    }

    fn requests(keys: &[&str]) -> Vec<TimedEvent> {
        keys.iter()
            .zip(1..)
            .map(|(key, second)| TimedEvent {
                at: at(second),
                event: TraceEvent::Request {
                    object: key.to_string(),
                },
            })
            .collect()
    }

    fn all_policies() -> Vec<Box<dyn RetentionPolicy>> {
        vec![
            Box::new(Lru),
            Box::new(CostPerByte),
            Box::new(GreedyDualSize::new()),
            Box::new(MarginalSavedLatency::new(4).unwrap()),
        ]
    }

    #[test]
    fn lru_cost_per_byte_and_greedy_dual_size_compared_on_a_small_trace() {
        // E is expensive and reused once across a scan of a, b, c; afterwards only a, b
        // and c recur, and the three fit in 8 GiB only without E.
        let config = CacheConfig {
            capacity_bytes: 8 * GIB,
            objects: vec![
                independent("E", 4, 4.0),
                independent("a", 2, 1.0),
                independent("b", 2, 1.0),
                independent("c", 2, 1.0),
            ],
            write_back_tier: Some(CopyTier::PinnedHost),
        };
        let trace = requests(&["E", "a", "b", "c", "E", "a", "b", "c", "a", "b", "c"]);
        let reports = compare(&config, all_policies(), &trace).unwrap();
        let expected =
            |policy: &str, hits, saved_seconds, paid_seconds, gib, evictions| SimulationReport {
                policy: policy.to_string(),
                requests: 11,
                hits,
                refused: 0,
                saved_seconds,
                paid_seconds,
                loaded_bytes: gib * GIB,
                written_back_bytes: 0,
                evictions,
                clean_drops: evictions,
                recaptures: 0,
            };
        // LRU loses E to the scan and pays for it again, then keeps the final working set.
        assert_eq!(reports[0], expected("lru", 3, 3.0, 14.0, 20, 5));
        // Cost per byte keeps E after its last use and thrashes a, b and c.
        assert_eq!(reports[1], expected("cost-per-byte", 1, 4.0, 13.0, 22, 7));
        // GreedyDual-Size keeps E while it is reused, then rent ages it out.
        assert_eq!(
            reports[2],
            expected("greedy-dual-size", 3, 6.0, 11.0, 18, 5)
        );

        let [lru, cost, gds] = [&reports[0], &reports[1], &reports[2]];
        assert_eq!(lru.hit_rate(), Some(3.0 / 11.0));
        assert_eq!(cost.hit_rate(), Some(1.0 / 11.0));
        assert!(gds.saved_seconds > lru.saved_seconds && gds.saved_seconds > cost.saved_seconds);
        assert!(gds.bytes_moved() < lru.bytes_moved() && gds.bytes_moved() < cost.bytes_moved());

        assert_eq!(reports[3].policy, "marginal-saved-latency");
        assert_eq!(reports[3].requests, 11);
        assert_eq!(
            landlord_guarantee(&config, &trace),
            ClassicalGuarantee::ClassicalSetting
        );
    }

    fn spec() -> TraceSpec {
        TraceSpec {
            bases: 3,
            sessions_per_base: 4,
            base_bytes: 8 * GIB,
            base_reload_seconds: 8.0,
            session_bytes: GIB / 2,
            session_reload_seconds: 1.0,
            requests: 200,
            spacing: Duration::from_millis(1),
            capacity_bytes: 20 * GIB,
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_trace_and_the_same_reports() {
        let (config, trace) = generate_trace(&spec(), 7).unwrap();
        let (config_again, trace_again) = generate_trace(&spec(), 7).unwrap();
        assert_eq!(config, config_again);
        assert_eq!(trace, trace_again);
        assert_eq!(config.objects.len(), 15);
        assert_eq!(trace.len(), 200);
        assert_eq!(trace[199].at, MonotonicTime::from_nanos(199_000_000));
        assert_ne!(generate_trace(&spec(), 8).unwrap().1, trace);

        let reports = compare(&config, all_policies(), &trace).unwrap();
        assert_eq!(reports, compare(&config, all_policies(), &trace).unwrap());
        for report in &reports {
            assert_eq!(report.requests, 200);
            assert!(report.hits <= report.requests);
            assert_eq!(report.refused, 0);
            assert_eq!(
                report.bytes_moved(),
                Some(report.loaded_bytes + report.written_back_bytes)
            );
            assert!(report.clean_drops <= report.evictions);
        }
        // Three 8 GiB bases do not fit in 20 GiB, so sessions are evicted and their dirty
        // KV is written back.
        assert!(reports.iter().all(|report| report.evictions > 0));
        assert!(reports.iter().any(|report| report.written_back_bytes > 0));
        // Popularity follows rank: base 0 is requested most.
        let count = |base: u64| {
            let prefix = format!("session-{base}-");
            trace
                .iter()
                .filter(|timed| match &timed.event {
                    TraceEvent::Request { object } => object.starts_with(&prefix),
                    _ => false,
                })
                .count()
        };
        assert!(count(0) > count(1) && count(1) > count(2));
        assert!(matches!(
            landlord_guarantee(&config, &trace),
            ClassicalGuarantee::NotClaimed { .. }
        ));
    }

    #[test]
    fn generated_traces_are_validated() {
        assert_eq!(
            generate_trace(&TraceSpec { bases: 0, ..spec() }, 1),
            Err(InputError::NotPositive { field: "bases" })
        );
        assert_eq!(
            generate_trace(
                &TraceSpec {
                    base_reload_seconds: f64::INFINITY,
                    ..spec()
                },
                1
            ),
            Err(InputError::NotFinite {
                field: "base reload seconds"
            })
        );
        assert_eq!(
            generate_trace(
                &TraceSpec {
                    bases: MAX_GENERATED_OBJECTS,
                    ..spec()
                },
                1
            ),
            Err(InputError::OutOfRange {
                field: "generated objects"
            })
        );
        assert_eq!(
            generate_trace(
                &TraceSpec {
                    spacing: Duration::MAX,
                    ..spec()
                },
                1
            ),
            Err(InputError::Overflow {
                field: "trace spacing"
            })
        );
    }

    #[test]
    fn splitmix64_matches_its_reference_output() {
        let mut random = SplitMix64::new(0);
        assert_eq!(random.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(random.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(random.next_u64(), 0x06C4_5D18_8009_454F);
        assert_eq!(SplitMix64::new(0).below(0), None);
        let mut bounded = SplitMix64::new(42);
        assert!((0..1000).all(|_| bounded.below(7).is_some_and(|value| value < 7)));
        assert_eq!(SplitMix64::new(9).below(1), Some(0));
    }

    #[test]
    fn refused_requests_stay_in_the_denominator() {
        let config = CacheConfig {
            capacity_bytes: 4 * GIB,
            objects: vec![independent("big", 8, 1.0), independent("small", 1, 1.0)],
            write_back_tier: None,
        };
        let report = simulate(&config, Lru, &requests(&["big", "small", "small"])).unwrap();
        assert_eq!(report.requests, 3);
        assert_eq!(report.refused, 1);
        assert_eq!(report.hits, 1);
        assert_eq!(report.hit_rate(), Some(1.0 / 3.0));
        assert_eq!(SimulationReport::default().hit_rate(), None);
    }

    #[test]
    fn pins_leases_and_releases_replay_through_the_cache() {
        let config = CacheConfig {
            capacity_bytes: 8 * GIB,
            objects: vec![
                independent("p", 4, 1.0),
                independent("q", 4, 1.0),
                independent("r", 4, 1.0),
            ],
            write_back_tier: None,
        };
        let execution = ExecutionId::new("exe-1").unwrap();
        let event = |second, event| TimedEvent {
            at: at(second),
            event,
        };
        let request = |object: &str| TraceEvent::Request {
            object: object.to_string(),
        };
        let trace = vec![
            event(1, request("p")),
            event(
                1,
                TraceEvent::Pin {
                    object: "p".to_string(),
                },
            ),
            event(2, request("q")),
            event(
                2,
                TraceEvent::Lease(SessionLease {
                    execution: execution.clone(),
                    authorization_epoch: None,
                    object: "q".to_string(),
                    expires_at: at(100),
                }),
            ),
            // p is pinned and q leased: no room for r.
            event(3, request("r")),
            event(
                4,
                TraceEvent::Release {
                    execution,
                    object: "q".to_string(),
                },
            ),
            // q's lease is released: r replaces it.
            event(5, request("r")),
            event(
                6,
                TraceEvent::Unpin {
                    object: "p".to_string(),
                },
            ),
            event(
                7,
                TraceEvent::Lease(SessionLease {
                    execution: ExecutionId::new("exe-2").unwrap(),
                    authorization_epoch: Some(AuthorizationEpoch::FIRST),
                    object: "r".to_string(),
                    expires_at: at(100),
                }),
            ),
            event(
                7,
                TraceEvent::Pin {
                    object: "p".to_string(),
                },
            ),
            // p is pinned and r leased under epoch 1: no room for q.
            event(8, request("q")),
            event(
                9,
                TraceEvent::RevokeAuthorization {
                    before: AuthorizationEpoch::new(2),
                },
            ),
            // Epoch 1 is revoked, so r's lease protects nothing: q replaces r.
            event(10, request("q")),
        ];
        let report = simulate(&config, GreedyDualSize::new(), &trace).unwrap();
        assert_eq!(report.requests, 6);
        assert_eq!(report.refused, 2);
        assert_eq!(report.evictions, 2);
        assert_eq!(
            landlord_guarantee(&config, &trace),
            ClassicalGuarantee::NotClaimed {
                extensions: vec![
                    LandlordExtension::PinnedObjects,
                    LandlordExtension::SessionLeases
                ]
            }
        );

        let mut backwards = trace.clone();
        backwards.swap(0, 2);
        assert!(matches!(
            simulate(&config, Lru, &backwards),
            Err(CacheError::TimeWentBack { .. })
        ));
        let unknown = requests(&["nothing"]);
        assert!(matches!(
            simulate(&config, Lru, &unknown),
            Err(CacheError::Input(InputError::Unknown { .. }))
        ));
    }

    /// A base with a verified copy, a merged variant with none, a graph pool over the
    /// variant, two sessions on the variant and one on the base, in 12 GiB.
    fn variant_and_pool() -> CacheConfig {
        let variant_key = ContentKey::of(b"m");
        let session = |key: &str, of: &str| CachedObject {
            key: key.to_string(),
            kind: ObjectKind::SessionKv,
            bytes: GIB,
            reload_seconds: 0.5,
            prerequisites: vec![of.to_string()],
            content: Content::SessionState(digest(SIMULATED_SESSION, &[key.as_bytes()])),
            copies: Vec::new(),
        };
        CacheConfig {
            capacity_bytes: 12 * GIB,
            objects: vec![
                independent("b", 8, 8.0),
                CachedObject {
                    key: "m".to_string(),
                    kind: ObjectKind::MergedVariant,
                    bytes: 8 * GIB,
                    reload_seconds: 4.0,
                    prerequisites: Vec::new(),
                    content: Content::Immutable(variant_key),
                    copies: Vec::new(),
                },
                CachedObject {
                    key: "m-graphs".to_string(),
                    kind: ObjectKind::GraphPool,
                    bytes: GIB,
                    reload_seconds: 1.0,
                    prerequisites: vec!["m".to_string()],
                    content: Content::GraphPool {
                        weights: variant_key,
                        execution_key: digest(
                            "yougori/test/residency/execution-key/v1",
                            &[b"bs1-8"],
                        ),
                    },
                    copies: Vec::new(),
                },
                session("s1", "m"),
                session("s2", "m"),
                session("t", "b"),
            ],
            write_back_tier: Some(CopyTier::PinnedHost),
        }
    }

    #[test]
    fn a_trace_with_a_merged_variant_and_a_graph_pool_replays_deterministically() {
        let config = variant_and_pool();
        let trace = requests(&["s1", "m-graphs", "s2", "t", "m-graphs", "b"]);
        let reports = compare(&config, all_policies(), &trace).unwrap();
        assert_eq!(reports, compare(&config, all_policies(), &trace).unwrap());
        for report in &reports {
            assert_eq!(report.requests, 6, "{}", report.policy);
            assert_eq!(report.refused, 0, "{}", report.policy);
            assert!(report.recaptures >= 1, "{report:?}");
            assert!(report.clean_drops <= report.evictions, "{report:?}");
        }
        // Under LRU: t evicts s1 and s2 (written back), the pool (recaptured) and the
        // variant, which has no copy and is written back; the pool again then b evict t
        // (written back) and b (dropped clean); b evicts the variant, chosen as the
        // older key, taking its pool first, and drops clean against its written-back
        // copy.
        assert_eq!(
            reports[0],
            SimulationReport {
                policy: "lru".to_string(),
                requests: 6,
                hits: 0,
                refused: 0,
                saved_seconds: 8.0,
                paid_seconds: 27.5,
                loaded_bytes: 37 * GIB,
                written_back_bytes: 11 * GIB,
                evictions: 8,
                clean_drops: 2,
                recaptures: 2,
            }
        );
        assert_eq!(reports[0].bytes_moved(), Some(48 * GIB));
        assert_eq!(
            landlord_guarantee(&config, &trace),
            ClassicalGuarantee::NotClaimed {
                extensions: vec![
                    LandlordExtension::SharedPrerequisites,
                    LandlordExtension::EvictionWriteBack
                ]
            }
        );
    }

    #[test]
    fn a_graph_pool_is_no_write_back_extension() {
        let base_key = ContentKey::of(b"b");
        let config = CacheConfig {
            capacity_bytes: 8 * GIB,
            objects: vec![
                independent("b", 4, 1.0),
                CachedObject {
                    key: "b-graphs".to_string(),
                    kind: ObjectKind::GraphPool,
                    bytes: GIB,
                    reload_seconds: 1.0,
                    prerequisites: vec!["b".to_string()],
                    content: Content::GraphPool {
                        weights: base_key,
                        execution_key: *base_key.digest(),
                    },
                    copies: Vec::new(),
                },
            ],
            write_back_tier: None,
        };
        assert_eq!(
            landlord_guarantee(&config, &[]),
            ClassicalGuarantee::NotClaimed {
                extensions: vec![LandlordExtension::SharedPrerequisites]
            }
        );
    }

    #[test]
    fn the_classical_guarantee_is_not_claimed_for_extended_settings() {
        let shared = CacheConfig {
            capacity_bytes: 8 * GIB,
            objects: vec![
                independent("base", 4, 1.0),
                CachedObject {
                    prerequisites: vec!["base".to_string()],
                    ..independent("adapter", 1, 1.0)
                },
            ],
            write_back_tier: None,
        };
        assert_eq!(
            landlord_guarantee(&shared, &[]),
            ClassicalGuarantee::NotClaimed {
                extensions: vec![LandlordExtension::SharedPrerequisites]
            }
        );
        let unverified = CacheConfig {
            capacity_bytes: 8 * GIB,
            objects: vec![CachedObject {
                copies: vec![ReconstructibleCopy {
                    tier: CopyTier::LocalStorage,
                    verification: Verification::Unverified,
                }],
                ..independent("u", 4, 1.0)
            }],
            write_back_tier: Some(CopyTier::PinnedHost),
        };
        assert_eq!(
            landlord_guarantee(&unverified, &[]),
            ClassicalGuarantee::NotClaimed {
                extensions: vec![LandlordExtension::EvictionWriteBack]
            }
        );
    }
}
