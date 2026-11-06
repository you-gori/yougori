//! Trusted CORE-08 load observations as the reload-cost and resource inputs of the
//! retention, bundle, transition and readiness decisions (GPU-W06, "measured reload
//! cost-per-byte baselines" and "uncertainty-aware ETA and stale-state reconciliation";
//! GPU §2.7, §2.9 and §4.5; S8; CORE-01 configuration fingerprints and freshness).
//!
//! An [`ObservedCosts`] store takes CORE-08 [`RunRecord`]s of load calls: a load attempt
//! (`Scenario::Stages` judged on [`IntervalKind::ReadyLatency`], as the runner adapter
//! writes it) or a request whose own demand load is inside its time to first token
//! ([`IntervalKind::DemandLoad`]). A record is kept only when it validates, comes from a
//! source at least as trusted as the policy's minimum, was collected on the store's own
//! clock session and not in its future, and ran on a Yougori substrate; fake-substrate
//! records count only when the policy says so, for simulations, and their provenance says
//! so. Each kept sample is bound to the [`ReloadConfiguration`] that determines a reload
//! (build, execution category, model, precision, engine, the stable host description and
//! the launch image) through its CORE-01 [`ConfigurationFingerprint`]. Concurrent waiters
//! of one load carry the same [`LoadAttemptKey`] and count once: the load is shared work
//! (docs/gpu-memory/demand-load-measurement.md).
//!
//! A query names the configuration it plans for and a [`DeclaredEstimate`]. It gets the
//! measured value only from at least `min_samples` fresh samples of exactly that
//! configuration, with the CORE-08 [`Provenance`] of the very records used; otherwise it
//! gets the declared estimate, labelled with why ([`EstimateReason`]): no observations,
//! only other configurations, refused records, stale samples or too few of them. A
//! stale, other-configuration or untrusted observation therefore never becomes a silent
//! measured value.
//!
//! The values feed the existing decisions unchanged:
//!
//! - [`Labelled::reload_seconds`] is `CachedObject::reload_seconds` of
//!   [`crate::model_memory::residency::retention`], the cost the LRU, cost-per-byte,
//!   marginal saved latency and GreedyDual-Size policies rank by;
//! - the [`DurationEstimate`] of a [`ReloadCost`] is `ObjectSpec::load` of
//!   [`crate::model_memory::bundles`] and any request-graph load node;
//! - [`ObservedCosts::load_curve`] fits the transitions' `MeasuredCurves::host_to_device`
//!   with [`LinearServiceFit`], and [`Basis::evidence`] is its evidence digest;
//! - [`Labelled::admission_duration`] is the pessimistic duration
//!   [`PrepareOperation::admit`](super::super::intent::PrepareOperation::admit) checks a
//!   deadline with;
//! - [`ObservedCosts::resources`] gives the retained and peak bytes a reservation or a
//!   transition peak needs.
//!
//! Records measure the runner's load-call boundary, not pure transfer time, and the store
//! keeps what it is given: freshness runs from collection on the store's clock, so a
//! caller stamps a record when it collects it, never later.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::evidence::{ClockSession, ConfigurationFingerprint, SourceClass};
use crate::foundation::ids::{Clock, Digest, DigestBuilder, ExecutionCategory, MonotonicTime};
use crate::foundation::report::{
    percentile, BuildIdentity, CpuDescription, EngineIdentity, GpuDescription, IntervalKind, Label,
    LaunchDescription, Measured, ModelIdentity, PercentileMethod, PowerSource, Precision,
    Provenance, Quantile, ReportError, RunRecord, RunSubstrate, Scenario,
};
use crate::model_memory::graph::node::DurationEstimate;
use crate::model_memory::math::chunking::{ChunkingError, LinearServiceFit, ServiceSample};
use crate::model_memory::transitions::LoadCurve;

/// Digest domain of [`LoadAttemptKey`].
pub const LOAD_ATTEMPT_DOMAIN: &str = "yougori/model-memory/readiness/adoption/load-attempt/v1";

const NANOS_PER_SECOND: f64 = 1e9;

/// The stable part of a host description that a reload depends on. Transient readings,
/// the GPU power and clock state and the displays driven, are left out: they change from
/// one record to the next without changing the configuration.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReloadHost {
    pub os: Label,
    pub os_version: Label,
    pub cpu: CpuDescription,
    pub host_memory_bytes: u64,
    pub gpus: Measured<Vec<GpuDescription>>,
    pub gpu_driver: Measured<Label>,
    pub power_source: Measured<PowerSource>,
}

/// Everything a reload's cost depends on (S8 record fields; BENCH-13 configuration
/// hashes): what was loaded, by which engine and build, on which host, from which image.
/// Per-request fields (workload, client, load, start state) are not part of it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReloadConfiguration {
    pub build: BuildIdentity,
    pub execution_category: ExecutionCategory,
    pub model: ModelIdentity,
    pub precision: Precision,
    pub engine: EngineIdentity,
    pub host: ReloadHost,
    pub launch: LaunchDescription,
}

impl ReloadConfiguration {
    /// The configuration a record ran under. Its model, precision and engine must be
    /// measured: a record that does not say what it loaded binds to no configuration.
    pub fn of_record(record: &RunRecord) -> Result<Self, ObservationRefusal> {
        let model = record
            .model
            .value()
            .ok_or(ObservationRefusal::Unbound { field: "model" })?;
        let precision = record
            .precision
            .value()
            .ok_or(ObservationRefusal::Unbound { field: "precision" })?;
        let engine = record
            .engine
            .value()
            .ok_or(ObservationRefusal::Unbound { field: "engine" })?;
        Ok(Self {
            build: record.build.clone(),
            execution_category: record.execution_category,
            model: model.clone(),
            precision: precision.clone(),
            engine: engine.clone(),
            host: ReloadHost {
                os: record.host.os.clone(),
                os_version: record.host.os_version.clone(),
                cpu: record.host.cpu.clone(),
                host_memory_bytes: record.host.host_memory_bytes,
                gpus: record.host.gpus.clone(),
                gpu_driver: record.host.gpu_driver.clone(),
                power_source: record.host.power_source.clone(),
            },
            launch: record.launch.clone(),
        })
    }

    /// The CORE-01 fingerprint of this configuration: each part as a named setting, so
    /// evidence observed under one configuration never satisfies another.
    pub fn fingerprint(&self) -> Result<ConfigurationFingerprint, ObservationRefusal> {
        let parts = [
            ("reload.build", json(&self.build)?),
            ("reload.execution_category", json(&self.execution_category)?),
            ("reload.model", json(&self.model)?),
            ("reload.precision", json(&self.precision)?),
            ("reload.engine", json(&self.engine)?),
            ("reload.host", json(&self.host)?),
            ("reload.launch", json(&self.launch)?),
        ];
        ConfigurationFingerprint::from_settings(
            parts.iter().map(|(name, value)| (*name, value.as_str())),
        )
        .map_err(|_| ObservationRefusal::Encoding)
    }
}

/// One configuration part as JSON text, the value of its named setting.
fn json<T: Serialize>(value: &T) -> Result<String, ObservationRefusal> {
    serde_json::to_string(value).map_err(|_| ObservationRefusal::Encoding)
}

/// One load call on one runner instance. Every record that observed the same load, the
/// load attempt itself and each request that waited for it, carries the same key, and
/// the store counts the load once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct LoadAttemptKey(Digest);

impl LoadAttemptKey {
    /// The load `attempt` of the runner instance `instance`, as the runner journal names
    /// them (its instance id and the load attempt id a demand load refers to).
    pub fn new(instance: &str, attempt: u64) -> Self {
        Self(
            DigestBuilder::new(LOAD_ATTEMPT_DOMAIN)
                .str(instance)
                .u64(attempt)
                .finish(),
        )
    }

    /// The digest that names the load.
    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// One record offered to the store.
#[derive(Clone, Debug, PartialEq)]
pub struct CostObservation {
    pub record: RunRecord,
    /// Who observed it (CORE-01 source classes): the host's own collector, or a report
    /// from inside a guest or provider.
    pub source: SourceClass,
    /// The clock session the collection time was read on.
    pub collected_in: ClockSession,
    /// When the collector took the record, on that session.
    pub collected_at: MonotonicTime,
    /// The load call the record measured.
    pub load: LoadAttemptKey,
}

/// Which records the store trusts and how long they stay fresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CostPolicy {
    /// The least trusted source whose records are kept.
    pub minimum_source: SourceClass,
    /// How long after collection a sample stays fresh.
    pub max_age: Duration,
    /// Fresh samples of one configuration needed before a measured value replaces the
    /// declared estimate; at least one.
    pub min_samples: usize,
    /// Samples kept per configuration; the oldest is dropped first. At least
    /// `min_samples`.
    pub max_samples_per_configuration: usize,
    /// Configurations kept; the one observed least recently is dropped first.
    pub max_configurations: usize,
    /// Whether fake-substrate records are kept. Only simulations set it; the provenance
    /// of every value computed from them says fake substrate, which backs no claim.
    pub accept_fake_substrate: bool,
}

impl CostPolicy {
    fn check(&self) -> Result<(), ObservationRefusal> {
        let invalid = |field| Err(ObservationRefusal::InvalidPolicy { field });
        if self.max_age.is_zero() {
            return invalid("max_age");
        }
        if self.min_samples == 0 {
            return invalid("min_samples");
        }
        if self.max_samples_per_configuration < self.min_samples {
            return invalid("max_samples_per_configuration");
        }
        if self.max_configurations == 0 {
            return invalid("max_configurations");
        }
        Ok(())
    }
}

/// Why a record was not trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum UntrustedReason {
    /// It ran on the fake, time-controlled substrate, which the policy does not accept.
    FakeSubstrate,
    /// Its source is less trusted than the policy's minimum.
    Source {
        source: SourceClass,
        minimum: SourceClass,
    },
    /// It was collected on another clock session, so its age cannot be known: a record
    /// saved before a restart never passes for a current one.
    OtherClockSession,
    /// Its collection time lies after now.
    CollectedInTheFuture {
        collected_at: MonotonicTime,
        now: MonotonicTime,
    },
}

/// Why a record was not kept.
#[derive(Clone, Debug, PartialEq)]
pub enum ObservationRefusal {
    InvalidPolicy {
        field: &'static str,
    },
    /// CORE-08 refused the record.
    Invalid {
        error: ReportError,
    },
    /// The record measures no load: neither a load attempt's ready latency nor a demand
    /// load inside a request.
    NoLoadInterval,
    /// The record does not say what it loaded.
    Unbound {
        field: &'static str,
    },
    Untrusted {
        configuration: ConfigurationFingerprint,
        reason: UntrustedReason,
    },
    /// A configuration part could not be encoded.
    Encoding,
}

impl fmt::Display for ObservationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy { field } => write!(f, "the cost policy's {field} is invalid"),
            Self::Invalid { error } => write!(f, "CORE-08 refused the record: {error}"),
            Self::NoLoadInterval => f.write_str("the record measures no load"),
            Self::Unbound { field } => {
                write!(
                    f,
                    "the record's {field} is not measured, so it binds to no configuration"
                )
            }
            Self::Untrusted { reason, .. } => write!(f, "the record is not trusted: {reason:?}"),
            Self::Encoding => f.write_str("a configuration part could not be encoded"),
        }
    }
}

impl std::error::Error for ObservationRefusal {}

/// What the store did with a trusted record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingested {
    /// Kept as a new sample of its configuration.
    Stored {
        configuration: ConfigurationFingerprint,
    },
    /// Its load is already a sample: another waiter of the same shared load.
    SharedLoad {
        configuration: ConfigurationFingerprint,
    },
}

/// A declared estimate: what the caller would use with no measurement, and where it
/// comes from (such as catalog bytes over a nominal bandwidth).
#[derive(Clone, Debug, PartialEq)]
pub struct DeclaredEstimate {
    pub load: DurationEstimate,
    pub source: Label,
}

/// Declared resource figures for one configuration, used where the records measured none.
#[derive(Clone, Debug, PartialEq)]
pub struct DeclaredResources {
    /// Device bytes held once loaded.
    pub retained_gpu_bytes: u64,
    /// The most device bytes held while loading.
    pub peak_gpu_bytes: u64,
    pub peak_host_bytes: u64,
    pub peak_pinned_host_bytes: u64,
    pub source: Label,
}

/// Why a value is the declared estimate rather than a measurement.
#[derive(Clone, Debug, PartialEq)]
pub enum EstimateReason {
    /// Nothing was observed at all.
    NoObservations,
    /// Samples exist, but only for other configurations.
    OtherConfiguration { observed_configurations: usize },
    /// Records of this configuration were offered but not trusted.
    Untrusted { reason: UntrustedReason },
    /// Every sample of this configuration is older than the policy allows.
    Stale {
        newest_age: Duration,
        max_age: Duration,
    },
    /// Fresh samples exist, but fewer than the policy requires.
    TooFewSamples { fresh: usize, required: usize },
    /// Fresh samples exist, but none measured this quantity.
    NotMeasured,
    /// A measured load took no time, which no duration estimate accepts.
    ZeroDuration,
    /// The load curve could not be fitted to the samples.
    CurveUnfit { error: ChunkingError },
    /// CORE-08 could not state the samples' provenance.
    ProvenanceUnavailable { error: ReportError },
}

/// Where a value came from.
#[derive(Clone, Debug, PartialEq)]
pub enum Basis {
    /// Computed from fresh, trusted samples of exactly these configurations.
    Measured {
        configurations: BTreeSet<ConfigurationFingerprint>,
        samples: usize,
        /// The age of the newest and oldest sample used.
        newest_age: Duration,
        oldest_age: Duration,
        /// CORE-08 provenance of the very records used: a Yougori measurement, or the
        /// fake substrate when a simulation accepted it.
        provenance: Provenance,
    },
    /// The declared estimate, with why no measurement was used.
    Estimated {
        source: Label,
        reason: EstimateReason,
    },
}

impl Basis {
    /// Whether the value was measured.
    pub fn is_measured(&self) -> bool {
        matches!(self, Self::Measured { .. })
    }

    /// The evidence digest of a measured value (a Yougori measurement, or a
    /// fake-substrate run that validates comparisons only); `None` for an estimate.
    pub fn evidence(&self) -> Option<Digest> {
        match self {
            Self::Measured { provenance, .. } => provenance.comparable_evidence().ok(),
            Self::Estimated { .. } => None,
        }
    }
}

/// A value and where it came from.
#[derive(Clone, Debug, PartialEq)]
pub struct Labelled<T> {
    pub value: T,
    pub basis: Basis,
}

/// A reload cost: its duration estimate with its uncertainty interval, and its basis.
pub type ReloadCost = Labelled<DurationEstimate>;

impl Labelled<DurationEstimate> {
    /// The expected reload time in seconds: `CachedObject::reload_seconds` of the §2.7
    /// retention policies.
    pub fn reload_seconds(&self) -> f64 {
        self.value.expected().as_secs_f64()
    }

    /// The pessimistic end of the interval, which deadline admission is judged by
    /// (GPU-W06 "uncertainty-aware ETA").
    pub fn admission_duration(&self) -> Duration {
        self.value.high()
    }
}

/// Measured or declared resource inputs of one configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct ResourceInputs {
    pub retained_gpu_bytes: Labelled<u64>,
    pub peak_gpu_bytes: Labelled<u64>,
    pub peak_host_bytes: Labelled<u64>,
    pub peak_pinned_host_bytes: Labelled<u64>,
}

#[derive(Clone, Debug, PartialEq)]
struct Sample {
    configuration: ConfigurationFingerprint,
    load: LoadAttemptKey,
    collected_at: MonotonicTime,
    load_nanos: u64,
    record: RunRecord,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Configuration {
    /// Oldest first.
    samples: VecDeque<Sample>,
    /// The latest reason a record of this configuration was refused.
    refused: Option<UntrustedReason>,
    last_offered: MonotonicTime,
}

/// The store of trusted load samples, bound to their configurations (see the module
/// documentation). Bounded by its policy.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservedCosts {
    policy: CostPolicy,
    session: ClockSession,
    configurations: BTreeMap<ConfigurationFingerprint, Configuration>,
    shared_loads: u64,
    dropped_samples: u64,
    dropped_configurations: u64,
}

/// The load a record measured, in nanoseconds: a request's demand load, or a load
/// attempt's ready latency.
fn load_interval(record: &RunRecord) -> Option<u64> {
    if let Ok(interval) = record.interval(IntervalKind::DemandLoad) {
        return Some(interval.elapsed_nanos());
    }
    match record.scenario {
        Scenario::Stages {
            primary: IntervalKind::ReadyLatency,
        } if record.is_success() => record
            .interval(IntervalKind::ReadyLatency)
            .ok()
            .map(|interval| interval.elapsed_nanos()),
        _ => None,
    }
}

impl ObservedCosts {
    /// An empty store whose freshness is judged on `session`, the clock session its
    /// queries' clock reads.
    pub fn new(policy: CostPolicy, session: ClockSession) -> Result<Self, ObservationRefusal> {
        policy.check()?;
        Ok(Self {
            policy,
            session,
            configurations: BTreeMap::new(),
            shared_loads: 0,
            dropped_samples: 0,
            dropped_configurations: 0,
        })
    }

    /// The policy records are judged by.
    pub fn policy(&self) -> CostPolicy {
        self.policy
    }

    /// Records skipped because their load was already a sample.
    pub fn shared_loads(&self) -> u64 {
        self.shared_loads
    }

    /// Samples dropped by the per-configuration bound.
    pub fn dropped_samples(&self) -> u64 {
        self.dropped_samples
    }

    /// Configurations dropped by the configuration bound.
    pub fn dropped_configurations(&self) -> u64 {
        self.dropped_configurations
    }

    /// How many samples of `configuration` are kept, fresh or not.
    pub fn samples(&self, configuration: ConfigurationFingerprint) -> usize {
        self.configurations
            .get(&configuration)
            .map_or(0, |entry| entry.samples.len())
    }

    /// Offers one record. A record that does not validate, measures no load or binds to
    /// no configuration is refused; an untrusted one is refused and remembered against
    /// its configuration, so a query for it says why it fell back.
    pub fn ingest(
        &mut self,
        observation: CostObservation,
        clock: &dyn Clock,
    ) -> Result<Ingested, ObservationRefusal> {
        let CostObservation {
            record,
            source,
            collected_in,
            collected_at,
            load,
        } = observation;
        record
            .validate()
            .map_err(|error| ObservationRefusal::Invalid { error })?;
        let load_nanos = load_interval(&record).ok_or(ObservationRefusal::NoLoadInterval)?;
        let configuration = ReloadConfiguration::of_record(&record)?.fingerprint()?;
        let now = clock.now();
        let untrusted = if record.substrate == RunSubstrate::FakeTimeControlled
            && !self.policy.accept_fake_substrate
        {
            Some(UntrustedReason::FakeSubstrate)
        } else if !source.satisfies(self.policy.minimum_source) {
            Some(UntrustedReason::Source {
                source,
                minimum: self.policy.minimum_source,
            })
        } else if collected_in != self.session {
            Some(UntrustedReason::OtherClockSession)
        } else if collected_at > now {
            Some(UntrustedReason::CollectedInTheFuture { collected_at, now })
        } else {
            None
        };
        let max_samples = self.policy.max_samples_per_configuration;
        let (shared, dropped) = {
            let entry = self.entry(configuration, now);
            if let Some(reason) = untrusted {
                entry.refused = Some(reason);
                return Err(ObservationRefusal::Untrusted {
                    configuration,
                    reason,
                });
            }
            if entry.samples.iter().any(|sample| sample.load == load) {
                (true, 0u64)
            } else {
                entry.samples.push_back(Sample {
                    configuration,
                    load,
                    collected_at,
                    load_nanos,
                    record,
                });
                let mut dropped = 0u64;
                while entry.samples.len() > max_samples {
                    entry.samples.pop_front();
                    dropped += 1;
                }
                (false, dropped)
            }
        };
        if shared {
            self.shared_loads = self.shared_loads.saturating_add(1);
            return Ok(Ingested::SharedLoad { configuration });
        }
        self.dropped_samples = self.dropped_samples.saturating_add(dropped);
        Ok(Ingested::Stored { configuration })
    }

    /// The configuration's entry, made room for under the configuration bound.
    fn entry(
        &mut self,
        configuration: ConfigurationFingerprint,
        now: MonotonicTime,
    ) -> &mut Configuration {
        if !self.configurations.contains_key(&configuration)
            && self.configurations.len() >= self.policy.max_configurations
        {
            let least_recent = self
                .configurations
                .iter()
                .min_by_key(|(_, entry)| entry.last_offered)
                .map(|(fingerprint, _)| *fingerprint);
            if let Some(fingerprint) = least_recent {
                self.configurations.remove(&fingerprint);
                self.dropped_configurations = self.dropped_configurations.saturating_add(1);
            }
        }
        let entry = self.configurations.entry(configuration).or_default();
        entry.last_offered = entry.last_offered.max(now);
        entry
    }

    /// Fresh samples of `configuration`, at least `min_samples` of them, or why not.
    fn fresh(
        &self,
        configuration: ConfigurationFingerprint,
        now: MonotonicTime,
    ) -> Result<Vec<&Sample>, EstimateReason> {
        let observed_configurations = self
            .configurations
            .values()
            .filter(|entry| !entry.samples.is_empty())
            .count();
        let Some(entry) = self.configurations.get(&configuration) else {
            return Err(if observed_configurations == 0 {
                EstimateReason::NoObservations
            } else {
                EstimateReason::OtherConfiguration {
                    observed_configurations,
                }
            });
        };
        let max_age = self.policy.max_age;
        let fresh: Vec<&Sample> = entry
            .samples
            .iter()
            .filter(|sample| now.saturating_duration_since(sample.collected_at) <= max_age)
            .collect();
        if fresh.len() >= self.policy.min_samples {
            return Ok(fresh);
        }
        if !fresh.is_empty() {
            return Err(EstimateReason::TooFewSamples {
                fresh: fresh.len(),
                required: self.policy.min_samples,
            });
        }
        if let Some(newest) = entry.samples.back() {
            return Err(EstimateReason::Stale {
                newest_age: now.saturating_duration_since(newest.collected_at),
                max_age,
            });
        }
        if let Some(reason) = entry.refused {
            return Err(EstimateReason::Untrusted { reason });
        }
        Err(if observed_configurations == 0 {
            EstimateReason::NoObservations
        } else {
            EstimateReason::OtherConfiguration {
                observed_configurations,
            }
        })
    }

    /// The measured basis of `samples`, which are fresh at `now`.
    fn measured_basis(samples: &[&Sample], now: MonotonicTime) -> Result<Basis, EstimateReason> {
        let records: Vec<RunRecord> = samples.iter().map(|sample| sample.record.clone()).collect();
        let provenance = Provenance::of_records(&records)
            .map_err(|error| EstimateReason::ProvenanceUnavailable { error })?;
        let mut newest_age = Duration::MAX;
        let mut oldest_age = Duration::ZERO;
        for sample in samples {
            let age = now.saturating_duration_since(sample.collected_at);
            newest_age = newest_age.min(age);
            oldest_age = oldest_age.max(age);
        }
        let configurations = samples.iter().map(|sample| sample.configuration).collect();
        Ok(Basis::Measured {
            configurations,
            samples: samples.len(),
            newest_age,
            oldest_age,
            provenance,
        })
    }

    /// The reload cost of `configuration` at the clock's now: the shortest, the median
    /// and the 95th-percentile fresh sample (nearest rank, so each is an observed value),
    /// or the declared estimate labelled with why.
    pub fn reload_cost(
        &self,
        configuration: ConfigurationFingerprint,
        declared: &DeclaredEstimate,
        clock: &dyn Clock,
    ) -> ReloadCost {
        let now = clock.now();
        let estimated = |reason| Labelled {
            value: declared.load,
            basis: Basis::Estimated {
                source: declared.source.clone(),
                reason,
            },
        };
        let samples = match self.fresh(configuration, now) {
            Ok(samples) => samples,
            Err(reason) => return estimated(reason),
        };
        let mut sorted: Vec<u64> = samples.iter().map(|sample| sample.load_nanos).collect();
        sorted.sort_unstable();
        let observed = |quantile| {
            percentile(&sorted, quantile, PercentileMethod::NearestRank)
                .ok()
                .and_then(|value| {
                    sorted
                        .iter()
                        .copied()
                        .find(|sample| *sample as f64 == value)
                })
        };
        let (Some(low), Some(expected), Some(high)) = (
            sorted.first().copied(),
            observed(Quantile::P50),
            observed(Quantile::P95),
        ) else {
            return estimated(EstimateReason::TooFewSamples {
                fresh: 0,
                required: self.policy.min_samples,
            });
        };
        let Ok(value) = DurationEstimate::new(
            Duration::from_nanos(low),
            Duration::from_nanos(expected),
            Duration::from_nanos(high),
        ) else {
            return estimated(EstimateReason::ZeroDuration);
        };
        match Self::measured_basis(&samples, now) {
            Ok(basis) => Labelled { value, basis },
            Err(reason) => estimated(reason),
        }
    }

    /// Retained and peak bytes of `configuration`: the largest fresh measured value of
    /// each, which is what a reservation must cover, or the declared figure labelled
    /// with why.
    pub fn resources(
        &self,
        configuration: ConfigurationFingerprint,
        declared: &DeclaredResources,
        clock: &dyn Clock,
    ) -> ResourceInputs {
        let now = clock.now();
        let fresh = self.fresh(configuration, now);
        let field = |pick: fn(&RunRecord) -> &Measured<u64>, fallback: u64| -> Labelled<u64> {
            let estimated = |reason| Labelled {
                value: fallback,
                basis: Basis::Estimated {
                    source: declared.source.clone(),
                    reason,
                },
            };
            let samples = match &fresh {
                Ok(samples) => samples,
                Err(reason) => return estimated(reason.clone()),
            };
            let measured: Vec<&Sample> = samples
                .iter()
                .copied()
                .filter(|sample| pick(&sample.record).is_measured())
                .collect();
            if measured.len() < self.policy.min_samples {
                return estimated(EstimateReason::NotMeasured);
            }
            let largest = measured
                .iter()
                .filter_map(|sample| pick(&sample.record).value().copied())
                .max();
            match (largest, Self::measured_basis(&measured, now)) {
                (Some(value), Ok(basis)) => Labelled { value, basis },
                (None, _) => estimated(EstimateReason::NotMeasured),
                (_, Err(reason)) => estimated(reason),
            }
        };
        ResourceInputs {
            retained_gpu_bytes: field(
                |record| &record.measurements.retained_gpu_memory_bytes,
                declared.retained_gpu_bytes,
            ),
            peak_gpu_bytes: field(
                |record| &record.measurements.peak_gpu_memory_bytes,
                declared.peak_gpu_bytes,
            ),
            peak_host_bytes: field(
                |record| &record.measurements.peak_host_memory_bytes,
                declared.peak_host_bytes,
            ),
            peak_pinned_host_bytes: field(
                |record| &record.measurements.peak_pinned_host_memory_bytes,
                declared.peak_pinned_host_bytes,
            ),
        }
    }

    /// The transitions' host-to-device [`LoadCurve`] fitted by least squares
    /// ([`LinearServiceFit`]) to the fresh samples of `members`, each a configuration
    /// with the bytes its load moves, or `declared` labelled with why. Every member,
    /// each configuration once, needs its own fresh samples; a fit needs two sizes.
    pub fn load_curve(
        &self,
        members: &[(ConfigurationFingerprint, u64)],
        declared: LoadCurve,
        source: &Label,
        clock: &dyn Clock,
    ) -> Labelled<LoadCurve> {
        let now = clock.now();
        let estimated = |reason| Labelled {
            value: declared,
            basis: Basis::Estimated {
                source: source.clone(),
                reason,
            },
        };
        let mut used: Vec<&Sample> = Vec::new();
        let mut points = Vec::new();
        for (configuration, bytes) in members {
            match self.fresh(*configuration, now) {
                Ok(samples) => {
                    for sample in samples {
                        points.push(ServiceSample {
                            chunk_bytes: *bytes,
                            seconds: sample.load_nanos as f64 / NANOS_PER_SECOND,
                        });
                        used.push(sample);
                    }
                }
                Err(reason) => return estimated(reason),
            }
        }
        let fit = match LinearServiceFit::fit(&points) {
            Ok(fit) => fit,
            Err(error) => return estimated(EstimateReason::CurveUnfit { error }),
        };
        match Self::measured_basis(&used, now) {
            Ok(basis) => Labelled {
                value: LoadCurve {
                    fixed_seconds: fit.overhead_seconds(),
                    bytes_per_second: fit.bandwidth_bytes_per_second(),
                },
                basis,
            },
            Err(reason) => estimated(reason),
        }
    }
}
