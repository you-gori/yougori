//! The lossy metrics stream (CORE-06 "performance metrics ... separate retention and
//! backpressure"; INT-10).
//!
//! Metrics may be lost under pressure, but never silently: every event the stream takes
//! is delivered, sampled out, dropped or expired, and each outcome is counted. A bounded
//! per-series summary keeps each series' levels whatever the buffer loses, so a multi-day
//! soak still sees its start and end levels (S7 long-run stability).

use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU32;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{
    check_name, ConfigError, EmitError, EventEnvelope, EventSequence, ResolvedThrough, StreamKey,
};
use super::redaction::{Field, RedactedFields, RedactionPolicy};
use crate::foundation::ids::MonotonicTime;

strict_tagged_enum! {
    /// One measured value, with its unit in its name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MetricValue (tag = "kind", wire = MetricValueWire, wire_name = "MetricValueWire") {
        /// A count that only rises.
        Counter { count: u64 },
        /// A level in bytes, such as allocated or pinned memory.
        GaugeBytes { bytes: u64 },
        /// A level in items, such as live graphs or communicators.
        GaugeCount { count: u64 },
        DurationNanoseconds { nanoseconds: u64 },
        RateBytesPerSecond { bytes_per_second: u64 },
    }
}

impl MetricValue {
    /// The value as a number, for series summaries.
    pub const fn level(self) -> u64 {
        match self {
            Self::Counter { count } | Self::GaugeCount { count } => count,
            Self::GaugeBytes { bytes } => bytes,
            Self::DurationNanoseconds { nanoseconds } => nanoseconds,
            Self::RateBytesPerSecond { bytes_per_second } => bytes_per_second,
        }
    }
}

/// A metric before redaction. The name is a compile-time constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricDraft {
    name: &'static str,
    value: MetricValue,
    labels: Vec<Field>,
}

impl MetricDraft {
    pub fn new(name: &'static str, value: MetricValue) -> Self {
        Self {
            name,
            value,
            labels: Vec::new(),
        }
    }

    pub fn with_label(mut self, label: Field) -> Self {
        self.labels.push(label);
        self
    }

    pub(super) fn redact(self, policy: &RedactionPolicy) -> Result<MetricSample, EmitError> {
        check_name(self.name).map_err(|error| EmitError::InvalidName {
            name: self.name,
            error,
        })?;
        Ok(MetricSample {
            name: self.name.to_owned(),
            value: self.value,
            labels: policy.redact(self.labels)?,
        })
    }
}

/// A metric as it leaves its producer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSample {
    name: String,
    value: MetricValue,
    labels: RedactedFields,
}

impl MetricSample {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> MetricValue {
        self.value
    }

    pub fn labels(&self) -> &RedactedFields {
        &self.labels
    }
}

/// Bounds of the metrics stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsConfig {
    /// Events buffered at most; when full, the oldest is dropped.
    pub capacity_events: usize,
    /// From this many buffered events on, only one event in `keep_one_in` per producer
    /// is kept.
    pub sample_above_events: usize,
    pub keep_one_in: NonZeroU32,
    /// Events older than this when drained are expired.
    pub retention: Duration,
    /// Series summarized at most; samples of further series are counted instead.
    pub max_series: usize,
}

impl MetricsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.capacity_events == 0 {
            return Err(ConfigError::Zero {
                setting: "capacity_events",
            });
        }
        if self.sample_above_events > self.capacity_events {
            return Err(ConfigError::Exceeds {
                setting: "sample_above_events",
                limit: "capacity_events",
            });
        }
        if self.retention.is_zero() {
            return Err(ConfigError::Zero {
                setting: "retention",
            });
        }
        Ok(())
    }
}

/// What the stream did with one offered event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricsAdmission {
    Queued,
    /// Queued; the oldest buffered event was dropped to make room, and counted.
    QueuedDroppingOldest,
    /// Discarded by sampling under pressure, and counted.
    SampledOut,
    /// Refused by the producer's emission limit before it took a sequence, and counted.
    RateLimited,
}

/// Counts of everything the stream took; `offered` always equals `delivered`, plus
/// [`MetricsStream::buffered`], plus [`MetricsTotals::lost`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsTotals {
    pub offered: u64,
    pub delivered: u64,
    pub sampled_out: u64,
    pub dropped_oldest: u64,
    pub expired: u64,
    /// Refused before sealing, so not part of `offered`.
    pub rate_limited: u64,
}

impl MetricsTotals {
    /// Events that took a sequence and will never be delivered.
    pub fn lost(&self) -> u64 {
        self.sampled_out
            .saturating_add(self.dropped_oldest)
            .saturating_add(self.expired)
    }
}

/// One delivery from the metrics stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricsBatch {
    pub events: Vec<EventEnvelope<MetricSample>>,
    /// Per key, every sequence up to `through` was delivered now or earlier, or lost in
    /// this stream; a receiver marks its missing ones lost.
    pub resolved: Vec<ResolvedThrough>,
}

/// One series: a metric name from one producer incarnation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeriesKey {
    pub stream: StreamKey,
    pub name: String,
}

/// The levels of one series over every sample offered, including samples the buffer
/// later lost (S7 long-run stability: leaks and drift).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeriesSummary {
    pub samples: u64,
    pub first_at: MonotonicTime,
    pub first_level: u64,
    pub last_at: MonotonicTime,
    pub last_level: u64,
    pub min_level: u64,
    pub max_level: u64,
}

impl SeriesSummary {
    fn first(at: MonotonicTime, level: u64) -> Self {
        Self {
            samples: 1,
            first_at: at,
            first_level: level,
            last_at: at,
            last_level: level,
            min_level: level,
            max_level: level,
        }
    }

    fn note(&mut self, at: MonotonicTime, level: u64) {
        self.samples = self.samples.saturating_add(1);
        self.last_at = at;
        self.last_level = level;
        self.min_level = self.min_level.min(level);
        self.max_level = self.max_level.max(level);
    }

    /// Time from the first to the last sample.
    pub fn span(&self) -> Duration {
        self.last_at.saturating_duration_since(self.first_at)
    }

    /// Last level minus first level.
    pub fn net_change(&self) -> i128 {
        i128::from(self.last_level) - i128::from(self.first_level)
    }
}

#[derive(Clone, Copy, Debug)]
struct KeyProgress {
    highest: EventSequence,
    reported: Option<EventSequence>,
}

/// The bounded, lossy metrics stream (CORE-06; INT-10).
#[derive(Clone, Debug)]
pub struct MetricsStream {
    config: MetricsConfig,
    buffer: VecDeque<EventEnvelope<MetricSample>>,
    pressure: BTreeMap<StreamKey, u64>,
    processed: BTreeMap<StreamKey, KeyProgress>,
    totals: MetricsTotals,
    series: BTreeMap<SeriesKey, SeriesSummary>,
    unsummarized_samples: u64,
}

impl MetricsStream {
    pub fn new(config: MetricsConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            buffer: VecDeque::new(),
            pressure: BTreeMap::new(),
            processed: BTreeMap::new(),
            totals: MetricsTotals::default(),
            series: BTreeMap::new(),
            unsummarized_samples: 0,
        })
    }

    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }

    /// Takes one sealed event. Under pressure it keeps one event in N per key; when full
    /// it drops the oldest buffered event. It never refuses and never blocks the producer.
    pub fn offer(&mut self, event: EventEnvelope<MetricSample>) -> MetricsAdmission {
        let key = event.key();
        self.totals.offered = self.totals.offered.saturating_add(1);
        self.note_series(&key, &event);
        self.note_processed(&key, event.sequence());
        if self.buffer.len() >= self.config.sample_above_events {
            let seen = self.pressure.entry(key).or_insert(0);
            *seen = seen.saturating_add(1);
            if !(*seen - 1).is_multiple_of(u64::from(self.config.keep_one_in.get())) {
                self.totals.sampled_out = self.totals.sampled_out.saturating_add(1);
                return MetricsAdmission::SampledOut;
            }
        } else {
            self.pressure.clear();
        }
        let admission = if self.buffer.len() >= self.config.capacity_events {
            self.buffer.pop_front();
            self.totals.dropped_oldest = self.totals.dropped_oldest.saturating_add(1);
            MetricsAdmission::QueuedDroppingOldest
        } else {
            MetricsAdmission::Queued
        };
        self.buffer.push_back(event);
        admission
    }

    pub(super) fn count_rate_limited(&mut self) {
        self.totals.rate_limited = self.totals.rate_limited.saturating_add(1);
    }

    /// Expires events older than the retention, then delivers up to `max_events` of the
    /// rest, oldest first, with how far each key is resolved.
    pub fn drain(&mut self, now: MonotonicTime, max_events: usize) -> MetricsBatch {
        while self.buffer.front().is_some_and(|event| {
            now.saturating_duration_since(event.emitted_at()) > self.config.retention
        }) {
            self.buffer.pop_front();
            self.totals.expired = self.totals.expired.saturating_add(1);
        }
        let take = max_events.min(self.buffer.len());
        let events: Vec<_> = self.buffer.drain(..take).collect();
        self.totals.delivered = self
            .totals
            .delivered
            .saturating_add(u64::try_from(events.len()).unwrap_or(u64::MAX));

        let mut lowest_buffered: BTreeMap<StreamKey, EventSequence> = BTreeMap::new();
        for event in &self.buffer {
            let sequence = event.sequence();
            lowest_buffered
                .entry(event.key())
                .and_modify(|lowest| *lowest = (*lowest).min(sequence))
                .or_insert(sequence);
        }
        let mut resolved = Vec::new();
        for (key, progress) in &mut self.processed {
            let through = match lowest_buffered.get(key) {
                Some(lowest) => match lowest.previous() {
                    Some(before) => before.min(progress.highest),
                    None => continue,
                },
                None => progress.highest,
            };
            if progress.reported.is_none_or(|reported| through > reported) {
                progress.reported = Some(through);
                resolved.push(ResolvedThrough {
                    key: key.clone(),
                    through,
                });
            }
        }
        self.processed.retain(|key, progress| {
            lowest_buffered.contains_key(key) || progress.reported != Some(progress.highest)
        });
        MetricsBatch { events, resolved }
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    pub fn totals(&self) -> MetricsTotals {
        self.totals
    }

    pub fn series(&self) -> impl Iterator<Item = (&SeriesKey, &SeriesSummary)> {
        self.series.iter()
    }

    /// Samples of series beyond `max_series`, counted rather than summarized.
    pub fn unsummarized_samples(&self) -> u64 {
        self.unsummarized_samples
    }

    fn note_processed(&mut self, key: &StreamKey, sequence: EventSequence) {
        self.processed
            .entry(key.clone())
            .and_modify(|progress| progress.highest = progress.highest.max(sequence))
            .or_insert(KeyProgress {
                highest: sequence,
                reported: None,
            });
    }

    fn note_series(&mut self, key: &StreamKey, event: &EventEnvelope<MetricSample>) {
        let series = SeriesKey {
            stream: key.clone(),
            name: event.payload().name.clone(),
        };
        let at = event.emitted_at();
        let level = event.payload().value.level();
        if let Some(summary) = self.series.get_mut(&series) {
            summary.note(at, level);
        } else if self.series.len() < self.config.max_series {
            self.series.insert(series, SeriesSummary::first(at, level));
        } else {
            self.unsummarized_samples = self.unsummarized_samples.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::envelope::{
        Phase, ProducerCore, ProducerIncarnation, StreamKind,
    };
    use crate::foundation::events::fakes::{context, producer};
    use crate::foundation::evidence::SourceClass;

    fn config(
        capacity_events: usize,
        sample_above_events: usize,
        keep_one_in: u32,
    ) -> MetricsConfig {
        MetricsConfig {
            capacity_events,
            sample_above_events,
            keep_one_in: NonZeroU32::new(keep_one_in).unwrap(),
            retention: Duration::from_secs(60),
            max_series: 4,
        }
    }

    fn core(name: &str) -> ProducerCore {
        ProducerCore::new(
            producer(name),
            ProducerIncarnation::FIRST,
            StreamKind::Metrics,
            SourceClass::HostProbe,
        )
    }

    fn sample(core: &mut ProducerCore, at_seconds: u64, bytes: u64) -> EventEnvelope<MetricSample> {
        let draft = MetricDraft::new("gpu.resident_bytes", MetricValue::GaugeBytes { bytes });
        let sample = draft.redact(&RedactionPolicy::metadata_only()).unwrap();
        core.seal(
            context("op-1", Phase::Loading),
            MonotonicTime::from_nanos(at_seconds * 1_000_000_000),
            sample,
        )
        .unwrap()
    }

    fn sequences(batch: &MetricsBatch) -> Vec<u64> {
        batch
            .events
            .iter()
            .map(|event| event.sequence().get())
            .collect()
    }

    fn check_identity(stream: &MetricsStream) {
        let totals = stream.totals();
        assert_eq!(
            totals.offered,
            totals.delivered + u64::try_from(stream.buffered()).unwrap() + totals.lost()
        );
    }

    #[test]
    fn under_pressure_one_event_in_n_is_kept_and_the_rest_counted() {
        let mut stream = MetricsStream::new(config(100, 4, 3)).unwrap();
        let mut runner = core("runner");
        let admissions: Vec<MetricsAdmission> = (0..10)
            .map(|second| stream.offer(sample(&mut runner, second, second)))
            .collect();
        use MetricsAdmission::{Queued, SampledOut};
        assert_eq!(
            admissions,
            [
                Queued, Queued, Queued, Queued, Queued, SampledOut, SampledOut, Queued, SampledOut,
                SampledOut
            ]
        );
        assert_eq!(stream.totals().sampled_out, 4);
        check_identity(&stream);
        let batch = stream.drain(MonotonicTime::from_nanos(10_000_000_000), usize::MAX);
        assert_eq!(sequences(&batch), [1, 2, 3, 4, 5, 8]);
        assert_eq!(batch.resolved.len(), 1);
        assert_eq!(batch.resolved[0].through.get(), 10);
        check_identity(&stream);
    }

    #[test]
    fn when_full_the_oldest_is_dropped_and_counted() {
        let mut stream = MetricsStream::new(config(3, 3, 1)).unwrap();
        let mut runner = core("runner");
        for second in 0..5 {
            stream.offer(sample(&mut runner, second, second));
        }
        assert_eq!(stream.buffered(), 3);
        assert_eq!(stream.totals().dropped_oldest, 2);
        check_identity(&stream);
        let batch = stream.drain(MonotonicTime::from_nanos(5_000_000_000), usize::MAX);
        assert_eq!(sequences(&batch), [3, 4, 5]);
        assert_eq!(stream.totals().lost(), 2);
    }

    #[test]
    fn events_past_retention_expire_and_are_counted() {
        let mut stream = MetricsStream::new(config(10, 10, 1)).unwrap();
        let mut runner = core("runner");
        stream.offer(sample(&mut runner, 0, 1));
        stream.offer(sample(&mut runner, 30, 2));
        stream.offer(sample(&mut runner, 90, 3));
        // At 100 s, the event from 0 s is 100 s old and the one from 30 s is 70 s old.
        let batch = stream.drain(MonotonicTime::from_nanos(100_000_000_000), usize::MAX);
        assert_eq!(sequences(&batch), [3]);
        assert_eq!(stream.totals().expired, 2);
        check_identity(&stream);
    }

    #[test]
    fn resolution_never_covers_an_event_still_buffered() {
        let mut stream = MetricsStream::new(config(100, 2, 2)).unwrap();
        let mut runner = core("runner");
        for second in 0..6 {
            stream.offer(sample(&mut runner, second, second));
        }
        // Buffered: 1, 2, 3, 5; sampled out: 4 and 6.
        let first = stream.drain(MonotonicTime::from_nanos(6_000_000_000), 2);
        assert_eq!(sequences(&first), [1, 2]);
        assert_eq!(first.resolved[0].through.get(), 2);
        let second = stream.drain(MonotonicTime::from_nanos(6_000_000_000), 1);
        assert_eq!(sequences(&second), [3]);
        assert_eq!(second.resolved[0].through.get(), 4);
        let third = stream.drain(MonotonicTime::from_nanos(6_000_000_000), 10);
        assert_eq!(sequences(&third), [5]);
        assert_eq!(third.resolved[0].through.get(), 6);
        // Nothing new: nothing is reported again.
        let fourth = stream.drain(MonotonicTime::from_nanos(6_000_000_000), 10);
        assert!(fourth.events.is_empty() && fourth.resolved.is_empty());
        check_identity(&stream);
    }

    #[test]
    fn series_summaries_keep_levels_whatever_the_buffer_loses() {
        let mut stream = MetricsStream::new(config(2, 1, 4)).unwrap();
        let mut runner = core("runner");
        let levels = [500, 900, 100, 700, 650];
        for (second, level) in levels.iter().enumerate() {
            stream.offer(sample(&mut runner, second as u64, *level));
        }
        assert!(stream.totals().lost() > 0);
        let (key, summary) = stream.series().next().unwrap();
        assert_eq!(key.name, "gpu.resident_bytes");
        assert_eq!(summary.samples, 5);
        assert_eq!((summary.first_level, summary.last_level), (500, 650));
        assert_eq!((summary.min_level, summary.max_level), (100, 900));
        assert_eq!(summary.net_change(), 150);
        assert_eq!(summary.span(), Duration::from_secs(4));
    }

    #[test]
    fn series_beyond_the_bound_are_counted() {
        let mut stream = MetricsStream::new(MetricsConfig {
            max_series: 1,
            ..config(10, 10, 1)
        })
        .unwrap();
        let mut first = core("first");
        let mut second = core("second");
        stream.offer(sample(&mut first, 0, 1));
        stream.offer(sample(&mut second, 0, 1));
        stream.offer(sample(&mut second, 1, 1));
        assert_eq!(stream.series().count(), 1);
        assert_eq!(stream.unsummarized_samples(), 2);
    }

    #[test]
    fn metric_names_are_checked() {
        let draft = MetricDraft::new("gpu bytes", MetricValue::Counter { count: 1 });
        assert!(matches!(
            draft.redact(&RedactionPolicy::metadata_only()),
            Err(EmitError::InvalidName {
                name: "gpu bytes",
                ..
            })
        ));
        let labelled = MetricDraft::new("gpu.bytes", MetricValue::Counter { count: 1 })
            .with_label(Field::untrusted("guest_label", "C:\\Users\\me"))
            .redact(&RedactionPolicy::metadata_only())
            .unwrap();
        assert_eq!(labelled.labels().fields().len(), 1);
        assert!(!serde_json::to_string(&labelled).unwrap().contains("Users"));
    }

    #[test]
    fn configuration_is_checked() {
        assert_eq!(
            MetricsStream::new(config(0, 0, 1)).err(),
            Some(ConfigError::Zero {
                setting: "capacity_events"
            })
        );
        assert_eq!(
            MetricsStream::new(config(2, 3, 1)).err(),
            Some(ConfigError::Exceeds {
                setting: "sample_above_events",
                limit: "capacity_events"
            })
        );
        assert_eq!(
            MetricsStream::new(MetricsConfig {
                retention: Duration::ZERO,
                ..config(2, 2, 1)
            })
            .err(),
            Some(ConfigError::Zero {
                setting: "retention"
            })
        );
    }

    #[test]
    fn metric_values_refuse_unknown_fields() {
        let value: MetricValue =
            serde_json::from_str(r#"{"kind":"gauge_bytes","bytes":4}"#).unwrap();
        assert_eq!(value, MetricValue::GaugeBytes { bytes: 4 });
        assert!(serde_json::from_str::<MetricValue>(
            r#"{"kind":"gauge_bytes","bytes":4,"unit":"GB"}"#
        )
        .is_err());
    }
}
