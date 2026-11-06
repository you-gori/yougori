//! Fan-out of numbered deliveries to subscribers that read at their own pace (CORE-06
//! "separate retention/backpressure" and "metrics floods cannot suppress revocation"; INT-10
//! "metrics pressure cannot block revocation"; VM part §8.2 "never block the revocation
//! channel"; docs/combined-plan-leftover-tasks.md S06).
//!
//! [`DeliveryFanout::publish`] gives each [`Delivery`] of an [`EventHub`] to every
//! subscriber and never waits or refuses. A subscriber that falls behind loses what CORE-06
//! lets it lose, in this order, and every loss is counted:
//!
//! 1. Metrics, oldest first, which stay best effort. A held delivery's metrics are shed and
//!    its resolved marks kept, so the receiver's [`Reconciler`] closes the shed sequences
//!    as discarded metrics.
//! 2. Whole deliveries, oldest first, never the newest. A shed delivery's number never
//!    arrives, so the receiver counts the delivery lost and closes the gaps it covered as
//!    lost, never as superseded; the subscriber is told it lagged ([`SubscriberLag`]) and resyncs
//!    from a progress snapshot.
//!
//! Revocations are never shed. They leave each delivery as it is held and wait in the
//! subscriber's own revocation reserve, which no metric or progress update can use; the
//! next delivery the subscriber takes carries all of them, before its other events. More
//! pending revocations than the reserve holds widen to a revoke-all for that subscriber,
//! as the revocation lane widens: stricter, never weaker. Their resolved marks stay in
//! their own deliveries, which the carrying delivery never follows, so a receiver meets
//! every revocation before a mark that covers it.
//!
//! [`EventHub`]: super::EventHub
//! [`Reconciler`]: super::Reconciler

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::envelope::{ConfigError, DeliveryNumber};
use super::hub::Delivery;
use super::revocation::{RevocationBatch, RevokeAll};
use crate::foundation::ids::MonotonicTime;

/// One subscriber of a [`DeliveryFanout`]. Identifiers are never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriberId(u64);

impl SubscriberId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "subscriber {}", self.0)
    }
}

/// Bounds of one subscriber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubscriberConfig {
    /// Deliveries held at most; the newest is always kept.
    pub max_deliveries: usize,
    /// Progress updates and metrics held at most over all held deliveries. The newest
    /// delivery's progress is kept even beyond it, so the subscriber's memory stays within
    /// this bound plus one delivery.
    pub max_events: usize,
    /// Revocations of executions and of grants held at most: a reserve no other traffic
    /// uses. More widen to a revoke-all.
    pub revocation_reserve: usize,
}

impl SubscriberConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (setting, value) in [
            ("max_deliveries", self.max_deliveries),
            ("max_events", self.max_events),
            ("revocation_reserve", self.revocation_reserve),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero { setting });
            }
        }
        Ok(())
    }
}

/// Counts of what one subscriber was given, took and lost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriberTotals {
    pub published: u64,
    pub taken: u64,
    /// Metrics shed, from held deliveries or with shed deliveries.
    pub metrics_shed: u64,
    pub deliveries_shed: u64,
    /// Progress updates in shed deliveries.
    pub progress_shed: u64,
    /// Revocations of executions and of grants the subscriber took.
    pub revocations_taken: u64,
    /// Revocations beyond the reserve, covered by a revoke-all instead.
    pub revocations_widened: u64,
}

/// Deliveries shed since the subscriber last took: it lagged. It resyncs from
/// [`super::EventHub::progress_snapshot`] through [`super::Reconciler::resync`]. Their
/// revocations were not shed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubscriberLag {
    pub first: DeliveryNumber,
    pub last: DeliveryNumber,
    pub deliveries: u64,
}

/// What one take returned, in the order a receiver applies it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriberBatch {
    /// The first carries every pending revocation.
    pub deliveries: Vec<Delivery>,
    pub lag: Option<SubscriberLag>,
}

/// What one subscriber holds now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubscriberHeld {
    pub deliveries: usize,
    pub events: usize,
    pub revocations: usize,
    pub revoke_all: Option<RevokeAll>,
}

/// Why the fan-out refused a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FanoutError {
    Config(ConfigError),
    UnknownSubscriber {
        subscriber: SubscriberId,
    },
    /// Every subscriber identifier was used.
    SubscribersExhausted,
}

impl fmt::Display for FanoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::UnknownSubscriber { subscriber } => write!(f, "{subscriber} is not subscribed"),
            Self::SubscribersExhausted => f.write_str("every subscriber identifier was used"),
        }
    }
}

impl std::error::Error for FanoutError {}

#[derive(Debug)]
struct Subscriber {
    config: SubscriberConfig,
    held: VecDeque<Delivery>,
    /// Progress updates and metrics in `held`.
    events: usize,
    /// Revocations waiting for the next delivery taken; their marks stay in `held`.
    pending: RevocationBatch,
    lag: Option<SubscriberLag>,
    totals: SubscriberTotals,
}

impl Subscriber {
    fn new(config: SubscriberConfig) -> Self {
        Self {
            config,
            held: VecDeque::new(),
            events: 0,
            pending: RevocationBatch::default(),
            lag: None,
            totals: SubscriberTotals::default(),
        }
    }

    /// Holds `delivery`, its revocations apart, then sheds what exceeds the bounds.
    fn offer(&mut self, delivery: &Delivery) {
        let mut held = delivery.clone();
        let revocations = std::mem::take(&mut held.revocations);
        held.revocations.resolved = revocations.resolved;
        if let Some(widened) = revocations.revoke_all {
            self.widen(widened);
        }
        for notice in revocations.notices {
            if self.pending_revocations() < self.config.revocation_reserve {
                self.pending.notices.push(notice);
            } else {
                self.widen_one(notice.emitted_at());
            }
        }
        for grant in revocations.grants {
            if self.pending_revocations() < self.config.revocation_reserve {
                self.pending.grants.push(grant);
            } else {
                self.widen_one(grant.emitted_at());
            }
        }
        self.events = self.events.saturating_add(events_in(&held));
        self.held.push_back(held);
        self.totals.published = self.totals.published.saturating_add(1);
        self.shed();
    }

    fn pending_revocations(&self) -> usize {
        self.pending
            .notices
            .len()
            .saturating_add(self.pending.grants.len())
    }

    fn widen_one(&mut self, since: MonotonicTime) {
        self.widen(RevokeAll { since, covered: 1 });
        self.totals.revocations_widened = self.totals.revocations_widened.saturating_add(1);
    }

    fn widen(&mut self, widened: RevokeAll) {
        self.pending.revoke_all = Some(match self.pending.revoke_all {
            None => widened,
            Some(held) => RevokeAll {
                since: held.since.min(widened.since),
                covered: held.covered.saturating_add(widened.covered),
            },
        });
    }

    /// Sheds metrics, then whole deliveries other than the newest, oldest first, until
    /// the bounds hold or only the newest delivery is left.
    fn shed(&mut self) {
        while self.held.len() > self.config.max_deliveries || self.events > self.config.max_events {
            if self.events > self.config.max_events {
                if let Some(delivery) = self
                    .held
                    .iter_mut()
                    .find(|delivery| !delivery.metrics.events.is_empty())
                {
                    let shed = delivery.metrics.events.len();
                    delivery.metrics.events.clear();
                    self.events = self.events.saturating_sub(shed);
                    self.totals.metrics_shed = self.totals.metrics_shed.saturating_add(count(shed));
                    continue;
                }
            }
            if self.held.len() <= 1 {
                break;
            }
            let Some(oldest) = self.held.pop_front() else {
                break;
            };
            self.events = self.events.saturating_sub(events_in(&oldest));
            let totals = &mut self.totals;
            totals.deliveries_shed = totals.deliveries_shed.saturating_add(1);
            totals.progress_shed = totals
                .progress_shed
                .saturating_add(count(oldest.progress.updates.len()));
            totals.metrics_shed = totals
                .metrics_shed
                .saturating_add(count(oldest.metrics.events.len()));
            let number = oldest.number;
            self.lag = Some(match self.lag {
                None => SubscriberLag {
                    first: number,
                    last: number,
                    deliveries: 1,
                },
                Some(lag) => SubscriberLag {
                    first: lag.first.min(number),
                    last: lag.last.max(number),
                    deliveries: lag.deliveries.saturating_add(1),
                },
            });
        }
    }

    /// Up to `max` held deliveries, oldest first; the first carries every pending
    /// revocation.
    fn take(&mut self, max: usize) -> SubscriberBatch {
        let taken = max.min(self.held.len());
        let mut deliveries: Vec<Delivery> = self.held.drain(..taken).collect();
        for delivery in &deliveries {
            self.events = self.events.saturating_sub(events_in(delivery));
        }
        if let Some(first) = deliveries.first_mut() {
            let pending = std::mem::take(&mut self.pending);
            self.totals.revocations_taken = self.totals.revocations_taken.saturating_add(count(
                pending.notices.len().saturating_add(pending.grants.len()),
            ));
            first.revocations.revoke_all = pending.revoke_all;
            first.revocations.notices = pending.notices;
            first.revocations.grants = pending.grants;
        }
        self.totals.taken = self.totals.taken.saturating_add(count(taken));
        SubscriberBatch {
            deliveries,
            lag: self.lag.take(),
        }
    }

    fn held(&self) -> SubscriberHeld {
        SubscriberHeld {
            deliveries: self.held.len(),
            events: self.events,
            revocations: self.pending_revocations(),
            revoke_all: self.pending.revoke_all,
        }
    }
}

fn events_in(delivery: &Delivery) -> usize {
    delivery
        .progress
        .updates
        .len()
        .saturating_add(delivery.metrics.events.len())
}

fn count(items: usize) -> u64 {
    u64::try_from(items).unwrap_or(u64::MAX)
}

/// Gives every delivery to every subscriber, each bounded on its own (CORE-06; S06).
#[derive(Debug, Default)]
pub struct DeliveryFanout {
    subscribers: BTreeMap<SubscriberId, Subscriber>,
    next: u64,
    published: u64,
}

impl DeliveryFanout {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a subscriber; it gets every delivery published from now on.
    pub fn subscribe(&mut self, config: SubscriberConfig) -> Result<SubscriberId, FanoutError> {
        config.validate().map_err(FanoutError::Config)?;
        let id = SubscriberId(self.next);
        self.next = self
            .next
            .checked_add(1)
            .ok_or(FanoutError::SubscribersExhausted)?;
        self.subscribers.insert(id, Subscriber::new(config));
        Ok(id)
    }

    /// Removes a subscriber and what it held; returns its totals.
    pub fn unsubscribe(
        &mut self,
        subscriber: SubscriberId,
    ) -> Result<SubscriberTotals, FanoutError> {
        self.subscribers
            .remove(&subscriber)
            .map(|removed| removed.totals)
            .ok_or(FanoutError::UnknownSubscriber { subscriber })
    }

    /// Gives `delivery` to every subscriber. It never waits and never refuses; a
    /// subscriber that is behind sheds as the module documentation describes.
    pub fn publish(&mut self, delivery: &Delivery) {
        for subscriber in self.subscribers.values_mut() {
            subscriber.offer(delivery);
        }
        self.published = self.published.saturating_add(1);
    }

    /// Up to `max_deliveries` of `subscriber`'s held deliveries, oldest first, the first
    /// carrying every pending revocation, and whether it lagged since it last took.
    pub fn take(
        &mut self,
        subscriber: SubscriberId,
        max_deliveries: usize,
    ) -> Result<SubscriberBatch, FanoutError> {
        self.subscriber_mut(subscriber)
            .map(|held| held.take(max_deliveries))
    }

    pub fn held(&self, subscriber: SubscriberId) -> Result<SubscriberHeld, FanoutError> {
        self.subscriber(subscriber).map(Subscriber::held)
    }

    pub fn totals(&self, subscriber: SubscriberId) -> Result<SubscriberTotals, FanoutError> {
        self.subscriber(subscriber).map(|held| held.totals)
    }

    /// Deliveries published so far.
    pub fn published(&self) -> u64 {
        self.published
    }

    pub fn subscribers(&self) -> usize {
        self.subscribers.len()
    }

    fn subscriber(&self, subscriber: SubscriberId) -> Result<&Subscriber, FanoutError> {
        self.subscribers
            .get(&subscriber)
            .ok_or(FanoutError::UnknownSubscriber { subscriber })
    }

    fn subscriber_mut(&mut self, subscriber: SubscriberId) -> Result<&mut Subscriber, FanoutError> {
        self.subscribers
            .get_mut(&subscriber)
            .ok_or(FanoutError::UnknownSubscriber { subscriber })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::foundation::events::envelope::{
        DeliverySequence, EventSequence, Phase, ProducerIncarnation, StreamKind,
    };
    use crate::foundation::events::fakes::{context, execution, manual_clock, producer, resource};
    use crate::foundation::events::hub::{
        EventHub, HubConfig, MetricsProducer, ProgressProducer, RevocationIssuer,
    };
    use crate::foundation::events::metrics::{MetricDraft, MetricValue, MetricsConfig};
    use crate::foundation::events::progress::{
        CancellationBoundary, ProgressConfig, ProgressUpdate, ResourceKind,
    };
    use crate::foundation::events::reconcile::{
        Arrival, DeliveryArrival, DeliveryRange, LossReason, ReconcileConfig, Reconciler,
        SequenceRange,
    };
    use crate::foundation::events::redaction::RedactionPolicy;
    use crate::foundation::events::revocation::{Revocation, RevocationConfig, RevocationReason};
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::ids::{AuthorizationEpoch, ManualClock};

    /// A hub with one metrics producer, one progress producer and one revocation issuer.
    struct Plane {
        hub: EventHub<Arc<ManualClock>>,
        runner: MetricsProducer,
        loader: ProgressProducer,
        issuer: RevocationIssuer,
    }

    impl Plane {
        fn new() -> Self {
            let mut hub = EventHub::new(
                manual_clock(),
                HubConfig {
                    metrics: MetricsConfig {
                        capacity_events: 1_024,
                        sample_above_events: 1_024,
                        keep_one_in: NonZeroU32::MIN,
                        retention: Duration::from_secs(600),
                        max_series: 8,
                    },
                    progress: ProgressConfig {
                        max_tracked: 32,
                        terminal_retention: Duration::from_secs(60),
                    },
                    revocation: RevocationConfig {
                        max_pending_executions: 64,
                    },
                    first_incarnation: ProducerIncarnation::FIRST,
                },
            )
            .unwrap();
            let runner = hub
                .register_metrics(
                    producer("runner"),
                    SourceClass::HostProbe,
                    RedactionPolicy::metadata_only(),
                    None,
                )
                .unwrap();
            let loader = hub
                .register_progress(producer("loader"), SourceClass::HostProbe, None)
                .unwrap();
            let issuer = hub
                .register_revocation_issuer(producer("coordinator"))
                .unwrap();
            Self {
                hub,
                runner,
                loader,
                issuer,
            }
        }

        fn metrics(&mut self, count: u64) {
            for bytes in 0..count {
                self.hub
                    .emit_metric(
                        &mut self.runner,
                        context("op-1", Phase::Running),
                        MetricDraft::new("gpu.resident_bytes", MetricValue::GaugeBytes { bytes }),
                    )
                    .unwrap();
            }
        }

        fn progress(&mut self, shard: &str, completed_bytes: u64) {
            self.hub
                .emit_progress(
                    &mut self.loader,
                    context("op-1", Phase::Loading),
                    ProgressUpdate::new(
                        resource(shard),
                        ResourceKind::Weights,
                        completed_bytes,
                        Some(100),
                        completed_bytes,
                        CancellationBoundary::Anytime,
                    ),
                )
                .unwrap();
        }

        fn revoke(&mut self, name: &str) {
            self.hub
                .emit_revocation(
                    &mut self.issuer,
                    context("op-1", Phase::Revoked),
                    Revocation {
                        execution: execution(name),
                        epoch: AuthorizationEpoch::new(2),
                        reason: RevocationReason::UserRequested,
                    },
                )
                .unwrap();
        }

        fn drain(&mut self) -> Delivery {
            self.hub.drain(usize::MAX)
        }
    }

    fn config(
        max_deliveries: usize,
        max_events: usize,
        revocation_reserve: usize,
    ) -> SubscriberConfig {
        SubscriberConfig {
            max_deliveries,
            max_events,
            revocation_reserve,
        }
    }

    fn number(sequence: u64) -> DeliveryNumber {
        DeliveryNumber {
            epoch: ProducerIncarnation::FIRST,
            sequence: DeliverySequence::new(sequence).unwrap(),
        }
    }

    fn reconciler() -> Reconciler {
        Reconciler::new(ReconcileConfig {
            max_streams: 8,
            window_sequences: 1 << 20,
            max_polls: 3,
            poll_interval: Duration::from_secs(1),
        })
        .unwrap()
    }

    fn executions(delivery: &Delivery) -> Vec<String> {
        delivery
            .revocations
            .notices
            .iter()
            .map(|notice| notice.payload().execution.to_string())
            .collect()
    }

    #[test]
    fn metrics_are_shed_first_and_their_marks_close_them_as_discarded() {
        let mut plane = Plane::new();
        let mut fanout = DeliveryFanout::new();
        let subscriber = fanout.subscribe(config(8, 4, 4)).unwrap();
        plane.metrics(10);
        plane.progress("a", 10);
        fanout.publish(&plane.drain());
        assert_eq!(
            fanout.held(subscriber).unwrap(),
            SubscriberHeld {
                deliveries: 1,
                events: 1,
                revocations: 0,
                revoke_all: None
            }
        );
        let batch = fanout.take(subscriber, 10).unwrap();
        assert_eq!(batch.lag, None);
        let delivery = &batch.deliveries[0];
        assert!(delivery.metrics.events.is_empty());
        assert_eq!(delivery.progress.updates.len(), 1);
        // The marks stayed, so the receiver closes the shed metrics as lost, explicitly.
        let mut receiver = reconciler();
        let received = receiver.receive(delivery).unwrap();
        assert_eq!(received.delivery, Some(DeliveryArrival::Fresh));
        assert_eq!(received.lost.len(), 1);
        assert_eq!(received.lost[0].key.stream, StreamKind::Metrics);
        assert_eq!(received.lost[0].reason, LossReason::MetricsDiscarded);
        assert_eq!(
            received.lost[0].range,
            SequenceRange::new(EventSequence::FIRST, EventSequence::new(10).unwrap()).unwrap()
        );
        assert!(receiver.gaps().is_empty());
        let totals = fanout.totals(subscriber).unwrap();
        assert_eq!((totals.metrics_shed, totals.taken), (10, 1));
    }

    #[test]
    fn whole_deliveries_are_shed_oldest_first_never_the_newest_and_a_snapshot_resyncs() {
        let mut plane = Plane::new();
        let mut fanout = DeliveryFanout::new();
        let subscriber = fanout.subscribe(config(2, 100, 4)).unwrap();
        for step in 1..=4 {
            plane.progress("a", step * 10);
            plane.progress("b", step * 10);
            fanout.publish(&plane.drain());
        }
        assert_eq!(fanout.held(subscriber).unwrap().deliveries, 2);
        let batch = fanout.take(subscriber, usize::MAX).unwrap();
        assert_eq!(
            batch.lag,
            Some(SubscriberLag {
                first: number(1),
                last: number(2),
                deliveries: 2
            })
        );
        let numbers: Vec<DeliveryNumber> = batch
            .deliveries
            .iter()
            .map(|delivery| delivery.number)
            .collect();
        assert_eq!(numbers, [number(3), number(4)]);
        let totals = fanout.totals(subscriber).unwrap();
        assert_eq!((totals.deliveries_shed, totals.progress_shed), (2, 4));

        // The receiver sees the shed deliveries missing and holds their gaps open, then
        // a reconnect snapshot accounts for them as lost and closes the gaps.
        let mut receiver = reconciler();
        let first = receiver.receive(&batch.deliveries[0]).unwrap();
        assert!(matches!(
            first.delivery,
            Some(DeliveryArrival::FreshAfterGap { .. })
        ));
        let _ = receiver.receive(&batch.deliveries[1]).unwrap();
        assert!(!receiver.gaps().is_empty());
        let resynced = receiver.resync(&plane.hub.progress_snapshot()).unwrap();
        assert_eq!(
            resynced.lost_deliveries,
            [DeliveryRange {
                epoch: ProducerIncarnation::FIRST,
                first: DeliverySequence::new(1).unwrap(),
                last: DeliverySequence::new(2).unwrap(),
            }]
        );
        assert!(receiver.gaps().is_empty());

        // The newest delivery stays whole, even beyond the bound on events.
        let tight = fanout.subscribe(config(4, 2, 4)).unwrap();
        for shard in ["a", "b", "c", "d", "e"] {
            plane.progress(shard, 90);
        }
        fanout.publish(&plane.drain());
        assert_eq!(fanout.held(tight).unwrap().events, 5);
        assert_eq!(fanout.totals(tight).unwrap().deliveries_shed, 0);
    }

    #[test]
    fn revocations_are_never_shed_and_ride_the_first_delivery_taken() {
        let mut plane = Plane::new();
        let mut fanout = DeliveryFanout::new();
        let subscriber = fanout.subscribe(config(1, 1, 3)).unwrap();
        for name in ["exe-1", "exe-2", "exe-3"] {
            plane.revoke(name);
            plane.metrics(5);
            plane.progress(name, 1);
            fanout.publish(&plane.drain());
        }
        // Only the newest delivery is held, and every revocation waits for it.
        let held = fanout.held(subscriber).unwrap();
        assert_eq!((held.deliveries, held.revocations), (1, 3));
        let batch = fanout.take(subscriber, usize::MAX).unwrap();
        assert_eq!(batch.deliveries.len(), 1);
        assert_eq!(batch.lag.map(|lag| lag.deliveries), Some(2));
        assert_eq!(
            executions(&batch.deliveries[0]),
            ["exe-1", "exe-2", "exe-3"]
        );
        let mut receiver = reconciler();
        let received = receiver.receive(&batch.deliveries[0]).unwrap();
        assert_eq!(received.revocations, [Arrival::Fresh; 3]);
        assert!(received
            .lost
            .iter()
            .all(|lost| lost.key.stream != StreamKind::Revocation));

        // Beyond the reserve, revocations widen to a revoke-all; none is dropped silently.
        for name in ["exe-4", "exe-5", "exe-6", "exe-7", "exe-8"] {
            plane.revoke(name);
            fanout.publish(&plane.drain());
        }
        let held = fanout.held(subscriber).unwrap();
        assert_eq!(held.revocations, 3);
        assert_eq!(held.revoke_all.map(|widened| widened.covered), Some(2));
        assert_eq!(fanout.totals(subscriber).unwrap().revocations_widened, 2);
        let batch = fanout.take(subscriber, usize::MAX).unwrap();
        let first = &batch.deliveries[0];
        assert!(first.revocations.revoke_all.is_some());
        assert_eq!(executions(first), ["exe-4", "exe-5", "exe-6"]);
        let totals = fanout.totals(subscriber).unwrap();
        assert_eq!(totals.revocations_taken, 6);
        assert_eq!(fanout.held(subscriber).unwrap().revoke_all, None);
    }

    #[test]
    fn subscribers_are_independent_and_publish_never_waits() {
        let mut plane = Plane::new();
        let mut fanout = DeliveryFanout::new();
        let slow = fanout.subscribe(config(1, 1, 1)).unwrap();
        let fast = fanout.subscribe(config(16, 1_000, 16)).unwrap();
        let mut taken_metrics = 0;
        for step in 0..50 {
            plane.metrics(20);
            plane.progress("a", step);
            fanout.publish(&plane.drain());
            for delivery in fanout.take(fast, usize::MAX).unwrap().deliveries {
                taken_metrics += delivery.metrics.events.len();
            }
            assert!(fanout.held(slow).unwrap().deliveries <= 1);
        }
        assert_eq!(fanout.published(), 50);
        assert_eq!(taken_metrics, 1_000);
        assert_eq!(fanout.totals(fast).unwrap().metrics_shed, 0);
        let slow_totals = fanout.totals(slow).unwrap();
        assert_eq!(slow_totals.metrics_shed, 1_000);
        assert_eq!(slow_totals.deliveries_shed, 49);
        assert_eq!(fanout.unsubscribe(slow), Ok(slow_totals));
        assert_eq!(
            fanout.take(slow, 1).err(),
            Some(FanoutError::UnknownSubscriber { subscriber: slow })
        );
        assert_eq!(fanout.subscribers(), 1);
    }

    #[test]
    fn configuration_is_checked() {
        let mut fanout = DeliveryFanout::new();
        assert_eq!(
            fanout.subscribe(config(0, 1, 1)),
            Err(FanoutError::Config(ConfigError::Zero {
                setting: "max_deliveries"
            }))
        );
        assert_eq!(
            fanout.subscribe(config(1, 1, 0)),
            Err(FanoutError::Config(ConfigError::Zero {
                setting: "revocation_reserve"
            }))
        );
        let first = fanout.subscribe(config(1, 1, 1)).unwrap();
        let second = fanout.subscribe(config(1, 1, 1)).unwrap();
        assert_ne!(first, second);
        assert_eq!(second.to_string(), "subscriber 1");
    }
}
