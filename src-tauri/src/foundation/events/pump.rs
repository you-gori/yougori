//! The one drain of the engine's shared event plane
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S2 CORE-06 "separate
//! retention/backpressure" and "metrics floods cannot suppress revocation"; S6 INT-10; GPU
//! part §3.10 "reconnect snapshot"; docs/combined-plan-leftover-tasks.md S06).
//!
//! The engine's producers share one [`EventHub`] behind a mutex: transfer progress
//! ([`EventProgress`]), model progress (the model-memory `ProgressPublisher`, through its
//! executor adapter), metrics, and the coordinator's revocation issuer. A [`DeliveryPump`]
//! is where their events leave it. Each [`DeliveryPump::pump`] drains one numbered delivery,
//! every pending revocation first, and gives it to every subscriber through its
//! [`DeliveryFanout`]. There each subscriber's own bounds shed what CORE-06 lets them shed,
//! metrics first and then whole deliveries of progress, every loss counted, and never a
//! revocation. The hub is locked only while draining, so no subscriber holds up a
//! producer, and nothing here touches storage: the durable revocation stream
//! ([`RevocationLog`]) and the audit journal are written by their owners when they publish.
//! A subscriber told it lagged resyncs from [`DeliveryPump::snapshot`].
//!
//! Every drained delivery is published, empty or not: its number is used, and a subscriber
//! that never saw a number counts the delivery lost. Pump when producers have emitted, or on
//! an interval.
//!
//! [`EventProgress`]: crate::foundation::transfer::EventProgress
//! [`RevocationLog`]: super::RevocationLog

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::envelope::{ConfigError, DeliveryNumber};
use super::fanout::{
    DeliveryFanout, FanoutError, SubscriberBatch, SubscriberConfig, SubscriberId, SubscriberTotals,
};
use super::hub::EventHub;
use super::progress::ProgressSnapshot;
use crate::foundation::ids::Clock;

/// Drains a shared [`EventHub`] into a [`DeliveryFanout`] (CORE-06; S06).
pub struct DeliveryPump<C> {
    hub: Arc<Mutex<EventHub<C>>>,
    fanout: DeliveryFanout,
    max_metrics: usize,
}

impl<C: Clock> DeliveryPump<C> {
    /// A pump draining `hub` with at most `max_metrics` metrics per delivery; the metrics
    /// stream keeps the rest, within its own bound, for the next delivery.
    pub fn new(hub: Arc<Mutex<EventHub<C>>>, max_metrics: usize) -> Result<Self, ConfigError> {
        if max_metrics == 0 {
            return Err(ConfigError::Zero {
                setting: "max_metrics",
            });
        }
        Ok(Self {
            hub,
            fanout: DeliveryFanout::new(),
            max_metrics,
        })
    }

    /// Adds a subscriber; it gets every delivery pumped from now on, and resyncs from
    /// [`DeliveryPump::snapshot`] for what came before.
    pub fn subscribe(&mut self, config: SubscriberConfig) -> Result<SubscriberId, FanoutError> {
        self.fanout.subscribe(config)
    }

    /// Removes a subscriber and what it held; returns its totals.
    pub fn unsubscribe(
        &mut self,
        subscriber: SubscriberId,
    ) -> Result<SubscriberTotals, FanoutError> {
        self.fanout.unsubscribe(subscriber)
    }

    /// Drains one delivery from the hub and gives it to every subscriber. It never waits on
    /// a subscriber and never refuses; returns the delivery's number.
    pub fn pump(&mut self) -> DeliveryNumber {
        let delivery = lock(&self.hub).drain(self.max_metrics);
        self.fanout.publish(&delivery);
        delivery.number
    }

    /// Up to `max_deliveries` of `subscriber`'s held deliveries, oldest first, the first
    /// carrying every pending revocation, and whether it lagged since it last took.
    pub fn take(
        &mut self,
        subscriber: SubscriberId,
        max_deliveries: usize,
    ) -> Result<SubscriberBatch, FanoutError> {
        self.fanout.take(subscriber, max_deliveries)
    }

    /// The hub's reconnect snapshot, with the last delivery pumped before it: what a
    /// subscriber that lagged or reconnected resyncs from (GPU part §3.10).
    pub fn snapshot(&self) -> ProgressSnapshot {
        lock(&self.hub).progress_snapshot()
    }

    /// The subscribers and what each holds and lost.
    pub fn fanout(&self) -> &DeliveryFanout {
        &self.fanout
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::time::Duration;

    use super::*;
    use crate::foundation::events::envelope::{DeliverySequence, Phase, ProducerIncarnation};
    use crate::foundation::events::fakes::{context, execution, manual_clock, producer, resource};
    use crate::foundation::events::hub::HubConfig;
    use crate::foundation::events::metrics::{MetricDraft, MetricValue, MetricsConfig};
    use crate::foundation::events::progress::{
        CancellationBoundary, ProgressConfig, ProgressUpdate, ResourceKind,
    };
    use crate::foundation::events::reconcile::{ReconcileConfig, Reconciler};
    use crate::foundation::events::redaction::RedactionPolicy;
    use crate::foundation::events::revocation::{Revocation, RevocationConfig, RevocationReason};
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::ids::{AuthorizationEpoch, ManualClock};

    type Hub = Arc<Mutex<EventHub<Arc<ManualClock>>>>;

    fn hub() -> Hub {
        Arc::new(Mutex::new(
            EventHub::new(
                manual_clock(),
                HubConfig {
                    metrics: MetricsConfig {
                        capacity_events: 256,
                        sample_above_events: 256,
                        keep_one_in: NonZeroU32::MIN,
                        retention: Duration::from_secs(600),
                        max_series: 4,
                    },
                    progress: ProgressConfig {
                        max_tracked: 8,
                        terminal_retention: Duration::from_secs(60),
                    },
                    revocation: RevocationConfig {
                        max_pending_executions: 8,
                    },
                    first_incarnation: ProducerIncarnation::FIRST,
                },
            )
            .unwrap(),
        ))
    }

    fn subscriber(max_deliveries: usize, max_events: usize) -> SubscriberConfig {
        SubscriberConfig {
            max_deliveries,
            max_events,
            revocation_reserve: 4,
        }
    }

    #[test]
    fn each_pump_drains_one_numbered_delivery_to_every_subscriber() {
        let shared = hub();
        let mut pump = DeliveryPump::new(Arc::clone(&shared), 4).unwrap();
        let slow = pump.subscribe(subscriber(1, 2)).unwrap();
        let fast = pump.subscribe(subscriber(64, 1_024)).unwrap();
        let (mut runner, mut loader, mut issuer) = {
            let mut hub = lock(&shared);
            (
                hub.register_metrics(
                    producer("runner"),
                    SourceClass::HostProbe,
                    RedactionPolicy::metadata_only(),
                    None,
                )
                .unwrap(),
                hub.register_progress(producer("loader"), SourceClass::HostProbe, None)
                    .unwrap(),
                hub.register_revocation_issuer(producer("coordinator"))
                    .unwrap(),
            )
        };
        for step in 1..=3u64 {
            let mut hub = lock(&shared);
            for bytes in 0..10 {
                hub.emit_metric(
                    &mut runner,
                    context("op-load", Phase::Loading),
                    MetricDraft::new("gpu.resident_bytes", MetricValue::GaugeBytes { bytes }),
                )
                .unwrap();
            }
            hub.emit_progress(
                &mut loader,
                context("op-load", Phase::Loading),
                ProgressUpdate::new(
                    resource("weights"),
                    ResourceKind::Weights,
                    step * 10,
                    Some(100),
                    step * 10,
                    CancellationBoundary::Anytime,
                ),
            )
            .unwrap();
            if step == 1 {
                hub.emit_revocation(
                    &mut issuer,
                    context("op-revoke", Phase::Revoked),
                    Revocation {
                        execution: execution("exe-1"),
                        epoch: AuthorizationEpoch::new(2),
                        reason: RevocationReason::UserRequested,
                    },
                )
                .unwrap();
            }
            drop(hub);
            let number = pump.pump();
            assert_eq!(number.sequence, DeliverySequence::new(step).unwrap());
        }
        assert_eq!(pump.fanout().published(), 3);

        // The fast subscriber gets everything, at most four metrics per delivery; the
        // rest wait in the metrics stream for later deliveries.
        let batch = pump.take(fast, usize::MAX).unwrap();
        assert_eq!(batch.lag, None);
        assert_eq!(batch.deliveries.len(), 3);
        assert_eq!(batch.deliveries[0].revocations.notices.len(), 1);
        assert!(batch
            .deliveries
            .iter()
            .all(|delivery| delivery.metrics.events.len() <= 4
                && delivery.progress.updates.len() == 1));

        // The slow one shed metrics and two whole deliveries, never the revocation, which
        // rides the first delivery it takes; it resyncs from the snapshot.
        let batch = pump.take(slow, usize::MAX).unwrap();
        assert_eq!(batch.lag.map(|lag| lag.deliveries), Some(2));
        assert_eq!(batch.deliveries.len(), 1);
        let delivery = &batch.deliveries[0];
        assert_eq!(delivery.revocations.notices.len(), 1);
        assert_eq!(
            delivery.revocations.notices[0].operation().as_str(),
            "op-revoke"
        );
        assert!(delivery.metrics.events.is_empty());
        let totals = pump.fanout().totals(slow).unwrap();
        assert_eq!((totals.deliveries_shed, totals.revocations_taken), (2, 1));
        let mut receiver = Reconciler::new(ReconcileConfig {
            max_streams: 8,
            window_sequences: 1 << 20,
            max_polls: 3,
            poll_interval: Duration::from_secs(1),
        })
        .unwrap();
        receiver.receive(delivery).unwrap();
        let snapshot = pump.snapshot();
        assert_eq!(snapshot.after.map(|after| after.sequence.get()), Some(3));
        assert_eq!(snapshot.states.len(), 1);
        assert_eq!(snapshot.states[0].payload().completed_bytes(), 30);
        let resynced = receiver.resync(&snapshot).unwrap();
        assert_eq!(resynced.lost_deliveries.len(), 1);
        assert!(receiver.gaps().is_empty());

        assert_eq!(pump.unsubscribe(slow), Ok(totals));
        assert_eq!(pump.fanout().subscribers(), 1);
    }

    #[test]
    fn a_pump_needs_room_for_metrics() {
        assert!(matches!(
            DeliveryPump::new(hub(), 0),
            Err(ConfigError::Zero {
                setting: "max_metrics"
            })
        ));
    }
}
