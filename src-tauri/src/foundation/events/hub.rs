//! The in-process event plane (CORE-06; INT-10). It registers producers, seals their
//! events after redaction, and keeps the metrics stream, the progress stream and the
//! revocation lane apart, each with its own bound. The audit journal is not part of it:
//! appending there needs the journal's own authority, which no handle issued here holds.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Weak};

use super::envelope::{
    ConfigError, DeliveryNumber, DeliverySequence, EmitError, EventContext, Phase, ProducerCore,
    ProducerId, ProducerIncarnation, StreamKey, StreamKind,
};
use super::metrics::{MetricDraft, MetricsAdmission, MetricsBatch, MetricsConfig, MetricsStream};
use super::progress::{
    ProgressAdmission, ProgressBatch, ProgressConfig, ProgressKey, ProgressRefusal,
    ProgressSnapshot, ProgressStream, ProgressUpdate,
};
use super::redaction::{EmissionLimit, RateLimiter, RedactionPolicy};
use super::revocation::{
    GrantRevocation, Revocation, RevocationAdmission, RevocationBatch, RevocationConfig,
    RevocationLane,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::Clock;

/// Bounds of the event plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HubConfig {
    pub metrics: MetricsConfig,
    pub progress: ProgressConfig,
    pub revocation: RevocationConfig,
    /// The incarnation each producer's first registration gets. After an engine restart,
    /// start above every incarnation issued before, so receivers never take new events
    /// for duplicates of old ones.
    pub first_incarnation: ProducerIncarnation,
}

impl HubConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.metrics.validate()?;
        self.progress.validate()?;
        self.revocation.validate()
    }
}

/// A registered metrics producer: the metrics sequence of one producer incarnation, its
/// fixed source class, its redaction policy and its optional emission limit.
#[derive(Debug)]
pub struct MetricsProducer {
    core: ProducerCore,
    policy: RedactionPolicy,
    limiter: Option<RateLimiter>,
}

impl MetricsProducer {
    pub fn key(&self) -> StreamKey {
        self.core.key()
    }
}

/// A registered progress producer.
#[derive(Debug)]
pub struct ProgressProducer {
    core: ProducerCore,
    limiter: Option<RateLimiter>,
}

impl ProgressProducer {
    pub fn key(&self) -> StreamKey {
        self.core.key()
    }
}

/// A registered issuer of revocations: always a host source and never rate limited. While
/// this handle exists nobody can register the issuer again; dropping it ends the
/// registration (VM part §8.2: never block the revocation channel).
#[derive(Debug)]
pub struct RevocationIssuer {
    core: ProducerCore,
    /// The hub counts the issuer as live while this exists.
    _live: Arc<()>,
}

impl RevocationIssuer {
    pub fn key(&self) -> StreamKey {
        self.core.key()
    }
}

/// Why a producer could not be registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HubError {
    /// The producer used its last incarnation on this stream.
    IncarnationExhausted {
        producer: ProducerId,
        stream: StreamKind,
    },
    /// A handle of this revocation issuer still exists. Registering the issuer again would
    /// retire that handle and refuse its revocations, so only dropping the handle ends the
    /// registration (VM part §8.2: never block the revocation channel).
    IssuerLive { producer: ProducerId },
}

impl fmt::Display for HubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncarnationExhausted { producer, stream } => write!(
                f,
                "{producer} used its last incarnation on the {stream} stream"
            ),
            Self::IssuerLive { producer } => write!(
                f,
                "{producer} is a live revocation issuer; only dropping its handle ends that registration"
            ),
        }
    }
}

impl std::error::Error for HubError {}

/// One delivery, in the order a receiver applies it; [`super::Reconciler::receive`]
/// applies it on the receiving side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    /// The delivery's number. A receiver that misses one cannot tell the lost delivery's
    /// events from superseded ones, so it applies no later resolved mark as a supersession
    /// until it accounts for the missing delivery.
    pub number: DeliveryNumber,
    /// Every pending revocation, never limited by the metrics bound.
    pub revocations: RevocationBatch,
    pub progress: ProgressBatch,
    pub metrics: MetricsBatch,
}

/// The in-process CORE-06 event plane.
#[derive(Debug)]
pub struct EventHub<C> {
    clock: C,
    first_incarnation: ProducerIncarnation,
    metrics: MetricsStream,
    progress: ProgressStream,
    revocations: RevocationLane,
    registrations: BTreeMap<(ProducerId, StreamKind), ProducerIncarnation>,
    /// Revocation issuers, live while their handle exists.
    issuers: BTreeMap<ProducerId, Weak<()>>,
    last_delivery: Option<DeliverySequence>,
}

impl<C: Clock> EventHub<C> {
    pub fn new(clock: C, config: HubConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            clock,
            first_incarnation: config.first_incarnation,
            metrics: MetricsStream::new(config.metrics)?,
            progress: ProgressStream::new(config.progress)?,
            revocations: RevocationLane::new(config.revocation)?,
            registrations: BTreeMap::new(),
            issuers: BTreeMap::new(),
            last_delivery: None,
        })
    }

    /// Registers `producer` on the metrics stream. Its source class is fixed here, so a
    /// guest-fed producer stays labelled a guest report (VM part §8.2). Registering the
    /// same producer again starts a new incarnation and retires the earlier handle.
    pub fn register_metrics(
        &mut self,
        producer: ProducerId,
        source: SourceClass,
        policy: RedactionPolicy,
        limit: Option<EmissionLimit>,
    ) -> Result<MetricsProducer, HubError> {
        let incarnation = self.register(&producer, StreamKind::Metrics)?;
        Ok(MetricsProducer {
            core: ProducerCore::new(producer, incarnation, StreamKind::Metrics, source),
            policy,
            limiter: limit.map(RateLimiter::new),
        })
    }

    /// Registers `producer` on the progress stream; see [`EventHub::register_metrics`].
    /// Progress carries only typed fields, so it has no text to redact.
    pub fn register_progress(
        &mut self,
        producer: ProducerId,
        source: SourceClass,
        limit: Option<EmissionLimit>,
    ) -> Result<ProgressProducer, HubError> {
        let incarnation = self.register(&producer, StreamKind::Progress)?;
        Ok(ProgressProducer {
            core: ProducerCore::new(producer, incarnation, StreamKind::Progress, source),
            limiter: limit.map(RateLimiter::new),
        })
    }

    /// Registers an issuer of revocations. A revocation is an authorization decision kept
    /// outside the guest, so its source is the host, and it has no emission limit: the
    /// revocation channel is never blocked (VM part §8.2). For the same reason a live
    /// issuer is not registered again, which would retire its handle: only dropping that
    /// handle ends the registration, and a new incarnation may then follow.
    pub fn register_revocation_issuer(
        &mut self,
        producer: ProducerId,
    ) -> Result<RevocationIssuer, HubError> {
        if self
            .issuers
            .get(&producer)
            .is_some_and(|live| live.strong_count() > 0)
        {
            return Err(HubError::IssuerLive { producer });
        }
        let incarnation = self.register(&producer, StreamKind::Revocation)?;
        let live = Arc::new(());
        self.issuers.insert(producer.clone(), Arc::downgrade(&live));
        Ok(RevocationIssuer {
            core: ProducerCore::new(
                producer,
                incarnation,
                StreamKind::Revocation,
                SourceClass::HostProbe,
            ),
            _live: live,
        })
    }

    /// Redacts, seals and offers one metric. Pressure never refuses or blocks the
    /// producer; it costs samples, and each one is counted.
    pub fn emit_metric(
        &mut self,
        producer: &mut MetricsProducer,
        context: EventContext,
        draft: MetricDraft,
    ) -> Result<MetricsAdmission, EmitError> {
        self.check_current(&producer.core)?;
        let now = self.clock.now();
        let sample = draft.redact(&producer.policy)?;
        if let Some(limiter) = producer.limiter.as_mut() {
            if limiter.admit(now).is_err() {
                self.metrics.count_rate_limited();
                return Ok(MetricsAdmission::RateLimited);
            }
        }
        let event = producer.core.seal(context, now, sample)?;
        Ok(self.metrics.offer(event))
    }

    /// Checks, seals and records one progress update. A refusal is backpressure on the
    /// producer and uses no sequence.
    pub fn emit_progress(
        &mut self,
        producer: &mut ProgressProducer,
        context: EventContext,
        update: ProgressUpdate,
    ) -> Result<ProgressAdmission, EmitError> {
        self.check_current(&producer.core)?;
        let now = self.clock.now();
        update
            .validate(context.phase)
            .map_err(|error| EmitError::Progress(ProgressRefusal::Invalid(error)))?;
        let key = ProgressKey::new(
            producer.core.producer().clone(),
            context.operation.clone(),
            update.resource(),
        );
        self.progress
            .admit(&key, producer.core.incarnation(), now)
            .map_err(EmitError::Progress)?;
        if let Some(limiter) = producer.limiter.as_mut() {
            limiter
                .admit(now)
                .map_err(|retry_after| EmitError::RateLimited {
                    producer: producer.core.producer().clone(),
                    retry_after,
                })?;
        }
        let event = producer.core.seal(context, now, update)?;
        self.progress
            .record(event, now)
            .map_err(EmitError::Progress)
    }

    /// Seals one revocation onto the priority lane. Nothing on the metrics or progress
    /// streams, and nothing in audit storage, can make this wait or fail.
    pub fn emit_revocation(
        &mut self,
        issuer: &mut RevocationIssuer,
        context: EventContext,
        revocation: Revocation,
    ) -> Result<RevocationAdmission, EmitError> {
        self.check_current(&issuer.core)?;
        if context.phase != Phase::Revoked {
            return Err(EmitError::WrongPhase {
                expected: Phase::Revoked,
                found: context.phase,
            });
        }
        let now = self.clock.now();
        let event = issuer.core.seal(context, now, revocation)?;
        Ok(self.revocations.push(event, now))
    }

    /// Seals the revocation of one grant onto the priority lane (CORE-04 per-grant
    /// revocation), as [`EventHub::emit_revocation`] seals a revocation: under the same
    /// issuer and phase, and nothing on the metrics or progress streams, and nothing in
    /// audit storage, can make it wait or fail.
    pub fn emit_grant_revocation(
        &mut self,
        issuer: &mut RevocationIssuer,
        context: EventContext,
        revocation: GrantRevocation,
    ) -> Result<RevocationAdmission, EmitError> {
        self.check_current(&issuer.core)?;
        if context.phase != Phase::Revoked {
            return Err(EmitError::WrongPhase {
                expected: Phase::Revoked,
                found: context.phase,
            });
        }
        let now = self.clock.now();
        let event = issuer.core.seal(context, now, revocation)?;
        Ok(self.revocations.push_grant(event, now))
    }

    /// The priority lane alone, for an in-process receiver that polls it more often than
    /// the rest. It takes no delivery number, and what it takes never appears in a numbered
    /// delivery, so a receiver across a link that can lose deliveries uses
    /// [`EventHub::drain`] only.
    pub fn drain_revocations(&mut self) -> RevocationBatch {
        self.revocations.drain()
    }

    /// One numbered delivery: every pending revocation first, then every changed progress
    /// state, then at most `max_metrics` metrics. Numbers rise by one per delivery within
    /// the hub's epoch; after `u64::MAX` deliveries, which no hub reaches, the last number
    /// repeats, and a receiver takes the repeat for a duplicate.
    pub fn drain(&mut self, max_metrics: usize) -> Delivery {
        let now = self.clock.now();
        let sequence = match self.last_delivery {
            None => DeliverySequence::FIRST,
            Some(last) => last.next().unwrap_or(last),
        };
        self.last_delivery = Some(sequence);
        Delivery {
            number: DeliveryNumber {
                epoch: self.first_incarnation,
                sequence,
            },
            revocations: self.revocations.drain(),
            progress: self.progress.drain_in(now, Some(sequence)),
            metrics: self.metrics.drain(now, max_metrics),
        }
    }

    /// What a reconnecting receiver starts from (GPU part §3.10 "reconnect snapshot"),
    /// with the last delivery made before it.
    pub fn progress_snapshot(&self) -> ProgressSnapshot {
        let mut snapshot = self.progress.snapshot();
        snapshot.after = self.last_delivery.map(|sequence| DeliveryNumber {
            epoch: self.first_incarnation,
            sequence,
        });
        snapshot
    }

    pub fn metrics(&self) -> &MetricsStream {
        &self.metrics
    }

    pub fn progress(&self) -> &ProgressStream {
        &self.progress
    }

    pub fn revocations(&self) -> &RevocationLane {
        &self.revocations
    }

    fn register(
        &mut self,
        producer: &ProducerId,
        stream: StreamKind,
    ) -> Result<ProducerIncarnation, HubError> {
        let slot = (producer.clone(), stream);
        let incarnation = match self.registrations.get(&slot) {
            None => self.first_incarnation,
            Some(current) => current
                .next()
                .ok_or_else(|| HubError::IncarnationExhausted {
                    producer: producer.clone(),
                    stream,
                })?,
        };
        self.registrations.insert(slot, incarnation);
        Ok(incarnation)
    }

    fn check_current(&self, core: &ProducerCore) -> Result<(), EmitError> {
        let slot = (core.producer().clone(), core.stream());
        if self.registrations.get(&slot) == Some(&core.incarnation()) {
            Ok(())
        } else {
            Err(EmitError::NotCurrent {
                producer: core.producer().clone(),
                stream: core.stream(),
                incarnation: core.incarnation(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::time::Duration;

    use super::*;
    use crate::foundation::events::envelope::EventSequence;
    use crate::foundation::events::fakes::{context, execution, manual_clock, producer, resource};
    use crate::foundation::events::metrics::MetricValue;
    use crate::foundation::events::progress::{CancellationBoundary, ResourceKind};
    use crate::foundation::events::revocation::RevocationReason;
    use crate::foundation::ids::AuthorizationEpoch;

    fn config() -> HubConfig {
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 8,
                sample_above_events: 8,
                keep_one_in: NonZeroU32::MIN,
                retention: Duration::from_secs(60),
                max_series: 4,
            },
            progress: ProgressConfig {
                max_tracked: 2,
                terminal_retention: Duration::from_secs(60),
            },
            revocation: RevocationConfig {
                max_pending_executions: 4,
            },
            first_incarnation: ProducerIncarnation::FIRST,
        }
    }

    fn metric(bytes: u64) -> MetricDraft {
        MetricDraft::new("gpu.resident_bytes", MetricValue::GaugeBytes { bytes })
    }

    fn update(name: &str) -> ProgressUpdate {
        ProgressUpdate::new(
            resource(name),
            ResourceKind::Weights,
            1,
            Some(2),
            1,
            CancellationBoundary::Anytime,
        )
    }

    fn revocation(epoch: u64) -> Revocation {
        Revocation {
            execution: execution("exe-1"),
            epoch: AuthorizationEpoch::new(epoch),
            reason: RevocationReason::PolicyChanged,
        }
    }

    #[test]
    fn a_retired_handle_cannot_emit_after_the_producer_registers_again() {
        let mut hub = EventHub::new(manual_clock(), config()).unwrap();
        let mut first = hub
            .register_metrics(
                producer("runner"),
                SourceClass::HostProbe,
                RedactionPolicy::default(),
                None,
            )
            .unwrap();
        hub.emit_metric(&mut first, context("op-1", Phase::Loading), metric(1))
            .unwrap();
        let mut second = hub
            .register_metrics(
                producer("runner"),
                SourceClass::HostProbe,
                RedactionPolicy::default(),
                None,
            )
            .unwrap();
        assert_eq!(second.key().incarnation.get(), 2);
        assert_eq!(
            hub.emit_metric(&mut first, context("op-1", Phase::Loading), metric(2)),
            Err(EmitError::NotCurrent {
                producer: producer("runner"),
                stream: StreamKind::Metrics,
                incarnation: ProducerIncarnation::FIRST
            })
        );
        hub.emit_metric(&mut second, context("op-1", Phase::Loading), metric(3))
            .unwrap();
        let delivered: Vec<(u64, u64)> = hub
            .drain(10)
            .metrics
            .events
            .iter()
            .map(|event| (event.key().incarnation.get(), event.sequence().get()))
            .collect();
        // The new incarnation restarts its sequence at 1.
        assert_eq!(delivered, [(1, 1), (2, 1)]);
    }

    #[test]
    fn incarnations_start_at_the_configured_floor() {
        let mut hub = EventHub::new(
            manual_clock(),
            HubConfig {
                first_incarnation: ProducerIncarnation::new(1_000).unwrap(),
                ..config()
            },
        )
        .unwrap();
        let issuer = hub
            .register_revocation_issuer(producer("coordinator"))
            .unwrap();
        assert_eq!(issuer.key().incarnation.get(), 1_000);
        let progress = hub
            .register_progress(producer("coordinator"), SourceClass::HostProbe, None)
            .unwrap();
        // Each stream has its own registrations and sequences.
        assert_eq!(progress.key().incarnation.get(), 1_000);
        assert_eq!(progress.key().stream, StreamKind::Progress);
    }

    #[test]
    fn a_revocation_must_be_in_the_revoked_phase() {
        let mut hub = EventHub::new(manual_clock(), config()).unwrap();
        let mut issuer = hub
            .register_revocation_issuer(producer("coordinator"))
            .unwrap();
        assert_eq!(
            hub.emit_revocation(&mut issuer, context("op-1", Phase::Running), revocation(2)),
            Err(EmitError::WrongPhase {
                expected: Phase::Revoked,
                found: Phase::Running
            })
        );
        assert_eq!(
            hub.emit_revocation(&mut issuer, context("op-1", Phase::Revoked), revocation(2)),
            Ok(RevocationAdmission::Queued)
        );
        let batch = hub.drain_revocations();
        // The refused attempt used no sequence.
        assert_eq!(batch.notices[0].sequence().get(), 1);
        assert_eq!(
            batch.notices[0].provenance().source(),
            SourceClass::HostProbe
        );
    }

    #[test]
    fn a_grant_revocation_takes_the_issuers_sequence_on_the_priority_lane() {
        let mut hub = EventHub::new(manual_clock(), config()).unwrap();
        let mut issuer = hub
            .register_revocation_issuer(producer("coordinator"))
            .unwrap();
        let grant = GrantRevocation {
            execution: execution("exe-1"),
            grant: crate::foundation::ids::GrantId::from_digest(crate::foundation::ids::digest(
                "yougori/test/grant/v1",
                &[b"route"],
            )),
            epoch: AuthorizationEpoch::new(2),
            reason: RevocationReason::SecurityEvent,
        };
        assert_eq!(
            hub.emit_grant_revocation(&mut issuer, context("op-1", Phase::Running), grant.clone()),
            Err(EmitError::WrongPhase {
                expected: Phase::Revoked,
                found: Phase::Running
            })
        );
        assert_eq!(
            hub.emit_revocation(&mut issuer, context("op-1", Phase::Revoked), revocation(2)),
            Ok(RevocationAdmission::Queued)
        );
        assert_eq!(
            hub.emit_grant_revocation(&mut issuer, context("op-1", Phase::Revoked), grant.clone()),
            Ok(RevocationAdmission::Queued)
        );
        let delivery = hub.drain(0);
        assert_eq!(delivery.revocations.notices[0].sequence().get(), 1);
        assert_eq!(delivery.revocations.grants.len(), 1);
        assert_eq!(delivery.revocations.grants[0].payload(), &grant);
        assert_eq!(delivery.revocations.grants[0].sequence().get(), 2);
        assert_eq!(
            delivery.revocations.grants[0].provenance().source(),
            SourceClass::HostProbe
        );
        assert_eq!(delivery.revocations.resolved[0].through.get(), 2);
    }

    #[test]
    fn deliveries_are_numbered_within_the_hub_epoch() {
        let epoch = ProducerIncarnation::new(7).unwrap();
        let mut hub = EventHub::new(
            manual_clock(),
            HubConfig {
                first_incarnation: epoch,
                ..config()
            },
        )
        .unwrap();
        assert_eq!(hub.progress_snapshot().after, None);
        let sequences: Vec<u64> = (0..3).map(|_| hub.drain(0).number.sequence.get()).collect();
        assert_eq!(sequences, [1, 2, 3]);
        // The in-process priority lane takes no number.
        let _ = hub.drain_revocations();
        let fourth = hub.drain(0).number;
        assert_eq!(
            fourth,
            DeliveryNumber {
                epoch,
                sequence: DeliverySequence::new(4).unwrap()
            }
        );
        assert_eq!(fourth.to_string(), "delivery 4 of epoch 7");
        assert_eq!(hub.progress_snapshot().after, Some(fourth));
        assert_eq!(
            serde_json::to_value(fourth).unwrap(),
            serde_json::json!({"epoch": 7, "sequence": 4})
        );
        assert_eq!(
            Delivery::default().number,
            DeliveryNumber {
                epoch: ProducerIncarnation::FIRST,
                sequence: DeliverySequence::FIRST
            }
        );
        assert_eq!(DeliverySequence::new(0), None);
        assert_eq!(DeliverySequence::new(u64::MAX).unwrap().next(), None);
    }

    #[test]
    fn a_live_revocation_issuer_is_not_registered_again() {
        let mut hub = EventHub::new(manual_clock(), config()).unwrap();
        let mut issuer = hub
            .register_revocation_issuer(producer("coordinator"))
            .unwrap();
        let refused = hub.register_revocation_issuer(producer("coordinator"));
        assert_eq!(
            refused.as_ref().err(),
            Some(&HubError::IssuerLive {
                producer: producer("coordinator")
            })
        );
        assert_eq!(
            refused.err().map(|error| error.to_string()).as_deref(),
            Some(
                "coordinator is a live revocation issuer; only dropping its handle ends that registration"
            )
        );
        // The issuer's other streams and other issuers are unaffected.
        hub.register_progress(producer("coordinator"), SourceClass::HostProbe, None)
            .unwrap();
        let warden = hub.register_revocation_issuer(producer("warden")).unwrap();
        assert_eq!(warden.key().incarnation, ProducerIncarnation::FIRST);
        assert_eq!(
            hub.emit_revocation(&mut issuer, context("op-1", Phase::Revoked), revocation(2)),
            Ok(RevocationAdmission::Queued)
        );
        // Dropping the handle ends the registration; the next incarnation follows it.
        drop(issuer);
        let mut renewed = hub
            .register_revocation_issuer(producer("coordinator"))
            .unwrap();
        assert_eq!(renewed.key().incarnation.get(), 2);
        assert_eq!(
            hub.emit_revocation(&mut renewed, context("op-1", Phase::Revoked), revocation(3)),
            Ok(RevocationAdmission::Raised)
        );
        let notices = hub.drain_revocations().notices;
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].key(), renewed.key());
        assert_eq!(notices[0].sequence(), EventSequence::FIRST);
    }

    #[test]
    fn rate_limited_metrics_are_counted_and_use_no_sequence() {
        let clock = manual_clock();
        let mut hub = EventHub::new(clock.clone(), config()).unwrap();
        let limit = EmissionLimit::new(2, Duration::from_secs(1)).unwrap();
        let mut guest = hub
            .register_metrics(
                producer("guest-agent"),
                SourceClass::GuestReport,
                RedactionPolicy::default(),
                Some(limit),
            )
            .unwrap();
        let admissions: Vec<MetricsAdmission> = (0..4)
            .map(|bytes| {
                hub.emit_metric(&mut guest, context("op-1", Phase::Running), metric(bytes))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            admissions,
            [
                MetricsAdmission::Queued,
                MetricsAdmission::Queued,
                MetricsAdmission::RateLimited,
                MetricsAdmission::RateLimited
            ]
        );
        clock.advance(Duration::from_secs(1));
        hub.emit_metric(&mut guest, context("op-1", Phase::Running), metric(9))
            .unwrap();
        let events = hub.drain(10).metrics.events;
        let sequences: Vec<u64> = events.iter().map(|event| event.sequence().get()).collect();
        assert_eq!(sequences, [1, 2, 3]);
        // A guest-fed producer stays labelled a guest report.
        assert!(events
            .iter()
            .all(|event| event.provenance().source() == SourceClass::GuestReport));
        assert_eq!(hub.metrics().totals().rate_limited, 2);
    }

    #[test]
    fn progress_refusals_are_backpressure_and_use_no_sequence() {
        let mut hub = EventHub::new(manual_clock(), config()).unwrap();
        let limit = EmissionLimit::new(3, Duration::from_secs(1)).unwrap();
        let mut loader = hub
            .register_progress(producer("loader"), SourceClass::HostProbe, Some(limit))
            .unwrap();
        hub.emit_progress(&mut loader, context("op-1", Phase::Loading), update("a"))
            .unwrap();
        hub.emit_progress(&mut loader, context("op-1", Phase::Loading), update("b"))
            .unwrap();
        assert_eq!(
            hub.emit_progress(&mut loader, context("op-1", Phase::Loading), update("c")),
            Err(EmitError::Progress(ProgressRefusal::TooManyTracked {
                limit: 2
            }))
        );
        assert!(matches!(
            hub.emit_progress(&mut loader, context("op-1", Phase::Queued), update("a")),
            Err(EmitError::Progress(ProgressRefusal::Invalid(_)))
        ));
        hub.emit_progress(&mut loader, context("op-1", Phase::Verifying), update("a"))
            .unwrap();
        assert!(matches!(
            hub.emit_progress(&mut loader, context("op-1", Phase::Verifying), update("b")),
            Err(EmitError::RateLimited { .. })
        ));
        let batch = hub.drain(0);
        let sequences: Vec<u64> = batch
            .progress
            .updates
            .iter()
            .map(|update| update.sequence().get())
            .collect();
        assert_eq!(sequences, [2, 3]);
        assert_eq!(batch.progress.resolved[0].through.get(), 3);
    }

    #[test]
    fn configuration_is_checked() {
        let broken = HubConfig {
            progress: ProgressConfig {
                max_tracked: 0,
                terminal_retention: Duration::ZERO,
            },
            ..config()
        };
        assert_eq!(
            EventHub::new(manual_clock(), broken).err(),
            Some(ConfigError::Zero {
                setting: "max_tracked"
            })
        );
    }
}
