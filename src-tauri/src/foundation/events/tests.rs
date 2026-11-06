//! CORE-06 flows across the streams, on fakes driven by a manual clock: the INT-10 flood,
//! revocation priority, separate append authority, redaction end to end, reconnect,
//! numbered deliveries over a lossy link, explicit loss of relayed audit events and a
//! multi-day soak.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use super::fakes::{
    context, execution, journal_id, manual_clock, producer, resource, FakeAuditSpool,
    FakeAuditStore, SplitMix64,
};
use super::*;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{AuthorizationEpoch, Clock, ManualClock, MonotonicTime};

type Hub = EventHub<Arc<ManualClock>>;

/// Whether `$type` satisfies the bound, decided by the compiler: the inherent constant
/// exists only when the bound holds, otherwise lookup falls back to the trait's `false`.
macro_rules! implements {
    ($type:ty: $($bound:tt)+) => {{
        #[allow(dead_code)]
        trait Fallback {
            const YES: bool = false;
        }
        impl<T: ?Sized> Fallback for T {}
        #[allow(dead_code)]
        struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + $($bound)+> Probe<T> {
            const YES: bool = true;
        }
        <Probe<$type>>::YES
    }};
}

fn hub_config(capacity_events: usize, sample_above_events: usize, keep_one_in: u32) -> HubConfig {
    HubConfig {
        metrics: MetricsConfig {
            capacity_events,
            sample_above_events,
            keep_one_in: NonZeroU32::new(keep_one_in).unwrap(),
            retention: Duration::from_secs(60),
            max_series: 16,
        },
        progress: ProgressConfig {
            max_tracked: 64,
            terminal_retention: Duration::from_secs(60),
        },
        revocation: RevocationConfig {
            max_pending_executions: 16,
        },
        first_incarnation: ProducerIncarnation::FIRST,
    }
}

fn audit_config(spool_records: usize, revocation_reserve_records: usize) -> AuditConfig {
    AuditConfig {
        spool_records,
        revocation_reserve_records,
        failure_policy: AuditFailurePolicy::SpoolHighImpact,
        guest_observations: EmissionLimit::new(10, Duration::from_secs(1)).unwrap(),
        redaction: RedactionPolicy::metadata_only(),
    }
}

fn reconcile_config() -> ReconcileConfig {
    ReconcileConfig {
        max_streams: 16,
        window_sequences: 10_000_000,
        max_polls: 3,
        poll_interval: Duration::from_secs(1),
    }
}

fn gauge(name: &'static str, bytes: u64) -> MetricDraft {
    MetricDraft::new(name, MetricValue::GaugeBytes { bytes })
}

fn weights(name: &str, completed_bytes: u64, total_bytes: u64) -> ProgressUpdate {
    ProgressUpdate::new(
        resource(name),
        ResourceKind::Weights,
        completed_bytes,
        Some(total_bytes),
        completed_bytes,
        CancellationBoundary::Anytime,
    )
}

fn revocation(name: &str, epoch: u64) -> Revocation {
    Revocation {
        execution: execution(name),
        epoch: AuthorizationEpoch::new(epoch),
        reason: RevocationReason::SecurityEvent,
    }
}

/// Applies one delivery over a link that loses nothing, and returns the losses it made
/// explicit. Every delivery is the next one, and no delivered event is a duplicate.
fn receive(receiver: &mut Reconciler, delivery: &Delivery) -> Vec<LostRange> {
    let received = receiver.receive(delivery).unwrap();
    assert_eq!(received.delivery, Some(DeliveryArrival::Fresh));
    assert!(received
        .revocations
        .iter()
        .chain(&received.progress)
        .chain(&received.metrics)
        .all(|arrival| arrival.is_new()));
    assert!(received.lost_deliveries.is_empty());
    received.lost
}

/// One delivery number of the first hub epoch.
fn delivery(sequence: u64) -> DeliveryNumber {
    DeliveryNumber {
        epoch: ProducerIncarnation::FIRST,
        sequence: DeliverySequence::new(sequence).unwrap(),
    }
}

/// Deliveries `first` to `last` of the first hub epoch.
fn deliveries(first: u64, last: u64) -> DeliveryRange {
    DeliveryRange {
        epoch: ProducerIncarnation::FIRST,
        first: DeliverySequence::new(first).unwrap(),
        last: DeliverySequence::new(last).unwrap(),
    }
}

fn sequences(first: u64, last: u64) -> SequenceRange {
    SequenceRange::new(
        EventSequence::new(first).unwrap(),
        EventSequence::new(last).unwrap(),
    )
    .unwrap()
}

/// `operation` loading weights, `completed_bytes` of 100.
fn load(hub: &mut Hub, loader: &mut ProgressProducer, operation: &str, completed_bytes: u64) {
    hub.emit_progress(
        loader,
        context(operation, Phase::Loading),
        weights(operation, completed_bytes, 100),
    )
    .unwrap();
}

/// INT-10: a metrics flood and busy progress while audit storage is slow, then full.
/// Audit keeps its order and fails closed visibly, the revocation goes through first,
/// and every lost metric is counted and reconciled.
#[test]
fn int10_flood_keeps_audit_order_delivers_revocation_and_counts_metric_loss() {
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(4_096, 3_072, 8)).unwrap();
    let mut runners: Vec<MetricsProducer> = (0..4)
        .map(|index| {
            hub.register_metrics(
                producer(&format!("runner-{index}")),
                SourceClass::HostProbe,
                RedactionPolicy::metadata_only(),
                None,
            )
            .unwrap()
        })
        .collect();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let mut coordinator = hub
        .register_revocation_issuer(producer("coordinator"))
        .unwrap();
    let store = FakeAuditStore::new(usize::MAX);
    let device = store.control();
    device.slow_for(6);
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        store,
        FakeAuditSpool::new(),
        clock.clone(),
        audit_config(16, 4),
    )
    .unwrap();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    let mut rng = SplitMix64::new(0x0123_4567_89AB_CDEF);
    let revoked = revocation("exe-1", 2);
    let steps = 120_000u64;
    let mut accepted = Vec::new();
    let mut refused = 0;

    for step in 0..steps {
        clock.advance(Duration::from_micros(50));
        let runner = &mut runners[usize::try_from(rng.below(4)).unwrap()];
        hub.emit_metric(
            runner,
            context("op-load", Phase::Loading),
            gauge("gpu.resident_bytes", step),
        )
        .unwrap();
        // High-volume GPU progress: four weight shards, one update every ten steps.
        if step % 10 == 0 {
            let shard = format!("weights-{}", (step / 10) % 4);
            hub.emit_progress(
                &mut loader,
                context("op-load", Phase::Loading),
                weights(&shard, step, steps).from_source(DataSource::LocalStorage),
            )
            .unwrap();
        }
        // Audit storage is slow at first, full from step 40,000, and back at 100,000.
        if step == 40_000 {
            device.set_capacity(journal.store().records().len());
        }
        if step == 100_000 {
            device.set_capacity(usize::MAX);
        }
        if step % 4_000 == 0 {
            match journal.admit_high_impact(
                &mut authority,
                context("op-load", Phase::Loading),
                vec![Field::metadata("step", step)],
            ) {
                Ok(receipt) => accepted.push(receipt.sequence.get()),
                Err(AuditRefusal::FailClosed { .. }) => refused += 1,
                Err(other) => panic!("unexpected refusal: {other}"),
            }
        }
        if step == 90_000 {
            let backlog = hub.metrics().buffered();
            assert!(backlog > 1_000, "the metrics backlog is only {backlog}");
            assert_eq!(
                hub.emit_revocation(
                    &mut coordinator,
                    context("op-load", Phase::Revoked),
                    revoked.clone()
                ),
                Ok(RevocationAdmission::Queued)
            );
            // The next delivery carries it, however small its share of metrics.
            let delivery = hub.drain(16);
            assert_eq!(delivery.revocations.notices.len(), 1);
            assert_eq!(delivery.revocations.notices[0].payload(), &revoked);
            receive(&mut receiver, &delivery);
            // Ordinary audit records fail closed now; the revocation's own record fits in
            // the reserve.
            assert!(matches!(
                journal.health(),
                AuditHealth::FailClosed {
                    store: StoreRefusal::Full,
                    ..
                }
            ));
            let receipt = journal
                .append(
                    &mut authority,
                    context("op-load", Phase::Revoked),
                    AuditDraft::Revocation(revoked.clone()),
                )
                .unwrap();
            assert!(matches!(receipt.durability, Durability::Spooled { .. }));
            accepted.push(receipt.sequence.get());
        }
        // The receiver stalls for a while, so the metrics buffer fills up.
        let receiver_stalled = (40_000..60_000).contains(&step);
        if step % 2_000 == 1_999 && !receiver_stalled {
            receive(&mut receiver, &hub.drain(512));
        }
    }
    receive(&mut receiver, &hub.drain(usize::MAX));

    // Audit: every accepted record is stored once, in order; the refusals were visible.
    assert_eq!(accepted, (1..=28).collect::<Vec<u64>>());
    assert_eq!(refused, 3);
    let head = verify_chain(
        &JournalHead::genesis(journal_id("engine"), producer("engine.audit")),
        journal.store().records(),
    )
    .unwrap();
    assert_eq!(head.last.map(EventSequence::get), Some(28));
    assert_eq!(journal.health(), AuditHealth::Durable);
    assert_eq!(journal.store().out_of_order_attempts(), 0);
    let revocations: Vec<u64> = journal
        .store()
        .records()
        .iter()
        .filter(|record| matches!(record.event().payload(), AuditEntry::Revocation { .. }))
        .map(|record| record.sequence().get())
        .collect();
    assert_eq!(revocations, [23]);

    // Metrics: everything taken was delivered or counted lost, and the receiver marked
    // exactly those lost.
    let totals = hub.metrics().totals();
    assert_eq!(totals.offered, steps);
    assert!(
        totals.sampled_out > 0 && totals.dropped_oldest > 0,
        "{totals:?}"
    );
    assert_eq!(totals.offered, totals.delivered + totals.lost());
    assert_eq!(hub.metrics().buffered(), 0);
    assert_eq!(receiver.totals().lost, totals.lost());
    assert!(receiver.gaps().is_empty());

    // Progress coalesced into far fewer deliveries, one slot per shard, ending at each
    // shard's latest state.
    let progress = hub.progress().totals();
    assert_eq!(progress.applied, steps / 10);
    assert!(progress.coalesced > 0);
    assert!(progress.delivered < steps / 100);
    assert_eq!(hub.progress().tracked(), 4);
    let latest: Vec<u64> = hub
        .progress_snapshot()
        .states
        .iter()
        .map(|state| state.payload().completed_bytes())
        .collect();
    assert_eq!(latest, [119_960, 119_970, 119_980, 119_990]);
    assert_eq!(hub.revocations().totals().delivered, 1);
}

#[test]
fn revocation_is_delivered_before_any_backlog_and_never_refused() {
    let mut hub = EventHub::new(
        manual_clock(),
        HubConfig {
            progress: ProgressConfig {
                max_tracked: 2,
                terminal_retention: Duration::from_secs(60),
            },
            ..hub_config(64, 64, 1)
        },
    )
    .unwrap();
    let mut runner = hub
        .register_metrics(
            producer("runner"),
            SourceClass::HostProbe,
            RedactionPolicy::metadata_only(),
            None,
        )
        .unwrap();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let mut coordinator = hub
        .register_revocation_issuer(producer("coordinator"))
        .unwrap();
    for bytes in 0..1_000 {
        hub.emit_metric(
            &mut runner,
            context("op-1", Phase::Loading),
            gauge("gpu.bytes", bytes),
        )
        .unwrap();
    }
    for name in ["a", "b"] {
        let update = ProgressUpdate::new(
            resource(name),
            ResourceKind::Adapter,
            1,
            Some(2),
            1,
            CancellationBoundary::Anytime,
        );
        hub.emit_progress(&mut loader, context("op-1", Phase::Loading), update)
            .unwrap();
    }
    let refused = ProgressUpdate::new(
        resource("c"),
        ResourceKind::Adapter,
        1,
        Some(2),
        1,
        CancellationBoundary::Anytime,
    );
    assert!(matches!(
        hub.emit_progress(&mut loader, context("op-1", Phase::Loading), refused),
        Err(EmitError::Progress(ProgressRefusal::TooManyTracked { .. }))
    ));
    assert_eq!(hub.metrics().buffered(), 64);

    // Both streams are saturated; the revocation is neither refused nor delayed.
    assert_eq!(
        hub.emit_revocation(
            &mut coordinator,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 3)
        ),
        Ok(RevocationAdmission::Queued)
    );
    let delivery = hub.drain(0);
    assert_eq!(delivery.revocations.notices.len(), 1);
    assert!(delivery.metrics.events.is_empty());
    assert_eq!(hub.metrics().buffered(), 64);
    // The lane can also be polled on its own.
    hub.emit_revocation(
        &mut coordinator,
        context("op-1", Phase::Revoked),
        revocation("exe-2", 2),
    )
    .unwrap();
    assert_eq!(hub.drain_revocations().notices.len(), 1);
}

#[test]
fn a_metrics_producer_cannot_append_to_audit() {
    // The journal's only append path takes `&mut AuditAppendAuthority`. No producer
    // handle converts into one or lends one ...
    assert!(!implements!(MetricsProducer: Into<AuditAppendAuthority>));
    assert!(!implements!(MetricsProducer: std::borrow::BorrowMut<AuditAppendAuthority>));
    assert!(!implements!(MetricsProducer: AsMut<AuditAppendAuthority>));
    assert!(!implements!(MetricsProducer: std::ops::DerefMut<Target = AuditAppendAuthority>));
    assert!(!implements!(ProgressProducer: std::borrow::BorrowMut<AuditAppendAuthority>));
    assert!(!implements!(RevocationIssuer: std::borrow::BorrowMut<AuditAppendAuthority>));
    // ... and the authority cannot be copied, made up or read back from JSON.
    assert!(!implements!(AuditAppendAuthority: Clone));
    assert!(!implements!(AuditAppendAuthority: Default));
    assert!(!implements!(AuditAppendAuthority: serde::de::DeserializeOwned));
    // The probe does see a capability where one exists.
    assert!(implements!(AuditAppendAuthority: std::borrow::BorrowMut<AuditAppendAuthority>));
    assert!(implements!(MetricsProducer: std::fmt::Debug));

    // At run time a metrics producer shares the envelope, even the owner's name, but not
    // the authority, and an authority of another journal is refused.
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut runner = hub
        .register_metrics(
            producer("engine.audit"),
            SourceClass::HostProbe,
            RedactionPolicy::metadata_only(),
            None,
        )
        .unwrap();
    hub.emit_metric(
        &mut runner,
        context("op-1", Phase::Running),
        gauge("gpu.bytes", 1),
    )
    .unwrap();
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(10),
        FakeAuditSpool::new(),
        clock.clone(),
        audit_config(4, 1),
    )
    .unwrap();
    let (_warden, mut warden_authority) = AuditJournal::open(
        journal_id("warden"),
        producer("engine.audit"),
        FakeAuditStore::new(10),
        FakeAuditSpool::new(),
        clock.clone(),
        audit_config(4, 1),
    )
    .unwrap();
    let fact = AuditDraft::HostFact {
        fact: HostFact::Lease,
        fields: vec![],
    };
    assert!(matches!(
        journal.append(
            &mut warden_authority,
            context("op-1", Phase::Running),
            fact.clone()
        ),
        Err(AuditRefusal::WrongJournal { .. })
    ));
    let receipt = journal
        .append(&mut authority, context("op-1", Phase::Running), fact)
        .unwrap();
    assert_eq!(receipt.durability, Durability::Durable);

    fn sequence_space<P>(event: &EventEnvelope<P>) -> StreamKey {
        event.key()
    }
    let metric = hub.drain(10).metrics.events.remove(0);
    let record = journal.store().records()[0].event().clone();
    assert_eq!(sequence_space(&metric).stream, StreamKind::Metrics);
    assert_eq!(sequence_space(&record).stream, StreamKind::Audit);
    assert_eq!(journal.store().records().len(), 1);
}

/// Whoever held the journal could borrow its storage mutably and store a record that never
/// passed the append authority (VM part §16.3). The journal lends its storage to nobody:
/// outside its module, `store_mut` finds only the fallback below.
#[test]
fn holding_the_journal_gives_no_way_around_its_append_authority() {
    struct NotLent;
    trait Fallback {
        fn store_mut(&mut self) -> NotLent {
            NotLent
        }
    }
    impl<T> Fallback for T {}
    trait Lends {
        const LENDS: bool;
    }
    impl Lends for NotLent {
        const LENDS: bool = false;
    }
    impl<T> Lends for &mut T {
        const LENDS: bool = true;
    }
    fn lends<T: Lends>(_: &T) -> bool {
        T::LENDS
    }

    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(10),
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    let fact = AuditDraft::HostFact {
        fact: HostFact::Lease,
        fields: vec![],
    };
    let _ = journal
        .append(&mut authority, context("op-1", Phase::Running), fact)
        .unwrap();
    assert!(!lends(&journal.store_mut()));
    assert_eq!(journal.store().records().len(), 1);
}

/// Storage stores a high-impact record yet reports slow, and the deny policy needs a
/// durable record, so the operation is denied (VM part §8.2). The refused record keeps its
/// sequence: the journal offers exactly it again before anything else and never different
/// content under it, so storage does not refuse the journal for good, and it resumes.
#[test]
fn an_unclear_refusal_on_the_fail_closed_path_never_wedges_the_journal() {
    let config = AuditConfig {
        failure_policy: AuditFailurePolicy::DenyHighImpact,
        ..audit_config(4, 1)
    };
    let store = FakeAuditStore::new(100);
    let device = store.control();
    let spool = FakeAuditSpool::new();
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        store,
        spool.clone(),
        manual_clock(),
        config,
    )
    .unwrap();
    let lease = |step: u64| AuditDraft::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    };
    let first = journal
        .append(&mut authority, context("op-1", Phase::Running), lease(1))
        .unwrap();
    assert_eq!(first.durability, Durability::Durable);

    device.store_but_report_slow_once();
    let denied = journal.admit_high_impact(
        &mut authority,
        context("op-2", Phase::Requested),
        vec![Field::metadata("action", "reset_device")],
    );
    assert!(matches!(denied, Err(AuditRefusal::FailClosed { .. })));
    // Storage holds the denied record anyway.
    let denied_record = journal.store().records()[1].clone();
    assert!(matches!(
        denied_record.event().payload(),
        AuditEntry::HostFact {
            fact: HostFact::HighImpactOperation,
            ..
        }
    ));

    // The next records follow that record; nothing else is ever offered as record 2.
    for step in 3..8u64 {
        let receipt = journal
            .append(&mut authority, context("op-3", Phase::Running), lease(step))
            .unwrap();
        assert_eq!(receipt.sequence.get(), step);
        assert_eq!(receipt.durability, Durability::Durable);
    }
    assert_eq!(journal.store().out_of_order_attempts(), 0);
    assert_eq!(journal.health(), AuditHealth::Durable);
    assert!(spool.snapshot().is_empty());
    let stored = journal.store().records().to_vec();
    assert_eq!(stored[1], denied_record);
    let head = verify_chain(
        &JournalHead::genesis(journal_id("engine"), producer("engine.audit")),
        &stored,
    )
    .unwrap();
    assert_eq!(head, journal.head());

    // After a restart the journal resumes after the stored head.
    drop(journal);
    let (mut resumed, mut resumed_authority) = AuditJournal::resume(
        head,
        FakeAuditStore::holding(stored, 100),
        spool,
        manual_clock(),
        config,
    )
    .unwrap();
    let next = resumed
        .append(
            &mut resumed_authority,
            context("op-3", Phase::Running),
            lease(8),
        )
        .unwrap();
    assert_eq!(next.sequence.get(), 8);
    assert_eq!(next.durability, Durability::Durable);
}

/// Another holder of the hub registering the coordinator's name again would retire the
/// coordinator's handle and refuse its revocations (VM part §8.2: never block the
/// revocation channel). A live issuer keeps its registration.
#[test]
fn a_live_revocation_issuer_cannot_be_displaced() {
    let mut hub = EventHub::new(manual_clock(), hub_config(16, 16, 1)).unwrap();
    let mut coordinator = hub
        .register_revocation_issuer(producer("coordinator"))
        .unwrap();
    let shadow = hub.register_revocation_issuer(producer("coordinator"));
    assert!(shadow.is_err());
    assert_eq!(
        hub.emit_revocation(
            &mut coordinator,
            context("op-1", Phase::Revoked),
            revocation("exe-1", 2)
        ),
        Ok(RevocationAdmission::Queued)
    );
    let delivered = hub.drain_revocations();
    assert_eq!(delivered.notices.len(), 1);
    assert_eq!(delivered.notices[0].key(), coordinator.key());
}

#[test]
fn redaction_is_applied_before_events_leave_their_producers() {
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut runner = hub
        .register_metrics(
            producer("runner"),
            SourceClass::HostProbe,
            RedactionPolicy::metadata_only(),
            None,
        )
        .unwrap();
    let draft = MetricDraft::new(
        "model.load_duration",
        MetricValue::DurationNanoseconds { nanoseconds: 5 },
    )
    .with_label(Field::metadata("loader", "safetensors"))
    .with_label(Field::new(
        "model_path",
        FieldClass::PrivatePath,
        "C:\\Users\\alice\\llama.safetensors",
    ))
    .with_label(Field::new(
        "hf_token",
        FieldClass::Credential,
        "hf_abcdefghijklmnopqrstuvwxyz",
    ))
    .with_label(Field::new(
        "prompt",
        FieldClass::Prompt,
        "my bank password is hunter2",
    ))
    .with_label(Field::untrusted("guest_log", "Authorization: Bearer abc"));
    hub.emit_metric(&mut runner, context("op-1", Phase::Loading), draft)
        .unwrap();
    let event = hub.drain(10).metrics.events.remove(0);
    let json = serde_json::to_string(&event).unwrap();
    for secret in ["alice", "llama", "hf_abcdef", "hunter2", "Bearer"] {
        assert!(!json.contains(secret), "{secret} leaked into {json}");
    }
    let labels = event.payload().labels();
    assert_eq!(
        labels.get("loader"),
        Some(&RedactedValue::Text {
            text: "safetensors".to_owned(),
            full_bytes: 11
        })
    );
    assert_eq!(
        labels.get("model_path"),
        Some(&RedactedValue::Removed {
            class: FieldClass::PrivatePath
        })
    );
    assert_eq!(
        labels.get("guest_log"),
        Some(&RedactedValue::Withheld { bytes: 25 })
    );

    // The journal redacts with its own policy before a record is chained.
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(10),
        FakeAuditSpool::new(),
        clock,
        audit_config(4, 1),
    )
    .unwrap();
    let _ = journal
        .append(
            &mut authority,
            context("op-1", Phase::Running),
            AuditDraft::HostFact {
                fact: HostFact::AuthorizationDecision,
                fields: vec![
                    Field::new("header", FieldClass::AuthorizationHeader, "Bearer xyz"),
                    Field::metadata("decision", "granted"),
                ],
            },
        )
        .unwrap();
    let record = serde_json::to_string(&journal.store().records()[0]).unwrap();
    assert!(!record.contains("xyz") && !record.contains("Bearer"));
    assert!(record.contains("granted"));
}

#[test]
fn kept_untrusted_text_drops_what_the_shared_classification_marks_hazardous() {
    // VM part §8.2 line 2371 ("bound attacker-controlled log fields"), decided by
    // foundation::text, the classification guest display uses.
    let policy = RedactionPolicy::metadata_only().keeping_untrusted_text();
    let kept = |line: &str| match policy
        .redact(vec![Field::untrusted("line", line)])
        .unwrap()
        .get("line")
    {
        Some(RedactedValue::Text { text, .. }) => text.clone(),
        other => panic!("expected kept text, found {other:?}"),
    };
    // Controls, bidirectional and zero-width characters go, as before.
    assert_eq!(kept("a\u{1b}\u{9b}\u{202E}\u{2066}\u{200B}\u{FEFF}b"), "ab");
    // And now every other hazard of the shared classification: private-use, tag and
    // variation-selector characters, a Hangul filler, a combining grapheme joiner and an
    // unassigned code point.
    assert_eq!(
        kept("ab\u{E000}\u{E0041}\u{FE0F}\u{3164}\u{034F}\u{0378}cd"),
        "abcd"
    );
    // The line policy is unchanged: line breaks, tabs and other spacing still separate
    // tokens, so a dropped character cannot join a keyword to the secret after it, and a
    // control line break still goes.
    assert_eq!(kept("Bearer\u{00A0}abc123"), "Bearer [redacted]");
    assert_eq!(kept("one\u{2028}two\tthree\r\nfour"), "one two three four");
    assert_eq!(kept("a\u{0B}b"), "ab");
}

#[test]
fn a_reconnecting_receiver_starts_from_the_snapshot() {
    let mut hub = EventHub::new(manual_clock(), hub_config(16, 16, 1)).unwrap();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    for step in 1..=50u64 {
        hub.emit_progress(
            &mut loader,
            context("op-1", Phase::Loading),
            weights("weights", step, 100),
        )
        .unwrap();
    }
    // A receiver that was away takes the snapshot instead of a replay.
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    let snapshot = hub.progress_snapshot();
    assert_eq!(snapshot.states.len(), 1);
    for state in &snapshot.states {
        receiver.observe_event(state).unwrap();
    }
    for resolved in &snapshot.resolved {
        receiver
            .resolve_through(resolved, Resolution::Superseded)
            .unwrap();
    }
    assert!(receiver.gaps().is_empty());
    assert_eq!(receiver.totals().superseded, 49);
    assert_eq!(receiver.totals().lost, 0);
    // The same state delivered again is not applied twice; the next one is fresh.
    let again = hub.drain(0);
    assert_eq!(
        receiver
            .observe_event(&again.progress.updates[0])
            .unwrap()
            .arrival,
        Arrival::Duplicate
    );
    hub.emit_progress(
        &mut loader,
        context("op-1", Phase::Loading),
        weights("weights", 51, 100),
    )
    .unwrap();
    let next = hub.drain(0);
    assert_eq!(
        receiver
            .observe_event(&next.progress.updates[0])
            .unwrap()
            .arrival,
        Arrival::Fresh
    );
}

#[test]
fn relayed_audit_gaps_are_recovered_or_recorded_as_lost() {
    let (mut warden, mut warden_authority) = AuditJournal::open(
        journal_id("warden"),
        producer("warden"),
        FakeAuditStore::new(100),
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 0..6u64 {
        let _ = warden
            .append(
                &mut warden_authority,
                context("op-1", Phase::Running),
                AuditDraft::HostFact {
                    fact: HostFact::Lease,
                    fields: vec![Field::metadata("step", step)],
                },
            )
            .unwrap();
    }
    let records = warden.store().records().to_vec();
    // Relayed to the engine, records 3 and 5 go missing on the way.
    let clock = manual_clock();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    for index in [0, 1, 3, 5] {
        receiver.observe_event(records[index].event()).unwrap();
    }
    let polling = receiver.poll(clock.now());
    assert_eq!(polling.requests.len(), 1);
    let missing = polling.requests[0].missing.clone();
    assert_eq!(
        missing,
        [
            SequenceRange::single(EventSequence::new(3).unwrap()),
            SequenceRange::single(EventSequence::new(5).unwrap())
        ]
    );
    // A poll recovers record 3 from the warden's store.
    let replay = &records[2];
    assert_eq!(
        receiver.observe_event(replay.event()).unwrap().arrival,
        Arrival::Recovered
    );
    // Record 5 never comes back; after the bounded polls it is marked lost, and the
    // engine records the loss in its own journal rather than skipping it.
    let mut lost = Vec::new();
    for _ in 0..4 {
        clock.advance(Duration::from_secs(1));
        lost.extend(receiver.poll(clock.now()).lost);
    }
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].reason, LossReason::RecoveryExhausted);
    assert_eq!(
        lost[0].range,
        SequenceRange::single(EventSequence::new(5).unwrap())
    );
    assert!(receiver.gaps().is_empty());
    let (mut engine, mut engine_authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(100),
        FakeAuditSpool::new(),
        clock.clone(),
        audit_config(4, 1),
    )
    .unwrap();
    let receipt = engine
        .append(
            &mut engine_authority,
            context("op-1", Phase::Running),
            AuditDraft::EventsLost(lost[0].clone()),
        )
        .unwrap();
    assert_eq!(receipt.sequence, EventSequence::FIRST);
    assert_eq!(
        engine.store().records()[0].event().payload(),
        &AuditEntry::EventsLost {
            lost: lost[0].clone()
        }
    );
}

/// S7 long-run stability: three days of one sample every 30 s, with a receiver that
/// goes away for two hours and a producer that restarts while it is away. The buffer
/// stays bounded, every loss is counted and reconciled, including the restarted
/// incarnation's undelivered tail, and each incarnation's levels survive.
#[test]
fn a_multi_day_soak_stays_bounded_and_keeps_its_levels_through_a_restart() {
    let clock = manual_clock();
    let mut hub = EventHub::new(
        clock.clone(),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 256,
                sample_above_events: 192,
                keep_one_in: NonZeroU32::new(4).unwrap(),
                retention: Duration::from_secs(3_600),
                max_series: 8,
            },
            ..hub_config(256, 192, 4)
        },
    )
    .unwrap();
    let mut runner = hub
        .register_metrics(
            producer("runner"),
            SourceClass::HostProbe,
            RedactionPolicy::metadata_only(),
            None,
        )
        .unwrap();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    let mut emitted: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut level = 1_000_000_000u64;
    let minutes = 3 * 24 * 60;
    for minute in 0..minutes {
        for _ in 0..2 {
            clock.advance(Duration::from_secs(30));
            level += 4_096;
            hub.emit_metric(
                &mut runner,
                context("op-soak", Phase::Running),
                gauge("gpu.pinned_bytes", level),
            )
            .unwrap();
            emitted
                .entry(runner.key().incarnation.get())
                .or_default()
                .push(level);
        }
        if minute == 51 * 60 {
            runner = hub
                .register_metrics(
                    producer("runner"),
                    SourceClass::HostProbe,
                    RedactionPolicy::metadata_only(),
                    None,
                )
                .unwrap();
        }
        let receiver_away = (50 * 60..52 * 60).contains(&minute);
        if minute % 10 == 9 && !receiver_away {
            receive(&mut receiver, &hub.drain(64));
        }
        assert!(hub.metrics().buffered() <= 256);
    }
    receive(&mut receiver, &hub.drain(usize::MAX));

    let totals = hub.metrics().totals();
    assert_eq!(totals.offered, 2 * u64::try_from(minutes).unwrap());
    assert!(totals.expired > 0 && totals.sampled_out > 0, "{totals:?}");
    assert_eq!(totals.offered, totals.delivered + totals.lost());
    assert_eq!(receiver.totals().lost, totals.lost());
    assert!(receiver.gaps().is_empty());

    let summaries: Vec<(u64, SeriesSummary)> = hub
        .metrics()
        .series()
        .map(|(key, summary)| (key.stream.incarnation.get(), *summary))
        .collect();
    assert_eq!(summaries.len(), 2);
    for (incarnation, summary) in summaries {
        let levels = &emitted[&incarnation];
        assert_eq!(summary.samples, u64::try_from(levels.len()).unwrap());
        assert_eq!(summary.first_level, levels[0]);
        assert_eq!(summary.last_level, *levels.last().unwrap());
        assert_eq!(summary.max_level, summary.last_level);
        assert_eq!(
            summary.net_change(),
            i128::from(4_096 * (summary.samples - 1))
        );
        assert_eq!(
            summary.span(),
            Duration::from_secs(30 * (summary.samples - 1))
        );
    }
    // The first incarnation ran for more than two days before it restarted.
    assert!(emitted[&1].len() > 2 * 2 * 24 * 60);
}

/// A delivery lost on the link carried a state that no later delivery repeats. Applying
/// the next delivery's marks would close its gap as superseded, silently; numbered
/// deliveries hold those marks back, poll, and recover the state from a snapshot.
#[test]
fn a_lost_delivery_never_closes_a_gap_as_superseded() {
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let key = loader.key();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    // What a receiver without delivery numbers does: apply every mark it gets.
    let mut unnumbered = Reconciler::new(reconcile_config()).unwrap();
    let mut apply_unnumbered = |delivery: &Delivery| {
        for update in &delivery.progress.updates {
            unnumbered.observe_event(update).unwrap();
        }
        for resolved in &delivery.progress.resolved {
            unnumbered
                .resolve_through(resolved, Resolution::Superseded)
                .unwrap();
        }
    };

    load(&mut hub, &mut loader, "op-a", 10);
    let first = hub.drain(16);
    let received = receiver.receive(&first).unwrap();
    assert_eq!(received.delivery, Some(DeliveryArrival::Fresh));
    assert_eq!(received.progress, [Arrival::Fresh]);
    apply_unnumbered(&first);
    // Delivery 2 carries op-b's only state, and the link loses it.
    load(&mut hub, &mut loader, "op-b", 10);
    let lost = hub.drain(16);
    assert_eq!(lost.number, delivery(2));
    load(&mut hub, &mut loader, "op-a", 20);
    let third = hub.drain(16);
    let received = receiver.receive(&third).unwrap();
    assert_eq!(
        received.delivery,
        Some(DeliveryArrival::FreshAfterGap {
            missing: deliveries(2, 2)
        })
    );
    assert_eq!(
        received.progress,
        [Arrival::FreshAfterGap {
            missing: sequences(2, 2)
        }]
    );
    apply_unnumbered(&third);
    // Without numbers the gap closed as superseded, though op-b's state was delivered.
    assert!(unnumbered.gaps().is_empty());
    assert_eq!(unnumbered.totals().superseded, 1);
    // With numbers its mark waits, and the gap stays open.
    assert_eq!(receiver.gaps(), [(key.clone(), sequences(2, 2))]);
    assert_eq!(receiver.missing_deliveries(), [deliveries(2, 2)]);
    assert_eq!(receiver.totals().superseded, 0);
    let polling = receiver.poll(clock.now());
    assert_eq!(
        polling.deliveries,
        Some(DeliveryPoll {
            missing: vec![deliveries(2, 2)],
            attempt: 1
        })
    );
    assert_eq!(polling.requests[0].missing, [sequences(2, 2)]);
    // The snapshot answers: op-b's state is recovered and delivery 2 is accounted for.
    let resynced = receiver.resync(&hub.progress_snapshot()).unwrap();
    assert_eq!(resynced.delivery, None);
    assert_eq!(resynced.progress, [Arrival::Recovered, Arrival::Duplicate]);
    assert_eq!(resynced.lost_deliveries, [deliveries(2, 2)]);
    assert!(resynced.lost.is_empty());
    assert!(receiver.gaps().is_empty());
    assert!(receiver.missing_deliveries().is_empty());
    // Deliveries go on after the snapshot, and marks close real supersession again: two
    // updates coalesce into one delivered state.
    load(&mut hub, &mut loader, "op-a", 30);
    load(&mut hub, &mut loader, "op-a", 40);
    let received = receiver.receive(&hub.drain(16)).unwrap();
    assert_eq!(received.delivery, Some(DeliveryArrival::Fresh));
    assert_eq!(
        received.progress,
        [Arrival::FreshAfterGap {
            missing: sequences(4, 4)
        }]
    );
    assert!(receiver.gaps().is_empty());
    let totals = receiver.totals();
    assert_eq!(
        (totals.superseded, totals.lost, totals.lost_deliveries),
        (1, 0, 1)
    );
}

/// A lost delivery carried the only notice of a revocation. Once the polls for it run
/// out, the gap closes as lost, explicitly, never as superseded.
#[test]
fn a_grant_revocation_rides_the_revocation_stream_without_a_gap() {
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut coordinator = hub
        .register_revocation_issuer(producer("coordinator"))
        .unwrap();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    let grant = GrantRevocation {
        execution: execution("exe-2"),
        grant: crate::foundation::ids::GrantId::from_digest(crate::foundation::ids::digest(
            "yougori/test/grant/v1",
            &[b"route"],
        )),
        epoch: AuthorizationEpoch::new(1),
        reason: RevocationReason::SecurityEvent,
    };
    hub.emit_revocation(
        &mut coordinator,
        context("op-1", Phase::Revoked),
        revocation("exe-1", 2),
    )
    .unwrap();
    hub.emit_grant_revocation(
        &mut coordinator,
        context("op-2", Phase::Revoked),
        grant.clone(),
    )
    .unwrap();
    hub.emit_revocation(
        &mut coordinator,
        context("op-3", Phase::Revoked),
        revocation("exe-3", 2),
    )
    .unwrap();
    let delivery = hub.drain(16);
    assert_eq!(delivery.revocations.grants.len(), 1);
    assert_eq!(delivery.revocations.grants[0].payload(), &grant);
    let received = receiver.receive(&delivery).unwrap();
    assert_eq!(received.revocations.len(), 3);
    assert!(received.revocations.iter().all(|arrival| arrival.is_new()));
    assert!(received.lost.is_empty());
    // The grant's sequence was received, not superseded by the issuer's resolved mark.
    let totals = receiver.totals();
    assert_eq!((totals.lost, totals.superseded), (0, 0));
}

#[test]
fn a_revocation_in_a_lost_delivery_is_lost_explicitly() {
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut coordinator = hub
        .register_revocation_issuer(producer("coordinator"))
        .unwrap();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    hub.emit_revocation(
        &mut coordinator,
        context("op-1", Phase::Revoked),
        revocation("exe-1", 2),
    )
    .unwrap();
    let _lost = hub.drain(16);
    hub.emit_revocation(
        &mut coordinator,
        context("op-2", Phase::Revoked),
        revocation("exe-2", 2),
    )
    .unwrap();
    let received = receiver.receive(&hub.drain(16)).unwrap();
    assert_eq!(
        received.delivery,
        Some(DeliveryArrival::FreshAfterGap {
            missing: deliveries(1, 1)
        })
    );
    assert_eq!(
        received.revocations,
        [Arrival::FreshAfterGap {
            missing: sequences(1, 1)
        }]
    );
    // Three polls a second apart, then the delivery is lost, and the mark held behind it
    // closes the missing notice as lost.
    let mut attempts = Vec::new();
    let mut lost = Vec::new();
    let mut lost_deliveries = Vec::new();
    for _ in 0..5 {
        clock.advance(Duration::from_secs(1));
        let polling = receiver.poll(clock.now());
        attempts.extend(polling.deliveries.map(|poll| poll.attempt));
        lost.extend(polling.lost);
        lost_deliveries.extend(polling.lost_deliveries);
    }
    assert_eq!(attempts, [1, 2, 3]);
    assert_eq!(lost_deliveries, [deliveries(1, 1)]);
    assert_eq!(
        lost,
        [LostRange {
            key: coordinator.key(),
            range: sequences(1, 1),
            reason: LossReason::DeliveryLost
        }]
    );
    assert!(receiver.gaps().is_empty());
    let totals = receiver.totals();
    assert_eq!(
        (totals.superseded, totals.lost, totals.lost_deliveries),
        (0, 1, 1)
    );
    // The stream is trusted again after that one mark.
    hub.emit_revocation(
        &mut coordinator,
        context("op-3", Phase::Revoked),
        revocation("exe-3", 2),
    )
    .unwrap();
    let received = receiver.receive(&hub.drain(16)).unwrap();
    assert_eq!(received.delivery, Some(DeliveryArrival::Fresh));
    assert!(received.lost.is_empty());
}

#[test]
fn reordered_and_repeated_deliveries_lose_nothing() {
    let mut hub = EventHub::new(manual_clock(), hub_config(16, 16, 1)).unwrap();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    load(&mut hub, &mut loader, "op-a", 10);
    let first = hub.drain(16);
    // Two updates coalesce: the second delivery carries sequence 3 only.
    load(&mut hub, &mut loader, "op-a", 20);
    load(&mut hub, &mut loader, "op-a", 30);
    let second = hub.drain(16);
    load(&mut hub, &mut loader, "op-a", 40);
    let third = hub.drain(16);
    let mut arrive = |delivery: &Delivery| {
        let received = receiver.receive(delivery).unwrap();
        (received.delivery, received.progress)
    };
    assert_eq!(
        arrive(&first),
        (Some(DeliveryArrival::Fresh), vec![Arrival::Fresh])
    );
    assert_eq!(
        arrive(&third),
        (
            Some(DeliveryArrival::FreshAfterGap {
                missing: deliveries(2, 2)
            }),
            vec![Arrival::FreshAfterGap {
                missing: sequences(2, 3)
            }]
        )
    );
    assert_eq!(
        arrive(&second),
        (Some(DeliveryArrival::Recovered), vec![Arrival::Recovered])
    );
    assert_eq!(
        arrive(&third),
        (Some(DeliveryArrival::Duplicate), vec![Arrival::Duplicate])
    );
    assert_eq!(
        arrive(&second),
        (Some(DeliveryArrival::Duplicate), vec![Arrival::Duplicate])
    );
    // Delivery 2's mark closed sequence 2 as superseded once delivery 2 was in.
    assert!(receiver.gaps().is_empty());
    assert!(receiver.missing_deliveries().is_empty());
    let totals = receiver.totals();
    assert_eq!(
        (totals.superseded, totals.lost, totals.lost_deliveries),
        (1, 0, 0)
    );
    assert_eq!(
        receiver.poll(MonotonicTime::from_nanos(u64::MAX)),
        Polling::default()
    );
}

/// A restarted hub numbers its deliveries in a later epoch. The earlier epoch's missing
/// delivery is lost, and its late deliveries change nothing.
#[test]
fn a_restarted_hub_starts_a_new_delivery_epoch() {
    let clock = manual_clock();
    let mut old_hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut loader = old_hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let old_key = loader.key();
    let mut receiver = Reconciler::new(reconcile_config()).unwrap();
    load(&mut old_hub, &mut loader, "op-a", 10);
    receive(&mut receiver, &old_hub.drain(16));
    load(&mut old_hub, &mut loader, "op-a", 20);
    let late = old_hub.drain(16);
    load(&mut old_hub, &mut loader, "op-a", 30);
    let after_gap = receiver.receive(&old_hub.drain(16)).unwrap();
    assert!(matches!(
        after_gap.delivery,
        Some(DeliveryArrival::FreshAfterGap { .. })
    ));

    let mut new_hub = EventHub::new(
        clock.clone(),
        HubConfig {
            first_incarnation: ProducerIncarnation::new(2).unwrap(),
            ..hub_config(16, 16, 1)
        },
    )
    .unwrap();
    let mut restarted = new_hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    load(&mut new_hub, &mut restarted, "op-a", 0);
    let first_of_epoch = new_hub.drain(16);
    assert_eq!(
        first_of_epoch.number,
        DeliveryNumber {
            epoch: ProducerIncarnation::new(2).unwrap(),
            sequence: DeliverySequence::FIRST
        }
    );
    let received = receiver.receive(&first_of_epoch).unwrap();
    assert_eq!(received.delivery, Some(DeliveryArrival::Fresh));
    assert_eq!(received.progress, [Arrival::Fresh]);
    // The earlier epoch's delivery 2 is lost, and the mark held behind it closes its
    // sequence as lost.
    assert_eq!(received.lost_deliveries, [deliveries(2, 2)]);
    assert_eq!(
        received.lost,
        [LostRange {
            key: old_key,
            range: sequences(2, 2),
            reason: LossReason::DeliveryLost
        }]
    );
    // The earlier epoch's delivery arriving late is ignored.
    let received = receiver.receive(&late).unwrap();
    assert_eq!(received.delivery, Some(DeliveryArrival::RetiredEpoch));
    assert_eq!(received.progress, [Arrival::RetiredIncarnation]);
    assert!(receiver.gaps().is_empty());
}

/// A terminal state travelled in a lost delivery, and the hub forgot it after its
/// retention. The snapshot cannot recover it, so its gap closes as lost; a gap whose
/// state the snapshot supersedes still closes as superseded.
#[test]
fn a_snapshot_never_passes_a_forgotten_state_off_as_superseded() {
    let clock = manual_clock();
    let mut hub = EventHub::new(clock.clone(), hub_config(16, 16, 1)).unwrap();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let key = loader.key();
    load(&mut hub, &mut loader, "op-a", 10);
    let first = hub.drain(16);
    hub.emit_progress(
        &mut loader,
        context("op-a", Phase::Completed),
        weights("op-a", 100, 100),
    )
    .unwrap();
    let second = hub.drain(16);
    load(&mut hub, &mut loader, "op-b", 10);
    let third = hub.drain(16);
    // After the retention the stream forgets op-a's delivered terminal state.
    clock.advance(Duration::from_secs(60));
    load(&mut hub, &mut loader, "op-b", 20);
    let fourth = hub.drain(16);
    let snapshot = hub.progress_snapshot();
    assert_eq!(snapshot.after, Some(delivery(4)));
    assert_eq!(snapshot.forgotten, DeliverySequence::new(2));
    assert_eq!(snapshot.states.len(), 1);

    // One receiver missed delivery 2, which carried the forgotten state.
    let mut missed_terminal = Reconciler::new(reconcile_config()).unwrap();
    for delivery in [&first, &third, &fourth] {
        missed_terminal.receive(delivery).unwrap();
    }
    let resynced = missed_terminal.resync(&snapshot).unwrap();
    assert_eq!(resynced.lost_deliveries, [deliveries(2, 2)]);
    assert_eq!(
        resynced.lost,
        [LostRange {
            key: key.clone(),
            range: sequences(2, 2),
            reason: LossReason::DeliveryLost
        }]
    );
    assert_eq!(missed_terminal.totals().superseded, 0);

    // Another missed delivery 3, whose state op-b's later one in the snapshot replaces.
    let mut missed_live = Reconciler::new(reconcile_config()).unwrap();
    for delivery in [&first, &second, &fourth] {
        missed_live.receive(delivery).unwrap();
    }
    let resynced = missed_live.resync(&snapshot).unwrap();
    assert_eq!(resynced.lost_deliveries, [deliveries(3, 3)]);
    assert!(resynced.lost.is_empty());
    assert_eq!(missed_live.totals().superseded, 1);
    for receiver in [&missed_terminal, &missed_live] {
        assert!(receiver.gaps().is_empty());
        assert!(receiver.missing_deliveries().is_empty());
    }
}

#[test]
fn deliveries_too_far_ahead_lose_the_oldest_missing() {
    let mut hub = EventHub::new(manual_clock(), hub_config(16, 16, 1)).unwrap();
    let mut loader = hub
        .register_progress(producer("loader"), SourceClass::HostProbe, None)
        .unwrap();
    let mut receiver = Reconciler::new(ReconcileConfig {
        window_sequences: 2,
        ..reconcile_config()
    })
    .unwrap();
    load(&mut hub, &mut loader, "op-a", 10);
    receive(&mut receiver, &hub.drain(16));
    // Deliveries 2 to 4 carry nothing, and the link loses them.
    for _ in 2..=4 {
        let _lost = hub.drain(16);
    }
    // Two updates coalesce: delivery 5 carries sequence 3 only.
    load(&mut hub, &mut loader, "op-a", 20);
    load(&mut hub, &mut loader, "op-a", 30);
    let received = receiver.receive(&hub.drain(16)).unwrap();
    assert_eq!(
        received.delivery,
        Some(DeliveryArrival::FreshAfterGap {
            missing: deliveries(2, 4)
        })
    );
    // Five runs more than two ahead of one: deliveries 2 to 4 are lost at once. The
    // receiver cannot know they were empty, so the stream's next mark closes sequence 2
    // as lost rather than superseded.
    assert_eq!(received.lost_deliveries, [deliveries(2, 4)]);
    assert_eq!(
        received.lost,
        [LostRange {
            key: loader.key(),
            range: sequences(2, 2),
            reason: LossReason::DeliveryLost
        }]
    );
    assert!(receiver.missing_deliveries().is_empty());
    assert!(receiver.gaps().is_empty());
    assert_eq!(receiver.totals().lost_deliveries, 3);
}
