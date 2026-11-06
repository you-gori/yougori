//! CORE-06 durable streams and subscribers across the modules (S06): an audit journal that
//! keeps its chain on a durable log through restarts and a stale owner, with one owner per
//! journal; and revocation that overtakes a metrics flood, audit overload and a slow
//! subscriber, while the slow subscriber's losses stay explicit and a fast one loses
//! nothing.

use std::num::NonZeroU32;
use std::time::Duration;

use super::fakes::{
    context, execution, journal_id, manual_clock, producer, resource, FakeAuditSpool,
    FakeAuditStore,
};
use super::*;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{AuthorizationEpoch, OperationId};

type AuditLog = DurableLog<AuditRecord>;

fn log_config() -> LogConfig {
    LogConfig {
        max_entries: 1_000,
        max_bytes: 1 << 24,
        segment_entries: 3,
        segment_bytes: 1 << 20,
    }
}

fn open_log(directory: &std::path::Path) -> Result<(AuditLog, OpenReport), LogError> {
    DurableLog::open(
        directory,
        DurableStreamId::new("engine.audit").unwrap(),
        producer("engine.audit"),
        log_config(),
    )
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

fn genesis() -> JournalHead {
    JournalHead::genesis(journal_id("engine"), producer("engine.audit"))
}

fn lease(step: u64) -> AuditDraft {
    AuditDraft::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    }
}

fn revocation(name: &str, epoch: u64) -> Revocation {
    Revocation {
        execution: execution(name),
        epoch: AuthorizationEpoch::new(epoch),
        reason: RevocationReason::SecurityEvent,
    }
}

/// The audit records a log holds, in order; markers are not records.
fn stored_records(log: &AuditLog) -> Vec<AuditRecord> {
    log.read(&log.start(), usize::MAX)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|item| match item {
            ReadItem::Entry {
                entry: LogEntry::Record(record),
                ..
            } => Some(record),
            _ => None,
        })
        .collect()
}

#[test]
fn an_audit_journal_keeps_its_chain_on_a_durable_log_across_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let (log, _) = open_log(directory.path()).unwrap();
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        log,
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 1..=5 {
        let receipt = journal
            .append(&mut authority, context("op-1", Phase::Running), lease(step))
            .unwrap();
        assert_eq!(receipt.durability, Durability::Durable);
        assert_eq!(receipt.sequence.get(), step);
    }
    // One append owner per durable stream: a second journal on it is refused at once.
    assert!(matches!(
        open_log(directory.path()),
        Err(LogError::Owner(OwnerError::HeldInProcess { .. }))
    ));
    let head = journal.head();
    drop(journal);

    // After a restart the chain read back verifies, and the journal resumes after it.
    let (log, report) = open_log(directory.path()).unwrap();
    assert!(report.markers.is_empty());
    let records = stored_records(&log);
    assert_eq!(verify_chain(&genesis(), &records).unwrap(), head);
    let (mut journal, mut authority) = AuditJournal::resume(
        head,
        log,
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    let receipt = journal
        .append(&mut authority, context("op-2", Phase::Running), lease(6))
        .unwrap();
    assert_eq!(receipt.sequence.get(), 6);
    assert_eq!(receipt.durability, Durability::Durable);
    // The operation's records correlate by the envelope's operation identity.
    let correlation = journal
        .store()
        .correlate(&OperationId::new("op-1").unwrap())
        .unwrap();
    assert_eq!(correlation.records.len(), 5);
    assert!(correlation.gaps.is_empty());
    verify_chain(&genesis(), &stored_records(journal.store())).unwrap();
}

#[test]
fn the_audit_store_takes_its_chain_in_order_and_repeats_as_stored() {
    // Records of one chain, made on a fake store.
    let (mut source, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(100),
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 1..=4 {
        let _ = source
            .append(&mut authority, context("op-1", Phase::Running), lease(step))
            .unwrap();
    }
    let records = source.store().records().to_vec();
    let (mut other, mut other_authority) = AuditJournal::open(
        journal_id("warden"),
        producer("warden.audit"),
        FakeAuditStore::new(100),
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 1..=3 {
        let _ = other
            .append(
                &mut other_authority,
                context("op-1", Phase::Running),
                lease(step),
            )
            .unwrap();
    }
    let foreign = other.store().records()[2].clone();

    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_log(directory.path()).unwrap();
    assert_eq!(AuditStore::append(&mut log, &records[0]), Ok(()));
    // A record that skips one, or belongs to another chain, is refused.
    assert_eq!(
        AuditStore::append(&mut log, &records[2]),
        Err(StoreRefusal::Failed)
    );
    assert_eq!(AuditStore::append(&mut log, &records[1]), Ok(()));
    assert_eq!(
        AuditStore::append(&mut log, &foreign),
        Err(StoreRefusal::Failed)
    );
    // A record already stored is taken again as stored, and stores nothing.
    assert_eq!(AuditStore::append(&mut log, &records[1]), Ok(()));
    assert_eq!(AuditStore::append(&mut log, &records[0]), Ok(()));
    assert_eq!(log.last().map(EventSequence::get), Some(2));
    assert_eq!(AuditStore::append(&mut log, &records[2]), Ok(()));
    // Full storage is reported as full; the journal then spools or fails closed.
    log.inject(super::durable::WriteFault::Partial(
        std::io::ErrorKind::StorageFull,
    ));
    assert_eq!(
        AuditStore::append(&mut log, &records[3]),
        Err(StoreRefusal::Full)
    );
    assert_eq!(AuditStore::append(&mut log, &records[3]), Ok(()));
    assert_eq!(stored_records(&log), records);
}

#[test]
fn a_stale_audit_owner_is_recorded_and_the_journal_resumes_after_it() {
    let directory = tempfile::tempdir().unwrap();
    let (log, _) = open_log(directory.path()).unwrap();
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        log,
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    for step in 1..=4 {
        let _ = journal
            .append(&mut authority, context("op-1", Phase::Running), lease(step))
            .unwrap();
    }
    // The process dies: its records stay, its release is never recorded.
    let records = stored_records(journal.store());
    let (log, _) = {
        drop(journal);
        open_log(directory.path()).unwrap()
    };
    log.crash();

    let (log, report) = open_log(directory.path()).unwrap();
    assert!(report.takeover.is_stale());
    assert!(matches!(
        report.markers.as_slice(),
        [(sequence, LogMarker::StaleOwner { .. })] if sequence.get() == 5
    ));
    // The marker is an entry of the log, not of the chain: the chain still verifies.
    assert_eq!(stored_records(&log), records);
    let head = verify_chain(&genesis(), &records).unwrap();
    let (mut journal, mut authority) = AuditJournal::resume(
        head,
        log,
        FakeAuditSpool::new(),
        manual_clock(),
        audit_config(4, 1),
    )
    .unwrap();
    let receipt = journal
        .append(&mut authority, context("op-1", Phase::Running), lease(5))
        .unwrap();
    assert_eq!(receipt.sequence.get(), 5);
    assert_eq!(journal.store().last().map(EventSequence::get), Some(6));
}

/// Four records of the `engine` chain and the third of the `warden` chain, made on fakes.
fn chains() -> (Vec<AuditRecord>, AuditRecord) {
    let chain = |journal: &str, producer_name: &str, steps: u64| {
        let (mut source, mut authority) = AuditJournal::open(
            journal_id(journal),
            producer(producer_name),
            FakeAuditStore::new(100),
            FakeAuditSpool::new(),
            manual_clock(),
            audit_config(4, 1),
        )
        .unwrap();
        for step in 1..=steps {
            let _ = source
                .append(&mut authority, context("op-1", Phase::Running), lease(step))
                .unwrap();
        }
        source.store().records().to_vec()
    };
    let foreign = chain("warden", "warden.audit", 3).remove(2);
    (chain("engine", "engine.audit", 4), foreign)
}

fn open_with(
    directory: &std::path::Path,
    config: LogConfig,
) -> Result<(AuditLog, OpenReport), LogError> {
    DurableLog::open(
        directory,
        DurableStreamId::new("engine.audit").unwrap(),
        producer("engine.audit"),
        config,
    )
}

/// Retention that leaves only markers never lets the store forget the record its chain
/// must continue.
#[test]
fn the_audit_store_keeps_its_last_record_when_retention_leaves_only_markers() {
    let (records, foreign) = chains();
    let one = LogConfig {
        max_entries: 1,
        max_bytes: 1 << 20,
        segment_entries: 1,
        segment_bytes: 1 << 16,
    };
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_with(directory.path(), one).unwrap();
    assert_eq!(AuditStore::append(&mut log, &records[0]), Ok(()));
    assert_eq!(AuditStore::append(&mut log, &records[1]), Ok(()));
    log.crash();
    // The stale owner's marker pushes the last record out of retention.
    let (log, report) = open_with(directory.path(), one).unwrap();
    assert!(report.takeover.is_stale());
    assert!(stored_records(&log).is_empty());
    log.close().unwrap();

    let (mut log, _) = open_with(directory.path(), one).unwrap();
    assert!(stored_records(&log).is_empty());
    assert!(!log.record_lost());
    // Another journal's record, or a chain started again from genesis, is refused.
    assert_eq!(
        AuditStore::append(&mut log, &foreign),
        Err(StoreRefusal::Failed)
    );
    assert_eq!(
        AuditStore::append(&mut log, &records[0]),
        Err(StoreRefusal::Failed)
    );
    // The last record is taken again as stored, and its successor is taken.
    assert_eq!(AuditStore::append(&mut log, &records[1]), Ok(()));
    assert_eq!(log.last().map(EventSequence::get), Some(3));
    assert_eq!(AuditStore::append(&mut log, &records[2]), Ok(()));
    assert_eq!(stored_records(&log), [records[2].clone()]);
}

/// A truncation that took the last record leaves nothing a record could be shown to
/// continue: the store refuses every record and the journal on it fails closed.
#[test]
fn the_audit_store_refuses_every_record_once_its_last_record_is_lost() {
    let (records, _) = chains();
    let directory = tempfile::tempdir().unwrap();
    let (mut log, _) = open_log(directory.path()).unwrap();
    for record in &records[..3] {
        assert_eq!(AuditStore::append(&mut log, record), Ok(()));
    }
    log.crash();
    // The segment loses its last two lines.
    let segment = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .unwrap();
    let bytes = std::fs::read(&segment).unwrap();
    let first_line = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    std::fs::write(&segment, &bytes[..first_line]).unwrap();

    let (mut log, report) = open_log(directory.path()).unwrap();
    assert!(matches!(
        report.markers.first(),
        Some((sequence, LogMarker::Truncated { missing }))
            if sequence.get() == 4 && missing.first().get() == 2 && missing.last().get() == 3
    ));
    assert!(log.record_lost());
    for record in &records {
        assert_eq!(
            AuditStore::append(&mut log, record),
            Err(StoreRefusal::Failed)
        );
    }
    log.close().unwrap();
    // It stays lost across restarts: the high-water mark still names the lost record.
    let (log, _) = open_log(directory.path()).unwrap();
    assert!(log.record_lost());
    assert_eq!(stored_records(&log), [records[0].clone()]);
}

/// INT-10 with subscribers: a metrics flood, audit storage that is full and a subscriber
/// that never keeps up. Revocations reach both subscribers first and whole; the slow one
/// sheds metrics and deliveries with every loss counted and explicit at its receiver, and
/// the fast one loses nothing.
#[test]
fn revocation_overtakes_a_metrics_flood_audit_overload_and_a_slow_subscriber() {
    let clock = manual_clock();
    let mut hub = EventHub::new(
        clock.clone(),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 4_096,
                sample_above_events: 4_096,
                keep_one_in: NonZeroU32::MIN,
                retention: Duration::from_secs(600),
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
    // Audit storage is full: ordinary records fail closed once the spool is full, and
    // revocation records still fit in the reserve.
    let (mut journal, mut authority) = AuditJournal::open(
        journal_id("engine"),
        producer("engine.audit"),
        FakeAuditStore::new(0),
        FakeAuditSpool::new(),
        clock.clone(),
        audit_config(6, 4),
    )
    .unwrap();
    let mut fanout = DeliveryFanout::new();
    let slow = fanout
        .subscribe(SubscriberConfig {
            max_deliveries: 3,
            max_events: 40,
            revocation_reserve: 4,
        })
        .unwrap();
    let fast = fanout
        .subscribe(SubscriberConfig {
            max_deliveries: 64,
            max_events: 1 << 20,
            revocation_reserve: 64,
        })
        .unwrap();
    let reconcile = ReconcileConfig {
        max_streams: 16,
        window_sequences: 1 << 20,
        max_polls: 3,
        poll_interval: Duration::from_secs(1),
    };
    let mut fast_receiver = Reconciler::new(reconcile).unwrap();
    let mut audit_refusals = 0;
    let rounds = 20u64;
    for round in 0..rounds {
        clock.advance(Duration::from_millis(10));
        for value in 0..200 {
            hub.emit_metric(
                &mut runner,
                context("op-flood", Phase::Running),
                MetricDraft::new(
                    "gpu.resident_bytes",
                    MetricValue::GaugeBytes { bytes: value },
                ),
            )
            .unwrap();
        }
        hub.emit_progress(
            &mut loader,
            context("op-load", Phase::Loading),
            ProgressUpdate::new(
                resource(&format!("shard-{}", round % 4)),
                ResourceKind::Weights,
                round,
                Some(rounds),
                round,
                CancellationBoundary::Anytime,
            ),
        )
        .unwrap();
        if journal
            .append(
                &mut authority,
                context("op-load", Phase::Loading),
                lease(round),
            )
            .is_err()
        {
            audit_refusals += 1;
        }
        if round % 5 == 4 {
            let revoked = revocation(&format!("exe-{round}"), 2);
            assert_eq!(
                hub.emit_revocation(
                    &mut coordinator,
                    context("op-load", Phase::Revoked),
                    revoked.clone()
                ),
                Ok(RevocationAdmission::Queued)
            );
            // Its durable copy uses the audit reserve; the lane never waited for it.
            let receipt = journal
                .append(
                    &mut authority,
                    context("op-load", Phase::Revoked),
                    AuditDraft::Revocation(revoked),
                )
                .unwrap();
            assert!(matches!(receipt.durability, Durability::Spooled { .. }));
        }
        fanout.publish(&hub.drain(usize::MAX));
        // The fast subscriber keeps up and loses nothing.
        for delivery in fanout.take(fast, usize::MAX).unwrap().deliveries {
            let received = fast_receiver.receive(&delivery).unwrap();
            assert!(received.lost.is_empty() && received.lost_deliveries.is_empty());
        }
    }
    assert!(audit_refusals > 0);
    assert!(matches!(journal.health(), AuditHealth::FailClosed { .. }));
    assert_eq!(fast_receiver.totals().fresh, rounds * 200 + rounds + 4);
    assert!(fast_receiver.gaps().is_empty());
    let fast_totals = fanout.totals(fast).unwrap();
    assert_eq!(
        (fast_totals.metrics_shed, fast_totals.deliveries_shed),
        (0, 0)
    );

    // The slow subscriber takes only now. Its first delivery carries every revocation,
    // in order, ahead of the rest; nothing it held exceeds its bounds by more than the
    // newest delivery.
    let held = fanout.held(slow).unwrap();
    assert!(held.deliveries <= 3);
    assert_eq!(held.revocations, 4);
    let batch = fanout.take(slow, usize::MAX).unwrap();
    let lag = batch.lag.unwrap();
    assert_eq!(lag.deliveries, rounds - 3);
    let first = &batch.deliveries[0];
    let revoked: Vec<String> = first
        .revocations
        .notices
        .iter()
        .map(|notice| notice.payload().execution.to_string())
        .collect();
    assert_eq!(revoked, ["exe-4", "exe-9", "exe-14", "exe-19"]);
    assert_eq!(first.revocations.revoke_all, None);

    // At the receiver, every revocation arrives and none is lost; the shed metrics are
    // lost explicitly, the shed deliveries are counted lost, and a snapshot resyncs it.
    let mut slow_receiver = Reconciler::new(reconcile).unwrap();
    let mut lost = Vec::new();
    for delivery in &batch.deliveries {
        let received = slow_receiver.receive(delivery).unwrap();
        assert!(received.revocations.iter().all(|arrival| arrival.is_new()));
        lost.extend(received.lost);
    }
    let resynced = slow_receiver.resync(&hub.progress_snapshot()).unwrap();
    lost.extend(resynced.lost);
    assert_eq!(resynced.lost_deliveries.len(), 1);
    assert_eq!(resynced.lost_deliveries[0].count(), lag.deliveries);
    assert!(lost
        .iter()
        .all(|range| range.key.stream != StreamKind::Revocation));
    let totals = fanout.totals(slow).unwrap();
    assert_eq!(totals.revocations_taken, 4);
    assert_eq!(totals.revocations_widened, 0);
    assert!(totals.metrics_shed >= (rounds - 1) * 200);
    let lost_metrics: u64 = lost
        .iter()
        .filter(|range| range.key.stream == StreamKind::Metrics)
        .map(|range| range.range.count())
        .sum();
    assert_eq!(lost_metrics, totals.metrics_shed);
    assert!(slow_receiver.gaps().is_empty());
}
