//! S06 (docs/combined-plan-leftover-tasks.md; CORE-06 "separate retention/backpressure";
//! GPU part §3.10 "reconnect snapshot"): transfer progress and model progress leave the
//! engine's shared event plane through its one [`DeliveryPump`] into the subscriber
//! fan-out, as their contract requires. Progress is never durable: a subscriber that falls
//! behind sheds it, counted, and resyncs from the hub's snapshot, while a revocation on
//! the same hub is never shed and reaches it first.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use super::{ProgressPublisher, PublishOutcome, PublishPolicy, Stage, TrackRequest};
use crate::foundation::events::{
    DataSource, DeliveryArrival, DeliveryPump, EventContext, EventHub, HubConfig, MetricsConfig,
    Phase, ProducerId, ProducerIncarnation, ProgressConfig, QueueReason, ReconcileConfig,
    Reconciler, ResourceKind, Revocation, RevocationConfig, RevocationReason, StreamKind,
    SubscriberConfig, TrackedResourceId,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ExecutionId, Incarnation, ManualClock, OperationId,
};
use crate::foundation::report::{ClockId, Label};
use crate::foundation::transfer::fakes::{
    download_connection, download_fields, object, operation, range, test_key, World, SESSION,
};
use crate::foundation::transfer::{EventProgress, TransferGate, TransferPorts};

type Hub = Arc<Mutex<EventHub<Arc<ManualClock>>>>;

fn lock(hub: &Hub) -> MutexGuard<'_, EventHub<Arc<ManualClock>>> {
    hub.lock().unwrap()
}

fn hub_config() -> HubConfig {
    HubConfig {
        metrics: MetricsConfig {
            capacity_events: 16,
            sample_above_events: 16,
            keep_one_in: NonZeroU32::MIN,
            retention: Duration::from_secs(60),
            max_series: 4,
        },
        progress: ProgressConfig {
            max_tracked: 8,
            terminal_retention: Duration::from_secs(3_600),
        },
        revocation: RevocationConfig {
            max_pending_executions: 4,
        },
        first_incarnation: ProducerIncarnation::FIRST,
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

#[test]
fn transfer_and_model_progress_reach_subscribers_through_the_pump_and_shed_before_a_revocation() {
    let world = World::new();
    let hub: Hub = Arc::new(Mutex::new(
        EventHub::new(world.clock.clone(), hub_config()).unwrap(),
    ));
    // The transfer gate reports through its progress port on the shared hub.
    let transfer = Arc::new(
        EventProgress::register(
            hub.clone(),
            ProducerId::new("transfer").unwrap(),
            ResourceKind::Weights,
        )
        .unwrap(),
    );
    let gate = TransferGate::new(
        test_key(),
        TransferPorts {
            clock: world.clock.clone(),
            clock_session: SESSION,
            authority: world.authority.clone(),
            budget: world.ledger.clone(),
            extents: world.extents.clone(),
            progress: transfer.clone(),
        },
    );
    // The model-memory publisher and the coordinator's issuer share it.
    let (producer, mut issuer) = {
        let mut hub = lock(&hub);
        (
            hub.register_progress(
                ProducerId::new("model-memory").unwrap(),
                SourceClass::HostProbe,
                None,
            )
            .unwrap(),
            hub.register_revocation_issuer(ProducerId::new("coordinator").unwrap())
                .unwrap(),
        )
    };
    let mut model = ProgressPublisher::new(
        producer,
        Incarnation::FIRST,
        world.clock.clone(),
        ClockId::new(Label::new("host-monotonic").unwrap()),
        PublishPolicy::default(),
    )
    .unwrap();
    let mut pump = DeliveryPump::new(hub.clone(), 16).unwrap();
    let fast = pump
        .subscribe(SubscriberConfig {
            max_deliveries: 64,
            max_events: 1_024,
            revocation_reserve: 4,
        })
        .unwrap();
    let slow = pump
        .subscribe(SubscriberConfig {
            max_deliveries: 1,
            max_events: 1,
            revocation_reserve: 4,
        })
        .unwrap();

    // A weights download through the gate while the model waits for GPU memory, then
    // restores from local storage; the coordinator revokes an execution meanwhile.
    let fields = download_fields();
    let mut session = gate
        .open(&world.seal(fields.clone()), &download_connection())
        .unwrap();
    pump.pump();
    let load = OperationId::new("op-load").unwrap();
    let weights = TrackedResourceId::new(digest(
        "yougori/test/weights/v1",
        &["chat-model".as_bytes()],
    ));
    assert_eq!(
        model.track(
            &mut lock(&hub),
            &load,
            TrackRequest {
                resource: weights,
                kind: ResourceKind::Weights,
                total_bytes: 100,
                stage: Stage::queued(QueueReason::GpuMemory { needed_bytes: 100 }),
            },
        ),
        Ok(PublishOutcome::Published)
    );
    pump.pump();
    for (start, end) in [(0, 40), (40, 80), (80, 100)] {
        let permit = session
            .admit(&object("weights"), range(start, end))
            .unwrap();
        session.deliver(permit).unwrap();
        world.verify(&fields, &object("weights"), range(start, end));
        pump.pump();
    }
    assert_eq!(
        model.set_stage(
            &mut lock(&hub),
            &load,
            Stage::from_source(Phase::Restoring, DataSource::LocalStorage),
        ),
        Ok(PublishOutcome::Published)
    );
    lock(&hub)
        .emit_revocation(
            &mut issuer,
            EventContext::new(OperationId::new("op-revoke").unwrap(), Phase::Revoked),
            Revocation {
                execution: ExecutionId::new("exe-1").unwrap(),
                epoch: AuthorizationEpoch::new(2),
                reason: RevocationReason::UserRequested,
            },
        )
        .unwrap();
    pump.pump();
    session.finish().unwrap();
    pump.pump();
    assert_eq!(pump.fanout().published(), 7);
    assert_eq!(transfer.refused(), 0);

    // The fast subscriber gets every delivery: both producers' progress, and the
    // revocation, which rides the first delivery it takes.
    let batch = pump.take(fast, usize::MAX).unwrap();
    assert_eq!(batch.lag, None);
    assert_eq!(batch.deliveries.len(), 7);
    let mut phases: Vec<(String, Phase)> = Vec::new();
    for delivery in &batch.deliveries {
        for update in &delivery.progress.updates {
            phases.push((update.provenance().producer().to_string(), update.phase()));
        }
    }
    assert_eq!(
        phases,
        [
            ("transfer".to_owned(), Phase::Transferring),
            ("model-memory".to_owned(), Phase::Queued),
            ("transfer".to_owned(), Phase::Transferring),
            ("transfer".to_owned(), Phase::Transferring),
            ("transfer".to_owned(), Phase::Transferring),
            ("model-memory".to_owned(), Phase::Restoring),
            ("transfer".to_owned(), Phase::Completed),
        ]
    );
    let revocations: Vec<usize> = batch
        .deliveries
        .iter()
        .map(|delivery| delivery.revocations.notices.len())
        .collect();
    assert_eq!(revocations, [1, 0, 0, 0, 0, 0, 0]);

    // The slow subscriber shed every delivery but the newest, with its progress, and
    // never the revocation: it rides the one delivery taken, ahead of the progress.
    let batch = pump.take(slow, usize::MAX).unwrap();
    assert_eq!(batch.lag.map(|lag| lag.deliveries), Some(6));
    assert_eq!(batch.deliveries.len(), 1);
    let delivery = &batch.deliveries[0];
    assert_eq!(delivery.revocations.notices.len(), 1);
    assert_eq!(delivery.progress.updates.len(), 1);
    let totals = pump.fanout().totals(slow).unwrap();
    assert_eq!((totals.deliveries_shed, totals.progress_shed), (6, 6));
    assert_eq!(totals.revocations_taken, 1);

    // It resyncs from the snapshot: the latest state of both operations, and the shed
    // deliveries accounted for as lost, every gap closed.
    let mut receiver = reconciler();
    let received = receiver.receive(delivery).unwrap();
    assert!(matches!(
        received.delivery,
        Some(DeliveryArrival::FreshAfterGap { .. })
    ));
    let snapshot = pump.snapshot();
    let mut states: Vec<(OperationId, Phase, u64)> = snapshot
        .states
        .iter()
        .map(|state| {
            (
                state.operation().clone(),
                state.phase(),
                state.payload().completed_bytes(),
            )
        })
        .collect();
    states.sort();
    assert_eq!(
        states,
        [
            (operation("op-download"), Phase::Completed, 100),
            (load.clone(), Phase::Restoring, 0),
        ]
    );
    let resynced = receiver.resync(&snapshot).unwrap();
    assert_eq!(resynced.lost_deliveries.len(), 1);
    assert!(receiver.gaps().is_empty());
    assert!(received
        .lost
        .iter()
        .all(|lost| lost.key.stream != StreamKind::Revocation));
}
