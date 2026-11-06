//! The progress port over the CORE-06 event plane (T10).
//!
//! Each transfer progress event becomes one sealed progress envelope per object it
//! changes, on the hub's coalescing progress stream. The envelope carries the transfer's
//! operation, its authorization epoch as the typed generation, and the phase. The payload
//! carries the object's catalog identity and its completed, total and committed usable
//! bytes (GPU part §3.10). The producer is registered once, as a host source. Progress
//! is lossy by design: an update the stream refuses is counted, and no transfer decision
//! waits for it (CORE-06, INT-10).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::ports::{ByteOrigin, ProgressPhase, ProgressPort, TransferProgress};
use super::status::StopReason;
use crate::foundation::events::{
    CancellationBoundary, DataSource, EventContext, EventHub, Generations, HubError, Phase,
    ProducerId, ProgressProducer, ProgressUpdate, QueueReason, ResourceKind, TrackedResourceId,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::Clock;

/// [`ProgressPort`] over the host's [`EventHub`], shared with its other producers and
/// its receivers.
///
/// Transfers tell nothing of what their objects hold, so the resource kind the events
/// report is the adapter's configuration: one adapter per kind, such as model weights.
pub struct EventProgress<C> {
    hub: Arc<Mutex<EventHub<C>>>,
    producer: Mutex<ProgressProducer>,
    kind: ResourceKind,
    refused: AtomicU64,
}

impl<C: Clock> EventProgress<C> {
    /// Registers `producer` on the hub's progress stream as a host source, for transfers
    /// of `kind`. Registering the same producer again retires this adapter's handle.
    pub fn register(
        hub: Arc<Mutex<EventHub<C>>>,
        producer: ProducerId,
        kind: ResourceKind,
    ) -> Result<Self, HubError> {
        let handle = lock(&hub).register_progress(producer, SourceClass::HostProbe, None)?;
        Ok(Self {
            hub,
            producer: Mutex::new(handle),
            kind,
            refused: AtomicU64::new(0),
        })
    }

    /// Updates the event plane refused, which progress loses.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }
}

impl<C: Clock> ProgressPort for EventProgress<C> {
    fn emit(&self, event: TransferProgress) {
        let phase = event_phase(&event.phase);
        let context = EventContext::new(event.operation.clone(), phase)
            .with_generations(Generations::NONE.with_authorization(event.epoch));
        let source = data_source(event.origin);
        let mut producer = lock(&self.producer);
        let mut hub = lock(&self.hub);
        for object in &event.objects {
            let mut update = ProgressUpdate::new(
                TrackedResourceId::new(*object.object.digest()),
                self.kind,
                object.completed_bytes,
                Some(object.granted_bytes),
                object.verified_bytes,
                CancellationBoundary::Anytime,
            )
            .from_source(source);
            if phase == Phase::Queued {
                update = update.queued_for(QueueReason::TransferSlot);
            }
            if hub
                .emit_progress(&mut producer, context.clone(), update)
                .is_err()
            {
                self.refused.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// The CORE-06 phase of a transfer event. An interrupted transfer waits for a retry; a
/// stop is cancelled, revoked, or else failed.
fn event_phase(phase: &ProgressPhase) -> Phase {
    match phase {
        ProgressPhase::Started | ProgressPhase::Resumed | ProgressPhase::ChunkDelivered { .. } => {
            Phase::Transferring
        }
        ProgressPhase::Interrupted { .. } => Phase::Queued,
        ProgressPhase::Completed => Phase::Completed,
        ProgressPhase::Stopped {
            reason: StopReason::Cancelled | StopReason::Abandoned,
        } => Phase::Cancelled,
        ProgressPhase::Stopped { reason } if reason.is_revocation() => Phase::Revoked,
        ProgressPhase::Stopped { .. } => Phase::Failed,
    }
}

fn data_source(origin: ByteOrigin) -> DataSource {
    match origin {
        ByteOrigin::Local => DataSource::LocalStorage,
        ByteOrigin::Peer => DataSource::PeerTransfer,
        ByteOrigin::Remote => DataSource::RemoteDownload,
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
    use crate::foundation::events::{
        EventEnvelope, HubConfig, MetricsConfig, ProducerIncarnation, ProgressConfig,
        RevocationConfig,
    };
    use crate::foundation::ids::ManualClock;
    use crate::foundation::transfer::fakes::{
        at, download_connection, download_fields, object, operation, parent, range, test_key,
        World, EPOCH, HOUR, SESSION,
    };
    use crate::foundation::transfer::{
        ObjectGrant, TransferGate, TransferPorts, TransferScope, TransferStatus,
    };

    type Hub = Mutex<EventHub<Arc<ManualClock>>>;

    fn hub_config() -> HubConfig {
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 8,
                sample_above_events: 8,
                keep_one_in: NonZeroU32::MIN,
                retention: Duration::from_secs(60),
                max_series: 4,
            },
            progress: ProgressConfig {
                max_tracked: 8,
                terminal_retention: Duration::from_secs(60),
            },
            revocation: RevocationConfig {
                max_pending_executions: 4,
            },
            first_incarnation: ProducerIncarnation::FIRST,
        }
    }

    /// An event hub, the adapter registered on it for model weights, and a gate whose
    /// other ports are the world's fakes.
    fn plane(world: &World) -> (Arc<Hub>, Arc<EventProgress<Arc<ManualClock>>>, TransferGate) {
        let hub = Arc::new(Mutex::new(
            EventHub::new(world.clock.clone(), hub_config()).unwrap(),
        ));
        let progress = Arc::new(
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
                progress: progress.clone(),
            },
        );
        (hub, progress, gate)
    }

    fn drain(hub: &Hub) -> Vec<EventEnvelope<ProgressUpdate>> {
        lock(hub).drain(0).progress.updates
    }

    fn weights() -> TrackedResourceId {
        TrackedResourceId::new(*object("weights").digest())
    }

    /// A transfer's start, each delivered chunk and its completion arrive as sealed
    /// progress envelopes: the transfer's operation and epoch, the phase, and the
    /// object's bytes under its catalog identity.
    #[test]
    fn a_transfers_chunk_progress_arrives_as_events() {
        let world = World::new();
        let (hub, progress, gate) = plane(&world);
        let fields = download_fields();
        let mut session = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();

        let opened = drain(&hub);
        assert_eq!(opened.len(), 1);
        let event = &opened[0];
        assert_eq!(event.operation(), &operation("op-download"));
        assert_eq!(event.generations().authorization, Some(EPOCH));
        assert_eq!(event.phase(), Phase::Transferring);
        assert_eq!(event.provenance().source(), SourceClass::HostProbe);
        assert_eq!(event.provenance().producer().as_str(), "transfer");
        let update = event.payload();
        assert_eq!(update.resource(), weights());
        assert_eq!(update.kind(), ResourceKind::Weights);
        assert_eq!(update.source(), Some(DataSource::RemoteDownload));
        assert_eq!(
            (
                update.completed_bytes(),
                update.total_bytes(),
                update.committed_usable_bytes()
            ),
            (0, Some(100), 0)
        );
        assert_eq!(
            update.describe(event.phase()),
            "transferring weights from a download"
        );

        let mut sequences = vec![event.sequence().get()];
        for (start, end) in [(0, 40), (40, 80), (80, 100)] {
            let permit = session
                .admit(&object("weights"), range(start, end))
                .unwrap();
            session.deliver(permit).unwrap();
            world.verify(&fields, &object("weights"), range(start, end));
            let arrived = drain(&hub);
            assert_eq!(arrived.len(), 1);
            let event = &arrived[0];
            assert_eq!(event.phase(), Phase::Transferring);
            assert_eq!(event.payload().resource(), weights());
            assert_eq!(event.payload().completed_bytes(), end);
            assert_eq!(event.payload().total_bytes(), Some(100));
            sequences.push(event.sequence().get());
        }

        session.finish().unwrap();
        let finished = drain(&hub);
        assert_eq!(finished.len(), 1);
        let event = &finished[0];
        assert_eq!(event.phase(), Phase::Completed);
        let update = event.payload();
        assert_eq!(
            (
                update.completed_bytes(),
                update.total_bytes(),
                update.committed_usable_bytes()
            ),
            (100, Some(100), 100)
        );
        assert_eq!(update.describe(event.phase()), "weights ready");
        sequences.push(event.sequence().get());
        assert_eq!(sequences, [1, 2, 3, 4, 5]);
        assert_eq!(progress.refused(), 0);
    }

    /// Updates not yet delivered coalesce per object; an interrupted transfer waits for a
    /// transfer slot; stops arrive as their terminal phases.
    #[test]
    fn floods_coalesce_and_stops_arrive_as_terminal_phases() {
        let world = World::new();
        let (hub, progress, gate) = plane(&world);
        let mut session = gate
            .open(&world.seal(download_fields()), &download_connection())
            .unwrap();
        for (start, end) in [(0, 20), (20, 40)] {
            let permit = session
                .admit(&object("weights"), range(start, end))
                .unwrap();
            session.deliver(permit).unwrap();
        }
        let flood = drain(&hub);
        assert_eq!(flood.len(), 1);
        assert_eq!(flood[0].payload().completed_bytes(), 40);
        assert_eq!(lock(&hub).progress().totals().coalesced, 2);

        session.interrupt().unwrap();
        let waiting = drain(&hub);
        assert_eq!(waiting[0].phase(), Phase::Queued);
        assert_eq!(
            waiting[0].payload().queue_reason(),
            Some(QueueReason::TransferSlot)
        );
        assert_eq!(
            waiting[0].payload().describe(Phase::Queued),
            "waiting for a transfer slot"
        );

        world.authority.revoke(&parent());
        assert!(session.retry(&download_connection()).is_err());
        let revoked = drain(&hub);
        assert_eq!(revoked[0].phase(), Phase::Revoked);
        assert_eq!(revoked[0].payload().completed_bytes(), 40);
        assert_eq!(
            revoked[0].payload().describe(Phase::Revoked),
            "weights stopped: authorization revoked"
        );

        let mut fields = download_fields();
        fields.operation = operation("op-cancelled");
        fields.epoch = EPOCH.next().unwrap();
        fields.scope = TransferScope::single(object("adapter"), ObjectGrant::whole(10).unwrap());
        world.authority.grant(&parent(), fields.epoch, at(HOUR));
        let mut cancelled = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap();
        assert!(matches!(cancelled.cancel(), TransferStatus::Stopped(_)));
        let phases: Vec<Phase> = drain(&hub).iter().map(|event| event.phase()).collect();
        assert_eq!(phases, [Phase::Cancelled]);
        assert_eq!(progress.refused(), 0);
    }

    /// Review R1-b, finding 1 (the T14 follow-up decision): a continuation under a
    /// re-issued grant after a revocation is a new operation, so its progress starts fresh
    /// instead of being refused after the stopped operation's terminal phase.
    #[test]
    fn a_continuation_after_revocation_reports_progress_as_a_new_operation() {
        let world = World::new();
        let (hub, progress, gate) = plane(&world);
        let fields = download_fields();
        let mut session = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();
        let permit = session.admit(&object("weights"), range(0, 40)).unwrap();
        session.deliver(permit).unwrap();
        world.verify(&fields, &object("weights"), range(0, 40));
        world.authority.revoke(&parent());
        assert!(matches!(session.poll(), TransferStatus::Stopped(_)));

        let epoch = EPOCH.next().unwrap();
        world.authority.grant(&parent(), epoch, at(24 * HOUR));
        let mut reissued = download_fields();
        reissued.epoch = epoch;
        session
            .retry_with_grant(&world.seal(reissued.clone()), &download_connection())
            .unwrap();
        for (start, end) in [(40, 80), (80, 100)] {
            let permit = session
                .admit(&object("weights"), range(start, end))
                .unwrap();
            session.deliver(permit).unwrap();
            world.verify(&reissued, &object("weights"), range(start, end));
        }
        session.finish().unwrap();

        assert_eq!(progress.refused(), 0);
        let snapshot = lock(&hub).progress_snapshot();
        assert_eq!(snapshot.states.len(), 2);
        let stopped = snapshot
            .states
            .iter()
            .find(|state| state.operation() == &operation("op-download"))
            .unwrap();
        assert_eq!(stopped.phase(), Phase::Revoked);
        assert_eq!(stopped.generations().authorization, Some(EPOCH));
        let continued = snapshot
            .states
            .iter()
            .find(|state| state.operation() != &operation("op-download"))
            .unwrap();
        assert_eq!(continued.phase(), Phase::Completed);
        assert_eq!(continued.generations().authorization, Some(epoch));
        assert_eq!(continued.payload().resource(), weights());
        assert_eq!(continued.payload().completed_bytes(), 100);
    }
}
