//! Durable streams of events one owner seals (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! S2 CORE-06 "operation identity ... monotonic sequence, phase, provenance"; S7 restart
//! recovery; GPU part §3.10; docs/combined-plan-leftover-tasks.md S06 "publish real launch,
//! load ... and recovery events through CORE-06. Give each durable stream a clear append
//! owner, correlate operations").
//!
//! An [`EventLog`] keeps one kind of event on its own [`DurableLog`] under its one
//! [`StreamOwner`]: the producer that decides the events, and the only appender. Each event
//! is an [`EventEnvelope`] the owner seals under the context it was decided in, with its
//! operation, typed generations and phase, its producer the stream's owner and its
//! incarnation the owner's. So the stream's events correlate with the hub's progress and
//! the audit journal by operation ([`DurableLog::correlate`]), survive a restart with their
//! sequence continued, and are read again from a cursor, by the owner or by a
//! [`DurableReader`](super::DurableReader) in another process, with every gap explicit.
//!
//! It carries what must not be shed: model lifecycle decisions and restart-recovery
//! outcomes. Metrics never travel here, since they are lossy by contract, and revocations
//! have their own stream ([`RevocationLog`]), so [`LoggedStream`] names only progress and
//! audit. Nothing here waits on the hub, the audit journal or a subscriber, and nothing
//! they do reaches it. The owner must not also be a producer registered on a hub: their
//! envelopes would share one sequence space.
//!
//! [`StreamOwner`]: super::StreamOwner
//! [`RevocationLog`]: super::RevocationLog

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::durable::{DurableLog, DurableStreamId, LogConfig, LogError, OpenReport};
use super::envelope::{
    EventContext, EventEnvelope, EventSequence, ProducerCore, ProducerId, ProducerIncarnation,
    StreamKey, StreamKind,
};
use super::owner::OwnerError;
use super::revocation_log::RecordError;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::MonotonicTime;

/// The CORE-06 stream an [`EventLog`]'s envelopes belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoggedStream {
    /// Where an operation is, such as a model's lifecycle: the latest state per
    /// operation is what a receiver shows.
    Progress,
    /// Facts the host decided or observed, such as what restart recovery did.
    Audit,
}

impl LoggedStream {
    pub const fn kind(self) -> StreamKind {
        match self {
            Self::Progress => StreamKind::Progress,
            Self::Audit => StreamKind::Audit,
        }
    }
}

/// One durable stream of events its one owner seals (CORE-06; S06).
#[derive(Debug)]
pub struct EventLog<P> {
    log: DurableLog<EventEnvelope<P>>,
    core: ProducerCore,
}

impl<P: Serialize + DeserializeOwned + Clone> EventLog<P> {
    /// Takes ownership of the stream `stream` in `directory` for `owner`, creating it if
    /// the directory holds none, and recovers it as [`DurableLog::open`] does. Its
    /// envelopes travel on `kind`. Refuses while any owner, in this process or another,
    /// holds the stream.
    pub fn open(
        directory: &Path,
        stream: DurableStreamId,
        owner: ProducerId,
        kind: LoggedStream,
        config: LogConfig,
    ) -> Result<(Self, OpenReport), LogError> {
        let (log, report) = DurableLog::open(directory, stream, owner.clone(), config)?;
        // An owner's incarnation is never zero: acquisition starts at one and only rises.
        // Should a record claim zero anyway, refuse instead of sealing under one.
        let Some(incarnation) = ProducerIncarnation::new(log.owner().incarnation().get()) else {
            log.close()?;
            return Err(LogError::Owner(OwnerError::IncarnationExhausted));
        };
        let core = ProducerCore::new(owner, incarnation, kind.kind(), SourceClass::HostProbe);
        Ok((Self { log, core }, report))
    }

    /// Seals `payload` under `context` at `at` on the owner's clock and returns its
    /// sequence in the stream once it is durable. A refusal uses no sequence of either
    /// kind and keeps nothing of the event.
    pub fn record(
        &mut self,
        context: EventContext,
        at: MonotonicTime,
        payload: P,
    ) -> Result<EventSequence, RecordError> {
        let envelope = self
            .core
            .draft(SourceClass::HostProbe, context, at, payload)
            .map_err(RecordError::Seal)?;
        let sealed = envelope.sequence();
        let stored = self.log.append(envelope).map_err(RecordError::Log)?;
        self.core.commit(sealed);
        Ok(stored)
    }

    /// The stream itself, for reads, cursors, correlation, retention and totals. Only
    /// [`EventLog::record`] appends to it.
    pub fn log(&self) -> &DurableLog<EventEnvelope<P>> {
        &self.log
    }

    /// The stream's owner, the producer of every event it seals.
    pub fn owner(&self) -> &ProducerId {
        self.core.producer()
    }

    /// The sequence space of the events this owner incarnation seals.
    pub fn key(&self) -> StreamKey {
        self.core.key()
    }

    /// Releases the stream, as [`DurableLog::close`] does.
    pub fn close(self) -> Result<(), LogError> {
        self.log.close()
    }

    /// Gives the stream up as a crashing process would.
    #[cfg(test)]
    pub(super) fn crash(self) {
        self.log.crash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::durable::{LogEntry, ReadItem};
    use crate::foundation::events::envelope::{Generations, Phase};
    use crate::foundation::events::fakes::{context, operation, producer};
    use crate::foundation::events::DurableReader;
    use crate::foundation::ids::ModelActivationGeneration;

    fn stream_id() -> DurableStreamId {
        DurableStreamId::new("model.lifecycle").unwrap()
    }

    fn config() -> LogConfig {
        LogConfig {
            max_entries: 1_000,
            max_bytes: 1 << 20,
            segment_entries: 4,
            segment_bytes: 1 << 16,
        }
    }

    fn open(directory: &Path) -> (EventLog<String>, OpenReport) {
        EventLog::open(
            directory,
            stream_id(),
            producer("model_memory.lifecycle"),
            LoggedStream::Progress,
            config(),
        )
        .unwrap()
    }

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn events(log: &EventLog<String>) -> Vec<(u64, EventEnvelope<String>)> {
        log.log()
            .read(&log.log().start(), usize::MAX)
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| match item {
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Record(event),
                    ..
                } => Some((sequence.get(), event)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_owner_seals_each_event_under_its_context_and_one_sequence_space() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path());
        let generation = ModelActivationGeneration::new(3);
        let prepared = context("op-load", Phase::Loading)
            .with_generations(Generations::NONE.with_model_activation(generation));
        assert_eq!(
            log.record(prepared, at(1), "prepared".to_owned())
                .unwrap()
                .get(),
            1
        );
        log.record(
            context("op-load", Phase::Running),
            at(2),
            "activated".to_owned(),
        )
        .unwrap();
        log.record(
            context("op-other", Phase::Releasing),
            at(3),
            "released".to_owned(),
        )
        .unwrap();
        let read = events(&log);
        assert_eq!(read.len(), 3);
        let (_, first) = &read[0];
        assert_eq!(first.operation(), &operation("op-load"));
        assert_eq!(first.phase(), Phase::Loading);
        assert_eq!(first.generations().model_activation, Some(generation));
        assert_eq!(first.stream(), StreamKind::Progress);
        assert_eq!(
            first.provenance().producer(),
            &producer("model_memory.lifecycle")
        );
        assert_eq!(first.provenance().source(), SourceClass::HostProbe);
        assert_eq!(first.emitted_at(), at(1));
        assert_eq!(first.key(), log.key());
        assert_eq!(
            read.iter()
                .map(|(_, event)| event.sequence().get())
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        // One operation's events correlate by the envelope's operation identity.
        let correlation = log.log().correlate(&operation("op-load")).unwrap();
        assert_eq!(correlation.records.len(), 2);
        assert!(correlation.gaps.is_empty());
    }

    #[test]
    fn a_restart_continues_the_stream_and_a_crash_is_recorded() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path());
        log.record(context("op-1", Phase::Loading), at(1), "one".to_owned())
            .unwrap();
        // One owner: a second one is refused while the first holds the stream.
        assert!(matches!(
            EventLog::<String>::open(
                directory.path(),
                stream_id(),
                producer("model_memory.lifecycle"),
                LoggedStream::Progress,
                config(),
            ),
            Err(LogError::Owner(OwnerError::HeldInProcess { .. }))
        ));
        log.crash();
        let (mut log, report) = open(directory.path());
        assert!(report.takeover.is_stale());
        let next = log
            .record(context("op-2", Phase::Running), at(2), "two".to_owned())
            .unwrap();
        // The stale-owner marker took sequence 2.
        assert_eq!(next.get(), 3);
        // The new incarnation seals in a sequence space of its own.
        let read = events(&log);
        assert_eq!(read[1].1.provenance().incarnation().get(), 2);
        assert_eq!(read[1].1.sequence().get(), 1);
        log.close().unwrap();
    }

    #[test]
    fn a_reader_in_another_handle_follows_the_stream() {
        let directory = tempfile::tempdir().unwrap();
        let (mut log, _) = open(directory.path());
        log.record(context("op-1", Phase::Loading), at(1), "one".to_owned())
            .unwrap();
        let mut reader =
            DurableReader::<EventEnvelope<String>>::open(directory.path(), stream_id()).unwrap();
        log.record(context("op-1", Phase::Running), at(2), "two".to_owned())
            .unwrap();
        let batch = reader.read(&reader.start(), usize::MAX).unwrap();
        assert!(batch.caught_up);
        assert_eq!(batch.items.len(), 2);
        let correlation = reader.correlate(&operation("op-1")).unwrap();
        assert_eq!(
            correlation
                .records
                .iter()
                .map(|(_, event)| event.payload().as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }
}
