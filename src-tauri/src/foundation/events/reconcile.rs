//! Receiving-side reconciliation (CORE-06 "duplicate/lost events reconcile"; GPU part
//! §3.10 "events can be lost or duplicated ... bounded reconciliation polling").
//!
//! Sequences make a repeated event idempotent and expose a missing one. Every gap closes
//! in one of three ways: the event arrives late or through a poll (recovered), the stream
//! says it was superseded, or it is marked lost explicitly and reported, with a reason.
//! Nothing is skipped silently.
//!
//! A remote receiver takes numbered deliveries ([`Reconciler::receive`]). A delivery's
//! resolved marks tell a delivered event from a superseded one only to a receiver that
//! holds every earlier delivery, so they are applied only then; until a missing delivery
//! arrives or is accounted for, they are held and the gaps they cover stay open. A
//! delivery that never arrives is lost explicitly, after bounded polling or through a
//! reconnect snapshot ([`Reconciler::resync`]), and every stream it may have carried then
//! closes its next gaps as lost rather than superseded.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{
    ConfigError, DeliveryNumber, DeliverySequence, EventEnvelope, EventSequence, ProducerId,
    ProducerIncarnation, ResolvedThrough, StreamKey, StreamKind,
};
use super::hub::Delivery;
use super::progress::ProgressSnapshot;
use crate::foundation::ids::MonotonicTime;

/// The streams a delivery carries.
const DELIVERED: [StreamKind; 3] = [
    StreamKind::Revocation,
    StreamKind::Progress,
    StreamKind::Metrics,
];

/// An inclusive range of sequences, `first` to `last`. Read back only through
/// [`SequenceRange::new`]'s check, so a stored range is never backward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SequenceRangeRecord", into = "SequenceRangeRecord")]
pub struct SequenceRange {
    first: EventSequence,
    last: EventSequence,
}

/// The stored form of a [`SequenceRange`].
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SequenceRangeRecord {
    first: EventSequence,
    last: EventSequence,
}

impl TryFrom<SequenceRangeRecord> for SequenceRange {
    type Error = BackwardRange;

    fn try_from(record: SequenceRangeRecord) -> Result<Self, Self::Error> {
        Self::new(record.first, record.last).ok_or(BackwardRange {
            first: record.first,
            last: record.last,
        })
    }
}

impl From<SequenceRange> for SequenceRangeRecord {
    fn from(range: SequenceRange) -> Self {
        Self {
            first: range.first,
            last: range.last,
        }
    }
}

/// A stored range whose `first` is after its `last`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackwardRange {
    pub first: EventSequence,
    pub last: EventSequence,
}

impl fmt::Display for BackwardRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the sequence range starts at {} after its end {}",
            self.first, self.last
        )
    }
}

impl std::error::Error for BackwardRange {}

impl SequenceRange {
    /// `None` when `first` is after `last`.
    pub fn new(first: EventSequence, last: EventSequence) -> Option<Self> {
        (first <= last).then_some(Self { first, last })
    }

    pub const fn single(sequence: EventSequence) -> Self {
        Self {
            first: sequence,
            last: sequence,
        }
    }

    pub const fn first(self) -> EventSequence {
        self.first
    }

    pub const fn last(self) -> EventSequence {
        self.last
    }

    /// How many sequences the range holds.
    pub const fn count(self) -> u64 {
        self.last
            .get()
            .saturating_sub(self.first.get())
            .saturating_add(1)
    }

    pub fn contains(self, sequence: EventSequence) -> bool {
        self.first <= sequence && sequence <= self.last
    }

    fn from_raw(first: u64, last: u64) -> Option<Self> {
        Self::new(EventSequence::new(first)?, EventSequence::new(last)?)
    }
}

impl fmt::Display for SequenceRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}–{}", self.first, self.last)
    }
}

/// Why events were marked lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossReason {
    /// Sampled out, dropped or expired on the lossy metrics stream, which counted them.
    MetricsDiscarded,
    /// The producer restarted before the gap was filled.
    ProducerRestarted,
    /// Bounded reconciliation polling ended without recovering them.
    RecoveryExhausted,
    /// The stream ran further ahead of its last contiguous sequence than the reconciler
    /// tracks.
    WindowExceeded,
    /// A delivery that may have carried them was lost, so they cannot be told apart from
    /// superseded ones.
    DeliveryLost,
}

/// Events marked lost explicitly, to be reported; for the audit stream, recorded as an
/// audit entry of their own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LostRange {
    pub key: StreamKey,
    pub range: SequenceRange,
    pub reason: LossReason,
}

/// How a stream says its undelivered sequences ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Lost, with a reason; counted and reported.
    Lost(LossReason),
    /// Replaced by a later state (progress) or covered by a later revocation; not a loss.
    Superseded,
}

/// What one received event was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// New and in order.
    Fresh,
    /// New, after a gap that is now open.
    FreshAfterGap { missing: SequenceRange },
    /// New, filling part of an open gap.
    Recovered,
    /// Already received or already resolved: apply nothing.
    Duplicate,
    /// From an incarnation a later one replaced: apply nothing.
    RetiredIncarnation,
}

impl Arrival {
    /// Whether the receiver applies the event.
    pub const fn is_new(self) -> bool {
        matches!(
            self,
            Self::Fresh | Self::FreshAfterGap { .. } | Self::Recovered
        )
    }
}

/// An arrival and any losses it made explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub arrival: Arrival,
    pub lost: Vec<LostRange>,
}

/// An inclusive run of deliveries of one hub epoch, `first` to `last`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryRange {
    pub epoch: ProducerIncarnation,
    pub first: DeliverySequence,
    pub last: DeliverySequence,
}

impl DeliveryRange {
    /// How many deliveries the run holds.
    pub const fn count(self) -> u64 {
        self.last
            .get()
            .saturating_sub(self.first.get())
            .saturating_add(1)
    }

    fn from_raw(epoch: ProducerIncarnation, first: u64, last: u64) -> Option<Self> {
        let first = DeliverySequence::new(first)?;
        let last = DeliverySequence::new(last)?;
        (first <= last).then_some(Self { epoch, first, last })
    }
}

/// How one numbered delivery arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryArrival {
    /// The next delivery.
    Fresh,
    /// Later than the next: the deliveries in `missing` have not arrived, so this one's
    /// marks wait for them.
    FreshAfterGap { missing: DeliveryRange },
    /// A missing delivery, late.
    Recovered,
    /// Already received or accounted for: its marks are not applied again.
    Duplicate,
    /// From a hub epoch a later one replaced: its marks are ignored.
    RetiredEpoch,
}

/// What one delivery or snapshot did on the receiving side. The receiver applies the
/// events whose arrival is new.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// How the delivery arrived; `None` for a snapshot.
    pub delivery: Option<DeliveryArrival>,
    /// One arrival per revocation notice, in delivery order.
    pub revocations: Vec<Arrival>,
    /// One arrival per progress update or snapshot state, in order.
    pub progress: Vec<Arrival>,
    /// One arrival per metric, in delivery order.
    pub metrics: Vec<Arrival>,
    /// Losses made explicit.
    pub lost: Vec<LostRange>,
    /// Deliveries now known to be lost. Revocations they carried are gone, so a receiver
    /// enforcing authorization reconciles with its authority, as after a revoke-all.
    pub lost_deliveries: Vec<DeliveryRange>,
}

/// Deliveries still missing. No delivery is sent twice, so a receiver answers this with a
/// reconnect snapshot ([`Reconciler::resync`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryPoll {
    pub missing: Vec<DeliveryRange>,
    /// 1 for the first poll of these deliveries.
    pub attempt: u32,
}

/// Bounds of the reconciler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileConfig {
    /// Producer streams tracked at most.
    pub max_streams: usize,
    /// How many sequences a stream may run past its last contiguous one before the oldest
    /// missing sequences are marked lost.
    pub window_sequences: u64,
    /// Polls per open gap before it is marked lost (bounded reconciliation polling).
    pub max_polls: u32,
    pub poll_interval: Duration,
}

impl ReconcileConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_streams == 0 {
            return Err(ConfigError::Zero {
                setting: "max_streams",
            });
        }
        if self.window_sequences == 0 {
            return Err(ConfigError::Zero {
                setting: "window_sequences",
            });
        }
        if self.poll_interval.is_zero() {
            return Err(ConfigError::Zero {
                setting: "poll_interval",
            });
        }
        Ok(())
    }
}

/// A request to ask a producer for the missing sequences of one stream again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollRequest {
    pub key: StreamKey,
    pub missing: Vec<SequenceRange>,
    /// 1 for the first poll of these gaps.
    pub attempt: u32,
}

/// The polls that are due and the gaps whose polls ran out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Polling {
    pub requests: Vec<PollRequest>,
    pub lost: Vec<LostRange>,
    /// Missing deliveries, polled like gaps.
    pub deliveries: Option<DeliveryPoll>,
    /// Missing deliveries whose polls ran out: lost.
    pub lost_deliveries: Vec<DeliveryRange>,
}

/// Why the reconciler refused to track a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileError {
    TooManyStreams { limit: usize },
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyStreams { limit } => {
                write!(f, "the reconciler already tracks {limit} producer streams")
            }
        }
    }
}

impl std::error::Error for ReconcileError {}

/// Counts of sequences by how they ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileTotals {
    pub fresh: u64,
    pub recovered: u64,
    pub duplicates: u64,
    pub retired: u64,
    pub lost: u64,
    pub superseded: u64,
    /// Numbered deliveries that never arrived.
    pub lost_deliveries: u64,
}

#[derive(Clone, Debug)]
struct StreamState {
    incarnation: ProducerIncarnation,
    /// Every sequence up to here is received or resolved.
    contiguous: u64,
    /// Sequences received above `contiguous`.
    received: BTreeSet<u64>,
    max_seen: u64,
    polls: u32,
    last_poll: Option<MonotonicTime>,
    /// The incarnation this one replaced, so the stream's later report of that
    /// incarnation's tail still closes it.
    retired: Option<Retired>,
    /// The earliest lost delivery that may have carried this stream's sequences: its next
    /// mark from a delivery closes its gaps as lost, not superseded.
    suspect_since: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct Retired {
    incarnation: ProducerIncarnation,
    /// Every sequence of the retired incarnation up to here is received or resolved.
    resolved: u64,
}

/// A producer stream's state as seen from one key.
enum Tracked<'a> {
    /// The key is the current incarnation; the losses are those a restart made explicit.
    Current(&'a mut StreamState, Vec<LostRange>),
    /// The key is from an incarnation a later one replaced.
    Retired,
}

/// How a mark's resolution is checked against lost deliveries.
#[derive(Clone, Copy, Debug)]
enum Check {
    /// Applied as given ([`Reconciler::resolve_through`]).
    AsGiven,
    /// From a delivery: a suspect stream closes its gaps as lost.
    Delivery,
    /// From a snapshot: a suspect stream closes its gaps as lost only if a state the hub
    /// forgot since may have travelled in the lost delivery.
    Snapshot { forgotten: Option<u64> },
}

/// One receiver's view of its hub's numbered deliveries, bounded like a stream.
#[derive(Clone, Debug, Default)]
struct Deliveries {
    /// The epoch being received; `None` before the first delivery or snapshot.
    epoch: Option<ProducerIncarnation>,
    /// Epochs up to here are retired.
    retired: Option<ProducerIncarnation>,
    /// Every delivery of the epoch up to here arrived or is accounted for.
    contiguous: u64,
    /// The highest delivery of the epoch that arrived or is accounted for.
    max_seen: u64,
    /// Deliveries above `contiguous` that arrived, with the marks they carried, held until
    /// every earlier delivery is accounted for.
    held: BTreeMap<u64, Vec<(ResolvedThrough, Resolution)>>,
    /// Per stream kind, the earliest lost delivery of the epoch: a stream first seen since
    /// may have had sequences in it.
    lost_since: BTreeMap<StreamKind, u64>,
    polls: u32,
    last_poll: Option<MonotonicTime>,
}

impl Deliveries {
    fn is_retired(&self, epoch: ProducerIncarnation) -> bool {
        self.retired.is_some_and(|retired| epoch <= retired)
            || self.epoch.is_some_and(|current| epoch < current)
    }

    /// The deliveries of the epoch up to `through` that neither arrived nor are accounted
    /// for.
    fn missing(&self, through: u64) -> Vec<DeliveryRange> {
        let Some(epoch) = self.epoch else {
            return Vec::new();
        };
        let mut missing = Vec::new();
        let mut next = self.contiguous.saturating_add(1);
        for &held in self.held.range(..=through).map(|(held, _)| held) {
            if held > next {
                missing.extend(DeliveryRange::from_raw(epoch, next, held - 1));
            }
            next = held.saturating_add(1);
        }
        if next <= through {
            missing.extend(DeliveryRange::from_raw(epoch, next, through));
        }
        missing
    }
}

impl StreamState {
    fn new(incarnation: ProducerIncarnation) -> Self {
        Self {
            incarnation,
            contiguous: 0,
            received: BTreeSet::new(),
            max_seen: 0,
            polls: 0,
            last_poll: None,
            retired: None,
            suspect_since: None,
        }
    }

    fn gaps(&self) -> Vec<SequenceRange> {
        let mut gaps = Vec::new();
        let mut next = self.contiguous.saturating_add(1);
        for &received in &self.received {
            if received > next {
                gaps.extend(SequenceRange::from_raw(next, received - 1));
            }
            next = received.saturating_add(1);
        }
        gaps
    }

    fn advance(&mut self) {
        while let Some(next) = self.contiguous.checked_add(1) {
            if !self.received.remove(&next) {
                break;
            }
            self.contiguous = next;
        }
        if self.received.is_empty() {
            self.polls = 0;
            self.last_poll = None;
        }
    }

    /// Resolves every missing sequence up to `through`; returns what was missing.
    fn resolve_to(&mut self, through: u64) -> Vec<SequenceRange> {
        if through <= self.contiguous {
            return Vec::new();
        }
        let below: Vec<u64> = self.received.range(..=through).copied().collect();
        let mut resolved = Vec::new();
        let mut next = self.contiguous.saturating_add(1);
        for &received in &below {
            if received > next {
                resolved.extend(SequenceRange::from_raw(next, received - 1));
            }
            next = received.saturating_add(1);
        }
        if next <= through {
            resolved.extend(SequenceRange::from_raw(next, through));
        }
        for received in below {
            self.received.remove(&received);
        }
        self.contiguous = through;
        self.max_seen = self.max_seen.max(through);
        self.advance();
        resolved
    }
}

/// Tracks, per producer stream, which sequences arrived, and resolves the rest (CORE-06).
#[derive(Clone, Debug)]
pub struct Reconciler {
    config: ReconcileConfig,
    streams: BTreeMap<(ProducerId, StreamKind), StreamState>,
    deliveries: Deliveries,
    totals: ReconcileTotals,
}

impl Reconciler {
    pub fn new(config: ReconcileConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            streams: BTreeMap::new(),
            deliveries: Deliveries::default(),
            totals: ReconcileTotals::default(),
        })
    }

    /// Records one received event. A duplicate or an event from a retired incarnation is
    /// to be ignored; a later incarnation marks the earlier one's open gaps lost.
    pub fn observe(
        &mut self,
        key: &StreamKey,
        sequence: EventSequence,
    ) -> Result<Observed, ReconcileError> {
        let window = self.config.window_sequences;
        let suspect = self.suspect_new(key.stream);
        let Tracked::Current(state, mut lost) = stream_state(
            &mut self.streams,
            self.config.max_streams,
            key,
            &mut self.totals,
            suspect,
        )?
        else {
            self.totals.retired = self.totals.retired.saturating_add(1);
            return Ok(Observed {
                arrival: Arrival::RetiredIncarnation,
                lost: Vec::new(),
            });
        };
        let value = sequence.get();
        let arrival = if value <= state.contiguous || state.received.contains(&value) {
            Arrival::Duplicate
        } else if value <= state.max_seen {
            Arrival::Recovered
        } else if state.max_seen.checked_add(1) == Some(value) {
            Arrival::Fresh
        } else {
            match SequenceRange::from_raw(state.max_seen.saturating_add(1), value - 1) {
                Some(missing) => Arrival::FreshAfterGap { missing },
                None => Arrival::Fresh,
            }
        };
        match arrival {
            Arrival::Duplicate => {
                self.totals.duplicates = self.totals.duplicates.saturating_add(1);
                return Ok(Observed { arrival, lost });
            }
            Arrival::Recovered => self.totals.recovered = self.totals.recovered.saturating_add(1),
            _ => self.totals.fresh = self.totals.fresh.saturating_add(1),
        }
        if state.contiguous.checked_add(1) == Some(value) {
            state.contiguous = value;
        } else {
            state.received.insert(value);
        }
        state.max_seen = state.max_seen.max(value);
        state.advance();
        while state.max_seen.saturating_sub(state.contiguous) > window {
            let Some(&next_received) = state.received.iter().next() else {
                break;
            };
            let Some(range) =
                SequenceRange::from_raw(state.contiguous.saturating_add(1), next_received - 1)
            else {
                break;
            };
            self.totals.lost = self.totals.lost.saturating_add(range.count());
            lost.push(LostRange {
                key: key.clone(),
                range,
                reason: LossReason::WindowExceeded,
            });
            state.contiguous = next_received - 1;
            state.advance();
        }
        Ok(Observed { arrival, lost })
    }

    /// [`Reconciler::observe`] for a received envelope.
    pub fn observe_event<P>(
        &mut self,
        event: &EventEnvelope<P>,
    ) -> Result<Observed, ReconcileError> {
        self.observe(&event.key(), event.sequence())
    }

    /// Closes every gap of `resolved.key` up to `resolved.through` as `resolution` says,
    /// including the tail of the incarnation a restart just replaced. Losses come back as
    /// explicit ranges; superseded sequences are only counted.
    pub fn resolve_through(
        &mut self,
        resolved: &ResolvedThrough,
        resolution: Resolution,
    ) -> Result<Vec<LostRange>, ReconcileError> {
        let mut lost = self.track(&resolved.key)?;
        lost.extend(self.close(resolved, resolution, Check::AsGiven));
        Ok(lost)
    }

    /// Receives one numbered delivery from an [`EventHub`](super::EventHub): observes its
    /// revocations, progress and metrics in order, then applies its resolved marks —
    /// revocations and progress as superseded, metrics as discarded — but only once every
    /// earlier delivery of its epoch arrived or is accounted for. Until then the marks are
    /// held and the gaps they cover stay open, because a lost delivery's events cannot be
    /// told from superseded ones. Missing deliveries are polled by [`Reconciler::poll`].
    pub fn receive(&mut self, delivery: &Delivery) -> Result<Received, ReconcileError> {
        let marks = delivery_marks(delivery);
        self.ensure_room(
            delivery
                .revocations
                .notices
                .iter()
                .map(|event| (event.provenance().producer(), event.stream()))
                .chain(
                    delivery
                        .revocations
                        .grants
                        .iter()
                        .map(|event| (event.provenance().producer(), event.stream())),
                )
                .chain(
                    delivery
                        .progress
                        .updates
                        .iter()
                        .map(|event| (event.provenance().producer(), event.stream())),
                )
                .chain(
                    delivery
                        .metrics
                        .events
                        .iter()
                        .map(|event| (event.provenance().producer(), event.stream())),
                )
                .chain(
                    marks
                        .iter()
                        .map(|(mark, _)| (&mark.key.producer, mark.key.stream)),
                ),
        )?;
        let mut received = Received::default();
        let arrival = self.arrive(delivery.number, &mut received);
        received.delivery = Some(arrival);
        for event in &delivery.revocations.notices {
            let observed = self.observe_event(event)?;
            received.revocations.push(observed.arrival);
            received.lost.extend(observed.lost);
        }
        for event in &delivery.revocations.grants {
            let observed = self.observe_event(event)?;
            received.revocations.push(observed.arrival);
            received.lost.extend(observed.lost);
        }
        for event in &delivery.progress.updates {
            let observed = self.observe_event(event)?;
            received.progress.push(observed.arrival);
            received.lost.extend(observed.lost);
        }
        for event in &delivery.metrics.events {
            let observed = self.observe_event(event)?;
            received.metrics.push(observed.arrival);
            received.lost.extend(observed.lost);
        }
        if matches!(
            arrival,
            DeliveryArrival::Duplicate | DeliveryArrival::RetiredEpoch
        ) {
            return Ok(received);
        }
        // Every stream a held mark names exists from now on, so releasing it later needs
        // no room.
        for (mark, _) in &marks {
            received.lost.extend(self.track(&mark.key)?);
        }
        let sequence = delivery.number.sequence.get();
        self.deliveries.held.insert(sequence, marks);
        self.deliveries.max_seen = self.deliveries.max_seen.max(sequence);
        while self
            .deliveries
            .max_seen
            .saturating_sub(self.deliveries.contiguous)
            > self.config.window_sequences
        {
            // Too far ahead: the oldest missing deliveries are lost.
            let Some(&first_held) = self.deliveries.held.keys().next() else {
                break;
            };
            self.account_through(
                first_held - 1,
                false,
                &mut received.lost,
                &mut received.lost_deliveries,
            );
            self.release_held(&mut received.lost);
        }
        self.release_held(&mut received.lost);
        Ok(received)
    }

    /// Applies a reconnect snapshot from the receiver's hub (GPU part §3.10): observes its
    /// states, accounts for every delivery up to the one it follows — those that have not
    /// arrived by then are lost — and closes each progress stream's gaps up to its mark as
    /// superseded, or as lost where a state the hub has forgotten since may have travelled
    /// in a lost delivery. Revocation and metrics streams, which a snapshot does not carry,
    /// stay suspect until their next mark. A snapshot of a retired epoch changes nothing.
    pub fn resync(&mut self, snapshot: &ProgressSnapshot) -> Result<Received, ReconcileError> {
        let mut received = Received::default();
        if snapshot
            .after
            .is_some_and(|after| self.deliveries.is_retired(after.epoch))
        {
            return Ok(received);
        }
        self.ensure_room(
            snapshot
                .states
                .iter()
                .map(|event| (event.provenance().producer(), event.stream()))
                .chain(
                    snapshot
                        .resolved
                        .iter()
                        .map(|mark| (&mark.key.producer, mark.key.stream)),
                ),
        )?;
        // States first, so that whatever they fill is never closed as a gap.
        for state in &snapshot.states {
            let observed = self.observe_event(state)?;
            received.progress.push(observed.arrival);
            received.lost.extend(observed.lost);
        }
        match snapshot.after {
            Some(after) if self.deliveries.epoch == Some(after.epoch) => {
                // The snapshot supersedes the held progress marks it covers.
                self.account_through(
                    after.sequence.get(),
                    true,
                    &mut received.lost,
                    &mut received.lost_deliveries,
                );
            }
            Some(after) => self.start_epoch(after.epoch, after.sequence.get(), &mut received),
            None => {
                // A hub that made no delivery yet replaced the epoch being received.
                if let Some(epoch) = self.deliveries.epoch {
                    let through = self.deliveries.max_seen;
                    self.account_through(
                        through,
                        false,
                        &mut received.lost,
                        &mut received.lost_deliveries,
                    );
                    self.deliveries = Deliveries {
                        retired: Some(epoch),
                        ..Deliveries::default()
                    };
                    self.clear_suspicion();
                }
            }
        }
        let forgotten = snapshot.forgotten.map(DeliverySequence::get);
        for mark in &snapshot.resolved {
            received.lost.extend(self.track(&mark.key)?);
            received.lost.extend(self.close(
                mark,
                Resolution::Superseded,
                Check::Snapshot { forgotten },
            ));
        }
        // The snapshot carried every progress stream of its hub.
        self.deliveries.lost_since.remove(&StreamKind::Progress);
        self.release_held(&mut received.lost);
        Ok(received)
    }

    /// Bounded reconciliation polling: each stream with open gaps is polled at most every
    /// `poll_interval`, `max_polls` times; after that its gaps are marked lost. Missing
    /// deliveries are polled the same way; once their polls run out they are lost, the
    /// marks held behind them are applied, and every stream they may have carried closes
    /// its gaps as lost.
    pub fn poll(&mut self, now: MonotonicTime) -> Polling {
        let mut polling = Polling::default();
        let missing = self.deliveries.missing(self.deliveries.max_seen);
        let due = !self
            .deliveries
            .last_poll
            .is_some_and(|last| now.saturating_duration_since(last) < self.config.poll_interval);
        if !missing.is_empty() && due {
            if self.deliveries.polls < self.config.max_polls {
                self.deliveries.polls += 1;
                self.deliveries.last_poll = Some(now);
                polling.deliveries = Some(DeliveryPoll {
                    missing,
                    attempt: self.deliveries.polls,
                });
            } else {
                let through = self.deliveries.max_seen;
                self.account_through(
                    through,
                    false,
                    &mut polling.lost,
                    &mut polling.lost_deliveries,
                );
                self.release_held(&mut polling.lost);
            }
        }
        for ((producer, stream), state) in &mut self.streams {
            let gaps = state.gaps();
            if gaps.is_empty() {
                continue;
            }
            if state
                .last_poll
                .is_some_and(|last| now.saturating_duration_since(last) < self.config.poll_interval)
            {
                continue;
            }
            let key = StreamKey {
                producer: producer.clone(),
                incarnation: state.incarnation,
                stream: *stream,
            };
            if state.polls < self.config.max_polls {
                state.polls += 1;
                state.last_poll = Some(now);
                polling.requests.push(PollRequest {
                    key,
                    missing: gaps,
                    attempt: state.polls,
                });
            } else {
                for range in gaps {
                    self.totals.lost = self.totals.lost.saturating_add(range.count());
                    polling.lost.push(LostRange {
                        key: key.clone(),
                        range,
                        reason: LossReason::RecoveryExhausted,
                    });
                }
                state.contiguous = state.max_seen;
                state.received.clear();
                state.advance();
            }
        }
        polling
    }

    /// Every open gap.
    pub fn gaps(&self) -> Vec<(StreamKey, SequenceRange)> {
        self.streams
            .iter()
            .flat_map(|((producer, stream), state)| {
                let key = StreamKey {
                    producer: producer.clone(),
                    incarnation: state.incarnation,
                    stream: *stream,
                };
                state
                    .gaps()
                    .into_iter()
                    .map(move |range| (key.clone(), range))
            })
            .collect()
    }

    pub fn totals(&self) -> ReconcileTotals {
        self.totals
    }

    /// Deliveries of the current epoch that have neither arrived nor been accounted for.
    pub fn missing_deliveries(&self) -> Vec<DeliveryRange> {
        self.deliveries.missing(self.deliveries.max_seen)
    }

    /// The suspicion a stream of `kind` starts with: a stream first seen after a lost
    /// delivery may have had sequences in it.
    fn suspect_new(&self, kind: StreamKind) -> Option<u64> {
        self.deliveries.lost_since.get(&kind).copied()
    }

    /// Refuses, before anything changes, a delivery or snapshot that would need more
    /// streams than the bound.
    fn ensure_room<'k>(
        &self,
        keys: impl IntoIterator<Item = (&'k ProducerId, StreamKind)>,
    ) -> Result<(), ReconcileError> {
        let fresh: BTreeSet<(&ProducerId, StreamKind)> = keys
            .into_iter()
            .filter(|(producer, stream)| {
                !self.streams.contains_key(&((*producer).clone(), *stream))
            })
            .collect();
        if self.streams.len().saturating_add(fresh.len()) > self.config.max_streams {
            return Err(ReconcileError::TooManyStreams {
                limit: self.config.max_streams,
            });
        }
        Ok(())
    }

    /// Creates or updates the stream of `key`; returns the losses a restart made explicit.
    fn track(&mut self, key: &StreamKey) -> Result<Vec<LostRange>, ReconcileError> {
        let suspect = self.suspect_new(key.stream);
        Ok(
            match stream_state(
                &mut self.streams,
                self.config.max_streams,
                key,
                &mut self.totals,
                suspect,
            )? {
                Tracked::Current(_, lost) => lost,
                Tracked::Retired => Vec::new(),
            },
        )
    }

    /// Closes the gaps of a tracked stream up to `resolved`, as `resolution` and `check`
    /// say. An untracked stream is left alone, so nothing closes.
    fn close(
        &mut self,
        resolved: &ResolvedThrough,
        resolution: Resolution,
        check: Check,
    ) -> Vec<LostRange> {
        let through = resolved.through.get();
        let key = (resolved.key.producer.clone(), resolved.key.stream);
        let Some(state) = self.streams.get_mut(&key) else {
            return Vec::new();
        };
        let suspect = match check {
            Check::AsGiven => false,
            Check::Delivery => state.suspect_since.is_some(),
            Check::Snapshot { forgotten } => state
                .suspect_since
                .is_some_and(|since| forgotten.is_some_and(|forgotten| forgotten >= since)),
        };
        let resolution = if suspect {
            Resolution::Lost(LossReason::DeliveryLost)
        } else {
            resolution
        };
        let ranges: Vec<SequenceRange> = if resolved.key.incarnation == state.incarnation {
            if !matches!(check, Check::AsGiven) {
                state.suspect_since = None;
            }
            state.resolve_to(through)
        } else if resolved.key.incarnation < state.incarnation {
            match state.retired.as_mut() {
                Some(retired)
                    if retired.incarnation == resolved.key.incarnation
                        && through > retired.resolved =>
                {
                    let tail = SequenceRange::from_raw(retired.resolved.saturating_add(1), through);
                    retired.resolved = through;
                    tail.into_iter().collect()
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let mut lost = Vec::new();
        for range in ranges {
            match resolution {
                Resolution::Lost(reason) => {
                    self.totals.lost = self.totals.lost.saturating_add(range.count());
                    lost.push(LostRange {
                        key: resolved.key.clone(),
                        range,
                        reason,
                    });
                }
                Resolution::Superseded => {
                    self.totals.superseded = self.totals.superseded.saturating_add(range.count());
                }
            }
        }
        lost
    }

    /// Classifies a delivery's number, starting a later epoch when it shows one.
    fn arrive(&mut self, number: DeliveryNumber, received: &mut Received) -> DeliveryArrival {
        if self.deliveries.is_retired(number.epoch) {
            return DeliveryArrival::RetiredEpoch;
        }
        if self.deliveries.epoch != Some(number.epoch) {
            self.start_epoch(number.epoch, 0, received);
        }
        let deliveries = &self.deliveries;
        let value = number.sequence.get();
        if value <= deliveries.contiguous || deliveries.held.contains_key(&value) {
            DeliveryArrival::Duplicate
        } else if value <= deliveries.max_seen {
            DeliveryArrival::Recovered
        } else {
            match DeliveryRange::from_raw(
                number.epoch,
                deliveries.max_seen.saturating_add(1),
                value - 1,
            ) {
                Some(missing) => DeliveryArrival::FreshAfterGap { missing },
                None => DeliveryArrival::Fresh,
            }
        }
    }

    /// Leaves the current epoch, whose missing deliveries are lost, for `epoch`, whose
    /// deliveries up to `start` this receiver takes as accounted for.
    fn start_epoch(&mut self, epoch: ProducerIncarnation, start: u64, received: &mut Received) {
        let previous = self.deliveries.epoch;
        if previous.is_some() {
            let through = self.deliveries.max_seen;
            self.account_through(
                through,
                false,
                &mut received.lost,
                &mut received.lost_deliveries,
            );
        }
        self.deliveries = Deliveries {
            epoch: Some(epoch),
            retired: self.deliveries.retired.max(previous),
            contiguous: start,
            max_seen: start,
            ..Deliveries::default()
        };
        // Suspicion counts deliveries of the epoch it was raised in.
        self.clear_suspicion();
    }

    fn clear_suspicion(&mut self) {
        for state in self.streams.values_mut() {
            state.suspect_since = None;
        }
    }

    /// Accounts for every delivery of the epoch up to `through`: those missing are lost,
    /// explicitly, and every stream a delivery carries becomes suspect; the marks held
    /// from those that arrived are then applied in order, except progress marks when
    /// `skip_progress` (a snapshot supersedes them).
    fn account_through(
        &mut self,
        through: u64,
        skip_progress: bool,
        lost: &mut Vec<LostRange>,
        lost_deliveries: &mut Vec<DeliveryRange>,
    ) {
        if through <= self.deliveries.contiguous {
            return;
        }
        let missing = self.deliveries.missing(through);
        if let Some(first) = missing.first().map(|range| range.first.get()) {
            let count = missing
                .iter()
                .fold(0u64, |count, range| count.saturating_add(range.count()));
            self.totals.lost_deliveries = self.totals.lost_deliveries.saturating_add(count);
            lost_deliveries.extend(missing);
            for kind in DELIVERED {
                let since = self.deliveries.lost_since.entry(kind).or_insert(first);
                *since = (*since).min(first);
            }
            for ((_, kind), state) in &mut self.streams {
                if DELIVERED.contains(kind) {
                    state.suspect_since =
                        Some(state.suspect_since.map_or(first, |since| since.min(first)));
                }
            }
        }
        let later = match through.checked_add(1) {
            Some(next) => self.deliveries.held.split_off(&next),
            None => BTreeMap::new(),
        };
        let accounted = std::mem::replace(&mut self.deliveries.held, later);
        for marks in accounted.into_values() {
            for (mark, resolution) in marks {
                if skip_progress && mark.key.stream == StreamKind::Progress {
                    continue;
                }
                lost.extend(self.close(&mark, resolution, Check::Delivery));
            }
        }
        self.deliveries.contiguous = through;
        self.deliveries.max_seen = self.deliveries.max_seen.max(through);
    }

    /// Applies, in order, the held marks of every delivery that is now next.
    fn release_held(&mut self, lost: &mut Vec<LostRange>) {
        while let Some(next) = self.deliveries.contiguous.checked_add(1) {
            let Some(marks) = self.deliveries.held.remove(&next) else {
                break;
            };
            self.deliveries.contiguous = next;
            for (mark, resolution) in marks {
                lost.extend(self.close(&mark, resolution, Check::Delivery));
            }
        }
        if self.deliveries.contiguous >= self.deliveries.max_seen {
            self.deliveries.polls = 0;
            self.deliveries.last_poll = None;
        }
    }
}

/// A delivery's resolved marks with the resolution each stream gives them.
fn delivery_marks(delivery: &Delivery) -> Vec<(ResolvedThrough, Resolution)> {
    delivery
        .revocations
        .resolved
        .iter()
        .chain(&delivery.progress.resolved)
        .map(|mark| (mark.clone(), Resolution::Superseded))
        .chain(
            delivery
                .metrics
                .resolved
                .iter()
                .map(|mark| (mark.clone(), Resolution::Lost(LossReason::MetricsDiscarded))),
        )
        .collect()
}

/// The state of `key`'s producer stream, created if new, with `suspect` as its suspicion.
/// A later incarnation replaces the state, marks the earlier one's open gaps lost and
/// remembers how far it got.
fn stream_state<'a>(
    streams: &'a mut BTreeMap<(ProducerId, StreamKind), StreamState>,
    max_streams: usize,
    key: &StreamKey,
    totals: &mut ReconcileTotals,
    suspect: Option<u64>,
) -> Result<Tracked<'a>, ReconcileError> {
    let tracked = streams.len();
    let state = match streams.entry((key.producer.clone(), key.stream)) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            if tracked >= max_streams {
                return Err(ReconcileError::TooManyStreams { limit: max_streams });
            }
            entry.insert(StreamState {
                suspect_since: suspect,
                ..StreamState::new(key.incarnation)
            })
        }
    };
    if key.incarnation < state.incarnation {
        return Ok(Tracked::Retired);
    }
    let mut lost = Vec::new();
    if key.incarnation > state.incarnation {
        let earlier = StreamKey {
            producer: key.producer.clone(),
            incarnation: state.incarnation,
            stream: key.stream,
        };
        for range in state.gaps() {
            totals.lost = totals.lost.saturating_add(range.count());
            lost.push(LostRange {
                key: earlier.clone(),
                range,
                reason: LossReason::ProducerRestarted,
            });
        }
        let retired = Retired {
            incarnation: state.incarnation,
            resolved: state.max_seen,
        };
        *state = StreamState {
            retired: Some(retired),
            suspect_since: suspect,
            ..StreamState::new(key.incarnation)
        };
    }
    Ok(Tracked::Current(state, lost))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::fakes::producer;

    fn config() -> ReconcileConfig {
        ReconcileConfig {
            max_streams: 4,
            window_sequences: 100,
            max_polls: 2,
            poll_interval: Duration::from_secs(1),
        }
    }

    fn key(incarnation: u64) -> StreamKey {
        StreamKey {
            producer: producer("warden"),
            incarnation: ProducerIncarnation::new(incarnation).unwrap(),
            stream: StreamKind::Audit,
        }
    }

    fn seq(value: u64) -> EventSequence {
        EventSequence::new(value).unwrap()
    }

    fn range(first: u64, last: u64) -> SequenceRange {
        SequenceRange::from_raw(first, last).unwrap()
    }

    fn arrive(reconciler: &mut Reconciler, incarnation: u64, value: u64) -> Arrival {
        reconciler
            .observe(&key(incarnation), seq(value))
            .unwrap()
            .arrival
    }

    #[test]
    fn duplicates_are_ignored() {
        let mut reconciler = Reconciler::new(config()).unwrap();
        assert_eq!(arrive(&mut reconciler, 1, 1), Arrival::Fresh);
        assert_eq!(arrive(&mut reconciler, 1, 2), Arrival::Fresh);
        assert_eq!(arrive(&mut reconciler, 1, 2), Arrival::Duplicate);
        assert_eq!(arrive(&mut reconciler, 1, 1), Arrival::Duplicate);
        assert_eq!(
            arrive(&mut reconciler, 1, 4),
            Arrival::FreshAfterGap {
                missing: range(3, 3)
            }
        );
        // A duplicate above a gap is ignored too.
        assert_eq!(arrive(&mut reconciler, 1, 4), Arrival::Duplicate);
        assert!(!Arrival::Duplicate.is_new());
        let totals = reconciler.totals();
        assert_eq!((totals.fresh, totals.duplicates), (3, 3));
    }

    #[test]
    fn gaps_are_detected_and_recovered() {
        let mut reconciler = Reconciler::new(config()).unwrap();
        arrive(&mut reconciler, 1, 1);
        assert_eq!(
            arrive(&mut reconciler, 1, 5),
            Arrival::FreshAfterGap {
                missing: range(2, 4)
            }
        );
        assert_eq!(
            arrive(&mut reconciler, 1, 8),
            Arrival::FreshAfterGap {
                missing: range(6, 7)
            }
        );
        assert_eq!(
            reconciler.gaps(),
            [(key(1), range(2, 4)), (key(1), range(6, 7))]
        );
        assert_eq!(arrive(&mut reconciler, 1, 3), Arrival::Recovered);
        assert_eq!(
            reconciler.gaps(),
            [
                (key(1), range(2, 2)),
                (key(1), range(4, 4)),
                (key(1), range(6, 7))
            ]
        );
        for value in [2, 4, 6, 7] {
            assert_eq!(arrive(&mut reconciler, 1, value), Arrival::Recovered);
        }
        assert!(reconciler.gaps().is_empty());
        assert_eq!(reconciler.totals().recovered, 5);
        assert_eq!(reconciler.totals().lost, 0);
    }

    #[test]
    fn unrecovered_gaps_are_marked_lost_after_bounded_polling() {
        let mut reconciler = Reconciler::new(config()).unwrap();
        arrive(&mut reconciler, 1, 1);
        arrive(&mut reconciler, 1, 4);
        let start = MonotonicTime::from_nanos(1_000_000_000);
        let first = reconciler.poll(start);
        assert_eq!(
            first.requests,
            [PollRequest {
                key: key(1),
                missing: vec![range(2, 3)],
                attempt: 1
            }]
        );
        // Not due again within the interval.
        assert_eq!(
            reconciler.poll(start.saturating_add(Duration::from_millis(500))),
            Polling::default()
        );
        // A poll recovers one of the two.
        assert_eq!(arrive(&mut reconciler, 1, 2), Arrival::Recovered);
        let second = reconciler.poll(start.saturating_add(Duration::from_secs(1)));
        assert_eq!(second.requests[0].missing, [range(3, 3)]);
        assert_eq!(second.requests[0].attempt, 2);
        // The polls ran out: the rest is marked lost, explicitly and with its reason.
        let third = reconciler.poll(start.saturating_add(Duration::from_secs(2)));
        assert!(third.requests.is_empty());
        assert_eq!(
            third.lost,
            [LostRange {
                key: key(1),
                range: range(3, 3),
                reason: LossReason::RecoveryExhausted
            }]
        );
        assert!(reconciler.gaps().is_empty());
        assert_eq!(reconciler.totals().lost, 1);
        // The lost sequence arriving afterwards is a duplicate, never applied twice.
        assert_eq!(arrive(&mut reconciler, 1, 3), Arrival::Duplicate);
        assert_eq!(arrive(&mut reconciler, 1, 5), Arrival::Fresh);
    }

    #[test]
    fn a_restart_marks_open_gaps_lost_and_retires_the_earlier_incarnation() {
        let mut reconciler = Reconciler::new(config()).unwrap();
        arrive(&mut reconciler, 1, 1);
        arrive(&mut reconciler, 1, 3);
        let observed = reconciler.observe(&key(2), seq(1)).unwrap();
        assert_eq!(observed.arrival, Arrival::Fresh);
        assert_eq!(
            observed.lost,
            [LostRange {
                key: key(1),
                range: range(2, 2),
                reason: LossReason::ProducerRestarted
            }]
        );
        assert_eq!(arrive(&mut reconciler, 1, 2), Arrival::RetiredIncarnation);
        assert_eq!(arrive(&mut reconciler, 2, 2), Arrival::Fresh);
        assert_eq!(reconciler.totals().retired, 1);
    }

    #[test]
    fn the_tail_of_a_retired_incarnation_is_still_closed_explicitly() {
        let mut reconciler = Reconciler::new(config()).unwrap();
        arrive(&mut reconciler, 1, 1);
        arrive(&mut reconciler, 1, 2);
        arrive(&mut reconciler, 2, 1);
        // The stream reports later that incarnation 1 ran to 5: 3 to 5 never arrived.
        let lost = reconciler
            .resolve_through(
                &ResolvedThrough {
                    key: key(1),
                    through: seq(5),
                },
                Resolution::Lost(LossReason::MetricsDiscarded),
            )
            .unwrap();
        assert_eq!(
            lost,
            [LostRange {
                key: key(1),
                range: range(3, 5),
                reason: LossReason::MetricsDiscarded
            }]
        );
        // Reported again, it changes nothing; the current incarnation is untouched.
        assert!(reconciler
            .resolve_through(
                &ResolvedThrough {
                    key: key(1),
                    through: seq(5),
                },
                Resolution::Lost(LossReason::MetricsDiscarded),
            )
            .unwrap()
            .is_empty());
        assert_eq!(reconciler.totals().lost, 3);
        assert_eq!(arrive(&mut reconciler, 2, 2), Arrival::Fresh);
    }

    #[test]
    fn running_past_the_window_marks_the_oldest_missing_lost() {
        let mut reconciler = Reconciler::new(ReconcileConfig {
            window_sequences: 3,
            ..config()
        })
        .unwrap();
        arrive(&mut reconciler, 1, 1);
        let observed = reconciler.observe(&key(1), seq(6)).unwrap();
        assert_eq!(
            observed.lost,
            [LostRange {
                key: key(1),
                range: range(2, 5),
                reason: LossReason::WindowExceeded
            }]
        );
        assert!(reconciler.gaps().is_empty());
        arrive(&mut reconciler, 1, 8);
        assert_eq!(reconciler.gaps(), [(key(1), range(7, 7))]);
    }

    #[test]
    fn a_stream_resolution_closes_gaps_as_lost_or_superseded() {
        let mut reconciler = Reconciler::new(config()).unwrap();
        arrive(&mut reconciler, 1, 2);
        arrive(&mut reconciler, 1, 5);
        let lost = reconciler
            .resolve_through(
                &ResolvedThrough {
                    key: key(1),
                    through: seq(7),
                },
                Resolution::Lost(LossReason::MetricsDiscarded),
            )
            .unwrap();
        let ranges: Vec<SequenceRange> = lost.iter().map(|lost| lost.range).collect();
        assert_eq!(ranges, [range(1, 1), range(3, 4), range(6, 7)]);
        assert_eq!(reconciler.totals().lost, 5);
        assert_eq!(arrive(&mut reconciler, 1, 7), Arrival::Duplicate);
        assert_eq!(
            arrive(&mut reconciler, 1, 9),
            Arrival::FreshAfterGap {
                missing: range(8, 8)
            }
        );
        let superseded = reconciler
            .resolve_through(
                &ResolvedThrough {
                    key: key(1),
                    through: seq(9),
                },
                Resolution::Superseded,
            )
            .unwrap();
        assert!(superseded.is_empty());
        assert_eq!(reconciler.totals().superseded, 1);
        assert!(reconciler.gaps().is_empty());
        // Resolving what is already resolved changes nothing.
        assert!(reconciler
            .resolve_through(
                &ResolvedThrough {
                    key: key(1),
                    through: seq(3),
                },
                Resolution::Lost(LossReason::MetricsDiscarded),
            )
            .unwrap()
            .is_empty());
    }

    #[test]
    fn the_number_of_streams_is_bounded() {
        let mut reconciler = Reconciler::new(ReconcileConfig {
            max_streams: 1,
            ..config()
        })
        .unwrap();
        arrive(&mut reconciler, 1, 1);
        let other = StreamKey {
            stream: StreamKind::Metrics,
            ..key(1)
        };
        assert_eq!(
            reconciler.observe(&other, seq(1)),
            Err(ReconcileError::TooManyStreams { limit: 1 })
        );
        assert_eq!(
            Reconciler::new(ReconcileConfig {
                window_sequences: 0,
                ..config()
            })
            .err(),
            Some(ConfigError::Zero {
                setting: "window_sequences"
            })
        );
        assert_eq!(range(3, 5).count(), 3);
        assert!(range(3, 5).contains(seq(4)));
        assert_eq!(SequenceRange::new(seq(5), seq(3)), None);
        assert_eq!(SequenceRange::single(seq(2)).count(), 1);
    }

    #[test]
    fn a_stored_range_reads_back_only_in_order() {
        let stored = serde_json::to_string(&range(3, 5)).unwrap();
        assert_eq!(stored, r#"{"first":3,"last":5}"#);
        assert_eq!(
            serde_json::from_str::<SequenceRange>(&stored).unwrap(),
            range(3, 5)
        );
        assert_eq!(
            serde_json::from_str::<SequenceRange>(r#"{"first":4,"last":4}"#).unwrap(),
            SequenceRange::single(seq(4))
        );
        for refused in [
            r#"{"first":7,"last":5}"#,
            r#"{"first":0,"last":5}"#,
            r#"{"first":3,"last":5,"extra":1}"#,
        ] {
            assert!(
                serde_json::from_str::<SequenceRange>(refused).is_err(),
                "{refused} was read back"
            );
        }
    }
}
