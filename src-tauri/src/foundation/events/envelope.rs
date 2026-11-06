//! The common CORE-06 envelope: operation identity, typed generations, a monotonic
//! sequence per producer incarnation and stream, phase and provenance.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::progress::ProgressRefusal;
use crate::foundation::evidence::{
    Capability, ClockSession, ConfigurationFingerprint, EvidenceEnvelope, SourceClass,
};
use crate::foundation::ids::{
    AuthorizationEpoch, Digest, GpuAllocationGeneration, IdError, ModelActivationGeneration,
    MonotonicTime, OperationId, PolicyEpoch, SandboxBootGeneration,
};

/// Applies the ids.rs identifier grammar: 1–128 letters, digits, '.', '_', ':' or '-',
/// starting with a letter or digit. ids.rs keeps its checker private, so the grammar is
/// applied through one of its public constructors instead of being copied here.
pub(super) fn check_name(value: &str) -> Result<(), IdError> {
    OperationId::new(value).map(drop)
}

name_type!(
    /// The component that emits events, such as `engine`, `warden` or `runner.vllm-1`
    /// (CORE-06 provenance: producer).
    ProducerId
);

/// One registration of a producer on one stream (CORE-06 monotonic sequence; S7 restart
/// recovery). Registering again gets a later incarnation whose sequence restarts at 1, so
/// a receiver never mistakes a restarted producer's events for duplicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProducerIncarnation(NonZeroU64);

impl ProducerIncarnation {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// `None` for zero.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The following incarnation; `None` at `u64::MAX`, which is never wrapped.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for ProducerIncarnation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Position of an event in one producer incarnation's stream (CORE-06 "monotonic
/// sequence"): 1, 2, 3, … without gaps at the producer. It never wraps; a producer whose
/// sequence is exhausted registers a new incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventSequence(NonZeroU64);

impl EventSequence {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// `None` for zero, which no event carries.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The following sequence; `None` at `u64::MAX`.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    /// The preceding sequence; `None` at [`EventSequence::FIRST`].
    pub fn previous(self) -> Option<Self> {
        Self::new(self.get() - 1)
    }
}

impl fmt::Display for EventSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The separate CORE-06 streams, plus the revocation priority lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    /// Performance metrics: lossy, with every loss counted.
    Metrics,
    /// Progress: coalescing, the latest state wins.
    Progress,
    /// Durable security audit: append-only, never dropped silently or reordered.
    Audit,
    /// Revocations: delivered before any metrics or progress.
    Revocation,
}

impl StreamKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::Progress => "progress",
            Self::Audit => "audit",
            Self::Revocation => "revocation",
        }
    }
}

impl fmt::Display for StreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One sequence space: a producer incarnation on one stream. Sequences are compared only
/// within a key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamKey {
    pub producer: ProducerId,
    pub incarnation: ProducerIncarnation,
    pub stream: StreamKind,
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} incarnation {} on {}",
            self.producer, self.incarnation, self.stream
        )
    }
}

/// Every sequence of `key` up to `through` was either delivered or deliberately not
/// delivered (superseded, sampled out, dropped or expired), so a receiver closes its gaps
/// up to there instead of waiting for them (CORE-06 "duplicate/lost events reconcile").
/// A mark tells a delivered event from a superseded one only to a receiver that holds
/// every delivery up to the one carrying it; [`super::Reconciler::receive`] applies it
/// only then.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedThrough {
    pub key: StreamKey,
    pub through: EventSequence,
}

/// Position of one delivery among those of its hub epoch: 1, 2, 3, … without gaps at the
/// hub (CORE-06 "duplicate/lost events reconcile"). A receiver that misses a number knows
/// a whole delivery was lost, so it never takes that delivery's events for superseded
/// ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeliverySequence(NonZeroU64);

impl DeliverySequence {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// `None` for zero.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The following sequence; `None` at `u64::MAX`.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for DeliverySequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The number of one delivery: its hub's epoch, then its sequence within the epoch. The
/// epoch is the hub's first producer incarnation (`HubConfig::first_incarnation`), which
/// rises across engine restarts, so a restarted hub's deliveries are never taken for an
/// earlier hub's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryNumber {
    pub epoch: ProducerIncarnation,
    pub sequence: DeliverySequence,
}

impl Default for DeliveryNumber {
    /// The first delivery of the first epoch.
    fn default() -> Self {
        Self {
            epoch: ProducerIncarnation::FIRST,
            sequence: DeliverySequence::FIRST,
        }
    }
}

impl fmt::Display for DeliveryNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "delivery {} of epoch {}", self.sequence, self.epoch)
    }
}

/// Where an operation is (CORE-06 phase; GPU part §3.10 adds the loading phases).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Requested,
    /// Waiting; a progress update says why (GPU part §3.10 "queue reason").
    Queued,
    Reserving,
    Transferring,
    Verifying,
    Restoring,
    Loading,
    Booting,
    Activating,
    Running,
    /// An attempt failed and the operation tries again; it has not ended (today's
    /// `retrying` client state, plan Appendix A.1).
    Retrying,
    Draining,
    Releasing,
    Completed,
    Failed,
    Cancelled,
    /// The operation's authority was revoked.
    Revoked,
}

impl Phase {
    pub const ALL: [Self; 17] = [
        Self::Requested,
        Self::Queued,
        Self::Reserving,
        Self::Transferring,
        Self::Verifying,
        Self::Restoring,
        Self::Loading,
        Self::Booting,
        Self::Activating,
        Self::Running,
        Self::Retrying,
        Self::Draining,
        Self::Releasing,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::Revoked,
    ];

    /// Whether the operation has ended. Within one producer incarnation nothing follows a
    /// terminal phase for the same resource.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Revoked
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Queued => "queued",
            Self::Reserving => "reserving",
            Self::Transferring => "transferring",
            Self::Verifying => "verifying",
            Self::Restoring => "restoring",
            Self::Loading => "loading",
            Self::Booting => "booting",
            Self::Activating => "activating",
            Self::Running => "running",
            Self::Retrying => "retrying",
            Self::Draining => "draining",
            Self::Releasing => "releasing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Revoked => "revoked",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One of the typed generations of S3.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationField {
    SandboxBoot,
    Policy,
    Authorization,
    ModelActivation,
    GpuAllocation,
}

/// The typed generations an event was produced under (CORE-06; S3.1). Each is its own
/// ids.rs type, never a bare integer, and setting one leaves the others as they were.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_boot: Option<SandboxBootGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<AuthorizationEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_activation: Option<ModelActivationGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_allocation: Option<GpuAllocationGeneration>,
}

impl Generations {
    pub const NONE: Self = Self {
        sandbox_boot: None,
        policy: None,
        authorization: None,
        model_activation: None,
        gpu_allocation: None,
    };

    pub fn with_sandbox_boot(mut self, generation: SandboxBootGeneration) -> Self {
        self.sandbox_boot = Some(generation);
        self
    }

    pub fn with_policy(mut self, epoch: PolicyEpoch) -> Self {
        self.policy = Some(epoch);
        self
    }

    pub fn with_authorization(mut self, epoch: AuthorizationEpoch) -> Self {
        self.authorization = Some(epoch);
        self
    }

    pub fn with_model_activation(mut self, generation: ModelActivationGeneration) -> Self {
        self.model_activation = Some(generation);
        self
    }

    pub fn with_gpu_allocation(mut self, generation: GpuAllocationGeneration) -> Self {
        self.gpu_allocation = Some(generation);
        self
    }

    /// The first generation present in both that is older here than in `current`, which
    /// makes an event stale (GPU part §3.10 "invalidate stale generations"). Fields are
    /// compared one by one: a newer value in one never makes up for an older value in
    /// another (S3.1).
    pub fn stale_against(&self, current: &Self) -> Option<GenerationField> {
        fn older<T: Ord>(event: Option<T>, current: Option<T>) -> bool {
            matches!((event, current), (Some(event), Some(current)) if event < current)
        }
        if older(self.sandbox_boot, current.sandbox_boot) {
            Some(GenerationField::SandboxBoot)
        } else if older(self.policy, current.policy) {
            Some(GenerationField::Policy)
        } else if older(self.authorization, current.authorization) {
            Some(GenerationField::Authorization)
        } else if older(self.model_activation, current.model_activation) {
            Some(GenerationField::ModelActivation)
        } else if older(self.gpu_allocation, current.gpu_allocation) {
            Some(GenerationField::GpuAllocation)
        } else {
            None
        }
    }
}

/// A link from an event to the CORE-01 evidence it relies on (CORE-06 provenance:
/// evidence link). It names one envelope exactly: capability, subject identity,
/// configuration fingerprint, source class, clock session and observation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLink {
    pub capability: Capability,
    pub subject: Digest,
    pub configuration: ConfigurationFingerprint,
    pub source: SourceClass,
    pub clock: ClockSession,
    pub observed_at: MonotonicTime,
}

impl EvidenceLink {
    pub fn of(envelope: &EvidenceEnvelope) -> Self {
        Self {
            capability: envelope.capability(),
            subject: envelope.subject_identity(),
            configuration: envelope.configuration(),
            source: envelope.source(),
            clock: envelope.clock(),
            observed_at: envelope.observed_at(),
        }
    }

    /// Whether `envelope` is the evidence this link names.
    pub fn names(&self, envelope: &EvidenceEnvelope) -> bool {
        *self == Self::of(envelope)
    }
}

/// Who produced an event and from what (CORE-06 provenance). The source class is fixed
/// when the producer registers, so a guest report stays labelled a guest report whatever
/// its payload claims (VM part §8.2 "label telemetry sources correctly").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    source: SourceClass,
    producer: ProducerId,
    incarnation: ProducerIncarnation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence: Option<EvidenceLink>,
}

impl Provenance {
    pub fn source(&self) -> SourceClass {
        self.source
    }

    pub fn producer(&self) -> &ProducerId {
        &self.producer
    }

    pub fn incarnation(&self) -> ProducerIncarnation {
        self.incarnation
    }

    pub fn evidence(&self) -> Option<&EvidenceLink> {
        self.evidence.as_ref()
    }
}

/// What the caller states about one event. The producer adds the stream, sequence, time
/// and provenance when it seals the event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContext {
    pub operation: OperationId,
    pub phase: Phase,
    pub generations: Generations,
    pub evidence: Option<EvidenceLink>,
}

impl EventContext {
    pub fn new(operation: OperationId, phase: Phase) -> Self {
        Self {
            operation,
            phase,
            generations: Generations::NONE,
            evidence: None,
        }
    }

    pub fn with_generations(mut self, generations: Generations) -> Self {
        self.generations = generations;
        self
    }

    pub fn with_evidence(mut self, evidence: EvidenceLink) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

/// One event in the common CORE-06 envelope.
///
/// Only producers in this module seal envelopes, after redacting the payload. An envelope
/// read back from JSON can be reconciled and shown, but it never enters an [`EventHub`]
/// stream or an audit journal as if it had been produced here.
///
/// [`EventHub`]: super::EventHub
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope<P> {
    operation: OperationId,
    generations: Generations,
    stream: StreamKind,
    sequence: EventSequence,
    phase: Phase,
    provenance: Provenance,
    emitted_at: MonotonicTime,
    payload: P,
}

impl<P> EventEnvelope<P> {
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    pub fn generations(&self) -> &Generations {
        &self.generations
    }

    pub fn stream(&self) -> StreamKind {
        self.stream
    }

    pub fn sequence(&self) -> EventSequence {
        self.sequence
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// When the producer sealed the event, on the producer's clock.
    pub fn emitted_at(&self) -> MonotonicTime {
        self.emitted_at
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    /// The sequence space this event belongs to.
    pub fn key(&self) -> StreamKey {
        StreamKey {
            producer: self.provenance.producer.clone(),
            incarnation: self.provenance.incarnation,
            stream: self.stream,
        }
    }
}

/// The identity and sequence counter of one producer incarnation on one stream. Every
/// sealed event takes the next sequence, so sequences rise by one without gaps.
#[derive(Debug)]
pub(super) struct ProducerCore {
    producer: ProducerId,
    incarnation: ProducerIncarnation,
    stream: StreamKind,
    source: SourceClass,
    next: Option<EventSequence>,
}

impl ProducerCore {
    pub(super) fn new(
        producer: ProducerId,
        incarnation: ProducerIncarnation,
        stream: StreamKind,
        source: SourceClass,
    ) -> Self {
        Self::continuing(
            producer,
            incarnation,
            stream,
            source,
            Some(EventSequence::FIRST),
        )
    }

    /// A core whose next sequence is `next`; `None` when the sequence is exhausted.
    pub(super) fn continuing(
        producer: ProducerId,
        incarnation: ProducerIncarnation,
        stream: StreamKind,
        source: SourceClass,
        next: Option<EventSequence>,
    ) -> Self {
        Self {
            producer,
            incarnation,
            stream,
            source,
            next,
        }
    }

    pub(super) fn producer(&self) -> &ProducerId {
        &self.producer
    }

    pub(super) fn incarnation(&self) -> ProducerIncarnation {
        self.incarnation
    }

    pub(super) fn stream(&self) -> StreamKind {
        self.stream
    }

    pub(super) fn key(&self) -> StreamKey {
        StreamKey {
            producer: self.producer.clone(),
            incarnation: self.incarnation,
            stream: self.stream,
        }
    }

    /// The envelope the next sequence would carry, without using the sequence; see
    /// [`ProducerCore::commit`].
    pub(super) fn draft<P>(
        &self,
        source: SourceClass,
        context: EventContext,
        now: MonotonicTime,
        payload: P,
    ) -> Result<EventEnvelope<P>, EmitError> {
        let sequence = self
            .next
            .ok_or_else(|| EmitError::SequenceExhausted { key: self.key() })?;
        Ok(EventEnvelope {
            operation: context.operation,
            generations: context.generations,
            stream: self.stream,
            sequence,
            phase: context.phase,
            provenance: Provenance {
                source,
                producer: self.producer.clone(),
                incarnation: self.incarnation,
                evidence: context.evidence,
            },
            emitted_at: now,
            payload,
        })
    }

    /// Uses `sequence`, which must be the one the last draft carried.
    pub(super) fn commit(&mut self, sequence: EventSequence) {
        if self.next == Some(sequence) {
            self.next = sequence.next();
        }
    }

    /// Drafts and commits in one step, under the producer's registered source class.
    pub(super) fn seal<P>(
        &mut self,
        context: EventContext,
        now: MonotonicTime,
        payload: P,
    ) -> Result<EventEnvelope<P>, EmitError> {
        let event = self.draft(self.source, context, now, payload)?;
        self.commit(event.sequence);
        Ok(event)
    }

    #[cfg(test)]
    pub(super) fn set_next(&mut self, next: Option<EventSequence>) {
        self.next = next;
    }
}

/// The highest sequence each producer's current incarnation reached on one stream, and
/// how far that was reported as resolved. Earlier incarnations are forgotten, so this
/// holds one mark per producer.
#[derive(Clone, Debug)]
pub(super) struct HighWater {
    stream: StreamKind,
    marks: BTreeMap<ProducerId, Mark>,
}

#[derive(Clone, Copy, Debug)]
struct Mark {
    incarnation: ProducerIncarnation,
    highest: EventSequence,
    reported: Option<EventSequence>,
}

impl HighWater {
    pub(super) fn new(stream: StreamKind) -> Self {
        Self {
            stream,
            marks: BTreeMap::new(),
        }
    }

    pub(super) fn note(&mut self, key: &StreamKey, sequence: EventSequence) {
        let current = self.marks.get(&key.producer).map(|mark| mark.incarnation);
        match current {
            Some(current) if current > key.incarnation => {}
            Some(current) if current == key.incarnation => {
                if let Some(mark) = self.marks.get_mut(&key.producer) {
                    mark.highest = mark.highest.max(sequence);
                }
            }
            _ => {
                self.marks.insert(
                    key.producer.clone(),
                    Mark {
                        incarnation: key.incarnation,
                        highest: sequence,
                        reported: None,
                    },
                );
            }
        }
    }

    /// Marks that rose since they were last reported; they are now reported.
    pub(super) fn take_unreported(&mut self) -> Vec<ResolvedThrough> {
        let stream = self.stream;
        self.marks
            .iter_mut()
            .filter_map(|(producer, mark)| {
                if mark
                    .reported
                    .is_some_and(|reported| reported >= mark.highest)
                {
                    return None;
                }
                mark.reported = Some(mark.highest);
                Some(ResolvedThrough {
                    key: StreamKey {
                        producer: producer.clone(),
                        incarnation: mark.incarnation,
                        stream,
                    },
                    through: mark.highest,
                })
            })
            .collect()
    }

    /// Every mark, for a reconnect snapshot.
    pub(super) fn all(&self) -> Vec<ResolvedThrough> {
        self.marks
            .iter()
            .map(|(producer, mark)| ResolvedThrough {
                key: StreamKey {
                    producer: producer.clone(),
                    incarnation: mark.incarnation,
                    stream: self.stream,
                },
                through: mark.highest,
            })
            .collect()
    }
}

/// Why a producer could not emit an event. The event was not delivered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmitError {
    /// The producer used its last sequence; sequences never wrap, so it must register a
    /// new incarnation.
    SequenceExhausted { key: StreamKey },
    /// The handle is not the producer's current registration on this hub.
    NotCurrent {
        producer: ProducerId,
        stream: StreamKind,
        incarnation: ProducerIncarnation,
    },
    /// The producer exceeded its emission limit (VM part §8.2 "bound ... emission rate").
    RateLimited {
        producer: ProducerId,
        retry_after: Duration,
    },
    /// A field or metric name breaks the identifier grammar.
    InvalidName { name: &'static str, error: IdError },
    /// Two fields share a name.
    DuplicateField { name: &'static str },
    /// The event's phase does not fit its stream.
    WrongPhase { expected: Phase, found: Phase },
    /// The progress stream refused the update.
    Progress(ProgressRefusal),
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceExhausted { key } => write!(
                f,
                "{key} used its last sequence; register the producer again"
            ),
            Self::NotCurrent {
                producer,
                stream,
                incarnation,
            } => write!(
                f,
                "{producer} incarnation {incarnation} is not the current {stream} registration"
            ),
            Self::RateLimited {
                producer,
                retry_after,
            } => write!(
                f,
                "{producer} exceeded its emission limit; retry in {} ms",
                retry_after.as_millis()
            ),
            Self::InvalidName { name, error } => write!(f, "the name {name:?} is invalid: {error}"),
            Self::DuplicateField { name } => write!(f, "the field {name:?} appears twice"),
            Self::WrongPhase { expected, found } => {
                write!(f, "this event must be {expected}, not {found}")
            }
            Self::Progress(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for EmitError {}

/// A stream, journal or reconciler setting that cannot work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A bound that must be at least one is zero.
    Zero { setting: &'static str },
    /// `setting` must not exceed `limit`.
    Exceeds {
        setting: &'static str,
        limit: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { setting } => write!(f, "{setting} must be at least one"),
            Self::Exceeds { setting, limit } => write!(f, "{setting} must not exceed {limit}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::foundation::events::fakes::{context, producer};
    use crate::foundation::evidence::fakes::FakeProbe;
    use crate::foundation::evidence::{
        HypervisorKind, HypervisorSubject, Observation, ProbeRegistry, Subject, SupportDetail,
    };
    use crate::foundation::ids::{digest, ManualClock};

    #[test]
    fn sequences_start_at_one_and_never_wrap() {
        assert_eq!(EventSequence::FIRST.get(), 1);
        assert_eq!(EventSequence::new(0), None);
        assert_eq!(EventSequence::FIRST.next(), EventSequence::new(2));
        assert_eq!(EventSequence::FIRST.previous(), None);
        assert_eq!(
            EventSequence::new(u64::MAX).and_then(EventSequence::next),
            None
        );
        assert!(serde_json::from_str::<EventSequence>("0").is_err());
        assert_eq!(
            serde_json::from_str::<EventSequence>("7").unwrap(),
            EventSequence::new(7).unwrap()
        );
        assert_eq!(ProducerIncarnation::new(0), None);
        assert_eq!(
            ProducerIncarnation::new(u64::MAX).and_then(ProducerIncarnation::next),
            None
        );
        assert!(serde_json::from_str::<ProducerIncarnation>("0").is_err());
    }

    #[test]
    fn a_producer_seals_consecutive_sequences_and_refuses_to_wrap() {
        let mut core = ProducerCore::new(
            producer("runner"),
            ProducerIncarnation::FIRST,
            StreamKind::Metrics,
            SourceClass::HostProbe,
        );
        let now = MonotonicTime::from_nanos(5);
        let sequences: Vec<u64> = (0..3)
            .map(|_| {
                core.seal(context("op-1", Phase::Loading), now, ())
                    .unwrap()
                    .sequence()
                    .get()
            })
            .collect();
        assert_eq!(sequences, [1, 2, 3]);

        // A draft that is not committed uses no sequence.
        let draft = core
            .draft(
                SourceClass::HostProbe,
                context("op-1", Phase::Loading),
                now,
                (),
            )
            .unwrap();
        assert_eq!(draft.sequence().get(), 4);
        assert_eq!(
            core.seal(context("op-1", Phase::Loading), now, ())
                .unwrap()
                .sequence()
                .get(),
            4
        );

        core.set_next(EventSequence::new(u64::MAX));
        let last = core.seal(context("op-1", Phase::Loading), now, ()).unwrap();
        assert_eq!(last.sequence().get(), u64::MAX);
        assert_eq!(
            core.seal(context("op-1", Phase::Loading), now, ()),
            Err(EmitError::SequenceExhausted { key: core.key() })
        );
    }

    #[test]
    fn generations_are_distinct_typed_fields() {
        let base = Generations::NONE
            .with_sandbox_boot(SandboxBootGeneration::new(3))
            .with_authorization(AuthorizationEpoch::new(5));
        let raised = base.with_model_activation(ModelActivationGeneration::new(2));
        // Setting one generation leaves the others as they were (S3.1).
        assert_eq!(raised.sandbox_boot, base.sandbox_boot);
        assert_eq!(raised.authorization, base.authorization);
        assert_eq!(raised.policy, None);
        assert_eq!(raised.gpu_allocation, None);

        let json = serde_json::to_value(raised).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"sandbox_boot": 3, "authorization": 5, "model_activation": 2})
        );
        assert!(serde_json::from_str::<Generations>(r#"{"generation": 3}"#).is_err());
    }

    #[test]
    fn a_newer_generation_never_makes_up_for_an_older_one() {
        let current = Generations::NONE
            .with_model_activation(ModelActivationGeneration::new(4))
            .with_gpu_allocation(GpuAllocationGeneration::new(7));
        let event = Generations::NONE
            .with_model_activation(ModelActivationGeneration::new(9))
            .with_gpu_allocation(GpuAllocationGeneration::new(6));
        assert_eq!(
            event.stale_against(&current),
            Some(GenerationField::GpuAllocation)
        );
        assert_eq!(
            current.stale_against(&event),
            Some(GenerationField::ModelActivation)
        );
        // Fields present on one side only are not compared.
        let other = Generations::NONE.with_policy(PolicyEpoch::new(1));
        assert_eq!(other.stale_against(&current), None);
        assert_eq!(current.stale_against(&current), None);
    }

    #[test]
    fn an_evidence_link_names_exactly_one_envelope() {
        let clock = ManualClock::new(MonotonicTime::from_nanos(10));
        let mut registry = ProbeRegistry::new(&clock);
        let probe = std::sync::Arc::new(FakeProbe::hypervisor_availability());
        registry.register(Box::new(probe.clone())).unwrap();
        let subject = Subject::Hypervisor(HypervisorSubject {
            machine: digest("yougori/test/machine/v1", &[b"workstation"]),
            hypervisor: HypervisorKind::Whpx,
        });
        let configuration = ConfigurationFingerprint::from_settings([("build", "1")]).unwrap();
        probe.respond(
            &subject,
            Observation::supported(
                configuration,
                Duration::from_secs(60),
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Whpx,
                },
            ),
        );
        let first = registry
            .refresh(Capability::HypervisorAvailable, &subject)
            .unwrap()
            .clone();
        let link = EvidenceLink::of(&first);
        assert!(link.names(&first));
        assert_eq!(link.source, SourceClass::HostProbe);
        assert_eq!(link.configuration, configuration);

        // A later observation is different evidence, even with the same result.
        clock.advance(Duration::from_secs(1));
        let second = registry
            .refresh(Capability::HypervisorAvailable, &subject)
            .unwrap()
            .clone();
        assert!(!link.names(&second));

        let event = ProducerCore::new(
            producer("loader"),
            ProducerIncarnation::FIRST,
            StreamKind::Progress,
            SourceClass::HostProbe,
        )
        .draft(
            SourceClass::HostProbe,
            context("op-1", Phase::Loading).with_evidence(link),
            MonotonicTime::from_nanos(20),
            (),
        )
        .unwrap();
        assert_eq!(event.provenance().evidence(), Some(&link));
    }

    #[test]
    fn envelopes_round_trip_and_refuse_unknown_fields() {
        let event = ProducerCore::new(
            producer("loader"),
            ProducerIncarnation::new(2).unwrap(),
            StreamKind::Progress,
            SourceClass::GuestReport,
        )
        .draft(
            SourceClass::GuestReport,
            context("op-1", Phase::Loading)
                .with_generations(Generations::NONE.with_policy(PolicyEpoch::new(4))),
            MonotonicTime::from_nanos(20),
            7u64,
        )
        .unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["provenance"]["source"], "guest_report");
        assert_eq!(json["provenance"]["incarnation"], 2);
        assert_eq!(json["sequence"], 1);
        assert_eq!(json["generations"]["policy"], 4);
        let back: EventEnvelope<u64> = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, event);
        assert_eq!(back.key().stream, StreamKind::Progress);

        let mut extra = json;
        extra["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<EventEnvelope<u64>>(extra).is_err());
    }

    #[test]
    fn names_use_the_shared_identifier_grammar() {
        assert!(ProducerId::new("runner.vllm-1:gpu_0").is_ok());
        assert_eq!(ProducerId::new(""), Err(IdError::Empty));
        assert_eq!(
            ProducerId::new("C:\\Users\\me"),
            Err(IdError::InvalidCharacter { character: '\\' })
        );
        assert_eq!(
            ProducerId::new("/home/me"),
            Err(IdError::InvalidCharacter { character: '/' })
        );
        assert!(serde_json::from_str::<ProducerId>("\"a b\"").is_err());
        assert_eq!(format!("{:?}", producer("engine")), "ProducerId(engine)");
    }

    #[test]
    fn high_water_forgets_earlier_incarnations() {
        let mut marks = HighWater::new(StreamKind::Progress);
        let first = StreamKey {
            producer: producer("loader"),
            incarnation: ProducerIncarnation::FIRST,
            stream: StreamKind::Progress,
        };
        let second = StreamKey {
            incarnation: ProducerIncarnation::new(2).unwrap(),
            ..first.clone()
        };
        marks.note(&first, EventSequence::new(9).unwrap());
        marks.note(&second, EventSequence::new(2).unwrap());
        marks.note(&first, EventSequence::new(12).unwrap());
        let reported = marks.take_unreported();
        assert_eq!(
            reported,
            [ResolvedThrough {
                key: second.clone(),
                through: EventSequence::new(2).unwrap()
            }]
        );
        assert!(marks.take_unreported().is_empty());
        assert_eq!(marks.all(), reported);
    }
}
