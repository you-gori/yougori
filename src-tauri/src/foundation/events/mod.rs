//! CORE-06: the correlation and event envelope, and the separate streams it travels on
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S2 CORE-06, S6 INT-10, S7 long-run
//! stability, S8 redaction, GPU part §3.10, VM part §8.2 and §16.3).
//!
//! Every event travels in one [`EventEnvelope`]: its operation, the typed generations it
//! was produced under, a sequence that rises by one per producer incarnation and stream,
//! a phase, provenance (source class, producer, CORE-01 evidence link) and a payload its
//! producer redacted with a [`RedactionPolicy`] before sealing it.
//!
//! The streams stay separate, each with its own bound, retention and backpressure:
//!
//! - [`MetricsStream`] is lossy. Under pressure it keeps one event in N, when full it
//!   drops the oldest, after its retention it expires events, and it counts every loss.
//! - [`ProgressStream`] coalesces. The latest state per producer, operation and resource
//!   wins; it tracks a bounded number of them and serves a reconnect snapshot.
//! - [`AuditJournal`] is the durable security audit: an append-only hash chain that only
//!   the one [`AuditAppendAuthority`] it issued can extend. When storage is slow or full
//!   it spools records in order within a bound, then fails closed; it never drops or
//!   reorders a record.
//! - [`RevocationLane`] is the priority lane. [`EventHub::drain`] delivers it before any
//!   progress or metrics, and it never waits on audit storage.
//!
//! On the receiving side, [`Reconciler`] ignores duplicates, exposes gaps, and closes
//! each gap by recovery, supersession or an explicitly recorded loss. Each [`Delivery`]
//! carries a [`DeliveryNumber`], so a receiver tells a lost delivery's events from
//! superseded ones and never closes their gaps as superseded.

/// Declares a name type checked against the ids.rs identifier grammar.
macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the ids.rs identifier grammar: 1–128 letters, digits, '.', '_', ':'
            /// or '-', starting with a letter or digit.
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::foundation::ids::IdError> {
                let value = value.into();
                super::envelope::check_name(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                Self::new(<String as serde::Deserialize>::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

/// `foundation::strict_serde`'s [`strict_tagged_enum!`](crate::foundation::strict_serde::strict_tagged_enum),
/// in this module's textual scope for the enums its child files declare with it.
macro_rules! strict_tagged_enum {
    ($($tokens:tt)*) => {
        $crate::foundation::strict_serde::strict_tagged_enum! { $($tokens)* }
    };
}

mod audit;
mod durable;
mod envelope;
mod event_log;
mod fanout;
mod high_water;
mod hub;
mod metrics;
mod owner;
mod progress;
mod pump;
mod reader;
mod reconcile;
mod redaction;
mod revocation;
mod revocation_log;
mod spool;

#[cfg(test)]
mod durable_tests;
#[cfg(test)]
mod fakes;
#[cfg(test)]
mod reader_tests;
#[cfg(test)]
mod spool_tests;
#[cfg(test)]
mod tests;

pub use audit::{
    verify_chain, AuditAppendAuthority, AuditConfig, AuditDraft, AuditEntry, AuditFailurePolicy,
    AuditHealth, AuditJournal, AuditReceipt, AuditRecord, AuditRefusal, AuditSpool, AuditStore,
    AuditTotals, ChainError, Durability, FlushReport, HostFact, JournalError, JournalHead,
    JournalId, StoreRefusal,
};
pub use durable::{
    Correlated, Correlation, CursorError, DurableLog, DurableStreamId, GapReason, LineProblem,
    LogConfig, LogCursor, LogDamage, LogEntry, LogError, LogMarker, LogTotals, OpenReport,
    ReadBatch, ReadItem, Retention, StreamInstance, TornTailFound,
};
pub use envelope::{
    ConfigError, DeliveryNumber, DeliverySequence, EmitError, EventContext, EventEnvelope,
    EventSequence, EvidenceLink, GenerationField, Generations, Phase, ProducerId,
    ProducerIncarnation, Provenance, ResolvedThrough, StreamKey, StreamKind,
};
pub use event_log::{EventLog, LoggedStream};
pub use fanout::{
    DeliveryFanout, FanoutError, SubscriberBatch, SubscriberConfig, SubscriberHeld, SubscriberId,
    SubscriberLag, SubscriberTotals,
};
pub use hub::{
    Delivery, EventHub, HubConfig, HubError, MetricsProducer, ProgressProducer, RevocationIssuer,
};
pub use metrics::{
    MetricDraft, MetricSample, MetricValue, MetricsAdmission, MetricsBatch, MetricsConfig,
    MetricsStream, MetricsTotals, SeriesKey, SeriesSummary,
};
pub use owner::{OwnerError, OwnerRecord, StreamOwner, Takeover};
pub(crate) use owner::write_atomic;
pub use progress::{
    format_bytes, CancellationBoundary, DataSource, EtaEstimate, ProgressAdmission, ProgressBatch,
    ProgressConfig, ProgressError, ProgressRefusal, ProgressSnapshot, ProgressStream,
    ProgressTotals, ProgressUpdate, QueueReason, ResourceKind, StaleBy, TrackedResourceId,
};
pub use pump::DeliveryPump;
pub use reader::{DurableReader, ReaderTotals};
pub use reconcile::{
    Arrival, DeliveryArrival, DeliveryPoll, DeliveryRange, LossReason, LostRange, Observed,
    PollRequest, Polling, Received, ReconcileConfig, ReconcileError, ReconcileTotals, Reconciler,
    Resolution, SequenceRange,
};
pub use redaction::{
    EmissionLimit, Field, FieldClass, FieldValue, RateLimiter, RedactedField, RedactedFields,
    RedactedValue, RedactionPolicy, UntrustedText, REDACTED, REDACTED_PATH,
};
pub use revocation::{
    GrantRevocation, Revocation, RevocationAdmission, RevocationBatch, RevocationConfig,
    RevocationLane, RevocationReason, RevocationTotals, RevokeAll,
};
pub use revocation_log::{
    DurablyPublished, RebuiltRevocations, RecordError, RevocationLog, RevocationRecord,
    RevocationReplay,
};
pub use spool::{FileAuditSpool, SpoolConfig, SpoolDamage, SpoolError, SpoolOpened, SpoolTotals};
