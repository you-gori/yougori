//! Durable security audit, incident correlation and the assurance ledger of the VM
//! sandbox (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §8.1 evidence records at
//! lines 2433–2439, §8.2 detection and audit at lines 2441–2450, §6.3 revocation at lines
//! 2304–2323, VM-W42, VM-W43, VM-W44 and VM-W52 at lines 2665–2675, the CORE-06 row at line
//! 215, VM-P12 and VM-P22 at lines 2787 and 2797).
//!
//! Everything here is pure library code built on the committed CORE-06 journal and
//! durable streams (`foundation::events`), CORE-01 evidence (`foundation::evidence`) and
//! CORE-08 claims (`foundation::report`):
//!
//! - [`AuditStream`] is one actor's durable audit stream: a CORE-06 [`AuditJournal`]
//!   whose records go to a [`SegmentedStore`], which rotates them into digest-linked
//!   segments, and whose head is optionally published to a [`HeadAnchor`]. A
//!   [`StreamDirectory`] issues exactly one live append authority per stream. Queues are
//!   the journal's bounded spool with its declared [`AuditFailurePolicy`]; redaction is
//!   the journal's [`RedactionPolicy`], applied before any record leaves the producer.
//!   A restart or truncation is detected when the stream resumes and recorded in the
//!   next segment's header and, when sequences were lost, as an in-chain
//!   `EventsLost` record (§8.2; VM-W42). A revocation, and the revocation of one grant,
//!   is a typed record that may use the journal's revocation reserve, so a stream that
//!   fails closed for ordinary records still takes it while the reserve has room (§6.3;
//!   §8.2 "never block the revocation channel").
//! - [`DurableSegments`] keeps a stream's segments in a CORE-06 [`DurableLog`] in the
//!   stream's own directory under a [`StreamDirectory::durable`] root
//!   ([`AuditStream::open_durable`]): the log's [`StreamOwner`] makes the stream's owner
//!   its only appender in this process and across the processes of the host, the
//!   sequence continues after a restart, a torn tail is quarantined and reported, and
//!   what retention dropped is declared and read as a gap, never hidden (S06).
//!   [`AuditStream::release`] closes such a stream and releases its log with the outcome,
//!   which dropping it cannot report.
//! - [`FileSpool`] is the journal's bounded spool on file in the same directory
//!   ([`AuditStream::open_durable_spooled`]): bounded by the journal's `spool_records`,
//!   durable across a restart, in chain order, a torn last line quarantined and reported,
//!   and the revocation reserve kept exactly as an in-memory spool keeps it, across a
//!   restart too: a spool holding more records than its bound does not open, and
//!   [`AuditStream::spool_room`] shows the slots ordinary records and revocations may
//!   still take ([`SpoolRoom`]) (§8.2 line 2445; VM-W42; VM-W43 at line 2666 "audit
//!   overload cannot block emergency revocation").
//! - [`CorrelationIndex`] links tool requests, approvals, operations and artifacts by
//!   CORE-06 identities and reconstructs an incident from them and the audit records,
//!   keeping no content: the record types hold identifiers, digests, counts and typed
//!   labels only (VM-W44).
//! - [`AssuranceLedger`] links claims to assumptions, configurations, tests, CORE-01
//!   evidence identities and residual risks; a claim is backed by evidence or carries an
//!   explicit gap, stale or superseded evidence invalidates it, and nothing in the API
//!   computes a score (VM-W52).
//!
//! The chain and the anchor make tampering detectable under the custody assumptions
//! stated in [`CUSTODY_STATEMENT`]; nothing here prevents a host administrator from
//! rewriting what they control (§8.2 "a same-user local log is not WORM").
//!
//! [`AuditJournal`]: crate::foundation::events::AuditJournal
//! [`AuditFailurePolicy`]: crate::foundation::events::AuditFailurePolicy
//! [`RedactionPolicy`]: crate::foundation::events::RedactionPolicy
//! [`DurableLog`]: crate::foundation::events::DurableLog
//! [`StreamOwner`]: crate::foundation::events::StreamOwner

/// Declares an internally tagged enum whose deserializer refuses unknown fields for every
/// variant. serde ignores unknown fields next to the tag of a unit variant even with
/// `deny_unknown_fields`, so reading goes through a twin enum whose unit variants are
/// empty struct variants; the written form is unchanged. The pattern is the one in
/// `foundation/events/mod.rs`, kept local so this module depends on no other's macros.
/// The twin reads through `foundation::strict_serde`'s `strict_tag!`, so a tag that is not
/// a string, a record that is not an object and a key repeated in one object are refused
/// even where serde buffers the record, as it does for one nested in another tagged enum.
macro_rules! strict_tagged_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident (tag = $tag:literal, wire = $wire:ident, wire_name = $wire_name:literal) {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $field_type:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", from = $wire_name)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({
                    $(
                        $(#[$field_meta])*
                        $field: $field_type
                    ),*
                })?
            ),*
        }

        #[derive(serde::Deserialize)]
        #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
        #[serde(remote = "Self")]
        enum $wire {
            $(
                $variant {
                    $($(
                        $field: $field_type
                    ),*)?
                }
            ),*
        }

        crate::foundation::strict_serde::strict_tag!($wire, $tag, deserialize);

        impl From<$wire> for $name {
            fn from(wire: $wire) -> Self {
                match wire {
                    $(
                        $wire::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?,
                    )*
                }
            }
        }
    };
}

/// Declares an identifier type checked against the shared ids.rs grammar (1–128 letters,
/// digits, '.', '_', ':' or '-', starting with a letter or digit), so no identifier can
/// carry free text, a path or a secret of any length.
macro_rules! identifier_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the ids.rs identifier grammar.
            pub fn new(
                value: impl Into<String>,
            ) -> Result<Self, crate::foundation::ids::IdError> {
                let value = value.into();
                crate::foundation::ids::validate_identifier(&value)?;
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

mod anchor;
mod correlation;
mod durable;
mod ledger;
mod segment;
mod spool;
mod stream;

#[cfg(test)]
mod durable_tests;
#[cfg(test)]
mod fakes;
#[cfg(test)]
mod spool_tests;
#[cfg(test)]
mod strict_tests;
#[cfg(test)]
mod tests;

pub use anchor::{
    compare_retained_with_anchor, compare_with_anchor, AnchorRefusal, AnchorState, AnchorVerdict,
    AnchoredHead, HeadAnchor, NoAnchor, CUSTODY_STATEMENT,
};
pub use correlation::{
    Approval, ApprovalDecision, ApprovalId, Approver, ArtifactLink, ArtifactRole, AuditPointer,
    CorrelationBounds, CorrelationError, CorrelationIndex, GuestReportKind, HostFactPointer,
    IncidentScope, NotHostObserved, Observation, ObservationSummary, OperationLink, Reconstruction,
    RequestId, TelemetrySource, TimelineEntry, TimelineEvent, ToolName, ToolRequest,
};
pub use durable::{
    check_retention, stream_directory_name, DurableError, DurableOpening, DurableSegments,
    LayoutProblem, SegmentLine,
};
pub use ledger::{
    AssumptionId, AssumptionKind, AssuranceLedger, Citation, CitationVerdict, Claim, ClaimEntry,
    ClaimId, ClaimStatus, ClaimSupport, EvidenceCheck, ExplicitGap, GapReason, Invalidation,
    LedgerError, LedgerSummary, ProbeCitation, ProfileId, Property, ReleaseCitation, RiskId,
    RiskKind, TestCitation, TestId,
};
pub use segment::{
    verify_retained_segments, verify_segments, Damage, ResumeFinding, ResumeReport, RetainedStart,
    SegmentConfig, SegmentControl, SegmentError, SegmentHeader, SegmentOpening, SegmentRetention,
    SegmentSeal, SegmentStorage, SegmentTotals, SegmentedStore, StoredSegment, TruncationWitness,
    VerifiedChain,
};
pub use spool::{FileSpool, SpoolError, SpoolOpening, SpoolProblem, SpoolTornTail, SpooledOpening};
pub use stream::{
    Anchoring, AuditEvent, AuditStream, SpoolRoom, StreamAuthority, StreamClose, StreamConfig,
    StreamDirectory, StreamError, StreamRefusal, StreamRelease, StreamResume, StreamState,
    StreamTotals, MAINTENANCE_OPERATION, SECRET_SCAN_COVERAGE,
};
