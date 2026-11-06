//! Why a transfer operation was refused (S2 CORE-05), and why a re-issued grant cannot
//! continue a transfer (INT-08).

use std::collections::BTreeMap;
use std::fmt;

use super::endpoint::Endpoint;
use super::envelope::StopBounds;
use super::ports::{ByteBudgetRefusal, NetworkSlotRefusal};
use super::range::{ByteRange, RangeSet};
use super::status::{StopReason, TransferStatus};
use crate::foundation::ids::{AuthorizationEpoch, ContentKey, IdError, MonotonicTime, OperationId};

/// How a re-issued envelope differs from the grant it would continue (INT-08: object,
/// range, recipient and expiry budgets persist across retries). Any difference other
/// than narrowing, or a newer authorization epoch, is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryViolation {
    OtherOperation,
    OtherTenant,
    OtherParent,
    /// A re-issued grant comes from a newer authorization epoch; within one epoch the
    /// original grant still applies.
    EpochNotNewer {
        granted: AuthorizationEpoch,
        proposed: AuthorizationEpoch,
    },
    OtherDirection,
    OtherSource {
        granted: Endpoint,
        proposed: Endpoint,
    },
    OtherRecipient {
        granted: Endpoint,
        proposed: Endpoint,
    },
    /// The credential boundary moved (INT-08).
    OtherCredential,
    /// Ranges or objects the original grant did not include.
    WiderScope {
        beyond: BTreeMap<ContentKey, RangeSet>,
    },
    LargerBudget {
        granted_bytes: u64,
        proposed_bytes: u64,
    },
    LooserStopBounds {
        granted: StopBounds,
        proposed: StopBounds,
    },
    /// The expiry is on another clock session, so it cannot be compared with the original.
    OtherClock,
    LaterExpiry {
        granted: MonotonicTime,
        proposed: MonotonicTime,
    },
}

impl fmt::Display for RetryViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherOperation => f.write_str("it names another transfer"),
            Self::OtherTenant => f.write_str("it names another tenant"),
            Self::OtherParent => f.write_str("it names another parent execution"),
            Self::EpochNotNewer { granted, proposed } => write!(
                f,
                "its authorization epoch {proposed} is not newer than the granted epoch {granted}"
            ),
            Self::OtherDirection => f.write_str("it changes the direction"),
            Self::OtherSource { granted, proposed } => {
                write!(f, "it changes the source from {granted} to {proposed}")
            }
            Self::OtherRecipient { granted, proposed } => {
                write!(f, "it changes the recipient from {granted} to {proposed}")
            }
            Self::OtherCredential => f.write_str("it changes the credential"),
            Self::WiderScope { beyond } => {
                let bytes = beyond.values().fold(0u64, |total, ranges| {
                    total.saturating_add(ranges.total_bytes())
                });
                write!(
                    f,
                    "it grants {bytes} bytes in {} object(s) beyond the original scope",
                    beyond.len()
                )
            }
            Self::LargerBudget {
                granted_bytes,
                proposed_bytes,
            } => write!(
                f,
                "it raises the byte budget from {granted_bytes} to {proposed_bytes}"
            ),
            Self::LooserStopBounds { .. } => f.write_str("it loosens the stop bounds"),
            Self::OtherClock => f.write_str("its expiry is on another clock session"),
            Self::LaterExpiry { granted, proposed } => write!(
                f,
                "it moves the expiry from {} ns to {} ns",
                granted.as_nanos(),
                proposed.as_nanos()
            ),
        }
    }
}

/// Why a transfer operation was refused (S2 CORE-05).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferRefusal {
    /// The seal does not match the envelope.
    Tampered,
    /// The operation was already opened and its envelope has not expired; a replayed
    /// envelope never restarts or re-budgets a transfer.
    AlreadyOpened {
        operation: OperationId,
    },
    /// The transfer cannot move: it stopped now or earlier, or cannot start, for
    /// `reason`.
    Stopped {
        reason: StopReason,
    },
    RecipientMismatch {
        granted: Endpoint,
        connected: Endpoint,
    },
    SourceMismatch {
        granted: Endpoint,
        connected: Endpoint,
    },
    /// The attempt presents another credential than the envelope's (INT-08).
    CredentialMismatch,
    /// The byte budget could not reserve the transfer's bytes.
    ReservationRefused {
        refusal: ByteBudgetRefusal,
    },
    /// No network slot is free for the transfer, which holds one from its open to its
    /// terminal phase (S10 line 179); the refusal says whether a retry can progress.
    NetworkSlotRefused {
        refusal: NetworkSlotRefusal,
    },
    ObjectOutOfScope {
        object: ContentKey,
    },
    RangeOutOfScope {
        object: ContentKey,
        range: ByteRange,
    },
    /// The range overlaps bytes already verified, delivered or in flight; verified bytes
    /// are reused, not moved again.
    AlreadyCovered {
        object: ContentKey,
        range: ByteRange,
    },
    /// The chunk would exceed the declared in-flight bound (INT-02).
    InFlightLimit {
        max_in_flight_bytes: u64,
        in_flight_bytes: u64,
        requested_bytes: u64,
    },
    /// The chunk would exceed the byte budget, which counts every attempt.
    BudgetExhausted {
        budget_bytes: u64,
        used_bytes: u64,
        requested_bytes: u64,
    },
    /// The permit is not one this session has in flight.
    UnknownChunk,
    /// The chunk arrived after its deadline; its bytes do not count.
    ChunkLate {
        deadline: MonotonicTime,
        delivered_at: MonotonicTime,
    },
    ChunksInFlight {
        in_flight_bytes: u64,
    },
    /// Granted ranges are not verified yet.
    Incomplete {
        missing_bytes: u64,
    },
    NotActive {
        status: TransferStatus,
    },
    NotRetryable {
        status: TransferStatus,
    },
    /// A re-issued envelope would widen the grant or is not a continuation of it.
    RetryWidens {
        violations: Vec<RetryViolation>,
    },
    /// The attempt counter is exhausted.
    AttemptsExhausted,
    /// The continuation's derived operation broke the identifier grammar; with the
    /// current grammar it cannot.
    ContinuationIdentity {
        error: IdError,
    },
}

impl fmt::Display for TransferRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tampered => {
                f.write_str("the transfer envelope's seal does not match its contents")
            }
            Self::AlreadyOpened { operation } => write!(
                f,
                "transfer {operation} was already opened; continue it through its session or \
                 ask for a new grant"
            ),
            Self::Stopped { reason } => write!(f, "the transfer cannot move: {reason}"),
            Self::RecipientMismatch { granted, connected } => write!(
                f,
                "the attempt is connected to {connected}, but the grant names recipient {granted}"
            ),
            Self::SourceMismatch { granted, connected } => write!(
                f,
                "the attempt reads from {connected}, but the grant names source {granted}"
            ),
            Self::CredentialMismatch => {
                f.write_str("the attempt presents another credential than the grant names")
            }
            Self::ReservationRefused { refusal } => write!(f, "{refusal}"),
            Self::NetworkSlotRefused { refusal } => write!(f, "{refusal}"),
            Self::ObjectOutOfScope { object } => {
                write!(f, "object {object} is not in the transfer's scope")
            }
            Self::RangeOutOfScope { object, range } => {
                write!(
                    f,
                    "{range} of object {object} is outside the granted ranges"
                )
            }
            Self::AlreadyCovered { object, range } => write!(
                f,
                "{range} of object {object} overlaps bytes already verified, delivered or in flight"
            ),
            Self::InFlightLimit {
                max_in_flight_bytes,
                in_flight_bytes,
                requested_bytes,
            } => write!(
                f,
                "{requested_bytes} more bytes would put {} in flight, over the declared bound of \
                 {max_in_flight_bytes}",
                in_flight_bytes.saturating_add(*requested_bytes)
            ),
            Self::BudgetExhausted {
                budget_bytes,
                used_bytes,
                requested_bytes,
            } => write!(
                f,
                "{requested_bytes} more bytes would exceed the byte budget: {used_bytes} of \
                 {budget_bytes} are used across all attempts"
            ),
            Self::UnknownChunk => f.write_str("the chunk permit is not in flight in this session"),
            Self::ChunkLate {
                deadline,
                delivered_at,
            } => write!(
                f,
                "the chunk arrived at {} ns, after its deadline at {} ns; its bytes do not count",
                delivered_at.as_nanos(),
                deadline.as_nanos()
            ),
            Self::ChunksInFlight { in_flight_bytes } => {
                write!(f, "{in_flight_bytes} bytes are still in flight")
            }
            Self::Incomplete { missing_bytes } => {
                write!(f, "{missing_bytes} granted bytes are not verified yet")
            }
            Self::NotActive { status } => write!(f, "the transfer is {status}, not active"),
            Self::NotRetryable { status } => {
                write!(f, "the transfer is {status} and cannot be retried")
            }
            Self::RetryWidens { violations } => {
                f.write_str("the re-issued grant cannot continue this transfer: ")?;
                for (index, violation) in violations.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(f, "{violation}")?;
                }
                Ok(())
            }
            Self::AttemptsExhausted => f.write_str("the transfer has no attempts left"),
            Self::ContinuationIdentity { error } => {
                write!(
                    f,
                    "the continuation has no valid operation identity: {error}"
                )
            }
        }
    }
}

impl std::error::Error for TransferRefusal {}
