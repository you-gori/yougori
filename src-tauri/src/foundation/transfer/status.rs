//! Where a transfer stands and why it stopped (S2 CORE-05; INT-02: expired or revoked
//! transfers stop by declared bounds).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{AuthorizationEpoch, MonotonicTime};

/// Where a transfer stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum TransferStatus {
    /// An attempt is moving bytes.
    Active,
    /// The attempt failed; a retry may continue it within the same bounds (INT-08).
    Interrupted,
    /// Every granted range is verified.
    Completed,
    /// Nothing more moves under this envelope.
    Stopped(StopRecord),
}

crate::foundation::strict_serde::strict_tag!(TransferStatus, "status");

impl TransferStatus {
    /// Whether the transfer can still move bytes, now or after a retry.
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Active | Self::Interrupted)
    }
}

impl fmt::Display for TransferStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Interrupted => f.write_str("interrupted"),
            Self::Completed => f.write_str("completed"),
            Self::Stopped(record) => write!(f, "stopped: {}", record.reason),
        }
    }
}

/// How a transfer stopped, and the declared bounds it stopped within (INT-02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopRecord {
    pub reason: StopReason,
    /// When the session observed the stop.
    pub at: MonotonicTime,
    /// Bytes admitted and not yet delivered at the stop: those in flight, and those an
    /// earlier attempt dropped that were still before their deadline. None of them is
    /// accepted, and there are never more than the envelope's `max_in_flight_bytes`.
    pub cancelled_in_flight_bytes: u64,
    /// The latest deadline among those chunks and any an earlier interrupted attempt
    /// dropped, or `at` when there were none. By then every chunk has stopped, and the
    /// byte budget port keeps counting their bytes until then; it is never later than
    /// `at` plus the envelope's `max_chunk_duration`.
    pub settled_by: MonotonicTime,
}

/// Why a transfer stopped or cannot start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum StopReason {
    /// The envelope's expiry is a point on another clock session, such as before a
    /// restart, so it cannot be compared with this clock and is not honoured.
    EnvelopeOnOtherClock,
    /// The envelope's expiry passed; retries never move it (INT-08).
    Expired { expires_at: MonotonicTime },
    /// The parent's authorization epoch is not the one the envelope binds: it was
    /// revoked (a later epoch), the parent is not running (`None`), or the envelope
    /// names an epoch the parent has not reached (S3.1, INT-02).
    AuthorityNotCurrent {
        granted: AuthorizationEpoch,
        current: Option<AuthorizationEpoch>,
    },
    /// The parent's own authority expired; a transfer never outlives it (INT-02: no
    /// extension of authority).
    AuthorityExpired { expires_at: MonotonicTime },
    /// The parent's authority is reported on another clock session, so its expiry cannot
    /// be compared with this clock.
    AuthorityOnOtherClock,
    /// The parent is at the envelope's epoch but holds no authority under it, so nothing
    /// moves until it does (S3.1).
    ParentWithoutAuthority { epoch: AuthorizationEpoch },
    /// The byte reservation behind the transfer was withdrawn, as when the ledger cancels
    /// the parent's reservations on revocation (CORE-03, INT-02).
    ReservationWithdrawn,
    /// The caller cancelled the transfer; cancellation is final.
    Cancelled,
    /// The session was dropped while the transfer was live.
    Abandoned,
}

crate::foundation::strict_serde::strict_tag!(StopReason, "kind");

impl StopReason {
    /// Whether the parent's authorization moved past the envelope's epoch (INT-02).
    pub fn is_revocation(&self) -> bool {
        matches!(
            self,
            Self::AuthorityNotCurrent {
                granted,
                current: Some(current),
            } if current > granted
        )
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvelopeOnOtherClock => f.write_str(
                "the grant's expiry is on another clock session, such as before a restart; a \
                 new grant is needed",
            ),
            Self::Expired { expires_at } => write!(
                f,
                "the transfer grant expired at {} ns",
                expires_at.as_nanos()
            ),
            Self::AuthorityNotCurrent {
                granted,
                current: Some(current),
            } if current > granted => write!(
                f,
                "authorization was revoked: the parent moved from epoch {granted} to epoch \
                 {current}; a new grant is needed"
            ),
            Self::AuthorityNotCurrent {
                granted,
                current: Some(current),
            } => write!(
                f,
                "the grant names authorization epoch {granted}, but the parent is at epoch \
                 {current}"
            ),
            Self::AuthorityNotCurrent { current: None, .. } => {
                f.write_str("the parent execution is not running")
            }
            Self::AuthorityExpired { expires_at } => write!(
                f,
                "the parent's authority expired at {} ns, and a transfer never outlives it",
                expires_at.as_nanos()
            ),
            Self::AuthorityOnOtherClock => f.write_str(
                "the parent's authority is reported on another clock session, so its expiry \
                 cannot be checked",
            ),
            Self::ParentWithoutAuthority { epoch } => write!(
                f,
                "the parent holds no authority under authorization epoch {epoch}"
            ),
            Self::ReservationWithdrawn => f.write_str(
                "the transfer's byte reservation was withdrawn, so no more bytes move under it",
            ),
            Self::Cancelled => f.write_str("the transfer was cancelled"),
            Self::Abandoned => f.write_str("the transfer session was dropped while live"),
        }
    }
}
