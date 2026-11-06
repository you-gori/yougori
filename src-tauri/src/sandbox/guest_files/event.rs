//! What the adapter tells the host, and what it counts (VM part §3.2 lines 2063–2070;
//! tracker S05). Events are the adapter's record of what happened; the host decides what
//! to log or audit, and nothing here is a guest's word presented as a host fact.

use serde::Serialize;

use crate::foundation::ids::{ContentKey, OperationId};
use crate::foundation::transfer::StopReason;
use crate::sandbox::link::{CancelCause, GrantHandle, SendRefusal, StreamId};
use crate::sandbox_contract::file_protocol::{ProtocolRefusal, RequestId};

use super::refusal::FilesRefusal;

/// Where a body's transfer moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyPhase {
    /// The grant was opened and its budget reserved.
    Opened { length_bytes: u64 },
    /// The link or its file channel was lost; what the host holds is kept.
    Interrupted { held_bytes: u64 },
    /// A new attempt continues it on a new stream.
    Resumed { attempt: u32, held_bytes: u64 },
    /// The content matched its declared key and the transfer completed; the request is
    /// performed next.
    Completed { length_bytes: u64 },
    /// The content's key is not the declared one; nothing was written.
    Mismatched {
        declared: ContentKey,
        received: ContentKey,
    },
    /// The guest, the host or a refusal ended it; nothing was written.
    Cancelled,
    /// CORE-05 stopped it, as on revocation or expiry; nothing was written.
    Stopped { reason: StopReason },
}

/// One thing the adapter did or refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilesEvent {
    /// A guest stream was opened for `grant`.
    Opened {
        grant: GrantHandle,
        stream: StreamId,
    },
    /// The file service performed a request (or refused it itself); its answer is queued.
    Performed {
        grant: GrantHandle,
        stream: StreamId,
        request: RequestId,
    },
    /// The dispatcher refused a message without consulting the service; its refusal is
    /// queued.
    ProtocolRefused {
        grant: GrantHandle,
        stream: StreamId,
        refusal: ProtocolRefusal,
    },
    /// The adapter refused; a stream it held is cancelled.
    Refused {
        grant: Option<GrantHandle>,
        stream: Option<StreamId>,
        refusal: FilesRefusal,
    },
    /// A body's transfer moved to `phase`.
    Body {
        grant: GrantHandle,
        request: RequestId,
        operation: OperationId,
        phase: BodyPhase,
    },
    /// The guest cancelled a stream.
    GuestCancelled {
        grant: GrantHandle,
        stream: StreamId,
        cause: CancelCause,
    },
    /// The host cancelled a stream.
    HostCancelled {
        grant: GrantHandle,
        stream: StreamId,
        cause: CancelCause,
    },
    /// The link refused something queued for a stream; the stream's other messages are
    /// dropped.
    Undelivered {
        stream: StreamId,
        refusal: SendRefusal,
    },
    /// The link or its file channel is gone: every stream ended and every body moving on
    /// it was interrupted.
    LinkLost,
}

/// What one channel has counted since it was made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FilesCounters {
    /// Guest streams opened.
    pub opened: u64,
    /// Opens refused.
    pub open_refusals: u64,
    /// Requests the file service was called for.
    pub performed: u64,
    /// Messages the dispatcher refused.
    pub protocol_refusals: u64,
    /// Refusals of this adapter.
    pub refusals: u64,
    /// Streams the guest cancelled.
    pub guest_cancels: u64,
    /// Streams the host cancelled.
    pub host_cancels: u64,
    /// Bodies whose transfer was opened.
    pub bodies_opened: u64,
    /// Bodies verified and completed.
    pub bodies_completed: u64,
    /// Bodies cancelled, mismatched or stopped.
    pub bodies_ended: u64,
    /// Bodies interrupted by a lost link.
    pub bodies_interrupted: u64,
    /// Bodies resumed on a new stream.
    pub bodies_resumed: u64,
    /// Parts sent again on a resuming stream that the host already held.
    pub resent_parts_dropped: u64,
    /// Guest messages held back while answers waited for credit.
    pub deferred: u64,
    /// Bytes of guest messages credited back to the link.
    pub credited_bytes: u64,
    /// Links lost.
    pub links_lost: u64,
}
