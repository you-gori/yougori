//! The backend the executor drives (GPU §3.5 steps 4–8): reads, hashing, decoding,
//! asynchronous copies and completion events, as checked native bindings expose them.
//!
//! Every call returns a `Result` and the executor acts on every error; nothing is
//! logged and ignored. Reads and copies are asynchronous: a read is polled by ticket and
//! a copy is tracked by the completion event recorded after it. Hashing and decoding
//! return when they are done.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::model::{
    AllocationKey, CopyApi, ReadMethod, SourceKind, StagingPlace, StoredForm, TransferPath,
};
use crate::foundation::ids::{ContentKey, Digest, GpuDeviceKey};
use crate::model_memory::manifest::{CodecFormat, DictionaryId};
use crate::model_memory::math::SourceId;

/// One staging slot: a bounded buffer in the host ring or a GPU's staging pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StagingBuffer {
    pub place: StagingPlace,
    pub slot: u32,
}

/// A byte range inside one staging buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StagedRange {
    pub buffer: StagingBuffer,
    pub offset_bytes: u64,
    pub length_bytes: u64,
}

/// A byte range of a destination allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DestinationRange {
    pub allocation: AllocationKey,
    pub offset_bytes: u64,
    pub length_bytes: u64,
}

/// A read in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReadTicket(pub u64);

/// A completion event recorded after a copy (§3.5 step 7). The backend hands out a new
/// event per record and may reuse an event object only after
/// [`TransferBackend::release_event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub u64);

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event {}", self.0)
    }
}

/// Read `length_bytes` at `offset_bytes` of the representation from `source` into
/// `into`, starting at the buffer's first byte (§3.5 step 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub source: SourceId,
    pub kind: SourceKind,
    pub method: ReadMethod,
    pub artifact: ContentKey,
    pub representation: ContentKey,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub into: StagingBuffer,
}

/// Where a read is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReadStatus {
    Pending,
    /// The read finished on exactly the path it was asked for; fewer bytes than requested
    /// means the source ended first. A backend that served a read any other way, or
    /// cannot tell how a direct read was served, reports [`ReadStatus::Served`] instead.
    Complete {
        bytes_read: u64,
    },
    /// The read finished on `path`, the path it actually took as the backend observed it
    /// (GPU-T21: the actual path is labelled and a direct transfer is never claimed): the
    /// path asked for, or its host fallback, such as cuFile's compatibility mode for
    /// GPUDirect Storage ([`TransferPath::serves`]).
    Served {
        bytes_read: u64,
        path: TransferPath,
    },
}

crate::foundation::strict_serde::strict_tag!(ReadStatus, "status");

/// Decode `from` into `into`, writing at most `into.length_bytes`, the extent's declared
/// true length (GPU §3.3 decompression bounds).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecodeRequest {
    /// The extent's declared codec format: codec, version and frame parameters (GPU-W08).
    pub codec: CodecFormat,
    pub dictionary: Option<DictionaryId>,
    pub from: StagedRange,
    pub into: StagedRange,
}

/// Enqueue an asynchronous copy of verified bytes into the destination (§3.5 step 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CopyRequest {
    pub api: CopyApi,
    pub from: StagedRange,
    pub to: DestinationRange,
}

/// Where a completion event is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Pending,
    /// Every copy enqueued before the event finished.
    Complete,
    /// A copy before the event failed; it no longer runs.
    Failed,
}

/// What a backend call failed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendErrorKind {
    /// The source could not be reached or opened.
    SourceUnavailable,
    /// The read failed partway, such as an I/O error.
    Io,
    /// Hashing staged bytes failed.
    Digest,
    /// Decoding failed.
    Decode,
    /// Enqueueing or running a copy failed.
    Copy,
    /// Recording, querying or releasing an event failed.
    Event,
    /// The destination allocation is gone or has another generation; retrying cannot
    /// help.
    StaleDestination,
    /// The backend does not implement the call.
    Unsupported,
}

impl BackendErrorKind {
    /// Whether the source is to blame, so it is blacklisted for the job (§3.5).
    pub const fn is_source_fault(self) -> bool {
        matches!(self, Self::SourceUnavailable | Self::Io)
    }
}

/// A failed backend call, with the native error code where there is one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub code: Option<i64>,
    pub message: String,
}

impl BackendError {
    /// An error without a native code.
    pub fn new(kind: BackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} error", self.kind)?;
        if let Some(code) = self.code {
            write!(f, " {code}")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl std::error::Error for BackendError {}

/// The native side of the executor: checked bindings for reads, hashing, decoding,
/// copies and events (§3.5 steps 4–8).
///
/// Implementations use actual backend APIs; [`TransferBackend::copy_api`] names the one
/// used for copies, from a closed list of real APIs (§3.5, line 568).
pub trait TransferBackend {
    /// The API used for every copy into a destination.
    fn copy_api(&self) -> CopyApi;

    /// The read methods this backend implements.
    fn read_methods(&self) -> BTreeSet<ReadMethod>;

    /// Whether `from` can copy peer to peer into `to`, as `cudaDeviceCanAccessPeer`
    /// answers. The executor no longer asks: GPU-peer reads rest on CORE-01's GPU peer
    /// access evidence, an exercised copy, which a capability query is not (FAST-02). The
    /// default answers no.
    fn can_access_peer(
        &mut self,
        _from: GpuDeviceKey,
        _to: GpuDeviceKey,
    ) -> Result<bool, BackendError> {
        Ok(false)
    }

    /// Starts a read. A ticket is new: it is never one of a read still in flight.
    fn begin_read(&mut self, request: &ReadRequest) -> Result<ReadTicket, BackendError>;

    /// Polls a read. After `Complete`, `Served` or an error the read no longer writes to
    /// its buffer and the ticket is spent.
    fn poll_read(&mut self, ticket: ReadTicket) -> Result<ReadStatus, BackendError>;

    /// The digest of stored bytes in the manifest's form: the [`ContentKey`] digest of a
    /// raw extent, or the encoded digest over codec format, dictionary and bytes of an
    /// encoded one; computed where the bytes are, on the host for the host ring and on the
    /// GPU for device staging (§3.5 step 5).
    fn stored_digest(
        &mut self,
        range: &StagedRange,
        form: &StoredForm,
    ) -> Result<Digest, BackendError>;

    /// The [`ContentKey`] of decoded bytes (§3.5 step 5).
    fn content_key(&mut self, range: &StagedRange) -> Result<ContentKey, BackendError>;

    /// Decodes staged bytes into another staged range; returns the decoded length.
    fn decode(&mut self, request: &DecodeRequest) -> Result<u64, BackendError>;

    /// Enqueues an asynchronous copy on the destination device's copy stream.
    fn enqueue_copy(&mut self, request: &CopyRequest) -> Result<(), BackendError>;

    /// Records a completion event after every copy enqueued so far on `device`.
    fn record_event(&mut self, device: GpuDeviceKey) -> Result<EventId, BackendError>;

    /// Queries an event without blocking.
    fn query_event(&mut self, event: EventId) -> Result<EventStatus, BackendError>;

    /// Returns a finished event so the backend may reuse it.
    fn release_event(&mut self, event: EventId) -> Result<(), BackendError>;
}
