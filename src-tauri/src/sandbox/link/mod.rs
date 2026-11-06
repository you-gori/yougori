//! The host side of the guest link protocol: bounded frames, typed channels and
//! host-bound identity (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §2.6 line 2004,
//! §3.1 lines 2019–2058 (relay row, line 2045), §3.2 lines 2059–2077, §3.3 lines
//! 1904–1917, VM-W06 line 2591, VM-W50 line 2675, VM-P28 and VM-P29 lines 2803–2804,
//! VM-R49, VM-R56, VM-R58, VM-R59 and VM-R64 lines 2916–2929, §16.1 line 3048, §16.2 line
//! 2886, VM-CP-25 line 3175). S4 role GUEST; the plan proposes a crate `sandbox-link/`
//! later, so this module depends on nothing in `sandbox::{backend, lifecycle, audit}`.
//!
//! - [`wire`]: one versioned frame header (version, channel, operation, stream, sequence,
//!   boot-generation binding, length, connection binding), the five channels and the
//!   closed operation set with its directionality table; version 1 is refused by name.
//! - [`fields`]: flat tag-length-value payloads read in one linear pass; no recursion.
//! - [`limits`]: fixed maximum frame, message, stream and buffered-byte counts, per
//!   channel, with timeouts and a refusal budget; documented defaults.
//! - [`secret`]: the per-instance bootstrap secret (never displayed, debugged or
//!   serialized), the per-direction keys derived from it and the binding of a link to the
//!   VM object the host launched (CORE-04 [`VmInstanceId`] and boot generation).
//! - [`connection`]: the nonce the host draws for each connection of a boot (§3.2 line
//!   2067 "generation/connection binding"): the host's challenge sends it, every frame
//!   carries it under the tag, and frames of an earlier connection are refused.
//! - [`sequence`]: monotonic sequence state per direction and connection; replays and
//!   reorders refused.
//! - [`decoder`]: the incremental frame decoder, holding at most one frame.
//! - [`messages`]: typed messages per operation, the host's sendable set and the closed
//!   set of guest requests a later broker authorizes; nothing decodes to a path, an
//!   executable or an endpoint.
//! - [`report`]: guest reports typed with CORE-01's guest source class, bound to the host's
//!   identity of the VM; no API turns one into a host-observed fact.
//! - [`link`]: the host link: authentication, generation, connection and sequence checks,
//!   challenge and handshake, streams, windows, quotas, control priority, cancellation,
//!   timeouts, half-close.
//! - [`corpus`]: the conformance corpus fixture (`corpus.json`), its format, the VM-CP-25
//!   mutations and the replay harness shared with the Go guest side.
//!
//! Everything is pure and synchronous: time comes from the shared clock, bytes come from
//! the caller, and no transport, process, VM or file is touched. The transports (vsock,
//! Hyper-V sockets, virtio-serial), the Go agent, the relay process and the policy that
//! decides what a request may do are outside this module.
//!
//! [`VmInstanceId`]: crate::foundation::coordination::VmInstanceId

pub mod connection;
pub mod corpus;
pub mod decoder;
pub mod fields;
pub mod limits;
pub mod link;
pub mod messages;
pub mod report;
pub mod secret;
pub mod sequence;
pub mod wire;

#[cfg(test)]
mod connection_tests;
#[cfg(test)]
mod strict_tests;
#[cfg(test)]
mod tests;

pub use connection::{Connection, ConnectionNonce, NonceRefusal, CONNECTION_NONCE_BYTES};
pub use corpus::{
    mutate, operation_of, replay, reseal, split_frame, CaseKind, Corpus, CorpusCase, CorpusError,
    Expectation, Feed, FrameParts, HostAction, LastOutcome, LinkExpectation, Mutation, Outcome,
    ReplayOutcome, Step, CORPUS_FORMAT, CORPUS_JSON,
};
pub use decoder::{DecodeStep, DecoderPhase, FrameDecoder, RawFrame};
pub use fields::{
    EncodeRefusal, FieldRefusal, FieldSpec, FieldWriter, Fields, LinkName, FIELD_OVERHEAD_BYTES,
    MAX_FIELD_TAG, MAX_FIELD_VALUE_BYTES, MAX_TEXT_BYTES,
};
pub use limits::{
    ChannelQuota, LimitsError, LinkLimits, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_MESSAGE_BYTES,
    MAX_STREAM_WINDOW_BYTES, STREAM_WINDOW_BYTES,
};
pub use link::{
    encode_frame, encode_frame_on, seal, ChannelCloseCause, ChannelSummary, ClaimedField,
    CloseCause, ConsumeRefusal, HostLink, LinkEvent, LinkPhase, Refusal, RefusalEffect,
    RefusalReason, SendRefusal,
};
pub use messages::{
    revocation_reason_code, revocation_reason_from_code, AllProbesPassed, CancelCause, Classified,
    CloseReason, FileMode, GrantHandle, GuestRequest, Hello, HostMessage, InitReport, InitStage,
    LinkMessage, OpenRefusalCause, PayloadRefusal, ProbeOutcome, ProbeResult, ReportBody, Revoke,
    Shutdown, StreamId, StreamOpen, WelcomeTerms,
};
pub use report::GuestReport;
pub use secret::{BootstrapSecret, LinkBinding, SecretRefusal, BOOTSTRAP_SECRET_BYTES, KEY_DOMAIN};
pub use sequence::{SequenceRefusal, SequenceState};
pub use wire::{
    Channel, Direction, FrameHeader, FramingRefusal, Operation, Sender, StreamUse,
    FRAME_OVERHEAD_BYTES, HEADER_BYTES, MAGIC, PROTOCOL_VERSION, RETIRED_PROTOCOL_VERSION,
    TAG_BYTES,
};
