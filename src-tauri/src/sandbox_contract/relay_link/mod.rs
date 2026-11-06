//! M09C: the private link between the guest relay and the transport broker
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1 "Separate authority
//! from guest-facing parsing": the relay is its own confined process with no provider
//! secret, no host path and no lifecycle privilege, and authority stays with the broker;
//! VM-W11 "Confined guest relay and restricted transport broker implementing CORE-05 with
//! bounded parsers, explicit endpoints, independent authorization and quotas. No vault
//! values in the generic relay"; VM part §6.3 replay protection, §6.4 process identity).
//! A slice of M09.
//!
//! The relay steps ([`relay`](super::relay)) leave the process boundary outside. This
//! module is the channel across it: a private channel only the registered relay process
//! can use, carrying typed, bounded, authenticated messages.
//!
//! - [`frame`]: versioned, length-prefixed frames within [`MAX_FRAME_BYTES`], read by a
//!   [`FrameDecoder`] that refuses an unknown version or an oversize frame from its header,
//!   before any body byte is kept.
//! - [`message`]: what moves. The relay sends a forward decision's bytes
//!   ([`RelayMessage::Forward`]); the broker answers each exchange once, with the guest
//!   response ([`BrokerMessage::Response`]) or a typed [`ExchangeRefusal`]; either side
//!   closes. No message type can hold a credential or a vault value.
//! - [`session`]: one end of a link, sans-IO. A frame is bound to a [`LinkBinding`] (the
//!   sandbox, the relay's registered PX1 process identity and the link session) and
//!   sealed with CORE-05's HMAC-SHA256 under the session key, with per-direction sequence
//!   numbers. Replay, reordering, a frame after close, an unknown version, an oversize
//!   frame, a frame for another sandbox, relay or session, a reflected frame and a
//!   changed byte are refused, and a refused frame ends the link.
//! - [`pipe`] (Windows): the broker's named-pipe adapter, thin over the session. The pipe
//!   has a protected DACL for the current user only, rejects remote clients and holds one
//!   instance, created first under its name. A connecting client's PID is read
//!   (`GetNamedPipeClientProcessId`) and checked through PX1 to be exactly the registered
//!   relay process, PID and creation time, before a frame is read; anything else is
//!   disconnected. The relay's connect checks the broker's PID the same way.
//!
//! On Unix the link adapter would be a Unix domain socket in a directory only the user can
//! enter, with the peer's PID read by `SO_PEERCRED` (Linux) or `LOCAL_PEERPID` (macOS) and
//! checked the same way; it is documented here and not compiled. The control channel to a
//! helper process is built that way on Linux (`control_pipe`, from `control_unix.rs`).
//!
//! Outside this module: starting the relay as a confined process (restricted token, low
//! integrity, its own job; the process boundary itself, including a pipe label a
//! low-integrity relay may open); handing the relay its session key, binding and pipe name
//! at launch; Unix; what the broker does with a forwarded request (authorization, the
//! connection, the executor's credential and its echo scan of the response).

pub mod frame;
pub mod message;
mod pipe_types;
pub mod session;

#[cfg(windows)]
pub mod control_pipe;
#[cfg(target_os = "linux")]
#[path = "control_unix.rs"]
pub mod control_pipe;
#[cfg(windows)]
pub mod guest_pipe;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
mod pipe_container;
#[cfg(windows)]
mod pipe_os;

#[cfg(all(test, windows))]
mod pipe_tests;
#[cfg(test)]
mod tests;

pub use frame::{
    FrameDecoder, RawFrame, FRAME_HEADER_BYTES, FRAME_TAG_BYTES, LINK_PROTOCOL_VERSION,
    MAX_BODY_BYTES, MAX_FRAME_BYTES,
};
pub use message::{
    BrokerMessage, CloseReason, ExchangeId, ExchangeRefusal, RelayMessage, WireBytes,
    MAX_OPEN_EXCHANGES,
};
#[cfg(windows)]
pub use pipe::{
    connect_relay, open_confined_relay, HandoverPipe, LinkPipe, PeerRefusal, PipeCall, PipeError,
    RelayPipeListener, RelayPipeName, RELAY_PIPE_MODE,
};
#[cfg(windows)]
pub use pipe_container::CONTAINER_PIPE_ACCESS;
#[cfg(target_os = "linux")]
pub use control_pipe::{PeerRefusal, PipeCall, PipeError, RelayPipeName};
pub use session::{
    BrokerLink, BrokerSide, LinkBinding, LinkDirection, LinkEnd, LinkKey, LinkMessage, LinkRefusal,
    LinkSession, LinkSessionId, LinkState, RelayLink, RelaySide, LINK_FRAME_DOMAIN,
};
