//! M12P: the guest file service request protocol and its dispatcher
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.2 "Guest channel and
//! bootstrap", §5.1 "Capability-rooted access"; VM-W14, the service half of M12's guest
//! connection; VM-R58).
//!
//! Tier 0 library code (VM §12.1). This is the payload a file channel carries and the host
//! side that serves it over one grant's
//! [`FileService`](crate::sandbox_contract::files::FileService).
//! Framing, channel identity, sequence state and authentication belong to the host/guest
//! link (VM-W06), which this module does not depend on: the link hands it one message and
//! the channel's authenticated trust scope, and sends back the messages it returns.
//! Nothing here starts a VM, opens a connection or opens a file outside the service.
//!
//! - [`GuestRequest`] is one typed, versioned request for a file service operation, with a
//!   request id; [`RequestPart::decode`] reads one message of its strict wire form (a JSON
//!   header line with [`GuestName`](crate::sandbox_contract::files::GuestName) strings,
//!   then content), and refuses anything else with a typed [`ProtocolRefusal`].
//! - Every message either way is at most the channel's `max_message_bytes`, 65,472 bytes
//!   by default ([`DEFAULT_MAX_MESSAGE_BYTES`]). Content that does not fit, and listings,
//!   travel in numbered parts with exact declared totals (`parts.rs`); the service is
//!   still called once per request.
//! - [`FileResponse`] answers an admitted request with the service's own results and
//!   refusals ([`Listing`](crate::sandbox_contract::files::Listing),
//!   [`ServiceRefusal`](crate::sandbox_contract::files::ServiceRefusal)), or refuses a
//!   message with a protocol refusal that names no request: the id it claimed is kept
//!   apart as `claimed_request_id`, and host code must never match a protocol refusal to a
//!   request by id.
//! - [`FileDispatcher`] builds each request's
//!   [`RequestContext`](crate::sandbox_contract::files::RequestContext) from the channel's
//!   scope and the host clock, never from the message, calls the service and bounds the
//!   channel's messages, requests in flight, buffered content and bytes per window
//!   ([`ChannelLimits`]).
//!
//! For the link's owner: the link (`sandbox/link/`, read, not used) models files as
//! streams opened with `OpenFile { stream, grant, entry, mode }`, then `Data` and
//! `EndOfStream`. Read, create and write could map onto those streams; list,
//! create_directory, delete, rename and set_executable have no stream form in the link
//! today. Mapping this protocol onto the link's `OpenFile` streams is M06's work.

mod dispatch;
mod parts;
mod refusal;
mod request;
mod response;

#[cfg(test)]
mod tests;

pub use dispatch::{
    Admitted, ChannelCounters, ChannelLimits, ChannelProblem, FileDispatcher, Received,
    DEFAULT_MAX_BUFFERED_BYTES, DEFAULT_MAX_IN_FLIGHT, DEFAULT_MAX_WINDOW_BYTES,
    MIN_MESSAGE_COST_BYTES,
};
pub use parts::EncodeError;
pub use refusal::{NameField, ProtocolRefusal};
pub use request::{
    FileProtocolVersion, GuestOperation, GuestRequest, RequestId, RequestPart,
    UndecodedRequest, DEFAULT_MAX_MESSAGE_BYTES, FILE_PROTOCOL_VERSION, MAX_CONTENT_BYTES,
    MAX_HEADER_BYTES, MAX_MESSAGE_BYTES, MIN_MESSAGE_BYTES,
};
pub use response::{Completed, FileResponse, ResponseOutcome, MAX_LISTED_ENTRY_BYTES};
