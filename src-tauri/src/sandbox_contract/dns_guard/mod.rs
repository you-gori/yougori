//! M10D: the DNS guard, the wire layer of the host DNS listener that answers a guest's DNS
//! queries only for names the sandbox's network profile grants
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM-W08 "Host independently
//! authorizes" with the acceptance "no external DNS for unauthorized names"; VM §4.2,
//! authorization before external DNS resolution and steps 1–4; VM §2.5, DNS queries are a
//! release channel; a slice of M10).
//!
//! Tier 0 (VM §12.1): sans-IO and synchronous, bytes in and bytes out. The decision is
//! V11's (`sandbox_contract::netprofile`, `HostNetwork::guest_dns`), built on V02's
//! authorization, resolution, address rules and budgets; this module adds only the DNS
//! wire format around it.
//!
//! - [`query`]: the strict parser for the minimal query subset a guest stub resolver
//!   sends (RFC 1035): one message within 512 bytes, one class IN question under an
//!   uncompressed name, no records; EDNS is refused. Everything else is refused, never
//!   guessed, and no byte sequence makes it panic.
//! - [`guard`]: a parsed question is handed to V11, which authorizes the name, resolves
//!   it only if granted (charged as V02 charges it) and records the bindings later flows
//!   are admitted against; its answer is encoded with a TTL no longer than the answer's
//!   remaining lifetime on the host clock. The mapping from V11's answers to response
//!   codes, and a note for V11's owner on NXDOMAIN against REFUSED, are in [`guard`].
//! - [`response`]: the strict response encoder, which keeps the transaction id and echoes
//!   the question exactly.
//!
//! Outside this module: the UDP socket the guard serves, the guest's resolver
//! configuration that points the guest at it, and the perimeter rule that forces every
//! guest DNS packet through it (V02 `perimeter`, V16 `perimeter_install`); a guest that
//! can reach another resolver bypasses the guard. DNS over TCP is not served.

pub mod guard;
pub mod query;
pub mod response;

#[cfg(test)]
mod tests;

pub use guard::{handle_query, refusal_code, response_code, GuardOutcome, GuardReply};
pub use query::{
    parse_query, GuestQuery, QueryHeader, QueryProblem, QueryRefusal, Question, CLASS_IN,
    HEADER_BYTES, MAX_MESSAGE_BYTES, MAX_WIRE_NAME_BYTES, TYPE_A, TYPE_AAAA,
};
pub use response::{answer_capacity, encode_response, EncodeError, ResponseCode, MAX_TTL_SECONDS};
