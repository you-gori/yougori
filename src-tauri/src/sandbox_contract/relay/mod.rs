//! M09R and M09B: the guest relay's request reader, from wire bytes to V02's inspected
//! request; the relay step that turns one request into a typed forward decision; and the
//! response reader and step that turn the upstream's answer into the bytes the guest gets
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part: §3.1 "Separate authority
//! from guest-facing parsing", §4.3 "TLS, HTTP and protocol confusion", §4.2 step 7 and
//! the release budgets of §2.5; VM-W11 "Confined guest relay and restricted transport
//! broker ... with bounded parsers, explicit endpoints, independent authorization and
//! quotas", VM-W03; scenarios VM-P10, VM-P30 and VM-P32). A slice of M09.
//!
//! Tier 0 only (VM §12.1): sans-IO, synchronous library code. Nothing here opens a socket,
//! terminates TLS, resolves a name or touches a VM; bytes come in as slices and go out as
//! a typed decision or the guest's rebuilt bytes.
//!
//! - [`reader`]: [`RequestReader`] feeds bytes incrementally into `httparse` with a fixed
//!   header count ([`MAX_HEADERS`]) and [`ReaderLimits`], HTTP/1.1 only, and produces V02's
//!   [`InspectedRequest`](crate::sandbox_contract::destinations::InspectedRequest) without
//!   dropping or merging anything V02 judges. When the head is complete it refuses
//!   underscore spellings of protected headers and request-target overrides, takes the
//!   framing from V02's one framing rule (refusing V02's header faults before any body
//!   byte is kept), and reports `Expect: 100-continue`. Content-Length bodies and strictly
//!   decoded chunked bodies are read within the body limit; bare line feeds, obsolete
//!   folding, trailers and pipelined bytes are refused ([`ReadRefusal`]). The result does
//!   not depend on how the bytes were split.
//! - [`step`]: [`RelayStep`] runs the reader, then the broker's authorization for the
//!   sandbox's route and V02's
//!   [`bind_request`](crate::sandbox_contract::destinations::bind_request), reserves the
//!   outbound bytes plus the executor's credential allowance against the route's byte
//!   budget and the provider-request release channel (and one route effect for an
//!   external operation) before anything would be sent, and returns a
//!   [`ForwardDecision`] carrying the exact bytes to send, rebuilt from the bound request
//!   and never copied from the guest, or a typed [`RelayRefusal`].
//!
//! - [`response`]: [`ResponseReader`] reads the upstream's HTTP/1.1 (or HTTP/1.0) response
//!   to one forwarded request, for the bound request's method, with `httparse`,
//!   [`MAX_HEADERS`] and [`ReaderLimits`] (all heads together within the head limit), the
//!   request reader's line scan and its strict chunked decoder. It refuses `101`, drops
//!   other interim responses (at most [`MAX_INTERIM_RESPONSES`]), frames the body per RFC
//!   9112 §6.3 (none for HEAD, `204` and `304`; chunked; Content-Length; until the end of
//!   the input only when neither is present), judges the framing fields with V02's
//!   framing rule, and refuses differing Content-Length values, Transfer-Encoding in
//!   HTTP/1.0, a repeated `Location` and bytes after the body ([`ResponseReadRefusal`]).
//!   The result does not depend on how the bytes were split.
//! - [`response_step`]: [`ResponseStep`] makes one reservation in the broker's own book
//!   before reading (V02's `reserve_received`, for the head and body limits capped by
//!   what the route's inbound budget has left), refuses a response that runs past it,
//!   and settles with the bytes received (heads, body and chunk framing), also on every
//!   refusal. It returns a [`GuestResponse`] rebuilt from the parsed response, never
//!   copied: a normalized status line, no hop-by-hop fields, the body framed by one
//!   `content-length`, and a 3xx `Location` passed on and reported as a [`Redirect`] but
//!   never followed; or a typed [`ResponseRefusal`].
//!
//! Outside this module: the process boundary (§3.1: the relay is its own confined process
//! with no provider secret, no host path and no lifecycle privilege, an OS-enforced
//! separation that Rust modules cannot provide); TLS (its termination at the executor,
//! and the server name the guest sent, which arrives here as V02
//! [`TlsFacts`](crate::sandbox_contract::destinations::TlsFacts)) and HTTP/2; the
//! transport's `100 Continue` answer to the guest; upstream connections and keep-alive
//! (the caller resolves and connects through the broker, hands in the
//! [`ConnectionPermit`](crate::sandbox_contract::destinations::ConnectionPermit), sends the
//! bytes, settles the send reservations, feeds the upstream's bytes to the response step
//! and closes the connection after one response, so nothing is pipelined or reused);
//! credential injection, which the executor does after the request step; credential-echo
//! scanning of responses, which belongs to the executor, since it holds the credential and
//! the relay does not; and following a redirect, which a caller does only through
//! [`DestinationBroker::follow_redirect`](crate::sandbox_contract::destinations::DestinationBroker::follow_redirect),
//! which applies the route's redirect policy and re-authorizes the target, before a new
//! request through the relay step.

mod chunked;
pub mod reader;
pub mod response;
pub mod response_step;
pub mod step;

#[cfg(test)]
mod tests;

pub use chunked::MAX_CHUNK_SIZE_DIGITS;
pub use reader::{
    HeadSyntax, LimitsError, ReadOutcome, ReadProgress, ReadRefusal, ReadRequest, ReaderLimits,
    RequestReader, HEAD_LIMIT_CEILING, MAX_HEADERS, TARGET_OVERRIDE_HEADERS,
    UNDERSCORE_PROTECTED_HEADERS,
};
pub use response::{
    ReadResponse, ResponseFraming, ResponseOutcome, ResponseReadRefusal, ResponseReader,
    ResponseVersion, MAX_INTERIM_RESPONSES,
};
pub use response_step::{
    GuestResponse, Redirect, ResponseRefusal, ResponseStep, NOT_RETURNED_HEADERS,
    PROXY_HEADER_PREFIX,
};
pub use step::{ForwardDecision, ForwardParts, RelayRefusal, RelayStep, NOT_FORWARDED_HEADERS};
