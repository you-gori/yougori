//! Guest file payloads over the link: the host side that carries the guest file protocol on
//! the file channel of one authenticated guest link, and moves large file bodies as CORE-05
//! transfers (docs/combined-gpu-memory-and-vm-sandbox-plan.md: S2 CORE-05 row line 214, S3
//! item 7 line 229, INT-02 line 270, INT-08 line 276; VM part §2.6 line 2004, §3.1 relay and
//! file broker rows lines 2049 and 2052, §3.2 lines 2059–2077, §5.1 lines 2218–2232, VM-W06
//! line 2591, VM-W11 line 2603, VM-W14 line 2606, VM-R58 and VM-R59 lines 2923–2924). It is
//! the guest-file part of tracker item S05 and the host half of M12's guest connection over
//! M06's link.
//!
//! The three pieces it joins are committed and used unchanged: `sandbox::link` authenticates
//! the guest's frames and keeps the file channel's streams, windows and quotas;
//! `sandbox_contract::file_protocol` reads each request and serves it over one grant's file
//! service, taking scope, clock session and time from the channel; `foundation::transfer`
//! (CORE-05) authorizes, reserves, bounds, stops and resumes byte transfers.
//!
//! - [`identity`]: the host's [`ChannelIdentity`] of the channel (VM instance, boot
//!   generation, trust scope, tenant, parent execution, channel operation), the check of
//!   every link against it, and the CORE-05 guest end and body operations derived from it.
//! - [`declaration`]: what a stream's open declares (an operation, or the content key of a
//!   create or write) and the check of its request against it.
//! - [`body`]: large bodies as CORE-05 transfers: the [`BodyAuthority`] port that issues
//!   their grants, the binding of a grant to its body, the channel's verified-extents port
//!   and the per-part admission and hashing.
//! - `outbound` (private): answers waiting for the guest's credit, released in turns.
//! - [`files`]: [`GuestFiles`], the sans-IO adapter: grants, streams, bodies, backpressure,
//!   cancellation, loss of the link and resume.
//! - [`event`] and [`refusal`]: what the adapter reports, counts and refuses.
//!
//! The wire mapping the guest follows:
//!
//! 1. Each request rides its own guest-opened stream of the file channel, opened with the
//!    link's `StreamOpen::File { grant, entry, mode }`. `grant` is a handle the host
//!    attached ([`GuestFiles::add_grant`]); any other is refused with `NotAuthorized`.
//!    `mode` is `Read` for `read` and `list` and `Write` for the rest. `entry` is, for a
//!    `create` or `write`, `content-` and the lowercase hex of the content's key; for any
//!    other operation, its wire name. A malformed declaration is refused with
//!    `Unsupported`.
//! 2. Each `Data` frame carries one file protocol message of at most [`message_room`] bytes:
//!    the request's first part, then, for a create or write, its later parts; nothing else.
//! 3. The host answers on the same stream with the file protocol's response messages as the
//!    guest's credit allows, then ends the stream. A refusal of this adapter is a `Cancel`
//!    whose cause says why ([`FilesRefusal::cancel_cause`]).
//! 4. A create or write whose content does not fit its first message is a body. Before any
//!    later part is kept, the host's [`BodyAuthority`] issues a sealed CORE-05 grant for
//!    exactly the declared object, which this channel's gate opens with its reservation;
//!    each part is a chunk admitted against it, and the file service is called only after
//!    the whole content matched the declared key and the transfer completed. A body whose
//!    bytes do not match is refused and nothing is written.
//! 5. When the link or its file channel is lost, a body's transfer is interrupted and what
//!    the host holds is kept. On a new link of the same VM instance and boot generation the
//!    guest sends the request again on a stream declaring the same content; the host drops
//!    the parts it holds and continues the same transfer in a new attempt, within the same
//!    budget. A link of another instance or boot is refused outright.
//!
//! Everything is pure and synchronous: time comes from the shared clock through the link,
//! the dispatchers and the transfer ports; no transport, process, VM or network is touched,
//! and files are reached only through the dispatchers' file services. The guest side (the
//! Go agent), the transports and the policy behind the body authority are outside it.

pub mod body;
pub mod declaration;
pub mod event;
pub mod files;
pub mod identity;
mod outbound;
pub mod refusal;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests;

pub use body::{AuthorityRefusal, BindingField, BodyAuthority, BodyRequest, BodyTransfers};
pub use declaration::{Declaration, DeclarationRefusal, OperationKind, CONTENT_ENTRY_PREFIX};
pub use event::{BodyPhase, FilesCounters, FilesEvent};
pub use files::{channel_limits, BodyView, FilesLimits, GrantRefused, GuestFiles, RemovedGrant};
pub use identity::{
    body_operation, guest_route, message_room, ChannelIdentity, LinkMismatch, BODY_DOMAIN,
    ROUTE_DOMAIN,
};
pub use refusal::{FilesRefusal, GrantError, SetupError};
