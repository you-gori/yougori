//! M14: the host enforcement point for ingress and sandbox connections
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.7 "Ingress, previews and
//! connected sandboxes", §2.5 "Bound releases and post-revocation exposure", §6.3
//! step 2; VM-W13: "unpublished service unreachable; revocation closes existing
//! sessions; public/private semantics preserved").
//!
//! Tier 0 only (VM §12.1): synchronous and transport-agnostic. It opens no socket and
//! listens on nothing: the socket or transport adapter (M06/M02) accepts connections,
//! terminates TLS, carries the caller's proof and hands the gate one [`SessionStream`]
//! per stream end. Everything that decides whether a byte may move is here, on V02's
//! contract ([`crate::sandbox_contract::destinations`]) and CORE-04's authority:
//!
//! - Authority (`authority`): a sandbox is served only while it holds the authorization
//!   and policy epochs it was attached under, and a service only while the sandbox's
//!   current CORE-04 authority holds the service's published-service network grant,
//!   CORE-04's own [`NetworkGrant::PublishedService`] named by `network_grant_id`, whose
//!   digest the gate derives from the service's V02 identity ([`published_service_grant`]);
//!   the host names only the services ([`SandboxRegistration`]), and a sandbox whose launch
//!   settings do not hold the derived grant of each is not attached.
//! - The ingress gate (`ingress`): a caller reaches a sandbox's service only through a
//!   live V02 publication that exists, is unexpired on the shared clock, names the
//!   service and port, has response budget left and admits the caller's audience.
//!   Unpublished means unreachable, and an outside caller is never told why a service is
//!   not served. A publication that authenticates admits a caller only on a proof its
//!   [`ProofVerifier`] accepted for that publication, sandbox and epoch, and the session
//!   ends when the proof expires; a private session is never served as public, and a
//!   public one stays public. Guest responses are outbound data: each byte is charged to
//!   the publication's response budget and the sandbox's release account before it is
//!   sent, and the session closes once the budget is spent.
//! - The connection broker (`broker`): a sandbox-to-sandbox connection needs V02's
//!   grant at both ends, recorded under each end's own mode for exactly the endpoints the
//!   host attached, and the callee's published-service grant; nothing is inferred
//!   transitively. Each connection is budgeted both ways, and the callee's responses are
//!   charged to its release account.
//! - Revocation (`closure`): when CORE-04 revokes a sandbox (its epoch advances), changes
//!   its policy (its policy epoch advances) or tombstones a published-service grant, every
//!   session and connection it covers is closed and new ones are refused; a typed
//!   [`ClosureReport`], made only by the gate, lets the host acknowledge `SocketsClosed`
//!   and `AllChannelsClosed` ([`acknowledge_closure`]) with the gate's proof, checked
//!   again, and the host's own observation of the sandbox's other channels
//!   ([`OtherChannels`]).
//! - Status (`status`): every publication with its audience, outgoing response budget and
//!   state as CORE-04 stands, every open session with whom it was admitted as, every
//!   connection with its budget each way.
//!
//! The gate's clock is CORE-04's ([`ConnectionAuthority::now`]) and never goes back. The
//! sandbox's release account stays the host's, lent per charge ([`ReleaseAccounts`]), so
//! the §2.5 bound has one account per sandbox. Preview origins and their headers are
//! V13's ([`crate::sandbox_contract::untrusted`]); this module only admits and moves
//! bytes.
//!
//! [`NetworkGrant::PublishedService`]: crate::foundation::evidence::NetworkGrant::PublishedService

mod authority;
mod broker;
mod closure;
mod gate;
mod ingress;
mod service_grant;
mod status;
mod stream;
mod verifier;

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod tests_authority;
#[cfg(test)]
mod tests_broker;
#[cfg(test)]
mod tests_ingress;
#[cfg(test)]
mod tests_revocation;
#[cfg(test)]
mod tests_service_grant;

pub use authority::{ConnectionAuthority, ReleaseAccounts};
pub use broker::{ConnectionBudget, ConnectionHandle, ConnectionRequest, Direction};
pub use closure::{
    acknowledge_closure, AcknowledgeRefusal, ClosedConnection, ClosedSession, ClosureCause,
    ClosureReport, OtherChannels,
};
pub use gate::{
    ChannelState, CloseReason, ConnectionGate, ConnectionId, GatePublicationId, GateRefusal,
    Pumped, SandboxRegistration, SessionId, DEFAULT_CHUNK_BYTES,
};
pub use ingress::{AdmittedAs, InboundRequest, IngressHandle};
pub use service_grant::{
    published_service_digest, published_service_grant, published_service_grant_id,
    PUBLISHED_SERVICE_DOMAIN,
};
pub use status::{
    ByteBudgetView, ConnectionStatus, PublicationState, PublicationStatus, SessionStatus,
};
pub use stream::{SessionStream, StreamError, StreamRead};
pub use verifier::{AuthenticationProof, ProofBinding, ProofRefusal, ProofVerifier, VerifiedProof};
