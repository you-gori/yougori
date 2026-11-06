//! M09D: the broker's side of a relay exchange: independent authorization, the upstream
//! TLS connection, the executor's credential and the echo scan
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1 "Separate authority
//! from guest-facing parsing", §4.3 "TLS, HTTP and protocol confusion", §4.5 "Credential
//! executors and secret classes" with the echo of line 2008, §4.2 step 7 and the budgets
//! of §2.5; VM-W11 "Confined guest relay and restricted transport broker ... independent
//! authorization and quotas. No vault values in the generic relay", VM-W03, VM-W28 "No
//! credential in relay"). The broker half of M09.
//!
//! - [`exchange`]: [`BrokerExchange`], the sans-IO core. For each
//!   [`RelayMessage::Forward`](crate::sandbox_contract::relay_link::RelayMessage::Forward)
//!   it re-reads the bytes with its own
//!   [`RequestReader`](crate::sandbox_contract::relay::RequestReader), authorizes the
//!   request's authority under its own
//!   [`DestinationBroker`](crate::sandbox_contract::destinations::DestinationBroker),
//!   checks the guest's TLS server name, plans the credential, opens the connection permit
//!   and runs its own [`RelayStep`](crate::sandbox_contract::relay::RelayStep) and
//!   [`ResponseStep`](crate::sandbox_contract::relay::ResponseStep), so every reservation
//!   is made, and settled, as those steps say, also on every failure. [`ExchangeBook`]
//!   bounds the exchanges and answers each once.
//! - [`credential`]: [`CredentialInjector`] adds exactly the header the route's
//!   [`CredentialAudience`] is granted under a V07
//!   [`VaultGrant`](crate::sandbox_contract::provider::VaultGrant), checked through
//!   [`GrantTable::permits`](crate::sandbox_contract::provider::GrantTable::permits), with
//!   the value from the [`HeaderVault`] port; [`EchoScan`] refuses a response that
//!   reflects it or a known secret, naming the encoding.
//! - [`transport`]: [`UpstreamTransport`] connects only to the permit's address through an
//!   [`UpstreamConnector`], terminates TLS with `tokio-rustls` ([`UpstreamTls`]: `ring`,
//!   TLS 1.2 or newer, the authorized name, ALPN `http/1.1` only, no resumption), sends
//!   the exact bytes, reads one response and closes, within [`UpstreamDeadlines`].
//!   Plaintext is used only where the [`UpstreamPolicy`] explicitly allows it.
//! - [`link`]: [`RelayBroker::serve`], the link loop over a [`LinkPort`] ([`StreamLink`]
//!   for any byte stream, [`BridgedLink`] for M09C's named pipe), answering in order of
//!   completion.
//! - [`refusal`]: [`BrokerRefusal`], the full typed reason for the broker's record, and
//!   its closed [`ExchangeRefusal`](crate::sandbox_contract::relay_link::ExchangeRefusal)
//!   for the relay.
//!
//! **What the relay must send (the contract M09E meets).** The broker decides everything
//! again and repairs nothing. A `RelayMessage::Forward { exchange, route, request }` is
//! answered with a guest response only if:
//!
//! - `exchange` is above every exchange the relay forwarded before, with at most
//!   [`MAX_OPEN_EXCHANGES`](crate::sandbox_contract::relay_link::MAX_OPEN_EXCHANGES)
//!   unanswered;
//! - `route` is the operation route of the sandbox's route table that the broker's
//!   current policy authorizes the request's `host` authority on (anything else is
//!   `NotPermitted`);
//! - `request` is one complete HTTP/1.1 request that is byte for byte what the broker's
//!   relay step rebuilds from it, that is, a fixed point of
//!   [`RelayStep`](crate::sandbox_contract::relay::RelayStep)'s rebuild: the request line
//!   `METHOD target HTTP/1.1` with the target written by
//!   [`BoundRequest::outbound_target`](crate::sandbox_contract::destinations::BoundRequest::outbound_target)
//!   (normalized path, query keys in sorted order); then `host: ` and the canonical host,
//!   with `:port` only for a port other than 443; then the guest's other accepted fields
//!   in received order with lowercase names, one space after the colon (none for an
//!   empty value), without
//!   [`NOT_FORWARDED_HEADERS`](crate::sandbox_contract::relay::NOT_FORWARDED_HEADERS);
//!   then one `content-length` of the decoded body (`0` for POST, PUT, PATCH or DELETE
//!   without a body, none for GET, HEAD or OPTIONS without one); CRLF line ends, the empty
//!   line and the decoded body, and no byte after it. It never carries a credential
//!   header, chunked framing, `Expect` or a second request. Any other bytes are refused as
//!   `RequestRefused`, with nothing sent upstream.
//!
//! The broker answers each exchange once: `BrokerMessage::Response` with the bytes its own
//! response step rebuilt and its echo scan passed, or `BrokerMessage::Refused` naming only
//! the stage. The credential never appears in a message, a `Debug` or `Display` output or
//! an error.
//!
//! Outside this module: the confined relay process and its launch (M09E); the real vault
//! (S04/S05); resolving and connecting through the host perimeter (M10: the
//! [`PermitSource`] and [`UpstreamConnector`] ports); the guest transport and the facts
//! of the guest's TLS connection (M06: [`GuestTlsSource`]; the link carries none);
//! HTTP/2; keep-alive and connection reuse; following redirects; and live validation
//! (E01).

pub mod credential;
pub mod exchange;
pub mod link;
pub mod refusal;
pub mod transport;

/// The fixtures (a real V02 broker over a fake resolver and vault, a scripted TLS upstream)
/// the relay host's tests reuse.
#[cfg(test)]
pub(crate) mod tests;

pub use credential::{
    CredentialAudience, CredentialHeader, CredentialInjector, CredentialPlan, EchoFinding,
    EchoScan, HeaderVault, InjectionRefusal, ResponsePart, UpstreamBytes,
};
pub use exchange::{
    BrokerExchange, ExchangeAnswer, ExchangeBook, ExchangeConfig, ExchangeLimits, ExchangeOutcome,
    ExchangeSlot, PermitSource, ResolvingPermits, TlsName, UpstreamPlan, UpstreamPolicy,
    UpstreamSecurity,
};
pub use link::{
    BlockingLink, BridgeTiming, BridgedLink, ExchangeObserver, ExchangeRecord, GuestTlsSource, LinkEnd, LinkFailure,
    LinkPort, LinkReport, RelayBroker, StreamLink,
};
pub use refusal::{BrokerRefusal, TlsFailure, UpstreamFailure, UpstreamStage};
pub use transport::{
    lock_broker, SharedBroker, TcpConnector, TlsSetupError, UpstreamConnector, UpstreamDeadlines,
    UpstreamIo, UpstreamTls, UpstreamTransport, HTTP_11_ALPN,
};
