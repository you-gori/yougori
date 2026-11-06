//! The broker's sans-IO core for one forwarded request (VM part §3.1: the relay forwards
//! typed requests and authority stays with the broker; VM-W11: independent authorization
//! and quotas; VM §4.2 step 7 and §2.5: bytes reserved centrally before use; VM-W03).
//!
//! [`ExchangeBook`] bounds a link's exchanges on the broker's side: at most
//! [`MAX_OPEN_EXCHANGES`] open, numbered upward, each answered once (an [`ExchangeSlot`]
//! is consumed by its answer).
//!
//! [`BrokerExchange::admit`] trusts nothing the relay decided. In order, with the
//! broker's own [`DestinationBroker`]:
//!
//! 1. [`RelayStep::start`] on the forwarded route, which must be an operation route of the
//!    current policy;
//! 2. the broker's own [`RequestReader`] reads the forwarded bytes, and the request's
//!    authority is taken from its `host` field with V02's one parser;
//! 3. the broker authorizes that authority under the current policy, and it must land on
//!    the forwarded route;
//! 4. the guest's TLS server name ([`TlsFacts`]) must be the authorized destination's
//!    name (and absent for an address), before any name is resolved or any connection is
//!    charged;
//! 5. V02's [`bind_request`] binds the request, and on a credentialed route the
//!    [`CredentialInjector`] plans the credential under the grant table and the vault's
//!    facts, still before anything is reserved;
//! 6. a [`PermitSource`] resolves through the route's allowed resolver (or validates the
//!    exact endpoint) and opens the [`ConnectionPermit`];
//! 7. the broker's own [`RelayStep`] reads the bytes again and finishes on that permit
//!    with the credential header's length as its allowance, reserving the send (and an
//!    effect for an external operation);
//! 8. the decision's bytes must equal the forwarded bytes exactly, and its binding the
//!    binding of step 5;
//! 9. the credential header is added ([`UpstreamBytes`]);
//! 10. [`ResponseStep::start`] reserves the response in the broker's book.
//!
//! Only then is an [`UpstreamPlan`] returned: the permit's address and port, never
//! anything resolved from guest input; TLS with the authorized server name, or plaintext
//! only on a route the [`UpstreamPolicy`] explicitly allows and that carries no
//! credential; and the exact bytes to send. A refusal at any step returns every
//! reservation made so far and answers with a typed [`BrokerRefusal`].
//!
//! The transport then reports what happened ([`BrokerExchange::record_sent`],
//! [`BrokerExchange::feed`], [`BrokerExchange::end_of_input`]), and the exchange ends
//! exactly once, in [`BrokerExchange::complete`] or [`BrokerExchange::fail`], which
//! settle what is still open: the send with the bytes that left, the receive with the
//! bytes that arrived, and the effect as committed (a response arrived), uncertain (bytes
//! left, no response) or not performed (nothing left). A complete response is scanned
//! for the credential and every known secret before it is answered.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::credential::{CredentialInjector, EchoScan, UpstreamBytes};
use super::refusal::BrokerRefusal;
use crate::foundation::ids::Clock;
use crate::sandbox_contract::destinations::{
    bind_request, AddressFamily, Authority, AuthorizedDestination, BoundRequest, CanonicalName,
    ConnectionPermit, DestinationBroker, DestinationHost, DestinationPort, DestinationRefusal,
    DestinationRequest, EffectOutcome, EffectReservation, OperationRoute, Reach, RequestRefusal,
    Resolver, RouteId, RouteKind, RouteProtocol, SendReservation, TlsFacts,
};
use crate::sandbox_contract::provider::KnownSecrets;
use crate::sandbox_contract::relay::{
    ForwardDecision, ReadOutcome, ReadProgress, ReadRequest, ReaderLimits, RelayRefusal, RelayStep,
    RequestReader, ResponseStep,
};
use crate::sandbox_contract::relay_link::{
    BrokerMessage, ExchangeId, WireBytes, MAX_OPEN_EXCHANGES,
};

/// The reader limits of one exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExchangeLimits {
    /// For the forwarded request; the body limit is lowered to the route's outbound byte
    /// budget.
    pub request: ReaderLimits,
    /// For the upstream's response; the reservation is capped by the route's inbound
    /// byte budget.
    pub response: ReaderLimits,
}

/// Turns an authorized destination into a permitted connection in the broker's book.
/// The host perimeter (M10) owns the real resolver.
pub trait PermitSource<C: Clock>: Send + Sync {
    fn permit(
        &self,
        broker: &mut DestinationBroker<C>,
        authorized: &AuthorizedDestination,
    ) -> Result<ConnectionPermit, DestinationRefusal>;
}

/// Resolves a name grant through `resolver`, which must be the grant's allowed resolver,
/// or validates an exact endpoint, and opens a connection to the first validated
/// address. Nothing is resolved from anything but the authorized destination.
pub struct ResolvingPermits<R> {
    resolver: R,
    family: AddressFamily,
}

impl<R> ResolvingPermits<R> {
    pub fn new(resolver: R, family: AddressFamily) -> Self {
        Self { resolver, family }
    }
}

impl<R> fmt::Debug for ResolvingPermits<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvingPermits")
            .field("family", &self.family)
            .finish_non_exhaustive()
    }
}

impl<C: Clock, R: Resolver + Send + Sync> PermitSource<C> for ResolvingPermits<R> {
    fn permit(
        &self,
        broker: &mut DestinationBroker<C>,
        authorized: &AuthorizedDestination,
    ) -> Result<ConnectionPermit, DestinationRefusal> {
        let validated = match authorized.reach() {
            Reach::Resolve { .. } => broker.resolve(authorized, self.family, &self.resolver)?,
            Reach::Endpoint { .. } => broker.validate_endpoint(authorized)?,
        };
        let address = validated
            .addresses()
            .first()
            .map(|verdict| verdict.address)
            .ok_or(DestinationRefusal::EmptyAnswer)?;
        broker.open_connection(&validated, address)
    }
}

/// The routes the upstream may be reached on in plaintext. Every other route uses TLS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpstreamPolicy {
    plaintext: BTreeSet<RouteId>,
}

impl UpstreamPolicy {
    /// TLS on every route.
    pub fn tls_only() -> Self {
        Self::default()
    }

    /// Explicitly allows plaintext upstream on `route`. A route with a credential is still
    /// refused at admission: a credential is never sent in plaintext.
    pub fn allow_plaintext(mut self, route: RouteId) -> Self {
        self.plaintext.insert(route);
        self
    }

    pub fn allows_plaintext(&self, route: &RouteId) -> bool {
        self.plaintext.contains(route)
    }
}

/// The name TLS verifies the upstream's certificate for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TlsName {
    Dns(CanonicalName),
    /// An exact endpoint grant without a name is verified for its address.
    Address(IpAddr),
}

impl fmt::Display for TlsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => fmt::Display::fmt(name, f),
            Self::Address(address) => fmt::Display::fmt(address, f),
        }
    }
}

/// How the upstream is reached.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamSecurity {
    Tls(TlsName),
    /// Only on a route the [`UpstreamPolicy`] allows and that carries no credential.
    Plaintext,
}

/// What the transport needs for one admitted exchange.
#[derive(Debug)]
pub struct UpstreamPlan {
    target: SocketAddr,
    security: UpstreamSecurity,
    request: UpstreamBytes,
}

impl UpstreamPlan {
    /// The permit's address and the authorized port; nothing else is connected to.
    pub const fn target(&self) -> SocketAddr {
        self.target
    }

    pub fn security(&self) -> &UpstreamSecurity {
        &self.security
    }

    /// The exact bytes to send: the decision's bytes plus the credential header.
    pub fn request(&self) -> &UpstreamBytes {
        &self.request
    }
}

/// Everything the broker's core needs besides its book (one per sandbox).
pub struct ExchangeConfig<C: Clock> {
    pub limits: ExchangeLimits,
    pub permits: Arc<dyn PermitSource<C>>,
    pub credentials: Arc<CredentialInjector>,
    pub upstream: UpstreamPolicy,
    /// Fixture secrets and canaries every response is scanned for.
    pub known: Arc<KnownSecrets>,
}

impl<C: Clock> fmt::Debug for ExchangeConfig<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeConfig")
            .field("limits", &self.limits)
            .field("credentials", &self.credentials)
            .field("upstream", &self.upstream)
            .field("known", &self.known)
            .finish_non_exhaustive()
    }
}

/// The right and the duty to answer one exchange once. Not `Clone`: the answer consumes
/// it.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an open exchange is answered exactly once"]
pub struct ExchangeSlot {
    exchange: ExchangeId,
}

impl ExchangeSlot {
    pub const fn exchange(&self) -> ExchangeId {
        self.exchange
    }

    /// The slot of an exchange whose state is already gone, so that it can still be
    /// answered once.
    pub(super) const fn closed(exchange: ExchangeId) -> Self {
        Self { exchange }
    }
}

/// The broker's own bound on a link's exchanges (see the module notes).
#[derive(Debug, Default)]
pub struct ExchangeBook {
    last: Option<ExchangeId>,
    open: BTreeSet<ExchangeId>,
}

impl ExchangeBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens `exchange`, which must be above every exchange opened before, while fewer
    /// than [`MAX_OPEN_EXCHANGES`] are open.
    pub fn open(&mut self, exchange: ExchangeId) -> Result<ExchangeSlot, BrokerRefusal> {
        if let Some(last) = self.last {
            if exchange <= last {
                return Err(BrokerRefusal::ExchangeNotIncreasing { exchange, last });
            }
        }
        if self.open.len() >= MAX_OPEN_EXCHANGES {
            return Err(BrokerRefusal::TooManyOpenExchanges {
                max: MAX_OPEN_EXCHANGES,
            });
        }
        self.last = Some(exchange);
        self.open.insert(exchange);
        Ok(ExchangeSlot { exchange })
    }

    /// Closes the slot's exchange as answered.
    pub fn answer(&mut self, slot: ExchangeSlot) -> ExchangeId {
        self.open.remove(&slot.exchange);
        slot.exchange
    }

    /// Exchanges opened and not yet answered.
    pub fn open_exchanges(&self) -> usize {
        self.open.len()
    }
}

/// How an exchange ended, for the broker's own record. It holds no credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// The guest response went to the relay.
    Answered {
        status: u16,
        sent_bytes: u64,
        received_bytes: u64,
    },
    Refused(BrokerRefusal),
}

/// One exchange's one answer: the message for the relay and the full outcome.
#[derive(Debug)]
#[must_use = "an answer is sent to the relay and its slot closed in the book"]
pub struct ExchangeAnswer {
    slot: ExchangeSlot,
    message: BrokerMessage,
    outcome: ExchangeOutcome,
}

impl ExchangeAnswer {
    /// The answer that refuses the slot's exchange with `refusal`.
    pub fn refused(slot: ExchangeSlot, refusal: BrokerRefusal) -> Self {
        Self {
            message: BrokerMessage::Refused {
                exchange: slot.exchange,
                refusal: refusal.exchange_refusal(),
            },
            outcome: ExchangeOutcome::Refused(refusal),
            slot,
        }
    }

    pub const fn exchange(&self) -> ExchangeId {
        self.slot.exchange
    }

    pub fn message(&self) -> &BrokerMessage {
        &self.message
    }

    pub fn outcome(&self) -> &ExchangeOutcome {
        &self.outcome
    }

    pub fn into_parts(self) -> (ExchangeSlot, BrokerMessage, ExchangeOutcome) {
        (self.slot, self.message, self.outcome)
    }
}

/// One admitted exchange, from its reservations to its answer (see the module notes).
#[derive(Debug)]
#[must_use = "an exchange holds reservations until it completes or fails"]
pub struct BrokerExchange {
    slot: ExchangeSlot,
    route: RouteId,
    bound: BoundRequest,
    permit: ConnectionPermit,
    send: Option<SendReservation>,
    effect: Option<EffectReservation>,
    response: Option<ResponseStep>,
    sent: u64,
    echo: EchoScan,
}

/// What admission produced before the slot is attached.
struct Admitted {
    exchange: BrokerExchangeParts,
    plan: UpstreamPlan,
}

struct BrokerExchangeParts {
    route: RouteId,
    bound: BoundRequest,
    permit: ConnectionPermit,
    send: SendReservation,
    effect: Option<EffectReservation>,
    response: ResponseStep,
    echo: EchoScan,
}

impl BrokerExchange {
    /// Admits the request the relay forwarded as the slot's exchange on `route`; `tls` are
    /// the facts of the guest's TLS connection, from the broker's side (see the module
    /// notes). A refusal is the exchange's answer, with nothing left reserved.
    pub fn admit<C: Clock>(
        config: &ExchangeConfig<C>,
        broker: &mut DestinationBroker<C>,
        slot: ExchangeSlot,
        route: RouteId,
        request: &WireBytes,
        tls: &TlsFacts,
    ) -> Result<(Self, UpstreamPlan), Box<ExchangeAnswer>> {
        match admit(config, broker, route, request.as_slice(), tls) {
            Ok(Admitted { exchange, plan }) => Ok((
                Self {
                    slot,
                    route: exchange.route,
                    bound: exchange.bound,
                    permit: exchange.permit,
                    send: Some(exchange.send),
                    effect: exchange.effect,
                    response: Some(exchange.response),
                    sent: 0,
                    echo: exchange.echo,
                },
                plan,
            )),
            Err(refusal) => Err(Box::new(ExchangeAnswer::refused(slot, refusal))),
        }
    }

    pub const fn exchange(&self) -> ExchangeId {
        self.slot.exchange
    }

    pub fn route(&self) -> &RouteId {
        &self.route
    }

    pub fn bound(&self) -> &BoundRequest {
        &self.bound
    }

    pub fn permit(&self) -> &ConnectionPermit {
        &self.permit
    }

    /// Records that `bytes` of the upstream request left, once the send ended, whether it
    /// finished or failed, and settles the send reservation with them.
    pub fn record_sent<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
        bytes: u64,
    ) -> Result<(), BrokerRefusal> {
        self.sent = bytes;
        match self.send.take() {
            Some(send) => Ok(broker.complete_send(send, bytes)?),
            None => Ok(()),
        }
    }

    /// Feeds the upstream's next bytes to the response step. A refusal is final.
    pub fn feed<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
        input: &[u8],
    ) -> Result<ReadProgress, BrokerRefusal> {
        match self.response.as_mut() {
            Some(response) => Ok(response.feed(broker, input)?),
            None => Err(BrokerRefusal::Cancelled),
        }
    }

    /// The upstream closed the connection.
    pub fn end_of_input<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
    ) -> Result<ReadProgress, BrokerRefusal> {
        match self.response.as_mut() {
            Some(response) => Ok(response.end_of_input(broker)?),
            None => Err(BrokerRefusal::Cancelled),
        }
    }

    /// Ends the exchange after its response was read: settles everything, scans the
    /// rebuilt response for the credential and every known secret, and answers with it,
    /// or refuses it without sending any of it.
    pub fn complete<C: Clock>(mut self, broker: &mut DestinationBroker<C>) -> ExchangeAnswer {
        let sent = self.sent;
        if let Err(refusal) = self.settle_send(broker) {
            return self.fail(broker, refusal);
        }
        let Some(response) = self.response.take() else {
            return self.fail(broker, BrokerRefusal::Cancelled);
        };
        match response.finish(broker) {
            Ok(guest) => {
                let settled = self.settle_effect(broker, EffectOutcome::Committed);
                if let Some(finding) = self.echo.scan(guest.bytes()) {
                    return ExchangeAnswer::refused(self.slot, BrokerRefusal::Echo(finding));
                }
                if let Err(refusal) = settled {
                    return ExchangeAnswer::refused(self.slot, refusal);
                }
                let status = guest.status();
                let received = guest.received_bytes();
                ExchangeAnswer {
                    message: BrokerMessage::response(self.slot.exchange, guest),
                    outcome: ExchangeOutcome::Answered {
                        status,
                        sent_bytes: sent,
                        received_bytes: received,
                    },
                    slot: self.slot,
                }
            }
            Err(refusal) => self.fail(broker, refusal.into()),
        }
    }

    /// Ends the exchange with `refusal`: the send settles with the bytes that left, the
    /// response with the bytes that arrived, and the effect as uncertain if any byte left
    /// or not performed if none did.
    pub fn fail<C: Clock>(
        mut self,
        broker: &mut DestinationBroker<C>,
        refusal: BrokerRefusal,
    ) -> ExchangeAnswer {
        // The refusal is the reason; a failure to settle as well would only hide it.
        let _ = self.settle_send(broker);
        if let Some(response) = self.response.take() {
            let _ = response.abandon(broker);
        }
        let outcome = if self.sent == 0 {
            EffectOutcome::NotPerformed
        } else {
            EffectOutcome::Uncertain
        };
        let _ = self.settle_effect(broker, outcome);
        ExchangeAnswer::refused(self.slot, refusal)
    }

    fn settle_send<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
    ) -> Result<(), BrokerRefusal> {
        match self.send.take() {
            Some(send) => Ok(broker.complete_send(send, self.sent)?),
            None => Ok(()),
        }
    }

    fn settle_effect<C: Clock>(
        &mut self,
        broker: &mut DestinationBroker<C>,
        outcome: EffectOutcome,
    ) -> Result<(), BrokerRefusal> {
        match self.effect.take() {
            Some(effect) => Ok(broker.settle_effect(effect, outcome)?),
            None => Ok(()),
        }
    }
}

/// Steps 1–10 of the module notes.
fn admit<C: Clock>(
    config: &ExchangeConfig<C>,
    broker: &mut DestinationBroker<C>,
    route: RouteId,
    forwarded: &[u8],
    tls: &TlsFacts,
) -> Result<Admitted, BrokerRefusal> {
    let mut step = RelayStep::start(broker, &route, config.limits.request)?;
    let read = read_own(broker, &route, config.limits.request, forwarded)?;
    let authority = request_authority(&read)?;
    let authorized = broker.authorize(&DestinationRequest {
        protocol: RouteProtocol::Https,
        authority,
    })?;
    if authorized.route() != &route {
        return Err(BrokerRefusal::RouteMismatch {
            forwarded: route,
            authorized: authorized.route().clone(),
        });
    }
    let server_name = server_name(broker, &authorized, &route)?;
    check_sni(authorized.authority(), &server_name, tls)?;
    let operation = operation_route(broker, &route)?;
    let first = bind_request(
        &route,
        &operation,
        authorized.authority(),
        read.request(),
        tls,
    )?;
    let credential = config.credentials.plan(&route, &operation, &first)?;
    let security = if config.upstream.allows_plaintext(&route) {
        if operation.is_credentialed() {
            return Err(BrokerRefusal::PlaintextRefused { route });
        }
        UpstreamSecurity::Plaintext
    } else {
        UpstreamSecurity::Tls(server_name)
    };
    let allowance = credential.as_ref().map_or(0, |plan| plan.allowance());
    let permit = config.permits.permit(broker, &authorized)?;
    step.feed(forwarded)?;
    let decision = step.finish(broker, &permit, tls, allowance)?;
    if decision.bytes() != forwarded {
        let refusal = BrokerRefusal::BytesDiffer {
            forwarded_bytes: length(forwarded),
            rebuilt_bytes: length(decision.bytes()),
        };
        return Err(abandon(broker, decision, refusal));
    }
    if decision.bound() != &first {
        return Err(abandon(broker, decision, BrokerRefusal::BindingDiffers));
    }
    let (request, echo) = match &credential {
        Some(plan) => {
            match config
                .credentials
                .inject(plan, decision.bytes(), Arc::clone(&config.known))
            {
                Ok(injected) => (injected.bytes, injected.echo),
                Err(refusal) => return Err(abandon(broker, decision, refusal.into())),
            }
        }
        None => (
            UpstreamBytes::new(decision.bytes().to_vec()),
            EchoScan::known_only(Arc::clone(&config.known)),
        ),
    };
    let response =
        match ResponseStep::start(broker, &permit, decision.bound(), config.limits.response) {
            Ok(response) => response,
            Err(refusal) => return Err(abandon(broker, decision, refusal.into())),
        };
    let parts = decision.into_parts();
    let target = SocketAddr::new(permit.address(), permit.authority().port.get());
    Ok(Admitted {
        exchange: BrokerExchangeParts {
            route,
            bound: parts.bound,
            permit,
            send: parts.send,
            effect: parts.effect,
            response,
            echo,
        },
        plan: UpstreamPlan {
            target,
            security,
            request,
        },
    })
}

/// Returns a decision's reservations unused and gives the refusal back.
fn abandon<C: Clock>(
    broker: &mut DestinationBroker<C>,
    decision: ForwardDecision,
    refusal: BrokerRefusal,
) -> BrokerRefusal {
    // The refusal is the reason; a failure to return the reservations would only hide it.
    let _ = decision.abandon(broker);
    refusal
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// The broker's own reading of the forwarded bytes, with the relay step's limits.
fn read_own<C: Clock>(
    broker: &DestinationBroker<C>,
    route: &RouteId,
    limits: ReaderLimits,
    forwarded: &[u8],
) -> Result<ReadRequest, BrokerRefusal> {
    let grant = broker
        .policy()
        .grant(route)
        .ok_or_else(|| DestinationRefusal::UnknownRoute {
            route: route.clone(),
        })?;
    let mut reader = RequestReader::new(limits.with_body_cap(grant.budgets.bytes_out));
    // A refusal is kept by the reader and reported by its outcome.
    let _ = reader.feed(forwarded);
    match reader.into_outcome() {
        ReadOutcome::Complete(read) => Ok(read),
        ReadOutcome::NeedMore => Err(RelayRefusal::Incomplete.into()),
        ReadOutcome::Refused(refusal) => Err(RelayRefusal::Read(refusal).into()),
    }
}

/// The request's authority from its one `host` field, with V02's parser.
fn request_authority(read: &ReadRequest) -> Result<Authority, BrokerRefusal> {
    let mut hosts = read
        .request()
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"));
    let (_, host) = hosts.next().ok_or(RequestRefusal::MissingAuthority)?;
    if hosts.next().is_some() {
        return Err(RequestRefusal::DuplicateHeader {
            name: "host".to_owned(),
        }
        .into());
    }
    Ok(Authority::parse(host, DestinationPort::HTTPS).map_err(RequestRefusal::InvalidAuthority)?)
}

/// The name the upstream's certificate must be valid for: the authorized name, an exact
/// endpoint's name, or an exact endpoint's address.
fn server_name<C: Clock>(
    broker: &DestinationBroker<C>,
    authorized: &AuthorizedDestination,
    route: &RouteId,
) -> Result<TlsName, BrokerRefusal> {
    if let Some(name) = authorized.tls_name(broker.policy()) {
        return Ok(TlsName::Dns(name.clone()));
    }
    match (&authorized.authority().host, authorized.reach()) {
        (DestinationHost::Address(address), Reach::Endpoint { address: endpoint })
            if address == endpoint =>
        {
            Ok(TlsName::Address(*address))
        }
        _ => Err(BrokerRefusal::NoServerName {
            route: route.clone(),
        }),
    }
}

/// The guest's server name must be the authorized name, and absent for an address (V02's
/// rule for the guest's TLS connection).
fn check_sni(
    authority: &Authority,
    server_name: &TlsName,
    tls: &TlsFacts,
) -> Result<(), BrokerRefusal> {
    let matches = match (&authority.host, server_name, tls.sni.as_deref()) {
        (DestinationHost::Name(host), TlsName::Dns(name), Some(sni)) => {
            host == name && CanonicalName::parse(sni).is_ok_and(|sni| sni == *name)
        }
        (DestinationHost::Address(_), _, None) => true,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(BrokerRefusal::SniMismatch {
            sni: tls.sni.clone(),
            server_name: server_name.to_string(),
        })
    }
}

fn operation_route<C: Clock>(
    broker: &DestinationBroker<C>,
    route: &RouteId,
) -> Result<OperationRoute, BrokerRefusal> {
    let grant = broker
        .policy()
        .grant(route)
        .ok_or_else(|| DestinationRefusal::UnknownRoute {
            route: route.clone(),
        })?;
    match &grant.route {
        RouteKind::Operation(operation) => Ok(operation.clone()),
        RouteKind::Transport(_) => Err(RelayRefusal::NotAnOperationRoute {
            route: route.clone(),
        }
        .into()),
    }
}
