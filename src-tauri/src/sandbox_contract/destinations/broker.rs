//! The destination broker's decision sequence (VM §4.2 steps 1–7; VM-W11; VM-P07–VM-P10,
//! VM-P32, VM-P33).
//!
//! 1–2. The request is parsed with the one parser and authorized by policy before any
//!      resolution ([`DestinationBroker::authorize`]).
//! 3.   Resolution goes only through the grant's allowed resolver, never for a sensitive
//!      task, and each query is charged to the route's name budget and to the DNS release
//!      channel before it is sent ([`DestinationBroker::resolve`]).
//! 4.   Every address in the answer is classified; one refused address refuses the answer.
//! 5–6. A connection goes only to a validated address, and only while the policy epoch,
//!      the host-address generation and the answer's lifetime are all still current;
//!      redirects go through steps 1–4 again ([`DestinationBroker::follow_redirect`]).
//! 7.   Connections, bytes and effects are reserved centrally before use.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use super::address::{
    classify, AddressRefused, AddressRule, AddressVerdict, HostAddressGeneration, HostAddressState,
};
use super::budget::{
    BudgetBook, BudgetExhausted, BudgetKind, BudgetReservation, ReleaseAccount, ReleaseChannel,
    ReleaseError, ReleaseReservation, RouteUsage, SettleError,
};
use super::http::{redirect_target, RequestRefusal};
use super::mode::{AddressFamily, SyntheticAddressPlan, SyntheticError};
use super::name::{Authority, CanonicalName, DestinationHost};
use super::policy::{
    AuthorizationRefusal, AuthorizedDestination, DestinationPolicy, DestinationRequest, Reach,
    RouteGrant, RouteId, TaskDataClass,
};
use super::resolver::{ResolutionQuery, Resolver, ResolverFailure, ResolverId, MAX_ALIAS_CHAIN};
use super::route::{RedirectPolicy, RouteKind};
use crate::foundation::ids::{Clock, MonotonicTime, PolicyEpoch};

/// Why the broker refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationRefusal {
    Authorization(AuthorizationRefusal),
    /// The destination was authorized under an older policy epoch, or the connection was
    /// validated under an older epoch or host-address generation: authorize again.
    Stale {
        policy_epoch: PolicyEpoch,
        host_generation: HostAddressGeneration,
    },
    /// The validated answer's lifetime ended: resolve again.
    Expired,
    UnknownRoute {
        route: RouteId,
    },
    /// The resolver is not the grant's allowed resolver.
    ResolverNotAllowed {
        resolver: ResolverId,
    },
    /// The grant reaches a fixed endpoint; nothing is resolved for it.
    EndpointNotResolved,
    /// The grant resolves names; use [`DestinationBroker::resolve`].
    NotAnEndpoint,
    /// A sensitive offline task never resolves names.
    ResolutionForbidden,
    /// AAAA was asked for a grant without IPv6 (line 1940: no misleading answers).
    Ipv6NotGranted,
    ResolverFailed(ResolverFailure),
    /// The answer is for another name, so the resolver applied a search suffix or
    /// answered something else.
    AnswerForOtherName {
        asked: CanonicalName,
        answered: CanonicalName,
    },
    /// The answer has addresses of the other family, such as IPv4 for an AAAA query.
    WrongFamily {
        asked: AddressFamily,
        address: IpAddr,
    },
    AliasChainTooLong {
        length: usize,
    },
    EmptyAnswer,
    Address(AddressRefused),
    Synthetic(SyntheticError),
    /// The address was not part of the validated answer.
    AddressNotValidated {
        address: IpAddr,
    },
    Budget(BudgetExhausted),
    Release(ReleaseError),
    Settle(SettleError),
    Redirect(RequestRefusal),
    /// Redirects are not followed on this route.
    RedirectsDisabled,
    /// A redirect may not leave its route.
    RedirectLeavesRoute {
        from: RouteId,
        to: RouteId,
    },
    /// A replacement policy or host-address state must have a newer epoch or generation.
    NotNewer,
}

impl fmt::Display for DestinationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(refusal) => fmt::Display::fmt(refusal, f),
            Self::Stale {
                policy_epoch,
                host_generation,
            } => write!(
                f,
                "the destination was checked under an older policy (now epoch {policy_epoch}) \
                 or host-address state (now generation {host_generation}); check it again"
            ),
            Self::Expired => f.write_str("the resolved answer expired; resolve it again"),
            Self::UnknownRoute { route } => write!(f, "route {route} is not in the policy"),
            Self::ResolverNotAllowed { resolver } => {
                write!(f, "resolver {resolver} is not the route's allowed resolver")
            }
            Self::EndpointNotResolved => f.write_str("an exact endpoint is never resolved"),
            Self::NotAnEndpoint => f.write_str("this route resolves names"),
            Self::ResolutionForbidden => f.write_str("this sensitive task may not resolve names"),
            Self::Ipv6NotGranted => f.write_str("IPv6 is not granted for this route"),
            Self::ResolverFailed(failure) => fmt::Display::fmt(failure, f),
            Self::AnswerForOtherName { asked, answered } => {
                write!(
                    f,
                    "asked for {asked} but the resolver answered for {answered}"
                )
            }
            Self::WrongFamily { asked, address } => {
                write!(f, "a {asked:?} query was answered with {address}")
            }
            Self::AliasChainTooLong { length } => write!(
                f,
                "the alias chain has {length} names; at most {MAX_ALIAS_CHAIN} are accepted"
            ),
            Self::EmptyAnswer => f.write_str("the answer has no address"),
            Self::Address(refused) => fmt::Display::fmt(refused, f),
            Self::Synthetic(error) => fmt::Display::fmt(error, f),
            Self::AddressNotValidated { address } => {
                write!(f, "{address} was not validated for this destination")
            }
            Self::Budget(exhausted) => fmt::Display::fmt(exhausted, f),
            Self::Release(error) => fmt::Display::fmt(error, f),
            Self::Settle(error) => fmt::Display::fmt(error, f),
            Self::Redirect(refusal) => fmt::Display::fmt(refusal, f),
            Self::RedirectsDisabled => f.write_str("redirects are disabled on this route"),
            Self::RedirectLeavesRoute { from, to } => {
                write!(f, "a redirect from route {from} may not land on route {to}")
            }
            Self::NotNewer => f.write_str("the replacement is not newer than the current state"),
        }
    }
}

impl std::error::Error for DestinationRefusal {}

impl From<AuthorizationRefusal> for DestinationRefusal {
    fn from(refusal: AuthorizationRefusal) -> Self {
        Self::Authorization(refusal)
    }
}

impl From<BudgetExhausted> for DestinationRefusal {
    fn from(exhausted: BudgetExhausted) -> Self {
        Self::Budget(exhausted)
    }
}

impl From<ReleaseError> for DestinationRefusal {
    fn from(error: ReleaseError) -> Self {
        Self::Release(error)
    }
}

/// A destination whose addresses were validated (VM §4.2 step 4), bound to the policy
/// epoch, host-address generation and lifetime it was checked under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDestination {
    route: RouteId,
    authority: Authority,
    tls_name: Option<CanonicalName>,
    addresses: Vec<AddressVerdict>,
    aliases: Vec<CanonicalName>,
    policy_epoch: PolicyEpoch,
    host_generation: HostAddressGeneration,
    valid_until: MonotonicTime,
}

impl ValidatedDestination {
    pub fn route(&self) -> &RouteId {
        &self.route
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The name TLS must be verified for (VM §4.2 step 5); never an alias.
    pub fn tls_name(&self) -> Option<&CanonicalName> {
        self.tls_name.as_ref()
    }

    pub fn addresses(&self) -> &[AddressVerdict] {
        &self.addresses
    }

    /// The CNAME chain the resolver followed, kept for audit; aliases grant nothing.
    pub fn aliases(&self) -> &[CanonicalName] {
        &self.aliases
    }

    pub const fn policy_epoch(&self) -> PolicyEpoch {
        self.policy_epoch
    }

    pub const fn host_generation(&self) -> HostAddressGeneration {
        self.host_generation
    }

    pub const fn valid_until(&self) -> MonotonicTime {
        self.valid_until
    }
}

/// Permission for one connection to one validated address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionPermit {
    route: RouteId,
    address: IpAddr,
    authority: Authority,
    tls_name: Option<CanonicalName>,
    policy_epoch: PolicyEpoch,
    host_generation: HostAddressGeneration,
}

impl ConnectionPermit {
    pub fn route(&self) -> &RouteId {
        &self.route
    }

    pub const fn address(&self) -> IpAddr {
        self.address
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    pub fn tls_name(&self) -> Option<&CanonicalName> {
        self.tls_name.as_ref()
    }
}

/// A send reserved against the route's byte budget and its release channel.
#[derive(Debug, PartialEq, Eq)]
pub struct SendReservation {
    route: BudgetReservation,
    release: ReleaseReservation,
}

impl SendReservation {
    pub const fn bytes(&self) -> u64 {
        self.release.bytes()
    }
}

/// Bytes to receive, reserved against the route's inbound byte budget. Settle it exactly
/// once, with [`DestinationBroker::complete_received`] or
/// [`DestinationBroker::cancel_received`].
#[derive(Debug, PartialEq, Eq)]
pub struct ReceiveReservation {
    route: BudgetReservation,
}

impl ReceiveReservation {
    pub const fn bytes(&self) -> u64 {
        self.route.amount()
    }
}

/// An external effect reserved against the route's effect budget.
#[derive(Debug, PartialEq, Eq)]
pub struct EffectReservation(BudgetReservation);

/// How a reserved effect ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectOutcome {
    Committed,
    /// The provider may have acted but the outcome was lost; it counts as spent, and a
    /// retry is a new effect (VM-P31).
    Uncertain,
    /// The effect certainly did not happen; the reservation returns.
    NotPerformed,
}

/// The host-side destination broker of one sandbox (VM §4.2).
pub struct DestinationBroker<C: Clock> {
    policy: DestinationPolicy,
    host: HostAddressState,
    synthetic: Option<SyntheticAddressPlan>,
    budgets: BudgetBook,
    release: ReleaseAccount,
    clock: C,
}

impl<C: Clock> DestinationBroker<C> {
    /// A broker for one sandbox, with empty route usage.
    pub fn new(
        policy: DestinationPolicy,
        host: HostAddressState,
        release: ReleaseAccount,
        clock: C,
    ) -> Self {
        Self {
            policy,
            host,
            synthetic: None,
            budgets: BudgetBook::new(),
            release,
            clock,
        }
    }

    /// Uses `plan` so a real address inside the synthetic range is refused.
    pub fn with_synthetic_plan(mut self, plan: SyntheticAddressPlan) -> Self {
        self.synthetic = Some(plan);
        self
    }

    pub fn policy(&self) -> &DestinationPolicy {
        &self.policy
    }

    pub fn host_addresses(&self) -> &HostAddressState {
        &self.host
    }

    pub fn release_account(&self) -> &ReleaseAccount {
        &self.release
    }

    pub fn release_account_mut(&mut self) -> &mut ReleaseAccount {
        &mut self.release
    }

    pub fn usage(&self, route: &RouteId) -> RouteUsage {
        self.budgets.usage(route)
    }

    /// Replaces the policy; its epoch must be newer. Everything validated earlier becomes
    /// stale, while route usage carries over.
    pub fn replace_policy(&mut self, policy: DestinationPolicy) -> Result<(), DestinationRefusal> {
        if policy.epoch() <= self.policy.epoch() {
            return Err(DestinationRefusal::NotNewer);
        }
        self.policy = policy;
        Ok(())
    }

    /// Replaces the host's own addresses; the generation must be newer. Everything
    /// validated earlier becomes stale.
    pub fn replace_host_addresses(
        &mut self,
        host: HostAddressState,
    ) -> Result<(), DestinationRefusal> {
        if host.generation() <= self.host.generation() {
            return Err(DestinationRefusal::NotNewer);
        }
        self.host = host;
        Ok(())
    }

    /// Steps 1–2: authorizes before any resolution.
    pub fn authorize(
        &self,
        request: &DestinationRequest,
    ) -> Result<AuthorizedDestination, DestinationRefusal> {
        Ok(self.policy.authorize(request, self.clock.now())?)
    }

    fn grant(&self, route: &RouteId) -> Result<&RouteGrant, DestinationRefusal> {
        self.policy
            .grant(route)
            .ok_or_else(|| DestinationRefusal::UnknownRoute {
                route: route.clone(),
            })
    }

    fn stale(&self) -> DestinationRefusal {
        DestinationRefusal::Stale {
            policy_epoch: self.policy.epoch(),
            host_generation: self.host.generation(),
        }
    }

    fn check_address(
        &self,
        address: IpAddr,
        rule: AddressRule,
    ) -> Result<AddressVerdict, DestinationRefusal> {
        let verdict = classify(address, &self.host);
        rule.check(verdict).map_err(DestinationRefusal::Address)?;
        if let Some(plan) = &self.synthetic {
            plan.check_real_address(address)
                .map_err(DestinationRefusal::Synthetic)?;
        }
        Ok(verdict)
    }

    /// Steps 3–4: resolves an authorized name through its allowed resolver and validates
    /// every address. The query is charged to the name budget and the DNS release channel
    /// before it is sent, and stays charged whatever the answer.
    pub fn resolve(
        &mut self,
        authorized: &AuthorizedDestination,
        family: AddressFamily,
        resolver: &dyn Resolver,
    ) -> Result<ValidatedDestination, DestinationRefusal> {
        if authorized.epoch() != self.policy.epoch() {
            return Err(self.stale());
        }
        if self.policy.data_class() == TaskDataClass::SensitiveOffline {
            return Err(DestinationRefusal::ResolutionForbidden);
        }
        let (allowed, ipv6) = match authorized.reach() {
            Reach::Resolve { resolver, ipv6 } => (resolver.clone(), *ipv6),
            Reach::Endpoint { .. } => return Err(DestinationRefusal::EndpointNotResolved),
        };
        if resolver.id() != &allowed || !self.policy.resolver_allowed(resolver.id()) {
            return Err(DestinationRefusal::ResolverNotAllowed {
                resolver: resolver.id().clone(),
            });
        }
        if family == AddressFamily::Ipv6 && !ipv6 {
            return Err(DestinationRefusal::Ipv6NotGranted);
        }
        let DestinationHost::Name(name) = &authorized.authority().host else {
            return Err(DestinationRefusal::EndpointNotResolved);
        };
        let grant = self.grant(authorized.route())?.clone();
        let query = ResolutionQuery::new(name.clone(), family);
        let release = self
            .release
            .reserve(ReleaseChannel::DnsQuery, query.released_bytes())?;
        if let Err(exhausted) =
            self.budgets
                .charge(&grant.id, &grant.budgets, BudgetKind::DnsQueries, 1)
        {
            self.release.cancel(release)?;
            return Err(exhausted.into());
        }
        self.release.commit(release, query.released_bytes())?;
        let answer = resolver
            .resolve(&query)
            .map_err(DestinationRefusal::ResolverFailed)?;
        if answer.name != *name {
            return Err(DestinationRefusal::AnswerForOtherName {
                asked: name.clone(),
                answered: answer.name,
            });
        }
        if answer.aliases.len() > MAX_ALIAS_CHAIN {
            return Err(DestinationRefusal::AliasChainTooLong {
                length: answer.aliases.len(),
            });
        }
        if answer.addresses.is_empty() {
            return Err(DestinationRefusal::EmptyAnswer);
        }
        let mut addresses = Vec::with_capacity(answer.addresses.len());
        for address in &answer.addresses {
            let family_matches = match family {
                AddressFamily::Ipv4 => address.is_ipv4(),
                AddressFamily::Ipv6 => address.is_ipv6(),
            };
            if !family_matches {
                return Err(DestinationRefusal::WrongFamily {
                    asked: family,
                    address: *address,
                });
            }
            addresses.push(self.check_address(*address, AddressRule::ResolvedName)?);
        }
        let lifetime = answer.ttl.min(self.policy.max_answer_ttl());
        Ok(ValidatedDestination {
            route: grant.id,
            authority: authorized.authority().clone(),
            tls_name: Some(name.clone()),
            addresses,
            aliases: answer.aliases,
            policy_epoch: self.policy.epoch(),
            host_generation: self.host.generation(),
            valid_until: self.clock.now().saturating_add(lifetime),
        })
    }

    /// Steps 4 for an exact endpoint: validates its fixed address without resolution.
    pub fn validate_endpoint(
        &self,
        authorized: &AuthorizedDestination,
    ) -> Result<ValidatedDestination, DestinationRefusal> {
        if authorized.epoch() != self.policy.epoch() {
            return Err(self.stale());
        }
        let Reach::Endpoint { address } = authorized.reach() else {
            return Err(DestinationRefusal::NotAnEndpoint);
        };
        let verdict = self.check_address(*address, AddressRule::ExactEndpoint)?;
        Ok(ValidatedDestination {
            route: authorized.route().clone(),
            authority: authorized.authority().clone(),
            tls_name: authorized.tls_name(&self.policy).cloned(),
            addresses: vec![verdict],
            aliases: Vec::new(),
            policy_epoch: self.policy.epoch(),
            host_generation: self.host.generation(),
            valid_until: self
                .clock
                .now()
                .saturating_add(self.policy.max_answer_ttl()),
        })
    }

    /// Steps 5–7 for a new connection: the address must be one validated, under the
    /// current policy epoch and host-address generation, before the answer expires; it
    /// is classified again against the current host state and charged to the connection
    /// budget.
    pub fn open_connection(
        &mut self,
        validated: &ValidatedDestination,
        address: IpAddr,
    ) -> Result<ConnectionPermit, DestinationRefusal> {
        if validated.policy_epoch != self.policy.epoch()
            || validated.host_generation != self.host.generation()
        {
            return Err(self.stale());
        }
        if self.clock.now() >= validated.valid_until {
            return Err(DestinationRefusal::Expired);
        }
        if !validated
            .addresses
            .iter()
            .any(|verdict| verdict.address == address)
        {
            return Err(DestinationRefusal::AddressNotValidated { address });
        }
        let grant = self.grant(&validated.route)?.clone();
        let rule = match grant.target {
            super::policy::GrantTarget::Endpoint(_) => AddressRule::ExactEndpoint,
            _ => AddressRule::ResolvedName,
        };
        self.check_address(address, rule)?;
        self.budgets
            .charge(&grant.id, &grant.budgets, BudgetKind::Connections, 1)?;
        Ok(ConnectionPermit {
            route: grant.id,
            address,
            authority: validated.authority.clone(),
            tls_name: validated.tls_name.clone(),
            policy_epoch: self.policy.epoch(),
            host_generation: self.host.generation(),
        })
    }

    fn check_permit(&self, permit: &ConnectionPermit) -> Result<RouteGrant, DestinationRefusal> {
        if permit.policy_epoch != self.policy.epoch()
            || permit.host_generation != self.host.generation()
        {
            return Err(self.stale());
        }
        Ok(self.grant(&permit.route)?.clone())
    }

    /// Reserves `bytes` to send on a permitted connection, against the route's byte
    /// budget and the route's release channel (provider requests for operation routes,
    /// transport streams for transport routes). Count every byte that leaves the trust
    /// domain: headers, URL, names and framing as well as the body (VM §2.5, line 1815).
    pub fn reserve_send(
        &mut self,
        permit: &ConnectionPermit,
        bytes: u64,
    ) -> Result<SendReservation, DestinationRefusal> {
        let grant = self.check_permit(permit)?;
        let channel = match grant.route {
            RouteKind::Operation(_) => ReleaseChannel::ProviderRequest,
            RouteKind::Transport(_) => ReleaseChannel::TransportStream,
        };
        let route = self
            .budgets
            .reserve(&grant.id, &grant.budgets, BudgetKind::BytesOut, bytes)?;
        match self.release.reserve(channel, bytes) {
            Ok(release) => Ok(SendReservation { route, release }),
            Err(error) => {
                self.budgets
                    .cancel(route)
                    .map_err(DestinationRefusal::Settle)?;
                Err(error.into())
            }
        }
    }

    /// Settles a send with the bytes that actually left. Both the route and the release
    /// reservation are settled even when one refuses (more than was reserved), so neither
    /// is left reserved; the route's refusal is reported first.
    pub fn complete_send(
        &mut self,
        reservation: SendReservation,
        actual_bytes: u64,
    ) -> Result<(), DestinationRefusal> {
        let route = self
            .budgets
            .commit(reservation.route, actual_bytes)
            .map_err(DestinationRefusal::Settle);
        let release = self
            .release
            .commit(reservation.release, actual_bytes)
            .map_err(DestinationRefusal::from);
        route.and(release)
    }

    /// Charges received bytes to the route's inbound budget.
    pub fn record_received(
        &mut self,
        permit: &ConnectionPermit,
        bytes: u64,
    ) -> Result<(), DestinationRefusal> {
        let grant = self.check_permit(permit)?;
        self.budgets
            .charge(&grant.id, &grant.budgets, BudgetKind::BytesIn, bytes)?;
        Ok(())
    }

    /// Reserves `bytes` to receive on a permitted connection against the route's inbound
    /// byte budget, before any of them is kept, so concurrent responses cannot each spend
    /// the same remainder (VM §2.5).
    pub fn reserve_received(
        &mut self,
        permit: &ConnectionPermit,
        bytes: u64,
    ) -> Result<ReceiveReservation, DestinationRefusal> {
        let grant = self.check_permit(permit)?;
        let route = self
            .budgets
            .reserve(&grant.id, &grant.budgets, BudgetKind::BytesIn, bytes)?;
        Ok(ReceiveReservation { route })
    }

    /// Settles a receive with the bytes that actually arrived; the rest returns to the
    /// budget. More than was reserved is refused but still charged, so an overrun is
    /// counted and never left reserved.
    pub fn complete_received(
        &mut self,
        reservation: ReceiveReservation,
        actual_bytes: u64,
    ) -> Result<(), DestinationRefusal> {
        self.budgets
            .commit(reservation.route, actual_bytes)
            .map_err(DestinationRefusal::Settle)
    }

    /// Returns a receive reservation unused.
    pub fn cancel_received(
        &mut self,
        reservation: ReceiveReservation,
    ) -> Result<(), DestinationRefusal> {
        self.budgets
            .cancel(reservation.route)
            .map_err(DestinationRefusal::Settle)
    }

    /// Reserves one external effect on the route before the provider is called.
    pub fn reserve_effect(
        &mut self,
        route: &RouteId,
    ) -> Result<EffectReservation, DestinationRefusal> {
        let grant = self.grant(route)?.clone();
        Ok(EffectReservation(self.budgets.reserve(
            &grant.id,
            &grant.budgets,
            BudgetKind::Effects,
            1,
        )?))
    }

    /// Settles an effect; committed and uncertain effects stay spent.
    pub fn settle_effect(
        &mut self,
        reservation: EffectReservation,
        outcome: EffectOutcome,
    ) -> Result<(), DestinationRefusal> {
        let result = match outcome {
            EffectOutcome::Committed | EffectOutcome::Uncertain => {
                self.budgets.commit(reservation.0, 1)
            }
            EffectOutcome::NotPerformed => self.budgets.cancel(reservation.0),
        };
        result.map_err(DestinationRefusal::Settle)
    }

    /// Step 6 for a redirect: the route must re-authorize redirects, and the target goes
    /// through parsing, authorization, resolution and address validation again, landing
    /// on the same route.
    pub fn follow_redirect(
        &mut self,
        from: &ValidatedDestination,
        location: &str,
        family: AddressFamily,
        resolver: &dyn Resolver,
    ) -> Result<ValidatedDestination, DestinationRefusal> {
        let grant = self.grant(&from.route)?.clone();
        match &grant.route {
            RouteKind::Operation(route) if route.redirects() == RedirectPolicy::Reauthorize => {}
            _ => return Err(DestinationRefusal::RedirectsDisabled),
        }
        let target =
            redirect_target(&from.authority, location).map_err(DestinationRefusal::Redirect)?;
        let request = DestinationRequest {
            protocol: grant.protocol,
            authority: target.authority,
        };
        let authorized = self.authorize(&request)?;
        if authorized.route() != &from.route {
            return Err(DestinationRefusal::RedirectLeavesRoute {
                from: from.route.clone(),
                to: authorized.route().clone(),
            });
        }
        match authorized.reach() {
            Reach::Resolve { .. } => self.resolve(&authorized, family, resolver),
            Reach::Endpoint { .. } => self.validate_endpoint(&authorized),
        }
    }

    /// The longest an answer is trusted under the current policy.
    pub fn max_answer_lifetime(&self) -> Duration {
        self.policy.max_answer_ttl()
    }
}
