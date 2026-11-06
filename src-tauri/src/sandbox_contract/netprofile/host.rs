//! The host-side flow model of broader-network VMs (VM-W59; VM-W08; VM §4.2, §4.7;
//! VM-P08, VM-P09, VM-P36), on fakes.
//!
//! [`HostNetwork`] is the host's NAT and connection-tracking view of every admitted
//! sandbox. It decides each new flow against the sandbox's profile at the current policy
//! epoch, using V02 for every single decision: [`DestinationPolicy::authorize`] for
//! names, ports and endpoints, [`classify`] and [`AddressRule`] for addresses, the
//! [`DestinationBroker`] for resolution through an allowed resolver, [`BudgetBook`] and
//! [`ReleaseAccount`] for budgets, [`IngressTable`] for publications and
//! [`SandboxConnections`] for links.
//!
//! The broker resolves; the flow model does not use the broker's connection permits.
//! A permit and a validated destination belong to one policy epoch, so an established
//! flow would otherwise need a new external query and a charged connection whenever an
//! unrelated grant changed. Instead the model keeps the host's DNS answers as bindings
//! from address to name and route, re-checks each binding and flow against the new
//! policy or host-address state when either changes, and closes what no longer passes.
//!
//! The host decision reads only the packet as the host observed it, the profile's grants
//! and the host's own state. The profile's guest compatibility section, the guest's proxy
//! variables and whatever resolver the guest chose are never inputs (VM-P09).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, PolicyEpoch, TrustScope};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    classify, AddressClass, AddressFamily, AddressRule, Authority, AuthorizationRefusal,
    BudgetBook, BudgetKind, CanonicalName, ConnectionRefusal, DestinationBroker, DestinationHost,
    DestinationPolicy, DestinationPort, DestinationRefusal, DestinationRequest, GuestQueryType,
    HazardHandling, HostAddressGeneration, HostAddressState, InboundCaller, IngressError,
    IngressTable, MissingSide, PassThroughHazard, Reach, ReleaseAccount, ReleaseChannel, Resolver,
    RouteId, RouteKind, SandboxConnections, SandboxEndpoint, ServiceIdentity,
};

use super::document::{
    EgressGrant, EgressTarget, LinkDirection, NetworkIdentity, NetworkProfile, ProfileError,
};
use super::flows::{
    CloseReason, ClosedFlow, DnsAnswer, FlowAdmission, FlowId, FlowKey, FlowKind, FlowRecord,
    FlowRefusal, NatScope, NatTable, ProxyListener, Revocation, RouteUsageView, Transport,
};
use super::pool::{PoolError, SandboxAddressPool};

/// Why a profile was not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitError {
    AlreadyAdmitted {
        execution: ExecutionId,
    },
    /// The pool assigned this execution no identity.
    IdentityNotAssigned {
        execution: ExecutionId,
    },
    /// The profile's identity is not the one the pool assigned.
    IdentityMismatch,
    /// An endpoint grant names a host or sandbox address (VM-W59: host and cross-sandbox
    /// access only as granted, and an endpoint grant never grants either).
    EndpointNotExternal {
        route: RouteId,
        address: IpAddr,
    },
    Profile(ProfileError),
    Ingress(IngressError),
    Connection(ConnectionRefusal),
}

impl fmt::Display for AdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyAdmitted { execution } => write!(f, "{execution} is already admitted"),
            Self::IdentityNotAssigned { execution } => {
                write!(f, "the pool assigned {execution} no network identity")
            }
            Self::IdentityMismatch => {
                f.write_str("the profile's identity is not the one the host assigned")
            }
            Self::EndpointNotExternal { route, address } => write!(
                f,
                "route {route} names {address}, a host or sandbox address"
            ),
            Self::Profile(error) => fmt::Display::fmt(error, f),
            Self::Ingress(error) => fmt::Display::fmt(error, f),
            Self::Connection(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for AdmitError {}

/// Why a profile or host-address replacement was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplaceError {
    UnknownSandbox {
        execution: ExecutionId,
    },
    UnknownRoute {
        route: RouteId,
    },
    /// Identity, kind, release budgets, publications and links change only by
    /// re-admission; publications and links are narrowed live by withdrawal and
    /// revocation.
    RequiresReadmission {
        section: &'static str,
    },
    /// The policy epoch must rise.
    NotNewer {
        current: PolicyEpoch,
        offered: PolicyEpoch,
    },
    EpochExhausted,
    /// The host-address generation must rise.
    HostNotNewer {
        current: HostAddressGeneration,
        offered: HostAddressGeneration,
    },
    EndpointNotExternal {
        route: RouteId,
        address: IpAddr,
    },
    Profile(ProfileError),
    Destination(DestinationRefusal),
}

impl fmt::Display for ReplaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSandbox { execution } => write!(f, "{execution} is not admitted"),
            Self::UnknownRoute { route } => write!(f, "route {route} is not in the profile"),
            Self::RequiresReadmission { section } => {
                write!(f, "a change to {section} needs the profile admitted again")
            }
            Self::NotNewer { current, offered } => write!(
                f,
                "policy epoch {offered} is not newer than the current epoch {current}"
            ),
            Self::EpochExhausted => f.write_str("the policy epoch cannot rise further"),
            Self::HostNotNewer { current, offered } => write!(
                f,
                "host-address generation {offered} is not newer than {current}"
            ),
            Self::EndpointNotExternal { route, address } => write!(
                f,
                "route {route} names {address}, a host or sandbox address"
            ),
            Self::Profile(error) => fmt::Display::fmt(error, f),
            Self::Destination(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ReplaceError {}

/// One host DNS answer the guest holds: the address was validated for the name under
/// this route, policy epoch and host-address generation, until `valid_until`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    route: RouteId,
    valid_until: MonotonicTime,
    epoch: PolicyEpoch,
    host_generation: HostAddressGeneration,
}

struct SandboxState<C: Clock> {
    profile: NetworkProfile,
    epoch: PolicyEpoch,
    perimeter: PerimeterId,
    broker: DestinationBroker<C>,
    budgets: BudgetBook,
    ingress: IngressTable,
    bindings: BTreeMap<IpAddr, BTreeMap<CanonicalName, Binding>>,
    flows: BTreeMap<FlowId, FlowRecord>,
    by_key: BTreeMap<FlowKey, FlowId>,
    new_flow_times: VecDeque<MonotonicTime>,
}

/// What a new flow was decided to be.
enum Decision {
    Local(FlowKind),
    External(FlowKind),
    Link {
        callee: SandboxEndpoint,
        service: ServiceIdentity,
    },
}

/// The host's network view of every admitted broader-network sandbox (VM-W59).
pub struct HostNetwork<C: Clock + Clone> {
    clock: C,
    host: HostAddressState,
    pool: SandboxAddressPool,
    connections: SandboxConnections,
    nat: NatTable,
    sandboxes: BTreeMap<ExecutionId, SandboxState<C>>,
    next_flow: u64,
}

fn endpoint_check(
    profile: &NetworkProfile,
    pool: &SandboxAddressPool,
    host: &HostAddressState,
) -> Result<(), (RouteId, IpAddr)> {
    for grant in profile.egress() {
        if let Some(address) = grant.target.endpoint_address() {
            if pool.contains(address) || host.owns(address) {
                return Err((grant.id.clone(), address));
            }
        }
    }
    Ok(())
}

fn destination_port(port: u16) -> Result<DestinationPort, FlowRefusal> {
    DestinationPort::new(port).map_err(|_| FlowRefusal::InvalidPort)
}

fn check_prefixes(grant: &EgressGrant, address: IpAddr) -> Result<(), FlowRefusal> {
    if grant.perimeter_prefixes.is_empty()
        || grant
            .perimeter_prefixes
            .iter()
            .any(|prefix| prefix.contains(address))
    {
        Ok(())
    } else {
        Err(FlowRefusal::OutsidePerimeterPrefixes {
            route: grant.id.clone(),
            address,
        })
    }
}

/// TCP always; UDP only where the V02 transport route accepted HTTP/3 under a broader
/// transport grant; nothing else (raw sockets, ICMP, other protocols).
fn check_transport(
    policy: &DestinationPolicy,
    route: &RouteId,
    transport: Transport,
) -> Result<(), FlowRefusal> {
    let http3_accepted = policy.grant(route).is_some_and(|grant| match &grant.route {
        RouteKind::Transport(route) => matches!(
            route.handling(PassThroughHazard::Http3),
            HazardHandling::BroaderTransportGrant(_)
        ),
        RouteKind::Operation(_) => false,
    });
    match transport {
        Transport::Tcp => Ok(()),
        Transport::Udp if http3_accepted => Ok(()),
        other => Err(FlowRefusal::TransportNotGranted { transport: other }),
    }
}

fn address_rule(grant: Option<&EgressGrant>) -> AddressRule {
    match grant.map(|grant| &grant.target) {
        Some(EgressTarget::Endpoint { .. }) => AddressRule::ExactEndpoint,
        _ => AddressRule::ResolvedName,
    }
}

fn link_service(
    profile: &NetworkProfile,
    direction: LinkDirection,
    peer: &SandboxEndpoint,
    port: DestinationPort,
) -> Option<ServiceIdentity> {
    profile
        .document()
        .links
        .iter()
        .find(|link| {
            link.direction == direction && link.peer.endpoint() == *peer && link.port == port
        })
        .map(|link| link.service.clone())
}

impl<C: Clock> SandboxState<C> {
    fn remove_flow(
        &mut self,
        nat: &mut NatTable,
        flow: FlowId,
        reason: CloseReason,
    ) -> Option<ClosedFlow> {
        let record = self.flows.remove(&flow)?;
        if let Some(key) = record.key {
            self.by_key.remove(&key);
        }
        if let Some(mapping) = &record.nat {
            nat.release(mapping);
        }
        Some(ClosedFlow {
            flow,
            sandbox: record.sandbox,
            kind: record.kind,
            reason,
        })
    }

    /// The concurrent-flow and new-flow-rate quotas, over a sliding window.
    fn check_quotas(&mut self, now: MonotonicTime) -> Result<(), FlowRefusal> {
        let quotas = self.profile.quotas();
        let concurrent = u32::try_from(self.flows.len()).unwrap_or(u32::MAX);
        if concurrent >= quotas.max_concurrent_flows.get() {
            return Err(FlowRefusal::ConcurrentFlowLimit {
                limit: quotas.max_concurrent_flows.get(),
            });
        }
        let interval = Duration::from_secs(quotas.interval_seconds.get());
        while self
            .new_flow_times
            .front()
            .is_some_and(|opened| now.saturating_duration_since(*opened) >= interval)
        {
            self.new_flow_times.pop_front();
        }
        let recent = u32::try_from(self.new_flow_times.len()).unwrap_or(u32::MAX);
        if recent >= quotas.max_new_flows_per_interval.get() {
            return Err(FlowRefusal::NewFlowRate {
                limit: quotas.max_new_flows_per_interval.get(),
                interval_seconds: quotas.interval_seconds.get(),
            });
        }
        Ok(())
    }

    fn charge_connection(&mut self, route: &RouteId) -> Result<(), FlowRefusal> {
        let limits = self
            .broker
            .policy()
            .grant(route)
            .map(|grant| grant.budgets)
            .ok_or_else(|| {
                FlowRefusal::Destination(DestinationRefusal::UnknownRoute {
                    route: route.clone(),
                })
            })?;
        self.budgets
            .charge(route, &limits, BudgetKind::Connections, 1)
            .map_err(FlowRefusal::Budget)
    }
}

impl<C: Clock + Clone> HostNetwork<C> {
    /// A host with no admitted sandbox: no flow is possible until a profile is admitted.
    pub fn new(clock: C, host: HostAddressState, pool: SandboxAddressPool) -> Self {
        Self {
            clock,
            host,
            pool,
            connections: SandboxConnections::new(),
            nat: NatTable::new(),
            sandboxes: BTreeMap::new(),
            next_flow: 0,
        }
    }

    /// The host clock every decision here reads, so a wire layer can turn an answer's
    /// `valid_until` into a remaining lifetime on the same clock.
    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    /// The host's own addresses, as last replaced.
    pub fn host_addresses(&self) -> &HostAddressState {
        &self.host
    }

    /// The host's sandbox address pool.
    pub fn pool(&self) -> &SandboxAddressPool {
        &self.pool
    }

    /// The host's NAT table (VM-W59 NAT).
    pub fn nat(&self) -> &NatTable {
        &self.nat
    }

    /// Assigns `execution` its guest addresses from the pool.
    pub fn assign_identity(
        &mut self,
        execution: ExecutionId,
        scope: TrustScope,
    ) -> Result<NetworkIdentity, PoolError> {
        self.pool.assign(execution, scope, &self.host)
    }

    /// Admits a profile under policy epoch 1: its identity must be the pool's
    /// assignment, no endpoint may name a host or sandbox address, its publications are
    /// published (within `max_publication_lifetime`) and its link copies granted.
    pub fn admit(
        &mut self,
        profile: NetworkProfile,
        perimeter: PerimeterId,
        general: GeneralReleaseBudget,
        max_publication_lifetime: Duration,
    ) -> Result<(), AdmitError> {
        let identity = profile.identity().clone();
        if self.sandboxes.contains_key(&identity.execution) {
            return Err(AdmitError::AlreadyAdmitted {
                execution: identity.execution,
            });
        }
        match self.pool.identity(&identity.execution) {
            None => {
                return Err(AdmitError::IdentityNotAssigned {
                    execution: identity.execution,
                })
            }
            Some(assigned) if *assigned != identity => return Err(AdmitError::IdentityMismatch),
            Some(_) => {}
        }
        endpoint_check(&profile, &self.pool, &self.host)
            .map_err(|(route, address)| AdmitError::EndpointNotExternal { route, address })?;
        let now = self.clock.now();
        let mode = profile.network_mode();
        let policy = profile
            .destination_policy(perimeter, PolicyEpoch::FIRST, now)
            .map_err(AdmitError::Profile)?;
        let release = profile
            .release_account(general)
            .map_err(AdmitError::Profile)?;
        let mut ingress =
            IngressTable::new(identity.execution.clone(), mode, max_publication_lifetime);
        for request in profile.publication_requests(now) {
            ingress.publish(request, now).map_err(AdmitError::Ingress)?;
        }
        let grants = profile.connection_grants(now);
        let mut scratch = SandboxConnections::new();
        for (direction, grant) in &grants {
            match direction {
                LinkDirection::Outbound => scratch.grant_outbound(mode, grant.clone(), now),
                LinkDirection::Inbound => scratch.grant_inbound(mode, grant.clone(), now),
            }
            .map_err(AdmitError::Connection)?;
        }
        for (direction, grant) in grants {
            match direction {
                LinkDirection::Outbound => self.connections.grant_outbound(mode, grant, now),
                LinkDirection::Inbound => self.connections.grant_inbound(mode, grant, now),
            }
            .map_err(AdmitError::Connection)?;
        }
        let broker = DestinationBroker::new(policy, self.host.clone(), release, self.clock.clone());
        self.sandboxes.insert(
            identity.execution,
            SandboxState {
                profile,
                epoch: PolicyEpoch::FIRST,
                perimeter,
                broker,
                budgets: BudgetBook::new(),
                ingress,
                bindings: BTreeMap::new(),
                flows: BTreeMap::new(),
                by_key: BTreeMap::new(),
                new_flow_times: VecDeque::new(),
            },
        );
        Ok(())
    }

    fn state(&self, sandbox: &ExecutionId) -> Result<&SandboxState<C>, FlowRefusal> {
        self.sandboxes
            .get(sandbox)
            .ok_or_else(|| FlowRefusal::UnknownSandbox {
                execution: sandbox.clone(),
            })
    }

    fn state_mut(&mut self, sandbox: &ExecutionId) -> Result<&mut SandboxState<C>, FlowRefusal> {
        self.sandboxes
            .get_mut(sandbox)
            .ok_or_else(|| FlowRefusal::UnknownSandbox {
                execution: sandbox.clone(),
            })
    }

    /// The profile `sandbox` is decided under now.
    pub fn profile(&self, sandbox: &ExecutionId) -> Option<&NetworkProfile> {
        self.sandboxes.get(sandbox).map(|state| &state.profile)
    }

    /// The policy epoch `sandbox` is decided under.
    pub fn epoch(&self, sandbox: &ExecutionId) -> Option<PolicyEpoch> {
        self.sandboxes.get(sandbox).map(|state| state.epoch)
    }

    /// The open flows of `sandbox`, by id.
    pub fn flows(&self, sandbox: &ExecutionId) -> Vec<&FlowRecord> {
        self.sandboxes
            .get(sandbox)
            .map(|state| state.flows.values().collect())
            .unwrap_or_default()
    }

    /// One open flow of `sandbox`.
    pub fn flow(&self, sandbox: &ExecutionId, flow: FlowId) -> Option<&FlowRecord> {
        self.sandboxes.get(sandbox)?.flows.get(&flow)
    }

    /// Usage of `route` by `sandbox` so far.
    pub fn usage(&self, sandbox: &ExecutionId, route: &RouteId) -> RouteUsageView {
        let Some(state) = self.sandboxes.get(sandbox) else {
            return RouteUsageView::default();
        };
        let book = state.budgets.usage(route);
        RouteUsageView {
            dns_queries: state.broker.usage(route).used(BudgetKind::DnsQueries),
            connections: book.used(BudgetKind::Connections),
            bytes_out: book.used(BudgetKind::BytesOut),
            bytes_in: book.used(BudgetKind::BytesIn),
        }
    }

    /// The release account of `sandbox` (VM §2.5).
    pub fn release_account(&self, sandbox: &ExecutionId) -> Option<&ReleaseAccount> {
        self.sandboxes
            .get(sandbox)
            .map(|state| state.broker.release_account())
    }

    /// The id the next admitted flow gets; ids rise and are never reused.
    fn peek_flow_id(&self) -> Result<FlowId, FlowRefusal> {
        self.next_flow
            .checked_add(1)
            .map(FlowId)
            .ok_or(FlowRefusal::FlowIdsExhausted)
    }

    fn commit_flow_id(&mut self, flow: FlowId) {
        self.next_flow = flow.get();
    }

    fn nat_scope(pool: &SandboxAddressPool, host: &HostAddressState, address: IpAddr) -> NatScope {
        if pool.contains(address) {
            NatScope::Sandbox
        } else if host.owns(address)
            || matches!(
                classify(address, host).class,
                AddressClass::HostOwned | AddressClass::Loopback | AddressClass::Unspecified
            )
        {
            NatScope::Host
        } else {
            NatScope::External
        }
    }

    /// Decides a new flow without changing anything.
    fn decide(
        &self,
        sandbox: &ExecutionId,
        key: &FlowKey,
        now: MonotonicTime,
    ) -> Result<Decision, FlowRefusal> {
        let state = self.state(sandbox)?;
        let identity = state.profile.identity();
        if key.source.is_ipv4() != key.destination.is_ipv4() {
            return Err(FlowRefusal::FamilyMismatch);
        }
        if key.source.is_ipv6() && identity.ipv6.is_none() {
            return Err(FlowRefusal::NoIpv6Identity);
        }
        if !identity.owns(key.source) {
            return Err(FlowRefusal::SpoofedSource { source: key.source });
        }
        if self.host.owns(key.source) {
            return Err(FlowRefusal::IdentityHostOwned {
                address: key.source,
            });
        }
        let ported = matches!(key.transport, Transport::Tcp | Transport::Udp);
        if ported && key.destination_port == 0 {
            return Err(FlowRefusal::InvalidPort);
        }
        if self.pool.gateway_for(key.destination) == Some(key.destination) {
            let config = self.pool.config();
            let port = key.destination_port;
            return match key.transport {
                Transport::Tcp | Transport::Udp if port == 53 => {
                    Ok(Decision::Local(FlowKind::LocalDns))
                }
                Transport::Tcp if port == config.http_proxy_port.get() => {
                    Ok(Decision::Local(FlowKind::LocalProxy {
                        listener: ProxyListener::HttpConnect,
                    }))
                }
                Transport::Tcp if port == config.socks_proxy_port.get() => {
                    Ok(Decision::Local(FlowKind::LocalProxy {
                        listener: ProxyListener::Socks5,
                    }))
                }
                _ => Err(FlowRefusal::HostService {
                    address: key.destination,
                    port,
                }),
            };
        }
        if self.pool.contains(key.destination) {
            if identity.owns(key.destination) {
                return Err(FlowRefusal::OwnAddress);
            }
            return self.decide_link(state, key, now);
        }
        self.decide_external(state, key, now)
    }

    /// A flow to another sandbox: both ends must hold a grant for this service and port
    /// (VM §4.7); nothing is inferred transitively and no route authority passes over.
    fn decide_link(
        &self,
        state: &SandboxState<C>,
        key: &FlowKey,
        now: MonotonicTime,
    ) -> Result<Decision, FlowRefusal> {
        let callee_identity = self
            .pool
            .owner_of(key.destination)
            .and_then(|execution| self.pool.identity(execution))
            .ok_or(FlowRefusal::UnassignedSandboxAddress {
                address: key.destination,
            })?;
        if key.transport != Transport::Tcp {
            return Err(FlowRefusal::TransportNotGranted {
                transport: key.transport,
            });
        }
        let port = destination_port(key.destination_port)?;
        let caller = state.profile.identity().endpoint();
        let callee = callee_identity.endpoint();
        let service =
            link_service(&state.profile, LinkDirection::Outbound, &callee, port).or_else(|| {
                self.sandboxes.get(&callee.execution).and_then(|peer| {
                    link_service(&peer.profile, LinkDirection::Inbound, &caller, port)
                })
            });
        let Some(service) = service else {
            return Err(FlowRefusal::Connection(ConnectionRefusal::MissingGrant {
                side: MissingSide::Both,
            }));
        };
        self.connections
            .connect(&caller, &callee, &service, port, now)
            .map_err(FlowRefusal::Connection)?;
        Ok(Decision::Link { callee, service })
    }

    /// A flow leaving the host: an exact endpoint grant for this address and port, or an
    /// address the host's own DNS answer bound to a granted name; anything else is
    /// refused, whatever the guest's proxy settings or resolver (VM-P09).
    fn decide_external(
        &self,
        state: &SandboxState<C>,
        key: &FlowKey,
        now: MonotonicTime,
    ) -> Result<Decision, FlowRefusal> {
        if !matches!(key.transport, Transport::Tcp | Transport::Udp) {
            return Err(FlowRefusal::TransportNotGranted {
                transport: key.transport,
            });
        }
        let address = key.destination;
        let port = destination_port(key.destination_port)?;
        let verdict = classify(address, &self.host);
        let policy = state.broker.policy();
        if let Some(grant) = state.profile.endpoint_grant(address, port) {
            AddressRule::ExactEndpoint
                .check(verdict)
                .map_err(FlowRefusal::Address)?;
            let authorized = policy.authorize(
                &DestinationRequest {
                    protocol: grant.protocol.into(),
                    authority: Authority {
                        host: DestinationHost::Address(address),
                        port,
                    },
                },
                now,
            )?;
            check_transport(policy, authorized.route(), key.transport)?;
            return Ok(Decision::External(FlowKind::Endpoint {
                route: authorized.route().clone(),
            }));
        }
        if let Some(names) = state.bindings.get(&address) {
            let current: Vec<(&CanonicalName, &Binding)> = names
                .iter()
                .filter(|(_, binding)| {
                    binding.valid_until > now
                        && binding.epoch == state.epoch
                        && binding.host_generation == self.host.generation()
                })
                .collect();
            if current.is_empty() {
                return Err(FlowRefusal::BindingExpired { address });
            }
            AddressRule::ResolvedName
                .check(verdict)
                .map_err(FlowRefusal::Address)?;
            let mut chosen: Option<(&EgressGrant, &CanonicalName)> = None;
            let mut first_refusal = None;
            for (name, binding) in current {
                let Some(grant) = state.profile.grant(&binding.route) else {
                    continue;
                };
                let request = DestinationRequest {
                    protocol: grant.protocol.into(),
                    authority: Authority {
                        host: DestinationHost::Name(name.clone()),
                        port,
                    },
                };
                match policy.authorize(&request, now) {
                    Ok(authorized) if *authorized.route() == binding.route => {
                        if chosen.is_none_or(|(best, _)| grant.id < best.id) {
                            chosen = Some((grant, name));
                        }
                    }
                    Ok(_) => {}
                    Err(refusal) => {
                        first_refusal.get_or_insert(refusal);
                    }
                }
            }
            let Some((grant, name)) = chosen else {
                return Err(FlowRefusal::Authorization(first_refusal.unwrap_or(
                    AuthorizationRefusal::AddressNeedsEndpointGrant { address },
                )));
            };
            check_prefixes(grant, address)?;
            check_transport(policy, &grant.id, key.transport)?;
            return Ok(Decision::External(FlowKind::Named {
                route: grant.id.clone(),
                name: name.clone(),
            }));
        }
        let other_port = state
            .profile
            .egress()
            .iter()
            .any(|grant| grant.target.endpoint_address() == Some(address));
        if other_port {
            AddressRule::ExactEndpoint
                .check(verdict)
                .map_err(FlowRefusal::Address)?;
            return Err(FlowRefusal::Authorization(
                AuthorizationRefusal::PortNotGranted {
                    authority: Authority {
                        host: DestinationHost::Address(address),
                        port,
                    },
                },
            ));
        }
        AddressRule::ResolvedName
            .check(verdict)
            .map_err(FlowRefusal::Address)?;
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant { address },
        ))
    }

    /// Decides and, if admitted, tracks a new guest flow (VM-W59). A reconnect is a new
    /// flow and is decided again under the current epoch. Quotas apply after the
    /// decision; an external flow gets a NAT mapping and is charged one connection.
    pub fn open_flow(
        &mut self,
        sandbox: &ExecutionId,
        key: FlowKey,
    ) -> Result<FlowAdmission, FlowRefusal> {
        let now = self.clock.now();
        if let Some(flow) = self.state(sandbox)?.by_key.get(&key) {
            return Err(FlowRefusal::AlreadyEstablished { flow: *flow });
        }
        let decision = self.decide(sandbox, &key, now)?;
        self.state_mut(sandbox)?.check_quotas(now)?;
        let flow = self.peek_flow_id()?;
        let (kind, nat) = match decision {
            Decision::Local(kind) => (kind, None),
            Decision::Link { callee, service } => (FlowKind::SandboxLink { callee, service }, None),
            Decision::External(kind) => {
                let block = self
                    .pool
                    .port_block(sandbox)
                    .ok_or(FlowRefusal::UnknownSandbox {
                        execution: sandbox.clone(),
                    })?;
                let egress = self.pool.egress_for(key.destination);
                let (pool, host) = (&self.pool, &self.host);
                let mapping = self
                    .nat
                    .map(sandbox, flow, &key, egress, block, |address| {
                        Self::nat_scope(pool, host, address)
                    })
                    .map_err(FlowRefusal::Nat)?;
                let charged = match kind.route() {
                    Some(route) => self.state_mut(sandbox)?.charge_connection(route),
                    None => Ok(()),
                };
                if let Err(refusal) = charged {
                    self.nat.release(&mapping);
                    return Err(refusal);
                }
                (kind, Some(mapping))
            }
        };
        let state = self.state_mut(sandbox)?;
        let record = FlowRecord {
            id: flow,
            sandbox: sandbox.clone(),
            key: Some(key),
            kind: kind.clone(),
            nat,
            epoch: state.epoch,
            opened_at: now,
        };
        state.flows.insert(flow, record);
        state.by_key.insert(key, flow);
        state.new_flow_times.push_back(now);
        self.commit_flow_id(flow);
        Ok(FlowAdmission { flow, kind, nat })
    }

    /// Connection tracking: a packet of an open flow passes without a new decision; a
    /// packet of no open flow is refused, so a closed or revoked flow cannot continue.
    /// A link flow is re-checked against both ends' grants and closed when one lapses.
    pub fn packet(&mut self, sandbox: &ExecutionId, key: &FlowKey) -> Result<FlowId, FlowRefusal> {
        let now = self.clock.now();
        let state = self.state(sandbox)?;
        let flow = *state.by_key.get(key).ok_or(FlowRefusal::NotEstablished)?;
        let link = match state.flows.get(&flow).map(|record| &record.kind) {
            Some(FlowKind::SandboxLink { callee, service }) => Some((
                state.profile.identity().endpoint(),
                callee.clone(),
                service.clone(),
            )),
            _ => None,
        };
        if let Some((caller, callee, service)) = link {
            let port = destination_port(key.destination_port)?;
            if let Err(refusal) = self
                .connections
                .connect(&caller, &callee, &service, port, now)
            {
                let nat = &mut self.nat;
                if let Some(state) = self.sandboxes.get_mut(sandbox) {
                    state.remove_flow(nat, flow, CloseReason::LinkRevoked);
                }
                return Err(FlowRefusal::Connection(refusal));
            }
        }
        Ok(flow)
    }

    /// Matches an inbound packet from `from` to the host egress `to` against the NAT
    /// table: only the reply direction of an open flow passes, to the guest address and
    /// port the mapping names. Anything else is unsolicited and refused.
    pub fn inbound_packet(
        &self,
        transport: Transport,
        from: (IpAddr, u16),
        to: (IpAddr, u16),
    ) -> Result<(ExecutionId, FlowId, (IpAddr, u16)), FlowRefusal> {
        let (sandbox, flow) = self.nat.holder(to).ok_or(FlowRefusal::UnsolicitedInbound)?;
        let mapping = self
            .sandboxes
            .get(sandbox)
            .and_then(|state| state.flows.get(flow))
            .and_then(|record| record.nat)
            .ok_or(FlowRefusal::UnsolicitedInbound)?;
        if mapping.transport != transport || mapping.destination != from {
            return Err(FlowRefusal::UnsolicitedInbound);
        }
        Ok((sandbox.clone(), *flow, mapping.inside))
    }

    /// Closes a flow; its NAT port and quota slot return.
    pub fn close_flow(
        &mut self,
        sandbox: &ExecutionId,
        flow: FlowId,
    ) -> Result<ClosedFlow, FlowRefusal> {
        let nat = &mut self.nat;
        let state = self
            .sandboxes
            .get_mut(sandbox)
            .ok_or_else(|| FlowRefusal::UnknownSandbox {
                execution: sandbox.clone(),
            })?;
        state
            .remove_flow(nat, flow, CloseReason::Closed)
            .ok_or(FlowRefusal::NotEstablished)
    }

    /// The host DNS listener (VM §4.2 steps 1–4; VM-W08). Authorization comes before any
    /// external query: a malformed or ungranted name, an unsupported type, AAAA without
    /// an IPv6 grant and an endpoint grant's name are all answered locally with no
    /// external query. A granted name is resolved by the V02 broker through the grant's
    /// own allowed resolver, picked from `resolvers` by id; other resolvers are never
    /// asked. Validated addresses become bindings that later flows are decided against.
    pub fn guest_dns(
        &mut self,
        sandbox: &ExecutionId,
        query_name: &str,
        query_type: GuestQueryType,
        resolvers: &[&dyn Resolver],
    ) -> Result<DnsAnswer, FlowRefusal> {
        let host_generation = self.host.generation();
        let state = self.state_mut(sandbox)?;
        let name = match CanonicalName::parse(query_name) {
            Ok(name) => name,
            Err(error) => return Ok(DnsAnswer::Malformed(error)),
        };
        let family = match query_type {
            GuestQueryType::A => AddressFamily::Ipv4,
            GuestQueryType::Aaaa => AddressFamily::Ipv6,
            other => return Ok(DnsAnswer::Unsupported(other)),
        };
        let Some(grant) = state.profile.grant_for_name(&name).cloned() else {
            return Ok(DnsAnswer::NameNotAuthorized);
        };
        if family == AddressFamily::Ipv6 && state.profile.identity().ipv6.is_none() {
            return Ok(DnsAnswer::NoData);
        }
        let request = DestinationRequest {
            protocol: grant.protocol.into(),
            authority: Authority {
                host: DestinationHost::Name(name.clone()),
                port: grant.port,
            },
        };
        let authorized = match state.broker.authorize(&request) {
            Ok(authorized) => authorized,
            Err(refusal) => return Ok(DnsAnswer::Refused(refusal.into())),
        };
        match authorized.reach().clone() {
            Reach::Endpoint { address } => {
                let family_matches = match family {
                    AddressFamily::Ipv4 => address.is_ipv4(),
                    AddressFamily::Ipv6 => address.is_ipv6(),
                };
                if !family_matches {
                    return Ok(DnsAnswer::NoData);
                }
                Ok(match state.broker.validate_endpoint(&authorized) {
                    Ok(validated) => DnsAnswer::Addresses {
                        route: grant.id,
                        addresses: vec![address],
                        valid_until: validated.valid_until(),
                        external: false,
                    },
                    Err(refusal) => DnsAnswer::Refused(refusal.into()),
                })
            }
            Reach::Resolve { resolver, ipv6 } => {
                if family == AddressFamily::Ipv6 && !ipv6 {
                    return Ok(DnsAnswer::NoData);
                }
                let Some(chosen) = resolvers
                    .iter()
                    .find(|candidate| *candidate.id() == resolver)
                else {
                    return Ok(DnsAnswer::Refused(FlowRefusal::ResolverUnavailable {
                        resolver,
                    }));
                };
                let validated = match state.broker.resolve(&authorized, family, *chosen) {
                    Ok(validated) => validated,
                    Err(refusal) => return Ok(DnsAnswer::Refused(refusal.into())),
                };
                let addresses: Vec<IpAddr> = validated
                    .addresses()
                    .iter()
                    .map(|verdict| verdict.address)
                    .collect();
                for address in &addresses {
                    if let Err(refusal) = check_prefixes(&grant, *address) {
                        return Ok(DnsAnswer::Refused(refusal));
                    }
                }
                for address in &addresses {
                    state.bindings.entry(*address).or_default().insert(
                        name.clone(),
                        Binding {
                            route: grant.id.clone(),
                            valid_until: validated.valid_until(),
                            epoch: state.epoch,
                            host_generation,
                        },
                    );
                }
                Ok(DnsAnswer::Addresses {
                    route: grant.id,
                    addresses,
                    valid_until: validated.valid_until(),
                    external: true,
                })
            }
        }
    }

    /// The host proxy (HTTP CONNECT or SOCKS5 with a name): the request's authority is
    /// parsed by the V02 parser and authorized by the same policy as a direct flow; a
    /// name is resolved through its allowed resolver and the first validated address
    /// inside the grant's perimeter prefixes is used. The proxy's outbound connection is
    /// tracked as a flow, counted against the quotas and charged one connection.
    pub fn proxy_connect(
        &mut self,
        sandbox: &ExecutionId,
        authority: &str,
        resolvers: &[&dyn Resolver],
    ) -> Result<FlowAdmission, FlowRefusal> {
        let now = self.clock.now();
        let authority =
            Authority::parse(authority, DestinationPort::HTTPS).map_err(FlowRefusal::Name)?;
        let flow = self.peek_flow_id()?;
        let state = self.state_mut(sandbox)?;
        let grant = match &authority.host {
            DestinationHost::Name(name) => state.profile.grant_for_name(name).cloned(),
            DestinationHost::Address(address) => state
                .profile
                .endpoint_grant(*address, authority.port)
                .cloned(),
        };
        let Some(grant) = grant else {
            return Err(FlowRefusal::Authorization(match &authority.host {
                DestinationHost::Name(_) => AuthorizationRefusal::NotGranted {
                    authority: authority.clone(),
                },
                DestinationHost::Address(address) => {
                    AuthorizationRefusal::AddressNeedsEndpointGrant { address: *address }
                }
            }));
        };
        let authorized = state.broker.authorize(&DestinationRequest {
            protocol: grant.protocol.into(),
            authority: authority.clone(),
        })?;
        state.check_quotas(now)?;
        let validated = match authorized.reach().clone() {
            Reach::Endpoint { .. } => state.broker.validate_endpoint(&authorized)?,
            Reach::Resolve { resolver, .. } => {
                let chosen = resolvers
                    .iter()
                    .find(|candidate| *candidate.id() == resolver)
                    .ok_or(FlowRefusal::ResolverUnavailable { resolver })?;
                state
                    .broker
                    .resolve(&authorized, AddressFamily::Ipv4, *chosen)?
            }
        };
        let mut address = None;
        for verdict in validated.addresses() {
            check_prefixes(&grant, verdict.address)?;
            address.get_or_insert(verdict.address);
        }
        let address = address.ok_or(FlowRefusal::Destination(DestinationRefusal::EmptyAnswer))?;
        state.charge_connection(&grant.id)?;
        let kind = FlowKind::Proxied {
            route: grant.id,
            authority,
            address,
        };
        state.flows.insert(
            flow,
            FlowRecord {
                id: flow,
                sandbox: sandbox.clone(),
                key: None,
                kind: kind.clone(),
                nat: None,
                epoch: state.epoch,
                opened_at: now,
            },
        );
        state.new_flow_times.push_back(now);
        self.commit_flow_id(flow);
        Ok(FlowAdmission {
            flow,
            kind,
            nat: None,
        })
    }

    /// Bytes the guest sends on an egress flow: reserved against the route's byte budget
    /// and the transport-stream release channel together, so neither is charged alone.
    pub fn send(
        &mut self,
        sandbox: &ExecutionId,
        flow: FlowId,
        bytes: u64,
    ) -> Result<(), FlowRefusal> {
        let state = self.state_mut(sandbox)?;
        let route = state
            .flows
            .get(&flow)
            .ok_or(FlowRefusal::NotEstablished)?
            .kind
            .route()
            .cloned()
            .ok_or(FlowRefusal::WrongFlowKind)?;
        let limits = state
            .broker
            .policy()
            .grant(&route)
            .map(|grant| grant.budgets)
            .ok_or_else(|| {
                FlowRefusal::Destination(DestinationRefusal::UnknownRoute {
                    route: route.clone(),
                })
            })?;
        let reservation = state
            .budgets
            .reserve(&route, &limits, BudgetKind::BytesOut, bytes)?;
        match state
            .broker
            .release_account_mut()
            .reserve(ReleaseChannel::TransportStream, bytes)
        {
            Ok(release) => {
                state
                    .budgets
                    .commit(reservation, bytes)
                    .map_err(FlowRefusal::Settle)?;
                state.broker.release_account_mut().commit(release, bytes)?;
                Ok(())
            }
            Err(error) => {
                state
                    .budgets
                    .cancel(reservation)
                    .map_err(FlowRefusal::Settle)?;
                Err(error.into())
            }
        }
    }

    /// Bytes received on an egress flow, charged to the route's inbound budget.
    pub fn receive(
        &mut self,
        sandbox: &ExecutionId,
        flow: FlowId,
        bytes: u64,
    ) -> Result<(), FlowRefusal> {
        let state = self.state_mut(sandbox)?;
        let route = state
            .flows
            .get(&flow)
            .ok_or(FlowRefusal::NotEstablished)?
            .kind
            .route()
            .cloned()
            .ok_or(FlowRefusal::WrongFlowKind)?;
        let limits = state
            .broker
            .policy()
            .grant(&route)
            .map(|grant| grant.budgets)
            .ok_or_else(|| {
                FlowRefusal::Destination(DestinationRefusal::UnknownRoute {
                    route: route.clone(),
                })
            })?;
        state
            .budgets
            .charge(&route, &limits, BudgetKind::BytesIn, bytes)
            .map_err(FlowRefusal::Budget)
    }

    /// An inbound caller of a publication (VM §4.7): admitted by the V02 ingress table
    /// (unpublished services are unreachable; audience and authentication hold) and
    /// tracked as a flow of this sandbox, counted against its quotas. Nothing is
    /// published by default, so a sandbox without publications admits no caller.
    pub fn admit_inbound(
        &mut self,
        sandbox: &ExecutionId,
        service: &ServiceIdentity,
        port: DestinationPort,
        caller: &InboundCaller,
    ) -> Result<FlowAdmission, FlowRefusal> {
        let now = self.clock.now();
        let state = self.state_mut(sandbox)?;
        state.check_quotas(now)?;
        let session = state
            .ingress
            .admit(service, port, caller, now)
            .map_err(FlowRefusal::Ingress)?;
        let flow = self.peek_flow_id()?;
        let state = self.state_mut(sandbox)?;
        let kind = FlowKind::Inbound {
            publication: session.publication(),
            session,
        };
        state.flows.insert(
            flow,
            FlowRecord {
                id: flow,
                sandbox: sandbox.clone(),
                key: None,
                kind: kind.clone(),
                nat: None,
                epoch: state.epoch,
                opened_at: now,
            },
        );
        state.new_flow_times.push_back(now);
        self.commit_flow_id(flow);
        Ok(FlowAdmission {
            flow,
            kind,
            nat: None,
        })
    }

    /// Response bytes the guest service sends (VM §4.7: guest responses are outbound
    /// data): on an inbound flow, charged by the V02 ingress table to the
    /// published-service channel of this sandbox; on a link flow, charged by V02 to the
    /// callee's release account.
    pub fn respond(
        &mut self,
        sandbox: &ExecutionId,
        flow: FlowId,
        bytes: u64,
    ) -> Result<(), FlowRefusal> {
        let now = self.clock.now();
        let state = self.state(sandbox)?;
        let record = state.flows.get(&flow).ok_or(FlowRefusal::NotEstablished)?;
        match record.kind.clone() {
            FlowKind::Inbound { session, .. } => {
                let state = self.state_mut(sandbox)?;
                let SandboxState {
                    ingress, broker, ..
                } = state;
                ingress
                    .respond(&session, bytes, broker.release_account_mut(), now)
                    .map_err(FlowRefusal::Ingress)
            }
            FlowKind::SandboxLink { callee, service } => {
                let caller = state.profile.identity().endpoint();
                let key = record.key.ok_or(FlowRefusal::WrongFlowKind)?;
                let port = destination_port(key.destination_port)?;
                let authorization = self
                    .connections
                    .connect(&caller, &callee, &service, port, now)
                    .map_err(FlowRefusal::Connection)?;
                let callee_state = self.sandboxes.get_mut(&callee.execution).ok_or(
                    FlowRefusal::UnknownSandbox {
                        execution: callee.execution.clone(),
                    },
                )?;
                self.connections
                    .record_response(
                        &authorization,
                        bytes,
                        callee_state.broker.release_account_mut(),
                        now,
                    )
                    .map_err(FlowRefusal::Connection)
            }
            _ => Err(FlowRefusal::WrongFlowKind),
        }
    }

    /// Replaces a sandbox's egress policy under a newer epoch (VM §4.2 step 6). Every
    /// flow and binding of a removed or changed grant is closed or dropped and listed;
    /// the rest are re-stamped with the new epoch, so new flows are decided under it, and
    /// a kept answer is trusted no longer than the new profile's answer lifetime allows.
    /// Route usage carries over.
    pub fn replace_profile(
        &mut self,
        sandbox: &ExecutionId,
        profile: NetworkProfile,
        epoch: PolicyEpoch,
    ) -> Result<Revocation, ReplaceError> {
        let now = self.clock.now();
        endpoint_check(&profile, &self.pool, &self.host)
            .map_err(|(route, address)| ReplaceError::EndpointNotExternal { route, address })?;
        let nat = &mut self.nat;
        let state =
            self.sandboxes
                .get_mut(sandbox)
                .ok_or_else(|| ReplaceError::UnknownSandbox {
                    execution: sandbox.clone(),
                })?;
        let old = state.profile.document();
        let new = profile.document();
        let section = if old.identity != new.identity {
            Some("the network identity")
        } else if old.kind != new.kind {
            Some("the network kind")
        } else if old.release != new.release {
            Some("the release budgets")
        } else if old.ingress != new.ingress {
            Some("the publications")
        } else if old.links != new.links {
            Some("the sandbox links")
        } else {
            None
        };
        if let Some(section) = section {
            return Err(ReplaceError::RequiresReadmission { section });
        }
        if epoch <= state.epoch {
            return Err(ReplaceError::NotNewer {
                current: state.epoch,
                offered: epoch,
            });
        }
        let policy = profile
            .destination_policy(state.perimeter, epoch, now)
            .map_err(ReplaceError::Profile)?;
        state
            .broker
            .replace_policy(policy)
            .map_err(ReplaceError::Destination)?;
        let mut revocation = Revocation::default();
        let flows: Vec<(FlowId, Option<RouteId>)> = state
            .flows
            .iter()
            .map(|(id, record)| (*id, record.kind.route().cloned()))
            .collect();
        for (flow, route) in flows {
            let reason = route.and_then(|route| {
                match (state.profile.grant(&route), profile.grant(&route)) {
                    (_, None) => Some(CloseReason::GrantRevoked { route }),
                    (old, Some(new)) if old != Some(new) => {
                        Some(CloseReason::GrantChanged { route })
                    }
                    _ => None,
                }
            });
            match reason {
                Some(reason) => revocation
                    .closed
                    .extend(state.remove_flow(nat, flow, reason)),
                None => {
                    if let Some(record) = state.flows.get_mut(&flow) {
                        record.epoch = epoch;
                    }
                }
            }
        }
        let trusted_until = now.saturating_add(Duration::from_secs(
            profile.document().max_answer_ttl_seconds.get(),
        ));
        for names in state.bindings.values_mut() {
            names.retain(|_, binding| {
                let kept = profile.grant(&binding.route).is_some()
                    && state.profile.grant(&binding.route) == profile.grant(&binding.route);
                if kept {
                    binding.epoch = epoch;
                    binding.valid_until = binding.valid_until.min(trusted_until);
                }
                kept
            });
        }
        state.bindings.retain(|_, names| !names.is_empty());
        state.profile = profile;
        state.epoch = epoch;
        Ok(revocation)
    }

    /// Revokes one egress grant: the profile without it, under the next epoch. Every
    /// flow on the route is listed and closed, and new ones are refused. A resolver only
    /// that grant used leaves the profile with it.
    pub fn revoke_route(
        &mut self,
        sandbox: &ExecutionId,
        route: &RouteId,
    ) -> Result<Revocation, ReplaceError> {
        let state = self
            .sandboxes
            .get(sandbox)
            .ok_or_else(|| ReplaceError::UnknownSandbox {
                execution: sandbox.clone(),
            })?;
        if state.profile.grant(route).is_none() {
            return Err(ReplaceError::UnknownRoute {
                route: route.clone(),
            });
        }
        let mut document = state.profile.document().clone();
        document.egress.retain(|grant| grant.id != *route);
        let used: Vec<_> = document
            .egress
            .iter()
            .filter_map(|grant| grant.resolver.clone())
            .collect();
        document
            .resolvers
            .retain(|resolver| used.contains(&resolver.id));
        let profile = NetworkProfile::new(document).map_err(ReplaceError::Profile)?;
        let epoch = state.epoch.next().ok_or(ReplaceError::EpochExhausted)?;
        self.replace_profile(sandbox, profile, epoch)
    }

    /// Revokes both copies of every link grant from `caller` to `callee` (V02) and
    /// closes every flow that used one.
    pub fn revoke_link(
        &mut self,
        caller: &SandboxEndpoint,
        callee: &SandboxEndpoint,
    ) -> Revocation {
        self.connections.revoke(caller, callee);
        let mut revocation = Revocation::default();
        let nat = &mut self.nat;
        if let Some(state) = self.sandboxes.get_mut(&caller.execution) {
            let closing: Vec<FlowId> = state
                .flows
                .iter()
                .filter(|(_, record)| {
                    matches!(&record.kind, FlowKind::SandboxLink { callee: target, .. } if target == callee)
                })
                .map(|(id, _)| *id)
                .collect();
            for flow in closing {
                revocation
                    .closed
                    .extend(state.remove_flow(nat, flow, CloseReason::LinkRevoked));
            }
        }
        revocation
    }

    /// Withdraws a publication (V02) and closes every inbound session it admitted.
    pub fn withdraw_publication(
        &mut self,
        sandbox: &ExecutionId,
        service: &ServiceIdentity,
        port: DestinationPort,
    ) -> Result<Revocation, FlowRefusal> {
        let now = self.clock.now();
        let nat = &mut self.nat;
        let state = self
            .sandboxes
            .get_mut(sandbox)
            .ok_or_else(|| FlowRefusal::UnknownSandbox {
                execution: sandbox.clone(),
            })?;
        let publication = state
            .ingress
            .active(now)
            .into_iter()
            .find(|publication| publication.service == *service && publication.port == port)
            .map(|publication| publication.id)
            .ok_or_else(|| {
                FlowRefusal::Ingress(IngressError::NotPublished {
                    service: service.clone(),
                    port,
                })
            })?;
        state
            .ingress
            .withdraw(publication)
            .map_err(FlowRefusal::Ingress)?;
        let closing: Vec<FlowId> = state
            .flows
            .iter()
            .filter(|(_, record)| {
                matches!(&record.kind, FlowKind::Inbound { publication: id, .. } if *id == publication)
            })
            .map(|(id, _)| *id)
            .collect();
        let mut revocation = Revocation::default();
        for flow in closing {
            revocation.closed.extend(state.remove_flow(
                nat,
                flow,
                CloseReason::PublicationWithdrawn,
            ));
        }
        Ok(revocation)
    }

    /// Replaces the host's own addresses under a newer generation (VM §4.2 step 6).
    /// Every binding and flow whose address no longer passes the V02 address rules (for
    /// example one the host now owns) is dropped or closed and listed.
    pub fn replace_host_addresses(
        &mut self,
        host: HostAddressState,
    ) -> Result<Revocation, ReplaceError> {
        if host.generation() <= self.host.generation() {
            return Err(ReplaceError::HostNotNewer {
                current: self.host.generation(),
                offered: host.generation(),
            });
        }
        let mut revocation = Revocation::default();
        let nat = &mut self.nat;
        for state in self.sandboxes.values_mut() {
            state
                .broker
                .replace_host_addresses(host.clone())
                .map_err(ReplaceError::Destination)?;
            state.bindings.retain(|address, names| {
                let passes = AddressRule::ResolvedName
                    .check(classify(*address, &host))
                    .is_ok();
                if passes {
                    for binding in names.values_mut() {
                        binding.host_generation = host.generation();
                    }
                }
                passes
            });
            let mut closing = Vec::new();
            for (id, record) in &state.flows {
                let address = match &record.kind {
                    FlowKind::Named { .. } | FlowKind::Endpoint { .. } => {
                        record.key.map(|key| key.destination)
                    }
                    FlowKind::Proxied { address, .. } => Some(*address),
                    _ => None,
                };
                let Some(address) = address else {
                    continue;
                };
                let rule = address_rule(
                    record
                        .kind
                        .route()
                        .and_then(|route| state.profile.grant(route)),
                );
                if let Err(refused) = rule.check(classify(address, &host)) {
                    closing.push((*id, refused));
                }
            }
            for (flow, refused) in closing {
                revocation.closed.extend(state.remove_flow(
                    nat,
                    flow,
                    CloseReason::AddressNowRefused(refused),
                ));
            }
        }
        self.host = host;
        Ok(revocation)
    }
}
