//! Tests for V11, one file per area, with shared builders, a fake resolver and an
//! explicit seeded generator. Nothing here resolves a name, opens a socket or touches a
//! VM; time is a `ManualClock`.

mod dns;
mod document;
mod flows;
mod guest;
mod perimeter;
mod pool;
mod properties;
mod revocation;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use super::*;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{
    digest, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime, TenantId,
    TrustScope,
};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    AddressFamily, CanonicalName, ChannelPolicy, DecisionRef, DestinationPort, GuestQueryType,
    HazardHandling, HostAddressGeneration, HostAddressState, InFlightAllowance, IpPrefix,
    PassThroughHazard, PerimeterOptions, PerimeterPlatform, ReleaseChannel, ReleaseTrustClass,
    ResolutionQuery, Resolver, ResolverAnswer, ResolverFailure, ResolverId, RouteBudgets, RouteId,
};

pub(super) const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);

pub(super) const PYPI_V4: &str = "151.101.0.223";
pub(super) const PYPI_V4_B: &str = "151.101.0.224";
pub(super) const PYPI_V6: &str = "2a04:4e42::223";
pub(super) const GITHUB_V4: &str = "140.82.112.3";
pub(super) const REGISTRY: &str = "10.50.0.20";
pub(super) const MIRROR: &str = "93.184.215.14";
pub(super) const UPSTREAM: &str = "9.9.9.9";
pub(super) const HOST_LAN: &str = "192.168.1.10";
pub(super) const HOST_VPN: &str = "100.101.102.103";
pub(super) const GATEWAY: &str = "10.200.0.1";
pub(super) const GATEWAY_V6: &str = "fd00:200::1";
pub(super) const EGRESS_V6: &str = "2a01:4f8::10";

pub(super) fn new_clock() -> ManualClock {
    ManualClock::new(START)
}

pub(super) fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

pub(super) fn port(value: u16) -> DestinationPort {
    DestinationPort::new(value).unwrap()
}

pub(super) fn name(text: &str) -> CanonicalName {
    CanonicalName::parse(text).unwrap()
}

pub(super) fn prefix(text: &str) -> IpPrefix {
    let (network, length) = text.split_once('/').unwrap();
    IpPrefix::new(ip(network), length.parse().unwrap()).unwrap()
}

pub(super) fn route(text: &str) -> RouteId {
    RouteId::new(text).unwrap()
}

pub(super) fn test_digest(text: &str) -> Digest {
    digest("yougori/test/netprofile/v1", &[text.as_bytes()])
}

pub(super) fn perimeter_id() -> PerimeterId {
    PerimeterId::new(test_digest("perimeter"))
}

pub(super) fn exec(text: &str) -> ExecutionId {
    ExecutionId::new(text).unwrap()
}

pub(super) fn scope(text: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, text)
}

pub(super) fn text(value: &str) -> RecordedText {
    RecordedText::new(value).unwrap()
}

/// The host's own addresses: a LAN address, an overlay VPN address in CGNAT space, the
/// sandbox gateways and the IPv6 egress address.
pub(super) fn host_state() -> HostAddressState {
    HostAddressState::new(
        HostAddressGeneration::FIRST,
        [HOST_LAN, HOST_VPN, GATEWAY, GATEWAY_V6, EGRESS_V6]
            .into_iter()
            .map(|address| IpPrefix::host(ip(address))),
    )
}

pub(super) fn pool_config() -> PoolConfig {
    PoolConfig {
        ipv4: prefix("10.200.0.0/24"),
        ipv6: Some(prefix("fd00:200::/64")),
        http_proxy_port: port(3128),
        socks_proxy_port: port(1080),
        nat: NatConfig {
            egress_ipv4: "192.168.1.10".parse().unwrap(),
            egress_ipv6: Some(EGRESS_V6.parse().unwrap()),
            first_port: 20_000,
            ports_per_sandbox: 8,
            max_sandboxes: 16,
        },
        synthetic_ipv4_candidates: vec![prefix("100.101.0.0/16"), prefix("198.18.0.0/24")],
        synthetic_ipv6_candidates: vec![prefix("fd99::/64")],
    }
}

pub(super) fn new_pool() -> SandboxAddressPool {
    SandboxAddressPool::new(pool_config(), &host_state()).unwrap()
}

pub(super) fn budgets() -> RouteBudgets {
    RouteBudgets {
        dns_queries: 20,
        connections: 20,
        bytes_out: 100_000,
        bytes_in: 100_000,
        effects: 0,
    }
}

pub(super) fn hazards(http3: HazardHandling) -> BTreeMap<PassThroughHazard, HazardHandling> {
    BTreeMap::from([
        (
            PassThroughHazard::EncryptedClientHello,
            HazardHandling::Refuse,
        ),
        (PassThroughHazard::MissingSni, HazardHandling::Refuse),
        (PassThroughHazard::Http3, http3),
        (
            PassThroughHazard::InTunnelProtocolChange,
            HazardHandling::BroaderTransportGrant(DecisionRef::new(test_digest("tunnel"))),
        ),
    ])
}

pub(super) fn name_grant(id: &str, host: &str, prefixes: &[&str], ipv6: bool) -> EgressGrant {
    EgressGrant {
        id: route(id),
        target: EgressTarget::ExactName { name: name(host) },
        port: DestinationPort::HTTPS,
        protocol: EgressProtocol::Tls,
        ipv6,
        resolver: Some(ResolverId::new("host-dns").unwrap()),
        hazards: hazards(HazardHandling::Refuse),
        budgets: budgets(),
        perimeter_prefixes: prefixes.iter().map(|text| prefix(text)).collect(),
    }
}

pub(super) fn endpoint_grant(
    id: &str,
    address: &str,
    port_number: u16,
    host: Option<&str>,
    reason: &str,
) -> EgressGrant {
    let address = ip(address);
    EgressGrant {
        id: route(id),
        target: EgressTarget::Endpoint {
            address,
            name: host.map(name),
            reason: text(reason),
        },
        port: port(port_number),
        protocol: EgressProtocol::Tls,
        ipv6: address.is_ipv6(),
        resolver: None,
        hazards: hazards(HazardHandling::Refuse),
        budgets: budgets(),
        perimeter_prefixes: Vec::new(),
    }
}

pub(super) fn resolver(id: &str, upstream: &[&str]) -> AllowedResolver {
    AllowedResolver {
        id: ResolverId::new(id).unwrap(),
        upstream: upstream
            .iter()
            .map(|address| ResolverUpstream {
                address: ip(address),
                port: port(53),
            })
            .collect(),
    }
}

pub(super) fn quotas(concurrent: u32, rate: u32, interval_seconds: u64) -> FlowQuotas {
    FlowQuotas {
        max_concurrent_flows: NonZeroU32::new(concurrent).unwrap(),
        max_new_flows_per_interval: NonZeroU32::new(rate).unwrap(),
        interval_seconds: NonZeroU64::new(interval_seconds).unwrap(),
    }
}

pub(super) fn identity(execution: &str, ipv4: &str, ipv6: Option<&str>) -> NetworkIdentity {
    NetworkIdentity {
        execution: exec(execution),
        scope: scope(execution),
        ipv4: ipv4.parse().unwrap(),
        ipv6: ipv6.map(|address| address.parse().unwrap()),
    }
}

/// A declared-transport profile: pypi.org pinned (IPv4 and IPv6), github.com unpinned,
/// a private registry endpoint with a name and a public mirror endpoint.
pub(super) fn base_document(identity: NetworkIdentity) -> NetworkProfileDocument {
    let has_ipv6 = identity.ipv6.is_some();
    let pypi = if has_ipv6 {
        name_grant(
            "pypi",
            "pypi.org",
            &["151.101.0.0/24", "2a04:4e42::/48"],
            true,
        )
    } else {
        name_grant("pypi", "pypi.org", &["151.101.0.0/24"], false)
    };
    NetworkProfileDocument {
        version: ProfileVersion::CURRENT,
        kind: BroaderNetworkKind::DeclaredTransport,
        tenant: TenantId::new("tenant-a").unwrap(),
        data_class: DataClass::Ordinary,
        identity,
        resolvers: vec![resolver("host-dns", &[UPSTREAM])],
        egress: vec![
            pypi,
            name_grant("github", "github.com", &[], false),
            endpoint_grant(
                "registry",
                REGISTRY,
                5000,
                Some("registry.corp.internal"),
                "the team's private package registry",
            ),
            endpoint_grant("mirror", MIRROR, 443, None, "a fixed public mirror"),
        ],
        ingress: Vec::new(),
        links: Vec::new(),
        quotas: quotas(64, 64, 1),
        release: ReleaseBudgets {
            channels: BTreeMap::from([
                (
                    ReleaseChannel::DnsQuery,
                    ChannelPolicy {
                        budget_bytes: 4_096,
                        trust_class: ReleaseTrustClass::Resolver,
                    },
                ),
                (
                    ReleaseChannel::TransportStream,
                    ChannelPolicy {
                        budget_bytes: 1_000_000,
                        trust_class: ReleaseTrustClass::External,
                    },
                ),
                (
                    ReleaseChannel::PublishedServiceResponse,
                    ChannelPolicy {
                        budget_bytes: 10_000,
                        trust_class: ReleaseTrustClass::PublishedAudience,
                    },
                ),
            ]),
            in_flight_allowance: InFlightAllowance {
                bytes: 1_024,
                documented_reason: "TLS record framing is sized only when sent".to_owned(),
            },
        },
        guest: GuestCompatibility {
            proxy: ProxyOffer {
                http_connect: true,
                socks5: true,
            },
            tun: None,
            synthetic_names: None,
        },
        max_answer_ttl_seconds: NonZeroU64::new(300).unwrap(),
    }
}

/// A document for sandbox `a` at 10.200.0.2 and fd00:200::2, the pool's first guest.
pub(super) fn sample_document() -> NetworkProfileDocument {
    base_document(identity("sbx-a", "10.200.0.2", Some("fd00:200::2")))
}

pub(super) fn sample_profile() -> NetworkProfile {
    NetworkProfile::new(sample_document()).unwrap()
}

/// The base document with github.com pinned too, so the perimeter can express it.
pub(super) fn pinned_document() -> NetworkProfileDocument {
    let mut document = sample_document();
    if let Some(github) = document
        .egress
        .iter_mut()
        .find(|grant| grant.id == route("github"))
    {
        github.perimeter_prefixes = vec![prefix("140.82.112.0/24")];
    }
    document
}

pub(super) fn perimeter_base() -> PerimeterBase {
    PerimeterBase {
        platform: PerimeterPlatform::Linux,
        options: PerimeterOptions::default(),
        declared: PerimeterPlatform::Linux.required_properties(PerimeterOptions::default()),
        remote: None,
        broker_identity: test_digest("broker"),
    }
}

pub(super) fn full_capabilities() -> PerimeterCapabilities {
    PerimeterCapabilities {
        ipv4_rules: true,
        ipv6_rules: true,
        port_scoped_rules: true,
        max_rules: 256,
    }
}

type Key = (String, AddressFamily);

/// A fake resolver: answers are queued per exact name and family, the last one repeats,
/// and every query is recorded. It performs no lookup.
pub(super) struct FakeResolver {
    id: ResolverId,
    answers: RefCell<BTreeMap<Key, VecDeque<Result<ResolverAnswer, ResolverFailure>>>>,
    calls: RefCell<Vec<ResolutionQuery>>,
}

impl FakeResolver {
    pub(super) fn new(id: &str) -> Self {
        Self {
            id: ResolverId::new(id).unwrap(),
            answers: RefCell::new(BTreeMap::new()),
            calls: RefCell::new(Vec::new()),
        }
    }

    pub(super) fn answer(
        &self,
        query_name: &str,
        family: AddressFamily,
        addresses: &[&str],
        ttl_seconds: u64,
    ) {
        self.answers
            .borrow_mut()
            .entry((query_name.to_owned(), family))
            .or_default()
            .push_back(Ok(ResolverAnswer {
                name: name(query_name),
                aliases: Vec::new(),
                addresses: addresses.iter().map(|address| ip(address)).collect(),
                ttl: Duration::from_secs(ttl_seconds),
            }));
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.borrow().len()
    }

    pub(super) fn queried(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|query| query.name().as_str().to_owned())
            .collect()
    }
}

impl Resolver for FakeResolver {
    fn id(&self) -> &ResolverId {
        &self.id
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        self.calls.borrow_mut().push(query.clone());
        let mut answers = self.answers.borrow_mut();
        let Some(queue) = answers.get_mut(&(query.name().as_str().to_owned(), query.family()))
        else {
            return Err(ResolverFailure::NameDoesNotExist);
        };
        if queue.len() > 1 {
            queue.pop_front().unwrap_or(Err(ResolverFailure::NoData))
        } else {
            queue
                .front()
                .cloned()
                .unwrap_or(Err(ResolverFailure::NoData))
        }
    }
}

/// The host resolver with the test answers.
pub(super) fn host_resolver() -> FakeResolver {
    let resolver = FakeResolver::new("host-dns");
    resolver.answer("pypi.org", AddressFamily::Ipv4, &[PYPI_V4, PYPI_V4_B], 120);
    resolver.answer("pypi.org", AddressFamily::Ipv6, &[PYPI_V6], 120);
    resolver.answer("github.com", AddressFamily::Ipv4, &[GITHUB_V4], 60);
    resolver.answer("dns.google", AddressFamily::Ipv4, &["8.8.8.8"], 60);
    resolver
}

/// SplitMix64, the explicit seeded generator for property tests.
pub(super) struct SplitMix64(u64);

impl SplitMix64 {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub(super) fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One host with its network, a host resolver and a resolver no grant names.
pub(super) struct World<'c> {
    pub(super) net: HostNetwork<&'c ManualClock>,
    pub(super) dns: FakeResolver,
    pub(super) rogue: FakeResolver,
    next_port: Cell<u16>,
}

impl<'c> World<'c> {
    pub(super) fn new(clock: &'c ManualClock) -> Self {
        Self::with_pool(clock, new_pool())
    }

    pub(super) fn with_pool(clock: &'c ManualClock, pool: SandboxAddressPool) -> Self {
        let rogue = FakeResolver::new("rogue-dns");
        rogue.answer("pypi.org", AddressFamily::Ipv4, &["203.0.113.66"], 60);
        Self {
            net: HostNetwork::new(clock, host_state(), pool),
            dns: host_resolver(),
            rogue,
            next_port: Cell::new(40_000),
        }
    }

    /// Assigns, builds and admits a sandbox whose document `edit` may change.
    pub(super) fn try_add(
        &mut self,
        label: &str,
        edit: impl FnOnce(&mut NetworkProfileDocument),
    ) -> Result<ExecutionId, AdmitError> {
        let execution = exec(label);
        let identity = self
            .net
            .assign_identity(execution.clone(), scope(label))
            .unwrap();
        let mut document = base_document(identity);
        edit(&mut document);
        let profile = NetworkProfile::new(document).unwrap();
        self.net.admit(
            profile,
            perimeter_id(),
            GeneralReleaseBudget::vm_d12_default(),
            Duration::from_secs(3_600),
        )?;
        Ok(execution)
    }

    pub(super) fn add(
        &mut self,
        label: &str,
        edit: impl FnOnce(&mut NetworkProfileDocument),
    ) -> ExecutionId {
        self.try_add(label, edit).unwrap()
    }

    pub(super) fn identity(&self, sandbox: &ExecutionId) -> NetworkIdentity {
        self.net.profile(sandbox).unwrap().identity().clone()
    }

    /// A key from `sandbox`'s own address of the destination's family, with a fresh
    /// source port.
    pub(super) fn key(
        &self,
        sandbox: &ExecutionId,
        transport: Transport,
        destination: &str,
        destination_port: u16,
    ) -> FlowKey {
        let destination = ip(destination);
        let identity = self.identity(sandbox);
        let source = identity
            .address_like(destination)
            .unwrap_or(IpAddr::V4(identity.ipv4));
        let source_port = self.next_port.get();
        self.next_port.set(source_port.wrapping_add(1));
        FlowKey {
            transport,
            source,
            source_port,
            destination,
            destination_port,
        }
    }

    pub(super) fn open(
        &mut self,
        sandbox: &ExecutionId,
        transport: Transport,
        destination: &str,
        destination_port: u16,
    ) -> Result<FlowAdmission, FlowRefusal> {
        let key = self.key(sandbox, transport, destination, destination_port);
        self.net.open_flow(sandbox, key)
    }

    pub(super) fn tcp(
        &mut self,
        sandbox: &ExecutionId,
        destination: &str,
        destination_port: u16,
    ) -> Result<FlowAdmission, FlowRefusal> {
        self.open(sandbox, Transport::Tcp, destination, destination_port)
    }

    pub(super) fn dns(
        &mut self,
        sandbox: &ExecutionId,
        query_name: &str,
        query_type: GuestQueryType,
    ) -> DnsAnswer {
        let resolvers: [&dyn Resolver; 2] = [&self.rogue, &self.dns];
        self.net
            .guest_dns(sandbox, query_name, query_type, &resolvers)
            .unwrap()
    }

    pub(super) fn proxy(
        &mut self,
        sandbox: &ExecutionId,
        authority: &str,
    ) -> Result<FlowAdmission, FlowRefusal> {
        let resolvers: [&dyn Resolver; 2] = [&self.rogue, &self.dns];
        self.net.proxy_connect(sandbox, authority, &resolvers)
    }

    pub(super) fn external_calls(&self) -> usize {
        self.dns.calls() + self.rogue.calls()
    }
}

/// A change to a document, for table-driven tests.
pub(super) type Edit = Box<dyn Fn(&mut NetworkProfileDocument)>;

/// The set of strict-mode claims (VM §4.1).
pub(super) fn strict_claims() -> BTreeSet<crate::sandbox_contract::destinations::ModeClaim> {
    use crate::sandbox_contract::destinations::ModeClaim;
    BTreeSet::from([
        ModeClaim::NoHostFacingNic,
        ModeClaim::TypedOperationsOnly,
        ModeClaim::HostValidatesEveryOperation,
        ModeClaim::BypassFailsWithoutNic,
        ModeClaim::NoNetworkExposure,
    ])
}
