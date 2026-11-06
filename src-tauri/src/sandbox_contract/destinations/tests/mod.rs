//! Tests for V02, one file per area, with shared builders and a fake resolver.

mod addresses;
mod broker;
mod budgets;
mod fakes;
mod http;
mod ingress;
mod modes;
mod names;
mod perimeter;
mod policy;
mod routes;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{digest, Digest, ManualClock, MonotonicTime, PolicyEpoch, TenantId};
use crate::foundation::transfer::{CredentialRef, GeneralReleaseBudget};

pub(super) const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);

pub(super) fn clock() -> ManualClock {
    ManualClock::new(START)
}

pub(super) fn name(text: &str) -> CanonicalName {
    CanonicalName::parse(text).unwrap()
}

pub(super) fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

pub(super) fn port(value: u16) -> DestinationPort {
    DestinationPort::new(value).unwrap()
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub(super) fn route_id(text: &str) -> RouteId {
    RouteId::new(text).unwrap()
}

pub(super) fn resolver_id() -> ResolverId {
    ResolverId::new("host-dns").unwrap()
}

pub(super) fn test_digest(text: &str) -> Digest {
    digest("yougori/test/destinations/v1", &[text.as_bytes()])
}

pub(super) fn perimeter_id() -> PerimeterId {
    PerimeterId::new(test_digest("perimeter"))
}

pub(super) fn budgets() -> RouteBudgets {
    RouteBudgets {
        dns_queries: 10,
        connections: 10,
        bytes_out: 10_000,
        bytes_in: 10_000,
        effects: 5,
    }
}

pub(super) fn spec(
    op: &str,
    method: HttpMethod,
    path: &str,
    keys: &[&str],
    effect: EffectClass,
) -> OperationSpec {
    OperationSpec {
        name: OperationName::new(op).unwrap(),
        method,
        path: PathTemplate::parse(path).unwrap(),
        query_keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        effect,
    }
}

pub(super) fn operation_route(redirects: RedirectPolicy, credentialed: bool) -> OperationRoute {
    OperationRoute::new(
        OperationTls::TerminatedAtExecutor,
        credentialed.then(|| CredentialRef::from_digest(test_digest("vault-handle"))),
        vec![
            spec(
                "list-models",
                HttpMethod::Get,
                "/v1/models",
                &["limit", "after"],
                EffectClass::ReadOnly,
            ),
            spec(
                "get-model",
                HttpMethod::Get,
                "/v1/models/{id}",
                &[],
                EffectClass::ReadOnly,
            ),
            spec(
                "create-job",
                HttpMethod::Post,
                "/v1/jobs",
                &[],
                EffectClass::External,
            ),
            spec("next", HttpMethod::Get, "/next", &[], EffectClass::ReadOnly),
        ],
        redirects,
        false,
    )
    .unwrap()
}

pub(super) fn transport_route(
    missing_sni: HazardHandling,
    ech: HazardHandling,
    http3: HazardHandling,
) -> TransportRoute {
    TransportRoute::new(BTreeMap::from([
        (PassThroughHazard::EncryptedClientHello, ech),
        (PassThroughHazard::MissingSni, missing_sni),
        (PassThroughHazard::Http3, http3),
        (
            PassThroughHazard::InTunnelProtocolChange,
            HazardHandling::BroaderTransportGrant(DecisionRef::new(test_digest("decision-tunnel"))),
        ),
    ]))
    .unwrap()
}

pub(super) fn refusing_transport() -> TransportRoute {
    transport_route(
        HazardHandling::Refuse,
        HazardHandling::Refuse,
        HazardHandling::Refuse,
    )
}

pub(super) fn exact_grant(id: &str, host: &str, route: RouteKind) -> RouteGrant {
    RouteGrant {
        id: route_id(id),
        protocol: match route {
            RouteKind::Operation(_) => RouteProtocol::Https,
            RouteKind::Transport(_) => RouteProtocol::Tls,
        },
        target: GrantTarget::ExactName(name(host)),
        port: DestinationPort::HTTPS,
        route,
        ipv6: false,
        resolver: Some(resolver_id()),
        budgets: budgets(),
    }
}

pub(super) fn api_grant(redirects: RedirectPolicy) -> RouteGrant {
    exact_grant(
        "provider-api",
        "api.example.com",
        RouteKind::Operation(operation_route(redirects, true)),
    )
}

pub(super) fn endpoint_grant(
    id: &str,
    host: Option<&str>,
    address: &str,
    port_number: u16,
) -> RouteGrant {
    let address = ip(address);
    let grant_port = port(port_number);
    RouteGrant {
        id: route_id(id),
        protocol: RouteProtocol::Https,
        target: GrantTarget::Endpoint(
            EndpointGrant::new(
                host.map(name),
                address,
                grant_port,
                EnforcementContext::dedicated(perimeter_id(), address, grant_port),
            )
            .unwrap(),
        ),
        port: grant_port,
        route: RouteKind::Operation(operation_route(RedirectPolicy::Disabled, false)),
        ipv6: address.is_ipv6(),
        resolver: None,
        budgets: budgets(),
    }
}

pub(super) fn parts(mode: NetworkMode, grants: Vec<RouteGrant>) -> PolicyParts {
    PolicyParts {
        tenant: tenant(),
        epoch: PolicyEpoch::FIRST,
        mode,
        data_class: TaskDataClass::Ordinary,
        grants,
        allowed_resolvers: BTreeSet::from([resolver_id()]),
        approved_objects: BTreeSet::new(),
        max_answer_ttl: Duration::from_secs(300),
    }
}

pub(super) fn policy(mode: NetworkMode, grants: Vec<RouteGrant>) -> DestinationPolicy {
    DestinationPolicy::new(parts(mode, grants), START).unwrap()
}

pub(super) fn channel(budget_bytes: u64, trust_class: ReleaseTrustClass) -> ChannelPolicy {
    ChannelPolicy {
        budget_bytes,
        trust_class,
    }
}

pub(super) fn release_account() -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([
            (
                ReleaseChannel::DnsQuery,
                channel(4_096, ReleaseTrustClass::Resolver),
            ),
            (
                ReleaseChannel::ProviderRequest,
                channel(1_000_000, ReleaseTrustClass::External),
            ),
            (
                ReleaseChannel::TransportStream,
                channel(1_000_000, ReleaseTrustClass::External),
            ),
            (
                ReleaseChannel::PublishedServiceResponse,
                channel(10_000, ReleaseTrustClass::PublishedAudience),
            ),
        ]),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 1_024,
            documented_reason: "TLS record framing is sized only when sent".to_owned(),
        },
    )
    .unwrap()
}

/// The host's own addresses in tests: a LAN address and an overlay VPN address in CGNAT
/// space.
pub(super) fn host_state() -> HostAddressState {
    HostAddressState::new(
        HostAddressGeneration::FIRST,
        [
            IpPrefix::host(ip("192.168.1.10")),
            IpPrefix::host(ip("100.101.102.103")),
        ],
    )
}

pub(super) fn request(text: &str) -> DestinationRequest {
    DestinationRequest::parse(RouteProtocol::Https, text).unwrap()
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
