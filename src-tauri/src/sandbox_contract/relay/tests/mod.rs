//! Tests for M09R: the reader on its own, then the relay step over a real V02 broker with
//! a fake resolver. Nothing here opens a socket.

mod reader;
mod step;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use super::*;
use crate::foundation::ids::{digest, Digest, ManualClock, MonotonicTime, PolicyEpoch, TenantId};
use crate::foundation::transfer::{CredentialRef, GeneralReleaseBudget};
use crate::sandbox_contract::destinations::{
    AddressFamily, CanonicalName, ChannelPolicy, ConnectionPermit, DecisionRef, DestinationBroker,
    DestinationPolicy, DestinationPort, DestinationRequest, EffectClass, GrantTarget,
    HazardHandling, HostAddressGeneration, HostAddressState, HttpMethod, InFlightAllowance,
    IpPrefix, NetworkMode, OperationName, OperationRoute, OperationSpec, OperationTls,
    PassThroughHazard, PathTemplate, PolicyParts, RedirectPolicy, ReleaseAccount, ReleaseChannel,
    ReleaseTrustClass, ResolutionQuery, Resolver, ResolverAnswer, ResolverFailure, ResolverId,
    RouteBudgets, RouteGrant, RouteId, RouteKind, RouteProtocol, TaskDataClass, TlsFacts,
    TransportRoute,
};

pub(super) const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);

/// The public address every name resolves to in these tests.
pub(super) const UPSTREAM: &str = "93.184.216.34";

pub(super) fn limits() -> ReaderLimits {
    ReaderLimits::new(4_096, 65_536).unwrap()
}

pub(super) fn route_id(text: &str) -> RouteId {
    RouteId::new(text).unwrap()
}

fn test_digest(text: &str) -> Digest {
    digest("yougori/test/relay/v1", &[text.as_bytes()])
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

fn spec(
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

/// The provider API: list and get models (read-only), create a job (external effect).
pub(super) fn operation_route(credentialed: bool) -> OperationRoute {
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
            spec(
                "upload",
                HttpMethod::Put,
                "/v1/files/{id}",
                &[],
                EffectClass::ReadOnly,
            ),
        ],
        RedirectPolicy::Disabled,
        false,
    )
    .unwrap()
}

pub(super) fn grant(id: &str, host: &str, route: RouteKind, budgets: RouteBudgets) -> RouteGrant {
    RouteGrant {
        id: route_id(id),
        protocol: match route {
            RouteKind::Operation(_) => RouteProtocol::Https,
            RouteKind::Transport(_) => RouteProtocol::Tls,
        },
        target: GrantTarget::ExactName(CanonicalName::parse(host).unwrap()),
        port: DestinationPort::HTTPS,
        route,
        ipv6: false,
        resolver: Some(resolver_id()),
        budgets,
    }
}

/// `provider-api` on api.example.com, credentialed or not.
pub(super) fn api_grant(credentialed: bool, budgets: RouteBudgets) -> RouteGrant {
    grant(
        "provider-api",
        "api.example.com",
        RouteKind::Operation(operation_route(credentialed)),
        budgets,
    )
}

/// `tls-stream` on stream.example.com: a pass-through transport route.
pub(super) fn transport_grant() -> RouteGrant {
    let route = TransportRoute::new(BTreeMap::from([
        (
            PassThroughHazard::EncryptedClientHello,
            HazardHandling::Refuse,
        ),
        (PassThroughHazard::MissingSni, HazardHandling::Refuse),
        (PassThroughHazard::Http3, HazardHandling::Refuse),
        (
            PassThroughHazard::InTunnelProtocolChange,
            HazardHandling::BroaderTransportGrant(DecisionRef::new(test_digest("tunnel"))),
        ),
    ]))
    .unwrap();
    grant(
        "tls-stream",
        "stream.example.com",
        RouteKind::Transport(route),
        budgets(),
    )
}

fn resolver_id() -> ResolverId {
    ResolverId::new("host-dns").unwrap()
}

pub(super) fn policy(epoch: PolicyEpoch, grants: Vec<RouteGrant>) -> DestinationPolicy {
    DestinationPolicy::new(
        PolicyParts {
            tenant: TenantId::new("tenant-a").unwrap(),
            epoch,
            mode: NetworkMode::DeclaredTransport,
            data_class: TaskDataClass::Ordinary,
            grants,
            allowed_resolvers: BTreeSet::from([resolver_id()]),
            approved_objects: BTreeSet::new(),
            max_answer_ttl: Duration::from_secs(300),
        },
        START,
    )
    .unwrap()
}

fn release_account() -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([
            (
                ReleaseChannel::DnsQuery,
                ChannelPolicy {
                    budget_bytes: 4_096,
                    trust_class: ReleaseTrustClass::Resolver,
                },
            ),
            (
                ReleaseChannel::ProviderRequest,
                ChannelPolicy {
                    budget_bytes: 1_000_000,
                    trust_class: ReleaseTrustClass::External,
                },
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

pub(super) type Broker = DestinationBroker<ManualClock>;

pub(super) fn broker(grants: Vec<RouteGrant>) -> Broker {
    DestinationBroker::new(
        policy(PolicyEpoch::FIRST, grants),
        HostAddressState::new(
            HostAddressGeneration::FIRST,
            [IpPrefix::host("192.168.1.10".parse::<IpAddr>().unwrap())],
        ),
        release_account(),
        ManualClock::new(START),
    )
}

/// Answers every query with [`UPSTREAM`]; performs no lookup.
pub(super) struct FixedResolver(ResolverId);

impl Resolver for FixedResolver {
    fn id(&self) -> &ResolverId {
        &self.0
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        Ok(ResolverAnswer {
            name: query.name().clone(),
            aliases: Vec::new(),
            addresses: vec![UPSTREAM.parse().unwrap()],
            ttl: Duration::from_secs(60),
        })
    }
}

/// Authorizes, resolves and opens a connection to `host` through the broker.
pub(super) fn permit(broker: &mut Broker, host: &str) -> ConnectionPermit {
    let authorized = broker
        .authorize(&DestinationRequest::parse(RouteProtocol::Https, host).unwrap())
        .unwrap();
    let validated = broker
        .resolve(
            &authorized,
            AddressFamily::Ipv4,
            &FixedResolver(resolver_id()),
        )
        .unwrap();
    broker
        .open_connection(&validated, UPSTREAM.parse().unwrap())
        .unwrap()
}

pub(super) fn tls(sni: &str) -> TlsFacts {
    TlsFacts {
        sni: Some(sni.to_owned()),
    }
}

/// Reads `wire` in one feed.
pub(super) fn read_whole(wire: &[u8]) -> ReadOutcome {
    let mut reader = RequestReader::new(limits());
    let _ = reader.feed(wire);
    reader.into_outcome()
}

/// The request a successful read produced.
pub(super) fn read_ok(wire: &[u8]) -> ReadRequest {
    match read_whole(wire) {
        ReadOutcome::Complete(request) => request,
        other => panic!("expected a complete request, got {other:?}"),
    }
}

/// The refusal an unsuccessful read produced.
pub(super) fn read_refused(wire: &[u8]) -> ReadRefusal {
    match read_whole(wire) {
        ReadOutcome::Refused(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}
