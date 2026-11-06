//! Tests for the DNS guard (M10D), one file per area: a query builder, a test-side
//! response decoder, a fake resolver and a real V11 `HostNetwork` with admitted profiles
//! (builders after netprofile's own tests, whose module is private). Nothing here
//! resolves a name or opens a socket; time is a `ManualClock`.

mod encoder;
mod fakes;
mod guard;
mod parser;
mod robustness;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use super::*;
use fakes::FakeResolver;

use crate::foundation::coordination::PerimeterId;
use crate::foundation::ids::{
    digest, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime, TenantId,
    TrustScope,
};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    AddressFamily, CanonicalName, ChannelPolicy, DecisionRef, DestinationPort, HazardHandling,
    HostAddressGeneration, HostAddressState, InFlightAllowance, IpPrefix, PassThroughHazard,
    ReleaseChannel, ReleaseTrustClass, Resolver, ResolverId, RouteBudgets, RouteId,
};
use crate::sandbox_contract::netprofile::{
    AdmitError, AllowedResolver, BroaderNetworkKind, DataClass, EgressGrant, EgressProtocol,
    EgressTarget, FlowAdmission, FlowKey, FlowQuotas, FlowRefusal, GuestCompatibility, HostNetwork,
    NatConfig, NetworkIdentity, NetworkProfile, NetworkProfileDocument, PoolConfig, ProfileVersion,
    ProxyOffer, RecordedText, ReleaseBudgets, ResolverUpstream, SandboxAddressPool, Transport,
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

/// The profile's longest answer lifetime in these tests.
pub(super) const MAX_ANSWER_TTL_SECONDS: u64 = 300;

/// The RD bit in the third header byte, as a stub sets it.
pub(super) const RD: u8 = 0x01;

pub(super) fn clock() -> ManualClock {
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
    digest("yougori/test/dns-guard/v1", &[text.as_bytes()])
}

pub(super) fn exec(text: &str) -> ExecutionId {
    ExecutionId::new(text).unwrap()
}

fn scope(text: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, text)
}

/// The host's own addresses: a LAN address, an overlay VPN address in CGNAT space, the
/// sandbox gateways and the IPv6 egress address.
fn host_state() -> HostAddressState {
    HostAddressState::new(
        HostAddressGeneration::FIRST,
        [HOST_LAN, HOST_VPN, GATEWAY, GATEWAY_V6, EGRESS_V6]
            .into_iter()
            .map(|address| IpPrefix::host(ip(address))),
    )
}

/// The sandbox pool; with `ipv6` false its guests get no IPv6 address.
pub(super) fn pool(ipv6: bool) -> SandboxAddressPool {
    let config = PoolConfig {
        ipv4: prefix("10.200.0.0/24"),
        ipv6: ipv6.then(|| prefix("fd00:200::/64")),
        http_proxy_port: port(3128),
        socks_proxy_port: port(1080),
        nat: NatConfig {
            egress_ipv4: HOST_LAN.parse().unwrap(),
            egress_ipv6: ipv6.then(|| EGRESS_V6.parse().unwrap()),
            first_port: 20_000,
            ports_per_sandbox: 8,
            max_sandboxes: 16,
        },
        synthetic_ipv4_candidates: vec![prefix("100.101.0.0/16"), prefix("198.18.0.0/24")],
        synthetic_ipv6_candidates: vec![prefix("fd99::/64")],
    };
    SandboxAddressPool::new(config, &host_state()).unwrap()
}

pub(super) fn budgets(dns_queries: u64) -> RouteBudgets {
    RouteBudgets {
        dns_queries,
        connections: 20,
        bytes_out: 100_000,
        bytes_in: 100_000,
        effects: 0,
    }
}

fn hazards() -> BTreeMap<PassThroughHazard, HazardHandling> {
    BTreeMap::from([
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
    ])
}

/// An exact-name grant on port 443 resolved through `host-dns`.
pub(super) fn name_grant(id: &str, host: &str, prefixes: &[&str], ipv6: bool) -> EgressGrant {
    EgressGrant {
        id: route(id),
        target: EgressTarget::ExactName { name: name(host) },
        port: DestinationPort::HTTPS,
        protocol: EgressProtocol::Tls,
        ipv6,
        resolver: Some(ResolverId::new("host-dns").unwrap()),
        hazards: hazards(),
        budgets: budgets(20),
        perimeter_prefixes: prefixes.iter().map(|text| prefix(text)).collect(),
    }
}

/// An exact endpoint grant, never resolved.
pub(super) fn endpoint_grant(
    id: &str,
    address: &str,
    port_number: u16,
    host: Option<&str>,
) -> EgressGrant {
    let address = ip(address);
    EgressGrant {
        id: route(id),
        target: EgressTarget::Endpoint {
            address,
            name: host.map(name),
            reason: RecordedText::new("a fixed endpoint for the tests").unwrap(),
        },
        port: port(port_number),
        protocol: EgressProtocol::Tls,
        ipv6: address.is_ipv6(),
        resolver: None,
        hazards: hazards(),
        budgets: budgets(20),
        perimeter_prefixes: Vec::new(),
    }
}

/// A declared-transport profile: pypi.org pinned (IPv6 too when the sandbox has it),
/// github.com unpinned and IPv4 only, a named private registry endpoint and an unnamed
/// public mirror endpoint, a 4 KiB DNS release channel and a 300 s answer lifetime.
fn base_document(identity: NetworkIdentity) -> NetworkProfileDocument {
    let pypi = if identity.ipv6.is_some() {
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
        resolvers: vec![AllowedResolver {
            id: ResolverId::new("host-dns").unwrap(),
            upstream: vec![ResolverUpstream {
                address: ip(UPSTREAM),
                port: port(53),
            }],
        }],
        egress: vec![
            pypi,
            name_grant("github", "github.com", &[], false),
            endpoint_grant("registry", REGISTRY, 5000, Some("registry.corp.internal")),
            endpoint_grant("mirror", MIRROR, 443, None),
        ],
        ingress: Vec::new(),
        links: Vec::new(),
        quotas: FlowQuotas {
            max_concurrent_flows: NonZeroU32::new(64).unwrap(),
            max_new_flows_per_interval: NonZeroU32::new(64).unwrap(),
            interval_seconds: NonZeroU64::new(1).unwrap(),
        },
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
        max_answer_ttl_seconds: NonZeroU64::new(MAX_ANSWER_TTL_SECONDS).unwrap(),
    }
}

/// The host resolver's standing answers.
pub(super) fn host_resolver() -> FakeResolver {
    let resolver = FakeResolver::allowed();
    resolver.answer("pypi.org", AddressFamily::Ipv4, &[PYPI_V4, PYPI_V4_B], 120);
    resolver.answer("pypi.org", AddressFamily::Ipv6, &[PYPI_V6], 120);
    resolver.answer("github.com", AddressFamily::Ipv4, &[GITHUB_V4], 60);
    resolver
}

/// One host: its V11 network, the host resolver every grant allows and a resolver no
/// grant names, offered first so the guard's caller cannot steer the choice.
pub(super) struct World<'c> {
    pub(super) net: HostNetwork<&'c ManualClock>,
    pub(super) dns: FakeResolver,
    pub(super) rogue: FakeResolver,
    next_port: Cell<u16>,
}

impl<'c> World<'c> {
    pub(super) fn new(clock: &'c ManualClock) -> Self {
        Self::with_pool(clock, pool(true))
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
        let profile = NetworkProfile::new(document).map_err(AdmitError::Profile)?;
        self.net.admit(
            profile,
            PerimeterId::new(test_digest("perimeter")),
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

    /// Sends `message` from `sandbox`'s guest to the guard.
    pub(super) fn ask(&mut self, sandbox: &ExecutionId, message: &[u8]) -> GuardReply {
        let resolvers: [&dyn Resolver; 2] = [&self.rogue, &self.dns];
        handle_query(&mut self.net, sandbox, &resolvers, message)
    }

    /// Opens a TCP flow from `sandbox`'s own address of the destination's family.
    pub(super) fn tcp(
        &mut self,
        sandbox: &ExecutionId,
        destination: &str,
        destination_port: u16,
    ) -> Result<FlowAdmission, FlowRefusal> {
        let destination = ip(destination);
        let identity = self.net.profile(sandbox).unwrap().identity().clone();
        let source = identity
            .address_like(destination)
            .unwrap_or(IpAddr::V4(identity.ipv4));
        let source_port = self.next_port.get();
        self.next_port.set(source_port.wrapping_add(1));
        let key = FlowKey {
            transport: Transport::Tcp,
            source,
            source_port,
            destination,
            destination_port,
        };
        self.net.open_flow(sandbox, key)
    }

    pub(super) fn external_calls(&self) -> usize {
        self.dns.calls() + self.rogue.calls()
    }

    pub(super) fn dns_released(&self, sandbox: &ExecutionId) -> u64 {
        self.net
            .release_account(sandbox)
            .unwrap()
            .used_bytes(ReleaseChannel::DnsQuery)
    }
}

/// A stub query: `id`, RD set, one question of raw `labels`, `qtype` and `class`.
pub(super) fn query_labels(id: u16, labels: &[&[u8]], qtype: u16, class: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[RD, 0x00]);
    message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in labels {
        message.push(u8::try_from(label.len()).unwrap());
        message.extend_from_slice(label);
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&class.to_be_bytes());
    message
}

/// A stub query for the dotted `text`, class IN.
pub(super) fn query(id: u16, text: &str, qtype: u16) -> Vec<u8> {
    let labels: Vec<&[u8]> = text.split('.').map(str::as_bytes).collect();
    query_labels(id, &labels, qtype, CLASS_IN)
}

/// The question section of a query built by [`query_labels`].
pub(super) fn question_bytes(message: &[u8]) -> Vec<u8> {
    message[HEADER_BYTES..].to_vec()
}

/// A response as the test decoder reads it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Decoded {
    pub id: u16,
    pub flags: [u8; 2],
    pub code: ResponseCode,
    pub question: Vec<u8>,
    /// Each answer's address and TTL.
    pub answers: Vec<(IpAddr, u32)>,
}

/// Decodes a response the guard sent, asserting the fixed shape: QR set, no authority or
/// additional record, at most one uncompressed question, answers that point at it.
pub(super) fn decode(response: &[u8]) -> Decoded {
    assert!(response.len() >= HEADER_BYTES && response.len() <= MAX_MESSAGE_BYTES);
    let id = u16::from_be_bytes([response[0], response[1]]);
    let flags = [response[2], response[3]];
    assert_eq!(flags[0] & 0x80, 0x80, "QR is set");
    assert_eq!(flags[0] & 0x06, 0, "AA and TC are clear");
    assert_eq!(flags[1] & 0x80, 0x80, "RA is set");
    assert_eq!(flags[1] & 0x60, 0, "Z and AD are clear");
    let code = ResponseCode::from_code(flags[1] & 0x0F).unwrap();
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    assert_eq!(
        &response[8..12],
        &[0, 0, 0, 0],
        "no authority or additional record"
    );
    assert!(questions <= 1);
    let mut offset = HEADER_BYTES;
    let mut question = Vec::new();
    let mut question_type = 0;
    if questions == 1 {
        while response[offset] != 0 {
            assert!(response[offset] < 64, "the question is not compressed");
            offset += 1 + usize::from(response[offset]);
        }
        offset += 1;
        question_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        offset += 4;
        question = response[HEADER_BYTES..offset].to_vec();
    }
    let mut decoded_answers = Vec::new();
    for _ in 0..answers {
        assert_eq!(
            &response[offset..offset + 2],
            &[0xC0, 0x0C],
            "points at the question"
        );
        let record_type = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        assert_eq!(record_type, question_type);
        let class = u16::from_be_bytes([response[offset + 4], response[offset + 5]]);
        assert_eq!(class, CLASS_IN);
        let ttl = u32::from_be_bytes(response[offset + 6..offset + 10].try_into().unwrap());
        let length = usize::from(u16::from_be_bytes([
            response[offset + 10],
            response[offset + 11],
        ]));
        let data = &response[offset + 12..offset + 12 + length];
        let address = match record_type {
            TYPE_A => IpAddr::from(<[u8; 4]>::try_from(data).unwrap()),
            TYPE_AAAA => IpAddr::from(<[u8; 16]>::try_from(data).unwrap()),
            other => panic!("unexpected record type {other}"),
        };
        decoded_answers.push((address, ttl));
        offset += 12 + length;
    }
    assert_eq!(offset, response.len(), "nothing follows the answers");
    Decoded {
        id,
        flags,
        code,
        question,
        answers: decoded_answers,
    }
}

/// SplitMix64, the explicit seeded generator for the robustness tests.
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

    pub(super) fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}
