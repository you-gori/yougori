//! Tests of the relay core, the serve loop and the handoff (M09E), with fakes: a scripted
//! guest port and a scripted link. The contract with the broker is checked against the
//! committed relay step over a real V02 broker with a fixed resolver. Nothing here opens
//! a socket or starts a process.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use super::handoff::{encode_handoff, wipe, HandoffParts};
use super::*;
use crate::foundation::ids::{
    digest, ExecutionId, ManualClock, MonotonicTime, PolicyEpoch, TenantId,
};
use crate::foundation::process::ProcessIdentity;
use crate::foundation::transfer::{GeneralReleaseBudget, KeyError};
use crate::sandbox_contract::destinations::{
    AddressFamily, CanonicalName, ChannelPolicy, ConnectionPermit, DestinationBroker,
    DestinationPolicy, DestinationPort, DestinationRequest, EffectClass, GrantTarget,
    HostAddressGeneration, HostAddressState, HttpMethod, InFlightAllowance, IpPrefix, NetworkMode,
    OperationName, OperationRoute, OperationSpec, OperationTls, PathTemplate, PolicyParts,
    RedirectPolicy, ReleaseAccount, ReleaseChannel, ReleaseTrustClass, ResolutionQuery, Resolver,
    ResolverAnswer, ResolverFailure, ResolverId, RouteBudgets, RouteGrant, RouteId, RouteKind,
    RouteProtocol, TaskDataClass, TlsFacts,
};
use crate::sandbox_contract::relay::{ReadOutcome, ReaderLimits, RelayStep, RequestReader};
use crate::sandbox_contract::relay_link::{
    BrokerLink, BrokerMessage, CloseReason, ExchangeId, ExchangeRefusal, FrameDecoder, LinkBinding,
    LinkKey, LinkSessionId, RelayLink, RelayMessage, WireBytes, MAX_OPEN_EXCHANGES,
};

const ENDPOINT: &str = "provider";
const ROUTE: &str = "provider-api";

const REQUEST: &[u8] =
    b"GET /v1/models?limit=2 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n";
const FORWARDED: &[u8] =
    b"GET /v1/models?limit=2 HTTP/1.1\r\nhost: api.example.com\r\naccept: application/json\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

fn endpoint() -> GuestEndpoint {
    GuestEndpoint::new(ENDPOINT).unwrap()
}

fn route() -> RouteId {
    RouteId::new(ROUTE).unwrap()
}

fn routes() -> RouteTable {
    RouteTable::new(vec![RouteEntry {
        endpoint: endpoint(),
        route: route(),
    }])
    .unwrap()
}

fn limits() -> ReaderLimits {
    ReaderLimits::new(4_096, 65_536).unwrap()
}

fn core() -> RelayCore {
    RelayCore::new(routes(), limits())
}

fn guest(number: u64) -> GuestConnection {
    GuestConnection::new(number)
}

/// The request a forward action carries, with its exchange and route.
fn forwarded(actions: &[RelayAction]) -> (ExchangeId, RouteId, Vec<u8>) {
    match actions {
        [RelayAction::Forward(RelayMessage::Forward {
            exchange,
            route,
            request,
        })] => (*exchange, route.clone(), request.as_slice().to_vec()),
        other => panic!("expected one forward, got {other:?}"),
    }
}

fn refusal(actions: &[RelayAction], connection: GuestConnection) -> GuestRefusal {
    match actions {
        [RelayAction::Refuse {
            connection: refused,
            refusal,
        }] if *refused == connection => refusal.clone(),
        other => panic!("expected one refusal of {connection}, got {other:?}"),
    }
}

/// Opens `connection` and sends `wire` in one piece.
fn send(core: &mut RelayCore, connection: GuestConnection, wire: &[u8]) -> Vec<RelayAction> {
    assert_eq!(core.open(connection, &endpoint()), Vec::new());
    core.receive(connection, wire)
}

// The core with fakes.

#[test]
fn a_guest_request_round_trips_through_the_core() {
    let mut core = core();
    let (exchange, forwarded_route, request) = forwarded(&send(&mut core, guest(1), REQUEST));
    assert_eq!(exchange, ExchangeId::FIRST);
    assert_eq!(forwarded_route, route());
    assert_eq!(request, FORWARDED);
    assert_eq!(core.open_exchanges(), 1);
    let actions = core.broker(BrokerMessage::Response {
        exchange,
        status: 200,
        response: WireBytes::new(RESPONSE.to_vec()),
    });
    assert_eq!(
        actions,
        vec![RelayAction::Respond {
            connection: guest(1),
            response: WireBytes::new(RESPONSE.to_vec()),
        }]
    );
    assert!(core.is_idle());
}

#[test]
fn guest_smuggling_forms_are_refused_before_anything_is_forwarded() {
    let smuggling: [&[u8]; 7] = [
        b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
        b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\nTransfer_Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
        b"GET /v1/models HTTP/1.1\nHost: api.example.com\r\n\r\n",
        b"GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\n folded\r\n\r\n",
        b"GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\n\r\nGET /v1/models HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        b"GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\nX-Original-URL: /admin\r\n\r\n",
    ];
    let mut core = core();
    for (number, wire) in (1_u64..).zip(smuggling) {
        let actions = send(&mut core, guest(number), wire);
        assert!(
            matches!(refusal(&actions, guest(number)), GuestRefusal::Read(_)),
            "{:?}",
            String::from_utf8_lossy(wire)
        );
    }
    assert!(core.is_idle());
    // No exchange number was used: the next request is the first exchange.
    let (exchange, _, _) = forwarded(&send(&mut core, guest(99), REQUEST));
    assert_eq!(exchange, ExchangeId::FIRST);
}

#[test]
fn an_unknown_endpoint_is_refused_at_once() {
    let mut core = core();
    let elsewhere = GuestEndpoint::new("elsewhere").unwrap();
    let actions = core.open(guest(1), &elsewhere);
    assert_eq!(
        refusal(&actions, guest(1)),
        GuestRefusal::UnknownEndpoint {
            endpoint: elsewhere
        }
    );
    assert_eq!(core.receive(guest(1), REQUEST), Vec::new());
    assert!(core.is_idle());
}

#[test]
fn a_request_the_relay_cannot_rebuild_is_refused_unforwarded() {
    let mut core = core();
    let dot_segment = send(
        &mut core,
        guest(1),
        b"GET /v1/../admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    );
    assert!(matches!(
        refusal(&dot_segment, guest(1)),
        GuestRefusal::Request(_)
    ));
    let bad_host = send(
        &mut core,
        guest(2),
        b"GET /v1/models HTTP/1.1\r\nHost: api..example.com\r\n\r\n",
    );
    assert!(matches!(
        refusal(&bad_host, guest(2)),
        GuestRefusal::Request(_)
    ));
    assert!(core.is_idle());
}

#[test]
fn a_broker_refusal_gives_the_guest_the_fixed_error() {
    let mut core = core();
    let (exchange, _, _) = forwarded(&send(&mut core, guest(1), REQUEST));
    let actions = core.broker(BrokerMessage::Refused {
        exchange,
        refusal: ExchangeRefusal::NotPermitted,
    });
    assert_eq!(
        refusal(&actions, guest(1)),
        GuestRefusal::Broker(ExchangeRefusal::NotPermitted)
    );
    assert!(core.is_idle());
    // Through the loop, the guest gets exactly the fixed bytes.
    let mut guest_port = FakeGuest::new(vec![
        GuestEvent::Opened {
            connection: guest(1),
            endpoint: endpoint(),
        },
        GuestEvent::Data {
            connection: guest(1),
            bytes: REQUEST.to_vec(),
        },
        GuestEvent::Ended,
    ]);
    let mut link = FakeLink::new(Answer::Refuse(ExchangeRefusal::BudgetExhausted));
    let end = serve(&mut self::core(), &mut guest_port, &mut link, timing());
    assert_eq!(end, ServeEnd::GuestEnded);
    assert_eq!(guest_port.written(guest(1)), GUEST_ERROR_RESPONSE);
    assert!(guest_port.ended.contains(&guest(1)));
}

#[test]
fn the_core_holds_at_most_max_open_exchanges_numbered_upward() {
    let mut core = core();
    for number in 0..MAX_OPEN_EXCHANGES {
        let number = u64::try_from(number).unwrap();
        let (exchange, _, _) = forwarded(&send(&mut core, guest(number), REQUEST));
        assert_eq!(exchange, ExchangeId::new(number));
    }
    assert_eq!(core.open_exchanges(), MAX_OPEN_EXCHANGES);
    let over = core.open(guest(100), &endpoint());
    assert_eq!(
        refusal(&over, guest(100)),
        GuestRefusal::TooManyExchanges {
            max: MAX_OPEN_EXCHANGES
        }
    );
    // An answer frees a place; the next exchange is numbered above every one before.
    core.broker(BrokerMessage::Response {
        exchange: ExchangeId::new(3),
        status: 200,
        response: WireBytes::new(RESPONSE.to_vec()),
    });
    let (exchange, _, _) = forwarded(&send(&mut core, guest(101), REQUEST));
    assert_eq!(
        exchange,
        ExchangeId::new(u64::try_from(MAX_OPEN_EXCHANGES).unwrap())
    );
    // Connections still being read count too.
    let mut reading = self::core();
    for number in 0..MAX_OPEN_EXCHANGES {
        let number = u64::try_from(number).unwrap();
        assert_eq!(reading.open(guest(number), &endpoint()), Vec::new());
    }
    assert!(matches!(
        refusal(&reading.open(guest(100), &endpoint()), guest(100)),
        GuestRefusal::TooManyExchanges { .. }
    ));
}

#[test]
fn a_link_closed_mid_exchange_gives_every_held_guest_the_fixed_error() {
    let mut core = core();
    forwarded(&send(&mut core, guest(1), REQUEST));
    assert_eq!(core.open(guest(2), &endpoint()), Vec::new());
    assert_eq!(
        core.receive(guest(2), b"GET /v1/models HTTP/1.1\r\n"),
        Vec::new()
    );
    let mut actions = core.broker(BrokerMessage::Close {
        reason: CloseReason::Revoked,
    });
    actions.sort_by_key(|action| match action {
        RelayAction::Refuse { connection, .. } => connection.get(),
        _ => u64::MAX,
    });
    assert_eq!(
        actions,
        vec![
            RelayAction::Refuse {
                connection: guest(1),
                refusal: GuestRefusal::LinkEnded
            },
            RelayAction::Refuse {
                connection: guest(2),
                refusal: GuestRefusal::LinkEnded
            },
        ]
    );
    assert!(!core.link_open());
    assert_eq!(
        refusal(&core.open(guest(3), &endpoint()), guest(3)),
        GuestRefusal::LinkEnded
    );
    // Through the loop: the link fails while the exchange waits.
    let mut guest_port = FakeGuest::new(vec![
        GuestEvent::Opened {
            connection: guest(1),
            endpoint: endpoint(),
        },
        GuestEvent::Data {
            connection: guest(1),
            bytes: REQUEST.to_vec(),
        },
    ]);
    let mut link = FakeLink::new(Answer::Fail);
    let end = serve(&mut self::core(), &mut guest_port, &mut link, timing());
    assert!(matches!(end, ServeEnd::LinkFailed(_)));
    assert_eq!(guest_port.written(guest(1)), GUEST_ERROR_RESPONSE);
    assert!(guest_port.ended.contains(&guest(1)));
}

#[test]
fn expect_100_continue_is_answered_by_the_relay_and_not_forwarded() {
    let mut core = core();
    let head = b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n";
    assert_eq!(core.open(guest(1), &endpoint()), Vec::new());
    assert_eq!(
        core.receive(guest(1), head),
        vec![RelayAction::Continue {
            connection: guest(1)
        }]
    );
    let (_, _, request) = forwarded(&core.receive(guest(1), b"{}"));
    assert_eq!(
        request,
        b"POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 2\r\n\r\n{}"
    );
}

#[test]
fn a_guest_that_stops_early_or_sends_more_after_its_request_is_refused() {
    let mut core = core();
    assert_eq!(core.open(guest(1), &endpoint()), Vec::new());
    assert_eq!(
        core.receive(guest(1), b"GET /v1/models HTTP/1.1\r\n"),
        Vec::new()
    );
    assert_eq!(
        refusal(&core.guest_closed(guest(1)), guest(1)),
        GuestRefusal::Incomplete
    );
    let (exchange, _, _) = forwarded(&send(&mut core, guest(2), REQUEST));
    assert_eq!(
        refusal(&core.receive(guest(2), b"more"), guest(2)),
        GuestRefusal::BytesAfterRequest
    );
    // The late answer goes nowhere, and the exchange closes.
    assert_eq!(
        core.broker(BrokerMessage::Response {
            exchange,
            status: 200,
            response: WireBytes::new(RESPONSE.to_vec()),
        }),
        Vec::new()
    );
    assert!(core.is_idle());
}

// The forwarded bytes: rebuilt, never copied, and the broker's fixed point.

/// Guest requests and what the relay forwards for each.
fn rebuilt_cases() -> Vec<(&'static [u8], &'static [u8])> {
    vec![
        (REQUEST, FORWARDED),
        (
            b"GET /v1/models?after=b&limit=%7e2 HTTP/1.1\r\nHOST: API.Example.COM:443\r\nX-Trace:  \r\n\r\n",
            b"GET /v1/models?after=b&limit=~2 HTTP/1.1\r\nhost: api.example.com\r\nx-trace:\r\n\r\n",
        ),
        (
            b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            b"POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
        ),
        (
            b"POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            b"POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 0\r\n\r\n",
        ),
        (
            b"PUT /v1/files/a%2ab HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 3\r\n\r\nabc",
            b"PUT /v1/files/a%2Ab HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 3\r\n\r\nabc",
        ),
    ]
}

fn read_complete(wire: &[u8]) -> crate::sandbox_contract::relay::ReadRequest {
    let mut reader = RequestReader::new(limits());
    let _ = reader.feed(wire);
    match reader.into_outcome() {
        ReadOutcome::Complete(read) => read,
        other => panic!("expected a complete request, got {other:?}"),
    }
}

#[test]
fn the_forwarded_request_is_rebuilt_from_the_parsed_request() {
    for (wire, expected) in rebuilt_cases() {
        let mut core = core();
        let (_, _, request) = forwarded(&send(&mut core, guest(1), wire));
        assert_eq!(
            String::from_utf8_lossy(&request),
            String::from_utf8_lossy(expected)
        );
        // A fresh reader of the same bytes, rebuilt, gives the same; and re-reading the
        // forwarded bytes changes nothing (a fixed point).
        assert_eq!(forward_bytes(&read_complete(wire)).unwrap(), request);
        assert_eq!(forward_bytes(&read_complete(&request)).unwrap(), request);
    }
    // A port other than 443 is kept, also as a fixed point.
    let other_port = forward_bytes(&read_complete(
        b"GET /v1/models HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n",
    ))
    .unwrap();
    assert_eq!(
        other_port,
        b"GET /v1/models HTTP/1.1\r\nhost: api.example.com:8443\r\n\r\n"
    );
    assert_eq!(
        forward_bytes(&read_complete(&other_port)).unwrap(),
        other_port
    );
}

const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);

fn operation_route() -> OperationRoute {
    let spec = |name: &str, method, path: &str, keys: &[&str], effect| OperationSpec {
        name: OperationName::new(name).unwrap(),
        method,
        path: PathTemplate::parse(path).unwrap(),
        query_keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        effect,
    };
    OperationRoute::new(
        OperationTls::TerminatedAtExecutor,
        None,
        vec![
            spec(
                "list-models",
                HttpMethod::Get,
                "/v1/models",
                &["limit", "after"],
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

fn resolver_id() -> ResolverId {
    ResolverId::new("host-dns").unwrap()
}

fn broker() -> DestinationBroker<ManualClock> {
    let grant = RouteGrant {
        id: route(),
        protocol: RouteProtocol::Https,
        target: GrantTarget::ExactName(CanonicalName::parse("api.example.com").unwrap()),
        port: DestinationPort::HTTPS,
        route: RouteKind::Operation(operation_route()),
        ipv6: false,
        resolver: Some(resolver_id()),
        budgets: RouteBudgets {
            dns_queries: 100,
            connections: 100,
            bytes_out: 100_000,
            bytes_in: 100_000,
            effects: 100,
        },
    };
    let policy = DestinationPolicy::new(
        PolicyParts {
            tenant: TenantId::new("tenant-a").unwrap(),
            epoch: PolicyEpoch::FIRST,
            mode: NetworkMode::DeclaredTransport,
            data_class: TaskDataClass::Ordinary,
            grants: vec![grant],
            allowed_resolvers: BTreeSet::from([resolver_id()]),
            approved_objects: BTreeSet::new(),
            max_answer_ttl: Duration::from_secs(300),
        },
        START,
    )
    .unwrap();
    let account = ReleaseAccount::new(
        BTreeMap::from([
            (
                ReleaseChannel::DnsQuery,
                ChannelPolicy {
                    budget_bytes: 65_536,
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
    .unwrap();
    DestinationBroker::new(
        policy,
        HostAddressState::new(
            HostAddressGeneration::FIRST,
            [IpPrefix::host("192.168.1.10".parse::<IpAddr>().unwrap())],
        ),
        account,
        ManualClock::new(START),
    )
}

struct FixedResolver(ResolverId);

impl Resolver for FixedResolver {
    fn id(&self) -> &ResolverId {
        &self.0
    }

    fn resolve(&self, query: &ResolutionQuery) -> Result<ResolverAnswer, ResolverFailure> {
        Ok(ResolverAnswer {
            name: query.name().clone(),
            aliases: Vec::new(),
            addresses: vec!["93.184.216.34".parse().unwrap()],
            ttl: Duration::from_secs(60),
        })
    }
}

fn permit(broker: &mut DestinationBroker<ManualClock>) -> ConnectionPermit {
    let authorized = broker
        .authorize(&DestinationRequest::parse(RouteProtocol::Https, "api.example.com").unwrap())
        .unwrap();
    let validated = broker
        .resolve(
            &authorized,
            AddressFamily::Ipv4,
            &FixedResolver(resolver_id()),
        )
        .unwrap();
    broker
        .open_connection(&validated, "93.184.216.34".parse().unwrap())
        .unwrap()
}

#[test]
fn the_forwarded_bytes_are_the_fixed_point_of_the_brokers_relay_step() {
    let mut broker = broker();
    for (wire, _) in rebuilt_cases() {
        let mut core = core();
        let (_, forwarded_route, request) = forwarded(&send(&mut core, guest(1), wire));
        let mut step = RelayStep::start(&broker, &forwarded_route, limits()).unwrap();
        step.feed(&request).unwrap();
        let permit = permit(&mut broker);
        let decision = step
            .finish(
                &mut broker,
                &permit,
                &TlsFacts {
                    sni: Some("api.example.com".to_owned()),
                },
                0,
            )
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(decision.bytes()),
            String::from_utf8_lossy(&request),
            "the broker would rebuild other bytes"
        );
        decision.abandon(&mut broker).unwrap();
    }
}

// The serve loop with fakes.

/// A scripted guest: its events in order, then idle; keeps what the relay writes.
struct FakeGuest {
    events: VecDeque<GuestEvent>,
    writes: BTreeMap<GuestConnection, Vec<u8>>,
    ended: BTreeSet<GuestConnection>,
}

impl FakeGuest {
    fn new(events: Vec<GuestEvent>) -> Self {
        Self {
            events: events.into(),
            writes: BTreeMap::new(),
            ended: BTreeSet::new(),
        }
    }

    fn written(&self, connection: GuestConnection) -> &[u8] {
        self.writes.get(&connection).map_or(&[], Vec::as_slice)
    }
}

impl GuestPort for FakeGuest {
    fn next_event(&mut self, _within: Duration) -> Result<GuestEvent, GuestPortError> {
        Ok(self.events.pop_front().unwrap_or(GuestEvent::Idle))
    }

    fn write(&mut self, connection: GuestConnection, bytes: &[u8]) -> Result<(), GuestPortError> {
        self.writes
            .entry(connection)
            .or_default()
            .extend_from_slice(bytes);
        Ok(())
    }

    fn end(&mut self, connection: GuestConnection) {
        self.ended.insert(connection);
    }
}

/// How the fake broker answers a forward.
enum Answer {
    Respond,
    Refuse(ExchangeRefusal),
    /// The link fails on the next receive.
    Fail,
}

/// The relay's end of a link over real sealed sessions, with a scripted broker at the
/// other end.
struct FakeLink {
    relay: RelayLink,
    broker: BrokerLink,
    answer: Answer,
    inbox: VecDeque<Vec<u8>>,
    sent: Vec<RelayMessage>,
    failed: bool,
}

impl FakeLink {
    fn new(answer: Answer) -> Self {
        let binding = LinkBinding {
            sandbox: ExecutionId::new("sandbox-a").unwrap(),
            relay: ProcessIdentity {
                pid: 4242,
                start_time_ticks: 7,
            },
            session: LinkSessionId::generate(),
        };
        let key = vec![7_u8; LinkKey::MIN_BYTES];
        Self {
            relay: RelayLink::open(binding.clone(), LinkKey::new(key.clone()).unwrap()),
            broker: BrokerLink::open(binding, LinkKey::new(key).unwrap()),
            answer,
            inbox: VecDeque::new(),
            sent: Vec::new(),
            failed: false,
        }
    }
}

fn frame(bytes: &[u8]) -> crate::sandbox_contract::relay_link::RawFrame {
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.feed(bytes).unwrap(), bytes.len());
    decoder.take().unwrap()
}

impl RelayLinkPort for FakeLink {
    fn send(&mut self, message: RelayMessage, _within: Duration) -> Result<(), LinkPortError> {
        let bytes = self
            .relay
            .seal(message.clone())
            .map_err(|error| LinkPortError {
                detail: error.to_string(),
            })?;
        let received = self.broker.accept(&frame(&bytes)).unwrap();
        assert_eq!(received, message);
        self.sent.push(message);
        if let RelayMessage::Forward { exchange, .. } = received {
            let reply = match &self.answer {
                Answer::Respond => Some(BrokerMessage::Response {
                    exchange,
                    status: 200,
                    response: WireBytes::new(RESPONSE.to_vec()),
                }),
                Answer::Refuse(refusal) => Some(BrokerMessage::Refused {
                    exchange,
                    refusal: *refusal,
                }),
                Answer::Fail => {
                    self.failed = true;
                    None
                }
            };
            if let Some(reply) = reply {
                self.inbox.push_back(self.broker.seal(reply).unwrap());
            }
        }
        Ok(())
    }

    fn receive(&mut self, _within: Duration) -> Result<Option<BrokerMessage>, LinkPortError> {
        if self.failed {
            return Err(LinkPortError {
                detail: "disconnected".to_owned(),
            });
        }
        match self.inbox.pop_front() {
            None => Ok(None),
            Some(bytes) => self
                .relay
                .accept(&frame(&bytes))
                .map(Some)
                .map_err(|error| LinkPortError {
                    detail: error.to_string(),
                }),
        }
    }
}

fn timing() -> ServeTiming {
    ServeTiming {
        poll: Duration::ZERO,
        send: Duration::from_secs(1),
    }
}

#[test]
fn the_loop_round_trips_and_closes_the_link_when_the_guest_ends() {
    let mut guest_port = FakeGuest::new(vec![
        GuestEvent::Opened {
            connection: guest(1),
            endpoint: endpoint(),
        },
        GuestEvent::Data {
            connection: guest(1),
            bytes: REQUEST[..10].to_vec(),
        },
        GuestEvent::Data {
            connection: guest(1),
            bytes: REQUEST[10..].to_vec(),
        },
        GuestEvent::Closed {
            connection: guest(1),
        },
        GuestEvent::Ended,
    ]);
    let mut link = FakeLink::new(Answer::Respond);
    let end = serve(&mut core(), &mut guest_port, &mut link, timing());
    assert_eq!(end, ServeEnd::GuestEnded);
    assert_eq!(guest_port.written(guest(1)), RESPONSE);
    assert!(guest_port.ended.contains(&guest(1)));
    assert_eq!(
        link.sent,
        vec![
            RelayMessage::Forward {
                exchange: ExchangeId::FIRST,
                route: route(),
                request: WireBytes::new(FORWARDED.to_vec()),
            },
            RelayMessage::Close {
                reason: CloseReason::Finished
            },
        ]
    );
}

#[test]
fn the_loop_ends_when_the_broker_closes() {
    let mut guest_port = FakeGuest::new(Vec::new());
    let mut link = FakeLink::new(Answer::Respond);
    let close = link
        .broker
        .seal(BrokerMessage::Close {
            reason: CloseReason::Revoked,
        })
        .unwrap();
    link.inbox.push_back(close);
    let end = serve(&mut core(), &mut guest_port, &mut link, timing());
    assert_eq!(
        end,
        ServeEnd::BrokerClosed {
            reason: CloseReason::Revoked
        }
    );
    assert!(link.sent.is_empty());
}

// The handoff.

fn binding() -> LinkBinding {
    LinkBinding {
        sandbox: ExecutionId::new("sandbox-a").unwrap(),
        relay: ProcessIdentity {
            pid: 4242,
            start_time_ticks: 133_000_000_000_000_000,
        },
        session: LinkSessionId::from_digest(digest("yougori/test/relay-process/v1", &[b"s"])),
    }
}

fn broker_identity() -> ProcessIdentity {
    ProcessIdentity {
        pid: 17,
        start_time_ticks: 132_000_000_000_000_000,
    }
}

/// A key whose encodings are easy to look for.
fn key_bytes() -> Vec<u8> {
    (0..32_u8)
        .map(|byte| byte.wrapping_mul(37).wrapping_add(11))
        .collect()
}

fn body_with_key(key: &[u8]) -> Vec<u8> {
    encode_handoff(&HandoffParts {
        key,
        binding: &binding(),
        broker: &broker_identity(),
        routes: &routes(),
        limits: limits(),
        guest: None,
    })
    .unwrap()
    .as_slice()
    .to_vec()
}

fn body() -> Vec<u8> {
    body_with_key(&key_bytes())
}

/// The handoff body as JSON, changed by `change`.
fn changed(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut json: serde_json::Value = serde_json::from_slice(&body()).unwrap();
    change(&mut json);
    serde_json::to_vec(&json).unwrap()
}

#[test]
fn a_handoff_reads_back_strictly() {
    let handoff = decode_handoff(&body()).unwrap();
    assert_eq!(handoff.binding, binding());
    assert_eq!(handoff.broker, broker_identity());
    assert_eq!(handoff.routes, routes());
    assert_eq!(handoff.limits, limits());
    // The key read back is the key written: a link sealed under one opens under the other.
    let mut relay = RelayLink::open(binding(), handoff.key);
    let mut broker = BrokerLink::open(binding(), LinkKey::new(key_bytes()).unwrap());
    let sealed = relay
        .seal(RelayMessage::Close {
            reason: CloseReason::Finished,
        })
        .unwrap();
    assert!(broker.accept(&frame(&sealed)).is_ok());

    let malformed = [
        changed(|json| json["extra"] = serde_json::json!(1)),
        changed(|json| json["binding"]["extra"] = serde_json::json!(1)),
        changed(|json| {
            json.as_object_mut().unwrap().remove("broker");
        }),
        // A pipe name is not read: the relay derives its pipe from its own identity.
        changed(|json| json["pipe"] = serde_json::json!(r"\\.\pipe\elsewhere")),
        changed(|json| json["routes"] = serde_json::json!([])),
        [body(), b" {}".to_vec()].concat(),
        body()[..body().len() - 1].to_vec(),
    ];
    for bad in malformed {
        assert_eq!(decode_handoff(&bad).unwrap_err(), HandoffError::Malformed);
    }
    assert_eq!(
        decode_handoff(&changed(|json| json["version"] = serde_json::json!(2))).unwrap_err(),
        HandoffError::UnsupportedVersion { found: 2 }
    );
    assert_eq!(
        decode_handoff(&changed(
            |json| json["key"] = serde_json::json!("not base64!")
        ))
        .unwrap_err(),
        HandoffError::KeyEncoding
    );
    assert_eq!(
        decode_handoff(&body_with_key(&[1; 8])).unwrap_err(),
        HandoffError::Key(KeyError::TooShort {
            min_bytes: LinkKey::MIN_BYTES,
            found_bytes: 8
        })
    );
    assert!(matches!(
        decode_handoff(&changed(
            |json| json["limits"]["max_head_bytes"] = serde_json::json!(0)
        ))
        .unwrap_err(),
        HandoffError::Limits(_)
    ));
    assert_eq!(decode_handoff(b"").unwrap_err(), HandoffError::Empty);
}

#[test]
fn an_oversize_handoff_is_refused_whole() {
    let oversize = vec![b' '; MAX_HANDOFF_BYTES + 1];
    assert_eq!(
        decode_handoff(&oversize).unwrap_err(),
        HandoffError::Oversize {
            declared: u64::try_from(MAX_HANDOFF_BYTES + 1).unwrap(),
            max: MAX_HANDOFF_BYTES
        }
    );
}

/// Every spelling of the key a leak would show.
fn key_spellings() -> Vec<String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let key = key_bytes();
    vec![
        STANDARD.encode(&key),
        hex::encode(&key),
        format!("{key:?}"),
        format!("{:?}", &key[..8]),
    ]
}

#[test]
fn the_key_is_absent_from_debug_display_and_errors() {
    let handoff = decode_handoff(&body()).unwrap();
    let shown = format!("{handoff:?} {:?}", handoff.key);
    for spelling in key_spellings() {
        assert!(!shown.contains(&spelling), "Debug shows the key: {shown}");
    }
    // A key in the wrong place, which serde's own message would quote, or a body cut
    // short, is refused without echoing it.
    let errors = [
        decode_handoff(&changed(|json| json["broker"]["pid"] = json["key"].clone())).unwrap_err(),
        decode_handoff(&changed(|json| json["version"] = json["key"].clone())).unwrap_err(),
        decode_handoff(&body()[..40]).unwrap_err(),
    ];
    for error in errors {
        let shown = format!("{error} {error:?}");
        for spelling in key_spellings() {
            assert!(
                !shown.contains(&spelling),
                "an error shows the key: {shown}"
            );
        }
    }
    let mut secret = key_bytes();
    wipe(&mut secret);
    assert!(secret.iter().all(|byte| *byte == 0));
}

#[test]
fn relay_main_refuses_to_run_outside_confinement() {
    let exit = relay_main(FakeGuest::new(Vec::new()));
    let expected = if cfg!(windows) {
        ConfinementError::NotAppContainer
    } else {
        ConfinementError::Unsupported
    };
    assert!(
        matches!(&exit, RelayExit::NotConfined(error) if *error == expected),
        "{exit:?}"
    );
    assert_eq!(exit.code(), 10);
}

#[test]
fn route_tables_are_bounded_and_read_back_strictly() {
    assert_eq!(RouteTable::new(Vec::new()), Err(RouteTableError::Empty));
    let twice = RouteTable::new(vec![
        RouteEntry {
            endpoint: endpoint(),
            route: route(),
        },
        RouteEntry {
            endpoint: endpoint(),
            route: RouteId::new("other").unwrap(),
        },
    ]);
    assert_eq!(
        twice,
        Err(RouteTableError::DuplicateEndpoint {
            endpoint: endpoint()
        })
    );
    let many: Vec<RouteEntry> = (0..=MAX_ROUTES)
        .map(|index| RouteEntry {
            endpoint: GuestEndpoint::new(format!("endpoint-{index}")).unwrap(),
            route: route(),
        })
        .collect();
    assert_eq!(
        RouteTable::new(many),
        Err(RouteTableError::TooManyRoutes { max: MAX_ROUTES })
    );
    let text = serde_json::to_string(&routes()).unwrap();
    assert_eq!(serde_json::from_str::<RouteTable>(&text).unwrap(), routes());
    assert!(serde_json::from_str::<RouteTable>(
        r#"[{"endpoint":"provider","route":"provider-api","budget":1}]"#
    )
    .is_err());
    assert!(serde_json::from_str::<RouteTable>(r#"[{"endpoint":"-bad","route":"r"}]"#).is_err());
}
