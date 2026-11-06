//! The relay step over a real V02 broker: rebuilt bytes, refusals before any reservation,
//! budgets charged before forwarding, and the same decision for any split (VM §2.5, §4.2
//! step 7, §4.3; VM-W11; VM-P10, VM-P30).

use super::*;
use crate::sandbox_contract::destinations::{
    BodyFraming, BudgetExhausted, BudgetKind, BudgetScope, DestinationRefusal, EffectOutcome,
    NameError, RequestRefusal, METHOD_OVERRIDE_HEADERS,
};

const API: &str = "api.example.com";

struct Setup {
    broker: Broker,
    permit: ConnectionPermit,
}

fn setup_with(grants: Vec<RouteGrant>) -> Setup {
    let mut broker = broker(grants);
    let permit = permit(&mut broker, API);
    Setup { broker, permit }
}

fn setup() -> Setup {
    setup_with(vec![api_grant(true, budgets())])
}

fn provider() -> RouteId {
    route_id("provider-api")
}

fn relay_with(
    setup: &mut Setup,
    wire: &[u8],
    facts: &TlsFacts,
) -> Result<ForwardDecision, RelayRefusal> {
    let mut step = RelayStep::start(&setup.broker, &provider(), limits())?;
    step.feed(wire)?;
    step.finish(&mut setup.broker, &setup.permit, facts, 0)
}

fn relay(setup: &mut Setup, wire: &[u8]) -> Result<ForwardDecision, RelayRefusal> {
    relay_with(setup, wire, &tls(API))
}

fn relay_bytewise(setup: &mut Setup, wire: &[u8]) -> Result<ForwardDecision, RelayRefusal> {
    let mut step = RelayStep::start(&setup.broker, &provider(), limits())?;
    for byte in wire {
        let _ = step.feed(&[*byte]);
    }
    step.finish(&mut setup.broker, &setup.permit, &tls(API), 0)
}

/// Nothing of the route's byte or effect budget and nothing of the provider-request
/// channel is used or held.
fn assert_nothing_reserved(broker: &Broker) {
    let usage = broker.usage(&provider());
    for kind in [BudgetKind::BytesOut, BudgetKind::Effects] {
        assert_eq!(usage.used(kind), 0, "{kind:?} used");
        assert_eq!(usage.reserved(kind), 0, "{kind:?} reserved");
    }
    assert_eq!(
        broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        0
    );
}

fn get(fields: &str) -> Vec<u8> {
    format!("GET /v1/models HTTP/1.1\r\nHost: api.example.com\r\n{fields}\r\n").into_bytes()
}

fn post(fields: &str, body: &str) -> Vec<u8> {
    format!("POST /v1/jobs HTTP/1.1\r\nHost: api.example.com\r\n{fields}\r\n{body}").into_bytes()
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

#[test]
fn a_valid_request_yields_bytes_rebuilt_from_the_bound_request() {
    let mut setup = setup();
    let wire = b"GET /v1/%6Dodels?limit=5&after=b HTTP/1.1\r\nHost: API.Example.com:443\r\n\
User-Agent: guest/1.0\r\nAccept: application/json\r\nConnection: close\r\nTE: trailers\r\n\r\n";
    let decision = relay(&mut setup, wire).unwrap();
    let expected: &[u8] = b"GET /v1/models?after=b&limit=5 HTTP/1.1\r\nhost: api.example.com\r\n\
user-agent: guest/1.0\r\naccept: application/json\r\n\r\n";
    assert_eq!(
        String::from_utf8_lossy(decision.bytes()),
        String::from_utf8_lossy(expected)
    );
    assert_ne!(decision.bytes(), &wire[..]);
    assert_eq!(decision.bound().operation.as_str(), "list-models");
    assert_eq!(decision.bound().body, BodyFraming::None);
    assert!(decision.effect_reservation().is_none());
    // The bytes are reserved before anything is sent, against the route and the channel.
    assert_eq!(decision.send_reservation().bytes(), length(expected));
    let usage = setup.broker.usage(&provider());
    assert_eq!(usage.reserved(BudgetKind::BytesOut), length(expected));
    assert_eq!(usage.used(BudgetKind::BytesOut), 0);
    let parts = decision.into_parts();
    setup
        .broker
        .complete_send(parts.send, length(&parts.bytes))
        .unwrap();
    let usage = setup.broker.usage(&provider());
    assert_eq!(usage.reserved(BudgetKind::BytesOut), 0);
    assert_eq!(usage.used(BudgetKind::BytesOut), length(expected));
    assert_eq!(
        setup
            .broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        length(expected)
    );
}

#[test]
fn the_rebuilt_bytes_read_and_bind_to_the_same_operation_and_bytes() {
    let mut setup = setup();
    for wire in [
        b"GET /v1/models?limit=5&after=%7euser HTTP/1.1\r\nHost: api.example.com:443\r\n\
Accept: */*\r\n\r\n"
            .to_vec(),
        post("Content-Type: application/json\r\nContent-Length: 2\r\n", "{}"),
        b"PUT /v1/files/abc HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n\
3\r\nabc\r\n0\r\n\r\n"
            .to_vec(),
    ] {
        let first = relay(&mut setup, &wire).unwrap();
        let again = relay(&mut setup, first.bytes()).unwrap();
        assert_eq!(again.bytes(), first.bytes());
        assert_eq!(again.bound().digest(), first.bound().digest());
        first.abandon(&mut setup.broker).unwrap();
        again.abandon(&mut setup.broker).unwrap();
    }
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn a_content_length_body_is_forwarded_with_one_content_length_and_an_effect_reserved() {
    let mut setup = setup();
    let decision = relay(
        &mut setup,
        &post(
            "Content-Type: application/json\r\nContent-Length: 13\r\n",
            "{\"model\":\"a\"}",
        ),
    )
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(decision.bytes()),
        "POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-type: application/json\r\n\
content-length: 13\r\n\r\n{\"model\":\"a\"}"
    );
    assert_eq!(decision.bound().operation.as_str(), "create-job");
    assert!(decision.effect_reservation().is_some());
    assert_eq!(
        setup
            .broker
            .usage(&provider())
            .reserved(BudgetKind::Effects),
        1
    );
    let parts = decision.into_parts();
    let sent = length(&parts.bytes);
    setup.broker.complete_send(parts.send, sent).unwrap();
    setup
        .broker
        .settle_effect(parts.effect.unwrap(), EffectOutcome::Committed)
        .unwrap();
    assert_eq!(setup.broker.usage(&provider()).used(BudgetKind::Effects), 1);
}

#[test]
fn a_chunked_body_is_forwarded_decoded_with_a_content_length() {
    let mut setup = setup();
    let decision = relay(
        &mut setup,
        b"PUT /v1/files/abc HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(decision.bound().body, BodyFraming::Chunked);
    assert_eq!(
        String::from_utf8_lossy(decision.bytes()),
        "PUT /v1/files/abc HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 11\r\n\r\n\
hello world"
    );
}

#[test]
fn smuggling_forms_are_refused_before_anything_is_reserved() {
    let cases: Vec<(Vec<u8>, RelayRefusal)> = vec![
        (
            post(
                "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
                "0\r\n\r\n",
            ),
            RelayRefusal::Read(ReadRefusal::Inspection(RequestRefusal::ConflictingFraming)),
        ),
        (
            post("Content-Length: 2\r\nContent-Length: 2\r\n", "{}"),
            RelayRefusal::Read(ReadRefusal::Inspection(RequestRefusal::DuplicateHeader {
                name: "content-length".to_owned(),
            })),
        ),
        (
            get("X-Long: a\r\n b\r\n"),
            RelayRefusal::Read(ReadRefusal::ObsoleteLineFolding),
        ),
        (
            b"GET /v1/models HTTP/1.1\nHost: api.example.com\r\n\r\n".to_vec(),
            RelayRefusal::Read(ReadRefusal::BareLineFeed),
        ),
        (
            post("Transfer-Encoding: chunked\r\n", "2 \r\n{}\r\n0\r\n\r\n"),
            RelayRefusal::Read(ReadRefusal::InvalidChunkSize),
        ),
        (
            post(
                "Transfer-Encoding: chunked\r\n",
                "2\r\n{}\r\n0\r\nX-A: 1\r\n\r\n",
            ),
            RelayRefusal::Read(ReadRefusal::Trailers),
        ),
        // V02's framing rule refuses these when the head is complete.
        (
            post("Content-Length: 02\r\n", "{}"),
            RelayRefusal::Read(ReadRefusal::Inspection(
                RequestRefusal::InvalidContentLength {
                    value: "02".to_owned(),
                },
            )),
        ),
        (
            get("Accept: a\r\naccept: b\r\n"),
            RelayRefusal::Read(ReadRefusal::Inspection(RequestRefusal::DuplicateHeader {
                name: "accept".to_owned(),
            })),
        ),
        (
            get("Content-Length: 5\r\n")
                .into_iter()
                .chain(*b"hello")
                .collect(),
            RelayRefusal::Read(ReadRefusal::Inspection(RequestRefusal::BodyNotAllowed {
                method: HttpMethod::Get,
            })),
        ),
        (
            get("Transfer-Encoding: chunked\r\n")
                .into_iter()
                .chain(*b"0\r\n\r\n")
                .collect(),
            RelayRefusal::Read(ReadRefusal::Inspection(RequestRefusal::BodyNotAllowed {
                method: HttpMethod::Get,
            })),
        ),
        (
            post("Transfer_Encoding: chunked\r\n", ""),
            RelayRefusal::Read(ReadRefusal::UnderscoreTwin {
                name: "Transfer_Encoding".to_owned(),
            }),
        ),
        (
            post("Content_Length: 0\r\nContent-Length: 2\r\n", "{}"),
            RelayRefusal::Read(ReadRefusal::UnderscoreTwin {
                name: "Content_Length".to_owned(),
            }),
        ),
        (
            post("Expect: 100-continue, x\r\nContent-Length: 2\r\n", "{}"),
            RelayRefusal::Read(ReadRefusal::UnsupportedExpectation {
                value: "100-continue, x".to_owned(),
            }),
        ),
    ];
    for (wire, expected) in cases {
        let mut setup = setup();
        assert_eq!(
            relay(&mut setup, &wire),
            Err(expected),
            "{}",
            String::from_utf8_lossy(&wire)
        );
        assert_nothing_reserved(&setup.broker);
    }
}

#[test]
fn absolute_form_asterisk_and_connect_targets_are_refused() {
    let cases: [(&[u8], RelayRefusal); 3] = [
        (
            b"GET https://api.example.com/v1/models HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            RelayRefusal::Request(RequestRefusal::TargetNotOriginForm),
        ),
        (
            b"OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            RelayRefusal::Request(RequestRefusal::TargetNotOriginForm),
        ),
        (
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
            // V02's framing rule knows no CONNECT method, so the reader refuses it.
            RelayRefusal::Read(ReadRefusal::Inspection(RequestRefusal::UnknownMethod {
                method: "CONNECT".to_owned(),
            })),
        ),
    ];
    for (wire, expected) in cases {
        let mut setup = setup();
        assert_eq!(relay(&mut setup, wire), Err(expected));
        assert_nothing_reserved(&setup.broker);
    }
}

#[test]
fn upgrades_are_refused() {
    for (fields, header) in [
        ("Upgrade: websocket\r\nConnection: Upgrade\r\n", "Upgrade"),
        ("Connection: upgrade\r\n", "Connection: upgrade"),
        (
            "HTTP2-Settings: AAMAAABkAAQAAP__\r\nConnection: HTTP2-Settings\r\n",
            "HTTP2-Settings (h2c)",
        ),
    ] {
        let mut setup = setup();
        assert_eq!(
            relay(&mut setup, &get(fields)),
            Err(RelayRefusal::Read(ReadRefusal::Inspection(
                RequestRefusal::Upgrade {
                    header: header.to_owned()
                }
            ))),
            "{fields}"
        );
        assert_nothing_reserved(&setup.broker);
    }
}

#[test]
fn method_override_headers_are_refused() {
    for header in METHOD_OVERRIDE_HEADERS {
        let mut setup = setup();
        let shouted = header.to_ascii_uppercase();
        assert_eq!(
            relay(&mut setup, &get(&format!("{shouted}: DELETE\r\n"))),
            Err(RelayRefusal::Read(ReadRefusal::Inspection(
                RequestRefusal::MethodOverride {
                    header: header.to_owned()
                }
            )))
        );
        assert_nothing_reserved(&setup.broker);
    }
}

#[test]
fn credential_headers_are_refused_on_a_credentialed_route_and_forwarded_on_others() {
    for (field, name) in [
        ("Authorization: Bearer guest-token", "authorization"),
        ("Cookie: session=1", "cookie"),
        (
            "Proxy-Authorization: Basic Zm9vOmJhcg==",
            "proxy-authorization",
        ),
    ] {
        let mut setup = setup();
        assert_eq!(
            relay(&mut setup, &get(&format!("{field}\r\n"))),
            Err(RelayRefusal::Request(RequestRefusal::ReservedHeader {
                name: name.to_owned()
            }))
        );
        assert_nothing_reserved(&setup.broker);
    }
    let mut open = setup_with(vec![api_grant(false, budgets())]);
    let decision = relay(&mut open, &get("Authorization: Bearer guest-token\r\n")).unwrap();
    assert!(String::from_utf8_lossy(decision.bytes())
        .contains("\r\nauthorization: Bearer guest-token\r\n"));
}

#[test]
fn the_authority_and_sni_must_name_the_permitted_destination() {
    let mut setup = setup();
    let wrong_host = b"GET /v1/models HTTP/1.1\r\nHost: evil.example.com\r\n\r\n";
    assert!(matches!(
        relay(&mut setup, wrong_host),
        Err(RelayRefusal::Request(
            RequestRefusal::AuthorityMismatch { .. }
        ))
    ));
    let no_host = b"GET /v1/models HTTP/1.1\r\nAccept: */*\r\n\r\n";
    assert_eq!(
        relay(&mut setup, no_host),
        Err(RelayRefusal::Request(RequestRefusal::MissingAuthority))
    );
    assert!(matches!(
        relay_with(&mut setup, &get(""), &tls("evil.example.com")),
        Err(RelayRefusal::Request(
            RequestRefusal::SniAuthorityMismatch { .. }
        ))
    ));
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn oversized_heads_and_bodies_are_refused() {
    let mut setup = setup();
    let huge = get(&format!("X-Pad: {}\r\n", "a".repeat(5_000)));
    assert_eq!(
        relay(&mut setup, &huge),
        Err(RelayRefusal::Read(ReadRefusal::HeadTooLarge {
            limit: 4_096
        }))
    );
    // The body limit is the route's whole outbound budget when that is smaller.
    let small = RouteBudgets {
        bytes_out: 100,
        ..budgets()
    };
    let mut setup = setup_with(vec![api_grant(true, small)]);
    let body = "x".repeat(200);
    assert_eq!(
        relay(&mut setup, &post("Content-Length: 200\r\n", &body)),
        Err(RelayRefusal::Read(ReadRefusal::BodyTooLarge {
            limit: 100,
            length: 200
        }))
    );
    // A body within the limit whose rebuilt request is over the budget is refused by the
    // reservation, and nothing stays held.
    let body = "x".repeat(90);
    assert!(matches!(
        relay(&mut setup, &post("Content-Length: 90\r\n", &body)),
        Err(RelayRefusal::Destination(DestinationRefusal::Budget(
            BudgetExhausted {
                scope: BudgetScope::Route(_),
                kind: Some(BudgetKind::BytesOut),
                limit: 100,
                ..
            }
        )))
    ));
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn a_spent_effect_budget_refuses_and_returns_the_byte_reservation() {
    let no_effects = RouteBudgets {
        effects: 0,
        ..budgets()
    };
    let mut setup = setup_with(vec![api_grant(true, no_effects)]);
    assert!(matches!(
        relay(&mut setup, &post("Content-Length: 2\r\n", "{}")),
        Err(RelayRefusal::Destination(DestinationRefusal::Budget(
            BudgetExhausted {
                kind: Some(BudgetKind::Effects),
                ..
            }
        )))
    ));
    assert_nothing_reserved(&setup.broker);
    // A read-only operation on the same route still goes through.
    assert!(relay(&mut setup, &get("")).is_ok());
}

#[test]
fn transport_and_unknown_routes_are_not_read() {
    let setup = setup_with(vec![api_grant(true, budgets()), transport_grant()]);
    assert_eq!(
        RelayStep::start(&setup.broker, &route_id("tls-stream"), limits()),
        Err(RelayRefusal::NotAnOperationRoute {
            route: route_id("tls-stream")
        })
    );
    assert_eq!(
        RelayStep::start(&setup.broker, &route_id("no-such-route"), limits()),
        Err(RelayRefusal::Destination(
            DestinationRefusal::UnknownRoute {
                route: route_id("no-such-route")
            }
        ))
    );
}

#[test]
fn a_permit_for_another_route_is_refused() {
    let uploads = grant(
        "uploads",
        "uploads.example.com",
        RouteKind::Operation(operation_route(false)),
        budgets(),
    );
    let mut setup = setup_with(vec![api_grant(true, budgets()), uploads]);
    let other = permit(&mut setup.broker, "uploads.example.com");
    let mut step = RelayStep::start(&setup.broker, &provider(), limits()).unwrap();
    step.feed(&get("")).unwrap();
    assert_eq!(
        step.finish(&mut setup.broker, &other, &tls(API), 0),
        Err(RelayRefusal::PermitForOtherRoute {
            route: provider(),
            permit: route_id("uploads"),
        })
    );
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn a_permit_from_an_older_policy_is_refused() {
    let mut setup = setup();
    let newer = policy(
        PolicyEpoch::FIRST.next().unwrap(),
        vec![api_grant(true, budgets())],
    );
    setup.broker.replace_policy(newer).unwrap();
    assert!(matches!(
        relay(&mut setup, &get("")),
        Err(RelayRefusal::Destination(DestinationRefusal::Stale { .. }))
    ));
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn an_authority_moved_to_another_route_is_refused() {
    let mut setup = setup();
    let mut step = RelayStep::start(&setup.broker, &provider(), limits()).unwrap();
    step.feed(&get("")).unwrap();
    // The new policy keeps `provider-api` for another host and gives api.example.com to
    // a new route.
    let moved = grant(
        "provider-api-2",
        API,
        RouteKind::Operation(operation_route(true)),
        budgets(),
    );
    let kept = grant(
        "provider-api",
        "old.example.com",
        RouteKind::Operation(operation_route(true)),
        budgets(),
    );
    let newer = policy(PolicyEpoch::FIRST.next().unwrap(), vec![moved, kept]);
    setup.broker.replace_policy(newer).unwrap();
    assert_eq!(
        step.finish(&mut setup.broker, &setup.permit, &tls(API), 0),
        Err(RelayRefusal::AuthorizedOnOtherRoute {
            route: provider(),
            authorized: route_id("provider-api-2"),
        })
    );
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn an_incomplete_request_is_not_forwarded() {
    let mut setup = setup();
    let wire = post("Content-Length: 2\r\n", "{");
    assert_eq!(relay(&mut setup, &wire), Err(RelayRefusal::Incomplete));
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn pipelined_requests_are_refused_by_the_step() {
    let mut setup = setup();
    let mut wire = get("");
    wire.extend_from_slice(&get(""));
    assert_eq!(
        relay(&mut setup, &wire),
        Err(RelayRefusal::Read(ReadRefusal::PipelinedBytes))
    );
    assert_nothing_reserved(&setup.broker);
}

#[test]
fn feeding_one_byte_at_a_time_gives_the_same_decision() {
    for wire in [
        get("Accept: */*\r\n"),
        post("Content-Length: 2\r\n", "{}"),
        b"PUT /v1/files/abc HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nhello\r\n0\r\n\r\n"
            .to_vec(),
        get("Upgrade: websocket\r\n"),
        post("Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", "{}"),
    ] {
        let whole = relay(&mut setup(), &wire);
        let bytewise = relay_bytewise(&mut setup(), &wire);
        assert_eq!(whole, bytewise, "{}", String::from_utf8_lossy(&wire));
    }
}

#[test]
fn an_abandoned_decision_returns_its_reservations() {
    let mut setup = setup();
    let decision = relay(&mut setup, &post("Content-Length: 2\r\n", "{}")).unwrap();
    assert_eq!(
        setup
            .broker
            .usage(&provider())
            .reserved(BudgetKind::Effects),
        1
    );
    decision.abandon(&mut setup.broker).unwrap();
    assert_nothing_reserved(&setup.broker);
}

fn relay_allowing(
    setup: &mut Setup,
    wire: &[u8],
    allowance: u64,
) -> Result<ForwardDecision, RelayRefusal> {
    let mut step = RelayStep::start(&setup.broker, &provider(), limits())?;
    step.feed(wire)?;
    step.finish(&mut setup.broker, &setup.permit, &tls(API), allowance)
}

#[test]
fn expect_100_continue_is_reported_to_the_transport_and_never_forwarded() {
    let mut setup = setup();
    let wire = post("Expect: 100-continue\r\nContent-Length: 2\r\n", "{}");
    let head_length = wire.len() - 2;
    let mut step = RelayStep::start(&setup.broker, &provider(), limits()).unwrap();
    assert_eq!(step.feed(&wire[..head_length]), Ok(ReadProgress::NeedMore));
    // The head is complete: the transport may answer the guest `100 Continue` now.
    assert!(step.expects_continue());
    assert_eq!(step.feed(&wire[head_length..]), Ok(ReadProgress::Complete));
    let decision = step
        .finish(&mut setup.broker, &setup.permit, &tls(API), 0)
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(decision.bytes()),
        "POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 2\r\n\r\n{}"
    );
    decision.abandon(&mut setup.broker).unwrap();
    assert_nothing_reserved(&setup.broker);
    // Before the head is complete, or without the header, nothing is reported.
    let mut step = RelayStep::start(&setup.broker, &provider(), limits()).unwrap();
    assert!(!step.expects_continue());
    step.feed(&post("Content-Length: 2\r\n", "")).unwrap();
    assert!(!step.expects_continue());
}

#[test]
fn a_method_that_may_carry_a_body_but_sent_none_gets_content_length_zero() {
    let mut setup = setup();
    let decision = relay(&mut setup, &post("", "")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(decision.bytes()),
        "POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 0\r\n\r\n"
    );
    decision.abandon(&mut setup.broker).unwrap();
    let decision = relay(
        &mut setup,
        b"PUT /v1/files/abc HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    )
    .unwrap();
    assert!(String::from_utf8_lossy(decision.bytes()).ends_with("\r\ncontent-length: 0\r\n\r\n"));
    decision.abandon(&mut setup.broker).unwrap();
    // GET may not carry a body, so nothing frames one.
    let decision = relay(&mut setup, &get("")).unwrap();
    assert!(!String::from_utf8_lossy(decision.bytes()).contains("content-length"));
    decision.abandon(&mut setup.broker).unwrap();
}

#[test]
fn the_credential_allowance_is_reserved_with_the_bytes_and_settles_exactly() {
    let mut setup = setup();
    let decision = relay_allowing(&mut setup, &get(""), 36).unwrap();
    let length = length(decision.bytes());
    assert_eq!(decision.send_reservation().bytes(), length + 36);
    assert_eq!(
        setup
            .broker
            .usage(&provider())
            .reserved(BudgetKind::BytesOut),
        length + 36
    );
    // The executor adds its 36-byte header and settles with what actually left.
    let parts = decision.into_parts();
    setup.broker.complete_send(parts.send, length + 36).unwrap();
    let usage = setup.broker.usage(&provider());
    assert_eq!(usage.reserved(BudgetKind::BytesOut), 0);
    assert_eq!(usage.used(BudgetKind::BytesOut), length + 36);
    assert_eq!(
        setup
            .broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        length + 36
    );
}

#[test]
fn settling_more_than_was_reserved_is_refused_and_still_charged() {
    let mut setup = setup();
    let decision = relay_allowing(&mut setup, &get(""), 10).unwrap();
    let reserved = decision.send_reservation().bytes();
    let parts = decision.into_parts();
    assert!(matches!(
        setup.broker.complete_send(parts.send, reserved + 26),
        Err(DestinationRefusal::Settle(_))
    ));
    let usage = setup.broker.usage(&provider());
    assert_eq!(usage.reserved(BudgetKind::BytesOut), 0);
    assert_eq!(usage.used(BudgetKind::BytesOut), reserved + 26);
}

#[test]
fn a_credential_allowance_needs_a_credentialed_route_and_fits_the_budget() {
    let mut open = setup_with(vec![api_grant(false, budgets())]);
    assert_eq!(
        relay_allowing(&mut open, &get(""), 5),
        Err(RelayRefusal::CredentialAllowanceWithoutCredential {
            route: provider(),
            bytes: 5,
        })
    );
    assert_nothing_reserved(&open.broker);
    let mut setup = setup();
    assert!(matches!(
        relay_allowing(&mut setup, &get(""), 10_000),
        Err(RelayRefusal::Destination(DestinationRefusal::Budget(
            BudgetExhausted {
                kind: Some(BudgetKind::BytesOut),
                ..
            }
        )))
    ));
    assert!(matches!(
        relay_allowing(&mut setup, &get(""), u64::MAX),
        Err(RelayRefusal::Destination(DestinationRefusal::Budget(_)))
    ));
    assert_nothing_reserved(&setup.broker);
}

/// The review's header probe, as assertions.
#[test]
fn reviewed_header_forms_are_refused_or_forwarded_exactly() {
    let forwarded = |field: &str| -> Result<String, RelayRefusal> {
        let mut setup = setup();
        let wire = post(&format!("{field}\r\nContent-Length: 2\r\n"), "{}");
        let decision = relay(&mut setup, &wire)?;
        let bytes = String::from_utf8_lossy(decision.bytes()).into_owned();
        decision.abandon(&mut setup.broker).unwrap();
        Ok(bytes)
    };
    let head = |fields: &str| {
        format!(
            "POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\n{fields}\
             content-length: 2\r\n\r\n{{}}"
        )
    };
    assert_eq!(forwarded("Expect: 100-continue"), Ok(head("")));
    assert_eq!(
        forwarded("Transfer_Encoding: chunked"),
        Err(RelayRefusal::Read(ReadRefusal::UnderscoreTwin {
            name: "Transfer_Encoding".to_owned()
        }))
    );
    assert_eq!(
        forwarded("Content_Length: 0"),
        Err(RelayRefusal::Read(ReadRefusal::UnderscoreTwin {
            name: "Content_Length".to_owned()
        }))
    );
    assert_eq!(
        forwarded("X-Original-URL: /admin"),
        Err(RelayRefusal::Read(ReadRefusal::TargetOverride {
            header: "x-original-url".to_owned()
        }))
    );
    assert_eq!(
        forwarded("X-Name: caf\u{e9}"),
        Ok(head("x-name: caf\u{e9}\r\n"))
    );
    assert_eq!(forwarded("X-Tab: a\tb"), Ok(head("x-tab: a\tb\r\n")));
    assert_eq!(forwarded("X-Empty:"), Ok(head("x-empty:\r\n")));
    assert_eq!(forwarded("Trailer: X-A"), Ok(head("")));
    assert_eq!(
        forwarded("Host: api.example.com"),
        Err(RelayRefusal::Read(ReadRefusal::Inspection(
            RequestRefusal::DuplicateHeader {
                name: "host".to_owned()
            }
        )))
    );
    let host = |value: &str| {
        let mut setup = setup();
        let wire = format!("GET /v1/models HTTP/1.1\r\nHost: {value}\r\n\r\n");
        relay(&mut setup, wire.as_bytes()).map(|decision| {
            let bytes = String::from_utf8_lossy(decision.bytes()).into_owned();
            decision.abandon(&mut setup.broker).unwrap();
            bytes
        })
    };
    let canonical = "GET /v1/models HTTP/1.1\r\nhost: api.example.com\r\n\r\n".to_owned();
    assert_eq!(host("api.example.com:443"), Ok(canonical.clone()));
    assert_eq!(host("API.EXAMPLE.COM"), Ok(canonical));
    assert_eq!(
        host("api.example.com:0443"),
        Err(RelayRefusal::Request(RequestRefusal::InvalidAuthority(
            NameError::InvalidPort {
                text: "0443".to_owned()
            }
        )))
    );
    assert!(matches!(
        host("api.example.com:8443"),
        Err(RelayRefusal::Request(
            RequestRefusal::AuthorityMismatch { .. }
        ))
    ));
    assert_eq!(
        host("api.example.com."),
        Err(RelayRefusal::Request(RequestRefusal::InvalidAuthority(
            NameError::TrailingDot
        )))
    );
}
