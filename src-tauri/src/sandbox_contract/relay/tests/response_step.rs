//! The response step over a real V02 broker: the guest's rebuilt bytes, the inbound
//! budget reserved in the broker's own book before use, settled exactly and on every
//! refusal, redirects reported and never followed, and the path from a forward decision
//! to the guest's bytes (VM §2.5, §4.2 step 7, §4.3; VM-W11; VM-P10, VM-P32). Declared by
//! `response_step.rs`, so the request side's `tests/mod.rs` is unchanged.

use std::collections::BTreeMap;

use crate::foundation::ids::PolicyEpoch;
use crate::sandbox_contract::destinations::{
    Authority, BodyFraming, BoundRequest, BudgetExhausted, BudgetKind, ConnectionPermit,
    DestinationPort, DestinationRefusal, EffectClass, HttpMethod, OperationName, RedirectTarget,
    ReleaseChannel, RequestRefusal, RouteBudgets, RouteId, RouteKind,
};
use crate::sandbox_contract::relay::tests::{
    api_grant, broker, budgets, grant, limits as request_limits, operation_route, permit, policy,
    route_id, tls, transport_grant, Broker,
};
use crate::sandbox_contract::relay::{
    GuestResponse, ReadProgress, ReadRefusal, ReaderLimits, Redirect, RelayStep,
    ResponseReadRefusal, ResponseRefusal, ResponseStep,
};

const API: &str = "api.example.com";

/// What one response may bring under [`limits`]: the head limit plus the body limit.
const MOST: u64 = 512 + 2_048;

fn provider() -> RouteId {
    route_id("provider-api")
}

fn limits() -> ReaderLimits {
    ReaderLimits::new(512, 2_048).unwrap()
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn api_authority() -> Authority {
    Authority::parse(API, DestinationPort::HTTPS).unwrap()
}

/// A request on `provider-api` bound to `method`, as the relay step binds one.
fn bound(method: HttpMethod) -> BoundRequest {
    BoundRequest {
        route: provider(),
        operation: OperationName::new("list-models").unwrap(),
        method,
        authority: api_authority(),
        path: vec!["v1".to_owned(), "models".to_owned()],
        query: BTreeMap::new(),
        body: BodyFraming::None,
        effect: EffectClass::ReadOnly,
    }
}

struct Setup {
    broker: Broker,
    permit: ConnectionPermit,
}

fn setup_with(budgets: RouteBudgets) -> Setup {
    let mut broker = broker(vec![api_grant(true, budgets)]);
    let permit = permit(&mut broker, API);
    Setup { broker, permit }
}

fn setup() -> Setup {
    setup_with(budgets())
}

/// `budgets()` with `bytes_in` inbound bytes.
fn inbound_budget(bytes_in: u64) -> RouteBudgets {
    RouteBudgets {
        bytes_in,
        ..budgets()
    }
}

fn start(setup: &mut Setup, method: HttpMethod) -> Result<ResponseStep, ResponseRefusal> {
    ResponseStep::start(&mut setup.broker, &setup.permit, &bound(method), limits())
}

/// Feeds `parts` in order, ends the input when `close` is set, and finishes.
fn respond_parts(
    setup: &mut Setup,
    method: HttpMethod,
    parts: &[&[u8]],
    close: bool,
) -> Result<GuestResponse, ResponseRefusal> {
    let mut step = start(setup, method)?;
    for part in parts {
        let _ = step.feed(&mut setup.broker, part);
    }
    if close {
        let _ = step.end_of_input(&mut setup.broker);
    }
    step.finish(&mut setup.broker)
}

fn respond(
    setup: &mut Setup,
    method: HttpMethod,
    wire: &[u8],
    close: bool,
) -> Result<GuestResponse, ResponseRefusal> {
    respond_parts(setup, method, &[wire], close)
}

fn respond_bytewise(
    setup: &mut Setup,
    method: HttpMethod,
    wire: &[u8],
    close: bool,
) -> Result<GuestResponse, ResponseRefusal> {
    let parts: Vec<&[u8]> = wire.chunks(1).collect();
    respond_parts(setup, method, &parts, close)
}

/// The route's inbound bytes in the broker: used, then reserved.
fn inbound(broker: &Broker) -> (u64, u64) {
    let usage = broker.usage(&provider());
    (
        usage.used(BudgetKind::BytesIn),
        usage.reserved(BudgetKind::BytesIn),
    )
}

fn read_refusal(refusal: ResponseReadRefusal) -> ResponseRefusal {
    ResponseRefusal::Read(refusal)
}

fn over_budget(reserved: u64) -> ResponseRefusal {
    ResponseRefusal::OverBudget {
        route: provider(),
        reserved,
    }
}

#[test]
fn the_guest_gets_a_response_rebuilt_from_the_parsed_one() {
    let mut setup = setup();
    let wire = b"HTTP/1.1 200  OK \r\nContent-Type: application/json\r\n\
Connection: keep-alive, X-Hop\r\nKeep-Alive: timeout=5\r\nX-Hop: 1\r\n\
Proxy-Authenticate: Basic\r\nProxy-Connection: keep-alive\r\nTE: trailers\r\n\
Trailer: X-Sum\r\nUpgrade: h2c\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Empty:\r\n\
Content-Length: 2\r\n\r\n{}";
    let guest = respond(&mut setup, HttpMethod::Get, wire, false).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nset-cookie: a=1\r\n\
set-cookie: b=2\r\nx-empty:\r\ncontent-length: 2\r\n\r\n{}"
    );
    assert_ne!(guest.bytes(), &wire[..]);
    assert_eq!(guest.status(), 200);
    assert_eq!(guest.redirect(), None);
    assert_eq!(guest.received_bytes(), length(wire));
}

#[test]
fn the_reason_phrase_is_kept_only_when_it_is_visible_ascii_and_spaces() {
    for (status_line, expected) in [
        (
            &b"HTTP/1.1 404 Not Found\r\n"[..],
            "HTTP/1.1 404 Not Found\r\n",
        ),
        (
            b"HTTP/1.1 418 I'm a teapot\r\n",
            "HTTP/1.1 418 I'm a teapot\r\n",
        ),
        (b"HTTP/1.1 200 \tOK\r\n", "HTTP/1.1 200 \r\n"),
        (b"HTTP/1.1 200 caf\xe9\r\n", "HTTP/1.1 200 \r\n"),
        (b"HTTP/1.1 200\r\n", "HTTP/1.1 200 \r\n"),
        (b"HTTP/1.1 200    \r\n", "HTTP/1.1 200 \r\n"),
        (b"HTTP/1.0 200 OK\r\n", "HTTP/1.1 200 OK\r\n"),
    ] {
        let mut setup = setup();
        let mut wire = status_line.to_vec();
        wire.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        let guest = respond(&mut setup, HttpMethod::Get, &wire, false).unwrap();
        assert_eq!(
            text(guest.bytes()),
            format!("{expected}content-length: 0\r\n\r\n")
        );
    }
}

#[test]
fn chunked_and_close_delimited_bodies_reach_the_guest_with_one_content_length() {
    let mut setup = setup();
    let chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n\
5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let guest = respond(&mut setup, HttpMethod::Get, chunked, false).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 11\r\n\r\nhello world"
    );
    let closed = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil close";
    let guest = respond(&mut setup, HttpMethod::Get, closed, true).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 11\r\n\r\nuntil close"
    );
    let repeated = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok";
    let guest = respond(&mut setup, HttpMethod::Get, repeated, false).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
    );
    // Without the end of input, a close-delimited body is never complete.
    assert_eq!(
        respond(&mut setup, HttpMethod::Get, closed, false),
        Err(ResponseRefusal::Incomplete)
    );
    assert_eq!(inbound(&setup.broker).1, 0);
}

#[test]
fn a_head_response_keeps_its_declared_length_and_brings_no_body() {
    let mut setup = setup();
    let wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1234\r\n\r\n";
    let mut step = start(&mut setup, HttpMethod::Head).unwrap();
    assert_eq!(
        step.feed(&mut setup.broker, wire),
        Ok(ReadProgress::Complete)
    );
    let guest = step.finish(&mut setup.broker).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1234\r\n\r\n"
    );
    assert_eq!(inbound(&setup.broker), (length(wire), 0));
    // A chunked HEAD response tells no length; a body after a HEAD response is refused.
    let guest = respond(
        &mut setup,
        HttpMethod::Head,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        false,
    )
    .unwrap();
    assert_eq!(text(guest.bytes()), "HTTP/1.1 200 OK\r\n\r\n");
    assert_eq!(
        respond(
            &mut setup,
            HttpMethod::Head,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
            false
        ),
        Err(read_refusal(ResponseReadRefusal::TrailingBytes))
    );
}

#[test]
fn no_content_gets_no_length_and_not_modified_keeps_its_declared_one() {
    let mut setup = setup();
    let guest = respond(
        &mut setup,
        HttpMethod::Get,
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        false,
    )
    .unwrap();
    assert_eq!(text(guest.bytes()), "HTTP/1.1 204 No Content\r\n\r\n");
    let guest = respond(
        &mut setup,
        HttpMethod::Get,
        b"HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\nContent-Length: 99\r\n\r\n",
        false,
    )
    .unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 304 Not Modified\r\netag: \"x\"\r\ncontent-length: 99\r\n\r\n"
    );
    assert_eq!(guest.redirect(), None);
}

#[test]
fn interim_responses_never_reach_the_guest_but_count_as_received() {
    let mut setup = setup();
    let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n\
HTTP/1.1 201 Created\r\nLocation: /v1/models/abc\r\nContent-Length: 0\r\n\r\n";
    let guest = respond(&mut setup, HttpMethod::Get, wire, false).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 201 Created\r\nlocation: /v1/models/abc\r\ncontent-length: 0\r\n\r\n"
    );
    // A 201's Location is not a redirect.
    assert_eq!(guest.redirect(), None);
    assert_eq!(guest.received_bytes(), length(wire));
    assert_eq!(inbound(&setup.broker), (length(wire), 0));
}

#[test]
fn switching_protocols_is_refused_and_the_reservation_settled() {
    let mut setup = setup();
    let wire =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    assert_eq!(
        respond(&mut setup, HttpMethod::Get, wire, false),
        Err(read_refusal(ResponseReadRefusal::SwitchingProtocols))
    );
    assert_eq!(inbound(&setup.broker), (length(wire), 0));
}

#[test]
fn the_inbound_budget_is_reserved_in_the_broker_before_use_and_settled_exactly() {
    let mut setup = setup();
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let mut step = start(&mut setup, HttpMethod::Get).unwrap();
    // One reservation for the most the response may bring, before any byte is read.
    assert_eq!(inbound(&setup.broker), (0, MOST));
    assert_eq!(
        step.feed(&mut setup.broker, &head[..10]),
        Ok(ReadProgress::NeedMore)
    );
    assert_eq!(
        step.feed(&mut setup.broker, &head[10..]),
        Ok(ReadProgress::NeedMore)
    );
    assert_eq!(
        step.feed(&mut setup.broker, b"hello"),
        Ok(ReadProgress::Complete)
    );
    assert_eq!(inbound(&setup.broker), (0, MOST));
    let guest = step.finish(&mut setup.broker).unwrap();
    // The broker's usage shows exactly the bytes received, and nothing stays reserved.
    assert_eq!(inbound(&setup.broker), (length(head) + 5, 0));
    assert_eq!(guest.received_bytes(), length(head) + 5);
    // Chunk framing was received too, so it is charged.
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let guest = respond(&mut setup, HttpMethod::Get, chunked, false).unwrap();
    assert_eq!(guest.received_bytes(), length(chunked));
    assert_eq!(
        inbound(&setup.broker),
        (length(head) + 5 + length(chunked), 0)
    );
    // Received bytes draw on no release channel.
    assert_eq!(
        setup
            .broker
            .release_account()
            .used_bytes(ReleaseChannel::ProviderRequest),
        0
    );
}

#[test]
fn near_the_end_of_the_budget_a_response_that_fits_is_accepted() {
    let mut setup = setup_with(inbound_budget(600));
    setup.broker.record_received(&setup.permit, 420).unwrap();
    // The reservation is capped by the 180 bytes left, never refused for its size,
    // though a chunked body may bring up to the 2,048-byte body limit.
    let chunked: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let mut step = start(&mut setup, HttpMethod::Get).unwrap();
    assert_eq!(inbound(&setup.broker), (420, 180));
    assert_eq!(
        step.feed(&mut setup.broker, chunked),
        Ok(ReadProgress::Complete)
    );
    let guest = step.finish(&mut setup.broker).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello"
    );
    assert_eq!(inbound(&setup.broker), (420 + length(chunked), 0));
    // A response of exactly what is left fits too: a 39-byte head and 79 body bytes.
    let left = 600 - 420 - length(chunked);
    let mut exact = b"HTTP/1.1 200 OK\r\nContent-Length: 79\r\n\r\n".to_vec();
    assert_eq!(length(&exact) + 79, left);
    exact.resize(usize::try_from(left).unwrap(), b'x');
    assert!(respond(&mut setup, HttpMethod::Get, &exact, false).is_ok());
    assert_eq!(inbound(&setup.broker), (600, 0));
}

#[test]
fn a_response_past_what_the_budget_has_left_is_refused_as_over_budget() {
    let mut setup = setup_with(inbound_budget(600));
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
    let mut step = start(&mut setup, HttpMethod::Get).unwrap();
    assert_eq!(inbound(&setup.broker), (0, 600));
    assert_eq!(
        step.feed(&mut setup.broker, head),
        Ok(ReadProgress::NeedMore)
    );
    assert_eq!(
        step.feed(&mut setup.broker, &[b'x'; 500]),
        Ok(ReadProgress::NeedMore)
    );
    // The next 100 bytes cross the 600 reserved: refused, and what arrived is charged
    // (V02 counts the overrun), with nothing left reserved.
    assert_eq!(
        step.feed(&mut setup.broker, &[b'x'; 100]),
        Err(over_budget(600))
    );
    assert_eq!(inbound(&setup.broker), (length(head) + 600, 0));
    // The refusal is final and charges nothing more.
    assert_eq!(
        step.feed(&mut setup.broker, &[b'x'; 400]),
        Err(over_budget(600))
    );
    assert_eq!(step.finish(&mut setup.broker), Err(over_budget(600)));
    assert_eq!(inbound(&setup.broker), (length(head) + 600, 0));
    // Over its limit, the route reserves nothing more.
    assert!(matches!(
        start(&mut setup, HttpMethod::Get),
        Err(ResponseRefusal::Destination(DestinationRefusal::Budget(
            BudgetExhausted {
                kind: Some(BudgetKind::BytesIn),
                limit: 600,
                ..
            }
        )))
    ));
    // A route with nothing left reserves nothing, and its first byte is over budget.
    let mut spent = setup_with(inbound_budget(600));
    spent.broker.record_received(&spent.permit, 600).unwrap();
    assert_eq!(
        respond(&mut spent, HttpMethod::Get, b"H", false),
        Err(over_budget(0))
    );
    assert_eq!(inbound(&spent.broker), (601, 0));
}

#[test]
fn every_refusal_settles_with_what_arrived() {
    let head_chunked: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let short: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
    let cases: Vec<(Vec<&[u8]>, bool, ResponseRefusal)> = vec![
        (
            vec![&b"HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\n\r\n"[..]],
            false,
            read_refusal(ResponseReadRefusal::Line(ReadRefusal::ObsoleteLineFolding)),
        ),
        (
            vec![
                &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            ],
            false,
            read_refusal(ResponseReadRefusal::Framing(
                RequestRefusal::ConflictingFraming,
            )),
        ),
        (
            vec![
                &b"HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n"
                    [..],
            ],
            false,
            read_refusal(ResponseReadRefusal::DuplicateLocation),
        ),
        (
            vec![head_chunked, b"5;x=1\r\nhello\r\n"],
            false,
            read_refusal(ResponseReadRefusal::Chunk(ReadRefusal::ChunkExtension)),
        ),
        (
            vec![&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"[..]],
            false,
            read_refusal(ResponseReadRefusal::TrailingBytes),
        ),
        (
            vec![short],
            true,
            read_refusal(ResponseReadRefusal::Truncated),
        ),
        (vec![short], false, ResponseRefusal::Incomplete),
        (
            vec![&[b'a'; 600][..]],
            false,
            read_refusal(ResponseReadRefusal::HeadTooLarge { limit: 512 }),
        ),
    ];
    for (parts, close, expected) in cases {
        let mut setup = setup();
        assert_eq!(
            respond_parts(&mut setup, HttpMethod::Get, &parts, close),
            Err(expected.clone()),
            "{expected:?}"
        );
        let arrived: u64 = parts.iter().map(|part| length(part)).sum();
        assert_eq!(inbound(&setup.broker), (arrived, 0), "{expected:?}");
    }
    // An abandoned step settles with what arrived too.
    let mut setup = setup();
    let mut step = start(&mut setup, HttpMethod::Get).unwrap();
    assert_eq!(
        step.feed(&mut setup.broker, b"HTTP/1.1 200 OK\r\n"),
        Ok(ReadProgress::NeedMore)
    );
    step.abandon(&mut setup.broker).unwrap();
    assert_eq!(inbound(&setup.broker), (17, 0));
    let step = start(&mut setup, HttpMethod::Get).unwrap();
    step.abandon(&mut setup.broker).unwrap();
    assert_eq!(inbound(&setup.broker), (17, 0));
}

#[test]
fn a_redirect_is_reported_and_never_followed() {
    let evil = Authority::parse("evil.example.com", DestinationPort::HTTPS).unwrap();
    let cases: Vec<(u16, &str, Result<RedirectTarget, RequestRefusal>)> = vec![
        (
            302,
            "https://api.example.com/v1/models/abc",
            Ok(RedirectTarget {
                authority: api_authority(),
                target: "/v1/models/abc".to_owned(),
            }),
        ),
        (
            301,
            "/v1/models?after=b",
            Ok(RedirectTarget {
                authority: api_authority(),
                target: "/v1/models?after=b".to_owned(),
            }),
        ),
        (
            307,
            "https://evil.example.com/steal",
            Ok(RedirectTarget {
                authority: evil,
                target: "/steal".to_owned(),
            }),
        ),
        (
            308,
            "http://api.example.com/v1/models",
            Err(RequestRefusal::RedirectSchemeNotHttps),
        ),
    ];
    // Everything but the inbound bytes: names resolved, connections, sends and effects.
    let others = |broker: &Broker| -> Vec<u64> {
        [
            BudgetKind::DnsQueries,
            BudgetKind::Connections,
            BudgetKind::BytesOut,
            BudgetKind::Effects,
        ]
        .iter()
        .map(|kind| broker.usage(&provider()).used(*kind))
        .collect()
    };
    for (status, location, target) in cases {
        let mut setup = setup();
        let before = others(&setup.broker);
        let wire =
            format!("HTTP/1.1 {status} Moved\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        let guest = respond(&mut setup, HttpMethod::Get, wire.as_bytes(), false).unwrap();
        assert_eq!(
            guest.redirect(),
            Some(&Redirect {
                status,
                location: location.to_owned(),
                target,
            })
        );
        // The Location is passed on as received.
        assert_eq!(
            text(guest.bytes()),
            format!("HTTP/1.1 {status} Moved\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n")
        );
        // Nothing was followed: the broker resolved, connected and sent nothing more.
        assert_eq!(others(&setup.broker), before);
        assert_eq!(inbound(&setup.broker), (length(wire.as_bytes()), 0));
    }
}

#[test]
fn feeding_one_byte_at_a_time_gives_the_same_result_and_charges() {
    let cases: Vec<(HttpMethod, &[u8], bool, RouteBudgets)> = vec![
        (
            HttpMethod::Get,
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"[..],
            false,
            budgets(),
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nhello\r\n0\r\n\r\n",
            false,
            budgets(),
        ),
        (
            HttpMethod::Head,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n",
            false,
            budgets(),
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 200 OK\r\n\r\nuntil close",
            true,
            budgets(),
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 302 Found\r\nLocation: /v1/models\r\nContent-Length: 0\r\n\r\n",
            false,
            budgets(),
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            false,
            budgets(),
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
            false,
            budgets(),
        ),
        // Under a budget-capped reservation: one that fits, one that runs past.
        (
            HttpMethod::Get,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            false,
            inbound_budget(70),
        ),
        (
            HttpMethod::Get,
            b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n0123456789012345678901234567890123456789",
            false,
            inbound_budget(70),
        ),
    ];
    for (method, wire, close, budgets) in cases {
        let mut whole_setup = setup_with(budgets);
        let whole = respond(&mut whole_setup, method, wire, close);
        let mut bytewise_setup = setup_with(budgets);
        let bytewise = respond_bytewise(&mut bytewise_setup, method, wire, close);
        assert_eq!(bytewise, whole, "{}", text(wire));
        if whole.is_ok() {
            assert_eq!(
                inbound(&bytewise_setup.broker),
                inbound(&whole_setup.broker),
                "{}",
                text(wire)
            );
        }
    }
    assert_eq!(
        respond(
            &mut setup_with(inbound_budget(70)),
            HttpMethod::Get,
            b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n0123456789012345678901234567890123456789",
            false
        ),
        Err(over_budget(70))
    );
}

#[test]
fn the_route_and_the_permit_must_be_the_bound_requests() {
    let uploads = grant(
        "uploads",
        "uploads.example.com",
        RouteKind::Operation(operation_route(false)),
        budgets(),
    );
    let mut broker = broker(vec![api_grant(true, budgets()), transport_grant(), uploads]);
    let api = permit(&mut broker, API);
    let other = permit(&mut broker, "uploads.example.com");
    let mut on = |route: &str, permit: &ConnectionPermit| {
        let bound = BoundRequest {
            route: route_id(route),
            ..bound(HttpMethod::Get)
        };
        ResponseStep::start(&mut broker, permit, &bound, limits())
    };
    assert_eq!(
        on("tls-stream", &api),
        Err(ResponseRefusal::NotAnOperationRoute {
            route: route_id("tls-stream")
        })
    );
    assert_eq!(
        on("no-such-route", &api),
        Err(ResponseRefusal::Destination(
            DestinationRefusal::UnknownRoute {
                route: route_id("no-such-route")
            }
        ))
    );
    assert_eq!(
        on("provider-api", &other),
        Err(ResponseRefusal::PermitForOtherRoute {
            route: provider(),
            permit: route_id("uploads"),
        })
    );
    for route in ["provider-api", "uploads", "tls-stream"] {
        let usage = broker.usage(&route_id(route));
        assert_eq!(usage.reserved(BudgetKind::BytesIn), 0, "{route}");
    }
    // A permit from an older policy reserves nothing.
    let mut setup = setup();
    let newer = policy(
        PolicyEpoch::FIRST.next().unwrap(),
        vec![api_grant(true, budgets())],
    );
    setup.broker.replace_policy(newer).unwrap();
    assert!(matches!(
        start(&mut setup, HttpMethod::Get),
        Err(ResponseRefusal::Destination(
            DestinationRefusal::Stale { .. }
        ))
    ));
    assert_eq!(inbound(&setup.broker), (0, 0));
}

#[test]
fn a_forward_decision_leads_to_the_guests_bytes() {
    let mut broker = broker(vec![api_grant(true, budgets())]);
    let permit = permit(&mut broker, API);
    // The guest's request, read, bound and reserved by the relay step.
    let mut request = RelayStep::start(&broker, &provider(), request_limits()).unwrap();
    request
        .feed(b"GET /v1/models?limit=5 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n")
        .unwrap();
    let parts = request
        .finish(&mut broker, &permit, &tls(API), 0)
        .unwrap()
        .into_parts();
    // The caller sends the bytes upstream and settles the send.
    let sent = length(&parts.bytes);
    broker.complete_send(parts.send, sent).unwrap();
    // The upstream answers; the response step reads it in two feeds.
    let mut response = ResponseStep::start(&mut broker, &permit, &parts.bound, limits()).unwrap();
    let upstream: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\
Date: Thu, 29 Oct 2026 12:00:00 GMT\r\n\r\n7\r\n{\"data\"\r\n4\r\n:[]}\r\n0\r\n\r\n";
    let (first, second) = upstream.split_at(60);
    assert_eq!(
        response.feed(&mut broker, first),
        Ok(ReadProgress::NeedMore)
    );
    assert_eq!(
        response.feed(&mut broker, second),
        Ok(ReadProgress::Complete)
    );
    let guest = response.finish(&mut broker).unwrap();
    assert_eq!(
        text(guest.bytes()),
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
date: Thu, 29 Oct 2026 12:00:00 GMT\r\ncontent-length: 11\r\n\r\n{\"data\":[]}"
    );
    // Both directions are charged to the route in the broker's own book.
    let usage = broker.usage(&provider());
    assert_eq!(usage.used(BudgetKind::BytesOut), sent);
    assert_eq!(usage.used(BudgetKind::BytesIn), length(upstream));
    assert_eq!(usage.reserved(BudgetKind::BytesOut), 0);
    assert_eq!(usage.reserved(BudgetKind::BytesIn), 0);
    assert_eq!(guest.received_bytes(), length(upstream));
}
