//! The sans-IO core over a real V02 broker: independent authorization, the credential
//! through the injector alone, the echo scan, the exchange bounds and the budget settled
//! on every path (VM §3.1, §4.3, §4.5; VM-W11, VM-W28, VM-W03).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use super::*;
use crate::sandbox_contract::destinations::{
    AuthorizationRefusal, DestinationRefusal, RequestRefusal, RESERVED_CREDENTIAL_HEADERS,
};
use crate::sandbox_contract::provider::LeakSource;
use crate::sandbox_contract::relay::{ReadRefusal, RelayRefusal, ResponseRefusal};
use crate::sandbox_contract::relay_link::{BrokerMessage, ExchangeRefusal, MAX_OPEN_EXCHANGES};

type Admission = Result<(BrokerExchange, UpstreamPlan), Box<ExchangeAnswer>>;

/// Whether a refusal is the one a case expects.
type Expectation = fn(&BrokerRefusal) -> bool;

fn admit_with(
    fixture: &Fixture,
    config: &ExchangeConfig<ManualClock>,
    route: RouteId,
    request: &[u8],
    sni: Option<&str>,
) -> Admission {
    let mut broker = lock_broker(&fixture.broker);
    BrokerExchange::admit(
        config,
        &mut broker,
        slot(7),
        route,
        &wire(request),
        &guest_tls(sni),
    )
}

fn admit(fixture: &Fixture, route: RouteId, request: &[u8], sni: Option<&str>) -> Admission {
    admit_with(
        fixture,
        &fixture.config(UpstreamPolicy::tls_only()),
        route,
        request,
        sni,
    )
}

/// The refusal of an admission, after checking the relay is told only its stage.
fn refused(admission: Admission) -> BrokerRefusal {
    let answer = match admission {
        Err(answer) => *answer,
        Ok((exchange, _)) => panic!("expected a refusal, admitted {exchange:?}"),
    };
    let refusal = refusal_of(&answer);
    assert_eq!(
        answer.message(),
        &BrokerMessage::Refused {
            exchange: ExchangeId::new(7),
            refusal: refusal.exchange_refusal(),
        }
    );
    refusal
}

fn admitted(admission: Admission) -> (BrokerExchange, UpstreamPlan) {
    match admission {
        Ok(admitted) => admitted,
        Err(answer) => panic!("expected admission, got {:?}", answer.outcome()),
    }
}

/// Sends the whole plan, feeds `response` and ends the exchange.
fn run(
    fixture: &Fixture,
    mut exchange: BrokerExchange,
    plan: &UpstreamPlan,
    response: &[u8],
) -> ExchangeAnswer {
    let mut broker = lock_broker(&fixture.broker);
    exchange
        .record_sent(&mut broker, plan.request().len_bytes())
        .unwrap();
    match exchange.feed(&mut broker, response) {
        Ok(_) => exchange.complete(&mut broker),
        Err(refusal) => exchange.fail(&mut broker, refusal),
    }
}

#[test]
fn a_forwarded_request_is_admitted_with_the_credential_added_and_everything_reserved() {
    let fixture = fixture();
    let request = list_models(API);
    let (exchange, plan) = admitted(admit(&fixture, provider(), &request, Some(API)));
    // Connect only to the permit's address and the authorized port, with TLS for the name.
    assert_eq!(plan.target(), upstream_target());
    assert_eq!(
        plan.security(),
        &UpstreamSecurity::Tls(TlsName::Dns(CanonicalName::parse(API).unwrap()))
    );
    assert_eq!(exchange.permit().address(), plan.target().ip());
    // The decision's bytes plus the one credential header, and nothing else.
    let expected = with_credential(&request);
    assert_eq!(
        String::from_utf8_lossy(plan.request().expose_to_transport()),
        String::from_utf8_lossy(&expected)
    );
    assert_eq!(exchange.bound().operation.as_str(), "list-models");
    // Everything is reserved before a byte leaves: the send exactly covers the bytes.
    let usage = fixture.usage(&provider());
    assert_eq!(usage.reserved(BudgetKind::BytesOut), length(&expected));
    assert!(usage.reserved(BudgetKind::BytesIn) > 0);
    assert_eq!(usage.used(BudgetKind::DnsQueries), 1);
    assert_eq!(usage.used(BudgetKind::Connections), 1);
    assert_eq!(lock(&fixture.vault.0).values_given, 1);

    let response = ok_response(OK_BODY);
    let answer = run(&fixture, exchange, &plan, &response);
    assert_eq!(
        answer.message(),
        &BrokerMessage::Response {
            exchange: ExchangeId::new(7),
            status: 200,
            response: wire(&response),
        }
    );
    assert_eq!(
        answer.outcome(),
        &ExchangeOutcome::Answered {
            status: 200,
            sent_bytes: length(&expected),
            received_bytes: length(&response),
        }
    );
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(usage.used(BudgetKind::BytesOut), length(&expected));
    assert_eq!(usage.used(BudgetKind::BytesIn), length(&response));
    assert_eq!(fixture.released(), length(&expected));
}

#[test]
fn the_credential_scope_is_the_routes_audience_under_the_grant() {
    let fixture = fixture();
    let config = fixture.config(UpstreamPolicy::tls_only());
    let (exchange, _plan) = admitted(admit_with(
        &fixture,
        &config,
        provider(),
        &list_models(API),
        Some(API),
    ));
    let operation = operation_route(true);
    let plan = fixture
        .injector
        .plan(&provider(), &operation, exchange.bound())
        .unwrap()
        .unwrap();
    assert_eq!(
        plan.scope(),
        &VaultScope {
            credential: credential(),
            executor: executor(),
            operation: operation_key("list-models"),
            route: DestinationBinding::route_ref_for(
                &Authority::parse(API, DestinationPort::HTTPS).unwrap()
            ),
            account: account(),
        }
    );
    assert_eq!(plan.header(), CredentialHeader::Authorization);
    let line = format!("authorization: Bearer {SECRET}\r\n");
    assert_eq!(plan.allowance(), length(line.as_bytes()));
    // A route without a credential plans none.
    assert_eq!(
        fixture
            .injector
            .plan(&open(), &operation_route(false), exchange.bound())
            .unwrap(),
        None
    );
    let mut broker = lock_broker(&fixture.broker);
    let _ = exchange.fail(&mut broker, BrokerRefusal::Cancelled);
}

#[test]
fn a_route_without_a_credential_sends_the_decisions_bytes_alone() {
    let fixture = fixture();
    let request = create_job(OPEN, r#"{"model":"a"}"#);
    let (exchange, plan) = admitted(admit(&fixture, open(), &request, Some(OPEN)));
    assert_eq!(plan.request().expose_to_transport(), &request[..]);
    assert_eq!(fixture.usage(&open()).reserved(BudgetKind::Effects), 1);
    let answer = run(&fixture, exchange, &plan, &ok_response(OK_BODY));
    assert!(matches!(answer.outcome(), ExchangeOutcome::Answered { .. }));
    fixture.assert_settled();
    assert_eq!(fixture.usage(&open()).used(BudgetKind::Effects), 1);
    assert_eq!(lock(&fixture.vault.0).values_given, 0);
}

#[test]
fn bytes_that_differ_from_the_brokers_rebuild_are_refused_and_nothing_sent() {
    let cases: Vec<(Vec<u8>, Expectation)> =
        vec![
        // A capital `Host`, a percent-encoded path and a chunked body all bind, but the
        // broker's rebuild differs, so nothing the relay wrote is sent.
        (
            b"GET /v1/models?limit=5 HTTP/1.1\r\nHost: api.example.com\r\n\
accept: application/json\r\n\r\n"
                .to_vec(),
            |r| matches!(r, BrokerRefusal::BytesDiffer { .. }),
        ),
        (
            b"GET /v1/%6Dodels?limit=5 HTTP/1.1\r\nhost: api.example.com\r\n\r\n".to_vec(),
            |r| matches!(r, BrokerRefusal::BytesDiffer { .. }),
        ),
        (
            b"POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ntransfer-encoding: chunked\r\n\
\r\n2\r\n{}\r\n0\r\n\r\n"
                .to_vec(),
            |r| matches!(r, BrokerRefusal::BytesDiffer { .. }),
        ),
        // A second request after the first is never kept.
        (
            [list_models(API), list_models(API)].concat(),
            |r| matches!(r, BrokerRefusal::Relay(RelayRefusal::Read(ReadRefusal::PipelinedBytes))),
        ),
        // Half a request.
        (
            b"POST /v1/jobs HTTP/1.1\r\nhost: api.example.com\r\ncontent-length: 10\r\n\r\n{}"
                .to_vec(),
            |r| matches!(r, BrokerRefusal::Relay(RelayRefusal::Incomplete)),
        ),
    ];
    for (request, expected) in cases {
        let fixture = fixture();
        let refusal = refused(admit(&fixture, provider(), &request, Some(API)));
        assert!(expected(&refusal), "{refusal:?}");
        assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::RequestRefused);
        fixture.assert_settled();
        let usage = fixture.usage(&provider());
        assert_eq!(usage.used(BudgetKind::BytesOut), 0);
        assert_eq!(usage.used(BudgetKind::Effects), 0);
        assert_eq!(fixture.released(), 0);
    }
}

#[test]
fn a_route_other_than_the_authorized_one_is_refused_before_anything_is_spent() {
    let fixture = fixture();
    // The relay names the credentialed route for a request to the open API.
    let refusal = refused(admit(&fixture, provider(), &list_models(OPEN), Some(OPEN)));
    assert_eq!(
        refusal,
        BrokerRefusal::RouteMismatch {
            forwarded: provider(),
            authorized: open(),
        }
    );
    assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::NotPermitted);
    // And the open route for a request to the credentialed API.
    let refusal = refused(admit(&fixture, open(), &list_models(API), Some(API)));
    assert!(matches!(refusal, BrokerRefusal::RouteMismatch { .. }));
    // A route the policy does not have.
    let refusal = refused(admit(
        &fixture,
        route_id("made-up"),
        &list_models(API),
        Some(API),
    ));
    assert!(matches!(
        refusal,
        BrokerRefusal::Relay(RelayRefusal::Destination(
            DestinationRefusal::UnknownRoute { .. }
        ))
    ));
    assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::NotPermitted);
    fixture.assert_untouched();
    assert_eq!(lock(&fixture.vault.0).values_given, 0);
}

#[test]
fn an_unauthorized_destination_is_refused_before_anything_is_spent() {
    let fixture = fixture();
    for host in ["evil.example.net", "api.example.com:8443", "93.184.216.34"] {
        let refusal = refused(admit(&fixture, provider(), &list_models(host), Some(host)));
        assert!(
            matches!(
                refusal,
                BrokerRefusal::Destination(DestinationRefusal::Authorization(
                    AuthorizationRefusal::NotGranted { .. }
                        | AuthorizationRefusal::PortNotGranted { .. }
                        | AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
                ))
            ),
            "{host}: {refusal:?}"
        );
        assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::NotPermitted);
    }
    fixture.assert_untouched();
}

#[test]
fn the_guests_server_name_must_be_the_authorized_destination() {
    let fixture = fixture();
    for sni in [Some("other.example.com"), Some("API.EXAMPLE.COM."), None] {
        let refusal = refused(admit(&fixture, provider(), &list_models(API), sni));
        assert_eq!(
            refusal,
            BrokerRefusal::SniMismatch {
                sni: sni.map(str::to_owned),
                server_name: API.to_owned(),
            }
        );
        assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::RequestRefused);
    }
    // Checked before any name is resolved or any connection charged.
    fixture.assert_untouched();
    // Letter case is canonicalized like the authority.
    let (exchange, _) = admitted(admit(
        &fixture,
        provider(),
        &list_models(API),
        Some("API.example.com"),
    ));
    let _ = exchange.fail(&mut lock_broker(&fixture.broker), BrokerRefusal::Cancelled);
    fixture.assert_settled();
}

#[test]
fn the_credential_is_added_only_under_a_current_grant_and_audience() {
    // Revoked.
    let fixture = fixture();
    assert!(fixture.injector.revoke(credential()));
    let refusal = refused(admit(&fixture, provider(), &list_models(API), Some(API)));
    assert_eq!(
        refusal,
        BrokerRefusal::Credential(InjectionRefusal::Grant(VaultRefusal::Revoked))
    );
    assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::NotPermitted);
    fixture.assert_untouched();
    assert_eq!(lock(&fixture.vault.0).values_given, 0);

    // Expired.
    let fixture = super::fixture();
    fixture.clock.advance(Duration::from_secs(7_200));
    let refusal = refused(admit(&fixture, provider(), &list_models(API), Some(API)));
    assert!(matches!(
        refusal,
        BrokerRefusal::Credential(InjectionRefusal::Grant(VaultRefusal::Expired { .. }))
    ));
    fixture.assert_untouched();

    // An operation outside the grant.
    let fixture = super::fixture();
    let mut narrower = vault_grant();
    narrower.operations.remove(&operation_key("create-job"));
    fixture.injector.grant(narrower).unwrap();
    let refusal = refused(admit(
        &fixture,
        provider(),
        &create_job(API, "{}"),
        Some(API),
    ));
    assert_eq!(
        refusal,
        BrokerRefusal::Credential(InjectionRefusal::Grant(VaultRefusal::OperationNotGranted))
    );
    fixture.assert_untouched();

    // No audience for the route.
    let fixture = super::fixture();
    let bare = CredentialInjector::new(
        executor(),
        SESSION,
        Arc::clone(&fixture.clock) as Arc<dyn crate::foundation::ids::Clock>,
        Arc::clone(&fixture.vault) as Arc<dyn HeaderVault>,
    );
    bare.grant(vault_grant()).unwrap();
    let config = ExchangeConfig {
        credentials: Arc::new(bare),
        ..fixture.config(UpstreamPolicy::tls_only())
    };
    let refusal = refused(admit_with(
        &fixture,
        &config,
        provider(),
        &list_models(API),
        Some(API),
    ));
    assert_eq!(
        refusal,
        BrokerRefusal::Credential(InjectionRefusal::NoAudience { route: provider() })
    );
    fixture.assert_untouched();
}

#[test]
fn a_vault_value_that_cannot_be_sent_as_the_header_returns_every_reservation() {
    for (mode, expected) in [
        (VaultMode::LineBreak, InjectionRefusal::InvalidHeaderValue),
        (
            VaultMode::Longer,
            InjectionRefusal::OverAllowance {
                allowance: length(format!("authorization: Bearer {SECRET}\r\n").as_bytes()),
                bytes: length(format!("authorization: Bearer {SECRET}-and-more\r\n").as_bytes()),
            },
        ),
    ] {
        let fixture = fixture();
        lock(&fixture.vault.0).mode = mode;
        let refusal = refused(admit(
            &fixture,
            provider(),
            &create_job(API, "{}"),
            Some(API),
        ));
        assert_eq!(refusal, BrokerRefusal::Credential(expected));
        fixture.assert_settled();
        let usage = fixture.usage(&provider());
        assert_eq!(usage.used(BudgetKind::BytesOut), 0);
        assert_eq!(usage.used(BudgetKind::Effects), 0);
        assert_eq!(fixture.released(), 0);
    }
}

#[test]
fn a_guest_credential_header_is_refused_by_the_brokers_own_binding() {
    let fixture = fixture();
    let request = b"GET /v1/models?limit=5 HTTP/1.1\r\nhost: api.example.com\r\n\
authorization: Bearer guest-token-123\r\n\r\n";
    let refusal = refused(admit(&fixture, provider(), request, Some(API)));
    assert_eq!(
        refusal,
        BrokerRefusal::Request(RequestRefusal::ReservedHeader {
            name: "authorization".to_owned()
        })
    );
    fixture.assert_untouched();
    for header in [
        CredentialHeader::Authorization,
        CredentialHeader::ProxyAuthorization,
        CredentialHeader::Cookie,
    ] {
        assert!(RESERVED_CREDENTIAL_HEADERS.contains(&header.name()));
    }
}

#[test]
fn plaintext_is_used_only_where_explicitly_allowed_and_never_with_a_credential() {
    let fixture = fixture();
    let allowing = fixture.config(UpstreamPolicy::tls_only().allow_plaintext(open()));
    let (exchange, plan) = admitted(admit_with(
        &fixture,
        &allowing,
        open(),
        &list_models(OPEN),
        Some(OPEN),
    ));
    assert_eq!(plan.security(), &UpstreamSecurity::Plaintext);
    let _ = exchange.fail(&mut lock_broker(&fixture.broker), BrokerRefusal::Cancelled);
    // Not allowed: TLS.
    let (exchange, plan) = admitted(admit(&fixture, open(), &list_models(OPEN), Some(OPEN)));
    assert!(matches!(plan.security(), UpstreamSecurity::Tls(_)));
    let _ = exchange.fail(&mut lock_broker(&fixture.broker), BrokerRefusal::Cancelled);
    fixture.assert_settled();
    // Allowed on a credentialed route: refused before anything is spent there.
    let fixture = super::fixture();
    let allowing = fixture.config(UpstreamPolicy::tls_only().allow_plaintext(provider()));
    let refusal = refused(admit_with(
        &fixture,
        &allowing,
        provider(),
        &list_models(API),
        Some(API),
    ));
    assert_eq!(
        refusal,
        BrokerRefusal::PlaintextRefused { route: provider() }
    );
    assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::NotPermitted);
    fixture.assert_untouched();
}

/// The body of `ok_response` with `text` inside a JSON field.
fn echoing_body(text: &str) -> Vec<u8> {
    ok_response(&format!(r#"{{"output":"{text}"}}"#))
}

#[test]
fn an_echoed_credential_or_known_secret_is_refused_naming_where_and_how() {
    let value = format!("Bearer {SECRET}");
    let cases: Vec<(Vec<u8>, ResponsePart, LeakSource, ScanEncoding)> = vec![
        (
            format!("HTTP/1.1 200 OK\r\nx-echo: {value}\r\ncontent-length: 2\r\n\r\n{{}}")
                .into_bytes(),
            ResponsePart::Head,
            LeakSource::VaultCredential,
            ScanEncoding::Verbatim,
        ),
        (
            echoing_body(&STANDARD.encode(value.as_bytes())),
            ResponsePart::Body,
            LeakSource::VaultCredential,
            ScanEncoding::Base64Standard,
        ),
        (
            echoing_body(&hex::encode(SECRET)),
            ResponsePart::Body,
            LeakSource::VaultCredential,
            ScanEncoding::Hexadecimal,
        ),
        (
            echoing_body(&SECRET.to_ascii_uppercase()),
            ResponsePart::Body,
            LeakSource::VaultCredential,
            ScanEncoding::AsciiCaseInsensitive,
        ),
        (
            echoing_body(FIXTURE),
            ResponsePart::Body,
            LeakSource::FixtureSecret,
            ScanEncoding::Verbatim,
        ),
        (
            format!(
                "HTTP/1.1 200 OK\r\nx-trace: {}\r\ncontent-length: 2\r\n\r\n{{}}",
                canary().marker.to_hex()
            )
            .into_bytes(),
            ResponsePart::Head,
            LeakSource::Canary,
            ScanEncoding::Verbatim,
        ),
    ];
    for (response, part, source, encoding) in cases {
        let fixture = fixture();
        let (exchange, plan) = admitted(admit(
            &fixture,
            provider(),
            &create_job(API, "{}"),
            Some(API),
        ));
        let answer = run(&fixture, exchange, &plan, &response);
        assert_eq!(
            answer.outcome(),
            &ExchangeOutcome::Refused(BrokerRefusal::Echo(EchoFinding {
                part,
                source,
                encoding
            })),
            "{}",
            String::from_utf8_lossy(&response)
        );
        // The response is never sent to the relay: only the stage.
        assert_eq!(
            answer.message(),
            &BrokerMessage::Refused {
                exchange: ExchangeId::new(7),
                refusal: ExchangeRefusal::UpstreamFailed,
            }
        );
        // The upstream answered, so the effect is spent and every byte counted.
        fixture.assert_settled();
        let usage = fixture.usage(&provider());
        assert_eq!(usage.used(BudgetKind::Effects), 1);
        assert_eq!(usage.used(BudgetKind::BytesIn), length(&response));
    }
}

#[test]
fn a_route_without_a_credential_is_still_scanned_for_known_secrets() {
    let fixture = fixture();
    let (exchange, plan) = admitted(admit(&fixture, open(), &list_models(OPEN), Some(OPEN)));
    let answer = run(
        &fixture,
        exchange,
        &plan,
        &echoing_body(&hex::encode(FIXTURE)),
    );
    assert_eq!(
        refusal_of(&answer),
        BrokerRefusal::Echo(EchoFinding {
            part: ResponsePart::Body,
            source: LeakSource::FixtureSecret,
            encoding: ScanEncoding::Hexadecimal,
        })
    );
    fixture.assert_settled();
}

#[test]
fn the_credential_never_appears_in_a_message_a_debug_or_display_output_or_an_error() {
    let fixture = fixture();
    let config = fixture.config(UpstreamPolicy::tls_only());
    let (exchange, plan) = admitted(admit_with(
        &fixture,
        &config,
        provider(),
        &create_job(API, "{}"),
        Some(API),
    ));
    assert!(String::from_utf8_lossy(plan.request().expose_to_transport()).contains(SECRET));
    let mut shown = vec![
        format!("{exchange:?}"),
        format!("{plan:?}"),
        format!("{config:?}"),
        format!("{:?}", fixture.injector),
    ];
    let response =
        format!("HTTP/1.1 200 OK\r\nx-echo: Bearer {SECRET}\r\ncontent-length: 2\r\n\r\n{{}}");
    let answer = run(&fixture, exchange, &plan, response.as_bytes());
    let refusal = refusal_of(&answer);
    shown.push(format!("{refusal}"));
    shown.push(format!("{refusal:?}"));
    shown.push(format!("{answer:?}"));
    shown.push(serde_json::to_string(answer.message()).unwrap());
    for mode in [VaultMode::LineBreak, VaultMode::Longer] {
        lock(&fixture.vault.0).mode = mode;
        let refusal = refused(admit(&fixture, provider(), &list_models(API), Some(API)));
        shown.push(format!("{refusal}"));
        shown.push(format!("{refusal:?}"));
    }
    for text in shown {
        assert!(!text.contains(SECRET), "{text}");
        assert!(!text.contains(&hex::encode(SECRET)), "{text}");
    }
    fixture.assert_settled();
}

#[test]
fn an_oversize_response_is_refused_with_its_bytes_charged() {
    let fixture = fixture();
    let (exchange, plan) = admitted(admit(&fixture, provider(), &list_models(API), Some(API)));
    let body = "x".repeat(5_000);
    let response = ok_response(&body);
    let answer = run(&fixture, exchange, &plan, &response);
    let refusal = refusal_of(&answer);
    assert!(
        matches!(refusal, BrokerRefusal::Response(ResponseRefusal::Read(_))),
        "{refusal:?}"
    );
    assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::UpstreamFailed);
    fixture.assert_settled();
    assert_eq!(
        fixture.usage(&provider()).used(BudgetKind::BytesIn),
        length(&response)
    );
}

#[test]
fn every_failure_after_admission_settles_the_budget() {
    // Nothing left: the send returns whole and the effect was not performed.
    let fixture = fixture();
    let (exchange, _plan) = admitted(admit(
        &fixture,
        provider(),
        &create_job(API, "{}"),
        Some(API),
    ));
    let failure = BrokerRefusal::Upstream(UpstreamFailure::TimedOut {
        stage: UpstreamStage::Connect,
    });
    let answer = exchange.fail(&mut lock_broker(&fixture.broker), failure.clone());
    assert_eq!(refusal_of(&answer), failure);
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(usage.used(BudgetKind::BytesOut), 0);
    assert_eq!(usage.used(BudgetKind::BytesIn), 0);
    assert_eq!(usage.used(BudgetKind::Effects), 0);

    // Part of the request left and part of a response came: both are charged, and the
    // effect is uncertain, so it stays spent.
    let fixture = super::fixture();
    let (mut exchange, _plan) = admitted(admit(
        &fixture,
        provider(),
        &create_job(API, "{}"),
        Some(API),
    ));
    let mut broker = lock_broker(&fixture.broker);
    exchange.record_sent(&mut broker, 40).unwrap();
    assert_eq!(
        exchange.feed(&mut broker, b"HTTP/1.1 200 OK\r\n").unwrap(),
        crate::sandbox_contract::relay::ReadProgress::NeedMore
    );
    let answer = exchange.fail(
        &mut broker,
        BrokerRefusal::Upstream(UpstreamFailure::TimedOut {
            stage: UpstreamStage::Receive,
        }),
    );
    drop(broker);
    assert_eq!(
        refusal_of(&answer).exchange_refusal(),
        ExchangeRefusal::UpstreamFailed
    );
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(usage.used(BudgetKind::BytesOut), 40);
    assert_eq!(usage.used(BudgetKind::BytesIn), 17);
    assert_eq!(usage.used(BudgetKind::Effects), 1);
    assert_eq!(fixture.released(), 40);

    // A response that ends early completes as a refusal and still settles.
    let fixture = super::fixture();
    let (exchange, plan) = admitted(admit(&fixture, provider(), &list_models(API), Some(API)));
    let answer = run(
        &fixture,
        exchange,
        &plan,
        b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\n{}",
    );
    assert_eq!(
        refusal_of(&answer),
        BrokerRefusal::Response(ResponseRefusal::Incomplete)
    );
    fixture.assert_settled();
}

#[test]
fn the_book_holds_at_most_the_open_limit_and_answers_each_exchange_once() {
    let mut book = ExchangeBook::new();
    let mut slots: Vec<ExchangeSlot> = (0..MAX_OPEN_EXCHANGES)
        .map(|n| {
            book.open(ExchangeId::new(u64::try_from(n).unwrap()))
                .unwrap()
        })
        .collect();
    assert_eq!(book.open_exchanges(), MAX_OPEN_EXCHANGES);
    let over = ExchangeId::new(100);
    let refusal = book.open(over).unwrap_err();
    assert_eq!(
        refusal,
        BrokerRefusal::TooManyOpenExchanges {
            max: MAX_OPEN_EXCHANGES
        }
    );
    assert_eq!(refusal.exchange_refusal(), ExchangeRefusal::Unavailable);
    // Answering one makes room; the slot is consumed, so it cannot be answered again.
    let first = slots.remove(0);
    assert_eq!(book.answer(first), ExchangeId::new(0));
    assert_eq!(book.open_exchanges(), MAX_OPEN_EXCHANGES - 1);
    let next = book.open(ExchangeId::new(101)).unwrap();
    // An exchange not above the last is refused, open or not.
    for stale in [ExchangeId::new(101), ExchangeId::new(3), ExchangeId::new(0)] {
        assert_eq!(
            book.open(stale).unwrap_err(),
            BrokerRefusal::ExchangeNotIncreasing {
                exchange: stale,
                last: ExchangeId::new(101)
            }
        );
    }
    for slot in slots {
        let _ = book.answer(slot);
    }
    let _ = book.answer(next);
    assert_eq!(book.open_exchanges(), 0);
}

#[test]
fn audiences_and_findings_read_back_strictly() {
    let json = serde_json::to_value(audience()).unwrap();
    assert_eq!(
        serde_json::from_value::<CredentialAudience>(json.clone()).unwrap(),
        audience()
    );
    let mut extra = json;
    extra["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<CredentialAudience>(extra).is_err());
    let finding = EchoFinding {
        part: ResponsePart::Body,
        source: LeakSource::VaultCredential,
        encoding: ScanEncoding::Base64UrlSafe,
    };
    let json = serde_json::to_string(&finding).unwrap();
    assert_eq!(serde_json::from_str::<EchoFinding>(&json).unwrap(), finding);
    assert!(serde_json::from_str::<EchoFinding>(
        r#"{"part":"body","source":"canary","encoding":"verbatim","x":1}"#
    )
    .is_err());
    assert!(serde_json::from_str::<CredentialHeader>(r#""x-api-key""#).is_err());
}
