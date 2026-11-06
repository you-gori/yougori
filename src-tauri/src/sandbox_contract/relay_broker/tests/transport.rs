//! The transport over in-memory streams: TLS to a server whose certificate rcgen made in
//! the test, the guest's server name, ALPN, no resumption, plaintext only where allowed,
//! deadlines, and the budget settled on every path (VM §4.3; VM §4.2 step 5; VM-W11).

use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use super::*;
use crate::sandbox_contract::relay::ResponseRefusal;
use crate::sandbox_contract::relay_link::{BrokerMessage, ExchangeRefusal};

const H2: &[u8] = b"h2";

/// Runs `request` on `route` as exchange 1 through `relay`.
async fn exchange(
    relay: &RelayBroker<ManualClock>,
    route: RouteId,
    request: &[u8],
) -> ExchangeAnswer {
    relay.exchange(slot(1), route, wire(request)).await
}

/// An upstream response with fields the guest never gets.
fn upstream_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\
keep-alive: timeout=5\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[tokio::test]
async fn a_tls_exchange_sends_the_exact_bytes_and_returns_the_rebuilt_response() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Send(upstream_response(OK_BODY)));
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(API),
    );
    let request = list_models(API);
    let answer = exchange(&relay, provider(), &request).await;
    assert_eq!(
        answer.message(),
        &BrokerMessage::Response {
            exchange: ExchangeId::new(1),
            status: 200,
            response: wire(&ok_response(OK_BODY)),
        }
    );
    let seen = connector.seen();
    assert_eq!(seen.targets, vec![upstream_target()]);
    assert_eq!(seen.requests, vec![with_credential(&request)]);
    assert_eq!(seen.alpn, vec![Some(HTTP_11_ALPN.to_vec())]);
    drop(seen);
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(
        usage.used(BudgetKind::BytesOut),
        length(&with_credential(&request))
    );
    assert_eq!(
        usage.used(BudgetKind::BytesIn),
        length(&upstream_response(OK_BODY))
    );
}

#[tokio::test]
async fn the_certificate_must_name_the_authorized_destination_and_be_trusted() {
    let presented = certificate(&["wrong.example.net"]);
    let trusted_elsewhere = certificate_from(&[API], "another issuer");
    for (server_cert, client, expected) in [
        (
            &presented,
            trusting(&presented),
            TlsFailure::CertificateNameMismatch,
        ),
        (
            &trusted_elsewhere,
            trusting(&presented),
            TlsFailure::UntrustedCertificate,
        ),
    ] {
        let fixture = fixture();
        let connector = ScriptedConnector::tls(server_cert, Reply::Send(ok_response(OK_BODY)));
        let relay = fixture.relay(
            UpstreamPolicy::tls_only(),
            connector.shared(),
            client,
            patient_deadlines(),
            Some(API),
        );
        let answer = exchange(&relay, provider(), &create_job(API, "{}")).await;
        assert_eq!(
            refusal_of(&answer),
            BrokerRefusal::Upstream(UpstreamFailure::Tls(expected))
        );
        assert_eq!(
            answer.message(),
            &BrokerMessage::Refused {
                exchange: ExchangeId::new(1),
                refusal: ExchangeRefusal::UpstreamFailed,
            }
        );
        // Nothing was sent, so the send returns whole and the effect was not performed.
        assert!(connector.seen().requests.is_empty());
        fixture.assert_settled();
        let usage = fixture.usage(&provider());
        assert_eq!(usage.used(BudgetKind::BytesOut), 0);
        assert_eq!(usage.used(BudgetKind::Effects), 0);
        assert_eq!(fixture.released(), 0);
    }
}

#[tokio::test]
async fn a_guest_server_name_other_than_the_destination_never_reaches_the_upstream() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some("other.example.com"),
    );
    let answer = exchange(&relay, provider(), &list_models(API)).await;
    assert!(matches!(
        refusal_of(&answer),
        BrokerRefusal::SniMismatch { .. }
    ));
    assert!(connector.seen().targets.is_empty());
    fixture.assert_untouched();
}

#[tokio::test]
async fn only_http_11_is_offered_and_http_2_is_never_negotiated() {
    // A server that prefers h2 settles on http/1.1, the only protocol offered.
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::new(Upstream::Tls {
        config: server_config(&cert, &[H2, HTTP_11_ALPN]),
        reply: Reply::Send(ok_response(OK_BODY)),
    });
    let tls = trusting(&cert);
    assert_eq!(
        tls.client_config().alpn_protocols,
        vec![HTTP_11_ALPN.to_vec()]
    );
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        tls,
        patient_deadlines(),
        Some(API),
    );
    let answer = exchange(&relay, provider(), &list_models(API)).await;
    assert!(matches!(answer.outcome(), ExchangeOutcome::Answered { .. }));
    assert_eq!(connector.seen().alpn, vec![Some(HTTP_11_ALPN.to_vec())]);

    // A server that speaks only h2 ends the handshake; nothing is sent.
    let fixture = super::fixture();
    let connector = ScriptedConnector::new(Upstream::Tls {
        config: server_config(&cert, &[H2]),
        reply: Reply::Send(ok_response(OK_BODY)),
    });
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(API),
    );
    let answer = exchange(&relay, provider(), &list_models(API)).await;
    assert_eq!(
        refusal_of(&answer),
        BrokerRefusal::Upstream(UpstreamFailure::Tls(TlsFailure::NoApplicationProtocol))
    );
    assert!(connector.seen().requests.is_empty());
    fixture.assert_settled();
    assert_eq!(fixture.usage(&provider()).used(BudgetKind::BytesOut), 0);
}

/// One request over a client that keeps TLS sessions, as a control.
async fn resuming_request(config: Arc<ClientConfig>, connector: &ScriptedConnector) {
    let stream = connector.connect(upstream_target()).await.unwrap();
    let mut tls = TlsConnector::from(config)
        .connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from(API).unwrap(),
            stream,
        )
        .await
        .unwrap();
    tls.write_all(&list_models(API)).await.unwrap();
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn no_tls_session_is_resumed_between_exchanges() {
    let cert = certificate(&[API]);
    // The control: a client that keeps sessions resumes its second connection.
    let control = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let mut keeping =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots(&cert))
            .with_no_client_auth();
    keeping.alpn_protocols = vec![HTTP_11_ALPN.to_vec()];
    let keeping = Arc::new(keeping);
    resuming_request(Arc::clone(&keeping), &control).await;
    resuming_request(keeping, &control).await;
    assert_eq!(
        control.seen().handshakes,
        vec![Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );

    // The broker's configuration does a full handshake every time.
    let fixture = fixture();
    let connector = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(API),
    );
    for n in 1..=3 {
        let answer = relay
            .exchange(slot(n), provider(), wire(&list_models(API)))
            .await;
        assert!(matches!(answer.outcome(), ExchangeOutcome::Answered { .. }));
    }
    assert_eq!(
        connector.seen().handshakes,
        vec![Some(HandshakeKind::Full); 3]
    );
    fixture.assert_settled();
}

#[tokio::test]
async fn an_upstream_that_never_answers_times_out_with_the_budget_settled() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Never);
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        short_deadlines(),
        Some(API),
    );
    let request = create_job(API, r#"{"model":"a"}"#);
    let answer = exchange(&relay, provider(), &request).await;
    assert_eq!(
        refusal_of(&answer),
        BrokerRefusal::Upstream(UpstreamFailure::TimedOut {
            stage: UpstreamStage::Receive
        })
    );
    assert_eq!(connector.seen().requests, vec![with_credential(&request)]);
    // The request left, so its bytes count and the effect stays spent (uncertain).
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(
        usage.used(BudgetKind::BytesOut),
        length(&with_credential(&request))
    );
    assert_eq!(usage.used(BudgetKind::Effects), 1);
    assert_eq!(usage.used(BudgetKind::BytesIn), 0);
}

/// A connector whose connection never opens.
struct NeverConnects;

impl UpstreamConnector for NeverConnects {
    fn connect(&self, _target: SocketAddr) -> BoxFuture<'_, std::io::Result<Box<dyn UpstreamIo>>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn a_connection_that_never_opens_times_out_with_nothing_sent() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let deadlines = UpstreamDeadlines {
        connect: Duration::from_millis(200),
        ..patient_deadlines()
    };
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        Arc::new(NeverConnects),
        trusting(&cert),
        deadlines,
        Some(API),
    );
    let answer = exchange(&relay, provider(), &create_job(API, "{}")).await;
    assert_eq!(
        refusal_of(&answer),
        BrokerRefusal::Upstream(UpstreamFailure::TimedOut {
            stage: UpstreamStage::Connect
        })
    );
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(usage.used(BudgetKind::BytesOut), 0);
    assert_eq!(usage.used(BudgetKind::Effects), 0);
}

#[tokio::test]
async fn a_dropped_exchange_settles_its_reservations() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Never);
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(API),
    );
    let request = create_job(API, "{}");
    // Drop the exchange once its request has left and while it waits for the response.
    let sent = async {
        while fixture.usage(&provider()).used(BudgetKind::BytesOut) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! {
        answer = exchange(&relay, provider(), &request) => {
            panic!("the exchange ended: {:?}", answer.outcome())
        }
        () = sent => {}
    }
    fixture.assert_settled();
    let usage = fixture.usage(&provider());
    assert_eq!(
        usage.used(BudgetKind::BytesOut),
        length(&with_credential(&request))
    );
    assert_eq!(usage.used(BudgetKind::Effects), 1);
}

#[tokio::test]
async fn plaintext_goes_upstream_only_where_the_policy_allows_it() {
    let plain = ok_response(OK_BODY);
    let cert = certificate(&[OPEN]);
    // Not allowed: the broker starts TLS, and the plaintext server sees a ClientHello and
    // never the request.
    let fixture = fixture();
    let connector = ScriptedConnector::new(Upstream::Plain(plain.clone()));
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(OPEN),
    );
    let request = list_models(OPEN);
    let answer = exchange(&relay, open(), &request).await;
    assert!(matches!(
        refusal_of(&answer),
        BrokerRefusal::Upstream(UpstreamFailure::Tls(_) | UpstreamFailure::ClosedEarly { .. })
    ));
    {
        let seen = connector.seen();
        assert_eq!(seen.first_bytes.len(), 1);
        assert_eq!(seen.first_bytes[0].first(), Some(&0x16));
        assert!(seen.requests.is_empty());
    }
    fixture.assert_settled();
    assert_eq!(fixture.usage(&open()).used(BudgetKind::BytesOut), 0);

    // Allowed for this route: the exact bytes in plaintext.
    let fixture = super::fixture();
    let connector = ScriptedConnector::new(Upstream::Plain(plain.clone()));
    let relay = fixture.relay(
        UpstreamPolicy::tls_only().allow_plaintext(open()),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(OPEN),
    );
    let answer = exchange(&relay, open(), &request).await;
    assert_eq!(
        answer.message(),
        &BrokerMessage::Response {
            exchange: ExchangeId::new(1),
            status: 200,
            response: wire(&plain),
        }
    );
    assert_eq!(connector.seen().requests, vec![request]);
    fixture.assert_settled();
}

#[tokio::test]
async fn a_response_framed_by_the_close_is_read_to_the_upstreams_close_notify() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(
        &cert,
        Reply::Send(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nhello".to_vec()),
    );
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(API),
    );
    let answer = exchange(&relay, provider(), &list_models(API)).await;
    assert_eq!(
        answer.message(),
        &BrokerMessage::Response {
            exchange: ExchangeId::new(1),
            status: 200,
            response: wire(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello"
            ),
        }
    );
    fixture.assert_settled();
}

#[tokio::test]
async fn an_oversize_response_over_tls_is_refused_and_never_returned() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let response = ok_response(&"x".repeat(5_000));
    let connector = ScriptedConnector::tls(&cert, Reply::Send(response));
    let relay = fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(&cert),
        patient_deadlines(),
        Some(API),
    );
    let answer = exchange(&relay, provider(), &list_models(API)).await;
    assert!(matches!(
        refusal_of(&answer),
        BrokerRefusal::Response(ResponseRefusal::Read(_))
    ));
    assert!(matches!(answer.message(), BrokerMessage::Refused { .. }));
    fixture.assert_settled();
    assert!(fixture.usage(&provider()).used(BudgetKind::BytesIn) > 0);
}

#[tokio::test]
async fn an_exchange_without_the_guests_tls_facts_is_refused() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let relay = RelayBroker::new(
        Arc::clone(&fixture.broker),
        fixture.config(UpstreamPolicy::tls_only()),
        UpstreamTransport::new(connector.shared(), trusting(&cert), patient_deadlines()),
        Arc::new(GuestTls(None)),
    );
    let answer = exchange(&relay, provider(), &list_models(API)).await;
    assert_eq!(refusal_of(&answer), BrokerRefusal::GuestTlsUnknown);
    assert_eq!(
        refusal_of(&answer).exchange_refusal(),
        ExchangeRefusal::Unavailable
    );
    assert!(connector.seen().targets.is_empty());
    fixture.assert_untouched();
}

#[test]
fn the_platform_verifier_gets_the_same_policy() {
    let tls = UpstreamTls::platform().unwrap();
    assert_eq!(
        tls.client_config().alpn_protocols,
        vec![HTTP_11_ALPN.to_vec()]
    );
    assert!(!tls.client_config().enable_early_data);
}
