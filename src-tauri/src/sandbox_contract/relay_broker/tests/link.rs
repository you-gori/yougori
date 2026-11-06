//! The link loop over in-memory streams with a real relay-side session: a whole exchange
//! from the relay's frame to the guest's bytes, answers in order of completion, the open
//! limit, the broker's close, a vanished relay, and the blocking-link bridge (VM §3.1;
//! VM-W11).

use std::sync::mpsc as std_mpsc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

use super::*;
use crate::foundation::ids::ExecutionId;
use crate::foundation::process::ProcessIdentity;
use crate::sandbox_contract::relay_link::{
    BrokerLink, BrokerMessage, CloseReason, ExchangeRefusal, FrameDecoder, LinkBinding, LinkKey,
    LinkRefusal, LinkSessionId, RelayLink, RelayMessage, MAX_OPEN_EXCHANGES,
};

fn binding() -> LinkBinding {
    LinkBinding {
        sandbox: ExecutionId::new("exe-sandbox-a").unwrap(),
        relay: ProcessIdentity {
            pid: 4242,
            start_time_ticks: 133_000_000_000_000_000,
        },
        session: LinkSessionId::from_digest(test_digest("link-session")),
    }
}

fn key() -> LinkKey {
    LinkKey::new(vec![7; 32]).unwrap()
}

/// The relay's end of the in-memory link: a real relay session over the stream.
struct Relay {
    stream: DuplexStream,
    session: RelayLink,
    decoder: FrameDecoder,
    pending: Vec<u8>,
    /// Every byte the broker sent.
    received: Vec<u8>,
}

impl Relay {
    async fn send(&mut self, message: RelayMessage) {
        let bytes = self.session.seal(message).unwrap();
        self.stream.write_all(&bytes).await.unwrap();
    }

    async fn forward(&mut self, exchange: u64, route: RouteId, request: &[u8]) {
        self.send(RelayMessage::Forward {
            exchange: ExchangeId::new(exchange),
            route,
            request: wire(request),
        })
        .await;
    }

    async fn receive(&mut self) -> BrokerMessage {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            if let Some(frame) = self.decoder.take() {
                return self.session.accept(&frame).unwrap();
            }
            if !self.pending.is_empty() {
                let used = self.decoder.feed(&self.pending).unwrap();
                self.pending.drain(..used);
                continue;
            }
            let count = self.stream.read(&mut buffer).await.unwrap();
            assert!(count > 0, "the broker closed the stream");
            self.received.extend_from_slice(&buffer[..count]);
            self.pending.extend_from_slice(&buffer[..count]);
        }
    }

    async fn close(&mut self) {
        self.send(RelayMessage::Close {
            reason: CloseReason::Finished,
        })
        .await;
    }
}

fn link_pair() -> (StreamLink<DuplexStream>, Relay) {
    let (broker_end, relay_end) = tokio::io::duplex(1024 * 1024);
    (
        StreamLink::new(
            broker_end,
            BrokerLink::open(binding(), key()),
            Duration::from_secs(10),
        ),
        Relay {
            stream: relay_end,
            session: RelayLink::open(binding(), key()),
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
            received: Vec::new(),
        },
    )
}

fn api_relay(
    fixture: &Fixture,
    connector: &ScriptedConnector,
    cert: &Certified,
) -> RelayBroker<ManualClock> {
    fixture.relay(
        UpstreamPolicy::tls_only(),
        connector.shared(),
        trusting(cert),
        patient_deadlines(),
        Some(API),
    )
}

#[tokio::test]
async fn a_whole_exchange_crosses_the_link_with_the_credential_added_upstream_only() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let request = create_job(API, r#"{"model":"a"}"#);
    let script = async {
        relay.forward(0, provider(), &request).await;
        let answer = relay.receive().await;
        relay.close().await;
        answer
    };
    let (report, answer) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    // The guest's bytes out: the response the broker's own step rebuilt.
    assert_eq!(
        answer,
        BrokerMessage::Response {
            exchange: ExchangeId::new(0),
            status: 200,
            response: wire(&ok_response(OK_BODY)),
        }
    );
    // The credential went upstream, added by the broker, and never back over the link.
    assert_eq!(connector.seen().requests, vec![with_credential(&request)]);
    assert!(!String::from_utf8_lossy(&relay.received).contains(SECRET));
    assert!(matches!(
        report.end,
        LinkEnd::ClosedByRelay(CloseReason::Finished)
    ));
    assert_eq!(report.exchanges.len(), 1);
    assert!(report.exchanges[0].delivered);
    assert!(matches!(
        report.exchanges[0].outcome,
        ExchangeOutcome::Answered { status: 200, .. }
    ));
    fixture.assert_settled();
    assert_eq!(fixture.usage(&provider()).used(BudgetKind::Effects), 1);
}

#[tokio::test]
async fn an_echoed_credential_never_crosses_the_link() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let echo = ok_response(&format!(r#"{{"seen":"Bearer {SECRET}"}}"#));
    let connector = ScriptedConnector::tls(&cert, Reply::Send(echo));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let script = async {
        relay.forward(0, provider(), &list_models(API)).await;
        let answer = relay.receive().await;
        relay.close().await;
        answer
    };
    let (report, answer) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    assert_eq!(
        answer,
        BrokerMessage::Refused {
            exchange: ExchangeId::new(0),
            refusal: ExchangeRefusal::UpstreamFailed,
        }
    );
    assert!(!String::from_utf8_lossy(&relay.received).contains(SECRET));
    assert!(matches!(
        &report.exchanges[0].outcome,
        ExchangeOutcome::Refused(BrokerRefusal::Echo(EchoFinding {
            part: ResponsePart::Body,
            ..
        }))
    ));
    fixture.assert_settled();
}

#[tokio::test]
async fn refusals_cross_the_link_as_the_stage_alone() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let script = async {
        let mut answers = Vec::new();
        // Bytes the broker would not have written, a route the destination is not on, and
        // a destination no route grants.
        relay
            .forward(
                0,
                provider(),
                b"GET /v1/models?limit=5 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .await;
        answers.push(relay.receive().await);
        relay.forward(1, open(), &list_models(API)).await;
        answers.push(relay.receive().await);
        relay
            .forward(2, provider(), &list_models("evil.example.net"))
            .await;
        answers.push(relay.receive().await);
        relay.close().await;
        answers
    };
    let (report, answers) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    let expected = [
        ExchangeRefusal::RequestRefused,
        ExchangeRefusal::NotPermitted,
        ExchangeRefusal::NotPermitted,
    ];
    for (n, (answer, refusal)) in answers.into_iter().zip(expected).enumerate() {
        assert_eq!(
            answer,
            BrokerMessage::Refused {
                exchange: ExchangeId::new(u64::try_from(n).unwrap()),
                refusal,
            }
        );
    }
    assert_eq!(report.exchanges.len(), 3);
    assert!(connector.seen().requests.is_empty());
    fixture.assert_settled();
    assert_eq!(fixture.usage(&provider()).used(BudgetKind::BytesOut), 0);
}

#[tokio::test]
async fn answers_go_back_in_order_of_completion() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let gate = Arc::new(Semaphore::new(0));
    let connector = ScriptedConnector::tls(
        &cert,
        Reply::GatedOn("limit=1 ", Arc::clone(&gate), ok_response(OK_BODY)),
    );
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let script = async {
        relay
            .forward(0, provider(), &list_models_limit(API, 1))
            .await;
        relay
            .forward(1, provider(), &list_models_limit(API, 2))
            .await;
        let first = relay.receive().await;
        gate.add_permits(1);
        let second = relay.receive().await;
        relay.close().await;
        (first, second)
    };
    let (report, (first, second)) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    let exchange_of = |message: &BrokerMessage| match message {
        BrokerMessage::Response { exchange, .. } => *exchange,
        other => panic!("expected a response, got {other:?}"),
    };
    assert_eq!(exchange_of(&first), ExchangeId::new(1));
    assert_eq!(exchange_of(&second), ExchangeId::new(0));
    let order: Vec<ExchangeId> = report.exchanges.iter().map(|r| r.exchange).collect();
    assert_eq!(order, vec![ExchangeId::new(1), ExchangeId::new(0)]);
    fixture.assert_settled();
}

/// Waits until the upstream has seen `count` requests.
async fn wait_for_requests(connector: &ScriptedConnector, count: usize) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while connector.seen().requests.len() < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn more_than_the_open_limit_ends_the_link_and_every_open_exchange_still_settles() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let gate = Arc::new(Semaphore::new(0));
    let connector =
        ScriptedConnector::tls(&cert, Reply::After(Arc::clone(&gate), ok_response(OK_BODY)));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let open = u64::try_from(MAX_OPEN_EXCHANGES).unwrap();
    let script = async {
        // The relay's own session refuses a seventeenth while sixteen are open.
        for n in 0..open {
            relay.forward(n, provider(), &list_models(API)).await;
        }
        let refused = relay.session.seal(RelayMessage::Forward {
            exchange: ExchangeId::new(open),
            route: provider(),
            request: wire(&list_models(API)),
        });
        assert_eq!(
            refused,
            Err(LinkRefusal::TooManyOpenExchanges {
                max: MAX_OPEN_EXCHANGES
            })
        );
        // A relay that ignores its own limit: a shadow session that saw an answer the
        // broker never sent seals the seventeenth with the next sequence number.
        let mut shadow = RelayLink::open(binding(), key());
        let mut forged_broker = BrokerLink::open(binding(), key());
        for n in 0..open {
            let bytes = shadow
                .seal(RelayMessage::Forward {
                    exchange: ExchangeId::new(n),
                    route: provider(),
                    request: wire(&list_models(API)),
                })
                .unwrap();
            let mut decoder = FrameDecoder::new();
            decoder.feed(&bytes).unwrap();
            forged_broker.accept(&decoder.take().unwrap()).unwrap();
        }
        let answer = forged_broker
            .seal(BrokerMessage::Refused {
                exchange: ExchangeId::new(0),
                refusal: ExchangeRefusal::Unavailable,
            })
            .unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&answer).unwrap();
        shadow.accept(&decoder.take().unwrap()).unwrap();
        let seventeenth = shadow
            .seal(RelayMessage::Forward {
                exchange: ExchangeId::new(open),
                route: provider(),
                request: wire(&list_models(API)),
            })
            .unwrap();
        relay.stream.write_all(&seventeenth).await.unwrap();
        // All sixteen reach the upstream concurrently before any is answered.
        wait_for_requests(&connector, MAX_OPEN_EXCHANGES).await;
        gate.add_permits(MAX_OPEN_EXCHANGES);
    };
    let (report, ()) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    assert!(
        matches!(
            report.end,
            LinkEnd::Failed(LinkFailure::Link(LinkRefusal::TooManyOpenExchanges { .. }))
        ),
        "{:?}",
        report.end
    );
    assert_eq!(report.exchanges.len(), MAX_OPEN_EXCHANGES);
    for record in &report.exchanges {
        assert!(!record.delivered);
        assert!(
            matches!(record.outcome, ExchangeOutcome::Answered { .. }),
            "{record:?}"
        );
    }
    assert_eq!(connector.seen().requests.len(), MAX_OPEN_EXCHANGES);
    fixture.assert_settled();
    assert_eq!(
        fixture.usage(&provider()).used(BudgetKind::Connections),
        open
    );
}

#[tokio::test]
async fn the_broker_closes_after_answering_what_is_in_flight() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let gate = Arc::new(Semaphore::new(0));
    let connector =
        ScriptedConnector::tls(&cert, Reply::After(Arc::clone(&gate), ok_response(OK_BODY)));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let (stop, stopped) = oneshot::channel::<()>();
    let script = async {
        relay.forward(0, provider(), &list_models(API)).await;
        wait_for_requests(&connector, 1).await;
        stop.send(()).unwrap();
        gate.add_permits(1);
        (relay.receive().await, relay.receive().await)
    };
    let (report, (answer, close)) = tokio::join!(
        relay_broker.serve(&mut link, async {
            stopped.await.unwrap();
            CloseReason::Revoked
        }),
        script
    );
    assert!(matches!(answer, BrokerMessage::Response { .. }));
    assert_eq!(
        close,
        BrokerMessage::Close {
            reason: CloseReason::Revoked
        }
    );
    assert!(matches!(
        report.end,
        LinkEnd::ClosedByBroker(CloseReason::Revoked)
    ));
    assert!(report.exchanges[0].delivered);
    fixture.assert_settled();
}

#[tokio::test]
async fn a_relay_that_vanishes_ends_the_link_and_its_exchange_still_settles() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let gate = Arc::new(Semaphore::new(0));
    let connector =
        ScriptedConnector::tls(&cert, Reply::After(Arc::clone(&gate), ok_response(OK_BODY)));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (mut link, mut relay) = link_pair();
    let script = async move {
        relay.forward(0, provider(), &create_job(API, "{}")).await;
        wait_for_requests(&connector, 1).await;
        drop(relay);
        gate.add_permits(1);
    };
    let (report, ()) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    assert!(matches!(
        report.end,
        LinkEnd::Failed(LinkFailure::Disconnected)
    ));
    assert_eq!(report.exchanges.len(), 1);
    assert!(!report.exchanges[0].delivered);
    fixture.assert_settled();
    assert_eq!(fixture.usage(&provider()).used(BudgetKind::Effects), 1);
}

/// A blocking link end made of channels, standing in for the named pipe.
struct ChannelLink {
    inbound: std_mpsc::Receiver<RelayMessage>,
    outbound: std_mpsc::Sender<BrokerMessage>,
}

impl BlockingLink for ChannelLink {
    fn receive(&mut self, within: Duration) -> Result<Option<RelayMessage>, LinkFailure> {
        match self.inbound.recv_timeout(within) {
            Ok(message) => Ok(Some(message)),
            Err(std_mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => Err(LinkFailure::Disconnected),
        }
    }

    fn send(&mut self, message: BrokerMessage, _within: Duration) -> Result<(), LinkFailure> {
        self.outbound
            .send(message)
            .map_err(|_| LinkFailure::Disconnected)
    }
}

#[tokio::test]
async fn a_blocking_link_is_served_through_the_bridge() {
    let fixture = fixture();
    let cert = certificate(&[API]);
    let connector = ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY)));
    let relay_broker = api_relay(&fixture, &connector, &cert);
    let (to_broker, inbound) = std_mpsc::channel();
    let (outbound, from_broker) = std_mpsc::channel();
    let mut link = BridgedLink::spawn(
        ChannelLink { inbound, outbound },
        BridgeTiming {
            poll: Duration::from_millis(20),
            send_within: Duration::from_secs(5),
        },
    )
    .unwrap();
    to_broker
        .send(RelayMessage::Forward {
            exchange: ExchangeId::new(0),
            route: provider(),
            request: wire(&list_models(API)),
        })
        .unwrap();
    let script = async {
        let answer = tokio::task::spawn_blocking(move || {
            let answer = from_broker.recv_timeout(Duration::from_secs(20)).unwrap();
            to_broker
                .send(RelayMessage::Close {
                    reason: CloseReason::Finished,
                })
                .unwrap();
            answer
        })
        .await
        .unwrap();
        answer
    };
    let (report, answer) = tokio::join!(
        relay_broker.serve(&mut link, std::future::pending()),
        script
    );
    assert_eq!(
        answer,
        BrokerMessage::Response {
            exchange: ExchangeId::new(0),
            status: 200,
            response: wire(&ok_response(OK_BODY)),
        }
    );
    assert!(matches!(
        report.end,
        LinkEnd::ClosedByRelay(CloseReason::Finished)
    ));
    fixture.assert_settled();
}
