//! Tests of the relay host's state machine over a scripted backend and an in-memory link,
//! with the real broker loop of M09D over its fixtures (a real V02 broker, a fake resolver and
//! vault, a scripted TLS upstream). No process, pipe or socket is created here.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::foundation::ids::{ExecutionId, ManualClock};
use crate::foundation::process::{Escalation, ProcessIdentity};
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_broker::tests::{
    certificate, fixture, list_models, ok_response, trusting, Reply, ScriptedConnector, API,
    OK_BODY, SECRET,
};
use crate::sandbox_contract::relay_broker::{
    BlockingLink, ExchangeOutcome, LinkFailure, RelayBroker, UpstreamDeadlines, UpstreamPolicy,
};
use crate::sandbox_contract::relay_link::{
    BrokerMessage, CloseReason, ExchangeId, RelayMessage, WireBytes,
};
use crate::sandbox_contract::relay_process::{GuestEndpoint, RouteEntry, RouteTable};

const PATIENT: Duration = Duration::from_secs(10);

/// The broker's end of an in-memory link.
struct FakeLink {
    inbound: Receiver<RelayMessage>,
    outbound: Sender<BrokerMessage>,
}

impl BlockingLink for FakeLink {
    fn receive(&mut self, within: Duration) -> Result<Option<RelayMessage>, LinkFailure> {
        match self.inbound.recv_timeout(within) {
            Ok(message) => Ok(Some(message)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(LinkFailure::Disconnected),
        }
    }

    fn send(&mut self, message: BrokerMessage, _within: Duration) -> Result<(), LinkFailure> {
        self.outbound
            .send(message)
            .map_err(|_| LinkFailure::Disconnected)
    }
}

/// The relay's end, held by the test.
struct RelaySide {
    to_broker: Sender<RelayMessage>,
    from_broker: Receiver<BrokerMessage>,
}

impl RelaySide {
    fn forward(&self, exchange: u64, route: &str, request: &[u8]) {
        self.to_broker
            .send(RelayMessage::Forward {
                exchange: ExchangeId::new(exchange),
                route: RouteId::new(route).unwrap(),
                request: WireBytes::new(request.to_vec()),
            })
            .unwrap();
    }

    fn next(&self) -> BrokerMessage {
        self.from_broker
            .recv_timeout(PATIENT)
            .expect("a broker message")
    }
}

/// What the scripted relay recorded.
#[derive(Default)]
struct Recorded {
    exited: AtomicBool,
    ended: Mutex<Vec<Escalation>>,
}

struct FakeHandle {
    identity: ProcessIdentity,
    link: Option<FakeLink>,
    accept_fails: bool,
    recorded: Arc<Recorded>,
}

impl RelayHandle for FakeHandle {
    fn identity(&self) -> Option<ProcessIdentity> {
        Some(self.identity)
    }

    fn accept(&mut self, _within: Duration) -> Result<Box<dyn BlockingLink>, StartError> {
        if self.accept_fails {
            return Err(StartError::Accept {
                detail: "scripted: another client came".to_owned(),
            });
        }
        let link = self.link.take().ok_or(StartError::Accept {
            detail: "scripted: accepted twice".to_owned(),
        })?;
        Ok(Box::new(link))
    }

    fn exited(&self) -> bool {
        self.recorded.exited.load(Ordering::Relaxed)
    }

    fn end(self: Box<Self>, escalation: Escalation) -> EndOutcome {
        self.recorded.ended.lock().unwrap().push(escalation);
        EndOutcome {
            proof: Ok(()),
            cleanup: Ok(()),
        }
    }
}

enum Scripted {
    Fails(String),
    Relay(FakeHandle),
}

#[derive(Default)]
struct FakeBackend {
    scripted: Vec<Scripted>,
    launches: usize,
}

impl RelayBackend for FakeBackend {
    fn launch(
        &mut self,
        _sandbox: &ExecutionId,
        _routes: &RouteTable,
        _limits: ReaderLimits,
    ) -> Result<Box<dyn RelayHandle>, StartError> {
        self.launches += 1;
        match self.scripted.pop() {
            Some(Scripted::Relay(handle)) => Ok(Box::new(handle)),
            Some(Scripted::Fails(detail)) => Err(StartError::Launch { detail }),
            None => Err(StartError::Launch {
                detail: "no scripted relay".to_owned(),
            }),
        }
    }
}

/// A scripted relay and its link's relay side.
fn relay(pid: u32, accept_fails: bool) -> (FakeHandle, RelaySide, Arc<Recorded>) {
    let (to_broker, inbound) = mpsc::channel();
    let (outbound, from_broker) = mpsc::channel();
    let recorded = Arc::new(Recorded::default());
    (
        FakeHandle {
            identity: ProcessIdentity {
                pid,
                start_time_ticks: 1,
            },
            link: Some(FakeLink { inbound, outbound }),
            accept_fails,
            recorded: Arc::clone(&recorded),
        },
        RelaySide {
            to_broker,
            from_broker,
        },
        recorded,
    )
}

fn sandbox(name: &str) -> ExecutionId {
    ExecutionId::new(format!("relay-host-{name}")).unwrap()
}

fn routes() -> RouteTable {
    RouteTable::new(vec![RouteEntry {
        endpoint: GuestEndpoint::new("provider").unwrap(),
        route: RouteId::new("provider-api").unwrap(),
    }])
    .unwrap()
}

fn limits() -> ReaderLimits {
    ReaderLimits::new(4_096, 65_536).unwrap()
}

/// The real broker loop over the fixtures: the credentialed `provider-api` route to
/// `api.example.com`, answered by a scripted TLS upstream with an OK body.
fn broker() -> Arc<RelayBroker<ManualClock>> {
    let fixture = fixture();
    let cert = certificate(&[API]);
    Arc::new(fixture.relay(
        UpstreamPolicy::tls_only(),
        ScriptedConnector::tls(&cert, Reply::Send(ok_response(OK_BODY))).shared(),
        trusting(&cert),
        UpstreamDeadlines::default(),
        Some(API),
    ))
}

fn settings() -> RelayHostSettings {
    RelayHostSettings {
        accept_within: Duration::from_secs(1),
        bridge: crate::sandbox_contract::relay_broker::BridgeTiming {
            poll: Duration::from_millis(10),
            send_within: Duration::from_secs(1),
        },
        stop_within: Duration::from_secs(5),
        escalation: Escalation {
            grace: Duration::ZERO,
            kill_wait: Duration::from_secs(1),
        },
    }
}

fn wait_for_life(host: &mut RelayHost) -> RelayLife {
    let deadline = Instant::now() + PATIENT;
    loop {
        if let Some(life) = host.poll() {
            return life.clone();
        }
        assert!(Instant::now() < deadline, "the relay never ended");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_relay_is_launched_admitted_and_served_and_a_stop_is_idempotent() {
    let (handle, relay_side, recorded) = relay(100, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("a"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    assert!(host.is_running());
    assert_eq!(
        host.status(),
        RelayStatus::Running {
            identity: Some(ProcessIdentity {
                pid: 100,
                start_time_ticks: 1
            })
        }
    );
    // One exchange through the real broker loop: the answer comes back on the link.
    relay_side.forward(0, "provider-api", &list_models(API));
    match relay_side.next() {
        BrokerMessage::Response {
            exchange, status, ..
        } => {
            assert_eq!(exchange, ExchangeId::FIRST);
            assert_eq!(status, 200);
        }
        other => panic!("expected a response, got {other:?}"),
    }
    assert!(host.poll().is_none(), "a served relay has no life yet");
    // The stop closes the link with `Stopping`, ends the relay and records the life.
    let life = host.stop(StopReason::Teardown).clone();
    assert_eq!(
        life.end,
        RelayEndReason::Stopped {
            reason: StopReason::Teardown
        }
    );
    assert!(life.admitted);
    assert!(life.serving_joined);
    assert!(life.ended_with_proof);
    assert!(life.cleanup_ok);
    assert_eq!(life.exchanges.len(), 1);
    assert!(matches!(
        life.exchanges[0].outcome,
        ExchangeOutcome::Answered { status: 200, .. }
    ));
    assert!(life.exchanges[0].delivered);
    assert_eq!(
        relay_side.next(),
        BrokerMessage::Close {
            reason: CloseReason::Stopping
        }
    );
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
    // Again: the same life, nothing ended twice.
    let again = host.stop(StopReason::Revoked).clone();
    assert_eq!(again.end, life.end);
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
    assert!(!host.is_running());
    assert!(matches!(host.status(), RelayStatus::Ended(_)));
    let summary = life.summary();
    assert_eq!(summary.exchanges, 1);
    assert_eq!(summary.exchanges_refused, 0);
    assert_eq!(summary.exchanges_undelivered, 0);
}

#[test]
fn a_revocation_closes_the_link_with_revoked_and_ends_the_relay() {
    let (handle, relay_side, recorded) = relay(101, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("b"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    let life = host.stop(StopReason::Revoked).clone();
    assert_eq!(
        life.end,
        RelayEndReason::Stopped {
            reason: StopReason::Revoked
        }
    );
    assert_eq!(
        relay_side.next(),
        BrokerMessage::Close {
            reason: CloseReason::Revoked
        }
    );
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
    assert!(life.exchanges.is_empty());
}

#[test]
fn a_relay_that_exits_on_its_own_is_noticed_and_not_restarted() {
    let (handle, _relay_side, recorded) = relay(102, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("c"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    assert!(host.poll().is_none());
    recorded.exited.store(true, Ordering::Relaxed);
    let life = wait_for_life(&mut host);
    assert_eq!(life.end, RelayEndReason::Exited);
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
    assert_eq!(backend.launches, 1, "no restart was attempted");
    assert!(!host.is_running());
}

#[test]
fn a_relay_that_closes_its_link_ends_the_life_with_its_reason() {
    let (handle, relay_side, recorded) = relay(103, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("d"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    relay_side
        .to_broker
        .send(RelayMessage::Close {
            reason: CloseReason::Finished,
        })
        .unwrap();
    let life = wait_for_life(&mut host);
    assert_eq!(
        life.end,
        RelayEndReason::ClosedByRelay {
            reason: "Finished".to_owned()
        }
    );
    assert!(life.serving_joined);
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
}

#[test]
fn a_link_that_fails_ends_the_life() {
    let (handle, relay_side, recorded) = relay(104, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("e"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    drop(relay_side);
    let life = wait_for_life(&mut host);
    assert!(
        matches!(life.end, RelayEndReason::LinkFailed { .. }),
        "{:?}",
        life.end
    );
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
}

#[test]
fn an_exchange_the_broker_refuses_is_recorded_as_refused_and_the_relay_goes_on() {
    let (handle, relay_side, _recorded) = relay(105, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("f"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    // A route the broker's policy has no grant for.
    relay_side.forward(0, "nowhere", &list_models(API));
    assert!(matches!(
        relay_side.next(),
        BrokerMessage::Refused { exchange, .. } if exchange == ExchangeId::FIRST
    ));
    relay_side.forward(1, "provider-api", &list_models(API));
    assert!(matches!(
        relay_side.next(),
        BrokerMessage::Response { status: 200, .. }
    ));
    let life = host.stop(StopReason::Teardown).clone();
    assert_eq!(life.exchanges.len(), 2);
    assert_eq!(life.summary().exchanges_refused, 1);
}

#[test]
fn a_launch_or_admission_failure_leaves_nothing_running() {
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Fails("scripted: no profile".to_owned())],
        launches: 0,
    };
    let error = RelayHost::start(
        &mut backend,
        sandbox("g"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .err()
    .unwrap();
    assert_eq!(
        error,
        StartError::Launch {
            detail: "scripted: no profile".to_owned()
        }
    );
    // Launched but not admitted: ended and cleaned up before the error returns.
    let (handle, _relay_side, recorded) = relay(106, true);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let error = RelayHost::start(
        &mut backend,
        sandbox("h"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .err()
    .unwrap();
    assert!(matches!(error, StartError::Accept { .. }), "{error}");
    assert_eq!(recorded.ended.lock().unwrap().len(), 1);
}

#[test]
fn the_registry_keeps_one_running_relay_per_sandbox_and_reports_each_end_once() {
    let (first, first_side, first_recorded) = relay(107, false);
    let (second, _second_side, _second_recorded) = relay(108, false);
    let backend = FakeBackend {
        // Popped from the end: the first start gets `first`.
        scripted: vec![Scripted::Relay(second), Scripted::Relay(first)],
        launches: 0,
    };
    let mut hosts = RelayHosts::new(Box::new(backend), settings());
    let broker = broker();
    hosts
        .start(sandbox("i"), &routes(), limits(), Arc::clone(&broker))
        .unwrap();
    assert_eq!(hosts.running(), 1);
    assert_eq!(
        hosts
            .start(sandbox("i"), &routes(), limits(), Arc::clone(&broker))
            .unwrap_err(),
        StartError::AlreadyRunning
    );
    assert!(matches!(
        hosts.status(&sandbox("i")),
        Some(RelayStatus::Running { .. })
    ));
    assert!(hosts.status(&sandbox("nobody")).is_none());
    // The relay ends on its own: reported once by poll, then forgotten.
    first_side
        .to_broker
        .send(RelayMessage::Close {
            reason: CloseReason::Finished,
        })
        .unwrap();
    let deadline = Instant::now() + PATIENT;
    let mut ended = Vec::new();
    while ended.is_empty() {
        ended = hosts.poll();
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].sandbox, sandbox("i"));
    assert!(hosts.poll().is_empty(), "a life is reported once");
    assert_eq!(first_recorded.ended.lock().unwrap().len(), 1);
    assert_eq!(hosts.running(), 0);
    // An ended relay is replaced by a new start.
    hosts
        .start(sandbox("i"), &routes(), limits(), Arc::clone(&broker))
        .unwrap();
    assert_eq!(hosts.running(), 1);
    assert_eq!(hosts.stop_all(StopReason::Teardown).len(), 1);
    assert_eq!(hosts.running(), 0);
    assert!(hosts.stop(&sandbox("i"), StopReason::Teardown).is_some());
    assert!(hosts
        .stop(&sandbox("nobody"), StopReason::Teardown)
        .is_none());
    assert_eq!(hosts.forget_ended(), 1);
    assert!(hosts.status(&sandbox("i")).is_none());
}

#[test]
fn nothing_secret_appears_in_debug_status_or_the_life() {
    let (handle, relay_side, _recorded) = relay(109, false);
    let mut backend = FakeBackend {
        scripted: vec![Scripted::Relay(handle)],
        launches: 0,
    };
    let mut host = RelayHost::start(
        &mut backend,
        sandbox("j"),
        &routes(),
        limits(),
        broker(),
        settings(),
    )
    .unwrap();
    relay_side.forward(0, "provider-api", &list_models(API));
    let _ = relay_side.next();
    let texts = [
        format!("{host:?}"),
        format!("{:?}", host.status()),
        serde_json::to_string(&host.status()).unwrap(),
    ];
    let life = host.stop(StopReason::Teardown).clone();
    let texts = [
        texts.as_slice(),
        &[
            format!("{life:?}"),
            serde_json::to_string(&life.summary()).unwrap(),
            format!("{:?}", backend.launches),
        ],
    ]
    .concat();
    for text in texts {
        assert!(!text.contains(SECRET), "{text}");
        assert!(!text.contains("Bearer"), "{text}");
        assert!(!text.contains(OK_BODY), "{text}");
    }
}

#[cfg(not(windows))]
#[test]
fn every_start_is_refused_without_a_confined_relay() {
    // The production backend does not exist off Windows; a scripted one stands in to show
    // the host itself is platform-neutral.
    let _ = StartError::Unsupported;
}
