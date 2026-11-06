//! Tests of the executor: the broker build from route declarations (no process), and the
//! Windows integration of the whole host side of the egress path over real processes.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use super::broker_build::{build_broker, BuildRefusal};
use super::protocol::*;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, ManualClock, MonotonicTime, TenantId};
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::relay_process::GuestEndpoint;
use crate::sandbox_contract::vault::KeyringStore;

const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);

fn tenant() -> TenantId {
    TenantId::new("local").unwrap()
}

fn operation(name: &str, method: &str, path: &str, effect: EffectDecl) -> OperationDecl {
    OperationDecl {
        name: name.to_owned(),
        method: method.to_owned(),
        path: path.to_owned(),
        query_keys: BTreeSet::new(),
        effect,
    }
}

fn provider_route() -> RouteDeclaration {
    RouteDeclaration {
        name: "provider".to_owned(),
        host: "api.example.com".to_owned(),
        port: 443,
        operations: vec![
            operation("list-models", "GET", "/v1/models", EffectDecl::ReadOnly),
            operation(
                "create-message",
                "POST",
                "/v1/messages",
                EffectDecl::External,
            ),
        ],
        credential: Some(CredentialDecl {
            name: "provider-key".to_owned(),
            header: CredentialHeaderDecl::Authorization,
            provider: "provider".to_owned(),
            contract_version: 1,
        }),
        resolver: Some(ResolverDecl::System),
        budgets: BudgetsDecl::default(),
        plaintext: false,
    }
}

/// A plaintext route with one `GET /` operation, resolved by the host.
fn open_route_to(name: &str, host: &str, port: u16) -> RouteDeclaration {
    RouteDeclaration {
        name: name.to_owned(),
        host: host.to_owned(),
        port,
        operations: vec![operation("get-root", "GET", "/", EffectDecl::ReadOnly)],
        credential: None,
        resolver: Some(ResolverDecl::System),
        budgets: BudgetsDecl::default(),
        plaintext: true,
    }
}

fn open_route() -> RouteDeclaration {
    let mut route = open_route_to("open", "open.example.com", 80);
    route.resolver = None;
    route
}

fn build(
    declarations: &[RouteDeclaration],
) -> Result<super::broker_build::BuiltBroker<Arc<ManualClock>>, BuildRefusal> {
    let clock = Arc::new(ManualClock::new(START));
    let shared: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    build_broker(
        declarations,
        &tenant(),
        KeyringStore::with_service("Yougori.SandboxVault.ExecutorTests"),
        ClockSession::generate(),
        clock,
        shared,
        START,
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        None,
    )
}

/// PROVES the executor reports a refused exchange with its route, number, class and a
/// bounded statement, and nothing for an answered one: an address outside the validated
/// answer is a perimeter violation, a binding the broker's rebuild contradicts is a relay
/// protocol fault, a guest-supplied credential header is an ordinary refusal.
#[test]
fn refused_exchanges_are_reported_classified_and_bounded() {
    use super::process::{bounded_detail, refused_exchange};
    use crate::foundation::ids::ExecutionId;
    use crate::sandbox_contract::destinations::DestinationRefusal;
    use crate::sandbox_contract::relay_broker::{
        BrokerRefusal, CredentialHeader, ExchangeOutcome, ExchangeRecord, InjectionRefusal,
    };
    use crate::sandbox_contract::relay_link::ExchangeId;
    use crate::sandbox_contract::response::{HostObserver, ViolationKind};

    let sandbox = ExecutionId::new("exe-1").unwrap();
    let record = |outcome| ExchangeRecord {
        exchange: ExchangeId::new(7),
        route: RouteId::new("secure").unwrap(),
        outcome,
        delivered: true,
    };
    let answered = record(ExchangeOutcome::Answered {
        status: 200,
        sent_bytes: 1,
        received_bytes: 1,
    });
    assert!(refused_exchange(&sandbox, &answered).is_none());
    let violation = refused_exchange(
        &sandbox,
        &record(ExchangeOutcome::Refused(BrokerRefusal::Destination(
            DestinationRefusal::AddressNotValidated {
                address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            },
        ))),
    )
    .unwrap();
    assert_eq!(
        violation.class,
        RefusalClass::Violation {
            kind: ViolationKind::PerimeterRule,
            observer: HostObserver::Perimeter,
        }
    );
    assert_eq!((violation.route.as_str(), violation.exchange), ("secure", 7));
    let fault = refused_exchange(
        &sandbox,
        &record(ExchangeOutcome::Refused(BrokerRefusal::BindingDiffers)),
    )
    .unwrap();
    assert_eq!(fault.class, RefusalClass::RelayProtocol);
    let ordinary = refused_exchange(
        &sandbox,
        &record(ExchangeOutcome::Refused(BrokerRefusal::Credential(
            InjectionRefusal::GuestCredentialHeader {
                header: CredentialHeader::Authorization,
            },
        ))),
    )
    .unwrap();
    assert_eq!(
        ordinary.class,
        RefusalClass::Ordinary {
            reason: "not_permitted".to_owned()
        }
    );
    assert!(ordinary.detail.contains("already carries"), "{}", ordinary.detail);
    let long = bounded_detail(&"\u{e9}".repeat(400));
    assert!(long.len() <= MAX_REFUSAL_DETAIL_BYTES + "\u{2026}".len());
    assert!(long.ends_with('\u{2026}'));
}

/// PROVES the executor's queue of refusals between two polls is bounded: past its bound an
/// ordinary refusal is dropped and counted, a violation displaces the oldest ordinary one,
/// and one poll carries at most its share, the rest staying for the next.
#[test]
fn the_refusal_queue_keeps_violations_past_its_bound() {
    use super::process::{Refusals, MAX_PENDING_REFUSALS};
    use crate::foundation::ids::ExecutionId;
    use crate::sandbox_contract::response::{HostObserver, ViolationKind};

    let sandbox = ExecutionId::new("exe-1").unwrap();
    let make = |exchange: u64, class: RefusalClass| RefusedExchange {
        sandbox: sandbox.clone(),
        route: "secure".to_owned(),
        exchange,
        class,
        detail: String::new(),
    };
    let ordinary = || RefusalClass::Ordinary {
        reason: "not_permitted".to_owned(),
    };
    let mut queue = Refusals::default();
    for exchange in 0..MAX_PENDING_REFUSALS as u64 {
        queue.push(make(exchange, ordinary()));
    }
    queue.push(make(5000, ordinary()));
    queue.push(make(
        5001,
        RefusalClass::Violation {
            kind: ViolationKind::PerimeterRule,
            observer: HostObserver::Perimeter,
        },
    ));
    let (first, dropped) = queue.take();
    assert_eq!(first.len(), MAX_REFUSALS_PER_POLL);
    assert_eq!(dropped, 2);
    assert_eq!(first[0].exchange, 1, "the oldest ordinary refusal made room");
    let mut rest = Vec::new();
    loop {
        let (taken, dropped) = queue.take();
        assert_eq!(dropped, 0);
        if taken.is_empty() {
            break;
        }
        rest.extend(taken);
    }
    assert_eq!(first.len() + rest.len(), MAX_PENDING_REFUSALS);
    assert_eq!(rest.last().unwrap().exchange, 5001);
}

/// PROVES a credentialed TLS route and an open plaintext route build one route table with
/// both endpoints, the request limits, and the credentialed route recorded as such.
#[test]
fn declarations_build_a_broker_with_the_declared_routes() {
    let built = build(&[provider_route(), open_route()]).unwrap();
    assert_eq!(built.routes.len(), 2);
    assert_eq!(
        built.routes.route(&GuestEndpoint::new("provider").unwrap()),
        Some(&RouteId::new("provider").unwrap())
    );
    assert_eq!(
        built.routes.route(&GuestEndpoint::new("open").unwrap()),
        Some(&RouteId::new("open").unwrap())
    );
    assert_eq!(
        built.credentialed_routes,
        vec![RouteId::new("provider").unwrap()]
    );
    assert_eq!(
        built.limits.max_head_bytes(),
        super::broker_build::REQUEST_HEAD_BYTES
    );
}

/// PROVES the refusals: nothing declared, a credential over plaintext, two resolvers, a
/// method outside the five, and a name that is not an identifier.
#[test]
fn malformed_or_unsafe_declarations_are_refused() {
    assert!(build(&[]).unwrap_err().detail.contains("no route"));
    let mut plaintext_credential = provider_route();
    plaintext_credential.plaintext = true;
    assert!(build(&[plaintext_credential])
        .unwrap_err()
        .detail
        .contains("plaintext"));
    let mut other_resolver = open_route();
    other_resolver.resolver = Some(ResolverDecl::Fixed {
        addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    });
    assert!(build(&[provider_route(), other_resolver])
        .unwrap_err()
        .detail
        .contains("different resolvers"));
    let mut bad_method = open_route();
    bad_method.operations[0].method = "TRACE".to_owned();
    assert!(build(&[bad_method]).unwrap_err().detail.contains("TRACE"));
    let mut bad_name = open_route();
    bad_name.name = "not an identifier".to_owned();
    assert!(build(&[bad_name]).is_err());
}

/// Lines on the engine's end of a control pipe pair in this process.
#[cfg(windows)]
fn ask(
    pipe: &mut crate::sandbox_contract::relay_link::control_pipe::ControlPipe,
    request: &ExecutorRequest,
) -> ExecutorReply {
    use std::time::Duration;
    pipe.send_line(&encode_line(request).unwrap(), Duration::from_secs(10))
        .unwrap();
    let line = pipe
        .read_line(Duration::from_secs(90))
        .unwrap()
        .expect("a reply within the bound");
    decode_line(&line).unwrap()
}

/// The relay helper of this executable: this process, launched confined by the executor
/// under test, runs the production relay mode (the guest pipe named in its handoff) and
/// exits with its code. Unconfined, the test does nothing.
#[cfg(windows)]
#[test]
fn confined_helper_pipe_relay() {
    if crate::sandbox_contract::relay_process::check_confined().is_ok() {
        std::process::exit(super::relay_mode::run_relay());
    }
}

/// PROVES the host side of the egress path end to end with real processes and the real
/// network: the executor (in this process, over the control pipe pair) builds the broker
/// from one plaintext route to example.com and launches this executable confined as the
/// relay; the engine's side serves the relay's guest pipe and attaches it to the real VM
/// service (over the fake VM) as the sandbox's egress port; the fake guest opens an egress
/// stream to the route's endpoint and sends one HTTP request; the relay parses it, the
/// broker authorizes, resolves and connects, and the upstream's status line comes back on
/// the guest's stream. Then the relay is stopped for a teardown with its life recorded
/// (one exchange, admitted, ended with proof, cleaned up) and the executor shuts down.
#[cfg(windows)]
#[test]
#[ignore = "launches this executable confined as a relay (an AppContainer profile and an ACL grant in the user's profile) and reaches example.com over the network; run with --ignored"]
fn a_guest_egress_stream_crosses_a_real_relay_and_the_executors_broker_to_a_public_upstream() {
    use std::ffi::OsString;
    use std::time::{Duration, Instant};

    use super::process::Executor;
    use super::PipeEgressPort;
    use crate::foundation::process::ProcessIdentity;
    use crate::sandbox::vm_service::fakes::{Behaviour, EgressScript, Harness};
    use crate::sandbox_contract::relay_host::{RelayEndReason, RelayStatus, StopReason};
    use crate::sandbox_contract::relay_link::control_pipe::{ControlListener, ControlPipe};
    use crate::sandbox_contract::relay_link::guest_pipe::GuestPipeListener;
    use crate::sandbox_contract::relay_link::RelayPipeName;

    let me = ProcessIdentity::holder_of(std::process::id())
        .unwrap()
        .unwrap();
    let control = RelayPipeName::new(format!(
        r"\\.\pipe\yougori-executor-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ))
    .unwrap();
    let mut listener = ControlListener::create(control.clone()).unwrap();
    let relay_arguments: Vec<OsString> = vec![
        "--exact".into(),
        "sandbox_vm::executor::tests::confined_helper_pipe_relay".into(),
        "--test-threads=1".into(),
        "--quiet".into(),
    ];
    let executor = std::thread::spawn(move || {
        let mut pipe = ControlPipe::connect(&control, &me, Duration::from_secs(10)).unwrap();
        let mut executor = Executor::with_relay(
            me,
            std::env::current_exe().unwrap(),
            relay_arguments,
            KeyringStore::with_service("Yougori.SandboxVault.ExecutorTests"),
        );
        executor.serve(&mut pipe)
    });
    let mut pipe = listener.accept(&me, Duration::from_secs(10)).unwrap();
    eprintln!("[test] executor admitted on the control pipe");
    assert!(matches!(
        ask(
            &mut pipe,
            &ExecutorRequest::Hello {
                version: PROTOCOL_VERSION,
                engine_pid: std::process::id()
            }
        ),
        ExecutorReply::Hello { .. }
    ));
    eprintln!("[test] hello answered");

    // The VM service over the fake VM, its guest opening the route's endpoint after a while.
    let mut harness = Harness::new();
    eprintln!("[test] harness ready");
    harness.guest(
        0,
        Behaviour {
            egress: Some(EgressScript {
                destination: "web",
                // Guest requests use the broker's HTTPS authority parser even when
                // an explicitly declared upstream permits plaintext. Name port 80;
                // omitting it requests 443 and must be refused by this route.
                request: b"GET / HTTP/1.1\r\nhost: example.com:80\r\n\r\n",
                delay: Duration::from_secs(2),
            }),
            ..Behaviour::default()
        },
    );
    let id = harness.service().launch(Harness::spec()).unwrap();
    eprintln!("[test] fake VM launched: {id}");

    // The relay for one plaintext route, started by the executor; the engine's side serves
    // its guest pipe and attaches it.
    let reply = ask(
        &mut pipe,
        &ExecutorRequest::StartRelay {
            sandbox: id.execution().clone(),
            routes: vec![open_route_to("web", "example.com", 80)],
        },
    );
    let ExecutorReply::RelayStarted {
        relay,
        container_sid,
        guest_pipe,
        credentialed_routes,
        ..
    } = reply
    else {
        panic!("the relay did not start: {reply:?}");
    };
    assert!(credentialed_routes.is_empty());
    eprintln!("[test] relay started: {relay} guest pipe {guest_pipe}");
    let mut guest_listener = GuestPipeListener::create(
        RelayPipeName::new(guest_pipe).unwrap(),
        &hex::decode(container_sid).unwrap(),
    )
    .unwrap();
    let server = guest_listener
        .accept(&relay, Duration::from_secs(30))
        .unwrap();
    eprintln!("[test] guest pipe accepted");
    harness
        .service()
        .attach_egress(&id, Box::new(PipeEgressPort::new(server)))
        .unwrap();
    eprintln!("[test] egress port attached");
    assert!(harness.service().status()[0].egress.attached);

    // The answer from the public upstream reaches the guest on its stream.
    let started = Instant::now();
    while !harness.guests[0].state().egress_ended {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "no egress answer within a minute: opened {} refused {:?} received {} bytes",
            harness.guests[0].state().egress_opened,
            harness.guests[0].state().egress_refused,
            harness.guests[0].state().egress_received.len()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    {
        let guest = harness.guests[0].state();
        assert!(guest.egress_opened);
        assert_eq!(guest.egress_refused, None);
        assert!(
            guest.egress_received.starts_with(b"HTTP/1.1 200 "),
            "the guest received {:?}",
            String::from_utf8_lossy(&guest.egress_received[..guest.egress_received.len().min(80)])
        );
    }
    assert!(matches!(
        ask(
            &mut pipe,
            &ExecutorRequest::Status {
                sandbox: id.execution().clone()
            }
        ),
        ExecutorReply::Status {
            relay: Some(RelayStatus::Running { .. }),
            ..
        }
    ));

    // Teardown: the egress port is detached, the relay stopped and its life recorded.
    assert!(harness.service().detach_egress(&id).unwrap());
    let reply = ask(
        &mut pipe,
        &ExecutorRequest::StopRelay {
            sandbox: id.execution().clone(),
            reason: StopReason::Teardown,
        },
    );
    let ExecutorReply::RelayStopped {
        life: Some(life), ..
    } = reply
    else {
        panic!("the relay was not stopped with a life: {reply:?}");
    };
    assert!(life.admitted);
    assert_eq!(
        life.end,
        RelayEndReason::Stopped {
            reason: StopReason::Teardown
        }
    );
    assert_eq!(life.exchanges, 1, "{life:?}");
    assert_eq!(life.exchanges_refused, 0, "{life:?}");
    assert!(life.ended_with_proof, "{life:?}");
    assert!(life.cleanup_ok, "{life:?}");
    assert!(matches!(
        ask(&mut pipe, &ExecutorRequest::Shutdown),
        ExecutorReply::ShuttingDown { stopped: 0 }
    ));
    executor.join().unwrap().unwrap();
    harness.service().stop(&id).unwrap();
}

/// Diagnostic for the handoff: launches this executable confined as the pipe relay directly
/// (no executor), with the guest pipe created either before the relay reads its handoff or
/// two seconds after, and reports whether the relay opened it, with the relay's exit code
/// when it did not (`RelayExit::code`: 13 link, 14 guest port, 11 handoff, 12 not this
/// process).
#[cfg(windows)]
fn relay_opens_guest_pipe(create_before: bool) -> Result<(), String> {
    use std::ffi::OsString;
    use std::time::Duration;

    use crate::foundation::ids::ExecutionId;
    use crate::sandbox_contract::relay::ReaderLimits;
    use crate::sandbox_contract::relay_link::guest_pipe::GuestPipeListener;
    use crate::sandbox_contract::relay_process::{
        launch_relay, RelayLaunch, RouteEntry, RouteTable, END_ESCALATION,
    };

    let arguments: Vec<OsString> = vec![
        "--exact".into(),
        "sandbox_vm::executor::tests::confined_helper_pipe_relay".into(),
        "--test-threads=1".into(),
        "--quiet".into(),
    ];
    let routes = RouteTable::new(vec![RouteEntry {
        endpoint: GuestEndpoint::new("web").unwrap(),
        route: RouteId::new("web").unwrap(),
    }])
    .unwrap();
    let variant = if create_before { "before" } else { "after" };
    let mut launched = launch_relay(RelayLaunch {
        sandbox: ExecutionId::new(format!("exe-diag-{variant}")).unwrap(),
        executable: std::env::current_exe().unwrap(),
        arguments,
        routes,
        limits: ReaderLimits::new(4_096, 65_536).unwrap(),
        guest_engine_pid: Some(std::process::id()),
    })
    .map_err(|error| error.to_string())?;
    let identity = launched.identity();
    let name = launched
        .guest_pipe()
        .cloned()
        .ok_or_else(|| "the launch named no guest pipe".to_owned())?;
    let sid = launched.container_sid().to_vec();
    let mut listener = if create_before {
        Some(GuestPipeListener::create(name.clone(), &sid).map_err(|error| error.to_string())?)
    } else {
        None
    };
    let _link = launched
        .accept(Duration::from_secs(30))
        .map_err(|error| format!("link accept: {error}"))?;
    if listener.is_none() {
        std::thread::sleep(Duration::from_secs(2));
        listener = Some(GuestPipeListener::create(name, &sid).map_err(|error| error.to_string())?);
    }
    let result = listener
        .as_mut()
        .expect("a listener")
        .accept(&identity, Duration::from_secs(20));
    let end = launched.end(END_ESCALATION);
    let exit = end
        .proof
        .as_ref()
        .map(|proof| (proof.exit_code(), proof.ending()))
        .map_err(|error| format!("{error:?}"));
    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(format!(
            "guest pipe ({variant}) not opened: {error}; relay end {exit:?}"
        )),
    }
}

#[cfg(windows)]
#[test]
#[ignore = "launches this executable confined as a relay (an AppContainer profile and an ACL grant in the user's profile); run with --ignored"]
fn diagnostic_a_confined_relay_opens_a_guest_pipe_created_before_its_handoff() {
    relay_opens_guest_pipe(true).unwrap();
}

#[cfg(windows)]
#[test]
#[ignore = "launches this executable confined as a relay (an AppContainer profile and an ACL grant in the user's profile); run with --ignored"]
fn diagnostic_a_confined_relay_opens_a_guest_pipe_created_after_its_handoff() {
    relay_opens_guest_pipe(false).unwrap();
}
