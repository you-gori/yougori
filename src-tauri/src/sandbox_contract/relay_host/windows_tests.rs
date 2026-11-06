//! Windows integration tests of the relay host over a real confined relay: this test
//! executable launched in a per-sandbox AppContainer by M09E's launch, running M09E's own
//! relay helper (`relay_process::launch_tests::confined_helper_relay`, which opens one guest
//! connection to the `provider` endpoint, sends one request and ends), served by the real
//! broker loop over the broker tests' fixtures with a scripted TLS upstream. Each test creates
//! and removes an AppContainer profile and an ACL grant on this executable, so they are
//! `#[ignore]`d by default.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::foundation::ids::{ExecutionId, ManualClock};
use crate::foundation::process::Escalation;
use crate::sandbox_contract::destinations::RouteId;
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_broker::tests::{
    certificate, fixture, trusting, Reply, ScriptedConnector, API,
};
use crate::sandbox_contract::relay_broker::{
    BridgeTiming, ExchangeOutcome, RelayBroker, UpstreamDeadlines, UpstreamPolicy,
};
use crate::sandbox_contract::relay_process::{GuestEndpoint, RouteEntry, RouteTable};

const IGNORE: &str =
    "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored";

/// The helper's exact expected response (`relay_process::launch_tests::RESPONSE`).
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

fn helper_arguments(helper: &str) -> Vec<OsString> {
    vec![
        "--exact".into(),
        format!("sandbox_contract::relay_process::launch_tests::{helper}").into(),
        "--test-threads=1".into(),
        "--quiet".into(),
    ]
}

fn backend(helper: &str) -> WindowsRelayBackend {
    WindowsRelayBackend {
        executable: std::env::current_exe().unwrap(),
        arguments: helper_arguments(helper),
        guest_engine_pid: None,
    }
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

fn broker() -> Arc<RelayBroker<ManualClock>> {
    let fixture = fixture();
    let cert = certificate(&[API]);
    Arc::new(fixture.relay(
        UpstreamPolicy::tls_only(),
        ScriptedConnector::tls(&cert, Reply::Send(RESPONSE.to_vec())).shared(),
        trusting(&cert),
        UpstreamDeadlines::default(),
        Some(API),
    ))
}

fn settings() -> RelayHostSettings {
    RelayHostSettings {
        accept_within: Duration::from_secs(30),
        bridge: BridgeTiming {
            poll: Duration::from_millis(20),
            send_within: Duration::from_secs(5),
        },
        stop_within: Duration::from_secs(10),
        escalation: Escalation {
            grace: Duration::ZERO,
            kill_wait: Duration::from_secs(10),
        },
    }
}

fn sandbox() -> ExecutionId {
    ExecutionId::new(format!("relay-host-test-{}", uuid::Uuid::new_v4().simple())).unwrap()
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn a_real_confined_relay_is_served_end_to_end_and_its_end_is_recorded() {
    let _ = IGNORE;
    let mut hosts = RelayHosts::new(Box::new(backend("confined_helper_relay")), settings());
    let sandbox = sandbox();
    hosts
        .start(sandbox.clone(), &routes(), limits(), broker())
        .unwrap();
    assert_eq!(hosts.running(), 1);
    // The helper forwards its one request, gets the answer and closes the link.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut ended = Vec::new();
    while ended.is_empty() {
        ended = hosts.poll();
        assert!(Instant::now() < deadline, "the relay never ended");
        std::thread::sleep(Duration::from_millis(50));
    }
    let life = &ended[0];
    assert_eq!(life.sandbox, sandbox);
    assert!(life.relay.is_some());
    assert!(life.admitted);
    assert_eq!(
        life.end,
        RelayEndReason::ClosedByRelay {
            reason: "Finished".to_owned()
        },
        "{life:?}"
    );
    assert_eq!(life.exchanges.len(), 1, "{life:?}");
    assert!(matches!(
        life.exchanges[0].outcome,
        ExchangeOutcome::Answered { status: 200, .. }
    ));
    assert!(life.exchanges[0].delivered);
    assert!(life.serving_joined);
    assert!(life.ended_with_proof, "{life:?}");
    assert!(life.cleanup_ok, "{life:?}");
    assert_eq!(hosts.running(), 0);
}

#[test]
#[ignore = "creates and removes an AppContainer profile and an ACL grant in the user's profile; run with --ignored"]
fn a_revocation_ends_a_real_relay_and_cleans_up_after_it() {
    // The late helper connects after three seconds, so the revocation lands while it serves
    // or before it forwarded anything.
    let mut hosts = RelayHosts::new(Box::new(backend("confined_helper_late_relay")), settings());
    let sandbox = sandbox();
    hosts
        .start(sandbox.clone(), &routes(), limits(), broker())
        .unwrap();
    assert!(matches!(
        hosts.status(&sandbox),
        Some(RelayStatus::Running { identity: Some(_) })
    ));
    let life = hosts.stop(&sandbox, StopReason::Revoked).unwrap();
    assert_eq!(
        life.end,
        RelayEndReason::Stopped {
            reason: StopReason::Revoked
        }
    );
    assert!(life.ended_with_proof, "{life:?}");
    assert!(life.cleanup_ok, "{life:?}");
    assert_eq!(hosts.running(), 0);
    // Idempotent: the same life, nothing ended twice.
    let again = hosts.stop(&sandbox, StopReason::Teardown).unwrap();
    assert_eq!(again.end, life.end);
}
