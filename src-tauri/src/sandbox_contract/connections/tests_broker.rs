//! VM §4.7 and VM-W13: the connection broker. A connection needs a grant at both ends for
//! exactly the attached endpoints, nothing is inferred transitively, and each connection
//! is budgeted both ways.

use super::fakes::*;
use super::*;
use crate::sandbox_contract::destinations::{ConnectionRefusal, MissingSide};

const CLIENT: &str = "exe-client";
const MODEL: &str = "exe-model";
const PROXY: &str = "exe-proxy";

fn budget(up: u64, down: u64) -> ConnectionBudget {
    ConnectionBudget {
        caller_to_callee_bytes: up,
        callee_to_caller_bytes: down,
    }
}

fn request(caller: &str, callee: &str, up: u64, down: u64) -> ConnectionRequest {
    ConnectionRequest {
        caller: execution(caller),
        callee: execution(callee),
        service: service("model-api"),
        port: port(8000),
        budget: budget(up, down),
    }
}

/// Grants `caller` to `callee` for the model API at both ends, expiring in `seconds`.
fn grant_both(gate: &mut ConnectionGate, world: &World, caller: &str, callee: &str, seconds: u64) {
    let grant = connection_grant(
        &endpoint(caller, "team-a"),
        &endpoint(callee, "team-a"),
        "model-api",
        8000,
        world.in_seconds(seconds),
    );
    gate.grant_outbound(&world.coordinator, grant.clone())
        .unwrap();
    gate.grant_inbound(&world.coordinator, grant).unwrap();
}

fn missing(side: MissingSide) -> GateRefusal {
    GateRefusal::Connection(ConnectionRefusal::MissingGrant { side })
}

#[test]
fn a_connection_needs_grants_at_both_ends() {
    let (world, mut gate) = attached(&[CLIENT, MODEL], &["model-api"]);
    let grant = connection_grant(
        &endpoint(CLIENT, "team-a"),
        &endpoint(MODEL, "team-a"),
        "model-api",
        8000,
        world.in_seconds(600),
    );
    let try_connect = |gate: &mut ConnectionGate| {
        let (ends, caller, callee) = channel();
        let result = gate.connect(
            &world.coordinator,
            request(CLIENT, MODEL, 100, 100),
            caller,
            callee,
        );
        if result.is_err() {
            assert!(ends.caller.peer_closed() && ends.guest.peer_closed());
        }
        result
    };
    assert_eq!(try_connect(&mut gate), Err(missing(MissingSide::Both)));
    gate.grant_outbound(&world.coordinator, grant.clone())
        .unwrap();
    assert_eq!(try_connect(&mut gate), Err(missing(MissingSide::Callee)));

    // A grant naming another trust scope than the attached one is refused at the gate.
    let mut foreign = grant.clone();
    foreign.callee = endpoint(MODEL, "team-b");
    assert_eq!(
        gate.grant_inbound(&world.coordinator, foreign.clone()),
        Err(GateRefusal::EndpointMismatch {
            sandbox: execution(MODEL),
            attached: scope("team-a"),
            named: scope("team-b"),
        })
    );
    gate.grant_inbound(&world.coordinator, grant).unwrap();
    let handle = try_connect(&mut gate).unwrap();
    assert_eq!(handle.authorization().caller, endpoint(CLIENT, "team-a"));
    assert_eq!(handle.authorization().callee, endpoint(MODEL, "team-a"));
    assert_eq!(gate.open_connections(), 1);

    // Revoking the grants closes the open connection and refuses new ones.
    assert_eq!(
        gate.revoke_connection_grants(&endpoint(CLIENT, "team-a"), &endpoint(MODEL, "team-a")),
        vec![handle.id()]
    );
    assert_eq!(gate.open_connections(), 0);
    assert_eq!(try_connect(&mut gate), Err(missing(MissingSide::Both)));
}

#[test]
fn transitive_access_is_never_inferred() {
    let (world, mut gate) = attached(&[CLIENT, MODEL, PROXY], &["model-api"]);
    grant_both(&mut gate, &world, CLIENT, MODEL, 600);
    grant_both(&mut gate, &world, MODEL, PROXY, 600);
    for (caller, callee, expected) in [
        (CLIENT, MODEL, None),
        (MODEL, PROXY, None),
        (CLIENT, PROXY, Some(missing(MissingSide::Both))),
        (MODEL, CLIENT, Some(missing(MissingSide::Both))),
        (PROXY, CLIENT, Some(missing(MissingSide::Both))),
    ] {
        let (_ends, caller_end, callee_end) = channel();
        let result = gate.connect(
            &world.coordinator,
            request(caller, callee, 100, 100),
            caller_end,
            callee_end,
        );
        assert_eq!(result.err(), expected, "{caller} to {callee}");
    }
    assert_eq!(gate.open_connections(), 2);
}

#[test]
fn each_connection_is_budgeted_both_ways() {
    let (world, mut gate) = attached(&[CLIENT, MODEL], &["model-api"]);
    grant_both(&mut gate, &world, CLIENT, MODEL, 600);
    let mut releases = releases(&[(CLIENT, 1_000), (MODEL, 1_000)]);

    // Six bytes back at most: the callee's last write is cut and the connection closes.
    let (mut ends, caller, callee) = channel();
    let handle = gate
        .connect(
            &world.coordinator,
            request(CLIENT, MODEL, 8, 6),
            caller,
            callee,
        )
        .unwrap();
    ends.caller.write(b"ask?!").unwrap();
    ends.guest.write(b"four").unwrap();
    let pumped = gate
        .pump_connection(&world.coordinator, &mut releases, handle.id())
        .unwrap();
    assert_eq!(
        pumped,
        Pumped {
            request_bytes: 5,
            response_bytes: 4,
            state: ChannelState::Open
        }
    );
    assert_eq!(ends.guest.drain(), (b"ask?!".to_vec(), false));
    let status = &gate.connection_status()[0];
    assert_eq!(
        (
            status.caller_to_callee.used_bytes,
            status.caller_to_callee.remaining_bytes,
            status.callee_to_caller.used_bytes,
            status.callee_to_caller.remaining_bytes
        ),
        (5, 3, 4, 2)
    );
    ends.guest.write(b"more!").unwrap();
    let pumped = gate
        .pump_connection(&world.coordinator, &mut releases, handle.id())
        .unwrap();
    assert_eq!(pumped.response_bytes, 2);
    assert_eq!(
        pumped.state,
        closed(CloseReason::ConnectionBudgetSpent {
            direction: Direction::CalleeToCaller
        })
    );
    assert_eq!(ends.caller.drain(), (b"fourmo".to_vec(), true));
    assert_eq!(ends.guest.unread_by_peer(), 3);
    // The callee's responses are its outbound data; the caller released nothing.
    assert_eq!(released(&releases, MODEL), 6);
    assert_eq!(released(&releases, CLIENT), 0);

    // Eight bytes out at most: the caller's long write is cut and the connection closes.
    let (mut ends, caller, callee) = channel();
    let handle = gate
        .connect(
            &world.coordinator,
            request(CLIENT, MODEL, 8, 6),
            caller,
            callee,
        )
        .unwrap();
    ends.caller.write(b"0123456789").unwrap();
    let pumped = gate
        .pump_connection(&world.coordinator, &mut releases, handle.id())
        .unwrap();
    assert_eq!(pumped.request_bytes, 8);
    assert_eq!(
        pumped.state,
        closed(CloseReason::ConnectionBudgetSpent {
            direction: Direction::CallerToCallee
        })
    );
    assert_eq!(ends.guest.drain(), (b"01234567".to_vec(), true));
    assert_eq!(gate.open_connections(), 0);

    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            request(CLIENT, MODEL, 8, 0),
            caller,
            callee
        ),
        Err(GateRefusal::ZeroBudget)
    );
}

#[test]
fn an_expired_connection_grant_closes_the_connection() {
    let (world, mut gate) = attached(&[CLIENT, MODEL], &["model-api"]);
    grant_both(&mut gate, &world, CLIENT, MODEL, 60);
    let mut releases = releases(&[(MODEL, 1_000)]);
    let (mut ends, caller, callee) = channel();
    let handle = gate
        .connect(
            &world.coordinator,
            request(CLIENT, MODEL, 100, 100),
            caller,
            callee,
        )
        .unwrap();
    world.advance(60);
    ends.caller.write(b"late").unwrap();
    assert_eq!(
        gate.pump_connection(&world.coordinator, &mut releases, handle.id())
            .unwrap(),
        Pumped::closed(CloseReason::ConnectionGrantEnded)
    );
    assert_eq!(ends.guest.drain(), (Vec::new(), true));
    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            request(CLIENT, MODEL, 100, 100),
            caller,
            callee
        ),
        Err(missing(MissingSide::Both))
    );
}

#[test]
fn a_caller_done_sending_still_gets_its_answer_and_the_connection_ends_with_both() {
    let (world, mut gate) = attached(&[CLIENT, MODEL], &["model-api"]);
    grant_both(&mut gate, &world, CLIENT, MODEL, 600);
    let mut releases = releases(&[(MODEL, 1_000)]);
    let (mut ends, caller, callee) = channel();
    let handle = gate
        .connect(
            &world.coordinator,
            request(CLIENT, MODEL, 100, 100),
            caller,
            callee,
        )
        .unwrap();
    ends.caller.write(b"ask").unwrap();
    ends.caller.finish();
    assert_eq!(gate.pump_connection(&world.coordinator, &mut releases, handle.id()).unwrap().request_bytes, 3);
    // The caller's end of writing reaches the callee once it read every byte.
    assert_eq!(gate.pump_connection(&world.coordinator, &mut releases, handle.id()).unwrap().state, ChannelState::Open);
    assert_eq!(ends.guest.drain(), (b"ask".to_vec(), true));
    ends.guest.write(b"answer").unwrap();
    let pumped = gate.pump_connection(&world.coordinator, &mut releases, handle.id()).unwrap();
    assert_eq!((pumped.response_bytes, pumped.state), (6, ChannelState::Open));
    ends.guest.finish();
    assert_eq!(
        gate.pump_connection(&world.coordinator, &mut releases, handle.id()).unwrap().state,
        closed(CloseReason::PeerEnded)
    );
    assert_eq!(ends.caller.drain(), (b"answer".to_vec(), true));
    assert_eq!(gate.open_connections(), 0);
    assert_eq!(released(&releases, MODEL), 6);
}

#[test]
fn revoking_one_services_grant_closes_only_its_connections() {
    let (world, mut gate) = attached(&[CLIENT, MODEL], &["model-api", "admin"]);
    grant_both(&mut gate, &world, CLIENT, MODEL, 600);
    let admin = connection_grant(
        &endpoint(CLIENT, "team-a"),
        &endpoint(MODEL, "team-a"),
        "admin",
        9000,
        world.in_seconds(600),
    );
    gate.grant_outbound(&world.coordinator, admin.clone())
        .unwrap();
    gate.grant_inbound(&world.coordinator, admin).unwrap();
    let admin_request = || ConnectionRequest {
        service: service("admin"),
        port: port(9000),
        ..request(CLIENT, MODEL, 100, 100)
    };
    let (_model_ends, caller, callee) = channel();
    let model = gate
        .connect(
            &world.coordinator,
            request(CLIENT, MODEL, 100, 100),
            caller,
            callee,
        )
        .unwrap();
    let (_admin_ends, caller, callee) = channel();
    gate.connect(&world.coordinator, admin_request(), caller, callee)
        .unwrap();
    assert_eq!(
        gate.revoke_connection_grant(
            &endpoint(CLIENT, "team-a"),
            &endpoint(MODEL, "team-a"),
            &service("model-api"),
            port(8000),
        ),
        vec![model.id()]
    );
    assert_eq!(gate.open_connections(), 1);
    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            request(CLIENT, MODEL, 100, 100),
            caller,
            callee
        ),
        Err(missing(MissingSide::Both))
    );
    let (_ends, caller, callee) = channel();
    assert!(gate
        .connect(&world.coordinator, admin_request(), caller, callee)
        .is_ok());
}
