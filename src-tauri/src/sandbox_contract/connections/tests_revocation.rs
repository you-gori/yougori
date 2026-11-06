//! VM §6.3 step 2 and VM-W13: revocation at the gate, against the real CORE-04
//! coordinator. Revoking a sandbox (its epoch) or tombstoning a published-service grant
//! closes every session and connection it covers and refuses new ones; the status shows
//! it at once; and the closure report, which only the gate makes, lets the host
//! acknowledge `SocketsClosed` and `AllChannelsClosed` only while the gate's proof still
//! holds and only for the epoch the revocation ended.

use super::fakes::*;
use super::*;
use crate::foundation::coordination::{MilestoneSource, RevocationMilestone};
use crate::foundation::evidence::SourceClass;
use crate::sandbox_contract::destinations::{ConnectionRefusal, IngressError, MissingSide};

const WEB: &str = "exe-web";
const CLIENT: &str = "exe-client";
const OTHER: &str = "exe-other";

/// A public publication of `name` on `at` by `sandbox`, with one admitted session.
fn publish_and_admit(
    gate: &mut ConnectionGate,
    world: &World,
    sandbox: &str,
    name: &str,
    at: u16,
) -> (GatePublicationId, IngressHandle, Ends) {
    let publication = gate
        .publish(
            &world.coordinator,
            &execution(sandbox),
            public_request(name, at, world.in_seconds(600)),
            1_000,
        )
        .unwrap();
    let (ends, handle) = admit(gate, world, sandbox, name, at).unwrap();
    (publication, handle, ends)
}

fn admit(
    gate: &mut ConnectionGate,
    world: &World,
    sandbox: &str,
    name: &str,
    at: u16,
) -> Result<(Ends, IngressHandle), GateRefusal> {
    let (ends, outside, guest) = channel();
    gate.admit(
        &world.coordinator,
        &FakeVerifier::default(),
        inbound(sandbox, name, at, None),
        outside,
        guest,
    )
    .map(|handle| (ends, handle))
}

/// What an outside caller is told of a service that is not served.
fn not_published(name: &str, at: u16) -> GateRefusal {
    GateRefusal::Ingress(IngressError::NotPublished {
        service: service(name),
        port: port(at),
    })
}

/// Grants and opens a connection from `caller` to `callee`'s `name` on `at`.
fn link(
    gate: &mut ConnectionGate,
    world: &World,
    caller: &str,
    callee: &str,
    name: &str,
    at: u16,
) -> (ConnectionHandle, Ends) {
    let grant = connection_grant(
        &endpoint(caller, "team-a"),
        &endpoint(callee, "team-a"),
        name,
        at,
        world.in_seconds(600),
    );
    gate.grant_outbound(&world.coordinator, grant.clone())
        .unwrap();
    gate.grant_inbound(&world.coordinator, grant).unwrap();
    let (ends, caller_end, callee_end) = channel();
    let handle = gate
        .connect(
            &world.coordinator,
            connection_request(caller, callee, name, at),
            caller_end,
            callee_end,
        )
        .unwrap();
    (handle, ends)
}

fn connection_request(caller: &str, callee: &str, name: &str, at: u16) -> ConnectionRequest {
    ConnectionRequest {
        caller: execution(caller),
        callee: execution(callee),
        service: service(name),
        port: port(at),
        budget: ConnectionBudget {
            caller_to_callee_bytes: 1_000,
            callee_to_caller_bytes: 1_000,
        },
    }
}

/// The host observed every socket and every other channel of the sandbox closed.
fn everything() -> OtherChannels {
    OtherChannels {
        sockets_closed: true,
        channels_closed: true,
    }
}

#[test]
fn revoking_a_sandbox_closes_its_sessions_and_connections_and_refuses_new_ones() {
    let (mut world, mut gate) = attached(&[WEB, CLIENT, OTHER], &["web"]);
    let epoch = world.epoch(WEB);
    let (publication, session, mut session_ends) =
        publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    let (inbound_link, mut inbound_ends) = link(&mut gate, &world, CLIENT, WEB, "web", 8080);
    let (outbound_link, mut outbound_ends) = link(&mut gate, &world, WEB, CLIENT, "web", 9090);
    let (_, bystander, _bystander_ends) = publish_and_admit(&mut gate, &world, OTHER, "web", 3000);
    let mut releases = releases(&[(WEB, 1_000), (CLIENT, 1_000), (OTHER, 1_000)]);

    world.coordinator.revoke(&execution(WEB)).unwrap();
    assert!(world.epoch(WEB) > epoch);
    let reports = gate.close_revoked(&world.coordinator);
    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert_eq!(
        report.cause(),
        &ClosureCause::AuthorityEnded {
            sandbox: execution(WEB),
            epoch,
        }
    );
    assert_eq!((report.sandbox(), report.epoch()), (&execution(WEB), epoch));
    assert_eq!(report.at(), world.now());
    assert_eq!(report.withdrawn().to_vec(), vec![publication]);
    assert_eq!(
        report.sessions().to_vec(),
        vec![ClosedSession {
            session: session.id(),
            publication,
            service: service("web"),
        }]
    );
    assert_eq!(
        report.connections().to_vec(),
        vec![
            ClosedConnection {
                connection: inbound_link.id(),
                caller: endpoint(CLIENT, "team-a"),
                callee: endpoint(WEB, "team-a"),
                service: service("web"),
                port: port(8080),
            },
            ClosedConnection {
                connection: outbound_link.id(),
                caller: endpoint(WEB, "team-a"),
                callee: endpoint(CLIENT, "team-a"),
                service: service("web"),
                port: port(9090),
            },
        ]
    );
    for ends in [&mut session_ends, &mut inbound_ends, &mut outbound_ends] {
        assert_eq!(ends.caller.drain(), (Vec::new(), true));
        assert_eq!(ends.guest.drain(), (Vec::new(), true));
    }
    assert!(gate.close_revoked(&world.coordinator).is_empty());

    // The bystander keeps its session; the revoked sandbox is refused everything new, and
    // an outside caller is told only that nothing is published.
    assert_eq!(gate.open_sessions(), 1);
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, bystander.id())
            .unwrap()
            .state,
        ChannelState::Open
    );
    assert_eq!(gate.attached_epoch(&execution(WEB)), None);
    assert_eq!(gate.proof_binding(&execution(WEB), publication), None);
    let ended = GateRefusal::AuthorityEnded {
        sandbox: execution(WEB),
    };
    assert_eq!(
        admit(&mut gate, &world, WEB, "web", 3000).err(),
        Some(not_published("web", 3000))
    );
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3001, world.in_seconds(600)),
            1_000
        ),
        Err(ended.clone())
    );
    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            connection_request(CLIENT, WEB, "web", 8080),
            caller,
            callee
        ),
        Err(ended.clone())
    );
    assert_eq!(
        gate.attach(&world.coordinator, registration(WEB, "team-a")),
        Err(ended)
    );
    assert_eq!(
        gate.publication_status(&world.coordinator, &execution(WEB))[0].state,
        PublicationState::AuthorityEnded
    );

    // The host acknowledges only what it observed of the sandbox's other channels.
    assert!(acknowledge_closure(
        &mut world.coordinator,
        &gate,
        report,
        OtherChannels::default()
    )
    .unwrap()
    .is_empty());
    let sockets = OtherChannels {
        sockets_closed: true,
        channels_closed: false,
    };
    let acknowledged = acknowledge_closure(&mut world.coordinator, &gate, report, sockets).unwrap();
    assert_eq!(
        acknowledged,
        [(RevocationMilestone::SocketsClosed, world.now())]
    );
    let operation = world.coordinator.revocation(&execution(WEB)).unwrap();
    assert_eq!(
        operation.milestone_source(RevocationMilestone::SocketsClosed),
        Some(MilestoneSource::Acknowledged {
            source: SourceClass::HostProbe
        })
    );
    assert_eq!(
        operation.milestone(RevocationMilestone::AllChannelsClosed),
        None
    );

    world.advance(2);
    let acknowledged =
        acknowledge_closure(&mut world.coordinator, &gate, report, everything()).unwrap();
    let sockets_at = acknowledged[0].1;
    assert_eq!(
        acknowledged,
        [
            (RevocationMilestone::SocketsClosed, sockets_at),
            (RevocationMilestone::AllChannelsClosed, world.now()),
        ]
    );
    assert!(
        sockets_at < world.now(),
        "sockets closed stays first recorded"
    );
    let operation = world.coordinator.revocation(&execution(WEB)).unwrap();
    assert_eq!(
        operation.milestone_source(RevocationMilestone::AllChannelsClosed),
        Some(MilestoneSource::Acknowledged {
            source: SourceClass::HostProbe
        })
    );
}

#[test]
fn a_revocation_found_by_a_pump_closes_everything_and_is_reported_once() {
    let (mut world, mut gate) = attached(&[WEB], &["web"]);
    let (publication, first, mut first_ends) =
        publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    let (mut second_ends, second) = admit(&mut gate, &world, WEB, "web", 3000).unwrap();
    let mut releases = releases(&[(WEB, 1_000)]);
    first_ends.guest.write(b"after revocation").unwrap();

    world.coordinator.revoke(&execution(WEB)).unwrap();
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, first.id())
            .unwrap(),
        Pumped::closed(CloseReason::AuthorityEnded)
    );
    assert_eq!(first_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(second_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(released(&releases, WEB), 0);
    assert_eq!(gate.open_sessions(), 0);
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, second.id()),
        Err(GateRefusal::UnknownSession {
            session: second.id()
        })
    );

    let reports = gate.close_revoked(&world.coordinator);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].withdrawn().to_vec(), vec![publication]);
    let closed: Vec<SessionId> = reports[0]
        .sessions()
        .iter()
        .map(|closed| closed.session)
        .collect();
    assert_eq!(closed, [first.id(), second.id()]);
    assert!(gate.close_revoked(&world.coordinator).is_empty());
}

#[test]
fn tombstoning_a_published_service_grant_closes_only_that_service() {
    let (mut world, mut gate) = attached(&[WEB, CLIENT], &["web", "api"]);
    let epoch = world.epoch(WEB);
    let (web_publication, web_session, mut web_ends) =
        publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    let (_, api_session, _api_ends) = publish_and_admit(&mut gate, &world, WEB, "api", 4000);
    let (web_link, mut web_link_ends) = link(&mut gate, &world, CLIENT, WEB, "web", 8080);
    let (api_link, _api_link_ends) = link(&mut gate, &world, CLIENT, WEB, "api", 8081);
    let mut releases = releases(&[(WEB, 1_000), (CLIENT, 1_000)]);

    // The gate's grant is CORE-04's own: the one CORE-04 withdraws from the settings.
    let grant = published_grant_id("web");
    let revoked = world
        .coordinator
        .revoke_grant(&execution(WEB), grant)
        .unwrap();
    assert_eq!(revoked.network, Some(published_grant("web")));
    assert_eq!(revoked.epoch, epoch);

    // A pump finds it first; everything the grant covers closes with that session.
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, web_session.id())
            .unwrap(),
        Pumped::closed(CloseReason::GrantRevoked { grant })
    );
    assert_eq!(web_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(web_link_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(
        gate.pump_connection(&world.coordinator, &mut releases, web_link.id()),
        Err(GateRefusal::UnknownConnection {
            connection: web_link.id()
        })
    );
    let reports = gate.close_revoked(&world.coordinator);
    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert_eq!(
        report.cause(),
        &ClosureCause::GrantRevoked {
            sandbox: execution(WEB),
            epoch,
            service: service("web"),
            grant,
        }
    );
    assert_eq!(report.at(), world.now());
    assert_eq!(report.withdrawn().to_vec(), vec![web_publication]);
    assert_eq!(
        report.sessions().to_vec(),
        vec![ClosedSession {
            session: web_session.id(),
            publication: web_publication,
            service: service("web"),
        }]
    );
    assert_eq!(
        report.connections().to_vec(),
        vec![ClosedConnection {
            connection: web_link.id(),
            caller: endpoint(CLIENT, "team-a"),
            callee: endpoint(WEB, "team-a"),
            service: service("web"),
            port: port(8080),
        }]
    );

    // The sandbox keeps its epoch and everything else.
    assert_eq!(gate.attached_epoch(&execution(WEB)), Some(epoch));
    for pumped in [
        gate.pump_session(&world.coordinator, &mut releases, api_session.id()),
        gate.pump_connection(&world.coordinator, &mut releases, api_link.id()),
    ] {
        assert_eq!(pumped.unwrap().state, ChannelState::Open);
    }
    assert!(admit(&mut gate, &world, WEB, "api", 4000).is_ok());

    // The tombstoned service is refused everything new; an outside caller is told only
    // that it is not published.
    let refused = GateRefusal::GrantRevoked {
        sandbox: execution(WEB),
        service: service("web"),
        grant,
    };
    assert_eq!(
        admit(&mut gate, &world, WEB, "web", 3000).err(),
        Some(not_published("web", 3000))
    );
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3001, world.in_seconds(600)),
            1_000
        ),
        Err(refused.clone())
    );
    let grant_again = connection_grant(
        &endpoint(CLIENT, "team-a"),
        &endpoint(WEB, "team-a"),
        "web",
        8082,
        world.in_seconds(600),
    );
    assert_eq!(
        gate.grant_inbound(&world.coordinator, grant_again),
        Err(refused.clone())
    );
    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            connection_request(CLIENT, WEB, "web", 8080),
            caller,
            callee
        ),
        Err(refused)
    );
    let states: Vec<(String, PublicationState)> = gate
        .publication_status(&world.coordinator, &execution(WEB))
        .into_iter()
        .map(|status| (status.service.to_string(), status.state))
        .collect();
    assert_eq!(
        states,
        [
            ("web".to_owned(), PublicationState::GrantRevoked),
            ("api".to_owned(), PublicationState::Active),
        ]
    );

    // A tombstone has no CORE-04 revocation operation, so it acknowledges nothing.
    assert!(report.acknowledgeable(everything()).is_empty());
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, report, everything()),
        Ok(Vec::new())
    );
}

#[test]
fn authority_that_expired_closes_everything_but_is_no_revocation_to_acknowledge() {
    let (mut world, mut gate) = attached(&[WEB], &["web"]);
    let (_, session, mut ends) = publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    world.advance(3_600);
    let reports = gate.close_revoked(&world.coordinator);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].sessions()[0].session, session.id());
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, &reports[0], everything()),
        Err(AcknowledgeRefusal::NoRevocation {
            sandbox: execution(WEB)
        })
    );
}

#[test]
fn a_closure_report_is_acknowledged_only_against_the_gate_that_closed_everything() {
    let (mut world, mut gate) = attached(&[WEB], &["web"]);
    // A second gate serves the same sandbox and has not looked since the revocation; a
    // third never served it.
    let mut second = ConnectionGate::new();
    second
        .attach(&world.coordinator, registration_of(WEB, "team-a", &["web"]))
        .unwrap();
    let unrelated = ConnectionGate::new();
    publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    let (_, _, mut second_ends) = publish_and_admit(&mut second, &world, WEB, "web", 3000);
    let epoch = world.epoch(WEB);
    world.coordinator.revoke(&execution(WEB)).unwrap();
    let reports = gate.close_revoked(&world.coordinator);
    let report = &reports[0];

    // Against a gate that still holds a session of the sandbox open, nothing is
    // acknowledged, and neither against a gate that never closed the sandbox.
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &second, report, everything()),
        Err(AcknowledgeRefusal::ChannelsStillOpen {
            sandbox: execution(WEB),
            sessions: 1,
            connections: 0,
        })
    );
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &unrelated, report, everything()),
        Err(AcknowledgeRefusal::NotClosedByThisGate {
            sandbox: execution(WEB),
            epoch,
        })
    );
    let operation = world.coordinator.revocation(&execution(WEB)).unwrap();
    for milestone in [
        RevocationMilestone::SocketsClosed,
        RevocationMilestone::AllChannelsClosed,
    ] {
        assert_eq!(operation.milestone(milestone), None);
    }

    // Once the second gate closed its own, each report acknowledges against its gate.
    let second_reports = second.close_revoked(&world.coordinator);
    assert_eq!(second_ends.caller.drain(), (Vec::new(), true));
    let at = world.now();
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, report, everything()),
        Ok(vec![
            (RevocationMilestone::SocketsClosed, at),
            (RevocationMilestone::AllChannelsClosed, at),
        ])
    );
    assert_eq!(
        acknowledge_closure(
            &mut world.coordinator,
            &second,
            &second_reports[0],
            everything()
        )
        .unwrap()
        .len(),
        2
    );
}

#[test]
fn a_report_from_an_earlier_epoch_is_refused() {
    let (mut world, mut gate) = attached(&[WEB], &["web"]);
    let first_epoch = world.epoch(WEB);
    publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    world.coordinator.revoke(&execution(WEB)).unwrap();
    let first = gate.close_revoked(&world.coordinator).remove(0);
    assert_eq!(first.epoch(), first_epoch);

    // A new boot: CORE-04 forgets the old revocation, so the old report has nothing to
    // acknowledge.
    world.stop_revoked(WEB);
    world.relaunch(WEB);
    let second_epoch = gate
        .attach(&world.coordinator, registration_of(WEB, "team-a", &["web"]))
        .unwrap();
    assert!(second_epoch > first_epoch);
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, &first, everything()),
        Err(AcknowledgeRefusal::NoRevocation {
            sandbox: execution(WEB)
        })
    );

    // Revoked again, the revocation ended the new epoch: the old report is refused, the
    // new one acknowledges.
    publish_and_admit(&mut gate, &world, WEB, "web", 3000);
    world.coordinator.revoke(&execution(WEB)).unwrap();
    let second = gate.close_revoked(&world.coordinator).remove(0);
    assert_eq!(second.epoch(), second_epoch);
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, &first, everything()),
        Err(AcknowledgeRefusal::StaleEpoch {
            sandbox: execution(WEB),
            reported: first_epoch,
            revoked: second_epoch,
        })
    );
    let operation = world.coordinator.revocation(&execution(WEB)).unwrap();
    assert_eq!(
        operation.milestone(RevocationMilestone::SocketsClosed),
        None
    );
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, &second, everything())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn publication_status_shows_a_revocation_at_once() {
    let (mut world, mut gate) = attached(&[WEB, CLIENT], &["web", "api"]);
    let web_epoch = world.epoch(WEB);
    let client_policy = world
        .coordinator
        .sandbox(&execution(CLIENT))
        .unwrap()
        .generations()
        .policy;
    for (sandbox, name, at) in [
        (WEB, "web", 3000),
        (WEB, "api", 4000),
        (CLIENT, "web", 3000),
    ] {
        gate.publish(
            &world.coordinator,
            &execution(sandbox),
            public_request(name, at, world.in_seconds(600)),
            1_000,
        )
        .unwrap();
    }
    let states = |gate: &ConnectionGate, world: &World, sandbox: &str| -> Vec<PublicationState> {
        gate.publication_status(&world.coordinator, &execution(sandbox))
            .into_iter()
            .map(|status| status.state)
            .collect()
    };
    use PublicationState::{Active, AuthorityEnded, GrantRevoked, PolicyChanged};
    assert_eq!(states(&gate, &world, WEB), [Active, Active]);

    // No gate operation runs between CORE-04's change and each view.
    world
        .coordinator
        .revoke_grant(&execution(WEB), published_grant_id("api"))
        .unwrap();
    assert_eq!(states(&gate, &world, WEB), [Active, GrantRevoked]);
    world.coordinator.revoke(&execution(WEB)).unwrap();
    assert_eq!(states(&gate, &world, WEB), [AuthorityEnded, AuthorityEnded]);
    world
        .coordinator
        .raise_policy_epoch(&execution(CLIENT))
        .unwrap();
    assert_eq!(states(&gate, &world, CLIENT), [PolicyChanged]);

    // The sweep then closes what the views already showed, and the views stay.
    let causes: Vec<ClosureCause> = gate
        .close_revoked(&world.coordinator)
        .iter()
        .map(|report| report.cause().clone())
        .collect();
    assert_eq!(
        causes,
        [
            ClosureCause::PolicyChanged {
                sandbox: execution(CLIENT),
                epoch: world.epoch(CLIENT),
                policy: client_policy,
            },
            ClosureCause::AuthorityEnded {
                sandbox: execution(WEB),
                epoch: web_epoch,
            },
        ]
    );
    assert_eq!(states(&gate, &world, WEB), [AuthorityEnded, AuthorityEnded]);
    assert_eq!(states(&gate, &world, CLIENT), [PolicyChanged]);
}

#[test]
fn a_new_epoch_starts_with_nothing_published_and_no_grants() {
    let mut authority = SettableAuthority::at(1_000);
    let mut gate = ConnectionGate::new();
    let later = crate::foundation::ids::MonotonicTime::from_nanos(2_000 * 1_000_000_000);
    for sandbox in [WEB, CLIENT] {
        gate.attach(&authority, registration(sandbox, "team-a"))
            .unwrap();
    }
    let grant = connection_grant(
        &endpoint(CLIENT, "team-a"),
        &endpoint(WEB, "team-a"),
        "web",
        8080,
        later,
    );
    gate.grant_outbound(&authority, grant.clone()).unwrap();
    gate.grant_inbound(&authority, grant).unwrap();
    gate.publish(
        &authority,
        &execution(WEB),
        public_request("web", 3000, later),
        1_000,
    )
    .unwrap();

    authority.revoke(WEB);
    assert_eq!(gate.close_revoked(&authority).len(), 1);
    authority.relaunch(WEB, 2);
    assert_eq!(
        gate.attach(&authority, registration(WEB, "team-a")),
        Ok(crate::foundation::ids::AuthorizationEpoch::new(2))
    );
    assert!(gate
        .publication_status(&authority, &execution(WEB))
        .is_empty());
    let (_ends, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &authority,
            &FakeVerifier::default(),
            inbound(WEB, "web", 3000, None),
            outside,
            guest
        ),
        Err(not_published("web", 3000))
    );
    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &authority,
            connection_request(CLIENT, WEB, "web", 8080),
            caller,
            callee
        ),
        Err(GateRefusal::Connection(ConnectionRefusal::MissingGrant {
            side: MissingSide::Both
        }))
    );
}
