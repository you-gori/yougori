//! VM §4.7 and CORE-04: the gate serves only what the sandbox's current authority holds.
//! A service is published, admitted or connected to only while that authority holds
//! CORE-04's own published-service grant; a policy change closes everything until the
//! host attaches the sandbox again; publication identities never repeat, so a proof never
//! carries over; and the gate's reading of the authority agrees with CORE-04's own.

use super::fakes::*;
use super::*;
use crate::foundation::coordination::{LeaseKind, LeaseTerms};
use crate::foundation::ids::{AuthorizationEpoch, MonotonicTime, OperationId};
use crate::sandbox_contract::destinations::{AuthenticationMode, IngressError, NetworkMode};

const WEB: &str = "exe-web";
const CLIENT: &str = "exe-client";

fn not_published(name: &str, at: u16) -> GateRefusal {
    GateRefusal::Ingress(IngressError::NotPublished {
        service: service(name),
        port: port(at),
    })
}

fn admit_public(
    gate: &mut ConnectionGate,
    authority: &dyn ConnectionAuthority,
    sandbox: &str,
    name: &str,
    at: u16,
) -> Result<(Ends, IngressHandle), GateRefusal> {
    let (ends, outside, guest) = channel();
    gate.admit(
        authority,
        &FakeVerifier::default(),
        inbound(sandbox, name, at, None),
        outside,
        guest,
    )
    .map(|handle| (ends, handle))
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

#[test]
fn a_service_the_authority_does_not_hold_is_neither_published_nor_served() {
    // CORE-04 launched the web sandbox granting no network at all, as an offline runtime:
    // a registration offering the service is refused, and one offering nothing attaches.
    let (mut world, mut gate) = attached(&[CLIENT], &["web"]);
    world.launch(WEB, &[]);
    assert_eq!(
        gate.attach(&world.coordinator, registration_of(WEB, "team-a", &["web"])),
        Err(GateRefusal::ServiceNotGranted {
            sandbox: execution(WEB),
            service: service("web"),
            grant: published_grant_id("web"),
        })
    );
    assert_eq!(gate.attached_epoch(&execution(WEB)), None);
    gate.attach(&world.coordinator, registration_of(WEB, "team-a", &[]))
        .unwrap();
    let lifecycle = world.coordinator.sandbox(&execution(WEB)).unwrap();
    assert!(lifecycle.settings_grant().network.is_empty());
    let not_registered = GateRefusal::ServiceNotRegistered {
        sandbox: execution(WEB),
        service: service("web"),
    };
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            100
        ),
        Err(not_registered.clone())
    );
    assert!(gate
        .publication_status(&world.coordinator, &execution(WEB))
        .is_empty());
    assert_eq!(
        admit_public(&mut gate, &world.coordinator, WEB, "web", 3000).err(),
        Some(not_published("web", 3000))
    );

    // No sandbox reaches it either.
    let grant = connection_grant(
        &endpoint(CLIENT, "team-a"),
        &endpoint(WEB, "team-a"),
        "web",
        8080,
        world.in_seconds(600),
    );
    gate.grant_outbound(&world.coordinator, grant.clone())
        .unwrap();
    assert_eq!(
        gate.grant_inbound(&world.coordinator, grant),
        Err(not_registered.clone())
    );
    let (ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            connection_request(CLIENT, WEB, "web", 8080),
            caller,
            callee
        ),
        Err(not_registered)
    );
    assert!(ends.caller.peer_closed() && ends.guest.peer_closed());

    // A service the registration does not name is never published, whatever CORE-04
    // granted.
    world.launch("exe-narrow", &["web"]);
    let mut narrow = registration("exe-narrow", "team-a");
    narrow.published_services.clear();
    gate.attach(&world.coordinator, narrow).unwrap();
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution("exe-narrow"),
            public_request("web", 3000, world.in_seconds(600)),
            100
        ),
        Err(GateRefusal::ServiceNotRegistered {
            sandbox: execution("exe-narrow"),
            service: service("web"),
        })
    );

    // The sandbox whose authority holds CORE-04's grant publishes and serves: the grant
    // the gate checks is the one in CORE-04's settings.
    assert!(world
        .coordinator
        .sandbox(&execution(CLIENT))
        .unwrap()
        .settings_grant()
        .network
        .contains(&published_grant("web")));
    gate.publish(
        &world.coordinator,
        &execution(CLIENT),
        public_request("web", 3000, world.in_seconds(600)),
        100,
    )
    .unwrap();
    let (mut ends, handle) =
        admit_public(&mut gate, &world.coordinator, CLIENT, "web", 3000).unwrap();
    let mut releases = releases(&[(CLIENT, 1_000)]);
    ends.guest.write(b"served").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut releases, handle.id())
        .unwrap();
    assert_eq!(
        (pumped.response_bytes, pumped.state),
        (6, ChannelState::Open)
    );
    assert_eq!(ends.caller.drain(), (b"served".to_vec(), false));
}

#[test]
fn a_policy_change_closes_everything_until_the_sandbox_is_attached_again() {
    let (mut world, mut gate) = attached(&[WEB, CLIENT], &["web"]);
    let epoch = world.epoch(WEB);
    let policy = world
        .coordinator
        .sandbox(&execution(WEB))
        .unwrap()
        .generations()
        .policy;
    let publication = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            1_000,
        )
        .unwrap();
    let (mut ends, session) =
        admit_public(&mut gate, &world.coordinator, WEB, "web", 3000).unwrap();
    let grant = connection_grant(
        &endpoint(CLIENT, "team-a"),
        &endpoint(WEB, "team-a"),
        "web",
        8080,
        world.in_seconds(600),
    );
    gate.grant_outbound(&world.coordinator, grant.clone())
        .unwrap();
    gate.grant_inbound(&world.coordinator, grant).unwrap();
    let (mut link_ends, caller, callee) = channel();
    let link = gate
        .connect(
            &world.coordinator,
            connection_request(CLIENT, WEB, "web", 8080),
            caller,
            callee,
        )
        .unwrap();
    let mut releases = releases(&[(WEB, 1_000), (CLIENT, 1_000)]);

    // The policy epoch moves on; the authorization epoch stays.
    world
        .coordinator
        .raise_policy_epoch(&execution(WEB))
        .unwrap();
    assert_eq!(world.epoch(WEB), epoch);
    assert_eq!(
        gate.publication_status(&world.coordinator, &execution(WEB))[0].state,
        PublicationState::PolicyChanged
    );

    // The next pump finds it: the session and the connection close before a byte moves.
    ends.guest.write(b"after").unwrap();
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, session.id())
            .unwrap(),
        Pumped::closed(CloseReason::PolicyChanged)
    );
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
    assert_eq!(link_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(link_ends.guest.drain(), (Vec::new(), true));
    assert_eq!(released(&releases, WEB), 0);
    assert_eq!(gate.attached_epoch(&execution(WEB)), None);

    // Everything is refused until the host attaches the sandbox again.
    let changed = GateRefusal::PolicyChanged {
        sandbox: execution(WEB),
    };
    assert_eq!(
        admit_public(&mut gate, &world.coordinator, WEB, "web", 3000).err(),
        Some(not_published("web", 3000))
    );
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3001, world.in_seconds(600)),
            1_000
        ),
        Err(changed.clone())
    );
    let (_ends, caller, callee) = channel();
    assert_eq!(
        gate.connect(
            &world.coordinator,
            connection_request(CLIENT, WEB, "web", 8080),
            caller,
            callee
        ),
        Err(changed)
    );
    let reports = gate.close_revoked(&world.coordinator);
    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].cause(),
        &ClosureCause::PolicyChanged {
            sandbox: execution(WEB),
            epoch,
            policy,
        }
    );
    assert_eq!(reports[0].withdrawn().to_vec(), vec![publication]);
    assert_eq!(reports[0].sessions()[0].session, session.id());
    assert_eq!(reports[0].connections()[0].connection, link.id());
    let everything = OtherChannels {
        sockets_closed: true,
        channels_closed: true,
    };
    assert_eq!(
        acknowledge_closure(&mut world.coordinator, &gate, &reports[0], everything),
        Ok(Vec::new())
    );

    // Attached again with the new policy, offline, it publishes nothing.
    let mut offline = registration_of(WEB, "team-a", &["web"]);
    offline.mode = NetworkMode::Offline;
    assert_eq!(gate.attach(&world.coordinator, offline), Ok(epoch));
    assert!(matches!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            1_000
        ),
        Err(GateRefusal::Ingress(IngressError::Mode(_)))
    ));
    assert_eq!(
        gate.attach(&world.coordinator, registration_of(WEB, "team-a", &["web"])),
        Err(GateRefusal::AlreadyAttached {
            sandbox: execution(WEB)
        })
    );

    // Another policy change, and the declared transport again: a fresh publication.
    world
        .coordinator
        .raise_policy_epoch(&execution(WEB))
        .unwrap();
    assert_eq!(
        gate.attach(&world.coordinator, registration_of(WEB, "team-a", &["web"])),
        Ok(epoch)
    );
    let again = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            1_000,
        )
        .unwrap();
    assert!(again > publication);
    assert!(admit_public(&mut gate, &world.coordinator, WEB, "web", 3000).is_ok());
}

#[test]
fn publication_ids_never_repeat_and_proofs_never_carry_over() {
    let mut authority = SettableAuthority::at(1_000);
    let mut gate = ConnectionGate::new();
    let later = MonotonicTime::from_nanos(2_000 * 1_000_000_000);
    let mode = AuthenticationMode::PlatformSession;
    for sandbox in [WEB, CLIENT] {
        gate.attach(&authority, registration(sandbox, "team-a"))
            .unwrap();
    }
    let private = |name: &str, at: u16| private_request(name, at, &["alice"], later);
    let first = gate
        .publish(&authority, &execution(WEB), private("preview", 3000), 1_000)
        .unwrap();
    let elsewhere = gate
        .publish(
            &authority,
            &execution(CLIENT),
            private("preview", 3000),
            1_000,
        )
        .unwrap();
    let first_binding = gate.proof_binding(&execution(WEB), first).unwrap();
    assert_eq!(
        first_binding,
        ProofBinding {
            sandbox: execution(WEB),
            epoch: AuthorizationEpoch::FIRST,
            publication: first,
        }
    );
    assert_eq!(gate.proof_binding(&execution(CLIENT), first), None);
    let mut verifier = FakeVerifier::default();
    verifier.issue("tok-preview", "alice", first_binding, mode);

    // The other sandbox's publication of the same service and port refuses the proof.
    let (_ends, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &authority,
            &verifier,
            inbound(CLIENT, "preview", 3000, proof(mode, "tok-preview")),
            outside,
            guest
        ),
        Err(GateRefusal::Proof(ProofRefusal::WrongPublication))
    );

    // A new epoch starts a new V02 table, but the gate's identities keep rising.
    authority.revoke(WEB);
    let reports = gate.close_revoked(&authority);
    assert_eq!(
        (reports[0].sandbox(), reports[0].epoch()),
        (&execution(WEB), AuthorizationEpoch::FIRST)
    );
    assert_eq!(reports[0].withdrawn().to_vec(), vec![first]);
    authority.relaunch(WEB, 2);
    gate.attach(&authority, registration(WEB, "team-a"))
        .unwrap();
    let admin = gate
        .publish(&authority, &execution(WEB), private("admin", 9000), 1_000)
        .unwrap();
    let preview = gate
        .publish(&authority, &execution(WEB), private("preview", 3000), 1_000)
        .unwrap();

    // The earlier proof admits to neither, though one has the same service and port.
    for (name, at) in [("admin", 9000), ("preview", 3000)] {
        let (_ends, outside, guest) = channel();
        assert_eq!(
            gate.admit(
                &authority,
                &verifier,
                inbound(WEB, name, at, proof(mode, "tok-preview")),
                outside,
                guest
            ),
            Err(GateRefusal::Proof(ProofRefusal::WrongPublication)),
            "{name}"
        );
    }
    let binding = gate.proof_binding(&execution(WEB), preview).unwrap();
    assert_eq!(binding.epoch, AuthorizationEpoch::new(2));
    verifier.issue("tok-new", "alice", binding, mode);
    let (_ends, outside, guest) = channel();
    let handle = gate
        .admit(
            &authority,
            &verifier,
            inbound(WEB, "preview", 3000, proof(mode, "tok-new")),
            outside,
            guest,
        )
        .unwrap();
    assert_eq!(
        (handle.publication(), handle.epoch()),
        (preview, AuthorizationEpoch::new(2))
    );

    // A policy re-attachment keeps counting too.
    authority.raise_policy(WEB);
    assert_eq!(gate.close_revoked(&authority).len(), 1);
    gate.attach(&authority, registration(WEB, "team-a"))
        .unwrap();
    let after_policy = gate
        .publish(&authority, &execution(WEB), private("preview", 3000), 1_000)
        .unwrap();
    let ids: Vec<u64> = [first, elsewhere, admin, preview, after_policy]
        .iter()
        .map(|id| id.get())
        .collect();
    assert_eq!(ids, [1, 2, 3, 4, 5]);
}

#[test]
fn current_epoch_holds_exactly_when_core04_starts_child_work() {
    let mut world = World::new();
    let terms = LeaseTerms {
        term: 60 * SECOND,
        max_lifetime: 600 * SECOND,
        cancel_within: 5 * SECOND,
    };
    let mut probes = 0u32;
    // CORE-04's own answer: whether it starts child work under the sandbox now.
    let mut check = |world: &mut World, of: &str, holds: bool, stage: &str| {
        let epoch = ConnectionAuthority::current_epoch(&world.coordinator, &execution(of));
        probes += 1;
        let started = world
            .coordinator
            .start_child_work(
                &execution(of),
                OperationId::new(format!("probe-{probes}")).unwrap(),
                LeaseKind::ChildWork,
                terms,
            )
            .is_ok();
        assert_eq!(epoch.is_some(), started, "{stage}");
        assert_eq!(started, holds, "{stage}");
        if let Some(epoch) = epoch {
            assert_eq!(epoch, world.epoch(of), "{stage}");
        }
    };
    check(&mut world, WEB, false, "unknown");
    world.launch_authority(WEB, &["web"]);
    check(&mut world, WEB, true, "authority_active");
    world.coordinator.start_running(&execution(WEB)).unwrap();
    check(&mut world, WEB, true, "running");
    world
        .coordinator
        .raise_policy_epoch(&execution(WEB))
        .unwrap();
    check(&mut world, WEB, true, "policy raised");
    world.coordinator.revoke(&execution(WEB)).unwrap();
    check(&mut world, WEB, false, "revoking");
    world.stop_revoked(WEB);
    check(&mut world, WEB, false, "stopped");
    world.relaunch(WEB);
    check(&mut world, WEB, true, "booted again");
    world.launch(CLIENT, &[]);
    check(&mut world, CLIENT, true, "another sandbox running");
    world.advance(3_600);
    check(&mut world, CLIENT, false, "authority expired");
    check(
        &mut world,
        WEB,
        false,
        "authority expired after the new boot",
    );
}
