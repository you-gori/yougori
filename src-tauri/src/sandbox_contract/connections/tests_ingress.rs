//! VM §4.7 and VM-W13: the ingress gate. An unpublished service is unreachable, an
//! expired publication is refused, a private publication needs authentication and is
//! never served as public, a public one stays public, a session closes when its proof
//! expires, and spending the response budget closes the session before anything more is
//! forwarded. An outside caller is never told why a service is not served.

use super::fakes::*;
use super::*;
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, BudgetScope, IngressError, ReleaseError,
};

const WEB: &str = "exe-web";

#[test]
fn an_unpublished_service_is_unreachable() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let verifier = FakeVerifier::default();
    let unreachable = |name: &str, at: u16| {
        GateRefusal::Ingress(IngressError::NotPublished {
            service: service(name),
            port: port(at),
        })
    };

    // Nothing is published by default, and an unknown sandbox looks the same.
    for sandbox in [WEB, "exe-unknown"] {
        let (ends, outside, guest) = channel();
        assert_eq!(
            gate.admit(
                &world.coordinator,
                &verifier,
                inbound(sandbox, "web", 3000, None),
                outside,
                guest
            ),
            Err(unreachable("web", 3000))
        );
        assert!(ends.caller.peer_closed() && ends.guest.peer_closed());
    }

    // Another port or another service of a sandbox that publishes is unreachable too.
    let published = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            1_024,
        )
        .unwrap();
    for (name, at) in [("web", 3001), ("admin", 3000)] {
        let (_ends, outside, guest) = channel();
        assert_eq!(
            gate.admit(
                &world.coordinator,
                &verifier,
                inbound(WEB, name, at, None),
                outside,
                guest
            ),
            Err(unreachable(name, at))
        );
    }
    assert_eq!(gate.open_sessions(), 0);

    let (mut ends, outside, guest) = channel();
    let admitted = gate
        .admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest,
        )
        .unwrap();
    assert_eq!(admitted.publication(), published);
    assert_eq!(admitted.id().get(), 1);
    assert_eq!(gate.open_sessions(), 1);

    // Withdrawn, it is unreachable again, and its open session is closed.
    assert_eq!(
        gate.withdraw(&execution(WEB), published),
        Ok(vec![admitted.id()])
    );
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
    assert!(ends.guest.peer_closed());
    let (_ends, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest
        ),
        Err(unreachable("web", 3000))
    );
    assert_eq!(
        gate.publication_status(&world.coordinator, &execution(WEB))[0].state,
        PublicationState::Withdrawn
    );
}

#[test]
fn an_expired_publication_is_refused_and_ends_its_sessions() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let verifier = FakeVerifier::default();
    let mut releases = releases(&[(WEB, 1_000)]);
    let published = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(60)),
            1_024,
        )
        .unwrap();
    let (mut ends, outside, guest) = channel();
    let session = gate
        .admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest,
        )
        .unwrap();
    assert_eq!(
        gate.publication_status(&world.coordinator, &execution(WEB))[0].remaining_lifetime,
        60 * SECOND
    );

    // Expired, it is not served: the caller is told it is not published, the host why.
    world.advance(60);
    let (_other, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest
        ),
        Err(GateRefusal::Ingress(IngressError::NotPublished {
            service: service("web"),
            port: port(3000)
        }))
    );
    ends.guest.write(b"late").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut releases, session.id())
        .unwrap();
    assert_eq!(pumped.state, closed(CloseReason::PublicationExpired));
    assert_eq!(pumped.response_bytes, 0);
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
    assert_eq!(released(&releases, WEB), 0);
    let status = &gate.publication_status(&world.coordinator, &execution(WEB))[0];
    assert_eq!(
        (status.publication, status.state, status.remaining_lifetime),
        (
            published,
            PublicationState::Expired,
            std::time::Duration::ZERO
        )
    );
}

#[test]
fn a_private_publication_needs_authentication_and_is_never_served_as_public() {
    let (world, mut gate) = attached(&[WEB], &["web", "api"]);
    let expires = world.in_seconds(600);
    let preview = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            private_request("web", 3000, &["alice"], expires),
            1_024,
        )
        .unwrap();
    let api = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            private_request("api", 4000, &["alice"], expires),
            1_024,
        )
        .unwrap();
    let session = AuthenticationMode::PlatformSession;
    let preview = gate.proof_binding(&execution(WEB), preview).unwrap();
    let api = gate.proof_binding(&execution(WEB), api).unwrap();
    let mut verifier = FakeVerifier::default();
    verifier.issue("tok-alice", "alice", preview.clone(), session);
    verifier.issue("tok-bob", "bob", preview.clone(), session);
    verifier.issue("tok-alice-api", "alice", api, session);
    verifier.issue(
        "tok-alice-bearer",
        "alice",
        preview.clone(),
        AuthenticationMode::BearerToken,
    );
    verifier.issue("tok-stale", "alice", preview, session);
    verifier.expired.insert(b"tok-stale".to_vec());

    let refusals = [
        (None, GateRefusal::Ingress(IngressError::NotAuthenticated)),
        (
            proof(session, "forged"),
            GateRefusal::Proof(ProofRefusal::Invalid),
        ),
        (
            proof(session, "tok-stale"),
            GateRefusal::Proof(ProofRefusal::Expired),
        ),
        (
            proof(session, "tok-alice-api"),
            GateRefusal::Proof(ProofRefusal::WrongPublication),
        ),
        (
            proof(session, "tok-bob"),
            GateRefusal::Ingress(IngressError::NotInAudience),
        ),
        (
            proof(AuthenticationMode::BearerToken, "tok-alice-bearer"),
            GateRefusal::Ingress(IngressError::WrongAuthentication { required: session }),
        ),
    ];
    for (presented, refusal) in refusals {
        let (ends, outside, guest) = channel();
        assert_eq!(
            gate.admit(
                &world.coordinator,
                &verifier,
                inbound(WEB, "web", 3000, presented),
                outside,
                guest
            ),
            Err(refusal)
        );
        assert!(ends.caller.peer_closed() && ends.guest.peer_closed());
    }
    assert_eq!(gate.open_sessions(), 0);

    let (_ends, outside, guest) = channel();
    let admitted = gate
        .admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, proof(session, "tok-alice")),
            outside,
            guest,
        )
        .unwrap();
    let alice = AdmittedAs::Private {
        principal: principal("alice"),
        mode: session,
    };
    assert_eq!(admitted.admitted_as(), &alice);
    let sessions = gate.session_status();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].admitted_as, alice);
    let status = &gate.publication_status(&world.coordinator, &execution(WEB))[0];
    assert_eq!(
        status.audience,
        Audience::Private {
            principals: [principal("alice")].into()
        }
    );
    assert_eq!(status.authentication, session);
    assert_eq!((status.open_sessions, status.sessions_admitted), (1, 1));

    // A public publication of the same service and port cannot shadow the private one.
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, expires),
            1_024
        ),
        Err(GateRefusal::Ingress(IngressError::AlreadyPublished {
            service: service("web"),
            port: port(3000)
        }))
    );
}

#[test]
fn a_public_publication_stays_public() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let expires = world.in_seconds(600);
    let verifier = FakeVerifier::default();
    let public = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, expires),
            1_024,
        )
        .unwrap();
    let anyone = AdmittedAs::Public { principal: None };
    let mut kept = Vec::new();
    for presented in [None, proof(AuthenticationMode::BearerToken, "whatever")] {
        let (ends, outside, guest) = channel();
        let admitted = gate
            .admit(
                &world.coordinator,
                &verifier,
                inbound(WEB, "web", 3000, presented),
                outside,
                guest,
            )
            .unwrap();
        assert_eq!(admitted.admitted_as(), &anyone);
        kept.push(ends);
    }
    let status = &gate.publication_status(&world.coordinator, &execution(WEB))[0];
    assert_eq!(
        (status.audience.clone(), status.authentication),
        (Audience::Public, AuthenticationMode::None)
    );

    // Going private takes a withdrawal, which ends every public session, and a new
    // publication with its own identity: the public exposure is never relabelled.
    let private = private_request("web", 3000, &["alice"], expires);
    assert!(matches!(
        gate.publish(&world.coordinator, &execution(WEB), private.clone(), 1_024),
        Err(GateRefusal::Ingress(IngressError::AlreadyPublished { .. }))
    ));
    assert_eq!(gate.withdraw(&execution(WEB), public).unwrap().len(), 2);
    for ends in &mut kept {
        assert_eq!(ends.caller.drain(), (Vec::new(), true));
    }
    let relabelled = gate
        .publish(&world.coordinator, &execution(WEB), private, 1_024)
        .unwrap();
    assert_ne!(relabelled, public);
    let (_ends, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest
        ),
        Err(GateRefusal::Ingress(IngressError::NotAuthenticated))
    );
    let shown: Vec<(PublicationState, Audience)> = gate
        .publication_status(&world.coordinator, &execution(WEB))
        .into_iter()
        .map(|status| (status.state, status.audience))
        .collect();
    assert_eq!(
        shown,
        [
            (PublicationState::Withdrawn, Audience::Public),
            (
                PublicationState::Active,
                Audience::Private {
                    principals: [principal("alice")].into()
                }
            ),
        ]
    );
}

#[test]
fn spending_the_response_budget_closes_the_session() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let verifier = FakeVerifier::default();
    let mut releases = releases(&[(WEB, 1_000)]);
    let published = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            10,
        )
        .unwrap();
    let (mut ends, outside, guest) = channel();
    let session = gate
        .admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest,
        )
        .unwrap();

    ends.caller.write(b"GET /").unwrap();
    ends.guest.write(b"hello!").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut releases, session.id())
        .unwrap();
    assert_eq!(
        pumped,
        Pumped {
            request_bytes: 5,
            response_bytes: 6,
            state: ChannelState::Open
        }
    );
    assert_eq!(ends.guest.drain(), (b"GET /".to_vec(), false));
    assert_eq!(ends.caller.drain(), (b"hello!".to_vec(), false));
    let budget = gate.publication_status(&world.coordinator, &execution(WEB))[0].response_budget;
    assert_eq!(
        (
            budget.limit_bytes,
            budget.used_bytes,
            budget.remaining_bytes
        ),
        (10, 6, 4)
    );

    // Ten more bytes: four fit, the session closes, and the rest never leaves.
    ends.guest.write(b"0123456789").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut releases, session.id())
        .unwrap();
    assert_eq!(pumped.response_bytes, 4);
    assert_eq!(pumped.state, closed(CloseReason::ResponseBudgetSpent));
    assert_eq!(ends.caller.drain(), (b"0123".to_vec(), true));
    assert_eq!(ends.guest.unread_by_peer(), 6);
    assert!(ends.guest.peer_closed());
    assert_eq!(released(&releases, WEB), 10);
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, session.id()),
        Err(GateRefusal::UnknownSession {
            session: session.id()
        })
    );

    let status = &gate.publication_status(&world.coordinator, &execution(WEB))[0];
    assert_eq!(status.publication, published);
    assert_eq!(status.state, PublicationState::ResponseBudgetSpent);
    let budget = status.response_budget;
    assert_eq!((budget.used_bytes, budget.remaining_bytes), (10, 0));
    let (late, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, None),
            outside,
            guest
        ),
        Err(GateRefusal::Ingress(IngressError::NotPublished {
            service: service("web"),
            port: port(3000)
        }))
    );
    assert!(late.caller.peer_closed());
}

#[test]
fn a_release_account_refusal_closes_the_session_before_bytes_leave() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let verifier = FakeVerifier::default();
    gate.publish(
        &world.coordinator,
        &execution(WEB),
        public_request("web", 3000, world.in_seconds(600)),
        100,
    )
    .unwrap();
    let admit = |gate: &mut ConnectionGate| {
        let (ends, outside, guest) = channel();
        let session = gate
            .admit(
                &world.coordinator,
                &verifier,
                inbound(WEB, "web", 3000, None),
                outside,
                guest,
            )
            .unwrap();
        (ends, session)
    };

    // The sandbox's response channel holds four bytes; eight are refused whole.
    let mut small = releases(&[(WEB, 4)]);
    let (mut ends, session) = admit(&mut gate);
    ends.guest.write(b"12345678").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut small, session.id())
        .unwrap();
    match pumped.state {
        ChannelState::Closed(CloseReason::ReleaseRefused(ReleaseError::Exhausted(exhausted))) => {
            assert_eq!(
                exhausted.scope,
                BudgetScope::ReleaseChannel(
                    crate::sandbox_contract::destinations::ReleaseChannel::PublishedServiceResponse
                )
            );
            assert_eq!(exhausted.requested, 8);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
    assert_eq!(released(&small, WEB), 0);

    // Without an account the sandbox releases nothing.
    let mut none = releases(&[]);
    let (mut ends, session) = admit(&mut gate);
    ends.guest.write(b"x").unwrap();
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut none, session.id())
            .unwrap()
            .state,
        closed(CloseReason::NoReleaseAccount)
    );
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
}

#[test]
fn either_side_ending_closes_the_session() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let verifier = FakeVerifier::default();
    let mut releases = releases(&[(WEB, 1_000)]);
    gate.publish(
        &world.coordinator,
        &execution(WEB),
        public_request("web", 3000, world.in_seconds(600)),
        1_000,
    )
    .unwrap();
    for caller_hangs_up in [true, false] {
        let (mut ends, outside, guest) = channel();
        let session = gate
            .admit(
                &world.coordinator,
                &verifier,
                inbound(WEB, "web", 3000, None),
                outside,
                guest,
            )
            .unwrap();
        if caller_hangs_up {
            ends.caller.close();
        } else {
            ends.guest.close();
        }
        assert_eq!(
            gate.pump_session(&world.coordinator, &mut releases, session.id())
                .unwrap()
                .state,
            closed(CloseReason::PeerEnded)
        );
        assert!(ends.caller.peer_closed() && ends.guest.peer_closed());
    }
    assert_eq!(gate.open_sessions(), 0);
}

#[test]
fn the_gate_clock_never_goes_back() {
    let mut authority = SettableAuthority::at(1_000);
    let mut gate = ConnectionGate::new();
    let verifier = FakeVerifier::default();
    gate.attach(&authority, registration(WEB, "team-a"))
        .unwrap();
    gate.publish(
        &authority,
        &execution(WEB),
        public_request(
            "web",
            3000,
            crate::foundation::ids::MonotonicTime::from_nanos(1_060 * 1_000_000_000),
        ),
        100,
    )
    .unwrap();
    for seconds in [1_060, 1_000] {
        authority.set(seconds);
        let (_ends, outside, guest) = channel();
        assert_eq!(
            gate.admit(
                &authority,
                &verifier,
                inbound(WEB, "web", 3000, None),
                outside,
                guest
            ),
            Err(GateRefusal::Ingress(IngressError::NotPublished {
                service: service("web"),
                port: port(3000)
            })),
            "at {seconds} s"
        );
    }
    assert_eq!(
        gate.publication_status(&authority, &execution(WEB))[0].state,
        PublicationState::Expired
    );
}

#[test]
fn zero_budgets_and_double_attachment_are_refused() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    assert_eq!(
        gate.publish(
            &world.coordinator,
            &execution(WEB),
            public_request("web", 3000, world.in_seconds(600)),
            0
        ),
        Err(GateRefusal::ZeroBudget)
    );
    assert_eq!(
        gate.attach(&world.coordinator, registration(WEB, "team-a")),
        Err(GateRefusal::AlreadyAttached {
            sandbox: execution(WEB)
        })
    );
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration("exe-never-launched", "team-a")
        ),
        Err(GateRefusal::AuthorityEnded {
            sandbox: execution("exe-never-launched")
        })
    );
}

#[test]
fn a_session_closes_when_the_proof_it_was_admitted_on_expires() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    let publication = gate
        .publish(
            &world.coordinator,
            &execution(WEB),
            private_request("web", 3000, &["alice"], world.in_seconds(3_000)),
            1_000,
        )
        .unwrap();
    let binding = gate.proof_binding(&execution(WEB), publication).unwrap();
    let mode = AuthenticationMode::PlatformSession;
    let valid_until = world.in_seconds(60);
    let mut verifier = FakeVerifier::default();
    verifier.issue_until("tok", "alice", binding, mode, valid_until);
    let (mut ends, outside, guest) = channel();
    let session = gate
        .admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, proof(mode, "tok")),
            outside,
            guest,
        )
        .unwrap();
    assert_eq!(session.proof_valid_until(), Some(valid_until));
    assert_eq!(
        gate.session_status()[0].proof_valid_until,
        Some(valid_until)
    );
    let mut releases = releases(&[(WEB, 1_000)]);

    // While the proof holds, the session is served.
    world.advance(59);
    ends.guest.write(b"early").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut releases, session.id())
        .unwrap();
    assert_eq!(
        (pumped.response_bytes, pumped.state),
        (5, ChannelState::Open)
    );
    assert_eq!(ends.caller.drain(), (b"early".to_vec(), false));

    // Once it expires, the session closes before anything moves either way, though the
    // publication itself runs for long after.
    world.advance(1);
    ends.guest.write(b"late").unwrap();
    ends.caller.write(b"GET /").unwrap();
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, session.id())
            .unwrap(),
        Pumped::closed(CloseReason::ProofExpired)
    );
    assert_eq!(ends.caller.drain(), (Vec::new(), true));
    assert_eq!(ends.guest.drain(), (Vec::new(), true));
    assert_eq!(released(&releases, WEB), 5);
    assert_eq!(
        gate.publication_status(&world.coordinator, &execution(WEB))[0].state,
        PublicationState::Active
    );

    // A validity that has ended admits no one, whatever the verifier says.
    let (late, outside, guest) = channel();
    assert_eq!(
        gate.admit(
            &world.coordinator,
            &verifier,
            inbound(WEB, "web", 3000, proof(mode, "tok")),
            outside,
            guest
        ),
        Err(GateRefusal::Proof(ProofRefusal::Expired))
    );
    assert!(late.caller.peer_closed());
}

#[test]
fn a_spent_response_budget_forwards_no_further_request() {
    let (world, mut gate) = attached(&[WEB], &["web"]);
    gate.publish(
        &world.coordinator,
        &execution(WEB),
        public_request("web", 3000, world.in_seconds(600)),
        4,
    )
    .unwrap();
    let mut releases = releases(&[(WEB, 1_000)]);
    let open = |gate: &mut ConnectionGate| {
        let (ends, outside, guest) = channel();
        let handle = gate
            .admit(
                &world.coordinator,
                &FakeVerifier::default(),
                inbound(WEB, "web", 3000, None),
                outside,
                guest,
            )
            .unwrap();
        (ends, handle)
    };
    let (mut first, first_handle) = open(&mut gate);
    let (mut second, second_handle) = open(&mut gate);

    // The first session spends the whole budget.
    first.guest.write(b"1234").unwrap();
    let pumped = gate
        .pump_session(&world.coordinator, &mut releases, first_handle.id())
        .unwrap();
    assert_eq!(pumped.response_bytes, 4);
    assert_eq!(pumped.state, closed(CloseReason::ResponseBudgetSpent));

    // The second closes without forwarding its caller's request to the guest.
    second.caller.write(b"POST /x").unwrap();
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, second_handle.id())
            .unwrap(),
        Pumped::closed(CloseReason::ResponseBudgetSpent)
    );
    assert_eq!(second.guest.drain(), (Vec::new(), true));
    assert_eq!(second.caller.unread_by_peer(), 7);
    assert_eq!(released(&releases, WEB), 4);
}

#[test]
fn an_outside_caller_learns_nothing_of_the_sandbox_state() {
    const REVOKED: &str = "exe-revoked";
    const TOMBSTONED: &str = "exe-tombstoned";
    const POLICY: &str = "exe-policy";
    const SPENT: &str = "exe-spent";
    const EXPIRED: &str = "exe-expired";
    const UNGRANTED: &str = "exe-ungranted";
    let (mut world, mut gate) = attached(&[REVOKED, TOMBSTONED, POLICY, SPENT, EXPIRED], &["web"]);
    // Granted nothing, it is attached offering nothing.
    world.launch(UNGRANTED, &[]);
    gate.attach(
        &world.coordinator,
        registration_of(UNGRANTED, "team-a", &[]),
    )
    .unwrap();
    for (sandbox, seconds, budget) in [
        (REVOKED, 600, 100),
        (TOMBSTONED, 600, 100),
        (POLICY, 600, 100),
        (SPENT, 600, 2),
        (EXPIRED, 10, 100),
    ] {
        gate.publish(
            &world.coordinator,
            &execution(sandbox),
            public_request("web", 3000, world.in_seconds(seconds)),
            budget,
        )
        .unwrap();
    }
    let mut releases = releases(&[(SPENT, 1_000)]);
    let (mut spent_ends, outside, guest) = channel();
    let spender = gate
        .admit(
            &world.coordinator,
            &FakeVerifier::default(),
            inbound(SPENT, "web", 3000, None),
            outside,
            guest,
        )
        .unwrap();
    spent_ends.guest.write(b"ok").unwrap();
    gate.pump_session(&world.coordinator, &mut releases, spender.id())
        .unwrap();
    world.coordinator.revoke(&execution(REVOKED)).unwrap();
    world
        .coordinator
        .revoke_grant(&execution(TOMBSTONED), published_grant_id("web"))
        .unwrap();
    world
        .coordinator
        .raise_policy_epoch(&execution(POLICY))
        .unwrap();
    world.advance(10);

    // The host sees each reason; the outside caller sees one answer for all of them.
    for (sandbox, shown) in [
        (REVOKED, Some(PublicationState::AuthorityEnded)),
        (TOMBSTONED, Some(PublicationState::GrantRevoked)),
        (POLICY, Some(PublicationState::PolicyChanged)),
        (SPENT, Some(PublicationState::ResponseBudgetSpent)),
        (EXPIRED, Some(PublicationState::Expired)),
        (UNGRANTED, None),
        ("exe-unknown", None),
    ] {
        let states: Vec<PublicationState> = gate
            .publication_status(&world.coordinator, &execution(sandbox))
            .into_iter()
            .map(|status| status.state)
            .collect();
        assert_eq!(states, shown.into_iter().collect::<Vec<_>>(), "{sandbox}");
        let (ends, outside, guest) = channel();
        assert_eq!(
            gate.admit(
                &world.coordinator,
                &FakeVerifier::default(),
                inbound(sandbox, "web", 3000, None),
                outside,
                guest
            ),
            Err(GateRefusal::Ingress(IngressError::NotPublished {
                service: service("web"),
                port: port(3000)
            })),
            "{sandbox}"
        );
        assert!(ends.caller.peer_closed() && ends.guest.peer_closed());
    }
    assert_eq!(gate.open_sessions(), 0);
}

#[test]
fn refusal_messages_read_as_single_sentences() {
    let mismatch = GateRefusal::EndpointMismatch {
        sandbox: execution("exe-model"),
        attached: scope("team-a"),
        named: scope("team-b"),
    };
    assert_eq!(
        mismatch.to_string(),
        format!(
            "the grant names sandbox exe-model in scope {:?}, but it was attached in scope {:?}",
            scope("team-b"),
            scope("team-a")
        )
    );
    let messages = [
        mismatch.to_string(),
        GateRefusal::PolicyChanged {
            sandbox: execution(WEB),
        }
        .to_string(),
        GateRefusal::ServiceNotRegistered {
            sandbox: execution(WEB),
            service: service("web"),
        }
        .to_string(),
        GateRefusal::ServiceNotGranted {
            sandbox: execution(WEB),
            service: service("web"),
            grant: published_grant_id("web"),
        }
        .to_string(),
        AcknowledgeRefusal::StaleEpoch {
            sandbox: execution(WEB),
            reported: crate::foundation::ids::AuthorizationEpoch::new(1),
            revoked: crate::foundation::ids::AuthorizationEpoch::new(2),
        }
        .to_string(),
        AcknowledgeRefusal::ChannelsStillOpen {
            sandbox: execution(WEB),
            sessions: 1,
            connections: 0,
        }
        .to_string(),
    ];
    for message in messages {
        assert!(!message.contains("  "), "{message}");
    }
}
