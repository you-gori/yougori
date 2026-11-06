//! VM §4.7, §1.3 network authority and VM-W13: the committed mapping from a V02 published
//! service to its CORE-04 grant. The digest is stable, distinct for every service and
//! kept apart by its domain; a registration names services only and is refused unless the
//! sandbox's launch settings hold the grant derived for each; publishing, serving and
//! connecting run on the derived grant through CORE-04; and tombstoning it closes that
//! service's sessions and connections, and only theirs.

use std::collections::BTreeSet;

use super::fakes::*;
use super::*;
use crate::foundation::coordination::network_grant_id;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{digest, DigestBuilder};
use crate::sandbox_contract::destinations::IngressError;

const WEB: &str = "exe-web";
const CLIENT: &str = "exe-client";

/// The digest of the service `web`, computed outside Rust from the encoding
/// `foundation::ids::digest` documents: SHA-256 over the big-endian u64 length and the
/// bytes of the domain, then of `web`. Changing the domain or the layout changes it.
const WEB_DIGEST: &str = "7ede1fab786c917da2558b99c4fa23d54874aa898aa5030121aca62e43de86c6";

fn not_published(name: &str, at: u16) -> GateRefusal {
    GateRefusal::Ingress(IngressError::NotPublished {
        service: service(name),
        port: port(at),
    })
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

fn publish(
    gate: &mut ConnectionGate,
    world: &World,
    sandbox: &str,
    name: &str,
    at: u16,
) -> Result<GatePublicationId, GateRefusal> {
    gate.publish(
        &world.coordinator,
        &execution(sandbox),
        public_request(name, at, world.in_seconds(600)),
        1_000,
    )
}

/// Grants `caller` to `callee`'s `name` on `at` at both ends and connects them.
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
    let request = ConnectionRequest {
        caller: execution(caller),
        callee: execution(callee),
        service: service(name),
        port: port(at),
        budget: ConnectionBudget {
            caller_to_callee_bytes: 1_000,
            callee_to_caller_bytes: 1_000,
        },
    };
    let handle = gate
        .connect(&world.coordinator, request, caller_end, callee_end)
        .unwrap();
    (handle, ends)
}

#[test]
fn the_mapping_is_stable_distinct_and_domain_separated() {
    let web = service("web");
    let derived = published_service_digest(&web);

    // Stable: a known answer, the same for every equal identity, and exactly one part,
    // the identifier text, under the published-service domain.
    assert_eq!(derived.to_hex(), WEB_DIGEST);
    assert_eq!(published_service_digest(&service("web")), derived);
    assert_eq!(
        DigestBuilder::new(PUBLISHED_SERVICE_DOMAIN)
            .str("web")
            .finish(),
        derived
    );
    // The grant and its identity follow from the digest, CORE-04's own way.
    assert_eq!(
        published_service_grant(&web),
        NetworkGrant::PublishedService { service: derived }
    );
    assert_eq!(
        published_service_grant_id(&web),
        network_grant_id(&NetworkGrant::PublishedService { service: derived })
    );

    // Distinct: no two services share a digest or a grant identity, whether they differ
    // in case, by a prefix or by a separator.
    let names = [
        "web",
        "Web",
        "WEB",
        "we",
        "web-1",
        "web1",
        "web.api",
        "web:api",
        "web_api",
        "api",
        "admin",
        "preview",
        "model-api",
    ];
    let digests: BTreeSet<_> = names
        .iter()
        .map(|name| published_service_digest(&service(name)))
        .collect();
    let ids: BTreeSet<_> = names
        .iter()
        .map(|name| published_service_grant_id(&service(name)))
        .collect();
    assert_eq!((digests.len(), ids.len()), (names.len(), names.len()));

    // Domain-separated: the same text under any other domain gives another digest, the
    // earlier tests' own convention included, and no other kind of grant naming the same
    // digest shares the grant's identity.
    for domain in [
        "yougori/test/published-service/v1",
        "yougori/sandbox/published-service/v2",
        "yougori/coordination/network-grant/v1",
        "yougori/content/v1",
    ] {
        assert_ne!(digest(domain, &[b"web"]), derived, "{domain}");
    }
    let id = published_service_grant_id(&web);
    assert_ne!(*id.digest(), derived);
    for other in [
        NetworkGrant::NamedRoute { route: derived },
        NetworkGrant::CredentialedOperation { operation: derived },
    ] {
        assert_ne!(network_grant_id(&other), id, "{other:?}");
    }
}

#[test]
fn registration_refuses_a_missing_or_mismatched_grant() {
    const MISSING: &str = "exe-missing";
    const MISMATCHED: &str = "exe-mismatched";
    const PARTIAL: &str = "exe-partial";
    const TOMBSTONED: &str = "exe-tombstoned";
    let mut world = World::new();
    let mut gate = ConnectionGate::new();
    let not_granted = |sandbox: &str, name: &str| GateRefusal::ServiceNotGranted {
        sandbox: execution(sandbox),
        service: service(name),
        grant: published_grant_id(name),
    };

    // Missing: the launch granted no network at all.
    world.launch(MISSING, &[]);
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(MISSING, "team-a", &["web"])
        ),
        Err(not_granted(MISSING, "web"))
    );

    // Mismatched: the launch granted a published-service grant under a digest the host
    // chose itself, as hosts did before the mapping.
    let chosen = NetworkGrant::PublishedService {
        service: digest("yougori/test/published-service/v1", &[b"web"]),
    };
    world.launch_granting(MISMATCHED, BTreeSet::from([chosen]));
    let settings = world
        .coordinator
        .sandbox(&execution(MISMATCHED))
        .unwrap()
        .settings_grant();
    assert!(settings.network.contains(&chosen));
    assert!(!settings.network.contains(&published_grant("web")));
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(MISMATCHED, "team-a", &["web"])
        ),
        Err(not_granted(MISMATCHED, "web"))
    );

    // One service the settings lack refuses the whole registration.
    world.launch(PARTIAL, &["web"]);
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(PARTIAL, "team-a", &["web", "api"])
        ),
        Err(not_granted(PARTIAL, "api"))
    );

    // A tombstoned grant left the settings and is never honoured there again.
    world.launch(TOMBSTONED, &["web"]);
    world
        .coordinator
        .revoke_grant(&execution(TOMBSTONED), published_grant_id("web"))
        .unwrap();
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(TOMBSTONED, "team-a", &["web"])
        ),
        Err(GateRefusal::GrantRevoked {
            sandbox: execution(TOMBSTONED),
            service: service("web"),
            grant: published_grant_id("web"),
        })
    );

    // A refused registration attaches nothing: nothing can be published, and an outside
    // caller is told only that nothing is.
    for sandbox in [MISSING, MISMATCHED, PARTIAL, TOMBSTONED] {
        assert_eq!(gate.attached_epoch(&execution(sandbox)), None, "{sandbox}");
        assert_eq!(
            publish(&mut gate, &world, sandbox, "web", 3000),
            Err(GateRefusal::UnknownSandbox {
                sandbox: execution(sandbox)
            }),
            "{sandbox}"
        );
        assert_eq!(
            admit(&mut gate, &world, sandbox, "web", 3000).err(),
            Some(not_published("web", 3000)),
            "{sandbox}"
        );
    }

    // Registering what the settings hold attaches, and offers only that.
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(PARTIAL, "team-a", &["web"])
        ),
        Ok(world.epoch(PARTIAL))
    );
    publish(&mut gate, &world, PARTIAL, "web", 3000).unwrap();
    assert_eq!(
        publish(&mut gate, &world, PARTIAL, "api", 4000),
        Err(GateRefusal::ServiceNotRegistered {
            sandbox: execution(PARTIAL),
            service: service("api"),
        })
    );
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(MISMATCHED, "team-a", &[])
        ),
        Ok(world.epoch(MISMATCHED))
    );
}

#[test]
fn publishing_and_serving_run_end_to_end_on_the_derived_grant() {
    let mut world = World::new();
    let mut gate = ConnectionGate::with_chunk_bytes(std::num::NonZeroUsize::new(64).unwrap());
    // The host launches each sandbox granting the derived grant of the service it offers,
    // then registers the service by name alone.
    let web = service("web");
    for sandbox in [WEB, CLIENT] {
        world.launch_granting(sandbox, BTreeSet::from([published_service_grant(&web)]));
        gate.attach(
            &world.coordinator,
            registration_of(sandbox, "team-a", &["web"]),
        )
        .unwrap();
    }
    let mut releases = releases(&[(WEB, 1_000), (CLIENT, 1_000)]);

    // Published and served to an outside caller.
    let publication = publish(&mut gate, &world, WEB, "web", 3000).unwrap();
    let (mut ends, session) = admit(&mut gate, &world, WEB, "web", 3000).unwrap();
    assert_eq!(session.publication(), publication);
    ends.caller.write(b"GET /").unwrap();
    ends.guest.write(b"served").unwrap();
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, session.id())
            .unwrap(),
        Pumped {
            request_bytes: 5,
            response_bytes: 6,
            state: ChannelState::Open
        }
    );
    assert_eq!(ends.guest.drain(), (b"GET /".to_vec(), false));
    assert_eq!(ends.caller.drain(), (b"served".to_vec(), false));
    assert_eq!(
        gate.publication_status(&world.coordinator, &execution(WEB))[0].state,
        PublicationState::Active
    );

    // Connected to from another sandbox, on the callee's derived grant.
    let (handle, mut link_ends) = link(&mut gate, &world, CLIENT, WEB, "web", 8080);
    link_ends.caller.write(b"ask").unwrap();
    link_ends.guest.write(b"answer").unwrap();
    assert_eq!(
        gate.pump_connection(&world.coordinator, &mut releases, handle.id())
            .unwrap(),
        Pumped {
            request_bytes: 3,
            response_bytes: 6,
            state: ChannelState::Open
        }
    );
    assert_eq!(link_ends.guest.drain(), (b"ask".to_vec(), false));
    assert_eq!(link_ends.caller.drain(), (b"answer".to_vec(), false));

    // Both responses are the web sandbox's outbound data.
    assert_eq!(released(&releases, WEB), 12);
    assert_eq!(released(&releases, CLIENT), 0);
}

#[test]
fn revoking_the_derived_grant_closes_the_services_sessions() {
    let (mut world, mut gate) = attached(&[WEB, CLIENT], &["web", "api"]);
    let epoch = world.epoch(WEB);
    let web_publication = publish(&mut gate, &world, WEB, "web", 3000).unwrap();
    publish(&mut gate, &world, WEB, "api", 4000).unwrap();
    let (mut web_ends, web_session) = admit(&mut gate, &world, WEB, "web", 3000).unwrap();
    let (_api_ends, api_session) = admit(&mut gate, &world, WEB, "api", 4000).unwrap();
    let (web_link, mut link_ends) = link(&mut gate, &world, CLIENT, WEB, "web", 8080);
    let mut releases = releases(&[(WEB, 1_000), (CLIENT, 1_000)]);

    // The host names the service; CORE-04 tombstones the grant derived for it, the very
    // grant it withdraws from the launch settings.
    let web = service("web");
    let grant = published_service_grant_id(&web);
    let revoked = world
        .coordinator
        .revoke_grant(&execution(WEB), grant)
        .unwrap();
    assert_eq!(revoked.network, Some(published_service_grant(&web)));

    let reports = gate.close_revoked(&world.coordinator);
    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert_eq!(
        report.cause(),
        &ClosureCause::GrantRevoked {
            sandbox: execution(WEB),
            epoch,
            service: web.clone(),
            grant,
        }
    );
    assert_eq!(report.withdrawn().to_vec(), vec![web_publication]);
    assert_eq!(
        report.sessions().to_vec(),
        vec![ClosedSession {
            session: web_session.id(),
            publication: web_publication,
            service: web.clone(),
        }]
    );
    let closed: Vec<ConnectionId> = report
        .connections()
        .iter()
        .map(|closed| closed.connection)
        .collect();
    assert_eq!(closed, [web_link.id()]);
    assert_eq!(web_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(web_ends.guest.drain(), (Vec::new(), true));
    assert_eq!(link_ends.caller.drain(), (Vec::new(), true));
    assert_eq!(link_ends.guest.drain(), (Vec::new(), true));

    // The other service keeps its session; the revoked one is unreachable.
    assert_eq!(
        gate.pump_session(&world.coordinator, &mut releases, api_session.id())
            .unwrap()
            .state,
        ChannelState::Open
    );
    assert_eq!(
        admit(&mut gate, &world, WEB, "web", 3000).err(),
        Some(not_published("web", 3000))
    );

    // Attached again after a policy change, the sandbox can no longer register the
    // revoked service; it registers the rest.
    world
        .coordinator
        .raise_policy_epoch(&execution(WEB))
        .unwrap();
    assert_eq!(gate.close_revoked(&world.coordinator).len(), 1);
    assert_eq!(
        gate.attach(
            &world.coordinator,
            registration_of(WEB, "team-a", &["web", "api"])
        ),
        Err(GateRefusal::GrantRevoked {
            sandbox: execution(WEB),
            service: web,
            grant,
        })
    );
    assert_eq!(
        gate.attach(&world.coordinator, registration_of(WEB, "team-a", &["api"])),
        Ok(epoch)
    );
    publish(&mut gate, &world, WEB, "api", 4000).unwrap();
}
